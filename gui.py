#!/usr/bin/env python3
"""
Графический интерфейс (Tkinter) для менеджера профилей.

Запуск:  python gui.py

Вкладки:
  • «Профили» — создать / запустить / удалить профиль, сменить ему прокси.
  • «Прокси»  — пул сохранённых прокси, который можно переиспользовать.

Каждый профиль запускается ОТДЕЛЬНЫМ процессом (python browser.py <имя>),
поэтому окно интерфейса не зависает и можно держать несколько браузеров разом.
Профиль «занят», пока открыто его окно браузера; закрыли окно — статус снимется.

Если Tkinter не установлен (минимальный Linux):
    sudo apt install python3-tk
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import threading
import time

import tkinter as tk
from tkinter import ttk, messagebox

from profile import list_profiles, create_profile, set_profile_proxy, PROFILES_DIR
from proxy_pool import (load_pool, add_proxy, remove_proxy, refresh_pool_geo,
                        check_proxy, PoolProxy)
from geo import country_flag

HERE = os.path.dirname(os.path.abspath(__file__))
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class _Session:
    """
    Запущенный профиль. Может быть либо запущен ЭТИМ GUI (есть Popen), либо
    подхвачен как «сирота» от прошлого запуска GUI (только PID, из running.pid).
    """
    def __init__(self, pid: int, popen: "subprocess.Popen | None" = None,
                 logf: object = None) -> None:
        self.pid = pid
        self.popen = popen
        self.logf = logf

    def alive(self, alive_pids: "set[int] | None") -> bool:
        if self.popen is not None:
            return self.popen.poll() is None
        if alive_pids is not None:
            return self.pid in alive_pids
        return _pid_running(self.pid)


def _pid_file_path(name: str) -> str:
    return os.path.join(PROFILES_DIR, name, "running.pid")


def _read_pid(name: str) -> "int | None":
    try:
        with open(_pid_file_path(name), encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:  # noqa: BLE001
        return None


def _remove_pid_file(name: str) -> None:
    try:
        os.remove(_pid_file_path(name))
    except OSError:
        pass


def _alive_pids() -> "set[int] | None":
    """Множество всех живых PID одним вызовом (Windows). None — если не Windows."""
    if sys.platform != "win32":
        return None
    try:
        out = subprocess.run(["tasklist", "/NH", "/FO", "CSV"],
                             capture_output=True, text=True,
                             creationflags=_CREATE_NO_WINDOW).stdout
    except Exception:  # noqa: BLE001
        return None
    pids: set[int] = set()
    for line in out.splitlines():
        parts = line.split('","')
        if len(parts) >= 2:
            try:
                pids.add(int(parts[1].strip('"').strip()))
            except ValueError:
                pass
    return pids


def _pid_running(pid: int) -> bool:
    """Жив ли процесс (для POSIX; на Windows используем _alive_pids)."""
    if sys.platform == "win32":
        pids = _alive_pids()
        return pids is None or pid in pids
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _kill_tree(pid: int) -> None:
    """Завершить процесс ВМЕСТЕ с дочерним Chromium (всё дерево)."""
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=_CREATE_NO_WINDOW)
        else:
            os.kill(pid, 9)
    except Exception:  # noqa: BLE001
        pass


def _find_browser_pids() -> "list[int]":
    """
    Найти ВСЕ python-процессы, запущенные как `browser.py <профиль>` — включая
    сирот без PID-файла (от старого кода/упавших сессий). Это и есть «утечка»:
    каждый такой сирота держит релей с открытыми соединениями к прокси.
    """
    pids: list[int] = []
    try:
        if sys.platform == "win32":
            # ТОЛЬКО python-процессы (python.exe/pythonw.exe), запускающие наш
            # browser.py из ЭТОЙ папки. Иначе матчатся и оболочки, где строка
            # 'browser.py' просто упомянута в команде — их убивать нельзя.
            ps = ("Get-CimInstance Win32_Process -Filter "
                  "\"Name='python.exe' OR Name='pythonw.exe'\" | "
                  "Where-Object { $_.CommandLine -like '*\\browser.py*' } | "
                  "Select-Object -ExpandProperty ProcessId")
            out = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True,
                                 creationflags=_CREATE_NO_WINDOW, timeout=15).stdout
        else:
            out = subprocess.run(["pgrep", "-f", r"python.*browser\.py"],
                                 capture_output=True, text=True, timeout=15).stdout
        for tok in out.split():
            try:
                pids.append(int(tok.strip()))
            except ValueError:
                pass
    except Exception:  # noqa: BLE001
        pass
    return pids


def _force_rmtree(path: str, attempts: int = 12, delay: float = 0.5) -> None:
    """
    Надёжно удалить каталог профиля на Windows.

    После закрытия окна дочерние процессы Chromium ещё пару секунд держат файлы
    (Account Web Data и т.п.) — WinError 32. Поэтому повторяем удаление с паузой,
    а read-only файлы (часть файлов Chromium такие) делаем доступными для записи.
    """
    def on_error(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:  # noqa: BLE001
            pass

    last: Exception | None = None
    for _ in range(attempts):
        try:
            shutil.rmtree(path, onerror=on_error)
        except Exception as e:  # noqa: BLE001
            last = e
        if not os.path.exists(path):
            return
        time.sleep(delay)
    raise last or OSError(f"каталог всё ещё занят: {path}")


def _geo_label(geo: dict) -> str:
    """Из словаря geo профиля -> '🇺🇸 US, New York' (флаг + страна + город)."""
    country = geo.get("country", "") or ""
    city = geo.get("city", "") or ""
    if not country:
        return "?"
    loc = country + (f", {city}" if city else "")
    return f"{country_flag(country)} {loc}".strip()


def enable_clipboard_shortcuts(root: tk.Tk) -> None:
    """
    Заставить Ctrl+C/V/X/A работать при ЛЮБОЙ раскладке (вкл. русскую).

    При раскладке РУ физические клавиши дают кириллические символы, и Tk не ловит
    стандартные Ctrl+C/V/X. Поэтому ориентируемся не на символ (keysym), а на
    keycode — код ФИЗИЧЕСКОЙ клавиши, одинаковый при любой раскладке:
        C=67, X=88, V=86, A=65 (Windows virtual-key codes).
    bind_all -> работает во всех полях, включая будущие диалоги.
    """
    keycode_to_event = {
        67: "<<Copy>>",       # C
        88: "<<Cut>>",        # X
        86: "<<Paste>>",      # V
        65: "<<SelectAll>>",  # A
    }
    # При ЛАТИНСКОЙ раскладке Tk уже сам обрабатывает Ctrl+C/V/X/A (keysym = буква),
    # поэтому такие события пропускаем — иначе вставка сработает дважды.
    latin_handled = {"c", "C", "v", "V", "x", "X", "a", "A"}

    def on_ctrl_key(e: tk.Event):
        if e.keysym in latin_handled:
            return None  # дефолтная обработка Tk уже сделает своё
        event = keycode_to_event.get(e.keycode)
        if not event:
            return None
        try:
            e.widget.event_generate(event)
        except Exception:  # noqa: BLE001
            return None
        return "break"

    root.bind_all("<Control-KeyPress>", on_ctrl_key)


def attach_context_menu(widget: tk.Widget) -> None:
    """Меню по правому клику: Вырезать / Копировать / Вставить."""
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(label="Вырезать",
                     command=lambda: widget.event_generate("<<Cut>>"))
    menu.add_command(label="Копировать",
                     command=lambda: widget.event_generate("<<Copy>>"))
    menu.add_command(label="Вставить",
                     command=lambda: widget.event_generate("<<Paste>>"))

    def popup(e: tk.Event) -> None:
        try:
            widget.focus_set()
        except Exception:  # noqa: BLE001
            pass
        menu.tk_popup(e.x_root, e.y_root)

    widget.bind("<Button-3>", popup)


class ProxyPicker:
    """
    Виджет выбора прокси: из пула ИЛИ вручную.

    Раскладывается через grid в переданный родитель (combobox + поле ввода,
    которое ВСЕГДА активно — туда можно вставить свой прокси). raw() возвращает
    итоговую строку: приоритет у введённого вручную, иначе выбранное из пула.
    """
    NONE = "(без прокси)"

    def __init__(self, parent: tk.Widget, row: int = 0) -> None:
        self.pool: list[PoolProxy] = load_pool()

        self.var = tk.StringVar()
        values = [self.NONE] + [p.display() for p in self.pool]
        self.combo = ttk.Combobox(parent, values=values, textvariable=self.var,
                                  state="readonly", width=46)
        self.combo.grid(row=row, column=0, sticky="we", pady=(2, 4))

        ttk.Label(parent, foreground="#666",
                  text="…или вставьте свой прокси (Ctrl+V или правый клик → Вставить):"
                  ).grid(row=row + 1, column=0, sticky="w")
        self.manual_var = tk.StringVar()
        self.manual_entry = ttk.Entry(parent, textvariable=self.manual_var, width=48)
        self.manual_entry.grid(row=row + 2, column=0, sticky="we", pady=(2, 0))
        attach_context_menu(self.manual_entry)
        ttk.Label(parent, foreground="#666",
                  text="http://user:pass@host:port  |  socks5://host:port  |  host:port:user:pass"
                  ).grid(row=row + 3, column=0, sticky="w", pady=(2, 0))

        self.var.set(self.NONE)

    def raw(self) -> str | None:
        # Введённое вручную имеет приоритет — поле всегда доступно для вставки.
        manual = self.manual_var.get().strip()
        if manual:
            return manual
        choice = self.var.get()
        if choice == self.NONE:
            return None
        # пункт из пула: индекс в combobox со смещением на пункт NONE
        idx = self.combo.current() - 1
        if 0 <= idx < len(self.pool):
            return self.pool[idx].raw
        return None


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.running: dict[str, _Session] = {}  # имя -> сессия (этого GUI ИЛИ сирота)

        root.title("Anti-detect QA browser")
        root.geometry("780x500")
        root.minsize(680, 440)

        enable_clipboard_shortcuts(root)  # Ctrl+C/V/X при русской раскладке
        self._build_ui()
        self._adopt_orphans()   # подхватить процессы, оставшиеся от прошлого запуска
        self.refresh()
        self.refresh_pool()
        self._poll_processes()

    def _adopt_orphans(self) -> None:
        """
        Найти профили, чьи процессы остались жить от прошлого сеанса GUI
        (по running.pid), и взять их под контроль — чтобы их было видно и можно
        было остановить/удалить. Мёртвые PID-файлы чистим. Плюс убиваем зависших
        сирот БЕЗ PID-файла (от старого кода) — они и забивали прокси/память.
        """
        alive = _alive_pids()
        adopted_pids = set()
        for name in list_profiles():
            pid = _read_pid(name)
            if pid is None:
                continue
            if (alive is not None and pid in alive) or \
               (alive is None and _pid_running(pid)):
                self.running[name] = _Session(pid, popen=None, logf=None)
                adopted_pids.add(pid)
            else:
                _remove_pid_file(name)  # процесс уже мёртв — PID-файл устарел

        # Зачистка сирот без PID-файла: все browser.py-процессы, которые мы НЕ
        # подхватили, — это зависшие хвосты прошлых сессий. Убиваем их деревья.
        strays = [p for p in _find_browser_pids()
                  if p not in adopted_pids and p != os.getpid()]
        for pid in strays:
            _kill_tree(pid)
        if strays:
            self._set_status(f"Очищено зависших процессов от прошлых сессий: {len(strays)}.")

    def kill_strays(self) -> None:
        """Кнопка: принудительно убить ВСЕ зависшие browser.py-процессы и сессии."""
        pids = set(_find_browser_pids())
        for sess in self.running.values():
            pids.add(sess.pid)
        pids.discard(os.getpid())
        if not pids:
            messagebox.showinfo("Очистка", "Зависших процессов не найдено.")
            return
        if not messagebox.askyesno(
                "Очистка",
                f"Найдено процессов браузера: {len(pids)}.\n"
                "Принудительно завершить ВСЕ (включая зависших сирот)?"):
            return
        for pid in pids:
            _kill_tree(pid)
        for name in list(self.running.keys()):
            self._drop_session(name)
        self._set_status(f"Завершено процессов: {len(pids)}.")
        self.refresh()

    # ---------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.tab_profiles = ttk.Frame(nb, padding=8)
        self.tab_proxies = ttk.Frame(nb, padding=8)
        nb.add(self.tab_profiles, text="Профили")
        nb.add(self.tab_proxies, text="Прокси")

        self._build_profiles_tab(self.tab_profiles)
        self._build_proxies_tab(self.tab_proxies)

        # ----- общая статус-строка
        self.status = tk.StringVar(value="Готово.")
        ttk.Label(self.root, textvariable=self.status, relief="sunken", anchor="w",
                  padding=(6, 3)).pack(fill="x", side="bottom")

    def _build_profiles_tab(self, outer: ttk.Frame) -> None:
        ttk.Label(outer, text="Профили", font=("", 12, "bold")).pack(anchor="w")

        body = ttk.Frame(outer)
        body.pack(fill="both", expand=True, pady=(6, 8))

        # ----- слева: список профилей
        left = ttk.Frame(body)
        left.pack(side="left", fill="both", expand=False)
        self.listbox = tk.Listbox(left, width=30, activestyle="dotbox",
                                  exportselection=False)
        self.listbox.pack(side="left", fill="y")
        self.listbox.bind("<<ListboxSelect>>", lambda e: self._show_details())
        self.listbox.bind("<Double-Button-1>", lambda e: self.launch())
        sb = ttk.Scrollbar(left, orient="vertical", command=self.listbox.yview)
        sb.pack(side="left", fill="y")
        self.listbox.config(yscrollcommand=sb.set)

        # ----- справа: детали выбранного профиля
        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))
        ttk.Label(right, text="Детали отпечатка").pack(anchor="w")
        self.details = tk.Text(right, wrap="word", height=10, state="disabled",
                               font=("Menlo", 10) if sys.platform == "darwin"
                               else ("Consolas", 9))
        self.details.pack(fill="both", expand=True, pady=(4, 0))

        # ----- кнопки
        btns = ttk.Frame(outer)
        btns.pack(fill="x")
        ttk.Button(btns, text="Создать профиль", command=self.create_dialog
                   ).pack(side="left")
        self.launch_btn = ttk.Button(btns, text="Запустить", command=self.launch)
        self.launch_btn.pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Стоп", command=self.stop_selected
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Запустить все", command=self.launch_all
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Остановить все", command=self.stop_all
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Очистить зависшие", command=self.kill_strays
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Сменить прокси", command=self.change_proxy_dialog
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Удалить", command=self.delete
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Обновить", command=self.refresh
                   ).pack(side="left", padx=(8, 0))

    def _build_proxies_tab(self, outer: ttk.Frame) -> None:
        ttk.Label(outer, text="Пул прокси", font=("", 12, "bold")).pack(anchor="w")
        ttk.Label(outer, foreground="#666",
                  text="Сохранённые прокси можно выбирать при создании профиля "
                       "и при смене прокси.").pack(anchor="w", pady=(0, 6))

        body = ttk.Frame(outer)
        body.pack(fill="both", expand=True)

        self.proxy_listbox = tk.Listbox(body, activestyle="dotbox",
                                        exportselection=False)
        self.proxy_listbox.pack(side="left", fill="both", expand=True)
        psb = ttk.Scrollbar(body, orient="vertical",
                            command=self.proxy_listbox.yview)
        psb.pack(side="left", fill="y")
        self.proxy_listbox.config(yscrollcommand=psb.set)

        # ----- форма добавления
        form = ttk.Frame(outer)
        form.pack(fill="x", pady=(8, 4))
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Метка").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.pool_label_var = tk.StringVar()
        label_entry = ttk.Entry(form, textvariable=self.pool_label_var, width=20)
        label_entry.grid(row=0, column=1, sticky="w", pady=(0, 4))
        attach_context_menu(label_entry)

        ttk.Label(form, text="Прокси").grid(row=1, column=0, sticky="w", padx=(0, 6))
        self.pool_raw_var = tk.StringVar()
        e = ttk.Entry(form, textvariable=self.pool_raw_var)
        e.grid(row=1, column=1, sticky="we")
        e.bind("<Return>", lambda ev: self.add_pool_proxy())
        attach_context_menu(e)
        ttk.Label(form, foreground="#666",
                  text="http://user:pass@host:port  |  socks5://host:port  |  host:port:user:pass"
                  ).grid(row=2, column=1, sticky="w", pady=(2, 0))

        btns = ttk.Frame(outer)
        btns.pack(fill="x", pady=(4, 0))
        ttk.Button(btns, text="Добавить в пул", command=self.add_pool_proxy
                   ).pack(side="left")
        ttk.Button(btns, text="Удалить из пула", command=self.remove_pool_proxy
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Обновить гео", command=self.update_pool_geo
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Проверить прокси", command=self.check_selected_proxy
                   ).pack(side="left", padx=(8, 0))

    # ----------------------------------------------------------- helpers
    def _set_status(self, text: str) -> None:
        self.status.set(text)

    def selected_name(self) -> str | None:
        sel = self.listbox.curselection()
        if not sel:
            return None
        # убираем маркер «● » статуса запуска
        return self.listbox.get(sel[0]).lstrip("● ").strip()

    def refresh(self) -> None:
        keep = self.selected_name()
        self.listbox.delete(0, "end")
        for name in list_profiles():
            mark = "● " if name in self.running else "   "
            self.listbox.insert("end", f"{mark}{name}")
        # восстановить выделение
        if keep:
            for i in range(self.listbox.size()):
                if self.listbox.get(i).lstrip("● ").strip() == keep:
                    self.listbox.selection_set(i)
                    break
        self._show_details()

    def _show_details(self) -> None:
        name = self.selected_name()
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        if name:
            path = os.path.join(PROFILES_DIR, name, "profile.json")
            try:
                with open(path, encoding="utf-8") as f:
                    d = json.load(f)
                self.details.insert("end", self._format_details(d, name))
            except Exception as e:  # noqa: BLE001
                self.details.insert("end", f"Не удалось прочитать профиль: {e}")
        self.details.config(state="disabled")

    @staticmethod
    def _format_details(d: dict, name: str) -> str:
        fp = d.get("fingerprint", {})
        geo = d.get("geo", {})
        px = d.get("proxy")
        lines = [
            f"Профиль:   {name}",
            f"UA:        {fp.get('user_agent', '?')}",
            f"ОС (CH):   {fp.get('ch_platform')} {fp.get('ch_platform_version')}",
            f"Экран:     {fp.get('screen_w')}x{fp.get('screen_h')}"
            f"  окно {fp.get('window_w')}x{fp.get('window_h')}",
            f"WebGL:     {fp.get('webgl_renderer')}",
            f"CPU/RAM:   {fp.get('hardware_concurrency')} ядер / "
            f"{fp.get('device_memory')} ГБ",
            f"Гео:       {_geo_label(geo)} | tz={geo.get('timezone_id')} | "
            f"{geo.get('locale')}",
        ]
        if px:
            auth = " (с авторизацией)" if px.get("username") else ""
            lines.append(f"Прокси:    {px.get('scheme')}://{px.get('host')}:"
                         f"{px.get('port')}{auth}")
        else:
            lines.append("Прокси:    нет")
        return "\n".join(lines)

    # --------------------------------------------------- proxy pool tab
    def refresh_pool(self) -> None:
        self.proxy_listbox.delete(0, "end")
        for p in load_pool():
            self.proxy_listbox.insert("end", p.display())

    def add_pool_proxy(self) -> None:
        raw = self.pool_raw_var.get().strip()
        if not raw:
            messagebox.showinfo("Пул прокси", "Введите строку прокси.")
            return
        label = self.pool_label_var.get()
        self._set_status("Добавляю прокси (определяю страну/город по IP)...")

        def work() -> None:
            err = None
            try:
                add_proxy(raw, label)  # тут сетевой запрос через прокси
            except Exception as e:  # noqa: BLE001
                err = e
            self.root.after(0, lambda: done(err))

        def done(err) -> None:
            if err:
                messagebox.showerror("Пул прокси", str(err))
                self._set_status("Готово.")
                return
            self.pool_raw_var.set("")
            self.pool_label_var.set("")
            self._set_status("Прокси добавлен в пул.")
            self.refresh_pool()

        threading.Thread(target=work, daemon=True).start()

    def check_selected_proxy(self) -> None:
        sel = self.proxy_listbox.curselection()
        if not sel:
            messagebox.showinfo("Проверка прокси", "Выберите прокси в списке.")
            return
        pool = load_pool()
        idx = sel[0]
        if not (0 <= idx < len(pool)):
            return
        item = pool[idx]
        self._set_status(f"Проверяю прокси {item.display()} ...")

        def work() -> None:
            res = check_proxy(item.raw)
            self.root.after(0, lambda: done(res))

        def done(res: dict) -> None:
            if not res["reachable"]:
                self._set_status("Прокси не отвечает.")
                messagebox.showerror(
                    "Проверка прокси",
                    f"Прокси НЕ отвечает ({res.get('error') or 'таймаут'}).\n"
                    "Сайты грузиться не будут.")
                return
            google = ("✓ открывается" if res["google"]
                      else "✗ НЕ открывается (режет провайдер прокси)")
            self._set_status(f"Прокси OK · гео {res['geo']} · Google "
                             f"{'ok' if res['google'] else 'нет'}.")
            messagebox.showinfo(
                "Проверка прокси",
                f"Прокси РАБОТАЕТ.\n\n"
                f"Гео (по факту):  {res['geo']}\n"
                f"Обычные сайты:   ✓ грузятся\n"
                f"Google:          {google}")

        threading.Thread(target=work, daemon=True).start()

    def update_pool_geo(self) -> None:
        pool = load_pool()
        if not pool:
            messagebox.showinfo("Пул прокси", "Пул пуст — добавьте прокси.")
            return
        self._set_status(f"Определяю гео для {len(pool)} прокси...")

        def progress(done: int, total: int) -> None:
            self.root.after(0, lambda: self._set_status(
                f"Определяю гео: {done}/{total}..."))

        def work() -> None:
            err = None
            n = 0
            try:
                n = refresh_pool_geo(progress=progress)
            except Exception as e:  # noqa: BLE001
                err = e
            self.root.after(0, lambda: done(err, n))

        def done(err, n) -> None:
            if err:
                messagebox.showerror("Пул прокси", str(err))
                self._set_status("Готово.")
                return
            self._set_status(f"Гео определено у {n} из {len(pool)} прокси.")
            self.refresh_pool()

        threading.Thread(target=work, daemon=True).start()

    def remove_pool_proxy(self) -> None:
        sel = self.proxy_listbox.curselection()
        if not sel:
            messagebox.showinfo("Пул прокси", "Выберите прокси в списке.")
            return
        pool = load_pool()
        idx = sel[0]
        if not (0 <= idx < len(pool)):
            return
        item = pool[idx]
        if not messagebox.askyesno("Пул прокси",
                                   f"Удалить из пула «{item.display()}»?\n"
                                   "(на уже созданные профили это не влияет)"):
            return
        remove_proxy(item.raw)
        self._set_status("Прокси удалён из пула.")
        self.refresh_pool()

    # ------------------------------------------------------------ actions
    def _spawn(self, name: str) -> bool:
        """
        Запустить ОДИН профиль отдельным процессом. Вывод процесса пишется в
        profiles/<name>/last_run.log (а не в общую консоль) — иначе при 50
        профилях это и спам, и риск зависания на заполненном буфере stdout.
        """
        if name in self.running:
            return False
        log_path = os.path.join(PROFILES_DIR, name, "last_run.log")
        try:
            logf: object = open(log_path, "w", encoding="utf-8")
        except Exception:  # noqa: BLE001
            logf = subprocess.DEVNULL
        try:
            proc = subprocess.Popen(
                [sys.executable, os.path.join(HERE, "browser.py"), name],
                cwd=HERE,
                stdout=logf, stderr=subprocess.STDOUT,
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception as e:  # noqa: BLE001
            if logf is not subprocess.DEVNULL:
                try:
                    logf.close()  # type: ignore[union-attr]
                except Exception:  # noqa: BLE001
                    pass
            messagebox.showerror("Запуск", f"Не удалось запустить «{name}»: {e}")
            return False
        self.running[name] = _Session(proc.pid, popen=proc, logf=logf)
        return True

    def _drop_session(self, name: str) -> None:
        """Убрать профиль из списка запущенных + закрыть лог + стереть PID-файл."""
        sess = self.running.pop(name, None)
        if sess is not None and sess.logf is not None \
                and sess.logf is not subprocess.DEVNULL:
            try:
                sess.logf.close()  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                pass
        _remove_pid_file(name)

    def launch(self) -> None:
        name = self.selected_name()
        if not name:
            messagebox.showinfo("Запуск", "Выберите профиль в списке.")
            return
        if name in self.running:
            sess = self.running[name]
            if sess.alive(_alive_pids()):  # процесс действительно жив
                if not messagebox.askyesno(
                        "Запуск",
                        f"Профиль «{name}» уже запущен (возможно, осиротевший "
                        "процесс от прошлого сеанса).\n\n"
                        "Принудительно завершить его и запустить заново?"):
                    return
                _kill_tree(sess.pid)
            self._drop_session(name)
        if self._spawn(name):
            self._set_status(f"Запущен «{name}». Лог: profiles/{name}/last_run.log")
            self.refresh()

    def launch_all(self) -> None:
        pending = [n for n in list_profiles() if n not in self.running]
        if not pending:
            messagebox.showinfo("Запустить все",
                                "Все профили уже запущены (или их нет).")
            return
        if not messagebox.askyesno(
                "Запустить все",
                f"Запустить {len(pending)} профилей?\n\n"
                f"Это тяжёлая нагрузка: {len(pending)} окон браузера "
                f"(ориентир ~0.3–0.5 ГБ ОЗУ на профиль). Запуск идёт постепенно, "
                "чтобы не было пика."):
            return
        self._stagger_launch(pending, 0)

    def _stagger_launch(self, names: list[str], idx: int) -> None:
        """Запуск пачкой, по одному раз в ~0.8с — без пика CPU/диска на старте."""
        if idx >= len(names):
            self._set_status(f"Запущено профилей: {len(self.running)}.")
            self.refresh()
            return
        name = names[idx]
        if name not in self.running:
            self._spawn(name)
        self._set_status(f"Запуск {idx + 1}/{len(names)}: «{name}» "
                         f"(всего активно: {len(self.running)})")
        self.refresh()
        self.root.after(800, lambda: self._stagger_launch(names, idx + 1))

    def stop_all(self) -> None:
        if not self.running:
            messagebox.showinfo("Остановить все", "Нет запущенных профилей.")
            return
        if not messagebox.askyesno(
                "Остановить все",
                f"Закрыть все {len(self.running)} запущенных браузеров?"):
            return
        for name, sess in list(self.running.items()):
            _kill_tree(sess.pid)
            self._drop_session(name)
        self._set_status("Все профили остановлены.")
        self.refresh()

    def stop_selected(self) -> None:
        name = self.selected_name()
        if not name or name not in self.running:
            messagebox.showinfo("Остановить", "Выберите запущенный профиль.")
            return
        _kill_tree(self.running[name].pid)
        self._drop_session(name)
        self._set_status(f"Профиль «{name}» остановлен.")
        self.refresh()

    def delete(self) -> None:
        name = self.selected_name()
        if not name:
            return
        if name in self.running:
            # профиль (возможно, сирота) запущен — предлагаем принудительно закрыть,
            # иначе его файлы залочены и удалить нельзя.
            if not messagebox.askyesno(
                    "Удаление",
                    f"Профиль «{name}» сейчас запущен. Принудительно завершить "
                    "его процесс и удалить?"):
                return
            _kill_tree(self.running[name].pid)
            self._drop_session(name)
        if not messagebox.askyesno(
                "Удаление",
                f"Удалить профиль «{name}» вместе со всеми его данными\n"
                f"(cookies, localStorage и т.д.)? Действие необратимо."):
            return
        path = os.path.join(PROFILES_DIR, name)
        self._set_status(f"Удаляю «{name}» (жду освобождения файлов браузером)...")

        def work() -> None:
            err = None
            try:
                _force_rmtree(path)  # ретраит, пока Chromium не отпустит файлы
            except Exception as e:  # noqa: BLE001
                err = e
            self.root.after(0, lambda: done(err))

        def done(err) -> None:
            if err:
                messagebox.showerror(
                    "Удаление",
                    f"Не удалось удалить «{name}»:\n{err}\n\n"
                    "Если окно браузера ещё открыто — закройте его и повторите.")
                self._set_status("Готово.")
                return
            self._set_status(f"Профиль «{name}» удалён.")
            self.refresh()

        threading.Thread(target=work, daemon=True).start()

    def create_dialog(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Новый профиль")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)

        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(0, weight=1)

        ttk.Label(frm, text="Имя профиля").grid(row=0, column=0, sticky="w")
        name_var = tk.StringVar()
        name_entry = ttk.Entry(frm, textvariable=name_var, width=48)
        name_entry.grid(row=1, column=0, pady=(2, 10), sticky="we")
        attach_context_menu(name_entry)

        ttk.Label(frm, text="Прокси (необязательно)").grid(row=2, column=0, sticky="w")
        picker = ProxyPicker(frm, row=3)  # занимает строки 3..6

        bar = ttk.Frame(frm)
        bar.grid(row=7, column=0, sticky="e", pady=(12, 0))
        ok_btn = ttk.Button(bar, text="Создать")
        ok_btn.pack(side="right")
        ttk.Button(bar, text="Отмена", command=win.destroy).pack(
            side="right", padx=(0, 8))

        def submit() -> None:
            name = name_var.get().strip()
            if not name:
                messagebox.showinfo("Новый профиль", "Введите имя.", parent=win)
                return
            proxy = picker.raw()
            ok_btn.config(state="disabled")
            self._set_status(f"Создаю «{name}» (определяю гео по прокси)...")

            def work() -> None:
                err = None
                try:
                    create_profile(name, proxy)
                except Exception as e:  # noqa: BLE001
                    err = e
                self.root.after(0, lambda: done(err))

            def done(err) -> None:
                if err:
                    messagebox.showerror("Новый профиль", str(err), parent=win)
                    ok_btn.config(state="normal")
                    self._set_status("Готово.")
                    return
                self._set_status(f"Профиль «{name}» создан.")
                win.destroy()
                self.refresh()

            threading.Thread(target=work, daemon=True).start()

        ok_btn.config(command=submit)
        name_entry.focus_set()
        win.bind("<Return>", lambda e: submit())

    def change_proxy_dialog(self) -> None:
        name = self.selected_name()
        if not name:
            messagebox.showinfo("Смена прокси", "Выберите профиль в списке.")
            return
        if name in self.running:
            messagebox.showwarning(
                "Смена прокси",
                f"Сначала закройте браузер профиля «{name}» — "
                "новый прокси применится при следующем запуске.")
            return

        win = tk.Toplevel(self.root)
        win.title(f"Прокси профиля «{name}»")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)

        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)
        frm.columnconfigure(0, weight=1)

        ttk.Label(frm, text=f"Новый прокси для «{name}»").grid(
            row=0, column=0, sticky="w")
        ttk.Label(frm, foreground="#666",
                  text="Гео (таймзона/язык) будет пере-определено по новому IP. "
                       "Отпечаток не меняется.").grid(row=1, column=0, sticky="w",
                                                      pady=(0, 8))
        picker = ProxyPicker(frm, row=2)  # строки 2..5

        bar = ttk.Frame(frm)
        bar.grid(row=6, column=0, sticky="e", pady=(12, 0))
        ok_btn = ttk.Button(bar, text="Применить")
        ok_btn.pack(side="right")
        ttk.Button(bar, text="Отмена", command=win.destroy).pack(
            side="right", padx=(0, 8))

        def submit() -> None:
            proxy = picker.raw()
            ok_btn.config(state="disabled")
            self._set_status(f"Меняю прокси «{name}» (определяю гео)...")

            def work() -> None:
                err = None
                try:
                    set_profile_proxy(name, proxy)
                except Exception as e:  # noqa: BLE001
                    err = e
                self.root.after(0, lambda: done(err))

            def done(err) -> None:
                if err:
                    messagebox.showerror("Смена прокси", str(err), parent=win)
                    ok_btn.config(state="normal")
                    self._set_status("Готово.")
                    return
                self._set_status(f"Прокси профиля «{name}» обновлён.")
                win.destroy()
                self.refresh()

            threading.Thread(target=work, daemon=True).start()

        ok_btn.config(command=submit)
        win.bind("<Return>", lambda e: submit())

    # --------------------------------------------------- background poll
    def _poll_processes(self) -> None:
        """Снять статус «запущен» с профилей, чьи браузеры закрыли."""
        # один вызов tasklist на цикл, если есть подхваченные сироты (без Popen)
        alive = _alive_pids() if any(
            s.popen is None for s in self.running.values()) else None
        finished = [n for n, s in self.running.items() if not s.alive(alive)]
        for n in finished:
            self._drop_session(n)
        if finished:
            self._set_status(f"Сессия завершена: {', '.join(finished[:5])}"
                             f"{' …' if len(finished) > 5 else ''}.")
            self.refresh()
        self.root.title(f"Anti-detect QA browser — активно: {len(self.running)}")
        self.root.after(1000, self._poll_processes)


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
