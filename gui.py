#!/usr/bin/env python3
"""
Графический интерфейс (Tkinter) для менеджера профилей.

Запуск:  python gui.py

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
import subprocess
import sys
import threading

import tkinter as tk
from tkinter import ttk, messagebox

from profile import list_profiles, create_profile, PROFILES_DIR

HERE = os.path.dirname(os.path.abspath(__file__))


class App:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.running: dict[str, subprocess.Popen] = {}  # имя -> процесс браузера

        root.title("Anti-detect QA browser")
        root.geometry("760x460")
        root.minsize(640, 400)

        self._build_ui()
        self.refresh()
        self._poll_processes()

    # ---------------------------------------------------------------- UI
    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

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
        ttk.Button(btns, text="Удалить", command=self.delete
                   ).pack(side="left", padx=(8, 0))
        ttk.Button(btns, text="Обновить", command=self.refresh
                   ).pack(side="left", padx=(8, 0))

        # ----- статус-строка
        self.status = tk.StringVar(value="Готово.")
        ttk.Label(outer, textvariable=self.status, relief="sunken", anchor="w",
                  padding=(6, 3)).pack(fill="x", pady=(8, 0))

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
            f"Гео:       {geo.get('country')} | tz={geo.get('timezone_id')} | "
            f"{geo.get('locale')}",
        ]
        if px:
            auth = " (с авторизацией)" if px.get("username") else ""
            lines.append(f"Прокси:    {px.get('scheme')}://{px.get('host')}:"
                         f"{px.get('port')}{auth}")
        else:
            lines.append("Прокси:    нет")
        return "\n".join(lines)

    # ------------------------------------------------------------ actions
    def launch(self) -> None:
        name = self.selected_name()
        if not name:
            messagebox.showinfo("Запуск", "Выберите профиль в списке.")
            return
        if name in self.running:
            messagebox.showinfo("Запуск", f"Профиль «{name}» уже запущен.")
            return
        try:
            proc = subprocess.Popen(
                [sys.executable, os.path.join(HERE, "browser.py"), name],
                cwd=HERE,
            )
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Запуск", f"Не удалось запустить: {e}")
            return
        self.running[name] = proc
        self._set_status(f"Запущен «{name}». Закройте окно браузера для завершения.")
        self.refresh()

    def delete(self) -> None:
        name = self.selected_name()
        if not name:
            return
        if name in self.running:
            messagebox.showwarning("Удаление",
                                   f"Сначала закройте браузер профиля «{name}».")
            return
        if not messagebox.askyesno(
                "Удаление",
                f"Удалить профиль «{name}» вместе со всеми его данными\n"
                f"(cookies, localStorage и т.д.)? Действие необратимо."):
            return
        try:
            shutil.rmtree(os.path.join(PROFILES_DIR, name))
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Удаление", f"Не удалось удалить: {e}")
            return
        self._set_status(f"Профиль «{name}» удалён.")
        self.refresh()

    def create_dialog(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Новый профиль")
        win.transient(self.root)
        win.grab_set()
        win.resizable(False, False)

        frm = ttk.Frame(win, padding=14)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Имя профиля").grid(row=0, column=0, sticky="w")
        name_var = tk.StringVar()
        ttk.Entry(frm, textvariable=name_var, width=42).grid(
            row=1, column=0, pady=(2, 10), sticky="we")

        ttk.Label(frm, text="Прокси (необязательно)").grid(row=2, column=0, sticky="w")
        proxy_var = tk.StringVar()
        ttk.Entry(frm, textvariable=proxy_var, width=42).grid(
            row=3, column=0, pady=(2, 2), sticky="we")
        ttk.Label(frm, foreground="#666",
                  text="http://user:pass@host:port  |  socks5://host:port  |  host:port:user:pass"
                  ).grid(row=4, column=0, sticky="w", pady=(0, 10))

        bar = ttk.Frame(frm)
        bar.grid(row=5, column=0, sticky="e")
        ok_btn = ttk.Button(bar, text="Создать")
        ok_btn.pack(side="right")
        ttk.Button(bar, text="Отмена", command=win.destroy).pack(
            side="right", padx=(0, 8))

        def submit() -> None:
            name = name_var.get().strip()
            proxy = proxy_var.get().strip()
            if not name:
                messagebox.showinfo("Новый профиль", "Введите имя.", parent=win)
                return
            ok_btn.config(state="disabled")
            self._set_status(f"Создаю «{name}» (определяю гео по прокси)...")

            def work() -> None:
                err = None
                try:
                    create_profile(name, proxy or None)
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
        name_var.set("")
        win.bind("<Return>", lambda e: submit())

    # --------------------------------------------------- background poll
    def _poll_processes(self) -> None:
        """Снять статус «запущен» с профилей, чьи браузеры закрыли."""
        finished = [n for n, p in self.running.items() if p.poll() is not None]
        for n in finished:
            self.running.pop(n, None)
        if finished:
            self._set_status(f"Сессия завершена: {', '.join(finished)}.")
            self.refresh()
        self.root.after(1000, self._poll_processes)


def main() -> None:
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
