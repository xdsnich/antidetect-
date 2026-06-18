"""
Запуск профиля в видимом (non-headless) Chromium с применением всех подмен.

Слои защиты (от прочного к косметическому):
  1. persistent context на отдельном userdata/  -> изоляция cookies/LS/IndexedDB.
  2. proxy на уровне контекста                   -> весь трафик через прокси.
  3. флаг WebRTC IP handling                      -> не отдавать UDP мимо прокси.
  4. CDP setUserAgentOverride                     -> UA + Client Hints согласованы.
  5. add_init_script (наш)                        -> Canvas/WebGL/WebRTC/navigator.
  6. playwright-stealth (если есть)               -> мелкие automation-tells.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Optional

from playwright.sync_api import sync_playwright

from profile import Profile
from stealth_scripts import build_init_script


_ENGINE_VERSION_CACHE: Optional[str] = None


def _real_engine_version() -> Optional[str]:
    """
    Реальная версия движка Playwright-Chromium ('148.0.7778.96').

    Нужна ДО запуска: context-level user_agent у Playwright перекрывает CDP-оверрайд,
    поэтому версию надо подставить в UA ещё до создания контекста. Делаем быстрый
    headless-запуск, читаем browser.version, кэшируем (в процессе и в файл, чтобы
    при 50 профилях не перезапускать движок ради версии каждый раз).
    """
    global _ENGINE_VERSION_CACHE
    if _ENGINE_VERSION_CACHE:
        return _ENGINE_VERSION_CACHE

    from profile import DATA_DIR
    cache_file = os.path.join(DATA_DIR, "engine_version.txt")
    try:
        if os.path.isfile(cache_file):
            v = open(cache_file, encoding="utf-8").read().strip()
            if re.match(r"^\d+\.", v):
                _ENGINE_VERSION_CACHE = v
                return v
    except Exception:  # noqa: BLE001
        pass

    try:
        with sync_playwright() as p:
            b = p.chromium.launch(headless=True)
            v = b.version           # напр. '148.0.7778.96'
            b.close()
    except Exception as e:  # noqa: BLE001
        print(f"[ua] не удалось определить версию движка: {e}")
        return None

    _ENGINE_VERSION_CACHE = v
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(cache_file, "w", encoding="utf-8") as f:
            f.write(v)
    except Exception:  # noqa: BLE001
        pass
    return v


def _match_engine_version(fp, real_full: str) -> None:
    """
    Подогнать заявленную версию Chrome под РЕАЛЬНЫЙ движок (на месте).

    Иначе UA говорит «Chrome 150», а движок — 148: и фичи могут не совпасть
    (белый экран на SPA вроде Telegram), и это прямое палево для антидетекта.
    Меняем только номер версии, платформа/хвост остаются от отпечатка.
    """
    old = fp.chrome_full_version
    if not real_full or real_full == old:
        return
    fp.user_agent = fp.user_agent.replace(old, real_full)
    fp.chrome_full_version = real_full
    fp.chrome_major = real_full.split(".")[0]


def _make_playwright_cm():
    """Вернуть (context_manager, stealth_on). Падение stealth не ломает запуск."""
    pw_cm = sync_playwright()
    try:
        from playwright_stealth import Stealth  # v2+ API
        s = Stealth()
        if hasattr(s, "use_sync"):
            return s.use_sync(pw_cm), True
        print("[stealth] версия без use_sync — продолжаю на своих init-скриптах")
    except Exception as e:  # noqa: BLE001
        print(f"[stealth] недоступен ({e}) — продолжаю на своих init-скриптах")
    return pw_cm, False


def _chrome_args(profile: Profile) -> list[str]:
    fp = profile.fingerprint
    geo = profile.geo
    # Язык интерфейса Chromium (новая вкладка, плейсхолдеры, страница Google) и
    # Accept-Language — по локали из гео прокси, а НЕ по языку ОС. Иначе UI берёт
    # язык системы (украинский), и получается рассинхрон с IP/выдачей — и неудобно,
    # и это тель для антифрода (IP NL, а интерфейс UA).
    accept_lang = ",".join(geo.languages) if geo.languages else geo.locale
    args = [
        f"--window-size={fp.window_w},{fp.window_h}",
        "--window-position=0,0",
        f"--lang={geo.locale}",
        f"--accept-lang={accept_lang}",
        # WebRTC: запретить UDP в обход прокси -> реальный IP не утечёт.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        # убрать самый дешёвый automation-флаг
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        # ВАЖНО: site-per-process НЕ отключаем — изоляция сайтов по процессам
        # держит тяжёлую/зависшую вкладку отдельно, иначе её фриз вешает все вкладки.
        # Стабильность под нагрузкой (YouTube и пр.):
        "--disable-dev-shm-usage",      # не упираться в маленький shm -> вкладки не виснут
        "--dns-prefetch-disable",       # не резолвить домены локально мимо прокси
    ]
    if profile.proxy:
        # QUIC — это UDP, в HTTP-прокси (тем более в локальный релей) он не идёт,
        # Chrome зря тратит время на попытки. Реальный Chrome за HTTP-прокси QUIC
        # тоже не использует, так что для фингерпринта это естественно.
        # HTTP/2 НЕ трогаем — релей (ниже) делает авторизацию прозрачной, и h2
        # работает как у настоящего Chrome.
        args += ["--disable-quic"]
    return args


def _start_dashboard_html(profile: Profile) -> str:
    """
    Лёгкая стартовая страница: грузится мгновенно (без внешних зависимостей),
    показывает ожидаемое гео профиля и подтягивает РЕАЛЬНЫЙ exit-IP по JS.
    Так сразу видно, что прокси работает, и не приходится ждать тяжёлый creepjs.
    """
    fp, geo = profile.fingerprint, profile.geo
    px = profile.proxy
    proxy_line = (f"{px.scheme}://{px.host}:{px.port}"
                  f"{' (auth)' if px and px.username else ''}") if px else "без прокси"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>{profile.name} — профиль</title>
<style>
  body{{font:14px/1.5 system-ui,Segoe UI,Arial;background:#0f1115;color:#e6e6e6;margin:0;padding:32px}}
  .card{{max-width:680px;margin:0 auto;background:#171a21;border:1px solid #262b36;border-radius:12px;padding:24px}}
  h1{{font-size:18px;margin:0 0 4px}} .sub{{color:#8b94a3;margin:0 0 18px}}
  table{{width:100%;border-collapse:collapse}} td{{padding:6px 0;border-bottom:1px solid #222631;vertical-align:top}}
  td.k{{color:#8b94a3;width:160px}} .big{{font-size:20px;font-weight:600}}
  .ok{{color:#46d369}} .bad{{color:#ff6b6b}} .muted{{color:#8b94a3}}
  .btns{{margin-top:20px;display:flex;gap:10px;flex-wrap:wrap}}
  a.btn{{display:inline-block;padding:9px 14px;background:#2563eb;color:#fff;border-radius:8px;text-decoration:none}}
  a.btn.alt{{background:#2b3140}}
</style></head><body><div class="card">
  <h1>Профиль «{profile.name}»</h1>
  <p class="sub">Ожидаемое гео по прокси — ниже. Справа подтянется реальный exit-IP.</p>
  <table>
    <tr><td class="k">Прокси</td><td>{proxy_line}</td></tr>
    <tr><td class="k">Ожидается страна</td><td class="big">{geo.country or '?'} {('· ' + geo.city) if geo.city else ''}</td></tr>
    <tr><td class="k">Часовой пояс</td><td>{geo.timezone_id} · {geo.locale}</td></tr>
    <tr><td class="k">Chrome</td><td>{fp.chrome_full_version} · {fp.ch_platform}</td></tr>
    <tr><td class="k">Реальный exit-IP</td><td id="ip" class="muted">проверяю…</td></tr>
    <tr><td class="k">Реальная страна</td><td id="loc" class="muted">проверяю…</td></tr>
  </table>
  <div class="btns">
    <a class="btn" href="https://abrahamjuliot.github.io/creepjs/">CreepJS (отпечаток)</a>
    <a class="btn alt" href="https://browserleaks.com/ip">BrowserLeaks IP</a>
    <a class="btn alt" href="https://iphey.com/">iphey</a>
    <a class="btn alt" href="https://www.google.com">Google</a>
  </div>
  <p class="muted" style="margin-top:14px">Если реальная страна совпала с ожидаемой — прокси работает.
  Если какой-то сайт не грузится — этот сайт режет провайдер прокси (например, Google).</p>
</div>
<script>
(async () => {{
  const expected = {geo.country!r};
  try {{
    const r = await fetch('https://ipwho.is/', {{cache:'no-store'}});
    const d = await r.json();
    document.getElementById('ip').textContent = d.ip || '—';
    document.getElementById('ip').className = '';
    const cc = d.country_code || '', city = d.city || '';
    const el = document.getElementById('loc');
    el.textContent = (d.country || cc || '—') + (city ? ' · ' + city : '');
    el.className = (cc && expected && cc === expected) ? 'ok' : (cc ? 'bad' : 'muted');
  }} catch (e) {{
    document.getElementById('ip').textContent = 'не удалось проверить (сеть/прокси)';
    document.getElementById('loc').textContent = '—';
  }}
}})();
</script></body></html>"""


def _apply_cdp_ua(context, page, profile: Profile) -> None:
    """Согласовать UA-строку и Client Hints через CDP (надёжнее заголовков)."""
    fp = profile.fingerprint
    client = None
    try:
        client = context.new_cdp_session(page)
        client.send("Network.setUserAgentOverride", {
            "userAgent": fp.user_agent,
            "acceptLanguage": profile.geo.accept_language,
            "platform": fp.nav_platform,
            "userAgentMetadata": {
                "brands": fp.ch_brands(),
                "fullVersionList": fp.ch_full_version_list(),
                "fullVersion": fp.chrome_full_version,
                "platform": fp.ch_platform,
                "platformVersion": fp.ch_platform_version,
                "architecture": "x86",
                "bitness": "64",
                "model": "",
                "mobile": False,
                "wow64": False,
            },
        })
    except Exception as e:  # noqa: BLE001
        print(f"[cdp] не удалось применить UA-override: {e}")
    finally:
        # ВАЖНО: отцепляем CDP-сессию. Иначе на каждую вкладку висит открытая
        # сессия, копящая события (особенно от тяжёлых страниц вроде YouTube) —
        # это утечка и потенциальный «затык» обработки.
        if client is not None:
            try:
                client.detach()
            except Exception:  # noqa: BLE001
                pass


def _make_proxy_extension(profile: Profile) -> str:
    """
    Сгенерировать мини-расширение (MV3), которое отдаёт логин/пароль прокси через
    chrome.webRequest.onAuthRequired. Так Chromium работает с прокси НАТИВНО
    (родной пул соединений, как Dolphin), а не через локальный релей-посредник.
    """
    px = profile.proxy
    ext_dir = os.path.join(profile.dir, "proxy_ext")
    os.makedirs(ext_dir, exist_ok=True)
    manifest = {
        "manifest_version": 3,
        "name": "proxy-auth",
        "version": "1.0",
        "permissions": ["proxy", "webRequest", "webRequestAuthProvider"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "bg.js"},
    }
    with open(os.path.join(ext_dir, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f)
    user = json.dumps(px.username or "")
    pwd = json.dumps(px.password or "")
    bg = ("chrome.webRequest.onAuthRequired.addListener("
          "function(d){return d.isProxy?{authCredentials:{username:%s,password:%s}}:{};},"
          "{urls:[\"<all_urls>\"]},[\"blocking\"]);" % (user, pwd))
    with open(os.path.join(ext_dir, "bg.js"), "w", encoding="utf-8") as f:
        f.write(bg)
    return ext_dir


def _setup_proxy(profile: Profile):
    """
    Вернуть (proxy_setting_для_playwright, доп_аргументы_chrome).

    HTTP/HTTPS-прокси С АВТОРИЗАЦИЕЙ -> НАТИВНО: флаг --proxy-server + мини-
    расширение для авторизации (как настоящие антидетекты). Без релея-посредника,
    Chromium сам пулит соединения к прокси — это устраняет зависания «новых=0».
    Прокси без пароля -> тоже --proxy-server. SOCKS с паролем -> предупреждение.
    """
    px = profile.proxy
    if not px:
        return None, []

    if px.scheme in ("http", "https"):
        args = [f"--proxy-server=http://{px.host}:{px.port}"]
        if px.username:
            ext = _make_proxy_extension(profile)
            args += [f"--load-extension={ext}", f"--disable-extensions-except={ext}"]
            print(f"[proxy] нативно: --proxy-server -> {px.host}:{px.port} "
                  f"+ расширение авторизации (как Dolphin)")
        else:
            print(f"[proxy] нативно: --proxy-server -> {px.host}:{px.port}")
        return None, args

    if px.is_authed_socks():
        print("[!] SOCKS5 с авторизацией Chromium не умеет — используйте HTTP-прокси.")
    return px.playwright_proxy(), []


def _pid_file(profile: Profile) -> str:
    return os.path.join(profile.dir, "running.pid")


def launch_profile(profile: Profile) -> None:
    fp = profile.fingerprint
    geo = profile.geo

    # PID-файл: по нему GUI узнаёт о процессе ДАЖE после своего перезапуска
    # (иначе процессы-сироты живут вечно и «Остановить все» их не видит).
    try:
        with open(_pid_file(profile), "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except OSError:
        pass

    # Подгоняем заявленную версию Chrome под РЕАЛЬНЫЙ движок ДО запуска контекста.
    # Иначе UA «150», а движок 148 -> несовпадение фич (белый экран на Telegram и
    # пр.) и палево. context.user_agent перекрывает CDP, поэтому правим заранее.
    real = _real_engine_version()
    if real and real != fp.chrome_full_version:
        print(f"[ua] версия под движок: {fp.chrome_full_version} -> {real}")
        _match_engine_version(fp, real)

    cm, stealth_on = _make_playwright_cm()
    print(f"[*] Запуск {profile.name!r} | stealth={'on' if stealth_on else 'off'} | "
          f"UA Chrome {fp.chrome_major} | {fp.screen_w}x{fp.screen_h} | tz={geo.timezone_id}")

    proxy_setting, proxy_args = _setup_proxy(profile)

    launch_kwargs = dict(
        user_data_dir=profile.userdata_dir,   # <- изоляция состояния тут
        headless=False,
        args=_chrome_args(profile) + proxy_args,
        user_agent=fp.user_agent,
        locale=geo.locale,
        timezone_id=geo.timezone_id,
        no_viewport=True,                     # размер страницы = размер окна
        ignore_default_args=["--enable-automation"],
    )
    if proxy_setting:
        launch_kwargs["proxy"] = proxy_setting

    try:
        with cm as p:
            context = p.chromium.launch_persistent_context(**launch_kwargs)

            # persistent context обычно открывает одну стартовую вкладку.
            page = context.pages[0] if context.pages else context.new_page()

            # Наши подмены — ДО любого скрипта страницы (версия уже подогнана выше).
            context.add_init_script(build_init_script(fp, geo))

            # Диагностика: если оборвётся со стороны браузера — это попадёт в лог.
            def _log(msg: str) -> None:
                print(f"[browser {time.strftime('%H:%M:%S')}] {msg}", flush=True)

            context.on("close", lambda: _log("КОНТЕКСТ закрыт/отключён"))

            # Новым страницам тоже применяем CDP-оверрайд + ловим падения/сетевые сбои.
            def _on_req_failed(req):
                # ERR_ABORTED — это норма (отменённые beacon/ads при навигации),
                # логируем только осмысленные сетевые ошибки.
                err = req.failure or ""
                if err and "ERR_ABORTED" not in err:
                    _log(f"запрос НЕ удался: {err} {req.url[:70]}")

            def _on_page(page):
                _apply_cdp_ua(context, page, profile)
                page.on("crash", lambda: _log(f"СТРАНИЦА УПАЛА (crash): {page.url}"))
                page.on("close", lambda: _log("вкладка закрыта"))
                page.on("requestfailed", _on_req_failed)
            context.on("page", _on_page)

            # Стартовой вкладке (она уже открыта) навешиваем обработчики сами —
            # context.on("page") на неё не срабатывает.
            _apply_cdp_ua(context, page, profile)
            page.on("crash", lambda: _log(f"СТРАНИЦА УПАЛА (crash): {page.url}"))
            page.on("requestfailed", _on_req_failed)

            # Лёгкая стартовая панель: грузится мгновенно, показывает реальный exit-IP.
            # (Тяжёлый creepjs и пр. — кнопками на самой панели.)
            page.set_content(_start_dashboard_html(profile), wait_until="domcontentloaded")
            print("\n[ok] Браузер открыт. Работайте вручную в окне.")
            print("     На стартовой панели виден реальный exit-IP и кнопки проверки.")
            print("     Для проверки отпечатка: creepjs / browserleaks.com / iphey.com")
            print("     Закройте окно браузера, чтобы завершить сессию профиля.")
            _wait_until_closed(context)
            # Окно закрыто. Гарантируем выход процесса, даже если очистка Playwright
            # зависнет (иначе GUI продолжит считать профиль «запущенным»).
            _arm_exit_watchdog(8)
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
    finally:
        # Окно закрыто (или запуск упал) — НАВЕРНЯКА завершаем процесс и чистим за собой.
        # os._exit гарантирует, что не останется процесса-сироты, шлющего логи и
        # держащего файлы профиля. Это и был корень «крестик не выключает».
        try:
            os.remove(_pid_file(profile))
        except OSError:
            pass
        os._exit(0)


def _arm_exit_watchdog(seconds: float) -> None:
    """Подстраховка: жёстко завершить процесс через N сек после закрытия окна."""
    def boom() -> None:
        time.sleep(seconds)
        os._exit(0)
    threading.Thread(target=boom, daemon=True).start()


def _wait_until_closed(context) -> None:
    """Блокируемся, пока пользователь не закроет окно браузера."""
    closed = threading.Event()
    try:
        context.on("close", lambda: closed.set())
    except Exception:  # noqa: BLE001
        pass
    while True:
        # сперва ждём событие закрытия (не дёргая Playwright) — если окно закрыли,
        # выходим сразу, не рискуя зависнуть на вызове context.pages.
        if closed.wait(0.5):
            break
        try:
            if not context.pages:        # все вкладки/окно закрыты
                break
        except Exception:  # noqa: BLE001
            break


if __name__ == "__main__":
    # Режим отдельного процесса: python browser.py <имя_профиля>
    # Используется GUI, чтобы не блокировать интерфейс и держать несколько окон.
    import sys
    from profile import Profile

    if len(sys.argv) < 2:
        print("usage: python browser.py <profile_name>")
        sys.exit(1)
    launch_profile(Profile.load(sys.argv[1]))