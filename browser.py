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

import threading
import time
from typing import Optional

from playwright.sync_api import sync_playwright

from profile import Profile
from stealth_scripts import build_init_script


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
    args = [
        f"--window-size={fp.window_w},{fp.window_h}",
        "--window-position=0,0",
        # WebRTC: запретить UDP в обход прокси -> реальный IP не утечёт.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        # убрать самый дешёвый automation-флаг
        "--disable-blink-features=AutomationControlled",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=IsolateOrigins,site-per-process",
    ]
    return args


def _apply_cdp_ua(context, page, profile: Profile) -> None:
    """Согласовать UA-строку и Client Hints через CDP (надёжнее заголовков)."""
    fp = profile.fingerprint
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


def launch_profile(profile: Profile) -> None:
    fp = profile.fingerprint
    geo = profile.geo

    if profile.proxy and profile.proxy.is_authed_socks():
        print("[!] ВНИМАНИЕ: SOCKS5 c авторизацией Chromium не умеет. "
              "Браузер запустится, но прокси может не подключиться — "
              "поднимите локальный мост (см. README) и укажите его как http://127.0.0.1:PORT.")

    cm, stealth_on = _make_playwright_cm()
    print(f"[*] Запуск {profile.name!r} | stealth={'on' if stealth_on else 'off'} | "
          f"UA Chrome {fp.chrome_major} | {fp.screen_w}x{fp.screen_h} | tz={geo.timezone_id}")

    launch_kwargs = dict(
        user_data_dir=profile.userdata_dir,   # <- изоляция состояния тут
        headless=False,
        args=_chrome_args(profile),
        user_agent=fp.user_agent,
        locale=geo.locale,
        timezone_id=geo.timezone_id,
        no_viewport=True,                     # размер страницы = размер окна
        ignore_default_args=["--enable-automation"],
    )
    if profile.proxy:
        launch_kwargs["proxy"] = profile.proxy.playwright_proxy()

    with cm as p:
        context = p.chromium.launch_persistent_context(**launch_kwargs)

        # Наши подмены — ДО любого скрипта страницы.
        context.add_init_script(build_init_script(fp, geo))

        # Новым страницам тоже применяем CDP-оверрайд.
        def _on_page(page):
            _apply_cdp_ua(context, page, profile)
        context.on("page", _on_page)

        # persistent context обычно открывает одну стартовую вкладку.
        page = context.pages[0] if context.pages else context.new_page()
        _apply_cdp_ua(context, page, profile)

        page.goto("https://abrahamjuliot.github.io/creepjs/", wait_until="domcontentloaded")
        print("\n[ok] Браузер открыт. Работайте вручную в окне.")
        print("     Для проверки отпечатка: creepjs / browserleaks.com / iphey.com")
        print("     Закройте окно браузера, чтобы завершить сессию профиля.")
        _wait_until_closed(context)
        try:
            context.close()
        except Exception:  # noqa: BLE001
            pass


def _wait_until_closed(context) -> None:
    """Блокируемся, пока пользователь не закроет окно браузера."""
    closed = threading.Event()
    try:
        context.on("close", lambda: closed.set())
    except Exception:  # noqa: BLE001
        pass
    while not closed.is_set():
        try:
            if not context.pages:        # все вкладки/окно закрыты
                break
        except Exception:  # noqa: BLE001
            break
        closed.wait(0.7)


if __name__ == "__main__":
    # Режим отдельного процесса: python browser.py <имя_профиля>
    # Используется GUI, чтобы не блокировать интерфейс и держать несколько окон.
    import sys
    from profile import Profile

    if len(sys.argv) < 2:
        print("usage: python browser.py <profile_name>")
        sys.exit(1)
    launch_profile(Profile.load(sys.argv[1]))