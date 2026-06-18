#!/usr/bin/env python3
"""
Диагностика «почему встаёт под нагрузкой» — запускать НА СВОЕЙ машине.

Зачем: на машине разработчика всё стабильно, а у тебя падает. Значит узкое место
в твоём окружении (путь до прокси / мощность ПК / сам прокси). Этот скрипт по
нарастающей нагружает браузер через твой прокси (как в реальной работе: вкладки,
YouTube, CreepJS) и печатает, на каком ШАГЕ и ПОЧЕМУ ломается — с цифрами.

Запуск:
    python diagnose.py                  # возьмёт первый живой прокси из пула
    python diagnose.py host:port:user:pass   # конкретный прокси

Пришли разработчику весь вывод — он точно покажет горлышко.
"""
from __future__ import annotations

import sys
import time
import tempfile
import os

import requests
from playwright.sync_api import sync_playwright

from profile import ProxyConfig
from proxy_pool import load_pool
from proxy_relay import ProxyRelay
from fingerprint import generate_fingerprint
from geo import detect_geo, default_geo
from stealth_scripts import build_init_script
from browser import _chrome_args, _apply_cdp_ua


class _P:  # лёгкий профиль-обёртка для _chrome_args
    def __init__(self, proxy, fp, geo):
        self.proxy, self.fingerprint, self.geo = proxy, fp, geo


def _pick_proxy() -> ProxyConfig | None:
    if len(sys.argv) > 1:
        return ProxyConfig.parse(sys.argv[1])
    print("Ищу живой прокси в пуле...")
    for pp in load_pool():
        c = ProxyConfig.parse(pp.raw)
        try:
            requests.get("http://ip-api.com/json/?fields=query",
                         proxies={"http": c.url(), "https": c.url()}, timeout=7)
            return c
        except Exception:  # noqa: BLE001
            continue
    return None


def _mem_mb() -> int:
    try:
        import subprocess
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq chrome.exe", "/NH", "/FO", "CSV"],
            capture_output=True, text=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
        tot = 0
        for line in out.strip().splitlines():
            cols = line.split('","')
            if len(cols) >= 5:
                import re
                kb = re.sub(r"[^0-9]", "", cols[-1])
                if kb:
                    tot += int(kb)
        return tot // 1024
    except Exception:  # noqa: BLE001
        return -1


def main() -> None:
    proxy = _pick_proxy()
    if not proxy:
        print("[!] Живой прокси не найден. Укажи: python diagnose.py host:port:user:pass")
        return

    print(f"\n[*] Прокси: {proxy.host}:{proxy.port} (auth={'да' if proxy.username else 'нет'})")
    print("[*] Проверяю прокси напрямую (requests)...")
    t = time.time()
    try:
        r = requests.get("http://ip-api.com/json/?fields=countryCode,city,query",
                         proxies={"http": proxy.url(), "https": proxy.url()}, timeout=15)
        print(f"    OK {time.time() - t:.1f}s -> {r.json()}")
    except Exception as e:  # noqa: BLE001
        print(f"    ПРОКСИ НЕ ОТВЕЧАЕТ напрямую: {e}\n    -> дело в прокси/сети, не в коде.")
        return

    geo = detect_geo(proxy.url()) or default_geo()
    fp = generate_fingerprint(use_live_version=False)
    prof = _P(proxy, fp, geo)

    relay = ProxyRelay(proxy)
    host, port = relay.start()
    print(f"[*] Релей: 127.0.0.1:{port}\n")

    sites = ["https://web.telegram.org", "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
             "https://en.wikipedia.org/wiki/Cat", "https://www.reddit.com",
             "https://www.bbc.com", "https://www.cnn.com"]

    with sync_playwright() as p:
        ctx = p.chromium.launch_persistent_context(
            user_data_dir=os.path.join(tempfile.gettempdir(), "antidetect_diag"),
            headless=False, args=_chrome_args(prof), user_agent=fp.user_agent,
            locale=geo.locale, timezone_id=geo.timezone_id, no_viewport=True,
            proxy={"server": f"http://{host}:{port}"},
            ignore_default_args=["--enable-automation"])
        ctx.add_init_script(build_init_script(fp, geo))
        crashes = []
        ctx.on("page", lambda pg: (_apply_cdp_ua(ctx, pg, prof),
                                   pg.on("crash", lambda: crashes.append(pg.url))))

        def probe(label: str) -> bool:
            """Открыть свежую вкладку — грузится ли НОВОЕ соединение?"""
            np = ctx.new_page()
            t0 = time.time()
            ok = True
            try:
                np.goto("https://en.wikipedia.org/wiki/Dog",
                        timeout=20000, wait_until="domcontentloaded")
            except Exception as e:  # noqa: BLE001
                ok = False
                why = type(e).__name__
            dt = time.time() - t0
            print(f"    [{label}] новая вкладка: "
                  f"{'OK' if ok else 'НЕ ГРУЗИТСЯ (' + why + ')'} {dt:.1f}s | "
                  f"active={relay._active} traffic={relay._bytes // 1048576}MB "
                  f"mem={_mem_mb()}MB up_fail={relay._up_fail} crashes={len(crashes)}")
            try:
                np.close()
            except Exception:  # noqa: BLE001
                pass
            return ok

        # ---- ШАГ 1: вкладки по нарастающей, держим их открытыми ----
        print("=== ШАГ 1: открываю тяжёлые вкладки по одной, держу открытыми ===")
        open_tabs = []
        for i, url in enumerate(sites):
            pg = ctx.pages[0] if (i == 0 and ctx.pages) else ctx.new_page()
            open_tabs.append(pg)
            t0 = time.time()
            st = "OK"
            try:
                pg.goto(url, timeout=35000, wait_until="domcontentloaded")
            except Exception as e:  # noqa: BLE001
                st = "FAIL " + type(e).__name__
            print(f"  вкладка {i + 1} ({url[:34]}): {st} {time.time() - t0:.1f}s "
                  f"| active={relay._active} mem={_mem_mb()}MB")
            if not probe(f"после {i + 1} вкладок"):
                print(f"\n[!!!] СЛОМАЛОСЬ после {i + 1} вкладок. Это горлышко.")
                break
            time.sleep(2)

        # ---- ШАГ 2: CreepJS (самый тяжёлый фингерпринт) ----
        print("\n=== ШАГ 2: CreepJS (тяжёлый фингерпринт) ===")
        cj = ctx.new_page()
        t0 = time.time()
        try:
            cj.goto("https://abrahamjuliot.github.io/creepjs/",
                    timeout=45000, wait_until="domcontentloaded")
            print(f"  CreepJS загрузилась {time.time() - t0:.1f}s, даю отработать 25с...")
        except Exception as e:  # noqa: BLE001
            print(f"  CreepJS goto: {type(e).__name__}")
        for s in range(5):
            time.sleep(5)
            if not probe(f"CreepJS+{(s + 1) * 5}s"):
                print(f"\n[!!!] СЛОМАЛОСЬ во время CreepJS (+{(s + 1) * 5}s). Это горлышко.")
                break

        print("\n=== ИТОГ ===")
        print(f"  обслужено туннелей: {relay._served} | сбоев к прокси: {relay._up_fail} "
              f"| крашей вкладок: {len(crashes)}")
        print("  Закрой окно браузера, чтобы завершить. Пришли весь этот вывод разработчику.")
        try:
            while ctx.pages:
                time.sleep(0.5)
        except Exception:  # noqa: BLE001
            pass
        try:
            ctx.close()
        except Exception:  # noqa: BLE001
            pass
    relay.stop()


if __name__ == "__main__":
    main()
