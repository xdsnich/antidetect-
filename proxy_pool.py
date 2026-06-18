"""
Пул прокси: сохранённый список прокси, который можно переиспользовать
при создании профиля и при смене прокси у существующего профиля.

Хранится в одном JSON-файле proxies.json рядом с модулями проекта.
Каждая запись — «сырая» строка прокси (в том же формате, что принимает
ProxyConfig.parse) плюс необязательная метка для удобства.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from typing import Any

import requests

from profile import ProxyConfig, DATA_DIR
from geo import detect_geo, country_flag

HERE = os.path.dirname(os.path.abspath(__file__))
POOL_PATH = os.path.join(DATA_DIR, "proxies.json")

# Одноразовая миграция пула из старого места (внутри проекта) в DATA_DIR.
_LEGACY_POOL = os.path.join(HERE, "proxies.json")
if os.path.isfile(_LEGACY_POOL) and not os.path.exists(POOL_PATH):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        os.replace(_LEGACY_POOL, POOL_PATH)
    except Exception:  # noqa: BLE001
        pass


@dataclass
class PoolProxy:
    raw: str            # строка в исходном формате, как ввёл пользователь
    label: str = ""     # метка (необязательно), напр. "US residential 1"
    country: str = ""   # ISO2 точки выхода, определяется по IP при добавлении
    city: str = ""      # город точки выхода

    def config(self) -> ProxyConfig:
        """Разобрать в ProxyConfig (бросает ValueError на кривом формате)."""
        return ProxyConfig.parse(self.raw)

    def geo_label(self) -> str:
        """'🇺🇸 US, New York' — флаг + страна + город (если определены)."""
        if not self.country:
            return ""
        loc = self.country + (f", {self.city}" if self.city else "")
        flag = country_flag(self.country)
        return f"{flag} {loc}".strip()

    def display(self) -> str:
        """Строка для списка: флаг/страна/город · метка · адрес (без пароля)."""
        try:
            c = self.config()
            auth = " (auth)" if c.username else ""
            base = f"{c.scheme}://{c.host}:{c.port}{auth}"
        except Exception:  # noqa: BLE001
            base = self.raw
        parts = [p for p in (self.geo_label(), self.label, base) if p]
        return "   ·   ".join(parts)


def load_pool() -> list[PoolProxy]:
    if not os.path.isfile(POOL_PATH):
        return []
    try:
        with open(POOL_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001
        return []
    out: list[PoolProxy] = []
    for d in data:
        if isinstance(d, dict) and d.get("raw"):
            out.append(PoolProxy(
                raw=d["raw"],
                label=d.get("label", ""),
                country=d.get("country", ""),
                city=d.get("city", ""),
            ))
    return out


def save_pool(items: list[PoolProxy]) -> None:
    with open(POOL_PATH, "w", encoding="utf-8") as f:
        json.dump([asdict(p) for p in items], f, indent=2, ensure_ascii=False)


def add_proxy(raw: str, label: str = "", detect: bool = True) -> PoolProxy:
    """
    Проверить формат, опционально определить гео по IP, добавить в пул и сохранить.

    detect=True делает сетевой запрос ЧЕРЕЗ прокси (страна/город точки выхода).
    Если прокси недоступен или гео не определилось — прокси всё равно добавится,
    просто без флага/страны/города.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("Пустая строка прокси.")
    cfg = ProxyConfig.parse(raw)  # валидация формата, бросит ValueError если кривой
    items = load_pool()
    for p in items:
        if p.raw == raw:
            raise ValueError("Такой прокси уже есть в пуле.")

    country, city = "", ""
    if detect:
        try:
            geo = detect_geo(cfg.url())
            if geo:
                country, city = geo.country, geo.city
        except Exception:  # noqa: BLE001
            pass  # гео — приятный бонус, не повод отказывать в добавлении

    item = PoolProxy(raw=raw, label=label.strip(), country=country, city=city)
    items.append(item)
    save_pool(items)
    return item


def remove_proxy(raw: str) -> None:
    items = [p for p in load_pool() if p.raw != raw]
    save_pool(items)


def check_proxy(raw: str, timeout: int = 12) -> dict[str, Any]:
    """
    Проверить прокси «по-настоящему»: грузятся ли сайты и проходит ли Google.

    Возвращает dict:
      reachable: bool   — прокси отвечает и обычные сайты доступны
      geo:       str    — 'NL/Eindhoven' (по факту), если определилось
      google:    bool   — открывается ли Google через этот прокси
      error:     str    — текст ошибки, если прокси не отвечает
    """
    res: dict[str, Any] = {"reachable": False, "geo": "", "google": False, "error": ""}
    try:
        cfg = ProxyConfig.parse(raw)
    except Exception as e:  # noqa: BLE001
        res["error"] = f"плохой формат: {e}"
        return res

    proxies = {"http": cfg.url(), "https": cfg.url()}

    # 1) обычная доступность + фактическое гео (через сам прокси)
    try:
        r = requests.get(
            "http://ip-api.com/json/?fields=status,countryCode,city,query",
            proxies=proxies, timeout=timeout,
        )
        d = r.json()
        if d.get("status") == "success":
            res["reachable"] = True
            res["geo"] = f"{d.get('countryCode','?')}/{d.get('city','')}".rstrip("/")
    except Exception as e:  # noqa: BLE001
        res["error"] = type(e).__name__
        return res  # прокси не отвечает — Google проверять смысла нет

    # 2) проходит ли Google (generate_204 — лёгкий эндпоинт проверки связности)
    try:
        r = requests.get("https://www.google.com/generate_204",
                         proxies=proxies, timeout=timeout)
        res["google"] = r.status_code in (204, 200)
    except Exception:  # noqa: BLE001
        res["google"] = False

    return res


def refresh_pool_geo(only_missing: bool = False, progress=None,
                     max_workers: int = 8) -> int:
    """
    Пере-определить страну/город для прокси в пуле (через каждый прокси).

    only_missing=True — обновлять только те, где гео ещё нет.
    progress(done, total) — необязательный колбэк прогресса (вызывается из
                            рабочих потоков, в GUI оборачивайте через after()).
    Возвращает число прокси, у которых гео в итоге определено.
    Запросы идут параллельно (каждый через свой прокси → разные exit-IP).
    """
    from concurrent.futures import ThreadPoolExecutor

    items = load_pool()
    targets = [p for p in items if not (only_missing and p.country)]
    total = len(targets)
    done = 0

    def work(p: PoolProxy) -> None:
        try:
            geo = detect_geo(p.config().url(), timeout=12)
            if geo:
                p.country, p.city = geo.country, geo.city
        except Exception:  # noqa: BLE001
            pass  # мёртвый/медленный прокси просто останется без гео

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for _ in ex.map(work, targets):
            done += 1
            if progress:
                progress(done, total)

    save_pool(items)
    return sum(1 for p in targets if p.country)
