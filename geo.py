"""
Определение таймзоны и языка по IP прокси.

Запрос к гео-сервису идёт ЧЕРЕЗ сам прокси, поэтому возвращается геопозиция
точки выхода прокси, а не вашей реальной машины. Это то, что нужно, чтобы
timezone_id и Accept-Language согласовались с IP (иначе рассинхрон IP/таймзоны —
классический детект).

Зависимость для SOCKS: pip install "requests[socks]"
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Optional

import requests


# Грубая карта страна -> основная локаль (расширяйте под свои гео).
_COUNTRY_LOCALE = {
    "US": "en-US", "GB": "en-GB", "CA": "en-CA", "AU": "en-AU",
    "DE": "de-DE", "FR": "fr-FR", "ES": "es-ES", "IT": "it-IT",
    "NL": "nl-NL", "PL": "pl-PL", "UA": "uk-UA", "RU": "ru-RU",
    "BR": "pt-BR", "PT": "pt-PT", "JP": "ja-JP", "KR": "ko-KR",
    "CN": "zh-CN", "TR": "tr-TR", "SE": "sv-SE", "CZ": "cs-CZ",
    "IN": "en-IN", "MX": "es-MX", "AR": "es-AR",
}


@dataclass
class GeoProfile:
    timezone_id: str          # напр. "America/New_York"
    locale: str               # напр. "en-US"  -> Playwright locale
    accept_language: str      # напр. "en-US,en;q=0.9"
    languages: list[str]      # navigator.languages, напр. ["en-US", "en"]
    country: str              # ISO2, напр. "US"
    city: str = ""            # город точки выхода прокси, напр. "New York"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GeoProfile":
        # игнорируем лишние ключи на случай миграций схемы (city добавлен позже)
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


def country_flag(code: str) -> str:
    """
    ISO2-код страны -> эмодзи-флаг ('US' -> '🇺🇸').

    Собирается из двух regional-indicator символов. На системах без флаг-шрифта
    (напр. обычный Windows) покажется как две буквы кода — это нормально.
    """
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return chr(0x1F1E6 + ord(code[0]) - ord("A")) + chr(0x1F1E6 + ord(code[1]) - ord("A"))


def _build_languages(locale: str) -> tuple[str, list[str]]:
    """'en-US' -> ('en-US,en;q=0.9', ['en-US', 'en'])."""
    base = locale.split("-")[0]
    langs = [locale, base] if base != locale else [locale]
    parts = [locale] + [f"{base};q=0.9"] if base != locale else [locale]
    return ",".join(parts), langs


def detect_geo(proxy_url: Optional[str], timeout: int = 15,
               attempts: int = 3) -> Optional[GeoProfile]:
    """
    Вернуть GeoProfile по выходному IP прокси, либо None если не удалось.
    proxy_url: полная строка вида 'http://user:pass@host:port' или
               'socks5://user:pass@host:port'. None -> прямое соединение.

    Делаем несколько попыток: резидентные прокси часто тайм-аутят разово, а
    тихий откат на дефолтную таймзону/язык = рассинхрон с IP = детект. Лучше
    переспросить, чем поставить US наугад.
    """
    proxies = None
    if proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}

    data = None
    for i in range(max(1, attempts)):
        try:
            # ip-api.com: бесплатно, без ключа, отдаёт timezone, countryCode и city.
            r = requests.get(
                "http://ip-api.com/json/?fields=status,countryCode,city,timezone,query",
                proxies=proxies, timeout=timeout,
            )
            data = r.json()
            break
        except Exception as e:  # noqa: BLE001
            print(f"[geo] попытка {i + 1}/{attempts} не удалась: {e}")
            data = None

    if data is None:
        print("[geo] не удалось определить гео по прокси (все попытки).")
        return None

    if data.get("status") != "success":
        print(f"[geo] гео-сервис вернул ошибку: {data}")
        return None

    country = data.get("countryCode", "US")
    city = data.get("city", "")
    tz = data.get("timezone", "UTC")
    locale = _COUNTRY_LOCALE.get(country, "en-US")
    accept_language, languages = _build_languages(locale)

    print(f"[geo] прокси выходит из {country}/{city} ({data.get('query')}), "
          f"tz={tz}, locale={locale}")
    return GeoProfile(
        timezone_id=tz,
        locale=locale,
        accept_language=accept_language,
        languages=languages,
        country=country,
        city=city,
    )


def default_geo() -> GeoProfile:
    """Фолбэк, если прокси нет или гео не определилось."""
    accept_language, languages = _build_languages("en-US")
    return GeoProfile(
        timezone_id="America/New_York",
        locale="en-US",
        accept_language=accept_language,
        languages=languages,
        country="US",
        city="New York",
    )
