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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "GeoProfile":
        return cls(**d)


def _build_languages(locale: str) -> tuple[str, list[str]]:
    """'en-US' -> ('en-US,en;q=0.9', ['en-US', 'en'])."""
    base = locale.split("-")[0]
    langs = [locale, base] if base != locale else [locale]
    parts = [locale] + [f"{base};q=0.9"] if base != locale else [locale]
    return ",".join(parts), langs


def detect_geo(proxy_url: Optional[str], timeout: int = 15) -> Optional[GeoProfile]:
    """
    Вернуть GeoProfile по выходному IP прокси, либо None если не удалось.
    proxy_url: полная строка вида 'http://user:pass@host:port' или
               'socks5://user:pass@host:port'. None -> прямое соединение.
    """
    proxies = None
    if proxy_url:
        proxies = {"http": proxy_url, "https": proxy_url}

    try:
        # ip-api.com: бесплатно, без ключа, отдаёт timezone и countryCode.
        r = requests.get(
            "http://ip-api.com/json/?fields=status,countryCode,timezone,query",
            proxies=proxies, timeout=timeout,
        )
        data = r.json()
    except Exception as e:  # noqa: BLE001
        print(f"[geo] не удалось определить гео по прокси: {e}")
        return None

    if data.get("status") != "success":
        print(f"[geo] гео-сервис вернул ошибку: {data}")
        return None

    country = data.get("countryCode", "US")
    tz = data.get("timezone", "UTC")
    locale = _COUNTRY_LOCALE.get(country, "en-US")
    accept_language, languages = _build_languages(locale)

    print(f"[geo] прокси выходит из {country} ({data.get('query')}), "
          f"tz={tz}, locale={locale}")
    return GeoProfile(
        timezone_id=tz,
        locale=locale,
        accept_language=accept_language,
        languages=languages,
        country=country,
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
    )
