"""
Модель профиля и его хранение на диске.

Структура на диске:
  profiles/<name>/
    profile.json      <- отпечаток, гео, прокси (метаданные)
    userdata/         <- настоящий каталог профиля Chromium
                         (Cookies, LocalStorage, IndexedDB, кэш — всё тут)

Изоляция достигается тем, что каждому профилю соответствует свой userdata/,
который Playwright открывает как persistent context. Никакого общего состояния.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from typing import Any, Optional
from urllib.parse import urlparse, quote

from fingerprint import Fingerprint, generate_fingerprint
from geo import GeoProfile, detect_geo, default_geo

PROFILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles")


@dataclass
class ProxyConfig:
    scheme: str               # 'http' | 'https' | 'socks5'
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None

    def playwright_proxy(self) -> dict[str, Any]:
        """Формат, который ждёт Playwright (креды отдельно от server)."""
        proxy: dict[str, Any] = {"server": f"{self.scheme}://{self.host}:{self.port}"}
        if self.username:
            proxy["username"] = self.username
        if self.password:
            proxy["password"] = self.password
        return proxy

    def url(self) -> str:
        """Полный URL (для requests при гео-определении)."""
        auth = ""
        if self.username:
            auth = quote(self.username, safe="")
            if self.password:
                auth += ":" + quote(self.password, safe="")
            auth += "@"
        return f"{self.scheme}://{auth}{self.host}:{self.port}"

    def is_authed_socks(self) -> bool:
        return self.scheme.startswith("socks") and bool(self.username)

    @classmethod
    def parse(cls, raw: str) -> "ProxyConfig":
        """
        Принимает 'http://user:pass@host:port', 'socks5://host:port'
        и короткое 'host:port:user:pass'.
        """
        raw = raw.strip()
        if "://" not in raw:
            # короткий формат host:port[:user:pass]
            parts = raw.split(":")
            if len(parts) == 2:
                return cls("http", parts[0], int(parts[1]))
            if len(parts) == 4:
                return cls("http", parts[0], int(parts[1]), parts[2], parts[3])
            raise ValueError(f"Не понял формат прокси: {raw!r}")
        p = urlparse(raw)
        if not p.hostname or not p.port:
            raise ValueError(f"В прокси нет host/port: {raw!r}")
        return cls(p.scheme, p.hostname, p.port, p.username, p.password)

    @classmethod
    def from_dict(cls, d: Optional[dict[str, Any]]) -> Optional["ProxyConfig"]:
        return cls(**d) if d else None


@dataclass
class Profile:
    name: str
    fingerprint: Fingerprint
    geo: GeoProfile
    proxy: Optional[ProxyConfig] = None

    @property
    def dir(self) -> str:
        return os.path.join(PROFILES_DIR, self.name)

    @property
    def userdata_dir(self) -> str:
        return os.path.join(self.dir, "userdata")

    @property
    def config_path(self) -> str:
        return os.path.join(self.dir, "profile.json")

    def save(self) -> None:
        os.makedirs(self.userdata_dir, exist_ok=True)
        data = {
            "name": self.name,
            "fingerprint": self.fingerprint.to_dict(),
            "geo": self.geo.to_dict(),
            "proxy": asdict(self.proxy) if self.proxy else None,
        }
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, name: str) -> "Profile":
        path = os.path.join(PROFILES_DIR, name, "profile.json")
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return cls(
            name=d["name"],
            fingerprint=Fingerprint.from_dict(d["fingerprint"]),
            geo=GeoProfile.from_dict(d["geo"]),
            proxy=ProxyConfig.from_dict(d.get("proxy")),
        )


def list_profiles() -> list[str]:
    if not os.path.isdir(PROFILES_DIR):
        return []
    out = []
    for name in sorted(os.listdir(PROFILES_DIR)):
        if os.path.isfile(os.path.join(PROFILES_DIR, name, "profile.json")):
            out.append(name)
    return out


def create_profile(name: str, proxy_raw: Optional[str]) -> Profile:
    """Создать новый профиль: сгенерировать отпечаток, определить гео по прокси."""
    if os.path.exists(os.path.join(PROFILES_DIR, name, "profile.json")):
        raise FileExistsError(f"Профиль {name!r} уже существует")

    proxy = ProxyConfig.parse(proxy_raw) if proxy_raw else None
    fingerprint = generate_fingerprint()  # случайный seed -> перманентный отпечаток

    geo = None
    if proxy:
        if proxy.is_authed_socks():
            print("[!] SOCKS5 с логином/паролем Chromium НЕ поддерживает напрямую — "
                  "гео определю, но в браузере нужен локальный мост (см. README).")
        geo = detect_geo(proxy.url())
    geo = geo or default_geo()

    profile = Profile(name=name, fingerprint=fingerprint, geo=geo, proxy=proxy)
    profile.save()
    print(f"[+] Профиль {name!r} создан в {profile.dir}")
    return profile
