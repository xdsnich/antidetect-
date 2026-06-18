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
import shutil
import sys
from dataclasses import dataclass, asdict
from typing import Any, Optional
from urllib.parse import urlparse, quote

from fingerprint import Fingerprint, generate_fingerprint
from geo import GeoProfile, detect_geo, default_geo


def _data_dir() -> str:
    """
    Каталог данных приложения — ВНЕ папки с исходниками.

    Данные профилей лочатся Chromium и пухнут; держать их в репозитории — это и
    git-мусор, и проблемы с удалением/блокировками. Кладём в пользовательский
    каталог ОС (можно переопределить переменной ANTIDETECT_DATA_DIR).
    """
    override = os.environ.get("ANTIDETECT_DATA_DIR")
    if override:
        return override
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.join(base, "antidetect")


DATA_DIR = _data_dir()
PROFILES_DIR = os.path.join(DATA_DIR, "profiles")
# Старое расположение (внутри проекта) — для одноразовой миграции.
_LEGACY_PROFILES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "profiles")


def _migrate_legacy_profiles() -> None:
    """
    Один раз перенести профили из старой папки проекта в DATA_DIR.

    Переносим АТОМАРНО (os.rename), без копирования — чтобы не плодить частичные
    дубликаты, если какой-то файл залочен (напр. last_run.log открыт в IDE).
    Если профиль уже есть в новом месте — старую копию просто чистим.
    """
    if os.path.abspath(_LEGACY_PROFILES_DIR) == os.path.abspath(PROFILES_DIR):
        return
    if not os.path.isdir(_LEGACY_PROFILES_DIR):
        return
    os.makedirs(PROFILES_DIR, exist_ok=True)
    for name in os.listdir(_LEGACY_PROFILES_DIR):
        src = os.path.join(_LEGACY_PROFILES_DIR, name)
        dst = os.path.join(PROFILES_DIR, name)
        if not os.path.isdir(src):
            continue
        if os.path.exists(os.path.join(dst, "profile.json")):
            shutil.rmtree(src, ignore_errors=True)  # уже перенесён — чистим старое
            continue
        if os.path.exists(os.path.join(src, "profile.json")):
            try:
                os.rename(src, dst)         # атомарный перенос, без частичных копий
            except OSError:
                pass                        # залочен -> оставим, перенесётся позже
        else:
            shutil.rmtree(src, ignore_errors=True)  # битый каталог без профиля — мусор
    try:
        os.rmdir(_LEGACY_PROFILES_DIR)      # уберём, если опустела
    except OSError:
        pass


_migrate_legacy_profiles()


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
        if geo is None:
            # НЕ создаём профиль с дефолтным US на не-US прокси — это рассинхрон
            # таймзоны/языка с IP и прямой повод для детекта. Лучше честно упасть.
            raise RuntimeError(
                "Не удалось определить гео по прокси (прокси недоступен или медленный). "
                "Профиль НЕ создан, чтобы таймзона/язык не разошлись с IP. "
                "Проверьте прокси и повторите.")
    geo = geo or default_geo()

    profile = Profile(name=name, fingerprint=fingerprint, geo=geo, proxy=proxy)
    profile.save()
    print(f"[+] Профиль {name!r} создан в {profile.dir}")
    return profile


def set_profile_proxy(name: str, proxy_raw: Optional[str]) -> Profile:
    """
    Сменить прокси у существующего профиля и пере-определить гео по нему.

    Отпечаток (fingerprint) остаётся прежним — это «личность» профиля.
    А таймзону/язык переопределяем по новому IP, чтобы IP и гео не рассинхронились
    (рассинхрон — классический признак для детекта).
    """
    profile = Profile.load(name)
    proxy = ProxyConfig.parse(proxy_raw) if proxy_raw else None

    geo = None
    if proxy:
        if proxy.is_authed_socks():
            print("[!] SOCKS5 с логином/паролем Chromium НЕ поддерживает напрямую — "
                  "гео определю, но в браузере нужен локальный мост (см. README).")
        geo = detect_geo(proxy.url())
        if geo is None:
            raise RuntimeError(
                "Не удалось определить гео по новому прокси (недоступен/медленный). "
                "Прокси НЕ изменён, чтобы таймзона/язык не разошлись с IP. "
                "Проверьте прокси и повторите.")
    geo = geo or default_geo()

    profile.proxy = proxy
    profile.geo = geo
    profile.save()
    print(f"[~] У профиля {name!r} обновлён прокси (гео: {geo.country}, tz={geo.timezone_id})")
    return profile
