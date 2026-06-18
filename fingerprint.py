"""
Генерация отпечатка (fingerprint), детерминированно привязанного к профилю.

Главная идея: один раз при создании профиля генерируется случайный seed.
Все «случайные» характеристики (UA, разрешение, WebGL и т.д.) выводятся ИЗ ЭТОГО seed.
Значит, при каждом запуске профиля отпечаток одинаковый ("перманентный"), но
у разных профилей он разный. Нестабильный отпечаток сам по себе является сигналом
для анти-бот систем, поэтому детерминированность тут принципиальна.

ВАЖНО: актуальную версию Chrome при создании профиля мы ТЯНЕМ ОНЛАЙН с
официального Google Version History API (fetch_latest_chrome). Локальный пул
_CHROME_VERSIONS ниже — это лишь фолбэк на случай оффлайна/недоступности API.
Устаревший UA — сам по себе детект, поэтому версия всегда должна быть свежей.
"""
from __future__ import annotations

import json
import random
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


# --- Фолбэк-пул. Используется ТОЛЬКО если онлайн-API недоступен. ------------

_CHROME_VERSIONS = ["148", "149"]
# Полные версии для fullVersionList в Client Hints (правдоподобные build-номера).
_FULL_VERSION = {"148": "148.0.7778.139", "149": "149.0.7827.103"}

# Официальный публичный API истории версий Chrome (без ключа).
# Отдаёт список версий канала stable для платформы, новейшая — с наибольшим номером.
_VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/"
    "{platform}/channels/stable/versions"
)
# Наш CH platform -> идентификатор платформы в API.
_PLATFORM_TO_API = {"Windows": "win64", "macOS": "mac"}

# Кэш на время жизни процесса: версия не меняется в рамках одной сессии,
# а профилей можно создавать много — не дёргаем API на каждый.
_version_cache: dict[str, str] = {}


def _ver_key(v: str) -> tuple[int, ...]:
    """'149.0.7827.103' -> (149, 0, 7827, 103) для корректного сравнения версий."""
    return tuple(int(x) for x in v.split(".") if x.isdigit())


def fetch_latest_chrome(platform: str = "win64", timeout: int = 8) -> Optional[str]:
    """
    Вернуть актуальную ПОЛНУЮ версию stable Chrome (напр. '149.0.7827.103')
    с официального Google Version History API, либо None при ошибке/оффлайне.

    platform: идентификатор API — 'win64' | 'win' | 'mac' | 'mac_arm64' | 'linux'.
    Результат кэшируется на время жизни процесса.
    """
    if platform in _version_cache:
        return _version_cache[platform]

    url = _VERSION_API.format(platform=platform)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "antidetect/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:  # noqa: BLE001
        print(f"[ua] не удалось получить актуальную версию Chrome ({e}) — "
              f"использую локальный фолбэк-пул")
        return None

    best: Optional[str] = None
    for item in data.get("versions", []):
        v = item.get("version")
        if not v:
            continue
        if best is None or _ver_key(v) > _ver_key(best):
            best = v

    if best:
        _version_cache[platform] = best
        print(f"[ua] актуальная stable-версия Chrome для {platform}: {best}")
    return best

_PLATFORMS = [
    # (navigator.platform, CH platform, CH platformVersion, шаблон UA-хвоста)
    ("Win32", "Windows", "15.0.0", "Windows NT 10.0; Win64; x64"),
    ("Win32", "Windows", "10.0.0", "Windows NT 10.0; Win64; x64"),
    ("MacIntel", "macOS", "14.5.0", "Macintosh; Intel Mac OS X 10_15_7"),
    ("MacIntel", "macOS", "15.3.0", "Macintosh; Intel Mac OS X 10_15_7"),
]

# Разрешения экрана (screen.width x height) с типовыми соотношениями.
_SCREENS = [
    (1920, 1080), (1920, 1200), (2560, 1440), (1536, 864),
    (1680, 1050), (1440, 900), (1366, 768), (3440, 1440),
]

# Реалистичные пары WebGL vendor / renderer (десктоп Windows/Mac).
_WEBGL = [
    ("Google Inc. (NVIDIA)",
     "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (NVIDIA)",
     "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Intel)",
     "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (AMD)",
     "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ("Google Inc. (Apple)",
     "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)"),
    ("Google Inc. (Apple)",
     "ANGLE (Apple, ANGLE Metal Renderer: Apple M1 Pro, Unspecified Version)"),
]

_HARDWARE_CONCURRENCY = [4, 6, 8, 8, 12, 16]
# navigator.deviceMemory в реальном Chrome ОГРАНИЧЕН сверху значением 8
# (приватность: отдаётся только 0.25/0.5/1/2/4/8). Значения 16/32 невозможны и
# являются прямым тель-сигналом «поддельный браузер». Поэтому максимум 8.
_DEVICE_MEMORY = [4, 8, 8, 8]


@dataclass
class Fingerprint:
    seed: int                     # семя для детерминированного шума (canvas/webgl)
    user_agent: str
    nav_platform: str             # navigator.platform ("Win32" / "MacIntel")
    ch_platform: str              # CH platform ("Windows" / "macOS")
    ch_platform_version: str
    chrome_major: str
    chrome_full_version: str
    screen_w: int
    screen_h: int
    window_w: int                 # размер окна браузера (<= screen)
    window_h: int
    webgl_vendor: str
    webgl_renderer: str
    hardware_concurrency: int
    device_memory: int

    def ch_brands(self) -> list[dict[str, str]]:
        """sec-ch-ua brands (с GREASE-брендом, как у настоящего Chrome)."""
        v = self.chrome_major
        return [
            {"brand": "Not(A:Brand", "version": "99"},
            {"brand": "Google Chrome", "version": v},
            {"brand": "Chromium", "version": v},
        ]

    def ch_full_version_list(self) -> list[dict[str, str]]:
        fv = self.chrome_full_version
        return [
            {"brand": "Not(A:Brand", "version": "99.0.0.0"},
            {"brand": "Google Chrome", "version": fv},
            {"brand": "Chromium", "version": fv},
        ]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Fingerprint":
        # игнорируем лишние ключи на случай миграций схемы
        known = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in d.items() if k in known})


def generate_fingerprint(seed: int | None = None,
                         use_live_version: bool = True) -> Fingerprint:
    """
    Сгенерировать отпечаток. Если seed задан — результат воспроизводим
    (за исключением версии Chrome, которая при use_live_version берётся онлайн).

    use_live_version=True  -> версия Chrome тянется с Google Version History API
                              под выбранную ОС; при недоступности — локальный пул.
    use_live_version=False -> только локальный пул (для тестов / оффлайна).
    """
    if seed is None:
        seed = random.getrandbits(64)
    rng = random.Random(seed)

    nav_platform, ch_platform, ch_ver, ua_tail = rng.choice(_PLATFORMS)

    # Версия Chrome: сначала пробуем актуальную онлайн под выбранную ОС,
    # иначе — детерминированно из локального фолбэк-пула.
    full = None
    if use_live_version:
        full = fetch_latest_chrome(_PLATFORM_TO_API.get(ch_platform, "win64"))
    if full:
        major = full.split(".")[0]
    else:
        major = rng.choice(_CHROME_VERSIONS)
        full = _FULL_VERSION[major]

    user_agent = (
        f"Mozilla/5.0 ({ua_tail}) AppleWebKit/537.36 (KHTML, like Gecko) "
        f"Chrome/{full} Safari/537.36"
    )

    sw, sh = rng.choice(_SCREENS)
    # Окно чуть меньше экрана — как у реального пользователя (есть таскбар/рамки).
    win_w = sw - rng.choice([0, 16, 80, 120])
    win_h = sh - rng.choice([74, 120, 140, 160])

    vendor, renderer = rng.choice(_WEBGL)
    # Apple-рендерер не должен оказаться на Windows-UA, и наоборот — поправим.
    is_mac = nav_platform == "MacIntel"
    if is_mac and "Apple" not in vendor:
        vendor, renderer = _WEBGL[-1]
    if not is_mac and "Apple" in vendor:
        vendor, renderer = _WEBGL[0]

    return Fingerprint(
        seed=seed & 0xFFFFFFFF,  # 32-битный seed для JS-PRNG
        user_agent=user_agent,
        nav_platform=nav_platform,
        ch_platform=ch_platform,
        ch_platform_version=ch_ver,
        chrome_major=major,
        chrome_full_version=full,
        screen_w=sw,
        screen_h=sh,
        window_w=win_w,
        window_h=win_h,
        webgl_vendor=vendor,
        webgl_renderer=renderer,
        hardware_concurrency=rng.choice(_HARDWARE_CONCURRENCY),
        device_memory=rng.choice(_DEVICE_MEMORY),
    )
