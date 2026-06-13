#!/usr/bin/env python3
"""
Текстовое меню для управления браузерными профилями.

Запуск:  python main.py
Зависимости:  pip install playwright playwright-stealth "requests[socks]"
              playwright install chromium
"""
from __future__ import annotations

import sys

from profile import list_profiles, create_profile, Profile
from browser import launch_profile


def _print_menu() -> None:
    profiles = list_profiles()
    print("\n" + "=" * 48)
    print(" Anti-detect QA browser — менеджер профилей")
    print("=" * 48)
    if profiles:
        print(" Профили:")
        for i, name in enumerate(profiles, 1):
            print(f"   [{i}] Запустить «{name}»")
    else:
        print(" (профилей пока нет)")
    print(" ---")
    print("   [n] Создать новый профиль")
    print("   [q] Выход")


def _create_flow() -> None:
    name = input("Имя профиля (напр. profile_1): ").strip()
    if not name:
        print("Пустое имя — отмена.")
        return
    proxy = input(
        "Прокси (Enter — без прокси)\n"
        "  форматы: http://user:pass@host:port | socks5://host:port | host:port:user:pass\n"
        "  > "
    ).strip()
    try:
        create_profile(name, proxy or None)
    except Exception as e:  # noqa: BLE001
        print(f"[!] Не удалось создать профиль: {e}")


def _launch_flow(index: int) -> None:
    profiles = list_profiles()
    if not (1 <= index <= len(profiles)):
        print("Нет профиля с таким номером.")
        return
    name = profiles[index - 1]
    try:
        profile = Profile.load(name)
        launch_profile(profile)
    except Exception as e:  # noqa: BLE001
        print(f"[!] Ошибка запуска {name!r}: {e}")


def main() -> None:
    while True:
        _print_menu()
        choice = input(" > ").strip().lower()
        if choice in ("q", "quit", "exit"):
            print("Пока.")
            return
        if choice in ("n", "new"):
            _create_flow()
            continue
        if choice.isdigit():
            _launch_flow(int(choice))
            continue
        print("Не понял выбор.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрервано.")
        sys.exit(0)
