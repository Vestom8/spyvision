"""Загрузка и запись главного экрана Spyvision (в т.ч. из PyInstaller exe)."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path


def _package_dir() -> Path:
    """Каталог пакета webscan: рядом с исходниками или во временной папке exe."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "webscan"
    return Path(__file__).resolve().parent


def resource_path(name: str) -> Path:
    """Путь к ресурсу пакета (landing.html, bg.jfif)."""
    return _package_dir() / name


def load_landing_html() -> str:
    """Читает шаблон главного экрана."""
    path = resource_path("landing.html")
    if not path.is_file():
        raise FileNotFoundError(
            f"Не найден шаблон главного экрана: {path}. "
            "Ожидается файл webscan/landing.html."
        )
    return path.read_text(encoding="utf-8")


def ensure_background(directory: str | Path = ".") -> None:
    """Копирует bg.jfif в рабочий каталог, если его ещё нет."""
    dest = Path(directory) / "bg.jfif"
    if dest.is_file():
        return
    src = resource_path("bg.jfif")
    if not src.is_file():
        return
    try:
        shutil.copy2(src, dest)
    except OSError:
        pass


def write_landing(directory: str | Path = ".") -> Path:
    """Записывает index.html и фон в каталог запуска. Возвращает путь к index.html."""
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    ensure_background(root)
    target = root / "index.html"
    target.write_text(load_landing_html(), encoding="utf-8")
    return target.resolve()
