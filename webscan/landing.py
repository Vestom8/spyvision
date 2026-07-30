"""Главный экран Spyvision: HTML-лендинг и запись на диск."""

import os
import sys
from pathlib import Path


def _landing_path() -> Path:
    """Путь к landing.html: рядом с модулем или в каталоге PyInstaller."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bundled = Path(sys._MEIPASS) / "webscan" / "landing.html"
        if bundled.is_file():
            return bundled
    return Path(__file__).with_name("landing.html")


def landing_html() -> str:
    """Возвращает HTML главного экрана Spyvision."""
    return _landing_path().read_text(encoding="utf-8")


def write_landing(path: str = "index.html") -> str:
    """Сохраняет главный экран в ``path`` и возвращает абсолютный путь."""
    output = os.path.abspath(path)
    directory = os.path.dirname(output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        handle.write(landing_html())
    return output
