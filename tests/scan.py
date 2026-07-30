#!/usr/bin/env python3
"""Запуск Spyvision из подпапки — находит корень проекта и стартует CLI."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _project_root() -> Path:
    for candidate in Path(__file__).resolve().parents:
        if (candidate / "webscan" / "cli.py").is_file():
            return candidate
    raise SystemExit(
        "Не найден корень Spyvision (папка webscan/).\n"
        "Запустите: python scan.py из C:\\Users\\User\\OneDrive\\Dokumente\\spiyvision"
    )


root = _project_root()
sys.path.insert(0, str(root))
os.chdir(root)

from webscan.cli import main

if __name__ == "__main__":
    sys.exit(main())

