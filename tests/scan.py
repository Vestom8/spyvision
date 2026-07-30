#!/usr/bin/env python3
"""Точка входа сканера Spyvision (копия для запуска из папки tests).

    python scan.py
    python scan.py --cli
    python scan.py https://example.com
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _project_root() -> Path:
    """Корень репозитория: папка, где лежит пакет ``webscan``."""
    here = Path(__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / "webscan" / "__init__.py").is_file():
            return candidate
    raise SystemExit(
        "Не найден корень проекта Spyvision (ожидалась папка webscan/).\n"
        "Запускайте: python scan.py из папки проекта или её подпапок."
    )


def _bootstrap() -> None:
    root = _project_root()
    root_s = str(root)
    if root_s not in sys.path:
        sys.path.insert(0, root_s)
    try:
        os.chdir(root_s)
    except OSError as exc:
        raise SystemExit(f"Не удалось перейти в корень проекта {root}: {exc}") from exc


_bootstrap()

from webscan.cli import main  # noqa: E402


if __name__ == "__main__":
    sys.exit(main())
