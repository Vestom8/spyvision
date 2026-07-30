"""Запуск: python -m webscan  (из корня проекта или любой подпапки)."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _bootstrap() -> None:
    package_dir = Path(__file__).resolve().parent
    root = package_dir.parent
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
    raise SystemExit(main())
