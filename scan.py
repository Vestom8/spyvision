#!/usr/bin/env python3
"""Точка входа сканера.

Запуск:
    python scan.py https://example.com [--max-pages N] [--max-depth N] [--output FILE]
"""

import sys

from webscan.cli import main

if __name__ == "__main__":
    sys.exit(main())
