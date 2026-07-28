"""Интерфейс командной строки сканера."""

import argparse
import os
import sys
from typing import Callable, List, Optional
from urllib.parse import urlparse

from .http_client import MAX_PAGES, MAX_REQUESTS, MAX_TIMEOUT, MIN_DELAY
from .models import HIGH, INFO, LOW, MEDIUM
from .report import build_report
from .scanner import ScanConfig, run_scan
from .utils import host_of, is_valid_host, supports_tls

DESCRIPTION = """
Сканер типовых ошибок конфигурации и базовых уязвимостей веб-приложения.
Выполняет только безопасные проверки: ничего не удаляет, не изменяет данные
и не передаёт информацию третьим лицам. Используйте только для систем,
на тестирование которых у вас есть разрешение.
"""

EPILOG = """
Примеры:
  python scan.py                        (адрес будет запрошен в консоли)
  python scan.py https://example.com
  python scan.py https://example.com --max-pages 10 --max-depth 1 --output otchet.html
  python scan.py http://127.0.0.1:8000 --no-active --verbose

Если аргумент URL не указан, сканер спросит адрес интерактивно. В этом режиме
можно вставить полный адрес со схемой, путём и параметрами (в том числе с
символом &, который в PowerShell пришлось бы брать в кавычки).
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", default=None,
                        help="URL целевого веб-приложения; если аргумент не указан, "
                             "сканер запросит адрес в консоли")
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES,
                        help=f"максимальное число страниц обхода (по умолчанию и максимум {MAX_PAGES})")
    parser.add_argument("--max-depth", type=int, default=2,
                        help="максимальная глубина обхода (по умолчанию 2)")
    parser.add_argument("--output", default="report.html",
                        help="путь к файлу отчёта (по умолчанию report.html)")
    parser.add_argument("--max-requests", type=int, default=MAX_REQUESTS,
                        help=f"общий лимит HTTP-запросов (по умолчанию и максимум {MAX_REQUESTS})")
    parser.add_argument("--timeout", type=float, default=MAX_TIMEOUT,
                        help=f"таймаут запроса в секундах (по умолчанию и максимум {MAX_TIMEOUT})")
    parser.add_argument("--delay", type=float, default=MIN_DELAY,
                        help=f"пауза между запросами в секундах (минимум {MIN_DELAY})")
    parser.add_argument("--no-active", action="store_true",
                        help="выполнить только проверки конфигурации, без активных тестов")
    parser.add_argument("--no-post-forms", action="store_true",
                        help="не отправлять тестовые значения в POST-формы")
    parser.add_argument("--insecure", action="store_true",
                        help="не прерывать запросы при недоверенном сертификате "
                             "(проверка сертификата всё равно выполняется и попадает в отчёт)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="подробный вывод выполняемых запросов")
    return parser


def _prepare_console() -> None:
    """В Windows-консоли кодировка по умолчанию может не отображать кириллицу."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


TRIM_CHARS = " \t\r\n\"'`«»<>,;"


def sanitize_url(raw: str) -> str:
    """Убирает кавычки, пробелы и прочие символы, попадающие при копировании адреса."""
    if not raw:
        return ""
    value = raw.strip().strip(TRIM_CHARS).strip()
    # Иногда вставляют строку вместе с командой запуска
    for prefix in ("python scan.py", "scan.py", "url:", "URL:", "адрес:"):
        if value.lower().startswith(prefix.lower()):
            value = value[len(prefix):].strip().strip(TRIM_CHARS).strip()
    if value.startswith("//"):
        value = "https:" + value
    return value


def normalize_target(url: str, detect_scheme: bool = True) -> str:
    """Добавляет схему, если пользователь ввёл адрес без неё.

    Если схема не указана, предпочитается HTTPS — при условии, что хост
    отвечает на TLS-рукопожатие. Проверка выполняется без HTTP-запроса и
    не расходует лимит.
    """
    if "://" in url:
        return url
    host_part = url.split("/")[0]
    host = host_part.split("@")[-1]
    port = None
    if ":" in host and not host.endswith("]"):
        host, _, port_text = host.rpartition(":")
        port = int(port_text) if port_text.isdigit() else None
    if detect_scheme and is_valid_host(host) and supports_tls(host, port or 443):
        return "https://" + url
    return "http://" + url


def ask_url(reader: Callable[[str], str] = input, attempts: int = 5,
            detect_scheme: bool = True) -> Optional[str]:
    """Запрашивает адрес в консоли. Возвращает None, если ввод не получен."""
    print("Введите адрес для сканирования (можно вставить полный URL со схемой, "
          "путём и параметрами).")
    print("Примеры: https://example.com/catalog?page=2&sort=new | 127.0.0.1:8099 | "
          "example.com")
    for _ in range(attempts):
        try:
            raw = reader("URL: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        candidate = sanitize_url(raw)
        if not candidate:
            print("  Адрес пустой. Повторите ввод или нажмите Ctrl+C для выхода.")
            continue
        target = normalize_target(candidate, detect_scheme=detect_scheme)
        scheme = urlparse(target).scheme.lower()
        if scheme not in ("http", "https"):
            print(f"  Схема «{scheme}» не поддерживается: нужен http или https.")
            continue
        if not is_valid_host(host_of(target)):
            print("  Не удалось разобрать имя хоста. Пример правильного адреса: "
                  "https://example.com/path")
            continue
        if "://" not in candidate:
            print(f"  Схема определена автоматически: {target}")
        return target
    print("Слишком много неудачных попыток ввода.", file=sys.stderr)
    return None


def main(argv: Optional[List[str]] = None) -> int:
    _prepare_console()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.url is None:
        target_url = ask_url()
        if target_url is None:
            print("Сканирование отменено: адрес не указан.", file=sys.stderr)
            return 2
        args.url = target_url

    if args.max_pages < 1:
        parser.error("--max-pages должен быть не меньше 1")
    if args.max_depth < 0:
        parser.error("--max-depth не может быть отрицательным")
    if args.max_requests < 1:
        parser.error("--max-requests должен быть не меньше 1")

    max_requests = min(args.max_requests, MAX_REQUESTS)
    max_pages = min(args.max_pages, MAX_PAGES)
    timeout = min(args.timeout, MAX_TIMEOUT)
    delay = max(args.delay, MIN_DELAY)
    if args.max_requests > MAX_REQUESTS:
        print(f"Внимание: общий лимит запросов ограничен значением {MAX_REQUESTS} "
              "(требование безопасности).")
    if args.max_pages > MAX_PAGES:
        print(f"Внимание: число страниц обхода ограничено значением {MAX_PAGES}.")
    if args.timeout > MAX_TIMEOUT:
        print(f"Внимание: таймаут ограничен значением {MAX_TIMEOUT} с.")
    if args.delay < MIN_DELAY:
        print(f"Внимание: пауза между запросами увеличена до {MIN_DELAY} с.")

    target = normalize_target(sanitize_url(args.url))
    config = ScanConfig(
        url=target,
        max_pages=max_pages,
        max_depth=args.max_depth,
        output=args.output,
        max_requests=max_requests,
        timeout=timeout,
        delay=delay,
        verify_tls=not args.insecure,
        active=not args.no_active,
        test_post_forms=not args.no_post_forms,
        verbose=args.verbose,
    )

    print("=" * 72)
    print(f"Цель: {target}")
    print(f"Лимиты: страниц {config.max_pages}, глубина {config.max_depth}, "
          f"запросов {config.max_requests}, таймаут {config.timeout} с, пауза {config.delay} с")
    print("=" * 72)

    try:
        result = run_scan(config)
    except ValueError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nСканирование прервано пользователем.", file=sys.stderr)
        return 130

    html = build_report(result.findings, result.stats)
    output_path = os.path.abspath(config.output)
    try:
        directory = os.path.dirname(output_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(html)
    except OSError as exc:
        print(f"Не удалось сохранить отчёт: {exc}", file=sys.stderr)
        return 3

    _print_summary(result, output_path)
    return 0


def _print_summary(result, output_path: str) -> None:
    counts = result.findings.count_by_severity()
    stats = result.stats
    print("-" * 72)
    print(f"Страниц просканировано: {stats['pages']}")
    print(f"HTTP-запросов выполнено: {stats['requests_made']} из {stats['max_requests']}")
    print(f"Проверок выполнено: {stats['checks']}")
    print(f"Найдено проблем: {len(result.findings)} "
          f"(High: {counts.get(HIGH, 0)}, Medium: {counts.get(MEDIUM, 0)}, "
          f"Low: {counts.get(LOW, 0)}, Info: {counts.get(INFO, 0)})")
    print(f"Время сканирования: {stats['duration']} с")
    for note in stats.get("notes", []):
        print(f"  ! {note}")
    print(f"Отчёт сохранён: {output_path}")
    print("-" * 72)


if __name__ == "__main__":
    raise SystemExit(main())
