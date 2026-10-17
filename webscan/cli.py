"""Интерфейс командной строки сканера."""

import argparse
import os
import sys
from typing import Callable, List, Optional
from urllib.parse import urlparse

from .http_client import (DEFAULT_CONCURRENCY, MAX_CONCURRENCY, MAX_PAGES, MAX_REQUESTS,
                          MAX_TIMEOUT, MIN_DELAY)
from .models import HIGH, INFO, LOW, MEDIUM
from .report import build_report
from .scanner import ScanConfig, run_scan
from .vulndb import DEFAULT_MAX_CVES
from .utils import host_of, is_valid_host, supports_tls

DESCRIPTION = """
Сканер типовых ошибок конфигурации и базовых уязвимостей веб-приложения.
Выполняет только безопасные проверки: ничего не удаляет, не изменяет данные
и не передаёт содержимое сайта третьим лицам. Для каталожного анализа в NVD
передаются только название и версия найденного компонента/CPE. Используйте
только для систем, на тестирование которых у вас есть разрешение.
"""

EPILOG = """
Примеры:
  python scan.py                        (главный экран Spyvision в браузере)
  python scan.py --cli                  (адрес будет запрошен в консоли)
  python scan.py https://example.com
  python scan.py https://example.com --max-pages 10 --max-depth 1 --output otchet.html
  python scan.py http://127.0.0.1:8000 --no-active --verbose
  python scan.py https://example.com --update-vuln-db
  python scan.py --update-vuln-db       (только обновить базы KEV, ExploitDB и выйти)
  python scan.py https://example.com --vuln-db-offline

Без аргумента URL открывается локальный веб-интерфейс. Режим --cli спрашивает
адрес в консоли (удобно вставлять полный URL с & без кавычек PowerShell).
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan.py",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", default=None,
                        help="URL целевого веб-приложения; если не указан — "
                             "открывается главный экран Spyvision (или ввод в консоли с --cli)")
    parser.add_argument("--cli", action="store_true",
                        help="спросить URL в консоли вместо веб-интерфейса")
    parser.add_argument("--ui-port", type=int, default=0,
                        help="порт локального интерфейса (0 — выбрать автоматически)")
    parser.add_argument("--no-browser", action="store_true",
                        help="не открывать браузер при старте веб-интерфейса")
    parser.add_argument("--max-pages", type=int, default=MAX_PAGES,
                        help=f"максимальное число страниц обхода (по умолчанию и максимум {MAX_PAGES})")
    parser.add_argument("--max-depth", type=int, default=4,
                        help="максимальная глубина обхода (по умолчанию 4)")
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
    parser.add_argument("--pentest", action="store_true",
                        help="расширенный режим: SSRF-пробы внутренней сети/cloud-metadata, "
                             "слепая SQL-инъекция по времени, обход авторизации через SQLi в "
                             "форме входа и безопасное (без изменения данных) подтверждение "
                             "эксплуатации для нескольких изученных CVE (Jenkins /script, "
                             "Grafana CVE-2021-43798). Требует --active и "
                             "--i-have-permission-to-attack")
    parser.add_argument("--i-have-permission-to-attack", action="store_true",
                        dest="pentest_consent",
                        help="подтверждение, что у вас есть разрешение владельца на тестирование "
                             "указанной цели этими методами; обязателен вместе с --pentest")
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY,
                        help="сколько запросов к сайту отправлять одновременно при переборе "
                             f"служебных путей и активных проверках (1–{MAX_CONCURRENCY}, "
                             f"по умолчанию {DEFAULT_CONCURRENCY}); частота стартов запросов "
                             "при этом не растёт, а при ответах 429/503 сканер замедляется сам")
    parser.add_argument("--no-vuln-db", action="store_true",
                        help="отключить сопоставление компонентов с NVD, KEV, ExploitDB и БДУ")
    parser.add_argument("--update-vuln-db", action="store_true",
                        help="принудительно обновить кэш каталогов уязвимостей; без URL — "
                             "только обновить KEV, ExploitDB и БДУ и выйти")
    parser.add_argument("--vuln-db-cache", default="",
                        help="каталог кэша баз уязвимостей (по умолчанию ~/.spyvision/cache)")
    parser.add_argument("--vuln-db-ttl-hours", type=float, default=24.0,
                        help="срок актуальности кэша каталогов в часах (по умолчанию 24)")
    parser.add_argument("--vuln-db-offline", action="store_true",
                        help="не обращаться к каталогам по сети: использовать только локальный кэш")
    parser.add_argument("--no-exploitdb", action="store_true",
                        help="не использовать ExploitDB")
    parser.add_argument("--no-bdu", action="store_true",
                        help="не использовать БДУ ФСТЭК (идентификаторы BDU, статус исправления)")
    parser.add_argument("--bdu-file", default="",
                        help="локальный файл vullist.xlsx из БДУ ФСТЭК вместо загрузки с bdu.fstec.ru "
                             "(первый разбор файла занимает около минуты и выполняется один раз)")
    parser.add_argument("--fstec-component-type", default="server",
                        choices=["important", "firewall", "network", "telecom", "server",
                                 "workstation", "storage", "other"],
                        help="тип уязвимого компонента для оценки по методике ФСТЭК (показатель K; "
                             "по умолчанию server)")
    parser.add_argument("--fstec-perimeter", default="auto", choices=["auto", "internet", "internal"],
                        help="доступность ресурса из Интернета для оценки по методике ФСТЭК "
                             "(показатель P; по умолчанию определяется по адресу цели)")
    parser.add_argument("--components", action="append", default=[], metavar="ФАЙЛ",
                        help="список компонентов для сверки с NVD, БДУ, KEV и ExploitDB: "
                             "requirements.txt, package-lock.json, package.json (точные версии), "
                             "composer.lock, CycloneDX/SPDX JSON или строки «имя версия»; "
                             "можно указать несколько раз")
    parser.add_argument("--max-cves", type=int, default=DEFAULT_MAX_CVES,
                        help="сколько CVE на компонент показывать в отчёте "
                             f"(по умолчанию {DEFAULT_MAX_CVES}); на время скана не влияет")
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

    if args.max_pages < 1:
        parser.error("--max-pages должен быть не меньше 1")
    if args.max_depth < 0:
        parser.error("--max-depth не может быть отрицательным")
    if args.max_requests < 1:
        parser.error("--max-requests должен быть не меньше 1")
    if not 1 <= args.concurrency <= MAX_CONCURRENCY:
        parser.error(f"--concurrency должен быть в диапазоне 1..{MAX_CONCURRENCY}")
    if args.ui_port < 0 or args.ui_port > 65535:
        parser.error("--ui-port должен быть в диапазоне 0..65535")
    for components_path in args.components:
        if not os.path.isfile(components_path):
            parser.error(f"--components: файл не найден: {components_path}")
    if args.vuln_db_ttl_hours < 0:
        parser.error("--vuln-db-ttl-hours не может быть отрицательным")
    if args.max_cves < 1:
        parser.error("--max-cves должен быть не меньше 1")
    if args.update_vuln_db and args.vuln_db_offline:
        parser.error("--update-vuln-db и --vuln-db-offline несовместимы")
    if args.pentest and args.no_active:
        parser.error("--pentest требует активные проверки: уберите --no-active")
    if args.pentest and not args.pentest_consent:
        parser.error(
            "--pentest требует явного подтверждения --i-have-permission-to-attack: "
            "режим отправляет дополнительные пробы (SSRF на внутренние адреса/cloud-metadata, "
            "подтверждение эксплуатации конкретных CVE) и предназначен только для систем, на "
            "тестирование которых у вас есть разрешение владельца."
        )
    if args.pentest_consent and not args.pentest:
        parser.error("--i-have-permission-to-attack указан без --pentest — добавьте --pentest")
    vuln_db_options = dict(
        use_vuln_db=not args.no_vuln_db,
        vuln_db_refresh=args.update_vuln_db,
        vuln_db_ttl_hours=args.vuln_db_ttl_hours,
        vuln_db_cache_dir=args.vuln_db_cache,
        vuln_db_offline=args.vuln_db_offline,
        nvd_api_key=os.environ.get("NVD_API_KEY", ""),
        use_exploitdb=not args.no_exploitdb,
        use_bdu=not args.no_bdu,
        bdu_file=args.bdu_file,
        fstec_component_type=args.fstec_component_type,
        fstec_perimeter=args.fstec_perimeter,
        components_files=list(args.components),
        vuln_max_cves=args.max_cves,
    )

    # --update-vuln-db без URL: только обновить справочники и выйти
    if args.update_vuln_db and args.url is None and not args.cli:
        return update_vuln_db(args)

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

    # Без URL: веб-интерфейс (по умолчанию) или интерактивный ввод (--cli)
    if args.url is None and not args.cli:
        from .ui_server import serve_ui  # noqa: WPS433 — избегаем циклического импорта
        return serve_ui(
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
            concurrency=args.concurrency,
            port=args.ui_port,
            open_browser=not args.no_browser,
            pentest=args.pentest,
            pentest_authorized_by=os.environ.get("USERNAME") or os.environ.get("USER") or "",
            **vuln_db_options,
        )

    if args.url is None:
        target_url = ask_url()
        if target_url is None:
            print("Сканирование отменено: адрес не указан.", file=sys.stderr)
            return 2
        args.url = target_url

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
        concurrency=args.concurrency,
        pentest=args.pentest,
        pentest_authorized_by=os.environ.get("USERNAME") or os.environ.get("USER") or "",
        **vuln_db_options,
    )

    print("=" * 72)
    print(f"Цель: {target}")
    print(f"Лимиты: страниц {config.max_pages}, глубина {config.max_depth}, "
          f"запросов {config.max_requests}, таймаут {config.timeout} с, пауза {config.delay} с")
    if config.pentest:
        print("Режим: --pentest (SSRF внутренней сети/cloud-metadata, слепая SQLi по времени, "
              "обход авторизации через SQLi, подтверждение CVE) — "
              f"подтверждено оператором: {config.pentest_authorized_by or '(не определён)'}")
        print("Используйте только для систем, на тестирование которых у вас есть разрешение "
              "владельца.")
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


def update_vuln_db(args) -> int:
    """Обновляет справочники KEV, ExploitDB и БДУ без сканирования."""
    from .vulndb import VulnDbConfig, update_databases

    print("Обновление справочников уязвимостей (NVD кэшируется по продуктам при сканах)…")
    statuses = update_databases(VulnDbConfig(
        cache_dir=args.vuln_db_cache,
        ttl_hours=args.vuln_db_ttl_hours,
        use_exploitdb=not args.no_exploitdb,
        use_bdu=not args.no_bdu,
        bdu_file=args.bdu_file,
        fstec_component_type=args.fstec_component_type,
        fstec_perimeter=args.fstec_perimeter,
        log=lambda message: print(message, flush=True),
    ))
    failed = 0
    for name, status in statuses.items():
        line = f"  {name}: {status.label}"
        if status.records:
            line += f", записей: {status.records}"
        if status.message:
            line += f" — {status.message}"
        print(line)
        failed += 0 if status.usable else 1
    return 1 if failed == len(statuses) else 0


def _print_summary(result, output_path: str) -> None:
    counts = result.findings.count_by_severity()
    stats = result.stats
    print("-" * 72)
    print(f"Страниц просканировано: {stats['pages']}")
    print(f"HTTP-запросов выполнено: {stats['requests_made']} из {stats['max_requests']}")
    print(f"Проверок выполнено: {stats['checks']}")
    intel = stats.get("vulnerability_intelligence") or {}
    if intel.get("enabled"):
        print(f"Компонентов распознано: {len(intel.get('products') or [])}; "
              f"CVE сопоставлено: {intel.get('matched_cves', 0)} (в CISA KEV: {intel.get('kev', 0)}, "
              f"с эксплойтом: {intel.get('exploits', 0)}, в БДУ ФСТЭК: {intel.get('bdu', 0)}); "
              f"запросов к каталогам: {stats.get('catalog_requests', 0)}")
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
