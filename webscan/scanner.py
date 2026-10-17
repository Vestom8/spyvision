"""Управляющий модуль: последовательность этапов сканирования."""

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .checks import access_control as access_control_check
from .checks import active as active_checks
from .checks import auth_bypass as auth_bypass_check
from .checks import clientside as clientside_check
from .checks import cookies as cookies_check
from .checks import cors as cors_check
from .checks import cve_confirm as cve_confirm_check
from .checks import exposed as exposed_check
from .checks import forms as forms_check
from .checks import headers as headers_check
from .checks import infoleak as infoleak_check
from .checks import methods as methods_check
from .checks import sast as sast_check
from .checks import ssrf as ssrf_check
from .checks import tls as tls_check
from .checks import waf_bypass as waf_bypass_check
from .crawler import crawl
from .http_client import MAX_CONSECUTIVE_TIMEOUTS, MAX_PAGES, MAX_REQUESTS, HttpClient
from .dedup import drop_superseded
from .models import (CONFIG, CONFIRMED, HIGH, INFO, Finding, FindingList,
                     apply_confidence_policy)
from .utils import host_of, is_valid_host, normalize_url, origin_of, query_params


@dataclass
class ScanConfig:
    url: str
    max_pages: int = MAX_PAGES
    max_depth: int = 4
    output: str = "report.html"
    max_requests: int = MAX_REQUESTS
    timeout: float = 5.0
    delay: float = 0.1
    verify_tls: bool = True
    active: bool = True
    test_post_forms: bool = True
    verbose: bool = False
    # Режим полноценного пентеста: SSRF-пробы внутренней сети и безопасное
    # подтверждение эксплуатации для нескольких изученных CVE (checks/ssrf.py,
    # checks/cve_confirm.py). Требует отдельного согласия оператора — см. cli.py.
    pentest: bool = False
    pentest_authorized_by: str = ""
    use_vuln_db: bool = True
    vuln_db_refresh: bool = False
    vuln_db_ttl_hours: float = 24.0
    vuln_db_cache_dir: str = ""
    vuln_db_offline: bool = False
    nvd_api_key: str = ""
    use_exploitdb: bool = True
    use_bdu: bool = True
    bdu_file: str = ""
    fstec_component_type: str = "server"
    fstec_perimeter: str = "auto"
    components_files: List[str] = field(default_factory=list)
    vuln_max_cves: int = 200
    concurrency: int = 4  # одновременных запросов к цели в пачечных проверках (1 — последовательно)
    progress: Optional[Callable[[str], None]] = None  # вызывается с названием текущего этапа


@dataclass
class ScanResult:
    findings: FindingList = field(default_factory=FindingList)
    stats: Dict[str, object] = field(default_factory=dict)


def run_scan(config: ScanConfig) -> ScanResult:
    started = time.monotonic()
    target = normalize_url(config.url)
    if not target or not is_valid_host(host_of(target)):
        raise ValueError(
            f"Некорректный URL: {config.url}. Ожидается адрес вида https://example.com "
            "или http://127.0.0.1:8000/path"
        )

    client = HttpClient(
        timeout=config.timeout,
        delay=config.delay,
        max_requests=config.max_requests,
        verify_tls=config.verify_tls,
        verbose=config.verbose,
        concurrency=config.concurrency,
    )

    findings = FindingList()
    notes: List[str] = []
    checks_list: List[Tuple[str, str]] = []
    checks_done = 0

    crawl_reserve = int(config.max_requests * 0.30)
    site_reserve = int(config.max_requests * 0.18) if config.active else 0

    # --- Этап 1: обход сайта ---------------------------------------------
    _say(config, f"[1/6] Обход сайта: {target}")
    pages, external_links = crawl(
        client, target, max_pages=config.max_pages, max_depth=config.max_depth,
        reserve=crawl_reserve, verbose=config.verbose,
    )
    checks_list.append(("Обход сайта в пределах домена", f"{len(pages)} стр., глубина ≤ {config.max_depth}"))
    _say(config, f"      загружено страниц: {len(pages)}; внешних ссылок пропущено: {len(external_links)}")

    if not pages:
        notes.append("Не удалось загрузить ни одну страницу — проверьте доступность адреса, "
                     "сетевые ограничения и правильность схемы (http/https). Остальные этапы "
                     "пропущены, чтобы не расходовать лимит запросов.")
        findings.add(
            Finding(
                url=target,
                title="Целевой адрес недоступен",
                kind="target_unreachable",
                category=CONFIG,
                severity=HIGH,
                recommendation="Проверьте, что адрес указан верно, сервер запущен и доступен из "
                               "этой сети (порт, файрвол, VPN, схема http/https).",
                request=f"GET {target}",
                evidence="\n".join(f"{url} — {message}" for url, message in client.errors[:5])
                or "Ответ не получен.",
                confidence=CONFIRMED,
            )
        )
        return _finish(config, client, findings, pages, external_links, notes, checks_list,
                       checks_done, active_tests=0, started=started, target=target)

    # --- Этап 2: пассивные проверки + SAST по загруженному коду -----------
    _say(config, f"[2/6] Проверка заголовков, cookies, форм, SAST по HTML/JS ({len(pages)} стр.)")
    for page in pages:
        findings.extend(headers_check.check_headers(page))
        findings.extend(cookies_check.check_cookies(page))
        findings.extend(tls_check.check_mixed_content(page))
        findings.extend(forms_check.check_forms(page))
        findings.extend(infoleak_check.check_info_leak(page))
        findings.extend(clientside_check.check_client_side(page))
        findings.extend(exposed_check.check_directory_listing(page.url, page.body))
        findings.extend(sast_check.check_sast(page))
        checks_done += 9
        if page.truncated:
            notes.append(f"Ответ страницы {page.url} обрезан по лимиту 1 МБ — анализировалась "
                         "только загруженная часть.")
    if pages:
        checks_list.append(("Защитные HTTP-заголовки", f"{len(pages)} стр."))
        checks_list.append(("Безопасность cookies", f"{len(pages)} стр."))
        checks_list.append(("Смешанный контент (HTTP на HTTPS)", f"{len(pages)} стр."))
        checks_list.append(("Анализ форм (HTTPS, метод, CSRF, внешний получатель)", f"{len(pages)} стр."))
        checks_list.append(("Утечки технической информации", f"{len(pages)} стр."))
        checks_list.append(("Клиентская часть: контроль целостности сторонних скриптов, "
                            "target=_blank, устаревшие библиотеки, кэш приватных страниц, "
                            "данные в адресах, сторонние iframe, формы загрузки файлов",
                            f"{len(pages)} стр."))
        checks_list.append(("Опасные места в JavaScript: DOM XSS, приём сообщений "
                            "postMessage без проверки отправителя, токены в localStorage, "
                            "ws:// на защищённой странице, обработчики событий в разметке",
                            f"{len(pages)} стр."))
        checks_list.append(("Листинг каталогов", f"{len(pages)} стр."))
        checks_list.append(("SAST по HTML/JS: eval, innerHTML, секреты, debug, source maps",
                            f"{len(pages)} стр."))

    # Этап 6 не обращается к цели (только к публичным каталогам) и использует лишь
    # уже загруженные страницы, поэтому стартует в фоне и ждёт своей очереди в конце.
    vuln_job = _start_vuln_job(config, pages) if config.use_vuln_db else None

    # --- Этап 3: проверки уровня сайта + служебные файлы -------------------
    _say(config, "[3/6] HTTPS/TLS, CORS, методы, служебные файлы (.git, .env, бэкапы, тесты)")
    findings.extend(tls_check.check_https_and_tls(client, target, reserve=site_reserve))
    checks_list.append(("HTTPS, редирект с HTTP, сертификат TLS", origin_of(target)))
    checks_done += 3

    findings.extend(cors_check.check_cors(client, target, reserve=site_reserve))
    findings.extend(cors_check.check_preflight(client, target, reserve=site_reserve))
    checks_list.append(("Политика CORS (Origin: сторонний, null, *)", origin_of(target)))
    checks_done += 4

    findings.extend(methods_check.check_http_methods(client, target, reserve=site_reserve))
    checks_list.append(("Разрешённые HTTP-методы (OPTIONS)", origin_of(target)))
    checks_done += 1

    exposed_findings = exposed_check.check_exposed_paths(client, target, reserve=site_reserve)
    findings.extend(exposed_findings)
    checks_list.append((
        f"Служебные файлы и тестовые страницы ({len(exposed_check.SENSITIVE_PATHS)} путей: "
        ".git, .env, бэкапы, phpinfo, /test, /staging…)",
        origin_of(target),
    ))
    checks_done += len(exposed_check.SENSITIVE_PATHS)

    findings.extend(exposed_check.check_robots(client, target, reserve=site_reserve))
    checks_list.append(("Служебные разделы в robots.txt", origin_of(target)))
    checks_done += 1

    # --- Этап 4: Broken Access Control -----------------------------------
    _say(config, f"[4/6] Broken Access Control (админ-разделы, IDOR, обход 403); "
                 f"доступно запросов: {client.remaining}")
    bac_findings = access_control_check.check_broken_access_control(
        client, target, pages, reserve=site_reserve,
    )
    findings.extend(bac_findings)
    checks_list.append((
        "Broken Access Control: админ/API без авторизации, IDOR по id, обход через заголовки",
        origin_of(target),
    ))
    checks_done += max(1, len(bac_findings))

    # --- Этап 5: DAST + WAF-bypass ---------------------------------------
    if config.active:
        _say(config, f"[5/6] DAST (XSS/SQLi/LFI/SSTI/…) и WAF-bypass; "
                     f"доступно запросов: {client.remaining}")
        waf_findings = waf_bypass_check.run_waf_checks(
            client, target, pages, reserve=0,
        )
        findings.extend(waf_findings)
        checks_list.append(("Обнаружение WAF и попытки обхода фильтров (маркерные payload'ы)",
                            origin_of(target)))
        checks_done += max(1, len(waf_findings))

        result = active_checks.run_active_checks(
            client, pages, reserve=0, test_post_forms=config.test_post_forms,
            verbose=config.verbose, pentest=config.pentest,
        )
        findings.extend(result.findings)
        checks_done += result.tests_executed
        active_tests = result.tests_executed
        targets_tested = result.targets_tested
        active_scope = (f"{result.targets_tested} точек внедрения, "
                        f"{result.tests_executed} запросов")
        sqli_checks = ["DAST: инъекции SQL и NoSQL (ошибки СУБД + булева слепая инъекция)"]
        if config.pentest:
            sqli_checks.append("Pentest: слепая SQL-инъекция по времени (SLEEP/pg_sleep/WAITFOR)")
        for check_name in (
            ["DAST: отражённый XSS (в т.ч. img/svg/script-маркеры)"]
            + sqli_checks
            + [
                "DAST: открытый редирект",
                "DAST: инъекция в шаблон (SSTI)",
                "DAST: чтение файлов сервера (LFI)",
                "DAST: выполнение команд ОС",
                "DAST: разделение заголовков (CRLF)",
            ]
        ):
            checks_list.append((check_name, active_scope))
        if result.skipped_forms:
            notes.append(f"Активно не тестировались {result.skipped_forms} форм(а): они выглядят "
                         "изменяющими состояние (регистрация, оплата, удаление и т. п.). "
                         "Это ограничение безопасности самого сканера.")
        if not result.tests_executed and pages:
            notes.append("Точек внедрения (URL-параметров и полей форм) не найдено либо не хватило "
                         "лимита запросов — активные проверки не выполнялись.")

        if config.pentest:
            _say(config, "      режим --pentest: SSRF-пробы внутренней сети и подтверждение "
                         "эксплуатации известных CVE")
            notes.append(
                "Выполнен расширенный режим --pentest (SSRF-пробы внутренней сети/cloud-metadata, "
                "слепая SQL-инъекция по времени, обход авторизации через SQLi в форме входа"
                + (f" и подтверждение CVE), подтверждено оператором: "
                   f"{config.pentest_authorized_by}."
                   if config.pentest_authorized_by else " и подтверждение CVE).")
            )
            ssrf_findings = ssrf_check.run_ssrf_checks(client, pages, reserve=0)
            findings.extend(ssrf_findings)
            checks_list.append(("Pentest: SSRF (cloud-metadata, внутренняя сеть)", active_scope))
            checks_done += max(1, len(ssrf_findings))

            if config.test_post_forms:
                auth_findings = auth_bypass_check.run_auth_bypass_checks(client, pages, reserve=0)
                findings.extend(auth_findings)
                checks_list.append((
                    "Pentest: подтверждение обхода авторизации через SQL-инъекцию в форме входа",
                    active_scope,
                ))
                checks_done += max(1, len(auth_findings))
        else:
            notes.append("Расширенные пентест-проверки (SSRF внутренней сети, подтверждение "
                         "эксплуатации конкретных CVE) не запускались: включаются ключом "
                         "--pentest при наличии разрешения на тестирование цели.")
    else:
        active_tests = 0
        targets_tested = 0
        notes.append("Активные проверки уязвимостей отключены ключом --no-active: "
                     "выполнены только проверки конфигурации (включая SAST и BAC).")

    # --- Этап 6: корреляция с публичными каталогами ----------------------
    # Fingerprint строится только по уже полученным ответам: цель не получает
    # ни одного дополнительного запроса. Каталоги опрашиваются отдельным
    # HTTP-клиентом и не расходуют бюджет запросов к цели.
    vuln_context: Dict[str, object] = {}
    if vuln_job is not None:
        _say(config, "[6/6] Сверка с NVD, CISA KEV и ExploitDB "
                     "(выполнялась параллельно с этапами 3–5)")
        try:
            enrichment = vuln_job.result()
            _suppress_heuristic_duplicates(findings, enrichment)
            findings.extend(enrichment.findings)
            notes.extend(enrichment.notes)
            checks_done += len(enrichment.components)
            checks_list.append((
                "Известные уязвимости: fingerprint → CPE/NVD → CISA KEV, ExploitDB",
                f"компонентов: {len(enrichment.components)}, CVE: {enrichment.matched_cves}, "
                f"запросов к каталогам: {enrichment.catalog_requests}",
            ))
            vuln_context = enrichment.as_context()
            _say(config, f"      компонентов: {len(enrichment.components)}; CVE: "
                         f"{enrichment.matched_cves} (KEV: {enrichment.kev_count}); "
                         f"запросов к каталогам: {enrichment.catalog_requests}; "
                         f"{enrichment.duration:.1f} с")

            if config.active and config.pentest:
                _say(config, "      режим --pentest: подтверждение эксплуатации по "
                             "обнаруженным компонентам")
                confirm_findings = cve_confirm_check.run_cve_confirmation(
                    client, enrichment.components, target, reserve=0,
                )
                findings.extend(confirm_findings)
                checks_list.append((
                    "Pentest: безопасное подтверждение эксплуатации (Jenkins /script, "
                    "Grafana CVE-2021-43798 и т. п.)",
                    f"компонентов проверено: {len(enrichment.components)}",
                ))
                checks_done += max(1, len(confirm_findings))
        except Exception as exc:  # noqa: BLE001 - сбой справочников не должен ломать основной скан
            notes.append(f"Анализ по каталогам уязвимостей не выполнен: {exc}")
            vuln_context = {"enabled": True, "error": str(exc)}
    else:
        notes.append("Сопоставление с NVD, CISA KEV и ExploitDB отключено (--no-vuln-db).")
        vuln_context = {"enabled": False}

    return _finish(config, client, findings, pages, external_links, notes, checks_list,
                   checks_done, active_tests=active_tests, started=started, target=target,
                   targets_tested=targets_tested, vuln_context=vuln_context)


class _BackgroundJob:
    """Результат функции, выполняемой в отдельном потоке; ошибка пробрасывается в result()."""

    def __init__(self, func) -> None:
        self._value = None
        self._error: Optional[BaseException] = None
        self._thread = threading.Thread(target=self._run, args=(func,), daemon=True)
        self._thread.start()

    def _run(self, func) -> None:
        try:
            self._value = func()
        except BaseException as exc:  # noqa: BLE001 - пробрасывается вызывающему
            self._error = exc

    def result(self):
        self._thread.join()
        if self._error is not None:
            raise self._error
        return self._value


def _start_vuln_job(config: ScanConfig, pages) -> _BackgroundJob:
    def run():
        from .vulndb import VulnDbConfig, enrich_with_catalogs

        return enrich_with_catalogs(pages, VulnDbConfig(
            cache_dir=config.vuln_db_cache_dir,
            ttl_hours=config.vuln_db_ttl_hours,
            refresh=config.vuln_db_refresh,
            offline=config.vuln_db_offline,
            nvd_api_key=config.nvd_api_key,
            use_exploitdb=config.use_exploitdb,
            use_bdu=config.use_bdu,
            bdu_file=config.bdu_file,
            fstec_component_type=config.fstec_component_type,
            fstec_perimeter=config.fstec_perimeter,
            components_files=list(config.components_files),
            max_cves_per_component=config.vuln_max_cves,
            log=lambda message: _say(config, message),
        ))

    return _BackgroundJob(run)


def _finish(config: ScanConfig, client: HttpClient, findings: FindingList, pages, external_links,
            notes: List[str], checks_list, checks_done: int, active_tests: int,
            started: float, target: str, targets_tested: int = 0,
            vuln_context: Dict[str, object] = None) -> ScanResult:
    """Итоговые заметки и сбор статистики."""
    if client.gave_up:
        notes.append(f"Сайт перестал отвечать ({MAX_CONSECUTIVE_TIMEOUTS} таймаутов подряд), "
                     "оставшиеся проверки пропущены, чтобы не ждать таймаут на каждом запросе. "
                     "Возможно, запросы блокирует WAF или сайт перегружен.")
    if client.budget_exhausted:
        notes.append(f"Достигнут лимит запросов ({config.max_requests}). Часть проверок могла быть "
                     "не выполнена — увеличьте --max-requests или уменьшите --max-pages.")
    if pages and len(pages) >= config.max_pages:
        notes.append(f"Достигнут лимит страниц (--max-pages {config.max_pages}); "
                     "часть сайта могла остаться непросканированной.")
    if external_links:
        findings.add(
            Finding(
                url=target,
                title=f"Обнаружены ссылки на внешние домены ({len(external_links)})",
                kind="external_links",
                category=CONFIG,
                severity=INFO,
                recommendation="Проверьте, что внешние ссылки ведут на доверенные ресурсы, и "
                               "добавьте rel=\"noopener noreferrer\" для ссылок с target=\"_blank\". "
                               "Сканер по внешним ссылкам не переходил.",
                request=f"Анализ ссылок на {len(pages)} загруженных страницах",
                evidence="\n".join(external_links[:15]),
                confidence=CONFIRMED,
            )
        )
    if client.insecure_requests:
        for host, message in client.tls_errors.items():
            notes.append(f"Проверка сертификата для {host} не пройдена; запросы выполнялись "
                         f"без проверки TLS, чтобы продолжить анализ. Причина: {message[:200]}")

    drop_superseded(findings)
    lowered = apply_confidence_policy(findings)
    if lowered:
        notes.append(f"У {lowered} находок уровень «Высокий» понижен до «Средний»: это подозрения "
                     "по эвристике без независимого подтверждения (проверьте вручную).")

    duration = round(time.monotonic() - started, 1)
    forms_found = sum(len(page.forms) for page in pages)
    params_found = len({(page.url.split("?")[0], name)
                        for page in pages for name, _v in query_params(page.url)})
    result = ScanResult(findings=findings)
    result.stats = {
        "target": target,
        "pages": len(pages),
        "checks": checks_done,
        "active_tests": active_tests,
        "targets_tested": targets_tested,
        "forms": forms_found,
        "url_params": params_found,
        "https": target.lower().startswith("https://"),
        "insecure_requests": client.insecure_requests,
        "error_count": len(client.errors),
        "external_count": len(external_links),
        "requests_made": client.requests_made,
        "max_requests": config.max_requests,
        "max_pages": config.max_pages,
        "max_depth": config.max_depth,
        "duration": duration,
        "notes": notes,
        "errors": client.errors,
        "checks_list": checks_list,
        "page_list": [
            {
                "url": page.url,
                "status": page.status,
                "depth": page.depth,
                "content_type": page.content_type,
                "size": len(page.body),
            }
            for page in pages
        ],
        "external_links": external_links,
        "vulnerability_intelligence": vuln_context or {"enabled": False},
        # Запросы к каталогам считаются отдельно: они не входят в бюджет запросов к цели.
        "catalog_requests": int((vuln_context or {}).get("catalog_requests") or 0),
        "catalog_duration": (vuln_context or {}).get("duration", 0),
    }
    return result


def _suppress_heuristic_duplicates(findings: FindingList, enrichment) -> None:
    """Убирает эвристическую «устаревшую библиотеку», если по ней есть CVE из каталогов.

    Каталожная находка точнее (конкретные CVE, KEV, эксплойты), а две записи
    об одной и той же библиотеке только засоряют отчёт.
    """
    covered = {item.component.label.lower() for item in enrichment.matches if item.component.label}
    if not covered:
        return

    def duplicate(finding: Finding) -> bool:
        if finding.kind != "outdated_library":
            return False
        name = finding.title.split(":", 1)[-1].strip().lower()
        return any(name.startswith(label + " ") for label in covered)

    findings.discard(duplicate)


def _say(config: ScanConfig, message: str) -> None:
    print(message, flush=True)
    # Строки вида «[3/6] …» — названия этапов; их показывает главный экран.
    if config.progress is not None and message.startswith("["):
        try:
            config.progress(message)
        except Exception:  # noqa: BLE001 - индикатор не должен ломать скан
            pass
