"""Управляющий модуль: последовательность этапов сканирования."""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .checks import access_control as access_control_check
from .checks import active as active_checks
from .checks import clientside as clientside_check
from .checks import cookies as cookies_check
from .checks import cors as cors_check
from .checks import exposed as exposed_check
from .checks import forms as forms_check
from .checks import headers as headers_check
from .checks import infoleak as infoleak_check
from .checks import methods as methods_check
from .checks import sast as sast_check
from .checks import tls as tls_check
from .checks import waf_bypass as waf_bypass_check
from .crawler import crawl
from .http_client import MAX_PAGES, MAX_REQUESTS, HttpClient
from .models import CONFIG, CONFIRMED, HIGH, INFO, Finding, FindingList
from .utils import host_of, is_valid_host, normalize_url, origin_of, query_params


@dataclass
class ScanConfig:
    url: str
    max_pages: int = MAX_PAGES
    max_depth: int = 3
    output: str = "report.html"
    max_requests: int = MAX_REQUESTS
    timeout: float = 5.0
    delay: float = 0.1
    verify_tls: bool = True
    active: bool = True
    test_post_forms: bool = True
    verbose: bool = False
    use_gigachat: bool = True


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
    )

    findings = FindingList()
    notes: List[str] = []
    checks_list: List[Tuple[str, str]] = []
    checks_done = 0

    crawl_reserve = int(config.max_requests * 0.30)
    site_reserve = int(config.max_requests * 0.18) if config.active else 0

    # --- Этап 1: обход сайта ---------------------------------------------
    _say(config, f"[1/5] Обход сайта: {target}")
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
    _say(config, f"[2/5] Проверка заголовков, cookies, форм, SAST по HTML/JS ({len(pages)} стр.)")
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

    # --- Этап 3: проверки уровня сайта + служебные файлы -------------------
    _say(config, "[3/5] HTTPS/TLS, CORS, методы, служебные файлы (.git, .env, бэкапы, тесты)")
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
    _say(config, f"[4/5] Broken Access Control (админ-разделы, IDOR, обход 403); "
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
        _say(config, f"[5/5] DAST (XSS/SQLi/LFI/SSTI/…) и WAF-bypass; "
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
            verbose=config.verbose,
        )
        findings.extend(result.findings)
        checks_done += result.tests_executed
        active_tests = result.tests_executed
        targets_tested = result.targets_tested
        active_scope = (f"{result.targets_tested} точек внедрения, "
                        f"{result.tests_executed} запросов")
        for check_name in (
            "DAST: отражённый XSS (в т.ч. img/svg/script-маркеры)",
            "DAST: инъекции SQL и NoSQL",
            "DAST: открытый редирект",
            "DAST: инъекция в шаблон (SSTI)",
            "DAST: чтение файлов сервера (LFI)",
            "DAST: выполнение команд ОС",
            "DAST: разделение заголовков (CRLF)",
        ):
            checks_list.append((check_name, active_scope))
        if result.skipped_forms:
            notes.append(f"Активно не тестировались {result.skipped_forms} форм(а): они выглядят "
                         "изменяющими состояние (регистрация, оплата, удаление и т. п.). "
                         "Это ограничение безопасности самого сканера.")
        if not result.tests_executed and pages:
            notes.append("Точек внедрения (URL-параметров и полей форм) не найдено либо не хватило "
                         "лимита запросов — активные проверки не выполнялись.")
    else:
        active_tests = 0
        targets_tested = 0
        notes.append("Активные проверки уязвимостей отключены ключом --no-active: "
                     "выполнены только проверки конфигурации (включая SAST и BAC).")

    return _finish(config, client, findings, pages, external_links, notes, checks_list,
                   checks_done, active_tests=active_tests, started=started, target=target,
                   targets_tested=targets_tested)


def _finish(config: ScanConfig, client: HttpClient, findings: FindingList, pages, external_links,
            notes: List[str], checks_list, checks_done: int, active_tests: int,
            started: float, target: str, targets_tested: int = 0) -> ScanResult:
    """Итоговые заметки и сбор статистики."""
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

    if config.use_gigachat:
        try:
            from .gigachat_fix import enrich_findings_with_gigachat

            enrich_findings_with_gigachat(findings, enabled=True)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"GigaChat недоступен для текстов «Как исправить»: {exc}")

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
    }
    return result


def _say(config: ScanConfig, message: str) -> None:
    print(message, flush=True)
