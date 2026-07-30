"""Проверка защитных HTTP-заголовков (раздел 3.1 требований)."""

from typing import List

from ..models import CONFIG, CONFIRMED, INFO, LOW, MEDIUM, Finding, Page
from ..utils import header_multivalues, parse_max_age, truncate

SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

SAFE_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin-when-cross-origin",
    "origin",
}

HSTS_MIN_AGE = 15552000  # 180 дней


def check_headers(page: Page) -> List[Finding]:
    findings: List[Finding] = []
    multi = header_multivalues(page.raw_headers)
    request_line = f"GET {page.url}"

    def add(title, severity, recommendation, evidence="", confidence=CONFIRMED, kind=""):
        findings.append(
            Finding(
                url=page.url,
                title=title,
                category=CONFIG,
                severity=severity,
                recommendation=recommendation,
                request=request_line,
                evidence=truncate(evidence, 500),
                confidence=confidence,
                kind=kind,
            )
        )

    csp = _first(multi, "content-security-policy")
    csp_ro = _first(multi, "content-security-policy-report-only")
    if not csp:
        if csp_ro:
            add(
                "Content-Security-Policy только в режиме Report-Only",
                LOW,
                "Report-Only не блокирует атаки. Включите рабочий заголовок Content-Security-Policy "
                "после проверки отчётов.",
                f"Content-Security-Policy-Report-Only: {csp_ro}",
                kind="csp_report_only",
            )
        else:
            add(
                "Отсутствует заголовок Content-Security-Policy",
                MEDIUM,
                "Добавьте CSP, например: default-src 'self'; script-src 'self'; object-src 'none'; "
                "frame-ancestors 'self'; base-uri 'self'.",
                "Заголовок Content-Security-Policy не найден в ответе.",
                kind="csp_missing",
            )
    else:
        lowered = csp.lower()
        weak = [token for token in ("'unsafe-inline'", "'unsafe-eval'", "data:", "*")
                if token in lowered]
        if "'unsafe-inline'" in lowered or "'unsafe-eval'" in lowered:
            add(
                "Небезопасные директивы в Content-Security-Policy",
                MEDIUM,
                "Уберите 'unsafe-inline' и 'unsafe-eval'; используйте nonce или hash для скриптов.",
                f"Content-Security-Policy: {csp}",
                kind="csp_unsafe",
            )
        elif "*" in lowered and "default-src *" in lowered.replace("'", ""):
            add(
                "Слишком широкая политика Content-Security-Policy",
                LOW,
                "Замените подстановочный символ * на конкретные источники.",
                f"Content-Security-Policy: {csp} (найдено: {', '.join(weak)})",
                kind="csp_wildcard",
            )
        if "default-src" not in lowered and "script-src" not in lowered:
            add(
                "В Content-Security-Policy нет директив default-src/script-src",
                LOW,
                "Задайте default-src 'self' как базовое правило и уточните script-src.",
                f"Content-Security-Policy: {csp}",
                kind="csp_no_default",
            )
        if "frame-ancestors" not in lowered and not _first(multi, "x-frame-options"):
            add(
                "Нет защиты от встраивания в iframe (frame-ancestors / X-Frame-Options)",
                MEDIUM,
                "Добавьте frame-ancestors 'self' в CSP либо заголовок X-Frame-Options: DENY.",
                f"Content-Security-Policy: {csp}",
                kind="csp_no_frame_ancestors",
            )

    hsts = _first(multi, "strict-transport-security")
    if page.is_https:
        if not hsts:
            add(
                "Отсутствует заголовок Strict-Transport-Security",
                MEDIUM,
                "Добавьте Strict-Transport-Security: max-age=31536000; includeSubDomains для "
                "HTTPS-ответов.",
                "Заголовок Strict-Transport-Security не найден в HTTPS-ответе.",
                kind="hsts_missing",
            )
        else:
            max_age = parse_max_age(hsts)
            if max_age is None:
                add(
                    "Некорректный Strict-Transport-Security: не задан max-age",
                    LOW,
                    "Укажите max-age, например max-age=31536000.",
                    f"Strict-Transport-Security: {hsts}",
                    kind="hsts_no_max_age",
                )
            elif max_age < HSTS_MIN_AGE:
                add(
                    "Слишком малое значение max-age в Strict-Transport-Security",
                    LOW,
                    f"Увеличьте max-age минимум до {HSTS_MIN_AGE} (180 дней), рекомендуется 31536000.",
                    f"Strict-Transport-Security: {hsts}",
                    kind="hsts_short",
                )
            if "includesubdomains" not in hsts.lower():
                add(
                    "В Strict-Transport-Security нет includeSubDomains",
                    LOW,
                    "Добавьте директиву includeSubDomains, если все поддомены работают по HTTPS.",
                    f"Strict-Transport-Security: {hsts}",
                    kind="hsts_no_subdomains",
                )
    elif hsts:
        add(
            "Strict-Transport-Security отдаётся по HTTP",
            LOW,
            "Браузеры игнорируют HSTS в HTTP-ответах — заголовок нужно отдавать по HTTPS.",
            f"Strict-Transport-Security: {hsts}",
            kind="hsts_over_http",
        )

    xfo = _first(multi, "x-frame-options")
    if xfo:
        value = xfo.strip().lower()
        if value.startswith("allow-from"):
            add(
                "Устаревшее значение X-Frame-Options: ALLOW-FROM",
                LOW,
                "ALLOW-FROM не поддерживается современными браузерами — используйте CSP "
                "frame-ancestors.",
                f"X-Frame-Options: {xfo}",
                kind="xfo_allow_from",
            )
        elif value not in ("deny", "sameorigin"):
            add(
                "Некорректное значение X-Frame-Options",
                LOW,
                "Допустимые значения: DENY или SAMEORIGIN.",
                f"X-Frame-Options: {xfo}",
                kind="xfo_invalid",
            )
    elif not csp or "frame-ancestors" not in csp.lower():
        add(
            "Отсутствует заголовок X-Frame-Options",
            MEDIUM,
            "Добавьте X-Frame-Options: DENY (или SAMEORIGIN) для защиты от clickjacking.",
            "Заголовок X-Frame-Options не найден в ответе.",
            kind="xfo_missing",
        )

    xcto = _first(multi, "x-content-type-options")
    if not xcto:
        add(
            "Отсутствует заголовок X-Content-Type-Options",
            LOW,
            "Добавьте X-Content-Type-Options: nosniff.",
            "Заголовок X-Content-Type-Options не найден в ответе.",
            kind="xcto_missing",
        )
    elif xcto.strip().lower() != "nosniff":
        add(
            "Некорректное значение X-Content-Type-Options",
            LOW,
            "Единственное корректное значение — nosniff.",
            f"X-Content-Type-Options: {xcto}",
            kind="xcto_invalid",
        )

    referrer = _first(multi, "referrer-policy")
    if not referrer:
        add(
            "Отсутствует заголовок Referrer-Policy",
            LOW,
            "Добавьте Referrer-Policy: strict-origin-when-cross-origin.",
            "Заголовок Referrer-Policy не найден в ответе.",
            kind="referrer_missing",
        )
    else:
        values = [v.strip().lower() for v in referrer.split(",") if v.strip()]
        if any(value == "unsafe-url" for value in values):
            add(
                "Небезопасное значение Referrer-Policy: unsafe-url",
                LOW,
                "Используйте strict-origin-when-cross-origin или no-referrer.",
                f"Referrer-Policy: {referrer}",
                kind="referrer_unsafe",
            )
        elif not any(value in SAFE_REFERRER_POLICIES for value in values):
            add(
                "Нераспознанное значение Referrer-Policy",
                LOW,
                "Проверьте значение: браузер применит политику по умолчанию.",
                f"Referrer-Policy: {referrer}",
                kind="referrer_unknown",
            )

    xss_protection = _first(multi, "x-xss-protection")
    if xss_protection and not xss_protection.strip().startswith("0"):
        add(
            "Включён устаревший фильтр X-XSS-Protection",
            LOW,
            "Замените заголовок на X-XSS-Protection: 0 и полагайтесь на Content-Security-Policy: "
            "встроенный фильтр браузеров снят с поддержки и сам мог создавать уязвимости.",
            f"X-XSS-Protection: {xss_protection}",
            kind="xss_protection_legacy",
        )

    if page.is_https and not _first(multi, "cross-origin-opener-policy"):
        add(
            "Отсутствует заголовок Cross-Origin-Opener-Policy",
            LOW,
            "Добавьте Cross-Origin-Opener-Policy: same-origin, чтобы окно сайта не делило "
            "процесс и объект window со сторонними страницами.",
            "Заголовок Cross-Origin-Opener-Policy не найден в ответе.",
            kind="coop_missing",
        )

    if page.is_https and not _first(multi, "cross-origin-resource-policy"):
        add(
            "Отсутствует заголовок Cross-Origin-Resource-Policy",
            LOW,
            "Добавьте Cross-Origin-Resource-Policy: same-origin (или same-site), чтобы "
            "сторонние сайты не могли незаметно подгружать ваши ресурсы.",
            "Заголовок Cross-Origin-Resource-Policy не найден в ответе.",
            kind="corp_missing",
        )

    acao = _first(multi, "access-control-allow-origin")
    if acao:
        credentials = _first(multi, "access-control-allow-credentials").lower() == "true"
        if acao == "*" or credentials:
            add(
                "Страница отдаётся с разрешением на чтение сторонними сайтами (CORS)",
                MEDIUM if credentials else LOW,
                "Уберите Access-Control-Allow-Origin с обычных страниц: он нужен только тем "
                "адресам, к которым действительно обращаются сторонние приложения. "
                "Сочетание значения * с Access-Control-Allow-Credentials: true браузеры "
                "считают ошибкой конфигурации.",
                f"Access-Control-Allow-Origin: {acao}\n"
                f"Access-Control-Allow-Credentials: "
                f"{_first(multi, 'access-control-allow-credentials') or '(нет)'}",
                kind="page_cors_open",
            )

    if not _first(multi, "permissions-policy"):
        legacy = _first(multi, "feature-policy")
        add(
            "Отсутствует заголовок Permissions-Policy",
            LOW,
            "Ограничьте доступ к API браузера, например: "
            "Permissions-Policy: geolocation=(), camera=(), microphone=().",
            f"Найден устаревший Feature-Policy: {legacy}" if legacy
            else "Заголовок Permissions-Policy не найден в ответе.",
            kind="permissions_missing",
        )

    findings.extend(_check_duplicates(page, multi, request_line))
    return findings


def _check_duplicates(page: Page, multi, request_line: str) -> List[Finding]:
    """Дублирующиеся и противоречащие друг другу заголовки."""
    findings: List[Finding] = []
    watched = SECURITY_HEADERS + ("access-control-allow-origin", "content-type", "location")
    for name in watched:
        values = multi.get(name, [])
        # Некоторые серверы/прокси склеивают повторы через запятую — это тоже дубль
        joined = values[0] if len(values) == 1 else ""
        implicit_duplicate = (
            name in ("x-frame-options", "x-content-type-options", "access-control-allow-origin")
            and "," in joined
        )
        if len(values) > 1 or implicit_duplicate:
            shown = values if len(values) > 1 else [joined]
            distinct = {v.strip().lower() for v in shown}
            conflicting = len(distinct) > 1 or implicit_duplicate
            findings.append(
                Finding(
                    url=page.url,
                    title=(f"Противоречащие копии заголовка {name}" if conflicting
                           else f"Дублирующийся заголовок {name}"),
                    category=CONFIG,
                    severity=MEDIUM if conflicting else LOW,
                    recommendation="Заголовок должен отдаваться один раз с одним значением. "
                                   "Проверьте настройки приложения, веб-сервера и обратного прокси "
                                   "— браузеры могут игнорировать противоречивые значения.",
                    request=request_line,
                    evidence=truncate("; ".join(f"{name}: {v}" for v in shown), 500),
                    confidence=CONFIRMED,
                    kind="header_conflict" if conflicting else "header_duplicate",
                )
            )
    return findings


def _first(multi, name: str) -> str:
    values = multi.get(name, [])
    return values[0].strip() if values else ""
