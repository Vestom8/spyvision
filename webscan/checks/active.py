"""Активные, но безопасные проверки уязвимостей (раздел 4 требований).

Проверяются отражённый XSS, признаки SQL-инъекции и открытый редирект.
Эксплуатация не выполняется: отправляются только маркерные строки, ответы
анализируются, никаких данных не изменяется и не удаляется.
"""

import difflib
import re
from dataclasses import dataclass, field
from itertools import zip_longest
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..http_client import HttpClient
from ..models import (CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, VULN, Finding, Form, Page)
from ..utils import build_url, describe_request, query_params, snippet, truncate

MARKER = "BAUMAN_TEST_92841"
XSS_PAYLOAD = f"{MARKER}\"'><x-{MARKER}>"
SQLI_PAYLOADS = ("'", "\"", "\\")
REDIRECT_PAYLOAD = "https://evil.com"
REDIRECT_HOST = "evil.com"
BASELINE_VALUE = "BAUMAN_BASE_1"

# Шаблонная инъекция: если движок шаблонов выполнит выражение, 7*191 превратится
# в 1337 рядом с маркером — совпадение случайно возникнуть не может.
SSTI_MARKER = "BAUMANSSTI"
SSTI_PAYLOAD = SSTI_MARKER + "{{7*191}}${7*191}"
SSTI_RESULT = "1337"

# Чтение файлов: запрашиваются только заведомо безвредные системные файлы,
# ничего не изменяется и не сохраняется.
LFI_PAYLOADS: Tuple[Tuple[str, Tuple[str, ...], str], ...] = (
    ("../../../../../../etc/passwd", ("root:x:0:0", "root:*:0:0", "daemon:x:"), "/etc/passwd"),
    ("..\\..\\..\\..\\..\\..\\windows\\win.ini", ("[fonts]", "[extensions]",
                                                 "for 16-bit app support"), "windows\\win.ini"),
)

# Разделение заголовков: значение содержит закодированные CR и LF и пробный заголовок.
CRLF_HEADER = "x-bauman-crlf"
CRLF_RAW = f"BAUMANCRLF%0d%0a{CRLF_HEADER}:%20injected"
CRLF_PLACEHOLDER = "BAUMANCRLFPLACEHOLDER"

# Внедрение команд ОС: отправляется имя несуществующей команды. Ничего не
# выполняется и не изменяется — интерес представляет только текст ошибки оболочки.
CMD_MARKER = "BAUMANCMD"
CMD_PAYLOAD = f"1;{CMD_MARKER}"
CMD_ERROR_MARKERS = (
    f"{CMD_MARKER}: not found",
    f"{CMD_MARKER}: command not found",
    "sh: 1:",
    "/bin/sh:",
    "command not found",
    "is not recognized as an internal or external command",
    "syntax error near unexpected token",
)

# Сколько точек внедрения проверять дополнительными (более дорогими) тестами
EXTRA_TARGET_LIMIT = 8

# Обход WAF / простых фильтров: альтернативные XSS и SQLi payloads
WAF_XSS_PAYLOADS = (
    f"<Svg/onload=confirm('{MARKER}')>",
    f"\"><img src=x onerror=alert('{MARKER}')>",
    f"<details/open/ontoggle=alert('{MARKER}')>",
    f"<img src=x onerror=alert`{MARKER}`>",
)
WAF_SQLI_PAYLOADS = (
    "'/**/OR/**/1=1--",
    "'%09OR%091=1--",
    "1'||'1",
)

REDIRECT_PARAM_HINTS = ("url", "redirect", "next", "return", "continue", "dest", "destination",
                        "target", "goto", "redir", "callback", "back", "link")

# Формы, отправка которых может изменить состояние приложения, активно не тестируются.
DESTRUCTIVE_HINTS = ("delete", "remove", "drop", "destroy", "logout", "signout", "unsubscribe",
                     "register", "signup", "order", "checkout", "payment", "pay", "purchase",
                     "upload", "reset", "restore", "import", "export", "install", "admin",
                     "удалить", "оплат", "заказ", "регистрац")

SQL_ERROR_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("MySQL", re.compile(r"(?i)you have an error in your sql syntax|warning:\s*mysql|"
                         r"mysql_fetch|mysqli?_|MySqlException|check the manual that corresponds")),
    ("PostgreSQL", re.compile(r"(?i)pg_query|pg_exec|psycopg2|PSQLException|"
                              r"syntax error at or near|unterminated quoted string")),
    ("SQLite", re.compile(r"(?i)sqlite3?\.(?:Operational|Programming|Database)Error|"
                          r"SQLITE_ERROR|unrecognized token|sqlite3_step")),
    ("Oracle", re.compile(r"(?i)ORA-\d{5}|quoted string not properly terminated|"
                          r"oracle\.jdbc|OracleException")),
    ("MS SQL Server", re.compile(r"(?i)unclosed quotation mark|incorrect syntax near|"
                                 r"SqlException|System\.Data\.SqlClient|SQLSTATE\[")),
    ("ORM/драйвер", re.compile(r"(?i)SQLAlchemy|OperationalError|ProgrammingError|"
                               r"IntegrityError|QueryException|ActiveRecord::StatementInvalid")),
)

# Ошибки нереляционных баз данных: тот же спецсимвол ломает разбор запроса.
NOSQL_ERROR_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("MongoDB", re.compile(r"(?i)MongoError|MongoServerError|BSONError|"
                           r"E11000 duplicate key|unknown operator: \$|"
                           r"CastError: Cast to (?:ObjectId|Number)")),
    ("Elasticsearch", re.compile(r"(?i)json_parse_exception|"
                                 r"search_phase_execution_exception|parsing_exception")),
    ("Redis", re.compile(r"(?i)WRONGTYPE Operation against|ERR unknown command")),
)

SCRIPT_CONTEXT = "внутри тега <script>"

STRUCTURE_TAG = re.compile(r"<\s*(/?[a-zA-Z0-9]+)")
COMPARE_LIMIT = 20000
META_REFRESH = re.compile(r"(?i)<meta[^>]+http-equiv=[\"']?refresh[\"']?[^>]*content=[\"'][^\"']*"
                          r"url\s*=\s*([^\"'>]+)")


@dataclass
class Target:
    """Точка внедрения: один параметр запроса или одно поле формы."""

    method: str
    action: str
    params: Dict[str, str]
    param_name: str
    page_url: str
    source: str  # "URL-параметр" или "поле формы"
    description: str = ""
    baseline_status: Optional[int] = None
    baseline_body: Optional[str] = None

    def payload_request(self, value: str) -> Tuple[str, Optional[Dict[str, str]]]:
        params = dict(self.params)
        params[self.param_name] = value
        if self.method == "GET":
            return build_url(self.action, list(params.items())), None
        return self.action, params

    def label(self) -> str:
        return f"{self.source} «{self.param_name}»"


@dataclass
class ActiveResult:
    findings: List[Finding] = field(default_factory=list)
    targets_tested: int = 0
    tests_executed: int = 0
    skipped_forms: int = 0


def build_targets(pages: List[Page], test_post_forms: bool = True,
                  max_params_per_page: int = 6) -> Tuple[List[Target], int]:
    """Собирает точки внедрения со всех страниц, чередуя страницы между собой."""
    per_page: List[List[Target]] = []
    skipped_forms = 0

    for page in pages:
        targets: List[Target] = []
        seen_params = set()
        # Адрес до редиректа тоже проверяется: параметры вида ?next=… обычно
        # существуют только в исходной ссылке.
        for source_url, redirected in ((page.url, False), (page.requested_url, True)):
            if not source_url:
                continue
            params = query_params(source_url)
            if not params:
                continue
            for name, _value in params:
                if not name or (source_url, name) in seen_params:
                    continue
                if redirected and any(name == other for _u, other in seen_params):
                    continue
                seen_params.add((source_url, name))
                targets.append(
                    Target(
                        method="GET",
                        action=source_url,
                        params=dict(params),
                        param_name=name,
                        page_url=source_url,
                        source="URL-параметр",
                        description=f"GET {source_url}",
                        baseline_status=page.status if not redirected else None,
                        baseline_body=page.body if not redirected else None,
                    )
                )
        for form in page.forms:
            if urlparse(form.action).scheme not in ("http", "https"):
                continue
            if form.method == "POST" and (not test_post_forms or _looks_destructive(form)):
                skipped_forms += 1
                continue
            if form.method == "GET" and _looks_destructive(form):
                skipped_forms += 1
                continue
            data = form.data()
            for form_field in form.testable_fields():
                targets.append(
                    Target(
                        method=form.method,
                        action=form.action,
                        params=dict(data),
                        param_name=form_field.name,
                        page_url=page.url,
                        source="поле формы",
                        description=form.describe(),
                    )
                )
        per_page.append(targets[:max_params_per_page])

    # чередование: сначала по одному параметру с каждой страницы
    interleaved = [t for group in zip_longest(*per_page) for t in group if t is not None]
    return interleaved, skipped_forms


def run_active_checks(client: HttpClient, pages: List[Page], reserve: int = 0,
                      test_post_forms: bool = True, verbose: bool = False) -> ActiveResult:
    result = ActiveResult()
    targets, result.skipped_forms = build_targets(pages, test_post_forms=test_post_forms)
    if not targets:
        return result

    baseline_cache: Dict[Tuple[str, str], Tuple[Optional[int], Optional[str]]] = {}
    tested_targets = set()

    # Очередь задач: сначала самые результативные проверки для всех точек,
    # затем более дорогие — для ограниченного числа точек.
    extra = targets[:EXTRA_TARGET_LIMIT]
    tasks: List[Tuple[str, Target, str]] = []
    tasks += [("xss", t, XSS_PAYLOAD) for t in targets]
    tasks += [("sqli", t, SQLI_PAYLOADS[0]) for t in targets]
    tasks += [("redirect", t, REDIRECT_PAYLOAD) for t in targets
              if _is_redirect_param(t.param_name)]
    tasks += [("ssti", t, SSTI_PAYLOAD) for t in extra]
    tasks += [("lfi", t, LFI_PAYLOADS[0][0]) for t in extra]
    tasks += [("lfi", t, LFI_PAYLOADS[1][0]) for t in extra[:4]]
    tasks += [("cmd", t, CMD_PAYLOAD) for t in extra]
    tasks += [("crlf", t, CRLF_PLACEHOLDER) for t in extra if t.method == "GET"]
    # дополнительные SQLi-payloads — только на extra-точках (экономия бюджета)
    for payload in SQLI_PAYLOADS[1:]:
        tasks += [("sqli", t, payload) for t in extra]
    # WAF-bypass: ограниченное число точек
    waf_targets = targets[: min(3, EXTRA_TARGET_LIMIT)]
    for payload in WAF_XSS_PAYLOADS[:3]:
        tasks += [("xss_waf", t, payload) for t in waf_targets]
    for payload in WAF_SQLI_PAYLOADS[:2]:
        tasks += [("sqli_waf", t, payload) for t in waf_targets]

    reported_sqli = set()
    reported_xss = set()
    reported_extra = set()
    reported_waf = set()
    for kind, target, payload in tasks:
        if not client.can_request(reserve):
            break
        target_key = (target.method, target.action, target.param_name)
        if kind == "sqli":
            # Одной находки на параметр достаточно: остальные payload'ы
            # только расходовали бы лимит запросов.
            if target_key in reported_sqli:
                continue
            if target.baseline_body is None and not _load_baseline(
                client, target, baseline_cache, reserve
            ):
                continue
        if kind == "sqli_waf":
            if target_key in reported_sqli or ("sqli_waf", target_key) in reported_waf:
                continue
            if target.baseline_body is None and not _load_baseline(
                client, target, baseline_cache, reserve
            ):
                continue
        if kind == "xss_waf":
            # если классический XSS уже подтверждён — обход WAF здесь лишний
            if target_key in reported_xss or ("xss_waf", target_key) in reported_waf:
                continue
        if kind in ("ssti", "lfi", "crlf", "cmd") and (kind, target_key) in reported_extra:
            continue

        url, data = target.payload_request(payload)
        if kind == "crlf":
            # значение подставляется без повторного кодирования: нужны «сырые» %0d%0a
            url = url.replace(CRLF_PLACEHOLDER, CRLF_RAW)
        follow = kind not in ("redirect", "crlf")
        response = client.request(target.method, url, data=data, allow_redirects=follow,
                                 reserve=reserve)
        if response is None:
            continue
        result.tests_executed += 1
        tested_targets.add(target_key)

        if kind == "xss":
            xss_found = _analyze_xss(target, response, url, data)
            if xss_found and any(f.kind != "xss_escaped" for f in xss_found):
                reported_xss.add(target_key)
            result.findings.extend(xss_found)
        elif kind == "xss_waf":
            found = _analyze_xss_waf(target, response, url, data, payload)
            if found:
                reported_waf.add(("xss_waf", target_key))
                reported_xss.add(target_key)
            result.findings.extend(found)
        elif kind == "sqli":
            sqli_findings = _analyze_sqli(target, response, url, data, payload)
            if sqli_findings:
                reported_sqli.add(target_key)
            result.findings.extend(sqli_findings)
        elif kind == "sqli_waf":
            sqli_findings = _analyze_sqli(target, response, url, data, payload)
            if sqli_findings:
                reported_sqli.add(target_key)
                reported_waf.add(("sqli_waf", target_key))
                result.findings.extend([
                    Finding(
                        url=f.url,
                        title=f"SQLi с обходом WAF/фильтра — {target.label()}",
                        kind="sqli_waf_bypass",
                        category=VULN,
                        severity=f.severity,
                        recommendation=f.recommendation,
                        request=f.request,
                        evidence=truncate(
                            f"WAF-bypass payload: {payload}\n{f.evidence}", 1600
                        ),
                        confidence=f.confidence,
                    )
                    for f in sqli_findings
                ])
        elif kind == "ssti":
            found = _analyze_ssti(target, response, url, data)
            if found:
                reported_extra.add((kind, target_key))
            result.findings.extend(found)
        elif kind == "lfi":
            found = _analyze_lfi(target, response, url, data, payload)
            if found:
                reported_extra.add((kind, target_key))
            result.findings.extend(found)
        elif kind == "cmd":
            found = _analyze_command_injection(target, response, url, data)
            if found:
                reported_extra.add((kind, target_key))
            result.findings.extend(found)
        elif kind == "crlf":
            found = _analyze_crlf(target, response, url, data)
            if found:
                reported_extra.add((kind, target_key))
            result.findings.extend(found)
        else:
            result.findings.extend(_analyze_redirect(target, response, url, data))

    result.targets_tested = len(tested_targets)
    return result


# --- отражённый XSS -------------------------------------------------------
def _analyze_xss(target: Target, response, url: str, data) -> List[Finding]:
    body = _text(response)
    if not body or MARKER not in body:
        return []
    content_type = response.headers.get("Content-Type", "").lower()
    is_html = "html" in content_type or (not content_type and "<html" in body.lower())
    request_text = describe_request(target.method, url, data)

    raw_reflected = XSS_PAYLOAD in body or f"<x-{MARKER}>" in body
    quote_reflected = f"{MARKER}\"" in body or f"{MARKER}'" in body
    context = _reflection_context(body)

    if context == SCRIPT_CONTEXT and (raw_reflected or quote_reflected):
        return [
            Finding(
                url=target.page_url,
                title=f"Ввод попадает внутрь скрипта страницы: {target.label()}",
                kind="xss_js_context",
                category=VULN,
                severity=HIGH,
                recommendation="Не вставляйте пользовательские данные прямо в текст скрипта. "
                               "Передавайте их через JSON-кодирование (JSON.stringify на "
                               "сервере) или через атрибут data-* и читайте из DOM. "
                               "HTML-экранирования здесь недостаточно: внутри <script> "
                               "опасны кавычки и последовательность </script>.",
                request=request_text,
                evidence=truncate(
                    f"Ответ HTTP/{response.status_code}, Content-Type: {content_type or '-'}\n"
                    f"Тестовая строка вернулась внутри тега <script> с неэкранированными "
                    f"спецсимволами:\n{snippet(body, MARKER, 320)}",
                    1600,
                ),
                confidence=SUSPECTED,
            )
        ]

    if raw_reflected:
        return [
            Finding(
                url=target.page_url,
                title=f"Подозрение на отражённый XSS: {target.label()}",
                kind="xss_unescaped",
                category=VULN,
                severity=HIGH if is_html else MEDIUM,
                recommendation="Экранируйте выводимые данные в соответствии с контекстом "
                               "(HTML-сущности для текста, экранирование кавычек в атрибутах, "
                               "JSON-кодирование в скриптах), используйте автоэкранирование "
                               "шаблонизатора и добавьте CSP без 'unsafe-inline'.",
                request=request_text,
                evidence=truncate(
                    f"Ответ HTTP/{response.status_code}, Content-Type: {content_type or '-'}\n"
                    f"Контекст отражения: {context}\n"
                    f"Тестовая строка вернулась без HTML-экранирования:\n"
                    f"{snippet(body, MARKER, 320)}",
                    1600,
                ),
                confidence=SUSPECTED,
            )
        ]

    if quote_reflected and is_html:
        return [
            Finding(
                url=target.page_url,
                title=f"Кавычки не экранируются при выводе: {target.label()}",
                kind="xss_quotes",
                category=VULN,
                severity=MEDIUM,
                recommendation="Экранируйте кавычки при выводе в HTML-атрибуты и JavaScript. "
                               "Угловые скобки экранируются, но незакрытая кавычка позволяет "
                               "выйти из значения атрибута.",
                request=request_text,
                evidence=truncate(snippet(body, MARKER, 320), 1400),
                confidence=SUSPECTED,
            )
        ]

    if is_html:
        return [
            Finding(
                url=target.page_url,
                title=f"Ввод отражается в ответе, но экранируется: {target.label()}",
                kind="xss_escaped",
                category=VULN,
                severity=INFO,
                recommendation="Признаков XSS не обнаружено: специальные символы преобразованы "
                               "в HTML-сущности. Отдельно проверьте вывод в JavaScript и "
                               "обработчики событий.",
                request=request_text,
                evidence=truncate(snippet(body, MARKER, 240), 1000),
                confidence=CONFIRMED,
            )
        ]
    return []


def _analyze_xss_waf(target: Target, response, url: str, data, payload: str) -> List[Finding]:
    """XSS через payload, рассчитанный на обход простых WAF/фильтров."""
    body = _text(response)
    if not body or MARKER not in body:
        return []
    if response.status_code in (403, 406, 419, 429):
        return []
    dangerous = (
        ("onerror" in body.lower() and MARKER in body)
        or ("onload" in body.lower() and MARKER in body)
        or ("ontoggle" in body.lower() and MARKER in body)
        or f"<Svg/onload=confirm('{MARKER}')>" in body
        or f"<svg/onload=confirm('{MARKER}')>" in body.lower()
    )
    if not dangerous:
        return []
    return [
        Finding(
            url=target.page_url,
            title=f"XSS с обходом WAF/фильтра: {target.label()}",
            kind="xss_waf_bypass",
            category=VULN,
            severity=HIGH,
            recommendation="Не полагайтесь только на WAF; экранируйте вывод контекстно, "
                           "ужесточите CSP, обновляйте правила фильтрации.",
            request=describe_request(target.method, url, data),
            evidence=truncate(
                f"WAF-bypass payload отразился с обработчиком события:\n"
                f"payload={payload}\n{snippet(body, MARKER, 320)}",
                1600,
            ),
            confidence=CONFIRMED,
        )
    ]


def _reflection_context(body: str) -> str:
    index = body.find(MARKER)
    before = body[max(0, index - 300):index].lower()
    if before.rfind("<script") > before.rfind("</script"):
        return SCRIPT_CONTEXT
    last_tag_open = before.rfind("<")
    last_tag_close = before.rfind(">")
    if last_tag_open > last_tag_close:
        return "внутри атрибута HTML-тега"
    return "в тексте HTML-документа"


# --- SQL-инъекция ---------------------------------------------------------
def _analyze_sqli(target: Target, response, url: str, data, payload: str) -> List[Finding]:
    body = _text(response)
    baseline_body = target.baseline_body or ""
    baseline_status = target.baseline_status
    request_text = describe_request(target.method, url, data)
    payload_view = payload.replace("\\", "\\\\")

    for engine, pattern in NOSQL_ERROR_PATTERNS:
        match = pattern.search(body)
        if match and not pattern.search(baseline_body):
            return [
                Finding(
                    url=target.page_url,
                    title=f"Подозрение на инъекцию в запрос к базе {engine}: {target.label()}",
                    kind="nosqli_error",
                    category=VULN,
                    severity=HIGH,
                    recommendation="Передавайте пользовательские значения в запрос только как "
                                   "данные, приводя их к ожидаемому типу (строка, число, "
                                   "идентификатор). Не собирайте условия запроса из строк и не "
                                   "передавайте в них объекты, пришедшие от клиента: так в "
                                   "запрос попадают операторы вида $ne и $where.",
                    request=request_text,
                    evidence=truncate(
                        f"Отправлено значение параметра: {payload_view}\n"
                        f"Ответ HTTP/{response.status_code} (обычный ответ: {baseline_status})\n"
                        f"Сообщение об ошибке базы данных в ответе:\n"
                        f"{snippet(body, match.group(0), 320)}",
                        1600,
                    ),
                    confidence=SUSPECTED,
                )
            ]

    for engine, pattern in SQL_ERROR_PATTERNS:
        match = pattern.search(body)
        if match and not pattern.search(baseline_body):
            return [
                Finding(
                    url=target.page_url,
                    title=f"Подозрение на SQL-инъекцию ({engine}): {target.label()}",
                    kind="sqli_error",
                    category=VULN,
                    severity=HIGH,
                    recommendation="Используйте параметризованные запросы (prepared statements) "
                                   "вместо конкатенации строк, проверяйте типы входных данных и "
                                   "скройте текст ошибок БД от пользователя.",
                    request=request_text,
                    evidence=truncate(
                        f"Отправлено значение параметра: {payload_view}\n"
                        f"Ответ HTTP/{response.status_code} (обычный ответ: {baseline_status})\n"
                        f"Сообщение об ошибке СУБД в ответе:\n{snippet(body, match.group(0), 320)}",
                        1600,
                    ),
                    confidence=SUSPECTED,
                )
            ]

    if baseline_status is not None and response.status_code != baseline_status:
        # Только ошибки сервера: 4xx обычно означает, что значение попало
        # в маршрут или было отклонено валидацией, и это не признак инъекции.
        if response.status_code >= 500:
            return [
                Finding(
                    url=target.page_url,
                    title=f"Ошибка обработки спецсимвола в параметре: {target.label()}",
                    kind="sqli_status",
                    category=VULN,
                    severity=MEDIUM,
                    recommendation="Одиночная кавычка не должна ломать обработку запроса. "
                                   "Проверьте, что значение параметра передаётся в БД через "
                                   "параметризованный запрос, и добавьте валидацию входных данных.",
                    request=request_text,
                    evidence=truncate(
                        f"Отправлено значение параметра: {payload_view}\n"
                        f"Статус изменился: {baseline_status} -> {response.status_code}\n"
                        f"Фрагмент ответа:\n{truncate(body.strip(), 700)}",
                        1400,
                    ),
                    confidence=SUSPECTED,
                )
            ]

    if baseline_body and body:
        if _structure_changed(baseline_body, body):
            return [
                Finding(
                    url=target.page_url,
                    title=f"Структура ответа меняется от спецсимвола: {target.label()}",
                    kind="sqli_structure",
                    category=VULN,
                    severity=LOW,
                    recommendation="Изменение структуры страницы при подстановке кавычки может "
                                   "указывать на то, что значение попадает в SQL-запрос. "
                                   "Проверьте обработку параметра вручную и используйте "
                                   "параметризованные запросы.",
                    request=request_text,
                    evidence=truncate(
                        f"Отправлено значение параметра: {payload_view}\n"
                        f"Размер обычного ответа: {len(baseline_body)} симв., "
                        f"с тестовым значением: {len(body)} симв.\n"
                        f"Набор HTML-тегов ответа изменился.",
                        600,
                    ),
                    confidence=SUSPECTED,
                )
            ]
    return []


def _structure_changed(baseline: str, body: str) -> bool:
    base_tags = STRUCTURE_TAG.findall(baseline[:COMPARE_LIMIT])
    test_tags = STRUCTURE_TAG.findall(body[:COMPARE_LIMIT])
    if not base_tags and not test_tags:
        return False
    if len(base_tags) != len(test_tags):
        ratio = difflib.SequenceMatcher(None, base_tags, test_tags).quick_ratio()
        return ratio < 0.9
    length_delta = abs(len(baseline) - len(body))
    threshold = max(120, int(0.25 * max(len(baseline), 1)))
    return length_delta > threshold


# --- открытый редирект ----------------------------------------------------
def _analyze_redirect(target: Target, response, url: str, data) -> List[Finding]:
    location = response.headers.get("Location", "")
    request_text = describe_request(target.method, url, data)
    if location and REDIRECT_HOST in location.lower():
        parsed = urlparse(location if "//" in location else "//" + location)
        external = (parsed.hostname or "").lower().endswith(REDIRECT_HOST)
        return [
            Finding(
                url=target.page_url,
                title=f"Открытый редирект: {target.label()}",
                kind="open_redirect",
                category=VULN,
                severity=MEDIUM if external else LOW,
                recommendation="Не подставляйте пользовательский адрес в Location. Используйте "
                               "белый список разрешённых адресов или разрешайте только "
                               "относительные пути (проверяя, что значение начинается с одного «/»). "
                               "Открытый редирект используется в фишинге для маскировки ссылок.",
                request=request_text,
                evidence=truncate(
                    f"Ответ HTTP/{response.status_code}\nLocation: {location}\n"
                    f"(переход по адресу не выполнялся)",
                    500,
                ),
                confidence=CONFIRMED if external else SUSPECTED,
            )
        ]

    body = _text(response)
    match = META_REFRESH.search(body or "")
    if match and REDIRECT_HOST in match.group(1).lower():
        return [
            Finding(
                url=target.page_url,
                title=f"Открытый редирект через meta refresh: {target.label()}",
                kind="open_redirect_meta",
                category=VULN,
                severity=LOW,
                recommendation="Проверяйте адрес перед подстановкой в meta refresh или "
                               "используйте белый список адресов.",
                request=request_text,
                evidence=truncate(f"HTTP/{response.status_code}\n{match.group(0)}", 400),
                confidence=SUSPECTED,
            )
        ]
    return []


# --- инъекция в шаблон (SSTI) ---------------------------------------------
def _analyze_ssti(target: Target, response, url: str, data) -> List[Finding]:
    body = _text(response)
    if not body or SSTI_MARKER not in body:
        return []
    index = body.find(SSTI_MARKER)
    window = body[index:index + 80]
    if SSTI_RESULT not in window:
        return []
    return [
        Finding(
            url=target.page_url,
            title=f"Инъекция в шаблон на сервере (SSTI): {target.label()}",
            kind="ssti",
            category=VULN,
            severity=HIGH,
            recommendation="Не подставляйте пользовательские данные в текст шаблона: передавайте "
                           "их как значения переменных, а не как часть самого шаблона. Если "
                           "пользовательские шаблоны нужны, выполняйте их в песочнице с "
                           "ограниченным набором функций.",
            request=describe_request(target.method, url, data),
            evidence=truncate(
                f"Отправлено: {SSTI_PAYLOAD}\n"
                f"В ответе выражение 7*191 вычислено сервером:\n"
                f"{snippet(body, SSTI_MARKER, 120)}",
                700,
            ),
            confidence=CONFIRMED,
        )
    ]


# --- чтение файлов сервера (path traversal / LFI) -------------------------
def _analyze_lfi(target: Target, response, url: str, data, payload: str) -> List[Finding]:
    body = _text(response)
    if not body:
        return []
    for probe, markers, human in LFI_PAYLOADS:
        if probe != payload:
            continue
        for marker in markers:
            if marker.lower() in body.lower():
                return [
                    Finding(
                        url=target.page_url,
                        title=f"Чтение файлов сервера через параметр: {target.label()}",
                        kind="lfi_traversal",
                        category=VULN,
                        severity=HIGH,
                        recommendation="Не подставляйте значение параметра в путь к файлу. "
                                       "Используйте белый список допустимых имён или "
                                       "идентификаторы вместо путей; при необходимости "
                                       "приводите путь к каноническому виду и проверяйте, что "
                                       "он остаётся внутри разрешённого каталога.",
                        request=describe_request(target.method, url, data),
                        evidence=truncate(
                            f"Запрошен системный файл {human} (только чтение)\n"
                            f"Ответ HTTP/{response.status_code}; в теле найдено содержимое файла:\n"
                            f"{snippet(body, marker, 160)}",
                            800,
                        ),
                        confidence=CONFIRMED,
                    )
                ]
    return []


# --- выполнение команд операционной системы -------------------------------
def _analyze_command_injection(target: Target, response, url: str, data) -> List[Finding]:
    body = _text(response)
    if not body:
        return []
    lowered = body.lower()
    baseline = (target.baseline_body or "").lower()
    for marker in CMD_ERROR_MARKERS:
        if marker.lower() in lowered and marker.lower() not in baseline:
            return [
                Finding(
                    url=target.page_url,
                    title=f"Подозрение на выполнение команд ОС: {target.label()}",
                    kind="command_injection",
                    category=VULN,
                    severity=HIGH,
                    recommendation="Не передавайте значения параметров в командную оболочку. "
                                   "Вызывайте программы напрямую, списком аргументов, без "
                                   "shell=True и без склейки строк; проверяйте значение по "
                                   "белому списку. Выполнение команд означает полный контроль "
                                   "над сервером.",
                    request=describe_request(target.method, url, data),
                    evidence=truncate(
                        f"Отправлено значение параметра: {CMD_PAYLOAD} "
                        f"(имя несуществующей команды, ничего не выполняется)\n"
                        f"Ответ HTTP/{response.status_code}; в теле — сообщение командной "
                        f"оболочки:\n{snippet(body, marker, 160)}",
                        800,
                    ),
                    confidence=SUSPECTED,
                )
            ]
    return []


# --- разделение заголовков (CRLF-инъекция) --------------------------------
def _analyze_crlf(target: Target, response, url: str, data) -> List[Finding]:
    injected = {name.lower() for name in response.headers}
    location = response.headers.get("Location", "")
    in_location = CRLF_HEADER in location.lower()
    if CRLF_HEADER not in injected and not in_location:
        return []
    return [
        Finding(
            url=target.page_url,
            title=f"Разделение HTTP-заголовков (CRLF-инъекция): {target.label()}",
            kind="crlf_injection",
            category=VULN,
            severity=HIGH,
            recommendation="Удаляйте символы перевода строки (%0d, %0a) из значений, которые "
                           "попадают в заголовки ответа — прежде всего в Location и Set-Cookie. "
                           "В большинстве фреймворков для этого достаточно использовать "
                           "штатные функции установки заголовков вместо ручной сборки.",
            request=describe_request(target.method, url, data),
            evidence=truncate(
                f"Ответ HTTP/{response.status_code}\n"
                f"Тестовый заголовок оказался в ответе сервера: {CRLF_HEADER}\n"
                + (f"Location: {location}" if location else ""),
                600,
            ),
            confidence=CONFIRMED,
        )
    ]


# --- вспомогательное ------------------------------------------------------
def _load_baseline(client: HttpClient, target: Target,
                   cache: Dict[Tuple[str, str], Tuple[Optional[int], Optional[str]]],
                   reserve: int) -> bool:
    """Получает «обычный» ответ для сравнения (для форм)."""
    key = (target.method, target.action)
    if key in cache:
        target.baseline_status, target.baseline_body = cache[key]
        return target.baseline_body is not None
    if not client.can_request(reserve):
        return False
    params = {name: (value or BASELINE_VALUE) for name, value in target.params.items()}
    if target.method == "GET":
        url, data = build_url(target.action, list(params.items())), None
    else:
        url, data = target.action, params
    response = client.request(target.method, url, data=data, reserve=reserve)
    if response is None:
        cache[key] = (None, None)
        return False
    cache[key] = (response.status_code, _text(response))
    target.baseline_status, target.baseline_body = cache[key]
    return True


def _is_redirect_param(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in REDIRECT_PARAM_HINTS)


def _looks_destructive(form: Form) -> bool:
    haystack = (form.action + " " + " ".join(f.name for f in form.fields)).lower()
    return any(hint in haystack for hint in DESTRUCTIVE_HINTS)


def _text(response) -> str:
    try:
        return response.text or ""
    except Exception:
        return ""
