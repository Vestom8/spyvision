"""Активные, но безопасные проверки уязвимостей (раздел 4 требований).

Проверяются отражённый XSS, признаки SQL-инъекции и открытый редирект.
Эксплуатация не выполняется: отправляются только маркерные строки, ответы
анализируются, никаких данных не изменяется и не удаляется.
"""

import difflib
import re
import time
from dataclasses import dataclass, field
from itertools import zip_longest
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..http_client import HttpClient
from ..models import (CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, VULN, Finding, Form, Page)
from ..utils import build_url, describe_request, query_params, snippet, truncate

MARKER = "BAUMAN_TEST_92841"
XSS_PAYLOAD = f"{MARKER}\"'><x-{MARKER}>"
# Дополнительные DAST-маркеры (без эксплуатации — только отражение/ошибки)
XSS_PAYLOADS_EXTRA = (
    f"<img src=x onerror=alert('{MARKER}')>",
    f"<svg/onload=confirm('{MARKER}')>",
    f"\"'><script>/*{MARKER}*/</script>",
)
SQLI_PAYLOADS = ("'", "\"", "\\")
SQLI_PAYLOADS_EXTRA = (
    f"' OR '{MARKER}'='{MARKER}",
    f"1' AND '{MARKER}'='{MARKER}",
)
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
# Общие фразы («command not found», «sh: 1:») встречаются в документации и логах, поэтому
# засчитывается только сообщение оболочки, в котором названа наша несуществующая команда.
CMD_ERROR_MARKERS = (
    f"{CMD_MARKER}: not found",
    f"{CMD_MARKER}: command not found",
    f"'{CMD_MARKER}' is not recognized as an internal or external command",
    f"\"{CMD_MARKER}\" is not recognized as an internal or external command",
)

# Косвенные SQLi-признаки (код 5xx, изменившаяся структура) подтверждаются контрольной пробой:
# парная кавычка не ломает запрос, а одиночная ломает. Если «сломалось» и с парной —
# дело не в SQL, а в обработке спецсимволов или в динамической странице.
WEAK_SQLI_KINDS = frozenset({"sqli_status", "sqli_structure"})
SQLI_CONTROL_VALUES = {"'": "''", "\"": "\"\"", "\\": "\\\\"}

# Булева слепая SQL-инъекция: TRUE-условие должно вести себя как обычный
# ответ, FALSE — заметно отличаться. Три формы контекста (одиночная кавычка,
# двойная кавычка, число) покрывают большинство типовых запросов.
BOOLEAN_SQLI_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("' OR '1'='1", "' AND '1'='2"),
    ('" OR "1"="1', '" AND "1"="2'),
    (" OR 1=1", " AND 1=2"),
)

# SQL-инъекция по времени (слепая, без видимой разницы в содержимом ответа):
# пауза короче жёсткого таймаута клиента (5 с), с запасом на сетевую задержку.
TIME_SQLI_SECONDS = 3
TIME_SQLI_PAYLOADS: Tuple[Tuple[str, str], ...] = (
    (f"' OR SLEEP({TIME_SQLI_SECONDS}) -- -", "MySQL/MariaDB"),
    (f" OR SLEEP({TIME_SQLI_SECONDS})", "MySQL/MariaDB (числовой контекст)"),
    (f"'; SELECT pg_sleep({TIME_SQLI_SECONDS}) -- -", "PostgreSQL"),
    (f"' WAITFOR DELAY '0:0:{TIME_SQLI_SECONDS}' -- -", "MS SQL Server"),
)
TIME_SQLI_CONTROL_SUFFIX = " OR SLEEP(0)"
TIME_SQLI_TARGET_LIMIT = 4  # проверка по времени дороже: не больше стольких точек

# Сколько точек внедрения проверять дополнительными (более дорогими) тестами
EXTRA_TARGET_LIMIT = 12
DEEP_TARGET_LIMIT = 5

REDIRECT_SUBSTRING_HINTS = ("redirect", "return", "continue", "destination", "callback",
                            "forward", "goto")
REDIRECT_PARAM_HINTS = ("url", "redirect", "next", "return", "continue", "dest", "destination",
                        "target", "goto", "redir", "callback", "back", "link", "returnUrl",
                        "return_url", "redirect_uri", "redirect_url", "go", "out", "view",
                        "forward", "rurl")

REDIRECT_WORD_HINTS = frozenset(hint.lower() for hint in REDIRECT_PARAM_HINTS)

# Формы, отправка которых может изменить состояние приложения, активно не тестируются.
DESTRUCTIVE_HINTS = ("delete", "remove", "drop", "destroy", "logout", "signout", "unsubscribe",
                     "register", "signup", "order", "checkout", "payment", "pay", "purchase",
                     "upload", "reset", "restore", "import", "export", "install", "admin",
                     "удалить", "оплат", "заказ", "регистрац")

SQL_ERROR_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("MySQL", re.compile(r"(?i)you have an error in your sql syntax|warning:\s*mysql|"
                         r"mysql_fetch|mysqli?_\w+\(|MySqlException|check the manual that corresponds")),
    ("PostgreSQL", re.compile(r"(?i)pg_query|pg_exec|psycopg2|PSQLException|"
                              r"syntax error at or near|unterminated quoted string")),
    ("SQLite", re.compile(r"(?i)sqlite3?\.(?:Operational|Programming|Database)Error|"
                          r"SQLITE_ERROR|unrecognized token:\s*[\"']|sqlite3_step")),
    ("Oracle", re.compile(r"(?i)ORA-\d{5}|quoted string not properly terminated|"
                          r"oracle\.jdbc|OracleException")),
    ("MS SQL Server", re.compile(r"(?i)unclosed quotation mark|incorrect syntax near|"
                                 r"SqlException|System\.Data\.SqlClient|SQLSTATE\[")),
    ("ORM/драйвер", re.compile(r"(?i)sqlalchemy\.exc\.|django\.db\.utils\.|"
                               r"\w+\.(?:OperationalError|ProgrammingError|IntegrityError)\b|"
                               r"Illuminate\\Database\\QueryException|"
                               r"ActiveRecord::StatementInvalid")),
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
                      test_post_forms: bool = True, verbose: bool = False,
                      pentest: bool = False) -> ActiveResult:
    result = ActiveResult()
    targets, result.skipped_forms = build_targets(pages, test_post_forms=test_post_forms)
    if not targets:
        return result

    baseline_cache: Dict[Tuple[str, str], Tuple[Optional[int], Optional[str]]] = {}
    tested_targets = set()

    # Очередь задач: сначала самые результативные проверки для всех точек,
    # затем более дорогие — для ограниченного числа точек.
    extra = targets[:EXTRA_TARGET_LIMIT]
    deep = targets[:DEEP_TARGET_LIMIT]
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
    for payload in SQLI_PAYLOADS[1:]:
        tasks += [("sqli", t, payload) for t in targets]
    # Углублённый DAST: альтернативные XSS/SQLi-маркеры на ограниченном наборе точек
    for payload in XSS_PAYLOADS_EXTRA:
        tasks += [("xss", t, payload) for t in deep]
    for payload in SQLI_PAYLOADS_EXTRA:
        tasks += [("sqli", t, payload) for t in deep]

    reported_sqli = set()
    weak_sqli: List[Tuple[Finding, Target, str]] = []
    reported_xss = set()
    reported_extra = set()

    def already_reported(kind, target_key) -> bool:
        if kind == "xss":
            return target_key in reported_xss
        if kind == "sqli":
            # Одной находки на параметр достаточно: остальные payload'ы
            # только расходовали бы лимит запросов.
            return target_key in reported_sqli
        if kind in ("ssti", "lfi", "crlf", "cmd"):
            return (kind, target_key) in reported_extra
        return False

    position = 0
    out_of_budget = False
    while position < len(tasks) and not out_of_budget:
        # Пачка независимых проб уходит параллельно; ответы разбираются строго по порядку
        # задач, а повторные находки по одному параметру отсекаются уже при разборе.
        batch = []
        while position < len(tasks) and len(batch) < max(1, client.concurrency):
            if not client.can_request(reserve):
                out_of_budget = True
                break
            kind, target, payload = tasks[position]
            position += 1
            target_key = (target.method, target.action, target.param_name)
            if already_reported(kind, target_key):
                continue
            if kind == "sqli" and target.baseline_body is None and not _load_baseline(
                client, target, baseline_cache, reserve
            ):
                continue

            url, data = target.payload_request(payload)
            if kind == "crlf":
                # значение подставляется без повторного кодирования: нужны «сырые» %0d%0a
                url = url.replace(CRLF_PLACEHOLDER, CRLF_RAW)
            batch.append((kind, target, payload, target_key, url, data))

        calls = [(target.method, url, dict(data=data, allow_redirects=kind not in ("redirect", "crlf"),
                                           reserve=reserve))
                 for kind, target, _payload, _key, url, data in batch]
        responses = client.request_many(calls)

        for (kind, target, payload, target_key, url, data), call, response in zip(batch, calls, responses):
            if response is not None and response.status_code == 429:
                # Ответ об ограничении частоты не несёт информации о параметре — повторяем один раз.
                response = client.request(call[0], call[1], **call[2])
            if response is None:
                continue
            result.tests_executed += 1
            tested_targets.add(target_key)
            if already_reported(kind, target_key):
                continue

            if kind == "xss":
                xss_findings = _analyze_xss(target, response, url, data, payload=payload)
                if xss_findings:
                    reported_xss.add(target_key)
                result.findings.extend(xss_findings)
            elif kind == "sqli":
                sqli_findings = _analyze_sqli(target, response, url, data, payload)
                if sqli_findings:
                    reported_sqli.add(target_key)
                    weak_sqli.extend((item, target, payload) for item in sqli_findings
                                     if item.kind in WEAK_SQLI_KINDS)
                result.findings.extend(sqli_findings)
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

    for finding, target, payload in weak_sqli:
        if not client.can_request(reserve):
            break  # подтвердить нечем — находка остаётся с пометкой «подозрение»
        result.tests_executed += 1
        if not _confirm_sqli(client, finding, target, payload, reserve):
            result.findings.remove(finding)
            continue
        # Контрольная проба прошла: пробуем независимо подтвердить находку булевым
        # оракулом. Если TRUE/FALSE-условие воспроизводимо меняет ответ — это уже не
        # предположение по эвристике, а продемонстрированная слепая SQL-инъекция.
        if client.can_request(reserve + 2):
            boolean_evidence = _boolean_blind_confirm(client, target, reserve)
            result.tests_executed += 1
            if boolean_evidence:
                finding.kind = "sqli_boolean_blind"
                finding.title = f"Подтверждена слепая SQL-инъекция (булева): {target.label()}"
                finding.severity = HIGH
                finding.confidence = CONFIRMED
                finding.exploited = True
                finding.evidence = truncate(f"{finding.evidence}\n\n{boolean_evidence}", 1400)

    # Проверка по времени: только в --pentest (дополнительная, заведомо замедляющая
    # сайт нагрузка) и только для точек, где остальные пробы ничего не нашли —
    # иначе это были бы лишние запросы к уже подтверждённой находке.
    if pentest:
        time_candidates = [t for t in targets[:TIME_SQLI_TARGET_LIMIT]
                           if (t.method, t.action, t.param_name) not in reported_sqli]
        for target in time_candidates:
            if not client.can_request(reserve + 3):
                break
            evidence = _time_blind_confirm(client, target, reserve)
            result.tests_executed += 1
            if evidence:
                result.findings.append(
                    Finding(
                        url=target.page_url,
                        title=f"Подтверждена слепая SQL-инъекция (по времени): {target.label()}",
                        kind="sqli_time_blind",
                        category=VULN,
                        severity=HIGH,
                        recommendation="Используйте параметризованные запросы (prepared "
                                       "statements) вместо конкатенации строк. Слепая "
                                       "инъекция по времени работает даже тогда, когда "
                                       "страница никак не меняется внешне.",
                        request=describe_request(target.method, *target.payload_request(
                            TIME_SQLI_PAYLOADS[0][0])),
                        evidence=truncate(evidence, 1000),
                        confidence=CONFIRMED,
                        exploited=True,
                    )
                )

    result.targets_tested = len(tested_targets)
    return result


def _boolean_blind_confirm(client: HttpClient, target: Target, reserve: int) -> Optional[str]:
    """TRUE-условие должно вести себя как обычный ответ, FALSE — заметно отличаться.

    Сравнение идёт не с ``target.baseline_body`` (для полей форм там может быть
    ответ на подставленное служебное значение — см. ``_load_baseline``), а со
    свежим ответом на исходное значение этой же точки внедрения, иначе TRUE
    может не совпасть с устаревшим baseline по не связанной с SQL причине.
    """
    original = target.params.get(target.param_name, "") or ""
    if not client.can_request(reserve + 1):
        return None
    normal_url, normal_data = target.payload_request(original)
    normal_resp = client.request(target.method, normal_url, data=normal_data, reserve=reserve)
    if normal_resp is None or getattr(normal_resp, "history", None) or \
            normal_resp.status_code >= 500:
        return None
    normal_body = _text(normal_resp)

    for true_suffix, false_suffix in BOOLEAN_SQLI_PAIRS:
        if not client.can_request(reserve + 1):
            break
        true_url, true_data = target.payload_request(f"{original}{true_suffix}")
        true_resp = client.request(target.method, true_url, data=true_data, reserve=reserve)
        if true_resp is None or getattr(true_resp, "history", None) or true_resp.status_code >= 500:
            continue
        true_body = _text(true_resp)
        if _structure_changed(normal_body, true_body):
            continue  # TRUE должно выглядеть как обычный ответ — здесь не так
        if not client.can_request(reserve):
            break
        false_url, false_data = target.payload_request(f"{original}{false_suffix}")
        false_resp = client.request(target.method, false_url, data=false_data, reserve=reserve)
        if false_resp is None or getattr(false_resp, "history", None) or \
                false_resp.status_code >= 500:
            continue
        false_body = _text(false_resp)
        if not _structure_changed(true_body, false_body):
            continue  # FALSE не отличается от TRUE — оракул не сработал
        return (f"TRUE ({original}{true_suffix}) -> ответ как обычно "
                f"({len(true_body)} симв.); "
                f"FALSE ({original}{false_suffix}) -> ответ заметно отличается "
                f"({len(false_body)} симв.).")
    return None


def _time_blind_confirm(client: HttpClient, target: Target, reserve: int) -> Optional[str]:
    """Проверка по времени для случаев, когда содержимое ответа вообще не меняется."""
    for payload, engine in TIME_SQLI_PAYLOADS:
        if not client.can_request(reserve + 2):
            return None
        url, data = target.payload_request(payload)
        started = time.monotonic()
        response = client.request(target.method, url, data=data, reserve=reserve)
        elapsed = time.monotonic() - started
        if response is None or elapsed < TIME_SQLI_SECONDS * 0.8:
            continue  # эта СУБД/синтаксис не подошли — пробуем следующий вариант

        # Контроль: тот же оператор с нулевой задержкой должен ответить быстро —
        # иначе «медленный» ответ объясняется нагрузкой на сайт, а не инъекцией.
        if not client.can_request(reserve + 1):
            return None
        control_url, control_data = target.payload_request(
            f"{target.params.get(target.param_name, '') or ''}{TIME_SQLI_CONTROL_SUFFIX}"
        )
        control_started = time.monotonic()
        control = client.request(target.method, control_url, data=control_data, reserve=reserve)
        control_elapsed = time.monotonic() - control_started
        if control is None or control_elapsed > TIME_SQLI_SECONDS * 0.5:
            continue

        # Повтор «медленного» payload'а: задержка должна воспроизводиться,
        # а не быть случайным совпадением (скачок нагрузки, GC и т. п.).
        if not client.can_request(reserve):
            return None
        again_started = time.monotonic()
        again = client.request(target.method, url, data=data, reserve=reserve)
        again_elapsed = time.monotonic() - again_started
        if again is None or again_elapsed < TIME_SQLI_SECONDS * 0.8:
            continue

        return (f"Параметр «{target.param_name}»: ответ с задержкой SLEEP "
                f"({engine}) занял {elapsed:.1f} с и {again_elapsed:.1f} с при повторе; "
                f"контрольный запрос с нулевой задержкой — {control_elapsed:.1f} с.")
    return None


def _confirm_sqli(client: HttpClient, finding: Finding, target: Target, payload: str,
                  reserve: int) -> bool:
    """Контрольная проба для косвенных признаков SQL-инъекции; False — признак ложный."""
    control = SQLI_CONTROL_VALUES.get(payload)
    if control is None:
        return True
    url, data = target.payload_request(control)
    response = client.request(target.method, url, data=data, reserve=reserve)
    if response is None:
        return True
    if finding.kind == "sqli_status":
        return response.status_code < 500
    if getattr(response, "history", None):
        return True  # контрольный запрос ушёл на другую страницу — вывода не сделать
    if _structure_changed(target.baseline_body or "", _text(response)):
        return False  # и парная кавычка меняет страницу: это не признак инъекции
    # Парная кавычка страницу не меняет. Повторяем «ломающую» пробу: изменение должно
    # воспроизводиться, а не быть случайным отличием динамической страницы.
    url, data = target.payload_request(payload)
    again = client.request(target.method, url, data=data, reserve=reserve)
    if again is None:
        return True
    return not getattr(again, "history", None) and _structure_changed(
        target.baseline_body or "", _text(again))


# --- отражённый XSS -------------------------------------------------------
def _analyze_xss(target: Target, response, url: str, data,
                 payload: str = XSS_PAYLOAD) -> List[Finding]:
    body = _text(response)
    if not body or MARKER not in body:
        return []
    content_type = response.headers.get("Content-Type", "").lower()
    is_html = "html" in content_type or (not content_type and "<html" in body.lower())
    if not (is_html or "xml" in content_type or "svg" in content_type):
        return []  # JSON, text/plain и т. п.: отражённая строка не исполняется браузером
    request_text = describe_request(target.method, url, data)

    raw_reflected = (
        payload in body
        or XSS_PAYLOAD in body
        or f"<x-{MARKER}>" in body
        or f"onerror=alert('{MARKER}')" in body
        or f"onload=confirm('{MARKER}')" in body
        or f"<script>/*{MARKER}*/</script>" in body
    )
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
                    f"спецсимволами:\n{snippet(body, MARKER, 160)}",
                    900,
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
                    f"{snippet(body, MARKER, 160)}",
                    900,
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
                evidence=truncate(snippet(body, MARKER, 160), 700),
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
                evidence=truncate(snippet(body, MARKER, 120), 500),
                confidence=CONFIRMED,
            )
        ]
    return []


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
                        f"{snippet(body, match.group(0), 200)}",
                        900,
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
                        f"Сообщение об ошибке СУБД в ответе:\n{snippet(body, match.group(0), 200)}",
                        900,
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
                        f"Фрагмент ответа:\n{truncate(body.strip(), 300)}",
                        800,
                    ),
                    confidence=SUSPECTED,
                )
            ]

    # Если запрос закончился переходом на другую страницу, структура отличается из-за
    # самого перехода (параметр next/url/return), а не из-за запроса к базе.
    if baseline_body and body and not getattr(response, "history", None):
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
    if location and _points_to_evil_host(location):
        return [
            Finding(
                url=target.page_url,
                title=f"Открытый редирект: {target.label()}",
                kind="open_redirect",
                category=VULN,
                severity=MEDIUM,
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
                confidence=CONFIRMED,
            )
        ]

    body = _text(response)
    match = META_REFRESH.search(body or "")
    if match and _points_to_evil_host(match.group(1).strip()):
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


def _points_to_evil_host(location: str) -> bool:
    """Ведёт ли адрес переадресации именно на тестовый внешний хост.

    Сравнивается хост разобранного адреса, а не подстрока: переход на собственную форму
    входа вида ``/login?next=https%3A//evil.com`` не является открытым редиректом.
    """
    value = location.strip().replace("\\", "/")
    if value.startswith("//"):
        value = "https:" + value
    host = (urlparse(value).hostname or "").lower()
    return host == REDIRECT_HOST or host.endswith("." + REDIRECT_HOST)


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
    # Длинные подсказки допустимы как часть имени (redirectTo, return_path), короткие
    # («out», «view», «go», «link») — только как отдельное слово, иначе «preview» и «about»
    # считались бы параметрами перехода.
    if any(hint in lowered for hint in REDIRECT_SUBSTRING_HINTS):
        return True
    words = [word for word in re.split(r"[^a-z0-9]+", lowered) if word]
    return lowered in REDIRECT_WORD_HINTS or any(word in REDIRECT_WORD_HINTS for word in words)


def _looks_destructive(form: Form) -> bool:
    haystack = (form.action + " " + " ".join(f.name for f in form.fields)).lower()
    return any(hint in haystack for hint in DESTRUCTIVE_HINTS)


def _text(response) -> str:
    try:
        return response.text or ""
    except Exception:
        return ""
