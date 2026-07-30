"""Углублённые проверки скрытых критических рисков.

Безопасные маркерные пробы (без эксплуатации): SSRF, XXE, stored/blind XSS,
IDOR, эвристики бизнес-логики, загрузка файлов, JWT, GraphQL, признаки
request smuggling и обход WAF. Все запросы укладываются в общий бюджет клиента.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple

from ..http_client import HttpClient
from ..models import CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, VULN, Finding, Form, Page
from ..utils import describe_request, truncate
from . import active as active_mod

STORE_MARKER = "BAUMAN_STORE_XSS_7f3a"
BLIND_MARKER = "BAUMAN_BLIND_XSS_9c2e"
SSRF_MARK = "BAUMANSSRF"
XXE_FILE_MARKERS = ("root:x:0:0", "root:*:0:0", "[fonts]", "for 16-bit app support")

SSRF_PARAM_HINTS = (
    "url", "uri", "src", "href", "link", "path", "dest", "destination", "target",
    "redirect", "next", "return", "callback", "webhook", "fetch", "proxy", "host",
    "endpoint", "feed", "image", "img", "avatar", "file", "document", "resource",
)

SSRF_PAYLOADS = (
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
)

SSRF_BODY_HINTS = (
    "ami-id", "instance-id", "local-ipv4", "meta-data", "computemetadata",
    "root:x:0:0", "apache", "nginx/", "iis windows", "it works!",
)

ID_PARAM_HINTS = ("id", "uid", "user_id", "userid", "account", "order", "order_id",
                  "doc", "document", "invoice", "profile", "item", "pid", "sid")

LOGIC_PARAM_HINTS = ("price", "amount", "qty", "quantity", "discount", "coupon",
                     "total", "cost", "count", "limit")

GRAPHQL_PATHS = (
    "/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1", "/query", "/api/query",
)

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b")
PATH_ID_RE = re.compile(
    r"(?i)/(?:user|users|account|accounts|order|orders|profile|profiles|"
    r"item|items|doc|docs|invoice|invoices|api/v\d+)/(\d{1,9})(?:/|$)"
)
NUM_QS_RE = re.compile(
    r"(?i)([?&](?:id|user_id|uid|order_id|account_id|item_id)=)(\d{1,9})"
)

WAF_BLOCK_RE = re.compile(
    r"(?i)(web application firewall|request blocked|access denied|attention required|"
    r"cloudflare|sucuri|incapsula|mod_security|not acceptable|"
    r"the request was rejected|security policy|your request has been blocked)"
)

DEEP_TARGET_LIMIT = 10

# Broken Access Control: принудительный обход служебных разделов без сессии
BAC_PATHS = (
    "/admin", "/administrator", "/wp-admin/", "/manage", "/dashboard",
    "/console", "/panel", "/api/admin", "/api/users", "/api/v1/users",
    "/account/settings", "/users/1", "/orders/1",
)


@dataclass
class DeepResult:
    findings: List[Finding] = field(default_factory=list)
    tests_executed: int = 0


def run_deep_checks(client: HttpClient, pages: Sequence[Page], base_url: str,
                    reserve: int = 0) -> DeepResult:
    """Дополнительные проверки поверх обычного active-этапа."""
    result = DeepResult()
    if not pages and not base_url:
        return result

    targets, _skipped = active_mod.build_targets(list(pages), test_post_forms=True)
    deep_targets = targets[:DEEP_TARGET_LIMIT]

    result.findings.extend(_check_jwt_and_tokens(pages))
    result.findings.extend(_check_graphql(client, base_url, result, reserve))
    result.findings.extend(_check_smuggling_signals(client, base_url, result, reserve))
    result.findings.extend(_check_ssrf(client, deep_targets, result, reserve))
    result.findings.extend(_check_xxe(client, pages, base_url, result, reserve))
    result.findings.extend(
        _check_stored_and_blind_xss(client, pages, deep_targets, result, reserve)
    )
    result.findings.extend(_check_idor(client, pages, result, reserve))
    result.findings.extend(_check_broken_access(client, base_url, pages, result, reserve))
    result.findings.extend(_check_business_logic(client, deep_targets, result, reserve))
    result.findings.extend(_check_upload(client, pages, result, reserve))
    result.findings.extend(_check_waf_bypass(client, deep_targets, result, reserve))
    return result


def _check_jwt_and_tokens(pages: Sequence[Page]) -> List[Finding]:
    findings: List[Finding] = []
    seen: Set[str] = set()
    blobs: List[Tuple[str, str]] = []
    for page in pages:
        blobs.append((page.url, page.body or ""))
        for cookie in page.cookies or []:
            blobs.append((page.url, cookie.raw or cookie.name))
        for key, value in (page.headers or {}).items():
            if key.lower() in ("set-cookie", "authorization", "x-auth-token"):
                blobs.append((page.url, f"{key}: {value}"))
        for raw_name, raw_val in page.raw_headers or []:
            if raw_name.lower() in ("set-cookie", "authorization", "x-auth-token"):
                blobs.append((page.url, f"{raw_name}: {raw_val}"))

    for url, text in blobs:
        for match in JWT_RE.findall(text or ""):
            token = match.strip().rstrip(".,;\"'")
            if token in seen or token.count(".") < 2:
                continue
            seen.add(token)
            finding = _analyze_jwt(url, token)
            if finding:
                findings.append(finding)
    return findings


def _analyze_jwt(url: str, token: str) -> Optional[Finding]:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = _b64json(parts[0])
        payload = _b64json(parts[1]) if len(parts) > 1 else {}
    except Exception:
        return None
    if not isinstance(header, dict):
        return None
    alg = str(header.get("alg", "")).lower()
    issues: List[str] = []
    severity = MEDIUM
    confidence = SUSPECTED
    kind = "jwt_weak"
    if alg in ("none", ""):
        issues.append("alg=none — подпись может не проверяться")
        severity = HIGH
        confidence = CONFIRMED
        kind = "jwt_alg_none"
    if len(parts) >= 3 and not parts[2]:
        issues.append("пустая подпись JWT")
        severity = HIGH
        kind = "jwt_alg_none"
    if isinstance(payload, dict):
        if "exp" not in payload:
            issues.append("нет claim exp (токен может жить бесконечно)")
        role = str(payload.get("role", "")).lower()
        if payload.get("admin") is True or role in ("admin", "root", "superuser"):
            issues.append(f"привилегированный claim в payload: {truncate(str(payload), 120)}")
            severity = HIGH
    if not issues:
        issues.append("JWT обнаружен в ответе — проверьте политику подписи и срок жизни")
        severity = LOW
        confidence = CONFIRMED
        kind = "jwt_weak"
    return Finding(
        url=url,
        title="Слабая конфигурация JWT" if severity != LOW else "Обнаружен JWT в ответе",
        kind=kind,
        category=VULN,
        severity=severity,
        recommendation="Проверяйте подпись JWT на сервере, запретите alg=none, задайте exp "
                        "и минимальные привилегии в claims.",
        request="Пассивный разбор токена из ответа/cookie/заголовка",
        evidence=truncate(
            f"header={header}\nissues={'; '.join(issues)}\ntoken_prefix={token[:48]}…",
            700,
        ),
        confidence=confidence,
    )


def _b64json(segment: str):
    pad = "=" * (-len(segment) % 4)
    raw = base64.urlsafe_b64decode(segment + pad)
    return json.loads(raw.decode("utf-8", errors="replace"))


def _check_graphql(client: HttpClient, base_url: str, result: DeepResult,
                   reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    query = {"query": "{ __schema { queryType { name } types { name } } }"}
    origin = base_url.rstrip("/")
    for path in GRAPHQL_PATHS:
        if not client.can_request(reserve):
            break
        url = origin + path
        response = client.request(
            "POST", url,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            data=json.dumps(query),
            reserve=reserve,
        )
        if response is None:
            continue
        result.tests_executed += 1
        body = _text(response)
        if response.status_code >= 400 and "__schema" not in body:
            continue
        if '"__schema"' in body or "queryType" in body:
            findings.append(Finding(
                url=url,
                title="GraphQL introspection включена",
                kind="graphql_introspection",
                category=VULN,
                severity=HIGH,
                recommendation="Отключите introspection на проде и ограничьте GraphQL авторизацией.",
                request=describe_request("POST", url, {"query": "__schema"}),
                evidence=truncate(body, 600),
                confidence=CONFIRMED,
            ))
            break
        if response.status_code == 200 and ("errors" in body or "data" in body):
            findings.append(Finding(
                url=url,
                title="Обнаружена GraphQL-точка без явной защиты introspection",
                kind="graphql_endpoint",
                category=VULN,
                severity=MEDIUM,
                recommendation="Проверьте auth на GraphQL, rate-limit и отключение introspection.",
                request=describe_request("POST", url, {"query": "__schema"}),
                evidence=truncate(body, 500),
                confidence=SUSPECTED,
            ))
            break
    return findings


def _check_smuggling_signals(client: HttpClient, base_url: str, result: DeepResult,
                             reserve: int) -> List[Finding]:
    """Безопасный сигнал: сервер принимает запрос с TE+CL без явного отказа."""
    if not client.can_request(reserve):
        return []
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Transfer-Encoding": "chunked",
        "Content-Length": "4",
        "Connection": "close",
    }
    response = client.request(
        "POST", base_url, headers=headers, data="0\r\n\r\n",
        allow_redirects=False, reserve=reserve,
    )
    if response is None:
        return []
    result.tests_executed += 1
    body = _text(response)
    status = response.status_code
    if status == 400 and re.search(r"(?i)ambiguous|smuggl|invalid transfer", body):
        return []
    te = response.headers.get("Transfer-Encoding", "")
    cl = response.headers.get("Content-Length", "")
    # Успех на TE+CL или 5xx после двусмысленного framing — сигнал для ручной проверки
    if status not in (200, 204, 500, 502):
        return []
    if status in (200, 204) or "chunked" in (te or "").lower():
        return [Finding(
            url=base_url,
            title="Признаки уязвимости к HTTP request smuggling (TE+CL)",
            kind="http_smuggling",
            category=VULN,
            severity=HIGH,
            recommendation="Настройте прокси/бэкенд одинаково: отклоняйте запросы с "
                            "одновременными Transfer-Encoding и Content-Length.",
            request="POST с заголовками Transfer-Encoding: chunked и Content-Length",
            evidence=truncate(
                f"status={status}\nresp_TE={te}\nresp_CL={cl}\n{body[:300]}",
                600,
            ),
            confidence=SUSPECTED,
        )]
    return []


def _check_ssrf(client: HttpClient, targets: Sequence[active_mod.Target], result: DeepResult,
                reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    candidates = [t for t in targets if _is_ssrf_param(t.param_name)][:6]
    if not candidates:
        for t in targets[:4]:
            val = (t.params.get(t.param_name) or "")
            if val.startswith(("http://", "https://")) or "url" in t.param_name.lower():
                candidates.append(t)
        candidates = candidates[:4]

    reported: Set[Tuple[str, str]] = set()
    for target in candidates:
        for payload in SSRF_PAYLOADS:
            if not client.can_request(reserve):
                return findings
            key = (target.action, target.param_name)
            if key in reported:
                break
            url, data = target.payload_request(payload)
            response = client.request(
                target.method, url, data=data, allow_redirects=False, reserve=reserve,
            )
            if response is None:
                continue
            result.tests_executed += 1
            body = _text(response)
            body_l = body.lower()
            hit = any(h in body_l for h in SSRF_BODY_HINTS)
            meta = "169.254.169.254" in payload and hit
            if hit or meta:
                findings.append(Finding(
                    url=target.page_url,
                    title=f"Возможный SSRF: {target.label()}",
                    kind="ssrf",
                    category=VULN,
                    severity=HIGH if meta or "127.0.0.1" in payload else MEDIUM,
                    recommendation="Не загружайте URL от пользователя на сервере без белого "
                                    "списка; блокируйте loopback/link-local/metadata.",
                    request=describe_request(target.method, url, data),
                    evidence=truncate(
                        f"payload={payload}\nstatus={response.status_code}\n{body[:500]}",
                        700,
                    ),
                    confidence=CONFIRMED if hit else SUSPECTED,
                ))
                reported.add(key)
                break
    return findings


def _is_ssrf_param(name: str) -> bool:
    low = (name or "").lower()
    return any(h in low for h in SSRF_PARAM_HINTS)


def _check_xxe(client: HttpClient, pages: Sequence[Page], base_url: str, result: DeepResult,
               reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    endpoints: List[str] = []
    for page in pages:
        ctype = (page.content_type or page.headers.get("Content-Type", "")).lower()
        if "xml" in ctype or "xml" in (page.url or "").lower():
            endpoints.append(page.url)
        for form in page.forms:
            if "xml" in (form.action or "").lower() or "soap" in (form.action or "").lower():
                endpoints.append(form.action)
    origin = base_url.rstrip("/")
    for suffix in ("/api", "/xml", "/soap", "/rpc"):
        endpoints.append(origin + suffix)

    seen: Set[str] = set()
    uniq = []
    for ep in endpoints:
        if ep and ep not in seen:
            seen.add(ep)
            uniq.append(ep)
    uniq = uniq[:5]

    xxe = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f"<foo>{SSRF_MARK}&xxe;</foo>"
    )
    for ep in uniq:
        if not client.can_request(reserve):
            break
        response = client.request(
            "POST", ep,
            headers={
                "Content-Type": "application/xml",
                "Accept": "application/xml,text/xml,*/*",
            },
            data=xxe,
            reserve=reserve,
        )
        if response is None:
            continue
        result.tests_executed += 1
        body = _text(response)
        if any(m in body for m in XXE_FILE_MARKERS):
            findings.append(Finding(
                url=ep,
                title="XXE: внешняя сущность читает файл сервера",
                kind="xxe",
                category=VULN,
                severity=HIGH,
                recommendation="Отключите внешние сущности/DTD в XML-парсере; "
                                "предпочитайте JSON API.",
                request=describe_request("POST", ep, {"xml": "DOCTYPE ENTITY file:///etc/passwd"}),
                evidence=truncate(body, 600),
                confidence=CONFIRMED,
            ))
        elif re.search(r"(?i)(DOCTYPE|ENTITY|SAXParse|XMLParser|external entity)", body):
            findings.append(Finding(
                url=ep,
                title="XXE: парсер реагирует на DOCTYPE/ENTITY",
                kind="xxe_suspected",
                category=VULN,
                severity=MEDIUM,
                recommendation="Запретите DTD и external entities в XML-парсере.",
                request=describe_request("POST", ep, {"xml": "DOCTYPE probe"}),
                evidence=truncate(body, 500),
                confidence=SUSPECTED,
            ))
    return findings


def _check_stored_and_blind_xss(client: HttpClient, pages: Sequence[Page],
                                targets: Sequence[active_mod.Target],
                                result: DeepResult, reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    safe: List[active_mod.Target] = []
    for t in targets:
        blob = f"{t.action} {t.param_name} {t.page_url}".lower()
        if any(h in blob for h in active_mod.DESTRUCTIVE_HINTS):
            continue
        if t.param_name.lower() in ("password", "pass", "csrf", "token", "_token"):
            continue
        safe.append(t)
    safe = safe[:5]

    injected_urls: List[str] = []
    for target in safe:
        if not client.can_request(reserve):
            break
        url, data = target.payload_request(STORE_MARKER)
        response = client.request(target.method, url, data=data, reserve=reserve)
        if response is None:
            continue
        result.tests_executed += 1
        injected_urls.append(target.page_url)

    check_urls = list(dict.fromkeys(injected_urls + [p.url for p in pages[:6]]))[:10]
    for page_url in check_urls:
        if not client.can_request(reserve):
            break
        response = client.get(page_url, reserve=reserve)
        if response is None:
            continue
        result.tests_executed += 1
        body = _text(response)
        if STORE_MARKER not in body:
            continue
        if f"&lt;{STORE_MARKER}" in body or f"&amp;{STORE_MARKER}" in body:
            continue
        idx = body.find(STORE_MARKER)
        ctx = body[max(0, idx - 40): idx + len(STORE_MARKER) + 40]
        findings.append(Finding(
            url=page_url,
            title="Возможный stored XSS: маркер сохранился в ответе",
            kind="xss_stored",
            category=VULN,
            severity=HIGH,
            recommendation="Экранируйте вывод пользовательских данных (HTML encoding); "
                            "CSP без unsafe-inline.",
            request=f"Повторная загрузка {page_url} после внедрения {STORE_MARKER}",
            evidence=truncate(ctx, 500),
            confidence=CONFIRMED,
        ))
        break

    blind_payload = f'"><img src=x id={BLIND_MARKER} onerror=void(0)>'
    for target in safe[:3]:
        if not client.can_request(reserve):
            break
        url, data = target.payload_request(blind_payload)
        response = client.request(target.method, url, data=data, reserve=reserve)
        if response is None:
            continue
        result.tests_executed += 1
        body = _text(response)
        blocked = response.status_code in (403, 406, 419, 429) or bool(WAF_BLOCK_RE.search(body))
        reflected = BLIND_MARKER in body
        if not blocked and not reflected and response.status_code < 400:
            findings.append(Finding(
                url=target.page_url,
                title=f"Возможный blind/stored XSS: payload принят без отражения ({target.label()})",
                kind="xss_blind",
                category=VULN,
                severity=MEDIUM,
                recommendation="Проверьте сохранение ввода в админках/логах/письмах; "
                                "экранируйте вывод везде, не только в том же ответе.",
                request=describe_request(target.method, url, data),
                evidence=f"status={response.status_code}; маркер не отражён, блок WAF не обнаружен",
                confidence=SUSPECTED,
            ))
    return findings


def _check_idor(client: HttpClient, pages: Sequence[Page], result: DeepResult,
                reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    candidates: List[Tuple[str, str, str]] = []
    for page in pages[:20]:
        url = page.url
        m = PATH_ID_RE.search(url)
        if m:
            num = int(m.group(1))
            if num > 0:
                other = url[:m.start(1)] + str(num + 1) + url[m.end(1):]
                candidates.append((url, other, f"path id {num} → {num + 1}"))
        for qm in NUM_QS_RE.finditer(url):
            num = int(qm.group(2))
            other = url[:qm.start(2)] + str(num + 1) + url[qm.end(2):]
            candidates.append((url, other, f"query {qm.group(1)}{num} → {num + 1}"))
            break
        # также параметры из URL с id-hints
        for name in ID_PARAM_HINTS:
            if f"{name}=" in url.lower():
                break

    seen: Set[str] = set()
    for original, other, note in candidates[:6]:
        if other in seen:
            continue
        seen.add(other)
        if not client.can_request(reserve):
            break
        response = client.get(other, reserve=reserve)
        if response is None:
            continue
        result.tests_executed += 1
        if response.status_code != 200:
            continue
        body = _text(response)
        if re.search(r"(?i)(login|sign in|unauthorized|forbidden|access denied)", body):
            continue
        if len(body) < 80:
            continue
        if re.search(r"(?i)(email|phone|order|invoice|profile|user id|account)", body):
            findings.append(Finding(
                url=original,
                title="Возможный IDOR: соседний идентификатор доступен без доп. авторизации",
                kind="idor",
                category=VULN,
                severity=HIGH,
                recommendation="Проверяйте права на объект на сервере (ownership), "
                                "не полагайтесь на скрытость числовых id.",
                request=f"GET {other}",
                evidence=truncate(f"{note}\nstatus=200\n{body[:400]}", 650),
                confidence=SUSPECTED,
            ))
    return findings


def _check_broken_access(client: HttpClient, base_url: str, pages: Sequence[Page],
                         result: DeepResult, reserve: int) -> List[Finding]:
    """Broken Access Control (OWASP A01): доступ к админке/API без авторизации."""
    findings: List[Finding] = []
    origin = base_url.rstrip("/")
    # сначала типовые пути (быстрее дают сигнал), затем интересные из crawl
    candidates: List[str] = [origin + path for path in BAC_PATHS]
    for page in pages:
        low = (page.url or "").lower()
        if any(h in low for h in ("/admin", "/dashboard", "/manage", "/api/", "/account",
                                   "/user/", "/order")):
            candidates.append(page.url)

    seen: Set[str] = set()
    hits = 0
    ordered = []
    for url in candidates:
        if url not in seen:
            seen.add(url)
            ordered.append(url)
    for url in ordered[:12]:
        if hits >= 4 or not client.can_request(reserve):
            break
        response = client.get(url, allow_redirects=False, reserve=reserve)
        if response is None:
            continue
        result.tests_executed += 1
        body = _text(response)
        status = response.status_code
        # редирект на логин — норма
        location = (response.headers.get("Location") or "").lower()
        if status in (301, 302, 303, 307, 308) and any(
            x in location for x in ("login", "signin", "auth", "sso")
        ):
            continue
        if status in (401, 403):
            continue
        if status != 200:
            continue
        if re.search(r"(?i)(type=[\"']password[\"']|sign in|log in|войти|авторизац)", body):
            continue
        # похоже на админку / данные без логина
        adminish = bool(re.search(
            r"(?i)(admin panel|dashboard|управление|пользовател|orders?|api\s*key|"
            r"\"role\"\s*:\s*\"admin\"|wp-admin)",
            body,
        ))
        apiish = "application/json" in (response.headers.get("Content-Type") or "").lower()
        if adminish or (apiish and len(body) > 40 and not re.search(
            r"(?i)(unauthorized|forbidden|authentication required)", body
        )):
            hits += 1
            findings.append(Finding(
                url=url,
                title="Broken Access Control: раздел доступен без авторизации",
                kind="broken_access",
                category=VULN,
                severity=HIGH,
                recommendation="Проверяйте права на каждый маршрут и объект на сервере; "
                                "не полагайтесь на скрытость URL. Закройте админку и API auth.",
                request=f"GET {url} (без сессии)",
                evidence=truncate(
                    f"status={status}\ncontent-type="
                    f"{response.headers.get('Content-Type', '-')}\n{body[:400]}",
                    650,
                ),
                confidence=CONFIRMED if adminish else SUSPECTED,
            ))

    # method override / verb tampering на найденных API-подобных URL
    for page in pages[:8]:
        if "/api/" not in (page.url or "").lower():
            continue
        if not client.can_request(reserve):
            break
        response = client.request(
            "POST", page.url,
            headers={"X-HTTP-Method-Override": "DELETE", "Content-Type": "application/json"},
            data="{}",
            allow_redirects=False,
            reserve=reserve,
        )
        if response is None:
            continue
        result.tests_executed += 1
        if response.status_code in (200, 202, 204) and not re.search(
            r"(?i)(unauthorized|forbidden|not allowed|method not)",
            _text(response),
        ):
            findings.append(Finding(
                url=page.url,
                title="Broken Access Control: принят X-HTTP-Method-Override: DELETE",
                kind="broken_access_method",
                category=VULN,
                severity=HIGH,
                recommendation="Игнорируйте Method-Override без жёсткой политики; "
                                "проверяйте роль перед DELETE/PUT.",
                request=f"POST {page.url} + X-HTTP-Method-Override: DELETE",
                evidence=truncate(
                    f"status={response.status_code}\n{_text(response)[:300]}", 500
                ),
                confidence=SUSPECTED,
            ))
            break
    return findings


def _check_business_logic(client: HttpClient, targets: Sequence[active_mod.Target],
                          result: DeepResult, reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    logic_targets = [
        t for t in targets
        if any(h in (t.param_name or "").lower() for h in LOGIC_PARAM_HINTS)
    ][:4]
    for target in logic_targets:
        if not client.can_request(reserve):
            return findings
        url, data = target.payload_request("-1")
        response = client.request(target.method, url, data=data, reserve=reserve)
        if response is None:
            continue
        result.tests_executed += 1
        body = _text(response)
        if response.status_code >= 400:
            continue
        if re.search(r"(?i)(invalid|must be positive|greater than|некоррект|ошибка)", body):
            continue
        findings.append(Finding(
            url=target.page_url,
            title=f"Бизнес-логика: параметр {target.param_name} принимает значение -1",
            kind="business_logic",
            category=VULN,
            severity=MEDIUM,
            recommendation="Валидируйте диапазоны на сервере (цена ≥ 0, qty ≥ 1); "
                            "не доверяйте клиентским суммам.",
            request=describe_request(target.method, url, data),
            evidence=truncate(body, 450),
            confidence=SUSPECTED,
        ))
    return findings


def _check_upload(client: HttpClient, pages: Sequence[Page], result: DeepResult,
                  reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    upload_forms: List[Form] = []
    for page in pages:
        for form in page.forms:
            if any(f.field_type == "file" for f in form.fields):
                upload_forms.append(form)

    for form in upload_forms[:3]:
        if not client.can_request(reserve):
            break
        boundary = "----BaumanBoundary7f3a"
        filename = "bauman_test.php.jpg"
        parts = []
        for field in form.fields:
            if field.field_type == "file" or not field.name:
                continue
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field.name}"\r\n\r\n'
                f"{field.value or '1'}\r\n"
            )
        file_fields = [f for f in form.fields if f.field_type == "file" and f.name]
        file_name = file_fields[0].name if file_fields else "file"
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{file_name}"; filename="{filename}"\r\n'
            f"Content-Type: image/jpeg\r\n\r\n"
            f"BAUMAN_UPLOAD_PROBE\r\n"
            f"--{boundary}--\r\n"
        )
        body = "".join(parts)
        response = client.request(
            form.method or "POST",
            form.action,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            data=body,
            reserve=reserve,
        )
        if response is None:
            continue
        result.tests_executed += 1
        text = _text(response)
        rejected = bool(re.search(
            r"(?i)(not allowed|forbidden|invalid (file|type|extension)|запрещ|недопуст)",
            text,
        ))
        if response.status_code in (200, 201) and not rejected:
            if filename in text or "BAUMAN_UPLOAD" in text or "bauman_test" in text.lower():
                findings.append(Finding(
                    url=form.page_url,
                    title="Загрузка файла: сервер принял имя .php.jpg (обход расширения)",
                    kind="upload_bypass",
                    category=VULN,
                    severity=HIGH,
                    recommendation="Проверяйте тип по содержимому (magic bytes), храните вне webroot, "
                                    "переименовывайте файлы, запретите исполняемые расширения.",
                    request=f"{form.method} {form.action} multipart filename={filename}",
                    evidence=truncate(f"status={response.status_code}\n{text[:400]}", 600),
                    confidence=SUSPECTED,
                ))
        elif response.status_code >= 500:
            findings.append(Finding(
                url=form.page_url,
                title="Загрузка файла: ошибка сервера на пробном upload",
                kind="upload_error",
                category=VULN,
                severity=MEDIUM,
                recommendation="Обработайте отказ загрузки без 500; ужесточите валидацию.",
                request=f"{form.method} {form.action}",
                evidence=truncate(text, 400),
                confidence=SUSPECTED,
            ))
    return findings


def _check_waf_bypass(client: HttpClient, targets: Sequence[active_mod.Target],
                      result: DeepResult, reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    if not targets:
        return findings
    base = targets[0]
    classic = active_mod.XSS_PAYLOAD
    bypasses = [
        f"<Svg/onload=confirm('{BLIND_MARKER}')>",
        f"\"><img src=x onerror=alert('{BLIND_MARKER}')>",
        f"<details/open/ontoggle=alert('{BLIND_MARKER}')>",
        f"<img src=x onerror=alert`{BLIND_MARKER}`>",
    ]

    if not client.can_request(reserve):
        return findings
    url, data = base.payload_request(classic)
    blocked_resp = client.request(base.method, url, data=data, reserve=reserve)
    classic_blocked = False
    if blocked_resp is not None:
        result.tests_executed += 1
        btxt = _text(blocked_resp)
        classic_blocked = (
            blocked_resp.status_code in (403, 406, 419, 429, 501)
            or bool(WAF_BLOCK_RE.search(btxt))
        )

    for payload in bypasses:
        for target in targets[:3]:
            if not client.can_request(reserve):
                return findings
            url, data = target.payload_request(payload)
            response = client.request(target.method, url, data=data, reserve=reserve)
            if response is None:
                continue
            result.tests_executed += 1
            body = _text(response)
            blocked = (
                response.status_code in (403, 406, 419, 429)
                or bool(WAF_BLOCK_RE.search(body))
            )
            reflected = (
                BLIND_MARKER in body
                and ("onerror" in body.lower() or "ontoggle" in body.lower()
                     or "onload" in body.lower())
            )
            if reflected and not blocked:
                kind = "waf_bypass" if classic_blocked else "xss_waf_bypass"
                title = (
                    f"Обход WAF: XSS-payload прошёл фильтр ({target.label()})"
                    if classic_blocked
                    else f"XSS с обходом фильтров — {target.label()}"
                )
                findings.append(Finding(
                    url=target.page_url,
                    title=title,
                    kind=kind,
                    category=VULN,
                    severity=HIGH,
                    recommendation="Не полагайтесь только на WAF; экранируйте вывод, "
                                    "ужесточите CSP, обновляйте правила WAF.",
                    request=describe_request(target.method, url, data),
                    evidence=truncate(
                        f"classic_blocked={classic_blocked}\n"
                        f"bypass_status={response.status_code}\n"
                        f"payload={payload}\n{body[:400]}",
                        700,
                    ),
                    confidence=CONFIRMED,
                ))
                return findings

    if classic_blocked:
        findings.append(Finding(
            url=base.page_url,
            title="Обнаружен WAF/фильтр, блокирующий классический XSS-маркер",
            kind="waf_detected",
            category=VULN,
            severity=INFO,
            recommendation="WAF полезен как слой, но не заменяет исправление в коде.",
            request=f"probe classic XSS on {base.label()}",
            evidence="Классический payload получил блокирующий ответ",
            confidence=SUSPECTED,
        ))
    return findings


def _text(response) -> str:
    try:
        return response.text or ""
    except Exception:
        return ""
