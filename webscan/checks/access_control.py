"""Проверки Broken Access Control (безопасный форсированный обход).

Без учётных данных: ищем админ/тестовые разделы, признаки IDOR по числовым
параметрам и обход 403 через альтернативные заголовки/методы.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlparse

from ..http_client import HttpClient
from ..models import (CONFIG, CONFIRMED, HIGH, LOW, MEDIUM, SUSPECTED, VULN, Finding,
                      Page)
from ..utils import build_url, query_params, truncate

PEEK = 800

# Пути, которые часто открывают админку / кабинет / API без должной проверки роли
BAC_PATHS: Tuple[Tuple[str, Tuple[str, ...], str, str], ...] = (
    ("/admin", ("admin", "dashboard", "login", "wp-admin", "control panel"),
     HIGH, "Административный раздел /admin"),
    ("/admin/", ("admin", "dashboard", "login"), HIGH, "Административный раздел /admin/"),
    ("/administrator", ("admin", "login", "joomla"), HIGH, "Раздел /administrator"),
    ("/wp-admin/", ("wp-admin", "wordpress", "dashboard"), MEDIUM, "Панель WordPress"),
    ("/wp-login.php", ("wordpress", "log in", "user_login"), MEDIUM, "Страница входа WordPress"),
    ("/dashboard", ("dashboard", "account", "welcome"), MEDIUM, "Личный кабинет /dashboard"),
    ("/account", ("account", "profile", "settings"), MEDIUM, "Раздел /account"),
    ("/user/1", ("user", "profile", "email", "username"), HIGH, "Профиль пользователя /user/1"),
    ("/users/1", ("user", "profile", "email"), HIGH, "Профиль /users/1"),
    ("/api/user/1", ("email", "username", "user", "\"id\""), HIGH, "API пользователя /api/user/1"),
    ("/api/users/1", ("email", "username", "\"id\""), HIGH, "API /api/users/1"),
    ("/api/admin", ("admin", "users", "role"), HIGH, "API /api/admin"),
    ("/api/v1/users", ("email", "username", "users"), HIGH, "API список пользователей"),
    ("/console", ("console", "login", "manager"), MEDIUM, "Консоль /console"),
    ("/manager/html", ("tomcat", "manager", "password"), HIGH, "Tomcat Manager"),
    ("/server-status", ("Apache Server Status",), MEDIUM, "Статус сервера"),
    ("/phpmyadmin/", ("phpMyAdmin", "pma_username"), HIGH, "phpMyAdmin"),
    ("/.well-known/security.txt", ("Contact:", "Expires:"), LOW, "security.txt"),
)

IDOR_PARAM_HINTS = ("id", "user_id", "userid", "uid", "account_id", "account", "profile_id",
                    "order_id", "doc_id", "file_id", "customer_id", "client_id")

BYPASS_HEADERS: Tuple[Dict[str, str], ...] = (
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
)


def check_broken_access_control(
    client: HttpClient,
    base_url: str,
    pages: Sequence[Page],
    reserve: int = 0,
) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(_probe_sensitive_paths(client, base_url, reserve))
    findings.extend(_probe_idor(client, pages, reserve))
    findings.extend(_probe_forbidden_bypass(client, base_url, reserve))
    return findings


def _probe_sensitive_paths(client: HttpClient, base_url: str,
                           reserve: int) -> List[Finding]:
    findings: List[Finding] = []
    baseline = _soft404_peek(client, base_url, reserve)

    for path, markers, severity, title in BAC_PATHS:
        if not client.can_request(reserve):
            break
        url = urljoin(base_url, path)
        response = client.get(url, allow_redirects=True, max_body_bytes=PEEK, reserve=reserve)
        if response is None:
            continue
        status = response.status_code
        peek = _peek(response)
        if status in (401, 403):
            # Само наличие закрытого админ-раздела — низкий риск (разведка)
            if any(m.lower() in peek.lower() for m in markers) or status == 403:
                findings.append(
                    Finding(
                        url=url,
                        title=f"Обнаружен защищённый раздел: {title}",
                        category=CONFIG,
                        severity=LOW,
                        recommendation="Убедитесь, что авторизация проверяет роль на каждом "
                                       "запросе, а не только скрывает ссылку в меню. "
                                       "На несуществующие разделы лучше отвечать 404.",
                        request=f"GET {url}",
                        evidence=f"HTTP/{status}",
                        confidence=CONFIRMED,
                        kind="bac_protected_area",
                    )
                )
            continue
        if status != 200:
            continue
        if baseline and _same_as_baseline(peek, baseline):
            continue
        confirmed = any(m.lower() in peek.lower() for m in markers)
        # Страница логина — infо; контент кабинета/данных — серьёзнее
        is_login = re.search(r"(?i)type=[\"']password[\"']|<form[^>]+login|name=[\"']password",
                             peek) is not None
        if is_login and not re.search(r"(?i)\"role\"\s*:|admin panel|welcome back", peek):
            sev, kind = LOW, "bac_login_exposed"
            conf = CONFIRMED
        else:
            sev = severity if confirmed else MEDIUM
            kind = "bac_unauthenticated_access"
            conf = CONFIRMED if confirmed else SUSPECTED
        findings.append(
            Finding(
                url=str(response.url or url),
                title=f"Возможен доступ без авторизации: {title}",
                category=VULN,
                severity=sev,
                recommendation="Закройте раздел проверкой сессии и роли на сервере. "
                               "Не полагайтесь на «скрытый URL». Для API возвращайте 401/403 "
                               "без утечки данных в теле ответа.",
                request=f"GET {url}",
                evidence=truncate(
                    f"HTTP/{status}\nContent-Type: {response.headers.get('Content-Type', '-')}\n"
                    f"Фрагмент:\n{peek[:400]}",
                    700,
                ),
                confidence=conf,
                kind=kind,
            )
        )
    return findings


def _probe_idor(client: HttpClient, pages: Sequence[Page], reserve: int) -> List[Finding]:
    """Меняет числовой id в URL и сравнивает ответ с исходным (признак IDOR)."""
    findings: List[Finding] = []
    tested: Set[str] = set()

    for page in pages:
        if not client.can_request(reserve):
            break
        params = query_params(page.url)
        if not params:
            continue
        for name, value in params:
            if name.lower() not in IDOR_PARAM_HINTS:
                continue
            if not re.fullmatch(r"\d{1,9}", str(value or "")):
                continue
            key = f"{urlparse(page.url).path}|{name}"
            if key in tested:
                continue
            tested.add(key)
            alt = "2" if str(value) == "1" else "1"
            mutated = [(n, alt if n == name else v) for n, v in params]
            probe_url = build_url(page.url.split("?", 1)[0], mutated)
            if not client.can_request(reserve):
                break
            response = client.get(probe_url, allow_redirects=True, max_body_bytes=PEEK,
                                  reserve=reserve)
            if response is None or response.status_code != 200:
                continue
            peek = _peek(response)
            base = (page.body or "")[:PEEK]
            if not base or peek == base[: len(peek)]:
                continue
            # Разный контент при смене id — возможный горизонтальный доступ
            if abs(len(peek) - len(base[:PEEK])) < 20 and peek[:120] == base[:120]:
                continue
            if re.search(r"(?i)login|sign in|unauthorized|access denied", peek):
                continue
            findings.append(
                Finding(
                    url=probe_url,
                    title=f"Возможен IDOR: параметр «{name}» меняет содержимое без авторизации",
                    category=VULN,
                    severity=HIGH,
                    recommendation="Проверяйте на сервере, что текущий пользователь имеет "
                                   "право читать объект с этим id. Не опирайтесь только на "
                                   "секретность числового идентификатора.",
                    request=f"GET {probe_url} (исходное значение {name}={value})",
                    evidence=truncate(
                        f"Исходный URL: {page.url}\n"
                        f"Ответ при {name}={alt}: HTTP/{response.status_code}\n"
                        f"Фрагмент:\n{peek[:350]}",
                        700,
                    ),
                    confidence=SUSPECTED,
                    kind="bac_idor",
                )
            )
            if len(findings) >= 4:
                return findings
    return findings


def _probe_forbidden_bypass(client: HttpClient, base_url: str,
                            reserve: int) -> List[Finding]:
    """Если /admin даёт 403 — пробуем обход заголовками (X-Original-URL и т. п.)."""
    findings: List[Finding] = []
    if not client.can_request(reserve):
        return findings
    admin_url = urljoin(base_url, "/admin")
    blocked = client.get(admin_url, allow_redirects=False, max_body_bytes=PEEK, reserve=reserve)
    if blocked is None or blocked.status_code not in (401, 403):
        return findings

    for headers in BYPASS_HEADERS:
        if not client.can_request(reserve):
            break
        # Запрос к корню с заголовком переписывания пути
        response = client.request(
            "GET",
            urljoin(base_url, "/"),
            headers=headers,
            allow_redirects=False,
            max_body_bytes=PEEK,
            reserve=reserve,
        )
        if response is None:
            continue
        if response.status_code == 200 and blocked.status_code in (401, 403):
            peek = _peek(response)
            if re.search(r"(?i)admin|dashboard|users|console", peek):
                findings.append(
                    Finding(
                        url=admin_url,
                        title="Возможен обход ограничения доступа через спецзаголовок",
                        category=VULN,
                        severity=HIGH,
                        recommendation="Не доверяйте заголовкам X-Original-URL / X-Rewrite-URL "
                                       "/ X-Forwarded-* для авторизации на origin-сервере. "
                                       "Проверяйте роль после нормализации пути на одном слое.",
                        request=f"GET / with headers {headers}",
                        evidence=truncate(
                            f"Прямой GET /admin → HTTP/{blocked.status_code}\n"
                            f"GET / + {headers} → HTTP/{response.status_code}\n"
                            f"Фрагмент:\n{peek[:300]}",
                            700,
                        ),
                        confidence=SUSPECTED,
                        kind="bac_header_bypass",
                    )
                )
                break
    return findings


def _soft404_peek(client: HttpClient, base_url: str, reserve: int) -> Optional[str]:
    if not client.can_request(reserve):
        return None
    url = urljoin(base_url, "/bauman-bac-404-probe-92841")
    response = client.get(url, allow_redirects=False, max_body_bytes=PEEK, reserve=reserve)
    if response is None or response.status_code != 200:
        return None
    return _peek(response)


def _same_as_baseline(peek: str, baseline: str) -> bool:
    if peek == baseline:
        return True
    return len(peek) > 40 and peek[:180] == baseline[:180]


def _peek(response) -> str:
    data = response.content or b""
    return data.decode(response.encoding or "utf-8", errors="replace")[:PEEK].replace("\r", "")
