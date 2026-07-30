"""Лёгкий статический анализ (SAST) загруженного HTML/JS.

Это не полноценный анализ исходников репозитория: сканер разбирает код,
который уже отдал сервер (страницы + несколько same-origin .js). Дополняет
эвристики clientside.py и помечается в отчёте как SAST.
"""

from __future__ import annotations

import re
from typing import List, Sequence, Set
from urllib.parse import urljoin, urlparse

from ..http_client import HttpClient
from ..models import HIGH, MEDIUM, SUSPECTED, VULN, Finding, Page
from ..utils import same_host, truncate

# Опасные стоки / антипаттерны в JS и шаблонах
SAST_PATTERNS = (
    ("sast_eval", HIGH, re.compile(r"(?i)\beval\s*\("),
     "Использование eval()",
     "Уберите eval; парсите данные через JSON.parse и безопасные API."),
    ("sast_function_ctor", HIGH, re.compile(r"(?i)\bnew\s+Function\s*\("),
     "Конструктор new Function()",
     "Не собирайте код из строк; используйте обычные функции."),
    ("sast_innerhtml", MEDIUM, re.compile(r"(?i)\.innerHTML\s*="),
     "Присваивание innerHTML",
     "Для текста используйте textContent; HTML — только после санитизации."),
    ("sast_document_write", MEDIUM, re.compile(r"(?i)\bdocument\.write\s*\("),
     "document.write()",
     "Откажитесь от document.write в пользу безопасного DOM API."),
    ("sast_sql_concat", HIGH, re.compile(
        r"(?i)(SELECT|INSERT|UPDATE|DELETE)\s+[^;'\"]*['\"]?\s*\+|`[^`]*\$\{"),
     "Конкатенация в SQL-подобной строке",
     "Используйте параметризованные запросы / prepared statements."),
    ("sast_shell_concat", HIGH, re.compile(
        r"(?i)(exec|system|popen|subprocess\.|os\.system|child_process)\s*\([^)]*(\+|`)"),
     "Сборка команды ОС из строк",
     "Не вызывайте shell с пользовательским вводом; передавайте argv-список."),
    ("sast_hardcoded_password", HIGH, re.compile(
        r"(?i)(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"),
     "Возможный пароль/секрет в коде",
     "Уберите секреты из фронтенда; храните на сервере в secrets/env."),
    ("sast_disable_security", MEDIUM, re.compile(
        r"(?i)(csrf\s*=\s*false|verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0)"),
     "Отключение проверки безопасности в коде",
     "Не отключайте CSRF/TLS-проверки в production."),
)

SCRIPT_SRC = re.compile(r"(?i)<script[^>]+src=['\"]([^'\"]+)['\"]")
MAX_JS_FETCH = 3
MAX_BODY_SCAN = 100_000
MAX_PAGES_SAST = 24


def run_sast(client: HttpClient, pages: Sequence[Page], reserve: int = 0) -> List[Finding]:
    findings: List[Finding] = []
    seen_keys: Set[str] = set()
    js_urls: List[str] = []

    for page in pages[:MAX_PAGES_SAST]:
        body = page.body or ""
        findings.extend(_scan_text(page.url, body, seen_keys))
        # ищем src только в первых 40 КБ разметки — там обычно <head>/начало
        for match in SCRIPT_SRC.finditer(body[:40_000]):
            src = urljoin(page.url, match.group(1))
            if same_host(src, page.url) and src not in js_urls:
                path = urlparse(src).path.lower()
                if path.endswith(".js") or "javascript" in path:
                    js_urls.append(src)

    for js_url in js_urls[:MAX_JS_FETCH]:
        if not client.can_request(reserve):
            break
        response = client.get(js_url, reserve=reserve)
        if response is None or response.status_code >= 400:
            continue
        try:
            text = response.text or ""
        except Exception:
            continue
        findings.extend(_scan_text(js_url, text, seen_keys))

    return findings


def _scan_text(url: str, text: str, seen: Set[str]) -> List[Finding]:
    body = text[:MAX_BODY_SCAN]
    if not body:
        return []
    # быстрый отсев: если нет ни одного опасного маркера — не гоняем все regex
    low = body.lower()
    if not any(token in low for token in (
        "eval(", "function(", "innerhtml", "document.write", "select ", "insert ",
        "password", "secret", "api_key", "apikey", "subprocess", "os.system",
        "csrf", "reject_unauthorized",
    )):
        return []
    out: List[Finding] = []
    for kind, severity, pattern, title, recommendation in SAST_PATTERNS:
        key = f"{kind}:{url}"
        if key in seen:
            continue
        match = pattern.search(body)
        if not match:
            continue
        seen.add(key)
        start = max(0, match.start() - 60)
        evidence = body[start: match.end() + 60]
        out.append(Finding(
            url=url,
            title=f"SAST: {title}",
            kind=kind,
            category=VULN,
            severity=severity,
            recommendation=recommendation,
            request=f"Статический разбор исходника {url}",
            evidence=truncate(evidence, 500),
            confidence=SUSPECTED,
        ))
    return out
