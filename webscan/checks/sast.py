"""Лёгкий SAST по уже загруженному HTML/JS (без отдельной загрузки исходников).

Ищет опасные конструкции и секреты в коде страниц, которые сервер уже отдал
браузеру. Это не полноценный анализ репозитория, но находит скрытые проблемы
в клиентской поставке: eval, innerHTML, ключи, debug-флаги, source maps.
"""

from __future__ import annotations

import re
from typing import List, Pattern, Tuple

from ..models import CONFIG, CONFIRMED, HIGH, LOW, MEDIUM, SUSPECTED, VULN, Finding, Page
from ..utils import truncate

# (kind, severity, category, title, pattern, recommendation)
SAST_RULES: Tuple[Tuple[str, str, str, str, Pattern[str], str], ...] = (
    (
        "sast_eval",
        HIGH,
        VULN,
        "В коде страницы вызывается eval / new Function",
        re.compile(
            r"(?i)(?:[^a-z0-9_]|^)(?:eval|new\s+Function)\s*\(",
        ),
        "Уберите eval/new Function: любой контроль над строкой превращается в XSS/RCE "
        "в браузере. Используйте JSON.parse и явные функции.",
    ),
    (
        "sast_innerhtml",
        MEDIUM,
        VULN,
        "Присвоение innerHTML / document.write без безопасной обёртки",
        re.compile(
            r"(?i)(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|"
            r"insertAdjacentHTML\s*\()",
        ),
        "Не вставляйте пользовательские данные через innerHTML/document.write. "
        "Используйте textContent, DOM API или библиотеку с автоэкранированием.",
    ),
    (
        "sast_hardcoded_secret",
        HIGH,
        VULN,
        "Похоже на захардкоженный секрет в коде страницы",
        re.compile(
            r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|"
            r"private[_-]?key|client[_-]?secret|aws_secret|password)\s*"
            r"[:=]\s*['\"][A-Za-z0-9_\-+/=]{12,}['\"]",
        ),
        "Немедленно отзовите секрет и уберите его из клиентского кода. "
        "На фронт можно отдавать только публичные ключи.",
    ),
    (
        "sast_aws_key",
        HIGH,
        VULN,
        "В коде страницы найден идентификатор ключа AWS (AKIA…)",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        "Отзовите ключ AWS в IAM и удалите его из фронтенда/репозитория.",
    ),
    (
        "sast_private_key",
        HIGH,
        VULN,
        "В ответе страницы есть фрагмент закрытого ключа",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Удалите закрытый ключ из публикации и перевыпустите пару ключей.",
    ),
    (
        "sast_debug_flag",
        MEDIUM,
        CONFIG,
        "В коде включён debug / development режим",
        re.compile(
            r"(?i)(?:DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true|"
            r"NODE_ENV\s*=\s*['\"]development['\"]|YII_DEBUG\s*=\s*true|"
            r"django\.conf\.settings\.DEBUG)",
        ),
        "Отключите debug в production: он раскрывает стеки ошибок и внутренности.",
    ),
    (
        "sast_sourcemap",
        LOW,
        CONFIG,
        "Публичная ссылка на source map (.map)",
        re.compile(r"(?i)sourceMappingURL\s*=\s*\S+\.map"),
        "Не публикуйте .map в production либо закрывайте их авторизацией — "
        "по ним восстанавливают исходники фронтенда.",
    ),
    (
        "sast_dangerously_set_html",
        MEDIUM,
        VULN,
        "React dangerouslySetInnerHTML в поставке страницы",
        re.compile(r"dangerouslySetInnerHTML\s*="),
        "Проверьте, что в HTML попадают только санитизированные данные "
        "(DOMPurify и т. п.), иначе это прямой XSS.",
    ),
    (
        "sast_sql_concat",
        MEDIUM,
        VULN,
        "Похоже на сборку SQL-запроса конкатенацией строк",
        re.compile(
            r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;\"']{0,80}"
            r"(?:\+|\$\{|`[^`]*\$\{)",
        ),
        "Не собирайте SQL строками. Используйте параметризованные запросы "
        "на сервере; клиентский SQL-код не должен содержать логику доступа к БД.",
    ),
)

_POSTMESSAGE = re.compile(
    r"(?i)addEventListener\s*\(\s*['\"]message['\"]",
)


def check_sast(page: Page) -> List[Finding]:
    """Статический разбор тела уже загруженной страницы."""
    body = page.body or ""
    if not body or len(body) < 40:
        return []
    ctype = (page.content_type or "text/html").lower()
    if "html" not in ctype and "javascript" not in ctype and "json" not in ctype:
        return []

    findings: List[Finding] = []
    # Ограничиваем объём для скорости на больших страницах
    haystack = body[:250_000]
    seen = set()

    for kind, severity, category, title, pattern, recommendation in SAST_RULES:
        match = pattern.search(haystack)
        if not match:
            continue
        key = (kind, page.url)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            _finding(page, kind, severity, category, title, recommendation, match, haystack)
        )

    # postMessage: есть слушатель, но в окрестности нет проверки origin
    for match in _POSTMESSAGE.finditer(haystack):
        window = haystack[match.start(): match.start() + 320]
        if ".origin" in window:
            continue
        key = ("sast_postmessage_open", page.url)
        if key in seen:
            break
        seen.add(key)
        findings.append(
            _finding(
                page,
                "sast_postmessage_open",
                MEDIUM,
                VULN,
                "Обработчик postMessage без проверки origin",
                "В обработчике message всегда проверяйте event.origin и формат данных.",
                match,
                haystack,
            )
        )
        break
    return findings


def _finding(page, kind, severity, category, title, recommendation, match, haystack) -> Finding:
    start = max(0, match.start() - 80)
    end = min(len(haystack), match.end() + 80)
    evidence = haystack[start:end].replace("\n", " ")
    return Finding(
        url=page.url,
        title=title,
        category=category,
        severity=severity,
        recommendation=recommendation,
        request=f"GET {page.url} (статический анализ ответа)",
        evidence=truncate(f"Фрагмент кода:\n…{evidence}…", 700),
        confidence=CONFIRMED if kind in (
            "sast_aws_key", "sast_private_key", "sast_eval",
        ) else SUSPECTED,
        kind=kind,
    )
