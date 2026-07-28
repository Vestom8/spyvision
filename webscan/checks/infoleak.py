"""Поиск утечек технической информации (раздел 4.5 требований)."""

import re
from typing import List, Tuple

from ..models import CONFIRMED, CONFIG, HIGH, INFO, LOW, MEDIUM, SUSPECTED, VULN, Finding, Page
from ..utils import header_multivalues, mask_secret, snippet, truncate

VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                   "x-generator", "x-runtime", "x-drupal-cache", "x-varnish", "via")

# Заголовки, прямо называющие серверное ПО: даже без номера версии это готовая
# подсказка, какие эксплойты пробовать, поэтому уровень не ниже среднего.
PRODUCT_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                   "x-generator")

# Заголовок содержит номер версии — раскрывает конкретную сборку ПО
VERSION_PATTERN = re.compile(r"\d+\.\d+(\.\d+)?")

WINDOWS_PATH = re.compile(r"[A-Za-z]:\\(?:[\w .\-]+\\){1,}[\w .\-]*")
UNIX_PATH = re.compile(r"/(?:home|root|var/www|usr/local|srv|opt|Users|www|app)/[\w./\-]{4,}")
PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3})\b"
)
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_KEYWORDS = ("todo", "fixme", "hack", "xxx", "password", "passwd", "pwd", "secret",
                    "token", "api key", "apikey", "api_key", "debug", "temporary", "временно",
                    "пароль", "заглушка", "убрать", "не забыть", "backdoor", "test account",
                    "database", "db_", "credentials", "внутренний", "закомментировано")
SOURCE_MAP = re.compile(r"(?:sourceMappingURL\s*=\s*|[\"'](?=[^\"']*\.map[\"']))([^\s\"'*]+\.map)")
STACK_TRACE_MARKERS = (
    "Traceback (most recent call last)", "Fatal error:", "Warning: include(",
    "Notice: Undefined", "Parse error:", "at java.", "System.NullReferenceException",
    "org.springframework", "Microsoft OLE DB Provider", ".php on line",
    "Werkzeug Debugger", "django.core.exceptions", "Whoops, looks like something went wrong",
    "ActionController::", "PDOException",
)
GENERATOR_META = re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)[\"']", re.I)
SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern], ...] = (
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Приватный ключ (PEM)", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Slack-токен", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("JWT-токен", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")),
    ("Строка подключения к БД",
     re.compile(r"\b(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s\"'<>]{6,}")),
    ("Присвоение секрета в коде",
     re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|access[_-]?token)\b\s*[:=]\s*"
                r"[\"'][^\"'\s]{8,}[\"']")),
)


def check_info_leak(page: Page) -> List[Finding]:
    findings: List[Finding] = []
    request_text = f"GET {page.url}"

    def add(title, severity, recommendation, evidence, kind, category=VULN,
            confidence=CONFIRMED):
        findings.append(
            Finding(
                url=page.url,
                title=title,
                category=category,
                severity=severity,
                recommendation=recommendation,
                request=request_text,
                evidence=truncate(evidence, 600),
                confidence=confidence,
                kind=kind,
            )
        )

    # --- версии в заголовках ---
    multi = header_multivalues(page.raw_headers)
    for name in VERSION_HEADERS:
        for value in multi.get(name, []):
            if not value.strip():
                continue
            detailed = bool(VERSION_PATTERN.search(value))
            add(
                f"Заголовок {name} раскрывает используемое ПО"
                + (" и его версию" if detailed else ""),
                MEDIUM if (detailed or name in PRODUCT_HEADERS) else LOW,
                "Скройте или обобщите заголовок (server_tokens off в nginx, ServerTokens Prod "
                "в Apache, expose_php=Off в PHP, удаление X-Powered-By). Точная версия помогает "
                "подобрать готовый эксплойт.",
                f"{name}: {value}",
                "version_header",
                category=CONFIG,
            )

    body = page.body or ""
    if not body:
        return findings

    # --- meta generator ---
    for match in GENERATOR_META.finditer(body):
        add(
            "Метатег generator раскрывает CMS/фреймворк",
            LOW,
            "Удалите метатег generator, если он не нужен.",
            f"<meta name=\"generator\" content=\"{match.group(1)}\">",
            "meta_generator",
            category=CONFIG,
        )
        break

    # --- абсолютные пути ---
    paths = _unique(WINDOWS_PATH.findall(body)) + _unique(UNIX_PATH.findall(body))
    paths = [p for p in _unique(paths) if len(p) > 8][:8]
    if paths:
        add(
            "В ответе раскрыты абсолютные пути файловой системы",
            LOW,
            "Уберите вывод путей из HTML/JS и сообщений об ошибках: они раскрывают структуру "
            "сервера, имя пользователя и используемое ПО.",
            "\n".join(paths),
            "absolute_paths",
        )

    # --- внутренние IP-адреса ---
    ips = _unique(PRIVATE_IP.findall(body))[:8]
    if ips:
        add(
            "В ответе раскрыты внутренние IP-адреса",
            LOW,
            "Уберите внутренние адреса из клиентского кода — они раскрывают схему внутренней сети.",
            "\n".join(ips),
            "internal_ips",
        )

    # --- комментарии разработчиков ---
    interesting = []
    for match in HTML_COMMENT.finditer(body):
        text = match.group(1).strip()
        if not text or text.startswith("["):  # условные комментарии IE
            continue
        lowered = text.lower()
        if any(keyword in lowered for keyword in COMMENT_KEYWORDS):
            interesting.append(truncate(text, 200))
        if len(interesting) >= 5:
            break
    if interesting:
        add(
            "Комментарии разработчиков в HTML",
            LOW,
            "Удаляйте служебные комментарии при сборке production-версии: они часто содержат "
            "внутренние адреса, тестовые учётные данные и подсказки об уязвимых местах.",
            "\n---\n".join(interesting),
            "dev_comments",
            confidence=SUSPECTED,
        )

    # --- source map ---
    maps = _unique(SOURCE_MAP.findall(body))[:5]
    if maps:
        add(
            "Ссылки на файлы карт исходного кода (.map)",
            LOW,
            "Не публикуйте .map-файлы в production: по ним восстанавливается исходный код "
            "фронтенда вместе с комментариями и внутренними URL.",
            "\n".join(maps),
            "source_maps",
        )

    # --- трассировки и ошибки ---
    for marker in STACK_TRACE_MARKERS:
        if marker.lower() in body.lower():
            add(
                "В ответе присутствует трассировка стека или отладочное сообщение",
                MEDIUM,
                "Отключите отображение ошибок пользователям (display_errors=Off, DEBUG=False), "
                "логируйте их на сервере и отдавайте обобщённую страницу ошибки.",
                snippet(body, marker, 200),
                "stack_trace",
            )
            break

    # --- потенциальные секреты (значения маскируются) ---
    for label, pattern in SECRET_PATTERNS:
        match = pattern.search(body)
        if match:
            add(
                f"Возможная утечка секретных данных в коде страницы: {label}",
                HIGH,
                "Уберите секрет из клиентского кода и считайте его скомпрометированным — "
                "перевыпустите ключ/пароль. Секреты должны храниться только на сервере.",
                f"{label}: {mask_secret(match.group(0), 6)} (значение в отчёте маскировано)",
                "secret_in_code",
                confidence=SUSPECTED,
            )
    return findings


def _unique(items) -> List[str]:
    seen = set()
    result = []
    for item in items:
        text = item if isinstance(item, str) else str(item)
        if text not in seen:
            seen.add(text)
            result.append(text)
    return result
