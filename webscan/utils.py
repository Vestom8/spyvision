"""Вспомогательные функции: нормализация URL, работа с доменами, обрезка текста."""

import re
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

DEFAULT_PORTS = {"http": 80, "https": 443}

# Расширения, которые нет смысла скачивать при обходе
BINARY_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".exe", ".msi", ".dmg",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".woff", ".woff2", ".ttf", ".eot",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
)


HOST_RE = re.compile(r"^(?:[A-Za-z0-9_](?:[A-Za-z0-9_\-]*[A-Za-z0-9_])?)(?:\.[A-Za-z0-9_\-]+)*$")


def is_valid_host(host: str) -> bool:
    """Проверка синтаксиса имени хоста (домен, IPv4 или имя в локальной сети)."""
    if not host or len(host) > 253:
        return False
    if host.startswith("[") and host.endswith("]"):  # IPv6-литерал
        return len(host) > 2
    return bool(HOST_RE.match(host))


def supports_tls(host: str, port: int = 443, timeout: float = 3.0) -> bool:
    """Отвечает ли хост на TLS-рукопожатие (нужно для выбора схемы http/https).

    Проверка выполняется на уровне TCP/TLS и не расходует лимит HTTP-запросов.
    Доверие к сертификату здесь не важно: его валидность проверяется отдельно.
    """
    if not host:
        return False
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host):
                return True
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """Приводит URL к каноническому виду: без фрагмента, с портом по умолчанию."""
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    netloc = host
    if parsed.port and parsed.port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    # свернуть повторяющиеся слэши, кроме схемы
    path = re.sub(r"/{2,}", "/", path)
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def same_host(url_a: str, url_b: str) -> bool:
    """Строгое совпадение хоста (субдомены считаются другим сайтом)."""
    host_a, host_b = host_of(url_a), host_of(url_b)
    return bool(host_a) and host_a == host_b


def is_http_url(url: str) -> bool:
    return urlparse(url).scheme.lower() in ("http", "https")


def looks_binary(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(BINARY_EXTENSIONS)


def query_params(url: str) -> List[Tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def build_url(url: str, params: List[Tuple[str, str]]) -> str:
    parsed = urlparse(url)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(params), "")
    )


def set_param(url: str, name: str, value: str) -> str:
    """Возвращает URL с заменённым значением одного query-параметра."""
    params = query_params(url)
    updated = [(k, value if k == name else v) for k, v in params]
    return build_url(url, updated)


def absolutize(base_url: str, link: str) -> str:
    try:
        return urljoin(base_url, link)
    except ValueError:
        return ""


def truncate(text: str, limit: int = 400) -> str:
    if text is None:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"… [обрезано, всего {len(text)} символов]"


def snippet(text: str, needle: str, radius: int = 280) -> str:
    """Фрагмент текста вокруг первого вхождения needle."""
    if not text:
        return ""
    index = text.find(needle)
    if index < 0:
        return truncate(text, radius * 2)
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return prefix + text[start:end] + suffix


def mask_secret(value: str, visible: int = 4) -> str:
    """Маскирует потенциально секретное значение — сканер не хранит секреты."""
    value = str(value)
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * min(12, len(value) - visible)


def header_multivalues(raw_headers: List[Tuple[str, str]]) -> Dict[str, List[str]]:
    """Группирует сырые заголовки по имени в нижнем регистре."""
    result: Dict[str, List[str]] = {}
    for name, value in raw_headers:
        result.setdefault(name.lower(), []).append(value)
    return result


def parse_max_age(directive_value: str) -> Optional[int]:
    match = re.search(r"max-age\s*=\s*\"?(\d+)", directive_value, re.I)
    return int(match.group(1)) if match else None


def describe_request(method: str, url: str, data=None,
                     headers: Optional[Dict[str, str]] = None) -> str:
    """Человекочитаемое описание отправленного запроса для отчёта."""
    parts = [f"{method} {url}"]
    if headers:
        parts.extend(f"{k}: {v}" for k, v in headers.items())
    if data:
        if isinstance(data, dict):
            parts.append("body: " + urlencode(data))
        else:
            text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else str(data)
            parts.append("body: " + truncate(text, 240))
    return "\n".join(parts)
