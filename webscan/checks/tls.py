"""Проверки HTTPS, TLS-сертификата и смешанного контента (раздел 3.2 требований)."""

import datetime
import re
import socket
import ssl
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from bs4 import BeautifulSoup

from ..http_client import HttpClient
from ..models import CONFIG, CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, Finding, Page
from ..utils import truncate

CERT_EXPIRY_WARNING_DAYS = 30
WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
RESOURCE_ATTRS = (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src"),
                  ("form", "action"), ("object", "data"), ("embed", "src"), ("source", "src"),
                  ("audio", "src"), ("video", "src"))
ACTIVE_TAGS = ("script", "link", "iframe", "object", "embed")


def check_https_and_tls(client: HttpClient, base_url: str, reserve: int = 0) -> List[Finding]:
    """Проверки уровня сайта: HTTPS, редирект с HTTP, сертификат."""
    findings: List[Finding] = []
    parsed = urlparse(base_url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)

    if scheme != "https":
        findings.append(
            Finding(
                url=base_url,
                title="Сайт работает по HTTP без шифрования",
                kind="no_https",
                category=CONFIG,
                severity=HIGH,
                recommendation="Включите HTTPS с валидным сертификатом, перенаправляйте весь "
                               "HTTP-трафик на HTTPS и добавьте заголовок HSTS.",
                request=f"GET {base_url}",
                evidence=f"Целевой адрес использует схему http://: {base_url}",
                confidence=CONFIRMED,
            )
        )
        findings.extend(_check_https_available(client, host, parsed, reserve))
    else:
        findings.extend(_check_http_redirect(client, host, parsed, reserve))

    findings.extend(_check_certificate(client, host, port, scheme, base_url))
    return findings


def _https_url(parsed) -> str:
    return urlunparse(("https", parsed.netloc, parsed.path or "/", "", "", ""))


def _http_url(parsed) -> str:
    host = parsed.hostname or ""
    netloc = host if not parsed.port or parsed.port in (80, 443) else f"{host}:{parsed.port}"
    return urlunparse(("http", netloc, parsed.path or "/", "", "", ""))


def _check_https_available(client: HttpClient, host: str, parsed, reserve: int) -> List[Finding]:
    """Если сканируется HTTP-адрес, проверяем, доступна ли вообще HTTPS-версия."""
    url = _https_url(parsed)
    response = client.get(url, allow_redirects=False, read_body=False, reserve=reserve)
    if response is None:
        return [
            Finding(
                url=url,
                title="HTTPS-версия сайта недоступна",
                kind="https_unavailable",
                category=CONFIG,
                severity=HIGH,
                recommendation="Настройте TLS на веб-сервере (сертификат можно получить бесплатно, "
                               "например через Let's Encrypt).",
                request=f"GET {url}",
                evidence="Запрос по HTTPS завершился ошибкой соединения или TLS.",
                confidence=SUSPECTED,
            )
        ]
    return [
        Finding(
            url=url,
            title="HTTPS доступен, но сканируемый адрес использует HTTP",
            kind="http_instead_of_https",
            category=CONFIG,
            severity=MEDIUM,
            recommendation="Настройте постоянное перенаправление (301) с HTTP на HTTPS и HSTS.",
            request=f"GET {url}",
            evidence=f"HTTPS-версия ответила со статусом {response.status_code}.",
            confidence=CONFIRMED,
        )
    ]


def _check_http_redirect(client: HttpClient, host: str, parsed, reserve: int) -> List[Finding]:
    """Проверка редиректа с HTTP на HTTPS."""
    url = _http_url(parsed)
    response = client.get(url, allow_redirects=False, read_body=False, reserve=reserve)
    if response is None:
        return [
            Finding(
                url=url,
                title="HTTP-порт недоступен (редирект на HTTPS проверить не удалось)",
                kind="http_port_closed",
                category=CONFIG,
                severity=INFO,
                recommendation="Отсутствие HTTP-слушателя допустимо, но пользователи, набравшие "
                               "адрес без https://, получат ошибку. Рекомендуется отдавать 301 на HTTPS.",
                request=f"GET {url}",
                evidence="Соединение по HTTP не установлено.",
                confidence=SUSPECTED,
            )
        ]

    location = response.headers.get("Location", "")
    status = response.status_code
    evidence = f"HTTP/{status}\nLocation: {location or '(отсутствует)'}"
    if status in (301, 308) and location.lower().startswith("https://"):
        return []
    if status in (302, 303, 307) and location.lower().startswith("https://"):
        return [
            Finding(
                url=url,
                title="Редирект с HTTP на HTTPS выполняется временным кодом",
                kind="redirect_temporary",
                category=CONFIG,
                severity=LOW,
                recommendation="Используйте постоянный редирект 301 (или 308) — он кэшируется "
                               "браузером и уменьшает окно для перехвата первого запроса.",
                request=f"GET {url}",
                evidence=evidence,
                confidence=CONFIRMED,
            )
        ]
    return [
        Finding(
            url=url,
            title="Нет перенаправления с HTTP на HTTPS",
            kind="redirect_missing",
            category=CONFIG,
            severity=MEDIUM,
            recommendation="Настройте автоматический редирект 301 со всех HTTP-адресов на HTTPS.",
            request=f"GET {url}",
            evidence=evidence,
            confidence=CONFIRMED,
        )
    ]


def _check_certificate(client: HttpClient, host: str, port: int, scheme: str,
                       base_url: str) -> List[Finding]:
    """Проверка валидности, срока действия и совпадения домена в сертификате."""
    if not host or scheme != "https":
        return []
    findings: List[Finding] = []
    url = f"https://{host}:{port}"

    cert, protocol, error = _fetch_certificate(host, port, verify=True)
    if error is not None:
        details, protocol_insecure = _fetch_certificate_unverified(host, port)
        findings.append(
            Finding(
                url=base_url,
                title="Сертификат TLS не прошёл проверку",
                kind="cert_untrusted",
                category=CONFIG,
                severity=HIGH,
                recommendation="Установите сертификат, выданный доверенным центром, с полной "
                               "цепочкой промежуточных сертификатов и корректным именем домена.",
                request=f"TLS handshake {url} (проверка сертификата включена)",
                evidence=truncate(f"Ошибка: {error}\n{details}", 600),
                confidence=CONFIRMED,
            )
        )
        if protocol_insecure:
            findings.extend(_protocol_finding(base_url, protocol_insecure, url))
        return findings

    if protocol:
        findings.extend(_protocol_finding(base_url, protocol, url))

    not_after = _cert_datetime(cert.get("notAfter"))
    not_before = _cert_datetime(cert.get("notBefore"))
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = _cert_names(cert)

    if not_after is not None:
        days_left = (not_after - now).days
        if days_left < 0:
            findings.append(
                Finding(
                    url=base_url,
                    title="Срок действия сертификата истёк",
                    kind="cert_expired",
                    category=CONFIG,
                    severity=HIGH,
                    recommendation="Немедленно перевыпустите сертификат и настройте автоматическое "
                                   "обновление.",
                    request=f"TLS handshake {url}",
                    evidence=f"notAfter: {cert.get('notAfter')} (истёк {abs(days_left)} дн. назад)",
                    confidence=CONFIRMED,
                )
            )
        elif days_left <= CERT_EXPIRY_WARNING_DAYS:
            findings.append(
                Finding(
                    url=base_url,
                    title=f"Сертификат истекает через {days_left} дн.",
                    kind="cert_expiring",
                    category=CONFIG,
                    severity=MEDIUM,
                    recommendation="Обновите сертификат заранее и настройте автопродление "
                                   "(например, certbot renew).",
                    request=f"TLS handshake {url}",
                    evidence=f"notAfter: {cert.get('notAfter')}",
                    confidence=CONFIRMED,
                )
            )
        else:
            findings.append(
                Finding(
                    url=base_url,
                    title="Сертификат TLS валиден",
                    kind="cert_ok",
                    category=CONFIG,
                    severity=INFO,
                    recommendation="Действий не требуется. Следите за сроком автопродления.",
                    request=f"TLS handshake {url}",
                    evidence=truncate(
                        f"Протокол: {protocol}\nnotBefore: {cert.get('notBefore')}\n"
                        f"notAfter: {cert.get('notAfter')} (осталось {days_left} дн.)\n"
                        f"Имена в сертификате: {', '.join(subject) or '-'}",
                        600,
                    ),
                    confidence=CONFIRMED,
                )
            )

    if not_before is not None and not_before > now:
        findings.append(
            Finding(
                url=base_url,
                title="Сертификат ещё не вступил в силу",
                kind="cert_not_yet_valid",
                category=CONFIG,
                severity=HIGH,
                recommendation="Проверьте системное время сервера и дату выпуска сертификата.",
                request=f"TLS handshake {url}",
                evidence=f"notBefore: {cert.get('notBefore')}",
                confidence=CONFIRMED,
            )
        )
    return findings


def _protocol_finding(base_url: str, protocol: str, url: str) -> List[Finding]:
    if protocol and protocol in WEAK_PROTOCOLS:
        return [
            Finding(
                url=base_url,
                title=f"Используется устаревшая версия протокола {protocol}",
                kind="weak_tls",
                category=CONFIG,
                severity=MEDIUM,
                recommendation="Отключите SSLv3/TLS 1.0/TLS 1.1, оставьте TLS 1.2 и TLS 1.3.",
                request=f"TLS handshake {url}",
                evidence=f"Согласованный протокол: {protocol}",
                confidence=CONFIRMED,
            )
        ]
    return []


def _fetch_certificate(host: str, port: int, verify: bool) -> Tuple[dict, Optional[str], Optional[str]]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                return tls_sock.getpeercert() or {}, tls_sock.version(), None
    except ssl.SSLCertVerificationError as exc:
        return {}, None, f"{exc.verify_message or exc}".strip()
    except ssl.SSLError as exc:
        return {}, None, f"Ошибка TLS: {exc}"
    except (socket.timeout, TimeoutError):
        return {}, None, "Таймаут TLS-соединения (5 с)"
    except OSError as exc:
        return {}, None, f"Ошибка соединения: {exc}"


def _fetch_certificate_unverified(host: str, port: int) -> Tuple[str, Optional[str]]:
    """Получает информацию о сертификате без проверки доверия — только для отчёта."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                protocol = tls_sock.version()
                der = tls_sock.getpeercert(binary_form=True) or b""
        info = f"Протокол: {protocol}"
        dates = _der_validity_dates(der)
        if dates:
            info += f"\nСрок действия из сертификата: {dates[0]} — {dates[1]}"
        return info, protocol
    except Exception as exc:
        return f"Не удалось получить сертификат без проверки: {exc}", None


def _der_validity_dates(der: bytes) -> Optional[Tuple[str, str]]:
    """Грубое извлечение даты действия из DER без внешних библиотек."""
    try:
        pattern = re.compile(rb"(\d{12})Z")
        matches = pattern.findall(der)
        if len(matches) >= 2:
            return (_utc_time(matches[0]), _utc_time(matches[1]))
    except Exception:
        pass
    return None


def _utc_time(value: bytes) -> str:
    text = value.decode("ascii", "ignore")
    year = int(text[0:2])
    year += 2000 if year < 50 else 1900
    return f"{year}-{text[2:4]}-{text[4:6]} {text[6:8]}:{text[8:10]}:{text[10:12]} UTC"


def _cert_datetime(value: Optional[str]) -> Optional[datetime.datetime]:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
    return None


def _cert_names(cert: dict) -> List[str]:
    names = []
    for entry in cert.get("subjectAltName", ()):  # [('DNS', 'example.com'), ...]
        if len(entry) == 2:
            names.append(entry[1])
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName" and value not in names:
                names.append(value)
    return names


# --- смешанный контент ----------------------------------------------------
def check_mixed_content(page: Page) -> List[Finding]:
    """HTTP-ресурсы, загружаемые на HTTPS-странице."""
    if not page.is_https or "html" not in page.content_type:
        return []
    try:
        soup = BeautifulSoup(page.body, "html.parser")
    except Exception:
        return []

    active: List[str] = []
    passive: List[str] = []
    for tag, attr in RESOURCE_ATTRS:
        for element in soup.find_all(tag):
            value = (element.get(attr) or "").strip()
            if not value.lower().startswith("http://"):
                continue
            record = f"<{tag} {attr}=\"{value}\">"
            (active if tag in ACTIVE_TAGS else passive).append(record)

    findings: List[Finding] = []
    if active:
        findings.append(
            Finding(
                url=page.url,
                title="Смешанный контент: активные HTTP-ресурсы на HTTPS-странице",
                kind="mixed_active",
                category=CONFIG,
                severity=MEDIUM,
                recommendation="Загружайте скрипты, стили и фреймы только по HTTPS "
                               "(или через относительные пути). Активный смешанный контент "
                               "блокируется браузерами и позволяет подменить код страницы.",
                request=f"GET {page.url}",
                evidence=truncate("\n".join(active[:10]), 600),
                confidence=CONFIRMED,
            )
        )
    if passive:
        findings.append(
            Finding(
                url=page.url,
                title="Смешанный контент: пассивные HTTP-ресурсы на HTTPS-странице",
                kind="mixed_passive",
                category=CONFIG,
                severity=LOW,
                recommendation="Замените http:// на https:// в адресах изображений и медиафайлов.",
                request=f"GET {page.url}",
                evidence=truncate("\n".join(passive[:10]), 600),
                confidence=CONFIRMED,
            )
        )
    return findings
