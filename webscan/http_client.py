"""HTTP-клиент сканера с жёсткими ограничениями выполнения.

Ограничения (раздел 5 требований):
  * таймаут не более 5 секунд;
  * общее число HTTP-запросов не более 400;
  * обход сайта не более 40 страниц в пределах домена;
  * размер читаемого тела ответа не более 1 МБ;
  * принудительная пауза 0.5 с между запросами.
"""

import time
from http.cookies import SimpleCookie
from typing import Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException

from .models import CookieInfo

MAX_TIMEOUT = 5.0
MIN_DELAY = 0.5
MAX_BODY_BYTES = 1024 * 1024  # 1 МБ
MAX_REQUESTS = 400  # жёсткий потолок общего числа HTTP-запросов за сканирование
MAX_PAGES = 40  # жёсткий потолок числа страниц обхода в пределах домена
CHUNK_SIZE = 8192
DEFAULT_USER_AGENT = (
    "BaumanSecScanner/1.0 (educational configuration scanner; "
    "safe, non-destructive checks)"
)


class HttpClient:
    def __init__(
        self,
        timeout: float = MAX_TIMEOUT,
        delay: float = MIN_DELAY,
        max_requests: int = MAX_REQUESTS,
        max_body_bytes: int = MAX_BODY_BYTES,
        user_agent: str = DEFAULT_USER_AGENT,
        verify_tls: bool = True,
        verbose: bool = False,
    ) -> None:
        self.timeout = min(float(timeout), MAX_TIMEOUT)
        self.delay = max(float(delay), MIN_DELAY)
        self.max_requests = int(max_requests)
        self.max_body_bytes = int(max_body_bytes)
        self.verify_tls = verify_tls
        self.verbose = verbose

        self.requests_made = 0
        self.insecure_requests = 0  # запросы, выполненные без проверки сертификата
        self.budget_exhausted = False
        self.errors: List[Tuple[str, str]] = []  # (url, описание ошибки)
        self.tls_errors: Dict[str, str] = {}  # host -> текст ошибки проверки сертификата

        self.session = requests.Session()
        self.session.max_redirects = 5
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close",
            }
        )
        self._last_request_at = 0.0

    # --- бюджет запросов --------------------------------------------------
    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.requests_made)

    def can_request(self, reserve: int = 0) -> bool:
        return self.remaining > reserve

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        if self._last_request_at and elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request_at = time.monotonic()

    # --- основной метод ---------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
        read_body: bool = True,
        max_body_bytes: Optional[int] = None,
        reserve: int = 0,
    ) -> Optional[requests.Response]:
        """Выполняет запрос. Возвращает None при ошибке или исчерпании бюджета."""
        if not self.can_request(reserve):
            self.budget_exhausted = True
            return None

        response = self._send(method, url, headers, data, allow_redirects, verify=self.verify_tls)
        if response is None and self.verify_tls and _host(url) in self.tls_errors:
            # Сертификат не прошёл проверку — повторяем без верификации,
            # чтобы всё равно проанализировать конфигурацию сайта.
            if not self.can_request(reserve):
                self.budget_exhausted = True
                return None
            response = self._send(method, url, headers, data, allow_redirects, verify=False)
            if response is not None:
                self.insecure_requests += 1

        if response is None:
            return None

        # Каждый промежуточный редирект — это отдельный сетевой запрос,
        # он тоже должен учитываться в общем лимите.
        self.requests_made += len(response.history)
        self._read_limited(response, read_body, max_body_bytes)
        return response

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    # --- внутреннее -------------------------------------------------------
    def _send(self, method, url, headers, data, allow_redirects, verify):
        self._throttle()
        self.requests_made += 1
        if self.verbose:
            print(f"  [{self.requests_made:>3}/{self.max_requests}] {method} {url}")
        try:
            import warnings

            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                return self.session.request(
                    method,
                    url,
                    headers=headers,
                    data=data,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    stream=True,
                    verify=verify,
                )
        except requests.exceptions.SSLError as exc:
            self.tls_errors.setdefault(_host(url), str(exc))
            self.errors.append((url, f"Ошибка TLS: {exc}"))
        except RequestException as exc:
            self.errors.append((url, f"{type(exc).__name__}: {exc}"))
        except Exception as exc:  # непредвиденная ошибка не должна ломать скан
            self.errors.append((url, f"{type(exc).__name__}: {exc}"))
        return None

    def _read_limited(self, response: requests.Response, read_body: bool,
                      max_body_bytes: Optional[int]) -> None:
        """Читает не более лимита байт и закрывает соединение."""
        limit = self.max_body_bytes if max_body_bytes is None else max_body_bytes
        content = b""
        truncated = False
        if read_body:
            try:
                for chunk in response.iter_content(CHUNK_SIZE):
                    content += chunk
                    if len(content) >= limit:
                        truncated = True
                        content = content[:limit]
                        break
            except RequestException as exc:
                self.errors.append((response.url, f"Ошибка чтения тела: {exc}"))
            except Exception as exc:
                self.errors.append((response.url, f"Ошибка чтения тела: {exc}"))
        else:
            truncated = True
        try:
            response.close()
        except Exception:
            pass
        response._content = content
        response._content_consumed = True
        response.truncated = truncated  # type: ignore[attr-defined]
        if not response.encoding:
            response.encoding = response.apparent_encoding or "utf-8"


def _host(url: str) -> str:
    from urllib.parse import urlparse

    return (urlparse(url).hostname or "").lower()


# --- работа с заголовками ответа -----------------------------------------
def raw_header_items(response: requests.Response) -> List[Tuple[str, str]]:
    """Все заголовки ответа, включая повторяющиеся, по одному на вхождение."""
    items: List[Tuple[str, str]] = []
    raw = getattr(response, "raw", None)
    raw_headers = getattr(raw, "headers", None)
    if raw_headers is not None:
        # urllib3 v1: get_all(); urllib3 v2: getlist()
        getter = getattr(raw_headers, "get_all", None) or getattr(raw_headers, "getlist", None)
        try:
            names = {name.lower() for name in raw_headers.keys()}
            if getter:
                for name in names:
                    for value in getter(name) or []:
                        items.append((name, value))
                return items
        except Exception:
            items = []
    for name, value in response.headers.items():
        items.append((name.lower(), value))
    return items


def get_set_cookie_values(response: requests.Response) -> List[str]:
    values = [value for name, value in raw_header_items(response) if name.lower() == "set-cookie"]
    if values:
        return values
    combined = response.headers.get("Set-Cookie")
    return [combined] if combined else []


def parse_cookies(response: requests.Response) -> List[CookieInfo]:
    """Разбирает заголовки Set-Cookie этого ответа."""
    cookies: List[CookieInfo] = []
    for raw in get_set_cookie_values(response):
        jar = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            continue
        attrs = raw.lower()
        for name, morsel in jar.items():
            max_age = None
            if morsel["max-age"]:
                try:
                    max_age = int(str(morsel["max-age"]).strip())
                except ValueError:
                    max_age = None
            expires_ts = _parse_http_date(str(morsel["expires"])) if morsel["expires"] else None
            same_site = str(morsel["samesite"]).strip() if morsel["samesite"] else None
            cookies.append(
                CookieInfo(
                    name=name,
                    secure=bool(morsel["secure"]) or "secure" in _attr_names(attrs),
                    http_only=bool(morsel["httponly"]) or "httponly" in _attr_names(attrs),
                    same_site=same_site,
                    expires=expires_ts,
                    max_age=max_age,
                    raw=raw,
                )
            )
    return cookies


def _attr_names(raw_lower: str) -> List[str]:
    """Имена атрибутов cookie (после первого ';')."""
    return [part.split("=")[0].strip() for part in raw_lower.split(";")[1:]]


def _parse_http_date(value: str) -> Optional[int]:
    from email.utils import parsedate_to_datetime

    try:
        return int(parsedate_to_datetime(value).timestamp())
    except Exception:
        return None
