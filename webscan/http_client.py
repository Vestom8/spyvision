"""HTTP-клиент сканера с жёсткими ограничениями выполнения.

Ограничения:
  * таймаут не более 5 секунд;
  * общее число HTTP-запросов не более 1000;
  * обход сайта не более 100 страниц в пределах домена;
  * размер читаемого тела ответа не более 1 МБ;
  * принудительная пауза 0.1 с между стартами запросов.

Параллельность (``request_many``) только перекрывает ожидание ответов: старты
запросов по-прежнему разнесены не менее чем на ``delay`` секунд, то есть частота
обращений к сайту не выше, чем при последовательной работе. Счётчики и лимит
запросов защищены блокировкой.
"""

import ipaddress
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import warnings
from http.cookies import SimpleCookie
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin

import requests
import urllib3
from requests.exceptions import RequestException

from .models import CookieInfo

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

MAX_TIMEOUT = 5.0
MIN_DELAY = 0.1
MAX_BODY_BYTES = 1024 * 1024  # 1 МБ
MAX_REQUESTS = 1000  # жёсткий потолок общего числа HTTP-запросов за сканирование
MAX_PAGES = 100  # жёсткий потолок числа страниц обхода в пределах домена
CHUNK_SIZE = 8192
MAX_CONCURRENCY = 8
DEFAULT_CONCURRENCY = 4
READ_DEADLINE = 20.0  # общий срок чтения тела ответа: защита от «медленной капли» (slowloris)
MAX_CONSECUTIVE_TIMEOUTS = 6  # после стольких таймаутов подряд сайт считается «молчащим»
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
        concurrency: int = DEFAULT_CONCURRENCY,
    ) -> None:
        self.timeout = min(float(timeout), MAX_TIMEOUT)
        self.delay = max(float(delay), MIN_DELAY)
        self.max_requests = int(max_requests)
        self.max_body_bytes = int(max_body_bytes)
        self.verify_tls = verify_tls
        self.verbose = verbose
        self.concurrency = max(1, min(int(concurrency), MAX_CONCURRENCY))
        self.rate_limited = False  # сайт ответил 429/503 — переходим на щадящий режим
        self._lock = threading.RLock()
        self._next_slot = 0.0

        self.requests_made = 0
        self.insecure_requests = 0  # запросы, выполненные без проверки сертификата
        self.budget_exhausted = False
        self.errors: List[Tuple[str, str]] = []  # (url, описание ошибки)
        self.tls_errors: Dict[str, str] = {}  # host -> текст ошибки проверки сертификата

        self.session = requests.Session()
        self.session.max_redirects = 5
        self.session.hooks["response"].append(_block_internal_redirect)
        adapter = requests.adapters.HTTPAdapter(pool_connections=MAX_CONCURRENCY,
                                                pool_maxsize=MAX_CONCURRENCY * 2)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": "*/*",
                "Accept-Encoding": "gzip, deflate",
            }
        )
        self.consecutive_timeouts = 0
        self.gave_up = False  # True, если сканирование остановлено из-за молчащего сайта

    # --- бюджет запросов --------------------------------------------------
    @property
    def remaining(self) -> int:
        return max(0, self.max_requests - self.requests_made)

    def can_request(self, reserve: int = 0) -> bool:
        return self.remaining > reserve

    def _acquire(self, reserve: int = 0) -> bool:
        """Атомарно занимает единицу бюджета; False — бюджет исчерпан."""
        with self._lock:
            if self.max_requests - self.requests_made <= reserve:
                self.budget_exhausted = True
                return False
            self.requests_made += 1
            return True

    def _throttle(self) -> None:
        """Резервирует слот старта: между стартами любых запросов — не меньше delay."""
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self.delay
        wait = slot - time.monotonic()
        if wait > 0:
            time.sleep(wait)

    def _note_response(self, response) -> None:
        """429/503 — признак ограничения частоты: убавляем параллельность и замедляемся."""
        if response.status_code in (429, 503) and not self.rate_limited:
            with self._lock:
                self.rate_limited = True
                self.concurrency = 1
                self.delay = max(self.delay, 0.5)

    def request_many(self, calls: Sequence[Tuple[str, str, dict]]) -> List[Optional[requests.Response]]:
        """Выполняет запросы ``(method, url, kwargs)`` параллельно; результаты — в порядке ввода.

        Анализ ответов вызывающий код ведёт последовательно по этому списку, поэтому
        порядок находок не зависит от скорости ответов.
        """
        if not calls:
            return []
        workers = min(self.concurrency, len(calls))
        if workers <= 1:
            return [self.request(method, url, **kwargs) for method, url, kwargs in calls]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(self.request, method, url, **kwargs)
                       for method, url, kwargs in calls]
            return [future.result() for future in futures]

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
        if self.consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
            # Сайт/WAF молча не отвечает: каждый запрос стоил бы полный таймаут.
            self.gave_up = True
            return None
        if not self._acquire(reserve):
            return None

        host = _host(url)
        # Если TLS для хоста уже падал — сразу ходим без verify (без двойного запроса).
        known_bad_tls = bool(self.verify_tls and host in self.tls_errors)
        verify = False if known_bad_tls else self.verify_tls
        response = self._send(method, url, headers, data, allow_redirects, verify=verify)

        if (
            response is None
            and self.verify_tls
            and not known_bad_tls
            and host in self.tls_errors
        ):
            # Первая ошибка сертификата — один повтор без верификации.
            if not self._acquire(reserve):
                return None
            response = self._send(method, url, headers, data, allow_redirects, verify=False)
            if response is not None:
                with self._lock:
                    self.insecure_requests += 1
        elif response is not None and known_bad_tls:
            with self._lock:
                self.insecure_requests += 1

        if response is None:
            return None
        self._note_response(response)

        # Каждый промежуточный редирект — это отдельный сетевой запрос,
        # он тоже должен учитываться в общем лимите.
        with self._lock:
            self.consecutive_timeouts = 0
            self.requests_made += len(response.history)
        self._read_limited(response, read_body, max_body_bytes)
        return response

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    # --- внутреннее -------------------------------------------------------
    def _send(self, method, url, headers, data, allow_redirects, verify):
        self._throttle()
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
            with self._lock:
                self.tls_errors.setdefault(_host(url), str(exc))
                self.errors.append((url, f"Ошибка TLS: {exc}"))
        except requests.exceptions.Timeout as exc:
            with self._lock:
                self.consecutive_timeouts += 1
                self.errors.append((url, f"{type(exc).__name__}: {exc}"))
        except RequestException as exc:
            with self._lock:
                self.errors.append((url, f"{type(exc).__name__}: {exc}"))
        except Exception as exc:  # непредвиденная ошибка не должна ломать скан
            with self._lock:
                self.errors.append((url, f"{type(exc).__name__}: {exc}"))
        return None

    def _read_limited(self, response: requests.Response, read_body: bool,
                      max_body_bytes: Optional[int]) -> None:
        """Читает не более лимита байт и закрывает соединение."""
        limit = self.max_body_bytes if max_body_bytes is None else max_body_bytes
        content = b""
        truncated = False
        deadline = time.monotonic() + max(READ_DEADLINE, self.timeout * 4)
        if read_body:
            try:
                for chunk in response.iter_content(CHUNK_SIZE):
                    content += chunk
                    if len(content) >= limit:
                        truncated = True
                        content = content[:limit]
                        break
                    if time.monotonic() > deadline:
                        truncated = True
                        break
            except Exception as exc:
                with self._lock:
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


def _is_internal_host(host: str) -> bool:
    """localhost, loopback, частные и link-local адреса (по литералу, без DNS-запроса)."""
    host = (host or "").strip("[]").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (address.is_loopback or address.is_private or address.is_link_local
            or address.is_unspecified or address.is_reserved)


def _block_internal_redirect(response, *_args, **_kwargs):
    """Публичный сайт не может перенаправить сканер на внутренний адрес (защита от SSRF)."""
    location = response.headers.get("Location")
    if not location or response.status_code not in (301, 302, 303, 307, 308):
        return response
    source = _host(response.url)
    destination = _host(urljoin(response.url, location))
    if _is_internal_host(destination) and not _is_internal_host(source):
        response.close()
        raise requests.exceptions.InvalidURL("перенаправление на внутренний адрес отклонено")
    return response


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
