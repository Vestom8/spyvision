"""HTTP-клиент только для публичных каталогов уязвимостей.

Он полностью отделён от ``webscan.http_client``: запросы к каталогам не
расходуют бюджет запросов к цели и не подчиняются его лимиту 5 с. Разрешены
только HTTPS-адреса из ``ALLOWED_HOSTS``. Проверка TLS не отключается никогда.
"""

from __future__ import annotations

from dataclasses import dataclass
import email.utils
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests

from .cache import OfflineRequestError

ALLOWED_HOSTS = {
    "services.nvd.nist.gov",
    "www.cisa.gov",
    "raw.githubusercontent.com",
    "gitlab.com",
    "bdu.fstec.ru",
}
RETRY_STATUSES = {403, 429, 500, 502, 503, 504}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 2.0
CONNECT_TIMEOUT = 10.0  # на установку соединения; чтение тела — по self.timeout
MAX_RETRY_AFTER = 60.0
USER_AGENT = "Spyvision/1.1 vulnerability-correlation (+catalog lookup; no target data)"


class OfflineError(OfflineRequestError, RuntimeError):
    """Запрос в сеть запрещён режимом --vuln-db-offline."""


class CatalogHttpError(RuntimeError):
    def __init__(self, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class FetchResult:
    status: int
    headers: Dict[str, str]
    content: bytes
    url: str

    def json(self) -> object:
        import json
        return json.loads(self.content.decode("utf-8-sig"))

    def header(self, name: str) -> str:
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return str(value)
        return ""


class CatalogHttpClient:
    """GET-запросы к каталогам с ретраями, backoff и лимитом размера.

    ``session`` и ``sleep`` подменяются в тестах; ``log`` — вывод прогресса.
    """

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES,
                 backoff: float = DEFAULT_BACKOFF, offline: bool = False,
                 session: Optional[requests.Session] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 log: Callable[[str], None] = lambda _msg: None) -> None:
        self.timeout = max(3.0, min(float(timeout), 120.0))
        self.retries = max(1, int(retries))
        self.backoff = max(0.0, float(backoff))
        self.offline = offline
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})
        self.sleep = sleep
        self.log = log
        self.requests_made = 0
        self.dead_hosts: Dict[str, str] = {}  # хосты, не ответившие ни на одну попытку
        self.history: List[Dict[str, object]] = []  # url, params, status — для статистики и тестов

    def get(self, url: str, *, params: Optional[dict] = None, headers: Optional[dict] = None,
            max_bytes: int = 20 * 1024 * 1024, accept_304: bool = False,
            label: str = "") -> FetchResult:
        host = self._validate(url)
        if self.offline:
            raise OfflineError("офлайн-режим: запросы к каталогам отключены")
        if host in self.dead_hosts:
            # Хост уже не отвечал во всех попытках — не тратим время повторно.
            raise CatalogHttpError(self.dead_hosts[host])
        last_error: Optional[Exception] = None
        for attempt in range(self.retries):
            if attempt:
                delay = self._retry_delay(attempt, last_error)
                self.log(f"      … {label or host}: повтор через {delay:.0f} с ({last_error})")
                self.sleep(delay)
            self.requests_made += 1
            entry: Dict[str, object] = {"url": url, "params": dict(params or {}), "status": 0}
            self.history.append(entry)
            try:
                response = self._get_following_redirects(url, params, headers)
            except requests.exceptions.SSLError as exc:
                # Повтор не поможет: цепочка сертификата не доверена.
                raise CatalogHttpError(f"ошибка TLS при обращении к {host}: {exc}") from exc
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
                last_error = CatalogHttpError(f"нет соединения с {host}: {exc.__class__.__name__}")
                continue
            entry["status"] = response.status_code
            if response.status_code == 304 and accept_304:
                response.close()
                return FetchResult(304, dict(response.headers), b"", url)
            if response.status_code in RETRY_STATUSES:
                last_error = CatalogHttpError(f"HTTP {response.status_code} от {host}",
                                              response.status_code)
                last_error.retry_after = response.headers.get("Retry-After", "")  # type: ignore[attr-defined]
                response.close()
                continue
            if response.status_code >= 400:
                response.close()
                raise CatalogHttpError(f"HTTP {response.status_code} от {host}", response.status_code)
            content = self._read_limited(response, max_bytes, label or host)
            return FetchResult(response.status_code, dict(response.headers), content, url)
        if isinstance(last_error, CatalogHttpError) and not last_error.status:
            self.dead_hosts[host] = str(last_error)
        raise last_error or CatalogHttpError(f"не удалось получить ответ от {host}")

    def _get_following_redirects(self, url: str, params: Optional[dict], headers: Optional[dict]):
        """GET с ручным разбором редиректов: каждый переход проверяется по списку источников."""
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            response = self.session.get(current, params=params, headers=headers or {},
                                        timeout=(min(CONNECT_TIMEOUT, self.timeout), self.timeout),
                                        stream=True, allow_redirects=False)
            if response.status_code not in REDIRECT_STATUSES:
                return response
            location = str(response.headers.get("Location") or "")
            response.close()
            if not location:
                raise CatalogHttpError(f"редирект без адреса от {urlparse(current).hostname}")
            current = urljoin(current, location)
            params = None  # адрес перенаправления уже содержит нужные параметры
            try:
                self._validate(current)
            except ValueError:
                raise CatalogHttpError("перенаправление на недопустимый источник отклонено") from None
        raise CatalogHttpError("слишком много перенаправлений")

    def _read_limited(self, response, max_bytes: int, label: str) -> bytes:
        parts: List[bytes] = []
        total = 0
        next_report = 5 * 1024 * 1024
        try:
            for chunk in response.iter_content(256 * 1024):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise CatalogHttpError(f"{label}: ответ больше допустимых {max_bytes // (1024 * 1024)} МБ")
                parts.append(chunk)
                if total >= next_report:
                    self.log(f"      ↓ {label}: {total / (1024 * 1024):.0f} МБ…")
                    next_report += 5 * 1024 * 1024
        finally:
            response.close()
        return b"".join(parts)

    def _retry_delay(self, attempt: int, error: Optional[Exception]) -> float:
        delay = self.backoff * (2 ** (attempt - 1))
        retry_after = str(getattr(error, "retry_after", "") or "").strip()
        if retry_after:
            seconds: Optional[float] = None
            if retry_after.isdigit():
                seconds = float(retry_after)
            else:
                try:
                    seconds = email.utils.parsedate_to_datetime(retry_after).timestamp() - time.time()
                except (TypeError, ValueError, IndexError):
                    seconds = None
            if seconds is not None:
                delay = max(delay, min(max(seconds, 0.0), MAX_RETRY_AFTER))
        return delay

    @staticmethod
    def _validate(url: str) -> str:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
            raise ValueError(f"Недопустимый источник каталога: {url}")
        return host
