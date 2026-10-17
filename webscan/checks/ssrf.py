"""Активная проверка SSRF (Server-Side Request Forgery) — режим --pentest.

В отличие от открытого редиректа (раздел ``active.py``, где подменяется адрес,
по которому переходит БРАУЗЕР), здесь проверяется, не запрашивает ли адрес,
подставленный в параметр, сам СЕРВЕР. Пробы ограничены чтением:

* запрашивается cloud-metadata-эндпоинт (169.254.169.254) — если его содержимое
  попадает в ответ, сервер выполнил запрос с правами облачного экземпляра;
* запрашивается заведомо закрытый порт на loopback-адресе и сравнивается с
  контрольным запросом на несуществующий внешний домен — разное поведение
  (другой статус/другое сообщение об ошибке) означает, что сервер реально
  попытался соединиться с адресом, который мы указали, то есть внутренняя сеть
  достижима через этот параметр.

Ничего не изменяется, не удаляется, нагрузка не создаётся: на каждую точку
внедрения уходит не более трёх дополнительных запросов. Проверка выполняется
только при явном согласии оператора (``--pentest`` и флаг подтверждения
полномочий), так как достижимость внутренней сети — более чувствительная
находка, чем типовой DAST.
"""

from __future__ import annotations

import re
from typing import List, Optional, Sequence

from ..http_client import HttpClient
from ..models import CONFIRMED, HIGH, MEDIUM, SUSPECTED, VULN, Finding, Page
from ..utils import describe_request, snippet, truncate

__all__ = ["run_ssrf_checks"]

# Параметры, которые часто означают «сервер сам запросит этот адрес»
# (превью по ссылке, аватар по URL, вебхук, импорт/экспорт, прокси-загрузка и т. п.).
SSRF_PARAM_HINTS = (
    "url", "uri", "link", "src", "source", "image", "img", "avatar", "photo",
    "logo", "icon", "thumbnail", "preview", "proxy", "fetch", "download",
    "import", "feed", "webhook", "callback", "endpoint", "target", "path",
    "file", "document", "host", "domain", "site", "page", "resource",
)

CONTROL_HOST = "bauman-ssrf-unreachable-92841.invalid"
CONTROL_URL = f"http://{CONTROL_HOST}/probe"
# Высокий закрытый порт на loopback: почти никогда не занят, зато адрес заведомо
# внутренний — реальный коннект к нему возможен только с самого сервера.
INTERNAL_PROBE_URL = "http://127.0.0.1:59123/probe"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
METADATA_MARKERS = ("ami-id", "instance-id", "local-ipv4", "placement/", "iam/security-credentials")

# Признаки, что ответ сервера различается из-за попытки реального соединения
# (а не просто из-за разного текста ошибки парсинга URL).
CONNECT_ERROR_HINTS = re.compile(
    r"(?i)connection refused|econnrefused|timed out|timeout|couldn'?t connect|"
    r"no route to host|connection reset|failed to connect"
)
DNS_ERROR_HINTS = re.compile(
    r"(?i)name or service not known|could not resolve host|getaddrinfo|"
    r"nodename nor servname|unknown host|dns lookup failed|enotfound"
)

PROBE_LIMIT = 15  # сколько точек внедрения проверять (запросов — втрое больше)


def _is_ssrf_param(name: str) -> bool:
    lowered = name.lower()
    return any(hint in lowered for hint in SSRF_PARAM_HINTS)


def run_ssrf_checks(client: HttpClient, pages: Sequence[Page], reserve: int = 0) -> List[Finding]:
    """Ищет параметры, похожие на адрес, который запрашивает сам сервер, и проверяет,
    достижима ли через них внутренняя сеть/облачные метаданные."""
    from .active import Target, build_targets  # отложенный импорт — без цикла при тестах модуля

    findings: List[Finding] = []
    targets, _skipped = build_targets(list(pages), test_post_forms=True)
    candidates = [t for t in targets if _is_ssrf_param(t.param_name)][:PROBE_LIMIT]
    if not candidates:
        return findings

    for target in candidates:
        if not client.can_request(reserve):
            break
        found = _probe_target(client, target, reserve)
        if found:
            findings.append(found)
    return findings


def _probe_target(client: HttpClient, target, reserve: int) -> Optional[Finding]:
    # 1) cloud-metadata: самый однозначный и самый опасный случай
    url, data = target.payload_request(METADATA_URL)
    response = client.request(target.method, url, data=data, allow_redirects=False, reserve=reserve)
    if response is not None:
        body = _text(response)
        hit = next((m for m in METADATA_MARKERS if m in body.lower()), None)
        if hit:
            return Finding(
                url=target.page_url,
                title=f"SSRF: сервер раскрывает cloud-metadata через параметр «{target.param_name}»",
                kind="ssrf_metadata_exposure",
                category=VULN,
                severity=HIGH,
                recommendation="Запретите серверным запросам (загрузка превью, вебхуки, импорт "
                               "по URL) обращаться к 169.254.169.254 и другим служебным адресам. "
                               "Используйте белый список разрешённых хостов/схем и, если облачная "
                               "платформа это поддерживает, включите IMDSv2 с токеном.",
                request=describe_request(target.method, url, data),
                evidence=truncate(
                    f"Параметр указывал на {METADATA_URL}; в ответе сервера найдено "
                    f"содержимое cloud-metadata:\n{snippet(body, hit, 200)}",
                    800,
                ),
                confidence=CONFIRMED,
            )

    if not client.can_request(reserve):
        return None  # бюджет исчерпан, дальше пробовать нечем

    # 2) контрольный запрос: заведомо несуществующий внешний домен
    control_url, control_data = target.payload_request(CONTROL_URL)
    control = client.request(target.method, control_url, data=control_data,
                             allow_redirects=False, reserve=reserve)
    if control is None or not client.can_request(reserve):
        return None

    # 3) внутренний адрес с закрытым портом
    internal_url, internal_data = target.payload_request(INTERNAL_PROBE_URL)
    internal = client.request(target.method, internal_url, data=internal_data,
                              allow_redirects=False, reserve=reserve)
    if internal is None:
        return None

    control_body = _text(control).lower()
    internal_body = _text(internal).lower()

    control_is_dns_error = bool(DNS_ERROR_HINTS.search(control_body))
    internal_is_connect_error = bool(CONNECT_ERROR_HINTS.search(internal_body))
    status_differs = control.status_code != internal.status_code

    # Внешний недостижимый домен обычно даёт ошибку DNS; внутренний закрытый порт —
    # ошибку соединения. Разные формулировки ошибки означают, что сервер в обоих
    # случаях действительно пытался соединиться по переданному адресу.
    if (control_is_dns_error and internal_is_connect_error) or (
        status_differs and (internal_is_connect_error or control_is_dns_error)
    ):
        return Finding(
            url=target.page_url,
            title=f"Подозрение на SSRF: сервер соединяется с адресом из параметра «{target.param_name}»",
            kind="ssrf_internal_connect",
            category=VULN,
            severity=MEDIUM,
            recommendation="Проверьте код, который обрабатывает этот параметр: если он "
                           "выполняет HTTP-запрос по переданному адресу, добавьте белый список "
                           "разрешённых хостов и запретите приватные/служебные диапазоны "
                           "адресов (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8 и т. д.).",
            request=describe_request(target.method, internal_url, internal_data),
            evidence=truncate(
                f"Внешний недостижимый адрес ({CONTROL_URL}) → HTTP/{control.status_code}\n"
                f"Внутренний адрес с закрытым портом ({INTERNAL_PROBE_URL}) → "
                f"HTTP/{internal.status_code}\n"
                f"Разные сообщения об ошибке указывают на реальную попытку соединения "
                f"сервера, а не только разбор строки адреса.",
                700,
            ),
            confidence=SUSPECTED,
        )
    return None


def _text(response) -> str:
    try:
        return response.text or ""
    except Exception:
        return ""
