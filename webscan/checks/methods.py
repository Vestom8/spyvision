"""Анализ разрешённых HTTP-методов (раздел 3.6 требований).

Отправляется только OPTIONS; опасные методы не вызываются — фиксируется лишь
факт того, что сервер их объявляет.
"""

from typing import List

from ..http_client import HttpClient
from ..models import CONFIG, CONFIRMED, INFO, LOW, MEDIUM, SUSPECTED, Finding
from ..utils import truncate

DANGEROUS_METHODS = {
    "TRACE": ("Метод TRACE может использоваться для атаки Cross-Site Tracing (XST) — "
              "сервер возвращает полученные заголовки, включая cookie."),
    "TRACK": ("TRACK — аналог TRACE в IIS, приводит к тем же рискам."),
    "PUT": ("PUT позволяет загружать файлы на сервер, что при слабой проверке прав ведёт "
            "к загрузке веб-шелла."),
    "DELETE": ("DELETE позволяет удалять ресурсы на сервере."),
    "CONNECT": ("CONNECT может превратить сервер в прокси для сторонних соединений."),
    "PATCH": ("PATCH изменяет ресурсы; убедитесь, что метод нужен и защищён авторизацией."),
}


def check_http_methods(client: HttpClient, url: str, reserve: int = 0) -> List[Finding]:
    if not client.can_request(reserve):
        return []
    response = client.request("OPTIONS", url, allow_redirects=False, read_body=False,
                              reserve=reserve)
    if response is None:
        return []

    allow = response.headers.get("Allow", "")
    cors_allow = response.headers.get("Access-Control-Allow-Methods", "")
    public = response.headers.get("Public", "")
    declared = _parse_methods(allow) | _parse_methods(public)
    cors_methods = _parse_methods(cors_allow)

    evidence_base = (
        f"OPTIONS {url} -> HTTP/{response.status_code}\n"
        f"Allow: {allow or '(нет)'}\n"
        f"Access-Control-Allow-Methods: {cors_allow or '(нет)'}"
    )

    findings: List[Finding] = []
    if not declared and not cors_methods:
        findings.append(
            Finding(
                url=url,
                title="Сервер не сообщает список разрешённых методов",
                category=CONFIG,
                severity=INFO,
                recommendation="Отсутствие заголовка Allow не является уязвимостью. Проверку "
                               "опасных методов стоит выполнить вручную на уровне веб-сервера.",
                request=f"OPTIONS {url}",
                evidence=truncate(evidence_base, 400),
                confidence=CONFIRMED,
                kind="methods_unknown",
            )
        )
        return findings

    for method in sorted(declared):
        if method in DANGEROUS_METHODS:
            findings.append(
                Finding(
                    url=url,
                    title=f"Разрешён потенциально опасный метод {method}",
                    category=CONFIG,
                    severity=MEDIUM if method in ("PUT", "DELETE", "TRACE", "TRACK", "CONNECT")
                    else LOW,
                    recommendation=DANGEROUS_METHODS[method] + " Отключите метод, если он не "
                    "используется приложением (LimitExcept в Apache, limit_except в nginx, "
                    "TraceEnable off для TRACE).",
                    request=f"OPTIONS {url}",
                    evidence=truncate(evidence_base, 400),
                    confidence=SUSPECTED,
                    kind=f"method_{method.lower()}",
                )
            )

    for method in sorted(cors_methods - declared):
        if method in DANGEROUS_METHODS:
            findings.append(
                Finding(
                    url=url,
                    title=f"Метод {method} объявлен как разрешённый для межсайтовых запросов",
                    category=CONFIG,
                    severity=LOW,
                    recommendation="Уберите изменяющие методы из Access-Control-Allow-Methods, "
                                   "если они не нужны сторонним источникам.",
                    request=f"OPTIONS {url}",
                    evidence=truncate(evidence_base, 400),
                    confidence=SUSPECTED,
                    kind="method_cors",
                )
            )
    return findings


def _parse_methods(value: str) -> set:
    return {item.strip().upper() for item in value.split(",") if item.strip()}
