"""Проверка политики CORS (раздел 3.4 требований)."""

from typing import List

from ..http_client import HttpClient
from ..models import CONFIG, CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, Finding
from ..utils import describe_request, truncate

TEST_ORIGIN = "https://bauman-scanner-test.example.net"
PROBES = (
    ("сторонний домен", TEST_ORIGIN),
    ("null", "null"),
    ("*", "*"),
)


def check_cors(client: HttpClient, url: str, reserve: int = 0) -> List[Finding]:
    findings: List[Finding] = []
    reported: set = set()
    for label, origin in PROBES:
        if not client.can_request(reserve):
            break
        headers = {"Origin": origin}
        response = client.get(url, headers=headers, allow_redirects=False,
                              read_body=False, reserve=reserve)
        if response is None:
            continue

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        expose = response.headers.get("Access-Control-Expose-Headers", "")
        if not acao:
            continue

        request_text = describe_request("GET", url, headers=headers)
        evidence = truncate(
            f"HTTP/{response.status_code}\n"
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac or '(нет)'}\n"
            f"Access-Control-Expose-Headers: {expose or '(нет)'}",
            600,
        )
        credentials = acac.strip().lower() == "true"
        reflected = acao.strip() == origin and origin not in ("*",)
        probe_start = len(findings)

        if acao.strip() == "*" and credentials:
            findings.append(
                Finding(
                    url=url,
                    title="Опасная политика CORS: Allow-Origin: * вместе с Allow-Credentials: true",
                    kind="cors_wildcard_credentials",
                    category=CONFIG,
                    severity=HIGH,
                    recommendation="Такая комбинация запрещена спецификацией и указывает на "
                                   "ошибочную конфигурацию. Укажите конкретный список доверенных "
                                   "источников либо уберите Access-Control-Allow-Credentials.",
                    request=request_text,
                    evidence=evidence,
                    confidence=CONFIRMED,
                )
            )
        elif reflected and credentials:
            findings.append(
                Finding(
                    url=url,
                    title="CORS отражает произвольный Origin вместе с Allow-Credentials: true",
                    kind="cors_reflect_credentials",
                    category=CONFIG,
                    severity=HIGH,
                    recommendation="Не отражайте заголовок Origin. Сравнивайте его с белым списком "
                                   "доверенных доменов — иначе любой сайт может читать данные "
                                   "аутентифицированного пользователя.",
                    request=request_text,
                    evidence=evidence,
                    confidence=CONFIRMED,
                )
            )
        elif reflected:
            findings.append(
                Finding(
                    url=url,
                    title="CORS отражает произвольный Origin",
                    kind="cors_reflect",
                    category=CONFIG,
                    severity=MEDIUM,
                    recommendation="Разрешайте только заранее известные источники (белый список).",
                    request=request_text,
                    evidence=evidence,
                    confidence=CONFIRMED,
                )
            )
        elif acao.strip().lower() == "null" and label == "null":
            findings.append(
                Finding(
                    url=url,
                    title="CORS разрешает Origin: null",
                    kind="cors_null",
                    category=CONFIG,
                    severity=MEDIUM if credentials else LOW,
                    recommendation="Origin: null отправляют изолированные документы (sandbox-iframe, "
                                   "data: URL). Такой источник нельзя считать доверенным.",
                    request=request_text,
                    evidence=evidence,
                    confidence=CONFIRMED,
                )
            )
        elif acao.strip() == "*":
            findings.append(
                Finding(
                    url=url,
                    title="CORS открыт для всех источников (Access-Control-Allow-Origin: *)",
                    kind="cors_wildcard",
                    category=CONFIG,
                    severity=LOW,
                    recommendation="Для публичных данных это допустимо. Если по этому адресу "
                                   "отдаются приватные данные, ограничьте список источников.",
                    request=request_text,
                    evidence=evidence,
                    confidence=SUSPECTED,
                )
            )

        # одну и ту же ошибку конфигурации не дублируем для каждого Origin
        fresh = [f for f in findings[probe_start:] if f.title not in reported]
        reported.update(f.title for f in fresh)
        findings[probe_start:] = fresh
    return findings


def check_preflight(client: HttpClient, url: str, reserve: int = 0) -> List[Finding]:
    """Предварительный запрос OPTIONS с Origin — что сервер разрешает межсайтово."""
    if not client.can_request(reserve):
        return []
    headers = {
        "Origin": TEST_ORIGIN,
        "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "X-Test-Header",
    }
    response = client.request("OPTIONS", url, headers=headers, allow_redirects=False,
                              read_body=False, reserve=reserve)
    if response is None:
        return []
    acao = response.headers.get("Access-Control-Allow-Origin", "")
    methods = response.headers.get("Access-Control-Allow-Methods", "")
    if not acao or not methods:
        return []
    if acao.strip() in ("*", TEST_ORIGIN):
        return [
            Finding(
                url=url,
                title="Preflight-запрос разрешает межсайтовые методы изменения данных",
                kind="cors_preflight",
                category=CONFIG,
                severity=LOW,
                recommendation="Проверьте, что список Access-Control-Allow-Methods минимально "
                               "необходим, а источники ограничены белым списком.",
                request=describe_request("OPTIONS", url, headers=headers),
                evidence=truncate(
                    f"HTTP/{response.status_code}\nAccess-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Methods: {methods}",
                    400,
                ),
                confidence=CONFIRMED,
            )
        ]
    return []
