"""Базовые структуры данных сканера: находки, страницы, формы."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .fixes import steps_for
from .knowledge import describe, references_for

# --- Уровни критичности ---------------------------------------------------
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
INFO = "Info"

SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

# --- Категории проверок ---------------------------------------------------
CONFIG = "Конфигурация"
VULN = "Уязвимость"

# --- Степень уверенности --------------------------------------------------
CONFIRMED = "подтверждено"
SUSPECTED = "подозрение"


@dataclass
class Finding:
    """Одна найденная проблема.

    Поля `threat_type`, `impact` и `detection` заполняются автоматически из базы
    знаний (`knowledge.py`) по значению `kind` — это тип угрозы, объяснение
    опасности и логика, по которой сканер сделал вывод.
    """

    url: str
    title: str
    category: str
    severity: str
    recommendation: str
    request: str = ""
    evidence: str = ""
    confidence: str = CONFIRMED
    kind: str = ""
    threat_type: str = ""
    impact: str = ""
    detection: str = ""
    fix_steps: List[str] = field(default_factory=list)
    # Внешний контекст для известных уязвимостей. Эти поля необязательны,
    # поэтому существующие проверки и отчёты остаются совместимыми.
    references: List[str] = field(default_factory=list)
    identifiers: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    cpe: str = ""
    exploited: bool = False
    # Для находок каталожного анализа: список CVE компонента (VulnMatch.as_dict()).
    vuln_matches: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        info = describe(self.kind)
        known_type = info.get("type", "")
        self.threat_type = self.threat_type or known_type
        self.impact = self.impact or info.get("impact", "")
        self.detection = self.detection or info.get("detection", "")
        if not self.threat_type:
            self.threat_type = ("Ошибка конфигурации" if self.category == CONFIG
                                else "Уязвимость приложения")
        if not self.fix_steps:
            self.fix_steps = steps_for(self.kind, self.recommendation)
        if not self.references:
            # Ссылка на документацию, чтобы разобраться в проблеме глубже (OWASP,
            # CWE/MITRE, PortSwigger). Находки с каталожными данными (NVD/KEV) уже
            # приходят со своими references — здесь это условие не сработает.
            self.references = references_for(self.kind, known_type)

    @property
    def dedup_key(self) -> Tuple[str, str, str]:
        return (self.url, self.title, self.request)


class FindingList:
    """Коллекция находок с дедупликацией и сортировкой по критичности."""

    def __init__(self) -> None:
        self._items: List[Finding] = []
        self._seen: set = set()

    def add(self, finding: Finding) -> bool:
        if finding.dedup_key in self._seen:
            return False
        self._seen.add(finding.dedup_key)
        self._items.append(finding)
        return True

    def extend(self, findings) -> None:
        for finding in findings:
            self.add(finding)

    def discard(self, predicate) -> int:
        """Удаляет находки, для которых ``predicate(finding)`` истинно."""
        kept = [item for item in self._items if not predicate(item)]
        removed = len(self._items) - len(kept)
        self._items = kept
        self._seen = {item.dedup_key for item in kept}
        return removed

    def sorted(self) -> List[Finding]:
        return sorted(
            self._items,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.url, f.title),
        )

    def count_by_severity(self) -> Dict[str, int]:
        counts = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        for finding in self._items:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def count_by_category(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in self._items:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return counts

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self):
        return iter(self._items)


# Находки уровня High, которые сама проба или каталог подтверждают независимо от эвристики:
# сообщение об ошибке СУБД, исполняемая разметка в ответе, ошибка оболочки, записи NVD/KEV.
# Остальные «подозрения» с уровнем High опускаются до Medium: без подтверждения такой
# уровень вводит в заблуждение и засоряет очередь работ.
VERIFIED_HIGH_KINDS = frozenset({
    "xss_js_context", "xss_unescaped", "sqli_error", "nosqli_error", "command_injection",
    "known_cve", "known_cve_kev", "known_bdu", "sqli_auth_bypass", "sqli_boolean_blind", "sqli_time_blind",
})


def apply_confidence_policy(findings: "FindingList") -> int:
    """Единая политика уверенности; возвращает число понижённых находок."""
    lowered = 0
    for finding in findings:
        if (finding.severity == HIGH and finding.confidence == SUSPECTED
                and finding.kind not in VERIFIED_HIGH_KINDS):
            finding.severity = MEDIUM
            lowered += 1
    return lowered


@dataclass
class CookieInfo:
    """Разобранный cookie из заголовка Set-Cookie."""

    name: str
    secure: bool
    http_only: bool
    same_site: Optional[str]
    expires: Optional[int]  # unix timestamp
    max_age: Optional[int]  # секунды
    raw: str


@dataclass
class FormField:
    name: str
    field_type: str
    value: str


@dataclass
class Form:
    """HTML-форма, найденная на странице."""

    page_url: str
    action: str  # абсолютный URL
    method: str  # GET / POST
    fields: List[FormField] = field(default_factory=list)
    raw: str = ""

    def data(self) -> Dict[str, str]:
        """Значения полей по умолчанию (для отправки безопасного запроса)."""
        return {f.name: f.value for f in self.fields if f.name}

    def testable_fields(self) -> List[FormField]:
        skip = {"submit", "button", "image", "reset", "file"}
        return [f for f in self.fields if f.name and f.field_type not in skip]

    def describe(self) -> str:
        names = ", ".join(f.name for f in self.fields if f.name)
        return f"{self.method} {self.action} [{names}]"


@dataclass
class Page:
    """Сохранённое содержимое посещённой страницы."""

    url: str
    depth: int
    status: int
    headers: Dict[str, str]
    raw_headers: List[Tuple[str, str]]
    body: str
    content_type: str
    requested_url: str = ""  # адрес до возможных редиректов
    cookies: List[CookieInfo] = field(default_factory=list)
    truncated: bool = False
    forms: List[Form] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    # Кэш BeautifulSoup после обхода — чтобы checks не парсили HTML повторно.
    soup: Optional[Any] = field(default=None, repr=False, compare=False)

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")
