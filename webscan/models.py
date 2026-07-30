"""Базовые структуры данных сканера: находки, страницы, формы."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .knowledge import describe, owasp_for

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
    опасности и логика, по которой сканер сделал вывод. Если в базе есть поле
    ``fix``, им заменяется краткая `recommendation` из кода проверки.
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
    owasp: str = ""  # категория OWASP Top 10:2021

    def __post_init__(self) -> None:
        info = describe(self.kind)
        self.threat_type = self.threat_type or info.get("type", "")
        self.impact = self.impact or info.get("impact", "")
        self.detection = self.detection or info.get("detection", "")
        self.owasp = self.owasp or info.get("owasp") or owasp_for(self.kind)
        if info.get("fix"):
            self.recommendation = info["fix"]
        if not self.threat_type:
            self.threat_type = ("Ошибка конфигурации" if self.category == CONFIG
                                else "Уязвимость приложения")

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

    @property
    def is_https(self) -> bool:
        return self.url.lower().startswith("https://")
