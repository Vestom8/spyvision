"""Уровень критичности уязвимости по методике ФСТЭК России (методический документ от 30.06.2025).

Итоговый показатель::

    V = Icvss × Iinfr × (Iat + Iimp)

* ``Icvss`` — базовая оценка CVSS (методика берёт 3.1 из БДУ; если её нет, используется
  оценка NVD, а при её отсутствии — CVSS 2.0 с пометкой).
* ``Iinfr = 0,5·K + 0,2·L + 0,3·P`` — влияние на функционирование информационной системы:
  K — тип уязвимого компонента, L — доля уязвимых компонентов, P — доступность из Интернета.
* ``Iat = E`` — возможность эксплуатации: 0,6 — эксплуатируется в реальных атаках (KEV),
  0,3 — есть сведения об эксплойте, 0,1 — сведений нет.
* ``Iimp = H`` — последствия: наибольшее из значений таблицы (RCE 0,5 … XSS 0,1).

Пороги: ``V > 8,0`` — критический; ``5,0 ≤ V ≤ 8,0`` — высокий; ``2,0 ≤ V < 5,0`` — средний;
``V < 2,0`` — низкий.

Рекомендуемые сроки устранения по уровню: критический — до 24 часов, высокий — до 7 дней,
средний — до 4 недель, низкий — до 4 месяцев (отсчёт от даты сканирования; 4 месяца
принято как 120 дней). Если обновление получить, установить или проверить нельзя,
методика предписывает компенсирующие меры.

Что сканер определить не может, принято по умолчанию и показывается в отчёте:
тип компонента (``server``, настраивается ``--fstec-component-type``), периметр (по адресу
цели, переопределяется ``--fstec-perimeter``), доля уязвимых компонентов (из числа
найденных компонентов с версией). Если последствия определить не удалось, ``Iimp = 0``:
оценка — нижняя граница, в расчёте это отмечено.

Константы взяты из текста методики, найденного в открытых источниках (rulaws.ru); в
таблице K для «других компонентов» в источнике указано расхождение (0,1 и 0,5) — принято
произведение 0,5·0,1 = 0,05. **Перед использованием для отчётности сверьте значения с
первоисточником на fstec.ru.**
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
import ipaddress
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

WEIGHT_K = 0.5
WEIGHT_L = 0.2
WEIGHT_P = 0.3

# тип компонента → (Ki, название по методике)
COMPONENT_TYPES: Dict[str, Tuple[float, str]] = {
    "important": (1.1, "важные процессы, функции, полномочия"),
    "firewall": (0.9, "межсетевые экраны"),
    "network": (0.9, "сетевые устройства и шлюзы"),
    "telecom": (0.8, "телекоммуникационное оборудование"),
    "server": (0.7, "серверы"),
    "workstation": (0.5, "пользовательские устройства"),
    "storage": (0.4, "системы хранения данных"),
    "other": (0.1, "другие компоненты"),
}
DEFAULT_COMPONENT_TYPE = "server"

PERIMETER_INTERNET = 1.1
PERIMETER_INTERNAL = 0.6

E_ATTACKED = 0.6
E_EXPLOIT = 0.3
E_NONE = 0.1

CRITICAL_ABOVE = 8.0
HIGH_FROM = 5.0
MEDIUM_FROM = 2.0

LEVEL_CRITICAL = "Критический"
LEVEL_HIGH = "Высокий"
LEVEL_MEDIUM = "Средний"
LEVEL_LOW = "Низкий"
LEVEL_RANK = {LEVEL_CRITICAL: 4, LEVEL_HIGH: 3, LEVEL_MEDIUM: 2, LEVEL_LOW: 1}

# уровень → (срок словами, календарных дней от даты сканирования)
DEADLINES: Dict[str, Tuple[str, int]] = {
    LEVEL_CRITICAL: ("до 24 часов", 1),
    LEVEL_HIGH: ("до 7 дней", 7),
    LEVEL_MEDIUM: ("до 4 недель", 28),
    LEVEL_LOW: ("до 4 месяцев", 120),
}
COMPENSATING_MEASURES = ("изменение конфигурации, ограничение или отключение уязвимых функций, "
                         "правила средств защиты, усиленный мониторинг событий безопасности")

CVSS_PREFERENCE = ("3.1", "3.0", "4.0", "2.0")

# (Hk, название, шаблоны RU+EN по описанию/названию уязвимости)
CONSEQUENCES: Tuple[Tuple[float, str, Tuple[str, ...]], ...] = (
    (0.5, "выполнение произвольного кода", (
        r"произвольн\w* (?:код|команд)", r"выполн\w+ (?:произвольн\w+ )?(?:код|команд)",
        r"remote code execution", r"execut\w+ arbitrary (?:code|commands?)", r"arbitrary code",
        r"code execution", r"command injection", r"\brce\b")),
    (0.5, "повышение привилегий", (
        r"повыс\w+ привилег", r"privilege escalation", r"escalat\w+ privileges",
        r"elevat\w+ privileges", r"gain\w* (?:elevated |root |admin\w* )?privileges")),
    (0.4, "обход механизмов безопасности", (
        r"обойти (?:ограничен|механизм|защит|аутентификац|авторизац)",
        r"обход\w* (?:ограничен|механизм|защит|аутентификац|авторизац)",
        r"\bbypass", r"authentication bypass")),
    (0.34, "внедрение кода", (
        r"внедр\w+ (?:sql|код|команд)", r"sql[- ]?инъекц", r"sql injection", r"\binjection\b",
        r"внедрение")),
    (0.3, "получение конфиденциальной информации", (
        r"раскр\w+ (?:защищаем|конфиденциал|информац)",
        r"получ\w+ (?:доступ\w* к )?(?:защищаем|конфиденциал)",
        r"information disclosure", r"sensitive information", r"\bdisclos")),
    (0.3, "нарушение целостности данных", (
        r"нарушить целостность", r"модифицир", r"изменить (?:данные|содержимое)",
        r"\bintegrity\b", r"\btamper")),
    (0.26, "отказ в обслуживании", (
        r"отказ\w* в обслуживании", r"denial[- ]of[- ]service", r"\bdos\b")),
    (0.22, "перезапись произвольных файлов", (
        r"перезапис", r"overwrit\w+ arbitrary files?")),
    (0.2, "запись локальных файлов", (
        r"запис\w+ (?:локальн|произвольн)\w* файл", r"write\w* arbitrary files?",
        r"arbitrary file upload")),
    (0.18, "чтение локальных файлов", (
        r"прочитать (?:произвольн|локальн)", r"чтение (?:произвольн|локальн)",
        r"read\w* arbitrary files?", r"path traversal", r"directory traversal", r"local file")),
    (0.12, "поддельный пользовательский интерфейс", (
        r"подмен\w+ интерфейс", r"clickjacking", r"\bui redress", r"\bspoof")),
    (0.1, "межсайтовый скриптинг", (
        r"межсайтов\w+ (?:сценарн|скриптинг)", r"cross[- ]site scripting", r"\bxss\b")),
)
_COMPILED = [(value, label, [re.compile(p, re.I) for p in patterns])
             for value, label, patterns in CONSEQUENCES]

# CWE → значение H: используется, когда в тексте последствия не названы.
CWE_CONSEQUENCES: Dict[str, Tuple[float, str]] = {
    "CWE-78": (0.5, "выполнение произвольного кода"), "CWE-77": (0.5, "выполнение произвольного кода"),
    "CWE-94": (0.5, "выполнение произвольного кода"), "CWE-502": (0.5, "выполнение произвольного кода"),
    "CWE-416": (0.5, "выполнение произвольного кода"), "CWE-787": (0.5, "выполнение произвольного кода"),
    "CWE-119": (0.5, "выполнение произвольного кода"), "CWE-120": (0.5, "выполнение произвольного кода"),
    "CWE-121": (0.5, "выполнение произвольного кода"), "CWE-122": (0.5, "выполнение произвольного кода"),
    "CWE-89": (0.34, "внедрение кода"),
    "CWE-287": (0.4, "обход механизмов безопасности"), "CWE-306": (0.4, "обход механизмов безопасности"),
    "CWE-862": (0.4, "обход механизмов безопасности"), "CWE-863": (0.4, "обход механизмов безопасности"),
    "CWE-288": (0.4, "обход механизмов безопасности"),
    "CWE-200": (0.3, "получение конфиденциальной информации"),
    "CWE-209": (0.3, "получение конфиденциальной информации"),
    "CWE-532": (0.3, "получение конфиденциальной информации"),
    "CWE-400": (0.26, "отказ в обслуживании"), "CWE-770": (0.26, "отказ в обслуживании"),
    "CWE-674": (0.26, "отказ в обслуживании"), "CWE-835": (0.26, "отказ в обслуживании"),
    "CWE-476": (0.26, "отказ в обслуживании"),
    "CWE-434": (0.2, "запись локальных файлов"),
    "CWE-22": (0.18, "чтение локальных файлов"), "CWE-23": (0.18, "чтение локальных файлов"),
    "CWE-79": (0.1, "межсайтовый скриптинг"),
}

_PRIVATE_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp", ".home", ".localdomain")


@dataclass
class FstecContext:
    """Параметры, общие для всех уязвимостей одного сканирования."""

    component_type: str = DEFAULT_COMPONENT_TYPE
    internet_facing: bool = True
    vulnerable_share: float = 0.0   # доля найденных компонентов, у которых есть уязвимости
    perimeter_source: str = "auto"  # auto | internet | internal
    scan_date: Optional[date] = None   # от этой даты отсчитываются сроки; None — сегодня

    @property
    def k(self) -> float:
        return COMPONENT_TYPES.get(self.component_type, COMPONENT_TYPES[DEFAULT_COMPONENT_TYPE])[0]

    @property
    def l(self) -> float:  # noqa: E743 - обозначение из методики
        share = self.vulnerable_share
        if share > 0.7:
            return 1.0
        if share >= 0.5:
            return 0.8
        if share >= 0.1:
            return 0.6
        return 0.5

    @property
    def p(self) -> float:
        return PERIMETER_INTERNET if self.internet_facing else PERIMETER_INTERNAL

    @property
    def iinfr(self) -> float:
        return WEIGHT_K * self.k + WEIGHT_L * self.l + WEIGHT_P * self.p

    def as_dict(self) -> Dict[str, object]:
        return {
            "component_type": self.component_type,
            "component_label": COMPONENT_TYPES.get(
                self.component_type, COMPONENT_TYPES[DEFAULT_COMPONENT_TYPE])[1],
            "internet_facing": self.internet_facing,
            "perimeter_source": self.perimeter_source,
            "vulnerable_share": round(self.vulnerable_share, 2),
            "k": self.k, "l": self.l, "p": self.p, "iinfr": round(self.iinfr, 3),
        }


def normalise_component_type(value: str) -> str:
    value = str(value or "").strip().lower()
    return value if value in COMPONENT_TYPES else DEFAULT_COMPONENT_TYPE


def detect_perimeter(target: str, mode: str = "auto") -> Tuple[bool, str]:
    """``(доступно_из_интернета, источник)``; ``mode`` — auto | internet | internal."""
    mode = str(mode or "auto").strip().lower()
    if mode == "internet":
        return True, "internet"
    if mode == "internal":
        return False, "internal"
    host = (urlparse(target if "//" in str(target) else f"//{target}").hostname or "").lower()
    if not host:
        return True, "auto"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # имя без точки или с «внутренним» суффиксом — внутренний ресурс
        internal = host == "localhost" or "." not in host or host.endswith(_PRIVATE_SUFFIXES)
        return not internal, "auto"
    internal = (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved)
    return not internal, "auto"


def deadline_for(level: str, start: Optional[date] = None) -> Dict[str, object]:
    """``{"deadline": "до 7 дней", "days": 7, "due": "2026-10-18"}`` для уровня критичности."""
    label, days = DEADLINES.get(level, DEADLINES[LEVEL_LOW])
    begin = start or date.today()
    return {"deadline": label, "deadline_days": days,
            "due": (begin + timedelta(days=days)).isoformat()}


def level_for(score: float) -> str:
    if score > CRITICAL_ABOVE:
        return LEVEL_CRITICAL
    if score >= HIGH_FROM:
        return LEVEL_HIGH
    if score >= MEDIUM_FROM:
        return LEVEL_MEDIUM
    return LEVEL_LOW


def consequence_of(text: str, cwes: Iterable[str] = ()) -> Tuple[float, str]:
    """Наибольшее значение H по тексту и CWE; ``(0.0, "")``, если последствия не определены."""
    best: Tuple[float, str] = (0.0, "")
    haystack = str(text or "")
    for value, label, patterns in _COMPILED:
        if value > best[0] and any(p.search(haystack) for p in patterns):
            best = (value, label)
    for cwe in cwes or ():
        found = CWE_CONSEQUENCES.get(str(cwe).strip().upper())
        if found and found[0] > best[0]:
            best = found
    return best


def pick_cvss(bdu_scores: Optional[Dict[str, float]],
              nvd: Optional[Dict[str, object]]) -> Optional[Tuple[float, str, str]]:
    """``(оценка, версия CVSS, источник)``: сначала БДУ 3.x, затем NVD, затем остальное БДУ."""
    scores = {str(k): float(v) for k, v in (bdu_scores or {}).items()
              if isinstance(v, (int, float))}
    for version in CVSS_PREFERENCE[:2]:
        if version in scores:
            return scores[version], version, "БДУ"
    if nvd and isinstance(nvd.get("score"), (int, float)):
        return float(nvd["score"]), str(nvd.get("version") or "NVD"), "NVD"
    for version in CVSS_PREFERENCE[2:]:
        if version in scores:
            return scores[version], version, "БДУ"
    return None


def assess(*, bdu_scores: Optional[Dict[str, float]] = None, nvd_cvss: Optional[Dict[str, object]] = None,
           attacked: bool = False, exploit_known: bool = False, text: str = "",
           cwes: Sequence[str] = (), context: Optional[FstecContext] = None) -> Optional[Dict[str, object]]:
    """Считает V и уровень; ``None``, если нет ни одной оценки CVSS."""
    context = context or FstecContext()
    cvss = pick_cvss(bdu_scores, nvd_cvss)
    if cvss is None:
        return None
    icvss, cvss_version, cvss_source = cvss
    if attacked:
        e, e_label = E_ATTACKED, "эксплуатируется в реальных атаках (CISA KEV)"
    elif exploit_known:
        e, e_label = E_EXPLOIT, "есть сведения об эксплойте"
    else:
        e, e_label = E_NONE, "сведений об эксплуатации нет"
    h, h_label = consequence_of(text, cwes)
    iinfr = context.iinfr
    value = icvss * iinfr * (e + h)
    notes: List[str] = []
    if not h:
        notes.append("последствия не определены (Iimp = 0): оценка — нижняя граница")
    if cvss_version == "2.0":
        notes.append("есть только CVSS 2.0, методика использует 3.1")
    level = level_for(value)
    return {
        "v": round(value, 2),
        "level": level,
        **deadline_for(level, context.scan_date),
        "icvss": round(icvss, 2),
        "cvss_version": cvss_version,
        "cvss_source": cvss_source,
        "iinfr": round(iinfr, 3),
        "iat": e,
        "iat_label": e_label,
        "iimp": h,
        "iimp_label": h_label or "не определены",
        "notes": notes,
    }
