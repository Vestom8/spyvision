"""Итоговый приоритет CVE и перевод совпадений в находки отчёта.

Формула приоритета прозрачная; веса вынесены в константы и описаны в разделе
отчёта «Как читать отчёт»::

    priority = CVSS base score (0–10)
             + KEV_BONUS                если CVE в CISA KEV
             + RANSOMWARE_BONUS         если в KEV отмечено использование шифровальщиками
             + EXPLOIT_VERIFIED_BONUS   если в ExploitDB есть verified-эксплойт
               (или EXPLOIT_UNVERIFIED_BONUS для непроверенного)
             + BDU_EXPLOIT_BONUS        если в ExploitDB эксплойта нет, но БДУ ФСТЭК
               отмечает эксплойт «в открытом доступе» (два источника не складываются)
    priority *= PRODUCT_ONLY_FACTOR     если совпадение только по продукту

Уровень находки: KEV или CVSS ≥ 7.0 → High; 4.0–6.9 → Medium; ниже → Low.
Отдельного уровня Critical нет — вместо него бейдж «Критическая (CVSS 9.8)».
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from ..fingerprint import DetectedProduct
from ..models import HIGH, INFO, LOW, MEDIUM, SEVERITY_ORDER, SUSPECTED, VULN, Finding
from .fstec import COMPENSATING_MEASURES, FstecContext, assess as fstec_assess
from .versions import EXACT, PLATFORM, PRODUCT_ONLY, RANGE

BDU_NAME = "bdu_name"   # версия подходит по записи БДУ, продукт найден по названию

KEV_BONUS = 3.0
RANSOMWARE_BONUS = 1.0
EXPLOIT_VERIFIED_BONUS = 1.5
EXPLOIT_UNVERIFIED_BONUS = 0.75
BDU_EXPLOIT_BONUS = 0.75
PRODUCT_ONLY_FACTOR = 0.5
BDU_NAME_FACTOR = 0.7   # совпадение только по названию продукта в БДУ (без CPE) — менее надёжно
PLATFORM_FACTOR = 0.5   # CVE зависит от платформы, которую сканер не определяет
DISTRO_FACTOR = 0.6     # версия из баннера дистрибутива: возможен бэкпорт исправления
CRITICAL_CVSS = 9.0
HIGH_CVSS = 7.0
MEDIUM_CVSS = 4.0

LABEL_EXPLOITED = "Эксплуатируется"
MATCH_LABELS = {
    EXACT: "точная версия",
    RANGE: "в диапазоне",
    PRODUCT_ONLY: "только продукт",
    PLATFORM: "зависит от платформы",
    BDU_NAME: "по названию продукта (БДУ)",
}
WEAK_MATCHES = (PRODUCT_ONLY, PLATFORM, BDU_NAME)
EVIDENCE_CVE_LINES = 10


BDU_PER_CVE = 3
BDU_VIEW_FIELDS = ("id", "url", "title", "exploit", "fix", "level", "scores", "measures",
                   "remediation", "status", "incident", "published", "updated",
                   "matched_name", "version_expr")
BDU_EXPLOIT_TEXT = {"public": "эксплойт в открытом доступе", "exists": "эксплойт существует"}
BDU_FIX_TEXT = {"fixed": "устранена", "unfixed": "не устранена"}


def _bdu_view(record: Dict[str, object]) -> Dict[str, object]:
    """Подмножество записи БДУ, которое попадает в отчёт."""
    return {key: record[key] for key in BDU_VIEW_FIELDS if record.get(key) not in (None, "", {})}


def _deadline_step(matches: Sequence["VulnMatch"]) -> str:
    """Шаг «срок устранения по методике ФСТЭК» по самой критичной уязвимости находки."""
    scored = [item for item in matches if item.fstec and item.fstec.get("v") is not None]
    if not scored:
        return ""
    worst = max(scored, key=lambda item: float(item.fstec["v"]))  # type: ignore[index,arg-type]
    fstec = worst.fstec or {}
    record = worst.bdu[0] if worst.source == "bdu" and worst.bdu else {}
    name = str(record.get("id") or worst.cve_id)
    return (f"Срок устранения по методике ФСТЭК: {fstec['deadline']} (до {fstec['due']}) — для "
            f"{name}, уровень «{fstec['level']}», V = {fstec['v']:g}. Если обновить в срок "
            f"нельзя — компенсирующие меры: {COMPENSATING_MEASURES}.")


def _bdu_note(match: "VulnMatch") -> str:
    """Короткая пометка «БДУ …» для строки CVE в доказательствах находки."""
    if not match.bdu:
        return ""
    first = match.bdu[0]
    details = [BDU_EXPLOIT_TEXT[first["exploit"]]] if first.get("exploit") in BDU_EXPLOIT_TEXT else []
    if first.get("fix") in BDU_FIX_TEXT:
        details.append(BDU_FIX_TEXT[first["fix"]])
    text = "БДУ " + str(first.get("id"))
    if len(match.bdu) > 1:
        text += f" (+{len(match.bdu) - 1})"
    return text + (f" ({', '.join(details)})" if details else "")


@dataclass
class VulnMatch:
    cve_id: str
    component: DetectedProduct
    cvss: Optional[Dict[str, object]] = None   # version, score, severity, vector
    cwe: List[str] = field(default_factory=list)
    description: str = ""
    published: str = ""
    nvd_url: str = ""
    cpe: str = ""
    kev: Optional[Dict[str, str]] = None
    exploits: List[Dict[str, object]] = field(default_factory=list)
    bdu: List[Dict[str, object]] = field(default_factory=list)   # записи БДУ ФСТЭК по этой CVE
    version_match: str = RANGE
    source: str = "nvd"   # "nvd" — найдено через NVD; "bdu" — только по записи БДУ ФСТЭК
    fstec: Optional[Dict[str, object]] = None   # оценка по методике ФСТЭК (см. fstec.assess)
    priority_score: float = 0.0
    priority_label: str = ""

    @property
    def cvss_score(self) -> Optional[float]:
        if self.cvss and self.cvss.get("score") is not None:
            return float(self.cvss["score"])  # type: ignore[arg-type]
        return None

    @property
    def ransomware(self) -> bool:
        return bool(self.kev) and str(self.kev.get("knownRansomwareCampaignUse", "")).lower() == "known"

    @property
    def bdu_public_exploit(self) -> bool:
        return any(item.get("exploit") == "public" for item in self.bdu)

    @property
    def verified_exploit(self) -> bool:
        return any(bool(item.get("verified")) for item in self.exploits)

    def as_dict(self) -> Dict[str, object]:
        """JSON-представление для отчёта и CSV. Строки не экранированы — это
        делает отчёт при выводе."""
        return {
            "cve": self.cve_id,
            "component": self.component.display_name,
            "product": self.component.label or self.component.product,
            "version": self.component.version,
            "where": list(self.component.evidences[:5]),
            "cvss": self.cvss,
            "cvss_score": self.cvss_score,
            "cwe": list(self.cwe),
            "description": self.description,
            "published": self.published,
            "nvd_url": self.nvd_url,
            "cpe": self.cpe,
            "kev": self.kev,
            "exploits": list(self.exploits[:10]),
            "exploit_count": len(self.exploits),
            "bdu": [_bdu_view(item) for item in self.bdu[:BDU_PER_CVE]],
            "bdu_count": len(self.bdu),
            "source": self.source,
            "fstec": self.fstec,
            "fstec_level": (self.fstec or {}).get("level", ""),
            "fstec_score": (self.fstec or {}).get("v"),
            "version_match": self.version_match,
            "version_match_label": MATCH_LABELS.get(self.version_match, self.version_match),
            "priority_score": self.priority_score,
            "priority_label": self.priority_label,
            "critical": (self.cvss_score or 0) >= CRITICAL_CVSS,
        }


def assess_match(match: VulnMatch, context: FstecContext) -> Optional[Dict[str, object]]:
    """Уровень критичности по методике ФСТЭК для найденной уязвимости (``None`` без CVSS)."""
    bdu_scores: Dict[str, float] = {}
    texts = [match.description]
    cwes = list(match.cwe)
    for record in match.bdu:
        for version, value in (record.get("scores") or {}).items():
            bdu_scores.setdefault(str(version), float(value))
        texts.extend(str(record.get(key) or "") for key in ("title", "exploitation"))
        if record.get("cwe"):
            cwes.append(str(record["cwe"]))
    exploit_known = bool(match.exploits) or any(
        record.get("exploit") in ("public", "exists") for record in match.bdu)
    return fstec_assess(bdu_scores=bdu_scores, nvd_cvss=match.cvss, attacked=bool(match.kev),
                        exploit_known=exploit_known, text=" ".join(texts), cwes=cwes,
                        context=context)


def rank_key(match: VulnMatch) -> Tuple[int, float, float, str]:
    """Порядок показа: надёжные совпадения, затем V по методике ФСТЭК, затем прежний приоритет.

    Уровень по ФСТЭК — функция V, поэтому сортировка по V включает и сортировку по уровню.
    Записи без оценки CVSS (V нет) идут после оценённых, в порядке прежнего приоритета.
    """
    value = (match.fstec or {}).get("v")
    return (1 if match.version_match in WEAK_MATCHES else 0,
            -float(value) if isinstance(value, (int, float)) else 1.0,
            -match.priority_score, match.cve_id)


def score_match(match: VulnMatch) -> Tuple[float, str]:
    score = match.cvss_score or 0.0
    if match.kev:
        score += KEV_BONUS
        if match.ransomware:
            score += RANSOMWARE_BONUS
    if match.exploits:
        score += EXPLOIT_VERIFIED_BONUS if match.verified_exploit else EXPLOIT_UNVERIFIED_BONUS
    elif match.bdu_public_exploit:
        score += BDU_EXPLOIT_BONUS
    if match.version_match == PRODUCT_ONLY:
        score *= PRODUCT_ONLY_FACTOR
    elif match.version_match == PLATFORM:
        score *= PLATFORM_FACTOR
    elif match.version_match == BDU_NAME:
        score *= BDU_NAME_FACTOR
    if match.component.distro and not match.kev:
        score *= DISTRO_FACTOR
    score = round(score, 2)
    if match.kev:
        label = LABEL_EXPLOITED
    elif score >= CRITICAL_CVSS:
        label = "Критический"
    elif score >= HIGH_CVSS:
        label = "Высокий"
    elif score >= MEDIUM_CVSS:
        label = "Средний"
    else:
        label = "Низкий"
    # Совпадение только по названию продукта: без KEV метка не выше «Средний» — так же, как и
    # у находки, чтобы строка таблицы не обещала больше, чем сама находка.
    if match.version_match == BDU_NAME and not match.kev and label in ("Критический", "Высокий"):
        label = "Средний"
    return score, label


def severity_for(match: VulnMatch) -> str:
    if match.kev:
        return HIGH
    score = match.cvss_score
    if score is None:
        return LOW
    if score >= HIGH_CVSS:
        return HIGH
    if score >= MEDIUM_CVSS:
        return MEDIUM
    return LOW


def _component_severity(component: DetectedProduct, matches: Sequence[VulnMatch]) -> str:
    """Уровень находки по самым надёжным совпадениям.

    «Слабые» совпадения (только продукт, зависит от платформы) сами по себе не поднимают уровень
    выше среднего; то же для версии из баннера дистрибутива, пока нет CVE из KEV.
    """
    strong = [item for item in matches if item.version_match not in WEAK_MATCHES]
    pool = strong or list(matches)
    severity = min((severity_for(item) for item in pool),
                   key=lambda value: SEVERITY_ORDER.get(value, 9), default=LOW)
    capped = not any(item.kev for item in matches) and (not strong or component.distro)
    if capped and SEVERITY_ORDER.get(severity, 9) < SEVERITY_ORDER[MEDIUM]:
        severity = MEDIUM
    return severity


def component_finding(component: DetectedProduct, matches: Sequence[VulnMatch], target: str,
                      hidden: int = 0) -> Finding:
    """Одна находка на компонент со списком CVE внутри.

    ``matches`` уже отсортированы по приоритету и обрезаны; ``hidden`` —
    сколько CVE не вошло в список («и ещё K»).
    """
    kev = [item for item in matches if item.kev]
    exploits = [item for item in matches if item.exploits]
    severity = _component_severity(component, matches)
    total = len(matches) + hidden
    top = matches[0] if matches else None
    title = f"{component.display_name}: известные уязвимости ({total} CVE"
    if kev:
        title += f", в KEV: {len(kev)}"
    bdu_ids = list(dict.fromkeys(str(rec.get("id")) for item in matches for rec in item.bdu))
    if bdu_ids:
        title += f", в БДУ: {len(bdu_ids)}"
    title += ")"

    lines = [f"Компонент: {component.display_name}",
             "Где найден: " + "; ".join(component.evidences[:5])]
    if top is not None and top.cpe:
        lines.append(f"CPE: {top.cpe}")
    lines.append("CVE (по убыванию приоритета):")
    for item in matches[:EVIDENCE_CVE_LINES]:
        parts = [item.cve_id]
        if item.cvss_score is not None:
            cvss_version = (item.cvss or {}).get("version") or "NVD"
            parts.append(f"CVSS {item.cvss_score:g} ({cvss_version})")
        if item.kev:
            parts.append("KEV" + (", ransomware" if item.ransomware else ""))
        if item.exploits:
            parts.append(f"ExploitDB ×{len(item.exploits)}"
                         + (" (verified)" if item.verified_exploit else ""))
        if item.fstec:
            parts.append(f"ФСТЭК {item.fstec['level']} (V={item.fstec['v']:g})")
        note = _bdu_note(item)
        if note:
            parts.append(note)
        parts.append(MATCH_LABELS.get(item.version_match, item.version_match))
        lines.append("  • " + " · ".join(parts))
    rest = total - min(len(matches), EVIDENCE_CVE_LINES)
    if rest > 0:
        lines.append(f"  … и ещё {rest}")
    if component.distro:
        lines.append(f"Дистрибутив в баннере: {component.distro}. Такие пакеты получают "
                     "исправления без смены номера версии — часть CVE может быть уже закрыта, "
                     "приоритет понижен (кроме CVE из KEV).")
    lines.append("Версия получена из баннера и может быть бэкпортирована дистрибутивом "
                 "(исправление без смены номера) — сверьте с инвентаризацией.")

    steps = [
        f"Подтвердите фактическую версию {component.label or component.product} по инвентаризации "
        "сервера или менеджеру пакетов: дистрибутив мог закрыть CVE без смены номера версии.",
    ]
    for item in kev[:3]:
        action = str((item.kev or {}).get("requiredAction") or "").strip()
        due = str((item.kev or {}).get("dueDate") or "").strip()
        if action:
            steps.append(f"{item.cve_id} (CISA KEV): {action}" + (f" Срок по KEV: {due}." if due else ""))
    for item in matches[:5]:
        for record in item.bdu[:1]:
            if record.get("measures") and len([s for s in steps if "(БДУ ФСТЭК)" in s]) < 2:
                steps.append(f"{record.get('id')} (БДУ ФСТЭК): {record['measures']}")
    deadline = _deadline_step(matches)
    if deadline:
        steps.append(deadline)
    steps.append(f"Обновите {component.label or component.product} до поддерживаемой версии, "
                 "в которой исправлены все перечисленные CVE.")
    steps.append("Скройте точную версию в баннерах и именах файлов, затем повторите сканирование.")

    recommendation = (
        f"Обновите {component.label or component.product} до исправленной поддерживаемой версии"
        + (" в первую очередь — уязвимости из CISA KEV реально эксплуатируются" if kev else "")
        + ". Перед этим подтвердите версию по инвентаризации."
    )
    references: List[str] = []
    for item in matches[:5]:
        for url in [item.nvd_url, (item.kev or {}).get("url", "")] + \
\
                   [str(ex.get("url") or "") for ex in item.exploits[:1]]:
            if url and url not in references:
                references.append(url)
    for item in matches[:5]:
        for record in item.bdu[:1]:
            if record.get("url") and record["url"] not in references:
                references.append(str(record["url"]))
    identifiers: List[str] = []
    for item in matches:
        identifiers.append(item.cve_id)
    identifiers.extend(bdu_ids)
    sources = ["NVD"]
    if kev:
        sources.append("CISA KEV")
    if exploits:
        sources.append("ExploitDB")
    if bdu_ids:
        sources.append("БДУ ФСТЭК")

    kind = "known_cve_kev" if kev else "known_cve"
    finding = Finding(
        url=target,
        title=title,
        kind=kind,
        category=VULN,
        severity=severity,
        recommendation=recommendation,
        request="Пассивный fingerprint → CPE/NVD → CISA KEV, ExploitDB"
                + (", БДУ ФСТЭК" if bdu_ids else "") + " (дополнительных запросов к сайту нет)",
        evidence="\n".join(lines),
        confidence=SUSPECTED,
        fix_steps=steps,
        references=references[:12],
        identifiers=list(dict.fromkeys(identifiers)),
        sources=sources,
        cpe=top.cpe if top is not None else "",
        exploited=bool(kev),
        vuln_matches=[item.as_dict() for item in matches],
    )
    if hidden:
        finding.vuln_matches.append({"more": hidden})
    return finding


def bdu_component_finding(component: DetectedProduct, matches: Sequence[VulnMatch], target: str,
                          hidden: int = 0) -> Finding:
    """Находка «по данным БДУ»: записи, которых нет среди CVE, найденных через NVD.

    Продукт здесь найден по названию, а не по CPE, поэтому уровень без KEV не выше
    среднего и находка выделена отдельно от ``known_cve``.
    """
    kev = [item for item in matches if item.kev]
    exploits = [item for item in matches if item.exploits]
    total = len(matches) + hidden
    title = f"{component.display_name}: уязвимости по данным БДУ ФСТЭК ({total}"
    if kev:
        title += f", в KEV: {len(kev)}"
    title += ")"

    lines = [f"Компонент: {component.display_name}",
             "Где найден: " + "; ".join(component.evidences[:5]),
             "Сопоставление: по названию продукта и версии из записей БДУ ФСТЭК. Эти записи не "
             "найдены среди CVE, привязанных к версии в NVD (нет CPE, нет CVE или NVD "
             "не относит к ней эту версию).",
             "Записи БДУ (по убыванию приоритета):"]
    for item in matches[:EVIDENCE_CVE_LINES]:
        record = item.bdu[0] if item.bdu else {}
        parts = [str(record.get("id") or item.cve_id)]
        if record.get("id") and item.cve_id != record.get("id"):
            parts.append(item.cve_id)
        if item.cvss_score is not None:
            parts.append(f"CVSS {item.cvss_score:g} ({(item.cvss or {}).get('version') or 'БДУ'})")
        if item.kev:
            parts.append("KEV" + (", ransomware" if item.ransomware else ""))
        if item.exploits:
            parts.append(f"ExploitDB ×{len(item.exploits)}")
        if item.fstec:
            parts.append(f"ФСТЭК {item.fstec['level']} (V={item.fstec['v']:g})")
        if record.get("exploit") in BDU_EXPLOIT_TEXT:
            parts.append(BDU_EXPLOIT_TEXT[str(record["exploit"])])
        if record.get("fix") in BDU_FIX_TEXT:
            parts.append(BDU_FIX_TEXT[str(record["fix"])])
        if record.get("version_expr"):
            parts.append(f"версии в БДУ: «{record['version_expr']}»"
                         + (f" ({record['matched_name']})" if record.get("matched_name") else ""))
        lines.append("  • " + " · ".join(parts))
    rest = total - min(len(matches), EVIDENCE_CVE_LINES)
    if rest > 0:
        lines.append(f"  … и ещё {rest}")
    lines.append("Продукт определён по баннеру и сопоставлен с БДУ по названию: возможна путаница "
                 "одноимённых продуктов и бэкпорт исправления — сверьте с инвентаризацией.")

    steps = [
        f"Подтвердите, что это именно {component.label or component.product} нужной версии, по "
        "инвентаризации сервера или менеджеру пакетов: сопоставление выполнено по названию.",
    ]
    for item in matches[:5]:
        for record in item.bdu[:1]:
            if record.get("measures") and len([s for s in steps if "(БДУ ФСТЭК)" in s]) < 3:
                steps.append(f"{record.get('id')} (БДУ ФСТЭК): {record['measures']}")
    deadline = _deadline_step(matches)
    if deadline:
        steps.append(deadline)
    steps.append(f"Обновите {component.label or component.product} до версии, в которой "
                 "исправлены перечисленные уязвимости (мера поставщика — в карточке БДУ).")
    steps.append("Скройте точную версию в баннерах и именах файлов, затем повторите сканирование.")

    references: List[str] = []
    for item in matches[:12]:
        for record in item.bdu[:1]:
            if record.get("url") and record["url"] not in references:
                references.append(str(record["url"]))
        for url in [item.nvd_url, (item.kev or {}).get("url", "")]:
            if url and url not in references:
                references.append(str(url))
    identifiers: List[str] = []
    for item in matches:
        for record in item.bdu[:1]:
            identifiers.append(str(record.get("id") or ""))
        identifiers.append(item.cve_id)
    sources = ["БДУ ФСТЭК"]
    if kev:
        sources.append("CISA KEV")
    if exploits:
        sources.append("ExploitDB")

    finding = Finding(
        url=target,
        title=title,
        kind="known_bdu",
        category=VULN,
        severity=_component_severity(component, matches),
        recommendation=(f"Проверьте версию {component.label or component.product} и обновите её "
                        "по мерам из карточек БДУ" + (" — часть уязвимостей из CISA KEV реально "
                                                      "эксплуатируется" if kev else "") + "."),
        request="Пассивный fingerprint → БДУ ФСТЭК (сопоставление по названию продукта и версии; "
                "дополнительных запросов к сайту нет)",
        evidence="\n".join(lines),
        confidence=SUSPECTED,
        fix_steps=steps,
        references=references[:12],
        identifiers=[item for item in dict.fromkeys(identifiers) if item],
        sources=sources,
        exploited=bool(kev),
        vuln_matches=[item.as_dict() for item in matches],
    )
    if hidden:
        finding.vuln_matches.append({"more": hidden})
    return finding


def disclosed_versions_finding(components: Sequence[DetectedProduct], target: str) -> Finding:
    names = ", ".join(item.display_name for item in components[:10])
    evidence = "\n".join(f"{item.display_name} — {item.evidences[0] if item.evidences else item.source}"
                         for item in components[:15])
    return Finding(
        url=target,
        title=f"Раскрыты версии компонентов без известных CVE ({len(components)})",
        kind="component_version_disclosed",
        category=VULN,
        severity=INFO,
        recommendation=f"Скройте версии в баннерах и именах файлов: {names}.",
        request="Пассивный fingerprint → NVD, CISA KEV, ExploitDB",
        evidence=evidence,
        confidence=SUSPECTED,
    )
