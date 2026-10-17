"""Раздел отчёта «Известные уязвимости компонентов» (этап 6).

Все строки из внешних каталогов (описания CVE, названия
эксплойтов) — недоверенный ввод: в HTML они попадают только через ``esc``,
а в встроенный JSON — через ``json_for_script`` (``</`` экранируется, чтобы
описание не могло закрыть тег ``<script>``).

CSV для аудита собирается в браузере из встроенного JSON: строки готовит
``audit_rows`` (Python), JS только экранирует ячейки, добавляет BOM и отдаёт файл.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Sequence, Tuple

from .models import Finding
from .vulndb.cache import STATE_LABELS, format_date
from .vulndb.scoring import (CRITICAL_CVSS, EXPLOIT_UNVERIFIED_BONUS, EXPLOIT_VERIFIED_BONUS,
                             KEV_BONUS, PRODUCT_ONLY_FACTOR, RANSOMWARE_BONUS)

AUDIT_COLUMNS = ["CVE", "Компонент", "Версия", "CVSS", "Рекомендация", "В KEV", "Публичный эксплойт"]
BDU_COLUMN = "БДУ ФСТЭК"  # добавляется к CSV только если в отчёте есть данные БДУ
FSTEC_COLUMNS = ["Уровень по ФСТЭК", "V (ФСТЭК)", "Срок устранения (ФСТЭК)"]  # если посчитан уровень
SOURCE_ORDER = ("NVD", "CISA KEV", "ExploitDB", "БДУ ФСТЭК")
STATE_CSS = {"fresh": "ok", "updated": "ok", "stale": "warn", "unavailable": "bad",
             "offline": "bad", "disabled": "off", "skipped": "off"}


def collect_vulns(items: Sequence[Finding]) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    """Все CVE из находок каталожного анализа и число скрытых «и ещё K» по компонентам."""
    vulns: List[Dict[str, object]] = []
    more: Dict[str, int] = {}
    for finding in items:
        component = ""
        for match in finding.vuln_matches or []:
            if "cve" in match:
                vulns.append(match)
                component = str(match.get("component") or "")
            elif match.get("more"):
                more[component] = int(match["more"])  # type: ignore[arg-type]
    return vulns, more


def audit_columns(vulns: Sequence[Dict[str, object]]) -> List[str]:
    """Колонки CSV: базовые, а «БДУ ФСТЭК» — только когда в отчёте есть записи БДУ."""
    return (AUDIT_COLUMNS
            + (FSTEC_COLUMNS if any(item.get("fstec") for item in vulns) else [])
            + ([BDU_COLUMN] if any(item.get("bdu") for item in vulns) else []))


def audit_rows(vulns: Sequence[Dict[str, object]]) -> List[List[str]]:
    """Строки CSV «для аудита»: одна строка на CVE (колонки — ``audit_columns``)."""
    with_bdu = any(item.get("bdu") for item in vulns)
    with_fstec = any(item.get("fstec") for item in vulns)
    rows: List[List[str]] = []
    for item in vulns:
        kev = item.get("kev") or {}
        score = item.get("cvss_score")
        cvss = f"{score:g}" if isinstance(score, (int, float)) else ""
        recommendation = (str(kev.get("requiredAction") or "")  # type: ignore[union-attr]
                          or f"Обновите {item.get('product')} до исправленной версии")
        row = [
            str(item.get("cve") or ""),
            str(item.get("product") or ""),
            str(item.get("version") or ""),
            cvss,
            recommendation,
            "да" if kev else "нет",
            "да" if item.get("exploit_count") else "нет",
        ]
        if with_fstec:
            fstec = item.get("fstec") or {}
            row.extend([str(fstec.get("level") or ""),  # type: ignore[union-attr]
                        f"{fstec['v']:g}" if fstec.get("v") is not None else "",  # type: ignore[union-attr]
                        _deadline_text(fstec)])
        if with_bdu:
            row.append(", ".join(str(rec.get("id")) for rec in (item.get("bdu") or [])))  # type: ignore[union-attr]
        rows.append(row)
    return rows


def json_for_script(value: object) -> str:
    """JSON для ``<script type="application/json">`` без возможности выйти из тега."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return (text.replace("</", "<\\/").replace("<!--", "<\\!--")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def stat_group(intel: Dict[str, object], vulns: Sequence[Dict[str, object]]) -> str:
    """Карточки «Общей статистики»: компоненты / CVE / KEV / эксплойты (кликабельны)."""
    components = list(intel.get("products") or [])
    cves = {v.get("cve") for v in vulns}
    kev = {v.get("cve") for v in vulns if v.get("kev")}
    exploits = {v.get("cve") for v in vulns if v.get("exploit_count")}
    in_bdu = {v.get("cve") for v in vulns if v.get("bdu")}
    cards = [
        _card(len(components), "Компонентов определено",
              "по заголовкам, meta generator, JS/CSS — без запросов к сайту", "all", "accent"),
        _card(len(cves), "CVE найдено", "версии сверены с диапазонами NVD", "all",
              "alarm" if cves else ""),
        _card(len(kev), "Из них в CISA KEV", "реально эксплуатируются — исправлять первыми",
              "kev", "alarm strong" if kev else ""),
        _card(len(exploits), "С публичным эксплойтом", "есть в ExploitDB", "exploit",
              "alarm" if exploits else ""),
    ]
    bdu_status = dict((intel.get("sources") or {}).get("БДУ ФСТЭК") or {})  # type: ignore[union-attr]
    if in_bdu or bdu_status.get("state") in ("fresh", "updated", "stale"):
        cards.append(_card(len(in_bdu), "Есть в БДУ ФСТЭК",
                           "российский идентификатор BDU, меры и статус исправления", "all", ""))
    return ("<div class=\"stat-group\"><h3>Известные уязвимости компонентов</h3>"
            f"<div class=\"cards\">{''.join(cards)}</div></div>")


def _card(number: int, label: str, sub: str, preset: str, css: str = "") -> str:
    classes = ("card " + css).strip()
    return (f"<button type=\"button\" class=\"{classes}\" data-vuln-open=\"{esc(preset)}\">"
            f"<div class=\"num\">{number}</div><div class=\"lbl\">{esc(label)}</div>"
            f"<div class=\"sub\">{esc(sub)}</div>"
            "<div class=\"go\">Открыть раздел →</div></button>")


def vulns_panel(intel: Dict[str, object], vulns: Sequence[Dict[str, object]],
                more: Dict[str, int], icon: str) -> str:
    parts = [
        f"<h2>{icon}Известные уязвимости компонентов</h2>",
        "<p class=\"section-note\">Компоненты и версии определены пассивно по уже загруженным "
        "страницам — сайту не отправлялось ни одного дополнительного запроса. Во внешние "
        "каталоги ушли только название и версия компонента. Версия из баннера может быть "
        "бэкпортирована дистрибутивом, поэтому все совпадения помечены как «подозрение».</p>",
        _sources_block(intel),
    ]
    if intel.get("error"):
        parts.append(f"<div class=\"note\">{esc(intel.get('error'))}</div>")

    if vulns:
        parts.append(
            "<div class=\"filters vuln-filters\"><div class=\"filter-row\">"
            "<span class=\"cap\">Показать</span>"
            "<label class=\"vf\"><input type=\"checkbox\" data-vf=\"kev\"> только CISA KEV</label>"
            "<label class=\"vf\"><input type=\"checkbox\" data-vf=\"exploit\"> есть публичный эксплойт</label>"
            "</div><div class=\"filter-row\">"
            "<span class=\"cap\">CVSS</span>"
            "<label class=\"vf\">от <input type=\"number\" id=\"vf-min\" min=\"0\" max=\"10\" "
            "step=\"0.1\" value=\"0\"></label>"
            "<label class=\"vf\">до <input type=\"number\" id=\"vf-max\" min=\"0\" max=\"10\" "
            "step=\"0.1\" value=\"10\"></label>"
            "<button type=\"button\" class=\"f\" id=\"vf-reset\">Сбросить</button>"
            "<button type=\"button\" class=\"f pdf-filter\" id=\"vf-csv\" "
            "title=\"CSV (UTF-8 с BOM, разделитель «;»): CVE, компонент, версия, CVSS, "
            "рекомендация, KEV, эксплойт\">"
            "Выгрузить для аудита (CSV)</button>"
            "<button type=\"button\" class=\"f pdf-filter\" id=\"vf-pdf\">PDF по фильтру</button>"
            "</div></div>"
            f"<p class=\"hint\">Показано <b id=\"vshown\">{len(vulns)}</b> из {len(vulns)} CVE. "
            "Сортировка — по приоритету (формула — в разделе «Как читать отчёт»). "
            "Наведите на оценку CVSS, чтобы увидеть вектор.</p>"
        )
        parts.append(_vuln_table(vulns, more))
        parts.append(_fstec_note(intel))
        parts.append("<script type=\"application/json\" id=\"vuln-data\">"
                     + json_for_script({"columns": audit_columns(vulns), "rows": audit_rows(vulns)})
                     + "</script>")
    else:
        parts.append("<div class=\"note\">Известных уязвимостей для определённых версий "
                     "компонентов не найдено.</div>")

    parts.append(_components_table(intel))
    return "".join(parts)


def _sources_block(intel: Dict[str, object]) -> str:
    sources = dict(intel.get("sources") or {})
    if not sources:
        legacy = dict(intel.get("source_status") or {})
        sources = {name: {"label": label} for name, label in legacy.items()}
    if not sources:
        return ""
    rows = []
    for name in list(SOURCE_ORDER) + [key for key in sources if key not in SOURCE_ORDER]:
        status = sources.get(name)
        if not status:
            continue
        state = str(status.get("state") or "")
        label = str(status.get("label") or STATE_LABELS.get(state, state))
        css = STATE_CSS.get(state, "")
        date = format_date(str(status.get("data_date") or "")) or "—"
        records = status.get("records")
        message = str(status.get("message") or "")
        rows.append(
            f"<tr><td><b>{esc(name)}</b></td>"
            f"<td><span class=\"src-state {css}\">{esc(label)}</span></td>"
            f"<td>{esc(date)}</td>"
            f"<td class=\"cat\">{esc(records) if records else '—'}</td>"
            f"<td class=\"cat\">{esc(status.get('requests', 0))}</td>"
            f"<td class=\"cat\">{esc(message) if message else ''}</td></tr>"
        )
    requests = intel.get("catalog_requests")
    note = (f"<p class=\"hint\">Запросов к каталогам: <b>{esc(requests)}</b> — они не входят "
            "в лимит запросов к сайту.</p>") if requests is not None else ""
    return ("<h3>Состояние справочников</h3>"
            "<table class=\"src-table\"><thead><tr><th>Источник</th><th>Состояние</th>"
            "<th>Дата данных</th><th>Записей</th><th>Запросов</th><th>Замечание</th></tr>"
            "</thead><tbody>" + "".join(rows) + "</tbody></table>" + note)


def _vuln_table(vulns: Sequence[Dict[str, object]], more: Dict[str, int]) -> str:
    head = ("<div class=\"table-scroll\"><table class=\"vuln-table\"><thead><tr>"
            "<th>Компонент</th><th>Где найден</th><th>CVE</th><th>CVSS</th><th>KEV</th>"
            "<th>ExploitDB</th><th>Приоритет</th><th>ФСТЭК</th></tr></thead><tbody>")
    rows: List[str] = []
    order: List[str] = []
    for item in vulns:
        component = str(item.get("component") or "")
        if component not in order:
            order.append(component)
    for component in order:
        for item in (v for v in vulns if str(v.get("component") or "") == component):
            rows.append(_vuln_row(item))
        if more.get(component):
            rows.append(f"<tr class=\"v-more\"><td colspan=\"8\">… и ещё {more[component]} CVE "
                        f"для {esc(component)} с более низким приоритетом (не показаны)</td></tr>")
    return head + "".join(rows) + "</tbody></table></div>"


def _vuln_row(item: Dict[str, object]) -> str:
    kev = item.get("kev") or {}
    score = item.get("cvss_score")
    cvss = item.get("cvss") or {}
    exploits = list(item.get("exploits") or [])
    has_score = isinstance(score, (int, float))

    cve = str(item.get("cve") or "")
    description = str(item.get("description") or "")
    cwe = ", ".join(str(value) for value in (item.get("cwe") or []))
    cve_cell = (_ext_link(str(item.get("nvd_url") or ""), cve, description[:400])
                + ("<div class=\"cat\">только по данным БДУ ФСТЭК</div>"
                   if item.get("source") == "bdu" else "")
                + _bdu_cell(item.get("bdu") or [])
                + (f"<div class=\"cat\">{esc(cwe)}</div>" if cwe else "")
                + (f"<div class=\"cat\">опубликовано {esc(format_date(str(item.get('published') or '')))}</div>"
                   if item.get("published") else ""))

    if has_score:
        vector = str(cvss.get("vector") or "") if isinstance(cvss, dict) else ""
        version = str(cvss.get("version") or "NVD") if isinstance(cvss, dict) and cvss else "NVD"
        cvss_cell = (f"<span class=\"cvss\" title=\"{esc(vector or 'вектор не указан')}\">"
                     f"{score:g}</span> <span class=\"cat\">v{esc(version)}</span>")
        if score >= CRITICAL_CVSS:  # type: ignore[operator]
            cvss_cell += f"<div><span class=\"vbadge crit\">Критическая (CVSS {score:g})</span></div>"
    else:
        cvss_cell = "<span class=\"cat\">нет оценки</span>"

    if kev:
        kev_cell = ("<span class=\"vbadge kev\" title=\""
                    + esc(str(kev.get("vulnerabilityName") or "CISA KEV")) + "\">KEV</span>")
        if kev.get("dueDate"):
            kev_cell += f"<div class=\"cat\">срок: {esc(format_date(str(kev.get('dueDate'))))}</div>"
        if str(kev.get("knownRansomwareCampaignUse") or "").lower() == "known":
            kev_cell += "<div class=\"cat\">используется шифровальщиками</div>"
    else:
        kev_cell = "<span class=\"cat\">—</span>"

    if exploits:
        exploit_cell = f"<b>{int(item.get('exploit_count') or len(exploits))}</b>" + "".join(
            f"<div>{_ext_link(str(ex.get('url') or ''), 'EDB-' + str(ex.get('edb_id') or ''), str(ex.get('title') or ''))}"
            + (" <span class=\"vbadge ok\" title=\"verified\">✓</span>" if ex.get("verified") else "")
            + "</div>"
            for ex in exploits[:3])
    else:
        exploit_cell = "<span class=\"cat\">—</span>"

    where = "".join(f"<div class=\"cat\">{esc(value)}</div>" for value in list(item.get("where") or [])[:2])
    priority = item.get("priority_score")
    label = str(item.get("priority_label") or "")
    priority_css = "kev" if item.get("kev") else ("crit" if label == "Критический" else "")
    priority_cell = (f"<b>{esc(priority)}</b><div><span class=\"vbadge {priority_css}\">{esc(label)}</span></div>")

    fstec_cell = _fstec_cell(item.get("fstec"))
    attrs = (f" data-kev=\"{1 if kev else 0}\" data-exploit=\"{1 if exploits else 0}\""
             f" data-cvss=\"{score if has_score else ''}\"")
    return (
        f"<tr class=\"v-row\"{attrs}>"
        f"<td><b>{esc(item.get('product'))}</b> {esc(item.get('version'))}"
        f"<div class=\"cat\">{esc(item.get('version_match_label') or '')}</div></td>"
        f"<td>{where or '—'}</td>"
        f"<td>{cve_cell}</td><td>{cvss_cell}</td><td>{kev_cell}</td>"
        f"<td>{exploit_cell}</td><td>{priority_cell}</td><td>{fstec_cell}</td></tr>"
    )


FSTEC_BADGE = {"Критический": "crit", "Высокий": "kev", "Средний": "", "Низкий": "ok"}


def _deadline_text(fstec) -> str:
    """``до 7 дней (до 18.10.2026)`` — срок устранения по уровню критичности."""
    if not isinstance(fstec, dict) or not fstec.get("deadline"):
        return ""
    due = format_date(str(fstec.get("due") or ""))
    return f"{fstec['deadline']} (до {due})" if due else str(fstec["deadline"])


def _fstec_cell(fstec) -> str:
    """Уровень по методике ФСТЭК: бейдж, значение V и расшифровка в подсказке."""
    if not isinstance(fstec, dict) or fstec.get("v") is None:
        return "<span class=\"cat\">нет оценки CVSS</span>"
    level = str(fstec.get("level") or "")
    title = (f"V = Icvss {fstec.get('icvss')} (CVSS {fstec.get('cvss_version')}, "
             f"{fstec.get('cvss_source')}) × Iinfr {fstec.get('iinfr')} × "
             f"(Iat {fstec.get('iat')} — {fstec.get('iat_label')} + "
             f"Iimp {fstec.get('iimp')} — {fstec.get('iimp_label')})")
    deadline = _deadline_text(fstec)
    deadline_html = f"<div class=\"cat\">срок: {esc(deadline)}</div>" if deadline else ""
    notes = "".join(f"<div class=\"cat\">{esc(note)}</div>"
                    for note in (fstec.get("notes") or []))
    return (f"<span class=\"vbadge {FSTEC_BADGE.get(level, '')}\" title=\"{esc(title)}\">"
            f"{esc(level)}</span> <span class=\"cat\">V={esc(fstec.get('v'))}</span>"
            f"{deadline_html}{notes}")


def _fstec_note(intel: Dict[str, object]) -> str:
    context = dict(intel.get("fstec") or {})
    if not context:
        return ""
    perimeter = ("доступен из Интернета" if context.get("internet_facing")
                 else "во внутренней сети")
    source = {"auto": "определён по адресу цели", "internet": "задан ключом",
              "internal": "задан ключом"}.get(str(context.get("perimeter_source")), "")
    return ("<p class=\"hint\"><b>Уровень по методике ФСТЭК</b> (методический документ от "
            "30.06.2025): V = Icvss × Iinfr × (Iat + Iimp); критический при V &gt; 8,0, "
            "высокий — 5,0…8,0, средний — 2,0…5,0, низкий — ниже. Допущения расчёта: тип "
            f"компонента — {esc(context.get('component_label'))} (K = {esc(context.get('k'))}), "
            f"ресурс {esc(perimeter)} ({esc(source)}; P = {esc(context.get('p'))}), доля уязвимых "
            f"компонентов {esc(int(float(context.get('vulnerable_share') or 0) * 100))} % "
            f"(L = {esc(context.get('l'))}). Если последствия уязвимости не определены, оценка "
            "— нижняя граница. Порядок строк: сначала надёжные совпадения, затем значение V "
            "по ФСТЭК (по убыванию), затем приоритет по формуле выше. Значения констант сверьте с "
            "первоисточником на fstec.ru. Рекомендуемые сроки устранения по уровню: критический "
            "— до 24 часов, высокий — до 7 дней, средний — до 4 недель, низкий — до 4 месяцев "
            "(отсчёт от даты сканирования); если обновить в срок нельзя, применяются "
            "компенсирующие меры.</p>")


BDU_EXPLOIT_BADGE = {"public": "эксплойт в открытом доступе", "exists": "эксплойт существует"}
BDU_FIX_BADGE = {"fixed": "устранена", "unfixed": "не устранена"}


def _bdu_cell(records) -> str:
    """Строки «БДУ ФСТЭК» под номером CVE: идентификатор-ссылка и пометки."""
    parts: List[str] = []
    for record in list(records)[:3]:
        if not isinstance(record, dict):
            continue
        notes = []
        if record.get("exploit") in BDU_EXPLOIT_BADGE:
            notes.append(BDU_EXPLOIT_BADGE[str(record["exploit"])])
        if record.get("fix") in BDU_FIX_BADGE:
            notes.append(BDU_FIX_BADGE[str(record["fix"])])
        title = str(record.get("title") or "")[:300]
        parts.append("<div class=\"cat\">БДУ: "
                     + _ext_link(str(record.get("url") or ""), str(record.get("id") or ""), title)
                     + (f" · {esc(', '.join(notes))}" if notes else "") + "</div>")
    return "".join(parts)


def _components_table(intel: Dict[str, object]) -> str:
    products = list(intel.get("products") or [])
    if not products:
        return ""
    rows = []
    for product in products:
        product = dict(product)
        version = str(product.get("version") or "")
        if version:
            version_cell = esc(version)
            if not product.get("nvd", True):
                version_cell += " <span class=\"cat\">(нет CPE в NVD)</span>"
        else:
            version_cell = "<span class=\"cat\">версия скрыта (это хорошо)</span>"
        name = product.get("label") or " / ".join(
            value for value in (str(product.get("vendor") or ""), str(product.get("product") or ""))
            if value)
        cves = product.get("cves")
        rows.append(
            f"<tr><td>{esc(name or '—')}</td><td>{version_cell}</td>"
            f"<td class=\"cat\">{esc(cves) if cves else '—'}</td>"
            f"<td class=\"cat\">{esc(product.get('source') or '—')}</td>"
            f"<td class=\"cat\">{esc(product.get('evidence') or '—')}</td></tr>"
        )
    return ("<h3>Распознанные компоненты</h3><div class=\"table-scroll\"><table><thead><tr>"
            "<th>Компонент</th><th>Версия</th><th>CVE</th><th>Источник признака</th>"
            "<th>Где найден</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></div>")


def help_block() -> str:
    """Пояснение к разделу и формуле приоритета (для «Как читать отчёт»)."""
    return (
        "<div class=\"help-item\" style=\"grid-column:1/-1\"><b>Известные уязвимости компонентов"
        "</b><span>Сканер определяет продукт и версию по уже полученным ответам (заголовки "
        "Server/X-Powered-By, meta generator, имена и баннеры JS/CSS) и сверяет версию с "
        "диапазонами CVE из NVD. «точная версия» — CVE заведена именно на эту версию; «в "
        "диапазоне» — версия попала в диапазон уязвимых; «только продукт» — NVD не указал "
        "диапазон, совпадение слабое. Бейдж <b>KEV</b> — уязвимость в каталоге CISA реально "
        "эксплуатируемых; <b>ExploitDB</b> — наличие публичного эксплойта (✓ — проверен "
        "ExploitDB).</span></div>"
        "<div class=\"help-item high\" style=\"grid-column:1/-1\"><b>Формула приоритета CVE</b>"
        f"<span>приоритет = CVSS (0–10) + {KEV_BONUS:g}, если CVE в KEV (+{RANSOMWARE_BONUS:g}, "
        f"если отмечено использование шифровальщиками) + {EXPLOIT_VERIFIED_BONUS:g} за "
        f"проверенный эксплойт в ExploitDB (или +{EXPLOIT_UNVERIFIED_BONUS:g} за непроверенный); "
        f"при совпадении «только продукт» результат умножается на {PRODUCT_ONLY_FACTOR:g}. "
        "Уровень находки: KEV или CVSS ≥ 7 — высокий, 4–6.9 — средний, ниже — низкий. "
        "Отдельного уровня «критический» нет: вместо него бейдж «Критическая (CVSS 9.8)».</span>"
        "</div>"
    )


def pdf_block(vulns: Sequence[Dict[str, object]], limit: int = 25) -> str:
    """Для печатной сводки: CVE из KEV и критические (CVSS ≥ 9)."""
    important = [v for v in vulns
                 if v.get("kev") or (isinstance(v.get("cvss_score"), (int, float))
                                     and v["cvss_score"] >= CRITICAL_CVSS)]  # type: ignore[operator]
    if not important:
        return ""
    rows = []
    for item in important[:limit]:
        kev = item.get("kev") or {}
        score = item.get("cvss_score")
        rows.append(
            f"<tr class=\"crit\"><td>{esc(item.get('component'))}</td><td>{esc(item.get('cve'))}</td>"
            f"<td>{esc(f'{score:g}' if isinstance(score, (int, float)) else '—')}</td>"
            f"<td>{'KEV, срок ' + esc(kev.get('dueDate')) if kev else '—'}</td>"
            f"<td>{esc(item.get('exploit_count') or 0)}</td></tr>"
        )
    return (f"<h2>Известные уязвимости компонентов: KEV и критические ({len(important)})</h2>"
            "<p class=\"pdf-sub\">Версии определены по баннерам — сверьте с инвентаризацией.</p>"
            "<table><thead><tr><th>Компонент</th><th>CVE</th><th>CVSS</th><th>CISA KEV</th>"
            "<th>Эксплойтов</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


def _ext_link(url: str, text: str, title: str = "") -> str:
    """Ссылка на карточку каталога: только https, текст и подсказка экранируются."""
    if not re.match(r"^https://", url or "", re.I):
        return esc(text)
    title_attr = f" title=\"{esc(title)}\"" if title else ""
    return (f"<a class=\"url\" href=\"{esc(url)}\" target=\"_blank\" rel=\"noopener noreferrer\""
            f"{title_attr}>{esc(text)}</a>")


def esc(value: object) -> str:
    import html
    return html.escape("" if value is None else str(value), quote=True)


CSS = """
/* ---------- известные уязвимости компонентов ---------- */
.table-scroll { overflow-x: auto; margin-bottom: 14px; }
.vuln-table { font-size: 13px; }
.vuln-table td { padding: 9px 10px; }
.vuln-table .cvss { font-weight: 800; border-bottom: 1px dotted var(--iron-light); cursor: help; }
.vbadge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 11.5px;
  font-weight: 700; white-space: nowrap; background: var(--mint); color: var(--green-dark);
  border: 1px solid var(--mint-deep); margin-top: 2px; }
.vbadge.kev { background: var(--high); border-color: var(--high); color: #fff; }
.vbadge.crit { background: #FDF0EC; border-color: var(--high); color: #8E3A2A; }
.vbadge.ok { background: var(--safe); border-color: var(--safe); color: #fff; }
tr.v-row[data-kev="1"] > td:first-child { box-shadow: inset 4px 0 0 var(--high); }
tr.v-more td { color: var(--muted); font-style: italic; background: var(--panel-2); }
.vuln-filters label.vf { display: inline-flex; align-items: center; gap: 6px; font-size: 13px;
  background: var(--panel); border: 1px solid var(--border); border-radius: 999px;
  padding: 6px 12px; cursor: pointer; font-weight: 600; }
.vuln-filters label.vf:hover { border-color: var(--green); }
.vuln-filters input[type=checkbox] { accent-color: var(--green); }
.vuln-filters input[type=number] { width: 64px; border: 1px solid var(--border); border-radius: 8px;
  padding: 3px 6px; font-family: inherit; background: var(--panel); color: var(--text); }
.src-table { font-size: 13px; margin-bottom: 6px; }
.src-state { display: inline-block; padding: 1px 9px; border-radius: 999px; font-size: 12px;
  font-weight: 700; background: var(--panel-2); border: 1px solid var(--border); color: var(--muted); }
.src-state.ok { background: var(--mint); border-color: var(--mint-deep); color: var(--green-dark); }
.src-state.warn { background: #FBF1E1; border-color: var(--medium); color: #7A5214; }
.src-state.bad { background: #FDF0EC; border-color: var(--high); color: #8E3A2A; }
@media print {
  .vuln-table, .src-table { font-size: 10.5px; }
  .vuln-filters, #vf-csv, #vf-pdf { display: none !important; }
}
"""

JS = r"""
function csvCell(value) {
  var s = String(value == null ? '' : value);
  // Защита от CSV-инъекции формул в Excel: описания приходят из внешних каталогов.
  if (/^[=+\-@\t\r]/.test(s)) { s = "'" + s; }
  if (/[";\r\n]/.test(s)) { s = '"' + s.replace(/"/g, '""') + '"'; }
  return s;
}
function buildAuditCsv(columns, rows) {
  var lines = [columns].concat(rows).map(function (row) {
    return row.map(csvCell).join(';');
  });
  return '\ufeff' + lines.join('\r\n') + '\r\n';
}
function vulnData() {
  var node = document.getElementById('vuln-data');
  if (!node) { return { columns: [], rows: [] }; }
  try { return JSON.parse(node.textContent); } catch (e) { return { columns: [], rows: [] }; }
}
function downloadAuditCsv() {
  var data = vulnData();
  var csv = buildAuditCsv(data.columns, data.rows);
  var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  var link = document.createElement('a');
  var host = (document.body.dataset.target || 'report').replace(/^https?:\/\//, '').replace(/[^\w.-]+/g, '_');
  link.href = URL.createObjectURL(blob);
  link.download = 'spyvision-audit-' + host + '.csv';
  document.body.appendChild(link);
  link.click();
  setTimeout(function () { URL.revokeObjectURL(link.href); link.remove(); }, 1000);
}
function vulnFilterState() {
  var state = { kev: false, exploit: false, min: 0, max: 10 };
  document.querySelectorAll('[data-vf]').forEach(function (box) { state[box.dataset.vf] = box.checked; });
  var min = parseFloat((document.getElementById('vf-min') || {}).value);
  var max = parseFloat((document.getElementById('vf-max') || {}).value);
  state.min = isNaN(min) ? 0 : min;
  state.max = isNaN(max) ? 10 : max;
  return state;
}
function applyVulnFilters() {
  var f = vulnFilterState();
  var shown = 0;
  var filtered = f.kev || f.exploit || f.min > 0 || f.max < 10;
  document.querySelectorAll('tr.v-row').forEach(function (row) {
    var cvss = row.dataset.cvss === '' ? null : parseFloat(row.dataset.cvss);
    var ok = (!f.kev || row.dataset.kev === '1')
      && (!f.exploit || row.dataset.exploit === '1')
      && ((f.min <= 0 && f.max >= 10) || (cvss !== null && cvss >= f.min && cvss <= f.max));
    row.style.display = ok ? '' : 'none';
    if (ok) { shown++; }
  });
  document.querySelectorAll('tr.v-more').forEach(function (row) {
    row.style.display = filtered ? 'none' : '';
  });
  var counter = document.getElementById('vshown');
  if (counter) { counter.textContent = shown; }
  var pdf = document.getElementById('vf-pdf');
  if (pdf) { pdf.disabled = shown === 0; }
}
function resetVulnFilters() {
  document.querySelectorAll('[data-vf]').forEach(function (box) { box.checked = false; });
  var min = document.getElementById('vf-min');
  var max = document.getElementById('vf-max');
  if (min) { min.value = 0; }
  if (max) { max.value = 10; }
  applyVulnFilters();
}
function openVulns(preset) {
  resetVulnFilters();
  if (preset === 'kev' || preset === 'exploit') {
    var box = document.querySelector('[data-vf="' + preset + '"]');
    if (box) { box.checked = true; }
  }
  applyVulnFilters();
  openPanel('catalogs');
}
function printVulns() {
  var box = document.getElementById('pdf-filtered');
  var rows = Array.prototype.filter.call(document.querySelectorAll('tr.v-row'),
    function (row) { return row.style.display !== 'none'; });
  if (!box || !rows.length) { return; }
  var heads = ['Компонент', 'CVE', 'CVSS', 'KEV', 'ExploitDB', 'Приоритет'];
  var html = '<h1>Известные уязвимости компонентов</h1>'
    + '<p class="pdf-sub">Цель: ' + escHtml(document.body.dataset.target || '') + ' · сформирован '
    + escHtml(document.body.dataset.generated || '') + ' · записей: ' + rows.length + '</p>'
    + '<table><thead><tr>' + heads.map(function (h) { return '<th>' + h + '</th>'; }).join('')
    + '</tr></thead><tbody>';
  rows.forEach(function (row) {
    var c = row.cells;
    var pick = [0, 2, 3, 4, 5, 6];
    html += '<tr' + (row.dataset.kev === '1' ? ' class="crit"' : '') + '>' + pick.map(function (i) {
      return '<td>' + escHtml((c[i].innerText || c[i].textContent || '').trim()) + '</td>';
    }).join('') + '</tr>';
  });
  html += '</tbody></table><p class="pdf-foot">Версии определены по баннерам и могут быть '
    + 'бэкпортированы дистрибутивом — сверьте с инвентаризацией.</p>';
  box.innerHTML = html;
  document.body.classList.add('print-filtered');
  closePanel();
  window.print();
  setTimeout(function () { document.body.classList.remove('print-filtered'); }, 500);
}
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('[data-vf], #vf-min, #vf-max').forEach(function (el) {
    el.addEventListener('input', applyVulnFilters);
    el.addEventListener('change', applyVulnFilters);
  });
  var reset = document.getElementById('vf-reset');
  if (reset) { reset.addEventListener('click', resetVulnFilters); }
  var csv = document.getElementById('vf-csv');
  if (csv) { csv.addEventListener('click', downloadAuditCsv); }
  var pdf = document.getElementById('vf-pdf');
  if (pdf) { pdf.addEventListener('click', printVulns); }
  document.querySelectorAll('[data-vuln-open]').forEach(function (btn) {
    btn.addEventListener('click', function () { openVulns(btn.dataset.vulnOpen); });
  });
});
"""
