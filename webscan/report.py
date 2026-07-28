"""Формирование HTML-отчёта (раздел 6 требований).

Оформление: светло-серые и зелёные оттенки, тематика пауков и паутины.
В шапке — кольцевая диаграмма распределения находок по уровням критичности
(уровни кликабельны: нажатие фильтрует таблицу «Найденные проблемы») и блок
«Общая статистика» из трёх групп показателей.
"""

import datetime
import html
import math
from typing import Dict, List, Tuple

from .models import (CONFIG, CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, VULN, Finding,
                     FindingList)

SEVERITY_CLASS = {HIGH: "sev-high", MEDIUM: "sev-medium", LOW: "sev-low", INFO: "sev-info"}

# Подписи уровней на диаграмме: Info показывается как «Безопасно»
CHART_CATEGORIES: Tuple[Tuple[str, str, str], ...] = (
    (HIGH, "Высокая", "var(--high)"),
    (MEDIUM, "Средняя", "var(--medium)"),
    (LOW, "Низкая", "var(--low)"),
    (INFO, "Безопасно", "var(--safe)"),
)

SEVERITY_LABEL = {severity: label for severity, label, _color in CHART_CATEGORIES}

SEVERITY_HINT = {
    HIGH: "прямая угроза данным или аккаунтам — разбирать в первую очередь",
    MEDIUM: "защита ослаблена, есть рабочий сценарий атаки — планировать исправление",
    LOW: "гигиена конфигурации, помогает атакующему в разведке",
    INFO: "проблем не найдено или запись справочная",
}

CSS = """
:root {
  --bg: #EEF2EE;
  --panel: #FFFFFF;
  --panel-2: #F4F8F5;
  --mint: #D8F1E6;
  --mint-deep: #BFE4D3;
  --green: #2C7A5B;
  --green-dark: #1E5A42;
  --iron: #858585;
  --iron-light: #B7B7B7;
  --border: #D7E1DA;
  --text: #26302B;
  --muted: #64716A;
  --high: #B4503C;
  --medium: #C98A2E;
  --low: #858585;
  --safe: #3F9D75;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 0 56px; background: var(--bg); color: var(--text);
  font: 15px/1.6 "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1280px; margin: 0 auto; padding: 0 22px; }
a { color: var(--green); }

/* ---------- шапка с диаграммой ---------- */
header {
  position: relative; overflow: hidden;
  background: linear-gradient(135deg, #FFFFFF 0%, var(--mint) 100%);
  border-bottom: 1px solid var(--border); padding: 26px 0 30px; margin-bottom: 26px;
}
header .web { position: absolute; top: -34px; right: -34px; opacity: .5; pointer-events: none; }
header .web-left { position: absolute; bottom: -46px; left: -50px; opacity: .3; pointer-events: none; }
.hero { display: grid; grid-template-columns: 290px 1fr; gap: 30px; align-items: start;
  position: relative; z-index: 1; }
@media (max-width: 900px) { .hero { grid-template-columns: 1fr; } }

.chart-card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
  padding: 18px 18px 14px; box-shadow: 0 2px 10px rgba(38,48,43,.06);
}
.chart-card h3 { margin: 0 0 4px; font-size: 14px; color: var(--muted); font-weight: 600;
  text-transform: uppercase; letter-spacing: .5px; text-align: center; }
.chart-card .tip { margin: 0 0 8px; font-size: 12px; color: var(--muted); text-align: center; }
.donut { display: block; margin: 0 auto; }
.donut circle.seg { cursor: pointer; transition: opacity .15s; }
.donut circle.seg:hover { opacity: .75; }
.donut-total { font: 700 42px "Segoe UI", Arial, sans-serif; fill: var(--text); }
.donut-caption { font: 500 12.5px "Segoe UI", Arial, sans-serif; fill: var(--muted);
  letter-spacing: .4px; }
.legend { margin: 12px 0 0; padding: 0; list-style: none; }
.legend li { border-top: 1px dashed var(--border); }
.legend li:first-child { border-top: none; }
.legend button {
  display: flex; align-items: center; gap: 9px; width: 100%; padding: 7px 6px;
  background: none; border: none; border-radius: 8px; cursor: pointer; text-align: left;
  font: inherit; font-size: 13.5px; color: var(--text); transition: background .15s;
}
.legend button:hover { background: var(--panel-2); }
.legend button:focus-visible { outline: 2px solid var(--green); }
.legend button[disabled] { cursor: default; opacity: .55; }
.legend button[disabled]:hover { background: none; }
.legend .dot { width: 11px; height: 11px; border-radius: 3px; flex: none; }
.legend .name { flex: 1; }
.legend .val { font-weight: 700; }
.legend .pct { color: var(--muted); font-size: 12.5px; min-width: 42px; text-align: right; }

.brand { display: flex; align-items: center; gap: 10px; color: var(--iron);
  font-size: 13px; letter-spacing: .6px; text-transform: uppercase; font-weight: 600; }
h1 { margin: 8px 0 6px; font-size: 27px; line-height: 1.25; letter-spacing: .2px;
  color: var(--green-dark); }
.target { font-size: 14.5px; color: var(--muted); }
.target b { color: var(--text); }
h2 { font-size: 19px; margin: 26px 0 12px; color: var(--green-dark);
  display: flex; align-items: center; gap: 9px; }
h2 .ico { flex: none; opacity: .8; }
.section-note { margin: -4px 0 14px; color: var(--muted); font-size: 13.5px; }

/* ---------- общая статистика ---------- */
.stat-group { margin-bottom: 12px; }
.stat-group > h3 {
  margin: 0 0 7px; font-size: 12px; text-transform: uppercase; letter-spacing: .7px;
  color: var(--muted); font-weight: 700;
}
.cards { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(158px, 1fr)); }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 11px 14px 12px; }
.card .num { font-size: 22px; font-weight: 700; color: var(--green-dark); line-height: 1.25; }
.card .num small { font-size: 14px; font-weight: 600; color: var(--muted); }
.card .lbl { color: var(--text); font-size: 13px; margin-top: 1px; }
.card .sub { color: var(--muted); font-size: 11.5px; margin-top: 3px; line-height: 1.35; }
.card.accent { background: var(--mint); border-color: var(--mint-deep); }
.card.alarm { border-color: #E8C4BB; background: #FDF6F4; }
.card.alarm .num { color: var(--high); }
.bar { height: 5px; border-radius: 99px; background: var(--panel-2); margin-top: 7px;
  overflow: hidden; border: 1px solid var(--border); }
.bar span { display: block; height: 100%; background: var(--green); }

/* ---------- пояснения ---------- */
.legend-help { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.help-item { background: var(--panel); border: 1px solid var(--border);
  border-left: 4px solid var(--iron-light); border-radius: 10px; padding: 10px 14px;
  font-size: 13.5px; text-align: left; font-family: inherit; color: var(--text); }
button.help-item { cursor: pointer; transition: box-shadow .15s, transform .15s; }
button.help-item:hover { box-shadow: 0 3px 10px rgba(38,48,43,.1); transform: translateY(-1px); }
.help-item.high { border-left-color: var(--high); }
.help-item.medium { border-left-color: var(--medium); }
.help-item.low { border-left-color: var(--low); }
.help-item.info { border-left-color: var(--safe); }
.help-item b { display: block; margin-bottom: 2px; }
.help-item span { color: var(--muted); }
.help-item .go { display: block; margin-top: 4px; color: var(--green); font-size: 12.5px; }

/* ---------- фильтры ---------- */
.filters { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 12px 14px; margin-bottom: 12px; }
.filter-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.filter-row + .filter-row { margin-top: 9px; padding-top: 9px; border-top: 1px dashed var(--border); }
.filter-row .cap { font-size: 12px; text-transform: uppercase; letter-spacing: .6px;
  color: var(--muted); font-weight: 700; min-width: 92px; }
button.f { background: var(--panel); color: var(--text); border: 1px solid var(--border);
  padding: 7px 14px; border-radius: 999px; cursor: pointer; font-size: 13px; transition: .15s;
  font-family: inherit; }
button.f:hover { border-color: var(--green); color: var(--green-dark); }
button.f.active { background: var(--green); border-color: var(--green); color: #fff; }
button.f .n { opacity: .7; font-size: 12px; }
button.f.active .n { opacity: .85; }
button.f.wide { font-weight: 600; }
input[type=search] { flex: 1; min-width: 230px; background: var(--panel); color: var(--text);
  border: 1px solid var(--border); border-radius: 9px; padding: 8px 13px; font-size: 14px;
  font-family: inherit; }
input[type=search]:focus { outline: 2px solid var(--mint-deep); border-color: var(--green); }
.hint { color: var(--muted); font-size: 13px; margin: 0 0 10px; }
.hint b { color: var(--text); }

/* ---------- таблица ---------- */
table { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 12px; overflow: hidden; font-size: 14px; }
th { text-align: left; background: var(--panel-2); padding: 11px 12px; font-size: 12px;
  text-transform: uppercase; letter-spacing: .5px; color: var(--muted);
  border-bottom: 1px solid var(--border); }
td { padding: 11px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
tr.f-row { cursor: pointer; }
tr.f-row:hover { background: var(--panel-2); }
tr.f-row.open { background: var(--mint); }
tr.details > td { background: var(--panel-2); }
.badge { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px;
  font-weight: 600; white-space: nowrap; color: #fff; }
.sev-high { background: var(--high); }
.sev-medium { background: var(--medium); }
.sev-low { background: var(--low); }
.sev-info { background: var(--safe); }
.threat { display: inline-block; background: var(--mint); border: 1px solid var(--mint-deep);
  color: var(--green-dark); border-radius: 7px; padding: 2px 9px; font-size: 12.5px; }
.cat { color: var(--muted); font-size: 13px; }
.nowrap { white-space: nowrap; }
.url { word-break: break-all; color: var(--green); font-size: 13px; }
a.url { text-decoration: none; border-bottom: 1px dotted var(--mint-deep); }
a.url:hover { text-decoration: none; border-bottom-color: var(--green); background: var(--mint); }
.title { font-weight: 600; }
.conf { font-size: 12.5px; color: var(--muted); white-space: nowrap; }
.conf.sus { color: var(--medium); }
.toggle { background: none; border: none; color: var(--green); cursor: pointer;
  font-size: 13px; padding: 0; text-decoration: underline dotted; white-space: nowrap;
  font-family: inherit; }

/* ---------- подробности ---------- */
.det { display: grid; gap: 12px; grid-template-columns: 1fr 1fr; padding: 4px 0 8px; }
@media (max-width: 860px) { .det { grid-template-columns: 1fr; } }
.det .full { grid-column: 1 / -1; }
.block { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
  padding: 12px 14px; }
.block.danger { border-left: 4px solid var(--high); }
.block.logic { border-left: 4px solid var(--iron); }
.block.fix { border-left: 4px solid var(--safe); background: #F6FBF8; }
.block h4 { margin: 0 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .5px;
  color: var(--muted); font-weight: 700; }
.block p { margin: 0; font-size: 14px; }
.det-head { display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  font-size: 13px; color: var(--muted); }
pre { margin: 0; padding: 10px 12px; background: #F7FAF8; border: 1px solid var(--border);
  border-radius: 8px; white-space: pre-wrap; word-break: break-word; color: #33403A;
  font: 12.5px/1.5 Consolas, "Courier New", monospace; max-height: 260px; overflow: auto; }

.empty { padding: 24px; text-align: center; color: var(--muted); background: var(--panel);
  border: 1px solid var(--border); border-radius: 12px; }
.note { background: var(--panel); border: 1px solid var(--border);
  border-left: 4px solid var(--iron); border-radius: 10px; padding: 11px 15px;
  color: var(--muted); font-size: 13.5px; margin-bottom: 8px; }
footer { margin-top: 32px; color: var(--muted); font-size: 12.5px; text-align: center;
  display: flex; align-items: center; justify-content: center; gap: 10px; flex-wrap: wrap; }
"""

JS = """
function currentFilters() {
  return {
    sev: document.querySelector('button.f.sev.active').dataset.value,
    cat: document.querySelector('button.f.cat-f.active').dataset.value,
    q: document.getElementById('q').value.trim().toLowerCase()
  };
}
function applyFilters() {
  var f = currentFilters();
  var shown = 0;
  document.querySelectorAll('tr.f-row').forEach(function (row) {
    var visible = (f.sev === 'all' || row.dataset.severity === f.sev)
      && (f.cat === 'all' || row.dataset.category === f.cat)
      && (f.q === '' || row.dataset.search.indexOf(f.q) !== -1);
    row.style.display = visible ? '' : 'none';
    if (!visible) { closeRow(row); }
    if (visible) { shown++; }
  });
  document.getElementById('shown').textContent = shown;
  var empty = document.getElementById('nothing');
  if (empty) { empty.style.display = shown ? 'none' : ''; }
  refreshToggleAll();
}
function selectButton(selector, value) {
  var found = false;
  document.querySelectorAll(selector).forEach(function (btn) {
    var active = btn.dataset.value === value;
    btn.classList.toggle('active', active);
    if (active) { found = true; }
  });
  if (!found) {
    var first = document.querySelector(selector);
    if (first) { first.classList.add('active'); }
  }
}
function showSeverity(value) {
  selectButton('button.f.sev', value);
  applyFilters();
  var anchor = document.getElementById('findings');
  if (anchor) { anchor.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
}
function initGroup(selector) {
  document.querySelectorAll(selector).forEach(function (btn) {
    btn.addEventListener('click', function () {
      selectButton(selector, btn.dataset.value);
      applyFilters();
    });
  });
}
function detailsOf(row) { return document.getElementById('d' + row.dataset.id); }
function isOpen(row) {
  var details = detailsOf(row);
  return !!details && details.style.display === 'table-row';
}
function setRow(row, open) {
  var details = detailsOf(row);
  if (!details) { return; }
  details.style.display = open ? 'table-row' : 'none';
  row.classList.toggle('open', open);
  var btn = row.querySelector('.toggle');
  if (btn) {
    btn.textContent = open ? 'свернуть' : 'подробнее';
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
}
function closeRow(row) { setRow(row, false); }
function toggleDetails(id) {
  var row = document.getElementById('r' + id);
  if (row) { setRow(row, !isOpen(row)); refreshToggleAll(); }
}
function visibleRows() {
  return Array.prototype.filter.call(
    document.querySelectorAll('tr.f-row'),
    function (row) { return row.style.display !== 'none'; }
  );
}
function refreshToggleAll() {
  var btn = document.getElementById('toggle-all');
  if (!btn) { return; }
  var rows = visibleRows();
  var allOpen = rows.length > 0 && rows.every(isOpen);
  btn.dataset.state = allOpen ? 'open' : 'closed';
  btn.textContent = allOpen ? 'Свернуть все' : 'Развернуть все';
  btn.disabled = rows.length === 0;
}
function toggleAll() {
  var btn = document.getElementById('toggle-all');
  var open = btn.dataset.state !== 'open';
  visibleRows().forEach(function (row) { setRow(row, open); });
  refreshToggleAll();
}
function resetFilters() {
  selectButton('button.f.sev', 'all');
  selectButton('button.f.cat-f', 'all');
  document.getElementById('q').value = '';
  applyFilters();
}
document.addEventListener('DOMContentLoaded', function () {
  initGroup('button.f.sev');
  initGroup('button.f.cat-f');
  document.getElementById('q').addEventListener('input', applyFilters);
  document.getElementById('toggle-all').addEventListener('click', toggleAll);
  document.querySelectorAll('[data-reset]').forEach(function (btn) {
    btn.addEventListener('click', resetFilters);
  });
  document.querySelectorAll('[data-severity-link]').forEach(function (element) {
    element.addEventListener('click', function () {
      showSeverity(element.dataset.severityLink);
    });
  });
  document.querySelectorAll('tr.f-row').forEach(function (row) {
    row.addEventListener('click', function (event) {
      // клик по ссылке открывает адрес, у кнопки «подробнее» свой обработчик
      if (event.target.closest('a') || event.target.closest('.toggle')) { return; }
      setRow(row, !isOpen(row));
      refreshToggleAll();
    });
  });
  applyFilters();
});
"""

SPIDER_ICON = """
<svg class="ico" width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
  <path d="M16 0v7" stroke="#B7B7B7" stroke-width="1.2"/>
  <g stroke="#858585" stroke-width="1.7" fill="none" stroke-linecap="round">
    <path d="M8.5 10 L13.5 15M23.5 10 L18.5 15M4.5 17 L12.5 18M27.5 17 L19.5 18
             M8.5 26 L13.5 21M23.5 26 L18.5 21"/>
  </g>
  <ellipse cx="16" cy="19" rx="5.2" ry="6.2" fill="#858585"/>
  <circle cx="16" cy="12" r="3.2" fill="#5F5F5F"/>
  <circle cx="14.7" cy="11.4" r="0.85" fill="#D8F1E6"/>
  <circle cx="17.3" cy="11.4" r="0.85" fill="#D8F1E6"/>
</svg>
"""

WEB_CORNER = """
<svg class="web" width="230" height="230" viewBox="0 0 200 200" aria-hidden="true">
  <g fill="none" stroke="#858585" stroke-width="1.1">
    <path d="M200 0 L0 200"/><path d="M200 0 L40 200"/><path d="M200 0 L110 200"/>
    <path d="M200 0 L200 200"/><path d="M200 0 L0 120"/><path d="M200 0 L0 40"/>
    <path d="M200 40 Q140 60 150 200" transform="rotate(0)"/>
    <path d="M170 0 Q120 70 30 90" />
    <path d="M200 70 Q110 90 70 200"/>
    <path d="M200 110 Q140 140 120 200"/>
    <path d="M130 0 Q90 40 10 60"/>
  </g>
</svg>
"""

WEB_LEFT = """
<svg class="web-left" width="200" height="200" viewBox="0 0 200 200" aria-hidden="true">
  <g fill="none" stroke="#858585" stroke-width="1">
    <path d="M0 200 L200 0"/><path d="M0 200 L160 0"/><path d="M0 200 L90 0"/>
    <path d="M0 200 L0 0"/><path d="M0 200 L200 80"/><path d="M0 200 L200 160"/>
    <path d="M0 160 Q60 140 50 0"/><path d="M0 120 Q100 100 130 0"/>
    <path d="M0 70 Q140 60 190 0"/>
  </g>
</svg>
"""

SPIDER_MARK = """
<svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
  <g stroke="#858585" stroke-width="1.8" fill="none" stroke-linecap="round">
    <path d="M9 8 L14 14M23 8 L18 14M5 16 L13 17M27 16 L19 17M9 25 L14 20M23 25 L18 20"/>
  </g>
  <ellipse cx="16" cy="19" rx="5.5" ry="6.5" fill="#858585"/>
  <circle cx="16" cy="12" r="3.4" fill="#5F5F5F"/>
  <circle cx="14.6" cy="11.4" r="0.9" fill="#D8F1E6"/>
  <circle cx="17.4" cy="11.4" r="0.9" fill="#D8F1E6"/>
</svg>
"""


def build_report(findings: FindingList, stats: Dict[str, object]) -> str:
    items = findings.sorted()
    by_severity = findings.count_by_severity()
    by_category = findings.count_by_category()
    by_confidence = _count_confidence(items)
    generated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    total = len(items)

    parts: List[str] = []
    parts.append(
        "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>Отчёт сканирования — {esc(str(stats.get('target', '')))}</title>\n"
        f"<style>{CSS}</style>\n</head>\n<body>\n"
    )

    # ---------- шапка: диаграмма слева, заголовок и статистика справа ----------
    parts.append("<header>")
    parts.append(WEB_CORNER)
    parts.append(WEB_LEFT)
    parts.append("<div class=\"wrap hero\">")
    parts.append(_chart_card(by_severity, total))
    parts.append("<div class=\"hero-main\">")
    parts.append(f"<div class=\"brand\">{SPIDER_MARK}<span>Сканер безопасности веб-приложений</span></div>")
    parts.append("<h1>Отчёт сканирования безопасности веб-приложения</h1>")
    parts.append(
        f"<div class=\"target\">Цель: <b>{_link(str(stats.get('target', '')))}</b> · "
        f"отчёт сформирован {generated}</div>"
    )
    parts.append(f"<h2>{SPIDER_ICON}Общая статистика</h2>")
    parts.append(_stat_cards(stats, by_severity, by_category, by_confidence, total))
    parts.append("</div></div></header>\n")

    parts.append("<div class=\"wrap\">")

    # ---------- как читать отчёт ----------
    parts.append(f"<h2>{SPIDER_ICON}Как читать отчёт</h2>")
    parts.append(
        "<p class=\"section-note\">Нажмите на уровень опасности — здесь, в диаграмме или в "
        "фильтрах — и в таблице «Найденные проблемы» останутся только записи этого уровня. "
        "Строка таблицы раскрывается щелчком по ней.</p>"
    )
    parts.append("<div class=\"legend-help\">")
    for severity, label, _color in CHART_CATEGORIES:
        css = SEVERITY_CLASS[severity].replace("sev-", "")
        count = by_severity.get(severity, 0)
        parts.append(
            f"<button type=\"button\" class=\"help-item {css}\" "
            f"data-severity-link=\"{esc(severity)}\">"
            f"<b>{esc(label)} ({esc(severity)}) — {count}</b>"
            f"<span>{esc(SEVERITY_HINT[severity])}</span>"
            f"<span class=\"go\">Показать эти находки →</span></button>"
        )
    parts.append(
        "<div class=\"help-item\"><b>Уверенность</b><span>«подтверждено» — факт виден прямо "
        "в ответе сервера; «подозрение» — признак требует ручной проверки, возможно ложное "
        "срабатывание.</span></div>"
        "<div class=\"help-item\"><b>Что внутри каждой записи</b><span>тип угрозы, чем она "
        "опасна, по какой логике сканер сделал вывод, отправленный запрос, фрагмент ответа "
        "и рекомендация.</span></div>"
    )
    parts.append("</div>")

    notes = stats.get("notes") or []
    if notes:
        parts.append(f"<h2>{SPIDER_ICON}Замечания по выполнению</h2>")
        for note in notes:
            parts.append(f"<div class=\"note\">{esc(str(note))}</div>")

    # ---------- таблица находок ----------
    parts.append(f"<h2 id=\"findings\">{SPIDER_ICON}Найденные проблемы</h2>")
    parts.append(_filters(by_severity, by_category, total))

    if not items:
        parts.append("<div class=\"empty\">Проблем не обнаружено. Это не гарантирует "
                     "отсутствие уязвимостей: сканер выполняет ограниченный набор "
                     "безопасных проверок.</div>")
    else:
        parts.append(
            "<table><thead><tr>"
            "<th>Уровень опасности</th><th>Что нашли</th><th>Тип угрозы</th>"
            "<th>Категория</th><th>Где нашли (адрес)</th><th>Насколько точно</th><th></th>"
            "</tr></thead><tbody>"
        )
        for index, finding in enumerate(items):
            parts.append(_row(index, finding))
        parts.append("</tbody></table>")
        parts.append(
            "<div class=\"empty\" id=\"nothing\" style=\"display:none\">"
            "Под выбранные условия не подходит ни одна запись. "
            "<button type=\"button\" class=\"toggle\" data-reset>Сбросить фильтры</button>"
            "</div>"
        )

    parts.append(_appendix(stats))
    parts.append(
        f"<footer>{SPIDER_MARK}<span>Отчёт сформирован сканером конфигурации веб-приложений. "
        "Все проверки безопасны и не изменяют данные; тестовые значения — "
        "BAUMAN_TEST_92841, https://evil.com, одиночные кавычки. "
        "Результаты со статусом «подозрение» требуют ручной проверки.</span></footer>"
    )
    parts.append("</div>")
    parts.append(f"<script>{JS}</script>\n</body>\n</html>")
    return "".join(parts)


# ---------- кольцевая диаграмма ----------
def _chart_card(by_severity: Dict[str, int], total: int) -> str:
    radius = 76
    stroke = 26
    circumference = 2 * math.pi * radius
    segments: List[str] = []
    offset = 0.0

    values = [(severity, label, color, by_severity.get(severity, 0))
              for severity, label, color in CHART_CATEGORIES]
    nonzero = [item for item in values if item[3] > 0]

    if total <= 0 or not nonzero:
        segments.append(
            f"<circle cx=\"110\" cy=\"110\" r=\"{radius}\" fill=\"none\" stroke=\"#E2E9E4\" "
            f"stroke-width=\"{stroke}\"/>"
        )
    else:
        for severity, label, color, count in nonzero:
            length = circumference * count / total
            gap = 2.0 if len(nonzero) > 1 and length > 6 else 0.0
            segments.append(
                f"<circle class=\"seg\" data-severity-link=\"{esc(severity)}\" "
                f"cx=\"110\" cy=\"110\" r=\"{radius}\" fill=\"none\" stroke=\"{color}\" "
                f"stroke-width=\"{stroke}\" stroke-linecap=\"butt\" "
                f"stroke-dasharray=\"{max(length - gap, 0.1):.2f} "
                f"{circumference - max(length - gap, 0.1):.2f}\" "
                f"stroke-dashoffset=\"{-offset:.2f}\" "
                f"transform=\"rotate(-90 110 110)\">"
                f"<title>{esc(label)}: {count} — нажмите, чтобы отфильтровать таблицу"
                f"</title></circle>"
            )
            offset += length

    legend: List[str] = []
    for severity, label, color, count in values:
        percent = (count * 100 / total) if total else 0
        disabled = "" if count else " disabled"
        legend.append(
            f"<li><button type=\"button\" data-severity-link=\"{esc(severity)}\"{disabled} "
            f"title=\"Показать в таблице только уровень «{esc(label)}»\">"
            f"<span class=\"dot\" style=\"background:{color}\"></span>"
            f"<span class=\"name\">{esc(label)}</span>"
            f"<span class=\"val\">{count}</span>"
            f"<span class=\"pct\">{percent:.0f}%</span></button></li>"
        )

    return (
        "<div class=\"chart-card\">"
        "<h3>Статистика уязвимостей</h3>"
        "<p class=\"tip\">Нажмите на уровень, чтобы увидеть эти находки</p>"
        "<svg class=\"donut\" width=\"220\" height=\"220\" viewBox=\"0 0 220 220\" "
        "role=\"img\" aria-label=\"Распределение находок по уровням критичности\">"
        f"<circle cx=\"110\" cy=\"110\" r=\"{radius}\" fill=\"none\" stroke=\"#EDF3EF\" "
        f"stroke-width=\"{stroke}\"/>"
        + "".join(segments) +
        f"<text class=\"donut-total\" x=\"110\" y=\"106\" text-anchor=\"middle\" "
        f"dominant-baseline=\"middle\">{total}</text>"
        "<text class=\"donut-caption\" x=\"110\" y=\"132\" text-anchor=\"middle\">"
        "всего находок</text>"
        "</svg>"
        "<ul class=\"legend\">" + "".join(legend) + "</ul>"
        "</div>"
    )


# ---------- общая статистика ----------
def _stat_cards(stats: Dict[str, object], by_severity: Dict[str, int],
                by_category: Dict[str, int], by_confidence: Dict[str, int],
                total: int) -> str:
    requests_made = _int(stats.get("requests_made"))
    max_requests = _int(stats.get("max_requests"))
    pages = _int(stats.get("pages"))
    max_pages = _int(stats.get("max_pages"))
    attention = by_severity.get(HIGH, 0) + by_severity.get(MEDIUM, 0)
    errors = _int(stats.get("error_count", len(stats.get("errors") or [])))
    external = _int(stats.get("external_count", len(stats.get("external_links") or [])))
    https = bool(stats.get("https", str(stats.get("target", "")).lower().startswith("https")))

    scanned = [
        _card(f"{pages}", "Страниц проверено", f"из лимита {max_pages} в пределах домена",
              css="accent"),
        _card(f"{_int(stats.get('forms'))}", "Форм на страницах",
              "поля ввода — основные точки для проверки"),
        _card(f"{_int(stats.get('url_params'))}", "Параметров в адресах",
              "значения в ссылках вида ?id=5"),
        _card(f"{external}", "Ссылок на чужие сайты",
              "сканер по ним не переходил"),
        _card(f"≤ {_int(stats.get('max_depth'))}", "Глубина обхода",
              "переходов по ссылкам от стартовой страницы"),
        _card("HTTPS" if https else "HTTP", "Протокол сайта",
              "соединение шифруется" if https else "соединение не шифруется"),
    ]

    found = [
        _card(f"{total}", "Всего записей в отчёте", "включая справочные «Безопасно»"),
        _card(f"{attention}", "Требуют внимания", "высокая и средняя опасность",
              css="alarm" if attention else ""),
        _card(f"{by_category.get(VULN, 0)}", "Уязвимостей приложения",
              "ошибки обработки пользовательского ввода"),
        _card(f"{by_category.get(CONFIG, 0)}", "Проблем конфигурации",
              "настройки сервера, заголовков, cookie"),
        _card(f"{by_confidence.get(CONFIRMED, 0)}", "Подтверждено",
              "факт виден прямо в ответе сервера"),
        _card(f"{by_confidence.get(SUSPECTED, 0)}", "Требуют ручной проверки",
              "признак есть, возможно ложное срабатывание"),
    ]

    percent = int(round(100 * requests_made / max_requests)) if max_requests else 0
    how = [
        _card(f"{requests_made}<small> / {max_requests}</small>", "Запросов к сайту",
              f"израсходовано {percent}% разрешённого лимита", bar=percent),
        _card(f"{_int(stats.get('checks'))}", "Проверок выполнено",
              "заголовки, cookie, формы, служебные адреса и другие"),
        _card(f"{_int(stats.get('active_tests'))}", "Активных тестов",
              f"безопасных проб на {_int(stats.get('targets_tested'))} точках ввода"),
        _card(f"{errors}", "Запросов без ответа",
              "таймаут, отказ соединения или ошибка сети"),
        _card(f"{stats.get('duration', 0)}<small> с</small>", "Длительность сканирования",
              "между запросами выдерживается пауза 0.5 с"),
        _card(f"{_int(stats.get('insecure_requests'))}", "Запросов без проверки сертификата",
              "выполняются, только если сертификат не прошёл проверку"),
    ]

    groups = (
        ("Что просканировано", scanned),
        ("Что найдено", found),
        ("Как выполнялось сканирование", how),
    )
    html_parts: List[str] = []
    for title, cards in groups:
        html_parts.append(
            f"<div class=\"stat-group\"><h3>{esc(title)}</h3>"
            f"<div class=\"cards\">{''.join(cards)}</div></div>"
        )
    return "".join(html_parts)


def _card(number: str, label: str, sub: str = "", css: str = "", bar: int = -1) -> str:
    bar_html = ""
    if bar >= 0:
        bar_html = f"<div class=\"bar\"><span style=\"width:{min(max(bar, 0), 100)}%\"></span></div>"
    sub_html = f"<div class=\"sub\">{esc(sub)}</div>" if sub else ""
    classes = ("card " + css).strip()
    return (
        f"<div class=\"{classes}\"><div class=\"num\">{number}</div>"
        f"<div class=\"lbl\">{esc(label)}</div>{sub_html}{bar_html}</div>"
    )


# ---------- фильтры ----------
def _filters(by_severity: Dict[str, int], by_category: Dict[str, int], total: int) -> str:
    severity_buttons = [
        f"<button class=\"f sev wide active\" data-value=\"all\">Все уровни "
        f"<span class=\"n\">{total}</span></button>"
    ]
    for severity, label, _color in CHART_CATEGORIES:
        severity_buttons.append(
            f"<button class=\"f sev\" data-value=\"{esc(severity)}\">{esc(label)} "
            f"<span class=\"n\">{by_severity.get(severity, 0)}</span></button>"
        )

    category_buttons = [
        f"<button class=\"f cat-f wide active\" data-value=\"all\">Все категории "
        f"<span class=\"n\">{total}</span></button>",
        f"<button class=\"f cat-f\" data-value=\"{CONFIG}\">Конфигурация "
        f"<span class=\"n\">{by_category.get(CONFIG, 0)}</span></button>",
        f"<button class=\"f cat-f\" data-value=\"{VULN}\">Уязвимости "
        f"<span class=\"n\">{by_category.get(VULN, 0)}</span></button>",
    ]

    return (
        "<div class=\"filters\">"
        "<div class=\"filter-row\"><span class=\"cap\">Уровень</span>"
        + "".join(severity_buttons) +
        "</div>"
        "<div class=\"filter-row\"><span class=\"cap\">Категория</span>"
        + "".join(category_buttons) +
        "</div>"
        "<div class=\"filter-row\"><span class=\"cap\">Поиск</span>"
        "<input type=\"search\" id=\"q\" placeholder=\"Введите слово: адрес, название "
        "проблемы, тип угрозы, текст доказательства…\">"
        "<button class=\"f\" id=\"toggle-all\" data-state=\"closed\">Развернуть все</button>"
        "<button class=\"f\" data-reset>Сбросить</button>"
        "</div>"
        "</div>"
        f"<p class=\"hint\">Показано записей: <b id=\"shown\">0</b> из {total}. "
        "Щёлкните по строке (или по слову «подробнее»), чтобы увидеть, чем проблема опасна, "
        "как сканер её нашёл, какой запрос отправлял и что нужно исправить.</p>"
    )


def _row(index: int, finding: Finding) -> str:
    severity_class = SEVERITY_CLASS.get(finding.severity, "sev-info")
    severity_label = SEVERITY_LABEL.get(finding.severity, finding.severity)
    confidence_class = "conf sus" if finding.confidence == SUSPECTED else "conf"
    search_blob = " ".join([finding.url, finding.title, finding.category, finding.severity,
                            severity_label, finding.threat_type, finding.impact,
                            finding.detection, finding.evidence, finding.request,
                            finding.confidence]).lower()
    row = (
        f"<tr class=\"f-row\" id=\"r{index}\" data-id=\"{index}\" "
        f"data-severity=\"{esc(finding.severity)}\" data-category=\"{esc(finding.category)}\" "
        f"data-search=\"{esc(search_blob)}\">"
        f"<td class=\"nowrap\"><span class=\"badge {severity_class}\">{esc(severity_label)}"
        f"</span></td>"
        f"<td class=\"title\">{esc(finding.title)}</td>"
        f"<td><span class=\"threat\">{esc(finding.threat_type)}</span></td>"
        f"<td class=\"cat\">{esc(finding.category)}</td>"
        f"<td>{_link(finding.url)}</td>"
        f"<td class=\"{confidence_class}\">{esc(finding.confidence)}</td>"
        f"<td class=\"nowrap\"><button class=\"toggle\" aria-expanded=\"false\" "
        f"onclick=\"toggleDetails({index})\">подробнее</button></td>"
        "</tr>"
    )
    details = (
        f"<tr class=\"details\" id=\"d{index}\" style=\"display:none\"><td colspan=\"7\">"
        "<div class=\"det\">"
        "<div class=\"block danger full\"><h4>Чем это опасно</h4>"
        f"<p>{esc(finding.impact or 'Описание для этого типа находки не задано.')}</p></div>"
        "<div class=\"block logic full\"><h4>Почему сканер так решил</h4>"
        f"<p>{esc(finding.detection or 'Логика проверки описана в названии находки.')}</p></div>"
        "<div class=\"block\"><h4>Что отправил сканер (безопасные тестовые данные)</h4>"
        f"<pre>{esc(finding.request or '—')}</pre></div>"
        "<div class=\"block\"><h4>Что ответил сервер (доказательство)</h4>"
        f"<pre>{esc(finding.evidence or '—')}</pre></div>"
        "<div class=\"block fix full\"><h4>Как исправить</h4>"
        f"<p>{esc(finding.recommendation or '—')}</p></div>"
        "</div></td></tr>"
    )
    return row + details


def _appendix(stats: Dict[str, object]) -> str:
    parts = [f"<h2>{SPIDER_ICON}Просканированные страницы</h2>"]
    pages = stats.get("page_list") or []
    if pages:
        parts.append(
            "<p class=\"section-note\">Адреса кликабельны — открываются в новой вкладке.</p>"
            "<table><thead><tr><th>№</th><th>Адрес страницы</th><th>Ответ сервера</th>"
            "<th>Глубина от стартовой</th><th>Тип содержимого</th>"
            "<th>Кол-во символов в коде</th></tr></thead><tbody>"
        )
        for number, page in enumerate(pages, 1):
            parts.append(
                f"<tr><td>{number}</td><td>{_link(str(page['url']))}</td>"
                f"<td class=\"nowrap\">{_status(page['status'])}</td>"
                f"<td>{page['depth']}</td>"
                f"<td class=\"cat\">{esc(page['content_type'] or '—')}</td>"
                f"<td class=\"nowrap\">{_thousands(page['size'])}</td></tr>"
            )
        parts.append("</tbody></table>")
    else:
        parts.append("<div class=\"empty\">Ни одна страница не была загружена.</div>")

    errors = stats.get("errors") or []
    if errors:
        parts.append(f"<h2>{SPIDER_ICON}Запросы, оставшиеся без ответа</h2>")
        parts.append("<table><thead><tr><th>Адрес</th><th>Что произошло</th>"
                     "</tr></thead><tbody>")
        for url, message in errors[:40]:
            parts.append(f"<tr><td>{_link(str(url))}</td>"
                         f"<td class=\"cat\">{esc(message)}</td></tr>")
        parts.append("</tbody></table>")

    performed = stats.get("checks_list") or []
    if performed:
        parts.append(f"<h2>{SPIDER_ICON}Какие проверки выполнялись</h2>")
        parts.append("<table><thead><tr><th>Проверка</th><th>Где выполнялась</th>"
                     "</tr></thead><tbody>")
        for name, scope in performed:
            parts.append(f"<tr><td>{esc(name)}</td><td class=\"cat\">{esc(scope)}</td></tr>")
        parts.append("</tbody></table>")
    return "".join(parts)


# ---------- вспомогательное ----------
def _count_confidence(items: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {CONFIRMED: 0, SUSPECTED: 0}
    for finding in items:
        counts[finding.confidence] = counts.get(finding.confidence, 0) + 1
    return counts


def _link(url: str, text: str = "") -> str:
    """Кликабельный адрес: открывается в новой вкладке и не передаёт отчёт как источник."""
    url = str(url or "")
    label = esc(text or url or "—")
    if url.lower().startswith(("http://", "https://")):
        return (f"<a class=\"url\" href=\"{esc(url)}\" target=\"_blank\" "
                f"rel=\"noopener noreferrer\" title=\"Открыть {esc(url)} в новой вкладке\">"
                f"{label}</a>")
    return f"<span class=\"url\">{label}</span>"


def _status(status: object) -> str:
    """Код ответа с пояснением на русском."""
    meanings = {2: "страница отдана", 3: "переадресация", 4: "не найдено или закрыто",
                5: "ошибка на сервере"}
    try:
        code = int(status)
    except (TypeError, ValueError):
        return esc(status)
    meaning = meanings.get(code // 100, "")
    return f"{code}" + (f" <span class=\"cat\">— {esc(meaning)}</span>" if meaning else "")


def _thousands(value: object) -> str:
    try:
        return f"{int(value):,}".replace(",", " ")
    except (TypeError, ValueError):
        return esc(value)


def _int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)
