"""Формирование HTML-отчёта (раздел 6 требований).

Оформление: светло-серые и зелёные оттенки, тематика пауков и паутины.
На главном экране — кольцевая диаграмма распределения находок по уровням
критичности (уровни кликабельны) и блок «Общая статистика». Подробные разделы
(как читать отчёт, найденные проблемы, просканированные страницы, список
проверок, запросы без ответа) вынесены в боковую выпадающую панель, чтобы
главный экран помещался без прокрутки. Кнопка «Скачать PDF» открывает печать
краткой сводки — браузер сохраняет её в PDF.
"""

import datetime
import html
import math
from typing import Dict, List, Optional, Sequence, Tuple

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
  margin: 0; padding: 0 0 28px; color: var(--text); min-height: 100vh;
  background: linear-gradient(135deg, #FFFFFF 0%, var(--mint) 100%) fixed;
  font: 15px/1.6 "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
body.locked { overflow: hidden; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 0 22px; }
a { color: var(--green); }

/* ---------- шапка с диаграммой ---------- */
header { position: relative; overflow: hidden; padding: 22px 0 6px; }
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
h1 { margin: 6px 0 5px; font-size: 26px; line-height: 1.25; letter-spacing: .2px;
  color: var(--green-dark); }
.target { font-size: 14.5px; color: var(--muted); margin-bottom: 4px; }
.target b { color: var(--text); }
h2 { font-size: 19px; margin: 18px 0 10px; color: var(--green-dark);
  display: flex; align-items: center; gap: 9px; }
h2 .ico { flex: none; opacity: .8; }
.section-note { margin: -4px 0 12px; color: var(--muted); font-size: 13.5px; }

/* ---------- общая статистика ---------- */
.stat-group { margin-bottom: 10px; }
.stat-group > h3 {
  margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .7px;
  color: var(--muted); font-weight: 700;
}
.cards { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(158px, 1fr)); }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 10px 14px 11px; text-align: left; font-family: inherit; color: var(--text); }
.card .num { font-size: 22px; font-weight: 700; color: var(--green-dark); line-height: 1.25; }
.card .num small { font-size: 14px; font-weight: 600; color: var(--muted); }
.card .lbl { color: var(--text); font-size: 13px; margin-top: 1px; }
.card .sub { color: var(--muted); font-size: 11.5px; margin-top: 3px; line-height: 1.35; }
.card .go { color: var(--high); font-size: 12px; margin-top: 4px; font-weight: 600; }
.card.accent { background: var(--mint); border-color: var(--mint-deep); }
.card.alarm { border-color: #E8C4BB; background: #FDF6F4; }
.card.alarm .num { color: var(--high); }
.card.alarm.strong { border-width: 2px; border-color: var(--high); background: #FBEDE9;
  box-shadow: 0 2px 10px rgba(180,80,60,.14); }
button.card { cursor: pointer; width: 100%; transition: transform .15s, box-shadow .15s; }
button.card:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(180,80,60,.2); }
.bar { height: 5px; border-radius: 99px; background: var(--panel-2); margin-top: 7px;
  overflow: hidden; border: 1px solid var(--border); }
.bar span { display: block; height: 100%; background: var(--green); }

/* ---------- карточки-разделы (открывают боковую панель) ---------- */
.nav-cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
.nav-card { display: block; text-align: left; font-family: inherit; cursor: pointer;
  background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
  padding: 13px 15px 12px; color: var(--text); transition: transform .15s, box-shadow .15s,
  border-color .15s; }
.nav-card:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(38,48,43,.12);
  border-color: var(--green); }
.nav-card .nav-n { font-size: 21px; font-weight: 700; color: var(--green-dark); }
.nav-card .nav-t { display: block; font-weight: 600; font-size: 14.5px; margin-top: 1px; }
.nav-card .nav-s { display: block; color: var(--muted); font-size: 12px; margin-top: 3px;
  line-height: 1.35; }
.nav-card .nav-go { display: block; color: var(--green); font-size: 12.5px; margin-top: 6px; }
.nav-card.pdf { background: var(--mint); border-color: var(--mint-deep); }
.nav-card.pdf .nav-t { color: var(--green-dark); }

/* ---------- боковая выпадающая панель ---------- */
.backdrop { position: fixed; inset: 0; background: rgba(30,42,36,.38); z-index: 30;
  opacity: 0; visibility: hidden; transition: opacity .22s, visibility .22s; }
.backdrop.open { opacity: 1; visibility: visible; }
.drawer { position: fixed; top: 0; right: 0; height: 100vh; width: min(1180px, 95vw);
  background: var(--bg); border-left: 1px solid var(--border); z-index: 31;
  box-shadow: -16px 0 40px rgba(38,48,43,.22); display: flex; flex-direction: column;
  transform: translateX(101%); transition: transform .26s ease; }
.drawer.open { transform: none; }
.drawer-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 11px 16px; background: var(--panel); border-bottom: 1px solid var(--border); }
.tab { background: var(--panel); border: 1px solid var(--border); border-radius: 999px;
  padding: 7px 14px; font: inherit; font-size: 13px; color: var(--text); cursor: pointer;
  transition: .15s; }
.tab:hover { border-color: var(--green); color: var(--green-dark); }
.tab.active { background: var(--green); border-color: var(--green); color: #fff; }
.tab .n { opacity: .7; font-size: 12px; }
.tab.active .n { opacity: .85; }
.drawer-close { margin-left: auto; background: var(--panel); border: 1px solid var(--border);
  border-radius: 9px; width: 34px; height: 34px; font-size: 17px; line-height: 1; cursor: pointer;
  color: var(--muted); font-family: inherit; }
.drawer-close:hover { border-color: var(--high); color: var(--high); }
.drawer-body { flex: 1; overflow: auto; padding: 4px 22px 40px; }
.drawer-body h2:first-child { margin-top: 14px; }
.panel[hidden] { display: none; }

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
tr.f-row.critical { background: #FDF6F4; }
tr.f-row.critical > td:first-child { box-shadow: inset 4px 0 0 var(--high); }
tr.f-row.critical:hover { background: #F8E7E1; }
tr.f-row.critical .title { color: #8E3A2A; }
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
.conf.yes { color: var(--high); font-weight: 600; }
.toggle { background: none; border: none; color: var(--green); cursor: pointer;
  font-size: 13px; padding: 0; text-decoration: underline dotted; white-space: nowrap;
  font-family: inherit; }
.lines { margin: 0; padding-left: 18px; }
.lines li { margin: 2px 0; }

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
pre { margin: 0; padding: 10px 12px; background: #F7FAF8; border: 1px solid var(--border);
  border-radius: 8px; white-space: pre-wrap; word-break: break-word; color: #33403A;
  font: 12.5px/1.5 Consolas, "Courier New", monospace; max-height: 260px; overflow: auto; }

.empty { padding: 24px; text-align: center; color: var(--muted); background: var(--panel);
  border: 1px solid var(--border); border-radius: 12px; }
.note { background: var(--panel); border: 1px solid var(--border);
  border-left: 4px solid var(--iron); border-radius: 10px; padding: 10px 15px;
  color: var(--muted); font-size: 13.5px; margin-bottom: 8px; }
footer { margin-top: 20px; color: var(--muted); font-size: 12.5px; text-align: center;
  display: flex; align-items: center; justify-content: center; gap: 10px; flex-wrap: wrap; }

/* ---------- печатная версия (сохранение в PDF) ---------- */
#pdf-report { display: none; }
@media print {
  @page { size: A4; margin: 12mm; }
  body { background: #FFFFFF !important; padding: 0; }
  body > *:not(#pdf-report) { display: none !important; }
  #pdf-report { display: block !important; }
}
#pdf-report h1 { font-size: 20px; margin: 0 0 2px; color: var(--green-dark); }
#pdf-report h2 { font-size: 15px; margin: 16px 0 6px; display: block; }
#pdf-report .pdf-sub { margin: 0 0 12px; color: var(--muted); font-size: 12px; }
#pdf-report table { font-size: 11.5px; border-radius: 0; page-break-inside: auto; }
#pdf-report th, #pdf-report td { padding: 5px 7px; }
#pdf-report thead { display: table-header-group; }
#pdf-report tr { page-break-inside: avoid; }
#pdf-report .kv { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }
#pdf-report .kv div { border: 1px solid var(--border); border-radius: 8px; padding: 5px 10px;
  font-size: 11.5px; }
#pdf-report .kv b { font-size: 15px; display: block; color: var(--green-dark); }
#pdf-report .kv.alarm b { color: var(--high); }
#pdf-report .pdf-foot { font-size: 10.5px; color: var(--muted); margin-top: 14px; }
#pdf-report .crit td { background: #FDF6F4; }
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
function openPanel(name) {
  document.querySelectorAll('.panel').forEach(function (panel) {
    panel.hidden = panel.dataset.panel !== name;
  });
  document.querySelectorAll('.tab').forEach(function (tab) {
    tab.classList.toggle('active', tab.dataset.open === name);
  });
  var drawer = document.getElementById('drawer');
  drawer.classList.add('open');
  drawer.setAttribute('aria-hidden', 'false');
  document.getElementById('backdrop').classList.add('open');
  document.body.classList.add('locked');
  var body = document.getElementById('drawer-body');
  if (body) { body.scrollTop = 0; }
}
function closePanel() {
  var drawer = document.getElementById('drawer');
  drawer.classList.remove('open');
  drawer.setAttribute('aria-hidden', 'true');
  document.getElementById('backdrop').classList.remove('open');
  document.body.classList.remove('locked');
}
function showSeverity(value) {
  selectButton('button.f.sev', value);
  selectButton('button.f.cat-f', 'all');
  document.getElementById('q').value = '';
  applyFilters();
  openPanel('findings');
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
  document.querySelectorAll('[data-open]').forEach(function (btn) {
    btn.addEventListener('click', function () { openPanel(btn.dataset.open); });
  });
  document.querySelectorAll('[data-close]').forEach(function (btn) {
    btn.addEventListener('click', closePanel);
  });
  document.querySelectorAll('[data-print]').forEach(function (btn) {
    btn.addEventListener('click', function () { closePanel(); window.print(); });
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { closePanel(); }
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
    critical = [item for item in items
                if item.severity == HIGH and item.confidence == CONFIRMED]
    generated = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    total = len(items)
    pages = list(stats.get("page_list") or [])
    errors = list(stats.get("errors") or [])
    performed = list(stats.get("checks_list") or [])
    target = str(stats.get("target", ""))

    # Разделы боковой панели: ключ, заголовок, число в карточке, пояснение, содержимое
    panels: List[Tuple[str, str, Optional[int], str, str]] = [
        ("findings", "Найденные проблемы", total,
         "фильтры по уровню и категории, поиск и подробный разбор каждой записи",
         _findings_panel(items, by_severity, by_category, total)),
        ("help", "Как читать отчёт", None,
         "что означают уровни опасности, уверенность и содержимое записи",
         _help_panel(by_severity)),
        ("pages", "Просканированные страницы", len(pages),
         "адреса, ответы сервера, глубина обхода и размер кода",
         _pages_panel(pages)),
        ("checks", "Какие проверки выполнялись", len(performed),
         "полный список выполненных проверок и их охват",
         _checks_panel(performed)),
    ]
    if errors:
        panels.append(("errors", "Запросы, оставшиеся без ответа", len(errors),
                       "таймауты, отказы соединения и другие сетевые ошибки",
                       _errors_panel(errors)))

    parts: List[str] = []
    parts.append(
        "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>Отчёт сканирования — {esc(target)}</title>\n"
        f"<style>{CSS}</style>\n</head>\n<body>\n"
    )

    # ---------- главный экран: диаграмма, заголовок, статистика ----------
    parts.append("<header>")
    parts.append(WEB_CORNER)
    parts.append(WEB_LEFT)
    parts.append("<div class=\"wrap hero\">")
    parts.append(_chart_card(by_severity, total))
    parts.append("<div class=\"hero-main\">")
    parts.append(f"<div class=\"brand\">{SPIDER_MARK}<span>Сканер безопасности веб-приложений</span></div>")
    parts.append("<h1>Отчёт сканирования безопасности веб-приложения</h1>")
    parts.append(
        f"<div class=\"target\">Цель: <b>{_link(target)}</b> · "
        f"отчёт сформирован {generated}</div>"
    )
    parts.append(f"<h2>{SPIDER_ICON}Общая статистика</h2>")
    parts.append(_stat_cards(stats, by_severity, by_category, len(critical), total))
    parts.append("</div></div></header>\n")

    parts.append("<div class=\"wrap\">")

    # ---------- карточки разделов и замечания ----------
    parts.append(f"<h2>{SPIDER_ICON}Разделы отчёта</h2>")
    parts.append(
        "<p class=\"section-note\">Подробности вынесены в боковую панель: нажмите карточку — "
        "раздел откроется поверх страницы, закрывается кнопкой «×», щелчком по фону или "
        "клавишей Esc.</p>"
    )
    parts.append(_nav_cards(panels))

    notes = stats.get("notes") or []
    if notes:
        parts.append(f"<h2>{SPIDER_ICON}Замечания по выполнению</h2>")
        for note in notes:
            parts.append(f"<div class=\"note\">{esc(str(note))}</div>")

    parts.append(
        f"<footer>{SPIDER_MARK}<span>Отчёт сформирован сканером конфигурации веб-приложений. "
        "Все проверки безопасны и не изменяют данные; тестовые значения — "
        "BAUMAN_TEST_92841, https://evil.com, одиночные кавычки. "
        "Результаты со статусом «подозрение» требуют ручной проверки.</span></footer>"
    )
    parts.append("</div>")

    # ---------- боковая панель ----------
    parts.append(_drawer(panels))

    # ---------- печатная версия для сохранения в PDF ----------
    parts.append(_pdf_report(stats, by_severity, by_confidence, critical, items,
                             total, generated))

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
                by_category: Dict[str, int], critical: int, total: int) -> str:
    requests_made = _int(stats.get("requests_made"))
    max_requests = _int(stats.get("max_requests"))
    pages = _int(stats.get("pages"))
    max_pages = _int(stats.get("max_pages"))
    attention = by_severity.get(HIGH, 0) + by_severity.get(MEDIUM, 0)
    errors = _int(stats.get("error_count", len(stats.get("errors") or [])))
    https = bool(stats.get("https", str(stats.get("target", "")).lower().startswith("https")))

    scanned = [
        _card(f"{pages}", "Страниц проверено", f"из лимита {max_pages} в пределах домена",
              css="accent"),
        _card(f"{_int(stats.get('forms'))}", "Форм на страницах",
              "поля ввода — основные точки для проверки"),
        _card(f"{_int(stats.get('url_params'))}", "Параметров в адресах",
              "значения в ссылках вида ?id=5"),
        _card("HTTPS" if https else "HTTP", "Протокол сайта",
              "соединение шифруется" if https else "соединение не шифруется"),
    ]

    found = [
        _card(f"{total}", "Всего записей в отчёте", "включая справочные «Безопасно»"),
        _card(f"{attention}", "Требуют внимания", "высокая и средняя опасность",
              css="alarm" if attention else ""),
        _card(f"{critical}", "Подтверждённые угрозы высокого уровня",
              "факт виден прямо в ответе сервера — исправлять первыми"
              if critical else "таких находок нет",
              css="alarm strong" if critical else "",
              link=HIGH if critical else ""),
        _card(f"{by_category.get(VULN, 0)}", "Уязвимостей приложения",
              "ошибки обработки пользовательского ввода"),
        _card(f"{by_category.get(CONFIG, 0)}", "Проблем конфигурации",
              "настройки сервера, заголовков, cookie"),
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


def _card(number: str, label: str, sub: str = "", css: str = "", bar: int = -1,
          link: str = "") -> str:
    bar_html = ""
    if bar >= 0:
        bar_html = f"<div class=\"bar\"><span style=\"width:{min(max(bar, 0), 100)}%\"></span></div>"
    sub_html = f"<div class=\"sub\">{esc(sub)}</div>" if sub else ""
    classes = ("card " + css).strip()
    body = (f"<div class=\"num\">{number}</div><div class=\"lbl\">{esc(label)}</div>"
            f"{sub_html}{bar_html}")
    if link:
        return (f"<button type=\"button\" class=\"{classes}\" "
                f"data-severity-link=\"{esc(link)}\">{body}"
                f"<div class=\"go\">Показать эти находки →</div></button>")
    return f"<div class=\"{classes}\">{body}</div>"


# ---------- карточки разделов и боковая панель ----------
def _nav_cards(panels: Sequence[Tuple[str, str, Optional[int], str, str]]) -> str:
    cards: List[str] = []
    for key, title, count, note, _content in panels:
        number = f"<span class=\"nav-n\">{count}</span> " if count is not None else ""
        cards.append(
            f"<button type=\"button\" class=\"nav-card\" data-open=\"{esc(key)}\">"
            f"{number}<span class=\"nav-t\">{esc(title)}</span>"
            f"<span class=\"nav-s\">{esc(note)}</span>"
            f"<span class=\"nav-go\">Открыть раздел →</span></button>"
        )
    cards.append(
        "<button type=\"button\" class=\"nav-card pdf\" data-print>"
        "<span class=\"nav-t\">Скачать PDF</span>"
        "<span class=\"nav-s\">только находки высокого уровня: подтверждённые угрозы "
        "и подозрения</span>"
        "<span class=\"nav-go\">Откроется окно печати — выберите «Сохранить в PDF» →</span>"
        "</button>"
    )
    return f"<div class=\"nav-cards\">{''.join(cards)}</div>"


def _drawer(panels: Sequence[Tuple[str, str, Optional[int], str, str]]) -> str:
    tabs: List[str] = []
    sections: List[str] = []
    for index, (key, title, count, _note, content) in enumerate(panels):
        active = " active" if index == 0 else ""
        number = f" <span class=\"n\">{count}</span>" if count is not None else ""
        tabs.append(f"<button type=\"button\" class=\"tab{active}\" "
                    f"data-open=\"{esc(key)}\">{esc(title)}{number}</button>")
        hidden = "" if index == 0 else " hidden"
        sections.append(f"<section class=\"panel\" data-panel=\"{esc(key)}\"{hidden}>"
                        f"{content}</section>")
    return (
        "<div class=\"backdrop\" id=\"backdrop\" data-close></div>"
        "<aside class=\"drawer\" id=\"drawer\" role=\"dialog\" aria-label=\"Разделы отчёта\" "
        "aria-hidden=\"true\">"
        f"<div class=\"drawer-top\">{''.join(tabs)}"
        "<button type=\"button\" class=\"drawer-close\" data-close "
        "title=\"Закрыть панель (Esc)\" aria-label=\"Закрыть панель\">×</button></div>"
        f"<div class=\"drawer-body\" id=\"drawer-body\">{''.join(sections)}</div>"
        "</aside>"
    )


# ---------- содержимое разделов ----------
def _help_panel(by_severity: Dict[str, int]) -> str:
    parts = [f"<h2>{SPIDER_ICON}Как читать отчёт</h2>",
             "<p class=\"section-note\">Нажмите на уровень опасности — здесь, в диаграмме на "
             "главном экране или в фильтрах — и в таблице «Найденные проблемы» останутся "
             "только записи этого уровня. Строка таблицы раскрывается щелчком по ней.</p>",
             "<div class=\"legend-help\">"]
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
        "<div class=\"help-item high\"><b>Красная строка в таблице</b><span>подтверждённая "
        "находка высокого уровня: угроза реальна и видна в ответе сервера — это первая "
        "очередь работ.</span></div>"
        "<div class=\"help-item\"><b>Что внутри каждой записи</b><span>тип угрозы, чем она "
        "опасна, по какой логике сканер сделал вывод, отправленный запрос, фрагмент ответа "
        "и рекомендация.</span></div>"
        "<div class=\"help-item info\"><b>PDF-версия</b><span>кнопка «Скачать PDF» на главном "
        "экране открывает печать краткой сводки только с находками высокого уровня "
        "(подтверждённые — первыми). Средние и низкие остаются в HTML-отчёте.</span></div>"
    )
    parts.append("</div>")
    return "".join(parts)


def _findings_panel(items: Sequence[Finding], by_severity: Dict[str, int],
                    by_category: Dict[str, int], total: int) -> str:
    parts = [f"<h2 id=\"findings\">{SPIDER_ICON}Найденные проблемы</h2>",
             _filters(by_severity, by_category, total)]
    if not items:
        parts.append("<div class=\"empty\">Проблем не обнаружено. Это не гарантирует "
                     "отсутствие уязвимостей: сканер выполняет ограниченный набор "
                     "безопасных проверок.</div>")
        return "".join(parts)

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
    return "".join(parts)


def _pages_panel(pages: Sequence[Dict[str, object]]) -> str:
    parts = [f"<h2>{SPIDER_ICON}Просканированные страницы</h2>"]
    if not pages:
        parts.append("<div class=\"empty\">Ни одна страница не была загружена.</div>")
        return "".join(parts)
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
    return "".join(parts)


def _checks_panel(performed: Sequence[Tuple[str, str]]) -> str:
    parts = [f"<h2>{SPIDER_ICON}Какие проверки выполнялись</h2>"]
    if not performed:
        parts.append("<div class=\"empty\">Проверки не выполнялись.</div>")
        return "".join(parts)
    parts.append("<table><thead><tr><th>Проверка</th><th>Где выполнялась</th>"
                 "</tr></thead><tbody>")
    for name, scope in performed:
        parts.append(f"<tr><td>{_lines(name)}</td><td class=\"cat\">{esc(scope)}</td></tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


def _errors_panel(errors: Sequence[Tuple[str, str]]) -> str:
    parts = [f"<h2>{SPIDER_ICON}Запросы, оставшиеся без ответа</h2>",
             "<p class=\"section-note\">Эти адреса не удалось загрузить: часть проверок для "
             "них не выполнялась.</p>",
             "<table><thead><tr><th>Адрес</th><th>Что произошло</th></tr></thead><tbody>"]
    for url, message in list(errors)[:40]:
        parts.append(f"<tr><td>{_link(str(url))}</td>"
                     f"<td class=\"cat\">{esc(message)}</td></tr>")
    parts.append("</tbody></table>")
    return "".join(parts)


# ---------- фильтры и строки таблицы ----------
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
        "как сканер её нашёл, какой запрос отправлял и что нужно исправить. "
        "<b>Красным</b> выделены подтверждённые находки высокого уровня.</p>"
    )


def _row(index: int, finding: Finding) -> str:
    severity_class = SEVERITY_CLASS.get(finding.severity, "sev-info")
    severity_label = SEVERITY_LABEL.get(finding.severity, finding.severity)
    critical = finding.severity == HIGH and finding.confidence == CONFIRMED
    confidence_class = "conf sus" if finding.confidence == SUSPECTED else "conf"
    if critical:
        confidence_class = "conf yes"
    row_class = "f-row critical" if critical else "f-row"
    search_blob = " ".join([finding.url, finding.title, finding.category, finding.severity,
                            severity_label, finding.threat_type, finding.impact,
                            finding.detection, finding.evidence, finding.request,
                            finding.confidence]).lower()
    row = (
        f"<tr class=\"{row_class}\" id=\"r{index}\" data-id=\"{index}\" "
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


# ---------- печатная версия (сохранение в PDF) ----------
def _pdf_report(stats: Dict[str, object], _by_severity: Dict[str, int],
                _by_confidence: Dict[str, int], critical: Sequence[Finding],
                items: Sequence[Finding], total: int, generated: str) -> str:
    # В PDF только самые опасные: уровень High (подтверждённые — первыми).
    high = [item for item in items if item.severity == HIGH]
    critical_ids = {id(item) for item in critical}
    suspected_high = [item for item in high if id(item) not in critical_ids]
    requests_made = _int(stats.get("requests_made"))
    max_requests = _int(stats.get("max_requests"))

    parts = ["<div id=\"pdf-report\">",
             "<h1>Краткий отчёт: самые опасные находки</h1>",
             f"<p class=\"pdf-sub\">Цель: {esc(str(stats.get('target', '')))} · "
             f"сформирован {esc(generated)} · только уровень «Высокая»</p>"]

    cells = [
        ("Страниц проверено", _int(stats.get("pages")), False),
        ("Запросов к сайту", f"{requests_made} / {max_requests}", False),
        ("Всего записей в полном отчёте", total, False),
        ("Высокий уровень", len(high), True),
        ("из них подтверждено", len(critical), True),
        ("Длительность, с", stats.get("duration", 0), False),
    ]
    parts.append("<div class=\"kv\">")
    for label, value, alarm in cells:
        css = " class=\"alarm\"" if alarm and _int(value, 1) else ""
        parts.append(f"<div{css}><b>{esc(value)}</b>{esc(label)}</div>")
    parts.append("</div>")

    if critical:
        parts.append(f"<h2>Подтверждённые угрозы высокого уровня ({len(critical)})</h2>"
                     "<p class=\"pdf-sub\">Факт виден в ответе сервера — исправлять первыми.</p>")
        parts.append(_pdf_table(critical, mark=True))
    if suspected_high:
        parts.append(f"<h2>Подозрения высокого уровня ({len(suspected_high)})</h2>"
                     "<p class=\"pdf-sub\">Признак есть, нужна ручная проверка.</p>")
        parts.append(_pdf_table(suspected_high, mark=False))
    if not high:
        parts.append("<h2>Находок высокого уровня нет</h2>"
                     "<p>Сканер не нашёл проблем наивысшей опасности. Средние и низкие "
                     "находки — только в HTML-версии отчёта.</p>")

    parts.append(
        "<p class=\"pdf-foot\">В PDF попали только находки уровня «Высокая». Средние, низкие "
        "и справочные записи, доказательства и логика проверок — в HTML-версии отчёта. "
        "Отсутствие находок не гарантирует отсутствие уязвимостей: сканер выполняет "
        "ограниченный набор безопасных проверок и не изменяет данные.</p>"
    )
    parts.append("</div>")
    return "".join(parts)


def _pdf_table(findings: Sequence[Finding], mark: bool) -> str:
    rows: List[str] = []
    for finding in findings:
        css = " class=\"crit\"" if mark else ""
        rows.append(
            f"<tr{css}><td>{esc(SEVERITY_LABEL.get(finding.severity, finding.severity))}</td>"
            f"<td>{esc(finding.title)}</td>"
            f"<td>{esc(finding.url)}</td>"
            f"<td>{esc(finding.confidence)}</td>"
            f"<td>{esc(finding.recommendation or '—')}</td></tr>"
        )
    return ("<table><thead><tr><th>Уровень</th><th>Что нашли</th><th>Где нашли</th>"
            "<th>Точность</th><th>Как исправить</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


# ---------- вспомогательное ----------
def _lines(text: object) -> str:
    """Длинное перечисление через «;» — по одному пункту на строку."""
    pieces = [piece.strip() for piece in str(text).split(";") if piece.strip()]
    if len(pieces) < 2:
        return esc(text)
    return "<ul class=\"lines\">" + "".join(f"<li>{esc(piece)}</li>" for piece in pieces) + "</ul>"


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
