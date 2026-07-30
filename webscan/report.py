"""Формирование HTML-отчёта (раздел 6 требований).

Оформление: тёмный HUD-стиль под фон (navy/cyan), стеклянные панели, объёмные кнопки.
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
import os
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .models import (CONFIG, CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, VULN, Finding,
                     FindingList)

REPORT_BG_NAME = "bg.jfif"


def report_bg_source() -> Optional[Path]:
    """Путь к фону отчёта: рядом с модулем или в каталоге PyInstaller."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bundled = Path(sys._MEIPASS) / "webscan" / REPORT_BG_NAME
        if bundled.is_file():
            return bundled
    local = Path(__file__).with_name(REPORT_BG_NAME)
    return local if local.is_file() else None


def ensure_report_bg(directory: str) -> Optional[str]:
    """Копирует фон отчёта в ``directory`` (рядом с report.html). Возвращает путь или None."""
    source = report_bg_source()
    if source is None:
        return None
    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, REPORT_BG_NAME)
    try:
        if not os.path.isfile(target) or os.path.getsize(target) != source.stat().st_size:
            shutil.copy2(source, target)
    except OSError:
        return None
    return target


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
  --bg: #07111f;
  --panel: rgba(8, 18, 40, .48);
  --panel-2: rgba(12, 28, 55, .58);
  --mint: rgba(0, 180, 230, .14);
  --mint-deep: rgba(0, 200, 255, .28);
  --green: #00C8F0;
  --green-dark: #7DE8FF;
  --iron: #8AA6BF;
  --iron-light: #A8C2D8;
  --border: rgba(0, 212, 255, .28);
  --text: #E6F6FF;
  --muted: #8FB0C8;
  --high: #FF6B6B;
  --medium: #FFB347;
  --low: #8AA6BF;
  --safe: #3DDCB8;
  --cyan: #00D4FF;
  --navy: #0A1631;
  --glass-blur: blur(16px) saturate(1.45);
  --glass-shadow:
    0 12px 36px rgba(0, 8, 24, .45),
    0 4px 0 rgba(0, 40, 70, .35),
    inset 0 1px 0 rgba(180, 230, 255, .22),
    inset 0 0 0 1px rgba(0, 212, 255, .08);
  --glass-shadow-sm:
    0 8px 22px rgba(0, 8, 24, .35),
    0 3px 0 rgba(0, 40, 70, .28),
    inset 0 1px 0 rgba(180, 230, 255, .18);
  --btn-depth:
    0 4px 0 rgba(0, 70, 100, .85),
    0 12px 28px rgba(0, 180, 255, .28),
    inset 0 1px 0 rgba(200, 245, 255, .35);
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 0 28px; color: var(--text); min-height: 100vh;
  background:
    linear-gradient(160deg, rgba(5,10,27,.22) 0%, rgba(8,18,40,.12) 50%, rgba(5,10,27,.28) 100%),
    url("bg.jfif") center/cover fixed no-repeat;
  font: 15px/1.6 "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
body.locked { overflow: hidden; }
.wrap { max-width: 1280px; margin: 0 auto; padding: 0 22px; }
a { color: var(--cyan); }

.home-btn {
  position: fixed; top: 14px; left: 14px; z-index: 40;
  display: inline-flex; align-items: center; gap: 7px;
  padding: 10px 15px; border-radius: 12px;
  background: rgba(8, 18, 40, .5);
  border: 1px solid rgba(0, 212, 255, .35); color: var(--iron-light);
  font: 600 12.5px/1.2 "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  letter-spacing: .4px; text-decoration: none;
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  box-shadow: var(--glass-shadow);
  transition: background .15s, border-color .15s, color .15s, transform .12s, box-shadow .15s;
}
.home-btn:hover {
  background: rgba(12, 28, 55, .65); border-color: rgba(0, 212, 255, .65); color: var(--green-dark);
  transform: translateY(-2px);
  box-shadow:
    0 14px 40px rgba(0, 8, 24, .5),
    0 5px 0 rgba(0, 50, 80, .4),
    0 0 18px rgba(0, 212, 255, .2),
    inset 0 1px 0 rgba(180, 230, 255, .3);
}
.home-btn:active {
  transform: translateY(1px);
  box-shadow: 0 4px 14px rgba(0,8,24,.4), 0 2px 0 rgba(0,40,70,.3), inset 0 1px 0 rgba(180,230,255,.15);
}
.home-btn:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
.home-btn svg { flex: none; opacity: .9; }
@media print { .home-btn { display: none !important; } }

.ask-actions {
  display: flex; flex-wrap: wrap; align-items: center; gap: 10px;
  margin: 0 0 14px; padding: 12px 14px;
  background: rgba(0, 40, 70, .28);
  border: 1px solid rgba(0, 212, 255, .28);
  border-radius: 14px;
  box-shadow: var(--glass-shadow-sm);
}
.ask-actions .ask-hint {
  flex: 1; min-width: 180px; margin: 0;
  font-size: 13px; color: var(--muted); line-height: 1.4;
}
.ask-btn {
  display: inline-flex; align-items: center; gap: 7px;
  padding: 10px 17px; border-radius: 12px;
  background: rgba(0, 40, 70, .45);
  border: 1.5px solid rgba(0, 212, 255, .55); color: var(--green-dark);
  font: 600 12.5px/1.2 "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  letter-spacing: .4px; cursor: pointer;
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  box-shadow: var(--btn-depth);
  transition: background .15s, border-color .15s, color .15s, transform .12s, box-shadow .15s;
}
.ask-btn:hover {
  background: rgba(0, 60, 100, .55); border-color: var(--cyan);
  transform: translateY(-2px);
  box-shadow:
    0 5px 0 rgba(0, 70, 100, .9),
    0 14px 32px rgba(0, 180, 255, .35),
    0 0 22px rgba(0, 212, 255, .25),
    inset 0 1px 0 rgba(200, 245, 255, .4);
}
.ask-btn:active {
  transform: translateY(1px);
  box-shadow: 0 2px 0 rgba(0,70,100,.8), 0 4px 12px rgba(0,180,255,.22), inset 0 1px 0 rgba(200,245,255,.2);
}
.ask-btn:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
.det .ask-btn { margin: 0; }
@media print { .ask-btn, .ask-actions { display: none !important; } }

.ask-backdrop {
  position: fixed; inset: 0; z-index: 50; background: rgba(2, 8, 20, .62);
  backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
  display: none; align-items: center; justify-content: center; padding: 18px;
}
.ask-backdrop.open { display: flex; }
.ask-dialog {
  width: min(560px, 100%); max-height: min(78vh, 640px);
  background: rgba(8, 18, 40, .62); border: 1px solid rgba(0, 212, 255, .35); border-radius: 18px;
  box-shadow: var(--glass-shadow), 0 0 40px rgba(0, 180, 255, .12);
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  display: flex; flex-direction: column; overflow: hidden;
}
.ask-head {
  display: flex; align-items: center; gap: 10px; padding: 12px 14px;
  border-bottom: 1px solid rgba(0, 212, 255, .2); background: rgba(12, 28, 55, .5);
}
.ask-head h3 { margin: 0; font-size: 15px; color: var(--green-dark); flex: 1; letter-spacing: .3px; }
.ask-close {
  border: 1px solid rgba(0, 212, 255, .3); background: rgba(8, 18, 40, .55); color: var(--muted);
  width: 34px; height: 34px; border-radius: 10px; cursor: pointer; font-size: 18px; line-height: 1;
  box-shadow: var(--glass-shadow-sm);
}
.ask-close:hover { color: var(--high); border-color: rgba(255,107,107,.5); }
.ask-log {
  flex: 1; overflow: auto; padding: 14px; display: flex; flex-direction: column; gap: 10px;
  background: rgba(4, 12, 28, .35); min-height: 220px;
}
.ask-msg {
  max-width: 92%; padding: 9px 12px; border-radius: 12px; font-size: 13.5px; line-height: 1.45;
  white-space: pre-wrap; word-break: break-word;
  backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
  box-shadow: 0 4px 14px rgba(0,8,24,.25), inset 0 1px 0 rgba(180,230,255,.12);
}
.ask-msg.user {
  align-self: flex-end; background: rgba(0, 120, 180, .28); color: var(--text);
  border: 1px solid rgba(0, 212, 255, .35);
}
.ask-msg.bot {
  align-self: flex-start; background: rgba(12, 28, 55, .55); color: var(--text);
  border: 1px solid rgba(0, 212, 255, .25);
}
.ask-msg.sys { align-self: center; color: var(--muted); font-size: 12.5px; background: transparent; border: none; box-shadow: none; }
.ask-form {
  display: flex; gap: 8px; padding: 12px; border-top: 1px solid rgba(0, 212, 255, .2);
  background: rgba(12, 28, 55, .45);
}
.ask-form textarea {
  flex: 1; min-height: 44px; max-height: 110px; resize: vertical;
  border: 1px solid rgba(0, 212, 255, .3); border-radius: 12px; padding: 9px 11px;
  font: inherit; font-size: 13.5px; color: var(--text);
  background: rgba(8, 18, 40, .55);
  box-shadow: inset 0 1px 0 rgba(180,230,255,.1), 0 3px 10px rgba(0,8,24,.2);
}
.ask-form textarea:focus { outline: 2px solid rgba(0, 212, 255, .45); outline-offset: 1px; }
.ask-form textarea::placeholder { color: rgba(143,176,200,.65); }
.ask-send {
  align-self: flex-end; padding: 12px 18px; border-radius: 12px;
  border: 1px solid rgba(0, 212, 255, .55);
  background: linear-gradient(180deg, rgba(0, 200, 255, .85) 0%, rgba(0, 140, 200, .92) 45%, rgba(0, 90, 150, .98) 100%);
  color: #041018; font: 700 13px/1 "Segoe UI", sans-serif; cursor: pointer;
  box-shadow: var(--btn-depth);
  transition: background .15s, transform .12s, box-shadow .15s;
}
.ask-send:disabled { opacity: .55; cursor: default; transform: none; }
.ask-send:hover:not(:disabled) {
  background: linear-gradient(180deg, rgba(80, 220, 255, .92) 0%, rgba(0, 170, 230, .95) 45%, rgba(0, 110, 170, 1) 100%);
  transform: translateY(-2px);
  box-shadow: 0 5px 0 rgba(0,70,100,.9), 0 14px 30px rgba(0,180,255,.4), 0 0 20px rgba(0,212,255,.25), inset 0 1px 0 rgba(255,255,255,.4);
}
.ask-send:active:not(:disabled) {
  transform: translateY(1px);
  box-shadow: 0 2px 0 rgba(0,70,100,.85), 0 4px 12px rgba(0,180,255,.25), inset 0 1px 0 rgba(255,255,255,.2);
}

header { position: relative; overflow: hidden; padding: 22px 0 6px; }
header .web { position: absolute; top: 0; right: 0; opacity: .4; pointer-events: none; filter: brightness(1.4) hue-rotate(160deg); }
.hero { display: grid; grid-template-columns: minmax(320px, 378px) 1fr; gap: 28px;
  align-items: start; position: relative; z-index: 1; }
.hero-main { min-width: 0; }
.chart-with-menu { position: relative; display: block; }
.chart-col { display: flex; flex-direction: column; gap: 12px; align-items: stretch;
  width: 100%; max-width: 378px; padding-left: 58px; box-sizing: border-box; }
.chart-hang {
  position: fixed; top: 58px; left: 22px; z-index: 30;
  width: 86px; pointer-events: none;
  filter: drop-shadow(0 8px 18px rgba(0,180,255,.25)) brightness(1.15) hue-rotate(150deg);
}
.chart-hang svg { display: block; width: 100%; height: auto; overflow: visible; }
.chart-hang-spider {
  transform-box: view-box; transform-origin: 50px 170px;
  animation: chartSpiderSway 3.6s ease-in-out infinite;
}
@keyframes chartSpiderSway {
  0%, 100% { transform: rotate(-2.4deg); }
  50% { transform: rotate(2.4deg); }
}
@media (max-width: 980px) {
  .hero { grid-template-columns: 1fr; }
  .chart-col { max-width: none; }
}
@media print { .chart-hang { display: none !important; } }

.help-menu {
  position: absolute; top: 62px; left: -58px; z-index: 2;
  display: flex; flex-direction: column; justify-content: center; gap: 7px;
  width: 50px; height: 50px; margin: 0; padding: 12px 11px;
  background: rgba(8, 18, 40, .52);
  border: 1px solid rgba(0, 212, 255, .35); border-radius: 14px;
  cursor: pointer;
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  box-shadow: var(--glass-shadow);
  transition: border-color .15s, background .15s, transform .12s, box-shadow .15s;
}
.help-menu:hover {
  border-color: rgba(0, 212, 255, .7); background: rgba(12, 28, 55, .65);
  transform: translateY(-2px);
  box-shadow: 0 14px 36px rgba(0,8,24,.45), 0 5px 0 rgba(0,40,70,.35), 0 0 16px rgba(0,212,255,.2), inset 0 1px 0 rgba(180,230,255,.25);
}
.help-menu:focus-visible { outline: 2px solid var(--cyan); }
.help-menu span { display: block; height: 3px; border-radius: 2px; }
.help-menu span:nth-child(1) { background: rgba(0, 180, 230, .45); }
.help-menu span:nth-child(2) { background: rgba(0, 200, 255, .65); }
.help-menu span:nth-child(3) { background: var(--cyan); }

.chart-card {
  background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .3); border-radius: 18px;
  padding: 18px 18px 14px;
  box-shadow: var(--glass-shadow), 0 0 28px rgba(0, 160, 255, .08);
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  width: 100%; min-width: 0; box-sizing: border-box;
}
.chart-card h3 { margin: 0 0 4px; font-size: 13px; color: var(--muted); font-weight: 700;
  text-transform: uppercase; letter-spacing: 1.2px; text-align: center; }
.chart-card .tip { margin: 0 0 8px; font-size: 12px; color: var(--muted); text-align: center; }
.donut { display: block; margin: 0 auto; filter: drop-shadow(0 6px 16px rgba(0,180,255,.2)); }
.donut circle.seg { cursor: pointer; transition: opacity .15s; }
.donut circle.seg:hover { opacity: .75; }
.donut-total { font: 700 42px "Segoe UI", Arial, sans-serif; fill: var(--text); }
.donut-caption { font: 500 12px "Segoe UI", Arial, sans-serif; fill: var(--muted); letter-spacing: .6px; }
.legend { margin: 12px 0 0; padding: 0; list-style: none; }
.legend li { border-top: 1px dashed rgba(0, 212, 255, .2); }
.legend li:first-child { border-top: none; }
.legend button {
  display: flex; align-items: center; gap: 9px; width: 100%; padding: 8px 8px;
  background: transparent; border: none; border-radius: 10px; cursor: pointer; text-align: left;
  font: inherit; font-size: 13.5px; color: var(--text); transition: background .15s, box-shadow .15s;
}
.legend button:hover { background: rgba(0, 160, 230, .12); box-shadow: inset 0 0 0 1px rgba(0,212,255,.2); }
.legend button:focus-visible { outline: 2px solid var(--cyan); }
.legend button[disabled] { cursor: default; opacity: .5; }
.legend button[disabled]:hover { background: none; box-shadow: none; }
.legend .dot { width: 11px; height: 11px; border-radius: 3px; flex: none;
  box-shadow: 0 0 8px currentColor; }
.legend .name { flex: 1; }
.legend .val { font-weight: 700; color: var(--green-dark); }
.legend .pct { color: var(--muted); font-size: 12.5px; min-width: 42px; text-align: right; }

.brand { display: flex; align-items: center; gap: 10px; color: var(--iron);
  font-size: 12px; letter-spacing: 1.4px; text-transform: uppercase; font-weight: 700; }
h1 { margin: 6px 0 5px; font-size: 26px; line-height: 1.25; letter-spacing: .35px;
  color: var(--green-dark); text-shadow: 0 0 18px rgba(0,212,255,.28), 0 2px 10px rgba(0,8,24,.45); }
.target { font-size: 14.5px; color: var(--muted); margin-bottom: 4px; }
.target b { color: var(--text); }
h2 { font-size: 19px; margin: 18px 0 10px; color: var(--green-dark);
  display: flex; align-items: center; gap: 9px;
  text-shadow: 0 0 14px rgba(0,212,255,.22); }
h2 .ico { flex: none; opacity: .85; filter: brightness(1.3) hue-rotate(150deg); }
.section-note { margin: -4px 0 12px; color: var(--muted); font-size: 13.5px; }

.stat-group { margin-bottom: 10px; }
.stat-group > h3 {
  margin: 0 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 1.1px;
  color: var(--muted); font-weight: 700;
}
.cards { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); }
@media (max-width: 1100px) { .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
@media (max-width: 560px) { .cards { grid-template-columns: 1fr; } }
.card {
  background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .3); border-radius: 14px;
  padding: 12px 14px 13px; text-align: left; font-family: inherit; color: var(--text);
  box-shadow: var(--glass-shadow);
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
}
.card .num { font-size: 22px; font-weight: 700; color: var(--green-dark); line-height: 1.25;
  text-shadow: none; }
.card .num small { font-size: 14px; font-weight: 600; color: var(--muted); }
.card .lbl { color: var(--text); font-size: 13px; margin-top: 1px; }
.card .sub { color: var(--muted); font-size: 11.5px; margin-top: 3px; line-height: 1.35; }
.card .go { color: var(--high); font-size: 12px; margin-top: 4px; font-weight: 600; }
.card.accent { background: rgba(0, 140, 200, .22); border-color: rgba(0, 212, 255, .4); }
.card.alarm { border-color: rgba(255,107,107,.45); background: rgba(80, 20, 30, .35); }
.card.alarm .num { color: var(--high); text-shadow: 0 0 12px rgba(255,107,107,.3); }
.card.alarm.strong { border-width: 1.5px; border-color: var(--high); background: rgba(90, 24, 34, .42);
  box-shadow: 0 10px 28px rgba(255,80,80,.18), 0 4px 0 rgba(80,20,30,.35), inset 0 1px 0 rgba(255,180,180,.15); }
button.card { cursor: pointer; width: 100%; transition: transform .15s, box-shadow .15s, border-color .15s; }
button.card:hover {
  transform: translateY(-3px);
  border-color: rgba(255,107,107,.65);
  box-shadow: 0 14px 34px rgba(255,80,80,.22), 0 5px 0 rgba(80,20,30,.3), 0 0 18px rgba(255,107,107,.15), inset 0 1px 0 rgba(255,200,200,.18);
}
.bar { height: 6px; border-radius: 99px; background: rgba(0, 40, 70, .45); margin-top: 7px;
  overflow: hidden; border: 1px solid rgba(0, 212, 255, .2);
  box-shadow: inset 0 1px 3px rgba(0,0,0,.35); }
.bar span { display: block; height: 100%;
  background: linear-gradient(90deg, #00A0D0, var(--cyan));
  box-shadow: 0 0 10px rgba(0,212,255,.45); }

.nav-cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
.nav-card { display: block; text-align: left; font-family: inherit; cursor: pointer;
  background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .3); border-radius: 16px;
  padding: 14px 16px 13px; color: var(--text);
  box-shadow: var(--glass-shadow);
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  transition: transform .15s, box-shadow .15s, border-color .15s, background .15s; }
.nav-card:hover {
  transform: translateY(-3px);
  background: rgba(12, 28, 55, .62);
  border-color: rgba(0, 212, 255, .6);
  box-shadow: 0 16px 40px rgba(0,8,24,.45), 0 5px 0 rgba(0,40,70,.35), 0 0 22px rgba(0,212,255,.18), inset 0 1px 0 rgba(180,230,255,.22);
}
.nav-card .nav-n { font-size: 21px; font-weight: 700; color: var(--green-dark); text-shadow: none; }
.nav-card .nav-t { display: block; font-weight: 600; font-size: 14.5px; margin-top: 1px; }
.nav-card .nav-s { display: block; color: var(--muted); font-size: 12px; margin-top: 3px; line-height: 1.35; }
.nav-card .nav-go { display: block; color: var(--cyan); font-size: 12.5px; margin-top: 6px; }
.nav-card.pdf {
  background: linear-gradient(180deg, rgba(0, 140, 200, .35) 0%, rgba(0, 80, 140, .4) 55%, rgba(0, 50, 100, .48) 100%);
  border: 1.5px solid rgba(0, 212, 255, .55);
  box-shadow: var(--btn-depth);
}
.nav-card.pdf:hover {
  border-color: var(--cyan);
  transform: translateY(-3px);
  box-shadow: 0 5px 0 rgba(0,70,100,.9), 0 16px 36px rgba(0,180,255,.35), 0 0 24px rgba(0,212,255,.22), inset 0 1px 0 rgba(200,245,255,.4);
}
.nav-card.pdf:active {
  transform: translateY(1px);
  box-shadow: 0 2px 0 rgba(0,70,100,.8), 0 4px 12px rgba(0,180,255,.22), inset 0 1px 0 rgba(200,245,255,.2);
}
.nav-card.pdf .nav-t { color: var(--green-dark); }
.chart-pdf { width: 100%; box-sizing: border-box; }
.under-pdf { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; width: 100%; }
.under-pdf .nav-card { margin: 0; }
.under-pdf .card { margin: 0; }
@media (max-width: 520px) { .under-pdf { grid-template-columns: 1fr; } }

.backdrop { position: fixed; inset: 0; background: rgba(2, 8, 20, .58); z-index: 30;
  backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
  opacity: 0; visibility: hidden; transition: opacity .22s, visibility .22s; }
.backdrop.open { opacity: 1; visibility: visible; }
.drawer { position: fixed; top: 0; right: 0; height: 100vh; width: min(1180px, 95vw);
  background: rgba(6, 14, 30, .72); border-left: 1px solid rgba(0, 212, 255, .3); z-index: 31;
  box-shadow: -24px 0 50px rgba(0, 8, 24, .55), 0 0 40px rgba(0, 160, 255, .08);
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur);
  display: flex; flex-direction: column;
  transform: translateX(101%); transition: transform .26s ease; }
.drawer.open { transform: none; }
.drawer-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 12px 16px; background: rgba(12, 28, 55, .55);
  border-bottom: 1px solid rgba(0, 212, 255, .25);
  box-shadow: 0 4px 18px rgba(0,8,24,.25), inset 0 1px 0 rgba(180,230,255,.12); }
.tab {
  background: rgba(8, 18, 40, .5); border: 1px solid rgba(0, 212, 255, .3); border-radius: 999px;
  padding: 8px 16px; font: inherit; font-size: 13px; color: var(--text); cursor: pointer;
  backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
  box-shadow: var(--glass-shadow-sm); transition: .15s; }
.tab:hover { border-color: rgba(0, 212, 255, .6); color: var(--green-dark);
  background: rgba(12, 28, 55, .65); transform: translateY(-1px);
  box-shadow: 0 8px 20px rgba(0,180,255,.16), 0 3px 0 rgba(0,40,70,.3), inset 0 1px 0 rgba(180,230,255,.2); }
.tab.active {
  background: linear-gradient(180deg, rgba(0, 200, 255, .85) 0%, rgba(0, 140, 200, .92) 45%, rgba(0, 90, 150, .98) 100%);
  border-color: rgba(0, 212, 255, .7); color: #041018; font-weight: 700;
  box-shadow: var(--btn-depth);
}
.tab .n { opacity: .7; font-size: 12px; }
.tab.active .n { opacity: .9; }
.drawer-close { margin-left: auto; background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .3);
  border-radius: 10px; width: 36px; height: 36px; font-size: 17px; line-height: 1; cursor: pointer;
  color: var(--muted); font-family: inherit; box-shadow: var(--glass-shadow-sm); }
.drawer-close:hover { border-color: rgba(255,107,107,.5); color: var(--high); transform: translateY(-1px); }
.drawer-body { flex: 1; overflow: auto; padding: 4px 22px 40px; }
.drawer-body h2:first-child { margin-top: 14px; }
.panel[hidden] { display: none; }

.legend-help { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.help-item { background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .25);
  border-left: 3px solid var(--iron-light); border-radius: 12px; padding: 10px 14px;
  font-size: 13.5px; text-align: left; font-family: inherit; color: var(--text);
  box-shadow: var(--glass-shadow-sm);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
button.help-item { cursor: pointer; transition: box-shadow .15s, transform .15s, background .15s, border-color .15s; }
button.help-item:hover {
  background: rgba(12, 28, 55, .62); border-color: rgba(0, 212, 255, .45);
  box-shadow: 0 10px 26px rgba(0,8,24,.35), 0 3px 0 rgba(0,40,70,.28), inset 0 1px 0 rgba(180,230,255,.18);
  transform: translateY(-2px);
}
.help-item.high { border-left-color: var(--high); }
.help-item.medium { border-left-color: var(--medium); }
.help-item.low { border-left-color: var(--low); }
.help-item.info { border-left-color: var(--safe); }
.help-item b { display: block; margin-bottom: 2px; }
.help-item span { color: var(--muted); }
.help-item .go { display: block; margin-top: 4px; color: var(--cyan); font-size: 12.5px; }

.filters { background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .3); border-radius: 14px;
  padding: 13px 15px; margin-bottom: 12px;
  box-shadow: var(--glass-shadow);
  backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur); }
.filter-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.filter-row + .filter-row { margin-top: 9px; padding-top: 9px; border-top: 1px dashed rgba(0, 212, 255, .2); }
.filter-row .cap { font-size: 11px; text-transform: uppercase; letter-spacing: 1px;
  color: var(--muted); font-weight: 700; min-width: 92px; }
button.f {
  background: rgba(8, 18, 40, .5); color: var(--text); border: 1px solid rgba(0, 212, 255, .3);
  padding: 8px 15px; border-radius: 999px; cursor: pointer; font-size: 13px;
  backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
  box-shadow: var(--glass-shadow-sm); transition: .15s; font-family: inherit; }
button.f:hover { border-color: rgba(0, 212, 255, .6); color: var(--green-dark);
  background: rgba(12, 28, 55, .65); transform: translateY(-1px);
  box-shadow: 0 8px 20px rgba(0,180,255,.16), 0 3px 0 rgba(0,40,70,.3), inset 0 1px 0 rgba(180,230,255,.2); }
button.f.active {
  background: linear-gradient(180deg, rgba(0, 200, 255, .85) 0%, rgba(0, 140, 200, .92) 45%, rgba(0, 90, 150, .98) 100%);
  border-color: rgba(0, 212, 255, .7); color: #041018; font-weight: 700;
  box-shadow: var(--btn-depth);
}
button.f .n { opacity: .7; font-size: 12px; }
button.f.active .n { opacity: .9; }
button.f.wide { font-weight: 600; }
input[type=search] { flex: 1; min-width: 230px; background: rgba(8, 18, 40, .55); color: var(--text);
  border: 1px solid rgba(0, 212, 255, .3); border-radius: 11px; padding: 9px 13px; font-size: 14px;
  font-family: inherit;
  box-shadow: inset 0 1px 0 rgba(180,230,255,.1), 0 3px 10px rgba(0,8,24,.2); }
input[type=search]:focus { outline: 2px solid rgba(0, 212, 255, .4); border-color: rgba(0, 212, 255, .55); }
input[type=search]::placeholder { color: rgba(143,176,200,.6); }
.hint { color: var(--muted); font-size: 13px; margin: 0 0 10px; }
.hint b { color: var(--text); }

table { width: 100%; border-collapse: collapse; background: rgba(8, 18, 40, .55);
  border: 1px solid rgba(0, 212, 255, .3); border-radius: 14px; overflow: hidden; font-size: 14px;
  box-shadow: var(--glass-shadow);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
th { text-align: left; background: rgba(12, 28, 55, .55); padding: 11px 12px; font-size: 11px;
  text-transform: uppercase; letter-spacing: .8px; color: var(--muted);
  border-bottom: 1px solid rgba(0, 212, 255, .2); }
td { padding: 11px 12px; border-bottom: 1px solid rgba(0, 212, 255, .12); vertical-align: top; }
tr.f-row { cursor: pointer; }
tr.f-row:hover { background: rgba(0, 140, 200, .12); }
tr.f-row.open { background: rgba(0, 140, 200, .2); }
tr.f-row.critical { background: rgba(80, 20, 30, .35); }
tr.f-row.critical > td:first-child { box-shadow: inset 3px 0 0 var(--high); }
tr.f-row.critical:hover { background: rgba(100, 28, 38, .42); }
tr.f-row.critical .title { color: #FFB0B0; }
tr.g-row { cursor: pointer; }
tr.g-row:hover { background: rgba(0, 140, 200, .12); }
tr.g-row.open { background: rgba(0, 140, 200, .2); }
tr.g-row.critical { background: rgba(80, 20, 30, .35); }
tr.g-row.critical > td:first-child { box-shadow: inset 3px 0 0 var(--high); }
tr.g-row.critical:hover { background: rgba(100, 28, 38, .42); }
tr.g-row.critical .title { color: #FFB0B0; }
tr.g-details > td, tr.details > td { background: rgba(12, 28, 55, .4); }
tr.i-row { cursor: pointer; }
tr.i-row:hover { background: rgba(0, 140, 200, .1); }
tr.i-row.open { background: rgba(0, 140, 200, .18); }
.count-pill { display: inline-block; background: rgba(0, 140, 200, .25); border: 1px solid rgba(0, 212, 255, .35);
  color: var(--green-dark); border-radius: 999px; padding: 2px 10px; font-size: 12.5px;
  font-weight: 700; white-space: nowrap;
  box-shadow: 0 2px 8px rgba(0,180,255,.15), inset 0 1px 0 rgba(180,230,255,.15); }
.inner-table { width: 100%; border: 1px solid rgba(0, 212, 255, .25); border-radius: 12px;
  overflow: hidden; background: rgba(8, 18, 40, .52); margin: 4px 0 6px;
  box-shadow: var(--glass-shadow-sm); }
.inner-table th { font-size: 11px; padding: 8px 10px; }
.inner-table td { padding: 9px 10px; font-size: 13.5px; }
.inner-empty { padding: 12px; color: var(--muted); font-size: 13px; text-align: center; }
.badge { display: inline-block; padding: 3px 11px; border-radius: 999px; font-size: 11px;
  font-weight: 700; white-space: nowrap; color: #041018; letter-spacing: .3px;
  box-shadow: 0 3px 10px rgba(0,8,24,.3), inset 0 1px 0 rgba(255,255,255,.28); }
.sev-high { background: linear-gradient(180deg, #FF8585, var(--high)); color: #1a0808; }
.sev-medium { background: linear-gradient(180deg, #FFC56A, var(--medium)); color: #1a1000; }
.sev-low { background: linear-gradient(180deg, #A8C2D8, var(--low)); color: #0a1520; }
.sev-info { background: linear-gradient(180deg, #5EE8C8, var(--safe)); color: #041814; }
.owasp { display: inline-block; margin-left: 6px; padding: 2px 8px; border-radius: 999px;
  font-size: 11px; font-weight: 700; letter-spacing: .02em; color: #d8f1e6;
  background: rgba(63, 157, 117, .22); border: 1px solid rgba(63, 157, 117, .45); }
.threat { display: inline-block; background: rgba(0, 140, 200, .22); border: 1px solid rgba(0, 212, 255, .3);
  color: var(--green-dark); border-radius: 8px; padding: 2px 9px; font-size: 12.5px; }
.cat { color: var(--muted); font-size: 13px; }
.nowrap { white-space: nowrap; }
.url { word-break: break-all; color: var(--cyan); font-size: 13px; }
a.url { text-decoration: none; border-bottom: 1px dotted rgba(0, 212, 255, .4); }
a.url:hover { border-bottom-color: var(--cyan); background: rgba(0, 140, 200, .15); }
.title { font-weight: 600; }
.conf { font-size: 12.5px; color: var(--muted); white-space: nowrap; }
.conf.sus { color: var(--medium); }
.conf.yes { color: var(--high); font-weight: 600; }
.toggle { background: none; border: none; color: var(--cyan); cursor: pointer;
  font-size: 13px; padding: 0; text-decoration: underline dotted; white-space: nowrap;
  font-family: inherit; }
.lines { margin: 0; padding-left: 18px; }
.lines li { margin: 2px 0; }

.det { display: grid; gap: 12px; grid-template-columns: 1fr 1fr; padding: 4px 0 8px; }
@media (max-width: 860px) { .det { grid-template-columns: 1fr; } }
.det .full { grid-column: 1 / -1; }
.block { background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .25); border-radius: 12px;
  padding: 12px 14px; box-shadow: var(--glass-shadow-sm);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
.block.danger { border-left: 3px solid var(--high); }
.block.logic { border-left: 3px solid var(--iron); }
.block.fix { border-left: 3px solid var(--safe); background: rgba(61, 220, 184, .08); }
.block.fix p { margin: 0 0 10px; }
.block.fix p:last-child { margin-bottom: 0; }
.block.fix p.step { padding-left: 10px; border-left: 2px solid rgba(0, 212, 255, .35); }
.block.fix .fix-brief { margin: 0 0 8px; }
.block.fix .fix-more-btn {
  display: inline-block; margin: 0; padding: 4px 12px;
  border: 1px solid rgba(0, 212, 255, .35); border-radius: 999px;
  background: rgba(8, 18, 40, .5); color: var(--green-dark); font: 600 12px/1.3 inherit;
  cursor: pointer; box-shadow: var(--glass-shadow-sm);
  transition: background .15s, border-color .15s, transform .12s, box-shadow .15s;
}
.block.fix .fix-more-btn:hover {
  background: rgba(0, 140, 200, .25); border-color: var(--cyan);
  transform: translateY(-1px);
  box-shadow: 0 6px 16px rgba(0,180,255,.18), 0 2px 0 rgba(0,40,70,.25), inset 0 1px 0 rgba(180,230,255,.2);
}
.block.fix .fix-full { display: none; margin-top: 10px; }
.block.fix .fix-full.open { display: block; }
.filters #q { flex: 1; min-width: 140px; max-width: 100%; }
.filters .pdf-filtered {
  flex: none; white-space: nowrap;
  background: rgba(0, 140, 200, .28); border-color: rgba(0, 212, 255, .45); color: var(--green-dark);
  font-weight: 600;
}
.filters .pdf-filtered:hover { border-color: var(--cyan); background: rgba(0, 160, 220, .35); }
.block h4 { margin: 0 0 6px; font-size: 11px; text-transform: uppercase; letter-spacing: .8px;
  color: var(--muted); font-weight: 700; }
.block p { margin: 0; font-size: 14px; }
pre { margin: 0; padding: 10px 12px; background: rgba(4, 12, 28, .65); border: 1px solid rgba(0, 212, 255, .25);
  border-radius: 10px; white-space: pre-wrap; word-break: break-word; color: #A8D8F0;
  font: 12.5px/1.5 Consolas, "Courier New", monospace; max-height: 480px; overflow: auto;
  box-shadow: inset 0 1px 0 rgba(180,230,255,.08), 0 3px 12px rgba(0,8,24,.25); }
.block.code-block pre { max-height: 560px; min-height: 120px; }

.empty { padding: 24px; text-align: center; color: var(--muted); background: rgba(8, 18, 40, .55);
  border: 1px solid rgba(0, 212, 255, .3); border-radius: 14px;
  box-shadow: var(--glass-shadow); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
.note { background: rgba(8, 18, 40, .55); border: 1px solid rgba(0, 212, 255, .25);
  border-left: 3px solid var(--iron); border-radius: 12px; padding: 10px 15px;
  color: var(--muted); font-size: 13.5px; margin-bottom: 8px;
  box-shadow: var(--glass-shadow-sm); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); }
footer { margin-top: 20px; color: var(--muted); font-size: 12.5px; text-align: center;
  display: flex; align-items: center; justify-content: center; gap: 10px; flex-wrap: wrap;
  position: relative; z-index: 1; }

#pdf-report, #pdf-filtered { display: none; }
@media print {
  @page { size: A4; margin: 12mm; }
  :root {
    --text: #26302B; --muted: #64716A; --green: #2C7A5B; --green-dark: #1E5A42;
    --border: #D7E1DA; --high: #B4503C; --medium: #C98A2E; --safe: #3F9D75;
  }
  body { background: #FFFFFF !important; padding: 0; color: #26302B; }
  body > *:not(#pdf-report):not(#pdf-filtered) { display: none !important; }
  body.print-filtered #pdf-report { display: none !important; }
  body.print-filtered #pdf-filtered { display: block !important; }
  body:not(.print-filtered) #pdf-report { display: block !important; }
  body:not(.print-filtered) #pdf-filtered { display: none !important; }
}
#pdf-report h1, #pdf-filtered h1 { font-size: 20px; margin: 0 0 2px; color: #1E5A42; }
#pdf-report h2, #pdf-filtered h2 { font-size: 15px; margin: 16px 0 6px; display: block; color: #1E5A42; }
#pdf-report .pdf-sub, #pdf-filtered .pdf-sub { margin: 0 0 12px; color: #64716A; font-size: 12px; }
#pdf-report table, #pdf-filtered table { font-size: 11.5px; border-radius: 0; page-break-inside: auto; background: #fff; }
#pdf-report th, #pdf-report td, #pdf-filtered th, #pdf-filtered td { padding: 5px 7px; color: #26302B; }
#pdf-report thead, #pdf-filtered thead { display: table-header-group; }
#pdf-report tr, #pdf-filtered tr { page-break-inside: avoid; }
#pdf-report .kv, #pdf-filtered .kv { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }
#pdf-report .kv div, #pdf-filtered .kv div { border: 1px solid #D7E1DA; border-radius: 8px; padding: 5px 10px; font-size: 11.5px; }
#pdf-report .kv b, #pdf-filtered .kv b { font-size: 15px; display: block; color: #1E5A42; }
#pdf-report .kv.alarm b, #pdf-filtered .kv.alarm b { color: #B4503C; }
#pdf-report .pdf-foot, #pdf-filtered .pdf-foot { font-size: 10.5px; color: #64716A; margin-top: 14px; }
#pdf-report .crit td, #pdf-filtered .crit td { background: #FDF6F4; }
"""




JS = """
var severityFilter = 'all';
function currentFilters() {
  var sevBtn = document.querySelector('button.f.sev.active');
  var confBtn = document.querySelector('button.f.conf-f.active');
  return {
    sev: severityFilter || (sevBtn ? sevBtn.dataset.value : 'all'),
    cat: document.querySelector('button.f.cat-f.active').dataset.value,
    conf: confBtn ? confBtn.dataset.value : 'all',
    q: document.getElementById('q').value.trim().toLowerCase()
  };
}
function severityMatch(rowSev, filter) {
  if (filter === 'all') { return true; }
  if (filter === 'attention') { return rowSev === 'High' || rowSev === 'Medium'; }
  if (filter === 'critical') { return rowSev === 'High'; }
  return rowSev === filter;
}
function rowMatches(row, f) {
  return severityMatch(row.dataset.severity, f.sev)
    && (f.cat === 'all' || row.dataset.category === f.cat)
    && (f.conf === 'all' || row.dataset.confidence === f.conf)
    && (f.sev !== 'critical' || row.dataset.confidence === 'подтверждено')
    && (f.q === '' || (row.dataset.search || '').indexOf(f.q) !== -1);
}
function applyFilters() {
  var f = currentFilters();
  var shownGroups = 0;
  var shownItems = 0;
  document.querySelectorAll('tr.g-row').forEach(function (group) {
    var gid = group.dataset.id;
    var visibleInGroup = 0;
    document.querySelectorAll('tr.i-row[data-group=\"' + gid + '\"]').forEach(function (row) {
      var ok = rowMatches(row, f);
      row.style.display = ok ? '' : 'none';
      if (!ok) { closeInstance(row); }
      if (ok) { visibleInGroup++; }
    });
    var empty = document.getElementById('ge' + gid);
    if (empty) { empty.style.display = visibleInGroup ? 'none' : ''; }
    var countEl = group.querySelector('.count-pill');
    if (countEl) {
      countEl.textContent = visibleInGroup + ' шт.';
    }
    var visible = visibleInGroup > 0;
    group.style.display = visible ? '' : 'none';
    if (!visible) { closeGroup(group); }
    if (visible) {
      shownGroups++;
      shownItems += visibleInGroup;
    }
  });
  document.getElementById('shown').textContent = shownGroups;
  var shownItemsEl = document.getElementById('shown-items');
  if (shownItemsEl) { shownItemsEl.textContent = shownItems; }
  var empty = document.getElementById('nothing');
  if (empty) { empty.style.display = shownGroups ? 'none' : ''; }
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
  if (selector === 'button.f.sev') { severityFilter = value; }
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
  if (value === 'critical') {
    // High + подтверждено: кнопка уровня подсвечивается, фильтр держит critical
    document.querySelectorAll('button.f.sev').forEach(function (btn) {
      btn.classList.toggle('active', btn.dataset.value === 'High');
    });
    severityFilter = 'critical';
    selectButton('button.f.conf-f', 'подтверждено');
  } else if (value === 'attention') {
    severityFilter = 'attention';
    document.querySelectorAll('button.f.sev').forEach(function (btn) {
      btn.classList.toggle('active',
        btn.dataset.value === 'High' || btn.dataset.value === 'Medium');
    });
    selectButton('button.f.conf-f', 'all');
  } else {
    selectButton('button.f.sev', value);
    selectButton('button.f.conf-f', 'all');
  }
  selectButton('button.f.cat-f', 'all');
  document.getElementById('q').value = '';
  applyFilters();
  openPanel('findings');
}
function showCategory(value) {
  severityFilter = 'all';
  selectButton('button.f.sev', 'all');
  selectButton('button.f.conf-f', 'all');
  selectButton('button.f.cat-f', value);
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
function groupDetails(row) { return document.getElementById('g' + row.dataset.id); }
function instanceDetails(row) { return document.getElementById('i' + row.dataset.id); }
function isGroupOpen(row) {
  var details = groupDetails(row);
  return !!details && details.style.display === 'table-row';
}
function isInstanceOpen(row) {
  var details = instanceDetails(row);
  return !!details && details.style.display === 'table-row';
}
function setGroup(row, open) {
  var details = groupDetails(row);
  if (!details) { return; }
  details.style.display = open ? 'table-row' : 'none';
  row.classList.toggle('open', open);
  var btn = row.querySelector('.toggle');
  if (btn) {
    btn.textContent = open ? 'свернуть' : 'развернуть';
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
}
function setInstance(row, open) {
  var details = instanceDetails(row);
  if (!details) { return; }
  details.style.display = open ? 'table-row' : 'none';
  row.classList.toggle('open', open);
  var btn = row.querySelector('.toggle');
  if (btn) {
    btn.textContent = open ? 'свернуть' : 'подробнее';
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
}
function closeGroup(row) {
  setGroup(row, false);
  document.querySelectorAll('tr.i-row[data-group=\"' + row.dataset.id + '\"]').forEach(closeInstance);
}
function closeInstance(row) { setInstance(row, false); }
function toggleGroup(id) {
  var row = document.getElementById('gr' + id);
  if (row) { setGroup(row, !isGroupOpen(row)); refreshToggleAll(); }
}
function toggleInstance(id) {
  var row = document.getElementById('ir' + id);
  if (row) { setInstance(row, !isInstanceOpen(row)); refreshToggleAll(); }
}
function visibleGroups() {
  return Array.prototype.filter.call(
    document.querySelectorAll('tr.g-row'),
    function (row) { return row.style.display !== 'none'; }
  );
}
function refreshToggleAll() {
  var btn = document.getElementById('toggle-all');
  if (!btn) { return; }
  var rows = visibleGroups();
  var allOpen = rows.length > 0 && rows.every(isGroupOpen);
  btn.dataset.state = allOpen ? 'open' : 'closed';
  btn.textContent = allOpen ? 'Свернуть все' : 'Развернуть все';
  btn.disabled = rows.length === 0;
}
function toggleAll() {
  var btn = document.getElementById('toggle-all');
  var open = btn.dataset.state !== 'open';
  visibleGroups().forEach(function (row) { setGroup(row, open); });
  refreshToggleAll();
}
function resetFilters() {
  severityFilter = 'all';
  selectButton('button.f.sev', 'all');
  selectButton('button.f.cat-f', 'all');
  selectButton('button.f.conf-f', 'all');
  document.getElementById('q').value = '';
  applyFilters();
}
function escText(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function printFilteredPdf() {
  var rows = [];
  document.querySelectorAll('tr.i-row').forEach(function (row) {
    if (row.style.display === 'none') { return; }
    var sev = row.dataset.pdfSeverity || row.dataset.severity || '';
    var title = row.dataset.pdfTitle || '';
    var url = row.dataset.pdfUrl || '';
    var conf = row.dataset.pdfConfidence || row.dataset.confidence || '';
    var fix = row.dataset.pdfFix || '';
    var crit = row.dataset.pdfCritical === '1';
    rows.push(
      '<tr' + (crit ? ' class="crit"' : '') + '>'
      + '<td>' + escText(sev) + '</td>'
      + '<td>' + escText(title) + '</td>'
      + '<td>' + escText(url) + '</td>'
      + '<td>' + escText(conf) + '</td>'
      + '<td>' + escText(fix) + '</td></tr>'
    );
  });
  var box = document.getElementById('pdf-filtered');
  if (!box) { return; }
  var count = rows.length;
  var target = document.body.dataset.target || '';
  box.innerHTML =
    '<h1>Отчёт по отфильтрованным находкам</h1>'
    + '<p class="pdf-sub">Цель: ' + escText(target) + ' · записей в выборке: ' + count + '</p>'
    + (count
      ? ('<table><thead><tr><th>Уровень</th><th>Вид ошибки</th><th>Где нашли</th>'
         + '<th>Точность</th><th>Как исправить</th></tr></thead><tbody>'
         + rows.join('') + '</tbody></table>')
      : '<p>Под текущие фильтры не подходит ни одна находка.</p>')
    + '<p class="pdf-foot">В PDF попали только находки, видимые при текущих фильтрах таблицы. '
    + 'Полные доказательства и пошаговые рекомендации — в HTML-версии отчёта.</p>';
  document.body.classList.add('print-filtered');
  closePanel();
  window.print();
}
function toggleFixMore(button) {
  var block = button.closest('.block.fix');
  if (!block) { return; }
  var full = block.querySelector('.fix-full');
  if (!full) { return; }
  var open = !full.classList.contains('open');
  full.classList.toggle('open', open);
  button.setAttribute('aria-expanded', open ? 'true' : 'false');
  button.textContent = open ? 'свернуть' : 'подробнее';
}
document.addEventListener('DOMContentLoaded', function () {
  initGroup('button.f.sev');
  initGroup('button.f.cat-f');
  initGroup('button.f.conf-f');
  document.getElementById('q').addEventListener('input', applyFilters);
  document.getElementById('toggle-all').addEventListener('click', toggleAll);
  var pdfFilteredBtn = document.getElementById('pdf-filtered-btn');
  if (pdfFilteredBtn) {
    pdfFilteredBtn.addEventListener('click', printFilteredPdf);
  }
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
    btn.addEventListener('click', function () {
      document.body.classList.remove('print-filtered');
      closePanel();
      window.print();
    });
  });
  window.addEventListener('afterprint', function () {
    document.body.classList.remove('print-filtered');
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { closePanel(); }
  });
  document.querySelectorAll('[data-severity-link]').forEach(function (element) {
    element.addEventListener('click', function () {
      showSeverity(element.dataset.severityLink);
    });
  });
  document.querySelectorAll('[data-category-link]').forEach(function (element) {
    element.addEventListener('click', function () {
      showCategory(element.dataset.categoryLink);
    });
  });
  document.querySelectorAll('tr.g-row').forEach(function (row) {
    row.addEventListener('click', function (event) {
      if (event.target.closest('a') || event.target.closest('.toggle')
          || event.target.closest('.fix-more-btn')
          || event.target.closest('.ask-btn')
          || event.target.closest('.ask-actions')) { return; }
      setGroup(row, !isGroupOpen(row));
      refreshToggleAll();
    });
  });
  document.querySelectorAll('tr.i-row').forEach(function (row) {
    row.addEventListener('click', function (event) {
      if (event.target.closest('a') || event.target.closest('.toggle')
          || event.target.closest('.ask-btn')
          || event.target.closest('.ask-actions')) { return; }
      setInstance(row, !isInstanceOpen(row));
      refreshToggleAll();
    });
  });
  applyFilters();
  initAskDialog();
});

var askHistory = [];
function initAskDialog() {
  var backdrop = document.getElementById('ask-backdrop');
  var closeBtn = document.getElementById('ask-close');
  var form = document.getElementById('ask-form');
  var input = document.getElementById('ask-input');
  var sendBtn = document.getElementById('ask-send');
  if (!backdrop || !form) { return; }

  function openAsk(preset) {
    backdrop.classList.add('open');
    backdrop.setAttribute('aria-hidden', 'false');
    if (input) {
      if (preset) { input.value = preset; }
      input.focus();
      try { input.setSelectionRange(input.value.length, input.value.length); } catch (e) {}
    }
  }
  function closeAsk() {
    backdrop.classList.remove('open');
    backdrop.setAttribute('aria-hidden', 'true');
  }
  document.addEventListener('click', function (event) {
    var btn = event.target.closest('.ask-btn');
    if (!btn || btn.id === 'ask-send') { return; }
    event.preventDefault();
    event.stopPropagation();
    var title = btn.getAttribute('data-ask-title') || '';
    var url = btn.getAttribute('data-ask-url') || '';
    var preset = '';
    if (title && url) {
      preset = 'Как исправить ошибку «' + title + '» на адресе ' + url + '?';
    } else if (title) {
      preset = 'Как исправить ошибку «' + title + '»?';
    }
    openAsk(preset);
  });
  if (closeBtn) { closeBtn.addEventListener('click', closeAsk); }
  backdrop.addEventListener('click', function (event) {
    if (event.target === backdrop) { closeAsk(); }
  });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && backdrop.classList.contains('open')) {
      closeAsk();
    }
  });
  form.addEventListener('submit', function (event) {
    event.preventDefault();
    sendAskMessage();
  });
  if (input) {
    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendAskMessage();
      }
    });
  }

  function appendMsg(role, text) {
    var log = document.getElementById('ask-log');
    if (!log) { return; }
    var div = document.createElement('div');
    div.className = 'ask-msg ' + role;
    div.textContent = text;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }

  function sendAskMessage() {
    if (!input || !sendBtn) { return; }
    var question = (input.value || '').trim();
    if (!question || sendBtn.disabled) { return; }
    if (location.protocol === 'file:') {
      appendMsg('sys', 'Диалог доступен при открытии отчёта через Spyvision (python scan.py), не как file://');
      return;
    }
    appendMsg('user', question);
    askHistory.push({ role: 'user', content: question });
    input.value = '';
    sendBtn.disabled = true;
    appendMsg('sys', 'GigaChat думает…');
    var thinking = document.getElementById('ask-log').lastElementChild;

    fetch('/api/gigachat-chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        question: question,
        history: askHistory.slice(0, -1),
        target: document.body.dataset.target || ''
      })
    }).then(function (response) {
      return response.json().then(function (data) {
        return { ok: response.ok, data: data };
      });
    }).then(function (result) {
      if (thinking && thinking.classList.contains('sys')) { thinking.remove(); }
      if (!result.ok || !result.data || !result.data.ok) {
        var err = (result.data && result.data.error) ? result.data.error : 'Не удалось получить ответ';
        appendMsg('sys', err);
        askHistory.pop();
        return;
      }
      var answer = result.data.answer || '';
      appendMsg('bot', answer);
      askHistory.push({ role: 'assistant', content: answer });
    }).catch(function () {
      if (thinking && thinking.classList.contains('sys')) { thinking.remove(); }
      appendMsg('sys', 'Нет связи с сервером Spyvision. Запустите python scan.py и откройте отчёт по http://127.0.0.1:…/report.html');
      askHistory.pop();
    }).finally(function () {
      sendBtn.disabled = false;
      if (input) { input.focus(); }
    });
  }
}
"""

SPIDER_ICON = """
<svg class="ico" width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
  <path d="M16 1v5.5" stroke="#B7B7B7" stroke-width="1.2" stroke-linecap="round"/>
  <g stroke="#858585" stroke-width="1.55" fill="none" stroke-linecap="round"
     stroke-linejoin="round">
    <path d="M12.8 11.2 L8.2 7.2 L4.2 3.8"/>
    <path d="M12.2 13.2 L6.5 12 L2.2 10.2"/>
    <path d="M12.2 15.8 L6.4 17.6 L2.4 21.5"/>
    <path d="M13 17.8 L8.2 22.2 L5.5 27.5"/>
    <path d="M19.2 11.2 L23.8 7.2 L27.8 3.8"/>
    <path d="M19.8 13.2 L25.5 12 L29.8 10.2"/>
    <path d="M19.8 15.8 L25.6 17.6 L29.6 21.5"/>
    <path d="M19 17.8 L23.8 22.2 L26.5 27.5"/>
  </g>
  <ellipse cx="16" cy="20.8" rx="5.4" ry="6.2" fill="#858585"/>
  <ellipse cx="16" cy="12.4" rx="4.1" ry="3.6" fill="#5F5F5F"/>
  <g stroke="#5F5F5F" stroke-width="1.2" fill="none" stroke-linecap="round">
    <path d="M13.8 14.2 L12.2 16.2"/><path d="M18.2 14.2 L19.8 16.2"/>
  </g>
  <circle cx="14.5" cy="11.6" r="0.85" fill="#D8F1E6"/>
  <circle cx="17.5" cy="11.6" r="0.85" fill="#D8F1E6"/>
</svg>
"""

# Паутина RGB(133,133,133) — правый верхний угол (как на образце)
WEB_CORNER = """
<svg class="web" width="280" height="280" viewBox="0 0 200 200" aria-hidden="true">
  <g fill="none" stroke="#858585" stroke-linecap="round" stroke-linejoin="round">
    <path d="M200 0 L200.00 168.00 M200 0 L156.52 162.28 M200 0 L116.00 145.49 M200 0 L81.21 118.79 M200 0 L54.51 84.00 M200 0 L37.72 43.48 M200 0 L32.00 0.00" stroke-width="1.35"/>
    <path d="M200.00 40.00 Q196.76 24.59 189.65 38.64 Q190.51 22.91 180.00 34.64 Q184.90 19.68 171.72 28.28 Q180.32 15.10 165.36 20.00 Q177.09 9.49 161.36 10.35 Q175.41 3.24 160.00 0.00" stroke-width="1.25"/>
    <path d="M200.00 75.00 Q193.93 46.10 180.59 72.44 Q182.21 42.96 162.50 64.95 Q171.69 36.89 146.97 53.03 Q163.11 28.31 135.05 37.50 Q157.04 17.79 127.56 19.41 Q153.90 6.07 125.00 0.00" stroke-width="1.25"/>
    <path d="M200.00 112.00 Q190.94 68.85 171.01 108.18 Q173.43 64.15 144.00 96.99 Q157.73 55.09 120.80 79.20 Q144.91 42.27 103.01 56.00 Q135.85 26.57 91.82 28.99 Q131.15 9.06 88.00 0.00" stroke-width="1.25"/>
    <path d="M200.00 152.00 Q187.70 93.43 160.66 146.82 Q163.94 87.07 124.00 131.64 Q142.63 74.77 92.52 107.48 Q125.23 57.37 68.36 76.00 Q112.93 36.06 53.18 39.34 Q106.57 12.30 48.00 0.00" stroke-width="1.25"/>
  </g>
</svg>
"""

# Паутина #858585 + паук с главной — под кнопкой «домой»
CHART_HANG = """
<div class="chart-hang" aria-hidden="true">
<svg viewBox="0 0 100 292" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="rptMetal" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#E8ECE9"/>
      <stop offset="35%" stop-color="#A8B0AB"/>
      <stop offset="70%" stop-color="#6E7771"/>
      <stop offset="100%" stop-color="#3A433E"/>
    </linearGradient>
    <linearGradient id="rptMetalDark" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" stop-color="#9AA39D"/>
      <stop offset="100%" stop-color="#4A534E"/>
    </linearGradient>
    <pattern id="rptBodyMatrix" width="8" height="10" patternUnits="userSpaceOnUse">
      <rect width="8" height="10" fill="#2A3330"/>
      <text x="1" y="7" fill="#3F9D75" font-size="6" font-family="Consolas,monospace">01</text>
    </pattern>
    <filter id="rptSoftGlow" x="-40%" y="-40%" width="180%" height="180%">
      <feGaussianBlur stdDeviation="1.6" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <radialGradient id="rptLensGrad" cx="40%" cy="35%" r="60%">
      <stop offset="0%" stop-color="#E8F7F0" stop-opacity=".9"/>
      <stop offset="60%" stop-color="#BFE4D3" stop-opacity=".55"/>
      <stop offset="100%" stop-color="#2C7A5B" stop-opacity=".35"/>
    </radialGradient>
  </defs>
  <!-- Паутина сверху (как на образце), цвет #858585 -->
  <g fill="none" stroke="#858585" stroke-linecap="round" stroke-linejoin="round">
    <path d="M50 6 L18 28 M50 6 L30 34 M50 6 L50 38 M50 6 L70 34 M50 6 L82 28" stroke-width="1.35"/>
    <path d="M26 18 Q38 24 50 20 Q62 24 74 18" stroke-width="1.15"/>
    <path d="M22 24 Q36 32 50 28 Q64 32 78 24" stroke-width="1.2"/>
    <path d="M19 30 Q34 40 50 36 Q66 40 81 30" stroke-width="1.25"/>
    <path d="M17 36 Q32 48 50 44 Q68 48 83 36" stroke-width="1.3"/>
    <line x1="50" y1="6" x2="50" y2="170" stroke-width="1.5"/>
    <circle cx="50" cy="6" r="2.1" fill="#858585" stroke="none"/>
  </g>
  <!-- Паук с главной страницы (качается на нити, головой вниз) -->
  <g class="chart-hang-spider">
  <g transform="translate(2,154) scale(0.74) rotate(180 60 60)">
    <g fill="none" stroke="url(#rptMetalDark)" stroke-width="3.2" stroke-linecap="round">
      <!-- левая передняя — чуть согнута, держит лупу -->
      <path d="M48 48 C34 40, 24 30, 18 22"/>
      <path d="M46 54 C24 54, 14 48, 6 40"/>
      <path d="M46 62 C26 68, 16 78, 10 92"/>
      <path d="M50 66 C34 78, 28 92, 24 104"/>
      <path d="M72 48 C92 42, 102 28, 108 16"/>
      <path d="M74 54 C96 54, 106 48, 114 40"/>
      <path d="M74 62 C94 68, 104 78, 110 92"/>
      <path d="M70 66 C86 78, 92 92, 96 104"/>
    </g>
    <g fill="#858585">
      <circle cx="28" cy="36" r="2.2"/><circle cx="20" cy="50" r="2.2"/>
      <circle cx="24" cy="74" r="2.2"/><circle cx="36" cy="84" r="2.2"/>
      <circle cx="92" cy="36" r="2.2"/><circle cx="100" cy="50" r="2.2"/>
      <circle cx="96" cy="74" r="2.2"/><circle cx="84" cy="84" r="2.2"/>
      <!-- «захват» лупы на левой передней лапе -->
      <circle cx="20" cy="24" r="2.6" fill="#6E7771"/>
    </g>
    <ellipse cx="60" cy="72" rx="22" ry="26" fill="url(#rptMetal)"/>
    <ellipse cx="60" cy="72" rx="14" ry="18" fill="url(#rptBodyMatrix)" opacity=".85"/>
    <ellipse cx="60" cy="72" rx="22" ry="26" fill="none" stroke="#5A635E" stroke-width="1.2"/>
    <ellipse cx="60" cy="46" rx="18" ry="14" fill="url(#rptMetal)"/>
    <ellipse cx="60" cy="46" rx="18" ry="14" fill="none" stroke="#5A635E" stroke-width="1.2"/>
    <rect x="50" y="40" width="20" height="10" rx="2" fill="url(#rptBodyMatrix)" opacity=".9"/>
    <g filter="url(#rptSoftGlow)">
      <ellipse cx="53" cy="44" rx="4.2" ry="4.8" fill="#1E5A42"/>
      <ellipse cx="67" cy="44" rx="4.2" ry="4.8" fill="#1E5A42"/>
      <circle cx="53" cy="44" r="2.4" fill="#3F9D75"/>
      <circle cx="67" cy="44" r="2.4" fill="#3F9D75"/>
      <circle cx="53.8" cy="43" r=".8" fill="#D8F1E6"/>
      <circle cx="67.8" cy="43" r=".8" fill="#D8F1E6"/>
      <circle cx="46" cy="48" r="1.6" fill="#2C7A5B"/>
      <circle cx="74" cy="48" r="1.6" fill="#2C7A5B"/>
      <circle cx="50" cy="38" r="1.3" fill="#2C7A5B"/>
      <circle cx="70" cy="38" r="1.3" fill="#2C7A5B"/>
    </g>
    <path d="M52 54 Q48 60 50 66" fill="none" stroke="url(#rptMetalDark)" stroke-width="2.4" stroke-linecap="round"/>
    <path d="M68 54 Q72 60 70 66" fill="none" stroke="url(#rptMetalDark)" stroke-width="2.4" stroke-linecap="round"/>
    <!-- Лупа: ручка у лапы/к телу паука, линза наружу к диаграмме -->
    <g transform="translate(20, 24) rotate(-128)">
      <line x1="0" y1="0" x2="15" y2="0" stroke="#5A635E" stroke-width="3.2" stroke-linecap="round"/>
      <line x1="0" y1="0" x2="15" y2="0" stroke="#B7B7B7" stroke-width="1.9" stroke-linecap="round"/>
      <circle cx="21" cy="0" r="8.2" fill="url(#rptLensGrad)" stroke="#6E7771" stroke-width="2.4"/>
      <circle cx="21" cy="0" r="8.2" fill="none" stroke="#E8ECE9" stroke-width="1" opacity=".6"/>
      <path d="M16 -4 Q20 -6 24 -3" fill="none" stroke="#fff" stroke-width="1.3" stroke-linecap="round" opacity=".7"/>
    </g>
  </g>
  </g>
</svg>
</div>
"""

SPIDER_MARK = """
<svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
  <g stroke="#858585" stroke-width="1.65" fill="none" stroke-linecap="round"
     stroke-linejoin="round">
    <path d="M12.8 11.2 L8.2 7.2 L4.2 3.8"/>
    <path d="M12.2 13.2 L6.5 12 L2.2 10.2"/>
    <path d="M12.2 15.8 L6.4 17.6 L2.4 21.5"/>
    <path d="M13 17.8 L8.2 22.2 L5.5 27.5"/>
    <path d="M19.2 11.2 L23.8 7.2 L27.8 3.8"/>
    <path d="M19.8 13.2 L25.5 12 L29.8 10.2"/>
    <path d="M19.8 15.8 L25.6 17.6 L29.6 21.5"/>
    <path d="M19 17.8 L23.8 22.2 L26.5 27.5"/>
  </g>
  <ellipse cx="16" cy="20.8" rx="5.6" ry="6.4" fill="#858585"/>
  <ellipse cx="16" cy="12.4" rx="4.3" ry="3.7" fill="#5F5F5F"/>
  <g stroke="#5F5F5F" stroke-width="1.25" fill="none" stroke-linecap="round">
    <path d="M13.8 14.2 L12.2 16.2"/><path d="M18.2 14.2 L19.8 16.2"/>
  </g>
  <circle cx="14.4" cy="11.5" r="0.9" fill="#D8F1E6"/>
  <circle cx="17.6" cy="11.5" r="0.9" fill="#D8F1E6"/>
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
    else:
        panels.append(("errors", "Запросы, оставшиеся без ответа", 0,
                       "таймауты, отказы соединения и другие сетевые ошибки",
                       _errors_panel([])))

    parts: List[str] = []
    parts.append(
        "<!DOCTYPE html>\n<html lang=\"ru\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>Отчёт сканирования — {esc(target)}</title>\n"
        f"<style>{CSS}</style>\n</head>\n"
        f"<body data-target=\"{esc(target)}\">\n"
        "<a class=\"home-btn\" href=\"index.html\" title=\"Вернуться на главный экран Spyvision\">"
        "<svg width=\"16\" height=\"16\" viewBox=\"0 0 24 24\" fill=\"none\" aria-hidden=\"true\">"
        "<path d=\"M15 18l-6-6 6-6\" stroke=\"currentColor\" stroke-width=\"2\" "
        "stroke-linecap=\"round\" stroke-linejoin=\"round\"/>"
        "<path d=\"M9 12h11\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\"/>"
        "</svg>Выйти на главный экран</a>\n"
    )

    # ---------- главный экран: диаграмма, заголовок, статистика ----------
    parts.append("<header>")
    parts.append(WEB_CORNER)
    parts.append("<div class=\"wrap hero\">")
    parts.append(_chart_card(by_severity, total, stats, len(performed)))
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
    parts.append(
        f"<footer>{SPIDER_MARK}<span>Отчёт сформирован сканером Spyvision (разведка DNS, "
        "SAST по HTML/JS, DAST, Broken Access Control). Находки сопоставлены с "
        "OWASP Top 10:2021. Проверки безопасны и не изменяют данные; маркеры — "
        "BAUMAN_TEST_92841, https://evil.com, одиночные кавычки. "
        "Статус «подозрение» требует ручной проверки.</span></footer>"
    )
    parts.append("</div>")

    # ---------- боковая панель ----------
    parts.append(_drawer(panels))

    # Диалоговое окно: пользователь спрашивает GigaChat про исправление ошибок.
    # Ответы приходят с /api/gigachat-chat (см. ui_server._handle_gigachat_chat).
    parts.append(
        "<div class=\"ask-backdrop\" id=\"ask-backdrop\" aria-hidden=\"true\">"
        "<div class=\"ask-dialog\" role=\"dialog\" aria-modal=\"true\" "
        "aria-labelledby=\"ask-title\">"
        "<div class=\"ask-head\">"
        "<h3 id=\"ask-title\">Вопрос GigaChat по исправлению</h3>"
        "<button type=\"button\" class=\"ask-close\" id=\"ask-close\" "
        "aria-label=\"Закрыть\">×</button>"
        "</div>"
        "<div class=\"ask-log\" id=\"ask-log\">"
        "<div class=\"ask-msg sys\">Спросите, как исправить конкретную ошибку из отчёта, "
        "что проверить после правки или как интерпретировать доказательство.</div>"
        "</div>"
        "<form class=\"ask-form\" id=\"ask-form\">"
        "<textarea id=\"ask-input\" rows=\"2\" maxlength=\"4000\" "
        "placeholder=\"Например: как закрыть XSS из параметра q?\" "
        "required></textarea>"
        "<button type=\"submit\" class=\"ask-send\" id=\"ask-send\">Спросить</button>"
        "</form>"
        "</div></div>\n"
    )

    # ---------- печатная версия для сохранения в PDF ----------
    parts.append(_pdf_report(stats, by_severity, by_confidence, critical, items,
                             total, generated))
    parts.append("<div id=\"pdf-filtered\"></div>")

    parts.append(f"<script>{JS}</script>\n</body>\n</html>")
    return "".join(parts)


# ---------- кольцевая диаграмма ----------
def _chart_card(by_severity: Dict[str, int], total: int,
                stats: Optional[Dict[str, object]] = None,
                checks_count: int = 0) -> str:
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
            f"<circle cx=\"110\" cy=\"110\" r=\"{radius}\" fill=\"none\" stroke=\"#152438\" "
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
        "<div class=\"chart-col\">"
        + CHART_HANG +
        "<div class=\"chart-with-menu\">"
        "<button type=\"button\" class=\"help-menu\" data-open=\"help\" "
        "title=\"Как читать отчёт\" aria-label=\"Открыть раздел «Как читать отчёт»\">"
        "<span></span><span></span><span></span></button>"
        "<div class=\"chart-card\">"
        "<h3>Статистика уязвимостей</h3>"
        "<p class=\"tip\">Нажмите на уровень, чтобы увидеть эти находки</p>"
        "<svg class=\"donut\" width=\"220\" height=\"220\" viewBox=\"0 0 220 220\" "
        "role=\"img\" aria-label=\"Распределение находок по уровням критичности\">"
        f"<circle cx=\"110\" cy=\"110\" r=\"{radius}\" fill=\"none\" stroke=\"#121E30\" "
        f"stroke-width=\"{stroke}\"/>"
        + "".join(segments) +
        f"<text class=\"donut-total\" x=\"110\" y=\"106\" text-anchor=\"middle\" "
        f"dominant-baseline=\"middle\">{total}</text>"
        "<text class=\"donut-caption\" x=\"110\" y=\"132\" text-anchor=\"middle\">"
        "всего находок</text>"
        "</svg>"
        "<ul class=\"legend\">" + "".join(legend) + "</ul>"
        "</div></div>"
        + _pdf_button()
        + _under_pdf(stats or {}, checks_count)
        + "</div>"
    )


def _under_pdf(stats: Dict[str, object], checks_count: int) -> str:
    duration = stats.get("duration", 0)
    return (
        "<div class=\"under-pdf\">"
        "<button type=\"button\" class=\"nav-card under-pdf-checks\" data-open=\"checks\">"
        f"<span class=\"nav-n\">{checks_count}</span> "
        "<span class=\"nav-t\">Какие проверки выполнялись</span>"
        "<span class=\"nav-s\">полный список выполненных проверок и их охват</span>"
        "<span class=\"nav-go\">Открыть раздел →</span></button>"
        + _card(f"{duration}<small> с</small>", "Длительность сканирования",
                "между запросами выдерживается пауза 0.5 с")
        + "</div>"
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

    found = [
        _card(f"{critical}", "Подтверждённые угрозы высокого уровня",
              "факт виден прямо в ответе сервера — исправлять первыми"
              if critical else "таких находок нет",
              css="alarm strong" if critical else "",
              link="critical"),
        _card(f"{attention}", "Требуют внимания", "высокая и средняя опасность",
              css="alarm" if attention else "",
              link="attention"),
        _card(f"{by_category.get(VULN, 0)}", "Уязвимостей приложения",
              "ошибки обработки пользовательского ввода",
              category=VULN),
        _card(f"{by_category.get(CONFIG, 0)}", "Проблем конфигурации",
              "настройки сервера, заголовков, cookie",
              category=CONFIG),
    ]

    scanned = [
        _card(f"{pages}", "Страниц проверено", f"из лимита {max_pages} в пределах домена",
              css="accent", panel="pages"),
        _card(f"{_int(stats.get('forms'))}", "Форм на страницах",
              "поля ввода — основные точки для проверки"),
        _card(f"{_int(stats.get('url_params'))}", "Параметров в адресах",
              "значения в ссылках вида ?id=5"),
        _card("HTTPS" if https else "HTTP", "Протокол сайта",
              "соединение шифруется" if https else "соединение не шифруется"),
    ]

    percent = int(round(100 * requests_made / max_requests)) if max_requests else 0
    how = [
        _card(f"{requests_made}<small> / {max_requests}</small>", "Запросов к сайту",
              f"израсходовано {percent}% разрешённого лимита", bar=percent,
              panel="findings"),
        _card(f"{_int(stats.get('checks'))}", "Проверок выполнено",
              "заголовки, cookie, формы, служебные адреса и другие"),
        _card(f"{_int(stats.get('active_tests'))}", "Активных тестов",
              f"безопасных проб на {_int(stats.get('targets_tested'))} точках ввода"),
        _card(f"{errors}", "Запросов без ответа",
              "таймаут, отказ соединения или ошибка сети",
              panel="errors"),
    ]

    groups = (
        ("Найденные проблемы", found),
        ("Что просканировано", scanned),
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
          link: str = "", category: str = "", panel: str = "") -> str:
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
    if category:
        return (f"<button type=\"button\" class=\"{classes}\" "
                f"data-category-link=\"{esc(category)}\">{body}"
                f"<div class=\"go\">Показать эти находки →</div></button>")
    if panel:
        return (f"<button type=\"button\" class=\"{classes}\" "
                f"data-open=\"{esc(panel)}\">{body}"
                f"<div class=\"go\">Открыть раздел →</div></button>")
    return f"<div class=\"{classes}\">{body}</div>"


# ---------- карточки разделов и боковая панель ----------
def _pdf_button() -> str:
    return (
        "<button type=\"button\" class=\"nav-card pdf chart-pdf\" data-print>"
        "<span class=\"nav-t\">Скачать PDF</span>"
        "<span class=\"nav-s\">только находки высокого уровня: подтверждённые угрозы "
        "и подозрения</span>"
        "<span class=\"nav-go\">Откроется окно печати — выберите «Сохранить в PDF» →</span>"
        "</button>"
    )


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
        "<div class=\"help-item info\"><b>PDF-версия</b><span>кнопка «Скачать PDF» под "
        "диаграммой открывает печать краткой сводки только с находками высокого уровня "
        "(подтверждённые — первыми). Средние и низкие остаются в HTML-отчёте.</span></div>"
    )
    parts.append("</div>")
    return "".join(parts)


def _findings_panel(items: Sequence[Finding], by_severity: Dict[str, int],
                    by_category: Dict[str, int], total: int) -> str:
    by_confidence = _count_confidence(list(items))
    groups = _group_findings(items)
    parts = [f"<h2 id=\"findings\">{SPIDER_ICON}Найденные проблемы</h2>",
             _filters(by_severity, by_category, by_confidence, total, len(groups))]
    if not items:
        parts.append("<div class=\"empty\">Проблем не обнаружено. Это не гарантирует "
                     "отсутствие уязвимостей: сканер выполняет ограниченный набор "
                     "безопасных проверок.</div>")
        return "".join(parts)

    parts.append(
        "<table><thead><tr>"
        "<th>Уровень опасности</th><th>Вид ошибки</th><th>Тип угрозы</th>"
        "<th>Категория</th><th>Кол-во</th><th>Точность</th><th></th>"
        "</tr></thead><tbody>"
    )
    instance_index = 0
    for group_index, group in enumerate(groups):
        html, instance_index = _group_block(group_index, group, instance_index)
        parts.append(html)
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
def _group_findings(items: Sequence[Finding]) -> List[List[Finding]]:
    """Группирует находки по виду ошибки (заголовку), сохраняя порядок критичности."""
    buckets: Dict[str, List[Finding]] = {}
    order: List[str] = []
    for finding in items:
        key = finding.title
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(finding)
    return [buckets[key] for key in order]


def _filters(by_severity: Dict[str, int], by_category: Dict[str, int],
             by_confidence: Dict[str, int], total: int, group_count: int) -> str:
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

    confidence_buttons = [
        f"<button class=\"f conf-f wide active\" data-value=\"all\">Любая "
        f"<span class=\"n\">{total}</span></button>",
        f"<button class=\"f conf-f\" data-value=\"{CONFIRMED}\">Подтверждено "
        f"<span class=\"n\">{by_confidence.get(CONFIRMED, 0)}</span></button>",
        f"<button class=\"f conf-f\" data-value=\"{SUSPECTED}\">Подозрение "
        f"<span class=\"n\">{by_confidence.get(SUSPECTED, 0)}</span></button>",
    ]

    return (
        "<div class=\"filters\">"
        "<div class=\"filter-row\"><span class=\"cap\">Уровень</span>"
        + "".join(severity_buttons) +
        "</div>"
        "<div class=\"filter-row\"><span class=\"cap\">Категория</span>"
        + "".join(category_buttons) +
        "</div>"
        "<div class=\"filter-row\"><span class=\"cap\">Точность</span>"
        + "".join(confidence_buttons) +
        "</div>"
        "<div class=\"filter-row\"><span class=\"cap\">Поиск</span>"
        "<input type=\"search\" id=\"q\" placeholder=\"Адрес, вид ошибки, тип угрозы…\">"
        "<button type=\"button\" class=\"f pdf-filtered\" id=\"pdf-filtered-btn\" "
        "title=\"Сохранить PDF по текущим фильтрам\">PDF по фильтру</button>"
        "<button class=\"f\" id=\"toggle-all\" data-state=\"closed\">Развернуть все</button>"
        "<button class=\"f\" data-reset>Сбросить</button>"
        "</div>"
        "</div>"
        f"<p class=\"hint\">Показано видов ошибок: <b id=\"shown\">0</b> из {group_count} "
        f"(экземпляров: <b id=\"shown-items\">0</b> из {total}). "
        "Щёлкните по виду ошибки, чтобы увидеть все адреса с этой проблемой; внутри списка "
        "каждая запись раскрывается до доказательств. Фильтры действуют и на виды, и на "
        "список внутри. <b>Красным</b> выделены подтверждённые находки высокого уровня. "
        "Кнопка «PDF по фильтру» сохраняет только видимые сейчас записи.</p>"
    )


def _group_block(group_index: int, group: Sequence[Finding],
                 instance_start: int) -> Tuple[str, int]:
    sample = group[0]
    severity_class = SEVERITY_CLASS.get(sample.severity, "sev-info")
    severity_label = SEVERITY_LABEL.get(sample.severity, sample.severity)
    confirmed = sum(1 for item in group if item.confidence == CONFIRMED)
    suspected = len(group) - confirmed
    critical = sample.severity == HIGH and confirmed > 0
    row_class = "g-row critical" if critical else "g-row"
    if confirmed and suspected:
        accuracy = f"Подтверждено: {confirmed}, Подозрение: {suspected}"
    elif confirmed:
        accuracy = "Подтверждено"
    else:
        accuracy = "Подозрение"
    owasp_label = getattr(sample, "owasp", "") or ""
    search_blob = " ".join(
        [sample.title, sample.category, sample.severity, severity_label, sample.threat_type,
         owasp_label, sample.impact, sample.detection, sample.recommendation, accuracy]
        + [item.url for item in group]
        + [item.evidence for item in group]
        + [item.request for item in group]
        + [item.confidence for item in group]
    ).lower()
    owasp_html = (f"<span class=\"owasp\" title=\"OWASP Top 10:2021\">{esc(owasp_label)}</span>"
                  if owasp_label else "")

    row = (
        f"<tr class=\"{row_class}\" id=\"gr{group_index}\" data-id=\"{group_index}\" "
        f"data-severity=\"{esc(sample.severity)}\" data-category=\"{esc(sample.category)}\" "
        f"data-search=\"{esc(search_blob)}\">"
        f"<td class=\"nowrap\"><span class=\"badge {severity_class}\">{esc(severity_label)}"
        f"</span></td>"
        f"<td class=\"title\">{esc(sample.title)}</td>"
        f"<td><span class=\"threat\">{esc(sample.threat_type)}</span>{owasp_html}</td>"
        f"<td class=\"cat\">{esc(sample.category)}</td>"
        f"<td class=\"nowrap\"><span class=\"count-pill\">{len(group)} шт.</span></td>"
        f"<td class=\"cat\">{esc(accuracy)}</td>"
        f"<td class=\"nowrap\"><button class=\"toggle\" aria-expanded=\"false\" "
        f"onclick=\"toggleGroup({group_index})\">развернуть</button></td>"
        "</tr>"
    )

    inner_parts = [
        "<table class=\"inner-table\"><thead><tr>"
        "<th>Где нашли (адрес)</th><th>Точность</th><th></th>"
        "</tr></thead><tbody>"
    ]
    instance_index = instance_start
    for finding in group:
        inner_parts.append(_instance_rows(group_index, instance_index, finding))
        instance_index += 1
    inner_parts.append(
        f"<tr id=\"ge{group_index}\" style=\"display:none\"><td colspan=\"3\" "
        f"class=\"inner-empty\">Под выбранные фильтры не подходит ни один экземпляр "
        f"этого вида ошибки.</td></tr>"
    )
    inner_parts.append("</tbody></table>")

    # Общие пояснения вида ошибки — один раз над списком экземпляров
    ask_btn = (
        "<div class=\"ask-actions\">"
        "<p class=\"ask-hint\">Нужна помощь по этой ошибке — спросите GigaChat.</p>"
        f"<button type=\"button\" class=\"ask-btn\" data-ask-title=\"{esc(sample.title)}\" "
        "title=\"Спросить GigaChat про исправление этой ошибки\">"
        "Спросить GigaChat</button>"
        "</div>"
    )
    owasp_block = ""
    if owasp_label:
        owasp_block = (
            "<div class=\"block full\"><h4>OWASP Top 10:2021</h4>"
            f"<p><span class=\"owasp\">{esc(owasp_label)}</span> — находка сопоставлена "
            "с актуальным списком угроз OWASP Top 10.</p></div>"
        )
    details = (
        f"<tr class=\"g-details\" id=\"g{group_index}\" style=\"display:none\">"
        f"<td colspan=\"7\"><div class=\"det\">"
        + ask_btn + owasp_block +
        "<div class=\"block danger full\"><h4>Чем это опасно</h4>"
        f"<p>{esc(sample.impact or 'Описание для этого типа находки не задано.')}</p></div>"
        "<div class=\"block logic full\"><h4>Почему сканер так решил</h4>"
        f"<p>{esc(sample.detection or 'Логика проверки описана в названии находки.')}</p></div>"
        + _fix_block(sample.recommendation or "—") +
        "<div class=\"block full\"><h4>Где встречается</h4>"
        + "".join(inner_parts) +
        "</div></div></td></tr>"
    )
    return row + details, instance_index


def _instance_rows(group_index: int, index: int, finding: Finding) -> str:
    critical = finding.severity == HIGH and finding.confidence == CONFIRMED
    confidence_class = "conf sus" if finding.confidence == SUSPECTED else "conf"
    if critical:
        confidence_class = "conf yes"
    severity_label = SEVERITY_LABEL.get(finding.severity, finding.severity)
    conf_label = ("Подтверждено" if finding.confidence == CONFIRMED
                  else "Подозрение" if finding.confidence == SUSPECTED
                  else finding.confidence)
    fix_short = (finding.recommendation or "—").split("\n\n", 1)[0]
    if len(fix_short) > 280:
        fix_short = fix_short[:277] + "…"
    search_blob = " ".join([finding.url, finding.title, finding.category, finding.severity,
                            finding.threat_type, finding.impact, finding.detection,
                            finding.evidence, finding.request, finding.confidence]).lower()
    row = (
        f"<tr class=\"i-row\" id=\"ir{index}\" data-id=\"{index}\" "
        f"data-group=\"{group_index}\" "
        f"data-severity=\"{esc(finding.severity)}\" data-category=\"{esc(finding.category)}\" "
        f"data-confidence=\"{esc(finding.confidence)}\" data-search=\"{esc(search_blob)}\" "
        f"data-pdf-severity=\"{esc(severity_label)}\" data-pdf-title=\"{esc(finding.title)}\" "
        f"data-pdf-url=\"{esc(finding.url)}\" data-pdf-confidence=\"{esc(conf_label)}\" "
        f"data-pdf-fix=\"{esc(fix_short)}\" data-pdf-critical=\"{1 if critical else 0}\">"
        f"<td>{_link(finding.url)}</td>"
        f"<td class=\"{confidence_class}\">{esc(conf_label)}</td>"
        f"<td class=\"nowrap\"><button class=\"toggle\" aria-expanded=\"false\" "
        f"onclick=\"toggleInstance({index})\">подробнее</button></td>"
        "</tr>"
    )
    details = (
        f"<tr class=\"details\" id=\"i{index}\" style=\"display:none\"><td colspan=\"3\">"
        "<div class=\"det\">"
        "<div class=\"ask-actions\">"
        "<p class=\"ask-hint\">Спросите GigaChat про этот конкретный адрес.</p>"
        f"<button type=\"button\" class=\"ask-btn\" data-ask-title=\"{esc(finding.title)}\" "
        f"data-ask-url=\"{esc(finding.url)}\" "
        "title=\"Спросить GigaChat про исправление этой ошибки\">"
        "Спросить GigaChat</button>"
        "</div>"
        "<div class=\"block code-block full\"><h4>Что отправил сканер "
        "(безопасные тестовые данные)</h4>"
        f"<pre>{esc(finding.request or '—')}</pre></div>"
        "<div class=\"block code-block full\"><h4>Что ответил сервер (доказательство)</h4>"
        f"<pre>{esc(finding.evidence or '—')}</pre></div>"
        "</div></td></tr>"
    )
    return row + details


def _row(index: int, finding: Finding) -> str:
    """Совместимость со старыми тестами: одна находка = одна группа."""
    html, _next = _group_block(index, [finding], index)
    return html


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
        # В PDF — краткий первый абзац; полный текст — в интерактивном отчёте
        fix_short = (finding.recommendation or "—").split("\n\n", 1)[0]
        if len(fix_short) > 320:
            fix_short = fix_short[:317] + "…"
        rows.append(
            f"<tr{css}><td>{esc(SEVERITY_LABEL.get(finding.severity, finding.severity))}</td>"
            f"<td>{esc(finding.title)}</td>"
            f"<td>{esc(finding.url)}</td>"
            f"<td>{esc(finding.confidence)}</td>"
            f"<td>{esc(fix_short)}</td></tr>"
        )
    return ("<table><thead><tr><th>Уровень</th><th>Вид ошибки</th><th>Где нашли</th>"
            "<th>Точность</th><th>Как исправить</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")


# ---------- вспомогательное ----------
def _fix_block(text: object) -> str:
    """Краткое «Как исправить» + кнопка «подробнее» с полным текстом."""
    raw = str(text or "").strip() or "—"
    paragraphs = [part.strip() for part in raw.split("\n\n") if part.strip()]
    brief = paragraphs[0] if paragraphs else "—"
    # Если первый абзац — служебная фраза-вступление, берём следующий содержательный
    skip_prefixes = ("ниже — подробный", "давайте разберём")
    if len(paragraphs) > 1 and brief.lower().startswith(skip_prefixes):
        brief = paragraphs[1]
    if len(brief) > 420:
        brief = brief[:417].rstrip() + "…"
    has_more = len(paragraphs) > 1 or len(raw) > len(brief) + 20
    parts = [
        "<div class=\"block fix full\"><h4>Как исправить</h4>",
        f"<p class=\"fix-brief\">{esc(brief)}</p>",
    ]
    if has_more:
        parts.append(
            "<button type=\"button\" class=\"fix-more-btn\" aria-expanded=\"false\" "
            "onclick=\"event.stopPropagation(); toggleFixMore(this)\">подробнее</button>"
            f"<div class=\"fix-full\">{_paragraphs(raw)}</div>"
        )
    parts.append("</div>")
    return "".join(parts)


def _paragraphs(text: object) -> str:
    """Несколько абзацев из текста с пустыми строками-разделителями."""
    raw = str(text or "").strip()
    if not raw:
        return "<p>—</p>"
    parts = [part.strip() for part in raw.split("\n\n") if part.strip()]
    if not parts:
        return f"<p>{esc(raw)}</p>"
    html_parts = []
    for part in parts:
        body = esc(part).replace("\n", "<br>\n")
        css = ' class="step"' if part.startswith("Шаг ") else ""
        html_parts.append(f"<p{css}>{body}</p>")
    return "".join(html_parts)


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
