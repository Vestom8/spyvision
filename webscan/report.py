"""Формирование HTML-отчёта (раздел 6 требований).

Оформление: светло-серые и зелёные оттенки, тематика пауков и паутины.
На главном экране — кольцевая диаграмма распределения находок по уровням
критичности (уровни кликабельны) и блок «Общая статистика». Подробные разделы
(как читать отчёт, найденные проблемы, просканированные страницы, список
проверок, запросы без ответа) вынесены в боковую выпадающую панель, чтобы
главный экран помещался без прокрутки. Кнопка «Скачать PDF» открывает печать
краткой сводки — браузер сохраняет её в PDF. В подробностях находки — кнопка
«ГигаЧат» с диалогом эксперта по информационной безопасности.
"""

import datetime
import html
import json
import math
from typing import Dict, List, Optional, Sequence, Tuple

from .models import (CONFIG, CONFIRMED, HIGH, INFO, LOW, MEDIUM, SEVERITY_ORDER, SUSPECTED,
                     VULN, Finding, FindingList)

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
@import url("https://fonts.googleapis.com/css2?family=Manrope:wght@500;600;700;800&display=swap");
:root {
  --bg: #E6F0E8;
  --bg-top: #F4FBF6;
  --panel: #FAFDFB;
  --panel-2: #F0F7F2;
  --mint: #C5E8D4;
  --mint-deep: #9ED4B8;
  --green: #2A8F5C;
  --green-dark: #165C3A;
  --moss: #4A7C59;
  --sage: #8FB996;
  --iron: #6E7A72;
  --iron-light: #A3AFA7;
  --border: #C8DCCF;
  --text: #1F2E26;
  --muted: #5A6B60;
  --high: #C24B3A;
  --medium: #C98A2E;
  --low: #6E7A72;
  --safe: #3AA66F;
  --aurora-lime: #8BE06A;
  --aurora-mint: #5ED9A0;
  --aurora-emerald: #2FBF78;
  --aurora-forest: #1A8F5C;
  --aurora-teal: #2AA88A;
  --lava-hi: #F3FBF7;
  --lava-mint: #D4F0E4;
  --lava-sage: #B5E2D2;
  --lava-sea: #96D4C4;
  --lava-teal: #7EC4B8;
  --lava-deep: #63B3A4;
  --shadow: 0 10px 28px rgba(22, 70, 48, .10);
  --shadow-soft: 0 4px 16px rgba(22, 70, 48, .07);
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 0 0 28px; color: var(--text); min-height: 100vh;
  background:
    radial-gradient(ellipse 80% 55% at 50% -8%, rgba(139,224,106,.22), transparent 55%),
    radial-gradient(ellipse 50% 40% at 15% 0%, rgba(94,217,160,.18), transparent 50%),
    radial-gradient(ellipse 45% 35% at 85% 5%, rgba(42,168,138,.14), transparent 48%),
    radial-gradient(ellipse 90% 60% at 50% 0%, #FFFFFF 0%, var(--bg-top) 40%, var(--bg) 100%) fixed;
  font: 15px/1.6 Manrope, "Segoe UI", sans-serif;
  -webkit-font-smoothing: antialiased;
}
body::before {
  content: "";
  position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background:
    radial-gradient(circle at 12% 18%, rgba(158,212,184,.4) 0%, transparent 22%),
    radial-gradient(circle at 88% 12%, rgba(197,232,212,.5) 0%, transparent 18%),
    radial-gradient(circle at 78% 78%, rgba(143,185,150,.3) 0%, transparent 24%),
    radial-gradient(circle at 18% 82%, rgba(197,232,212,.35) 0%, transparent 20%);
}
body.locked { overflow: hidden; }

/* Северное сияние + лавовая лампа — как на главном экране */
.atmosphere {
  position: fixed;
  inset: 0;
  pointer-events: none;
  z-index: 0;
  overflow: hidden;
}

/* Северное сияние — мягкие зелёные завесы сверху */
.aurora {
  position: absolute;
  top: -8%;
  left: -10%;
  right: -10%;
  height: 58vh;
  overflow: hidden;
  opacity: .85;
  mask-image: linear-gradient(to bottom, #000 35%, transparent 92%);
  -webkit-mask-image: linear-gradient(to bottom, #000 35%, transparent 92%);
}
.aurora-band {
  position: absolute;
  inset: -20% -5%;
  border-radius: 40% 60% 50% 50% / 30% 40% 60% 70%;
  filter: blur(28px);
  mix-blend-mode: multiply;
  animation: auroraDrift ease-in-out infinite;
}
.aurora-band.a1 {
  background:
    linear-gradient(105deg,
      transparent 8%,
      rgba(139, 224, 106, .55) 22%,
      rgba(47, 191, 120, .42) 38%,
      transparent 52%,
      rgba(94, 217, 160, .5) 68%,
      rgba(26, 143, 92, .35) 82%,
      transparent 95%);
  animation-duration: 14s;
  opacity: .9;
}
.aurora-band.a2 {
  background:
    linear-gradient(78deg,
      transparent 5%,
      rgba(42, 168, 138, .4) 28%,
      rgba(139, 224, 106, .48) 45%,
      transparent 60%,
      rgba(47, 191, 120, .38) 75%,
      transparent 92%);
  top: 8%;
  height: 70%;
  filter: blur(36px);
  animation-duration: 18s;
  animation-delay: -4s;
  opacity: .75;
}
.aurora-band.a3 {
  background:
    radial-gradient(ellipse 40% 80% at 30% 20%, rgba(139, 224, 106, .45), transparent 70%),
    radial-gradient(ellipse 35% 70% at 70% 35%, rgba(94, 217, 160, .4), transparent 65%),
    radial-gradient(ellipse 30% 60% at 50% 10%, rgba(26, 143, 92, .28), transparent 60%);
  filter: blur(22px);
  animation-duration: 11s;
  animation-delay: -7s;
  opacity: .8;
}
@keyframes auroraDrift {
  0%, 100% { transform: translate3d(0, 0, 0) skewX(-2deg) scale(1, 1); }
  33% { transform: translate3d(3%, 2%, 0) skewX(3deg) scale(1.04, .96); }
  66% { transform: translate3d(-4%, 1%, 0) skewX(-4deg) scale(.97, 1.05); }
}

.lava-svg {
  position: absolute;
  width: 0;
  height: 0;
  overflow: hidden;
}
.lava-lamp {
  position: absolute;
  inset: 0;
  overflow: hidden;
}
/* Мягкое холодное свечение у дна */
.lava-heat {
  position: absolute;
  left: -10%;
  right: -10%;
  bottom: -14%;
  height: 28%;
  background:
    radial-gradient(ellipse 60% 70% at 50% 100%, rgba(190, 235, 220, .45), transparent 70%),
    radial-gradient(ellipse 80% 55% at 30% 100%, rgba(170, 220, 210, .28), transparent 62%),
    radial-gradient(ellipse 70% 50% at 70% 100%, rgba(150, 210, 200, .22), transparent 58%);
  filter: blur(36px);
  opacity: .75;
}
/* Metaball / goo — пузыри тянутся и сливаются с лужей */
.lava-goo {
  position: absolute;
  inset: 0;
  filter: url(#lava-goo) blur(1.2px)
    drop-shadow(0 0 22px rgba(160, 220, 200, .35))
    drop-shadow(0 0 48px rgba(140, 205, 190, .18));
  transform: translateZ(0);
}
.lava-pool {
  position: absolute;
  left: 2%;
  right: 2%;
  bottom: -16%;
  height: 22%;
  border-radius: 48% 52% 40% 42% / 60% 55% 40% 45%;
  background:
    radial-gradient(ellipse 55% 50% at 22% 30%, var(--lava-hi) 0%, transparent 52%),
    radial-gradient(ellipse 48% 46% at 78% 38%, var(--lava-mint) 0%, transparent 50%),
    linear-gradient(125deg,
      var(--lava-mint) 0%,
      var(--lava-sage) 28%,
      var(--lava-sea) 55%,
      var(--lava-teal) 78%,
      var(--lava-deep) 100%),
    radial-gradient(ellipse 90% 100% at 50% 70%,
      var(--lava-sage) 0%,
      var(--lava-sea) 40%,
      var(--lava-teal) 70%,
      var(--lava-deep) 100%);
  background-blend-mode: soft-light, soft-light, normal, normal;
  opacity: .8;
  filter: blur(2px);
  animation: lavaPool 18s cubic-bezier(0.42, 0.05, 0.58, 0.95) infinite;
}
/* Лужа «принимает» капли — лёгкая рябь */
@keyframes lavaPool {
  0%, 100% { transform: scale(1, 1) translateY(0); border-radius: 48% 52% 40% 42% / 60% 55% 40% 45%; }
  22% { transform: scale(1.04, .9) translateY(3%); border-radius: 52% 48% 45% 40% / 50% 58% 38% 48%; }
  48% { transform: scale(.98, 1.05) translateY(-1%); border-radius: 44% 56% 38% 48% / 62% 48% 48% 40%; }
  72% { transform: scale(1.06, .88) translateY(4%); border-radius: 55% 45% 48% 38% / 48% 55% 42% 52%; }
}
.lava-blob {
  position: absolute;
  bottom: 2%;
  display: block;
  will-change: transform, border-radius, background-position;
  background:
    radial-gradient(circle at 32% 26%,
      var(--lava-hi) 0%,
      transparent 42%),
    linear-gradient(155deg,
      var(--lava-hi) 0%,
      var(--lava-mint) 22%,
      var(--lava-sage) 45%,
      var(--lava-sea) 68%,
      var(--lava-teal) 85%,
      var(--lava-deep) 100%);
  background-size: 100% 100%, 140% 140%;
  background-position: center, 30% 20%;
  opacity: .84;
  filter: blur(1.5px);
  border-radius: 48% 52% 45% 55% / 55% 48% 52% 45%;
  animation:
    lavaFloat var(--lava-float, 40s) cubic-bezier(0.4, 0.0, 0.2, 1) infinite,
    lavaMorph var(--lava-morph, 16s) cubic-bezier(0.45, 0.02, 0.55, 0.98) infinite,
    lavaGradShift calc(var(--lava-float, 40s) * .85) ease-in-out infinite;
}
.lava-blob::before,
.lava-blob::after {
  content: "";
  position: absolute;
  border-radius: inherit;
  pointer-events: none;
}
.lava-blob::before {
  inset: 14% 20% auto 16%;
  height: 26%;
  background: radial-gradient(ellipse at 40% 40%,
    rgba(255, 255, 255, .8) 0%,
    rgba(243, 251, 247, .4) 45%,
    transparent 72%);
  filter: blur(2px);
}
.lava-blob::after {
  inset: auto 12% 10% 20%;
  height: 36%;
  background: linear-gradient(180deg,
    transparent 0%,
    rgba(99, 179, 164, .22) 55%,
    rgba(126, 196, 184, .18) 100%);
  filter: blur(1px);
}
.lava-blob.b1 {
  left: 14%; width: 176px; height: 196px;
  --lava-float: 38s; --lava-morph: 15s;
  animation-delay: 0s, 0s, 0s;
  background:
    radial-gradient(circle at 30% 24%, var(--lava-hi) 0%, transparent 40%),
    linear-gradient(148deg, var(--lava-hi), var(--lava-mint) 30%, var(--lava-sage) 55%, var(--lava-teal) 80%, var(--lava-deep));
  background-size: 100% 100%, 150% 150%;
}
.lava-blob.b2 {
  left: 34%; width: 154px; height: 178px;
  --lava-float: 46s; --lava-morph: 18s;
  animation-delay: -12s, -4s, -5s;
  background:
    radial-gradient(circle at 38% 30%, var(--lava-hi) 0%, transparent 42%),
    linear-gradient(168deg, var(--lava-mint), var(--lava-sage) 35%, var(--lava-sea) 60%, var(--lava-deep));
  background-size: 100% 100%, 150% 150%;
}
.lava-blob.b3 {
  left: 52%; width: 198px; height: 214px;
  --lava-float: 50s; --lava-morph: 17s;
  animation-delay: -22s, -8s, -10s;
  background:
    radial-gradient(circle at 28% 28%, var(--lava-hi) 0%, transparent 44%),
    linear-gradient(135deg, var(--lava-hi), var(--lava-sage) 28%, var(--lava-sea) 52%, var(--lava-teal) 75%, var(--lava-deep));
  background-size: 100% 100%, 150% 150%;
}
.lava-blob.b4 {
  left: 70%; width: 162px; height: 186px;
  --lava-float: 42s; --lava-morph: 14s;
  animation-delay: -6s, -2s, -3s;
  background:
    radial-gradient(circle at 35% 22%, var(--lava-hi) 0%, transparent 40%),
    linear-gradient(160deg, var(--lava-mint), var(--lava-sea) 40%, var(--lava-teal) 70%, var(--lava-deep));
  background-size: 100% 100%, 150% 150%;
}
@keyframes lavaGradShift {
  0%, 100% { background-position: center, 25% 15%; }
  50% { background-position: center, 75% 80%; }
}
.lava-speck {
  position: absolute;
  bottom: 4%;
  display: block;
  border-radius: 50%;
  background:
    radial-gradient(circle at 35% 30%,
      var(--lava-hi) 0%,
      var(--lava-mint) 40%,
      var(--lava-sea) 75%,
      var(--lava-teal) 100%);
  opacity: .72;
  filter: blur(1.2px);
  animation: lavaSpeck var(--speck-dur, 30s) cubic-bezier(0.4, 0.0, 0.2, 1) infinite;
}
.lava-speck.s1 { left: 24%; width: 28px; height: 32px; --speck-dur: 28s; animation-delay: -3s; }
.lava-speck.s2 { left: 46%; width: 22px; height: 26px; --speck-dur: 33s; animation-delay: -11s; }
.lava-speck.s3 { left: 62%; width: 34px; height: 38px; --speck-dur: 31s; animation-delay: -17s; }
.lava-speck.s4 { left: 78%; width: 20px; height: 24px; --speck-dur: 26s; animation-delay: -7s; }
/* Непрерывный цикл: выход из лужи → подъём → сразу спуск → слияние с лужей */
@keyframes lavaFloat {
  0% {
    transform: translate3d(0, 14%, 0) scale(1.22, .72);
  }
  8% {
    transform: translate3d(.3%, 6%, 0) scale(.68, 1.4);
  }
  18% {
    transform: translate3d(-.7%, -12vh, 0) scale(.9, 1.14);
  }
  30% {
    transform: translate3d(.9%, -30vh, 0) scale(.98, 1.04);
  }
  42% {
    transform: translate3d(-.4%, -48vh, 0) scale(1.04, .96);
  }
  50% {
    transform: translate3d(0, -58vh, 0) scale(1.1, .88);
  }
  58% {
    transform: translate3d(.5%, -50vh, 0) scale(.85, 1.2);
  }
  70% {
    transform: translate3d(-.8%, -32vh, 0) scale(.92, 1.1);
  }
  82% {
    transform: translate3d(.4%, -14vh, 0) scale(1.0, 1.0);
  }
  90% {
    transform: translate3d(0, -2vh, 0) scale(.7, 1.35);
  }
  96% {
    transform: translate3d(0, 8%, 0) scale(1.08, .82);
  }
  100% {
    transform: translate3d(0, 14%, 0) scale(1.22, .72);
  }
}
@keyframes lavaMorph {
  0%, 100% { border-radius: 46% 54% 42% 58% / 58% 46% 54% 42%; }
  15% { border-radius: 60% 40% 55% 45% / 40% 60% 40% 60%; }
  30% { border-radius: 40% 60% 48% 52% / 62% 38% 58% 42%; }
  45% { border-radius: 55% 45% 38% 62% / 48% 52% 38% 62%; }
  60% { border-radius: 42% 58% 58% 42% / 55% 45% 55% 45%; }
  75% { border-radius: 58% 42% 45% 55% / 42% 58% 48% 52%; }
  90% { border-radius: 48% 52% 60% 40% / 52% 48% 40% 60%; }
}
@keyframes lavaSpeck {
  0% { transform: translate3d(0, 12%, 0) scale(1.15, .8); opacity: .4; }
  10% { transform: translate3d(1%, 2%, 0) scale(.75, 1.25); opacity: .75; }
  28% { transform: translate3d(2%, -20vh, 0) scale(.92, 1.1); opacity: .8; }
  48% { transform: translate3d(-1.5%, -46vh, 0) scale(1.1, .9); opacity: .75; }
  52% { transform: translate3d(0, -52vh, 0) scale(1.15, .85); opacity: .7; }
  68% { transform: translate3d(1%, -30vh, 0) scale(.88, 1.15); opacity: .8; }
  85% { transform: translate3d(-.5%, -8vh, 0) scale(.72, 1.3); opacity: .65; }
  94% { transform: translate3d(0, 6%, 0) scale(1.05, .88); opacity: .5; }
  100% { transform: translate3d(0, 12%, 0) scale(1.15, .8); opacity: .4; }
}
@media (prefers-reduced-motion: reduce) {
  .lava-blob, .lava-speck, .lava-pool {
    animation: none !important;
    transform: none !important;
    opacity: .55;
  }
  .aurora-band { animation: none !important; }
}

@media (max-width: 560px) {
  .lava-blob.b1 { width: 120px; height: 136px; }
  .lava-blob.b2 { width: 108px; height: 124px; }
  .lava-blob.b3 { width: 132px; height: 148px; }
  .lava-blob.b4 { width: 112px; height: 128px; }
  .lava-speck { transform: scale(.85); }
  .aurora { height: 48vh; opacity: .65; }
}


.wrap { max-width: 1280px; margin: 0 auto; padding: 0 22px; position: relative; z-index: 1; }
a { color: var(--green); }

/* Первый экран отчёта — контент по центру по вертикали */
.first-screen {
  min-height: 100vh;
  display: flex; flex-direction: column; justify-content: center;
  padding: 20px 0 36px; box-sizing: border-box;
  position: relative; z-index: 1;
}
.home-btn {
  position: absolute; top: 12px; left: 12px; z-index: 3;
  display: inline-flex; align-items: center; gap: 5px;
  padding: 5px 11px; border-radius: 999px; text-decoration: none;
  background: var(--panel); border: 1px solid var(--border); color: var(--text);
  font: 650 13px/1.25 Manrope, "Segoe UI", sans-serif;
  letter-spacing: .1px;
  box-shadow: var(--shadow-soft); transition: .15s;
  white-space: nowrap;
}
.home-btn:hover {
  border-color: var(--green); color: var(--green-dark);
  box-shadow: 0 8px 20px rgba(47,143,99,.18); transform: translateY(-1px);
}
.topbar {
  position: relative; z-index: 2;
  display: flex; justify-content: center; width: 100%;
  margin: 0 0 10px; padding: 4px 22px 0; box-sizing: border-box;
}
.report-intro {
  display: flex; flex-direction: column; align-items: center;
  text-align: center; max-width: 760px; width: 100%;
  box-sizing: border-box;
}
.report-intro .brand { margin: 0 0 8px; justify-content: center; }
.report-intro h1 { margin: 0; }
.report-intro .target { margin: 6px 0 0; }

/* ---------- шапка с диаграммой ---------- */
header { position: relative; overflow: visible; padding: 8px 0 18px; z-index: 1; }
.hero { position: relative; z-index: 1; }
.hero-main > h2 { margin-top: 0; }
.hero-align {
  display: grid; grid-template-columns: minmax(300px, 360px) 1fr; gap: 28px;
  align-items: start;
}
@media (max-width: 900px) {
  .hero-align { grid-template-columns: 1fr; }
  .chart-card { margin-top: 0 !important; margin-bottom: 0 !important; height: auto !important; }
}

.chart-card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 22px;
  padding: 16px 18px 12px; box-shadow: 0 10px 18px rgba(22, 70, 48, .12);
  box-sizing: border-box; display: flex; flex-direction: column; min-height: 0;
  width: 100%;
}
.chart-card h3 { margin: 0 0 4px; font-size: 13px; color: var(--muted); font-weight: 700;
  text-transform: uppercase; letter-spacing: .5px; text-align: center; flex: none; }
.chart-card .tip { margin: 0 0 8px; font-size: 12px; color: var(--muted); text-align: center;
  flex: none; }
.chart-card .donut-wrap {
  flex: 1 1 auto; display: flex; align-items: center; justify-content: center;
  min-height: 180px; margin: 4px 0;
}
.donut { display: block; width: min(100%, 300px); height: auto; aspect-ratio: 1; }
.donut circle.seg { cursor: pointer; transition: opacity .15s; }
.donut circle.seg:hover { opacity: .75; }
.donut-total { font: 800 42px Manrope, "Segoe UI", sans-serif; fill: var(--text); }
.donut-caption { font: 600 12.5px Manrope, "Segoe UI", sans-serif; fill: var(--muted);
  letter-spacing: .4px; }
.legend { margin: 8px 0 0; padding: 0; list-style: none; flex: none; }
.legend li { border-top: 1px dashed var(--border); }
.legend li:first-child { border-top: none; }
.legend button {
  display: flex; align-items: center; gap: 9px; width: 100%; padding: 7px 6px;
  background: none; border: none; border-radius: 10px; cursor: pointer; text-align: left;
  font: inherit; font-size: 13.5px; color: var(--text); transition: background .15s;
}
.legend button:hover { background: var(--panel-2); }
.legend button:focus-visible { outline: 2px solid var(--green); }
.legend button[disabled] { cursor: default; opacity: .55; }
.legend button[disabled]:hover { background: none; }
.legend .dot { width: 11px; height: 11px; border-radius: 999px; flex: none; }
.legend .name { flex: 1; }
.legend .val { font-weight: 700; }
.legend .pct { color: var(--muted); font-size: 12.5px; min-width: 42px; text-align: right; }

.brand { display: flex; align-items: center; gap: 10px; color: var(--iron);
  font-size: 13px; letter-spacing: .6px; text-transform: uppercase; font-weight: 700; }
h1 { margin: 6px 0 5px; font-size: 26px; line-height: 1.25; letter-spacing: .2px;
  color: var(--green-dark); font-weight: 800; }
.target { font-size: 14.5px; color: var(--muted); margin-bottom: 4px; }
.target b { color: var(--text); }
h2 { font-size: 19px; margin: 18px 0 10px; color: var(--green-dark); font-weight: 800;
  display: flex; align-items: center; gap: 9px; }
h2 .ico { flex: none; opacity: .8; }
.section-note { margin: -4px 0 12px; color: var(--muted); font-size: 13.5px; }

/* ---------- общая статистика ---------- */
.stats-body { min-width: 0; }
.stat-group { margin-bottom: 10px; }
.stat-group:last-child { margin-bottom: 0; }
.stat-group > h3 {
  margin: 0 0 6px; font-size: 12px; line-height: 1.25; text-transform: uppercase;
  letter-spacing: .7px; color: var(--muted); font-weight: 700;
}
.cards { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(158px, 1fr)); }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 16px;
  padding: 10px 14px 11px; text-align: left; font-family: inherit; color: var(--text);
  box-shadow: var(--shadow-soft); }
.card .num { font-size: 22px; font-weight: 800; color: var(--green-dark); line-height: 1.25; }
.card .num small { font-size: 14px; font-weight: 600; color: var(--muted); }
.card .lbl { color: var(--text); font-size: 13px; margin-top: 1px; font-weight: 600; }
.card .sub { color: var(--muted); font-size: 11.5px; margin-top: 3px; line-height: 1.35; }
.card .go { color: var(--high); font-size: 12px; margin-top: 4px; font-weight: 700; }
.card.accent { background: var(--mint); border-color: var(--mint-deep); }
.card.alarm { border-color: #E8C4BB; background: #FDF6F4; }
.card.alarm .num { color: var(--high); }
.card.alarm.strong { border-width: 2px; border-color: var(--high); background: #FBEDE9;
  box-shadow: 0 2px 10px rgba(180,80,60,.14); }
button.card { cursor: pointer; width: 100%; transition: transform .15s, box-shadow .15s; }
button.card:hover { transform: translateY(-1px); box-shadow: 0 8px 18px rgba(180,80,60,.18); }
.bar { height: 5px; border-radius: 99px; background: var(--panel-2); margin-top: 7px;
  overflow: hidden; border: 1px solid var(--border); }
.bar span { display: block; height: 100%; background: var(--green); }

/* ---------- карточки-разделы (открывают боковую панель) ---------- */
.nav-cards { display: grid; gap: 12px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
.nav-card { display: block; text-align: left; font-family: inherit; cursor: pointer;
  background: var(--panel); border: 1px solid var(--border); border-radius: 18px;
  padding: 13px 15px 12px; color: var(--text); box-shadow: var(--shadow-soft);
  transition: transform .15s, box-shadow .15s, border-color .15s; }
.nav-card:hover { transform: translateY(-2px); box-shadow: var(--shadow);
  border-color: var(--green); }
.nav-card .nav-n { font-size: 21px; font-weight: 800; color: var(--green-dark); }
.nav-card .nav-t { display: block; font-weight: 700; font-size: 14.5px; margin-top: 1px; }
.nav-card .nav-s { display: block; color: var(--muted); font-size: 12px; margin-top: 3px;
  line-height: 1.35; }
.nav-card .nav-go { display: block; color: var(--green); font-size: 12.5px; margin-top: 6px;
  font-weight: 650; }
.nav-card.pdf { background: var(--mint); border-color: var(--mint-deep); }
.nav-card.pdf .nav-t { color: var(--green-dark); }

/* ---------- боковая выпадающая панель ---------- */
.backdrop { position: fixed; inset: 0; background: rgba(27, 70, 48, .28); z-index: 30;
  opacity: 0; visibility: hidden; transition: opacity .22s, visibility .22s; }
.backdrop.open { opacity: 1; visibility: visible; }
.drawer { position: fixed; top: 0; right: 0; height: 100vh; width: min(1180px, 95vw);
  background: var(--bg-top); border-left: 1px solid var(--border); z-index: 31;
  box-shadow: -16px 0 40px rgba(27,70,48,.18); display: flex; flex-direction: column;
  transform: translateX(101%); transition: transform .26s ease; }
.drawer.open { transform: none; }
.drawer-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 11px 16px; background: var(--panel); border-bottom: 1px solid var(--border); }
.tab { background: var(--panel); border: 1px solid var(--border); border-radius: 999px;
  padding: 7px 14px; font: inherit; font-size: 13px; color: var(--text); cursor: pointer;
  transition: .15s; font-weight: 600; }
.tab:hover { border-color: var(--green); color: var(--green-dark); }
.tab.active { background: var(--green); border-color: var(--green); color: #fff; }
.tab .n { opacity: .7; font-size: 12px; }
.tab.active .n { opacity: .85; }
.drawer-close { margin-left: auto; background: var(--panel); border: 1px solid var(--border);
  border-radius: 999px; width: 34px; height: 34px; font-size: 17px; line-height: 1; cursor: pointer;
  color: var(--muted); font-family: inherit; }
.drawer-close:hover { border-color: var(--high); color: var(--high); }
.drawer-body { flex: 1; overflow: auto; padding: 4px 22px 40px; }
.drawer-body h2:first-child { margin-top: 14px; }
.panel[hidden] { display: none; }

/* ---------- пояснения ---------- */
.legend-help { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.help-item { background: var(--panel); border: 1px solid var(--border);
  border-left: 4px solid var(--iron-light); border-radius: 14px; padding: 10px 14px;
  font-size: 13.5px; text-align: left; font-family: inherit; color: var(--text);
  box-shadow: var(--shadow-soft); }
button.help-item { cursor: pointer; transition: box-shadow .15s, transform .15s; }
button.help-item:hover { box-shadow: var(--shadow); transform: translateY(-1px); }
.help-item.high { border-left-color: var(--high); }
.help-item.medium { border-left-color: var(--medium); }
.help-item.low { border-left-color: var(--low); }
.help-item.info { border-left-color: var(--safe); }
.help-item b { display: block; margin-bottom: 2px; }
.help-item span { color: var(--muted); }
.help-item .go { display: block; margin-top: 4px; color: var(--green); font-size: 12.5px; }

/* ---------- фильтры ---------- */
.filters { background: var(--panel); border: 1px solid var(--border); border-radius: 18px;
  padding: 12px 14px; margin-bottom: 12px; box-shadow: var(--shadow-soft); }
.filter-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.filter-row + .filter-row { margin-top: 9px; padding-top: 9px; border-top: 1px dashed var(--border); }
.filter-row .cap { font-size: 12px; text-transform: uppercase; letter-spacing: .6px;
  color: var(--muted); font-weight: 700; min-width: 92px; }
button.f { background: var(--panel); color: var(--text); border: 1px solid var(--border);
  padding: 7px 14px; border-radius: 999px; cursor: pointer; font-size: 13px; transition: .15s;
  font-family: inherit; font-weight: 600; }
button.f:hover { border-color: var(--green); color: var(--green-dark); }
button.f.active { background: var(--green); border-color: var(--green); color: #fff; }
button.f .n { opacity: .7; font-size: 12px; }
button.f.active .n { opacity: .85; }
button.f.wide { font-weight: 700; }
input[type=search] { flex: 1; min-width: 230px; background: var(--panel); color: var(--text);
  border: 1px solid var(--border); border-radius: 999px; padding: 8px 16px; font-size: 14px;
  font-family: inherit; box-shadow: inset 0 1px 2px rgba(27,70,48,.04); }
input[type=search]:focus { outline: 2px solid rgba(47,143,99,.22); border-color: var(--green); }
.hint { color: var(--muted); font-size: 13px; margin: 0 0 10px; }
.hint b { color: var(--text); }

/* ---------- таблица ---------- */
table { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--border); border-radius: 18px; overflow: hidden; font-size: 14px;
  box-shadow: var(--shadow-soft); }
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
  font-weight: 700; white-space: nowrap; color: #fff; }
.sev-high { background: var(--high); }
.sev-medium { background: var(--medium); }
.sev-low { background: var(--low); }
.sev-info { background: var(--safe); }
.threat { display: inline-block; background: var(--mint); border: 1px solid var(--mint-deep);
  color: var(--green-dark); border-radius: 999px; padding: 2px 10px; font-size: 12.5px;
  font-weight: 650; }
.cat { color: var(--muted); font-size: 13px; }
.nowrap { white-space: nowrap; }
.url { word-break: break-all; color: var(--green); font-size: 13px; }
a.url { text-decoration: none; border-bottom: 1px dotted var(--mint-deep); }
a.url:hover { text-decoration: none; border-bottom-color: var(--green); background: var(--mint); }
.title { font-weight: 700; }
.conf { font-size: 12.5px; color: var(--muted); white-space: nowrap; }
.conf.sus { color: var(--medium); }
.conf.yes { color: var(--high); font-weight: 700; }
.toggle { background: none; border: none; color: var(--green); cursor: pointer;
  font-size: 13px; padding: 0; text-decoration: underline dotted; white-space: nowrap;
  font-family: inherit; font-weight: 650; }
.lines { margin: 0; padding-left: 18px; }
.lines li { margin: 2px 0; }

/* ---------- подробности ---------- */
.det { display: grid; gap: 12px; grid-template-columns: 1fr 1fr; padding: 4px 0 8px; }
@media (max-width: 860px) { .det { grid-template-columns: 1fr; } }
.det .full { grid-column: 1 / -1; }
.det .fix-steps { margin: 0; padding-left: 1.3em; }
.det .fix-steps li { margin: 0 0 8px; line-height: 1.45; }
.det .fix-steps li:last-child { margin-bottom: 0; }
.det .fix-cap {
  margin: 12px 0 6px; font-size: 12.5px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .4px; color: var(--green-dark);
}
.det .fix-steps.verify { border-left: 3px solid var(--mint-deep); padding-left: 1em; margin-left: 2px; }
.det .giga-actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
  margin-top: 12px; padding-top: 10px; border-top: 1px dashed var(--border); }
button.giga-btn {
  background: var(--green); color: #fff; border: 1px solid var(--green-dark);
  border-radius: 999px; padding: 8px 16px; font: inherit; font-size: 13.5px; font-weight: 700;
  cursor: pointer; box-shadow: var(--shadow-soft); transition: .15s;
}
button.giga-btn:hover { background: var(--green-dark); transform: translateY(-1px); }
.giga-actions .giga-hint { color: var(--muted); font-size: 12.5px; }
.repeat { display: inline-block; margin-left: 8px; padding: 2px 9px; border-radius: 999px;
  background: var(--mint); border: 1px solid var(--mint-deep); color: var(--green-dark);
  font-size: 12px; font-weight: 750; white-space: nowrap; vertical-align: middle; }
.case-list { display: grid; gap: 8px; }
.case-item { background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  box-shadow: var(--shadow-soft); overflow: hidden; }
.case-item > summary {
  display: grid; grid-template-columns: 120px minmax(140px, 1.4fr) minmax(110px, .9fr) auto;
  gap: 10px; align-items: center; list-style: none; cursor: pointer;
  padding: 10px 12px; font-size: 13.5px;
}
.case-item > summary::-webkit-details-marker { display: none; }
.case-item > summary:hover { background: var(--panel-2); }
.case-item[open] > summary { border-bottom: 1px solid var(--border); background: var(--mint); }
.case-conf { font-weight: 700; white-space: nowrap; }
.case-conf.yes { color: var(--high); }
.case-conf.sus { color: var(--medium); }
.case-cat { color: var(--muted); font-size: 13px; }
.case-more { color: var(--green); font-weight: 650; text-decoration: underline dotted;
  white-space: nowrap; justify-self: end; }
.case-item[open] .case-more { color: var(--green-dark); }
.case-item .case-more::after { content: "подробнее"; }
.case-item[open] .case-more::after { content: "свернуть"; }
.case-extra { padding: 10px 12px 12px; display: grid; gap: 10px;
  grid-template-columns: 1fr 1fr; }
@media (max-width: 860px) {
  .case-item > summary { grid-template-columns: 1fr; gap: 4px; }
  .case-more { justify-self: start; }
  .case-extra { grid-template-columns: 1fr; }
}
.case-extra h5 { margin: 0 0 4px; font-size: 12px; text-transform: uppercase;
  letter-spacing: .4px; color: var(--muted); font-weight: 700; }
.case-extra pre { max-height: 180px; }
button.f.pdf-filter {
  background: var(--mint); border-color: var(--mint-deep); color: var(--green-dark);
  font-weight: 700;
}
button.f.pdf-filter:hover { border-color: var(--green); color: var(--green-dark); }
.block { background: var(--panel); border: 1px solid var(--border); border-radius: 14px;
  padding: 12px 14px; box-shadow: var(--shadow-soft); }
.block.danger { border-left: 4px solid var(--high); }
.block.logic { border-left: 4px solid var(--iron); }
.block.fix { border-left: 4px solid var(--safe); background: #F6FBF8; }
.block h4 { margin: 0 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .5px;
  color: var(--muted); font-weight: 700; }
.block p { margin: 0; font-size: 14px; }
pre { margin: 0; padding: 10px 12px; background: #F7FAF8; border: 1px solid var(--border);
  border-radius: 12px; white-space: pre-wrap; word-break: break-word; color: #33403A;
  font: 12.5px/1.5 Consolas, "Courier New", monospace; max-height: 260px; overflow: auto; }

/* ---------- диалог ГигаЧат ---------- */
.giga-backdrop { position: fixed; inset: 0; background: rgba(27, 70, 48, .38); z-index: 40;
  opacity: 0; visibility: hidden; transition: opacity .2s, visibility .2s; }
.giga-backdrop.open { opacity: 1; visibility: visible; }
.giga-dialog { position: fixed; z-index: 41; top: 50%; left: 50%; width: min(560px, 94vw);
  max-height: min(82vh, 720px); transform: translate(-50%, -46%) scale(.97);
  background: var(--bg-top); border: 1px solid var(--border); border-radius: 18px;
  box-shadow: 0 22px 50px rgba(27,70,48,.28); display: flex; flex-direction: column;
  opacity: 0; visibility: hidden; transition: .2s ease; }
.giga-dialog.open { opacity: 1; visibility: visible; transform: translate(-50%, -50%) scale(1); }
.giga-head { display: flex; align-items: flex-start; gap: 10px; padding: 14px 16px;
  border-bottom: 1px solid var(--border); background: var(--panel); border-radius: 18px 18px 0 0; }
.giga-head .giga-title { font-weight: 800; font-size: 16px; color: var(--green-dark); margin: 0; }
.giga-head .giga-sub { display: block; color: var(--muted); font-size: 12.5px; margin-top: 3px;
  line-height: 1.35; }
.giga-head .giga-warn { display: block; color: var(--muted); font-size: 11px; margin-top: 6px;
  line-height: 1.4; opacity: .92; }
.giga-head .giga-close { margin-left: auto; background: var(--panel); border: 1px solid var(--border);
  border-radius: 999px; width: 34px; height: 34px; font-size: 17px; line-height: 1; cursor: pointer;
  color: var(--muted); font-family: inherit; flex-shrink: 0; }
.giga-head .giga-close:hover { border-color: var(--high); color: var(--high); }
.giga-finding { margin: 0; padding: 10px 16px; font-size: 13px; color: var(--text);
  background: var(--mint); border-bottom: 1px solid var(--mint-deep); }
.giga-finding b { color: var(--green-dark); }
.giga-messages { flex: 1; overflow: auto; padding: 14px 16px; display: flex; flex-direction: column;
  gap: 10px; min-height: 220px; background: var(--panel-2); }
.giga-msg { max-width: 92%; padding: 10px 12px; border-radius: 14px; font-size: 14px;
  line-height: 1.45; white-space: pre-wrap; word-break: break-word; }
.giga-msg.bot { align-self: flex-start; background: var(--panel); border: 1px solid var(--border);
  border-left: 3px solid var(--green); }
.giga-msg.user { align-self: flex-end; background: var(--mint); border: 1px solid var(--mint-deep);
  color: var(--green-dark); }
.giga-msg.err { align-self: stretch; background: #FDF6F4; border: 1px solid #E8C4B8;
  border-left: 3px solid var(--high); color: #8E3A2A; }
.giga-msg.busy { opacity: .75; font-style: italic; }
.giga-form { display: flex; gap: 8px; padding: 12px 16px; border-top: 1px solid var(--border);
  background: var(--panel); border-radius: 0 0 18px 18px; }
.giga-form textarea { flex: 1; min-height: 44px; max-height: 110px; resize: vertical;
  border: 1px solid var(--border); border-radius: 12px; padding: 10px 12px; font: inherit;
  font-size: 14px; background: var(--bg-top); color: var(--text); }
.giga-form textarea:focus { outline: 2px solid rgba(47,143,99,.22); border-color: var(--green); }
.giga-form button { background: var(--green); color: #fff; border: 1px solid var(--green-dark);
  border-radius: 12px; padding: 0 16px; font: inherit; font-weight: 700; cursor: pointer;
  white-space: nowrap; }
.giga-form button:disabled { opacity: .55; cursor: wait; }
.giga-form button:hover:not(:disabled) { background: var(--green-dark); }
.giga-tools { display: flex; gap: 8px; padding: 0 16px 10px; background: var(--panel); }
.giga-tools button { background: transparent; border: 1px solid var(--border); color: var(--muted);
  border-radius: 999px; padding: 5px 12px; font: inherit; font-size: 12.5px; cursor: pointer; }
.giga-tools button:hover { border-color: var(--high); color: var(--high); }

.empty { padding: 24px; text-align: center; color: var(--muted); background: var(--panel);
  border: 1px solid var(--border); border-radius: 18px; box-shadow: var(--shadow-soft); }
.note { background: var(--panel); border: 1px solid var(--border);
  border-left: 4px solid var(--iron); border-radius: 14px; padding: 10px 15px;
  color: var(--muted); font-size: 13.5px; margin-bottom: 8px; box-shadow: var(--shadow-soft); }
footer { margin-top: 20px; color: var(--muted); font-size: 12.5px; text-align: center;
  display: flex; align-items: center; justify-content: center; gap: 10px; flex-wrap: wrap; }

/* ---------- печатная версия (сохранение в PDF) ---------- */
#pdf-report, #pdf-filtered { display: none; }
@media print {
  .atmosphere, .lava-lamp, .lava-blob, .lava-pool, .lava-goo, .lava-heat, .lava-speck, .aurora, .aurora-band { display: none !important; }
  @page { size: A4; margin: 12mm; }
  body { background: #FFFFFF !important; padding: 0; }
  body::before { display: none !important; }
  body > *:not(#pdf-report):not(#pdf-filtered) { display: none !important; }
  body.print-filtered #pdf-report { display: none !important; }
  body.print-filtered #pdf-filtered { display: block !important; }
  body:not(.print-filtered) #pdf-report { display: block !important; }
  body:not(.print-filtered) #pdf-filtered { display: none !important; }
}
#pdf-report h1, #pdf-filtered h1 { font-size: 20px; margin: 0 0 2px; color: var(--green-dark); }
#pdf-report h2, #pdf-filtered h2 { font-size: 15px; margin: 16px 0 6px; display: block; }
#pdf-report .pdf-sub, #pdf-filtered .pdf-sub { margin: 0 0 12px; color: var(--muted); font-size: 12px; }
#pdf-report table, #pdf-filtered table { font-size: 11.5px; border-radius: 0; page-break-inside: auto; box-shadow: none; }
#pdf-report th, #pdf-report td, #pdf-filtered th, #pdf-filtered td { padding: 5px 7px; }
#pdf-report thead, #pdf-filtered thead { display: table-header-group; }
#pdf-report tr, #pdf-filtered tr { page-break-inside: avoid; }
#pdf-report .kv, #pdf-filtered .kv { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 6px; }
#pdf-report .kv div, #pdf-filtered .kv div { border: 1px solid var(--border); border-radius: 8px; padding: 5px 10px;
  font-size: 11.5px; }
#pdf-report .kv b, #pdf-filtered .kv b { font-size: 15px; display: block; color: var(--green-dark); }
#pdf-report .kv.alarm b, #pdf-filtered .kv.alarm b { color: var(--high); }
#pdf-report .pdf-foot, #pdf-filtered .pdf-foot { font-size: 10.5px; color: var(--muted); margin-top: 14px; }
#pdf-report .crit td, #pdf-filtered .crit td { background: #FDF6F4; }
#pdf-filtered .steps { margin: 4px 0 0; padding-left: 1.1em; font-size: 11px; }
#pdf-filtered .steps li { margin: 0 0 3px; }
"""

JS = """
function currentFilters() {
  var confBtn = document.querySelector('button.f.conf-f.active');
  return {
    sev: document.querySelector('button.f.sev.active').dataset.value,
    cat: document.querySelector('button.f.cat-f.active').dataset.value,
    conf: confBtn ? confBtn.dataset.value : 'all',
    q: document.getElementById('q').value.trim().toLowerCase()
  };
}
function applyFilters() {
  var f = currentFilters();
  var shown = 0;
  document.querySelectorAll('tr.f-row').forEach(function (row) {
    var sevOk = f.sev === 'all'
      || (f.sev === 'attention'
          ? (row.dataset.severity === 'High' || row.dataset.severity === 'Medium')
          : row.dataset.severity === f.sev);
    var visible = sevOk
      && (f.cat === 'all' || row.dataset.category === f.cat)
      && (f.conf === 'all' || row.dataset.confidence === f.conf)
      && (f.q === '' || row.dataset.search.indexOf(f.q) !== -1);
    row.style.display = visible ? '' : 'none';
    if (!visible) { closeRow(row); }
    if (visible) { shown++; }
  });
  document.getElementById('shown').textContent = shown;
  var empty = document.getElementById('nothing');
  if (empty) { empty.style.display = shown ? 'none' : ''; }
  refreshToggleAll();
  var pdfBtn = document.getElementById('pdf-filtered-btn');
  if (pdfBtn) { pdfBtn.disabled = shown === 0; }
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
  if (!document.getElementById('giga-dialog') ||
      !document.getElementById('giga-dialog').classList.contains('open')) {
    document.body.classList.remove('locked');
  }
}
var gigaState = { history: [], context: null, busy: false, storageKey: '' };
var GIGA_GREETING = 'Здравствуйте! Я ГигаЧат — эксперт по информационной безопасности. '
  + 'Могу разобрать эту находку, объяснить риск и подсказать, как исправить. '
  + 'Задайте вопрос или нажмите «Спросить про эту находку».';
function gigaStorageKey(title) {
  var target = document.body.dataset.target || '';
  return 'spyvision-giga:' + target + '|' + (title || '');
}
function loadGigaHistory(key) {
  try {
    var raw = localStorage.getItem(key);
    if (!raw) { return []; }
    var parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) { return []; }
    return parsed.filter(function (item) {
      return item && (item.role === 'user' || item.role === 'assistant')
        && typeof item.content === 'string' && item.content.trim();
    }).slice(-40);
  } catch (e) { return []; }
}
function saveGigaHistory() {
  if (!gigaState.storageKey) { return; }
  try {
    localStorage.setItem(gigaState.storageKey, JSON.stringify(gigaState.history.slice(-40)));
  } catch (e) { /* quota / private mode */ }
}
function renderGigaHistory() {
  var box = document.getElementById('giga-messages');
  if (!box) { return; }
  box.innerHTML = '';
  if (!gigaState.history.length) {
    appendGigaMsg('bot', GIGA_GREETING);
    return;
  }
  gigaState.history.forEach(function (item) {
    appendGigaMsg(item.role === 'user' ? 'user' : 'bot', item.content);
  });
}
function openGigaChat(button) {
  var dialog = document.getElementById('giga-dialog');
  var backdrop = document.getElementById('giga-backdrop');
  if (!dialog || !backdrop) { return; }
  saveGigaHistory();
  gigaState.context = {
    title: button.getAttribute('data-title') || '',
    severity: button.getAttribute('data-severity') || '',
    url: button.getAttribute('data-url') || '',
    threat_type: button.getAttribute('data-threat') || '',
    impact: button.getAttribute('data-impact') || '',
    detection: button.getAttribute('data-detection') || '',
    request: button.getAttribute('data-request') || '',
    evidence: button.getAttribute('data-evidence') || '',
    recommendation: button.getAttribute('data-recommendation') || ''
  };
  gigaState.storageKey = gigaStorageKey(gigaState.context.title);
  gigaState.history = loadGigaHistory(gigaState.storageKey);
  var findingEl = document.getElementById('giga-finding');
  if (findingEl) {
    findingEl.innerHTML = '<b>' + escHtml(gigaState.context.title || 'Находка') + '</b>'
      + (gigaState.context.severity ? ' · ' + escHtml(gigaState.context.severity) : '')
      + (gigaState.context.url ? '<br><span class="url">' + escHtml(gigaState.context.url) + '</span>' : '');
  }
  renderGigaHistory();
  var input = document.getElementById('giga-input');
  if (input) { input.value = ''; }
  dialog.classList.add('open');
  dialog.setAttribute('aria-hidden', 'false');
  backdrop.classList.add('open');
  document.body.classList.add('locked');
  if (input) { setTimeout(function () { input.focus(); }, 80); }
}
function closeGigaChat() {
  saveGigaHistory();
  var dialog = document.getElementById('giga-dialog');
  var backdrop = document.getElementById('giga-backdrop');
  if (dialog) {
    dialog.classList.remove('open');
    dialog.setAttribute('aria-hidden', 'true');
  }
  if (backdrop) { backdrop.classList.remove('open'); }
  var drawer = document.getElementById('drawer');
  if (!drawer || !drawer.classList.contains('open')) {
    document.body.classList.remove('locked');
  }
}
function clearGigaHistory() {
  if (gigaState.busy) { return; }
  gigaState.history = [];
  saveGigaHistory();
  renderGigaHistory();
}
function appendGigaMsg(kind, text) {
  var box = document.getElementById('giga-messages');
  if (!box) { return null; }
  var el = document.createElement('div');
  el.className = 'giga-msg ' + kind;
  el.textContent = text;
  box.appendChild(el);
  box.scrollTop = box.scrollHeight;
  return el;
}
function setGigaBusy(busy) {
  gigaState.busy = busy;
  var send = document.getElementById('giga-send');
  var ask = document.getElementById('giga-ask-finding');
  var clear = document.getElementById('giga-clear');
  var input = document.getElementById('giga-input');
  if (send) { send.disabled = busy; }
  if (ask) { ask.disabled = busy; }
  if (clear) { clear.disabled = busy; }
  if (input) { input.disabled = busy; }
}
function sendGigaChat(message) {
  var text = String(message || '').trim();
  if (!text || gigaState.busy) { return; }
  if (location.protocol === 'file:') {
    appendGigaMsg('err',
      'Диалог GigaChat работает только через локальный сервер Spyvision '
      + '(python scan.py → откройте отчёт по ссылке http://127.0.0.1:…/report.html), '
      + 'а не из файла report.html на диске.');
    return;
  }
  appendGigaMsg('user', text);
  gigaState.history.push({ role: 'user', content: text });
  saveGigaHistory();
  var busyEl = appendGigaMsg('bot busy', 'ГигаЧат думает…');
  setGigaBusy(true);
  fetch('/api/gigachat-chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      message: text,
      history: gigaState.history.slice(0, -1),
      context: gigaState.context || {}
    })
  }).then(function (res) {
    return res.json().then(function (data) {
      return { okHttp: res.ok, data: data };
    });
  }).then(function (result) {
    if (busyEl && busyEl.parentNode) { busyEl.parentNode.removeChild(busyEl); }
    var data = result.data || {};
    if (!result.okHttp || !data.ok) {
      appendGigaMsg('err', data.error || 'Не удалось получить ответ GigaChat.');
      saveGigaHistory();
      return;
    }
    var reply = data.reply || '';
    appendGigaMsg('bot', reply);
    gigaState.history.push({ role: 'assistant', content: reply });
    saveGigaHistory();
  }).catch(function (err) {
    if (busyEl && busyEl.parentNode) { busyEl.parentNode.removeChild(busyEl); }
    appendGigaMsg('err',
      'Ошибка сети при обращении к /api/gigachat-chat. '
      + 'Убедитесь, что отчёт открыт через локальный сервер Spyvision. '
      + (err && err.message ? err.message : ''));
  }).finally(function () { setGigaBusy(false); });
}
function showSeverity(value) {
  selectButton('button.f.sev', value);
  selectButton('button.f.cat-f', 'all');
  selectButton('button.f.conf-f', 'all');
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
  selectButton('button.f.conf-f', 'all');
  document.getElementById('q').value = '';
  applyFilters();
}
function escHtml(text) {
  return String(text == null ? '' : text)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function printFiltered() {
  var rows = visibleRows();
  var box = document.getElementById('pdf-filtered');
  if (!box) { return; }
  if (!rows.length) { return; }
  var f = currentFilters();
  var filterBits = [];
  if (f.sev !== 'all') {
    filterBits.push(f.sev === 'attention' ? 'требуют внимания (высокая+средняя)' : ('уровень: ' + f.sev));
  }
  if (f.cat !== 'all') { filterBits.push('категория: ' + f.cat); }
  if (f.conf !== 'all') { filterBits.push('точность: ' + f.conf); }
  if (f.q) { filterBits.push('поиск: «' + f.q + '»'); }
  var filterText = filterBits.length ? filterBits.join(' · ') : 'без дополнительных ограничений';
  var target = document.body.dataset.target || '';
  var generated = document.body.dataset.generated || '';
  var html = '<h1>Отчёт по текущему фильтру</h1>'
    + '<p class="pdf-sub">Цель: ' + escHtml(target) + ' · сформирован ' + escHtml(generated)
    + ' · записей: ' + rows.length + ' · фильтр: ' + escHtml(filterText) + '</p>'
    + '<div class="kv"><div><b>' + rows.length + '</b>Записей в PDF</div></div>'
    + '<table><thead><tr><th>Уровень</th><th>Что нашли</th><th>Где нашли</th>'
    + '<th>Точность</th><th>Как исправить</th></tr></thead><tbody>';
  rows.forEach(function (row) {
    var steps = [];
    try { steps = JSON.parse(row.dataset.steps || '[]'); } catch (e) { steps = []; }
    var stepsHtml = '';
    if (steps && steps.length) {
      stepsHtml = '<ol class="steps">' + steps.map(function (s) {
        return '<li>' + escHtml(s) + '</li>';
      }).join('') + '</ol>';
    } else {
      stepsHtml = escHtml(row.dataset.recommendation || '—');
    }
    var count = parseInt(row.dataset.count || '1', 10) || 1;
    var title = row.dataset.title || '';
    if (count > 1) { title = title + ' (×' + count + ')'; }
    html += '<tr><td>' + escHtml(row.dataset.severityLabel || row.dataset.severity) + '</td>'
      + '<td>' + escHtml(title) + '</td>'
      + '<td>' + escHtml(row.dataset.url || '') + '</td>'
      + '<td>' + escHtml(row.dataset.confidence || '') + '</td>'
      + '<td>' + stepsHtml + '</td></tr>';
  });
  html += '</tbody></table>'
    + '<p class="pdf-foot">В PDF попали только записи, видимые при текущем фильтре в разделе '
    + '«Найденные проблемы». Полные доказательства и логика проверок — в HTML-версии отчёта.</p>';
  box.innerHTML = html;
  document.body.classList.add('print-filtered');
  window.print();
  setTimeout(function () { document.body.classList.remove('print-filtered'); }, 500);
}
function chartShadowBottomExtent(el) {
  var sh = getComputedStyle(el).boxShadow || '';
  if (!sh || sh === 'none') { return 0; }
  var parts = sh.match(/-?[\d.]+px/g);
  if (!parts || parts.length < 3) { return 10; }
  var y = parseFloat(parts[1]) || 0;
  var blur = parseFloat(parts[2]) || 0;
  var spread = parts.length > 3 ? (parseFloat(parts[3]) || 0) : 0;
  // Нижняя видимая граница тени ≈ смещение + размытие + spread
  return Math.max(0, y + blur + spread);
}
function syncChartToStats() {
  var align = document.querySelector('.hero-align');
  var chart = document.querySelector('.chart-card');
  var firstCard = document.querySelector('.stats-body .stat-group:first-child .card');
  var reqLbl = null;
  document.querySelectorAll('.stats-body .card .lbl').forEach(function (el) {
    if (el.textContent.trim() === 'Запросов к сайту') { reqLbl = el; }
  });
  var reqCard = reqLbl ? reqLbl.closest('.card') : null;
  if (!align || !chart || !firstCard || !reqCard || window.matchMedia('(max-width: 900px)').matches) {
    if (chart) {
      chart.style.marginTop = '';
      chart.style.height = '';
    }
    return;
  }
  chart.style.marginTop = '0px';
  chart.style.height = 'auto';
  var alignBox = align.getBoundingClientRect();
  var firstTop = firstCard.getBoundingClientRect().top;
  var reqBottom = reqCard.getBoundingClientRect().bottom;
  var shadowExtent = chartShadowBottomExtent(chart);
  var topGap = Math.max(0, firstTop - alignBox.top);
  var targetHeight = Math.max(120, Math.round(reqBottom - firstTop - shadowExtent));
  chart.style.marginTop = Math.round(topGap) + 'px';
  chart.style.height = targetHeight + 'px';
}
document.addEventListener('DOMContentLoaded', function () {
  initGroup('button.f.sev');
  initGroup('button.f.cat-f');
  initGroup('button.f.conf-f');
  document.getElementById('q').addEventListener('input', applyFilters);
  document.getElementById('toggle-all').addEventListener('click', toggleAll);
  var pdfFilteredBtn = document.getElementById('pdf-filtered-btn');
  if (pdfFilteredBtn) { pdfFilteredBtn.addEventListener('click', printFiltered); }
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
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      var giga = document.getElementById('giga-dialog');
      if (giga && giga.classList.contains('open')) { closeGigaChat(); return; }
      closePanel();
    }
  });
  document.querySelectorAll('[data-severity-link]').forEach(function (element) {
    element.addEventListener('click', function () {
      showSeverity(element.dataset.severityLink);
    });
  });
  document.querySelectorAll('tr.f-row').forEach(function (row) {
    row.addEventListener('click', function (event) {
      // клик по ссылке открывает адрес, у кнопки «подробнее» свой обработчик
      if (event.target.closest('a') || event.target.closest('.toggle')
          || event.target.closest('.giga-btn')) { return; }
      setRow(row, !isOpen(row));
      refreshToggleAll();
    });
  });
  document.querySelectorAll('.giga-btn').forEach(function (btn) {
    btn.addEventListener('click', function (event) {
      event.preventDefault();
      event.stopPropagation();
      openGigaChat(btn);
    });
  });
  document.querySelectorAll('.case-item summary a').forEach(function (link) {
    link.addEventListener('click', function (event) { event.stopPropagation(); });
  });
  var gigaClose = document.querySelectorAll('[data-giga-close]');
  gigaClose.forEach(function (el) {
    el.addEventListener('click', closeGigaChat);
  });
  var gigaForm = document.getElementById('giga-form');
  if (gigaForm) {
    gigaForm.addEventListener('submit', function (event) {
      event.preventDefault();
      var input = document.getElementById('giga-input');
      var value = input ? input.value : '';
      if (input) { input.value = ''; }
      sendGigaChat(value);
    });
  }
  var gigaAsk = document.getElementById('giga-ask-finding');
  if (gigaAsk) {
    gigaAsk.addEventListener('click', function () {
      sendGigaChat(
        'Разбери эту находку: чем она опасна, как её исправить по шагам '
        + 'и как проверить, что исправление сработало.'
      );
    });
  }
  var gigaClear = document.getElementById('giga-clear');
  if (gigaClear) {
    gigaClear.addEventListener('click', clearGigaHistory);
  }
  var gigaInput = document.getElementById('giga-input');
  if (gigaInput) {
    gigaInput.addEventListener('keydown', function (event) {
      if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        if (gigaForm) { gigaForm.requestSubmit ? gigaForm.requestSubmit() : gigaForm.dispatchEvent(new Event('submit', { cancelable: true })); }
      }
    });
  }
  applyFilters();
  syncChartToStats();
  requestAnimationFrame(syncChartToStats);
  window.addEventListener('resize', syncChartToStats);
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(function () {
      syncChartToStats();
      requestAnimationFrame(syncChartToStats);
    });
  }
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
  <circle cx="14.7" cy="11.4" r="0.85" fill="#4CBF86"/>
  <circle cx="17.3" cy="11.4" r="0.85" fill="#4CBF86"/>
</svg>
"""


SPIDER_MARK = """
<svg width="26" height="26" viewBox="0 0 32 32" aria-hidden="true">
  <g stroke="#6B756F" stroke-width="1.8" fill="none" stroke-linecap="round">
    <path d="M9 8 L14 14M23 8 L18 14M5 16 L13 17M27 16 L19 17M9 25 L14 20M23 25 L18 20"/>
  </g>
  <ellipse cx="16" cy="19" rx="5.5" ry="6.5" fill="#6B756F"/>
  <circle cx="16" cy="12" r="3.4" fill="#3A433E"/>
  <circle cx="14.6" cy="11.4" r="0.9" fill="#4CBF86"/>
  <circle cx="17.4" cy="11.4" r="0.9" fill="#4CBF86"/>
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
         "фильтры по уровню, категории и точности; поиск; подробный разбор и шаги исправления",
         _findings_panel(items, by_severity, by_category, by_confidence, total)),
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
        f"<style>{CSS}</style>\n</head>\n"
        f"<body data-target=\"{esc(target)}\" data-generated=\"{esc(generated)}\">\n"
    )

    parts.append(
        '<div class="atmosphere" aria-hidden="true"><div class="aurora"><span class="aurora-band a1"></span><span class="aurora-band a2"></span><span class="aurora-band a3"></span></div><div class="lava-lamp"><svg class="lava-svg" aria-hidden="true" focusable="false"><defs><filter id="lava-goo" x="-40%" y="-40%" width="180%" height="180%" color-interpolation-filters="sRGB"><feGaussianBlur in="SourceGraphic" stdDeviation="15" result="blur"/><feColorMatrix in="blur" mode="matrix" values="1 0 0 0 0 0 1 0 0 0 0 0 1 0 0 0 0 0 18 -9" result="goo"/></filter></defs></svg><div class="lava-heat"></div><div class="lava-goo"><div class="lava-pool"></div><span class="lava-blob b1"></span><span class="lava-blob b2"></span><span class="lava-blob b3"></span><span class="lava-blob b4"></span><span class="lava-speck s1"></span><span class="lava-speck s2"></span><span class="lava-speck s3"></span><span class="lava-speck s4"></span></div></div></div>'
    )

    # ---------- главный экран: диаграмма, заголовок, статистика ----------
    parts.append('<div class="first-screen">')
    parts.append(
        "<a class=\"home-btn\" href=\"index.html\">← Главный экран</a>"
        "<div class=\"topbar\">"
        "<div class=\"report-intro\">"
        f"<div class=\"brand\">{SPIDER_MARK}<span>Spyvision · сканер безопасности</span></div>"
        "<h1>Отчёт сканирования безопасности веб-приложения</h1>"
        f"<div class=\"target\">Цель: <b>{_link(target)}</b> · "
        f"отчёт сформирован {generated}</div>"
        "</div>"
        "</div>"
    )
    parts.append("<header>")
    parts.append("<div class=\"wrap hero\">")
    parts.append("<div class=\"hero-main\">")
    parts.append(f"<h2>{SPIDER_ICON}Общая статистика</h2>")
    parts.append("<div class=\"hero-align\">")
    parts.append(_chart_card(by_severity, total))
    parts.append(_stat_cards(stats, by_severity, by_category, len(critical), total))
    parts.append("</div></div></div></header>\n")

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
    parts.append("</div></div>")

    # ---------- боковая панель ----------
    parts.append(_drawer(panels))
    parts.append(_giga_dialog())

    # ---------- печатная версия для сохранения в PDF ----------
    parts.append(_pdf_report(stats, by_severity, by_confidence, critical, items,
                             total, generated))
    parts.append('<div id="pdf-filtered"></div>')
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
        "<div class=\"donut-wrap\">"
        "<svg class=\"donut\" viewBox=\"0 0 220 220\" "
        "role=\"img\" aria-label=\"Распределение находок по уровням критичности\">"
        f"<circle cx=\"110\" cy=\"110\" r=\"{radius}\" fill=\"none\" stroke=\"#EDF3EF\" "
        f"stroke-width=\"{stroke}\"/>"
        + "".join(segments) +
        f"<text class=\"donut-total\" x=\"110\" y=\"106\" text-anchor=\"middle\" "
        f"dominant-baseline=\"middle\">{total}</text>"
        "<text class=\"donut-caption\" x=\"110\" y=\"132\" text-anchor=\"middle\">"
        "всего находок</text>"
        "</svg>"
        "</div>"
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
        _card(f"{attention}", "Требуют внимания", "высокая и средняя опасность — нажмите, чтобы открыть",
              css="alarm" if attention else "",
              link="attention" if attention else ""),
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
              "между запросами выдерживается пауза 0.1 с"),
    ]

    groups = (
        ("Что просканировано", scanned),
        ("Что найдено", found),
        ("Как выполнялось сканирование", how),
    )
    html_parts: List[str] = ["<div class=\"stats-body\">"]
    for title, cards in groups:
        html_parts.append(
            f"<div class=\"stat-group\"><h3>{esc(title)}</h3>"
            f"<div class=\"cards\">{''.join(cards)}</div></div>"
        )
    html_parts.append("</div>")
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


def _giga_dialog() -> str:
    """Модальное окно чата с ГигаЧатом (эксперт ИБ)."""
    return (
        '<div class="giga-backdrop" id="giga-backdrop" data-giga-close></div>'
        '<div class="giga-dialog" id="giga-dialog" role="dialog" '
        'aria-modal="true" aria-labelledby="giga-title" aria-hidden="true">'
        '<div class="giga-head">'
        '<div><p class="giga-title" id="giga-title">ГигаЧат</p>'
        '<span class="giga-sub">Эксперт в сфере информационной безопасности · '
        'разбор находки и советы по исправлению</span>'
        '<span class="giga-warn">Вы соглашаетесь с тем, что написав информацию '
        'вы делитесь не только с ботом, но и с серверами ИИ. '
        'SpyVision не несёт ответственность.</span></div>'
        '<button type="button" class="giga-close" data-giga-close '
        'title="Закрыть (Esc)" aria-label="Закрыть диалог">×</button>'
        '</div>'
        '<p class="giga-finding" id="giga-finding"></p>'
        '<div class="giga-messages" id="giga-messages"></div>'
        '<div class="giga-form" style="padding-bottom:8px;border-bottom:none;'
        'border-radius:0;justify-content:flex-start">'
        '<button type="button" id="giga-ask-finding">Спросить про эту находку</button>'
        '</div>'
        '<div class="giga-tools">'
        '<button type="button" id="giga-clear">Очистить историю</button>'
        '</div>'
        '<form class="giga-form" id="giga-form">'
        '<textarea id="giga-input" rows="2" maxlength="4000" '
        'placeholder="Например: как срочно закрыть эту уязвимость?" '
        'aria-label="Сообщение ГигаЧату"></textarea>'
        '<button type="submit" id="giga-send">Отправить</button>'
        '</form>'
        '</div>'
    )


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


def _group_findings(items: Sequence[Finding]) -> List[List[Finding]]:
    """Группирует одинаковые виды ошибок (по названию) с сохранением порядка."""
    groups: Dict[str, List[Finding]] = {}
    order: List[str] = []
    for finding in items:
        key = finding.title.strip() or finding.kind or "—"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)
    return [groups[key] for key in order]


def _findings_panel(items: Sequence[Finding], by_severity: Dict[str, int],
                    by_category: Dict[str, int], by_confidence: Dict[str, int],
                    total: int) -> str:
    groups = _group_findings(items)
    group_total = len(groups)
    parts = [f"<h2 id=\"findings\">{SPIDER_ICON}Найденные проблемы</h2>",
             _filters(by_severity, by_category, by_confidence, total, group_total)]
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
    for index, group in enumerate(groups):
        parts.append(_group_row(index, group))
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
def _filters(by_severity: Dict[str, int], by_category: Dict[str, int],
             by_confidence: Dict[str, int], total: int,
             group_total: Optional[int] = None) -> str:
    shown_total = group_total if group_total is not None else total
    severity_buttons = [
        f"<button class=\"f sev wide active\" data-value=\"all\">Все уровни "
        f"<span class=\"n\">{total}</span></button>",
        f"<button class=\"f sev\" data-value=\"attention\">Требуют внимания "
        f"<span class=\"n\">{by_severity.get(HIGH, 0) + by_severity.get(MEDIUM, 0)}</span></button>",
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
        f"<button class=\"f conf-f wide active\" data-value=\"all\">Все "
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
        "<input type=\"search\" id=\"q\" placeholder=\"Введите слово: адрес, название "
        "проблемы, тип угрозы, текст доказательства…\">"
        "<button class=\"f pdf-filter\" id=\"pdf-filtered-btn\" type=\"button\" "
        "title=\"Сохранить в PDF только видимые сейчас записи\">Скачать PDF</button>"
        "<button class=\"f\" id=\"toggle-all\" data-state=\"closed\">Развернуть все</button>"
        "<button class=\"f\" data-reset>Сбросить</button>"
        "</div>"
        "</div>"
        f"<p class=\"hint\">Показано видов ошибок: <b id=\"shown\">0</b> из {shown_total}"
        f" (всего случаев: {total}). "
        "Одинаковые проблемы собраны в одну строку — число повторов указано рядом с названием. "
        "Щёлкните по строке (или по слову «подробнее»), чтобы увидеть все случаи выявления, "
        "чем проблема опасна, как сканер её нашёл и пошаговое исправление. "
        "<b>Красным</b> выделены подтверждённые находки высокого уровня. "
        "Кнопка «Скачать PDF» слева от «Развернуть все» сохраняет только отфильтрованные записи.</p>"
    )


def _fix_block(finding: Finding) -> str:
    from .fixes import FIX_GUIDES, fix_guide

    # Если есть статический гайд — он приоритетнее; иначе берём шаги
    # из Finding (в т.ч. после обогащения GigaChat).
    if (finding.kind or "") in FIX_GUIDES:
        guide = fix_guide(finding.kind, finding.recommendation)
    elif finding.fix_steps:
        guide = {
            "intro": finding.recommendation or "Выполните шаги ниже.",
            "steps": list(finding.fix_steps),
            "verify": [
                "Повторите проверку сканером — исходный признак должен исчезнуть.",
            ],
        }
    else:
        guide = fix_guide(finding.kind, finding.recommendation)

    steps = [step for step in guide.get("steps", []) if str(step).strip()]
    verify = [step for step in guide.get("verify", []) if str(step).strip()]
    intro = guide.get("intro") or finding.recommendation or "Выполните шаги ниже."

    parts = [f"<p>{esc(intro)}</p>"]
    if steps:
        parts.append("<p class=\"fix-cap\">Что сделать</p>")
        parts.append(
            "<ol class=\"fix-steps\">"
            + "".join(f"<li>{esc(step)}</li>" for step in steps)
            + "</ol>"
        )
    if verify:
        parts.append("<p class=\"fix-cap\">Как проверить, что исправлено</p>")
        parts.append(
            "<ol class=\"fix-steps verify\">"
            + "".join(f"<li>{esc(step)}</li>" for step in verify)
            + "</ol>"
        )
    if not steps and not verify:
        parts = [f"<p>{esc(finding.recommendation or '—')}</p>"]
    return "".join(parts)


def _repeat_label(count: int) -> str:
    if count <= 1:
        return ""
    mod10 = count % 10
    mod100 = count % 100
    if mod10 == 1 and mod100 != 11:
        word = "повтор"
    elif 2 <= mod10 <= 4 and not 12 <= mod100 <= 14:
        word = "повтора"
    else:
        word = "повторов"
    return f"<span class=\"repeat\" title=\"Найдено случаев: {count}\">×{count} {word}</span>"


def _group_row(index: int, findings: Sequence[Finding]) -> str:
    primary = findings[0]
    count = len(findings)
    # Берём наихудший уровень и «подтверждено», если есть хотя бы один такой случай
    severity = min(
        (item.severity for item in findings),
        key=lambda value: SEVERITY_ORDER.get(value, 9),
    )
    confidence = CONFIRMED if any(item.confidence == CONFIRMED for item in findings) else primary.confidence
    severity_class = SEVERITY_CLASS.get(severity, "sev-info")
    severity_label = SEVERITY_LABEL.get(severity, severity)
    critical = any(item.severity == HIGH and item.confidence == CONFIRMED for item in findings)
    confidence_class = "conf sus" if confidence == SUSPECTED else "conf"
    if critical:
        confidence_class = "conf yes"
    row_class = "f-row critical" if critical else "f-row"

    urls = [item.url for item in findings]
    unique_urls = list(dict.fromkeys(urls))
    if len(unique_urls) == 1:
        where_cell = _link(unique_urls[0])
        url_summary = unique_urls[0]
    else:
        where_cell = (
            f"<span class=\"cat\">{len(unique_urls)} адресов</span>"
            f"<div style=\"margin-top:4px;font-size:12px;color:var(--muted)\">"
            f"см. случаи ниже</div>"
        )
        url_summary = f"{len(unique_urls)} адресов"

    search_parts = []
    for item in findings:
        search_parts.extend([
            item.url, item.title, item.category, item.severity, severity_label,
            item.threat_type, item.impact, item.detection, item.evidence,
            item.request, item.confidence, item.recommendation,
            " ".join(item.fix_steps or []),
        ])
    search_blob = " ".join(search_parts).lower()
    steps_json = esc(json.dumps(list(primary.fix_steps or []), ensure_ascii=False))
    title_html = f"{esc(primary.title)}{_repeat_label(count)}"
    conf_label = confidence
    if count > 1 and confidence == CONFIRMED and any(
        item.confidence == SUSPECTED for item in findings
    ):
        conf_label = f"{CONFIRMED} / есть подозрения"

    row = (
        f"<tr class=\"{row_class}\" id=\"r{index}\" data-id=\"{index}\" "
        f"data-severity=\"{esc(severity)}\" data-category=\"{esc(primary.category)}\" "
        f"data-confidence=\"{esc(confidence)}\" "
        f"data-severity-label=\"{esc(severity_label)}\" "
        f"data-title=\"{esc(primary.title)}\" data-url=\"{esc(url_summary)}\" "
        f"data-count=\"{count}\" "
        f"data-recommendation=\"{esc(primary.recommendation or '')}\" "
        f"data-steps=\"{steps_json}\" data-search=\"{esc(search_blob)}\">"
        f"<td class=\"nowrap\"><span class=\"badge {severity_class}\">{esc(severity_label)}"
        f"</span></td>"
        f"<td class=\"title\">{title_html}</td>"
        f"<td><span class=\"threat\">{esc(primary.threat_type)}</span></td>"
        f"<td class=\"cat\">{esc(primary.category)}</td>"
        f"<td>{where_cell}</td>"
        f"<td class=\"{confidence_class}\">{esc(conf_label)}</td>"
        f"<td class=\"nowrap\"><button class=\"toggle\" aria-expanded=\"false\" "
        f"onclick=\"toggleDetails({index})\">подробнее</button></td>"
        "</tr>"
    )

    cases_html = _cases_block(findings)
    # Контекст для ГигаЧата: сводка по всем случаям группы
    giga_urls = "\n".join(unique_urls[:20])
    giga_requests = "\n---\n".join(
        (item.request or "—") for item in findings[:8]
    )
    giga_evidence = "\n---\n".join(
        (item.evidence or "—") for item in findings[:8]
    )

    fix_block = (
        "<div class=\"block fix full\"><h4>Как исправить — по шагам</h4>"
        f"{_fix_block(primary)}"
        "<div class=\"giga-actions\">"
        f"<button type=\"button\" class=\"giga-btn\" "
        f"data-title=\"{esc(primary.title)}\" "
        f"data-severity=\"{esc(severity_label)}\" "
        f"data-url=\"{esc(giga_urls)}\" "
        f"data-threat=\"{esc(primary.threat_type)}\" "
        f"data-impact=\"{esc(primary.impact or '')}\" "
        f"data-detection=\"{esc(primary.detection or '')}\" "
        f"data-request=\"{esc(giga_requests)}\" "
        f"data-evidence=\"{esc(giga_evidence)}\" "
        f"data-recommendation=\"{esc(primary.recommendation or '')}\">"
        "ГигаЧат</button>"
        "<span class=\"giga-hint\">спросить эксперта по информационной безопасности "
        "(история диалога сохраняется для этого вида ошибки)</span>"
        "</div></div>"
    )

    details = (
        f"<tr class=\"details\" id=\"d{index}\" style=\"display:none\"><td colspan=\"7\">"
        "<div class=\"det\">"
        "<div class=\"block danger full\"><h4>Чем это опасно</h4>"
        f"<p>{esc(primary.impact or 'Описание для этого типа находки не задано.')}</p></div>"
        "<div class=\"block logic full\"><h4>Почему сканер так решил</h4>"
        f"<p>{esc(primary.detection or 'Логика проверки описана в названии находки.')}</p></div>"
        f"{fix_block}"
        f"{cases_html}"
        "</div></td></tr>"
    )
    return row + details


def _cases_block(findings: Sequence[Finding]) -> str:
    """Список случаев: статус, URL, категория; запрос/ответ — по «подробнее»."""
    if len(findings) == 1:
        finding = findings[0]
        return (
            "<div class=\"block\"><h4>Что отправил сканер (безопасные тестовые данные)</h4>"
            f"<pre>{esc(finding.request or '—')}</pre></div>"
            "<div class=\"block\"><h4>Что ответил сервер (доказательство)</h4>"
            f"<pre>{esc(finding.evidence or '—')}</pre></div>"
        )

    parts = [
        f"<div class=\"block full\"><h4>Случаи выявления — {len(findings)}</h4>"
        "<div class=\"case-list\">"
    ]
    for finding in findings:
        conf_class = "sus" if finding.confidence == SUSPECTED else "yes"
        parts.append(
            "<details class=\"case-item\">"
            "<summary>"
            f"<span class=\"case-conf {conf_class}\">{esc(finding.confidence)}</span>"
            f"<span>{_link(finding.url)}</span>"
            f"<span class=\"case-cat\">{esc(finding.category)}</span>"
            "<span class=\"case-more\"></span>"
            "</summary>"
            "<div class=\"case-extra\">"
            "<div><h5>Что отправил сканер</h5>"
            f"<pre>{esc(finding.request or '—')}</pre></div>"
            "<div><h5>Что ответил сервер</h5>"
            f"<pre>{esc(finding.evidence or '—')}</pre></div>"
            "</div>"
            "</details>"
        )
    parts.append("</div></div>")
    return "".join(parts)


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
