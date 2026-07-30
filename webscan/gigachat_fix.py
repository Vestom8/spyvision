"""Опциональные подсказки GigaChat: тексты «Как исправить» и диалог в отчёте.

Ключ авторизации (Authorization key из личного кабинета GigaChat API)
прописывается в GIGACHAT_API_KEY ниже или через переменную окружения
GIGACHAT_API_KEY / GIGACHAT_CREDENTIALS. Отдельные пакеты не нужны —
используется requests. Без ключа или с --no-gigachat остаются тексты
из базы знаний.
"""

from __future__ import annotations

import os
import threading
import uuid
from typing import Any, Dict, List, Optional, Sequence

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ключ авторизации GigaChat API (Base64 ClientID:ClientSecret из кабинета Сбера).
# Можно оставить пустым и задать через окружение GIGACHAT_API_KEY.
GIGACHAT_API_KEY = "MDE5ZmFlMjgtMWUyOS03MDQ5LWIyM2MtZGExNzY0MzYyYjdiOmUwNDhhMDMwLTYwOTYtNGRlZC1hY2I2LTUyNDRjMjk5Mzc0OA=="

GIGACHAT_SCOPE = os.environ.get("GIGACHAT_SCOPE", "GIGACHAT_API_PERS")
OAUTH_URL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"
CHAT_URL = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"
MODEL = os.environ.get("GIGACHAT_MODEL", "GigaChat")

# У сертификатов Сбера часто нет цепочки в системном хранилище Windows.
VERIFY_SSL = False

# Сколько уникальных видов ошибок обогащать за один скан (остальное — из базы знаний).
MAX_ENRICH_PER_SCAN = 8

SYSTEM_PROMPT = (
    "Ты — эксперт в сфере информационной безопасности и безопасной разработки. "
    "Помогаешь разобрать находки веб-сканера Spyvision: объяснить риск простым языком, "
    "предложить конкретные шаги исправления и проверки. Отвечай по-русски, кратко и по делу. "
    "Не предлагай атаковать чужие системы и не генерируй вредоносный код. "
    "Если данных мало — задай уточняющий вопрос."
)

_token_lock = threading.Lock()
_cached_token: Optional[str] = None
_cached_expires_at: float = 0.0


def _credentials() -> str:
    return (
        (GIGACHAT_API_KEY or "").strip()
        or os.environ.get("GIGACHAT_API_KEY", "").strip()
        or os.environ.get("GIGACHAT_CREDENTIALS", "").strip()
    )


def is_configured() -> bool:
    """True, если задан ключ авторизации."""
    return bool(_credentials())


def _get_access_token() -> str:
    """Получает (и кэширует) access token по ключу авторизации."""
    global _cached_token, _cached_expires_at
    import time

    now = time.time()
    with _token_lock:
        if _cached_token and now < _cached_expires_at - 60:
            return _cached_token

        key = _credentials()
        if not key:
            raise RuntimeError(
                "Ключ GigaChat не задан. Пропишите GIGACHAT_API_KEY в "
                "webscan/gigachat_fix.py или в переменной окружения."
            )

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "RqUID": str(uuid.uuid4()),
            "Authorization": f"Basic {key}",
        }
        response = requests.post(
            OAUTH_URL,
            headers=headers,
            data={"scope": GIGACHAT_SCOPE},
            timeout=30,
            verify=VERIFY_SSL,
        )
        if response.status_code >= 400:
            raise RuntimeError(
                f"GigaChat OAuth: HTTP {response.status_code}. "
                f"Проверьте ключ авторизации. Ответ: {response.text[:300]}"
            )
        payload = response.json()
        token = payload.get("access_token")
        if not token:
            raise RuntimeError(f"GigaChat OAuth: нет access_token в ответе: {payload}")
        expires_at = payload.get("expires_at")
        if isinstance(expires_at, (int, float)):
            _cached_expires_at = (
                expires_at / 1000.0 if expires_at > 1e12 else float(expires_at)
            )
        else:
            _cached_expires_at = now + 25 * 60
        _cached_token = str(token)
        return _cached_token


def ask_gigachat(
    message: str,
    *,
    history: Optional[Sequence[Dict[str, str]]] = None,
    context: Optional[Dict[str, Any]] = None,
) -> str:
    """Отправляет сообщение эксперту GigaChat и возвращает текст ответа."""
    text = (message or "").strip()
    if not text:
        raise ValueError("Пустое сообщение")

    # GigaChat допускает только одно system-сообщение — и только первым.
    system_parts = [SYSTEM_PROMPT]
    if context:
        bits = []
        for key, label in (
            ("title", "Находка"),
            ("severity", "Уровень"),
            ("url", "URL"),
            ("threat_type", "Тип угрозы"),
            ("impact", "Чем опасно"),
            ("detection", "Почему сканер так решил"),
            ("request", "Запрос сканера"),
            ("evidence", "Доказательство"),
            ("recommendation", "Рекомендация сканера"),
        ):
            value = str(context.get(key) or "").strip()
            if value:
                bits.append(f"{label}: {value[:2000]}")
        if bits:
            system_parts.append("Контекст текущей находки из отчёта:\n" + "\n".join(bits))
    messages: List[Dict[str, str]] = [
        {"role": "system", "content": "\n\n".join(system_parts)}
    ]

    if history:
        for item in history[-12:]:
            role = item.get("role")
            content = (item.get("content") or "").strip()
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": content[:6000]})

    messages.append({"role": "user", "content": text[:6000]})

    token = _get_access_token()
    response = requests.post(
        CHAT_URL,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={
            "model": MODEL,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1200,
        },
        timeout=90,
        verify=VERIFY_SSL,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"GigaChat chat: HTTP {response.status_code}. Ответ: {response.text[:400]}"
        )
    data = response.json()
    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Неожиданный ответ GigaChat: {data}") from exc
    return str(content).strip()


def _has_static_guide(kind: str) -> bool:
    try:
        from .fixes import FIX_GUIDES
    except Exception:  # noqa: BLE001
        return False
    return bool(kind and kind in FIX_GUIDES)


def enrich_findings_with_gigachat(findings, *, enabled: bool = True) -> None:
    """Обогащает тексты «Как исправить» через GigaChat (best-effort).

    Ускорения без потери смысла:
    - виды с готовым гайдом в fixes.py не трогаем;
    - одинаковые названия обогащаются один раз и копируются на повторы;
    - не больше MAX_ENRICH_PER_SCAN уникальных запросов за скан.
    """
    if not enabled or not is_configured():
        return
    items = list(getattr(findings, "_items", findings) or [])
    by_title: Dict[str, List[Any]] = {}
    order: List[str] = []
    for finding in items:
        if getattr(finding, "severity", "") not in ("High", "Medium"):
            continue
        if _has_static_guide(getattr(finding, "kind", "") or ""):
            continue
        title = (getattr(finding, "title", "") or "").strip() or "—"
        if title not in by_title:
            by_title[title] = []
            order.append(title)
        by_title[title].append(finding)

    calls = 0
    for title in order:
        if calls >= MAX_ENRICH_PER_SCAN:
            break
        group = by_title[title]
        primary = group[0]
        prompt = (
            f"Кратко (3–6 шагов) опиши, как исправить проблему веб-приложения.\n"
            f"Название: {primary.title}\n"
            f"URL: {primary.url}\n"
            f"Тип: {getattr(primary, 'threat_type', '')}\n"
            f"Чем опасно: {getattr(primary, 'impact', '')}\n"
            f"Текущая рекомендация: {primary.recommendation}\n"
            f"Ответь только текстом шагов исправления, без приветствия."
        )
        try:
            answer = ask_gigachat(prompt)
            calls += 1
        except Exception:  # noqa: BLE001 — обогащение не должно ломать скан
            continue
        if not answer:
            continue
        steps = [
            line.strip(" •-\t")
            for line in answer.splitlines()
            if line.strip()
        ][:12]
        for finding in group:
            finding.recommendation = answer
            if hasattr(finding, "fix_steps") and steps:
                finding.fix_steps = list(steps)
