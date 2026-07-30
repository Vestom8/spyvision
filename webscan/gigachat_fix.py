"""Связь сканера с GigaChat (Сбер).

Две задачи:
1) После скана — сгенерировать короткий текст «Как исправить» для каждой находки.
2) В отчёте — отвечать на вопросы пользователя в диалоге «Спросить GigaChat».

Как включить:
  подставьте Authorization Key в GIGACHAT_API_KEY ниже
  (кабинет: https://developers.sber.ru/studio → GigaChat API).

Пока в ключе стоит плейсхолдер «ТУТ ДОЛЖЕН БЫТЬ API КЛЮЧ»,
сканер не ходит в API и оставляет тексты из knowledge_fix.py.
Диалог в отчёте работает только если отчёт открыт через
локальный сервер Spyvision (python scan.py), не как file://.
"""

from __future__ import annotations

import uuid
from typing import Dict, List, Optional

import requests

from .models import Finding, FindingList, INFO

# ---------------------------------------------------------------------------
# API-ключ GigaChat (Authorization Key в формате Base64).
# Замените значение на свой ключ из личного кабинета разработчика.
# ---------------------------------------------------------------------------
GIGACHAT_API_KEY = "MDE5ZmFlMjgtMWUyOS03MDQ5LWIyM2MtZGExNzY0MzYyYjdiOmRjNTM3YjBlLWQ2NzgtNDNjNy1hNDgxLWJjZjZiNzgzOGJmOQ=="

# Адреса официального API GigaChat
AUTH_URL = "https://ngw.devices.sberbank.ru:9443/api/v2/oauth"  # получение access_token
CHAT_URL = "https://gigachat.devices.sberbank.ru/api/v1/chat/completions"
SCOPE = "GIGACHAT_API_PERS"  # персональный тариф; для бизнеса: GIGACHAT_API_B2B / _CORP
MODEL = "GigaChat"
REQUEST_TIMEOUT = 60  # секунд на один HTTP-запрос к API

# Сколько символов доказательств/запроса отдаём модели (чтобы не раздувать промпт)
MAX_EVIDENCE_CHARS = 1800
MAX_REQUEST_CHARS = 900

# Инструкция для блока «Как исправить» в карточке находки (краткий структурированный ответ)
FIX_SYSTEM_PROMPT = (
    "Ты — эксперт по безопасной разработке веб-приложений. "
    "По данным сканера напиши инструкцию «Как исправить» на русском "
    "для разработчика без узкой специализации в ИБ. "
    "Опирайся на доказательства, запрос и ответ сервера, вид ошибки, уровень и категорию. "
    "Структура ответа:\n"
    "1) краткое резюме — 1–2 предложения;\n"
    "2) 3–5 коротких шагов исправления;\n"
    "3) при необходимости один мини-пример кода/настройки (до 4 строк);\n"
    "4) одна фраза, как проверить результат.\n"
    "Пиши сжато: суммарно не больше 900–1100 знаков, без воды и повторов. "
    "Не выдумывай факты, которых нет во входных данных. "
    "Не предлагай деструктивных действий. Без приветствий."
)

# Инструкция для живого диалога в окне «Спросить GigaChat»
CHAT_SYSTEM_PROMPT = (
    "Ты помощник по исправлению ошибок безопасности веб-приложений. "
    "Пользователь смотрит отчёт сканера Spyvision и задаёт вопросы "
    "по исправлению найденных проблем. "
    "Отвечай по-русски, конкретно и коротко (обычно до 8–12 предложений). "
    "Если не хватает данных — уточни. Не предлагай взлом и деструктивные действия."
)

# Кэш access_token в памяти процесса (токен живёт ~30 минут)
_token_cache: Dict[str, str] = {}


def is_configured() -> bool:
    """True, если в файле указан реальный ключ, а не плейсхолдер."""
    key = (GIGACHAT_API_KEY or "").strip()
    return bool(key) and key != "ТУТ ДОЛЖЕН БЫТЬ API КЛЮЧ"


def enrich_findings_with_gigachat(
    findings: FindingList,
    *,
    enabled: bool = True,
    verbose: bool = False,
) -> int:
    """Подставить в findings.recommendation тексты от GigaChat.

    Вызывается в конце сканирования (см. scanner._finish).
    Возвращает, сколько находок удалось обновить.
    Находки уровня Info пропускаем — для них рекомендации обычно не нужны.
    Одинаковые по смыслу находки кэшируются, чтобы не дергать API лишний раз.
    """
    if not enabled:
        return 0
    if not is_configured():
        if verbose:
            print("GigaChat: ключ не задан — оставлены стандартные рекомендации.", flush=True)
        return 0

    items = [f for f in findings.sorted() if f.severity != INFO]
    if not items:
        return 0

    try:
        token = _get_access_token()
    except Exception as exc:  # noqa: BLE001
        print(f"GigaChat: не удалось получить токен ({exc}). "
              "Используются стандартные рекомендации.", flush=True)
        return 0

    print(f"GigaChat: генерация «Как исправить» для {len(items)} находок…", flush=True)
    cache: Dict[str, str] = {}
    updated = 0

    for index, finding in enumerate(items, start=1):
        cache_key = _cache_key(finding)
        text = cache.get(cache_key)
        if text is None:
            try:
                text = _chat(
                    token,
                    FIX_SYSTEM_PROMPT,
                    [{"role": "user", "content": _build_fix_prompt(finding)}],
                    temperature=0.35,
                    max_tokens=700,
                )
            except Exception as exc:  # noqa: BLE001
                if verbose:
                    print(f"  [{index}/{len(items)}] ошибка: {exc}", flush=True)
                continue
            if not text:
                continue
            cache[cache_key] = text
        finding.recommendation = text
        updated += 1
        if verbose:
            print(f"  [{index}/{len(items)}] {finding.title[:70]}", flush=True)

    print(f"GigaChat: обновлено рекомендаций: {updated}", flush=True)
    return updated


def ask_gigachat(
    question: str,
    history: Optional[List[Dict[str, str]]] = None,
    target: str = "",
) -> str:
    """Ответ на вопрос из диалога отчёта (кнопка «Спросить GigaChat»).

    history — предыдущие реплики [{role, content}, ...] с фронтенда.
    target — URL просканированного сайта (для контекста).
    """
    if not is_configured():
        raise RuntimeError(
            "GigaChat не настроен: укажите ключ в webscan/gigachat_fix.py"
        )
    question = (question or "").strip()
    if not question:
        raise ValueError("Введите вопрос")
    if len(question) > 4000:
        question = question[:4000]

    token = _get_access_token()
    messages: List[Dict[str, str]] = []
    # Берём только последние 8 сообщений, чтобы уложиться в лимит контекста
    for item in (history or [])[-8:]:
        role = item.get("role")
        content = (item.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            messages.append({"role": role, "content": content[:4000]})

    context = (
        f"Контекст: отчёт сканирования цели {target}."
        if target else
        "Контекст: отчёт сканирования безопасности веб-приложения."
    )
    messages.append({
        "role": "user",
        "content": f"{context}\n\nВопрос пользователя:\n{question}",
    })
    return _chat(
        token,
        CHAT_SYSTEM_PROMPT,
        messages,
        temperature=0.45,
        max_tokens=900,
    )


def _get_access_token() -> str:
    """OAuth: обменять API-ключ на краткоживущий Bearer-токен."""
    cached = _token_cache.get("access_token")
    if cached:
        return cached
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "RqUID": str(uuid.uuid4()),  # обязательный уникальный id запроса
        "Authorization": f"Basic {GIGACHAT_API_KEY.strip()}",
    }
    response = requests.post(
        AUTH_URL,
        headers=headers,
        data={"scope": SCOPE},
        timeout=REQUEST_TIMEOUT,
        verify=False,  # у шлюза Sber часто свой сертификат
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise RuntimeError(f"в ответе нет access_token: {payload!r}")
    _token_cache["access_token"] = str(token)
    return str(token)


def _chat(
    token: str,
    system: str,
    messages: List[Dict[str, str]],
    *,
    temperature: float,
    max_tokens: int,
) -> str:
    """Один запрос к /chat/completions. При 401 пробуем обновить токен."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    body = {
        "model": MODEL,
        "messages": [{"role": "system", "content": system}] + messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    response = requests.post(
        CHAT_URL,
        headers=headers,
        json=body,
        timeout=REQUEST_TIMEOUT,
        verify=False,
    )
    if response.status_code == 401:
        # токен протух — запросим новый и повторим один раз
        _token_cache.clear()
        token = _get_access_token()
        headers["Authorization"] = f"Bearer {token}"
        response = requests.post(
            CHAT_URL,
            headers=headers,
            json=body,
            timeout=REQUEST_TIMEOUT,
            verify=False,
        )
    response.raise_for_status()
    payload = response.json()
    choices = payload.get("choices") or []
    if not choices:
        return ""
    message = choices[0].get("message") or {}
    return (message.get("content") or "").strip()


def _build_fix_prompt(finding: Finding) -> str:
    """Собрать пользовательский промпт из полей одной находки."""
    evidence = (finding.evidence or "—")[:MAX_EVIDENCE_CHARS]
    request = (finding.request or "—")[:MAX_REQUEST_CHARS]
    return "\n".join([
        f"Вид ошибки (kind): {finding.kind or '—'}",
        f"Заголовок находки: {finding.title}",
        f"Категория: {finding.category}",
        f"Уровень критичности: {finding.severity}",
        f"Точность: {finding.confidence}",
        f"Тип угрозы: {finding.threat_type or '—'}",
        f"URL: {finding.url}",
        "",
        "Чем это опасно:",
        finding.impact or "—",
        "",
        "Почему сканер так решил:",
        finding.detection or "—",
        "",
        "Входные данные / request:",
        request,
        "",
        "Выходные данные / evidence:",
        evidence,
        "",
        "Напиши краткий блок «Как исправить» по структуре из системной инструкции.",
    ])


def _cache_key(finding: Finding) -> str:
    """Ключ дедупликации: похожие находки → один ответ модели."""
    evidence_head = (finding.evidence or "")[:180]
    request_head = (finding.request or "")[:120]
    return "|".join([
        finding.kind or "",
        finding.title or "",
        finding.severity or "",
        evidence_head,
        request_head,
    ])


# Не засоряем консоль предупреждениями SSL при verify=False
try:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # noqa: BLE001
    pass
