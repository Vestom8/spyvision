"""Анализ небезопасных форм (раздел 4.4 требований)."""

from typing import List
from urllib.parse import urlparse

from ..models import CONFIRMED, HIGH, MEDIUM, SUSPECTED, VULN, Finding, Page
from ..utils import same_host, truncate

SENSITIVE_FIELD_HINTS = ("pass", "pwd", "card", "cvv", "cvc", "secret", "token", "ssn",
                         "inn", "snils", "passport", "pin", "otp", "code", "birth", "email",
                         "phone", "login", "user")
CSRF_HINTS = ("csrf", "xsrf", "authenticity_token", "_token", "nonce", "requestverificationtoken")


def check_forms(page: Page) -> List[Finding]:
    findings: List[Finding] = []
    for form in page.forms:
        field_names = [f.name.lower() for f in form.fields if f.name]
        has_password = any(f.field_type == "password" for f in form.fields)
        sensitive_fields = [name for name in field_names
                           if any(hint in name for hint in SENSITIVE_FIELD_HINTS)]
        if has_password:
            sensitive_fields += [f.name for f in form.fields if f.field_type == "password"]
        action_scheme = urlparse(form.action).scheme.lower()
        request_text = f"Форма на странице {page.url}\n{form.describe()}"
        evidence = truncate(form.raw, 700)

        def add(title, severity, recommendation, kind, confidence=CONFIRMED):
            findings.append(
                Finding(
                    url=page.url,
                    title=title,
                    category=VULN,
                    severity=severity,
                    recommendation=recommendation,
                    request=request_text,
                    evidence=evidence,
                    confidence=confidence,
                    kind=kind,
                )
            )

        if action_scheme == "http":
            add(
                "Форма отправляет данные по HTTP без шифрования",
                HIGH if (has_password or sensitive_fields) else MEDIUM,
                "Измените action на https://. Данные формы, включая пароли, передаются "
                "открытым текстом и могут быть перехвачены или изменены в пути.",
                "form_http",
            )
        elif has_password and not page.is_https:
            add(
                "Поле пароля на странице, загруженной по HTTP",
                HIGH,
                "Отдавайте страницы с формами входа только по HTTPS: код страницы может быть "
                "подменён до отправки формы.",
                "form_password_http",
            )

        if form.action and not same_host(form.action, page.url) and action_scheme in ("http", "https"):
            add(
                "Форма отправляет данные на внешний домен",
                MEDIUM if not sensitive_fields else HIGH,
                f"Проверьте получателя данных: {urlparse(form.action).hostname}. Если это не "
                "доверенный сервис, отправка данных наружу должна быть удалена.",
                "form_external",
            )

        if form.method == "GET" and sensitive_fields:
            add(
                "Чувствительные данные отправляются методом GET",
                MEDIUM,
                "Используйте POST: параметры GET попадают в историю браузера, логи сервера, "
                "заголовок Referer и кэш прокси. Поля: " + ", ".join(sorted(set(sensitive_fields))[:8]),
                "form_get_sensitive",
            )

        if form.method == "POST" and not any(
            any(hint in name for hint in CSRF_HINTS) for name in field_names
        ):
            add(
                "В POST-форме не найден CSRF-токен",
                MEDIUM,
                "Добавьте скрытое поле с CSRF-токеном и проверяйте его на сервере "
                "(либо используйте cookie с SameSite=Strict/Lax как дополнительную меру). "
                "Проверка выполняется по имени полей, поэтому возможны ложные срабатывания.",
                "form_csrf",
                confidence=SUSPECTED,
            )

    return findings
