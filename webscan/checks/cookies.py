"""Проверка безопасности cookies (раздел 3.3 требований)."""

import time
from typing import List, Optional

from ..models import CONFIG, CONFIRMED, LOW, MEDIUM, Finding, Page
from ..utils import truncate

LONG_LIFETIME_DAYS = 30
VALID_SAME_SITE = ("strict", "lax")
SESSION_NAME_HINTS = ("sess", "sid", "auth", "token", "login", "jwt", "csrf", "remember")


def check_cookies(page: Page) -> List[Finding]:
    findings: List[Finding] = []
    request_line = f"GET {page.url}"

    for cookie in page.cookies:
        evidence = truncate(_safe_raw(cookie.raw), 400)
        sensitive = any(hint in cookie.name.lower() for hint in SESSION_NAME_HINTS)

        def add(title, severity, recommendation, kind):
            findings.append(
                Finding(
                    url=page.url,
                    title=f"{title}: cookie «{cookie.name}»",
                    category=CONFIG,
                    severity=severity,
                    recommendation=recommendation,
                    request=request_line,
                    evidence=evidence,
                    confidence=CONFIRMED,
                    kind=kind,
                )
            )

        if not cookie.secure:
            add(
                "Отсутствует флаг Secure",
                MEDIUM if (page.is_https or sensitive) else LOW,
                "Добавьте атрибут Secure, чтобы cookie передавалась только по HTTPS.",
                "cookie_secure",
            )
        if not cookie.http_only:
            add(
                "Отсутствует флаг HttpOnly",
                MEDIUM if sensitive else LOW,
                "Добавьте атрибут HttpOnly, чтобы cookie была недоступна из JavaScript "
                "(снижает риск кражи сессии через XSS).",
                "cookie_httponly",
            )

        same_site = (cookie.same_site or "").strip().lower()
        if not same_site:
            add(
                "Не задан атрибут SameSite",
                LOW,
                "Укажите SameSite=Lax (или Strict для чувствительных cookie).",
                "cookie_samesite_missing",
            )
        elif same_site not in VALID_SAME_SITE:
            if same_site == "none":
                add(
                    "SameSite=None (межсайтовая отправка разрешена)",
                    MEDIUM if not cookie.secure else LOW,
                    "SameSite=None допустим только вместе с Secure и только если cookie "
                    "действительно нужна в сторонних контекстах. Иначе используйте Lax или Strict.",
                    "cookie_samesite_none",
                )
            else:
                add(
                    f"Недопустимое значение SameSite={cookie.same_site}",
                    LOW,
                    "Допустимые значения: Strict или Lax.",
                    "cookie_samesite_invalid",
                )

        lifetime_days = _lifetime_days(cookie)
        if lifetime_days is not None and lifetime_days > LONG_LIFETIME_DAYS:
            add(
                f"Слишком большой срок жизни ({lifetime_days} дн.)",
                LOW,
                f"Срок жизни свыше {LONG_LIFETIME_DAYS} дней увеличивает окно для повторного "
                "использования украденной cookie. Сократите срок или используйте сессионные cookie.",
                "cookie_lifetime",
            )
    return findings


def _lifetime_days(cookie) -> Optional[int]:
    if cookie.max_age is not None:
        return int(cookie.max_age // 86400)
    if cookie.expires is not None:
        return int(max(0, cookie.expires - time.time()) // 86400)
    return None


def _safe_raw(raw: str) -> str:
    """Скрывает значение cookie — сканер не сохраняет секреты."""
    if "=" not in raw:
        return raw
    name, rest = raw.split("=", 1)
    value, _, attrs = rest.partition(";")
    masked = "<значение скрыто>" if value.strip() else ""
    return f"{name}={masked}" + (f";{attrs}" if attrs else "")
