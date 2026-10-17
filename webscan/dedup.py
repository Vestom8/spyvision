"""Семантическая дедупликация находок разных модулей.

Ключ ``(url, title, request)`` в ``FindingList`` склеивает только полностью одинаковые
записи. Но один и тот же факт нередко находят сразу несколько проверок (SAST и поиск
утечек, SAST и клиентская часть) под разными заголовками. Здесь описано, какая находка
вытесняет какую на одном адресе: остаётся более точная.
"""

from typing import Callable, List, NamedTuple, Optional

from .models import Finding, FindingList


class Rule(NamedTuple):
    dropped: str                       # вид находки, которая вытесняется
    kept: str                          # вид находки, которая её заменяет
    only_if: Optional[Callable[[Finding], bool]] = None  # дополнительное условие к dropped


def _title_has(*parts: str) -> Callable[[Finding], bool]:
    return lambda finding: any(part in finding.title for part in parts)


RULES: List[Rule] = [
    # Секреты: общий поиск присвоений в SAST дублирует поиск утечек по шаблонам.
    Rule("sast_hardcoded_secret", "secret_in_code"),
    # Ключ AWS и закрытый ключ: «подтверждённая» запись SAST точнее общей.
    Rule("secret_in_code", "sast_aws_key", _title_has("AWS")),
    Rule("secret_in_code", "sast_private_key", _title_has("PEM")),
    # Источник → приёмник (DOM XSS) точнее, чем просто «есть innerHTML».
    Rule("sast_innerhtml", "dom_xss_sink"),
    # Обработчик postMessage без проверки origin находят и SAST, и клиентская проверка.
    Rule("sast_postmessage_open", "postmessage_no_origin"),
    # Source map: клиентская утечка содержит найденные адреса файлов.
    Rule("sast_sourcemap", "source_maps"),
]


def drop_superseded(findings: FindingList) -> int:
    """Убирает вытесненные находки; возвращает их число."""
    kinds_by_url = {}
    for finding in findings:
        kinds_by_url.setdefault(finding.url, set()).add(finding.kind)
    # Правило действует, если замещающая находка есть на том же адресе. Для «AWS»/«PEM»
    # нужна именно замещающая запись, поэтому проверка идёт по виду, а не по числу.
    active = {}
    for rule in RULES:
        active.setdefault(rule.dropped, []).append(rule)

    def superseded(finding: Finding) -> bool:
        for rule in active.get(finding.kind, ()):
            if rule.kept not in kinds_by_url.get(finding.url, ()):
                continue
            if rule.only_if is None or rule.only_if(finding):
                return True
        return False

    return findings.discard(superseded)
