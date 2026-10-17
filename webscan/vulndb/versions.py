"""Разбор и сравнение версий программных компонентов без внешних зависимостей.

Модуль нужен, чтобы проверять диапазоны NVD (`versionStartIncluding`,
`versionEndExcluding` и т. п.) локально. Поддерживаются типичные для веб-стека
форматы:

* обычные числовые версии: ``2.4.49``, ``1.18``, ``1.18.0`` (хвостовые нули
  не влияют на сравнение);
* буквенный патч-уровень OpenSSL/OpenSSH: ``1.0.2k`` > ``1.0.2``, ``7.4p1``;
* предрелизы: ``3.0.0-rc1``, ``5.0.0-beta.2``, ``1.0a1`` — младше релиза;
* ревизии дистрибутивов: ``7.4.3-1ubuntu1``, ``1.18.0-6+deb11u3``,
  ``2.4.6-97.el7`` — отбрасываются, сравнивается upstream-версия.

Пустое значение, ``*`` и ``-`` — «версия не указана»: такие значения не
разбираются (``parse_version`` возвращает ``None``).
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

# Метки предрелизов в порядке старшинства (всё это младше финального релиза).
PRERELEASE_RANK = {
    "dev": 0, "snapshot": 0, "nightly": 0,
    "alpha": 1, "a": 1,
    "beta": 2, "b": 2,
    "preview": 3, "pre": 3,
    "rc": 4, "c": 4, "cr": 4,
}

_EMPTY = {"", "*", "-", "n/a", "na", "unknown"}
_RELEASE_RE = re.compile(r"\d+(?:[._]\d+)*")
_PRE_RE = re.compile(r"^[-._]?(?P<tag>dev|snapshot|nightly|alpha|beta|preview|pre|rc|cr|a|b|c)"
                     r"(?![a-z])[-._]?(?P<num>\d*)")
_TOKEN_RE = re.compile(r"\d+|[a-z]+")
# Ревизия пакета дистрибутива: "-1ubuntu1", "-6", ".el7", ".el8_4", "~deb".
_DISTRO_RE = re.compile(r"(?:-(?=\d)|\.el\d|\.fc\d|\.amzn\d|~).*$")


class Version:
    """Разобранная версия. Сравнивается через ``compare``/операторы."""

    __slots__ = ("raw", "release", "pre", "post")

    def __init__(self, raw: str, release: Tuple[int, ...],
                 pre: Optional[Tuple[int, int]], post: Tuple[Tuple[int, int, str], ...]) -> None:
        self.raw = raw
        self.release = release
        self.pre = pre
        self.post = post

    def _key(self, width: int) -> tuple:
        release = self.release + (0,) * (width - len(self.release))
        # Релиз без предрелизной метки старше любого предрелиза той же версии.
        pre_key = (0,) + self.pre if self.pre is not None else (1, 0, 0)
        return (release, pre_key, self.post)

    def compare(self, other: "Version") -> int:
        width = max(len(self.release), len(other.release))
        left, right = self._key(width), other._key(width)
        return (left > right) - (left < right)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self.compare(other) == 0

    def __lt__(self, other: "Version") -> bool:
        return self.compare(other) < 0

    def __le__(self, other: "Version") -> bool:
        return self.compare(other) <= 0

    def __gt__(self, other: "Version") -> bool:
        return self.compare(other) > 0

    def __ge__(self, other: "Version") -> bool:
        return self.compare(other) >= 0

    def __hash__(self) -> int:
        release = self.release
        while release and release[-1] == 0:
            release = release[:-1]
        return hash((release, self.pre, self.post))

    def __repr__(self) -> str:
        return f"Version({self.raw!r})"


def is_unspecified(value: Optional[str]) -> bool:
    """True для пустой версии, ``*`` и ``-`` (в CPE: «любая» и «неприменимо»)."""
    return str(value or "").strip().lower() in _EMPTY


def parse_version(value: Optional[str]) -> Optional[Version]:
    """Разбирает строку версии; ``None`` — если версия не указана или не числовая."""
    raw = str(value or "").strip()
    text = raw.lower()
    if text in _EMPTY:
        return None
    text = text.split()[0]  # "2.4.49 (unix)" → "2.4.49"
    if text.startswith("v") and text[1:2].isdigit():
        text = text[1:]
    text = text.split("+", 1)[0]
    match = _RELEASE_RE.match(text)
    if not match:
        return None
    release = tuple(int(part) for part in re.split(r"[._]", match.group(0)))
    rest = _DISTRO_RE.sub("", text[match.end():])

    pre: Optional[Tuple[int, int]] = None
    post: Tuple[Tuple[int, int, str], ...] = ()
    if rest:
        pre_match = _PRE_RE.match(rest)
        attached_letter = re.fullmatch(r"[a-z]", rest) is not None
        if pre_match and not attached_letter:
            # "1.0.2a" (OpenSSL) — это патч-уровень, а не alpha: одиночная буква
            # сразу после цифр без номера считается post-релизом.
            tag = pre_match.group("tag")
            num = int(pre_match.group("num") or 0)
            pre = (PRERELEASE_RANK[tag], num)
            rest = rest[pre_match.end():]
        post = tuple(
            (1, int(token), "") if token.isdigit() else (0, 0, token)
            for token in _TOKEN_RE.findall(rest)
        )
    return Version(raw, release, pre, post)


def compare_versions(left: Optional[str], right: Optional[str]) -> Optional[int]:
    """-1 / 0 / 1 или ``None``, если хотя бы одну версию разобрать нельзя."""
    a, b = parse_version(left), parse_version(right)
    if a is None or b is None:
        return None
    return a.compare(b)


def in_range(version: Optional[str], *,
             start_including: Optional[str] = None,
             start_excluding: Optional[str] = None,
             end_including: Optional[str] = None,
             end_excluding: Optional[str] = None) -> Optional[bool]:
    """Попадает ли версия в диапазон NVD.

    Отсутствующая граница не ограничивает диапазон. Возвращает ``None``, если
    версию компонента или одну из заданных границ нельзя разобрать — тогда
    вызывающий код сам решает, считать ли совпадение ненадёжным.
    """
    current = parse_version(version)
    if current is None:
        return None
    checks = (
        (start_including, lambda c: c >= 0),
        (start_excluding, lambda c: c > 0),
        (end_including, lambda c: c <= 0),
        (end_excluding, lambda c: c < 0),
    )
    for bound, accept in checks:
        if is_unspecified(bound):
            continue
        parsed = parse_version(bound)
        if parsed is None:
            return None
        if not accept(current.compare(parsed)):
            return False
    return True


EXACT = "exact"
RANGE = "range"
PRODUCT_ONLY = "product_only"
# Версия подходит, но CVE действует только в сочетании с платформой (запись NVD с условием
# «AND»: приложение + ОС/оборудование). Платформу сканер не определяет.
PLATFORM = "platform"


def match_cpe_version(version: Optional[str], criteria_version: Optional[str], *,
                      start_including: Optional[str] = None,
                      start_excluding: Optional[str] = None,
                      end_including: Optional[str] = None,
                      end_excluding: Optional[str] = None) -> Optional[str]:
    """Сопоставляет версию компонента с записью ``cpeMatch`` из NVD.

    Возвращает ``"exact"`` (версия в CPE совпала), ``"range"`` (версия попала в
    заданный диапазон), ``"product_only"`` (в записи «все версии» без границ или
    версию нельзя сравнить с границами — совпадение только по продукту) или
    ``None`` (версия не затронута).
    """
    bounds = dict(start_including=start_including, start_excluding=start_excluding,
                  end_including=end_including, end_excluding=end_excluding)
    has_bounds = any(not is_unspecified(value) for value in bounds.values())
    if not is_unspecified(criteria_version):
        result = compare_versions(version, criteria_version)
        if result is None:
            # Нечисловые версии сравниваем как строки (без учёта регистра).
            same = str(version or "").strip().lower() == str(criteria_version).strip().lower()
            return EXACT if same else None
        return EXACT if result == 0 else None
    if has_bounds:
        inside = in_range(version, **bounds)
        if inside is None:
            # Версию нельзя сравнить с границами — совпадение только по продукту.
            return PRODUCT_ONLY
        return RANGE if inside else None
    return PRODUCT_ONLY
