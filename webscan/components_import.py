"""Импорт списка компонентов (зависимостей) для сверки с NVD, БДУ ФСТЭК, KEV и ExploitDB.

Сканер снаружи видит лишь то, что выдают заголовки и страницы; зависимости приложения
(Flask, Jinja2, библиотеки из ``requirements.txt``) по баннерам не определяются. Импорт
позволяет передать их явно: файл читается локально, наружу уходят только названия и версии
компонентов — как и у найденных по баннерам.

Поддерживаются форматы (определяются по содержимому и имени файла):

* ``requirements.txt`` — строки ``name==1.2.3`` (диапазоны без точной версии пропускаются);
* ``package-lock.json`` / ``npm-shrinkwrap.json`` (v1, v2, v3);
* ``package.json`` — только точные версии (диапазоны ``^``/``~``/``>=`` не являются установленной
  версией и пропускаются);
* ``composer.lock``;
* CycloneDX JSON и SPDX JSON (SBOM);
* простой текст: ``имя версия`` / ``имя@версия`` в строке.

Каждый компонент без известной CPE-пары помечается ``keyword_search``: подходящая пара
подбирается в NVD по названию и отфильтровывается по схожести; в БДУ он ищется по названию.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
import re
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from .fingerprint import PACKAGE_ALIASES, DetectedProduct

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_COMPONENTS = 5000
SOURCE_PREFIX = "Импорт"

# Только пары, в которых уверенность высокая (проверены по словарю CPE); остальные
# подбираются по ключевому слову.
EXTRA_ALIASES: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {
    "flask": ("Flask", [("palletsprojects", "flask")]),
    "jinja2": ("Jinja2", [("palletsprojects", "jinja2")]),
    "werkzeug": ("Werkzeug", [("palletsprojects", "werkzeug")]),
    "django": ("Django", [("djangoproject", "django")]),
    "express": ("Express", [("expressjs", "express")]),
    "axios": ("Axios", [("axios", "axios")]),
}

_REQ_LINE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?P<op>===|==)\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._+!*-]*)")
_REQ_UNPINNED = re.compile(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[^\]]*\])?\s*(?:[<>~!]=?|$|;)")
_PLAIN_LINE = re.compile(r"^\s*(?P<name>[A-Za-z0-9@][A-Za-z0-9@._/+-]*?)\s*(?:@|:|\s)\s*v?"
                         r"(?P<version>\d[A-Za-z0-9._+-]*)\s*$")
_EXACT_NPM = re.compile(r"^v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.+-]+)?$")


class ImportFailure(ValueError):
    """Файл не прочитан или формат не распознан (текст — для пользователя)."""


@dataclass
class ImportResult:
    components: List[DetectedProduct] = field(default_factory=list)
    fmt: str = ""
    skipped: int = 0             # записей без точной версии
    path: str = ""

    def note(self) -> str:
        text = (f"Импорт компонентов из {os.path.basename(self.path)} ({self.fmt}): "
                f"{len(self.components)}")
        if self.skipped:
            text += f"; пропущено без точной версии: {self.skipped}"
        return text + "."


def import_components(path: str) -> ImportResult:
    """Читает файл со списком компонентов; ``ImportFailure`` — понятное сообщение об ошибке."""
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ImportFailure(f"файл со списком компонентов недоступен: {exc.strerror or exc}") from exc
    if size > MAX_FILE_BYTES:
        raise ImportFailure(f"файл {os.path.basename(path)} больше "
                            f"{MAX_FILE_BYTES // (1024 * 1024)} МБ")
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise ImportFailure(f"файл не прочитан: {exc.strerror or exc}") from exc
    text = raw.decode("utf-8-sig", errors="replace")
    name = os.path.basename(path)

    result = ImportResult(path=path)
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ImportFailure(f"{name}: некорректный JSON ({exc})") from exc
        _from_json(data, name, result)
    else:
        _from_text(text, name, result)
    if not result.components:
        raise ImportFailure(f"{name}: компонентов с точной версией не найдено"
                            + (f" (пропущено без версии: {result.skipped})" if result.skipped else ""))
    result.components = _dedupe(result.components)[:MAX_COMPONENTS]
    return result


# --- форматы -------------------------------------------------------------------------
def _from_json(data, name: str, result: ImportResult) -> None:
    if not isinstance(data, dict):
        raise ImportFailure(f"{name}: ожидался объект JSON")
    if str(data.get("bomFormat", "")).lower() == "cyclonedx" or (
            isinstance(data.get("components"), list) and "specVersion" in data):
        result.fmt = "CycloneDX"
        for item in _cyclonedx(data.get("components") or []):
            _add(result, name, item["name"], item["version"], item.get("cpe", ""), item["where"])
    elif "spdxVersion" in data or isinstance(data.get("packages"), list) and any(
            isinstance(p, dict) and "SPDXID" in p for p in data["packages"]):
        result.fmt = "SPDX"
        for package in data.get("packages") or []:
            if not isinstance(package, dict):
                continue
            cpe = ""
            for ref in package.get("externalRefs") or []:
                if isinstance(ref, dict) and str(ref.get("referenceType", "")).lower().startswith("cpe"):
                    cpe = str(ref.get("referenceLocator") or "")
                    break
            _add(result, name, str(package.get("name") or ""), str(package.get("versionInfo") or ""),
                 cpe, f"SPDX: {package.get('SPDXID', '')}")
    elif "lockfileVersion" in data:
        result.fmt = "npm lock"
        for pkg, version in _npm_lock(data):
            _add(result, name, pkg, version, "", "npm lock")
    elif "content-hash" in data or (isinstance(data.get("packages"), list)
                                    and "packages-dev" in data):
        result.fmt = "composer.lock"
        for key in ("packages", "packages-dev"):
            for package in data.get(key) or []:
                if isinstance(package, dict):
                    _add(result, name, str(package.get("name") or ""),
                         str(package.get("version") or ""), "", "composer.lock")
    elif any(k in data for k in ("dependencies", "devDependencies", "optionalDependencies")):
        result.fmt = "package.json"
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(key)
            if isinstance(deps, dict):
                for pkg, spec in deps.items():
                    version = str(spec or "").strip()
                    if _EXACT_NPM.match(version):
                        _add(result, name, str(pkg), version, "", f"package.json {key}")
                    else:
                        result.skipped += 1
    else:
        raise ImportFailure(f"{name}: формат JSON не распознан (нужны CycloneDX, SPDX, "
                            "package-lock.json, composer.lock или package.json)")


def _cyclonedx(components: Iterable) -> Iterator[Dict[str, str]]:
    for item in components:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        group = str(item.get("group") or "")
        yield {"name": name, "version": str(item.get("version") or ""),
               "cpe": str(item.get("cpe") or ""),
               "where": "CycloneDX" + (f": {group}/{name}" if group else "")}
        nested = item.get("components")
        if isinstance(nested, list):
            yield from _cyclonedx(nested)


def _npm_lock(data: dict) -> Iterator[Tuple[str, str]]:
    packages = data.get("packages")
    if isinstance(packages, dict):                       # lockfile v2 / v3
        for key, entry in packages.items():
            if not key or not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or key.split("node_modules/")[-1])
            yield name, str(entry.get("version") or "")
    else:                                                # lockfile v1
        def walk(deps: dict) -> Iterator[Tuple[str, str]]:
            for pkg, entry in deps.items():
                if not isinstance(entry, dict):
                    continue
                yield str(pkg), str(entry.get("version") or "")
                nested = entry.get("dependencies")
                if isinstance(nested, dict):
                    yield from walk(nested)

        deps = data.get("dependencies")
        if isinstance(deps, dict):
            yield from walk(deps)


def _from_text(text: str, name: str, result: ImportResult) -> None:
    pinned = unpinned = plain = 0
    entries: List[Tuple[str, str, int]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        body = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        if not body or body.startswith(("#", "-", "\\", "--")):
            continue
        match = _REQ_LINE.match(body)
        if match:
            version = match.group("version")
            if "*" in version:
                unpinned += 1
            else:
                pinned += 1
                entries.append((match.group("name"), version, number))
            continue
        if _REQ_UNPINNED.match(body) and not _PLAIN_LINE.match(body):
            unpinned += 1
            continue
        match = _PLAIN_LINE.match(body)
        if match:
            plain += 1
            entries.append((match.group("name"), match.group("version"), number))
        else:
            unpinned += 1
    result.fmt = "requirements.txt" if pinned >= plain else "список «имя версия»"
    result.skipped += unpinned
    for pkg, version, number in entries:
        _add(result, name, pkg, version, "", f"строка {number}")


# --- общее ---------------------------------------------------------------------------
def _add(result: ImportResult, filename: str, name: str, version: str, cpe: str, where: str) -> None:
    name = name.strip()
    version = version.strip().lstrip("vV=")
    if not name or not re.match(r"^\d", version):
        result.skipped += 1
        return
    key = name.lower()
    short = key.split("/")[-1]
    alias = (EXTRA_ALIASES.get(key) or EXTRA_ALIASES.get(short)
             or PACKAGE_ALIASES.get(key) or PACKAGE_ALIASES.get(short))
    pairs: List[Tuple[str, str]] = []
    label = name
    if alias:
        label, pairs = alias[0], [tuple(pair) for pair in alias[1]]  # type: ignore[misc]
    elif cpe:
        parsed = _cpe_pair(cpe)
        if parsed:
            pairs = [parsed]
    vendor, product = (pairs[0] if pairs else ("", _normalise_product(short)))
    result.components.append(DetectedProduct(
        vendor=vendor, product=product, version=version,
        source=f"{SOURCE_PREFIX}: {result.fmt}",
        evidence=f"{filename}, {where}",
        confidence="high", label=label, cpe_pairs=pairs,
        keyword_search=not pairs,
    ))


def _cpe_pair(cpe: str) -> Optional[Tuple[str, str]]:
    parts = cpe.split(":")
    if len(parts) > 5 and parts[0] == "cpe" and parts[3] not in ("", "*", "-") \
            and parts[4] not in ("", "*", "-"):
        return parts[3], parts[4]
    return None


def _normalise_product(name: str) -> str:
    return re.sub(r"[^a-z0-9._+-]+", "_", name.lower()).strip("_")


def _dedupe(items: List[DetectedProduct]) -> List[DetectedProduct]:
    found: Dict[Tuple[str, str, str], DetectedProduct] = {}
    for item in items:
        key = (item.vendor.lower(), item.product.lower(), item.version.lower())
        current = found.get(key)
        if current is None:
            found[key] = item
        else:
            current.merge(item)
    return list(found.values())
