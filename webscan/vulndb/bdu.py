"""БДУ ФСТЭК России: загрузка выгрузки ``vullist.xlsx`` и индекс по CVE.

Выгрузка (~35 МБ, ~97 тыс. записей) скачивается целиком и сопоставляется
локально; цели и внешним сервисам ничего не отправляется. Формат — XLSX, но
читается он стандартной библиотекой (``zipfile`` + ``iterparse``), без
``openpyxl``: внутри архива лежит ``sharedStrings.xml`` на 200+ МБ, и потоковый
разбор с отбором нужных строк обходится заметно дешевле по памяти.

Что делает модуль:

* скачивает и кэширует XLSX (ETag/Last-Modified, если сервер их отдаёт);
* разбирает лист «Уязвимости» по **названиям колонок**, а не по буквам — сдвиг
  колонок в будущих выгрузках не ломает разбор;
* строит компактный индекс ``BDU-ID → запись`` и ``CVE → [BDU-ID]``;
* сохраняет его в SQLite рядом с кэшем (перестраивается только при смене sha256) —
  при скане читаются лишь записи нужных CVE, а не весь индекс целиком;
* разбирает «Версия ПО» в проверяемые выражения и ищет записи **по продукту и
  версии** (``for_product``) — для уязвимостей, которых NVD не связал с версией
  компонента или в которых нет CVE вовсе.

Семантика выражений версии БДУ (проверена по выгрузке, ~750 тыс. вхождений):
``X`` — ровно эта версия; ``до X`` — строго ниже X; ``до X включительно``;
``от X до Y`` — от X включительно до Y **не включая**; ``от X до Y включительно``.
Всё, что содержит слова (SP, Update, названия релизов) или «-», не оценивается:
лучше пропустить запись, чем выдать подозрение по неразобранной версии.

Безопасность разбора: читаются только именованные части архива (ничего не
распаковывается на диск), размер каждой части и число строк ограничены, а
счётчик считает уже распакованные байты — заниженный размер в заголовке ZIP не
обходит лимит.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple, Union
import xml.etree.ElementTree as ET
import zipfile
import zlib

from .cache import (FRESH, CacheStore, NotModified, SourceStatus, load_with_cache,
                    now_iso, short_error)
from .catalog_http import CatalogHttpClient
from .versions import EXACT, RANGE, in_range

BDU_URLS = ("https://bdu.fstec.ru/files/documents/vullist.xlsx",)
BDU_CACHE = "bdu/vullist.xlsx"
BDU_STORE = "bdu/index.sqlite"
BDU_DETAIL = "https://bdu.fstec.ru/vul/{number}"
INDEX_VERSION = 6
BATCH = 500  # переменных в одном SQL-запросе (лимит SQLite — 999 в старых сборках)

MAX_XLSX_BYTES = 150 * 1024 * 1024         # сам скачиваемый файл (сейчас ~35 МБ)
MAX_STRINGS_BYTES = 600 * 1024 * 1024      # sharedStrings.xml в распакованном виде (сейчас ~205 МБ)
MAX_SHEET_BYTES = 500 * 1024 * 1024        # лист в распакованном виде (сейчас ~120 МБ)
MAX_SMALL_PART_BYTES = 4 * 1024 * 1024     # workbook.xml и rels
MAX_ROWS = 1_000_000                       # сейчас ~97 тыс.
HEADER_SCAN_ROWS = 50
MIN_HEADER_CELLS = 8
SHEET_NAME = "уязвимости"

BDU_ID_RE = re.compile(r"^BDU:\d{4}-\d{4,6}$")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
CVSS_SCORE_RE = re.compile(r"CVSS\s*(\d(?:\.\d)?)\s+составляет\s+(\d+(?:[.,]\d+)?)", re.I)
URL_RE = re.compile(r"https?://[^\s,;<>\"']+")

# ключ записи -> заголовок колонки в выгрузке (сравнение без регистра и лишних пробелов)
FIELDS: Dict[str, str] = {
    "id": "Идентификатор",
    "title": "Наименование уязвимости",
    "vendor": "Вендор ПО",
    "product": "Название ПО",
    "versions": "Версия ПО",
    "severity": "Уровень опасности уязвимости",
    "measures": "Возможные меры по устранению",
    "status": "Статус уязвимости",
    "exploit": "Наличие эксплойта",
    "fix": "Информация об устранении",
    "sources": "Ссылки на источники",
    "other_ids": "Идентификаторы других систем описаний уязвимости",
    "incident": "Связь с инцидентами ИБ",
    "exploitation": "Способ эксплуатации",
    "remediation": "Способ устранения",
    "published": "Дата публикации",
    "updated": "Дата последнего обновления",
    "cwe": "Тип ошибки CWE",
}
REQUIRED_FIELDS = ("id", "vendor", "product", "other_ids")

# Индекс хранит только то, что попадает в отчёт. Списки версий, платформ и вендоров у
# многопродуктовых записей занимали >200 МБ и для обогащения по CVE не нужны, поэтому
# они не читаются вовсе; vendor/product остаются короткой подписью.
CLIP = {"title": 300, "vendor": 80, "product": 80, "measures": 200,
        "remediation": 120, "exploitation": 120, "incident": 60}
MAX_SOURCE_URLS = 3

EXPLOIT_LABELS = {
    "public": "эксплойт в открытом доступе",
    "exists": "эксплойт существует",
    "none": "эксплойт отсутствует",
    "unknown": "наличие эксплойта уточняется",
}
FIX_LABELS = {
    "fixed": "устранена",
    "unfixed": "не устранена",
    "unknown": "информации об устранении нет",
}
LEVELS = (("критическ", "critical"), ("высок", "high"), ("средн", "medium"), ("низк", "low"))
LEVEL_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}

Raw = Union[int, str]  # int — индекс в sharedStrings, str — готовое значение


@dataclass
class BduIndex:
    """Разобранная выгрузка: записи по BDU-ID и обратный индекс по CVE."""

    records: Dict[str, dict] = field(default_factory=dict)
    by_cve: Dict[str, List[str]] = field(default_factory=dict)
    catalog_date: str = ""
    # нормализованное название продукта -> [(BDU-ID, выражение версии, название как в БДУ)]
    affected: Dict[str, List[Tuple[str, str, str]]] = field(default_factory=dict)
    vendors: Dict[str, List[str]] = field(default_factory=dict)  # BDU-ID -> производители (norm)

    def __len__(self) -> int:
        return len(self.records)

    def get(self, bdu_id: str) -> Optional[dict]:
        record = self.records.get(str(bdu_id or "").strip().upper())
        return _public(record) if record else None

    def for_cve(self, cve_id: str) -> List[dict]:
        """Записи БДУ для CVE (пустой список, если CVE в БДУ нет)."""
        ids = self.by_cve.get(str(cve_id or "").strip().upper(), [])
        return [_public(self.records[item]) for item in ids if item in self.records]

    def for_cves(self, cve_ids) -> Dict[str, List[dict]]:
        """``{CVE: [записи БДУ]}`` только для CVE, которые есть в БДУ."""
        result: Dict[str, List[dict]] = {}
        for cve_id in cve_ids:
            found = self.for_cve(cve_id)
            if found:
                result[str(cve_id).strip().upper()] = found
        return result

    def for_product(self, query: "ProductQuery", version: str) -> List[dict]:
        """Записи БДУ, в которых продукт назван как ``query`` и ``version`` попадает в версии."""
        return _match_product(self, query, version)

    def _candidate_rows(self, names) -> List[Tuple[str, str, str, str]]:
        return [(name, bdu_id, expr, raw) for name in names
                for bdu_id, expr, raw in self.affected.get(name, [])]

    def _vendors_for(self, ids) -> Dict[str, List[str]]:
        return {item: self.vendors.get(item, []) for item in ids}


def _public(record: dict) -> dict:
    """Запись для отчёта: к сохранённым полям добавляется ссылка на карточку БДУ."""
    result = dict(record)
    result["url"] = BDU_DETAIL.format(number=str(record.get("id", ""))[4:])
    return result


def _dump(record: dict) -> bytes:
    return json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _make_zdict(records: Dict[str, dict]) -> bytes:
    """Словарь для zlib из равномерной выборки записей.

    Поля записей БДУ повторяются слово в слово (статусы, меры, ключи JSON), поэтому
    общий словарь сжимает кэш в несколько раз сильнее, чем сжатие каждой записи отдельно.
    """
    values = list(records.values())
    if not values:
        return b""
    step = max(1, len(values) // 120)
    return b"".join(_dump(record) for record in values[::step])[-32768:]


def _pack(record: dict, zdict: bytes) -> bytes:
    packer = zlib.compressobj(9, zdict=zdict) if zdict else zlib.compressobj(9)
    return packer.compress(_dump(record)) + packer.flush()


def _unpack(blob, zdict: bytes) -> dict:
    unpacker = zlib.decompressobj(zdict=zdict) if zdict else zlib.decompressobj()
    return json.loads((unpacker.decompress(blob) + unpacker.flush()).decode("utf-8"))


class BduStore:
    """Тот же интерфейс, что у ``BduIndex``, но данные лежат в SQLite-файле кэша.

    Соединение открывается на каждый запрос и сразу закрывается: так файл не
    остаётся занятым (в Windows его иначе нельзя заменить при обновлении), а
    несколько потоков UI-сервера не делят одно соединение.
    """

    def __init__(self, path) -> None:
        self.path = Path(path)
        meta = self._meta()
        self.catalog_date = str(meta.get("catalog_date", ""))
        self.sha256 = str(meta.get("sha256", ""))
        self.version = str(meta.get("version", ""))
        zdict = meta.get("zdict", b"")
        self._zdict = zdict if isinstance(zdict, bytes) else b""
        try:
            self._count = int(meta.get("count") or 0)
        except ValueError:
            self._count = 0

    def __len__(self) -> int:
        return self._count

    def usable(self, digest: str) -> bool:
        return self.version == str(INDEX_VERSION) and self.sha256 == digest and self._count > 0

    def get(self, bdu_id: str) -> Optional[dict]:
        rows = self._query("SELECT data FROM records WHERE id = ?",
                           (str(bdu_id or "").strip().upper(),))
        return _public(_unpack(rows[0][0], self._zdict)) if rows else None

    def for_cve(self, cve_id: str) -> List[dict]:
        rows = self._query(
            "SELECT r.data FROM cves c JOIN records r ON r.n = c.r WHERE c.cve = ? ORDER BY r.id",
            (str(cve_id or "").strip().upper(),))
        return [_public(_unpack(row[0], self._zdict)) for row in rows]

    def for_cves(self, cve_ids) -> Dict[str, List[dict]]:
        """Пакетный поиск: один запрос на ``BATCH`` CVE вместо запроса на каждую."""
        wanted = list(dict.fromkeys(str(item or "").strip().upper() for item in cve_ids if item))
        result: Dict[str, List[dict]] = {}
        for start in range(0, len(wanted), BATCH):
            chunk = wanted[start:start + BATCH]
            rows = self._query(
                "SELECT c.cve, r.data FROM cves c JOIN records r ON r.n = c.r "
                f"WHERE c.cve IN ({','.join('?' * len(chunk))}) ORDER BY r.id", tuple(chunk))
            for cve, data in rows:
                result.setdefault(cve, []).append(_public(_unpack(data, self._zdict)))
        return result

    def for_product(self, query: "ProductQuery", version: str) -> List[dict]:
        return _match_product(self, query, version)

    def _candidate_rows(self, names) -> List[Tuple[str, str, str, str]]:
        wanted = sorted(set(names))
        rows: List[Tuple[str, str, str, str]] = []
        for start in range(0, len(wanted), BATCH):
            chunk = wanted[start:start + BATCH]
            rows.extend(self._query(
                "SELECT sn.s, r.id, se.s, sw.s FROM strings sn "
                "JOIN affected a ON a.name = sn.n JOIN records r ON r.n = a.r "
                "JOIN strings se ON se.n = a.expr JOIN strings sw ON sw.n = a.raw "
                f"WHERE sn.s IN ({','.join('?' * len(chunk))})", tuple(chunk)))
        return rows

    def _vendors_for(self, ids) -> Dict[str, List[str]]:
        wanted = sorted(set(ids))
        result: Dict[str, List[str]] = {}
        for start in range(0, len(wanted), BATCH):
            chunk = wanted[start:start + BATCH]
            for bdu_id, joined in self._query(
                    "SELECT r.id, v.v FROM vendors v JOIN records r ON r.n = v.r "
                    f"WHERE r.id IN ({','.join('?' * len(chunk))})",
                    tuple(chunk)):
                result[bdu_id] = joined.split("|") if joined else []
        return result

    def _query(self, sql: str, params: tuple = ()) -> list:
        if not self.path.is_file():
            return []
        try:
            connection = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro",
                                         uri=True, timeout=10)
        except sqlite3.Error:
            return []
        try:
            return connection.execute(sql, params).fetchall()
        except sqlite3.Error:
            return []
        finally:
            connection.close()

    def _meta(self) -> Dict[str, str]:
        return {key: value for key, value in self._query("SELECT key, value FROM meta")}


def write_store(path, index: BduIndex, digest: str) -> BduStore:
    """Пишет индекс в SQLite во временный файл и атомарно подменяет им прежний."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp_name = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=str(path.parent))
    os.close(handle)
    try:
        connection = sqlite3.connect(tmp_name)
        try:
            connection.executescript(
                "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);"
                "CREATE TABLE records (n INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, "
                "data BLOB NOT NULL);"
                "CREATE TABLE cves (cve TEXT NOT NULL, r INTEGER NOT NULL);"
                "CREATE TABLE strings (n INTEGER PRIMARY KEY, s TEXT UNIQUE NOT NULL);"
                "CREATE TABLE affected (name INTEGER NOT NULL, r INTEGER NOT NULL, "
                "expr INTEGER NOT NULL, raw INTEGER NOT NULL);"
                "CREATE TABLE vendors (r INTEGER PRIMARY KEY, v TEXT NOT NULL);")
            zdict = _make_zdict(index.records)
            numbers = {bdu_id: number for number, bdu_id in enumerate(index.records, 1)}
            connection.executemany(
                "INSERT INTO records VALUES (?, ?, ?)",
                ((numbers[key], key, _pack(value, zdict)) for key, value in index.records.items()))
            connection.executemany(
                "INSERT INTO cves VALUES (?, ?)",
                ((cve, numbers[bdu_id]) for cve, ids in index.by_cve.items()
                 for bdu_id in ids if bdu_id in numbers))
            connection.execute("CREATE INDEX cves_by_cve ON cves (cve)")
            # Повторяющиеся строки (названия, выражения версий) хранятся один раз.
            interned: Dict[str, int] = {}

            def intern(text: str) -> int:
                number = interned.get(text)
                if number is None:
                    number = interned[text] = len(interned) + 1
                return number

            rows = [(intern(name), numbers[bdu_id], intern(expr), intern(raw))
                    for name, items in index.affected.items()
                    for bdu_id, expr, raw in items if bdu_id in numbers]
            connection.executemany("INSERT INTO strings VALUES (?, ?)",
                                   ((number, text) for text, number in interned.items()))
            connection.executemany("INSERT INTO affected VALUES (?, ?, ?, ?)", rows)
            connection.execute("CREATE INDEX affected_by_name ON affected (name)")
            connection.executemany(
                "INSERT INTO vendors VALUES (?, ?)",
                ((numbers[bdu_id], "|".join(names)) for bdu_id, names in index.vendors.items()
                 if bdu_id in numbers))
            connection.executemany("INSERT INTO meta VALUES (?, ?)", [
                ("version", str(INDEX_VERSION)), ("sha256", digest),
                ("catalog_date", index.catalog_date), ("count", str(len(index.records))),
                ("zdict", zdict),
            ])
            connection.commit()
        finally:
            connection.close()
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return BduStore(path)


class BduCatalog:
    def __init__(self, cache: CacheStore, http: CatalogHttpClient, *, ttl_hours: float,
                 refresh: bool = False, offline: bool = False, local_file: str = "",
                 log: Callable[[str], None] = lambda _msg: None) -> None:
        self.cache = cache
        self.http = http
        self.ttl_hours = ttl_hours
        self.refresh = refresh
        self.offline = offline
        self.local_file = local_file
        self.log = log
        self.status = SourceStatus("БДУ ФСТЭК")

    def load(self) -> Union[BduIndex, BduStore]:
        """Индекс БДУ (``get`` / ``for_cve``); пустой, если источник недоступен."""
        before = self.http.requests_made
        if self.local_file:
            raw = self._read_local(Path(self.local_file))
        else:
            raw = load_with_cache(self.cache, BDU_CACHE, self.status, self._download,
                                  ttl_hours=self.ttl_hours, refresh=self.refresh,
                                  offline=self.offline, log=self.log)
            if raw is None:
                raw = self._read_fallback_file()
        self.status.requests = self.http.requests_made - before
        if raw is None:
            return BduIndex()
        digest = hashlib.sha256(raw).hexdigest()
        index: Union[BduIndex, BduStore] = BduStore(self.cache.path(BDU_STORE))
        if not index.usable(digest):
            self.log("      … БДУ ФСТЭК: разбор выгрузки (около минуты, выполняется один раз)")
            try:
                parsed = parse_bdu_xlsx(raw)
            except ValueError as exc:
                self.status.state = "unavailable"
                self.status.message = f"повреждённая выгрузка БДУ: {short_error(exc)}"
                return BduIndex()
            try:
                index = write_store(self.cache.path(BDU_STORE), parsed, digest)
            except (OSError, sqlite3.Error) as exc:  # кэш недоступен — работаем из памяти
                self.log(f"      ! БДУ ФСТЭК: индекс не сохранён: {short_error(exc)}")
                index = parsed
        if index.catalog_date:
            self.status.data_date = index.catalog_date
        self.status.records = len(index)
        return index

    # --- источники данных ------------------------------------------------------------
    def _read_fallback_file(self) -> Optional[bytes]:
        """Выгрузка, положенная рядом с кэшем, когда скачать БДУ не удалось.

        Ищем ``<кэш>/vullist.xlsx`` и ``<кэш>/../bdu/vullist.xlsx`` (для кэша по умолчанию —
        ``~/.spyvision/bdu/vullist.xlsx``): файл подхватывается без ``--bdu-file``.
        """
        root = Path(self.cache.root)
        for path in (root / "vullist.xlsx", root.parent / "bdu" / "vullist.xlsx"):
            if path.is_file():
                before = (self.status.state, self.status.message)
                raw = self._read_local(path)
                if raw is not None:
                    self.log(f"      … БДУ ФСТЭК: загрузка недоступна, использован файл {path}")
                    return raw
                self.status.state, self.status.message = before
        return None

    def _read_local(self, path: Path) -> Optional[bytes]:
        path = path.expanduser()
        try:
            if path.stat().st_size > MAX_XLSX_BYTES:
                raise OSError(f"файл больше {MAX_XLSX_BYTES // (1024 * 1024)} МБ")
            raw = path.read_bytes()
            _check_xlsx_signature(raw)
        except (OSError, ValueError) as exc:
            self.status.state = "unavailable"
            self.status.message = f"локальный файл БДУ не прочитан: {short_error(exc)}"
            return None
        self.status.state = FRESH
        self.status.data_date = datetime.fromtimestamp(
            path.stat().st_mtime, timezone.utc).replace(microsecond=0).isoformat()
        self.status.message = f"использован локальный файл {path.name}"
        return raw

    def _download(self, meta: Dict[str, object]) -> Tuple[bytes, Dict[str, str]]:
        headers: Dict[str, str] = {}
        if meta.get("etag"):
            headers["If-None-Match"] = str(meta["etag"])
        if meta.get("last_modified"):
            headers["If-Modified-Since"] = str(meta["last_modified"])
        error: Optional[Exception] = None
        for url in BDU_URLS:
            try:
                self.log("      ↓ БДУ ФСТЭК: загрузка vullist.xlsx (~35 МБ)")
                result = self.http.get(url, headers=headers, max_bytes=MAX_XLSX_BYTES,
                                       accept_304=True, label="БДУ ФСТЭК")
                if result.status == 304:
                    raise NotModified()
                _check_xlsx_signature(result.content)
                return result.content, {
                    "source_url": url,
                    "etag": result.header("ETag"),
                    "last_modified": result.header("Last-Modified"),
                    "data_date": now_iso(),
                }
            except NotModified:
                raise
            except Exception as exc:  # noqa: BLE001 - сбой источника не ломает скан
                error = exc
        raise error or RuntimeError("БДУ ФСТЭК недоступен")


# --- разбор XLSX ---------------------------------------------------------------------
def parse_bdu_xlsx(raw: bytes, *, max_rows: int = MAX_ROWS) -> BduIndex:
    """Разбирает ``vullist.xlsx`` → ``BduIndex``. ``ValueError`` — файл не тот или повреждён."""
    _check_xlsx_signature(raw)
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ValueError("файл не является XLSX (ZIP)") from exc
    with archive:
        sheet_path = _find_sheet_path(archive)
        has_strings = "xl/sharedStrings.xml" in archive.namelist()

        header_row, header_cells = _scan_header(archive, sheet_path)
        header_text = _resolve(archive, {col: value for col, value in header_cells.items()},
                               has_strings)
        columns = _map_columns(header_text)

        wanted_cols = set(columns.values())
        rows: List[Dict[str, Raw]] = []
        needed: Set[int] = set()
        field_by_col = {col: key for key, col in columns.items()}
        for number, cells in _iter_rows(archive, sheet_path, wanted_cols):
            if number <= header_row:
                continue
            if len(rows) >= max_rows:
                raise ValueError(f"в выгрузке больше {max_rows} строк")
            row = {field_by_col[col]: value for col, value in cells.items()}
            if not row.get("id"):
                continue
            rows.append(row)
            needed.update(value for value in row.values() if isinstance(value, int))

        strings = _load_strings(archive, needed) if needed and has_strings else {}

    return _build_index(rows, strings)


def _build_index(rows: List[Dict[str, Raw]], strings: Dict[int, str]) -> BduIndex:
    index = BduIndex()
    latest = ""
    for row in rows:
        values = {key: _text(value, strings) for key, value in row.items()}
        bdu_id = values.get("id", "").upper()
        if not BDU_ID_RE.match(bdu_id):
            continue
        record = _normalise(bdu_id, values)
        index.records[bdu_id] = record
        entries, vendor_names = extract_affected(values)
        for name, expr, raw in entries:
            index.affected.setdefault(name, []).append((bdu_id, expr, raw))
        if entries:
            index.vendors[bdu_id] = vendor_names
        for cve in record.get("cves", []):
            bucket = index.by_cve.setdefault(cve, [])
            if bdu_id not in bucket:
                bucket.append(bdu_id)
        if record.get("updated", "") > latest:
            latest = record["updated"]
    index.catalog_date = latest
    return index


def _normalise(bdu_id: str, values: Dict[str, str]) -> dict:
    record: dict = {"id": bdu_id}
    for key in ("title", "vendor", "product", "measures", "status", "incident",
                "exploitation", "remediation", "cwe"):
        text = _clip(values.get(key, ""), CLIP.get(key, 200))
        if text:
            record[key] = text
    other = values.get("other_ids", "")
    cves: List[str] = []
    for match in CVE_RE.finditer(other):
        cve = match.group(0).upper()
        if cve not in cves:
            cves.append(cve)
    record["cves"] = cves
    record["exploit"] = _exploit_code(values.get("exploit", ""))
    record["fix"] = _fix_code(values.get("fix", ""))
    scores, level = _severity(values.get("severity", ""))
    if scores:
        record["scores"] = scores
    record["level"] = level
    urls = [url.rstrip(".)") for url in URL_RE.findall(values.get("sources", ""))]
    if urls:
        record["links"] = list(dict.fromkeys(urls))[:MAX_SOURCE_URLS]
    for key in ("published", "updated"):
        iso = _iso_date(values.get(key, ""))
        if iso:
            record[key] = iso
    return record


# --- прямой поиск по продукту и версии ------------------------------------------------
MAX_ENTRIES_PER_RECORD = 400   # у записей про ОС и прошивки бывают тысячи версий
MAX_VENDORS_PER_RECORD = 30
MIN_VENDOR_LEN = 3
# Короткие общие слова: совпадение названия без согласования производителя — частый
# источник ложных срабатываний (``Express`` и российский мессенджер ``eXpress``).
AMBIGUOUS_NAMES = frozenset({
    "express", "react", "ghost", "next", "core", "server", "admin", "panel", "portal",
    "cms", "agent", "gateway", "manager", "client", "shop", "forum", "mail", "web",
})

_DELIMS = re.compile(r"[(\[«»)\],]")
_ENTRY_RE = re.compile(r"^(.*?)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$")
_V = r"(\d+(?:\.\d+)*[a-z]?)"
_RE_UP_TO_INCL = re.compile(rf"^до {_V} включительно$")
_RE_UP_TO = re.compile(rf"^до {_V}$")
_RE_FROM_TO_INCL = re.compile(rf"^от {_V} до {_V} включительно$")
_RE_FROM_TO = re.compile(rf"^от {_V} до {_V}$")
_RE_EXACT = re.compile(rf"^{_V}$")

VersionSpec = Tuple[Optional[str], bool, Optional[str], bool]  # (lo, lo_incl, hi, hi_incl)


def norm_name(text: str) -> str:
    """Название для сравнения: без регистра, пробелов и знаков (``HTTP Server`` → ``httpserver``)."""
    return re.sub(r"[^0-9a-zа-яё]+", "", str(text or "").casefold())


def split_top(text: str) -> List[str]:
    """Делит по запятым вне скобок и кавычек «»."""
    parts: List[str] = []
    depth = 0
    start = 0
    for match in _DELIMS.finditer(text or ""):
        char = match.group()
        if char in "([«":
            depth += 1
        elif char in ")]»":
            depth = max(0, depth - 1)
        elif depth == 0:
            parts.append(text[start:match.start()].strip())
            start = match.end()
    parts.append((text or "")[start:].strip())
    return [part for part in parts if part]


def parse_version_expr(expr: str) -> Optional[VersionSpec]:
    """Выражение версии БДУ → границы; ``None``, если его нельзя оценить надёжно."""
    text = " ".join(str(expr or "").casefold().split())
    match = _RE_UP_TO_INCL.match(text)
    if match:
        return (None, False, match.group(1), True)
    match = _RE_UP_TO.match(text)
    if match:
        return (None, False, match.group(1), False)
    match = _RE_FROM_TO_INCL.match(text)
    if match:
        return (match.group(1), True, match.group(2), True)
    match = _RE_FROM_TO.match(text)
    if match:
        return (match.group(1), True, match.group(2), False)
    match = _RE_EXACT.match(text)
    if match:
        return (match.group(1), True, match.group(1), True)
    return None


def version_in_expr(version: str, expr: str) -> Optional[str]:
    """``EXACT`` / ``RANGE``, если версия подпадает под выражение, иначе ``None``."""
    spec = parse_version_expr(expr)
    if spec is None:
        return None
    low, low_incl, high, high_incl = spec
    inside = in_range(version,
                      start_including=low if low_incl else None,
                      start_excluding=None if low_incl else low,
                      end_including=high if high_incl else None,
                      end_excluding=None if high_incl else high)
    if not inside:  # False — вне диапазона, None — версию не удалось разобрать
        return None
    return EXACT if low is not None and low == high else RANGE


def extract_affected(values: Dict[str, str]) -> Tuple[List[Tuple[str, str, str]], List[str]]:
    """``[(название_norm, выражение, название_как_в_БДУ)]`` и производители записи (norm).

    Версии в БДУ записаны как ``<выражение> (<продукт>)``; без скобок продукт берётся
    из колонки «Название ПО», но только если он один. Производители не выровнены
    с продуктами (число не совпадает у ~40 % записей), поэтому хранятся списком на запись.
    """
    products = split_top(values.get("product", ""))
    vendors = [item for item in (norm_name(v) for v in split_top(values.get("vendor", "")))
               if item][:MAX_VENDORS_PER_RECORD]
    rows: List[Tuple[str, str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for entry in split_top(values.get("versions", ""))[:MAX_ENTRIES_PER_RECORD]:
        match = _ENTRY_RE.match(entry)
        if match:
            expr, raw = match.group(1).strip(), match.group(2).strip()
        elif len(products) == 1:
            expr, raw = entry, products[0]
        else:
            continue
        if parse_version_expr(expr) is None:
            continue
        name = norm_name(raw)
        if not name or (name, expr) in seen:
            continue
        seen.add((name, expr))
        rows.append((name, expr, raw[:120]))
    return rows, vendors


@dataclass
class ProductQuery:
    """Какие названия БДУ считать названием обнаруженного компонента.

    ``names`` — принимаются как есть (полное название или «производитель + продукт»);
    ``vendor_names`` — короткое имя продукта из CPE (``http_server``), которое
    принимается, только если производитель записи БДУ согласуется с одним из
    указанных (``apache`` ⊂ ``apachesoftwarefoundation``).
    """

    names: Set[str] = field(default_factory=set)
    vendor_names: Dict[str, Set[str]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.names or self.vendor_names)


def product_query(label: str, cpe_pairs) -> ProductQuery:
    query = ProductQuery()
    pairs = [(norm_name(v), norm_name(p)) for v, p in (cpe_pairs or [])]
    vendors = {v for v, _p in pairs if len(v) >= MIN_VENDOR_LEN}
    label_norm = norm_name(label)
    if label_norm:
        if label_norm in AMBIGUOUS_NAMES:
            query.vendor_names.setdefault(label_norm, set()).update(vendors)
        else:
            query.names.add(label_norm)
    for vendor, product in pairs:
        if vendor and product:
            query.names.add(vendor + product)
        if product and product not in query.names:
            query.vendor_names.setdefault(product, set()).add(vendor)
    return query


def _vendor_ok(record_vendors, wanted) -> bool:
    return any(w in v or v in w
               for w in wanted if len(w) >= MIN_VENDOR_LEN
               for v in record_vendors if len(v) >= MIN_VENDOR_LEN)


def _match_product(source, query: ProductQuery, version: str) -> List[dict]:
    if not query or not str(version or "").strip():
        return []
    wanted = set(query.names) | set(query.vendor_names)
    rows = source._candidate_rows(wanted)
    need_vendors = {bdu_id for name, bdu_id, _expr, _raw in rows if name not in query.names}
    vendors = source._vendors_for(need_vendors) if need_vendors else {}
    best: Dict[str, Tuple[int, str, str, str]] = {}
    for name, bdu_id, expr, raw in rows:
        if name not in query.names:
            if not _vendor_ok(vendors.get(bdu_id, ()), query.vendor_names.get(name, ())):
                continue
        kind = version_in_expr(version, expr)
        if kind is None:
            continue
        rank = 2 if kind == EXACT else 1
        if bdu_id not in best or rank > best[bdu_id][0]:
            best[bdu_id] = (rank, kind, expr, raw)
    found: List[dict] = []
    for bdu_id, (_rank, kind, expr, raw) in sorted(best.items()):
        record = source.get(bdu_id)
        if record:
            found.append(dict(record, matched_name=raw, version_expr=expr, version_match=kind))
    return found


def _exploit_code(text: str) -> str:
    value = text.casefold()
    if "в открытом доступе" in value:
        return "public"
    if value.startswith("существует"):
        return "exists"
    if "отсутству" in value:
        return "none"
    return "unknown"


def _fix_code(text: str) -> str:
    value = text.casefold()
    if "не устранен" in value:
        return "unfixed"
    if "устранена" in value or "устранено" in value:
        return "fixed"
    return "unknown"


def _severity(text: str) -> Tuple[Dict[str, float], str]:
    """``{'3.0': 8.8, ...}`` и самый высокий качественный уровень из строки опасности."""
    scores: Dict[str, float] = {}
    for match in CVSS_SCORE_RE.finditer(text):
        try:
            version = match.group(1) if "." in match.group(1) else match.group(1) + ".0"
            scores[version] = float(match.group(2).replace(",", "."))
        except ValueError:
            continue
    best = ""
    folded = text.casefold()
    for prefix, code in LEVELS:
        if prefix in folded and LEVEL_ORDER[code] > LEVEL_ORDER[best]:
            best = code
    return scores, best


def _iso_date(value: str) -> str:
    text = value.strip()
    match = re.match(r"^(\d{2})\.(\d{2})\.(\d{4})$", text)
    if match:
        return f"{match.group(3)}-{match.group(2)}-{match.group(1)}"
    if re.match(r"^\d{4}-\d{2}-\d{2}", text):
        return text[:10]
    if re.match(r"^\d{5}(\.\d+)?$", text):  # серийный номер даты Excel
        try:
            return (date(1899, 12, 30) + timedelta(days=int(float(text)))).isoformat()
        except (OverflowError, ValueError):
            return ""
    return ""


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _text(value: Raw, strings: Dict[int, str]) -> str:
    if isinstance(value, int):
        return strings.get(value, "")
    return str(value or "")


# --- уровень XLSX/OOXML --------------------------------------------------------------
def _check_xlsx_signature(raw: bytes) -> None:
    if raw[:4] != b"PK\x03\x04":
        raise ValueError("ответ не похож на XLSX (нет сигнатуры ZIP)")


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


class _Limited:
    """Читает часть архива и обрывает разбор, если распакованных байт больше лимита."""

    def __init__(self, stream, limit: int, label: str) -> None:
        self._stream = stream
        self._limit = limit
        self._label = label
        self._seen = 0

    def read(self, size: int = -1) -> bytes:
        data = self._stream.read(size)
        self._seen += len(data)
        if self._seen > self._limit:
            raise ValueError(f"{self._label}: распакованный размер больше "
                             f"{self._limit // (1024 * 1024)} МБ")
        return data

    def close(self) -> None:
        self._stream.close()


def _open_part(archive: zipfile.ZipFile, name: str, limit: int) -> _Limited:
    try:
        info = archive.getinfo(name)
    except KeyError:
        raise ValueError(f"в архиве нет части {name}") from None
    if info.file_size > limit:
        raise ValueError(f"{name}: размер {info.file_size // (1024 * 1024)} МБ превышает лимит")
    return _Limited(archive.open(info), limit, name)


def _read_small(archive: zipfile.ZipFile, name: str) -> bytes:
    stream = _open_part(archive, name, MAX_SMALL_PART_BYTES)
    try:
        return stream.read()
    finally:
        stream.close()


def _find_sheet_path(archive: zipfile.ZipFile) -> str:
    """Путь к листу «Уязвимости» (если такого имени нет — к первому листу)."""
    try:
        workbook = ET.fromstring(_read_small(archive, "xl/workbook.xml"))
        rels = ET.fromstring(_read_small(archive, "xl/_rels/workbook.xml.rels"))
    except ET.ParseError as exc:
        raise ValueError(f"повреждён workbook.xml: {exc}") from exc
    targets = {rel.get("Id"): rel.get("Target") or "" for rel in rels}
    sheets: List[Tuple[str, str]] = []
    for element in workbook.iter():
        if _local(element.tag) != "sheet":
            continue
        rel_id = next((value for key, value in element.attrib.items()
                       if _local(key) == "id"), "")
        target = targets.get(rel_id, "")
        if target:
            path = target.lstrip("/")
            sheets.append((element.get("name") or "", path if path.startswith("xl/") else "xl/" + path))
    if not sheets:
        raise ValueError("в книге нет листов")
    for name, path in sheets:
        if name.strip().casefold() == SHEET_NAME:
            return path
    return sheets[0][1]


def _column(ref: str) -> str:
    match = re.match(r"[A-Za-z]+", ref or "")
    return match.group(0).upper() if match else ""


def _col_number(letters: str) -> int:
    number = 0
    for char in letters:
        number = number * 26 + (ord(char) - 64)
    return number


def _col_letters(number: int) -> str:
    letters = ""
    while number > 0:
        number, rest = divmod(number - 1, 26)
        letters = chr(65 + rest) + letters
    return letters


def _cell_value(cell) -> Optional[Raw]:
    kind = cell.get("t") or "n"
    if kind == "inlineStr":
        return "".join(item.text or "" for item in cell.iter() if _local(item.tag) == "t")
    value = next((child for child in cell if _local(child.tag) == "v"), None)
    if value is None or value.text is None:
        return None
    if kind == "s":
        try:
            return int(value.text)
        except ValueError:
            return None
    return value.text


def _iter_rows(archive: zipfile.ZipFile, sheet_path: str,
               columns: Optional[Set[str]] = None) -> Iterator[Tuple[int, Dict[str, Raw]]]:
    """Строки листа: ``(номер строки, {колонка: значение})`` только для непустых ячеек."""
    stream = _open_part(archive, sheet_path, MAX_SHEET_BYTES)
    sheet_data = None
    seq = 0
    try:
        try:
            for event, element in ET.iterparse(stream, events=("start", "end")):
                name = _local(element.tag)
                if event == "start":
                    if name == "sheetData":
                        sheet_data = element
                    continue
                if name != "row":
                    continue
                seq += 1
                try:
                    number = int(element.get("r") or seq)
                except ValueError:
                    number = seq
                cells: Dict[str, Raw] = {}
                position = 0
                for cell in element:
                    if _local(cell.tag) != "c":
                        continue
                    position += 1
                    letters = _column(cell.get("r") or "") or _col_letters(position)
                    position = _col_number(letters)
                    if columns is not None and letters not in columns:
                        continue
                    value = _cell_value(cell)
                    if value is None or (isinstance(value, str) and not value.strip()):
                        continue
                    cells[letters] = value
                element.clear()
                if sheet_data is not None:
                    sheet_data.clear()
                yield number, cells
        except ET.ParseError as exc:
            raise ValueError(f"повреждён лист {sheet_path}: {exc}") from exc
    finally:
        stream.close()


def _scan_header(archive: zipfile.ZipFile, sheet_path: str) -> Tuple[int, Dict[str, Raw]]:
    """Первая «широкая» строка в начале листа — строка заголовков."""
    for count, (number, cells) in enumerate(_iter_rows(archive, sheet_path), start=1):
        if len(cells) >= MIN_HEADER_CELLS:
            return number, cells
        if count >= HEADER_SCAN_ROWS:
            break
    raise ValueError("не найдена строка заголовков таблицы")


def _resolve(archive: zipfile.ZipFile, cells: Dict[str, Raw], has_strings: bool) -> Dict[str, str]:
    wanted = {value for value in cells.values() if isinstance(value, int)}
    strings = _load_strings(archive, wanted) if wanted and has_strings else {}
    return {col: _text(value, strings) for col, value in cells.items()}


def _map_columns(header: Dict[str, str]) -> Dict[str, str]:
    """``ключ поля -> буква колонки`` по первому вхождению заголовка."""
    by_name: Dict[str, str] = {}
    for col, text in sorted(header.items(), key=lambda item: _col_number(item[0])):
        name = " ".join(text.split()).casefold()
        by_name.setdefault(name, col)
    columns: Dict[str, str] = {}
    for key, title in FIELDS.items():
        col = by_name.get(" ".join(title.split()).casefold())
        if col:
            columns[key] = col
    missing = [FIELDS[key] for key in REQUIRED_FIELDS if key not in columns]
    if missing:
        raise ValueError("в выгрузке нет колонок: " + ", ".join(missing))
    return columns


def _load_strings(archive: zipfile.ZipFile, wanted: Set[int]) -> Dict[int, str]:
    """Нужные записи ``sharedStrings.xml`` по индексу; остальные не удерживаются в памяти."""
    found: Dict[int, str] = {}
    if not wanted:
        return found
    stream = _open_part(archive, "xl/sharedStrings.xml", MAX_STRINGS_BYTES)
    root = None
    position = -1
    try:
        try:
            for event, element in ET.iterparse(stream, events=("start", "end")):
                name = _local(element.tag)
                if event == "start":
                    if root is None:
                        root = element
                    continue
                if name != "si":
                    continue
                position += 1
                if position in wanted:
                    found[position] = _si_text(element)
                    if len(found) == len(wanted):
                        break
                element.clear()
                if root is not None:
                    root.clear()
        except ET.ParseError as exc:
            raise ValueError(f"повреждён sharedStrings.xml: {exc}") from exc
    finally:
        stream.close()
    return found


def _si_text(element) -> str:
    """Текст записи без фонетических подсказок ``rPh``."""
    parts: List[str] = []
    for child in element:
        name = _local(child.tag)
        if name == "t":
            parts.append(child.text or "")
        elif name == "r":
            parts.extend(item.text or "" for item in child if _local(item.tag) == "t")
    return "".join(parts)
