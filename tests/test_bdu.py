"""Тесты загрузчика БДУ ФСТЭК без доступа в Интернет.

Выгрузка ``vullist.xlsx`` собирается прямо в тесте из стандартной библиотеки
(``zipfile``), поэтому в репозитории нет бинарных фикстур и нет ничего, что
исполнялось бы из скачанного файла.
"""

import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from xml.sax.saxutils import escape
import zipfile

from test_vulndb import TARGET, catalog_session, target_page
from vulndb_fakes import FakeResponse, FakeSession
from webscan.fingerprint import DetectedProduct
from webscan.models import FindingList
from webscan.report import build_report
from webscan.vulndb import VulnDbConfig, bdu, enrich_with_catalogs, update_databases
from webscan.vulndb.scoring import VulnMatch, score_match
from webscan.vulndb.bdu import (BduCatalog, BduIndex, extract_affected, norm_name, parse_bdu_xlsx,
                                parse_version_expr, product_query, split_top, version_in_expr)
from webscan.vulndb.cache import (FRESH, OFFLINE, STALE, UNAVAILABLE, UPDATED, CacheStore)
from webscan.vulndb.catalog_http import CatalogHttpClient

H_ID = "Идентификатор"
HEADER = [
    H_ID, "Наименование уязвимости", "Описание уязвимости", "Вендор ПО", "Название ПО",
    "Версия ПО", "Тип ПО", "Наименование ОС и тип аппаратной платформы", "Класс уязвимости",
    "Дата выявления", "CVSS 2.0", "CVSS 3.0", "CVSS 4.0", "Уровень опасности уязвимости",
    "Возможные меры по устранению", "Статус уязвимости", "Наличие эксплойта",
    "Информация об устранении", "Ссылки на источники",
    "Идентификаторы других систем описаний уязвимости", "Прочая информация",
    "Связь с инцидентами ИБ", "Способ эксплуатации", "Способ устранения",
    "Дата публикации", "Дата последнего обновления", "Последствия эксплуатации уязвимости",
    "Состояние уязвимости", "Описание ошибки CWE", "Тип ошибки CWE",
    H_ID, "Наименование",   # повторные заголовки справа, как в настоящей выгрузке
]

ROWS = [
    {   # CVE, устранена, эксплойт существует
        H_ID: "BDU:2022-01428",
        "Наименование уязвимости": "Уязвимость пакета chromium операционной системы Debian",
        "Вендор ПО": "Сообщество свободного программного обеспечения",
        "Название ПО": "Debian GNU/Linux", "Версия ПО": "10", "Тип ПО": "Операционная система",
        "Класс уязвимости": "Уязвимость кода",
        "CVSS 2.0": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "CVSS 3.0": "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "Уровень опасности уязвимости":
            "Критический уровень опасности (базовая оценка CVSS 2.0 составляет 10)\n"
            "Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 8,8)",
        "Возможные меры по устранению":
            "Для Debian GNU/Linux:\nhttps://security-tracker.debian.org/tracker/CVE-2022-0975",
        "Статус уязвимости": "Подтверждена производителем",
        "Наличие эксплойта": "Существует",
        "Информация об устранении": "Уязвимость устранена",
        "Ссылки на источники":
            "https://security-tracker.debian.org/tracker/CVE-2022-0975\n"
            "https://example.org/advisory.",
        "Идентификаторы других систем описаний уязвимости": "CVE-2022-0975",
        "Связь с инцидентами ИБ": "Да",
        "Способ устранения": "Обновление программного обеспечения",
        "Дата публикации": "23.03.2022", "Дата последнего обновления": "13.09.2024",
        "Тип ошибки CWE": "CWE-416",
    },
    {   # без CVE, эксплойт «уточняется»
        H_ID: "BDU:2014-00010",
        "Наименование уязвимости": "Уязвимость браузера Google Chrome",
        "Вендор ПО": "Google Inc", "Название ПО": "Google Chrome",
        "Версия ПО": "34.0.1847.131 (Google Chrome)",
        "Наличие эксплойта": "Данные уточняются",
        "Информация об устранении": "Информация об устранении отсутствует",
        "Идентификаторы других систем описаний уязвимости": "OSVDB ID:106684",
    },
    {   # несколько CVE (с дублем в другом регистре), эксплойт в открытом доступе
        H_ID: "BDU:2013-00005",
        "Наименование уязвимости": "Уязвимость D-Link DSR-500",
        "Вендор ПО": "D-Link Corp.", "Название ПО": "DSR-500",
        "Версия ПО": "1.02b11 (DSR-500), 1.02b25 (DSR-500)",
        "Наличие эксплойта": "Существует в открытом доступе",
        "Информация об устранении": "Уязвимость не устранена",
        "Идентификаторы других систем описаний уязвимости":
            "CVE-2013-5946, cve-2013-5946, CVE-2012-3556, OSVDB ID:100840",
        "Дата публикации": "44634",   # серийный номер даты Excel = 2022-03-14
    },
    {   # вторая запись БДУ на ту же CVE
        H_ID: "BDU:2022-02000",
        "Наименование уязвимости": "Ещё одна запись про ту же CVE",
        "Вендор ПО": "Google Inc", "Название ПО": "Chromium",
        "Идентификаторы других систем описаний уязвимости": "CVE-2022-0975",
    },
    {H_ID: "XYZ-1", "Вендор ПО": "Мусор", "Название ПО": "Некорректный идентификатор"},
    {"Вендор ПО": "Без идентификатора", "Название ПО": "Строка без BDU"},
]


def column_letters(number):
    letters = ""
    while number > 0:
        number, rest = divmod(number - 1, 26)
        letters = chr(65 + rest) + letters
    return letters


def build_xlsx(rows=ROWS, *, header=HEADER, sheet_names=("Уязвимости", "Компоненты"),
               first_sheet="main", inline=False, extra_rows_in_other_sheet=True):
    """Собирает минимальную XLSX-книгу в формате настоящей выгрузки (3 строки шапки)."""
    shared = []
    positions = {}

    def sst(text):
        if text not in positions:
            positions[text] = len(shared)
            shared.append(text)
        return positions[text]

    def cell(ref, value):
        if inline:
            return f'<c r="{ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>'
        return f'<c r="{ref}" t="s"><v>{sst(value)}</v></c>'

    def sheet(data_rows, title):
        out = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
               '<sheetData>']
        out.append(f'<row r="1">{cell("A1", title)}<c r="B1"/></row>')
        out.append(f'<row r="2">{cell("A2", "Общая информация")}{cell("AC2", "CWE")}</row>')
        out.append('<row r="3">' + "".join(
            cell(f"{column_letters(i)}3", name) for i, name in enumerate(header, start=1)) + "</row>")
        for number, row in enumerate(data_rows, start=4):
            cells = []
            for i, name in enumerate(header, start=1):
                value = row.get(name)
                if value in (None, "") or (name in (H_ID, "Наименование") and i > 3):
                    continue
                ref = f"{column_letters(i)}{number}"
                if name == "Дата публикации" and str(value).isdigit():
                    cells.append(f'<c r="{ref}"><v>{value}</v></c>')   # числовая ячейка
                else:
                    cells.append(cell(ref, str(value)))
            out.append(f'<row r="{number}">' + "".join(cells) + "</row>")
        out.append("</sheetData></worksheet>")
        return "".join(out)

    other_rows = [{H_ID: "BDU:2099-00001", "Вендор ПО": "Лист компонентов",
                   "Название ПО": "Не должен попасть в индекс"}] if extra_rows_in_other_sheet else []
    main_xml = sheet(rows, "Описание уязвимостей")
    other_xml = sheet(other_rows, "Компоненты")
    sheets = [(sheet_names[0], main_xml), (sheet_names[1], other_xml)]
    if first_sheet != "main":
        sheets.reverse()

    sst_xml = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
               + "".join(f"<si><t>{escape(text)}</t></si>" for text in shared) + "</sst>")
    workbook = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
                + "".join(f'<sheet name="{escape(name)}" sheetId="{i}" r:id="rId{i + 3}"/>'
                          for i, (name, _xml) in enumerate(sheets, start=1))
                + "</sheets></workbook>")
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            + "".join(f'<Relationship Id="rId{i + 3}" Type="worksheet" '
                      f'Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(sheets) + 1))
            + "</Relationships>")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", rels)
        if not inline:
            archive.writestr("xl/sharedStrings.xml", sst_xml)
        for i, (_name, xml) in enumerate(sheets, start=1):
            archive.writestr(f"xl/worksheets/sheet{i}.xml", xml)
    return buffer.getvalue()


class TestParse(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = parse_bdu_xlsx(build_xlsx())

    def test_records_and_skips(self):
        self.assertEqual(sorted(self.index.records),
                         ["BDU:2013-00005", "BDU:2014-00010", "BDU:2022-01428", "BDU:2022-02000"])
        self.assertEqual(len(self.index), 4)
        # лист «Компоненты» и строки с неверным идентификатором в индекс не попадают
        self.assertNotIn("BDU:2099-00001", self.index.records)

    def test_basic_fields(self):
        record = self.index.get("bdu:2022-01428")
        self.assertEqual(record["vendor"], "Сообщество свободного программного обеспечения")
        self.assertEqual(record["product"], "Debian GNU/Linux")
        self.assertEqual(record["cwe"], "CWE-416")
        self.assertEqual(record["url"], "https://bdu.fstec.ru/vul/2022-01428")
        self.assertEqual(record["cves"], ["CVE-2022-0975"])

    def test_cve_index(self):
        self.assertEqual(self.index.by_cve["CVE-2022-0975"], ["BDU:2022-01428", "BDU:2022-02000"])
        self.assertEqual([r["id"] for r in self.index.for_cve("cve-2022-0975")],
                         ["BDU:2022-01428", "BDU:2022-02000"])
        self.assertEqual(self.index.for_cve("CVE-1999-0001"), [])
        # запись без CVE найти по CVE нельзя, но по БДУ-идентификатору можно
        self.assertEqual(self.index.get("BDU:2014-00010")["cves"], [])
        self.assertTrue(all("BDU:2014-00010" not in ids for ids in self.index.by_cve.values()))

    def test_duplicate_cve_in_one_record_collapses(self):
        record = self.index.get("BDU:2013-00005")
        self.assertEqual(record["cves"], ["CVE-2013-5946", "CVE-2012-3556"])
        self.assertEqual(self.index.by_cve["CVE-2013-5946"], ["BDU:2013-00005"])

    def test_exploit_and_fix_codes(self):
        by_id = self.index.records
        self.assertEqual(by_id["BDU:2022-01428"]["exploit"], "exists")
        self.assertEqual(by_id["BDU:2013-00005"]["exploit"], "public")
        self.assertEqual(by_id["BDU:2014-00010"]["exploit"], "unknown")
        self.assertEqual(by_id["BDU:2022-01428"]["fix"], "fixed")
        self.assertEqual(by_id["BDU:2013-00005"]["fix"], "unfixed")
        self.assertEqual(by_id["BDU:2014-00010"]["fix"], "unknown")
        self.assertEqual(by_id["BDU:2022-02000"]["exploit"], "unknown")

    def test_scores_and_level(self):
        record = self.index.get("BDU:2022-01428")
        self.assertEqual(record["scores"], {"2.0": 10.0, "3.0": 8.8})
        self.assertEqual(record["level"], "critical")
        self.assertEqual(self.index.get("BDU:2014-00010")["level"], "")
        self.assertNotIn("scores", self.index.get("BDU:2014-00010"))

    def test_dates(self):
        record = self.index.get("BDU:2022-01428")
        self.assertEqual((record["published"], record["updated"]), ("2022-03-23", "2024-09-13"))
        self.assertEqual(self.index.get("BDU:2013-00005")["published"], "2022-03-14")
        self.assertEqual(self.index.catalog_date, "2024-09-13")

    def test_links_are_clean_and_limited(self):
        links = self.index.get("BDU:2022-01428")["links"]
        self.assertEqual(links, ["https://security-tracker.debian.org/tracker/CVE-2022-0975",
                                 "https://example.org/advisory"])

    def test_long_fields_are_clipped(self):
        rows = [dict(ROWS[0], **{"Возможные меры по устранению": "м" * 5000})]
        record = parse_bdu_xlsx(build_xlsx(rows)).get("BDU:2022-01428")
        self.assertLessEqual(len(record["measures"]), bdu.CLIP["measures"])

    def test_parser_follows_column_names_not_letters(self):
        shifted = ["Служебная колонка"] + [name for name in HEADER if name != "Дата выявления"]
        index = parse_bdu_xlsx(build_xlsx(header=shifted))
        record = index.get("BDU:2022-01428")
        self.assertEqual(record["vendor"], "Сообщество свободного программного обеспечения")
        self.assertEqual(index.by_cve["CVE-2022-0975"], ["BDU:2022-01428", "BDU:2022-02000"])

    def test_sheet_is_selected_by_name(self):
        index = parse_bdu_xlsx(build_xlsx(first_sheet="other"))
        self.assertIn("BDU:2022-01428", index.records)
        self.assertNotIn("BDU:2099-00001", index.records)

    def test_inline_strings_workbook(self):
        index = parse_bdu_xlsx(build_xlsx(inline=True))
        self.assertEqual(len(index), 4)
        self.assertEqual(index.get("BDU:2013-00005")["exploit"], "public")

    def test_missing_required_columns(self):
        header = [name for name in HEADER if name != "Вендор ПО"]
        with self.assertRaises(ValueError) as caught:
            parse_bdu_xlsx(build_xlsx(header=header))
        self.assertIn("Вендор ПО", str(caught.exception))

    def test_not_an_xlsx(self):
        for payload in (b"<html>captcha</html>", b"", b"PK\x03\x04 not really a zip"):
            with self.assertRaises(ValueError):
                parse_bdu_xlsx(payload)

    def test_archive_without_workbook(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("readme.txt", "x")
        with self.assertRaises(ValueError):
            parse_bdu_xlsx(buffer.getvalue())

    def test_size_limits_stop_the_parse(self):
        data = build_xlsx()
        with mock.patch.object(bdu, "MAX_SHEET_BYTES", 200):
            with self.assertRaises(ValueError):
                parse_bdu_xlsx(data)
        with mock.patch.object(bdu, "MAX_STRINGS_BYTES", 200):
            with self.assertRaises(ValueError):
                parse_bdu_xlsx(data)
        with self.assertRaises(ValueError):
            parse_bdu_xlsx(data, max_rows=2)

    def test_empty_index_helpers(self):
        empty = BduIndex()
        self.assertEqual(len(empty), 0)
        self.assertIsNone(empty.get("BDU:2022-01428"))
        self.assertEqual(empty.for_cve("CVE-2022-0975"), [])


class TestCatalog(unittest.TestCase):
    URL = "https://bdu.fstec.ru/files/documents/vullist.xlsx"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = CacheStore(self.tmp.name)
        self.xlsx = build_xlsx()

    def tearDown(self):
        self.tmp.cleanup()

    def _catalog(self, session, **kwargs):
        http = CatalogHttpClient(session=session, sleep=lambda _s: None, backoff=0.0)
        options = dict(ttl_hours=24)
        options.update(kwargs)
        return BduCatalog(self.cache, http, **options)

    def _age(self, hours):
        meta = self.cache.meta(bdu.BDU_CACHE)
        meta["fetched_epoch"] = time.time() - hours * 3600
        self.cache.meta_path(bdu.BDU_CACHE).write_text(json.dumps(meta), encoding="utf-8")

    def _serve(self, **headers):
        return FakeSession([("bdu.fstec.ru", FakeResponse(200, self.xlsx, headers))])

    def test_download_parses_and_caches(self):
        session = self._serve(ETag='"v1"')
        catalog = self._catalog(session)
        index = catalog.load()
        self.assertEqual(len(index), 4)
        self.assertEqual(catalog.status.state, UPDATED)
        self.assertEqual(catalog.status.records, 4)
        self.assertEqual(catalog.status.data_date, "2024-09-13")
        self.assertEqual([call["url"] for call in session.calls], [self.URL])
        self.assertTrue(session.calls[0]["verify"])   # проверка TLS не отключается
        self.assertTrue(self.cache.exists(bdu.BDU_CACHE))
        self.assertTrue(self.cache.exists(bdu.BDU_STORE))
        self.assertEqual(self.cache.meta(bdu.BDU_CACHE)["etag"], '"v1"')

    def test_fresh_cache_needs_no_network_and_no_reparse(self):
        self._catalog(self._serve()).load()
        session = FakeSession()
        catalog = self._catalog(session)
        with mock.patch.object(bdu, "parse_bdu_xlsx", side_effect=AssertionError("повторный разбор")):
            index = catalog.load()
        self.assertEqual(len(index), 4)
        self.assertEqual(catalog.status.state, FRESH)
        self.assertEqual(session.calls, [])

    def test_changed_file_rebuilds_the_index(self):
        self._catalog(self._serve()).load()
        self._age(48)
        smaller = build_xlsx(ROWS[:1])
        session = FakeSession([("bdu.fstec.ru", FakeResponse(200, smaller))])
        index = self._catalog(session).load()
        self.assertEqual(len(index), 1)
        self.assertIsNotNone(index.get("BDU:2022-01428"))
        self.assertIsNone(index.get("BDU:2013-00005"))
        self.assertEqual(len(index.for_cve("CVE-2022-0975")), 1)

    def test_store_answers_like_the_in_memory_index(self):
        memory = parse_bdu_xlsx(self.xlsx)
        store = self._catalog(self._serve()).load()
        self.assertIsInstance(store, bdu.BduStore)
        self.assertEqual(len(store), len(memory))
        self.assertEqual(store.catalog_date, memory.catalog_date)
        for cve in ("CVE-2022-0975", "cve-2013-5946", "CVE-2012-3556", "CVE-1999-0001"):
            self.assertEqual(store.for_cve(cve), memory.for_cve(cve), cve)
        for bdu_id in ("BDU:2022-01428", "bdu:2014-00010", "BDU:2000-00000"):
            self.assertEqual(store.get(bdu_id), memory.get(bdu_id), bdu_id)
        self.assertEqual(store.get("BDU:2022-01428")["url"], "https://bdu.fstec.ru/vul/2022-01428")

    def test_unwritable_cache_falls_back_to_memory(self):
        with mock.patch.object(bdu, "write_store", side_effect=OSError("только чтение")):
            catalog = self._catalog(self._serve())
            index = catalog.load()
        self.assertIsInstance(index, BduIndex)
        self.assertEqual(len(index), 4)
        self.assertEqual(catalog.status.state, UPDATED)

    def test_damaged_store_is_rebuilt(self):
        self._catalog(self._serve()).load()
        self.cache.path(bdu.BDU_STORE).write_bytes(b"not a sqlite file")
        catalog = self._catalog(FakeSession())
        index = catalog.load()
        self.assertEqual(len(index), 4)
        self.assertEqual(len(index.for_cve("CVE-2022-0975")), 2)

    def test_not_modified_keeps_cache_and_sends_validators(self):
        self._catalog(self._serve(ETag='"v1"')).load()
        self._age(48)
        session = FakeSession([("bdu.fstec.ru", FakeResponse(304))])
        catalog = self._catalog(session)
        index = catalog.load()
        self.assertEqual(len(index), 4)
        self.assertEqual(catalog.status.state, UPDATED)
        self.assertEqual(session.calls[0]["headers"].get("If-None-Match"), '"v1"')

    def test_html_instead_of_xlsx_is_rejected(self):
        session = FakeSession([("bdu.fstec.ru", FakeResponse(200, b"<html>Access denied</html>"))])
        catalog = self._catalog(session)
        index = catalog.load()
        self.assertEqual(len(index), 0)
        self.assertEqual(catalog.status.state, UNAVAILABLE)
        self.assertFalse(self.cache.exists(bdu.BDU_CACHE))

    def test_file_next_to_cache_is_used_when_download_fails(self):
        (Path(self.tmp.name) / "vullist.xlsx").write_bytes(self.xlsx)
        session = FakeSession([("bdu.fstec.ru", FakeResponse(503))])
        catalog = self._catalog(session)
        index = catalog.load()
        self.assertEqual(len(index), 4)
        self.assertEqual(catalog.status.state, FRESH)
        self.assertIn("vullist.xlsx", catalog.status.message)

    def test_broken_file_next_to_cache_keeps_unavailable(self):
        (Path(self.tmp.name) / "vullist.xlsx").write_bytes(b"<html>no</html>")
        catalog = self._catalog(FakeSession([("bdu.fstec.ru", FakeResponse(503))]))
        self.assertEqual(len(catalog.load()), 0)
        self.assertEqual(catalog.status.state, UNAVAILABLE)

    def test_stale_cache_when_site_is_down(self):
        self._catalog(self._serve()).load()
        self._age(48)
        catalog = self._catalog(FakeSession([("bdu.fstec.ru", FakeResponse(503))]))
        index = catalog.load()
        self.assertEqual(len(index), 4)
        self.assertEqual(catalog.status.state, STALE)

    def test_unreachable_without_cache(self):
        catalog = self._catalog(FakeSession())
        self.assertEqual(len(catalog.load()), 0)
        self.assertEqual(catalog.status.state, UNAVAILABLE)

    def test_offline_without_cache_makes_no_requests(self):
        session = FakeSession()
        catalog = self._catalog(session, offline=True)
        self.assertEqual(len(catalog.load()), 0)
        self.assertEqual(catalog.status.state, OFFLINE)
        self.assertEqual(session.calls, [])

    def test_corrupt_download_is_reported_not_raised(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("readme.txt", "x")
        session = FakeSession([("bdu.fstec.ru", FakeResponse(200, buffer.getvalue()))])
        catalog = self._catalog(session)
        self.assertEqual(len(catalog.load()), 0)
        self.assertEqual(catalog.status.state, "unavailable")
        self.assertIn("повреждённая выгрузка", catalog.status.message)

    def test_local_file_mode_uses_no_network(self):
        path = Path(self.tmp.name) / "vullist.xlsx"
        path.write_bytes(self.xlsx)
        session = FakeSession()
        catalog = self._catalog(session, local_file=str(path))
        index = catalog.load()
        self.assertEqual(len(index), 4)
        self.assertEqual(catalog.status.state, FRESH)
        self.assertIn("vullist.xlsx", catalog.status.message)
        self.assertEqual(session.calls, [])

    def test_local_file_errors(self):
        missing = self._catalog(FakeSession(), local_file=str(Path(self.tmp.name) / "нет.xlsx"))
        self.assertEqual(len(missing.load()), 0)
        self.assertEqual(missing.status.state, "unavailable")
        junk = Path(self.tmp.name) / "junk.xlsx"
        junk.write_bytes(b"not an xlsx")
        broken = self._catalog(FakeSession(), local_file=str(junk))
        self.assertEqual(len(broken.load()), 0)
        self.assertEqual(broken.status.state, "unavailable")

    def test_host_is_allowlisted_but_plain_http_is_not(self):
        http = CatalogHttpClient(session=FakeSession([("bdu", FakeResponse(200, b"x"))]),
                                 sleep=lambda _s: None)
        self.assertEqual(http.get(self.URL, max_bytes=10).content, b"x")
        with self.assertRaises(ValueError):
            http.get("http://bdu.fstec.ru/files/documents/vullist.xlsx")
        with self.assertRaises(ValueError):
            http.get("https://bdu.fstec.ru.evil.test/files/documents/vullist.xlsx")


APACHE_ROWS = [
    {
        H_ID: "BDU:2021-04903",
        "Наименование уязвимости": "Уязвимость веб-сервера Apache HTTP Server, позволяющая прочитать файлы",
        "Вендор ПО": "Apache Software Foundation", "Название ПО": "HTTP Server",
        "Версия ПО": "2.4.49",
        "Уровень опасности уязвимости": "Критический уровень опасности (базовая оценка CVSS 3.0 составляет 9,8)",
        "Возможные меры по устранению": "Использование рекомендаций: обновить Apache HTTP Server до 2.4.51",
        "Наличие эксплойта": "Существует в открытом доступе",
        "Информация об устранении": "Уязвимость устранена",
        "Идентификаторы других систем описаний уязвимости": "CVE-2021-41773",
        "Дата публикации": "06.10.2021", "Дата последнего обновления": "22.05.2026",
    },
    {   # CVE, которой нет в фикстуре NVD — в находки попасть не должна
        H_ID: "BDU:2020-00001",
        "Наименование уязвимости": "Посторонняя запись",
        "Вендор ПО": "Другой", "Название ПО": "Продукт",
        "Идентификаторы других систем описаний уязвимости": "CVE-2000-0001",
    },
]


class TestCorrelationWithBdu(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.xlsx_path = Path(self.tmp.name) / "vullist.xlsx"
        self.xlsx_path.write_bytes(build_xlsx(APACHE_ROWS))

    def tearDown(self):
        self.tmp.cleanup()

    def _cfg(self, session, **kwargs):
        options = dict(cache_dir=self.tmp.name + "/cache", session=session,
                       sleep=lambda _s: None, bdu_file=str(self.xlsx_path))
        options.update(kwargs)
        return VulnDbConfig(**options)

    def _run(self, session=None, **kwargs):
        return enrich_with_catalogs([target_page()], self._cfg(session or catalog_session(), **kwargs))

    def _apache(self, result):
        return next(f for f in result.findings if "Apache HTTP Server" in f.title)

    def test_cve_is_enriched_with_bdu(self):
        result = self._run()
        match = next(m for m in result.matches if m.cve_id == "CVE-2021-41773")
        self.assertEqual([item["id"] for item in match.bdu], ["BDU:2021-04903"])
        self.assertEqual(result.bdu_count, 1)
        self.assertEqual(result.as_context()["bdu"], 1)
        self.assertEqual(result.sources["БДУ ФСТЭК"].state, FRESH)
        self.assertEqual(result.sources["БДУ ФСТЭК"].records, 2)
        # CVE без записи в БДУ остаются как были
        other = next(m for m in result.matches if m.cve_id == "CVE-2021-44224")
        self.assertEqual(other.bdu, [])

    def test_finding_carries_bdu_identifiers_and_text(self):
        finding = self._apache(self._run())
        self.assertIn("CVE-2021-41773", finding.identifiers)
        self.assertIn("BDU:2021-04903", finding.identifiers)
        self.assertIn("БДУ ФСТЭК", finding.sources)
        self.assertIn(", в БДУ: 1)", finding.title)
        self.assertIn("БДУ BDU:2021-04903", finding.evidence)
        self.assertIn("эксплойт в открытом доступе", finding.evidence)
        self.assertIn("https://bdu.fstec.ru/vul/2021-04903", finding.references)
        self.assertTrue(any("(БДУ ФСТЭК)" in step and "2.4.51" in step for step in finding.fix_steps))
        row = finding.vuln_matches[0]
        self.assertEqual(row["cve"], "CVE-2021-41773")   # порядок сортировки не изменился
        self.assertEqual(row["bdu"][0]["id"], "BDU:2021-04903")
        self.assertEqual(row["bdu"][0]["fix"], "fixed")
        self.assertEqual(row["bdu"][0]["scores"], {"3.0": 9.8})

    def test_existing_priority_and_kind_are_unchanged(self):
        result = self._run()
        match = next(m for m in result.matches if m.cve_id == "CVE-2021-41773")
        # 9.8 + 3 (KEV) + 1 (ransomware) + 1.5 (verified ExploitDB); БДУ не прибавляет второй раз
        self.assertAlmostEqual(match.priority_score, 15.3)
        self.assertEqual(self._apache(result).kind, "known_cve_kev")

    def test_bdu_exploit_bonus_does_not_double_count(self):
        component = DetectedProduct("x", "y", "1.0")
        public = [{"id": "BDU:2020-00001", "exploit": "public"}]
        base = VulnMatch("CVE-2020-0001", component, cvss={"score": 8.0})
        with_bdu = VulnMatch("CVE-2020-0001", component, cvss={"score": 8.0}, bdu=public)
        unknown = VulnMatch("CVE-2020-0001", component, cvss={"score": 8.0},
                            bdu=[{"id": "BDU:2020-00001", "exploit": "unknown"}])
        both = VulnMatch("CVE-2020-0001", component, cvss={"score": 8.0}, bdu=public,
                         exploits=[{"edb_id": "1", "verified": False}])
        self.assertEqual(score_match(base)[0], 8.0)
        self.assertEqual(score_match(with_bdu)[0], 8.75)
        self.assertEqual(score_match(unknown)[0], 8.0)
        self.assertEqual(score_match(both)[0], 8.75)   # только бонус ExploitDB (0,75), не оба

    def test_bdu_can_be_disabled(self):
        session = catalog_session()
        result = self._run(session, use_bdu=False)
        self.assertEqual(result.sources["БДУ ФСТЭК"].state, "disabled")
        self.assertTrue(all(not m.bdu for m in result.matches))
        self.assertNotIn("BDU:2021-04903", self._apache(result).identifiers)
        self.assertNotIn("БДУ ФСТЭК", self._apache(result).sources)
        self.assertFalse(any("bdu.fstec.ru" in call["url"] for call in session.calls))

    def test_local_file_needs_no_network_for_bdu(self):
        session = catalog_session()
        self._run(session)
        self.assertFalse(any("bdu.fstec.ru" in call["url"] for call in session.calls))

    def test_download_from_site_when_no_local_file(self):
        session = catalog_session()
        session.add("bdu.fstec.ru", FakeResponse(200, build_xlsx(APACHE_ROWS)))
        result = self._run(session, bdu_file="")
        self.assertEqual(result.bdu_count, 1)
        self.assertEqual(result.sources["БДУ ФСТЭК"].state, UPDATED)
        calls = [call for call in session.calls if "bdu.fstec.ru" in call["url"]]
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0]["verify"])
        # к цели ни одного запроса, а в БДУ не уходит ничего, кроме загрузки общего файла
        dump = json.dumps(calls, ensure_ascii=False)
        for secret in ("shop.example.test", "s3cr3tvalue", "PHPSESSID", "2.4.49"):
            self.assertNotIn(secret, dump)
        self.assertEqual(calls[0]["params"], {})

    def test_unavailable_bdu_does_not_break_the_scan(self):
        session = catalog_session()   # маршрута на bdu.fstec.ru нет → ошибка соединения
        result = self._run(session, bdu_file="")
        self.assertEqual(result.sources["БДУ ФСТЭК"].state, UNAVAILABLE)
        self.assertTrue(any("БДУ ФСТЭК недоступен" in note for note in result.notes))
        self.assertIn("CVE-2021-41773", {m.cve_id for m in result.matches})
        self.assertEqual(self._apache(result).kind, "known_cve_kev")

    def test_corrupt_local_file_is_reported(self):
        self.xlsx_path.write_bytes(b"PK\x03\x04 truncated")
        result = self._run()
        self.assertEqual(result.sources["БДУ ФСТЭК"].state, "unavailable")
        self.assertTrue(all(not m.bdu for m in result.matches))

    def test_nothing_to_check_skips_bdu(self):
        session = FakeSession()
        page = target_page()
        page.headers = {}
        result = enrich_with_catalogs([page], self._cfg(session, bdu_file=""))
        self.assertEqual(session.calls, [])
        self.assertEqual(result.sources["БДУ ФСТЭК"].state, "skipped")

    def test_update_databases_includes_bdu(self):
        session = FakeSession([
            ("known_exploited", FakeResponse(200, json.dumps({"vulnerabilities": []}).encode())),
            ("files_exploits.csv", FakeResponse(200, b"id,file,description,codes\n")),
            ("bdu.fstec.ru", FakeResponse(200, build_xlsx(APACHE_ROWS))),
        ])
        statuses = update_databases(self._cfg(session, bdu_file=""))
        self.assertIn("БДУ ФСТЭК", statuses)
        self.assertEqual(statuses["БДУ ФСТЭК"].state, UPDATED)
        self.assertEqual(statuses["БДУ ФСТЭК"].records, 2)

    def _report(self, **kwargs):
        result = self._run(**kwargs)
        findings = FindingList()
        findings.extend(result.findings)
        stats = {"target": TARGET, "pages": 1, "max_pages": 60, "requests_made": 5,
                 "max_requests": 600, "notes": result.notes, "duration": 1.0,
                 "vulnerability_intelligence": result.as_context()}
        return build_report(findings, stats), result

    def test_report_shows_bdu_and_csv_column(self):
        html_text, result = self._report()
        self.assertIn("БДУ: ", html_text)
        self.assertIn("https://bdu.fstec.ru/vul/2021-04903", html_text)
        self.assertIn("Есть в БДУ ФСТЭК", html_text)
        start = html_text.index('<script type="application/json" id="vuln-data">')
        block = html_text[start:html_text.index("</script>", start)]
        data = json.loads(block[block.index(">") + 1:])
        self.assertEqual(data["columns"][-1], "БДУ ФСТЭК")
        row = next(r for r in data["rows"] if r[0] == "CVE-2021-41773")
        self.assertEqual(row[-1], "BDU:2021-04903")
        self.assertTrue(all(len(r) == len(data["columns"]) for r in data["rows"]))

    def test_report_csv_keeps_old_columns_without_bdu(self):
        html_text, _result = self._report(use_bdu=False)
        start = html_text.index('<script type="application/json" id="vuln-data">')
        block = html_text[start:html_text.index("</script>", start)]
        data = json.loads(block[block.index(">") + 1:])
        self.assertNotIn("БДУ ФСТЭК", data["columns"])
        self.assertTrue(all(len(r) == len(data["columns"]) for r in data["rows"]))
        self.assertNotIn("Есть в БДУ ФСТЭК", html_text)

    def test_bdu_text_is_escaped_in_report(self):
        poisoned = [dict(APACHE_ROWS[0], **{
            "Наименование уязвимости": "<script>alert(1)</script><img src=x onerror=alert(2)>"})]
        self.xlsx_path.write_bytes(build_xlsx(poisoned))
        html_text, _result = self._report()
        self.assertNotIn("<img src=x", html_text)
        self.assertNotIn("<script>alert(1)", html_text)
        self.assertIn("&lt;script&gt;alert(1)", html_text)   # название выведено, но экранировано
        self.assertEqual(html_text.count("<script"), html_text.count("</script>"))


class TestVersionExpressions(unittest.TestCase):
    def test_parse_forms_seen_in_the_export(self):
        self.assertEqual(parse_version_expr("2.4.49"), ("2.4.49", True, "2.4.49", True))
        self.assertEqual(parse_version_expr("до 3.4.15"), (None, False, "3.4.15", False))
        self.assertEqual(parse_version_expr("до 27.0.1 включительно"), (None, False, "27.0.1", True))
        self.assertEqual(parse_version_expr("от 4.0 до 5.0.5"), ("4.0", True, "5.0.5", False))
        self.assertEqual(parse_version_expr("от 3.0 до 3.14.3 включительно"), ("3.0", True, "3.14.3", True))
        self.assertEqual(parse_version_expr("  ОТ 1.0   ДО 2.0 "), ("1.0", True, "2.0", False))
        self.assertEqual(parse_version_expr("1.0.1e"), ("1.0.1e", True, "1.0.1e", True))

    def test_unjudgeable_expressions_are_skipped(self):
        for expr in ("-", "", "2010 SP2", "12.04 ESM", "1.6 «Смоленск»", "до 7.2 Муром",
                     "до 2015.006.30060 Classic", "6.2(14)S1", "Server 2013", "все версии",
                     "до 4.8 P26", "от 14.0 до 14.1X53-D30"):
            self.assertIsNone(parse_version_expr(expr), expr)

    def test_boundaries(self):
        cases = [
            ("2.4.49", "2.4.49", "exact"), ("2.4.50", "2.4.49", None),
            ("2.4.49", "до 2.4.50", "range"), ("2.4.50", "до 2.4.50", None),
            ("2.4.50", "до 2.4.50 включительно", "range"), ("2.4.51", "до 2.4.50 включительно", None),
            ("2.4.0", "от 2.4.0 до 2.4.50", "range"), ("2.3.9", "от 2.4.0 до 2.4.50", None),
            ("2.4.50", "от 2.4.0 до 2.4.50", None), ("2.4.50", "от 2.4.0 до 2.4.50 включительно", "range"),
            ("7.4.3", "от 7.4.0 до 7.4.3 включительно", "range"),
            ("1.0.1e", "до 1.0.1f", "range"), ("1.0.1g", "до 1.0.1f", None),
            ("2.4", "2.4.0", "exact"),   # 2.4 и 2.4.0 — одна версия
        ]
        for version, expr, expected in cases:
            self.assertEqual(version_in_expr(version, expr), expected, f"{version} vs {expr}")

    def test_unparsable_version_never_matches(self):
        self.assertIsNone(version_in_expr("latest", "до 2.0"))
        self.assertIsNone(version_in_expr("", "до 2.0"))


class TestAffectedExtraction(unittest.TestCase):
    def test_split_respects_brackets_and_quotes(self):
        text = "1.6 «Смоленск, СЕ» (Astra Linux Special Edition (запись №369)), до 9 (Debian, Linux)"
        self.assertEqual(split_top(text), [
            "1.6 «Смоленск, СЕ» (Astra Linux Special Edition (запись №369))", "до 9 (Debian, Linux)"])
        self.assertEqual(split_top(""), [])
        self.assertEqual(split_top("a,, b ,"), ["a", "b"])

    def test_entries_become_name_and_expression(self):
        rows, vendors = extract_affected({
            "vendor": "Google Inc, Microsoft Corp",
            "product": "Google Chrome, Microsoft Edge",
            "versions": "до 99.0.4844.74 (Google Chrome), 9 (Debian GNU/Linux), "
                        "1.6 «Смоленск» (Astra Linux), от 2.0 до 2.5 включительно (Microsoft Edge), "
                        "- (Microsoft Word 2007), 2010 SP2 (Microsoft SharePoint Server), "
                        "до 99.0.4844.74 (Google Chrome)",
        })
        self.assertEqual(rows, [
            ("googlechrome", "до 99.0.4844.74", "Google Chrome"),
            ("debiangnulinux", "9", "Debian GNU/Linux"),
            ("microsoftedge", "от 2.0 до 2.5 включительно", "Microsoft Edge"),
        ])
        self.assertEqual(vendors, ["googleinc", "microsoftcorp"])

    def test_single_product_without_parentheses(self):
        rows, _vendors = extract_affected({"vendor": "Apache", "product": "HTTP Server",
                                           "versions": "2.4.49"})
        self.assertEqual(rows, [("httpserver", "2.4.49", "HTTP Server")])
        # без скобок и с несколькими продуктами название определить нельзя
        none, _ = extract_affected({"vendor": "A, B", "product": "X, Y", "versions": "1.0"})
        self.assertEqual(none, [])

    def test_huge_records_are_capped(self):
        versions = ", ".join(f"{i}.0 (Linux)" for i in range(1, 2001))
        rows, _ = extract_affected({"vendor": "x", "product": "Linux", "versions": versions})
        self.assertLessEqual(len(rows), 400)

    def test_norm_name(self):
        self.assertEqual(norm_name("HTTP Server"), "httpserver")
        self.assertEqual(norm_name("http_server"), "httpserver")
        self.assertEqual(norm_name("ОС Astra Linux, v1.7"), "осastralinuxv17")


class TestProductQuery(unittest.TestCase):
    def test_label_and_cpe_pairs(self):
        query = product_query("Apache HTTP Server", [("apache", "http_server")])
        self.assertEqual(query.names, {"apachehttpserver"})
        self.assertEqual(query.vendor_names, {"httpserver": {"apache"}})

    def test_ambiguous_label_requires_vendor(self):
        query = product_query("Express", [("expressjs", "express")])
        self.assertNotIn("express", query.names)
        self.assertEqual(query.vendor_names["express"], {"expressjs"})

    def test_empty_query(self):
        self.assertFalse(product_query("", []))
        self.assertTrue(product_query("nginx", []))


DIRECT_ROWS = [
    {   # без CVE; 2.4.49 внутри «от 2.4.0 до 2.4.50» (верхняя граница не включается)
        H_ID: "BDU:2099-00001", "Наименование уязвимости": "Уязвимость HTTP Server без CVE",
        "Вендор ПО": "Apache Software Foundation", "Название ПО": "HTTP Server",
        "Версия ПО": "от 2.4.0 до 2.4.50 (HTTP Server)",
        "Уровень опасности уязвимости": "Критический уровень опасности (базовая оценка CVSS 3.0 составляет 9,8)",
        "Возможные меры по устранению": "Обновить HTTP Server до 2.4.51",
        "Наличие эксплойта": "Существует в открытом доступе",
        "Идентификаторы других систем описаний уязвимости": "OSVDB ID:1",
    },
    {   # версия не подходит
        H_ID: "BDU:2099-00002", "Наименование уязвимости": "Старая версия",
        "Вендор ПО": "Apache Software Foundation", "Название ПО": "HTTP Server",
        "Версия ПО": "до 2.4.40 (HTTP Server)",
    },
    {   # одноимённый продукт другого производителя
        H_ID: "BDU:2099-00003", "Наименование уязвимости": "Oracle HTTP Server",
        "Вендор ПО": "Oracle Corp.", "Название ПО": "HTTP Server",
        "Версия ПО": "до 3.0 (HTTP Server)",
    },
    {   # CVE уже найдена через NVD — только обогащение, второй записи быть не должно
        H_ID: "BDU:2021-04903", "Наименование уязвимости": "Уже известная CVE",
        "Вендор ПО": "Apache Software Foundation", "Название ПО": "HTTP Server",
        "Версия ПО": "2.4.49 (HTTP Server)",
        "Идентификаторы других систем описаний уязвимости": "CVE-2021-41773",
    },
    {   # есть CVE, которой нет в NVD-фикстуре
        H_ID: "BDU:2099-00004", "Наименование уязвимости": "CVE без привязки к версии в NVD",
        "Вендор ПО": "Apache Software Foundation", "Название ПО": "HTTP Server",
        "Версия ПО": "2.4.49 (HTTP Server)",
        "Уровень опасности уязвимости": "Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 7,5)",
        "Идентификаторы других систем описаний уязвимости": "CVE-2099-0001",
    },
    {   # PHP 7.4.3: верхняя граница «включительно»
        H_ID: "BDU:2099-00005", "Наименование уязвимости": "Уязвимость PHP",
        "Вендор ПО": "The PHP Group", "Название ПО": "PHP",
        "Версия ПО": "от 7.4.0 до 7.4.3 включительно (PHP)",
        "Идентификаторы других систем описаний уязвимости": "OSVDB ID:2",
    },
    {   # CVE есть в NVD для Apache с диапазоном 2.4.20–2.4.40: NVD явно «не затронуто»
        H_ID: "BDU:2099-00007", "Наименование уязвимости": "Противоречит диапазонам NVD",
        "Вендор ПО": "Apache Software Foundation", "Название ПО": "HTTP Server",
        "Версия ПО": "2.4.49 (HTTP Server)",
        "Идентификаторы других систем описаний уязвимости": "CVE-2019-9517",
    },
    {   # «до 7.4.3» — строго ниже, PHP 7.4.3 не затрагивает
        H_ID: "BDU:2099-00006", "Наименование уязвимости": "Исправлено в 7.4.3",
        "Вендор ПО": "The PHP Group", "Название ПО": "PHP",
        "Версия ПО": "до 7.4.3 (PHP)",
    },
]


class TestDirectLookup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.xlsx_path = Path(self.tmp.name) / "vullist.xlsx"
        self.xlsx_path.write_bytes(build_xlsx(DIRECT_ROWS))

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, **kwargs):
        cfg = VulnDbConfig(cache_dir=self.tmp.name + "/cache", session=catalog_session(),
                           sleep=lambda _s: None, bdu_file=str(self.xlsx_path), **kwargs)
        return enrich_with_catalogs([target_page()], cfg)

    def _only(self, result):
        return {m.bdu[0]["id"]: m for m in result.matches if m.source == "bdu"}

    def test_index_matches_by_product_and_version(self):
        index = parse_bdu_xlsx(build_xlsx(DIRECT_ROWS))
        apache = product_query("Apache HTTP Server", [("apache", "http_server")])
        found = {r["id"]: r for r in index.for_product(apache, "2.4.49")}
        self.assertEqual(sorted(found), ["BDU:2021-04903", "BDU:2099-00001", "BDU:2099-00004",
                                         "BDU:2099-00007"])
        self.assertEqual(found["BDU:2021-04903"]["version_match"], "exact")
        self.assertEqual(found["BDU:2099-00001"]["version_match"], "range")
        self.assertEqual(found["BDU:2099-00001"]["version_expr"], "от 2.4.0 до 2.4.50")
        self.assertEqual(found["BDU:2099-00001"]["matched_name"], "HTTP Server")
        # Oracle HTTP Server не должен совпасть по короткому названию «HTTP Server»
        self.assertNotIn("BDU:2099-00003", found)
        self.assertEqual(index.for_product(apache, ""), [])

    def test_store_gives_the_same_answers_as_memory(self):
        memory = parse_bdu_xlsx(build_xlsx(DIRECT_ROWS))
        store = bdu.write_store(Path(self.tmp.name) / "s.sqlite", memory, "digest")
        for label, pairs, version in (("Apache HTTP Server", [("apache", "http_server")], "2.4.49"),
                                      ("PHP", [("php", "php")], "7.4.3"),
                                      ("PHP", [("php", "php")], "7.4.4"),
                                      ("Nginx", [("nginx", "nginx")], "1.0")):
            query = product_query(label, pairs)
            self.assertEqual(store.for_product(query, version), memory.for_product(query, version))
        self.assertEqual(len(store.for_product(product_query("PHP", [("php", "php")]), "7.4.3")), 1)

    def test_bdu_only_findings(self):
        result = self._run()
        only = self._only(result)
        self.assertEqual(sorted(only), ["BDU:2099-00001", "BDU:2099-00004", "BDU:2099-00005"])
        self.assertEqual(result.bdu_only_count, 3)
        self.assertEqual(result.as_context()["bdu_only"], 3)
        # уже найденная через NVD CVE не дублируется, а лишь обогащается
        known = [m for m in result.matches if m.cve_id == "CVE-2021-41773"]
        self.assertEqual(len(known), 1)
        self.assertEqual(known[0].source, "nvd")
        self.assertEqual(known[0].bdu[0]["id"], "BDU:2021-04903")
        self.assertNotIn("BDU:2099-00006", only)   # «до 7.4.3» не включает 7.4.3

    def test_record_contradicting_nvd_ranges_is_rejected(self):
        result = self._run()
        self.assertNotIn("BDU:2099-00007", self._only(result))
        self.assertTrue(any("записей БДУ не показано: 1" in note and "Apache HTTP Server" in note
                            for note in result.notes), result.notes)
        # при отключённом NVD противоречить нечему — запись показывается
        cfg = VulnDbConfig(cache_dir=self.tmp.name + "/cache3", session=catalog_session(nvd=False),
                           sleep=lambda _s: None, bdu_file=str(self.xlsx_path))
        offline_nvd = enrich_with_catalogs([target_page()], cfg)
        self.assertIn("BDU:2099-00007", {m.bdu[0]["id"] for m in offline_nvd.matches})

    def test_scoring_of_name_based_matches(self):
        only = self._only(self._run())
        with_cve = only["BDU:2099-00004"]
        self.assertEqual(with_cve.cve_id, "CVE-2099-0001")
        self.assertEqual(with_cve.version_match, "bdu_name")
        self.assertEqual(with_cve.cvss, {"version": "3.0", "score": 7.5, "vector": ""})
        self.assertAlmostEqual(with_cve.priority_score, 5.25)   # 7.5 × 0.7
        self.assertEqual(with_cve.priority_label, "Средний")
        no_cve = only["BDU:2099-00001"]
        self.assertEqual(no_cve.cve_id, "BDU:2099-00001")        # идентификатор — сам номер БДУ
        self.assertEqual(no_cve.nvd_url, "")
        # 9.8 × 0.7 = 6.86, бонус за открытый эксплойт БДУ даёт +0.75 до умножения
        self.assertAlmostEqual(no_cve.priority_score, round((9.8 + 0.75) * 0.7, 2))
        # балл ≥ 7, но совпадение только по названию: метка остаётся «Средний»
        self.assertEqual(no_cve.priority_label, "Средний")

    def test_separate_finding_group_with_capped_severity(self):
        result = self._run()
        nvd_finding = next(f for f in result.findings if f.kind == "known_cve_kev")
        self.assertNotIn("BDU:2099-00001", nvd_finding.identifiers)   # NVD-находка не загрязнена
        groups = {f.title.split(":")[0]: f for f in result.findings if f.kind == "known_bdu"}
        self.assertEqual(sorted(groups), ["Apache HTTP Server 2.4.49", "PHP 7.4.3"])
        apache = groups["Apache HTTP Server 2.4.49"]
        self.assertIn("(2)", apache.title)
        self.assertEqual(apache.severity, "Medium")      # без KEV выше среднего не поднимается
        self.assertEqual(apache.sources, ["БДУ ФСТЭК"])
        self.assertIn("BDU:2099-00001", apache.identifiers)
        self.assertIn("CVE-2099-0001", apache.identifiers)
        self.assertIn("версии в БДУ: «от 2.4.0 до 2.4.50»", apache.evidence)
        self.assertIn("по названию", apache.evidence)
        self.assertTrue(any("(БДУ ФСТЭК): Обновить HTTP Server до 2.4.51" in step
                            for step in apache.fix_steps))
        self.assertIn("https://bdu.fstec.ru/vul/2099-00001", apache.references)
        # PHP с BDU-записью больше не попадает в «раскрыты версии без CVE»
        disclosed = [f for f in result.findings if f.kind == "component_version_disclosed"]
        self.assertTrue(all("PHP" not in f.evidence for f in disclosed))

    def test_disabling_bdu_removes_direct_lookup(self):
        result = self._run(use_bdu=False)
        self.assertEqual(self._only(result), {})
        self.assertFalse(any(f.kind == "known_bdu" for f in result.findings))

    def test_direct_lookup_works_without_nvd_results(self):
        cfg = VulnDbConfig(cache_dir=self.tmp.name + "/cache2", session=catalog_session(nvd=False),
                           sleep=lambda _s: None, bdu_file=str(self.xlsx_path))
        result = enrich_with_catalogs([target_page()], cfg)
        self.assertEqual(result.sources["NVD"].state, "unavailable")
        ids = {m.bdu[0]["id"] for m in result.matches}
        self.assertTrue({"BDU:2099-00001", "BDU:2021-04903", "BDU:2099-00005"} <= ids)

    def test_report_marks_bdu_only_rows(self):
        result = self._run()
        findings = FindingList()
        findings.extend(result.findings)
        stats = {"target": TARGET, "pages": 1, "max_pages": 60, "requests_made": 5,
                 "max_requests": 600, "notes": result.notes, "duration": 1.0,
                 "vulnerability_intelligence": result.as_context()}
        html_text = build_report(findings, stats)
        self.assertIn("только по данным БДУ ФСТЭК", html_text)
        self.assertIn("по названию продукта (БДУ)", html_text)
        self.assertIn("BDU:2099-00001", html_text)


if __name__ == "__main__":
    unittest.main()
