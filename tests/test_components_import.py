"""Импорт списка компонентов: форматы, пропуски, дедупликация, интеграция с БДУ и NVD."""

import json
import os
import tempfile
import unittest

from test_bdu import H_ID, build_xlsx
from test_vulndb import catalog_session, target_page
from vulndb_fakes import FakeSession
from webscan.components_import import ImportFailure, import_components
from webscan.vulndb import VulnDbConfig, enrich_with_catalogs


class ImportCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, content, binary=False):
        path = os.path.join(self.tmp.name, name)
        if isinstance(content, (dict, list)):
            content = json.dumps(content)
        with open(path, "wb" if binary else "w", **({} if binary else {"encoding": "utf-8"})) as handle:
            handle.write(content)
        return path

    def by_label(self, result):
        return {item.label: item for item in result.components}


class TestRequirements(ImportCase):
    def test_pinned_lines_only(self):
        path = self.write("requirements.txt", "\n".join([
            "# зависимости",
            "Flask==2.0.1",
            "jinja2 == 3.0.1  # шаблоны",
            "requests[security]==2.25.0 ; python_version >= '3.6'",
            "numpy>=1.20",
            "pytest",
            "-r other.txt",
            "--index-url https://example.org/simple",
            "Django===4.2.1",
            "urllib3==1.26.*",
        ]))
        result = import_components(path)
        self.assertEqual(result.fmt, "requirements.txt")
        self.assertEqual(sorted(i.label for i in result.components),
                         ["Django", "Flask", "Jinja2", "requests"])
        self.assertEqual(result.skipped, 3)   # numpy>=, pytest, urllib3==1.26.*
        flask = self.by_label(result)["Flask"]
        self.assertEqual((flask.version, flask.cpe_pairs), ("2.0.1", [("palletsprojects", "flask")]))
        self.assertFalse(flask.keyword_search)
        self.assertTrue(flask.nvd_eligible)

    def test_unknown_package_is_searched_by_keyword(self):
        result = import_components(self.write("requirements.txt", "pyyaml==5.3.1\n"))
        item = result.components[0]
        self.assertEqual((item.label, item.product, item.vendor), ("pyyaml", "pyyaml", ""))
        self.assertTrue(item.keyword_search)
        self.assertTrue(item.nvd_eligible)       # NVD подберёт CPE по названию
        self.assertEqual(item.cpe_pairs, [])
        self.assertIn("requirements.txt, строка 1", item.evidences[0])

    def test_plain_name_version_lines(self):
        path = self.write("components.txt", "nginx 1.18.0\nopenssl@1.1.1k\nlodash:4.17.15\nмусор\n")
        result = import_components(path)
        self.assertEqual({i.label: i.version for i in result.components},
                         {"nginx": "1.18.0", "openssl": "1.1.1k", "Lodash": "4.17.15"})
        self.assertEqual(result.fmt, "список «имя версия»")
        self.assertEqual(result.skipped, 1)

    def test_empty_or_versionless_file_fails_clearly(self):
        with self.assertRaises(ImportFailure) as caught:
            import_components(self.write("r.txt", "flask\nrequests>=2\n"))
        self.assertIn("точной версией не найдено", str(caught.exception))


class TestJsonFormats(ImportCase):
    def test_package_lock_v2_and_v1(self):
        v2 = {"lockfileVersion": 2, "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/@scope/pkg": {"version": "2.0.0"},
            "node_modules/a/node_modules/jquery": {"version": "3.4.0"},
        }}
        result = import_components(self.write("package-lock.json", v2))
        self.assertEqual(result.fmt, "npm lock")
        self.assertEqual(sorted((i.label, i.version) for i in result.components),
                         [("@scope/pkg", "2.0.0"), ("Lodash", "4.17.15"), ("jQuery", "3.4.0")])
        v1 = {"lockfileVersion": 1, "dependencies": {
            "express": {"version": "4.17.1", "dependencies": {"qs": {"version": "6.7.0"}}}}}
        result = import_components(self.write("lock1.json", v1))
        self.assertEqual({i.label: i.version for i in result.components},
                         {"Express": "4.17.1", "qs": "6.7.0"})

    def test_package_json_exact_versions_only(self):
        data = {"name": "app", "dependencies": {"lodash": "4.17.15", "express": "^4.17.1",
                                                "axios": "0.21.1", "left-pad": "latest"},
                "devDependencies": {"jest": "~26.0.0"}}
        result = import_components(self.write("package.json", data))
        self.assertEqual(result.fmt, "package.json")
        self.assertEqual({i.label for i in result.components}, {"Lodash", "Axios"})
        self.assertEqual(result.skipped, 3)

    def test_composer_lock(self):
        data = {"content-hash": "abc", "packages": [
            {"name": "symfony/http-kernel", "version": "v5.4.2"},
            {"name": "laravel/framework", "version": "dev-master"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}]}
        result = import_components(self.write("composer.lock", data))
        self.assertEqual(result.fmt, "composer.lock")
        self.assertEqual(sorted(i.version for i in result.components), ["5.4.2", "9.5.0"])
        self.assertEqual(result.skipped, 1)

    def test_cyclonedx_uses_cpe_when_present(self):
        data = {"bomFormat": "CycloneDX", "specVersion": "1.4", "components": [
            {"name": "struts2-core", "group": "org.apache.struts", "version": "2.5.10",
             "cpe": "cpe:2.3:a:apache:struts:2.5.10:*:*:*:*:*:*:*"},
            {"name": "logger", "version": "1.0.0", "components": [{"name": "inner", "version": "0.1"}]},
            {"name": "no-version"}]}
        result = import_components(self.write("bom.json", data))
        self.assertEqual(result.fmt, "CycloneDX")
        items = {i.label: i for i in result.components}
        self.assertEqual(items["struts2-core"].cpe_pairs, [("apache", "struts")])
        self.assertFalse(items["struts2-core"].keyword_search)
        self.assertEqual(set(items), {"struts2-core", "logger", "inner"})
        self.assertEqual(result.skipped, 1)

    def test_spdx(self):
        data = {"spdxVersion": "SPDX-2.3", "packages": [
            {"SPDXID": "SPDXRef-1", "name": "openssl", "versionInfo": "1.1.1k",
             "externalRefs": [{"referenceType": "cpe23Type",
                               "referenceLocator": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"}]}]}
        result = import_components(self.write("sbom.spdx.json", data))
        self.assertEqual(result.fmt, "SPDX")
        self.assertEqual(result.components[0].cpe_pairs, [("openssl", "openssl")])

    def test_unknown_json_and_broken_json(self):
        with self.assertRaises(ImportFailure):
            import_components(self.write("x.json", {"hello": "world"}))
        with self.assertRaises(ImportFailure) as caught:
            import_components(self.write("bad.json", "{не json"))
        self.assertIn("некорректный JSON", str(caught.exception))


class TestCommon(ImportCase):
    def test_duplicates_collapse_and_versions_stay_distinct(self):
        path = self.write("r.txt", "flask==2.0.1\nFlask==2.0.1\nflask==1.1.2\n")
        result = import_components(path)
        self.assertEqual(sorted(i.version for i in result.components), ["1.1.2", "2.0.1"])

    def test_missing_and_oversized_files(self):
        with self.assertRaises(ImportFailure):
            import_components(os.path.join(self.tmp.name, "нет.txt"))
        from webscan import components_import
        path = self.write("big.txt", "flask==2.0.1\n")
        original = components_import.MAX_FILE_BYTES
        components_import.MAX_FILE_BYTES = 3
        try:
            with self.assertRaises(ImportFailure):
                import_components(path)
        finally:
            components_import.MAX_FILE_BYTES = original

    def test_bom_and_cp_variants_are_read(self):
        path = self.write("r.txt", "﻿flask==2.0.1\n")
        self.assertEqual(import_components(path).components[0].version, "2.0.1")

    def test_v_prefix_is_stripped(self):
        result = import_components(self.write("r.txt", "tool v1.2.3\n"))
        self.assertEqual(result.components[0].version, "1.2.3")


class TestInCorrelation(ImportCase):
    BDU_ROWS = [
        {H_ID: "BDU:2099-10001", "Наименование уязвимости": "Уязвимость Flask",
         "Вендор ПО": "Pallets", "Название ПО": "Flask",
         "Версия ПО": "до 2.2.5 (Flask)",
         "Уровень опасности уязвимости": "Высокий уровень опасности (базовая оценка CVSS 3.0 составляет 7,5)",
         "Идентификаторы других систем описаний уязвимости": "CVE-2099-0001"},
        {H_ID: "BDU:2099-10002", "Наименование уязвимости": "Уязвимость PyYAML",
         "Вендор ПО": "Сообщество свободного программного обеспечения", "Название ПО": "PyYAML",
         "Версия ПО": "от 5.0 до 5.4 (PyYAML)",
         "Идентификаторы других систем описаний уязвимости": "OSVDB ID:5"},
        {H_ID: "BDU:2099-10003", "Наименование уязвимости": "Уязвимость Flask новее",
         "Вендор ПО": "Pallets", "Название ПО": "Flask", "Версия ПО": "до 1.0 (Flask)"},
    ]

    def run_with(self, requirements, **kwargs):
        xlsx = os.path.join(self.tmp.name, "vullist.xlsx")
        with open(xlsx, "wb") as handle:
            handle.write(build_xlsx(self.BDU_ROWS))
        req = self.write("requirements.txt", requirements)
        cfg = VulnDbConfig(cache_dir=os.path.join(self.tmp.name, "cache"), session=catalog_session(),
                           sleep=lambda _s: None, bdu_file=xlsx, components_files=[req], **kwargs)
        return enrich_with_catalogs([target_page()], cfg)

    def test_imported_components_are_matched_against_bdu(self):
        result = self.run_with("flask==2.0.1\npyyaml==5.3.1\nnumpy==1.19.0\n")
        names = {c.label for c in result.components}
        self.assertTrue({"Flask", "pyyaml", "numpy", "Apache HTTP Server"} <= names)
        self.assertEqual(result.imported_components, 3)
        only = {m.bdu[0]["id"]: m for m in result.matches if m.source == "bdu"}
        self.assertEqual(sorted(only), ["BDU:2099-10001", "BDU:2099-10002"])
        self.assertNotIn("BDU:2099-10003", only)          # 2.0.1 не «до 1.0»
        self.assertEqual(only["BDU:2099-10001"].component.version, "2.0.1")
        # источник и место видны в отчёте компонентов
        flask = next(c for c in result.components if c.label == "Flask")
        self.assertIn("requirements.txt", flask.evidences[0])
        self.assertTrue(flask.source.startswith("Импорт"))
        self.assertTrue(any("Импорт компонентов из requirements.txt" in n for n in result.notes))
        self.assertEqual(result.as_context()["imported"], 3)

    def test_findings_are_created_per_imported_component(self):
        result = self.run_with("flask==2.0.1\npyyaml==5.3.1\n")
        titles = [f.title for f in result.findings if f.kind == "known_bdu"]
        self.assertTrue(any(t.startswith("Flask 2.0.1") for t in titles), titles)
        self.assertTrue(any(t.startswith("pyyaml 5.3.1") for t in titles), titles)

    def test_failure_to_load_is_a_note_not_an_error(self):
        cfg = VulnDbConfig(cache_dir=os.path.join(self.tmp.name, "c"), session=catalog_session(),
                           sleep=lambda _s: None, use_bdu=False,
                           components_files=[os.path.join(self.tmp.name, "нет.txt")])
        result = enrich_with_catalogs([target_page()], cfg)
        self.assertTrue(any("Список компонентов не загружен" in n for n in result.notes))
        self.assertEqual(result.imported_components, 0)
        self.assertIn("CVE-2021-41773", {m.cve_id for m in result.matches})   # скан не пострадал

    def test_component_found_by_banner_and_in_list_is_merged(self):
        path = self.write("r.txt", "http_server 2.4.49\n")
        cfg = VulnDbConfig(cache_dir=os.path.join(self.tmp.name, "c2"), session=catalog_session(),
                           sleep=lambda _s: None, use_bdu=False, components_files=[path])
        result = enrich_with_catalogs([target_page()], cfg)
        apache = [c for c in result.components if c.version == "2.4.49"]
        self.assertEqual(len(apache), 1)                  # без дубля
        self.assertEqual(result.imported_components, 0)   # не новый компонент

    def test_every_component_is_analysed_without_a_cap(self):
        # Flask и PyYAML стоят в самом конце длинного списка: раньше они не попадали в лимит
        lines = "\n".join(f"pkg{i}==1.0.{i}" for i in range(60)) + "\nflask==2.0.1\npyyaml==5.3.1\n"
        xlsx = os.path.join(self.tmp.name, "vullist.xlsx")
        with open(xlsx, "wb") as handle:
            handle.write(build_xlsx(self.BDU_ROWS))
        session = catalog_session()
        cfg = VulnDbConfig(cache_dir=os.path.join(self.tmp.name, "c3"), session=session,
                           sleep=lambda _s: None, bdu_file=xlsx,
                           components_files=[self.write("many.txt", lines)])
        result = enrich_with_catalogs([target_page()], cfg)
        imported = [c for c in result.components if c.source.startswith("Импорт")]
        self.assertEqual(len(imported), 62)
        self.assertFalse(any("проверены первые" in n or "не проверены" in n for n in result.notes))
        only = {m.bdu[0]["id"] for m in result.matches if m.source == "bdu"}
        self.assertEqual(only, {"BDU:2099-10001", "BDU:2099-10002"})
        # в NVD ушли запросы и по самым последним компонентам списка
        keywords = {str(call["params"].get("keywordSearch")) for call in session.calls}
        self.assertIn("pkg59", keywords)
        self.assertIn("pyyaml", keywords)

    def test_nvd_requests_go_to_known_cpe_pairs_first(self):
        lines = "\n".join(f"pkg{i}==1.0.{i}" for i in range(40)) + "\nflask==2.0.1\n"
        session = catalog_session()
        cfg = VulnDbConfig(cache_dir=os.path.join(self.tmp.name, "c4"), session=session,
                           sleep=lambda _s: None, use_bdu=False,
                           components_files=[self.write("many.txt", lines)])
        result = enrich_with_catalogs([target_page()], cfg)
        self.assertEqual(result.imported_components, 41)
        # flask известна по CPE: запрос в NVD по её паре ушёл, хотя она последняя в файле
        urls = " ".join(str(call["params"]) for call in session.calls)
        self.assertIn("palletsprojects", urls)


if __name__ == "__main__":
    unittest.main()
