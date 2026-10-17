"""Изолированные тесты каталожной корреляции без доступа в Интернет."""

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
import tempfile
import time
import unittest

from webscan.fingerprint import DetectedProduct, detect_products
from webscan.models import HIGH, SUSPECTED, Page
from webscan.vulndb import VulnDbConfig, enrich_with_catalogs
from webscan.vulndb.exploitdb import parse_exploitdb_csv
from webscan.vulndb.kev import parse_kev
from webscan.vulndb.nvd import _best_match as nvd_best_match, _condense as nvd_condense, pick_cvss, score_cpe
from webscan.vulndb.scoring import VulnMatch, score_match
from webscan.vulndb.cache import (
    FRESH,
    STALE,
    UNAVAILABLE,
    UPDATED,
    CacheStore,
    NotModified,
    SourceStatus,
    load_with_cache,
)
from webscan.vulndb.catalog_http import CatalogHttpClient, CatalogHttpError, OfflineError
from vulndb_fakes import FakeResponse, FakeSession, fixture_bytes, fixture_json
from webscan.vulndb.versions import (
    compare_versions,
    in_range,
    match_cpe_version,
    parse_version,
)


class TestVersions(unittest.TestCase):
    def test_numeric_ordering_and_padding(self):
        self.assertEqual(compare_versions("1.18.0", "1.20"), -1)
        self.assertEqual(compare_versions("1.20", "1.18.0"), 1)
        self.assertEqual(compare_versions("1.18", "1.18.0"), 0)
        self.assertEqual(compare_versions("2.4.10", "2.4.9"), 1)

    def test_nvd_half_open_range(self):
        self.assertTrue(in_range("2.4.49", start_including="2.4.49", end_excluding="2.4.50"))
        self.assertFalse(in_range("2.4.50", start_including="2.4.49", end_excluding="2.4.50"))
        self.assertFalse(in_range("2.4.48", start_including="2.4.49", end_excluding="2.4.50"))
        self.assertTrue(in_range("2.4.50", end_including="2.4.50"))
        self.assertFalse(in_range("2.4.49", start_excluding="2.4.49"))
        self.assertTrue(in_range("1.0", start_including="*", end_excluding="-"))

    def test_distro_revision_is_ignored(self):
        self.assertEqual(compare_versions("7.4.3-1ubuntu", "7.4.3"), 0)
        self.assertEqual(compare_versions("1.18.0-6+deb11u3", "1.18.0"), 0)
        self.assertEqual(compare_versions("2.4.6-97.el7", "2.4.6"), 0)

    def test_openssl_letter_patch_levels(self):
        self.assertEqual(compare_versions("1.0.2k", "1.0.2u"), -1)
        self.assertEqual(compare_versions("1.0.2k", "1.0.2"), 1)
        self.assertEqual(compare_versions("1.0.2a", "1.0.2"), 1)
        self.assertEqual(compare_versions("1.1.0", "1.0.2u"), 1)
        self.assertEqual(compare_versions("7.4p1", "7.4"), 1)

    def test_prereleases_are_older_than_release(self):
        self.assertEqual(compare_versions("3.0.0-rc1", "3.0.0"), -1)
        self.assertEqual(compare_versions("3.0.0-beta.2", "3.0.0-rc1"), -1)
        self.assertEqual(compare_versions("1.0a1", "1.0"), -1)
        self.assertEqual(compare_versions("3.0.0-rc2", "3.0.0-rc10"), -1)

    def test_empty_and_wildcards_are_unparsed(self):
        for value in ("", None, "*", "-", "  "):
            self.assertIsNone(parse_version(value))
        self.assertIsNone(compare_versions("*", "1.0"))
        self.assertIsNone(in_range("-", end_excluding="2.0"))
        self.assertIsNone(parse_version("latest"))

    def test_cpe_match_labels(self):
        self.assertEqual(match_cpe_version("2.4.49", "2.4.49"), "exact")
        self.assertIsNone(match_cpe_version("2.4.48", "2.4.49"))
        self.assertEqual(match_cpe_version("2.4.49", "*", start_including="2.4.0",
                                           end_excluding="2.4.50"), "range")
        self.assertIsNone(match_cpe_version("2.4.51", "*", end_excluding="2.4.50"))
        self.assertEqual(match_cpe_version("2.4.49", "*"), "product_only")
        self.assertEqual(match_cpe_version("2.4.49", "-"), "product_only")


class TestFingerprint(unittest.TestCase):
    def test_detects_headers_generator_and_assets(self):
        page = Page(
            url="https://example.test/",
            depth=0,
            status=200,
            headers={"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1.2"},
            raw_headers=[],
            body=("<html><head><meta name='generator' content='WordPress 6.4.2'>"
                  "<script src='/js/jquery-3.6.0.min.js'></script></head></html>"),
            content_type="text/html",
        )
        products = {(item.product, item.version) for item in detect_products([page])}
        self.assertIn(("nginx", "1.24.0"), products)
        self.assertIn(("php", "8.1.2"), products)
        self.assertIn(("wordpress", "6.4.2"), products)
        self.assertIn(("jquery", "3.6.0"), products)

    @staticmethod
    def _page(headers=None, body="", content_type="text/html", cookies=None, url="https://example.test/"):
        return Page(url=url, depth=0, status=200, headers=headers or {}, raw_headers=[],
                    body=body, content_type=content_type, cookies=cookies or [])

    def _by_label(self, products):
        return {item.label: item for item in products}

    def test_server_banners_from_prompt(self):
        products = self._by_label(detect_products([self._page(headers={
            "Server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1k",
            "X-Powered-By": "PHP/7.4.3",
        })]))
        self.assertEqual(products["Apache HTTP Server"].version, "2.4.49")
        self.assertEqual(products["Apache HTTP Server"].cpe_pairs, [("apache", "http_server")])
        self.assertEqual(products["OpenSSL"].version, "1.1.1k")
        self.assertEqual(products["PHP"].version, "7.4.3")

    def test_added_products_with_versions(self):
        products = self._by_label(detect_products([
            self._page(headers={"Server": "Caddy", "X-Jenkins": "2.426.1", "Via": "1.1 haproxy"},
                       body=("<script src='/js/messages.php?v=4.9.5&lang=en'></script>"
                             "<script>window.grafanaBootData={\"settings\":{\"buildInfo\":"
                             "{\"hasUpdate\":false,\"version\":\"9.3.2\"}}};</script>")),
        ]))
        self.assertEqual(products["Jenkins"].version, "2.426.1")
        self.assertEqual(products["Jenkins"].cpe_pairs, [("jenkins", "jenkins")])
        self.assertEqual(products["phpMyAdmin"].version, "4.9.5")
        self.assertEqual(products["Grafana"].version, "9.3.2")
        self.assertEqual(products["Caddy"].cpe_pairs, [("caddyserver", "caddy")])
        self.assertEqual(products["HAProxy"].cpe_pairs, [("haproxy", "haproxy")])

    def test_phpmyadmin_modern_route_version(self):
        page = self._page(body="<script src='index.php?route=/messages&v=5.2.1&lang=en'></script>")
        item = self._by_label(detect_products([page]))["phpMyAdmin"]
        self.assertEqual(item.version, "5.2.1")

    def test_added_products_by_path_and_header_have_no_version(self):
        page = self._page(
            headers={"X-Magento-Cache-Debug": "HIT", "X-Gitlab-Meta": '{"correlation_id":"x","version":"1"}'},
            body=("<link href='/static/version1700/frontend/Magento/luma/en_US/css/styles.css' rel='stylesheet'>"
                  "<script src='/catalog/view/javascript/jquery/common.js'></script>"
                  "<a href='/phpmyadmin/'>db</a>"))
        page.links = ["https://example.test/phpmyadmin/"]  # ссылки в реальном скане собирает краулер
        products = self._by_label(detect_products([page]))
        for label in ("Magento", "OpenCart", "phpMyAdmin", "GitLab"):
            self.assertIn(label, products)
            self.assertEqual(products[label].version, "")
        self.assertIn(("adobe", "magento"), products["Magento"].cpe_pairs)

    def test_unrelated_site_does_not_trigger_added_products(self):
        page = self._page(
            headers={"Server": "nginx/1.24.0"},
            body=("<script src='/assets/app.js?v=3.1.4'></script><a href='/catalog/view/all'></a>"
                  "<p>We use Caddy-like speed and a jenkins of our own</p>"))
        labels = {item.label for item in detect_products([page])}
        self.assertFalse(labels & {"Caddy", "HAProxy", "Jenkins", "Grafana", "phpMyAdmin",
                                   "GitLab", "Magento", "OpenCart"})

    def test_nginx_has_both_nvd_vendors(self):
        item = detect_products([self._page(headers={"Server": "nginx/1.18.0"})])[0]
        self.assertEqual(item.version, "1.18.0")
        self.assertIn(("f5", "nginx"), item.cpe_pairs)
        self.assertIn(("nginx", "nginx"), item.cpe_pairs)

    def test_banner_without_version_is_not_sent_to_nvd(self):
        products = detect_products([self._page(headers={"Server": "nginx"})])
        self.assertEqual(len(products), 1)
        self.assertEqual(products[0].version, "")
        self.assertFalse(products[0].nvd_eligible)

    def test_asset_generator_and_js_banner(self):
        body = ("<html><head><meta name='generator' content='WordPress 5.8'>"
                "<script src='/static/jquery-3.4.1.min.js'></script>"
                "<link rel='stylesheet' href='/wp-content/themes/x/style.css'>"
                "<script>/*! Bootstrap v4.3.1 */</script></head></html>")
        products = self._by_label(detect_products([self._page(body=body)]))
        self.assertEqual(products["jQuery"].version, "3.4.1")
        self.assertEqual(products["WordPress"].version, "5.8")
        # Путь /wp-content/ без версии слит с версионной записью, а не продублирован.
        self.assertIn("характерный путь", products["WordPress"].sources)
        self.assertEqual(products["Bootstrap"].version, "4.3.1")

    def test_js_file_banner_and_cdn(self):
        js = self._page(body="/*! jQuery v1.12.4 | (c) jQuery Foundation */\n!function(){}",
                        content_type="application/javascript", url="https://example.test/app.js")
        html = self._page(body="<script src='https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.15/lodash.min.js'></script>")
        products = self._by_label(detect_products([js, html]))
        self.assertEqual(products["jQuery"].version, "1.12.4")
        self.assertEqual(products["Lodash"].version, "4.17.15")

    def test_cookie_names_give_product_without_version(self):
        from webscan.models import CookieInfo
        cookie = CookieInfo("PHPSESSID", False, False, None, None, None, "PHPSESSID=x")
        products = detect_products([self._page(cookies=[cookie])])
        self.assertEqual([(p.label, p.version) for p in products], [("PHP", "")])

    def test_evidence_is_merged_across_pages(self):
        pages = [self._page(headers={"Server": "nginx/1.18.0"}, url=f"https://example.test/{i}")
                 for i in range(3)]
        pages.append(self._page(headers={"Via": "1.1 nginx/1.18.0"}))
        products = detect_products(pages)
        self.assertEqual(len(products), 1)
        self.assertEqual(len(products[0].evidences), 2)  # Server и Via, без повторов

    def test_werkzeug_python_dev_server(self):
        products = self._by_label(detect_products([self._page(headers={
            "Server": "Werkzeug/2.0.1 Python/3.9.5"})]))
        self.assertEqual(products["Werkzeug"].version, "2.0.1")
        self.assertEqual(products["Python"].version, "3.9.5")

    def test_cpe_scoring_prefers_exact_product_and_version(self):
        product = DetectedProduct("nginx", "nginx", "1.24.0")
        exact = score_cpe("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", product)
        wildcard = score_cpe("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", product)
        wrong = score_cpe("cpe:2.3:a:apache:http_server:1.24.0:*:*:*:*:*:*:*", product)
        self.assertGreater(exact, wildcard)
        self.assertEqual(wrong, 0)


class TestCatalogParsing(unittest.TestCase):
    def test_kev_index(self):
        index, date = parse_kev(fixture_bytes("kev.json"))
        self.assertEqual(len(index), 5)
        entry = index["CVE-2021-41773"]
        self.assertEqual(entry["knownRansomwareCampaignUse"], "Known")
        self.assertEqual(entry["dueDate"], "2021-11-17")
        self.assertTrue(date.startswith("20"))

    def test_exploitdb_index(self):
        index = parse_exploitdb_csv(fixture_bytes("files_exploits.csv"))
        exploits = index["CVE-2021-41773"]
        self.assertEqual({item["edb_id"] for item in exploits}, {"50383"})
        self.assertTrue(exploits[0]["verified"])
        self.assertEqual(exploits[0]["url"], "https://www.exploit-db.com/exploits/50383")
        self.assertIn("CVE-2021-44228", index)
        # строка без CVE не индексируется
        self.assertFalse(any(item["edb_id"] == "34588" for items in index.values() for item in items))

    def test_nvd_condense_and_local_version_check(self):
        data = fixture_json("nvd_cves_apache_http_server.json")
        cves = {item["cve"]["id"]: nvd_condense(item["cve"], "apache", "http_server")
                for item in data["vulnerabilities"]}
        main = cves["CVE-2021-41773"]
        self.assertEqual(main["cvss"]["version"], "3.1")
        self.assertEqual(main["cvss"]["score"], 9.8)  # Primary, а не Secondary 7.5
        self.assertEqual(main["cwe"], ["CWE-22"])
        self.assertEqual(nvd_best_match("2.4.49", main["matches"]), "exact")
        self.assertEqual(nvd_best_match("2.4.49", cves["CVE-2021-44224"]["matches"]), "range")
        self.assertIsNone(nvd_best_match("2.4.49", cves["CVE-2019-9517"]["matches"]))
        self.assertIsNone(nvd_best_match("2.4.52", main["matches"]))

    def test_cvss_priority_v4_first(self):
        metrics = {
            "cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 5.0}}],
            "cvssMetricV40": [{"type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 8.7,
                                                                   "baseSeverity": "HIGH"}}],
        }
        self.assertEqual(pick_cvss(metrics)["version"], "4.0")


TARGET = "https://shop.example.test/"


def catalog_session(nvd=True, catalogs=True):
    """Фейковые NVD/KEV/ExploitDB на фикстурах."""
    session = FakeSession()
    if nvd:
        session.add(lambda url, p: "cpes/2.0" in url and "apache:http_server:2.4.49" in str(p.get("cpeMatchString")),
                    FakeResponse(200, fixture_bytes("nvd_cpes_apache_http_server_2.4.49.json")))
        session.add("cpes/2.0", FakeResponse(200, {"totalResults": 0, "products": []}))
        session.add(lambda url, p: "cves/2.0" in url and "apache:http_server" in str(p.get("virtualMatchString")),
                    FakeResponse(200, fixture_bytes("nvd_cves_apache_http_server.json")))
        session.add("cves/2.0", FakeResponse(200, {"totalResults": 0, "vulnerabilities": []}))
    if catalogs:
        session.add("known_exploited", FakeResponse(200, fixture_bytes("kev.json")))
        session.add("files_exploits.csv", FakeResponse(200, fixture_bytes("files_exploits.csv")))
    return session


def target_page():
    from webscan.models import CookieInfo
    return Page(
        url=TARGET, depth=0, status=200,
        headers={"Server": "Apache/2.4.49 (Unix)", "X-Powered-By": "PHP/7.4.3"},
        raw_headers=[], body="<html><body>SECRET-PAGE-MARKER</body></html>", content_type="text/html",
        cookies=[CookieInfo("PHPSESSID", False, False, None, None, None, "PHPSESSID=s3cr3tvalue")],
    )


class TestCorrelation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _cfg(self, session, **kwargs):
        return VulnDbConfig(cache_dir=self.tmp.name, session=session, sleep=lambda _s: None, **kwargs)

    def _run(self, session, **kwargs):
        return enrich_with_catalogs([target_page()], self._cfg(session, **kwargs))

    def test_apache_2_4_49_full_chain(self):
        result = self._run(catalog_session())
        by_cve = {m.cve_id: m for m in result.matches}
        self.assertIn("CVE-2021-41773", by_cve)
        self.assertIn("CVE-2021-44224", by_cve)       # диапазон 2.4.7–2.4.52
        self.assertNotIn("CVE-2019-9517", by_cve)     # 2.4.20–2.4.40 не затрагивает
        match = by_cve["CVE-2021-41773"]
        self.assertEqual(match.version_match, "exact")
        self.assertIsNotNone(match.kev)
        self.assertEqual(match.exploits[0]["edb_id"], "50383")
        self.assertEqual(match.priority_label, "Эксплуатируется")
        # 9.8 + 3 (KEV) + 1 (ransomware) + 1.5 (verified exploit)
        self.assertAlmostEqual(match.priority_score, 15.3)

        apache = [f for f in result.findings if "Apache HTTP Server" in f.title]
        self.assertEqual(len(apache), 1)              # одна находка на компонент
        finding = apache[0]
        self.assertEqual(finding.kind, "known_cve_kev")
        self.assertEqual(finding.severity, HIGH)
        self.assertEqual(finding.confidence, SUSPECTED)
        self.assertTrue(finding.exploited)
        self.assertIn("CVE-2021-41773", finding.identifiers)
        self.assertEqual(finding.vuln_matches[0]["cve"], "CVE-2021-41773")  # сортировка по приоритету
        self.assertIn("бэкпортирована", finding.evidence)
        self.assertEqual(result.kev_count, 2)
        # PHP 7.4.3 без CVE в фейковом NVD → информационная находка о раскрытой версии
        self.assertTrue(any(f.kind == "component_version_disclosed" for f in result.findings))

    def test_no_target_data_leaves_to_catalogs(self):
        session = catalog_session()
        self._run(session)
        self.assertTrue(session.calls)
        dump = json.dumps(session.calls, ensure_ascii=False)
        for secret in ("shop.example.test", "s3cr3tvalue", "PHPSESSID", "SECRET-PAGE-MARKER"):
            self.assertNotIn(secret, dump)
        for call in session.calls:
            if "nvd.nist.gov" in call["url"]:
                self.assertTrue(set(call["params"]) <= {"cpeMatchString", "virtualMatchString",
                                                        "keywordSearch", "resultsPerPage", "startIndex"})

    def test_nvd_down_does_not_break_scan(self):
        result = self._run(catalog_session(nvd=False))
        self.assertEqual(result.matches, [])
        self.assertEqual(result.sources["NVD"].state, "unavailable")
        self.assertTrue(any("NVD" in note for note in result.notes))

    def test_nvd_429_then_200(self):
        session = catalog_session()
        session.routes.insert(0, (lambda url, p: "cves/2.0" in url and "apache" in str(p),
                                  [FakeResponse(429),
                                   FakeResponse(200, fixture_bytes("nvd_cves_apache_http_server.json"))]))
        result = self._run(session)
        self.assertIn("CVE-2021-41773", {m.cve_id for m in result.matches})
        statuses = [call for call in session.calls if "virtualMatchString" in call["params"]
                    and "apache" in call["params"]["virtualMatchString"]]
        self.assertEqual(len(statuses), 2)

    def test_offline_makes_no_requests(self):
        session = FakeSession()
        result = self._run(session, offline=True)
        self.assertEqual(session.calls, [])
        self.assertEqual(result.sources["NVD"].state, "offline")
        # после онлайн-запуска офлайн работает из кэша, тоже без запросов
        self._run(catalog_session())
        offline_session = FakeSession()
        cached = self._run(offline_session, offline=True)
        self.assertEqual(offline_session.calls, [])
        self.assertIn("CVE-2021-41773", {m.cve_id for m in cached.matches})

    def test_stale_cache_used_when_network_fails(self):
        self._run(catalog_session())
        for meta in Path(self.tmp.name).rglob("*.meta.json"):
            data = json.loads(meta.read_text(encoding="utf-8"))
            data["fetched_epoch"] = time.time() - 72 * 3600
            meta.write_text(json.dumps(data), encoding="utf-8")
        result = self._run(FakeSession(), ttl_hours=24)
        self.assertIn("CVE-2021-41773", {m.cve_id for m in result.matches})
        self.assertEqual(result.sources["NVD"].state, "stale")
        self.assertEqual(result.sources["CISA KEV"].state, "stale")

    def test_no_versions_no_requests(self):
        session = FakeSession()
        page = Page(url=TARGET, depth=0, status=200, headers={"Server": "nginx"}, raw_headers=[],
                    body="", content_type="text/html")
        result = enrich_with_catalogs([page], self._cfg(session))
        self.assertEqual(session.calls, [])
        self.assertEqual(result.sources["NVD"].state, "skipped")
        self.assertTrue(any("скрыты" in note for note in result.notes))

    def test_product_only_halves_priority(self):
        component = DetectedProduct("x", "y", "1.0")
        full = VulnMatch("CVE-2020-0001", component, cvss={"score": 8.0}, version_match="range")
        weak = VulnMatch("CVE-2020-0001", component, cvss={"score": 8.0}, version_match="product_only")
        self.assertEqual(score_match(full)[0], 8.0)
        self.assertEqual(score_match(weak)[0], 4.0)


XSS = "<script>alert(1)</script></script><img src=x onerror=alert(2)>"


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, poison=False):
        from webscan.models import FindingList
        from webscan.report import build_report
        session = catalog_session()
        if poison:
            data = fixture_json("nvd_cves_apache_http_server.json")
            for item in data["vulnerabilities"]:
                item["cve"]["descriptions"] = [{"lang": "en", "value": XSS}]
            session.routes.insert(0, (lambda url, p: "cves/2.0" in url and "apache" in str(p),
                                      FakeResponse(200, data)))
        cfg = VulnDbConfig(cache_dir=self.tmp.name, session=session, sleep=lambda _s: None)
        result = enrich_with_catalogs([target_page()], cfg)
        findings = FindingList()
        findings.extend(result.findings)
        stats = {"target": TARGET, "pages": 1, "max_pages": 60, "requests_made": 5,
                 "max_requests": 600, "notes": result.notes, "duration": 1.0,
                 "vulnerability_intelligence": result.as_context()}
        return build_report(findings, stats), result

    def test_vuln_section_cards_and_sources(self):
        html_text, _result = self._report()
        self.assertIn("Известные уязвимости компонентов", html_text)
        self.assertIn('data-vuln-open="kev"', html_text)
        self.assertIn("Состояние справочников", html_text)
        self.assertIn("https://www.exploit-db.com/exploits/50383", html_text)
        self.assertIn("Критическая (CVSS 9.8)", html_text)
        self.assertIn('data-kev="1"', html_text)
        self.assertIn("Выгрузить для аудита (CSV)", html_text)
        self.assertIn("Формула приоритета", html_text)

    def test_cve_description_xss_is_escaped(self):
        html_text, result = self._report(poison=True)
        self.assertTrue(result.matches)
        self.assertNotIn("<img src=x", html_text)
        self.assertNotIn("<script>alert(1)", html_text)
        self.assertIn("&lt;script&gt;alert(1)", html_text)
        # Каждый открытый <script> закрыт своим </script> — описание не выходит из JSON-блока.
        self.assertEqual(html_text.count("<script"), html_text.count("</script>"))
        start = html_text.index('<script type="application/json" id="vuln-data">')
        block = html_text[start:html_text.index("</script>", start)]
        self.assertNotIn("</", block[len('<script type="application/json" id="vuln-data">'):])

    def test_audit_rows(self):
        from webscan.report_vulns import AUDIT_COLUMNS, audit_rows, collect_vulns
        _html, result = self._report()
        vulns, _more = collect_vulns(result.findings)
        rows = audit_rows(vulns)
        self.assertEqual(AUDIT_COLUMNS, ["CVE", "Компонент", "Версия", "CVSS", "Рекомендация",
                                         "В KEV", "Публичный эксплойт"])
        row = next(r for r in rows if r[0] == "CVE-2021-41773")
        self.assertEqual(row[1:4], ["Apache HTTP Server", "2.4.49", "9.8"])
        self.assertEqual(row[5:7], ["да", "да"])   # ФСТЭК/БДУ добавляются справа

    @unittest.skipUnless(shutil.which("node"), "нужен Node.js для проверки JS-экспорта")
    def test_csv_export_js_has_bom_and_columns(self):
        from webscan.report_vulns import AUDIT_COLUMNS, JS
        rows = [["CVE-2021-41773", "Apache", "2.4.49", "9.8",
                 "=HYPERLINK(\"evil\"); обновить", "да", "да"]]
        script = ("global.document={addEventListener:function(){}};\n" + JS
                  + "\nprocess.stdout.write(JSON.stringify(buildAuditCsv("
                  + json.dumps(AUDIT_COLUMNS) + "," + json.dumps(rows) + ")));")
        path = Path(self.tmp.name) / "csv_test.js"
        path.write_text(script, encoding="utf-8")
        out = subprocess.run(["node", str(path)], capture_output=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr.decode("utf-8", "replace"))
        csv_text = json.loads(out.stdout.decode("utf-8"))
        self.assertTrue(csv_text.startswith("﻿"))
        lines = csv_text[1:].split("\r\n")
        self.assertEqual(lines[0], ";".join(AUDIT_COLUMNS))
        # формула из внешнего текста нейтрализована и взята в кавычки
        self.assertIn('"\'=HYPERLINK(""evil""); обновить"', lines[1])


class TestStandEndToEnd(unittest.TestCase):
    """Полный скан учебного стенда (Server: Apache/2.4.49) на офлайн-кэше из фикстур."""

    @classmethod
    def setUpClass(cls):
        import threading
        from vulnerable_app import create_server
        cls.server = create_server(0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_offline_scan_of_stand(self):
        from webscan.report import build_report
        from webscan.scanner import ScanConfig, run_scan
        with tempfile.TemporaryDirectory() as cache_dir:
            # Кэш наполняется из фикстур (как если бы базы были скачаны ранее).
            enrich_with_catalogs([target_page()], VulnDbConfig(
                cache_dir=cache_dir, session=catalog_session(), sleep=lambda _s: None))

            def scan(use_vuln_db):
                return run_scan(ScanConfig(
                    url=f"http://127.0.0.1:{self.port}", max_pages=4, max_depth=1,
                    max_requests=40, active=False,
                    use_vuln_db=use_vuln_db, vuln_db_offline=True, vuln_db_cache_dir=cache_dir))

            result = scan(True)
            baseline = scan(False)
            # Этап 6 не отправляет цели ни одного запроса и не ходит в сеть в офлайн-режиме.
            self.assertEqual(result.stats["requests_made"], baseline.stats["requests_made"])
            self.assertEqual(result.stats["catalog_requests"], 0)

            kev = [f for f in result.findings if f.kind == "known_cve_kev"]
            self.assertEqual(len(kev), 1, [f.title for f in result.findings])
            self.assertIn("Apache HTTP Server 2.4.49", kev[0].title)
            self.assertIn("CVE-2021-41773", kev[0].identifiers)

            intel = result.stats["vulnerability_intelligence"]
            self.assertEqual(intel["kev"], 2)
            html_text = build_report(result.findings, result.stats)
            self.assertIn("CVE-2021-41773", html_text)
            self.assertIn('id="vuln-data"', html_text)


class TestCatalogHttp(unittest.TestCase):
    def _client(self, session, **kwargs):
        sleeps = []
        client = CatalogHttpClient(session=session, sleep=sleeps.append, backoff=1.0, **kwargs)
        return client, sleeps

    def test_backoff_on_429_then_success(self):
        session = FakeSession([("nvd", [FakeResponse(429, headers={"Retry-After": "3"}),
                                        FakeResponse(200, {"ok": True})])])
        client, sleeps = self._client(session)
        result = client.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.assertEqual(result.json(), {"ok": True})
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(sleeps, [3.0])  # Retry-After важнее базового backoff

    def test_gives_up_after_retries(self):
        session = FakeSession([("nvd", FakeResponse(503))])
        client, sleeps = self._client(session)
        with self.assertRaises(CatalogHttpError):
            client.get("https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.assertEqual(len(session.calls), 3)
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_offline_makes_no_requests(self):
        session = FakeSession()
        client, _ = self._client(session, offline=True)
        with self.assertRaises(OfflineError):
            client.get("https://www.cisa.gov/x.json")
        self.assertEqual(session.calls, [])

    def test_only_allowlisted_https_hosts(self):
        client, _ = self._client(FakeSession())
        for url in ("http://services.nvd.nist.gov/x", "https://example.com/x",
                    "https://www.cisa.gov.evil.test/x"):
            with self.assertRaises(ValueError):
                client.get(url)

    def test_size_limit(self):
        session = FakeSession([("", FakeResponse(200, b"x" * 1000))])
        client, _ = self._client(session)
        with self.assertRaises(CatalogHttpError):
            client.get("https://gitlab.com/f.csv", max_bytes=100)


class TestCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = CacheStore(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _age(self, name, hours):
        meta = self.cache.meta(name)
        meta["fetched_epoch"] = time.time() - hours * 3600
        self.cache.meta_path(name).write_text(json.dumps(meta), encoding="utf-8")

    def test_write_stores_metadata(self):
        self.cache.write_bytes("kev/kev.json", b"{}", source_url="https://www.cisa.gov/k", etag='"abc"')
        meta = self.cache.meta("kev/kev.json")
        self.assertEqual(meta["etag"], '"abc"')
        self.assertEqual(meta["sha256"], hashlib.sha256(b"{}").hexdigest())
        self.assertTrue(self.cache.is_fresh("kev/kev.json", 24))

    def test_fresh_cache_skips_download(self):
        self.cache.write_bytes("a.bin", b"old")
        status = SourceStatus("X")
        data = load_with_cache(self.cache, "a.bin", status, self._fail, ttl_hours=24)
        self.assertEqual((data, status.state), (b"old", FRESH))

    def test_stale_cache_used_when_network_fails(self):
        self.cache.write_bytes("a.bin", b"old")
        self._age("a.bin", 48)
        status = SourceStatus("X")
        data = load_with_cache(self.cache, "a.bin", status, self._fail, ttl_hours=24)
        self.assertEqual((data, status.state), (b"old", STALE))
        self.assertIn("данные от", status.label)

    def test_no_cache_no_network_is_unavailable(self):
        status = SourceStatus("X")
        self.assertIsNone(load_with_cache(self.cache, "a.bin", status, self._fail, ttl_hours=24))
        self.assertEqual(status.state, UNAVAILABLE)

    def test_offline_uses_cache_without_download(self):
        self.cache.write_bytes("a.bin", b"old")
        self._age("a.bin", 48)
        status = SourceStatus("X")
        data = load_with_cache(self.cache, "a.bin", status, self._fail, ttl_hours=24, offline=True)
        self.assertEqual((data, status.state), (b"old", STALE))

    def test_not_modified_refreshes_timestamp(self):
        self.cache.write_bytes("a.bin", b"old", etag='"e"')
        self._age("a.bin", 48)
        seen = {}

        def download(meta):
            seen.update(meta)
            raise NotModified()

        status = SourceStatus("X")
        data = load_with_cache(self.cache, "a.bin", status, download, ttl_hours=24)
        self.assertEqual(seen.get("etag"), '"e"')
        self.assertEqual((data, status.state), (b"old", UPDATED))
        self.assertTrue(self.cache.is_fresh("a.bin", 24))

    def test_failure_is_remembered_for_an_hour(self):
        calls = []

        def failing(_meta):
            calls.append(1)
            raise CatalogHttpError("таймаут")

        load_with_cache(self.cache, "a.bin", SourceStatus("X"), failing, ttl_hours=24)
        status = SourceStatus("X")
        self.assertIsNone(load_with_cache(self.cache, "a.bin", status, failing, ttl_hours=24))
        self.assertEqual(len(calls), 1)  # второй раз сеть не трогаем
        self.assertEqual(status.state, UNAVAILABLE)
        self.assertIn("--update-vuln-db", status.message)
        # --update-vuln-db (refresh) пробует снова, успех снимает отметку
        data = load_with_cache(self.cache, "a.bin", SourceStatus("X"),
                               lambda _m: (b"new", {}), ttl_hours=24, refresh=True)
        self.assertEqual(data, b"new")
        self.assertIsNone(self.cache.recent_failure("a.bin"))

    def test_offline_errors_are_not_remembered(self):
        def offline(_meta):
            raise OfflineError("офлайн")

        load_with_cache(self.cache, "a.bin", SourceStatus("X"), offline, ttl_hours=24)
        self.assertIsNone(self.cache.recent_failure("a.bin"))

    def test_lock_is_exclusive(self):
        with self.cache.lock("a.bin") as first:
            with self.cache.lock("a.bin", wait_seconds=0, sleep=lambda _s: None) as second:
                self.assertTrue(first)
                self.assertFalse(second)
        with self.cache.lock("a.bin") as again:
            self.assertTrue(again)

    @staticmethod
    def _fail(_meta):
        raise CatalogHttpError("нет сети")


if __name__ == "__main__":
    unittest.main(verbosity=2)
