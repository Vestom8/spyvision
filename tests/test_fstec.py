"""Оценка уровня критичности по методике ФСТЭК: формула, пороги, допущения, интеграция."""

import json
import tempfile
import unittest

from test_vulndb import TARGET, catalog_session, target_page
from webscan.models import FindingList
from webscan.report import build_report
from webscan.report_vulns import audit_columns, audit_rows, collect_vulns
from webscan.vulndb import VulnDbConfig, enrich_with_catalogs
import re
from datetime import date

from webscan.vulndb.fstec import (FstecContext, assess, consequence_of, deadline_for,
                                  detect_perimeter, level_for, normalise_component_type,
                                  pick_cvss)


def internet_server(share=1.0):
    return FstecContext(component_type="server", internet_facing=True, vulnerable_share=share)


class TestThresholds(unittest.TestCase):
    def test_level_boundaries(self):
        cases = [(10, "Критический"), (8.01, "Критический"), (8.0, "Высокий"), (5.0, "Высокий"),
                 (4.99, "Средний"), (2.0, "Средний"), (1.99, "Низкий"), (0, "Низкий")]
        for value, level in cases:
            self.assertEqual(level_for(value), level, value)


class TestFormula(unittest.TestCase):
    def test_context_components(self):
        context = internet_server(1.0)
        # Iinfr = 0,5·0,7 + 0,2·1,0 + 0,3·1,1
        self.assertAlmostEqual(context.iinfr, 0.88)
        self.assertAlmostEqual(FstecContext(internet_facing=False, vulnerable_share=1.0).iinfr, 0.73)
        self.assertAlmostEqual(FstecContext(component_type="firewall").k, 0.9)
        shares = {0.9: 1.0, 0.71: 1.0, 0.7: 0.8, 0.5: 0.8, 0.49: 0.6, 0.1: 0.6, 0.09: 0.5, 0.0: 0.5}
        for share, expected in shares.items():
            self.assertEqual(FstecContext(vulnerable_share=share).l, expected, share)

    def test_exploited_rce_is_critical(self):
        result = assess(nvd_cvss={"score": 9.8, "version": "3.1"}, attacked=True,
                        text="remote code execution", context=internet_server())
        # V = 9,8 × 0,88 × (0,6 + 0,5)
        self.assertAlmostEqual(result["v"], 9.49, places=2)
        self.assertEqual(result["level"], "Критический")
        self.assertEqual(result["iat"], 0.6)
        self.assertEqual(result["iimp"], 0.5)
        self.assertEqual(result["notes"], [])

    def test_same_flaw_without_exploit_is_high(self):
        result = assess(nvd_cvss={"score": 9.8, "version": "3.1"}, text="remote code execution",
                        context=internet_server())
        self.assertAlmostEqual(result["v"], 5.17, places=2)   # 9,8 × 0,88 × (0,1 + 0,5)
        self.assertEqual(result["level"], "Высокий")

    def test_internal_resource_lowers_the_level(self):
        public = assess(nvd_cvss={"score": 8.0}, exploit_known=True, text="arbitrary code execution",
                        context=internet_server())
        internal = assess(nvd_cvss={"score": 8.0}, exploit_known=True,
                          text="arbitrary code execution",
                          context=FstecContext(internet_facing=False, vulnerable_share=1.0))
        self.assertGreater(public["v"], internal["v"])
        self.assertAlmostEqual(internal["v"], 8.0 * 0.73 * (0.3 + 0.5), places=2)

    def test_xss_with_no_exploit_is_low(self):
        result = assess(nvd_cvss={"score": 4.3, "version": "3.1"}, text="cross-site scripting (XSS)",
                        context=internet_server())
        self.assertEqual(result["level"], "Низкий")   # 4,3 × 0,88 × 0,2 = 0,76

    def test_unknown_consequence_is_a_lower_bound(self):
        result = assess(nvd_cvss={"score": 7.0}, text="некое описание", context=internet_server())
        self.assertEqual(result["iimp"], 0.0)
        self.assertTrue(any("нижняя граница" in note for note in result["notes"]))

    def test_no_cvss_means_no_assessment(self):
        self.assertIsNone(assess(text="remote code execution", attacked=True))


class TestDeadlines(unittest.TestCase):
    def test_deadline_per_level(self):
        start = date(2026, 10, 10)
        expected = {
            "Критический": ("до 24 часов", 1, "2026-10-11"),
            "Высокий": ("до 7 дней", 7, "2026-10-17"),
            "Средний": ("до 4 недель", 28, "2026-11-07"),
            "Низкий": ("до 4 месяцев", 120, "2027-02-07"),
        }
        for level, (label, days, due) in expected.items():
            result = deadline_for(level, start)
            self.assertEqual((result["deadline"], result["deadline_days"], result["due"]),
                             (label, days, due), level)

    def test_assessment_carries_the_deadline(self):
        context = FstecContext(internet_facing=True, vulnerable_share=1.0,
                               scan_date=date(2026, 10, 10))
        critical = assess(nvd_cvss={"score": 9.8}, attacked=True, text="remote code execution",
                          context=context)
        self.assertEqual((critical["level"], critical["deadline"], critical["due"]),
                         ("Критический", "до 24 часов", "2026-10-11"))
        low = assess(nvd_cvss={"score": 4.3}, text="cross-site scripting", context=context)
        self.assertEqual((low["level"], low["deadline"], low["due"]),
                         ("Низкий", "до 4 месяцев", "2027-02-07"))

    def test_default_start_is_today(self):
        self.assertEqual(deadline_for("Высокий")["due"],
                         date.fromordinal(date.today().toordinal() + 7).isoformat())

    def test_unknown_level_gets_the_longest_deadline(self):
        self.assertEqual(deadline_for("")["deadline"], "до 4 месяцев")


class TestInputs(unittest.TestCase):
    def test_cvss_preference(self):
        # БДУ 3.x важнее NVD; CVSS 2.0 из БДУ — только если больше ничего нет
        self.assertEqual(pick_cvss({"3.0": 8.1, "2.0": 9.3}, {"score": 9.8, "version": "3.1"}),
                         (8.1, "3.0", "БДУ"))
        self.assertEqual(pick_cvss({"3.0": 8.1, "3.1": 8.2}, None), (8.2, "3.1", "БДУ"))
        self.assertEqual(pick_cvss({"2.0": 9.3}, {"score": 9.8, "version": "3.1"}),
                         (9.8, "3.1", "NVD"))
        self.assertEqual(pick_cvss({"2.0": 9.3}, None), (9.3, "2.0", "БДУ"))
        self.assertIsNone(pick_cvss({}, None))
        old = assess(bdu_scores={"2.0": 9.3}, context=internet_server())
        self.assertTrue(any("CVSS 2.0" in note for note in old["notes"]))

    def test_consequences_take_the_maximum(self):
        self.assertEqual(consequence_of("позволяющая вызвать отказ в обслуживании или "
                                        "выполнить произвольный код")[0], 0.5)
        self.assertEqual(consequence_of("cross-site scripting and denial of service")[0], 0.26)
        self.assertEqual(consequence_of("Directory traversal")[0], 0.18)
        self.assertEqual(consequence_of("")[0], 0.0)

    def test_cwe_is_used_when_text_is_silent(self):
        self.assertEqual(consequence_of("описание без последствий", ["CWE-79"])[0], 0.1)
        self.assertEqual(consequence_of("", ["cwe-416", "CWE-79"])[0], 0.5)
        self.assertEqual(consequence_of("", ["CWE-999999"])[0], 0.0)

    def test_perimeter_detection(self):
        internal = ["http://127.0.0.1:8099", "http://192.168.1.5/", "10.0.0.7", "http://localhost",
                    "https://portal.corp.local", "http://intranet", "https://[::1]:8443/"]
        public = ["https://example.com", "http://93.184.216.34/", "shop.example.ru"]
        for target in internal:
            self.assertEqual(detect_perimeter(target), (False, "auto"), target)
        for target in public:
            self.assertEqual(detect_perimeter(target), (True, "auto"), target)
        self.assertEqual(detect_perimeter("http://127.0.0.1", "internet"), (True, "internet"))
        self.assertEqual(detect_perimeter("https://example.com", "internal"), (False, "internal"))

    def test_component_type_is_validated(self):
        self.assertEqual(normalise_component_type("Firewall"), "firewall")
        self.assertEqual(normalise_component_type("что-то"), "server")


class TestInCorrelation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, **kwargs):
        cfg = VulnDbConfig(cache_dir=self.tmp.name, session=catalog_session(),
                           sleep=lambda _s: None, use_bdu=False, **kwargs)
        return enrich_with_catalogs([target_page()], cfg)

    def test_every_match_with_cvss_gets_an_assessment(self):
        result = self._run()
        by_cve = {m.cve_id: m for m in result.matches}
        self.assertEqual(by_cve["CVE-2021-41773"].fstec["level"], "Критический")
        self.assertEqual(by_cve["CVE-2021-41773"].fstec["iat"], 0.6)      # KEV
        self.assertEqual(by_cve["CVE-2021-44224"].fstec["level"], "Средний")
        self.assertTrue(all(m.fstec is not None for m in result.matches))

    def test_context_is_reported(self):
        context = self._run().as_context()["fstec"]
        self.assertEqual(context["component_type"], "server")
        self.assertEqual(context["perimeter_source"], "auto")
        self.assertTrue(context["internet_facing"])   # shop.example.test — публичное имя
        self.assertEqual(context["vulnerable_share"], 0.5)   # Apache с CVE, PHP без

    def test_settings_change_the_result(self):
        base = {m.cve_id: m.fstec["v"] for m in self._run().matches}
        internal = {m.cve_id: m.fstec["v"]
                    for m in self._run(fstec_perimeter="internal").matches}
        firewall = {m.cve_id: m.fstec["v"]
                    for m in self._run(fstec_component_type="firewall").matches}
        for cve, value in base.items():
            self.assertLess(internal[cve], value)
            self.assertGreater(firewall[cve], value)

    def test_order_is_reliable_matches_then_v_then_priority(self):
        result = self._run()
        finding = next(f for f in result.findings if f.kind == "known_cve_kev")
        order = [row["cve"] for row in finding.vuln_matches if "cve" in row]
        self.assertEqual(order[0], "CVE-2021-41773")     # V равны, выше прежний приоритет
        self.assertEqual(order[-1], "CVE-2021-44224")
        values = [row["fstec_score"] for row in finding.vuln_matches if "cve" in row]
        self.assertEqual(values, sorted(values, reverse=True))   # V не возрастает
        self.assertIn("ФСТЭК Критический", finding.evidence)

    def test_finding_has_deadline_step_with_compensating_measures(self):
        finding = next(f for f in self._run().findings if f.kind == "known_cve_kev")
        step = next(s for s in finding.fix_steps if s.startswith("Срок устранения по методике ФСТЭК"))
        self.assertRegex(step, r"до 24 часов \(до \d{4}-\d{2}-\d{2}\)")
        self.assertIn("«Критический»", step)
        self.assertIn("компенсирующие меры", step)
        # срок идёт до шага «Обновите …», чтобы читался как требование к нему
        titles = [i for i, s in enumerate(finding.fix_steps)
                  if s.startswith("Срок устранения") or s.startswith("Обновите")]
        self.assertEqual(titles, sorted(titles))

    def test_report_and_csv(self):
        result = self._run()
        findings = FindingList()
        findings.extend(result.findings)
        stats = {"target": TARGET, "pages": 1, "max_pages": 60, "requests_made": 5,
                 "max_requests": 600, "notes": result.notes, "duration": 1.0,
                 "vulnerability_intelligence": result.as_context()}
        html_text = build_report(findings, stats)
        self.assertIn("<th>ФСТЭК</th>", html_text)
        self.assertIn("Уровень по методике ФСТЭК", html_text)
        self.assertIn("V = Icvss", html_text)
        self.assertRegex(html_text, r"срок: до 24 часов \(до \d{2}\.\d{2}\.\d{4}\)")
        self.assertIn("Рекомендуемые сроки устранения по уровню", html_text)
        vulns, _more = collect_vulns(result.findings)
        columns = audit_columns(vulns)
        self.assertEqual(columns[-3:], ["Уровень по ФСТЭК", "V (ФСТЭК)", "Срок устранения (ФСТЭК)"])
        rows = audit_rows(vulns)
        self.assertTrue(all(len(row) == len(columns) for row in rows))
        row = next(r for r in rows if r[0] == "CVE-2021-41773")
        self.assertEqual(row[-3], "Критический")
        self.assertEqual(float(row[-2]), 9.06)
        self.assertRegex(row[-1], r"^до 24 часов \(до \d{2}\.\d{2}\.\d{4}\)$")
        data = json.loads(html_text[html_text.index('id="vuln-data">') + len('id="vuln-data">'):
                                    html_text.index("</script>", html_text.index('id="vuln-data">'))])
        self.assertEqual(data["columns"], columns)


if __name__ == "__main__":
    unittest.main()
