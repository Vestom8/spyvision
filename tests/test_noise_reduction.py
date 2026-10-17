"""Тесты снижения шума: политика уверенности, дедупликация, заголовки, NVD, контрольные пробы.

Запуск:  python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webscan.checks.active import _confirm_sqli, _structure_changed
from webscan.checks.headers import check_headers
from webscan.dedup import drop_superseded
from webscan.fingerprint import DetectedProduct, detect_distro
from webscan.models import (CONFIG, CONFIRMED, HIGH, MEDIUM, SUSPECTED, VULN, Finding,
                            FindingList, Page, apply_confidence_policy)
from webscan.vulndb.nvd import NvdClient, _best_match, _condense
from webscan.vulndb.scoring import VulnMatch, component_finding, score_match
from webscan.vulndb.versions import PLATFORM, PRODUCT_ONLY

from test_false_positives import FakeResponse, make_target


def finding(kind, severity=MEDIUM, confidence=SUSPECTED, url="https://site.test/", title=None):
    return Finding(url=url, title=title or f"{kind} title", category=VULN, severity=severity,
                   recommendation="fix", kind=kind, confidence=confidence)


class TestConfidencePolicy(unittest.TestCase):
    def test_unconfirmed_high_is_lowered_to_medium(self):
        items = FindingList()
        items.add(finding("secret_in_code", HIGH))
        items.add(finding("waf_bypass_xss", HIGH, url="https://site.test/a"))
        self.assertEqual(apply_confidence_policy(items), 2)
        self.assertTrue(all(item.severity == MEDIUM for item in items))

    def test_probe_verified_and_catalog_findings_keep_high(self):
        items = FindingList()
        for kind in ("sqli_error", "xss_unescaped", "command_injection", "known_cve"):
            items.add(finding(kind, HIGH, url=f"https://site.test/{kind}"))
        items.add(finding("ssti", HIGH, CONFIRMED, url="https://site.test/ssti"))
        self.assertEqual(apply_confidence_policy(items), 0)
        self.assertTrue(all(item.severity == HIGH for item in items))


class TestSemanticDedup(unittest.TestCase):
    def kinds(self, items):
        return sorted(item.kind for item in items)

    def test_generic_secret_rule_is_dropped_when_pattern_search_found_it(self):
        items = FindingList()
        items.add(finding("sast_hardcoded_secret", HIGH))
        items.add(finding("secret_in_code", HIGH, title="Утечка: Присвоение секрета в коде"))
        self.assertEqual(drop_superseded(items), 1)
        self.assertEqual(self.kinds(items), ["secret_in_code"])

    def test_same_fact_on_other_page_is_kept(self):
        items = FindingList()
        items.add(finding("sast_hardcoded_secret", HIGH, url="https://site.test/a"))
        items.add(finding("secret_in_code", HIGH, url="https://site.test/b"))
        self.assertEqual(drop_superseded(items), 0)

    def test_only_matching_secret_label_is_replaced(self):
        items = FindingList()
        items.add(finding("sast_aws_key", HIGH, CONFIRMED))
        items.add(finding("secret_in_code", HIGH, title="Утечка: AWS Access Key ID"))
        items.add(finding("secret_in_code", HIGH, title="Утечка: JWT-токен"))
        drop_superseded(items)
        self.assertEqual(sorted(item.title for item in items if item.kind == "secret_in_code"),
                         ["Утечка: JWT-токен"])
        self.assertIn("sast_aws_key", self.kinds(items))

    def test_specific_client_side_findings_replace_generic_sast(self):
        items = FindingList()
        for kind in ("sast_innerhtml", "dom_xss_sink", "sast_postmessage_open",
                     "postmessage_no_origin", "sast_sourcemap", "source_maps"):
            items.add(finding(kind))
        drop_superseded(items)
        self.assertEqual(self.kinds(items), ["dom_xss_sink", "postmessage_no_origin", "source_maps"])


def doc_page(headers=None, content_type="text/html", status=200):
    headers = headers or {}
    return Page(url="https://site.test/", depth=0, status=status, headers=headers,
                raw_headers=[(k.lower(), v) for k, v in headers.items()], body="<html></html>",
                content_type=content_type, requested_url="https://site.test/")


class TestHeaderNoise(unittest.TestCase):
    DOCUMENT_KINDS = {"csp_missing", "xfo_missing", "referrer_missing", "permissions_missing",
                      "coop_missing", "corp_missing"}

    def kinds(self, page):
        return {item.kind for item in check_headers(page)}

    def test_json_and_redirect_responses_get_no_document_header_findings(self):
        self.assertFalse(self.kinds(doc_page(content_type="application/json")) & self.DOCUMENT_KINDS)
        self.assertFalse(self.kinds(doc_page(status=302)) & self.DOCUMENT_KINDS)
        self.assertFalse(self.kinds(doc_page(status=404)) & self.DOCUMENT_KINDS)

    def test_html_page_still_gets_them(self):
        self.assertTrue(self.DOCUMENT_KINDS <= self.kinds(doc_page()))

    def test_nosniff_is_still_required_for_non_documents(self):
        self.assertIn("xcto_missing", self.kinds(doc_page(content_type="application/json")))

    def test_clickjacking_is_reported_once(self):
        page = doc_page({"Content-Security-Policy": "default-src 'self'"})
        kinds = self.kinds(page)
        self.assertIn("xfo_missing", kinds)
        self.assertNotIn("csp_no_frame_ancestors", kinds)


def nvd_cve(config_operator="OR", nodes=1, description="Overflow in Foo.", tags=()):
    entry = {"vulnerable": True, "criteria": "cpe:2.3:a:acme:foo:*:*:*:*:*:*:*:*",
             "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}
    os_entry = {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}
    node_list = [{"operator": "OR", "negate": False, "cpeMatch": [entry]}]
    if nodes > 1:
        node_list.append({"operator": "OR", "negate": False, "cpeMatch": [os_entry]})
    return {"id": "CVE-2024-0001", "vulnStatus": "Analyzed", "cveTags": list(tags),
            "descriptions": [{"lang": "en", "value": description}],
            "configurations": [{"operator": config_operator, "nodes": node_list}]}


class TestNvdFiltering(unittest.TestCase):
    def test_disputed_cve_is_excluded(self):
        self.assertIsNone(_condense(nvd_cve(description="** DISPUTED ** A bug in Foo."), "acme", "foo"))
        self.assertIsNone(_condense(nvd_cve(tags=["disputed"]), "acme", "foo"))
        self.assertIsNotNone(_condense(nvd_cve(), "acme", "foo"))

    def test_and_configuration_gives_platform_dependent_match(self):
        plain = _condense(nvd_cve(), "acme", "foo")
        self.assertEqual(_best_match("1.5", plain["matches"]), "range")
        conditional = _condense(nvd_cve("AND", nodes=2), "acme", "foo")
        self.assertEqual(_best_match("1.5", conditional["matches"]), PLATFORM)
        self.assertIsNone(_best_match("2.5", conditional["matches"]))

    def _client(self, include_product_only=False):
        http = SimpleNamespace(sleep=lambda _s: None, requests_made=0)
        client = NvdClient(None, http, ttl_hours=1, include_product_only=include_product_only)
        client._candidate_pairs = lambda product: [("acme", "foo")]
        unversioned = {"id": "CVE-2024-0002", "matches": [{"v": "*", "si": "", "se": "", "ei": "",
                                                           "ee": "", "p": 0}]}
        ranged = {"id": "CVE-2024-0003", "matches": [{"v": "*", "si": "1.0", "se": "", "ei": "",
                                                      "ee": "2.0", "p": 0}]}
        client.product_cves = lambda vendor, name: [unversioned, ranged]
        return client

    def test_unversioned_cves_are_hidden_and_counted_by_default(self):
        client = self._client()
        product = DetectedProduct("acme", "foo", "1.5", label="Foo")
        cves, _pairs = client.match_product(product)
        self.assertEqual([item["id"] for item in cves], ["CVE-2024-0003"])
        self.assertEqual(client.skipped_product_only, {"Foo 1.5": 1})

    def test_unversioned_cves_can_be_enabled(self):
        client = self._client(include_product_only=True)
        cves, _pairs = client.match_product(DetectedProduct("acme", "foo", "1.5", label="Foo"))
        self.assertEqual({item["id"]: item["version_match"] for item in cves},
                         {"CVE-2024-0002": PRODUCT_ONLY, "CVE-2024-0003": "range"})


def vuln(component, cve="CVE-2024-0001", score=9.8, match="range", kev=None):
    item = VulnMatch(cve, component, cvss={"score": score, "version": "3.1"}, version_match=match,
                     kev=kev)
    item.priority_score, item.priority_label = score_match(item)
    return item


class TestDistroBackports(unittest.TestCase):
    def test_distro_detection(self):
        self.assertEqual(detect_distro("Apache/2.4.6 (CentOS)"), "CentOS")
        self.assertEqual(detect_distro("Apache/2.4.52 (Ubuntu)"), "Ubuntu")
        self.assertEqual(detect_distro("nginx/1.18.0 (Ubuntu)"), "Ubuntu")
        self.assertEqual(detect_distro("Apache/2.4.6 (Red Hat Enterprise Linux)"), "Red Hat")
        self.assertEqual(detect_distro("Apache/2.4.49 (Unix)"), "")
        self.assertEqual(detect_distro("nginx/1.25.3"), "")

    def test_distro_lowers_priority_but_not_for_kev(self):
        plain = DetectedProduct("apache", "http_server", "2.4.6", label="Apache")
        patched = DetectedProduct("apache", "http_server", "2.4.6", label="Apache", distro="CentOS")
        self.assertLess(vuln(patched).priority_score, vuln(plain).priority_score)
        kev = {"vulnerabilityName": "x"}
        self.assertEqual(vuln(patched, kev=kev).priority_score, vuln(plain, kev=kev).priority_score)

    def test_distro_banner_caps_severity_without_kev(self):
        patched = DetectedProduct("apache", "http_server", "2.4.6", label="Apache", distro="CentOS")
        plain = DetectedProduct("apache", "http_server", "2.4.6", label="Apache")
        self.assertEqual(component_finding(plain, [vuln(plain)], "t").severity, HIGH)
        capped = component_finding(patched, [vuln(patched)], "t")
        self.assertEqual(capped.severity, MEDIUM)
        self.assertIn("CentOS", capped.evidence)
        self.assertEqual(component_finding(patched, [vuln(patched, kev={"x": "y"})], "t").severity,
                         HIGH)

    def test_platform_dependent_cve_does_not_raise_severity(self):
        product = DetectedProduct("acme", "foo", "1.5", label="Foo")
        weak = component_finding(product, [vuln(product, match=PLATFORM)], "t")
        self.assertEqual(weak.severity, MEDIUM)
        self.assertLess(vuln(product, match=PLATFORM).priority_score, vuln(product).priority_score)


class _ScriptedClient:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.sent = []

    def request(self, method, url, data=None, **_kwargs):
        self.sent.append(url)
        return self.responses.pop(0) if self.responses else None


BASE = "<html><body><p>ok</p></body></html>"
BROKEN = "<html><body>" + "<div><p>x</p></div>" * 30 + "</body></html>"


class TestSqliConfirmation(unittest.TestCase):
    def target(self):
        target = make_target()
        target.baseline_body = BASE
        return target

    def weak(self, kind):
        return finding(kind)

    def test_status_kept_when_paired_quote_is_harmless(self):
        client = _ScriptedClient(FakeResponse(200, BASE))
        self.assertTrue(_confirm_sqli(client, self.weak("sqli_status"), self.target(), "'", 0))
        self.assertIn("%27%27", client.sent[0])

    def test_status_dropped_when_paired_quote_also_breaks(self):
        client = _ScriptedClient(FakeResponse(500, "error"))
        self.assertFalse(_confirm_sqli(client, self.weak("sqli_status"), self.target(), "'", 0))

    def test_structure_dropped_when_paired_quote_also_changes_page(self):
        client = _ScriptedClient(FakeResponse(200, BROKEN))
        self.assertFalse(_confirm_sqli(client, self.weak("sqli_structure"), self.target(), "'", 0))

    def test_structure_kept_only_when_reproducible(self):
        reproducible = _ScriptedClient(FakeResponse(200, BASE), FakeResponse(200, BROKEN))
        self.assertTrue(_confirm_sqli(reproducible, self.weak("sqli_structure"), self.target(),
                                      "'", 0))
        random_change = _ScriptedClient(FakeResponse(200, BASE), FakeResponse(200, BASE))
        self.assertFalse(_confirm_sqli(random_change, self.weak("sqli_structure"), self.target(),
                                       "'", 0))

    def test_unverifiable_cases_keep_the_finding(self):
        self.assertTrue(_confirm_sqli(_ScriptedClient(), self.weak("sqli_status"), self.target(),
                                      "'", 0))
        client = _ScriptedClient()
        self.assertTrue(_confirm_sqli(client, self.weak("sqli_status"), self.target(),
                                      "' OR 'x'='x", 0))
        self.assertEqual(client.sent, [])

    def test_helper_sanity(self):
        self.assertTrue(_structure_changed(BASE, BROKEN))


if __name__ == "__main__":
    unittest.main(verbosity=2)
