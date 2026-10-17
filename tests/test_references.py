"""Тесты ссылок на документацию (раздел «Подробнее об этой проблеме» в отчёте).

Запуск:  python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webscan.knowledge import KIND_REFERENCES, KNOWLEDGE, T_OK, TYPE_REFERENCES, references_for
from webscan.models import CONFIG, HIGH, VULN, Finding


class ReferencesForTest(unittest.TestCase):
    def test_kind_level_reference_wins_over_type_level(self):
        # ssti — и в KIND_REFERENCES, и его type (T_RCE) есть в TYPE_REFERENCES;
        # должна вернуться более точная, кодовая ссылка.
        refs = references_for("ssti", KNOWLEDGE["ssti"]["type"])
        self.assertEqual(refs, KIND_REFERENCES["ssti"])

    def test_falls_back_to_type_level_reference(self):
        # csp_missing не в KIND_REFERENCES, но его type — T_XSS, который есть в TYPE_REFERENCES.
        self.assertNotIn("csp_missing", KIND_REFERENCES)
        kind_type = KNOWLEDGE["csp_missing"]["type"]
        self.assertEqual(references_for("csp_missing", kind_type), TYPE_REFERENCES[kind_type])

    def test_unknown_type_yields_no_reference(self):
        self.assertEqual(references_for("totally_unknown_kind", "совершенно неизвестный тип"), [])

    def test_no_problem_type_has_no_reference(self):
        self.assertNotIn(T_OK, TYPE_REFERENCES)

    def test_every_catalogued_kind_with_a_type_resolves_to_a_list(self):
        # Ни для одного вида находки со знакомым типом угрозы вызов не должен падать.
        for kind, info in KNOWLEDGE.items():
            refs = references_for(kind, info.get("type", ""))
            self.assertIsInstance(refs, list, kind)

    def test_all_reference_urls_use_https(self):
        for kind, urls in KIND_REFERENCES.items():
            for url in urls:
                self.assertTrue(url.startswith("https://"), f"{kind}: {url}")
        for kind, urls in TYPE_REFERENCES.items():
            for url in urls:
                self.assertTrue(url.startswith("https://"), f"{kind}: {url}")


class FindingAutoFillsReferencesTest(unittest.TestCase):
    def test_heuristic_finding_gets_a_reference_automatically(self):
        finding = Finding(url="https://site.test/", title="t", category=VULN, severity=HIGH,
                          recommendation="fix", kind="ssti")
        self.assertEqual(finding.references, KIND_REFERENCES["ssti"])

    def test_explicit_references_are_not_overwritten(self):
        # Находки с данными каталога (NVD/KEV) уже приходят со своими references —
        # автозаполнение не должно их затирать.
        own_refs = ["https://nvd.nist.gov/vuln/detail/CVE-2099-0001"]
        finding = Finding(url="https://site.test/", title="t", category=VULN, severity=HIGH,
                          recommendation="fix", kind="ssti", references=own_refs)
        self.assertEqual(finding.references, own_refs)

    def test_config_category_finding_without_knowledge_entry_has_no_reference(self):
        finding = Finding(url="https://site.test/", title="t", category=CONFIG, severity=HIGH,
                          recommendation="fix", kind="totally_unknown_kind_xyz")
        self.assertEqual(finding.references, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
