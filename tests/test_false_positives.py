"""Регрессионные тесты на ложные срабатывания.

Запуск:  python -m unittest discover -s tests -v
"""

import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webscan.checks import access_control, exposed, waf_bypass
from webscan.checks.active import (MARKER, Target, _analyze_command_injection, _analyze_redirect,
                                   _analyze_sqli, _analyze_xss, _is_redirect_param)
from webscan.checks.infoleak import check_info_leak
from webscan.checks.sast import check_sast
from webscan.models import CONFIRMED, HIGH, LOW, MEDIUM, Page
from webscan.scanner import ScanConfig, run_scan

from clean_app import create_server


class FakeResponse:
    def __init__(self, status=200, body="", headers=None, history=None, url=""):
        self.status_code = status
        self.content = body if isinstance(body, bytes) else body.encode("utf-8")
        self.text = self.content.decode("utf-8", "replace")
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        self.encoding = "utf-8"
        self.history = history or []
        self.url = url


def make_page(body, content_type="text/html", headers=None):
    headers = headers or {}
    return Page(url="https://site.test/", depth=0, status=200, headers=headers,
                raw_headers=[(k.lower(), v) for k, v in headers.items()], body=body,
                content_type=content_type, requested_url="https://site.test/")


def make_target(method="GET"):
    return Target(method=method, action="https://site.test/p?x=1", params={"x": "1"},
                  param_name="x", page_url="https://site.test/p?x=1", source="URL-параметр",
                  baseline_status=200, baseline_body="<html><body><p>ok</p></body></html>")


ENV_ENTRY = next(entry for entry in exposed.SENSITIVE_PATHS if entry[0] == "/.env")
ZIP_ENTRY = next(entry for entry in exposed.SENSITIVE_PATHS if entry[0] == "/backup.zip")
TEST_DIR_ENTRY = next(entry for entry in exposed.SENSITIVE_PATHS if entry[0] == "/test/")
GITIGNORE_ENTRY = next(entry for entry in exposed.SENSITIVE_PATHS if entry[0] == "/.gitignore")
SOFT_PAGE = "<!DOCTYPE html><html><head><title>App</title></head><body>test dev = PK</body></html>"


class TestExposedPaths(unittest.TestCase):
    def analyze(self, entry, response, baseline=None):
        return exposed._analyze_exposed(entry, "https://site.test" + entry[0], response, baseline)

    def test_html_page_instead_of_env_is_ignored(self):
        self.assertEqual(self.analyze(ENV_ENTRY, FakeResponse(body=SOFT_PAGE)), [])

    def test_html_page_instead_of_archive_is_ignored(self):
        self.assertEqual(self.analyze(ZIP_ENTRY, FakeResponse(body=SOFT_PAGE)), [])

    def test_real_env_is_confirmed(self):
        response = FakeResponse(body="APP_KEY=base64:abc\nDB_PASSWORD=secret\n",
                                headers={"Content-Type": "text/plain"})
        findings = self.analyze(ENV_ENTRY, response)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, CONFIRMED)
        self.assertEqual(findings[0].severity, HIGH)

    def test_archive_is_confirmed_by_signature_only(self):
        zipped = FakeResponse(body=b"PK\x03\x04" + b"\x00" * 40,
                              headers={"Content-Type": "application/zip"})
        self.assertEqual(self.analyze(ZIP_ENTRY, zipped)[0].confidence, CONFIRMED)
        # «PK» где-то в тексте — не архив: не подтверждается и не получает высокий уровень
        text = FakeResponse(body="some PK text", headers={"Content-Type": "text/plain"})
        findings = self.analyze(ZIP_ENTRY, text)
        self.assertTrue(all(f.severity != HIGH and f.confidence != CONFIRMED for f in findings))

    def test_ordinary_page_in_test_directory_is_ignored(self):
        self.assertEqual(self.analyze(TEST_DIR_ENTRY, FakeResponse(body=SOFT_PAGE)), [])

    def test_directory_listing_in_test_directory_is_reported(self):
        listing = FakeResponse(body="<html><title>Index of /test/</title><body>Index of /test/"
                                    "</body></html>")
        self.assertEqual(len(self.analyze(TEST_DIR_ENTRY, listing)), 1)

    def test_plain_gitignore_is_reported_but_html_is_not(self):
        plain = FakeResponse(body="node_modules/\n*.log\n", headers={"Content-Type": "text/plain"})
        self.assertEqual(len(self.analyze(GITIGNORE_ENTRY, plain)), 1)
        self.assertEqual(self.analyze(GITIGNORE_ENTRY, FakeResponse(body=SOFT_PAGE)), [])

    def test_forbidden_everywhere_is_not_a_finding(self):
        baseline = {"status": 403, "peek": "denied", "title": ""}
        self.assertEqual(self.analyze(ENV_ENTRY, FakeResponse(status=403, body="denied"), baseline),
                         [])
        self.assertEqual(len(self.analyze(ENV_ENTRY, FakeResponse(status=403, body="denied"),
                                          {"status": 404, "peek": "", "title": ""})), 1)

    def test_same_title_as_not_found_page_is_soft_404(self):
        baseline = {"status": 200, "peek": "<title>Nothing here</title> aaa", "title": "nothing here"}
        peek = "<html><title>Nothing here</title> different body text that is long enough........"
        self.assertTrue(exposed._looks_like_soft_404(peek, baseline))


class TestOpenRedirect(unittest.TestCase):
    def analyze(self, location):
        response = FakeResponse(status=302, headers={"Location": location})
        return _analyze_redirect(make_target(), response, "https://site.test/go?x=1", None)

    def test_relative_redirect_with_evil_host_in_query_is_not_reported(self):
        self.assertEqual(self.analyze("/login?next=https%3A//evil.com"), [])
        self.assertEqual(self.analyze("https://site.test/login?next=https://evil.com"), [])

    def test_lookalike_host_is_not_reported(self):
        self.assertEqual(self.analyze("https://notevil.com/"), [])

    def test_real_open_redirect_is_reported(self):
        for location in ("https://evil.com", "//evil.com/x", "https://sub.evil.com/"):
            findings = self.analyze(location)
            self.assertEqual(len(findings), 1, location)
            self.assertEqual(findings[0].confidence, CONFIRMED)

    def test_redirect_param_names(self):
        for name in ("url", "redirectTo", "return_path", "next", "dest"):
            self.assertTrue(_is_redirect_param(name), name)
        for name in ("preview", "about", "layout", "page", "outline"):
            self.assertFalse(_is_redirect_param(name), name)


class TestActiveAnalysis(unittest.TestCase):
    def test_json_reflection_is_not_xss(self):
        payload = f"{MARKER}\"'><x-{MARKER}>"
        response = FakeResponse(body='{"echo": "%s"}' % payload,
                                headers={"Content-Type": "application/json"})
        self.assertEqual(_analyze_xss(make_target(), response, "https://site.test/api", None), [])

    def test_html_reflection_is_still_reported(self):
        payload = f"{MARKER}\"'><x-{MARKER}>"
        response = FakeResponse(body=f"<html><body><p>{payload}</p></body></html>")
        findings = _analyze_xss(make_target(), response, "https://site.test/p", None)
        self.assertEqual(findings[0].kind, "xss_unescaped")

    def test_generic_command_not_found_is_ignored(self):
        response = FakeResponse(body="<p>If you see 'command not found' or sh: 1: error, "
                                     "check your PATH.</p>")
        self.assertEqual(
            _analyze_command_injection(make_target(), response, "https://site.test/p", None), [])

    def test_shell_error_naming_our_command_is_reported(self):
        response = FakeResponse(body="sh: 1: BAUMANCMD: not found")
        findings = _analyze_command_injection(make_target(), response, "https://site.test/p", None)
        self.assertEqual(findings[0].kind, "command_injection")

    def test_orm_class_name_in_prose_is_not_sql_error(self):
        response = FakeResponse(body="<html><p>Catch OperationalError and ProgrammingError in "
                                     "Python; sqlite unrecognized token explained.</p></html>")
        target = make_target()
        target.baseline_body = response.text
        self.assertEqual(_analyze_sqli(target, response, "https://site.test/p", None, "'"), [])

    def test_redirect_to_another_page_is_not_structure_change(self):
        other = FakeResponse(body="<html><body>" + "<div><p>x</p></div>" * 30 + "</body></html>",
                             history=[FakeResponse(status=302)])
        self.assertEqual(_analyze_sqli(make_target(), other, "https://site.test/p", None, "'"), [])


class TestWafBypass(unittest.TestCase):
    def test_escaped_marker_next_to_script_tag_is_not_bypass(self):
        body = ("<html><head><script src=\"/a.js\"></script></head><body><p>You searched: "
                f"&lt;script&gt;alert(&#39;{MARKER}&#39;)&lt;/script&gt;</p></body></html>")
        self.assertIsNone(waf_bypass.EXECUTABLE_REFLECTION.search(body))
        plain_marker = f"<html><head><script></script><title>{MARKER}</title></head></html>"
        self.assertIsNone(waf_bypass.EXECUTABLE_REFLECTION.search(plain_marker))

    def test_raw_reflection_is_executable(self):
        for body in (f"<p><ScRiPt>alert('{MARKER}')</ScRiPt></p>",
                     f"<img src=x onerror=alert('{MARKER}')>",
                     f"<svg/onload=alert('{MARKER}')>"):
            self.assertIsNotNone(waf_bypass.EXECUTABLE_REFLECTION.search(body), body)

    def test_ordinary_security_words_are_not_a_block_page(self):
        text = "Our security team and firewall protect your data. Forbidden fruit recipes."
        self.assertIsNone(waf_bypass.BLOCK_PAGE.search(text))
        self.assertIsNotNone(waf_bypass.BLOCK_PAGE.search("Request blocked by firewall"))


class _ScriptedClient:
    """Клиент, отвечающий по таблице; считает, что бюджета запросов хватает."""

    def __init__(self, routes):
        self.routes = routes

    def can_request(self, reserve=0):
        return True

    def get(self, url, headers=None, **_kwargs):
        key = (url.split("://", 1)[-1].split("/", 1)[-1], tuple(sorted((headers or {}).items())))
        return self.routes.get(key) or self.routes.get(key[0]) or FakeResponse(404, "nf")

    request = None


class TestAccessControl(unittest.TestCase):
    def test_header_bypass_requires_change_against_plain_request(self):
        home = FakeResponse(body="<html><nav><a href=/admin>Admin</a> dashboard users</nav></html>")
        client = _ScriptedClient({"admin": FakeResponse(403, "denied"), "": home})
        client.request = lambda method, url, headers=None, **kw: home
        self.assertEqual(access_control._probe_forbidden_bypass(client, "https://site.test/", 0),
                         [])

    def test_spa_api_paths_and_login_redirects_are_not_reported(self):
        spa = FakeResponse(body="<html><div id=app>user email profile</div></html>")
        redirect = FakeResponse(302, "", headers={"Location": "/login"})
        client = _ScriptedClient({"api/user/1": spa, "api/users/1": spa, "api/admin": spa,
                                  "api/v1/users": spa, "admin": redirect, "admin/": redirect,
                                  "dashboard": redirect, "account": redirect})
        self.assertEqual(access_control._probe_sensitive_paths(client, "https://site.test/", 0), [])

    def test_html_page_without_markers_is_ignored_and_markers_are_not_high(self):
        public = FakeResponse(body="<html><h1>My account benefits</h1><p>Sign up today</p></html>")
        client = _ScriptedClient({"account": public})
        findings = access_control._probe_sensitive_paths(client, "https://site.test/", 0)
        self.assertTrue(all(f.severity in (LOW, MEDIUM) for f in findings))
        self.assertTrue(all(f.confidence != CONFIRMED for f in findings))


class TestStaticRules(unittest.TestCase):
    def kinds(self, body, ctype="text/html"):
        return [f.kind for f in check_sast(make_page(body, ctype))]

    def test_prose_and_code_samples_are_not_findings(self):
        body = ("<html><body><p>Update your profile + settings, select a country + city.</p>"
                "<pre><code>eval(userInput); el.innerHTML = x;</code></pre></body></html>")
        self.assertEqual(self.kinds(body), [])

    def test_literal_html_assignment_is_not_a_finding(self):
        body = "<html><script>box.innerHTML = '<b>x</b>'; document.write('<p>hi</p>');</script></html>"
        self.assertNotIn("sast_innerhtml", self.kinds(body))

    def test_dangerous_code_is_still_found_in_scripts(self):
        body = ("<html><script>el.innerHTML = userValue; eval(code);"
                "db.query('SELECT * FROM t WHERE id=' + id);</script></html>")
        kinds = self.kinds(body)
        for expected in ("sast_innerhtml", "sast_eval", "sast_sql_concat"):
            self.assertIn(expected, kinds)

    def test_eval_is_no_longer_confirmed_high(self):
        finding = check_sast(make_page("<html><script>eval(code)</script></html>"))[0]
        self.assertNotEqual(finding.severity, HIGH)
        self.assertNotEqual(finding.confidence, CONFIRMED)

    def test_site_urls_are_not_filesystem_paths(self):
        body = ("<script src=\"/app/static/main.js\"></script><img src='/www/pic.png'>"
                "<a href=\"/app/static/pic.png\">x</a><p>/www/assets/site.js</p>")
        kinds = [f.kind for f in check_info_leak(make_page(body))]
        self.assertNotIn("absolute_paths", kinds)

    def test_real_filesystem_path_is_still_reported(self):
        body = "<pre>Fatal error in /var/www/shop/app.php on line 3</pre>"
        kinds = [f.kind for f in check_info_leak(make_page(body))]
        self.assertIn("absolute_paths", kinds)

    def test_cdn_server_name_and_via_protocol_are_not_version_leaks(self):
        headers = {"Server": "cloudflare", "Via": "1.1 vegur"}
        findings = [f for f in check_info_leak(make_page("<p>x</p>", headers=headers))
                    if f.kind == "version_header"]
        self.assertTrue(all(f.severity == LOW and "версию" not in f.title for f in findings))
        self.assertFalse(any("server" in f.title for f in findings))

    def test_public_google_key_is_informational(self):
        key = "AIza" + "S" * 35
        found = [f for f in check_info_leak(make_page(f"<script>var k='{key}';</script>"))
                 if f.kind == "secret_in_code"]
        self.assertEqual([f.severity for f in found], ["Info"])


VULNERABILITY_KINDS = ("exposed_", "bac_", "open_redirect", "xss_", "sqli_", "nosqli_", "waf_",
                       "sast_", "command_injection", "lfi_", "ssti", "crlf_", "dom_xss",
                       "secret_in_code", "absolute_paths", "stack_trace")
# Допустимый информационный шум на чистом стенде (не выше «Низкий»/«Инфо»).
TOLERATED = {"xss_escaped", "bac_idor", "bac_login_exposed"}


class TestCleanApplication(unittest.TestCase):
    """Полный прогон по безопасному приложению: серьёзных находок быть не должно."""

    @classmethod
    def setUpClass(cls):
        cls.server = create_server(0)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.result = run_scan(ScanConfig(url=f"http://127.0.0.1:{cls.port}", use_vuln_db=False))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_no_vulnerability_findings_above_low(self):
        noisy = [(f.severity, f.confidence, f.kind, f.title) for f in self.result.findings
                 if f.kind.startswith(VULNERABILITY_KINDS)
                 and (f.kind not in TOLERATED or f.severity in (HIGH, MEDIUM))]
        self.assertEqual(noisy, [])

    def test_scan_actually_ran_the_checks(self):
        self.assertGreaterEqual(self.result.stats["pages"], 3)
        self.assertGreater(self.result.stats["active_tests"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
