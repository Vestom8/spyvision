"""Защита самого сканера: локальный интерфейс, редиректы, медленные ответы."""

from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest

import requests

from vulndb_fakes import FakeResponse, FakeSession
from webscan.http_client import _block_internal_redirect, _is_internal_host
from webscan.ui_server import UiState, make_handler
from webscan.vulndb.catalog_http import CatalogHttpClient, CatalogHttpError


class TestUiServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        (root / "secret.txt").write_text("secret", encoding="utf-8")
        (root / "report.html").write_text("<html>report</html>", encoding="utf-8")
        handler = make_handler(root, {"output": "report.html"}, UiState())
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, method, path, headers=None, body=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, response, data

    def test_only_interface_files_are_served(self):
        self.assertEqual(self.request("GET", "/report.html")[0], 200)
        self.assertEqual(self.request("GET", "/")[0], 200)
        for path in ("/secret.txt", "/.git/config", "/../secret.txt", "/%2e%2e/secret.txt"):
            self.assertEqual(self.request("GET", path)[0], 404, path)

    def test_foreign_host_is_rejected(self):
        self.assertEqual(self.request("GET", "/api/status", {"Host": "evil.example"})[0], 403)
        self.assertEqual(self.request("GET", "/api/status", {"Host": f"localhost:{self.port}"})[0], 200)

    def test_post_requires_json_and_same_origin(self):
        body = '{"url": ""}'
        json_headers = {"Content-Type": "application/json"}
        self.assertEqual(self.request("POST", "/api/scan", {**json_headers, "Origin": "http://evil.example"},
                                      body)[0], 403)
        self.assertEqual(self.request("POST", "/api/scan", {"Content-Type": "text/plain"}, body)[0], 415)
        # свой Origin и JSON доходят до обработчика (пустой адрес → 400)
        own = {**json_headers, "Origin": f"http://127.0.0.1:{self.port}"}
        self.assertEqual(self.request("POST", "/api/scan", own, body)[0], 400)

    def test_security_headers_and_bad_content_length(self):
        _status, response, _data = self.request("GET", "/api/status")
        self.assertEqual(response.getheader("X-Content-Type-Options"), "nosniff")
        status, _r, _d = self.request("POST", "/api/scan",
                                      {"Content-Type": "application/json", "Content-Length": "abc"}, None)
        self.assertEqual(status, 400)

    def test_status_reports_whether_active_checks_are_enabled(self):
        import json as _json
        status, _response, data = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        # Хэндлер этого класса создан без "active" в defaults — поведение по умолчанию: включено.
        self.assertTrue(_json.loads(data)["active"])

    def test_pentest_without_consent_is_rejected(self):
        own = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.port}"}
        body = '{"url": "http://example.com", "pentest": true}'
        status, _r, data = self.request("POST", "/api/scan", own, body)
        self.assertEqual(status, 400)
        self.assertIn("разрешение", data.decode("utf-8"))

    def test_pentest_consent_without_pentest_flag_is_a_normal_scan(self):
        # Галочка согласия без включённого переключателя ничего не даёт сама по себе —
        # и не должна отклоняться как «нет согласия» (pentest вообще не запрашивался).
        own = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.port}"}
        body = '{"url": "", "pentest_consent": true}'
        status, _r, data = self.request("POST", "/api/scan", own, body)
        # Отклонено по пустому URL (400), а не по отсутствию pentest-согласия.
        self.assertEqual(status, 400)
        self.assertIn("адрес", data.decode("utf-8"))


class TestUiServerReportOutsideWorkdir(unittest.TestCase):
    """--output за пределами workdir: /report.html должен отдавать именно этот файл."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.report_tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.report_path = Path(cls.report_tmp.name) / "report.html"
        cls.report_path.write_text("<html>свежий отчёт</html>", encoding="utf-8")
        # Одноимённый файл прямо в workdir — должен быть ПРОИГНОРИРОВАН: если бы сервер
        # всё ещё искал report.html только в workdir, отдал бы именно его (старую находку).
        (root / "report.html").write_text("<html>устаревший файл в workdir</html>",
                                          encoding="utf-8")
        handler = make_handler(root, {"output": str(cls.report_path)}, UiState())
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()
        cls.report_tmp.cleanup()

    def request(self, method, path, headers=None, body=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, response, data

    def test_report_route_serves_the_configured_output_path(self):
        status, _r, data = self.request("GET", "/report.html")
        self.assertEqual(status, 200)
        self.assertIn("свежий отчёт", data.decode("utf-8"))
        self.assertNotIn("устаревший", data.decode("utf-8"))

    def test_missing_report_at_configured_path_is_404(self):
        self.report_path.unlink()
        try:
            status, _r, data = self.request("GET", "/report.html")
            self.assertEqual(status, 404)
            self.assertIn("не готов", data.decode("utf-8"))
        finally:
            self.report_path.write_text("<html>свежий отчёт</html>", encoding="utf-8")


class TestUiServerNoActive(unittest.TestCase):
    """Отдельный сервер с defaults={"active": False} — как при запуске с --no-active."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        handler = make_handler(root, {"output": "report.html", "active": False}, UiState())
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def request(self, method, path, headers=None, body=None):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, response, data

    def test_status_reports_active_disabled(self):
        import json as _json
        _status, _response, data = self.request("GET", "/api/status")
        self.assertFalse(_json.loads(data)["active"])

    def test_pentest_is_rejected_when_active_checks_are_disabled(self):
        own = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{self.port}"}
        body = '{"url": "http://example.com", "pentest": true, "pentest_consent": true}'
        status, _r, data = self.request("POST", "/api/scan", own, body)
        self.assertEqual(status, 400)
        self.assertIn("no-active", data.decode("utf-8"))


class FakeRedirect:
    def __init__(self, url, location, status=302):
        self.url = url
        self.status_code = status
        self.headers = {"Location": location}
        self.closed = False

    def close(self):
        self.closed = True


class TestRedirects(unittest.TestCase):
    def test_internal_host_detection(self):
        for host in ("localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "[::1]", "app.localhost"):
            self.assertTrue(_is_internal_host(host), host)
        for host in ("example.com", "8.8.8.8", ""):
            self.assertFalse(_is_internal_host(host), host)

    def test_public_site_cannot_redirect_to_internal_address(self):
        for location in ("http://127.0.0.1:8080/admin", "http://169.254.169.254/latest/meta-data/",
                         "//localhost/x"):
            response = FakeRedirect("https://example.com/", location)
            with self.assertRaises(requests.exceptions.RequestException):
                _block_internal_redirect(response)
            self.assertTrue(response.closed)

    def test_normal_redirects_are_untouched(self):
        for source, location in (("http://example.com/", "https://example.com/"),
                                 ("https://example.com/", "https://www.example.com/"),
                                 ("http://127.0.0.1:8000/", "http://127.0.0.1:8000/login")):
            response = FakeRedirect(source, location, 301)
            self.assertIs(_block_internal_redirect(response), response)

    def test_catalog_redirect_must_stay_on_allowlist(self):
        session = FakeSession([("known_exploited", FakeResponse(302, b"", {"Location": "https://evil.example/kev.json"}))])
        client = CatalogHttpClient(session=session, sleep=lambda _s: None)
        with self.assertRaises(CatalogHttpError):
            client.get("https://www.cisa.gov/known_exploited.json")
        self.assertEqual(len(session.calls), 1)  # на чужой хост запрос не ушёл

        session = FakeSession([("known_exploited", FakeResponse(302, b"", {"Location": "http://www.cisa.gov/x"}))])
        client = CatalogHttpClient(session=session, sleep=lambda _s: None)
        with self.assertRaises(CatalogHttpError):  # понижение до http
            client.get("https://www.cisa.gov/known_exploited.json")

    def test_catalog_redirect_within_allowlist_is_followed(self):
        session = FakeSession([
            ("known_exploited", FakeResponse(301, b"", {"Location": "https://raw.githubusercontent.com/k/kev.json"})),
            ("raw.githubusercontent.com", FakeResponse(200, b"{}")),
        ])
        client = CatalogHttpClient(session=session, sleep=lambda _s: None)
        self.assertEqual(client.get("https://www.cisa.gov/known_exploited.json").content, b"{}")


class TestReadDeadline(unittest.TestCase):
    def test_slow_drip_body_is_cut_off(self):
        import webscan.http_client as http_client

        class Slow:
            url = "http://example.com/"
            status_code = 200
            encoding = "utf-8"
            apparent_encoding = "utf-8"
            history = []

            def iter_content(self, _size):
                while True:
                    yield b"x"

            def close(self):
                pass

        old = http_client.READ_DEADLINE
        http_client.READ_DEADLINE = 0.0
        try:
            client = http_client.HttpClient(timeout=0.01)
            client.timeout = 0.0
            response = Slow()
            client._read_limited(response, True, None)
        finally:
            http_client.READ_DEADLINE = old
        self.assertTrue(response.truncated)
        self.assertLess(len(response._content), 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
