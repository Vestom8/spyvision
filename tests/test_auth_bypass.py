"""Тесты подтверждения обхода авторизации через SQLi в форме входа (режим --pentest).

Запуск:  python -m unittest discover -s tests -v
"""

import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webscan.checks.auth_bypass import run_auth_bypass_checks
from webscan.http_client import HttpClient
from webscan.models import Form, FormField, Page

LOGIN_URL_TMPL = "http://127.0.0.1:{port}/login"


def _login_page(base: str) -> Page:
    form = Form(
        page_url=f"{base}/login",
        action=f"{base}/login",
        method="POST",
        fields=[
            FormField(name="username", field_type="text", value=""),
            FormField(name="password", field_type="password", value=""),
        ],
    )
    return Page(url=f"{base}/login", depth=0, status=200, headers={}, raw_headers=[],
                body="<html></html>", content_type="text/html", forms=[form])


class _VulnerableHandler(BaseHTTPRequestHandler):
    """Имитация логина, склеивающего SQL без параметризации: payload admin' -- обходит пароль."""

    def log_message(self, fmt, *args):  # noqa: N802
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        data = parse_qs(body)
        username = (data.get("username") or [""])[0]

        if username.startswith("admin'") or "' OR '1'='1" in username or \
                '" OR "1"="1' in username:
            payload = b"<html>redirecting</html>"
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie", "session=valid-admin-session; HttpOnly; Path=/")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        payload = "<html>Неверный логин или пароль</html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _SafeHandler(BaseHTTPRequestHandler):
    """Параметризованный логин: ни один payload не проходит, включая контрольный."""

    def log_message(self, fmt, *args):  # noqa: N802
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        payload = "<html>Неверный логин или пароль</html>".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _AlwaysSucceedsHandler(BaseHTTPRequestHandler):
    """Форма пускает кого угодно (не связано с SQL) — находки быть не должно."""

    def log_message(self, fmt, *args):  # noqa: N802
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        payload = b"<html>welcome</html>"
        self.send_response(302)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", "session=anyone; HttpOnly; Path=/")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _run_server(handler_cls):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class AuthBypassTest(unittest.TestCase):
    def _client(self):
        return HttpClient(timeout=3.0, delay=0.0, max_requests=200, concurrency=1)

    def test_sqli_auth_bypass_confirmed(self):
        server, thread = _run_server(_VulnerableHandler)
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            findings = run_auth_bypass_checks(self._client(), [_login_page(base)])
            kinds = {f.kind for f in findings}
            self.assertIn("sqli_auth_bypass", kinds)
            hit = next(f for f in findings if f.kind == "sqli_auth_bypass")
            self.assertEqual(hit.severity, "High")
            self.assertEqual(hit.confidence, "подтверждено")
            self.assertTrue(hit.exploited)
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_parameterized_login_yields_nothing(self):
        server, thread = _run_server(_SafeHandler)
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            findings = run_auth_bypass_checks(self._client(), [_login_page(base)])
            self.assertEqual(findings, [])
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_form_that_always_succeeds_is_not_flagged(self):
        """Контрольный (логически ложный) payload тоже 'проходит' — это не SQLi."""
        server, thread = _run_server(_AlwaysSucceedsHandler)
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            findings = run_auth_bypass_checks(self._client(), [_login_page(base)])
            self.assertEqual(findings, [])
        finally:
            server.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
