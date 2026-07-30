"""Тесты сканера.

Запуск:  python -m unittest discover -s tests -v
        (или)  python tests/test_scanner.py
"""

import os
import re
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webscan.checks.active import (MARKER, SQLI_PAYLOADS, XSS_PAYLOAD, _is_redirect_param,
                                   _structure_changed)
from webscan.cli import ask_url, normalize_target, sanitize_url
from webscan.checks.clientside import check_client_side
from webscan.checks.cookies import check_cookies
from webscan.checks.headers import check_headers
from webscan.checks.infoleak import check_info_leak
from webscan.http_client import MAX_BODY_BYTES, MAX_TIMEOUT, MIN_DELAY, HttpClient
from webscan.models import (CONFIG, CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, CookieInfo,
                            Finding, FindingList, Page, VULN)
from webscan.knowledge import KNOWLEDGE
from webscan.report import build_report
from webscan.scanner import ScanConfig, run_scan
from webscan.utils import (is_valid_host, mask_secret, normalize_url, same_host, set_param,
                           snippet)

from vulnerable_app import create_server


def make_page(url="https://site.test/", headers=None, body="", cookies=None,
              content_type="text/html"):
    headers = headers or {}
    return Page(
        url=url,
        depth=0,
        status=200,
        headers=headers,
        raw_headers=[(name.lower(), value) for name, value in headers.items()],
        body=body,
        content_type=content_type,
        requested_url=url,
        cookies=cookies or [],
    )


class TestUtils(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("HTTP://Example.COM:80/a//b?x=1#frag"),
                         "http://example.com/a/b?x=1")
        self.assertEqual(normalize_url("https://example.com"), "https://example.com/")
        self.assertEqual(normalize_url("https://example.com:8443/x"),
                         "https://example.com:8443/x")

    def test_same_host_excludes_subdomains(self):
        self.assertTrue(same_host("https://a.test/x", "https://a.test/y"))
        self.assertFalse(same_host("https://sub.a.test/x", "https://a.test/y"))
        self.assertFalse(same_host("https://a.test.evil/x", "https://a.test/y"))

    def test_is_valid_host(self):
        self.assertTrue(is_valid_host("example.com"))
        self.assertTrue(is_valid_host("127.0.0.1"))
        self.assertTrue(is_valid_host("localhost"))
        self.assertFalse(is_valid_host("not a url"))
        self.assertFalse(is_valid_host(""))

    def test_set_param(self):
        self.assertEqual(set_param("https://a.test/s?q=1&r=2", "q", "X"),
                         "https://a.test/s?q=X&r=2")

    def test_mask_secret_does_not_store_value(self):
        masked = mask_secret("supersecretpassword", 4)
        self.assertTrue(masked.startswith("supe"))
        self.assertNotIn("password", masked)

    def test_snippet_centers_on_needle(self):
        text = "a" * 500 + "NEEDLE" + "b" * 500
        result = snippet(text, "NEEDLE", 20)
        self.assertIn("NEEDLE", result)
        self.assertLess(len(result), 120)


class TestConsoleInput(unittest.TestCase):
    """Ввод адреса в консоли (интерактивный режим)."""

    def test_sanitize_url(self):
        self.assertEqual(sanitize_url('  "https://a.test/x?y=1&z=2"  '),
                         "https://a.test/x?y=1&z=2")
        self.assertEqual(sanitize_url("<https://a.test/>"), "https://a.test/")
        self.assertEqual(sanitize_url("python scan.py https://a.test/"), "https://a.test/")
        self.assertEqual(sanitize_url("//a.test/x"), "https://a.test/x")
        self.assertEqual(sanitize_url("   "), "")

    def test_normalize_target_adds_scheme(self):
        self.assertEqual(normalize_target("a.test/x", detect_scheme=False), "http://a.test/x")
        self.assertEqual(normalize_target("https://a.test/x", detect_scheme=False),
                         "https://a.test/x")

    def test_ask_url_accepts_full_url(self):
        answers = iter(["", "ftp://a.test/", "  https://a.test/catalog?page=2&sort=new  "])
        result = ask_url(reader=lambda _prompt: next(answers), detect_scheme=False)
        self.assertEqual(result, "https://a.test/catalog?page=2&sort=new")

    def test_ask_url_adds_missing_scheme(self):
        result = ask_url(reader=lambda _prompt: "127.0.0.1:8099/path", detect_scheme=False)
        self.assertEqual(result, "http://127.0.0.1:8099/path")

    def test_ask_url_returns_none_on_cancel(self):
        def cancel(_prompt):
            raise EOFError

        self.assertIsNone(ask_url(reader=cancel, detect_scheme=False))

    def test_ask_url_gives_up_after_attempts(self):
        result = ask_url(reader=lambda _prompt: "", attempts=2, detect_scheme=False)
        self.assertIsNone(result)


class TestLandingUi(unittest.TestCase):
    def test_landing_html_contains_spyvision_and_api(self):
        from webscan.landing import landing_html
        html = landing_html()
        self.assertIn("Spyvision", html)
        self.assertIn("Сканировать", html)
        self.assertIn("/api/scan", html)
        self.assertIn("urlInput", html)

    def test_write_landing_creates_index(self):
        from webscan.landing import write_landing
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "index.html")
            saved = write_landing(path)
            self.assertTrue(os.path.isfile(saved))
            with open(saved, encoding="utf-8") as handle:
                content = handle.read()
            self.assertIn("Spyvision", content)
            self.assertIn("/api/scan", content)

    def test_validate_scan_url_rejects_empty_and_bad_scheme(self):
        from webscan.ui_server import validate_scan_url
        target, error = validate_scan_url("")
        self.assertIsNone(target)
        self.assertTrue(error)
        target, error = validate_scan_url("ftp://example.com")
        self.assertIsNone(target)
        self.assertIn("http", error.lower())

    def test_validate_scan_url_accepts_https(self):
        from webscan.ui_server import validate_scan_url
        target, error = validate_scan_url("https://example.com/path")
        self.assertEqual(error, "")
        self.assertEqual(target, "https://example.com/path")

    def test_api_scan_rejects_bad_json_url(self):
        from webscan.ui_server import UiConfig, make_handler
        from http.server import ThreadingHTTPServer
        import json
        import urllib.request

        with tempfile.TemporaryDirectory() as directory:
            cfg = UiConfig(work_dir=directory, max_pages=1, max_depth=0, max_requests=5,
                           active=False, delay=0.5)
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                host, port = server.server_address[:2]
                base = f"http://{host}:{port}"
                # landing
                with urllib.request.urlopen(base + "/") as resp:
                    page = resp.read().decode("utf-8")
                self.assertIn("Spyvision", page)
                # bad url
                req = urllib.request.Request(
                    base + "/api/scan",
                    data=json.dumps({"url": ""}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req)
                    self.fail("expected HTTPError")
                except urllib.error.HTTPError as exc:
                    with exc:
                        self.assertEqual(exc.code, 400)
                        body = json.loads(exc.read().decode("utf-8"))
                    self.assertFalse(body.get("ok"))
                    self.assertTrue(body.get("error"))
                # status
                with urllib.request.urlopen(base + "/api/status") as resp:
                    status = json.loads(resp.read().decode("utf-8"))
                self.assertIn("scanning", status)
            finally:
                server.shutdown()
                server.server_close()


class TestLimits(unittest.TestCase):
    def test_limits_are_enforced(self):
        client = HttpClient(timeout=30, delay=0.01, max_requests=500)
        self.assertEqual(client.timeout, MAX_TIMEOUT)
        self.assertEqual(client.delay, MIN_DELAY)
        self.assertEqual(client.max_body_bytes, MAX_BODY_BYTES)

    def test_budget_and_reserve(self):
        client = HttpClient(max_requests=3)
        client.requests_made = 2
        self.assertTrue(client.can_request())
        self.assertFalse(client.can_request(reserve=1))
        self.assertIsNone(client.get("http://127.0.0.1:9/", reserve=1))
        self.assertTrue(client.budget_exhausted)


class TestHeaderChecks(unittest.TestCase):
    def test_missing_headers_reported(self):
        findings = check_headers(make_page())
        titles = [f.title for f in findings]
        for expected in ("Content-Security-Policy", "Strict-Transport-Security",
                         "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
                         "Permissions-Policy"):
            self.assertTrue(any(expected in title for title in titles),
                            f"нет находки про {expected}: {titles}")
        self.assertTrue(all(f.category == CONFIG for f in findings))

    def test_good_headers_produce_no_findings(self):
        page = make_page(headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        })
        self.assertEqual([f.title for f in check_headers(page)], [])

    def test_open_cors_on_page_is_reported(self):
        page = make_page(headers={"Access-Control-Allow-Origin": "*",
                                  "Access-Control-Allow-Credentials": "true"})
        findings = [f for f in check_headers(page) if f.kind == "page_cors_open"]
        self.assertTrue(findings)
        self.assertEqual(findings[0].severity, MEDIUM)

    def test_conflicting_duplicate_headers(self):
        page = make_page()
        page.raw_headers = [("x-frame-options", "DENY"), ("x-frame-options", "SAMEORIGIN"),
                            ("content-security-policy", "default-src 'self'")]
        titles = [f.title for f in check_headers(page)]
        self.assertTrue(any("Противоречащие копии" in title for title in titles), titles)

    def test_short_hsts_max_age(self):
        page = make_page(headers={"Strict-Transport-Security": "max-age=60"})
        titles = [f.title for f in check_headers(page)]
        self.assertTrue(any("max-age" in title for title in titles), titles)


class TestCookieChecks(unittest.TestCase):
    def test_insecure_cookie(self):
        cookie = CookieInfo(name="sid", secure=False, http_only=False, same_site=None,
                            expires=None, max_age=90 * 86400, raw="sid=abc; Max-Age=7776000")
        titles = [f.title for f in check_cookies(make_page(cookies=[cookie]))]
        self.assertTrue(any("Secure" in title for title in titles), titles)
        self.assertTrue(any("HttpOnly" in title for title in titles), titles)
        self.assertTrue(any("SameSite" in title for title in titles), titles)
        self.assertTrue(any("срок жизни" in title for title in titles), titles)

    def test_secure_cookie_is_clean(self):
        cookie = CookieInfo(name="sid", secure=True, http_only=True, same_site="Lax",
                            expires=None, max_age=3600, raw="sid=abc; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(check_cookies(make_page(cookies=[cookie])), [])

    def test_cookie_value_is_not_stored_in_report(self):
        cookie = CookieInfo(name="sid", secure=False, http_only=True, same_site="Lax",
                            expires=None, max_age=None, raw="sid=SUPER_SECRET_VALUE; Path=/")
        findings = check_cookies(make_page(cookies=[cookie]))
        self.assertTrue(findings)
        for finding in findings:
            self.assertNotIn("SUPER_SECRET_VALUE", finding.evidence)


class TestInfoLeak(unittest.TestCase):
    def test_detects_paths_ips_comments_and_maps(self):
        body = ("<html><!-- TODO: убрать пароль admin -->"
                "<p>C:\\inetpub\\wwwroot\\app\\index.php</p>"
                "<p>10.1.2.3</p>"
                "<script src=\"/static/app.js.map\"></script></html>")
        page = make_page(headers={"Server": "nginx/1.18.0"}, body=body)
        titles = [f.title for f in check_info_leak(page)]
        self.assertTrue(any("server" in title for title in titles), titles)
        self.assertTrue(any("абсолютные пути" in title for title in titles), titles)
        self.assertTrue(any("IP-адреса" in title for title in titles), titles)
        self.assertTrue(any("Комментарии" in title for title in titles), titles)
        self.assertTrue(any(".map" in title for title in titles), titles)

    def test_secret_value_is_masked(self):
        page = make_page(body="var conf = {api_key: \"ABCDEF1234567890XYZ\"};")
        findings = [f for f in check_info_leak(page) if "секрет" in f.title.lower()]
        self.assertTrue(findings)
        self.assertNotIn("ABCDEF1234567890XYZ", findings[0].evidence)


class TestClientSideChecks(unittest.TestCase):
    """Проверки клиентской части: опасные места в JavaScript и разметке."""

    def test_dom_xss_sink_detected(self):
        body = ("<html><body><script>var t = location.hash.slice(1);"
                "document.getElementById('x').innerHTML = t;</script></body></html>")
        kinds = [f.kind for f in check_client_side(make_page(body=body))]
        self.assertIn("dom_xss_sink", kinds)

    def test_safe_script_is_not_reported(self):
        body = "<html><body><script>document.title = 'ok';</script></body></html>"
        kinds = [f.kind for f in check_client_side(make_page(body=body))]
        self.assertNotIn("dom_xss_sink", kinds)

    def test_postmessage_without_origin_check(self):
        body = ("<html><script>window.addEventListener('message', function (e) "
                "{ render(e.data); });</script></html>")
        kinds = [f.kind for f in check_client_side(make_page(body=body))]
        self.assertIn("postmessage_no_origin", kinds)

    def test_postmessage_with_origin_check_is_clean(self):
        body = ("<html><script>window.addEventListener('message', function (e) "
                "{ if (e.origin !== 'https://a.test') { return; } render(e.data); });"
                "</script></html>")
        kinds = [f.kind for f in check_client_side(make_page(body=body))]
        self.assertNotIn("postmessage_no_origin", kinds)

    def test_token_in_local_storage(self):
        body = "<html><script>localStorage.setItem('auth_token', value);</script></html>"
        kinds = [f.kind for f in check_client_side(make_page(body=body))]
        self.assertIn("token_in_storage", kinds)

    def test_insecure_websocket_on_https_page(self):
        body = "<html><script>var s = new WebSocket('ws://a.test/live');</script></html>"
        kinds = [f.kind for f in check_client_side(make_page(body=body))]
        self.assertIn("insecure_websocket", kinds)


class TestActiveHelpers(unittest.TestCase):
    def test_payloads_are_safe(self):
        self.assertIn(MARKER, XSS_PAYLOAD)
        self.assertNotIn("onerror", XSS_PAYLOAD.lower())
        self.assertNotIn("script", XSS_PAYLOAD.lower())
        self.assertEqual(SQLI_PAYLOADS, ("'", "\"", "\\"))

    def test_redirect_param_detection(self):
        for name in ("url", "redirect", "next", "returnUrl", "continue"):
            self.assertTrue(_is_redirect_param(name), name)
        self.assertFalse(_is_redirect_param("page"))

    def test_structure_comparison(self):
        base = "<html><body><p>ok</p></body></html>"
        self.assertFalse(_structure_changed(base, base))
        self.assertTrue(_structure_changed(base, "<html><body><p>ok</p><div>SQL error</div>"
                                                 "<table><tr><td>x</td></tr></table></body></html>"))


class TestReport(unittest.TestCase):
    def test_report_escapes_html(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/?q=<script>alert(1)</script>",
                             title="<b>Тест</b>", category=VULN, severity=HIGH,
                             recommendation="<i>fix</i>", request="GET <x>",
                             evidence="<img src=x onerror=alert(1)>"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 5,
                                       "requests_made": 5, "max_requests": 100, "max_pages": 20,
                                       "max_depth": 2, "duration": 1.0, "page_list": []})
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertNotIn("onerror=alert(1)>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_report_contains_statistics(self):
        findings = FindingList()
        for severity in (HIGH, MEDIUM, LOW, INFO):
            findings.add(Finding(url="https://a.test/", title=f"t-{severity}", category=CONFIG,
                                 severity=severity, recommendation="r"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 3, "checks": 10,
                                       "requests_made": 12, "max_requests": 100, "max_pages": 20,
                                       "max_depth": 2, "duration": 2.0, "page_list": []})
        self.assertIn("Общая статистика", html)
        self.assertIn("Найденные проблемы", html)
        for severity in (HIGH, MEDIUM, LOW, INFO):
            self.assertIn(f'data-severity="{severity}"', html)

    def test_report_contains_donut_chart(self):
        findings = FindingList()
        for index, severity in enumerate((HIGH, HIGH, MEDIUM, LOW, INFO)):
            findings.add(Finding(url=f"https://a.test/{index}", title=f"t-{index}",
                                 category=CONFIG, severity=severity, recommendation="r"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 5,
                                       "requests_made": 5, "max_requests": 100, "max_pages": 20,
                                       "max_depth": 2, "duration": 1.0, "page_list": []})
        # заголовок отчёта и диаграмма находятся в одном блоке шапки
        header = html.split("</header>")[0]
        self.assertIn("Отчёт сканирования безопасности веб-приложения", header)
        self.assertIn("class=\"donut\"", header)
        self.assertIn("Общая статистика", header)
        self.assertIn("class=\"help-menu\"", header)
        self.assertIn('data-open="help"', header)
        # четыре категории легенды и общее число находок в центре
        for label in ("Высокая", "Средняя", "Низкая", "Безопасно"):
            self.assertIn(label, header)
        self.assertIn(">5</text>", header)
        self.assertIn("stroke-dasharray", header)

    def test_severity_levels_are_clickable_and_filters_are_grouped(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/", title="t", category=CONFIG, severity=HIGH,
                             recommendation="r"))
        findings.add(Finding(url="https://a.test/", title="m", category=CONFIG, severity=MEDIUM,
                             recommendation="r"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 1,
                                       "requests_made": 1, "max_requests": 200, "max_pages": 40,
                                       "max_depth": 2, "duration": 1.0, "page_list": []})
        # уровень опасности кликабелен и в диаграмме, и в блоке «Как читать отчёт»
        self.assertGreaterEqual(html.count('data-severity-link="High"'), 2)
        self.assertIn('data-severity-link="attention"', html)
        self.assertIn("severityFilter", html)
        # фильтр категорий находится внутри раздела «Найденные проблемы»
        before, findings_section = html.split('id="findings"', 1)
        self.assertIn("Все категории", findings_section)
        self.assertIn("Все уровни", findings_section)
        self.assertNotIn("Все категории", before)
        self.assertIn("code-block full", html)
        # HUD-тема отчёта: акцентный cyan, не старая светлая рамка
        self.assertIn("--green:", html)
        self.assertIn("var(--green-dark)", html)
        self.assertIn("rgba(0, 212, 255", html)

    def test_single_expand_collapse_button(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/", title="t", category=CONFIG, severity=LOW,
                             recommendation="r"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 1,
                                       "requests_made": 1, "max_requests": 200, "max_pages": 40,
                                       "max_depth": 2, "duration": 1.0, "page_list": []})
        self.assertIn('id="toggle-all"', html)
        self.assertIn("Развернуть все", html)
        self.assertIn("Свернуть все", html)  # надпись меняется в JS
        self.assertNotIn('id="expand"', html)
        self.assertNotIn('id="collapse"', html)

    def test_urls_are_clickable_links(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/page?id=1", title="t", category=VULN,
                             severity=HIGH, recommendation="r"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 1,
                                       "requests_made": 1, "max_requests": 200, "max_pages": 40,
                                       "max_depth": 2, "duration": 1.0,
                                       "page_list": [{"url": "https://a.test/page?id=1",
                                                      "status": 200, "depth": 0,
                                                      "content_type": "text/html",
                                                      "size": 1234}]})
        self.assertIn('<a class="url" href="https://a.test/page?id=1"', html)
        self.assertIn('rel="noopener noreferrer"', html)
        self.assertIn("Кол-во символов в коде", html)
        self.assertNotIn("Размер, симв.", html)

    def test_statistics_block_is_detailed(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/", title="t", category=VULN, severity=HIGH,
                             recommendation="r", confidence=CONFIRMED))
        html = build_report(findings, {"target": "https://a.test/", "pages": 3, "checks": 40,
                                       "requests_made": 60, "max_requests": 400, "max_pages": 40,
                                       "max_depth": 2, "duration": 5.0, "page_list": [],
                                       "forms": 2, "url_params": 4, "active_tests": 12,
                                       "targets_tested": 3, "error_count": 1,
                                       "external_count": 7, "https": True,
                                       "insecure_requests": 0})
        for label in ("Что просканировано", "Найденные проблемы", "Как выполнялось сканирование",
                      "Страниц проверено", "Форм на страницах", "Параметров в адресах",
                      "Требуют внимания", "Подтверждённые угрозы высокого уровня",
                      "Запросов к сайту", "Активных тестов", "Какие проверки выполнялись",
                      "Длительность сканирования"):
            self.assertIn(label, html)
        self.assertNotIn("Что найдено", html)
        self.assertNotIn("Всего записей в отчёте", html)
        self.assertNotIn("Разделы отчёта", html.split('id="drawer"', 1)[0])
        self.assertIn('data-category-link="Уязвимость"', html)
        self.assertIn('data-open="pages"', html)
        self.assertIn("under-pdf", html)
        header = html.split("</header>", 1)[0]
        self.assertIn("Длительность сканирования", header)
        self.assertIn("Какие проверки выполнялись", header)
        for removed in ("Ссылок на чужие сайты", "Глубина обхода",
                        "Запросов без проверки сертификата", "Требуют ручной проверки"):
            self.assertNotIn(removed, html)
        # «Подтверждено» как отдельная карточка статистики не показывается
        self.assertNotIn("Подтверждено</div>", html)
        header = html.split("</header>", 1)[0]
        self.assertNotIn(">Подтверждено<", header)
        # в фильтрах таблицы подпись с заглавной — нормально
        self.assertIn(">Подтверждено ", html)
        self.assertIn("home-btn", html)
        self.assertIn("pdf-filtered-btn", html)
        self.assertIn("fix-more-btn", html)

    def test_side_drawer_and_pdf_export(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/", title="Секрет в коде", category=VULN,
                             severity=HIGH, recommendation="сменить ключ", confidence=CONFIRMED))
        findings.add(Finding(url="https://a.test/", title="Нет CSP", category=CONFIG,
                             severity=MEDIUM, recommendation="добавить CSP"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 5,
                                       "requests_made": 5, "max_requests": 400, "max_pages": 40,
                                       "max_depth": 2, "duration": 1.0,
                                       "page_list": [{"url": "https://a.test/", "status": 200,
                                                      "depth": 0, "content_type": "text/html",
                                                      "size": 100}],
                                       "checks_list": [("Отражённый XSS", "1 точка")],
                                       "errors": [("https://a.test/x", "timeout")]})
        self.assertIn('id="drawer"', html)
        self.assertNotIn("Разделы отчёта", html.split('id="drawer"', 1)[0])
        self.assertIn("Скачать PDF", html)
        self.assertIn("chart-pdf", html)
        header = html.split("</header>", 1)[0]
        self.assertIn("Скачать PDF", header)
        self.assertNotIn("Подробности вынесены в боковую панель", html)
        self.assertIn('id="pdf-report"', html)
        pdf = html.split('id="pdf-report"', 1)[1]
        self.assertIn("самые опасные", pdf)
        self.assertIn("Секрет в коде", pdf)  # High
        self.assertNotIn("Нет CSP", pdf)  # Medium не попадает в PDF
        for section in ("Найденные проблемы", "Как читать отчёт",
                        "Просканированные страницы", "Какие проверки выполнялись",
                        "Запросы, оставшиеся без ответа"):
            self.assertIn(section, html)
        # подтверждённый High выделен красным; таблица сгруппирована по виду ошибки
        self.assertIn('class="g-row critical"', html)
        self.assertIn("Вид ошибки", html)
        self.assertIn('data-severity-link="critical"', html)
        self.assertIn('class="f conf-f"', html)
        self.assertIn("подтверждено", html)
        self.assertIn("подозрение", html)
        self.assertIn("Подтверждённые угрозы высокого уровня", html)
        self.assertIn("toggleGroup", html)
        self.assertIn("toggleInstance", html)
        # фон на всю страницу (HUD: фото + затемняющий градиент), не только в шапке
        self.assertIn('url("bg.jfif") center/cover fixed no-repeat', html)
        self.assertIn("linear-gradient(160deg, rgba(5,10,27,.22)", html)

    def test_report_explains_threat_and_logic(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/", title="Отсутствует CSP", category=CONFIG,
                             severity=MEDIUM, recommendation="r", kind="csp_missing"))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 1,
                                       "requests_made": 1, "max_requests": 400, "max_pages": 40,
                                       "max_depth": 2, "duration": 1.0, "page_list": []})
        self.assertIn("Чем это опасно", html)
        self.assertIn("Почему сканер так решил", html)
        self.assertIn("Внедрение кода в страницу (XSS)", html)

    def test_findings_grouped_by_error_type(self):
        findings = FindingList()
        findings.add(Finding(url="https://a.test/a", title="HTTPS-версия сайта недоступна",
                             category=CONFIG, severity=MEDIUM, recommendation="r",
                             confidence=CONFIRMED))
        findings.add(Finding(url="https://a.test/b", title="HTTPS-версия сайта недоступна",
                             category=CONFIG, severity=MEDIUM, recommendation="r",
                             confidence=SUSPECTED))
        findings.add(Finding(url="https://a.test/c", title="Нет CSP", category=CONFIG,
                             severity=LOW, recommendation="r", confidence=CONFIRMED))
        html = build_report(findings, {"target": "https://a.test/", "pages": 1, "checks": 1,
                                       "requests_made": 1, "max_requests": 400, "max_pages": 40,
                                       "max_depth": 2, "duration": 1.0, "page_list": []})
        self.assertEqual(html.count('class="g-row"'), 2)
        self.assertIn("2 шт.", html)
        self.assertIn("1 шт.", html)
        self.assertIn('data-group="0"', html)
        self.assertIn('data-value="подтверждено"', html)
        self.assertIn('data-value="подозрение"', html)
        self.assertIn("https://a.test/a", html)
        self.assertIn("https://a.test/b", html)


class TestKnowledge(unittest.TestCase):
    def test_finding_is_enriched_from_knowledge_base(self):
        finding = Finding(url="u", title="t", category=CONFIG, severity=MEDIUM,
                          recommendation="r", kind="cookie_httponly")
        self.assertEqual(finding.threat_type, "Кража сессии")
        self.assertTrue(finding.impact)
        self.assertTrue(finding.detection)

    def test_unknown_kind_falls_back_to_category(self):
        config = Finding(url="u", title="t", category=CONFIG, severity=LOW, recommendation="r")
        vuln = Finding(url="u", title="t", category=VULN, severity=LOW, recommendation="r")
        self.assertEqual(config.threat_type, "Ошибка конфигурации")
        self.assertEqual(vuln.threat_type, "Уязвимость приложения")

    def test_every_kind_has_all_three_texts(self):
        for kind, entry in KNOWLEDGE.items():
            for field_name in ("type", "impact", "detection"):
                self.assertTrue(entry.get(field_name), f"{kind}: не заполнено поле {field_name}")

    def test_every_kind_has_detailed_fix(self):
        from webscan.knowledge_fix import FIXES
        from webscan.knowledge import describe
        self.assertEqual(set(FIXES), set(KNOWLEDGE))
        for kind in KNOWLEDGE:
            fix = describe(kind).get("fix", "")
            self.assertGreaterEqual(len(fix), 900, f"{kind}: слишком короткое «Как исправить»")
            self.assertIn("\n\n", fix, f"{kind}: ожидаются абзацы")
            self.assertIn("Шаг 1.", fix, f"{kind}: ожидаются нумерованные шаги")
            self.assertIn("Шаг 2.", fix, f"{kind}: ожидаются нумерованные шаги")

    def test_finding_uses_knowledge_fix(self):
        finding = Finding(url="u", title="t", category=CONFIG, severity=MEDIUM,
                          recommendation="коротко", kind="csp_missing")
        self.assertNotEqual(finding.recommendation, "коротко")
        self.assertIn("Content-Security-Policy", finding.recommendation)
        self.assertIn("Шаг 1.", finding.recommendation)
        self.assertGreater(len(finding.recommendation), 900)

    def test_every_kind_used_in_checks_is_described(self):
        """Каждый вид находки из кода проверок должен иметь пояснения в базе знаний."""
        package = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "webscan")
        used = set()
        for folder, _dirs, files in os.walk(package):
            for name in files:
                if not name.endswith(".py") or name == "knowledge.py":
                    continue
                with open(os.path.join(folder, name), encoding="utf-8") as handle:
                    used.update(re.findall(r'kind=["\']([a-z0-9_]+)["\']', handle.read()))
        missing = sorted(kind for kind in used if kind not in KNOWLEDGE)
        self.assertEqual(missing, [], f"нет пояснений в knowledge.py: {missing}")


class TestFindingList(unittest.TestCase):
    def test_deduplication_and_sorting(self):
        findings = FindingList()
        first = Finding(url="u", title="t", category=CONFIG, severity=LOW, recommendation="r")
        duplicate = Finding(url="u", title="t", category=CONFIG, severity=LOW, recommendation="r")
        high = Finding(url="u", title="t2", category=VULN, severity=HIGH, recommendation="r")
        self.assertTrue(findings.add(first))
        self.assertFalse(findings.add(duplicate))
        findings.add(high)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings.sorted()[0].severity, HIGH)
        self.assertEqual(findings.count_by_severity()[HIGH], 1)


class TestEndToEnd(unittest.TestCase):
    """Полный прогон против локального уязвимого приложения."""

    @classmethod
    def setUpClass(cls):
        cls.server = create_server(0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_scan_finds_expected_issues(self):
        with tempfile.TemporaryDirectory() as directory:
            output = os.path.join(directory, "report.html")
            config = ScanConfig(
                url=f"http://127.0.0.1:{self.port}",
                max_pages=4,
                max_depth=1,
                output=output,
                max_requests=40,
            )
            result = run_scan(config)

            self.assertLessEqual(result.stats["requests_made"], 40,
                                 "нарушен лимит общего числа запросов")
            self.assertGreaterEqual(result.stats["pages"], 2)

            titles = " | ".join(f.title for f in result.findings)
            self.assertIn("Content-Security-Policy", titles)
            self.assertIn("cookie", titles)
            self.assertIn("HTTP без шифрования", titles)
            self.assertTrue(any("XSS" in t or "SQL" in t for t in
                                [f.title for f in result.findings]), titles)

            without_texts = [f.title for f in result.findings
                             if not (f.kind and f.impact and f.detection)]
            self.assertEqual(without_texts, [],
                             "у находки нет пояснений из базы знаний")

            html = build_report(result.findings, result.stats)
            with open(output, "w", encoding="utf-8") as handle:
                handle.write(html)
            self.assertTrue(os.path.exists(output))
            self.assertGreater(os.path.getsize(output), 3000)

    def test_external_links_are_not_visited(self):
        config = ScanConfig(url=f"http://127.0.0.1:{self.port}", max_pages=4, max_depth=1,
                            max_requests=25, active=False)
        result = run_scan(config)
        for page in result.stats["page_list"]:
            self.assertIn(f"127.0.0.1:{self.port}", page["url"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
