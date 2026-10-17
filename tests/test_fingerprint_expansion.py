"""Тесты расширенной базы fingerprint-сигнатур и путей (checks/exposed.py).

Проверяет представительную выборку новых продуктов по каждому источнику
признаков (HEADER/GENERATOR/COOKIE/PATH/ASSET/BODY), а не все сигнатуры —
полный список и так защищён тем, что модуль успешно импортируется и все
регулярные выражения компилируются (see test_vulndb.TestFingerprint).

Запуск:  python -m unittest discover -s tests -v
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webscan.checks.exposed import MAGIC_BYTES, SENSITIVE_PATHS, STRICT_PATTERNS, _is_confirmed
from webscan.fingerprint import detect_products
from webscan.models import CookieInfo, Page


def page(headers=None, body="", content_type="text/html", cookies=None,
         url="https://example.test/"):
    return Page(url=url, depth=0, status=200, headers=headers or {}, raw_headers=[],
                body=body, content_type=content_type, cookies=cookies or [])


def by_label(products):
    return {item.label: item for item in products}


class NewFingerprintSignaturesTest(unittest.TestCase):
    """По одному представителю на каждый источник признаков из новой партии."""

    def test_header_based_products(self):
        products = by_label(detect_products([page(headers={
            "Server": "openresty/1.21.4.1",
        })]))
        self.assertEqual(products["OpenResty"].version, "1.21.4.1")

        webmin = by_label(detect_products([page(headers={"Server": "MiniServ/2.1"})]))
        self.assertEqual(webmin["Webmin"].version, "2.1")

        nexus = by_label(detect_products([page(headers={"Server": "Nexus/3.41.0-01"})]))
        self.assertIn("Nexus Repository Manager", nexus)

        docker_registry = by_label(detect_products([page(headers={
            "Docker-Distribution-Api-Version": "registry/2.0",
        })]))
        self.assertEqual(docker_registry["Docker Registry"].version, "2.0")

    def test_generator_based_products(self):
        products = by_label(detect_products([page(
            body="<html><head><meta name='generator' content='PrestaShop 8.1.2'></head></html>",
        )]))
        self.assertEqual(products["PrestaShop"].version, "8.1.2")

        phpbb = by_label(detect_products([page(
            body="<html><head><meta name='generator' content='phpBB 3.3.10'></head></html>",
        )]))
        self.assertEqual(phpbb["phpBB"].version, "3.3.10")

    def test_cookie_based_products(self):
        gitea = by_label(detect_products([page(
            cookies=[CookieInfo("i_like_gitea", False, True, None, None, None,
                                "i_like_gitea=abc")],
        )]))
        self.assertIn("Gitea", gitea)

        zabbix = by_label(detect_products([page(
            cookies=[CookieInfo("zbx_session", False, True, None, None, None,
                                "zbx_session=abc")],
        )]))
        self.assertIn("Zabbix", zabbix)

    def test_path_based_products(self):
        products = by_label(detect_products([page(
            url="https://example.test/dana-na/auth/url_default/welcome.cgi",
            body="<html></html>",
        )]))
        self.assertIn("Ivanti Connect Secure / Pulse Secure", products)

        woocommerce = by_label(detect_products([page(
            body="<html><script src='/wp-content/plugins/woocommerce/assets/js/app.js'>"
                 "</script></html>",
        )]))
        self.assertIn("WooCommerce", woocommerce)

    def test_asset_based_product_with_version(self):
        products = by_label(detect_products([page(
            body="<html><script src='/js/handlebars-4.7.8.min.js'></script></html>",
        )]))
        self.assertEqual(products["Handlebars"].version, "4.7.8")

    def test_body_text_based_products(self):
        zabbix = by_label(detect_products([page(
            body="<html><head><title>Zabbix</title></head><body></body></html>",
        )]))
        self.assertIn("Zabbix", zabbix)

        pfsense = by_label(detect_products([page(
            body="<html><head><title>Login - pfSense</title></head></html>",
        )]))
        self.assertIn("pfSense", pfsense)

    def test_unrelated_page_triggers_none_of_the_new_signatures(self):
        products = by_label(detect_products([page(
            body="<html><head><title>Ordinary blog post</title></head>"
                 "<body><p>Nothing special here.</p></body></html>",
        )]))
        new_labels = {"OpenResty", "Webmin", "PrestaShop", "phpBB", "Gitea", "Zabbix",
                     "pfSense", "WooCommerce", "Handlebars"}
        self.assertEqual(new_labels & set(products), set())


class NewExposedPathsTest(unittest.TestCase):
    """Представительная выборка новых путей exposed.py и их подтверждение."""

    def test_new_paths_are_registered(self):
        paths = {entry[0] for entry in SENSITIVE_PATHS}
        for expected in ("/.kube/config", "/actuator/heapdump", "/vendor/phpunit/phpunit/"
                         "src/Util/PHP/eval-stdin.php", "/_cluster/health", "/metrics",
                         "/wp-json/wp/v2/users", "/.ssh/id_ed25519"):
            self.assertIn(expected, paths)

    def test_kube_config_is_confirmed_by_markers(self):
        entry = next(e for e in SENSITIVE_PATHS if e[0] == "/.kube/config")
        _path, markers, *_ = entry
        body = "apiVersion: v1\nclusters:\n- cluster:\nusers:\n- name: default\n"
        self.assertTrue(_is_confirmed("/.kube/config", markers, body, None))

    def test_pgpass_strict_pattern_requires_real_format(self):
        pattern = STRICT_PATTERNS["/.pgpass"]
        self.assertIsNotNone(pattern.search("db.example.com:5432:mydb:admin:s3cr3t\n"))
        self.assertIsNone(pattern.search("just some unrelated text with a colon: here"))

    def test_service_account_token_strict_pattern_requires_jwt_shape(self):
        pattern = STRICT_PATTERNS["/serviceaccount/token"]
        self.assertIsNotNone(pattern.search("eyJhbGciOiJSUzI1NiIsImtpZCI6IngifQ.eyJpc3Mi"))
        self.assertIsNone(pattern.search("eyJust a coincidental prefix, not a real token"))

    def test_new_zip_and_7z_paths_use_magic_bytes(self):
        for path in ("/.git.zip", "/vendor.zip", "/node_modules.zip", "/site.sql.zip"):
            self.assertEqual(MAGIC_BYTES[path], (b"PK\x03\x04", 0))
        self.assertEqual(MAGIC_BYTES["/backup.7z"][0][:2], b"7z")


class UnknownLibraryDetectionTest(unittest.TestCase):
    """Библиотеки вне словаря подписей тоже становятся компонентами (поиск по названию)."""

    HTML = (
        '<script src="https://cdnjs.cloudflare.com/ajax/libs/knockout/3.4.0/knockout-min.js"></script>'
        '<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/'
        'font-awesome.min.css">'
        '<script src="/static/js/flatpickr-4.6.9.min.js"></script>'
        '<script src="/static/js/app.js"></script>'
        '<script src="/static/js/main-2.0.js"></script>'
    )

    def test_unknown_cdn_and_local_assets_are_components(self):
        found = {item.label: item for item in detect_products([page(body=self.HTML)])}
        self.assertEqual(found["Knockout"].version, "3.4.0")
        self.assertEqual(found["Font Awesome"].version, "4.7.0")
        self.assertEqual(found["Flatpickr"].version, "4.6.9")
        for item in (found["Knockout"], found["Font Awesome"], found["Flatpickr"]):
            self.assertTrue(item.keyword_search)
            self.assertTrue(item.nvd_eligible)
        self.assertNotIn("App", found)
        self.assertNotIn("Main", found)

    def test_known_library_is_not_duplicated_by_generic_rule(self):
        products = detect_products([page(body='<script src="/js/jquery-3.6.0.min.js"></script>')])
        self.assertEqual([item.label for item in products], ["jQuery"])
        self.assertFalse(products[0].keyword_search)


if __name__ == "__main__":
    unittest.main(verbosity=2)
