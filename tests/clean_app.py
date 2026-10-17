"""Безопасное «чистое» приложение: на нём сканер не должен находить уязвимостей.

Содержит типовые конструкции, на которых эвристики ошибаются: SPA с ответом 200 на любой
путь, редирект на собственную форму входа с адресом в параметре, JSON с отражённым
значением, публичный каталог с разным содержимым по ``id``, слова «security»/«firewall»
в тексте, пути вида ``/app/static/…`` и примеры кода в статье.
Запуск:  python tests/clean_app.py [порт]
"""

import html
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

DEFAULT_PORT = 8098

SHELL = (
    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
    "<title>Clean Shop</title></head><body>{body}</body></html>"
)

HOME = """
<h1>Clean Shop</h1>
<p>Our security team and firewall keep your data safe. Update your profile + settings,
select a country + city, then continue. Contact: sales@clean-shop.example</p>
<ul>
  <li><a href="/search?q=phone">Search</a></li>
  <li><a href="/product?id=1">Product 1</a></li>
  <li><a href="/go?next=/product%3Fid%3D1">Continue</a></li>
  <li><a href="/article">Article</a></li>
  <li><a href="/dashboard">Dashboard</a></li>
</ul>
<script src="/app/static/main.js"></script>
<script>document.title = 'Clean Shop';</script>
"""

ARTICLE = """
<h1>Escaping in templates</h1>
<p>Never call <code>eval(userInput)</code> and never build queries like
<code>"SELECT * FROM users WHERE id=" + id</code>.</p>
<pre><code>el.innerHTML = userInput; // unsafe</code></pre>
<p>Image: <img src="/app/static/pic.png" alt=""> Script path: /www/assets/site.js</p>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "CleanServer"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body, content_type="text/html; charset=utf-8", extra=()):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in extra:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _page(self, body):
        self._send(200, SHELL.format(body=body))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/":
            self._page(HOME)
        elif path == "/article":
            self._page(ARTICLE)
        elif path == "/search":
            term = (query.get("q") or [""])[0]
            self._page(f"<h1>Results</h1><p>You searched: {html.escape(term)}</p>")
        elif path == "/product":
            ident = (query.get("id") or [""])[0]
            names = {"1": "Phone", "2": "Laptop"}
            if ident in names:
                self._page(f"<h1>{names[ident]}</h1><p>Public description of {names[ident]}.</p>")
            else:
                self._send(404, SHELL.format(body="<h1>Not found</h1>"))
        elif path == "/go":
            target = (query.get("next") or ["/"])[0]
            # безопасно: переход только на собственные относительные адреса
            if not target.startswith("/") or target.startswith("//"):
                target = "/"
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path in ("/admin", "/admin/", "/dashboard", "/account"):
            self.send_response(302)
            self.send_header("Location", "/login?next=" + quote("https://evil.com"))
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/login":
            self._page("<h1>Sign in</h1><form action=\"/login\" method=\"post\">"
                       "<input type=\"password\" name=\"password\"></form>")
        elif path == "/app/static/main.js":
            self._send(200, "console.log('ready');\n", "application/javascript")
        elif path == "/api/echo":
            value = (query.get("x") or [""])[0]
            self._send(200, json.dumps({"echo": value}), "application/json")
        elif path.startswith("/api/"):
            # SPA-маршрутизатор: любой /api/… отдаёт оболочку приложения
            self._page("<div id=\"app\"></div>")
        elif path in ("/.env", "/backup.zip", "/.gitignore", "/dev/", "/test/", "/staging/"):
            # SPA-заглушка вместо файла: 200 с HTML (в отличие от «настоящей» 404)
            self._page("<div id=\"app\">test dev staging backup index</div>")
        else:
            self._send(404, SHELL.format(body="<h1>Not found</h1>"))

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(min(length, 65536))
        self._page("<h1>Invalid credentials</h1>")


def create_server(port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = create_server(port)
    print(f"Чистое тестовое приложение: http://127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
