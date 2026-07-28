"""Учебное уязвимое веб-приложение для проверки работы сканера.

Приложение НАМЕРЕННО содержит типовые ошибки конфигурации: отсутствуют защитные
заголовки, cookie без флагов, открытые служебные файлы, отражённый XSS,
имитация ошибки SQL, открытый редирект. Запускать только локально.

Запуск:  python tests/vulnerable_app.py [порт]
"""

import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DEFAULT_PORT = 8099

PAGES = {
    "/": """
      <h1>Тестовый магазин</h1>
      <!-- TODO: убрать тестовый пароль admin/admin перед релизом -->
      <p>Внутренний сервер сборки: 192.168.10.14, каталог /var/www/shop/public/index.php</p>
      <ul>
        <li><a href="/search?q=telefon&amp;lang=ru">Поиск</a></li>
        <li><a href="/product?id=5">Товар</a></li>
        <li><a href="/login">Вход</a></li>
        <li><a href="/go?next=/product?id=1">Переход</a></li>
        <li><a href="https://external-site.example.org/partner">Партнёр (внешняя ссылка)</a></li>
      </ul>
      <img src="http://insecure.example.org/banner.png" alt="banner">
      <p id="box" onclick="show(1)">Блок 1</p>
      <p onclick="show(2)">Блок 2</p>
      <a href="javascript:show(3)">Блок 3</a>
      <script src="/static/app.js"></script>
      <script>
        var API_KEY = "sk_live_9f8e7d6c5b4a3210";
        // намеренная DOM-уязвимость: данные из адреса попадают в разметку
        document.getElementById("box").innerHTML = decodeURIComponent(location.hash.slice(1));
        window.addEventListener("message", function (e) { render(e.data); });
        localStorage.setItem("auth_token", "demo-token");
        var live = new WebSocket("ws://127.0.0.1:8099/live");
      </script>
    """,
    "/login": """
      <h1>Вход</h1>
      <form action="http://%(host)s/login" method="post">
        <input type="text" name="username">
        <input type="password" name="password">
        <button type="submit">Войти</button>
      </form>
      <form action="/subscribe" method="get">
        <input type="email" name="email">
        <input type="password" name="pass_confirm">
        <button type="submit">Подписаться</button>
      </form>
      <form action="/avatar" method="post" enctype="multipart/form-data">
        <input type="file" name="avatar">
        <button type="submit">Загрузить фото</button>
      </form>
    """,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "TestServer/1.2.3"
    sys_version = "Python/3.11.0-test"

    def log_message(self, fmt, *args):  # тише в консоли
        pass

    # --- служебное --------------------------------------------------------
    def _send(self, status, body, content_type="text/html; charset=utf-8", extra=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for name, value in (extra or []):
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _page(self, body, extra=None):
        document = (
            "<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
            "<meta name=\"generator\" content=\"TestCMS 4.1\">"
            "<title>Тестовое приложение</title></head><body>"
            f"{body}<script src=\"/static/app.js.map\"></script></body></html>"
        )
        self._send(200, document, extra=extra)

    # --- маршруты ---------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/":
            cookies = [
                ("Set-Cookie", "sessionid=abc123; Path=/"),
                ("Set-Cookie", "tracking=zzz; Path=/; Max-Age=31536000; SameSite=None"),
                ("X-Frame-Options", "DENY"),
                ("X-Frame-Options", "SAMEORIGIN"),
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "true"),
            ]
            self._page(PAGES["/"] % {"host": self.headers.get("Host", "")}, extra=cookies)
        elif path == "/login":
            self._page(PAGES["/login"] % {"host": self.headers.get("Host", "")})
        elif path == "/search":
            term = (query.get("q") or [""])[0]
            # уязвимость: значение выводится без экранирования
            self._page(f"<h1>Результаты поиска</h1><p>Вы искали: {term}</p>"
                       f"<a href=\"/product?id=1\">Товар 1</a>")
        elif path == "/product":
            ident = (query.get("id") or [""])[0]
            if any(char in ident for char in "'\"\\"):
                self._send(500, "<h1>500</h1><pre>You have an error in your SQL syntax; check "
                                "the manual that corresponds to your MySQL server version near "
                                f"'{html.escape(ident)}'</pre>")
                return
            self._page(f"<h1>Товар {html.escape(ident)}</h1><p>Описание товара.</p>")
        elif path == "/go":
            target = (query.get("next") or ["/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/.env":
            self._send(200, "APP_DEBUG=true\nDB_PASSWORD=secret123\n", "text/plain")
        elif path == "/.git/config":
            self._send(200, "[core]\n\trepositoryformatversion = 0\n", "text/plain")
        elif path == "/swagger.json":
            self._send(200, '{"openapi": "3.0.0", "paths": {"/api/users": {}}}',
                       "application/json")
        elif path == "/static/app.js":
            self._send(200, "// build path C:\\builds\\shop\\src\\app.js\n"
                            "var db = 'mysql://root:root@10.0.0.5:3306/shop';\n"
                            "//# sourceMappingURL=app.js.map\n",
                       "application/javascript")
        else:
            self._send(404, "<h1>404</h1>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 65536)).decode("utf-8", "replace")
        values = parse_qs(body, keep_blank_values=True)
        username = (values.get("username") or [""])[0]
        # уязвимость: отражение POST-параметра без экранирования
        self._page(f"<h1>Ошибка входа</h1><p>Пользователь {username} не найден.</p>")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, PUT, DELETE, TRACE")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
        self.send_header("Content-Length", "0")
        self.end_headers()


def create_server(port: int = 0) -> ThreadingHTTPServer:
    """Создаёт сервер (port=0 — свободный порт выбирает ОС)."""
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = create_server(port)
    print(f"Тестовое уязвимое приложение: http://127.0.0.1:{server.server_address[1]}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
