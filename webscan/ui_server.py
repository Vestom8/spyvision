"""Локальный HTTP-интерфейс Spyvision: главный экран → скан → отчёт."""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .landing import landing_html, write_landing
from .report import REPORT_BG_NAME, build_report, ensure_report_bg, report_bg_source
from .scanner import ScanConfig, run_scan
from .utils import host_of, is_valid_host


class UiConfig:
    """Параметры UI и сканирования для локального сервера."""

    def __init__(
        self,
        work_dir: str,
        landing_name: str = "index.html",
        report_name: str = "report.html",
        max_pages: int = 40,
        max_depth: int = 8,
        max_requests: int = 400,
        timeout: float = 5.0,
        delay: float = 0.5,
        verify_tls: bool = True,
        active: bool = True,
        test_post_forms: bool = True,
        verbose: bool = False,
        use_gigachat: bool = True,
    ) -> None:
        self.work_dir = os.path.abspath(work_dir)
        self.landing_name = landing_name
        self.report_name = report_name
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.max_requests = max_requests
        self.timeout = timeout
        self.delay = delay
        self.verify_tls = verify_tls
        self.active = active
        self.test_post_forms = test_post_forms
        self.verbose = verbose
        self.use_gigachat = use_gigachat
        self.lock = threading.Lock()
        self.scanning = False
        self.last_error = ""

    @property
    def landing_path(self) -> str:
        return os.path.join(self.work_dir, self.landing_name)

    @property
    def report_path(self) -> str:
        return os.path.join(self.work_dir, self.report_name)


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def _send_file(handler: BaseHTTPRequestHandler, path: str, content_type: str) -> None:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError:
        handler.send_error(404, "Not found")
        return
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def _send_bytes(handler: BaseHTTPRequestHandler, data: bytes, content_type: str,
                status: int = 200) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(data)


def validate_scan_url(raw: str) -> tuple[Optional[str], str]:
    """Проверяет и нормализует URL. Возвращает (target, error)."""
    # Импорт здесь, чтобы не создавать цикл cli ↔ ui_server
    from .cli import normalize_target, sanitize_url

    candidate = sanitize_url(raw or "")
    if not candidate:
        return None, "Введите адрес для сканирования"
    target = normalize_target(candidate)
    scheme = urlparse(target).scheme.lower()
    if scheme not in ("http", "https"):
        return None, f"Схема «{scheme}» не поддерживается: нужен http или https"
    if not is_valid_host(host_of(target)):
        return None, "Не удалось разобрать имя хоста. Пример: https://example.com"
    return target, ""


def run_scan_to_report(cfg: UiConfig, target: str) -> tuple[bool, str]:
    """Запускает скан и пишет report.html. Возвращает (ok, error)."""
    config = ScanConfig(
        url=target,
        max_pages=cfg.max_pages,
        max_depth=cfg.max_depth,
        output=cfg.report_path,
        max_requests=cfg.max_requests,
        timeout=cfg.timeout,
        delay=cfg.delay,
        verify_tls=cfg.verify_tls,
        active=cfg.active,
        test_post_forms=cfg.test_post_forms,
        verbose=cfg.verbose,
        use_gigachat=cfg.use_gigachat,
    )
    try:
        result = run_scan(config)
    except ValueError as exc:
        return False, str(exc)
    except Exception as exc:  # noqa: BLE001 — отдаём текст в UI
        return False, f"Сканирование прервалось: {exc}"

    html = build_report(result.findings, result.stats)
    try:
        os.makedirs(cfg.work_dir, exist_ok=True)
        with open(cfg.report_path, "w", encoding="utf-8") as handle:
            handle.write(html)
        ensure_report_bg(cfg.work_dir)
    except OSError as exc:
        return False, f"Не удалось сохранить отчёт: {exc}"
    return True, ""


def make_handler(cfg: UiConfig):
    class Handler(BaseHTTPRequestHandler):
        server_version = "SpyvisionUI/1.0"

        def log_message(self, fmt: str, *args) -> None:
            print(f"[ui] {self.address_string()} - {fmt % args}")

        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                data = landing_html().encode("utf-8")
                _send_bytes(self, data, "text/html; charset=utf-8")
                return
            if path in ("/report.html", f"/{cfg.report_name}"):
                if not os.path.isfile(cfg.report_path):
                    self.send_error(404, "Отчёт ещё не создан. Сначала нажмите «Сканировать».")
                    return
                _send_file(self, cfg.report_path, "text/html; charset=utf-8")
                return
            if path in (f"/{REPORT_BG_NAME}", "/bg.jfif", "/bg.jpg"):
                work_bg = os.path.join(cfg.work_dir, REPORT_BG_NAME)
                source = work_bg if os.path.isfile(work_bg) else None
                if source is None:
                    bg = report_bg_source()
                    source = str(bg) if bg is not None else None
                if not source or not os.path.isfile(source):
                    self.send_error(404, "Background not found")
                    return
                _send_file(self, source, "image/jpeg")
                return
            if path == "/api/status":
                _json_response(self, 200, {
                    "scanning": cfg.scanning,
                    "report_ready": os.path.isfile(cfg.report_path),
                    "last_error": cfg.last_error,
                })
                return
            self.send_error(404, "Not found")

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if path == "/api/gigachat-chat":
                self._handle_gigachat_chat()
                return
            if path != "/api/scan":
                self.send_error(404, "Not found")
                return
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                _json_response(self, 400, {"ok": False, "error": "Ожидался JSON с полем url"})
                return
            if not isinstance(payload, dict):
                _json_response(self, 400, {"ok": False, "error": "Ожидался JSON-объект"})
                return

            target, error = validate_scan_url(str(payload.get("url", "")))
            if error or not target:
                _json_response(self, 400, {"ok": False, "error": error or "Некорректный URL"})
                return

            if not cfg.lock.acquire(blocking=False):
                _json_response(self, 409, {
                    "ok": False,
                    "error": "Сканирование уже выполняется. Дождитесь завершения.",
                })
                return
            cfg.scanning = True
            cfg.last_error = ""
            try:
                print(f"[ui] Сканирование: {target}")
                ok, scan_error = run_scan_to_report(cfg, target)
                if not ok:
                    cfg.last_error = scan_error
                    _json_response(self, 500, {"ok": False, "error": scan_error})
                    return
                print(f"[ui] Отчёт сохранён: {cfg.report_path}")
                _json_response(self, 200, {
                    "ok": True,
                    "report_url": f"/{cfg.report_name}",
                    "target": target,
                })
            finally:
                cfg.scanning = False
                cfg.lock.release()

        def _handle_gigachat_chat(self) -> None:
            """POST /api/gigachat-chat — ответ ассистента для окна диалога в отчёте.

            Тело JSON: { question, history: [{role, content}, ...], target }.
            Ключ API берётся только на сервере из gigachat_fix.py (в браузер не отдаётся).
            """
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                _json_response(self, 400, {"ok": False, "error": "Ожидался JSON"})
                return
            if not isinstance(payload, dict):
                _json_response(self, 400, {"ok": False, "error": "Ожидался JSON-объект"})
                return

            from .gigachat_fix import ask_gigachat, is_configured

            if not is_configured():
                _json_response(self, 503, {
                    "ok": False,
                    "error": "GigaChat не настроен: укажите ключ в webscan/gigachat_fix.py",
                })
                return

            question = str(payload.get("question", ""))
            history = payload.get("history") or []
            if not isinstance(history, list):
                history = []
            target = str(payload.get("target", "") or "")
            try:
                answer = ask_gigachat(question, history=history, target=target)
            except ValueError as exc:
                _json_response(self, 400, {"ok": False, "error": str(exc)})
                return
            except Exception as exc:  # noqa: BLE001
                _json_response(self, 502, {
                    "ok": False,
                    "error": f"GigaChat не ответил: {exc}",
                })
                return
            _json_response(self, 200, {"ok": True, "answer": answer})

    return Handler


def serve_ui(cfg: UiConfig, host: str = "127.0.0.1", port: int = 0,
             open_browser: bool = True) -> int:
    """Пишет главный экран, поднимает сервер, открывает браузер. Блокирует до Ctrl+C."""
    os.makedirs(cfg.work_dir, exist_ok=True)
    landing_path = write_landing(cfg.landing_path)
    ensure_report_bg(cfg.work_dir)

    handler = make_handler(cfg)
    server = ThreadingHTTPServer((host, port), handler)
    bound_host, bound_port = server.server_address[:2]
    base = f"http://{bound_host}:{bound_port}"

    print("=" * 72)
    print("Spyvision — веб-интерфейс")
    print(f"Главный экран сохранён: {landing_path}")
    print(f"Откройте в браузере: {base}/")
    print("Введите URL на главном экране и нажмите «Сканировать».")
    print("Остановка: Ctrl+C")
    print("=" * 72)

    if open_browser:
        try:
            webbrowser.open(f"{base}/")
        except Exception:  # noqa: BLE001
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nВеб-интерфейс остановлен.")
    finally:
        server.server_close()
    return 0
