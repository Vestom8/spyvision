"""Локальный HTTP-сервер главного экрана Spyvision (только 127.0.0.1)."""

from __future__ import annotations

import json
import mimetypes
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import unquote, urlparse

from .cli import normalize_target, sanitize_url
from .landing import ensure_background, load_landing_html, write_landing
from .report import build_report
from .scanner import ScanConfig, run_scan
from .utils import host_of, is_valid_host


class UiState:
    """Состояние UI: одно сканирование за раз."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.scanning = False
        self.report_ready = False
        self.last_error: Optional[str] = None
        self.last_target: Optional[str] = None


def run_scan_to_report(config: ScanConfig) -> str:
    """Выполняет скан и сохраняет HTML-отчёт. Возвращает абсолютный путь к файлу."""
    result = run_scan(config)
    html = build_report(result.findings, result.stats)
    output_path = os.path.abspath(config.output)
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return output_path


def make_handler(workdir: Path, defaults: Dict[str, Any], state: UiState):
    """Фабрика обработчика HTTP с замыканием на каталог и параметры скана."""

    report_name = Path(str(defaults.get("output", "report.html"))).name or "report.html"

    class Handler(BaseHTTPRequestHandler):
        server_version = "SpyvisionUI/1.0"

        def log_message(self, fmt: str, *args) -> None:
            # Тихий лог: только важные события печатает serve_ui
            pass

        def _send(self, code: int, body: bytes, content_type: str,
                  extra_headers: Optional[Dict[str, str]] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if extra_headers:
                for key, value in extra_headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, code: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(code, data, "application/json; charset=utf-8")

        def _safe_path(self, url_path: str) -> Optional[Path]:
            """Разрешает путь только внутри workdir (без выхода наружу)."""
            raw = unquote(url_path.split("?", 1)[0])
            if raw in ("", "/"):
                raw = "/index.html"
            rel = raw.lstrip("/").replace("\\", "/")
            if ".." in rel.split("/"):
                return None
            candidate = (workdir / rel).resolve()
            try:
                candidate.relative_to(workdir.resolve())
            except ValueError:
                return None
            return candidate

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/status":
                with state.lock:
                    self._send_json(200, {
                        "scanning": state.scanning,
                        "report_ready": state.report_ready,
                        "last_error": state.last_error,
                        "last_target": state.last_target,
                    })
                return

            file_path = self._safe_path(path)
            if file_path is None:
                self._send_json(400, {"ok": False, "error": "Некорректный путь"})
                return

            if path in ("/", "/index.html"):
                # Отдаём шаблон из памяти — без перезаписи index.html на каждый запрос.
                try:
                    body = load_landing_html().encode("utf-8")
                except OSError as exc:
                    self._send_json(500, {"ok": False, "error": str(exc)})
                    return
                self._send(200, body, "text/html; charset=utf-8")
                return

            if not file_path.is_file():
                if file_path.name == report_name:
                    self._send_json(404, {
                        "ok": False,
                        "error": "Отчёт ещё не готов. Сначала запустите сканирование.",
                    })
                else:
                    self._send(404, b"Not found", "text/plain; charset=utf-8")
                return

            content_type, _ = mimetypes.guess_type(str(file_path))
            if not content_type:
                content_type = "application/octet-stream"
            if content_type.startswith("text/") or content_type in (
                "application/javascript", "application/json",
            ):
                content_type = f"{content_type}; charset=utf-8"
            try:
                body = file_path.read_bytes()
            except OSError as exc:
                self._send_json(500, {"ok": False, "error": str(exc)})
                return
            self._send(200, body, content_type)

        def _read_json_body(self, max_length: int = 1_000_000) -> tuple:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length < 0 or length > max_length:
                return None, "Слишком большой запрос"
            raw = self.rfile.read(length) if length else b"{}"
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return None, "Ожидается JSON"
            if not isinstance(payload, dict):
                return None, "Ожидается JSON-объект"
            return payload, None

        def _handle_gigachat_chat(self) -> None:
            from .gigachat_fix import ask_gigachat, is_configured

            if not is_configured():
                self._send_json(503, {
                    "ok": False,
                    "error": (
                        "GigaChat не настроен. Пропишите ключ в "
                        "webscan/gigachat_fix.py → GIGACHAT_API_KEY "
                        "или в переменной окружения GIGACHAT_API_KEY."
                    ),
                })
                return

            payload, err = self._read_json_body(max_length=400_000)
            if err:
                self._send_json(400, {"ok": False, "error": err})
                return

            message = str(payload.get("message", "") or "").strip()
            if not message:
                self._send_json(400, {"ok": False, "error": "Укажите сообщение"})
                return

            history = payload.get("history") or []
            if not isinstance(history, list):
                history = []
            context = payload.get("context") or {}
            if not isinstance(context, dict):
                context = {}

            try:
                answer = ask_gigachat(message, history=history, context=context)
                self._send_json(200, {"ok": True, "reply": answer})
            except ValueError as exc:
                self._send_json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                print(f"[UI] GigaChat: {exc}")
                self._send_json(502, {
                    "ok": False,
                    "error": f"Не удалось получить ответ GigaChat: {exc}",
                })

        def _handle_scan(self) -> None:
            payload, err = self._read_json_body()
            if err:
                self._send_json(400, {
                    "ok": False,
                    "error": err if err != "Ожидается JSON" else "Ожидается JSON с полем url",
                })
                return

            raw_url = sanitize_url(str(payload.get("url", "") or ""))
            if not raw_url:
                self._send_json(400, {"ok": False, "error": "Укажите адрес для сканирования"})
                return

            try:
                target = normalize_target(raw_url)
            except Exception as exc:  # noqa: BLE001
                self._send_json(400, {"ok": False, "error": f"Некорректный URL: {exc}"})
                return

            scheme = urlparse(target).scheme.lower()
            if scheme not in ("http", "https"):
                self._send_json(400, {
                    "ok": False,
                    "error": f"Схема «{scheme}» не поддерживается: нужен http или https.",
                })
                return
            if not is_valid_host(host_of(target)):
                self._send_json(400, {
                    "ok": False,
                    "error": "Не удалось разобрать имя хоста. Пример: https://example.com",
                })
                return

            with state.lock:
                if state.scanning:
                    self._send_json(409, {
                        "ok": False,
                        "error": "Сканирование уже выполняется. Дождитесь завершения.",
                    })
                    return
                state.scanning = True
                state.last_error = None
                state.report_ready = False
                state.last_target = target

            print(f"\n[UI] Сканирование: {target}")
            config = ScanConfig(
                url=target,
                max_pages=int(defaults["max_pages"]),
                max_depth=int(defaults["max_depth"]),
                output=str(defaults["output"]),
                max_requests=int(defaults["max_requests"]),
                timeout=float(defaults["timeout"]),
                delay=float(defaults["delay"]),
                verify_tls=bool(defaults["verify_tls"]),
                active=bool(defaults["active"]),
                test_post_forms=bool(defaults["test_post_forms"]),
                verbose=bool(defaults["verbose"]),
                use_gigachat=bool(defaults.get("use_gigachat", True)),
            )

            try:
                run_scan_to_report(config)
                with state.lock:
                    state.scanning = False
                    state.report_ready = True
                    state.last_error = None
                report_url = "/" + report_name
                print(f"[UI] Готово. Отчёт: {os.path.abspath(config.output)}")
                self._send_json(200, {
                    "ok": True,
                    "report_url": report_url,
                    "target": target,
                })
            except ValueError as exc:
                with state.lock:
                    state.scanning = False
                    state.last_error = str(exc)
                print(f"[UI] Ошибка: {exc}")
                self._send_json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                with state.lock:
                    state.scanning = False
                    state.last_error = str(exc)
                print(f"[UI] Ошибка сканирования: {exc}")
                self._send_json(500, {"ok": False, "error": f"Ошибка сканирования: {exc}"})

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/api/gigachat-chat":
                self._handle_gigachat_chat()
                return
            if parsed.path == "/api/scan":
                self._handle_scan()
                return
            self._send_json(404, {"ok": False, "error": "Неизвестный API-путь"})

    return Handler


def serve_ui(
    *,
    max_pages: int,
    max_depth: int,
    output: str,
    max_requests: int,
    timeout: float,
    delay: float,
    verify_tls: bool = True,
    active: bool = True,
    test_post_forms: bool = True,
    verbose: bool = False,
    use_gigachat: bool = True,
    port: int = 0,
    open_browser: bool = True,
    workdir: Optional[str] = None,
) -> int:
    """Поднимает UI на 127.0.0.1 и блокируется до Ctrl+C. Возвращает код выхода."""
    root = Path(workdir or os.getcwd()).resolve()
    try:
        write_landing(root)
        ensure_background(root)
    except OSError as exc:
        print(f"Не удалось записать главный экран: {exc}", flush=True)
        return 3

    defaults = {
        "max_pages": max_pages,
        "max_depth": max_depth,
        "output": output,
        "max_requests": max_requests,
        "timeout": timeout,
        "delay": delay,
        "verify_tls": verify_tls,
        "active": active,
        "test_post_forms": test_post_forms,
        "verbose": verbose,
        "use_gigachat": use_gigachat,
    }
    state = UiState()
    handler = make_handler(root, defaults, state)

    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    except OSError as exc:
        print(f"Не удалось запустить локальный сервер на порту {port}: {exc}", flush=True)
        return 3

    host, bound_port = server.server_address[:2]
    url = f"http://{host}:{bound_port}/"
    print("=" * 72)
    print("Spyvision — локальный интерфейс")
    print(f"Откройте в браузере: {url}")
    print("Остановка: Ctrl+C")
    print("=" * 72, flush=True)

    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nСервер остановлен.", flush=True)
    finally:
        server.server_close()
    return 0
