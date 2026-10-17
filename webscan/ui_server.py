"""Локальный HTTP-сервер главного экрана Spyvision (только 127.0.0.1)."""

from __future__ import annotations

import json
import mimetypes
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

from .cli import normalize_target, sanitize_url
from .landing import ensure_background, load_landing_html, write_landing
from .http_client import DEFAULT_CONCURRENCY
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
        self.stage: str = ""  # название текущего этапа скана для главного экрана
        # Состояние справочников после последнего скана (для /api/status)
        self.vuln_db: Optional[Dict[str, Dict[str, str]]] = None


def run_scan_to_report(config: ScanConfig, state: Optional["UiState"] = None) -> str:
    """Выполняет скан и сохраняет HTML-отчёт. Возвращает абсолютный путь к файлу."""
    if state is not None:
        def set_stage(message: str) -> None:
            with state.lock:
                state.stage = message

        config.progress = set_stage
    result = run_scan(config)
    if state is not None:
        with state.lock:
            state.stage = ""
            state.vuln_db = vuln_db_status(result.stats.get("vulnerability_intelligence") or {})
    html = build_report(result.findings, result.stats)
    output_path = os.path.abspath(config.output)
    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return output_path


VULN_DB_KEYS = (("nvd", "NVD"), ("kev", "CISA KEV"), ("exploitdb", "ExploitDB"),
                ("bdu", "БДУ ФСТЭК"))


def vuln_db_status(intel: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """``{nvd, kev, exploitdb: {state, data_date}}`` по итогам скана."""
    sources = dict(intel.get("sources") or {})
    result: Dict[str, Dict[str, str]] = {}
    for key, name in VULN_DB_KEYS:
        item = dict(sources.get(name) or {})
        result[key] = {"state": str(item.get("state") or ("disabled" if not intel.get("enabled")
                                                         else "unknown")),
                       "data_date": str(item.get("data_date") or "")}
    return result


def vuln_db_snapshot(defaults: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    """До первого скана — состояние локального кэша (без сети)."""
    if not defaults.get("use_vuln_db", True):
        return {key: {"state": "disabled", "data_date": ""} for key, _name in VULN_DB_KEYS}
    try:
        from .vulndb import sources_snapshot
        snapshot = sources_snapshot(str(defaults.get("vuln_db_cache_dir", "")))
    except Exception:  # noqa: BLE001 - статус не должен ронять UI
        snapshot = {}
    return {key: {"state": str((snapshot.get(key) or {}).get("state") or "unknown"),
                  "data_date": str((snapshot.get(key) or {}).get("data_date") or "")}
            for key, _name in VULN_DB_KEYS}


def make_handler(workdir: Path, defaults: Dict[str, Any], state: UiState):
    """Фабрика обработчика HTTP с замыканием на каталог и параметры скана."""

    _output_setting = Path(str(defaults.get("output", "report.html")))
    report_name = _output_setting.name or "report.html"
    # Отчёт сканер пишет по пути --output, который может быть абсолютным и лежать вне
    # workdir (рабочего каталога главного экрана). Запоминаем его настоящее место, чтобы
    # /report.html всегда отдавал именно записанный файл, а не одноимённый файл в workdir.
    report_path = (
        _output_setting if _output_setting.is_absolute() else workdir / _output_setting
    ).resolve()
    # Отдаём только файлы интерфейса: рабочий каталог может содержать исходники, .git и секреты.
    public_files = {"index.html", "bg.jfif", report_name}

    class Handler(BaseHTTPRequestHandler):
        server_version = "SpyvisionUI/1.0"
        timeout = 60  # зависшее чтение запроса не держит поток бесконечно

        def _trusted_host(self) -> bool:
            """Защита от DNS rebinding: Host должен быть локальным адресом нашего порта."""
            host = (self.headers.get("Host") or "").strip().lower()
            if not host:
                return True
            port = self.server.server_address[1]
            return host in (f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}")

        def _trusted_origin(self) -> bool:
            """Защита от CSRF: запросы с другой страницы (чужой Origin) отклоняются."""
            origin = (self.headers.get("Origin") or "").strip().lower()
            if not origin:
                return True
            port = self.server.server_address[1]
            return origin in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")

        def log_message(self, fmt: str, *args) -> None:
            # Тихий лог: только важные события печатает serve_ui
            pass

        def _send(self, code: int, body: bytes, content_type: str,
                  extra_headers: Optional[Dict[str, str]] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Referrer-Policy", "no-referrer")
            if extra_headers:
                for key, value in extra_headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, code: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(code, data, "application/json; charset=utf-8")

        def _safe_path(self, url_path: str) -> Optional[Path]:
            """Разрешает путь только внутри workdir (без выхода наружу).

            Исключение — сам файл отчёта: он отдаётся по настоящему пути из --output,
            который оператор может указать вне workdir (см. ``report_path`` выше).
            """
            raw = unquote(url_path.split("?", 1)[0])
            if raw in ("", "/"):
                raw = "/index.html"
            rel = raw.lstrip("/").replace("\\", "/")
            if rel not in public_files:
                return None
            if rel == report_name:
                return report_path
            if ".." in rel.split("/"):
                return None
            candidate = (workdir / rel).resolve()
            try:
                candidate.relative_to(workdir.resolve())
            except ValueError:
                return None
            return candidate

        def do_GET(self) -> None:  # noqa: N802
            if not self._trusted_host():
                self._send_json(403, {"ok": False, "error": "Недопустимый Host"})
                return
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/api/status":
                with state.lock:
                    self._send_json(200, {
                        "scanning": state.scanning,
                        "report_ready": state.report_ready,
                        "last_error": state.last_error,
                        "last_target": state.last_target,
                        "stage": state.stage,
                        "vuln_db": state.vuln_db or vuln_db_snapshot(defaults),
                        # Режим pentest требует активных проверок; если сервер запущен с
                        # --no-active, главный экран отключает переключатель pentest.
                        "active": bool(defaults.get("active", True)),
                        # Если сервер запущен с --pentest --i-have-permission-to-attack,
                        # главный экран заранее включает переключатель и согласие — но
                        # оператор видит это явно и может снять галочку перед сканом.
                        # Согласие на КОНКРЕТНОЕ сканирование всё равно проверяется в
                        # _handle_scan по полям запроса, а не по этому значению.
                        "pentest_default": bool(defaults.get("pentest", False)),
                    })
                return

            file_path = self._safe_path(path)
            if file_path is None:
                self._send(404, b"Not found", "text/plain; charset=utf-8")
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
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                return None, "Некорректный Content-Length"
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

            # Режим --pentest включается только на это конкретное сканирование и только
            # при обоих условиях: переключатель и явное подтверждение полномочий оператора.
            # Серверные значения по умолчанию (--pentest при запуске UI) здесь не используются —
            # согласие должно даваться отдельно для каждой цели, которую вводит оператор.
            pentest_requested = bool(payload.get("pentest", False))
            pentest_consent = bool(payload.get("pentest_consent", False))
            if pentest_requested and not pentest_consent:
                self._send_json(400, {
                    "ok": False,
                    "error": "Для режима pentest подтвердите, что у вас есть разрешение "
                             "владельца на тестирование этого адреса такими методами.",
                })
                return
            if pentest_requested and not bool(defaults["active"]):
                self._send_json(400, {
                    "ok": False,
                    "error": "Режим pentest требует активные проверки "
                             "(сервер запущен с --no-active).",
                })
                return
            pentest = pentest_requested and pentest_consent
            pentest_authorized_by = (
                os.environ.get("USERNAME") or os.environ.get("USER") or ""
            ) if pentest else ""

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
                pentest=pentest,
                pentest_authorized_by=pentest_authorized_by,
                verbose=bool(defaults["verbose"]),
                concurrency=int(defaults.get("concurrency", DEFAULT_CONCURRENCY)),
                use_vuln_db=bool(defaults.get("use_vuln_db", True)),
                vuln_db_refresh=bool(defaults.get("vuln_db_refresh", False)),
                vuln_db_ttl_hours=float(defaults.get("vuln_db_ttl_hours", 24.0)),
                vuln_db_cache_dir=str(defaults.get("vuln_db_cache_dir", "")),
                vuln_db_offline=bool(defaults.get("vuln_db_offline", False)),
                nvd_api_key=str(defaults.get("nvd_api_key", "")),
                use_exploitdb=bool(defaults.get("use_exploitdb", True)),
                use_bdu=bool(defaults.get("use_bdu", True)),
                bdu_file=str(defaults.get("bdu_file", "")),
                fstec_component_type=str(defaults.get("fstec_component_type", "server")),
                fstec_perimeter=str(defaults.get("fstec_perimeter", "auto")),
                components_files=list(defaults.get("components_files") or []),
                vuln_max_cves=int(defaults.get("vuln_max_cves", 200)),
            )

            try:
                run_scan_to_report(config, state)
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
                    state.stage = ""
                    state.last_error = str(exc)
                print(f"[UI] Ошибка: {exc}")
                self._send_json(400, {"ok": False, "error": str(exc)})
            except Exception as exc:  # noqa: BLE001
                with state.lock:
                    state.scanning = False
                    state.stage = ""
                    state.last_error = str(exc)
                print(f"[UI] Ошибка сканирования: {exc}")
                self._send_json(500, {"ok": False, "error": f"Ошибка сканирования: {exc}"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._trusted_host() or not self._trusted_origin():
                self._send_json(403, {"ok": False, "error": "Запрос отклонён: чужой Origin или Host"})
                return
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if content_type != "application/json":
                self._send_json(415, {"ok": False, "error": "Ожидается Content-Type: application/json"})
                return
            parsed = urlparse(self.path)
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
    concurrency: int = DEFAULT_CONCURRENCY,
    pentest: bool = False,
    pentest_authorized_by: str = "",
    use_vuln_db: bool = True,
    vuln_db_refresh: bool = False,
    vuln_db_ttl_hours: float = 24.0,
    vuln_db_cache_dir: str = "",
    vuln_db_offline: bool = False,
    nvd_api_key: str = "",
    use_exploitdb: bool = True,
    use_bdu: bool = True,
    bdu_file: str = "",
    fstec_component_type: str = "server",
    fstec_perimeter: str = "auto",
    components_files: Optional[List[str]] = None,
    vuln_max_cves: int = 200,
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
        "concurrency": concurrency,
        "pentest": pentest,
        "pentest_authorized_by": pentest_authorized_by,
        "use_vuln_db": use_vuln_db,
        "vuln_db_refresh": vuln_db_refresh,
        "vuln_db_ttl_hours": vuln_db_ttl_hours,
        "vuln_db_cache_dir": vuln_db_cache_dir,
        "vuln_db_offline": vuln_db_offline,
        "nvd_api_key": nvd_api_key,
        "use_exploitdb": use_exploitdb,
        "use_bdu": use_bdu,
        "bdu_file": bdu_file,
        "fstec_component_type": fstec_component_type,
        "fstec_perimeter": fstec_perimeter,
        "components_files": list(components_files or []),
        "vuln_max_cves": vuln_max_cves,
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
    if pentest:
        print("Режим: --pentest заранее включён на главном экране (переключатель и согласие "
              "предзаполнены) — подтверждено оператором при запуске: "
              f"{pentest_authorized_by or '(не определён)'}. Согласие на каждое конкретное "
              "сканирование оператор всё равно подтверждает в интерфейсе.")
        print("Используйте только для систем, на тестирование которых у вас есть разрешение "
              "владельца.")
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
