"""Файловый кэш справочников уязвимостей.

* Каталог по умолчанию — ``<проект>/.spyvision/cache``, если он есть, иначе
  ``~/.spyvision/cache`` (переопределяется ``--vuln-db-cache`` или переменной
  ``SPYVISION_CACHE_DIR``). Рядом с ним, в ``../bdu``, лежит выгрузка БДУ.
* Рядом с каждым файлом лежит ``<имя>.meta.json``: ``fetched_at``, ``etag``,
  ``last_modified``, ``sha256``, ``source_url``, ``data_date``.
* Запись атомарная (временный файл + ``os.replace``).
* Lock-файл не даёт UI и CLI одновременно качать один и тот же источник.
* Стратегия: свежий кэш → используем; устарел → пробуем обновить, при ошибке
  используем старый с пометкой даты; нет кэша и нет сети → источник недоступен.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Callable, Dict, Iterator, Optional, Tuple

# Состояния источника для отчёта и /api/status
FRESH = "fresh"            # кэш актуален, сеть не понадобилась
UPDATED = "updated"        # данные только что загружены или подтверждены (304)
STALE = "stale"            # обновить не удалось — используем старые данные
UNAVAILABLE = "unavailable"  # нет ни сети, ни кэша
DISABLED = "disabled"      # источник выключен флагом
OFFLINE = "offline"        # --vuln-db-offline и кэша нет
SKIPPED = "skipped"        # не понадобился: нет компонентов с версией

STATE_LABELS = {
    FRESH: "свежий",
    UPDATED: "обновлён",
    STALE: "устаревший",
    UNAVAILABLE: "недоступен",
    DISABLED: "отключён",
    OFFLINE: "офлайн, кэша нет",
    SKIPPED: "не запрашивался",
}

LOCK_WAIT_SECONDS = 600.0   # сколько ждать чужую загрузку того же источника
LOCK_STALE_SECONDS = 1800.0  # lock старше этого считается брошенным
RETRY_AFTER_FAILURE = 3600.0  # после сбоя источник не опрашивается час (кроме --update-vuln-db)


class OfflineRequestError(Exception):
    """Базовый класс «сеть запрещена настройкой» — такие сбои не запоминаются."""


class NotModified(Exception):
    """Сервер ответил 304 — кэш по-прежнему актуален."""


@dataclass
class SourceStatus:
    """Состояние одного справочника после попытки загрузки."""

    name: str
    state: str = UNAVAILABLE
    data_date: str = ""   # ISO-дата данных (когда загружены / дата каталога)
    message: str = ""
    requests: int = 0
    records: int = 0
    extra: Dict[str, object] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.state in (FRESH, UPDATED, STALE)

    @property
    def label(self) -> str:
        text = STATE_LABELS.get(self.state, self.state)
        if self.state == STALE and self.data_date:
            text += f", данные от {format_date(self.data_date)}"
        return text

    def as_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "state": self.state,
            "label": self.label,
            "data_date": self.data_date,
            "message": self.message,
            "requests": self.requests,
            "records": self.records,
        }


def default_cache_dir() -> Path:
    """Кэш внутри папки проекта, если он там создан; иначе кэш пользователя."""
    local = Path(__file__).resolve().parents[2] / ".spyvision" / "cache"
    return local if local.is_dir() else Path.home() / ".spyvision" / "cache"


class CacheStore:
    """Кэш с метаданными, TTL, атомарной записью и lock-файлами."""

    def __init__(self, directory: str = "") -> None:
        base = directory or os.environ.get("SPYVISION_CACHE_DIR", "")
        self.root = Path(base).expanduser() if base else default_cache_dir()
        self.root.mkdir(parents=True, exist_ok=True)

    # --- пути ---------------------------------------------------------------
    def path(self, name: str) -> Path:
        """Путь к файлу кэша. Имя может содержать подкаталоги (``kev/kev.json``)."""
        safe = "/".join(_safe_part(part) for part in str(name).replace("\\", "/").split("/") if part)
        return self.root / safe

    def hashed_name(self, prefix: str, key: str, suffix: str = ".json") -> str:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]
        return f"{prefix}/{digest}{suffix}"

    def meta_path(self, name: str) -> Path:
        path = self.path(name)
        return path.with_name(path.name + ".meta.json")

    # --- метаданные и свежесть ---------------------------------------------
    def meta(self, name: str) -> Dict[str, object]:
        try:
            with self.meta_path(name).open("r", encoding="utf-8") as handle:
                value = json.load(handle)
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def exists(self, name: str) -> bool:
        return self.path(name).is_file()

    def age_seconds(self, name: str) -> Optional[float]:
        meta = self.meta(name)
        try:
            fetched = float(meta.get("fetched_epoch"))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            try:
                fetched = self.path(name).stat().st_mtime
            except OSError:
                return None
        return max(0.0, time.time() - fetched)

    def is_fresh(self, name: str, ttl_hours: float) -> bool:
        age = self.age_seconds(name)
        return age is not None and self.exists(name) and age < max(0.0, ttl_hours) * 3600

    # --- негативный кэш: помнить неудачную попытку -----------------------------
    def fail_path(self, name: str) -> Path:
        path = self.path(name)
        return path.with_name(path.name + ".fail.json")

    def record_failure(self, name: str, message: str) -> None:
        payload = {"failed_at": now_iso(), "failed_epoch": time.time(), "message": message}
        try:
            _atomic_write(self.fail_path(name), json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        except OSError:
            pass

    def recent_failure(self, name: str, window: float = RETRY_AFTER_FAILURE) -> Optional[Dict[str, object]]:
        try:
            with self.fail_path(name).open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if time.time() - float(data.get("failed_epoch")) < window:
                return data if isinstance(data, dict) else None
        except (OSError, ValueError, TypeError):
            pass
        return None

    def clear_failure(self, name: str) -> None:
        try:
            self.fail_path(name).unlink()
        except OSError:
            pass

    def touch(self, name: str) -> None:
        """Отмечает кэш как проверенный сейчас (после 304 Not Modified)."""
        meta = self.meta(name)
        meta["fetched_at"] = now_iso()
        meta["fetched_epoch"] = time.time()
        _atomic_write(self.meta_path(name), json.dumps(meta, ensure_ascii=False).encode("utf-8"))

    # --- чтение и запись ------------------------------------------------------
    def read_bytes(self, name: str) -> Optional[bytes]:
        try:
            return self.path(name).read_bytes()
        except OSError:
            return None

    def read_json(self, name: str) -> Optional[object]:
        raw = self.read_bytes(name)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def write_bytes(self, name: str, data: bytes, *, source_url: str = "", etag: str = "",
                    last_modified: str = "", data_date: str = "") -> None:
        path = self.path(name)
        _atomic_write(path, data)
        meta = {
            "fetched_at": now_iso(),
            "fetched_epoch": time.time(),
            "etag": etag,
            "last_modified": last_modified,
            "sha256": hashlib.sha256(data).hexdigest(),
            "source_url": source_url,
            "data_date": data_date or now_iso(),
            "size": len(data),
        }
        _atomic_write(self.meta_path(name), json.dumps(meta, ensure_ascii=False).encode("utf-8"))

    def write_json(self, name: str, value: object, **meta: str) -> None:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.write_bytes(name, data, **meta)

    def data_date(self, name: str) -> str:
        meta = self.meta(name)
        return str(meta.get("data_date") or meta.get("fetched_at") or "")

    # --- блокировка -------------------------------------------------------------
    @contextmanager
    def lock(self, name: str, wait_seconds: float = LOCK_WAIT_SECONDS,
             sleep: Callable[[float], None] = time.sleep) -> Iterator[bool]:
        """Эксклюзивная блокировка источника между процессами.

        Отдаёт ``True``, если блокировка получена, и ``False``, если другой
        процесс так и не закончил загрузку за ``wait_seconds`` — тогда вызывающий
        код работает с тем кэшем, что есть.
        """
        lock_path = self.path(name).with_name(self.path(name).name + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + max(0.0, wait_seconds)
        acquired = False
        while True:
            try:
                fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                with os.fdopen(fd, "w") as handle:
                    handle.write(f"{os.getpid()} {now_iso()}")
                acquired = True
                break
            except FileExistsError:
                try:
                    if time.time() - lock_path.stat().st_mtime > LOCK_STALE_SECONDS:
                        lock_path.unlink()
                        continue
                except OSError:
                    continue
                if time.monotonic() >= deadline:
                    break
                sleep(0.5)
            except OSError:
                break  # каталог только для чтения и т. п. — работаем без блокировки
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    lock_path.unlink()
                except OSError:
                    pass


def load_with_cache(
    cache: CacheStore,
    name: str,
    status: SourceStatus,
    download: Callable[[Dict[str, object]], Tuple[bytes, Dict[str, str]]],
    *,
    ttl_hours: float,
    refresh: bool = False,
    offline: bool = False,
    log: Callable[[str], None] = lambda _msg: None,
    accept: Optional[Callable[[bytes], bool]] = None,
) -> Optional[bytes]:
    """Общая стратегия «свежий кэш → обновление → устаревший кэш».

    ``download(meta)`` получает метаданные кэша (для ETag / If-Modified-Since)
    и возвращает ``(данные, {"etag", "last_modified", "source_url", "data_date"})``
    или бросает ``NotModified``. Любая другая ошибка превращается в устаревший
    кэш либо в состояние «недоступен» — исключения наружу не выходят.

    ``accept(данные)`` — проверка формата кэша: свежий файл, не прошедший её
    (например, старой версии), считается устаревшим и скачивается заново.
    """
    def usable() -> bool:
        if not cache.is_fresh(name, ttl_hours):
            return False
        if accept is None:
            return True
        raw = cache.read_bytes(name)
        return raw is not None and accept(raw)

    if not refresh and usable():
        status.state = FRESH
        status.data_date = cache.data_date(name)
        return cache.read_bytes(name)
    if offline:
        if cache.exists(name):
            status.state = STALE if not cache.is_fresh(name, ttl_hours) else FRESH
            status.data_date = cache.data_date(name)
            status.message = "офлайн-режим: использован кэш без обновления"
            return cache.read_bytes(name)
        status.state = OFFLINE
        status.message = "офлайн-режим, а локальной копии нет"
        return None

    failure = None if refresh else cache.recent_failure(name)
    if failure is not None:
        # Недавно источник не ответил — не тратим время скана на повторные таймауты.
        retry_in = max(1, int((RETRY_AFTER_FAILURE - (time.time() - float(failure["failed_epoch"]))) // 60))
        status.message = (f"недоступен при попытке {format_date(str(failure.get('failed_at')))} "
                          f"{str(failure.get('failed_at'))[11:16]} UTC ({failure.get('message')}); "
                          f"повтор через ~{retry_in} мин или с --update-vuln-db")
        if cache.exists(name):
            status.state = STALE
            status.data_date = cache.data_date(name)
            return cache.read_bytes(name)
        status.state = UNAVAILABLE
        return None

    with cache.lock(name) as acquired:
        # Пока ждали блокировку, другой процесс мог обновить файл.
        if acquired and not refresh and usable():
            status.state = FRESH
            status.data_date = cache.data_date(name)
            return cache.read_bytes(name)
        try:
            data, meta = download(cache.meta(name) if cache.exists(name) else {})
            cache.write_bytes(name, data, **{key: str(value or "") for key, value in meta.items()})
            cache.clear_failure(name)
            status.state = UPDATED
            status.data_date = cache.data_date(name)
            return data
        except NotModified:
            cache.touch(name)
            cache.clear_failure(name)
            status.state = UPDATED
            status.data_date = cache.data_date(name)
            status.message = "не изменился с прошлой загрузки (304)"
            return cache.read_bytes(name)
        except Exception as exc:  # noqa: BLE001 - сбой источника не должен ломать скан
            status.message = short_error(exc)
            log(f"      ! {status.name}: {status.message}")
            if not isinstance(exc, OfflineRequestError):
                cache.record_failure(name, status.message)
            if cache.exists(name):
                status.state = STALE
                status.data_date = cache.data_date(name)
                return cache.read_bytes(name)
            status.state = UNAVAILABLE
            return None


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def format_date(value: str) -> str:
    """ISO-дата → ДД.ММ.ГГГГ (для отчёта)."""
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})", str(value or ""))
    return f"{match.group(3)}.{match.group(2)}.{match.group(1)}" if match else str(value or "")


def short_error(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or exc.__class__.__name__
    return text[:300]


def _safe_part(part: str) -> str:
    part = re.sub(r"[^A-Za-z0-9._-]+", "_", part)
    return part.strip(".") or "_"


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, tmp_name = tempfile.mkstemp(prefix=path.name, suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
