"""NVD API 2.0: подбор CPE и выборка CVE с локальной проверкой диапазонов версий.

Что уходит в NVD: только строки CPE (``cpe:2.3:a:vendor:product[:version]``),
название продукта для ``keywordSearch`` и параметры пагинации. URL цели,
cookie и содержимое страниц не передаются.

CVE запрашиваются по ``virtualMatchString=cpe:2.3:a:{vendor}:{product}:*`` —
все CVE продукта; затем версия компонента сверяется локально с
``configurations[].nodes[].cpeMatch[]`` через ``versions.py``. Это надёжнее
``cpeName`` для диапазонов (``versionEndExcluding`` и т. п.), а сжатый ответ
кэшируется на продукт и переиспользуется для любых версий.
"""

from __future__ import annotations

from collections import deque
import os
import re
import time
from typing import Callable, Deque, Dict, List, Optional, Sequence, Set, Tuple

from ..fingerprint import DetectedProduct
from .cache import (FRESH, STALE, UNAVAILABLE, UPDATED, CacheStore, SourceStatus,
                    load_with_cache)
from .catalog_http import CatalogHttpClient
from .versions import EXACT, PLATFORM, PRODUCT_ONLY, RANGE, match_cpe_version

NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/{cve}"

RESULTS_PER_PAGE = 2000     # максимум CVE API 2.0
MAX_PAGES = 10              # до 20 000 CVE на продукт — с запасом
MAX_PAGE_BYTES = 80 * 1024 * 1024
DESCRIPTION_LIMIT = 1500
RATE_WINDOW = 30.0
RATE_LIMIT_ANON = 5         # запросов за 30 с без ключа (правила NVD)
RATE_LIMIT_KEY = 50         # с ключом NVD_API_KEY
CVSS_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
MATCH_RANK = {EXACT: 4, RANGE: 3, PLATFORM: 2, PRODUCT_ONLY: 1}
CACHE_VERSION = 2


class RateLimiter:
    """Скользящее окно: не больше ``limit`` запросов за ``window`` секунд."""

    def __init__(self, limit: int, window: float = RATE_WINDOW,
                 clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.limit = max(1, int(limit))
        self.window = float(window)
        self.clock = clock
        self.sleep = sleep
        self.stamps: Deque[float] = deque()

    def wait(self) -> float:
        waited = 0.0
        now = self.clock()
        while self.stamps and now - self.stamps[0] >= self.window:
            self.stamps.popleft()
        if len(self.stamps) >= self.limit:
            waited = self.stamps[0] + self.window - now + 0.05
            if waited > 0:
                self.sleep(waited)
            now = self.clock()
            while self.stamps and now - self.stamps[0] >= self.window:
                self.stamps.popleft()
        self.stamps.append(self.clock())
        return max(waited, 0.0)


class NvdClient:
    def __init__(self, cache: CacheStore, http: CatalogHttpClient, *, ttl_hours: float,
                 refresh: bool = False, offline: bool = False, api_key: str = "",
                 limiter: Optional[RateLimiter] = None,
                 include_product_only: bool = False,
                 log: Callable[[str], None] = lambda _msg: None) -> None:
        self.cache = cache
        self.http = http
        self.ttl_hours = ttl_hours
        self.refresh = refresh
        self.offline = offline
        self.api_key = api_key if api_key else os.environ.get("NVD_API_KEY", "")
        self.limiter = limiter or RateLimiter(RATE_LIMIT_KEY if self.api_key else RATE_LIMIT_ANON,
                                              sleep=http.sleep)
        self.log = log
        self.status = SourceStatus("NVD")
        self._states: List[SourceStatus] = []
        self.product_notes: Dict[str, str] = {}
        # «Только продукт»: запись NVD без границ версий — это любая версия, а не наша.
        # По умолчанию такие CVE не показываются, чтобы не выдавать весь список продукта.
        self.include_product_only = include_product_only
        self.skipped_product_only: Dict[str, int] = {}
        # CVE, у которых NVD задаёт диапазоны версий, и версия компонента в них не входит:
        # по ним NVD явно говорит «не затронуто» (ключ — ``DetectedProduct.key``).
        self.version_conflicts: Dict[Tuple[str, str, str], Set[str]] = {}

    # --- публичный API -------------------------------------------------------------
    def match_product(self, product: DetectedProduct) -> Tuple[List[dict], List[str]]:
        """CVE, затрагивающие версию компонента, и подтверждённые CPE-пары.

        Каждая запись — сжатая CVE (см. ``_condense``) с полями ``version_match``
        и ``cpe`` (пара vendor:product, по которой найдено совпадение).
        """
        if not product.nvd_eligible:
            return [], []
        best: Dict[str, dict] = {}
        skipped_ids = set()
        outside: Set[str] = set()
        pairs_used: List[str] = []
        for vendor, name in self._candidate_pairs(product):
            cves = self.product_cves(vendor, name)
            if cves is None:
                continue
            pairs_used.append(f"{vendor}:{name}")
            for cve in cves:
                label = _best_match(product.version, cve.get("matches") or [])
                if label is None:
                    outside.add(str(cve["id"]).upper())
                    continue
                if label == PRODUCT_ONLY and not self.include_product_only:
                    skipped_ids.add(cve["id"])
                    continue
                current = best.get(cve["id"])
                if current is None or MATCH_RANK[label] > MATCH_RANK[current["version_match"]]:
                    item = {key: value for key, value in cve.items() if key != "matches"}
                    item["version_match"] = label
                    item["cpe"] = f"cpe:2.3:a:{vendor}:{name}:{product.version}:*:*:*:*:*:*:*"
                    best[cve["id"]] = item
        self.version_conflicts[product.key] = outside - {str(item).upper() for item in best} \
            - {str(item).upper() for item in skipped_ids}
        skipped = len(skipped_ids - set(best))
        if skipped:
            self.skipped_product_only[product.display_name] = skipped
        return list(best.values()), pairs_used

    def finish(self) -> SourceStatus:
        """Сводит состояния отдельных запросов в одно состояние источника."""
        states = self._states
        status = self.status
        status.requests = sum(item.requests for item in states)
        if not states:
            return status
        usable = [item for item in states if item.usable]
        if not usable:
            status.state = next((item.state for item in states if item.state != UNAVAILABLE), UNAVAILABLE)
            status.message = next((item.message for item in states if item.message), "")
        elif any(item.state == STALE for item in usable):
            status.state = STALE
        elif any(item.state == UPDATED for item in usable):
            status.state = UPDATED
        else:
            status.state = FRESH
        dates = sorted(item.data_date for item in usable if item.data_date)
        status.data_date = dates[0] if dates else ""
        errors = [item.message for item in states if item.message and not item.usable]
        if errors and usable:
            status.message = f"часть запросов не выполнена: {errors[0]}"
        return status

    # --- CPE ------------------------------------------------------------------------
    def _candidate_pairs(self, product: DetectedProduct) -> List[Tuple[str, str]]:
        """Пары vendor:product для запроса CVE.

        Для каждой пары из fingerprint проверяется наличие точной CPE в словаре
        (``cpeMatchString`` с версией) — это только диагностика, CVE всё равно
        запрашиваются по продукту. Если пар нет вообще, выполняется
        ``keywordSearch`` по названию продукта с фильтром результатов.
        """
        pairs = [tuple(pair) for pair in product.cpe_pairs]
        found_exact = []
        for vendor, name in pairs:
            data = self._cached_json(
                f"nvd/cpe/{_slug(vendor)}__{_slug(name)}__{_slug(product.version)}.json",
                NVD_CPE_API,
                {"cpeMatchString": f"cpe:2.3:a:{vendor}:{name}:{product.version}",
                 "resultsPerPage": 20},
            )
            if data and int(data.get("totalResults") or 0) > 0:
                found_exact.append(f"{vendor}:{name}")
        if pairs and not found_exact:
            self.product_notes[product.display_name] = (
                "точной CPE для этой версии в словаре NVD нет — совпадения ищутся по диапазонам")
        if pairs:
            return [(str(v), str(n)) for v, n in pairs]
        return self._keyword_pairs(product)

    def _keyword_pairs(self, product: DetectedProduct) -> List[Tuple[str, str]]:
        keyword = (product.label or product.product).strip()
        if not keyword:
            return []
        data = self._cached_json(f"nvd/cpe-keyword/{_slug(keyword)}.json", NVD_CPE_API,
                                 {"keywordSearch": keyword, "resultsPerPage": 100})
        scored: Dict[Tuple[str, str], int] = {}
        for item in (data or {}).get("products", []):
            name = str(((item or {}).get("cpe") or {}).get("cpeName") or "")
            score = score_cpe(name, product)
            parts = _split_cpe(name)
            if score > 0 and len(parts) > 5:
                pair = (parts[3], parts[4])
                scored[pair] = max(scored.get(pair, 0), score)
        return [pair for pair, _ in sorted(scored.items(), key=lambda kv: -kv[1])[:2]]

    # --- CVE ------------------------------------------------------------------------
    def product_cves(self, vendor: str, name: str) -> Optional[List[dict]]:
        """Все CVE продукта в сжатом виде (из кэша или NVD); ``None`` — источник недоступен."""
        cache_name = f"nvd/cves/{_slug(vendor)}__{_slug(name)}.json"
        status = SourceStatus(f"NVD {vendor}:{name}")
        before = self.http.requests_made

        def download(_meta: Dict[str, object]) -> Tuple[bytes, Dict[str, str]]:
            import json
            items: List[dict] = []
            start = 0
            virtual = f"cpe:2.3:a:{vendor}:{name}:*"
            for page in range(MAX_PAGES):
                self.log(f"      ↓ NVD: CVE для {vendor}:{name}"
                         + (f" (стр. {page + 1})" if page else ""))
                data = self._request(NVD_CVE_API, {"virtualMatchString": virtual,
                                                   "resultsPerPage": RESULTS_PER_PAGE,
                                                   "startIndex": start})
                chunk = data.get("vulnerabilities") or []
                items.extend(_condense(wrapper.get("cve") or {}, vendor, name)
                             for wrapper in chunk if isinstance(wrapper, dict))
                total = int(data.get("totalResults") or 0)
                start += len(chunk)
                if not chunk or start >= total:
                    break
            payload = {"version": CACHE_VERSION, "cpe": virtual,
                       "cves": [item for item in items if item]}
            return json.dumps(payload, ensure_ascii=False).encode("utf-8"), {"source_url": NVD_CVE_API}

        raw = load_with_cache(self.cache, cache_name, status, download, ttl_hours=self.ttl_hours,
                              refresh=self.refresh, offline=self.offline, log=self.log,
                              accept=_current_cache_format)
        status.requests = self.http.requests_made - before
        self._states.append(status)
        if raw is None:
            return None
        try:
            import json
            data = json.loads(raw.decode("utf-8"))
            return list(data.get("cves") or [])
        except (ValueError, UnicodeDecodeError, AttributeError):
            status.state = UNAVAILABLE
            status.message = "повреждённый кэш NVD"
            return None

    # --- транспорт --------------------------------------------------------------------
    def _cached_json(self, cache_name: str, url: str, params: dict) -> Optional[dict]:
        import json
        status = SourceStatus("NVD CPE")
        before = self.http.requests_made

        def download(_meta: Dict[str, object]) -> Tuple[bytes, Dict[str, str]]:
            data = self._request(url, params)
            slim = {"totalResults": data.get("totalResults", 0),
                    "products": [{"cpe": {"cpeName": ((item or {}).get("cpe") or {}).get("cpeName", ""),
                                          "deprecated": ((item or {}).get("cpe") or {}).get("deprecated", False)}}
                                 for item in (data.get("products") or [])]}
            return json.dumps(slim).encode("utf-8"), {"source_url": url}

        raw = load_with_cache(self.cache, cache_name, status, download, ttl_hours=self.ttl_hours,
                              refresh=self.refresh, offline=self.offline, log=self.log)
        status.requests = self.http.requests_made - before
        self._states.append(status)
        if raw is None:
            return None
        try:
            value = json.loads(raw.decode("utf-8"))
            return value if isinstance(value, dict) else None
        except (ValueError, UnicodeDecodeError):
            return None

    def _request(self, url: str, params: dict) -> dict:
        self.limiter.wait()
        headers = {"apiKey": self.api_key} if self.api_key else {}
        result = self.http.get(url, params=params, headers=headers, max_bytes=MAX_PAGE_BYTES,
                               label="NVD")
        data = result.json()
        if not isinstance(data, dict):
            raise ValueError("неожиданный формат ответа NVD")
        return data


# --- разбор ответа NVD ------------------------------------------------------------------
def _current_cache_format(raw: bytes) -> bool:
    """Кэш CVE записан текущей версией формата (иначе его надо скачать заново)."""
    import json
    try:
        data = json.loads(raw.decode("utf-8"))
        return int(data.get("version") or 0) >= CACHE_VERSION
    except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
        return False


def _condense(cve: dict, vendor: str, name: str) -> Optional[dict]:
    cve_id = str(cve.get("id") or "").upper()
    if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
        return None
    if str(cve.get("vulnStatus") or "").lower() == "rejected":
        return None
    tags = [str(tag).lower() for tag in cve.get("cveTags") or []]
    if "disputed" in tags or "** DISPUTED **" in _english(cve.get("descriptions")):
        return None  # производитель оспаривает уязвимость — в отчёте это почти всегда шум
    matches = []
    for config in cve.get("configurations") or []:
        nodes = (config or {}).get("nodes") or []
        # «AND»: уязвимость требует ещё и платформу (ОС, оборудование) — её мы не знаем.
        conditional = str((config or {}).get("operator") or "").upper() == "AND" and len(nodes) > 1
        for node in nodes:
            if (node or {}).get("negate"):
                continue
            for entry in (node or {}).get("cpeMatch") or []:
                if not entry.get("vulnerable"):
                    continue
                parts = _split_cpe(str(entry.get("criteria") or ""))
                if len(parts) < 6 or parts[3].lower() != vendor.lower() or parts[4].lower() != name.lower():
                    continue
                matches.append({
                    "v": parts[5],
                    "si": entry.get("versionStartIncluding") or "",
                    "se": entry.get("versionStartExcluding") or "",
                    "ei": entry.get("versionEndIncluding") or "",
                    "ee": entry.get("versionEndExcluding") or "",
                    "p": 1 if conditional else 0,
                })
    if not matches:
        return None
    return {
        "id": cve_id,
        "published": str(cve.get("published") or "")[:10],
        "description": _english(cve.get("descriptions"))[:DESCRIPTION_LIMIT],
        "cvss": pick_cvss(cve.get("metrics") or {}),
        "cwe": _cwes(cve.get("weaknesses") or []),
        "nvd_url": NVD_DETAIL.format(cve=cve_id),
        "matches": matches,
    }


def pick_cvss(metrics: dict) -> Optional[dict]:
    """Первая доступная метрика v4.0 → v3.1 → v3.0 → v2; приоритет у ``Primary``."""
    for key in CVSS_ORDER:
        entries = [item for item in (metrics.get(key) or []) if isinstance(item, dict)]
        if not entries:
            continue
        entry = next((item for item in entries if item.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        try:
            score = float(data.get("baseScore"))
        except (TypeError, ValueError):
            continue
        return {
            "version": str(data.get("version") or key[len("cvssMetricV"):]),
            "score": score,
            "severity": str(data.get("baseSeverity") or entry.get("baseSeverity") or "").upper(),
            "vector": str(data.get("vectorString") or ""),
        }
    return None


def _cwes(weaknesses: Sequence[dict]) -> List[str]:
    ordered = sorted((item for item in weaknesses if isinstance(item, dict)),
                     key=lambda item: item.get("type") != "Primary")
    result: List[str] = []
    for item in ordered:
        for desc in item.get("description") or []:
            value = str((desc or {}).get("value") or "")
            if value.startswith("CWE-") and value not in result:
                result.append(value)
    return result


def _english(values: object) -> str:
    if not isinstance(values, list):
        return ""
    for item in values:
        if isinstance(item, dict) and item.get("lang") == "en":
            return " ".join(str(item.get("value") or "").split())
    return ""


def _best_match(version: str, matches: Sequence[dict]) -> Optional[str]:
    best: Optional[str] = None
    for entry in matches:
        label = match_cpe_version(version, entry.get("v"),
                                  start_including=entry.get("si") or None,
                                  start_excluding=entry.get("se") or None,
                                  end_including=entry.get("ei") or None,
                                  end_excluding=entry.get("ee") or None)
        if label in (EXACT, RANGE) and entry.get("p"):
            label = PLATFORM
        if label and (best is None or MATCH_RANK[label] > MATCH_RANK[best]):
            best = label
            if best == EXACT:
                break
    return best


def score_cpe(cpe: str, product: DetectedProduct) -> int:
    """Насколько CPE из keywordSearch похожа на найденный продукт (0 — не подходит)."""
    parts = _split_cpe(cpe)
    if len(parts) < 6 or parts[2] not in {"a", "o", "h"}:
        return 0
    vendor = parts[3].replace("\\", "").lower()
    name = parts[4].replace("\\", "").lower()
    version = parts[5].replace("\\", "").lower()
    expected_vendor = product.vendor.lower().replace(" ", "_")
    expected_name = product.product.lower().replace(" ", "_").replace("\\", "")
    score = 0
    if name == expected_name:
        score += 60
    elif expected_name and (expected_name in name or name in expected_name):
        score += 30
    else:
        return 0
    if vendor == expected_vendor:
        score += 25
    elif expected_vendor and (expected_vendor in vendor or vendor in expected_vendor):
        score += 10
    if product.version:
        if version == product.version.lower():
            score += 30
        elif version in {"*", "-"}:
            score += 2
        else:
            score -= 15
    return score


def _split_cpe(value: str) -> List[str]:
    return re.split(r"(?<!\\):", value)


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._") or "_"
