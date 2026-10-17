"""CISA Known Exploited Vulnerabilities: загрузка и индекс по CVE.

Каталог скачивается целиком (~2 МБ JSON) и сопоставляется локально. Повторная
загрузка учитывает ``ETag``/``Last-Modified``: при ответе 304 кэш просто
помечается как проверенный.
"""

from __future__ import annotations

import json
import re
from typing import Callable, Dict, Optional, Tuple

from .cache import CacheStore, NotModified, SourceStatus, load_with_cache
from .catalog_http import CatalogHttpClient

KEV_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    # Официальное зеркало CISA на GitHub — если сайт CISA недоступен.
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
KEV_CACHE = "kev/known_exploited_vulnerabilities.json"
KEV_DETAIL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"
MAX_KEV_BYTES = 30 * 1024 * 1024
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
KEV_FIELDS = ("vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate",
              "requiredAction", "knownRansomwareCampaignUse", "notes", "shortDescription")


class KevCatalog:
    def __init__(self, cache: CacheStore, http: CatalogHttpClient, *, ttl_hours: float,
                 refresh: bool = False, offline: bool = False,
                 log: Callable[[str], None] = lambda _msg: None) -> None:
        self.cache = cache
        self.http = http
        self.ttl_hours = ttl_hours
        self.refresh = refresh
        self.offline = offline
        self.log = log
        self.status = SourceStatus("CISA KEV")

    def load(self) -> Dict[str, dict]:
        """Индекс ``CVE → запись KEV``; пустой словарь, если источник недоступен."""
        before = self.http.requests_made
        raw = load_with_cache(self.cache, KEV_CACHE, self.status, self._download,
                              ttl_hours=self.ttl_hours, refresh=self.refresh,
                              offline=self.offline, log=self.log)
        self.status.requests = self.http.requests_made - before
        if raw is None:
            return {}
        try:
            index, catalog_date = parse_kev(raw)
        except ValueError as exc:
            self.status.state = "unavailable"
            self.status.message = f"повреждённый файл KEV: {exc}"
            return {}
        if catalog_date:
            self.status.data_date = catalog_date
        self.status.records = len(index)
        return index

    def _download(self, meta: Dict[str, object]) -> Tuple[bytes, Dict[str, str]]:
        headers = {}
        if meta.get("etag"):
            headers["If-None-Match"] = str(meta["etag"])
        if meta.get("last_modified"):
            headers["If-Modified-Since"] = str(meta["last_modified"])
        error: Optional[Exception] = None
        for url in KEV_URLS:
            try:
                self.log("      ↓ CISA KEV: загрузка каталога")
                result = self.http.get(url, headers=headers if url == KEV_URLS[0] else {},
                                       max_bytes=MAX_KEV_BYTES, accept_304=True, label="CISA KEV")
                if result.status == 304:
                    raise NotModified()
                _index, catalog_date = parse_kev(result.content)  # проверяем, что файл целый
                return result.content, {
                    "source_url": url,
                    "etag": result.header("ETag"),
                    "last_modified": result.header("Last-Modified"),
                    "data_date": catalog_date,
                }
            except NotModified:
                raise
            except Exception as exc:  # noqa: BLE001 - пробуем зеркало
                error = exc
        raise error or RuntimeError("KEV недоступен")


def parse_kev(raw: bytes) -> Tuple[Dict[str, dict], str]:
    """Разбирает JSON каталога → (индекс по CVE, дата выпуска каталога)."""
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("нет списка vulnerabilities")
    index: Dict[str, dict] = {}
    for item in data["vulnerabilities"]:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not CVE_RE.match(cve):
            continue
        entry = {name: str(item.get(name) or "") for name in KEV_FIELDS}
        entry["cveID"] = cve
        entry["url"] = KEV_DETAIL.format(cve=cve)
        index[cve] = entry
    date = str(data.get("dateReleased") or data.get("catalogVersion") or "")
    if re.match(r"^\d{4}\.\d{2}\.\d{2}$", date):
        date = date.replace(".", "-")
    return index, date
