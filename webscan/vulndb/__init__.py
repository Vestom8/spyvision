"""Этап 6: сопоставление найденных компонентов с каталогами уязвимостей.

| Роль           | Источник     | Что даёт                                        |
|----------------|--------------|-------------------------------------------------|
| Ядро           | NVD API 2.0  | CPE, CVE, CVSS, диапазоны версий                |
| Приоритизация  | CISA KEV     | «реально эксплуатируется», срок, ransomware     |
| Контекст       | ExploitDB    | наличие публичного эксплойта, verified, ссылка  |
| Российский контекст | БДУ ФСТЭК | идентификатор BDU, статус исправления, меры  |

Приватность: цели не отправляется ни одного дополнительного запроса;
во внешние каталоги уходит только vendor/product/version или CPE. KEV
и ExploitDB скачиваются целиком и сопоставляются локально. Любая ошибка
каталогов не роняет скан — источник помечается в отчёте, используется
устаревший кэш, анализ продолжается.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import time
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ..components_import import ImportFailure, import_components
from ..fingerprint import DetectedProduct, detect_products
from ..models import Finding, Page
from .bdu import BduCatalog, norm_name, product_query
from .cache import DISABLED, SKIPPED, STALE, CacheStore, SourceStatus, format_date
from .fstec import FstecContext, detect_perimeter, normalise_component_type
from .catalog_http import CatalogHttpClient
from .exploitdb import ExploitDbCatalog
from .kev import KevCatalog
from .nvd import NVD_DETAIL, NvdClient, RateLimiter
from .scoring import (BDU_NAME, VulnMatch, assess_match, bdu_component_finding,
                      component_finding, disclosed_versions_finding, rank_key, score_match)

BDU_SOURCE = "БДУ ФСТЭК"
SOURCE_ORDER = ("NVD", "CISA KEV", "ExploitDB", BDU_SOURCE)
DEFAULT_MAX_CVES = 200       # CVE на компонент, показываемых в отчёте


@dataclass
class VulnDbConfig:
    cache_dir: str = ""
    ttl_hours: float = 24.0
    refresh: bool = False
    offline: bool = False
    nvd_api_key: str = ""
    use_exploitdb: bool = True
    use_bdu: bool = True
    bdu_file: str = ""  # локальный vullist.xlsx вместо загрузки
    fstec_component_type: str = "server"   # тип компонента для показателя K методики ФСТЭК
    fstec_perimeter: str = "auto"          # auto | internet | internal — показатель P
    components_files: List[str] = field(default_factory=list)  # списки компонентов для импорта
    max_cves_per_component: int = DEFAULT_MAX_CVES
    include_product_only: bool = False  # CVE без привязки к версии (по умолчанию скрыты)
    log: Callable[[str], None] = lambda _msg: None
    # Для тестов: подмена транспорта и ожидания
    session: object = None
    sleep: Optional[Callable[[float], None]] = None


@dataclass
class CorrelationResult:
    components: List[DetectedProduct] = field(default_factory=list)
    matches: List[VulnMatch] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    sources: Dict[str, SourceStatus] = field(default_factory=dict)
    imported_components: int = 0
    fstec_context: Dict[str, object] = field(default_factory=dict)
    catalog_requests: int = 0
    duration: float = 0.0

    @property
    def matched_cves(self) -> int:
        return len({item.cve_id for item in self.matches})

    @property
    def kev_count(self) -> int:
        return len({item.cve_id for item in self.matches if item.kev})

    @property
    def exploit_count(self) -> int:
        return len({item.cve_id for item in self.matches if item.exploits})

    @property
    def bdu_count(self) -> int:
        return len({item.cve_id for item in self.matches if item.bdu})

    @property
    def bdu_only_count(self) -> int:
        """Записей, найденных только по БДУ (поиск по названию продукта и версии)."""
        return len({item.cve_id for item in self.matches if item.source == "bdu"})

    # Совместимость со старым именем поля
    @property
    def products(self) -> List[DetectedProduct]:
        return self.components

    @property
    def source_status(self) -> Dict[str, str]:
        return {name: status.label for name, status in self.sources.items()}

    def as_context(self) -> Dict[str, object]:
        """Сводка для ``stats['vulnerability_intelligence']`` (JSON-совместимая)."""
        return {
            "enabled": True,
            "products": [{
                "vendor": item.vendor, "product": item.product, "label": item.label,
                "version": item.version, "source": ", ".join(item.sources),
                "evidence": "; ".join(item.evidences[:3]),
                "nvd": item.nvd_eligible,
                "cves": sum(1 for match in self.matches if match.component is item),
            } for item in self.components],
            "sources": {name: status.as_dict() for name, status in self.sources.items()},
            "source_status": self.source_status,
            "matched_cves": self.matched_cves,
            "kev": self.kev_count,
            "exploits": self.exploit_count,
            "bdu": self.bdu_count,
            "bdu_only": self.bdu_only_count,
            "imported": self.imported_components,
            "fstec": dict(self.fstec_context),
            "catalog_findings": len(self.findings),
            "catalog_requests": self.catalog_requests,
            "duration": round(self.duration, 1),
            "notes": list(self.notes),
        }


def correlate(components: Sequence[DetectedProduct], cfg: VulnDbConfig,
              target: str = "") -> CorrelationResult:
    """Сопоставляет компоненты с NVD, KEV и ExploitDB."""
    started = time.monotonic()
    result = CorrelationResult(components=list(components))
    eligible = [item for item in components if item.nvd_eligible]
    versioned = [item for item in components if item.version]
    direct = cfg.use_bdu and bool(versioned)   # прямой поиск по БДУ не требует CPE
    # Проверяются все компоненты с версией, без ограничения числа: сначала те, у которых
    # CPE-пара известна, затем подбираемые по названию (им нужны дополнительные запросы).
    eligible.sort(key=lambda item: item.keyword_search)
    for item in components:
        if item.version and not item.nvd_eligible:
            result.notes.append(f"{item.display_name}: нет записи в словаре CPE NVD — "
                                "каталожная проверка для него не выполняется.")

    if not eligible and not direct:
        for name in SOURCE_ORDER:
            if name == BDU_SOURCE and not cfg.use_bdu:
                result.sources[name] = SourceStatus(name, state=DISABLED, message="--no-bdu")
                continue
            status = SourceStatus(name, state=SKIPPED,
                                  message="нет компонентов с известной версией")
            result.sources[name] = status
        hidden = [item.display_name for item in components if not item.version]
        if hidden:
            result.notes.append("Компоненты определены, но версии скрыты (это хорошо): "
                                + ", ".join(hidden[:10]) + ". Сверка с каталогами не нужна.")
        elif not components:
            result.notes.append("Компоненты и версии по загруженным страницам не определены — "
                                "сверка с каталогами уязвимостей не выполнялась.")
        result.duration = time.monotonic() - started
        return result

    http = _http_client(cfg)
    cache = CacheStore(cfg.cache_dir)
    common = dict(ttl_hours=cfg.ttl_hours, refresh=cfg.refresh, offline=cfg.offline, log=cfg.log)

    raw_matches: List[tuple] = []
    if eligible:
        nvd = NvdClient(cache, http, api_key=cfg.nvd_api_key,
                        limiter=RateLimiter(50 if (cfg.nvd_api_key or os.environ.get("NVD_API_KEY")) else 5,
                                            sleep=http.sleep),
                        include_product_only=cfg.include_product_only, **common)
        for component in eligible:
            cves, pairs = nvd.match_product(component)
            if not pairs:
                result.notes.append(f"NVD: не удалось проверить {component.display_name}.")
            for cve in cves:
                raw_matches.append((component, cve))
        for name, note in nvd.product_notes.items():
            result.notes.append(f"{name}: {note}.")
        for name, count in nvd.skipped_product_only.items():
            result.notes.append(f"{name}: скрыто CVE без привязки к версии (запись NVD относится ко "
                                f"всем версиям продукта): {count}.")
        result.sources["NVD"] = nvd.finish()
    else:
        result.sources["NVD"] = SourceStatus("NVD", state=SKIPPED,
                                             message="нет компонентов с версией и CPE")

    # БДУ: обогащение CVE из NVD и прямой поиск по названию продукта и версии.
    bdu: Dict[str, List[dict]] = {}
    bdu_only: List[Tuple[DetectedProduct, dict]] = []
    bdu_rejected: Dict[str, int] = {}
    if not cfg.use_bdu:
        result.sources[BDU_SOURCE] = SourceStatus(BDU_SOURCE, state=DISABLED, message="--no-bdu")
    elif raw_matches or versioned:
        bdu_catalog = BduCatalog(cache, http, local_file=cfg.bdu_file, **common)
        bdu_index = bdu_catalog.load()
        result.sources[BDU_SOURCE] = bdu_catalog.status
        if len(bdu_index):
            if raw_matches:
                bdu = bdu_index.for_cves({cve["id"] for _component, cve in raw_matches})
            nvd_ids: Dict[int, set] = {}
            for component, cve in raw_matches:
                nvd_ids.setdefault(id(component), set()).add(str(cve["id"]).upper())
            for component in versioned:
                query = product_query(component.label or component.product, component.cpe_pairs)
                conflicts = nvd.version_conflicts.get(component.key, set()) if eligible else set()
                for record in bdu_index.for_product(query, component.version):
                    cves = {str(item).upper() for item in (record.get("cves") or [])}
                    if cves & nvd_ids.get(id(component), set()):
                        continue   # эта уязвимость уже найдена через NVD и обогащена выше
                    if cves & conflicts:
                        # NVD знает эту CVE для продукта и явно не относит к ней нашу версию:
                        # поиск по названию противоречит структурированным данным — не показываем.
                        bdu_rejected[component.display_name] = \
                            bdu_rejected.get(component.display_name, 0) + 1
                        continue
                    bdu_only.append((component, record))
            for name, count in bdu_rejected.items():
                result.notes.append(
                    f"{name}: записей БДУ не показано: {count} — NVD для этих CVE явно не "
                    "относит данную версию к затронутым (приоритет у структурированных диапазонов NVD).")
    else:
        result.sources[BDU_SOURCE] = _skipped(BDU_SOURCE)

    bdu_cves = {cve for _component, record in bdu_only for cve in (record.get("cves") or [])}
    need_catalogs = bool(raw_matches or bdu_cves)
    kev_catalog = KevCatalog(cache, http, **common)
    kev = kev_catalog.load() if need_catalogs else {}
    result.sources["CISA KEV"] = kev_catalog.status if need_catalogs else _skipped("CISA KEV")

    if cfg.use_exploitdb:
        edb_catalog = ExploitDbCatalog(cache, http, **common)
        edb = edb_catalog.load() if need_catalogs else {}
        result.sources["ExploitDB"] = edb_catalog.status if need_catalogs else _skipped("ExploitDB")
    else:
        edb = {}
        result.sources["ExploitDB"] = SourceStatus("ExploitDB", state=DISABLED, message="--no-exploitdb")

    for status in result.sources.values():
        if status.message and not status.usable and status.state not in (SKIPPED, DISABLED):
            result.notes.append(f"{status.name} недоступен: {status.message}")
        elif status.state == STALE:
            result.notes.append(f"{status.name}: обновить не удалось, использованы данные "
                                f"от {format_date(status.data_date)}.")

    for component, cve in raw_matches:
        match = VulnMatch(
            cve_id=cve["id"],
            component=component,
            cvss=cve.get("cvss"),
            cwe=list(cve.get("cwe") or []),
            description=str(cve.get("description") or ""),
            published=str(cve.get("published") or ""),
            nvd_url=str(cve.get("nvd_url") or ""),
            cpe=str(cve.get("cpe") or ""),
            kev=kev.get(cve["id"]),
            exploits=list(edb.get(cve["id"]) or []),
            bdu=list(bdu.get(str(cve["id"]).upper()) or []),
            version_match=str(cve.get("version_match") or "range"),
        )
        match.priority_score, match.priority_label = score_match(match)
        result.matches.append(match)

    for component, record in bdu_only:
        cves = [str(item).upper() for item in (record.get("cves") or [])]
        match = VulnMatch(
            cve_id=cves[0] if cves else str(record["id"]),
            component=component,
            cvss=_bdu_cvss(record.get("scores") or {}),
            description=str(record.get("title") or ""),
            published=str(record.get("published") or ""),
            nvd_url=NVD_DETAIL.format(cve=cves[0]) if cves else "",
            kev=next((kev[item] for item in cves if item in kev), None),
            exploits=list(next((edb[item] for item in cves if edb.get(item)), [])),
            bdu=[record],
            version_match=BDU_NAME,
            source="bdu",
        )
        match.priority_score, match.priority_label = score_match(match)
        result.matches.append(match)

    # Уровень критичности по методике ФСТЭК: показатели, которые сканер знает (адрес цели,
    # число уязвимых компонентов), считаются, остальные берутся из настроек.
    internet_facing, perimeter_source = detect_perimeter(target, cfg.fstec_perimeter)
    share = (len({id(item.component) for item in result.matches}) / len(versioned)
             if versioned else 0.0)
    context = FstecContext(component_type=normalise_component_type(cfg.fstec_component_type),
                           internet_facing=internet_facing, vulnerable_share=min(1.0, share),
                           perimeter_source=perimeter_source)
    result.fstec_context = context.as_dict()
    for match in result.matches:
        match.fstec = assess_match(match, context)

    by_component: Dict[int, List[VulnMatch]] = {}
    by_bdu: Dict[int, List[VulnMatch]] = {}
    for match in result.matches:
        target_map = by_bdu if match.source == "bdu" else by_component
        target_map.setdefault(id(match.component), []).append(match)
    no_cves: List[DetectedProduct] = []
    for component in eligible:
        items = sorted(by_component.get(id(component), []), key=rank_key)
        if not items:
            if id(component) not in by_bdu:
                no_cves.append(component)
            continue
        shown = items[:cfg.max_cves_per_component]
        result.findings.append(component_finding(component, shown, target,
                                                 hidden=len(items) - len(shown)))
    for component in versioned:
        items = sorted(by_bdu.get(id(component), []), key=rank_key)
        if items:
            shown = items[:cfg.max_cves_per_component]
            result.findings.append(bdu_component_finding(component, shown, target,
                                                         hidden=len(items) - len(shown)))
    if no_cves and result.sources["NVD"].usable:
        result.findings.append(disclosed_versions_finding(no_cves, target))

    result.catalog_requests = http.requests_made
    result.duration = time.monotonic() - started
    return result


def enrich_with_catalogs(pages: Sequence[Page], cfg: Optional[VulnDbConfig] = None,
                         **kwargs) -> CorrelationResult:
    """Fingerprint по уже загруженным страницам + ``correlate``."""
    cfg = cfg or VulnDbConfig(**kwargs)
    components = detect_products(pages)
    notes: List[str] = []
    imported = 0
    known = {item.key: item for item in components}
    by_name = {}   # (нормализованное название, версия) → компонент, найденный по баннеру
    for item in components:
        for name in (item.label, item.product):
            if name and item.version:
                by_name.setdefault((norm_name(name), item.version.lower()), item)
    for path in cfg.components_files:
        try:
            loaded = import_components(path)
        except ImportFailure as exc:
            notes.append(f"Список компонентов не загружен: {exc}.")
            continue
        notes.append(loaded.note())
        for item in loaded.components:
            current = known.get(item.key)
            if current is None and item.keyword_search:
                # у импортированного компонента нет вендора — ищем тот же продукт по названию
                for name in (item.label, item.product):
                    current = by_name.get((norm_name(name), item.version.lower()))
                    if current is not None:
                        break
            if current is None:
                known[item.key] = item
                components.append(item)
                imported += 1
            else:   # тот же компонент найден и по баннеру, и в списке — места сливаются
                current.merge(item)
    target = pages[0].url if pages else ""
    result = correlate(components, cfg, target=target)
    result.imported_components = imported
    result.notes[0:0] = notes
    return result


def update_databases(cfg: VulnDbConfig) -> Dict[str, SourceStatus]:
    """``--update-vuln-db`` без URL: принудительно обновить KEV, ExploitDB и БДУ.

    NVD не выгружается целиком — ответы по продуктам кэшируются при сканах.
    """
    cfg.refresh = True
    http = _http_client(cfg)
    cache = CacheStore(cfg.cache_dir)
    common = dict(ttl_hours=cfg.ttl_hours, refresh=True, offline=cfg.offline, log=cfg.log)
    statuses: Dict[str, SourceStatus] = {}
    kev = KevCatalog(cache, http, **common)
    kev.load()
    statuses["CISA KEV"] = kev.status
    if cfg.use_exploitdb:
        edb = ExploitDbCatalog(cache, http, **common)
        edb.load()
        statuses["ExploitDB"] = edb.status
    if cfg.use_bdu:
        bdu_catalog = BduCatalog(cache, http, local_file=cfg.bdu_file, **common)
        bdu_catalog.load()
        statuses[BDU_SOURCE] = bdu_catalog.status
    return statuses


def sources_snapshot(cache_dir: str = "") -> Dict[str, Dict[str, str]]:
    """Состояние локальных копий справочников (для /api/status), без сети."""
    from .bdu import BDU_CACHE
    from .exploitdb import EXPLOITDB_CACHE
    from .kev import KEV_CACHE
    try:
        cache = CacheStore(cache_dir)
    except OSError:
        return {}
    result: Dict[str, Dict[str, str]] = {}
    for key, name in (("kev", KEV_CACHE), ("exploitdb", EXPLOITDB_CACHE), ("bdu", BDU_CACHE)):
        result[key] = {"state": "cached" if cache.exists(name) else "missing",
                       "data_date": cache.data_date(name) if cache.exists(name) else ""}
    if result["bdu"]["state"] == "missing":
        for path in (cache.root / "vullist.xlsx", cache.root.parent / "bdu" / "vullist.xlsx"):
            if path.is_file():
                result["bdu"] = {"state": "cached", "data_date": ""}
                break
    nvd_dir = cache.path("nvd/cves")
    count = len(list(nvd_dir.glob("*.json"))) - len(list(nvd_dir.glob("*.meta.json"))) if nvd_dir.is_dir() else 0
    result["nvd"] = {"state": "cached" if count > 0 else "missing", "data_date": "",
                     "products": str(max(count, 0))}
    return result


def _http_client(cfg: VulnDbConfig) -> CatalogHttpClient:
    kwargs: Dict[str, object] = {
        "offline": cfg.offline,
        "log": cfg.log,
    }
    if cfg.session is not None:
        kwargs["session"] = cfg.session
    if cfg.sleep is not None:
        kwargs["sleep"] = cfg.sleep
    return CatalogHttpClient(**kwargs)  # type: ignore[arg-type]


def _bdu_cvss(scores: Dict[str, float]) -> Optional[Dict[str, object]]:
    """Оценка из БДУ в формате NVD-записи: предпочитаем более новую версию CVSS."""
    for version in ("4.0", "3.1", "3.0", "2.0"):
        if version in scores:
            return {"version": version, "score": float(scores[version]), "vector": ""}
    return None


def _skipped(name: str) -> SourceStatus:
    return SourceStatus(name, state=SKIPPED, message="CVE не найдены — сверка не понадобилась")


__all__ = [
    "CorrelationResult", "VulnDbConfig", "VulnMatch", "correlate", "enrich_with_catalogs",
    "update_databases", "sources_snapshot",
]
