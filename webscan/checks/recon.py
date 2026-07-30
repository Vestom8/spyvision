"""Разведка: доменные имена, IP-адреса, DNS и поддомены.

Не эксплуатирует уязвимости: только DNS-запросы (вне HTTP-бюджета) и разбор
уже загруженных страниц. Поддомены проверяются коротким словарём.
DNS-запросы выполняются параллельно с таймаутом и кэшем.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ..models import CONFIG, CONFIRMED, INFO, LOW, MEDIUM, SUSPECTED, Finding, Page
from ..utils import host_of

# Уникальные префиксы — без агрессивного перебора
SUBDOMAIN_PREFIXES = (
    "www", "mail", "api", "admin", "staging", "stage", "dev", "test", "app",
    "portal", "cdn", "static", "blog", "shop", "m", "mobile", "vpn", "git",
    "gitlab", "jenkins", "grafana", "monitor", "status", "docs", "support",
    "secure", "auth", "sso", "remote", "db", "sql", "ftp", "ns1", "ns2",
    "mx", "webmail", "cpanel", "panel", "beta", "demo", "old", "backup",
)

HOST_IN_TEXT = re.compile(
    r"(?i)(?:https?://|//)?((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,24})(?::\d{2,5})?(?:[/\s\"'<>]|$)"
)
IPV4_IN_TEXT = re.compile(
    r"(?<!\d)((?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d))(?!\d)"
)

SKIP_TLDS = frozenset({
    "png", "jpg", "jpeg", "gif", "svg", "js", "css", "woff", "woff2",
    "ttf", "eot", "map", "json", "xml", "pdf", "zip",
})

DNS_WORKERS = 16
DNS_TIMEOUT = 2.0
CONTENT_PAGE_LIMIT = 20
CONTENT_BODY_LIMIT = 80_000

_RESOLVE_CACHE: Dict[str, List[str]] = {}


@dataclass
class ReconResult:
    findings: List[Finding] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)


def run_recon(base_url: str, pages: Sequence[Page] | None = None,
              *, dns: bool = True, content: bool = True) -> ReconResult:
    """DNS + извлечение хостов/IP из страниц + словарь поддоменов."""
    result = ReconResult()
    target_host = host_of(base_url)
    if not target_host:
        return result

    ips: List[str] = []
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(DNS_TIMEOUT)
        if dns:
            records = _dns_lookup(target_host)
            result.dns_records = records
            ips = sorted(set(records.get("A", []) + records.get("AAAA", [])))
            result.ips = ips

            if ips:
                result.findings.append(Finding(
                    url=base_url,
                    title=f"DNS: IP-адреса цели ({len(ips)})",
                    kind="recon_dns_a",
                    category=CONFIG,
                    severity=INFO,
                    recommendation="Убедитесь, что на этих адресах нет лишних открытых сервисов "
                                    "и что служебные IP не светятся в публичных ответах без нужды.",
                    request=f"DNS A/AAAA {target_host}",
                    evidence="\n".join(ips),
                    confidence=CONFIRMED,
                ))

            extra_dns = []
            for rtype in ("MX", "NS", "TXT"):
                if records.get(rtype):
                    extra_dns.append(f"{rtype}: " + "; ".join(records[rtype][:8]))
            if extra_dns:
                result.findings.append(Finding(
                    url=base_url,
                    title="DNS-разведка: MX / NS / TXT",
                    kind="recon_dns_extra",
                    category=CONFIG,
                    severity=INFO,
                    recommendation="Проверьте SPF/DMARC в TXT, не оставляйте устаревшие MX/NS.",
                    request=f"DNS MX/NS/TXT {target_host}",
                    evidence="\n".join(extra_dns),
                    confidence=CONFIRMED,
                ))

            for ip in ips[:4]:
                ptr = _reverse_dns(ip)
                if ptr and ptr.lower() != target_host.lower():
                    result.findings.append(Finding(
                        url=base_url,
                        title=f"Обратный DNS (PTR): {ip} → {ptr}",
                        kind="recon_ptr",
                        category=CONFIG,
                        severity=LOW,
                        recommendation="PTR не должен раскрывать внутренние имена без необходимости.",
                        request=f"PTR {ip}",
                        evidence=ptr,
                        confidence=CONFIRMED,
                    ))

            root = _dns_root(target_host)
            if root and "." in root and not _is_ip(target_host):
                candidates = [
                    f"{prefix}.{root}"
                    for prefix in SUBDOMAIN_PREFIXES
                    if f"{prefix}.{root}" != target_host
                ]
                resolved = _resolve_many(candidates)
                discovered = [
                    (name, ", ".join(addrs[:3]))
                    for name, addrs in resolved.items()
                    if addrs
                ]
                discovered.sort(key=lambda item: item[0])
                result.subdomains = [d[0] for d in discovered]
                if discovered:
                    result.findings.append(Finding(
                        url=base_url,
                        title=f"DNS-разведка: найдены поддомены ({len(discovered)})",
                        kind="recon_subdomains",
                        category=CONFIG,
                        severity=MEDIUM if len(discovered) >= 3 else LOW,
                        recommendation="Закройте или защитите тестовые/служебные поддомены "
                                        "(staging, admin, jenkins). Они часто слабее основного сайта.",
                        request=f"DNS brute ({len(SUBDOMAIN_PREFIXES)} префиксов) для *.{root}",
                        evidence="\n".join(
                            f"{name} → {addrs}" for name, addrs in discovered[:30]
                        ),
                        confidence=CONFIRMED,
                    ))
    finally:
        socket.setdefaulttimeout(old_timeout)

    if content and pages:
        found_hosts: Set[str] = set()
        found_ips: Set[str] = set(ips)
        for page in pages[:CONTENT_PAGE_LIMIT]:
            text = (page.body or "")[:CONTENT_BODY_LIMIT]
            for match in HOST_IN_TEXT.finditer(text):
                host = match.group(1).lower().rstrip(".")
                if _looks_like_host(host):
                    found_hosts.add(host)
            for match in IPV4_IN_TEXT.finditer(text):
                ip = match.group(1)
                if not _is_loopback_or_broadcast(ip):
                    found_ips.add(ip)
            for link in page.links or []:
                h = host_of(link)
                if h:
                    found_hosts.add(h)

        found_hosts.discard(target_host)
        related = sorted(h for h in found_hosts if _related_or_external(h, target_host))
        result.hosts = [target_host] + related[:40]
        result.ips = sorted(set(result.ips) | found_ips)[:40]

        if related:
            same_root = [h for h in related if _same_registered_like(h, target_host)]
            external = [h for h in related if h not in same_root]
            if same_root:
                result.findings.append(Finding(
                    url=base_url,
                    title=f"Обнаружены связанные доменные имена ({len(same_root)})",
                    kind="recon_hosts",
                    category=CONFIG,
                    severity=INFO,
                    recommendation="Проверьте, что все связанные хосты входят в периметр защиты "
                                    "и закрыты так же, как основной сайт.",
                    request="Пассивный разбор HTML/ссылок",
                    evidence="\n".join(same_root[:25]),
                    confidence=CONFIRMED,
                ))
            if external[:15]:
                result.findings.append(Finding(
                    url=base_url,
                    title=f"Сторонние домены в контенте ({min(len(external), 15)}+)",
                    kind="recon_third_party_hosts",
                    category=CONFIG,
                    severity=INFO,
                    recommendation="Инвентаризируйте сторонние домены (аналитика, CDN, виджеты).",
                    request="Пассивный разбор HTML/ссылок",
                    evidence="\n".join(external[:15]),
                    confidence=CONFIRMED,
                ))

        page_ips = sorted(found_ips - set(ips))
        if page_ips:
            result.findings.append(Finding(
                url=base_url,
                title=f"IP-адреса в содержимом страниц ({len(page_ips)})",
                kind="recon_ips_in_content",
                category=CONFIG,
                severity=LOW,
                recommendation="Не публикуйте внутренние IP в HTML/JS; используйте имена и прокси.",
                request="Пассивный разбор HTML/JS",
                evidence="\n".join(page_ips[:20]),
                confidence=SUSPECTED if any(_is_private_ipv4(ip) for ip in page_ips)
                else CONFIRMED,
            ))

    return result


def _dns_lookup(host: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
    if _is_ip(host):
        out["A"] = [host]
        return out
    addrs = _resolve_a(host)
    for addr in addrs:
        if ":" in addr:
            if addr not in out["AAAA"]:
                out["AAAA"].append(addr)
        elif addr not in out["A"]:
            out["A"].append(addr)
    root = _dns_root(host)
    extras = {
        f"mail.{root}": "MX",
        f"mx.{root}": "MX",
        f"ns1.{root}": "NS",
        f"ns2.{root}": "NS",
    }
    resolved = _resolve_many(list(extras.keys()))
    for cand, rtype in extras.items():
        addrs = resolved.get(cand) or []
        if addrs:
            out[rtype].append(f"{cand} ({', '.join(addrs[:2])})")
    return out


def _resolve_many(hosts: Sequence[str]) -> Dict[str, List[str]]:
    """Параллельный DNS A/AAAA с кэшем и таймаутом на запрос."""
    unique = list(dict.fromkeys(hosts))
    results: Dict[str, List[str]] = {}
    pending = []
    for host in unique:
        cached = _RESOLVE_CACHE.get(host)
        if cached is not None:
            results[host] = cached
        else:
            pending.append(host)
    if not pending:
        return results
    with ThreadPoolExecutor(max_workers=min(DNS_WORKERS, len(pending))) as pool:
        futures = {pool.submit(_resolve_a_uncached, host): host for host in pending}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                addrs = fut.result(timeout=DNS_TIMEOUT + 0.5)
            except Exception:
                addrs = []
            _RESOLVE_CACHE[host] = addrs
            results[host] = addrs
    return results


def _resolve_a(host: str) -> List[str]:
    cached = _RESOLVE_CACHE.get(host)
    if cached is not None:
        return cached
    addrs = _resolve_a_uncached(host)
    _RESOLVE_CACHE[host] = addrs
    return addrs


def _resolve_a_uncached(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addrs: List[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in addrs:
                addrs.append(addr)
        return addrs
    except Exception:
        return []


def _reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _aliases, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except Exception:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host.strip("[]"))
        return True
    except Exception:
        return False


def _is_loopback_or_broadcast(ip: str) -> bool:
    return ip.startswith(("127.", "0.")) or ip == "255.255.255.255"


def _is_private_ipv4(ip: str) -> bool:
    if ip.startswith(("10.", "192.168.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False


def _dns_root(host: str) -> str:
    """Грубая «корневая» зона для словаря поддоменов (example.com)."""
    if _is_ip(host):
        return host
    parts = host.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host


def _looks_like_host(host: str) -> bool:
    if not host or len(host) > 200 or "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1].lower()
    if tld in SKIP_TLDS or tld.isdigit():
        return False
    if host.startswith(".") or ".." in host:
        return False
    return True


def _same_registered_like(host: str, target: str) -> bool:
    return _dns_root(host) == _dns_root(target)


def _related_or_external(host: str, target: str) -> bool:
    return _looks_like_host(host) and host != target
