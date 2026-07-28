"""Обход веб-сайта в пределах одного домена (BFS) с сохранением страниц."""

from collections import deque
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup

from .http_client import HttpClient, parse_cookies, raw_header_items
from .models import Form, FormField, Page
from .utils import absolutize, is_http_url, looks_binary, normalize_url, same_host

TEXT_CONTENT_TYPES = ("text/", "application/json", "application/xml", "application/javascript",
                      "application/xhtml", "+json", "+xml")


def crawl(client: HttpClient, start_url: str, max_pages: int, max_depth: int,
          reserve: int = 0, verbose: bool = False) -> Tuple[List[Page], List[str]]:
    """Обходит сайт, возвращает (страницы, внешние ссылки)."""
    start = normalize_url(start_url)
    queue: deque = deque([(start, 0)])
    seen = {start}
    pages: List[Page] = []
    external_links: List[str] = []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if not client.can_request(reserve):
            break

        response = client.get(url, reserve=reserve)
        if response is None:
            continue

        page = build_page(response, url, depth)
        pages.append(page)
        seen.add(normalize_url(page.url))  # адрес после редиректа не запрашиваем повторно
        if verbose:
            print(f"      -> {page.status} {page.content_type or '-'} ({len(page.body)} симв.)")

        if depth >= max_depth:
            continue

        for link in page.links:
            if not is_http_url(link):
                continue
            candidate = normalize_url(link)
            if not candidate:
                continue
            if not same_host(candidate, start):
                if candidate not in external_links:
                    external_links.append(candidate)
                continue  # запрет на переход по внешним ссылкам
            if candidate in seen or looks_binary(candidate):
                continue
            seen.add(candidate)
            queue.append((candidate, depth + 1))

    return pages, external_links


def build_page(response, requested_url: str, depth: int) -> Page:
    content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
    body = ""
    if _is_texty(content_type) or not content_type:
        try:
            body = response.text
        except Exception:
            body = ""
    page = Page(
        url=response.url or requested_url,
        requested_url=requested_url,
        depth=depth,
        status=response.status_code,
        headers=dict(response.headers),
        raw_headers=raw_header_items(response),
        body=body,
        content_type=content_type,
        cookies=parse_cookies(response),
        truncated=getattr(response, "truncated", False),
    )
    if body and ("html" in content_type or not content_type):
        soup = parse_html(body)
        if soup is not None:
            page.links = extract_links(soup, page.url)
            page.forms = extract_forms(soup, page.url)
    return page


def parse_html(body: str) -> Optional[BeautifulSoup]:
    for parser in ("html.parser",):
        try:
            return BeautifulSoup(body, parser)
        except Exception:
            continue
    return None


def extract_links(soup: BeautifulSoup, base_url: str) -> List[str]:
    links: List[str] = []
    for tag, attr in (("a", "href"), ("area", "href"), ("iframe", "src"), ("frame", "src")):
        for element in soup.find_all(tag):
            value = element.get(attr)
            if not value:
                continue
            value = value.strip()
            if value.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                continue
            absolute = absolutize(base_url, value)
            if absolute and absolute not in links:
                links.append(absolute)
    return links


def extract_forms(soup: BeautifulSoup, base_url: str) -> List[Form]:
    forms: List[Form] = []
    for element in soup.find_all("form"):
        action = absolutize(base_url, (element.get("action") or "").strip() or base_url)
        method = (element.get("method") or "GET").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"
        form = Form(page_url=base_url, action=action, method=method, raw=str(element)[:1500])
        for field in element.find_all(["input", "textarea", "select"]):
            name = (field.get("name") or "").strip()
            field_type = (field.get("type") or ("textarea" if field.name == "textarea" else "text")).lower()
            value = field.get("value") or ""
            if field.name == "select":
                field_type = "select"
                option = field.find("option")
                value = (option.get("value") if option and option.get("value") else
                         (option.get_text(strip=True) if option else ""))
            form.fields.append(FormField(name=name, field_type=field_type, value=str(value)))
        forms.append(form)
    return forms


def _is_texty(content_type: str) -> bool:
    return any(marker in content_type for marker in TEXT_CONTENT_TYPES)
