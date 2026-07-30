"""Проверки клиентской части страницы.

Всё, что можно увидеть в уже загруженном HTML: подключаемые сторонние ресурсы,
ссылки, устаревшие JS-библиотеки, кэширование приватных страниц и чувствительные
данные в адресах. Дополнительные HTTP-запросы не выполняются.
"""

import re
from typing import Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

from bs4 import BeautifulSoup

from ..models import CONFIG, CONFIRMED, LOW, MEDIUM, SUSPECTED, VULN, Finding, Page
from ..utils import absolutize, header_multivalues, same_host, truncate

# (название, шаблон поиска версии, первая безопасная версия, чем опасна старая)
VULNERABLE_LIBRARIES: Tuple[Tuple[str, "re.Pattern", Tuple[int, int, int], str], ...] = (
    ("jQuery", re.compile(r"jquery[/\-. ]v?(\d+)\.(\d+)(?:\.(\d+))?", re.I), (3, 5, 0),
     "в версиях до 3.5.0 есть XSS в htmlPrefilter (CVE-2020-11022, CVE-2020-11023)"),
    ("jQuery UI", re.compile(r"jquery[.\-]ui[/\-. ]v?(\d+)\.(\d+)(?:\.(\d+))?", re.I), (1, 13, 2),
     "в версиях до 1.13.2 есть XSS в компонентах datepicker и dialog"),
    ("Bootstrap", re.compile(r"bootstrap[/\-. ]v?(\d+)\.(\d+)(?:\.(\d+))?", re.I), (4, 3, 1),
     "в версиях до 4.3.1 есть XSS в tooltip и popover (CVE-2019-8331)"),
    ("Lodash", re.compile(r"lodash[/\-. ]v?(\d+)\.(\d+)(?:\.(\d+))?", re.I), (4, 17, 21),
     "в версиях до 4.17.21 есть загрязнение прототипа и ReDoS"),
    ("Moment.js", re.compile(r"moment[/\-. ]v?(\d+)\.(\d+)(?:\.(\d+))?", re.I), (2, 29, 4),
     "в версиях до 2.29.4 есть обход пути при загрузке локалей (CVE-2022-31129)"),
    ("Handlebars", re.compile(r"handlebars[/\-. ]v?(\d+)\.(\d+)(?:\.(\d+))?", re.I), (4, 7, 7),
     "в версиях до 4.7.7 возможно выполнение кода через шаблон"),
    ("AngularJS", re.compile(r"angular(?![a-z])[/\-. ]v?(1)\.(\d+)(?:\.(\d+))?", re.I),
     (99, 0, 0),
     "ветка AngularJS 1.x снята с поддержки в 2022 году и больше не получает исправлений"),
)

# Параметры, значения которых не должны появляться в адресной строке
SENSITIVE_PARAMS = ("token", "access_token", "auth", "authorization", "session", "sessionid",
                    "sid", "password", "passwd", "pwd", "api_key", "apikey", "secret",
                    "signature", "otp", "reset_key")

SENSITIVE_FIELD_HINTS = ("pass", "pwd", "card", "cvv", "cvc", "secret", "token", "otp",
                         "пароль", "карт")

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
NO_STORE_RE = re.compile(r"(?i)\b(?:no-store|private)\b")

# --- признаки уязвимостей в клиентском JavaScript --------------------------
# «Приёмник» — место, где строка превращается в разметку или в код.
DOM_SINKS: Tuple[Tuple[str, "re.Pattern"], ...] = (
    ("document.write()", re.compile(r"document\s*\.\s*write(?:ln)?\s*\(")),
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*[+]?=")),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*[+]?=")),
    ("insertAdjacentHTML()", re.compile(r"\.\s*insertAdjacentHTML\s*\(")),
    ("eval()", re.compile(r"(?<![\w.$])eval\s*\(")),
    ("new Function()", re.compile(r"new\s+Function\s*\(")),
    ("jQuery .html()", re.compile(r"\$\s*\([^)]*\)\s*\.\s*html\s*\(")),
    ("setTimeout со строкой", re.compile(r"set(?:Timeout|Interval)\s*\(\s*[\"']")),
)
# «Источник» — данные, которыми управляет тот, кто прислал ссылку.
DOM_SOURCE = re.compile(
    r"location\s*\.\s*(?:hash|search|href|pathname)|document\s*\.\s*URL|"
    r"document\s*\.\s*documentURI|document\s*\.\s*referrer|window\s*\.\s*name|"
    r"URLSearchParams\s*\("
)
MESSAGE_LISTENER = re.compile(r"addEventListener\s*\(\s*[\"']message[\"']|onmessage\s*=")
ORIGIN_CHECK = re.compile(r"\.\s*origin\s*(?:===|==|!==|!=)|\bcheckOrigin|\ballowedOrigins")
STORAGE_SECRET = re.compile(
    r"(?:local|session)Storage\s*(?:\.\s*setItem\s*\(\s*[\"'][^\"']*"
    r"(?:token|jwt|auth|pass|secret|key|session)[^\"']*[\"']"
    r"|\.\s*[A-Za-z_$][\w$]*(?:token|jwt|auth|pass|secret|key|session)[\w$]*\s*=)",
    re.I,
)
INSECURE_WS = re.compile(r"ws://[^\s\"'<>]{4,}")
INLINE_HANDLER = re.compile(r"<[a-zA-Z][^>]*?\son[a-z]{3,15}\s*=\s*[\"'][^\"']", re.S)
JAVASCRIPT_HREF = re.compile(r"(?:href|src)\s*=\s*[\"']\s*javascript:", re.I)


def check_client_side(page: Page) -> List[Finding]:
    """Пассивный анализ HTML страницы: ресурсы, ссылки, кэш, адреса."""
    findings: List[Finding] = []
    body = page.body or ""
    if not body or "html" not in (page.content_type or "text/html"):
        return findings

    request_text = f"GET {page.url}"
    soup = page.soup if page.soup is not None else BeautifulSoup(body, "html.parser")
    page.soup = soup

    def add(title, severity, recommendation, evidence, kind, category=CONFIG,
            confidence=CONFIRMED):
        findings.append(
            Finding(
                url=page.url,
                title=title,
                category=category,
                severity=severity,
                recommendation=recommendation,
                request=request_text,
                evidence=truncate(evidence, 600),
                confidence=confidence,
                kind=kind,
            )
        )

    # --- ссылки target="_blank" без rel="noopener" ---
    risky_links = []
    for tag in soup.find_all("a", href=True):
        target = (tag.get("target") or "").strip().lower()
        if target != "_blank":
            continue
        rel = " ".join(tag.get("rel") or []).lower()
        if "noopener" in rel or "noreferrer" in rel:
            continue
        href = absolutize(page.url, tag["href"])
        if urlparse(href).scheme in ("http", "https") and not same_host(href, page.url):
            risky_links.append(href)
    if risky_links:
        add(
            f"Внешние ссылки target=\"_blank\" без rel=\"noopener\" ({len(risky_links)})",
            LOW,
            "Добавьте rel=\"noopener noreferrer\" ко всем ссылкам с target=\"_blank\". "
            "Без этого открытая страница получает доступ к объекту window вашей вкладки.",
            "\n".join(risky_links[:8]),
            "tabnabbing",
        )

    # --- сторонние скрипты и стили без Subresource Integrity ---
    no_sri = []
    for tag in soup.find_all(["script", "link"]):
        url = tag.get("src") if tag.name == "script" else tag.get("href")
        if not url:
            continue
        if tag.name == "link" and "stylesheet" not in " ".join(tag.get("rel") or []).lower():
            continue
        absolute = absolutize(page.url, url)
        if urlparse(absolute).scheme not in ("http", "https") or same_host(absolute, page.url):
            continue
        if tag.get("integrity"):
            continue
        no_sri.append(absolute)
    if no_sri:
        add(
            f"Сторонние скрипты и стили подключены без контроля целостности ({len(no_sri)})",
            LOW,
            "Добавьте атрибуты integrity и crossorigin для файлов со сторонних доменов (CDN) "
            "или разместите их у себя. Тогда браузер откажется выполнять подменённый файл.",
            "\n".join(no_sri[:8]),
            "missing_sri",
        )

    # --- устаревшие клиентские библиотеки ---
    sources = [absolutize(page.url, tag.get("src") or "") for tag in soup.find_all("script", src=True)]
    sources += [absolutize(page.url, tag.get("href") or "") for tag in soup.find_all("link", href=True)]
    banners = re.findall(r"(?:jQuery|Bootstrap|lodash|moment|Handlebars|AngularJS)\s+v?\d+\.\d+"
                         r"(?:\.\d+)?", body[:20000], re.I)
    for name, pattern, safe_version, danger in VULNERABLE_LIBRARIES:
        found = _find_version(pattern, sources + banners)
        if not found:
            continue
        version, evidence_text = found
        if version >= safe_version:
            continue
        readable = ".".join(str(part) for part in version)
        add(
            f"Устаревшая клиентская библиотека: {name} {readable}",
            MEDIUM,
            f"Обновите {name} минимум до версии "
            f"{'.'.join(str(p) for p in safe_version)}"
            + (" (или перейдите на поддерживаемый аналог)" if safe_version[0] == 99 else "")
            + f". Известная проблема: {danger}.",
            f"Найдено подключение: {evidence_text}",
            "outdated_library",
            category=VULN,
        )

    # --- кэширование страниц с приватными данными ---
    multi = header_multivalues(page.raw_headers)
    cache_control = " ".join(multi.get("cache-control", []))
    has_password = any(
        (form_field.field_type or "").lower() == "password"
        for form in page.forms for form_field in form.fields
    )
    has_sensitive_field = any(
        any(hint in (form_field.name or "").lower() for hint in SENSITIVE_FIELD_HINTS)
        for form in page.forms for form_field in form.fields
    )
    if (has_password or has_sensitive_field or page.cookies) and not NO_STORE_RE.search(cache_control):
        add(
            "Страница с приватными данными кэшируется",
            LOW,
            "Отдавайте такие страницы с заголовком Cache-Control: no-store (и Pragma: no-cache "
            "для старых прокси), чтобы копия не оставалась в кэше браузера и промежуточных узлов.",
            f"Cache-Control: {cache_control or 'заголовок отсутствует'}\n"
            f"На странице: {'поле пароля' if has_password else ''}"
            f"{', ' if has_password and page.cookies else ''}"
            f"{'установка cookie' if page.cookies else ''}",
            "no_cache_private",
        )

    # --- чувствительные данные в адресах ---
    leaky = _sensitive_params(page.url)
    for tag in soup.find_all("a", href=True):
        leaky.extend(_sensitive_params(absolutize(page.url, tag["href"])))
    if leaky:
        unique = sorted(set(leaky))[:8]
        add(
            "Чувствительные данные передаются в адресе страницы",
            MEDIUM,
            "Передавайте токены, сессии и пароли в теле POST-запроса или в заголовках. "
            "Значения из адреса попадают в историю браузера, журналы сервера и прокси, "
            "а также в заголовок Referer при переходе на сторонний сайт.",
            "Параметры (значения маскированы): " + ", ".join(unique),
            "sensitive_param_in_url",
            category=VULN,
        )

    # --- сторонние iframe без ограничений ---
    frames = []
    for tag in soup.find_all("iframe", src=True):
        absolute = absolutize(page.url, tag["src"])
        if urlparse(absolute).scheme not in ("http", "https") or same_host(absolute, page.url):
            continue
        if tag.get("sandbox") is not None:
            continue
        frames.append(absolute)
    if frames:
        add(
            f"Сторонние iframe подключены без атрибута sandbox ({len(frames)})",
            LOW,
            "Добавьте атрибут sandbox с минимально необходимыми разрешениями. Без него "
            "содержимое чужого домена может открывать всплывающие окна, запускать скрипты "
            "и переадресовывать вкладку.",
            "\n".join(frames[:8]),
            "third_party_iframe",
        )

    # --- адреса электронной почты в коде страницы ---
    emails = sorted(set(EMAIL_RE.findall(body)))[:10]
    if emails:
        add(
            f"В коде страницы найдены адреса электронной почты ({len(emails)})",
            LOW,
            "Если адреса не предназначены для публикации, замените их формой обратной связи "
            "или защитой от сбора (обфускация, изображение). Открытые адреса собирают "
            "спам-боты и используют для целевых фишинговых писем сотрудникам.",
            "\n".join(emails),
            "email_exposed",
            confidence=SUSPECTED,
        )

    # --- формы загрузки файлов ---
    upload_forms = [form for form in page.forms
                    if any((f.field_type or "").lower() == "file" for f in form.fields)]
    if upload_forms:
        add(
            f"На странице есть загрузка файлов на сервер ({len(upload_forms)})",
            LOW,
            "Проверьте вручную: разрешённые расширения и MIME-типы должны определяться "
            "белым списком, имя файла — генерироваться сервером, а каталог загрузок не "
            "должен исполнять скрипты. Загрузка файлов — типовой путь к веб-шеллу.",
            "\n".join(form.describe() for form in upload_forms[:5]),
            "file_upload_form",
            category=VULN,
            confidence=SUSPECTED,
        )

    _check_inline_scripts(soup, add)

    # --- незашифрованные веб-сокеты на защищённой странице ---
    if page.is_https:
        sockets = sorted(set(INSECURE_WS.findall(body)))[:5]
        if sockets:
            add(
                "Веб-сокет подключается по незашифрованному протоколу ws://",
                MEDIUM,
                "Используйте wss://: соединение ws:// идёт открытым текстом, его можно "
                "прочитать и подменить в пути, а браузеры блокируют такие подключения "
                "со страниц HTTPS.",
                "\n".join(sockets),
                "insecure_websocket",
                category=VULN,
            )

    # --- inline-обработчики и javascript:-ссылки ---
    inline_handlers = len(INLINE_HANDLER.findall(body))
    javascript_links = len(JAVASCRIPT_HREF.findall(body))
    if inline_handlers + javascript_links >= 3:
        add(
            f"Обработчики событий записаны прямо в HTML ({inline_handlers + javascript_links})",
            LOW,
            "Перенесите код из атрибутов onclick/onload и ссылок javascript: в отдельные "
            "файлы скриптов. Пока код лежит в разметке, политику Content-Security-Policy "
            "приходится ослаблять директивой 'unsafe-inline', а она снимает основную "
            "защиту от внедрения чужого кода.",
            f"Атрибутов-обработчиков: {inline_handlers}, ссылок javascript:: {javascript_links}",
            "inline_handlers",
        )
    return findings


def _check_inline_scripts(soup: BeautifulSoup, add) -> None:
    """Анализ встроенных <script>: опасные приёмники DOM, postMessage, хранилища."""
    scripts = [tag.get_text() or "" for tag in soup.find_all("script") if not tag.get("src")]
    if not scripts:
        return

    for code in scripts:
        source = DOM_SOURCE.search(code)
        if not source:
            continue
        sinks = [name for name, pattern in DOM_SINKS if pattern.search(code)]
        if not sinks:
            continue
        add(
            "Данные из адреса страницы попадают в опасную функцию JavaScript (DOM XSS)",
            MEDIUM,
            "Не передавайте значения из location, document.referrer и window.name в "
            "innerHTML, document.write и eval. Вставляйте такие данные как текст "
            "(textContent) или экранируйте их перед вставкой в разметку.",
            f"Источник данных: {source.group(0)}\n"
            f"Приёмник: {', '.join(sinks)}\n"
            f"Фрагмент кода:\n{truncate(code.strip(), 300)}",
            "dom_xss_sink",
            category=VULN,
            confidence=SUSPECTED,
        )
        break

    for code in scripts:
        if MESSAGE_LISTENER.search(code) and not ORIGIN_CHECK.search(code):
            add(
                "Сообщения из других окон принимаются без проверки отправителя (postMessage)",
                MEDIUM,
                "В обработчике события message сравнивайте event.origin со списком "
                "разрешённых адресов до обработки данных. Без проверки любой сайт, "
                "открывший вашу страницу в iframe или новом окне, может прислать "
                "произвольные данные в этот обработчик.",
                truncate(code.strip(), 300),
                "postmessage_no_origin",
                category=VULN,
                confidence=SUSPECTED,
            )
            break

    for code in scripts:
        match = STORAGE_SECRET.search(code)
        if match:
            add(
                "Токены или пароли сохраняются в хранилище браузера",
                LOW,
                "Храните идентификатор сессии в cookie с флагами HttpOnly и Secure. "
                "Содержимое localStorage доступно любому скрипту на странице, поэтому "
                "одна XSS-уязвимость означает кражу сохранённого там токена.",
                truncate(match.group(0), 200),
                "token_in_storage",
                category=VULN,
                confidence=SUSPECTED,
            )
            break


def _find_version(pattern: "re.Pattern", haystacks: Iterable[str]
                  ) -> Optional[Tuple[Tuple[int, int, int], str]]:
    for text in haystacks:
        if not text:
            continue
        match = pattern.search(text)
        if not match:
            continue
        parts = [int(part) if part else 0 for part in match.groups()]
        while len(parts) < 3:
            parts.append(0)
        return (parts[0], parts[1], parts[2]), text
    return None


def _sensitive_params(url: str) -> List[str]:
    """Имена чувствительных параметров с непустыми значениями (значения не сохраняются)."""
    if not url:
        return []
    found = []
    for name, value in parse_qsl(urlparse(url).query, keep_blank_values=False):
        lowered = name.lower()
        if any(hint == lowered or hint in lowered for hint in SENSITIVE_PARAMS) and value:
            found.append(f"{name}=***")
    return found
