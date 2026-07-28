"""Поиск открытых служебных ресурсов (раздел 3.5 требований).

Читаются только статус ответа и первые байты — большие файлы не скачиваются.
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from ..http_client import HttpClient
from ..models import CONFIG, CONFIRMED, HIGH, LOW, MEDIUM, SUSPECTED, Finding
from ..utils import truncate

PEEK_BYTES = 512
RANDOM_PATH = "/bauman-scanner-404-probe-92841"

# (путь, маркеры подтверждения, критичность, описание, рекомендация, вид находки)
SENSITIVE_PATHS: Tuple[Tuple[str, Tuple[str, ...], str, str, str, str], ...] = (
    ("/.env", ("=", "APP_", "DB_", "SECRET"), HIGH, "Файл окружения .env",
     "Удалите файл из веб-каталога и запретите доступ к скрытым файлам на уровне веб-сервера. "
     "Считайте все находившиеся в нём учётные данные скомпрометированными и смените их.",
     "exposed_env"),
    ("/.git/config", ("[core]", "[remote", "repositoryformatversion"), HIGH,
     "Конфигурация репозитория Git",
     "Удалите каталог .git из корня сайта или запретите к нему доступ — иначе исходный код "
     "можно полностью восстановить.",
     "exposed_git"),
    ("/.git/HEAD", ("ref:", "refs/heads"), HIGH, "Служебный файл Git HEAD",
     "Запретите доступ к каталогу .git на уровне веб-сервера.",
     "exposed_git"),
    ("/backup.zip", ("PK",), HIGH, "Архив резервной копии",
     "Уберите резервные копии из публичного каталога, храните их вне веб-корня.",
     "exposed_backup"),
    ("/backup.tar.gz", ("\x1f",), HIGH, "Архив резервной копии",
     "Уберите резервные копии из публичного каталога, храните их вне веб-корня.",
     "exposed_backup"),
    ("/dump.sql", ("CREATE TABLE", "INSERT INTO", "--"), HIGH, "Дамп базы данных",
     "Немедленно удалите дамп из веб-каталога и смените пароли, которые могли в нём находиться.",
     "exposed_dbdump"),
    ("/debug", ("debug", "trace", "traceback", "phpinfo"), MEDIUM, "Отладочный интерфейс",
     "Отключите отладочные режимы и панели в production-окружении.",
     "exposed_debug"),
    ("/swagger.json", ("swagger", "openapi", "\"paths\""), LOW, "Описание API (Swagger/OpenAPI)",
     "Если API внутреннее, закройте документацию аутентификацией.",
     "exposed_api_docs"),
    ("/openapi.json", ("openapi", "\"paths\""), LOW, "Описание API (OpenAPI)",
     "Если API внутреннее, закройте документацию аутентификацией.",
     "exposed_api_docs"),
    ("/.svn/entries", ("dir", "svn"), MEDIUM, "Служебные файлы Subversion",
     "Удалите каталог .svn из веб-корня.",
     "exposed_svn"),
    ("/.DS_Store", ("Bud1",), LOW, "Файл .DS_Store (структура каталогов)",
     "Удалите файл и добавьте его в .gitignore / правила деплоя.",
     "exposed_dsstore"),
    ("/phpinfo.php", ("phpinfo", "PHP Version"), MEDIUM, "Страница phpinfo()",
     "Удалите файл: он раскрывает конфигурацию сервера, пути и расширения PHP.",
     "exposed_phpinfo"),
    ("/server-status", ("Apache Server Status", "Server uptime"), MEDIUM,
     "Страница состояния веб-сервера",
     "Ограничьте mod_status доступом с localhost или отключите его.",
     "exposed_server_status"),
    ("/actuator/health", ("\"status\"", "UP"), LOW, "Actuator (Spring Boot)",
     "Закройте служебные эндпоинты actuator аутентификацией, оставив наружу минимум.",
     "exposed_actuator"),
    ("/web.config", ("<configuration", "<system.web"), MEDIUM, "Конфигурация IIS web.config",
     "Файл не должен отдаваться по HTTP — проверьте обработчики статических файлов.",
     "exposed_webconfig"),
    ("/.htpasswd", (":",), HIGH, "Файл паролей .htpasswd",
     "Запретите доступ к файлам .ht* и смените все пароли из файла.",
     "exposed_htpasswd"),
    ("/docker-compose.yml", ("services:", "image:", "version:"), MEDIUM,
     "Файл docker-compose.yml",
     "Уберите инфраструктурные файлы из веб-каталога.",
     "exposed_compose"),
    ("/config.php.bak", ("<?php", "password", "define("), HIGH, "Резервная копия конфигурации",
     "Удалите *.bak/*.old файлы из веб-каталога: они отдаются как текст вместе с паролями.",
     "exposed_config_backup"),
    ("/wp-config.php.bak", ("<?php", "DB_PASSWORD", "define("), HIGH,
     "Резервная копия конфигурации WordPress",
     "Удалите файл: в нём открытым текстом лежат логин и пароль к базе данных сайта.",
     "exposed_config_backup"),
    ("/.aws/credentials", ("aws_access_key_id", "[default]"), HIGH,
     "Ключи доступа к облаку AWS",
     "Немедленно удалите файл и отзовите ключи: они дают доступ к облачной инфраструктуре "
     "и оплачиваемым ресурсам.",
     "exposed_cloud_credentials"),
    ("/id_rsa", ("PRIVATE KEY",), HIGH, "Закрытый SSH-ключ",
     "Удалите ключ из веб-каталога и перевыпустите пару ключей: закрытый ключ даёт вход "
     "на сервер без пароля.",
     "exposed_private_key"),
    ("/.npmrc", ("_authToken", "registry="), MEDIUM, "Файл настроек npm (.npmrc)",
     "Уберите файл из веб-каталога: он содержит токен доступа к реестру пакетов.",
     "exposed_package_token"),
    ("/composer.json", ("\"require\"", "\"autoload\"", "\"name\""), LOW,
     "Список зависимостей PHP (composer.json)",
     "Файл раскрывает состав и версии библиотек. По возможности не публикуйте его: по "
     "версиям зависимостей подбирают известные уязвимости.",
     "exposed_dependencies"),
    ("/package.json", ("\"dependencies\"", "\"devDependencies\"", "\"scripts\""), LOW,
     "Список зависимостей Node.js (package.json)",
     "Файл раскрывает состав и версии библиотек, а иногда и внутренние команды сборки. "
     "Не публикуйте его в корне сайта.",
     "exposed_dependencies"),
    ("/phpmyadmin/", ("phpMyAdmin", "pma_username"), MEDIUM,
     "Панель управления базой данных (phpMyAdmin)",
     "Закройте панель доступом по IP или VPN: она открывает прямой доступ к базе и "
     "постоянно перебирается ботами.",
     "exposed_db_admin"),
    ("/adminer.php", ("Adminer", "Login"), MEDIUM,
     "Панель управления базой данных (Adminer)",
     "Удалите файл или закройте доступ: один PHP-файл даёт полный доступ к базе данных.",
     "exposed_db_admin"),
    ("/storage/logs/laravel.log", ("stacktrace", "local.ERROR", "#0 /"), MEDIUM,
     "Журнал ошибок приложения",
     "Уберите каталог логов из веб-корня: в трассировках ошибок оказываются пути, "
     "SQL-запросы и параметры пользователей.",
     "exposed_logs"),
)

DIRECTORY_LISTING_MARKERS = ("Index of /", "<title>Directory listing for", "Parent Directory")


def check_exposed_paths(client: HttpClient, base_url: str, reserve: int = 0,
                        limit: Optional[int] = None) -> List[Finding]:
    findings: List[Finding] = []
    baseline = _baseline(client, base_url, reserve)

    checked = 0
    for path, markers, severity, name, recommendation, kind in SENSITIVE_PATHS:
        if limit is not None and checked >= limit:
            break
        if not client.can_request(reserve):
            break
        url = urljoin(base_url, path)
        response = client.get(url, allow_redirects=False, max_body_bytes=PEEK_BYTES,
                              reserve=reserve)
        checked += 1
        if response is None:
            continue

        status = response.status_code
        peek = _peek(response)
        request_text = f"GET {url}"

        if status in (401, 403):
            findings.append(
                Finding(
                    url=url,
                    title=f"Служебный ресурс существует, но закрыт: {name}",
                    category=CONFIG,
                    severity=LOW,
                    recommendation="Доступ ограничен. По возможности отдавайте 404, чтобы не "
                                   "раскрывать наличие файла.",
                    request=request_text,
                    evidence=f"HTTP/{status}",
                    confidence=CONFIRMED,
                    kind="exposed_protected",
                )
            )
            continue

        if status != 200:
            continue

        if baseline is not None and _looks_like_soft_404(peek, baseline):
            continue  # сервер отдаёт 200 на любой путь — это не находка

        confirmed = any(marker.lower() in peek.lower() for marker in markers)
        findings.append(
            Finding(
                url=url,
                title=f"Доступен служебный ресурс: {name}",
                category=CONFIG,
                severity=severity if confirmed else _downgrade(severity),
                recommendation=recommendation,
                request=request_text,
                evidence=truncate(
                    f"HTTP/{status}\n"
                    f"Content-Type: {response.headers.get('Content-Type', '-')}\n"
                    f"Content-Length: {response.headers.get('Content-Length', '-')}\n"
                    f"Первые байты ответа:\n{peek}",
                    700,
                ),
                confidence=CONFIRMED if confirmed else SUSPECTED,
                kind=kind,
            )
        )
    return findings


SENSITIVE_ROBOTS_HINTS = ("admin", "backup", "config", "private", "secret", "internal",
                          "db", "sql", "dump", "test", "dev", "staging", "phpmyadmin",
                          "manager", "console", "upload", "log", "tmp", "old", "cgi-bin",
                          "wp-admin", "user", "account", "billing", "invoice")


def check_robots(client: HttpClient, base_url: str, reserve: int = 0) -> List[Finding]:
    """Служебные разделы, перечисленные в robots.txt (один запрос)."""
    if not client.can_request(reserve):
        return []
    url = urljoin(base_url, "/robots.txt")
    response = client.get(url, allow_redirects=False, max_body_bytes=PEEK_BYTES, reserve=reserve)
    if response is None or response.status_code != 200:
        return []
    text = _peek(response)
    if "user-agent" not in text.lower() and "disallow" not in text.lower():
        return []

    disallowed = re.findall(r"(?im)^\s*(?:dis)?allow\s*:\s*(\S+)", text)
    interesting = [path for path in disallowed
                   if any(hint in path.lower() for hint in SENSITIVE_ROBOTS_HINTS)]
    if not interesting:
        return []
    return [
        Finding(
            url=url,
            title=f"robots.txt перечисляет служебные разделы ({len(interesting)})",
            category=CONFIG,
            severity=LOW,
            recommendation="Не перечисляйте в robots.txt адреса административных и служебных "
                           "разделов: файл открыт всем. Закрывайте такие разделы авторизацией, "
                           "а от индексации защищайте заголовком X-Robots-Tag или метатегом.",
            request=f"GET {url}",
            evidence=truncate("Найденные пути:\n" + "\n".join(interesting[:12]), 600),
            confidence=CONFIRMED,
            kind="robots_sensitive",
        )
    ]


def check_directory_listing(page_url: str, body: str) -> List[Finding]:
    """Открытый листинг каталога в уже загруженной странице."""
    for marker in DIRECTORY_LISTING_MARKERS:
        if marker.lower() in body.lower():
            return [
                Finding(
                    url=page_url,
                    title="Включён листинг каталога",
                    category=CONFIG,
                    severity=MEDIUM,
                    recommendation="Отключите автоиндекс каталогов (Options -Indexes в Apache, "
                                   "autoindex off в nginx) и добавьте индексный файл.",
                    request=f"GET {page_url}",
                    evidence=truncate(marker + " …", 200),
                    confidence=CONFIRMED,
                    kind="directory_listing",
                )
            ]
    return []


def _baseline(client: HttpClient, base_url: str, reserve: int) -> Optional[Dict[str, object]]:
    """Ответ на несуществующий путь — для распознавания «мягких 404»."""
    if not client.can_request(reserve):
        return None
    url = urljoin(base_url, RANDOM_PATH)
    response = client.get(url, allow_redirects=False, max_body_bytes=PEEK_BYTES, reserve=reserve)
    if response is None:
        return None
    return {"status": response.status_code, "peek": _peek(response)}


def _looks_like_soft_404(peek: str, baseline: Dict[str, object]) -> bool:
    if baseline.get("status") != 200:
        return False
    base_peek = str(baseline.get("peek", ""))
    if not base_peek:
        return False
    if peek == base_peek:
        return True
    shorter = min(len(peek), len(base_peek))
    if shorter < 40:
        return False
    return peek[:200] == base_peek[:200]


def _peek(response) -> str:
    data = response.content or b""
    text = data.decode(response.encoding or "utf-8", errors="replace")
    return text[:PEEK_BYTES].replace("\r", "")


def _downgrade(severity: str) -> str:
    """Понижение уровня для неподтверждённых находок; ниже «Низкой» не опускаемся:
    уровень «Безопасно» зарезервирован для записей, где проблемы нет."""
    return {HIGH: MEDIUM, MEDIUM: LOW}.get(severity, LOW)
