"""Поиск открытых служебных ресурсов (раздел 3.5 требований).

Читаются только статус ответа и первые байты — большие файлы не скачиваются.
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

from ..http_client import HttpClient
from ..models import CONFIG, CONFIRMED, HIGH, INFO, LOW, MEDIUM, SUSPECTED, Finding
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
    ("/.git/index", ("DIRC",), HIGH, "Индекс репозитория Git",
     "Запретите доступ к каталогу .git: по индексу и объектам восстанавливают исходный код.",
     "exposed_git"),
    ("/.hg/hgrc", ("[paths]", "[ui]"), MEDIUM, "Конфигурация Mercurial",
     "Удалите служебный каталог .hg из веб-корня.",
     "exposed_generic"),
    ("/backup.sql", ("CREATE TABLE", "INSERT INTO"), HIGH, "Дамп базы данных backup.sql",
     "Немедленно удалите дамп из веб-каталога и смените пароли из файла.",
     "exposed_dbdump"),
    ("/db.sql", ("CREATE TABLE", "INSERT INTO"), HIGH, "Дамп базы данных db.sql",
     "Немедленно удалите дамп из веб-каталога и смените пароли из файла.",
     "exposed_dbdump"),
    ("/database.sql", ("CREATE TABLE", "INSERT INTO"), HIGH, "Дамп базы данных database.sql",
     "Немедленно удалите дамп из веб-каталога и смените пароли из файла.",
     "exposed_dbdump"),
    ("/site.zip", ("PK",), HIGH, "Архив сайта site.zip",
     "Уберите архивы из публичного каталога.",
     "exposed_backup"),
    ("/www.zip", ("PK",), HIGH, "Архив сайта www.zip",
     "Уберите архивы из публичного каталога.",
     "exposed_backup"),
    ("/html.zip", ("PK",), HIGH, "Архив сайта html.zip",
     "Уберите архивы из публичного каталога.",
     "exposed_backup"),
    ("/.env.backup", ("=", "APP_", "DB_", "SECRET"), HIGH, "Резервная копия .env",
     "Удалите файл и смените все секреты, которые в нём были.",
     "exposed_env"),
    ("/.env.local", ("=", "APP_", "DB_"), HIGH, "Локальный файл окружения .env.local",
     "Удалите файл из веб-каталога и смените секреты.",
     "exposed_env"),
    ("/.env.production", ("=", "APP_", "DB_"), HIGH, "Файл окружения .env.production",
     "Удалите файл из веб-каталога и смените секреты.",
     "exposed_env"),
    ("/config.yml", ("password:", "secret:", "api_key:"), MEDIUM, "Конфигурация config.yml",
     "Не отдавайте конфигурационные файлы по HTTP.",
     "exposed_generic"),
    ("/config.yaml", ("password:", "secret:", "api_key:"), MEDIUM, "Конфигурация config.yaml",
     "Не отдавайте конфигурационные файлы по HTTP.",
     "exposed_generic"),
    ("/settings.py", ("SECRET_KEY", "DATABASES", "PASSWORD"), HIGH,
     "Файл настроек Django settings.py",
     "Уберите исходники и секреты из веб-корня.",
     "exposed_config_backup"),
    ("/wp-config.php.save", ("<?php", "DB_PASSWORD"), HIGH,
     "Сохранённая копия wp-config.php",
     "Удалите файл и смените пароль базы данных.",
     "exposed_config_backup"),
    ("/server-info", ("Apache Server Information", "Server Version"), MEDIUM,
     "Страница server-info",
     "Отключите mod_info или ограничьте доступ localhost.",
     "exposed_server_status"),
    ("/actuator/env", ("\"propertySources\"", "spring"), HIGH,
     "Actuator env (Spring Boot)",
     "Закройте /actuator/* аутентификацией: env раскрывает переменные окружения.",
     "exposed_actuator"),
    ("/actuator/mappings", ("\"mappings\"", "dispatcherServlets"), MEDIUM,
     "Actuator mappings (Spring Boot)",
     "Закройте служебные эндпоинты actuator.",
     "exposed_actuator"),
    ("/.well-known/security.txt", ("Contact:", "Expires:"), INFO,
     "Файл security.txt",
     "Файл полезен для ответственного раскрытия уязвимостей — это не проблема, "
     "если контакты указаны намеренно.",
     "exposed_generic"),
    ("/elmah.axd", ("ELMAH", "Error Log"), MEDIUM, "Журнал ошибок ELMAH",
     "Отключите публичный доступ к elmah.axd.",
     "exposed_logs"),
    ("/trace.axd", ("Application Trace", "Trace Information"), MEDIUM,
     "Страница трассировки ASP.NET",
     "Отключите tracing в production.",
     "exposed_debug"),
    ("/telescope", ("Laravel Telescope", "telescope"), MEDIUM,
     "Laravel Telescope",
     "Не публикуйте Telescope без аутентификации.",
     "exposed_debug"),
    ("/horizon", ("Laravel Horizon", "horizon"), MEDIUM,
     "Laravel Horizon",
     "Закройте панель очередей аутентификацией.",
     "exposed_debug"),
    ("/graphql", ("__schema", "GraphQL"), LOW, "GraphQL endpoint",
     "Отключите интроспекцию в production и ограничьте доступ к GraphQL.",
     "exposed_api_docs"),
    ("/api/graphql", ("__schema", "GraphQL"), LOW, "GraphQL API",
     "Отключите интроспекцию в production и ограничьте доступ к GraphQL.",
     "exposed_api_docs"),
    ("/swagger-ui.html", ("Swagger UI", "swagger"), LOW, "Swagger UI",
     "Закройте документацию API аутентификацией, если API внутреннее.",
     "exposed_api_docs"),
    ("/api-docs", ("swagger", "openapi"), LOW, "Документация API",
     "Закройте документацию API аутентификацией, если API внутреннее.",
     "exposed_api_docs"),
    ("/debug/default/view", ("Yii", "stack-trace", "PHP Warning"), MEDIUM,
     "Отладочная страница Yii",
     "Отключите YII_DEBUG в production.",
     "exposed_debug"),
    ("/rails/info/properties", ("Rails version", "Ruby version"), MEDIUM,
     "Страница свойств Rails",
     "Отключите публичный /rails/info в production.",
     "exposed_debug"),
    # --- дополнительные служебные / резервные / тестовые ---
    ("/.env.example", ("=", "APP_", "DB_"), LOW, "Пример файла окружения .env.example",
     "Не публикуйте шаблоны окружения с реальными именами переменных и примерами секретов.",
     "exposed_env"),
    ("/.env.dev", ("=", "APP_", "DB_", "SECRET"), HIGH, "Файл окружения .env.dev",
     "Удалите файл из веб-каталога и смените все секреты из него.",
     "exposed_env"),
    ("/.env.old", ("=", "APP_", "DB_", "SECRET"), HIGH, "Резервная копия .env.old",
     "Удалите резервные копии окружения из веб-корня и ротируйте секреты.",
     "exposed_env"),
    ("/.git/objects/info/packs", ("P ", "pack-"), HIGH, "Объекты репозитория Git",
     "Закройте весь каталог .git: по объектам восстанавливают исходный код.",
     "exposed_git"),
    ("/.gitignore", ("*", "/"), LOW, "Файл .gitignore",
     "Файл раскрывает структуру проекта. По возможности не отдавайте его из веб-корня.",
     "exposed_git"),
    ("/backup.rar", ("Rar!",), HIGH, "Архив резервной копии .rar",
     "Уберите архивы резервных копий из публичного каталога.",
     "exposed_backup"),
    ("/backup.tar", ("ustar",), HIGH, "Архив резервной копии .tar",
     "Уберите архивы резервных копий из публичного каталога.",
     "exposed_backup"),
    ("/db_backup.sql", ("CREATE TABLE", "INSERT INTO"), HIGH, "Дамп базы db_backup.sql",
     "Немедленно удалите дамп и смените пароли из него.",
     "exposed_dbdump"),
    ("/database.sql.gz", ("\x1f",), HIGH, "Сжатый дамп базы данных",
     "Удалите дамп из веб-каталога.",
     "exposed_dbdump"),
    ("/site.tar.gz", ("\x1f",), HIGH, "Архив сайта site.tar.gz",
     "Уберите архивы сайта из публичного каталога.",
     "exposed_backup"),
    ("/wwwroot.zip", ("PK",), HIGH, "Архив wwwroot.zip",
     "Уберите архивы из веб-корня.",
     "exposed_backup"),
    ("/public_html.zip", ("PK",), HIGH, "Архив public_html.zip",
     "Уберите архивы из веб-корня.",
     "exposed_backup"),
    ("/config.php.old", ("<?php", "password", "define("), HIGH,
     "Старая копия config.php",
     "Удалите *.old/*.bak файлы конфигурации из веб-каталога.",
     "exposed_config_backup"),
    ("/config.php~", ("<?php", "password", "define("), HIGH,
     "Редакторная копия config.php~",
     "Удалите временные файлы редакторов из веб-каталога.",
     "exposed_config_backup"),
    ("/wp-config.php.old", ("<?php", "DB_PASSWORD"), HIGH,
     "Старая копия wp-config.php",
     "Удалите файл: в нём пароли к базе WordPress.",
     "exposed_config_backup"),
    ("/settings.py.bak", ("SECRET_KEY", "DATABASES", "PASSWORD"), HIGH,
     "Резервная копия settings.py",
     "Удалите *.bak с секретами Django из веб-корня.",
     "exposed_config_backup"),
    ("/web.config.bak", ("<configuration", "<system.web"), HIGH,
     "Резервная копия web.config",
     "Удалите *.bak конфигурации IIS из веб-каталога.",
     "exposed_config_backup"),
    ("/info.php", ("phpinfo", "PHP Version"), MEDIUM, "Страница info.php (phpinfo)",
     "Удалите тестовую страницу phpinfo из production.",
     "exposed_phpinfo"),
    ("/test.php", ("phpinfo", "test", "<?php"), MEDIUM, "Тестовая страница test.php",
     "Удалите тестовые PHP-скрипты с production-сервера.",
     "exposed_test_page"),
    ("/test/", ("test", "Index of", "phpinfo"), LOW, "Каталог /test/",
     "Уберите тестовые каталоги из production или закройте их авторизацией.",
     "exposed_test_page"),
    ("/testing/", ("test", "Index of"), LOW, "Каталог /testing/",
     "Уберите тестовые каталоги из production.",
     "exposed_test_page"),
    ("/qa/", ("qa", "test", "Index of"), LOW, "Каталог /qa/",
     "Закройте QA-окружение от публичного доступа.",
     "exposed_test_page"),
    ("/demo/", ("demo", "sample", "Index of"), LOW, "Каталог /demo/",
     "Не публикуйте демо-разделы рядом с production без изоляции.",
     "exposed_test_page"),
    ("/dev/", ("dev", "debug", "Index of"), MEDIUM, "Каталог /dev/",
     "Закройте dev-разделы авторизацией или уберите их с публичного хоста.",
     "exposed_test_page"),
    ("/staging/", ("staging", "Index of"), MEDIUM, "Каталог /staging/",
     "Staging не должен быть доступен из интернета без VPN/авторизации.",
     "exposed_test_page"),
    ("/temp/", ("Index of", "tmp"), LOW, "Каталог /temp/",
     "Временные каталоги не должны быть в веб-корне.",
     "exposed_test_page"),
    ("/tmp/", ("Index of",), LOW, "Каталог /tmp/",
     "Временные каталоги не должны быть в веб-корне.",
     "exposed_test_page"),
    ("/old/", ("Index of", "backup"), MEDIUM, "Каталог /old/",
     "Старые копии сайта часто содержат уязвимые версии — уберите /old из публикации.",
     "exposed_backup"),
    ("/backup/", ("Index of", "backup", ".sql", ".zip"), HIGH, "Каталог /backup/",
     "Каталог резервных копий не должен быть доступен по HTTP.",
     "exposed_backup"),
    ("/_profiler", ("profiler", "Token", "Symfony"), MEDIUM, "Профайлер Symfony",
     "Отключите веб-профайлер в production.",
     "exposed_debug"),
    ("/__debug__/", ("Werkzeug", "Console", "Debugger"), HIGH, "Отладчик Werkzeug/Flask",
     "Немедленно отключите debug-режим: интерактивная консоль даёт выполнение на сервере.",
     "exposed_debug"),
    ("/.vscode/sftp.json", ("host", "username", "password", "remotePath"), HIGH,
     "Конфиг VS Code SFTP",
     "Удалите IDE-конфиги с паролями из веб-корня и смените пароли.",
     "exposed_config_backup"),
    ("/.idea/workspace.xml", ("project", "component"), LOW, "Файлы IDE JetBrains",
     "Не публикуйте каталоги IDE (.idea, .vscode) в веб-корне.",
     "exposed_config_backup"),
    ("/crossdomain.xml", ("cross-domain-policy", "allow-access-from"), MEDIUM,
     "Политика crossdomain.xml",
     "Ограничьте allow-access-from только доверенными доменами или удалите файл.",
     "exposed_api_docs"),
    ("/clientaccesspolicy.xml", ("access-policy", "allow-from"), MEDIUM,
     "Политика clientaccesspolicy.xml",
     "Ограничьте политику только нужными доменами.",
     "exposed_api_docs"),
    ("/server-info", ("Apache Server Information", "Server Settings"), MEDIUM,
     "Страница server-info",
     "Отключите mod_info или ограничьте доступ localhost.",
     "exposed_server_status"),
    ("/.htaccess", ("RewriteEngine", "AuthType", "Deny from"), MEDIUM,
     "Файл .htaccess",
     "Файл не должен отдаваться как текст — проверьте конфигурацию Apache.",
     "exposed_webconfig"),
    ("/cgi-bin/", ("Index of", "cgi"), LOW, "Каталог cgi-bin",
     "Ограничьте выполнение к cgi-bin и уберите ненужные скрипты.",
     "exposed_test_page"),
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
