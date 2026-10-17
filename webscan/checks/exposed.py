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

    # ========================================================================
    # Дальше — расширение базы путей до размеров аналогичных сканеров (Nikto,
    # Nuclei): больше вариантов резервных копий и секретов, конфигов CI/CD,
    # файлов IDE и облачных учётных данных, известных RCE-путей конкретных
    # продуктов и прямых адресов панелей мониторинга/администрирования.
    # Все запросы — GET, читаются только первые 512 байт ответа.
    # ========================================================================

    # --- ещё варианты файлов окружения и секретов -------------------------------
    ("/.env.staging", ("=", "APP_", "DB_", "SECRET"), HIGH, "Файл окружения .env.staging",
     "Удалите файл из веб-каталога и смените все секреты из него.",
     "exposed_env"),
    ("/.env.test", ("=", "APP_", "DB_"), HIGH, "Файл окружения .env.test",
     "Удалите файл из веб-каталога и смените секреты.",
     "exposed_env"),
    ("/.env~", ("=", "APP_", "DB_", "SECRET"), HIGH, "Редакторная копия .env~",
     "Удалите временные файлы редакторов из веб-корня и смените секреты.",
     "exposed_env"),
    ("/.netrc", ("machine", "login", "password"), HIGH, "Файл учётных данных .netrc",
     "Удалите файл: в нём открытым текстом хранятся пароли для FTP/HTTP-хостов.",
     "exposed_cloud_credentials"),
    ("/.pgpass", (":",), HIGH, "Файл паролей PostgreSQL .pgpass",
     "Удалите файл из веб-каталога и смените пароли к базе данных.",
     "exposed_cloud_credentials"),
    ("/.my.cnf", ("[client]", "password"), HIGH, "Конфигурация клиента MySQL .my.cnf",
     "Удалите файл: в нём пароль к базе данных открытым текстом.",
     "exposed_cloud_credentials"),
    ("/.ssh/id_rsa", ("PRIVATE KEY",), HIGH, "Закрытый SSH-ключ id_rsa",
     "Удалите ключ из веб-каталога и перевыпустите пару ключей.",
     "exposed_private_key"),
    ("/.ssh/id_ed25519", ("PRIVATE KEY",), HIGH, "Закрытый SSH-ключ id_ed25519",
     "Удалите ключ из веб-каталога и перевыпустите пару ключей.",
     "exposed_private_key"),
    ("/.ssh/known_hosts", ("ssh-rsa", "ssh-ed25519", "ecdsa-sha2"), MEDIUM,
     "Файл known_hosts",
     "Удалите файл: он раскрывает адреса серверов, с которыми работает приложение.",
     "exposed_cloud_credentials"),
    ("/.gcloud/credentials.db", ("access_token", "refresh_token"), HIGH,
     "Учётные данные Google Cloud SDK",
     "Немедленно удалите файл и отзовите токены доступа к Google Cloud.",
     "exposed_cloud_credentials"),
    ("/.azure/credentials", ("subscription", "client_id", "client_secret"), HIGH,
     "Учётные данные Azure CLI",
     "Немедленно удалите файл и отзовите ключи доступа к Azure.",
     "exposed_cloud_credentials"),
    ("/.kube/config", ("apiVersion", "clusters:", "users:"), HIGH,
     "Конфигурация доступа к кластеру Kubernetes",
     "Немедленно удалите kubeconfig и отзовите учётные данные: файл даёт полный доступ "
     "к управлению кластером.",
     "exposed_cloud_credentials"),
    ("/.docker/config.json", ("auths", "auth"), HIGH,
     "Учётные данные Docker Registry",
     "Удалите файл и отзовите токены доступа к реестру образов.",
     "exposed_cloud_credentials"),
    ("/serviceaccount/token", ("eyJ",), HIGH, "Токен Kubernetes ServiceAccount",
     "Токен даёт доступ к Kubernetes API от имени службы — немедленно отозвать и "
     "расследовать, как он попал в веб-корень.",
     "exposed_cloud_credentials"),

    # --- ещё резервные копии и дампы ---------------------------------------------
    ("/backup.sql.gz", ("\x1f",), HIGH, "Сжатый дамп backup.sql.gz",
     "Удалите дамп из веб-каталога.",
     "exposed_dbdump"),
    ("/dump.sql.gz", ("\x1f",), HIGH, "Сжатый дамп dump.sql.gz",
     "Удалите дамп из веб-каталога.",
     "exposed_dbdump"),
    ("/mysql.sql", ("CREATE TABLE", "INSERT INTO"), HIGH, "Дамп базы данных mysql.sql",
     "Немедленно удалите дамп и смените пароли из него.",
     "exposed_dbdump"),
    ("/backup.7z", ("7z",), HIGH, "Архив резервной копии .7z",
     "Уберите архивы резервных копий из публичного каталога.",
     "exposed_backup"),
    ("/site.sql.zip", ("PK",), HIGH, "Архив дампа базы site.sql.zip",
     "Уберите дамп базы из публичного каталога.",
     "exposed_backup"),
    ("/.git.zip", ("PK",), HIGH, "Архив репозитория .git.zip",
     "Удалите архив: по нему полностью восстанавливается исходный код и история коммитов.",
     "exposed_backup"),
    ("/vendor.zip", ("PK",), MEDIUM, "Архив зависимостей vendor.zip",
     "Уберите архивы зависимостей из веб-корня — они раскрывают версии библиотек.",
     "exposed_backup"),
    ("/node_modules.zip", ("PK",), MEDIUM, "Архив node_modules.zip",
     "Уберите архивы зависимостей из веб-корня.",
     "exposed_backup"),

    # --- ещё системы контроля версий ---------------------------------------------
    ("/.bzr/branch-format", ("Bazaar",), MEDIUM, "Служебные файлы Bazaar",
     "Удалите каталог .bzr из веб-корня.",
     "exposed_svn"),
    ("/CVS/Root", (":", "/"), MEDIUM, "Служебные файлы CVS",
     "Удалите каталог CVS из веб-корня.",
     "exposed_svn"),
    ("/.gitlab-ci.yml", ("stages:", "script:", "image:"), LOW, "Конфигурация GitLab CI",
     "Файл раскрывает структуру пайплайна сборки. Не публикуйте секреты прямо в нём.",
     "exposed_compose"),
    ("/.travis.yml", ("language:", "script:"), LOW, "Конфигурация Travis CI",
     "Файл раскрывает структуру сборки — проверьте, что в нём нет секретов открытым текстом.",
     "exposed_compose"),
    ("/.circleci/config.yml", ("version:", "jobs:"), LOW, "Конфигурация CircleCI",
     "Файл раскрывает структуру пайплайна. Секреты должны храниться в переменных CI, а не в файле.",
     "exposed_compose"),
    ("/azure-pipelines.yml", ("trigger:", "steps:", "pool:"), LOW, "Конфигурация Azure Pipelines",
     "Файл раскрывает структуру сборки — проверьте отсутствие секретов в открытом виде.",
     "exposed_compose"),
    ("/Jenkinsfile", ("pipeline", "stage(", "node {"), LOW, "Jenkinsfile",
     "Файл раскрывает структуру CI/CD-пайплайна и используемые инструменты.",
     "exposed_compose"),
    ("/docker-compose.override.yml", ("services:", "image:"), MEDIUM,
     "Файл docker-compose.override.yml",
     "Уберите инфраструктурные файлы из веб-каталога.",
     "exposed_compose"),
    ("/Dockerfile", ("FROM ", "RUN ", "COPY "), LOW, "Файл Dockerfile",
     "Файл раскрывает состав образа и внутреннюю структуру приложения.",
     "exposed_compose"),

    # --- известные RCE-пути конкретных продуктов ---------------------------------
    ("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
     ("PHPUnit", "eval-stdin"), HIGH,
     "PHPUnit eval-stdin.php в веб-каталоге (CVE-2017-9841)",
     "Удалите каталог vendor/ из веб-корня или запретите к нему доступ: файл выполняет "
     "произвольный PHP-код из тела запроса без авторизации.",
     "exposed_debug"),
    ("/_profiler/phpinfo", ("phpinfo", "PHP Version"), MEDIUM,
     "phpinfo через профайлер Symfony",
     "Отключите веб-профайлер Symfony в production.",
     "exposed_debug"),
    ("/console/", ("Symfony", "Web Debug Toolbar"), MEDIUM, "Консоль разработчика Symfony",
     "Отключите debug-режим и веб-консоль Symfony в production.",
     "exposed_debug"),
    ("/actuator/heapdump", ("JAVA PROFILE", "HPROF"), HIGH,
     "Actuator heapdump (Spring Boot)",
     "Немедленно закройте /actuator/heapdump: дамп памяти приложения может содержать "
     "пароли, токены и сессии пользователей в открытом виде.",
     "exposed_actuator"),
    ("/actuator/configprops", ("\"beans\"", "properties"), HIGH,
     "Actuator configprops (Spring Boot)",
     "Закройте /actuator/* аутентификацией: эндпоинт раскрывает конфигурацию приложения, "
     "включая пароли подключений, если они не замаскированы.",
     "exposed_actuator"),
    ("/actuator/loggers", ("\"configuredLevel\"", "loggers"), MEDIUM,
     "Actuator loggers (Spring Boot)",
     "Закройте служебные эндпоинты actuator.",
     "exposed_actuator"),
    ("/jolokia", ("\"request\"", "mbean"), HIGH, "JMX через Jolokia",
     "Закройте Jolokia аутентификацией или уберите из production: открытый JMX-мост "
     "часто используют для выполнения кода на сервере.",
     "exposed_debug"),
    ("/solr/admin/info/system", ("\"responseHeader\"", "solr-spec-version"), MEDIUM,
     "Административная консоль Apache Solr",
     "Закройте админку Solr доступом по IP/VPN: через неё возможна загрузка конфигов "
     "и выполнение кода в уязвимых версиях.",
     "exposed_admin_panel"),
    ("/manager/text/list", ("OK - Listed applications",), HIGH,
     "Tomcat Manager (text interface)",
     "Закройте Tomcat Manager аутентификацией или уберите из production: через него "
     "разворачивают произвольные .war-приложения.",
     "exposed_admin_panel"),

    # --- прямые адреса панелей мониторинга и администрирования ------------------
    ("/grafana/login", ("Grafana", "Welcome to Grafana"), MEDIUM,
     "Панель Grafana",
     "Закройте Grafana доступом по IP/VPN и отключите анонимный доступ в настройках.",
     "exposed_admin_panel"),
    ("/kibana/app/kibana", ("Kibana",), MEDIUM, "Панель Kibana",
     "Закройте Kibana доступом по IP/VPN — по умолчанию она не требует авторизации.",
     "exposed_admin_panel"),
    ("/_cluster/health", ("\"cluster_name\"", "\"status\""), HIGH,
     "Elasticsearch REST API без авторизации",
     "Закройте Elasticsearch firewall'ом/VPN и включите аутентификацию (X-Pack Security "
     "или аналог) — без неё через REST API читают и удаляют все данные кластера.",
     "exposed_admin_panel"),
    ("/_cat/indices?v", ("health", "status", "index"), HIGH,
     "Список индексов Elasticsearch без авторизации",
     "Закройте Elasticsearch аутентификацией: список индексов раскрывает структуру "
     "хранимых данных, а REST API без защиты даёт полный доступ к ним.",
     "exposed_admin_panel"),
    ("/_utils/", ("CouchDB", "Fauxton"), MEDIUM, "Панель администрирования CouchDB",
     "Закройте _utils/ аутентификацией — административная консоль CouchDB не должна "
     "быть доступна анонимно.",
     "exposed_admin_panel"),
    ("/api/overview", ("rabbitmq_version", "management_version"), HIGH,
     "RabbitMQ Management API без авторизации",
     "Закройте плагин управления RabbitMQ аутентификацией и доступом по IP/VPN.",
     "exposed_admin_panel"),
    ("/v1/catalog/services", ("consul",), HIGH, "Consul API без авторизации",
     "Включите ACL в Consul и закройте API доступом по IP/VPN: без защиты через него "
     "читают и меняют конфигурацию всех зарегистрированных сервисов.",
     "exposed_admin_panel"),
    ("/version", ("etcdserver", "etcdcluster"), HIGH, "etcd API без авторизации",
     "Включите аутентификацию etcd и закройте доступ сетевыми правилами: в etcd "
     "обычно хранятся секреты и конфигурация кластера.",
     "exposed_admin_panel"),
    ("/pgadmin4/", ("pgAdmin", "PostgreSQL Tools"), MEDIUM,
     "Панель управления базой данных (pgAdmin)",
     "Закройте панель доступом по IP/VPN: она даёт прямой доступ к базе данных.",
     "exposed_db_admin"),
    ("/phpliteadmin.php", ("phpLiteAdmin", "SQLite"), MEDIUM,
     "Панель управления базой данных (phpLiteAdmin)",
     "Удалите файл или закройте доступ: панель даёт полный доступ к файлам SQLite.",
     "exposed_db_admin"),
    ("/mongo-express/", ("Mongo Express", "mongodb"), MEDIUM,
     "Панель управления базой данных (Mongo Express)",
     "Закройте панель аутентификацией и доступом по IP/VPN: она даёт полный доступ к MongoDB.",
     "exposed_db_admin"),

    # --- ещё отладочные/тестовые разделы и файлы ---------------------------------
    ("/wp-json/wp/v2/users", ("\"id\"", "\"slug\"", "\"name\""), LOW,
     "Перечисление пользователей WordPress через REST API",
     "Ограничьте доступ к /wp-json/wp/v2/users или скройте поле slug/name для "
     "неавторизованных запросов: по нему подбирают логины для брутфорса.",
     "exposed_api_docs"),
    ("/xmlrpc.php", ("methodCall", "XML-RPC server accepts POST"), LOW,
     "Включённый XML-RPC в WordPress",
     "Отключите xmlrpc.php, если не используете Jetpack/мобильное приложение: его "
     "используют для подбора пароля и DDoS-усиления (pingback).",
     "exposed_debug"),
    ("/CHANGELOG.txt", ("Drupal", "fixed in"), LOW, "CHANGELOG.txt Drupal",
     "Файл раскрывает точную версию Drupal, по которой подбирают известные CVE. "
     "Ограничьте к нему доступ.",
     "exposed_generic"),
    ("/core/CHANGELOG.txt", ("Drupal", "fixed in"), LOW, "CHANGELOG.txt Drupal (core)",
     "Файл раскрывает точную версию Drupal. Ограничьте к нему доступ.",
     "exposed_generic"),
    ("/npm-debug.log", ("npm ERR!",), MEDIUM, "Журнал ошибок npm-debug.log",
     "Удалите журналы сборки из веб-каталога: в них попадают пути и иногда токены.",
     "exposed_logs"),
    ("/yarn-error.log", ("Arguments:", "PATH:"), MEDIUM, "Журнал ошибок yarn-error.log",
     "Удалите журналы сборки из веб-каталога.",
     "exposed_logs"),
    ("/storage/debugbar/", ("Laravel Debugbar",), MEDIUM, "Laravel Debugbar",
     "Отключите Debugbar в production — он раскрывает запросы к БД и параметры сессии.",
     "exposed_debug"),
    ("/_ignition/health-check", ("canExecuteCommands", "ignition"), HIGH,
     "Laravel Ignition (CVE-2021-3129)",
     "Обновите facade/ignition и отключите debug-режим: уязвимые версии позволяют "
     "выполнить код через подмену файла логов.",
     "exposed_debug"),
    ("/.well-known/openid-configuration", ("issuer", "authorization_endpoint"), INFO,
     "Конфигурация OpenID Connect",
     "Это служебный, предназначенный для публикации файл — проверьте, что в нём нет "
     "внутренних адресов, не видимых снаружи.",
     "exposed_generic"),
    ("/metrics", ("# HELP", "# TYPE"), MEDIUM, "Метрики Prometheus без авторизации",
     "Закройте эндпоинт /metrics доступом по IP/VPN: метрики приложения часто "
     "раскрывают внутренние адреса, версии и объём трафика по каждому маршруту.",
     "exposed_admin_panel"),
    ("/debug/pprof/", ("profile", "goroutine", "heap"), HIGH,
     "Профилировщик Go net/http/pprof",
     "Отключите /debug/pprof в production — он раскрывает состояние памяти и "
     "трассировки горутин приложения.",
     "exposed_debug"),
)

# Строгие проверки содержимого. Короткие маркеры («=», «PK», «dir», «test») встречаются
# в любой HTML-странице, поэтому для таких путей подтверждение идёт по формату файла.
_LISTING = r"Index of /|Directory listing for|<title>Index of|Parent Directory"
_ENV_LINES = r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]{2,}\s*=\s*\S"
STRICT_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    path: re.compile(pattern, re.I if ignore_case else 0)
    for path, pattern, ignore_case in (
        ("/.env", _ENV_LINES, False),
        ("/.env.backup", _ENV_LINES, False),
        ("/.env.local", _ENV_LINES, False),
        ("/.env.production", _ENV_LINES, False),
        ("/.env.example", _ENV_LINES, False),
        ("/.env.dev", _ENV_LINES, False),
        ("/.env.old", _ENV_LINES, False),
        ("/.env.staging", _ENV_LINES, False),
        ("/.env.test", _ENV_LINES, False),
        ("/.env~", _ENV_LINES, False),
        ("/.htpasswd", r"(?m)^[^\s:<>]+:(?:\$|\{SHA\}|[A-Za-z0-9./]{13})", False),
        ("/.svn/entries", r"(?m)^(?:dir|file)\s*$", False),
        ("/.git/objects/info/packs", r"(?m)^P pack-", False),
        ("/.idea/workspace.xml", r"<project[^>]*version", True),
        ("/.vscode/sftp.json", r"\"(?:password|remotePath|privateKeyPath)\"\s*:", True),
        ("/actuator/health", r"\"status\"\s*:\s*\"(?:UP|DOWN|OUT_OF_SERVICE)", True),
        ("/debug", r"Traceback \(most recent|phpinfo\(\)|PHP Version|Werkzeug|Debug Toolbar|"
                   r"Stack trace", True),
        ("/test.php", r"phpinfo\(\)|PHP Version|<\?php", True),
        ("/telescope", r"Laravel Telescope", True),
        ("/horizon", r"Laravel Horizon", True),
        ("/test/", _LISTING, True),
        ("/testing/", _LISTING, True),
        ("/qa/", _LISTING, True),
        ("/demo/", _LISTING, True),
        ("/dev/", _LISTING, True),
        ("/staging/", _LISTING, True),
        ("/temp/", _LISTING, True),
        ("/tmp/", _LISTING, True),
        ("/old/", _LISTING, True),
        ("/backup/", _LISTING, True),
        ("/cgi-bin/", _LISTING, True),
        ("/.pgpass", r"(?m)^[^:\s]+:\d+:[^:\s]+:[^:\s]+:", False),
        ("/serviceaccount/token", r"^eyJ[A-Za-z0-9_-]{8,}\.eyJ", False),
    )
}
# Бинарные форматы: подтверждаются сигнатурой в начале файла (или со смещением).
MAGIC_BYTES: Dict[str, Tuple[bytes, int]] = {
    "/backup.zip": (b"PK\x03\x04", 0), "/site.zip": (b"PK\x03\x04", 0),
    "/www.zip": (b"PK\x03\x04", 0), "/html.zip": (b"PK\x03\x04", 0),
    "/wwwroot.zip": (b"PK\x03\x04", 0), "/public_html.zip": (b"PK\x03\x04", 0),
    "/.git.zip": (b"PK\x03\x04", 0), "/vendor.zip": (b"PK\x03\x04", 0),
    "/node_modules.zip": (b"PK\x03\x04", 0), "/site.sql.zip": (b"PK\x03\x04", 0),
    "/backup.tar.gz": (b"\x1f\x8b", 0), "/site.tar.gz": (b"\x1f\x8b", 0),
    "/database.sql.gz": (b"\x1f\x8b", 0), "/backup.sql.gz": (b"\x1f\x8b", 0),
    "/dump.sql.gz": (b"\x1f\x8b", 0),
    "/backup.rar": (b"Rar!", 0), "/backup.tar": (b"ustar", 257),
    "/backup.7z": (b"7z\xbc\xaf\x27\x1c", 0),
}
MIN_MARKER_LENGTH = 4

# Виды находок, где ожидается не HTML-страница, а файл: HTML-ответ — это «мягкая 404».
NON_HTML_KINDS = frozenset({
    "exposed_env", "exposed_git", "exposed_backup", "exposed_dbdump", "exposed_htpasswd",
    "exposed_private_key", "exposed_cloud_credentials", "exposed_package_token",
    "exposed_dependencies", "exposed_dsstore", "exposed_config_backup", "exposed_webconfig",
    "exposed_generic", "exposed_svn",
})
HTML_SIGNS = ("<!doctype html", "<html", "<head", "<body")


DIRECTORY_LISTING_MARKERS = ("Index of /", "<title>Directory listing for", "Parent Directory")


def check_exposed_paths(client: HttpClient, base_url: str, reserve: int = 0,
                        limit: Optional[int] = None) -> List[Finding]:
    findings: List[Finding] = []
    baseline = _baseline(client, base_url, reserve)

    entries = list(SENSITIVE_PATHS)
    if limit is not None:
        entries = entries[:limit]
    position = 0
    while position < len(entries):
        if not client.can_request(reserve):
            break
        # Пачка запросов уходит параллельно, а разбор идёт по порядку списка путей —
        # набор и порядок находок не зависят от скорости ответов.
        chunk = entries[position:position + max(1, client.concurrency * 2)]
        position += len(chunk)
        urls = [urljoin(base_url, entry[0]) for entry in chunk]
        request_kwargs = dict(allow_redirects=False, max_body_bytes=PEEK_BYTES, reserve=reserve)
        responses = client.request_many([("GET", url, request_kwargs) for url in urls])
        for entry, url, response in zip(chunk, urls, responses):
            if response is not None and response.status_code == 429:
                # Сайт ограничил частоту: ответ 429 — не результат проверки, повторяем один раз.
                response = client.get(url, **request_kwargs)
            findings.extend(_analyze_exposed(entry, url, response, baseline))
    return findings


def _analyze_exposed(entry, url: str, response, baseline) -> List[Finding]:
    path, markers, severity, name, recommendation, kind = entry
    findings: List[Finding] = []
    if response is None:
        return findings

    status = response.status_code
    peek = _peek(response)
    request_text = f"GET {url}"

    if status in (401, 403):
        if baseline is not None and baseline.get("status") == status:
            return findings  # закрыто всё подряд (WAF, глобальная авторизация) — это не находка
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
        return findings

    if status != 200:
        return findings

    if baseline is not None and _looks_like_soft_404(peek, baseline):
        return findings  # сервер отдаёт 200 на любой путь — это не находка

    html_like = _looks_like_html(peek)
    if html_like and kind in NON_HTML_KINDS and not path.endswith("/"):
        return findings  # вместо файла пришла HTML-страница (SPA, кастомная 404)

    confirmed = _is_confirmed(path, markers, peek, response)
    if not confirmed and html_like:
        return findings  # обычная страница без признаков искомого ресурса

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


def _is_confirmed(path: str, markers: Tuple[str, ...], peek: str, response) -> bool:
    """Подтверждение по формату файла, а для остальных — по достаточно длинным маркерам."""
    magic = MAGIC_BYTES.get(path)
    if magic is not None:
        signature, offset = magic
        raw = bytes(response.content or b"")[:PEEK_BYTES]
        return raw[offset:offset + len(signature)] == signature
    strict = STRICT_PATTERNS.get(path)
    if strict is not None:
        return strict.search(peek) is not None
    lowered = peek.lower()
    return any(marker.lower() in lowered for marker in markers
               if len(marker) >= MIN_MARKER_LENGTH)


def _looks_like_html(text: str) -> bool:
    head = text[:400].lower()
    return any(sign in head for sign in HTML_SIGNS)


def _title(text: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    return " ".join(match.group(1).split()).lower() if match else ""


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
    peek = _peek(response)
    return {"status": response.status_code, "peek": peek, "title": _title(peek)}


def _looks_like_soft_404(peek: str, baseline: Dict[str, object]) -> bool:
    if baseline.get("status") != 200:
        return False
    base_peek = str(baseline.get("peek", ""))
    if not base_peek:
        return False
    if peek == base_peek:
        return True
    title = _title(peek)
    if title and title == baseline.get("title"):
        return True  # тот же <title>, что у страницы «не найдено»
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
