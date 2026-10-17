"""Пассивное определение программных компонентов по уже загруженным страницам.

Модуль не выполняет дополнительных запросов к целевому сайту. Он использует
заголовки, meta generator, адреса и баннеры подключённых JS/CSS, характерные
пути и имена cookie — всё, что уже собрано BFS-обходом.

Сигнатуры описаны данными (``SIGNATURES``): чтобы научить сканер новому
продукту, достаточно добавить словарь в список. Пары ``vendor:product`` для CPE
сверены со словарём NVD CPE Dictionary; у продукта может быть несколько пар
(например, nginx до 2022 г. заведён как ``nginx:nginx``, после — ``f5:nginx``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlparse

from bs4 import BeautifulSoup

from .models import Page


V = r"(?P<version>\d+(?:\.\d+){0,4}(?:[a-z](?![a-z]))?(?:[-+~][0-9A-Za-z.+~-]+)?)"

# Источники признаков
HEADER = "header"        # поле ``headers`` — какие HTTP-заголовки смотреть
GENERATOR = "generator"  # <meta name="generator"> и X-Generator
ASSET = "asset"          # адреса <script src>, <link href>
BANNER = "banner"        # комментарии-баннеры в теле JS/CSS и inline-скриптах
PATH = "path"            # характерные пути в ссылках и ресурсах
COOKIE = "cookie"        # имена cookie (дают продукт без версии)
BODY = "body"            # текст HTML-страницы целиком (заголовок <title>, фирменные строки) —
                         # используется только для очень характерных строк, которые не
                         # встречаются на обычных сайтах, чтобы не плодить ложные совпадения

SERVER_HEADERS = ("server", "via")
POWERED_HEADERS = ("x-powered-by", "server")

SIGNATURES: List[Dict[str, object]] = [
    # --- веб-серверы и платформы (HTTP-заголовки) -------------------------------
    {"label": "nginx", "cpe": [("f5", "nginx"), ("nginx", "nginx")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bnginx(?:/" + V + r")?"},
    {"label": "Apache HTTP Server", "cpe": [("apache", "http_server")],
     "source": HEADER, "headers": SERVER_HEADERS,
     "pattern": r"\bApache(?![-\s]*(?:Coyote|Tomcat))(?:/" + V + r")?"},
    {"label": "Apache Tomcat", "cpe": [("apache", "tomcat")],
     "source": HEADER, "headers": SERVER_HEADERS + ("x-powered-by",),
     "pattern": r"\bApache[ -](?:Tomcat(?:/" + V + r")?|Coyote)"},
    {"label": "Microsoft IIS", "cpe": [("microsoft", "internet_information_services")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bMicrosoft-IIS(?:/" + V + r")?"},
    {"label": "LiteSpeed", "cpe": [("litespeedtech", "litespeed_web_server")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bLiteSpeed(?:/" + V + r")?"},
    {"label": "lighttpd", "cpe": [("lighttpd", "lighttpd")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\blighttpd(?:/" + V + r")?"},
    {"label": "Eclipse Jetty", "cpe": [("eclipse", "jetty")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bJetty(?:[(/]" + V + r")?"},
    {"label": "gunicorn", "cpe": [("gunicorn", "gunicorn")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bgunicorn(?:/" + V + r")?"},
    {"label": "Werkzeug", "cpe": [("palletsprojects", "werkzeug")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bWerkzeug(?:/" + V + r")?"},
    {"label": "Python", "cpe": [("python", "python")], "confidence": "medium",
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bC?Python/" + V},
    {"label": "OpenSSL", "cpe": [("openssl", "openssl")], "confidence": "medium",
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bOpenSSL(?:/" + V + r")?"},
    {"label": "PHP", "cpe": [("php", "php")],
     "source": HEADER, "headers": POWERED_HEADERS, "pattern": r"\bPHP(?:/" + V + r")?"},
    {"label": "Express", "cpe": [("openjsf", "express")],
     "source": HEADER, "headers": ("x-powered-by",), "pattern": r"^\s*Express(?:/" + V + r")?\s*$"},
    {"label": "Next.js", "cpe": [("vercel", "next.js")],
     "source": HEADER, "headers": ("x-powered-by",), "pattern": r"\bNext\.js(?:\s+" + V + r")?"},
    {"label": "ASP.NET", "cpe": [], "confidence": "medium",
     "source": HEADER, "headers": ("x-powered-by",), "pattern": r"\bASP\.NET\b"},
    {"label": "ASP.NET", "cpe": [], "confidence": "medium",
     "source": HEADER, "headers": ("x-aspnet-version",), "pattern": r"^\s*" + V},
    {"label": "ASP.NET MVC", "cpe": [("microsoft", "asp.net_mvc")],
     "source": HEADER, "headers": ("x-aspnetmvc-version",), "pattern": r"^\s*" + V},

    # --- CMS (meta generator / X-Generator) --------------------------------------
    {"label": "WordPress", "cpe": [("wordpress", "wordpress")],
     "source": GENERATOR, "pattern": r"\bWordPress(?:\s+" + V + r")?"},
    {"label": "Drupal", "cpe": [("drupal", "drupal")],
     "source": GENERATOR, "pattern": r"\bDrupal(?:\s+" + V + r")?"},
    {"label": "Joomla!", "cpe": [("joomla", "joomla\\!")],
     "source": GENERATOR, "pattern": r"\bJoomla!?(?:\s+" + V + r")?"},
    {"label": "TYPO3", "cpe": [("typo3", "typo3")],
     "source": GENERATOR, "pattern": r"\bTYPO3(?:\s+(?:CMS\s+)?" + V + r")?"},

    # --- прокси, серверы приложений и инструменты (заголовки, ресурсы, пути) ----------
    {"label": "Caddy", "cpe": [("caddyserver", "caddy")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bCaddy(?:/" + V + r")?"},
    {"label": "HAProxy", "cpe": [("haproxy", "haproxy")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bHAProxy(?:/" + V + r")?"},
    {"label": "Jenkins", "cpe": [("jenkins", "jenkins")],
     "source": HEADER, "headers": ("x-jenkins",), "pattern": r"^\s*" + V},
    {"label": "Grafana", "cpe": [("grafana", "grafana")], "source": BANNER,
     "pattern": r'"buildInfo"\s*:\s*\{[^{}]{0,300}?"version"\s*:\s*"' + V},
    {"label": "Grafana", "cpe": [("grafana", "grafana")], "source": PATH, "confidence": "medium",
     "pattern": r"/public/build/grafana\.|/public/img/grafana_"},
    {"label": "phpMyAdmin", "cpe": [("phpmyadmin", "phpmyadmin")], "source": ASSET,
     "pattern": r"(?:js/messages\.php|[?&]route=/messages)[^\"']*?[?&]v=" + V},
    {"label": "phpMyAdmin", "cpe": [("phpmyadmin", "phpmyadmin")], "source": PATH, "confidence": "medium",
     "pattern": r"/phpmyadmin(?:/|\?|$)"},
    {"label": "GitLab", "cpe": [("gitlab", "gitlab")],
     "source": HEADER, "headers": ("x-gitlab-meta",), "pattern": r"correlation_id"},
    {"label": "GitLab", "cpe": [("gitlab", "gitlab")], "source": COOKIE, "confidence": "medium",
     "pattern": r"^_gitlab_session$"},

    # --- интернет-магазины (характерные пути и заголовки, версия обычно скрыта) ---------
    {"label": "Magento", "cpe": [("magento", "magento"), ("adobe", "magento")],
     "source": HEADER, "headers": ("x-magento-cache-debug", "x-magento-tags"), "pattern": r"."},
    {"label": "Magento", "cpe": [("magento", "magento"), ("adobe", "magento")], "source": PATH,
     "confidence": "medium", "pattern": r"/(?:static/(?:version\d+/)?frontend/Magento/|skin/frontend/|pub/static/)"},
    {"label": "OpenCart", "cpe": [("opencart", "opencart")], "source": PATH, "confidence": "medium",
     "pattern": r"/catalog/view/(?:theme|javascript)/"},
    {"label": "OpenCart", "cpe": [("opencart", "opencart")], "source": COOKIE, "confidence": "low",
     "pattern": r"^OCSESSID$"},

    # --- JS/CSS-библиотеки по имени файла ----------------------------------------
    {"label": "jQuery", "cpe": [("jquery", "jquery")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])jquery(?:[.-]|@)" + V + r"(?:\.slim)?(?:\.min)?\.js"},
    {"label": "jQuery UI", "cpe": [("jqueryui", "jquery_ui"), ("jquery", "jquery_ui")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])jquery[.-]ui(?:[.-]|@)" + V + r"(?:\.min)?\.(?:js|css)"},
    {"label": "Bootstrap", "cpe": [("getbootstrap", "bootstrap")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])bootstrap(?:[.-]|@)" + V + r"(?:\.bundle)?(?:\.min)?\.(?:js|css)"},
    {"label": "AngularJS", "cpe": [("angularjs", "angular.js")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])angular(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "React", "cpe": [("facebook", "react")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])react(?:-dom)?(?:[.-]|@)" + V + r"(?:\.production)?(?:\.min)?\.js"},
    {"label": "Vue.js", "cpe": [("vuejs", "vue.js")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])vue(?:[.-]|@)" + V + r"(?:\.global)?(?:\.prod)?(?:\.min)?\.js"},
    {"label": "Lodash", "cpe": [("lodash", "lodash")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])lodash(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "Moment.js", "cpe": [("momentjs", "moment")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])moment(?:[.-]|@)" + V + r"(?:\.min)?\.js"},

    # --- баннеры в теле JS/CSS ---------------------------------------------------
    {"label": "jQuery", "cpe": [("jquery", "jquery")], "source": BANNER,
     "pattern": r"(?:/\*!\s*jQuery\s+v|jQuery JavaScript Library v)" + V},
    {"label": "jQuery UI", "cpe": [("jqueryui", "jquery_ui"), ("jquery", "jquery_ui")], "source": BANNER,
     "pattern": r"/\*!\s*jQuery UI\s*-\s*v" + V},
    {"label": "Bootstrap", "cpe": [("getbootstrap", "bootstrap")], "source": BANNER,
     "pattern": r"\*!?\s*Bootstrap\s+v" + V},
    {"label": "AngularJS", "cpe": [("angularjs", "angular.js")], "source": BANNER,
     "pattern": r"@license\s+AngularJS\s+v" + V},
    {"label": "React", "cpe": [("facebook", "react")], "source": BANNER,
     "pattern": r"@license\s+React(?:\s+\w+)*?\s+v" + V},
    {"label": "Vue.js", "cpe": [("vuejs", "vue.js")], "source": BANNER,
     "pattern": r"\*!?\s*Vue\.js\s+v" + V},
    {"label": "Lodash", "cpe": [("lodash", "lodash")], "source": BANNER,
     "pattern": r"@license\s+Lodash\s+(?:lodash\.com/license\s*\|\s*)?v?" + V},
    {"label": "Moment.js", "cpe": [("momentjs", "moment")], "source": BANNER,
     "pattern": r"//!\s*moment\.js\s*(?:\r?\n)+//!\s*version\s*:\s*" + V},

    # --- характерные пути (без версии) ------------------------------------------
    {"label": "WordPress", "cpe": [("wordpress", "wordpress")], "source": PATH,
     "confidence": "medium", "pattern": r"/wp-(?:content|includes)/"},
    {"label": "Drupal", "cpe": [("drupal", "drupal")], "source": PATH,
     "confidence": "medium", "pattern": r"/sites/(?:default|all)/(?:files|modules|themes)/"},
    {"label": "Joomla!", "cpe": [("joomla", "joomla\\!")], "source": PATH,
     "confidence": "low", "pattern": r"/media/(?:jui|system)/js/"},

    # --- имена cookie (без версии) ----------------------------------------------
    {"label": "PHP", "cpe": [("php", "php")], "source": COOKIE, "confidence": "low",
     "pattern": r"^PHPSESSID$"},
    {"label": "Java Servlet-контейнер", "cpe": [], "source": COOKIE, "confidence": "low",
     "pattern": r"^JSESSIONID$"},
    {"label": "Laravel", "cpe": [("laravel", "framework")], "source": COOKIE, "confidence": "low",
     "pattern": r"^laravel_session$"},
    {"label": "ASP.NET", "cpe": [], "source": COOKIE, "confidence": "low",
     "pattern": r"^ASP\.NET_SessionId$"},
    {"label": "Django", "cpe": [("djangoproject", "django")], "source": COOKIE, "confidence": "low",
     "pattern": r"^csrftoken$"},

    # ========================================================================
    # Дальше — расширение базы до размеров аналогичных сканеров (Wappalyzer,
    # WhatWeb, Nikto): больше веб-серверов, CMS, панелей администрирования,
    # систем мониторинга, CI/VCS, groupware и JS-библиотек. Каждая новая
    # запись — это дополнительные продукты, по которым этап 6 (``vulndb``)
    # сверяет версию с NVD/CISA KEV/ExploitDB; без сигнатуры продукт просто
    # не попадёт в эту сверку, даже если на сайте есть известные уязвимости.
    # ========================================================================

    # --- ещё веб-серверы и платформы (HTTP-заголовки) ---------------------------
    {"label": "OpenResty", "cpe": [("openresty", "openresty")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bopenresty(?:/" + V + r")?"},
    {"label": "Varnish", "cpe": [("varnish_cache_project", "varnish_cache")], "confidence": "low",
     "source": HEADER, "headers": ("via", "x-varnish"), "pattern": r"\bvarnish\b"},
    {"label": "Squid", "cpe": [("squid-cache", "squid")],
     "source": HEADER, "headers": ("via", "server"), "pattern": r"\bsquid(?:/" + V + r")?"},
    {"label": "uWSGI", "cpe": [("unbit", "uwsgi")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\buWSGI(?:/" + V + r")?"},
    {"label": "Kestrel", "cpe": [], "confidence": "medium",
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bKestrel\b"},
    {"label": "Node.js", "cpe": [("nodejs", "node.js")], "confidence": "medium",
     "source": HEADER, "headers": ("x-powered-by",), "pattern": r"^\s*Node\.js(?:/" + V + r")?"},
    {"label": "Ruby on Rails", "cpe": [("rubyonrails", "rails")], "confidence": "low",
     "source": HEADER, "headers": ("x-runtime",), "pattern": r"."},
    {"label": "Symfony", "cpe": [("symfony", "symfony")], "confidence": "low",
     "source": HEADER, "headers": ("x-debug-token",), "pattern": r"."},
    {"label": "Webmin", "cpe": [("webmin", "webmin")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bMiniServ(?:/" + V + r")?"},
    {"label": "cPanel", "cpe": [("cpanel", "cpanel")], "confidence": "medium",
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bcpsrvd(?:/" + V + r")?"},
    {"label": "DirectAdmin", "cpe": [("directadmin", "directadmin")], "confidence": "medium",
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bDirectAdmin\b"},
    {"label": "Plesk", "cpe": [("plesk", "plesk")], "confidence": "low",
     "source": HEADER, "headers": POWERED_HEADERS, "pattern": r"\bPleskLin\b|\bPlesk\b"},
    {"label": "Docker Registry", "cpe": [("docker", "registry")], "confidence": "medium",
     "source": HEADER, "headers": ("docker-distribution-api-version",),
     "pattern": r"registry/" + V},
    {"label": "Nexus Repository Manager", "cpe": [("sonatype", "nexus_repository_manager")],
     "source": HEADER, "headers": SERVER_HEADERS, "pattern": r"\bNexus/" + V},

    # --- ещё CMS и e-commerce (meta generator / характерные пути) ---------------
    {"label": "PrestaShop", "cpe": [("prestashop", "prestashop")],
     "source": GENERATOR, "pattern": r"\bPrestaShop(?:\s+" + V + r")?"},
    {"label": "vBulletin", "cpe": [("vbulletin", "vbulletin")],
     "source": GENERATOR, "pattern": r"\bvBulletin(?:\s+" + V + r")?"},
    {"label": "phpBB", "cpe": [("phpbb", "phpbb")],
     "source": GENERATOR, "pattern": r"\bphpBB(?:\s+" + V + r")?"},
    {"label": "MediaWiki", "cpe": [("wikimedia", "mediawiki")],
     "source": GENERATOR, "pattern": r"\bMediaWiki(?:\s+" + V + r")?"},
    {"label": "Ghost", "cpe": [("ghost", "ghost")],
     "source": GENERATOR, "pattern": r"\bGhost(?:\s+" + V + r")?"},
    {"label": "Contao", "cpe": [("contao", "contao")],
     "source": GENERATOR, "pattern": r"\bContao(?:\s+" + V + r")?"},
    {"label": "Shopware", "cpe": [("shopware", "shopware")], "confidence": "medium",
     "source": GENERATOR, "pattern": r"\bShopware(?:\s+" + V + r")?"},
    {"label": "Craft CMS", "cpe": [("craftcms", "craft_cms")], "confidence": "medium",
     "source": HEADER, "headers": ("x-powered-by",), "pattern": r"\bCraft CMS\b"},
    {"label": "Umbraco", "cpe": [("umbraco", "umbraco_cms")],
     "source": HEADER, "headers": ("x-umbraco-version",), "pattern": r"^\s*" + V},
    {"label": "osCommerce", "cpe": [("oscommerce", "oscommerce")], "source": PATH,
     "confidence": "low", "pattern": r"/catalog/includes/classes/"},
    {"label": "WooCommerce", "cpe": [("woocommerce", "woocommerce")], "source": PATH,
     "confidence": "medium", "pattern": r"/wp-content/plugins/woocommerce/"},
    {"label": "Moodle", "cpe": [("moodle", "moodle")], "source": COOKIE,
     "confidence": "low", "pattern": r"^MoodleSession"},

    # --- популярные плагины WordPress (отдельный продукт — отдельные CVE) -------
    {"label": "Yoast SEO", "cpe": [("yoast", "yoast_seo")], "source": PATH,
     "confidence": "low", "pattern": r"/wp-content/plugins/wordpress-seo/"},
    {"label": "Elementor", "cpe": [("elementor", "elementor")], "source": PATH,
     "confidence": "low", "pattern": r"/wp-content/plugins/elementor/"},
    {"label": "Contact Form 7", "cpe": [("rocklobster", "contact_form_7")], "source": PATH,
     "confidence": "low", "pattern": r"/wp-content/plugins/contact-form-7/"},
    {"label": "WPForms", "cpe": [("wpforms", "wpforms")], "source": PATH,
     "confidence": "low", "pattern": r"/wp-content/plugins/wpforms-lite/"},
    {"label": "Jetpack", "cpe": [("automattic", "jetpack")], "source": PATH,
     "confidence": "low", "pattern": r"/wp-content/plugins/jetpack/"},
    {"label": "WP Super Cache", "cpe": [("automattic", "wp_super_cache")], "source": PATH,
     "confidence": "low", "pattern": r"/wp-content/plugins/wp-super-cache/"},
    {"label": "Duplicator", "cpe": [("snapcreek", "duplicator")], "source": PATH,
     "confidence": "low", "pattern": r"/wp-content/plugins/duplicator/"},

    # --- панели мониторинга и администрирования ----------------------------------
    {"label": "Zabbix", "cpe": [("zabbix", "zabbix")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^zbx_session$"},
    {"label": "Zabbix", "cpe": [("zabbix", "zabbix")], "source": BODY,
     "confidence": "medium", "pattern": r"<title>\s*Zabbix\b"},
    {"label": "Nagios", "cpe": [("nagios", "nagios_core")], "source": BODY,
     "confidence": "medium", "pattern": r"<title>[^<]*Nagios Core"},
    {"label": "Cacti", "cpe": [("cacti", "cacti")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^Cacti$"},
    {"label": "phpPgAdmin", "cpe": [("phppgadmin", "phppgadmin")], "source": BODY,
     "confidence": "medium", "pattern": r"<title>\s*phpPgAdmin\b"},
    {"label": "Portainer", "cpe": [("portainer", "portainer")], "source": PATH,
     "confidence": "low", "pattern": r"/portainer(?:\.css|\.js|/)"},
    {"label": "Prometheus", "cpe": [("prometheus", "prometheus")], "source": PATH,
     "confidence": "low", "pattern": r"/graph\?g0\."},
    {"label": "Kibana", "cpe": [("elastic", "kibana")], "source": PATH,
     "confidence": "low", "pattern": r"/bundles/kibana|/app/kibana"},

    # --- сетевые шлюзы, VPN и файрволы (известные служебные пути и cookie) ------
    {"label": "Ivanti Connect Secure / Pulse Secure",
     "cpe": [("ivanti", "connect_secure"), ("pulsesecure", "pulse_connect_secure")],
     "source": PATH, "confidence": "medium", "pattern": r"/dana-na/"},
    {"label": "Citrix NetScaler ADC/Gateway",
     "cpe": [("citrix", "netscaler_application_delivery_controller"),
             ("citrix", "netscaler_gateway")],
     "source": COOKIE, "confidence": "medium", "pattern": r"^NSC_|^citrix_ns_id$"},
    {"label": "Cisco ASA WebVPN", "cpe": [("cisco", "adaptive_security_appliance_software")],
     "source": PATH, "confidence": "medium", "pattern": r"/\+CSCOE\+/"},
    {"label": "pfSense", "cpe": [("pfsense", "pfsense")], "source": BODY,
     "confidence": "medium", "pattern": r"<title>[^<]*pfSense\b"},
    {"label": "OPNsense", "cpe": [("opnsense", "opnsense")], "source": BODY,
     "confidence": "medium", "pattern": r"<title>[^<]*OPNsense\b"},
    {"label": "FortiGate", "cpe": [("fortinet", "fortios")], "source": BODY,
     "confidence": "low", "pattern": r"<title>[^<]*FortiGate\b"},

    # --- CI/CD, системы контроля версий и артефакты -------------------------------
    {"label": "Gitea", "cpe": [("gitea", "gitea")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^i_like_gitea$"},
    {"label": "TeamCity", "cpe": [("jetbrains", "teamcity")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^TCSESSIONID$"},
    {"label": "Bamboo", "cpe": [("atlassian", "bamboo")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^BAMBOOSESSIONID$"},
    {"label": "Bitbucket Server", "cpe": [("atlassian", "bitbucket")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^BITBUCKETSESSIONID$"},
    {"label": "Jira", "cpe": [("atlassian", "jira")], "source": PATH,
     "confidence": "low", "pattern": r"/s/[^/]+/_/download/batch/com\.atlassian\.jira"},
    {"label": "Confluence", "cpe": [("atlassian", "confluence")], "source": PATH,
     "confidence": "low", "pattern": r"/s/[^/]+/_/download/batch/com\.atlassian\.confluence"},
    {"label": "SonarQube", "cpe": [("sonarsource", "sonarqube")], "source": PATH,
     "confidence": "low", "pattern": r"/sonarqube/|/sonar/js/bundles"},
    {"label": "Harbor", "cpe": [("goharbor", "harbor")], "source": PATH,
     "confidence": "low", "pattern": r"/api/v2\.0/systeminfo"},

    # --- groupware и почтовые веб-интерфейсы --------------------------------------
    {"label": "Roundcube", "cpe": [("roundcube", "webmail")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^roundcube_sessid$"},
    {"label": "SquirrelMail", "cpe": [("squirrelmail", "squirrelmail")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^SQMSESSID$"},
    {"label": "Zimbra Collaboration", "cpe": [("zimbra", "collaboration")], "source": COOKIE,
     "confidence": "medium", "pattern": r"^ZM_TEST$|^ZM_AUTH_TOKEN$"},
    {"label": "Microsoft Exchange OWA", "cpe": [("microsoft", "exchange_server")], "source": PATH,
     "confidence": "medium", "pattern": r"/owa/auth/logon\.aspx"},

    # --- ещё JS-библиотеки по имени файла (версия в имени) -----------------------
    {"label": "Handlebars", "cpe": [("handlebarsjs", "handlebars")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])handlebars(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "Underscore.js", "cpe": [("underscorejs", "underscore.js")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])underscore(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "Backbone.js", "cpe": [("backbonejs", "backbone")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])backbone(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "D3.js", "cpe": [("d3js", "d3")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])d3(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "Chart.js", "cpe": [("chartjs", "chart.js")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])chart(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "CKEditor", "cpe": [("ckeditor", "ckeditor"), ("ckeditor", "ckeditor4")],
     "source": ASSET, "pattern": r"(?:^|[/@_-])ckeditor(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "TinyMCE", "cpe": [("tiny", "tinymce")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])tinymce(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "Highcharts", "cpe": [("highsoft", "highcharts")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])highcharts(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "Ember.js", "cpe": [("emberjs", "ember.js")], "source": ASSET,
     "pattern": r"(?:^|[/@_-])ember(?:[.-]|@)" + V + r"(?:\.min)?\.js"},
    {"label": "Socket.IO", "cpe": [("socket.io", "socket.io")], "confidence": "medium",
     "source": ASSET, "pattern": r"(?:^|[/@_-])socket\.io(?:[.-]|@)" + V + r"(?:\.min)?\.js"},

    # --- баннеры в теле JS/CSS для новых библиотек --------------------------------
    {"label": "Handlebars", "cpe": [("handlebarsjs", "handlebars")], "source": BANNER,
     "pattern": r"handlebars\.js\s+v" + V},
    {"label": "Underscore.js", "cpe": [("underscorejs", "underscore.js")], "source": BANNER,
     "pattern": r"@license\s+Underscore\.js\s+" + V},
    {"label": "Backbone.js", "cpe": [("backbonejs", "backbone")], "source": BANNER,
     "pattern": r"@license\s+Backbone\.js\s+" + V},
    {"label": "Highcharts", "cpe": [("highsoft", "highcharts")], "source": BANNER,
     "pattern": r"Highcharts\s+JS\s+v" + V},
    {"label": "TinyMCE", "cpe": [("tiny", "tinymce")], "source": BANNER,
     "pattern": r"Version:\s*" + V + r"\s*\*/\s*\(\s*function\s*tinymce"},
]

CDN_PATTERNS: Sequence[re.Pattern] = (
    re.compile(r"/ajax/libs/(?P<name>[^/]+)/(?P<version>[^/]+)/", re.I),
    re.compile(r"/npm/(?P<name>@?[^/@]+(?:/[^/@]+)?)@(?P<version>[^/]+)/", re.I),
    re.compile(r"/(?:unpkg|package)/(?P<name>@?[^/@]+(?:/[^/@]+)?)@(?P<version>[^/]+)/", re.I),
    re.compile(r"unpkg\.com/(?P<name>@?[^/@]+(?:/[^/@]+)?)@(?P<version>[^/]+)/", re.I),
)

# Имя npm/cdnjs-пакета → (метка, CPE-пары)
PACKAGE_ALIASES: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {
    "jquery": ("jQuery", [("jquery", "jquery")]),
    "jqueryui": ("jQuery UI", [("jqueryui", "jquery_ui"), ("jquery", "jquery_ui")]),
    "jquery-ui": ("jQuery UI", [("jqueryui", "jquery_ui"), ("jquery", "jquery_ui")]),
    "bootstrap": ("Bootstrap", [("getbootstrap", "bootstrap")]),
    "twitter-bootstrap": ("Bootstrap", [("getbootstrap", "bootstrap")]),
    "angular.js": ("AngularJS", [("angularjs", "angular.js")]),
    "angular": ("AngularJS", [("angularjs", "angular.js")]),
    "react": ("React", [("facebook", "react")]),
    "react-dom": ("React", [("facebook", "react")]),
    "vue": ("Vue.js", [("vuejs", "vue.js")]),
    "lodash": ("Lodash", [("lodash", "lodash")]),
    "lodash.js": ("Lodash", [("lodash", "lodash")]),
    "moment": ("Moment.js", [("momentjs", "moment")]),
    "moment.js": ("Moment.js", [("momentjs", "moment")]),
    "handlebars": ("Handlebars", [("handlebarsjs", "handlebars")]),
    "handlebars.js": ("Handlebars", [("handlebarsjs", "handlebars")]),
    "underscore": ("Underscore.js", [("underscorejs", "underscore.js")]),
    "underscore.js": ("Underscore.js", [("underscorejs", "underscore.js")]),
    "backbone": ("Backbone.js", [("backbonejs", "backbone")]),
    "backbone.js": ("Backbone.js", [("backbonejs", "backbone")]),
    "d3": ("D3.js", [("d3js", "d3")]),
    "chart.js": ("Chart.js", [("chartjs", "chart.js")]),
    "ckeditor": ("CKEditor", [("ckeditor", "ckeditor"), ("ckeditor", "ckeditor4")]),
    "ckeditor4": ("CKEditor", [("ckeditor", "ckeditor"), ("ckeditor", "ckeditor4")]),
    "tinymce": ("TinyMCE", [("tiny", "tinymce")]),
    "highcharts": ("Highcharts", [("highsoft", "highcharts")]),
    "ember-source": ("Ember.js", [("emberjs", "ember.js")]),
    "socket.io": ("Socket.IO", [("socket.io", "socket.io")]),
}

_COMPILED: List[Tuple[Dict[str, object], re.Pattern]] = [
    (sig, re.compile(str(sig["pattern"]), re.I)) for sig in SIGNATURES
]
_SCRIPT_TYPES = ("javascript", "ecmascript", "text/css")
_BANNER_SCAN_LIMIT = 200_000  # символов тела JS/CSS, где ищутся баннеры


@dataclass
class DetectedProduct:
    """Компонент, найденный пассивным fingerprint-анализом.

    ``vendor``/``product`` — основная CPE-пара; ``cpe_pairs`` — все пары,
    под которыми продукт заведён в NVD. ``evidence`` — первое место находки,
    ``evidences`` — все места (дедуплицированы).
    """

    vendor: str
    product: str
    version: str = ""
    source: str = ""
    evidence: str = ""
    confidence: str = "medium"
    cpe: str = ""
    label: str = ""
    cpe_pairs: List[Tuple[str, str]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    evidences: List[str] = field(default_factory=list)
    # Дистрибутив из баннера («Apache/2.4.6 (CentOS)»): такие пакеты получают исправления
    # без смены номера версии, поэтому CVE по номеру версии могут быть уже закрыты.
    distro: str = ""
    # Импортированный компонент без известной CPE-пары: пару подбирает NVD по названию.
    keyword_search: bool = False

    def __post_init__(self) -> None:
        if not self.cpe_pairs and self.vendor and self.product:
            self.cpe_pairs = [(self.vendor, self.product)]
        if self.source and self.source not in self.sources:
            self.sources.insert(0, self.source)
        if self.evidence and self.evidence not in self.evidences:
            self.evidences.insert(0, self.evidence)

    @property
    def display_name(self) -> str:
        return f"{self.label or self.product} {self.version}".strip()

    @property
    def query(self) -> str:
        return " ".join(part for part in (self.vendor, self.product, self.version) if part)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.vendor.lower(), self.product.lower(), self.version.lower())

    @property
    def has_version(self) -> bool:
        return bool(self.version)

    @property
    def nvd_eligible(self) -> bool:
        """Можно ли отправлять компонент в NVD: нужна и версия, и CPE-пара."""
        return bool(self.version and (self.cpe_pairs or self.keyword_search))

    def merge(self, other: "DetectedProduct") -> None:
        for value in other.sources:
            if value not in self.sources:
                self.sources.append(value)
        for value in other.evidences:
            if value not in self.evidences:
                self.evidences.append(value)
        if other.distro and not self.distro:
            self.distro = other.distro
        order = {"high": 0, "medium": 1, "low": 2}
        if order.get(other.confidence, 9) < order.get(self.confidence, 9):
            self.confidence = other.confidence


# Совместимое имя из спецификации этапа 6.
Component = DetectedProduct


def detect_products(pages: Iterable[Page]) -> List[DetectedProduct]:
    """Возвращает дедуплицированный перечень компонентов сайта.

    Дедупликация — по ``(vendor, product, version)``; места находки сливаются.
    Если у продукта есть запись с версией, запись того же продукта без версии
    отбрасывается (её признаки переносятся в версионную).
    """
    found: Dict[Tuple[str, str, str], DetectedProduct] = {}

    def add(item: Optional[DetectedProduct]) -> None:
        if item is None or not (item.product or item.label):
            return
        current = found.get(item.key)
        if current is None:
            found[item.key] = item
        else:
            current.merge(item)

    for page in pages:
        for item in _from_headers(page):
            add(item)
        for item in _from_cookies(page):
            add(item)

        content_type = (page.content_type or "").lower()
        if any(marker in content_type for marker in _SCRIPT_TYPES):
            for item in _from_banners(page.body, f"баннер в {page.url}"):
                add(item)
            continue

        soup = _soup(page)
        if soup is None:
            continue

        generator = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
        if generator is not None:
            value = str(generator.get("content") or "")
            for item in _match_source(GENERATOR, value, "meta generator",
                                      f"generator: {value[:240]}"):
                add(item)

        if page.body:
            chunk = page.body[:_BANNER_SCAN_LIMIT]
            for item in _match_source(BODY, chunk, "текст страницы",
                                      f"{page.url}: {' '.join(chunk.split())[:200]}"):
                add(item)

        asset_urls: List[str] = []
        for tag, attr in (("script", "src"), ("link", "href")):
            for element in soup.find_all(tag):
                value = str(element.get(attr) or "").strip()
                if value:
                    asset_urls.append(unquote(value))
        for asset_url in asset_urls:
            known_asset = _match_source(ASSET, asset_url, "JS/CSS asset", asset_url[:300])
            for item in known_asset:
                add(item)
            cdn_item = _from_cdn_url(asset_url)
            add(cdn_item)
            if not known_asset and cdn_item is None:
                add(_from_asset_filename(asset_url))
        for url in asset_urls + list(page.links or []) + [page.url]:
            for item in _match_source(PATH, url, "характерный путь", url[:300]):
                add(item)

        for script in soup.find_all("script"):
            if script.get("src"):
                continue
            text = script.string or script.get_text() or ""
            if text:
                for item in _from_banners(text, f"inline-скрипт на {page.url}"):
                    add(item)

    versioned = {(item.vendor, item.product) for item in found.values() if item.version}
    result: List[DetectedProduct] = []
    for item in found.values():
        if not item.version and (item.vendor, item.product) in versioned and item.vendor:
            target = next(other for other in found.values()
                          if other.version and (other.vendor, other.product) == (item.vendor, item.product))
            target.merge(item)
            continue
        result.append(item)
    return sorted(result, key=lambda item: item.key)


def _from_headers(page: Page) -> List[DetectedProduct]:
    items: List[DetectedProduct] = []
    headers = {str(key).lower(): str(value) for key, value in (page.headers or {}).items()}
    for sig, regex in _COMPILED:
        if sig["source"] != HEADER:
            continue
        for name in sig["headers"]:  # type: ignore[union-attr]
            value = headers.get(name, "")
            if not value:
                continue
            for match in regex.finditer(value):
                item = _make(sig, match, f"HTTP {_title(name)}", f"{_title(name)}: {value[:240]}")
                item.distro = detect_distro(value)
                items.append(item)
    generator = headers.get("x-generator", "")
    if generator:
        items.extend(_match_source(GENERATOR, generator, "HTTP X-Generator",
                                   f"X-Generator: {generator[:240]}"))
    return items


DISTRO_RE = re.compile(
    r"\((?:[^)]*\b)?(Ubuntu|Debian|CentOS|Red ?Hat|RHEL|Fedora|Amazon|SUSE|openSUSE|Alpine|"
    r"Rocky|AlmaLinux|Oracle)\b[^)]*\)|\b(ubuntu|deb\d+u\d+)\b|\.(el\d+)(?:_\d+)?\b",
    re.I,
)


def detect_distro(value: str) -> str:
    """Название дистрибутива из баннера сервера или пустая строка."""
    match = DISTRO_RE.search(value or "")
    if not match:
        return ""
    return next(group for group in match.groups() if group)


def _from_cookies(page: Page) -> List[DetectedProduct]:
    names = {cookie.name for cookie in (page.cookies or []) if cookie.name}
    items: List[DetectedProduct] = []
    for name in sorted(names):
        items.extend(_match_source(COOKIE, name, "имя cookie", f"Set-Cookie: {name}=…"))
    return items


def _from_banners(text: str, where: str) -> List[DetectedProduct]:
    chunk = (text or "")[:_BANNER_SCAN_LIMIT]
    items: List[DetectedProduct] = []
    for sig, regex in _COMPILED:
        if sig["source"] != BANNER:
            continue
        match = regex.search(chunk)
        if match:
            snippet = " ".join(match.group(0).split())[:160]
            items.append(_make(sig, match, "баннер JS/CSS", f"{where}: {snippet}"))
    return items


def _match_source(source: str, value: str, source_label: str, evidence: str) -> List[DetectedProduct]:
    items: List[DetectedProduct] = []
    if not value:
        return items
    for sig, regex in _COMPILED:
        if sig["source"] != source:
            continue
        match = regex.search(value)
        if match:
            items.append(_make(sig, match, source_label, evidence))
    return items


def _make(sig: Dict[str, object], match: "re.Match", source: str, evidence: str) -> DetectedProduct:
    pairs = [tuple(pair) for pair in sig.get("cpe") or []]  # type: ignore[union-attr]
    vendor, product = pairs[0] if pairs else ("", _slug(str(sig["label"])))
    version = ""
    if "version" in (match.re.groupindex or {}):
        version = _clean_version(match.group("version") or "")
    return DetectedProduct(
        vendor=vendor,
        product=product,
        version=version,
        source=source,
        evidence=evidence,
        confidence=str(sig.get("confidence") or "high"),
        label=str(sig["label"]),
        cpe_pairs=list(pairs),  # type: ignore[arg-type]
    )


def _from_cdn_url(url: str) -> Optional[DetectedProduct]:
    parsed = urlparse(url if "://" in url else "https://local.invalid" + (url if url.startswith("/") else "/" + url))
    value = (parsed.netloc or "") + parsed.path
    for regex in CDN_PATTERNS:
        match = regex.search(value)
        if not match:
            continue
        raw_name = match.group("name").lower().strip()
        short_name = raw_name.split("/")[-1]
        alias = PACKAGE_ALIASES.get(raw_name) or PACKAGE_ALIASES.get(short_name)
        version = _clean_version(match.group("version"))
        if not re.match(r"^\d", version):
            return None  # "latest", диапазоны npm и т. п. — не версия
        if not alias:
            return _unknown_package(short_name, version, "CDN package URL", url, "medium")
        label, pairs = alias
        return DetectedProduct(
            vendor=pairs[0][0],
            product=pairs[0][1],
            version=version,
            source="CDN package URL",
            evidence=url[:300],
            confidence="high",
            label=label,
            cpe_pairs=list(pairs),
        )
    return None


# Файл библиотеки с версией в имени: «knockout-3.4.0.min.js», «lib.v2.1.css», «foo@1.2.3.js».
_ASSET_FILE_RE = re.compile(
    r"^(?P<name>[A-Za-z][A-Za-z0-9_.-]*?)[-_.@]v?(?P<version>\d+(?:\.\d+){1,3}(?:-[A-Za-z0-9.]+)?)"
    r"(?:\.(?:min|slim|bundle|prod|production))*\.(?:js|css)$", re.I)
_ASSET_DIR_RE = re.compile(r"/(?P<name>[A-Za-z][A-Za-z0-9_.-]+)/v?(?P<version>\d+(?:\.\d+){1,3})/")
_GENERIC_NAMES = {"app", "main", "site", "style", "styles", "script", "scripts", "index", "bundle",
                  "vendor", "vendors", "common", "theme", "custom", "global", "all", "min"}


def _unknown_package(name: str, version: str, source: str, evidence: str,
                     confidence: str) -> Optional[DetectedProduct]:
    """Компонент, которого нет в словаре подписей: CPE-пару подбирает NVD по названию."""
    clean = re.sub(r"[-_.]?(?:min|slim|bundle|js)$", "", name.strip(), flags=re.I).strip("-_. ")
    if len(clean) < 2 or clean.lower() in _GENERIC_NAMES or not re.match(r"^\d", version):
        return None
    label = " ".join(part.capitalize() if part.islower() else part
                     for part in re.split(r"[-_]+", clean) if part)
    return DetectedProduct(vendor="", product=_slug(clean), version=version, source=source,
                           evidence=evidence[:300], confidence=confidence, label=label,
                           keyword_search=True)


def _from_asset_filename(url: str) -> Optional[DetectedProduct]:
    """Неизвестная библиотека по имени файла со версией — чтобы проверялись все компоненты."""
    path = urlparse(url if "://" in url else "https://local.invalid/" + url.lstrip("/")).path
    filename = path.rsplit("/", 1)[-1]
    match = _ASSET_FILE_RE.match(filename)
    if match is not None:
        return _unknown_package(match.group("name"), _clean_version(match.group("version")),
                                "JS/CSS asset", url, "low")
    # версия в каталоге: «/font-awesome/4.7.0/css/font-awesome.min.css»
    for folder in _ASSET_DIR_RE.finditer(path):
        name = folder.group("name")
        if name.lower() in filename.lower():
            return _unknown_package(name, folder.group("version"), "JS/CSS asset", url, "low")
    return None


def _soup(page: Page):
    if page.soup is not None:
        return page.soup
    if page.body and "html" in (page.content_type or "text/html"):
        try:
            return BeautifulSoup(page.body, "html.parser")
        except Exception:  # noqa: BLE001 - битый HTML не должен ломать анализ
            return None
    return None


def _clean_version(value: str) -> str:
    """Не принимает суффиксы имени файла (`.min`, `.slim`) за часть версии."""
    value = str(value or "").strip().rstrip(".-")
    return re.sub(r"(?:\.(?:min|slim|bundle|prod|production|global|js|css))+$", "", value, flags=re.I)


def _title(header: str) -> str:
    return "-".join(part.capitalize() for part in header.split("-"))


def _slug(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
