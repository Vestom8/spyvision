"""Служебный скрипт: выводит список находок из HTML-отчёта (для самопроверки)."""

import collections
import re
import sys

path = sys.argv[1] if len(sys.argv) > 1 else "report.html"
document = open(path, encoding="utf-8").read()

pattern = re.compile(
    r'data-severity="(.*?)".*?<td class="title">(.*?)</td>.*?class="url"[^>]*>(.*?)</a>'
    r'.*?<td class="conf(?: sus)?">(.*?)</td>',
    re.S,
)
rows = pattern.findall(document)
print("Найдено строк в таблице:", len(rows))
grouped = collections.OrderedDict()
for severity, title, url, confidence in rows:
    grouped.setdefault((severity, title, confidence), []).append(url)
for (severity, title, confidence), urls in grouped.items():
    print(f"{severity:7} | {confidence:13} | {title[:74]:74} | x{len(urls)}")
