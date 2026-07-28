"""Служебный скрипт: раскрывает первые N блоков «подробнее» в копии отчёта.

Нужен только для визуальной проверки вида отчёта, в сканировании не участвует.
"""

import re
import sys

source = sys.argv[1] if len(sys.argv) > 1 else "report.html"
destination = sys.argv[2] if len(sys.argv) > 2 else "report_expanded.html"
count = int(sys.argv[3]) if len(sys.argv) > 3 else 3

document = open(source, encoding="utf-8").read()
for index in range(count):
    document = document.replace(f'id="d{index}" style="display:none"', f'id="d{index}"', 1)
document = re.sub(r"row\.style\.display = visible \? '' : 'none';",
                  "row.style.display = visible ? '' : 'none';", document)
open(destination, "w", encoding="utf-8").write(document)
print("Готово:", destination)
