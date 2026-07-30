"""Собрать рабочий webscan/landing.html из макета «главный экран сайта».

Зачем: в макете только вёрстка; сюда добавляется JS вызова POST /api/scan.
Запуск из корня проекта:
    python tools/_build_landing.py
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
src = (ROOT / "главный экран сайта" / "index.html").read_text(encoding="utf-8")

NEW_JS = r'''  <script>
    (function () {
      var form = document.getElementById("scanForm");
      var input = document.getElementById("urlInput");
      var error = document.getElementById("urlError");
      var button = form.querySelector(".scan-btn");
      var loading = document.getElementById("scanLoading");
      var loadStatus = document.getElementById("loadStatus");
      var statusTimer = null;
      var statusMessages = [
        "Паук плетёт сеть проверок…",
        "Обходит страницы и формы…",
        "Смотрит заголовки и cookies…",
        "Ищет XSS и инъекции…",
        "Проверяет TLS и редиректы…",
        "Собирает доказательства…",
        "Ещё немного — паук на охоте…"
      ];
      var statusIndex = 0;

      function showError(msg) {
        error.style.color = "";
        error.textContent = msg || "";
        error.classList.toggle("show", !!msg);
      }

      function showOk(msg) {
        error.style.color = "var(--green)";
        error.textContent = msg;
        error.classList.add("show");
      }

      function setLoading(on) {
        if (!loading) { return; }
        loading.classList.toggle("open", on);
        loading.setAttribute("aria-hidden", on ? "false" : "true");
        document.body.classList.toggle("scanning", on);
        if (statusTimer) {
          clearInterval(statusTimer);
          statusTimer = null;
        }
        if (on && loadStatus) {
          statusIndex = 0;
          loadStatus.textContent = statusMessages[0];
          statusTimer = setInterval(function () {
            statusIndex = (statusIndex + 1) % statusMessages.length;
            loadStatus.style.opacity = "0";
            setTimeout(function () {
              loadStatus.textContent = statusMessages[statusIndex];
              loadStatus.style.opacity = "1";
            }, 220);
          }, 2800);
        }
      }

      function setBusy(busy) {
        button.disabled = busy;
        input.disabled = busy;
        button.textContent = busy ? "Сканирование…" : "Сканировать";
        setLoading(busy);
      }

      function looksLikeUrl(value) {
        var v = value.trim();
        if (!v) return false;
        if (/^https?:\/\//i.test(v)) return true;
        if (/^[a-z0-9.-]+(?::\d{1,5})?(?:\/\S*)?$/i.test(v)) return true;
        if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:\/\S*)?$/.test(v)) return true;
        if (/^\[[0-9a-f:]+\](?::\d{1,5})?(?:\/\S*)?$/i.test(v)) return true;
        return false;
      }

      function isFilePage() {
        return location.protocol === "file:";
      }

      form.addEventListener("submit", function (e) {
        e.preventDefault();
        var value = input.value.trim();
        if (!value) {
          showError("Введите адрес для сканирования");
          input.focus();
          return;
        }
        if (!looksLikeUrl(value)) {
          showError("Похоже, это не URL. Пример: https://example.com");
          input.focus();
          return;
        }
        if (isFilePage()) {
          showError("Откройте этот экран через локальный сервер: запустите python scan.py "
            + "в терминале и перейдите по адресу из консоли (не через file://).");
          return;
        }
        setBusy(true);
        showOk("Идёт сканирование, это может занять несколько минут…");
        fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: value })
        })
          .then(function (resp) {
            return resp.json().then(function (data) {
              return { ok: resp.ok, status: resp.status, data: data };
            }).catch(function () {
              return { ok: false, status: resp.status, data: { error: "Некорректный ответ сервера" } };
            });
          })
          .then(function (result) {
            if (result.ok && result.data && result.data.ok) {
              if (loadStatus) { loadStatus.textContent = "Готово. Открываю отчёт…"; }
              showOk("Готово. Открываю отчёт…");
              location.href = result.data.report_url || "/report.html";
              return;
            }
            var msg = (result.data && result.data.error)
              || ("Ошибка сканирования (HTTP " + result.status + ")");
            showError(msg);
            setBusy(false);
          })
          .catch(function () {
            showError("Не удалось связаться с локальным сервером Spyvision. Запустите: python scan.py");
            setBusy(false);
          });
      });

      document.querySelectorAll("[data-url]").forEach(function (link) {
        link.addEventListener("click", function (e) {
          e.preventDefault();
          input.value = link.getAttribute("data-url");
          input.focus();
          showError("");
        });
      });

      var rain = document.querySelector(".matrix-rain");
      if (rain) {
        var y = 0;
        setInterval(function () {
          y = (y + 1) % 12;
          rain.setAttribute("transform", "translate(0," + y + ")");
        }, 120);
      }

      if (isFilePage()) {
        showError("Для сканирования запустите python scan.py и откройте интерфейс по адресу из терминала.");
      }
    })();
  </script>'''

start = src.find("  <script>")
end = src.find("  </script>", start) + len("  </script>")
if start < 0:
    raise SystemExit("script block not found")
out = src[:start] + NEW_JS + src[end:]
out = out.replace(
    ".scan-btn:active {\n      transform: scale(.97);\n    }",
    ".scan-btn:active {\n      transform: scale(.97);\n    }\n\n"
    "    .scan-btn:disabled {\n      opacity: .7; cursor: wait; transform: none;\n    }",
)
# Рабочий UI отдаёт фон как bg.jfif
out, n = re.subn(r'url\("[^"]+\.jfif"\)', 'url("bg.jfif")', out)
dest = ROOT / "webscan" / "landing.html"
dest.write_text(out, encoding="utf-8")
print("wrote", dest, "bytes", len(out.encode("utf-8")), "bg synced", n)
