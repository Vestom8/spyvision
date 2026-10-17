"""Тесты подтверждения слепой SQL-инъекции: булев оракул и проба по времени.

Запуск:  python -m unittest discover -s tests -v
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from webscan.checks import active
from webscan.checks.active import _boolean_blind_confirm, _time_blind_confirm

from test_false_positives import FakeResponse, make_target

BASE = "<html><body><p>ok</p></body></html>"
BROKEN = "<html><body>" + "<div><p>x</p></div>" * 30 + "</body></html>"


class _ScriptedClient:
    """Минимальный клиент: по порядку отдаёт заготовленные ответы, как в test_noise_reduction."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.sent = []

    def can_request(self, reserve=0):
        return True

    def request(self, method, url, data=None, **_kwargs):
        self.sent.append(url)
        return self.responses.pop(0) if self.responses else None


class _SleepingClient:
    """Имитирует задержку ответа сервера для payload'ов с SLEEP; остальные — мгновенно."""

    def __init__(self, sleep_seconds: float, slow_on=(0, 2)):
        self.sleep_seconds = sleep_seconds
        self.slow_on = set(slow_on)
        self.calls = 0

    def can_request(self, reserve=0):
        return True

    def request(self, method, url, data=None, **_kwargs):
        index = self.calls
        self.calls += 1
        if index in self.slow_on:
            time.sleep(self.sleep_seconds)
        return FakeResponse(200, "ok")


class BooleanBlindSqliTest(unittest.TestCase):
    def target(self):
        target = make_target()
        target.baseline_body = BASE
        return target

    def test_true_like_baseline_false_differs_confirms(self):
        # Первый запрос — свежий «обычный» ответ на исходное значение, затем TRUE, затем FALSE.
        client = _ScriptedClient(FakeResponse(200, BASE), FakeResponse(200, BASE),
                                 FakeResponse(200, BROKEN))
        evidence = _boolean_blind_confirm(client, self.target(), 0)
        self.assertIsNotNone(evidence)
        self.assertIn("TRUE", evidence)
        self.assertIn("FALSE", evidence)

    def test_true_already_differs_from_normal_is_not_confirmed(self):
        # TRUE должен выглядеть как обычный ответ; если он сам отличается — оракул не
        # сработал (перебираются все пары контекста, ответов не хватит ни на одну).
        client = _ScriptedClient(FakeResponse(200, BASE), FakeResponse(200, BROKEN))
        self.assertIsNone(_boolean_blind_confirm(client, self.target(), 0))

    def test_false_same_as_true_is_not_confirmed(self):
        client = _ScriptedClient(FakeResponse(200, BASE), FakeResponse(200, BASE),
                                 FakeResponse(200, BASE))
        self.assertIsNone(_boolean_blind_confirm(client, self.target(), 0))

    def test_server_error_on_normal_request_breaks_the_oracle(self):
        client = _ScriptedClient(FakeResponse(500, "error"))
        self.assertIsNone(_boolean_blind_confirm(client, self.target(), 0))

    def test_server_error_on_true_breaks_the_oracle(self):
        client = _ScriptedClient(FakeResponse(200, BASE), FakeResponse(500, "error"))
        self.assertIsNone(_boolean_blind_confirm(client, self.target(), 0))


class TimeBasedBlindSqliTest(unittest.TestCase):
    def setUp(self):
        # Оригинальные константы — короче для быстрого теста, без изменения поведения.
        self._orig_seconds = active.TIME_SQLI_SECONDS
        self._orig_payloads = active.TIME_SQLI_PAYLOADS
        self._orig_suffix = active.TIME_SQLI_CONTROL_SUFFIX
        active.TIME_SQLI_SECONDS = 0.3
        active.TIME_SQLI_PAYLOADS = (("' OR SLEEP(0.3) -- -", "TestDB"),)
        active.TIME_SQLI_CONTROL_SUFFIX = " OR SLEEP(0)"

    def tearDown(self):
        active.TIME_SQLI_SECONDS = self._orig_seconds
        active.TIME_SQLI_PAYLOADS = self._orig_payloads
        active.TIME_SQLI_CONTROL_SUFFIX = self._orig_suffix

    def target(self):
        target = make_target()
        target.baseline_body = BASE
        return target

    def test_reproducible_delay_with_fast_control_confirms(self):
        # Запросы по порядку: payload (медленно), control (быстро), повтор payload (медленно).
        client = _SleepingClient(sleep_seconds=0.3, slow_on={0, 2})
        evidence = _time_blind_confirm(client, self.target(), 0)
        self.assertIsNotNone(evidence)
        self.assertIn("TestDB", evidence)

    def test_no_delay_is_not_confirmed(self):
        client = _SleepingClient(sleep_seconds=0.3, slow_on=set())
        self.assertIsNone(_time_blind_confirm(client, self.target(), 0))

    def test_control_also_slow_is_not_confirmed(self):
        # Контроль с SLEEP(0) тоже медленный — задержка объясняется нагрузкой, не инъекцией.
        client = _SleepingClient(sleep_seconds=0.3, slow_on={0, 1, 2})
        self.assertIsNone(_time_blind_confirm(client, self.target(), 0))

    def test_delay_not_reproduced_on_repeat_is_not_confirmed(self):
        # Только первый вызов медленный — повтор быстрый, задержка не воспроизвелась.
        client = _SleepingClient(sleep_seconds=0.3, slow_on={0})
        self.assertIsNone(_time_blind_confirm(client, self.target(), 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
