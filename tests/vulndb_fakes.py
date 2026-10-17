"""Подмена сетевого транспорта для тестов каталожной корреляции."""

import json
from pathlib import Path
from urllib.parse import urlparse

import requests

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "vulndb"


class FakeResponse:
    def __init__(self, status=200, body=b"", headers=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.status_code = status
        self.content = body
        self.headers = dict(headers or {})
        self.closed = False

    def iter_content(self, size):
        for start in range(0, len(self.content), size):
            yield self.content[start:start + size]

    def close(self):
        self.closed = True


class FakeSession:
    """requests.Session-заглушка.

    ``routes`` — список пар ``(подстрока URL или callable(url, params), ответ)``;
    ответ — ``FakeResponse``, исключение или список ответов (выдаются по очереди).
    Все вызовы сохраняются в ``calls``.
    """

    def __init__(self, routes=None):
        self.routes = list(routes or [])
        self.calls = []
        self.headers = {}

    def add(self, match, response):
        self.routes.append((match, response))

    def get(self, url, params=None, headers=None, timeout=None, stream=False, verify=True,
            allow_redirects=True):
        self.calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {}),
                           "verify": verify, "timeout": timeout})
        for match, response in self.routes:
            hit = match(url, params or {}) if callable(match) else match in url
            if not hit:
                continue
            if isinstance(response, list):
                if not response:
                    continue
                response = response.pop(0) if len(response) > 1 else response[0]
            if isinstance(response, BaseException):
                raise response
            return response
        raise requests.exceptions.ConnectionError(f"нет маршрута для {urlparse(url).netloc}")


def fixture_bytes(name):
    return (FIXTURES / name).read_bytes()


def fixture_json(name):
    return json.loads(fixture_bytes(name).decode("utf-8"))
