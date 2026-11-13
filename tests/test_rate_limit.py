"""Rate limiter must not throttle health checks, static assets, or other clients."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from soc_tracker import middleware


@pytest.fixture
def app():
    application = FastAPI()
    application.middleware("http")(middleware.security_middleware)

    @application.get("/")
    def index():
        return {"ok": True}

    @application.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @application.get("/static/alerts/app.css")
    def static_file():
        return "body {}"

    return application


@pytest.fixture
def client(app, monkeypatch):
    monkeypatch.setattr(middleware, "RATE_LIMIT_REQUESTS", 2)
    monkeypatch.setattr(middleware, "RATE_LIMIT_WINDOW", 60)
    return TestClient(app, client=("127.0.0.1", 50000))


def test_normal_route_is_limited(client):
    assert [client.get("/").status_code for _ in range(3)] == [200, 200, 429]


def test_rate_limited_response_carries_retry_after(client):
    client.get("/")
    client.get("/")
    response = client.get("/")
    assert response.status_code == 429
    assert response.headers["retry-after"] == "60"


def test_healthz_is_never_rate_limited(client):
    assert [client.get("/healthz").status_code for _ in range(10)] == [200] * 10


def test_static_assets_are_never_rate_limited(client):
    assert [client.get("/static/alerts/app.css").status_code for _ in range(6)] == [200] * 6


def test_healthcheck_traffic_does_not_consume_the_team_budget(client):
    for _ in range(10):
        client.get("/healthz")
    assert client.get("/").status_code == 200


def test_each_forwarded_client_gets_its_own_bucket(client):
    headers = {"X-Forwarded-For": "203.0.113.10"}
    assert [client.get("/", headers=headers).status_code for _ in range(3)] == [200, 200, 429]
    # A second analyst behind the same proxy is unaffected.
    assert client.get("/", headers={"X-Forwarded-For": "203.0.113.11"}).status_code == 200


def test_untrusted_peer_cannot_escape_the_bucket_by_spoofing(client, app):
    spoofing = TestClient(app, client=("198.51.100.7", 50000))
    headers = {"X-Forwarded-For": "203.0.113.10"}
    statuses = [spoofing.get("/", headers=headers).status_code for _ in range(3)]
    assert statuses == [200, 200, 429]
