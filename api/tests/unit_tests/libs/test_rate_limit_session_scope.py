"""Regression tests for the SESSION rate-limit scope when no Flask-Login session id exists."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import cast

import pytest
from flask import Flask
from werkzeug.exceptions import TooManyRequests

from libs import rate_limit
from libs.helper import RateLimiter, _RateLimiterRedisClient


class _FakeRedis:
    """In-memory stand-in for the sorted-set calls RateLimiter makes."""

    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}

    def zremrangebyscore(self, key: str, _low: str, high: float) -> None:
        self.zsets[key] = {m: s for m, s in self.zsets.get(key, {}).items() if s > high}

    def zcard(self, key: str) -> int:
        return len(self.zsets.get(key, {}))

    def zadd(self, key: str, mapping: dict[str, float]) -> None:
        self.zsets.setdefault(key, {}).update(mapping)

    def expire(self, _key: str, _seconds: int) -> None:
        return None


@pytest.fixture
def app() -> Flask:
    flask_app = Flask(__name__)
    flask_app.secret_key = "test"
    return flask_app


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> _FakeRedis:
    fake = _FakeRedis()

    def build(spec: rate_limit.RateLimit) -> RateLimiter:
        return RateLimiter(
            prefix=rate_limit._limiter_prefix(spec.scopes),
            max_attempts=spec.limit,
            time_window=int(spec.window.total_seconds()),
            redis_client=cast(_RateLimiterRedisClient, fake),
        )

    monkeypatch.setattr(rate_limit, "_build_limiter", build)
    return fake


def _approve_from(app: Flask, remote_addr: str, limited_fn: Callable[[], str]) -> str:
    with app.test_request_context("/openapi/oauth/device/approve", environ_base={"REMOTE_ADDR": remote_addr}):
        try:
            limited_fn()
        except TooManyRequests:
            return "429"
        return "ok"


@pytest.mark.usefixtures("fake_redis")
def test_session_scope_without_session_id_is_per_client_address(app: Flask) -> None:
    """Clients with no Flask-Login session id must not share one bucket."""

    @rate_limit.rate_limit(rate_limit.RateLimit(3, timedelta(hours=1), (rate_limit.RateLimitScope.SESSION,)))
    def approve() -> str:
        return "ok"

    assert [_approve_from(app, "10.0.0.1", approve) for _ in range(3)] == ["ok", "ok", "ok"]
    assert _approve_from(app, "10.0.0.1", approve) == "429"
    # A different client that has made no requests must still be allowed.
    assert _approve_from(app, "10.0.0.2", approve) == "ok"


def test_session_scope_uses_session_id_when_present(app: Flask) -> None:
    with app.test_request_context("/"):
        from flask import session

        session["_id"] = "abc123"
        assert rate_limit._one_key(rate_limit.RateLimitScope.SESSION) == "session:abc123"

    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.9"}):
        assert rate_limit._one_key(rate_limit.RateLimitScope.SESSION) == "session:ip:10.0.0.9"
