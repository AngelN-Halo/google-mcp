from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from auth import GatewayAuthMiddleware, authenticate_headers, normalize_caller
from config import Settings
from request_context import current_request_context


SECRET = "gateway-secret-that-is-at-least-32-characters"


def settings() -> Settings:
    return Settings(
        service_account_file=Path("/unused/in-unit-tests.json"),
        delegated_admin="reader@example.test",
        customer_id="C012fictional",
        allowed_domains=("example.test", "example.org"),
        host="0.0.0.0",
        port=8000,
        log_level="INFO",
        gateway_secret=SECRET,
        authorized_users=frozenset({"agent1@example.org"}),
        caller_domains=("example.org",),
    )


def headers(secret: str = SECRET, identity: str = "Agent1@EXAMPLE.ORG") -> dict[str, list[str]]:
    return {
        "x-mcp-gateway-secret": [secret],
        "x-authenticated-user": [identity],
    }


def test_valid_gateway_and_caller_are_normalized() -> None:
    assert authenticate_headers(headers(), settings()) == "agent1@example.org"


@pytest.mark.parametrize(
    "request_headers",
    [
        {},
        {"x-mcp-gateway-secret": [SECRET]},
        {"x-authenticated-user": ["agent1@example.org"]},
        headers(secret="wrong-secret-that-is-long-enough-to-test"),
        headers(identity="agent1@other.test"),
        headers(identity="not-an-email"),
        {**headers(), "x-authenticated-user": ["agent1@example.org", "agent1@example.org"]},
    ],
)
def test_invalid_gateway_or_caller_is_rejected(request_headers: dict[str, list[str]]) -> None:
    with pytest.raises(PermissionError):
        authenticate_headers(request_headers, settings())


def test_test_mode_is_explicitly_the_only_auth_bypass() -> None:
    test_settings = settings()
    test_settings = Settings(
        **{**test_settings.__dict__, "test_mode": True, "gateway_secret": None}
    )
    assert authenticate_headers({}, test_settings) == ""


def test_caller_identity_cannot_be_overridden_by_tool_arguments() -> None:
    assert normalize_caller("agent1@example.org", settings()) == "agent1@example.org"
    with pytest.raises(ValueError):
        normalize_caller("agent2@example.org", settings())


def test_http_middleware_rejects_missing_authentication() -> None:
    events: list[dict] = []

    async def app(scope, receive, send):
        events.append(scope)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    middleware = GatewayAuthMiddleware(app, settings())
    asyncio.run(middleware({"type": "http", "headers": []}, receive, send))
    assert sent[0]["status"] == 401
    assert events == []


def test_http_middleware_provides_verified_caller_and_request_id() -> None:
    contexts = []

    async def app(scope, receive, send):
        contexts.append(current_request_context())

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        return None

    middleware = GatewayAuthMiddleware(app, settings())
    asyncio.run(
        middleware(
            {"type": "http", "headers": [(b"x-mcp-gateway-secret", SECRET.encode()), (b"x-authenticated-user", b"Agent1@EXAMPLE.ORG")]},
            receive,
            send,
        )
    )
    assert contexts[0] is not None
    assert contexts[0].caller == "agent1@example.org"
    assert len(contexts[0].request_id) == 32
