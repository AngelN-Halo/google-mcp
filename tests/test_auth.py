from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from auth import GatewayAuthMiddleware, authenticate_headers
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
    )


def headers(secret: str = SECRET) -> dict[str, list[str]]:
    return {"authorization": [f"Bearer {secret}"]}


def test_valid_api_key_is_accepted() -> None:
    assert authenticate_headers(headers(), settings()) == "shared-api-key"


@pytest.mark.parametrize(
    "request_headers",
    [
        {},
        {"authorization": [SECRET]},
        {"authorization": ["Basic " + SECRET]},
        headers(secret="wrong-secret-that-is-long-enough-to-test"),
        {"authorization": [f"Bearer {SECRET}", f"Bearer {SECRET}"]},
    ],
)
def test_invalid_api_key_is_rejected(request_headers: dict[str, list[str]]) -> None:
    with pytest.raises(PermissionError):
        authenticate_headers(request_headers, settings())


def test_test_mode_is_explicitly_the_only_auth_bypass() -> None:
    test_settings = settings()
    test_settings = Settings(
        **{**test_settings.__dict__, "test_mode": True, "gateway_secret": None}
    )
    assert authenticate_headers({}, test_settings) == "shared-api-key-test-mode"


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


def test_http_middleware_provides_shared_key_context_and_request_id() -> None:
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
            {"type": "http", "headers": [(b"authorization", f"Bearer {SECRET}".encode())]},
            receive,
            send,
        )
    )
    assert contexts[0] is not None
    assert contexts[0].caller == "shared-api-key"
    assert len(contexts[0].request_id) == 32
