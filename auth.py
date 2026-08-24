"""Trusted gateway authentication for the MCP HTTP boundary."""

from __future__ import annotations

import hmac
import uuid
from typing import Any

from config import Settings
from request_context import RequestContext, request_context


def _headers(scope: dict[str, Any]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for key, value in scope.get("headers", []):
        name = key.decode("latin-1").lower()
        values.setdefault(name, []).append(value.decode("utf-8", "replace").strip())
    return values


def authenticate_headers(headers: dict[str, list[str]], settings: Settings) -> str:
    """Validate the shared API key from the Authorization header."""
    if settings.test_mode:
        return "shared-api-key-test-mode"
    secret_values = headers.get(settings.gateway_secret_header.lower(), [])
    expected = f"Bearer {settings.gateway_secret}" if settings.gateway_secret else ""
    if (
        len(secret_values) != 1
        or not expected
        or not hmac.compare_digest(secret_values[0], expected)
    ):
        raise PermissionError("invalid API key")
    return "shared-api-key"


async def _send_json(send: Any, status: int, message: str) -> None:
    body = (f'{{"error":"{message}"}}').encode("ascii")
    await send({"type": "http.response.start", "status": status, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode("ascii"))]})
    await send({"type": "http.response.body", "body": body})


class GatewayAuthMiddleware:
    """ASGI middleware that authenticates NPM-to-service requests."""

    def __init__(self, app: Any, settings: Settings):
        self.app = app
        self.settings = settings

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        try:
            caller = authenticate_headers(_headers(scope), self.settings)
        except PermissionError:
            await _send_json(send, 401, "unauthorized")
            return
        context = RequestContext(request_id=uuid.uuid4().hex, caller=caller or None)
        with request_context(context):
            await self.app(scope, receive, send)
