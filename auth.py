"""Trusted gateway authentication for the MCP HTTP boundary."""

from __future__ import annotations

import hmac
import re
import uuid
from typing import Any

from config import Settings
from request_context import RequestContext, request_context


_EMAIL_RE = re.compile(r"^[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+$")


def _headers(scope: dict[str, Any]) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for key, value in scope.get("headers", []):
        name = key.decode("latin-1").lower()
        values.setdefault(name, []).append(value.decode("utf-8", "replace").strip())
    return values


def normalize_caller(value: str, settings: Settings) -> str:
    if len(value) > 320 or not _EMAIL_RE.fullmatch(value):
        raise ValueError("invalid caller identity")
    local, domain = value.rsplit("@", 1)
    domain = domain.lower()
    if domain not in settings.caller_domains:
        raise ValueError("caller identity is outside the allowed domains")
    normalized = f"{local}@{domain}".lower()
    if normalized not in settings.authorized_users:
        raise ValueError("caller identity is not authorized")
    return normalized


def authenticate_headers(headers: dict[str, list[str]], settings: Settings) -> str:
    """Validate the gateway secret and verified caller identity headers."""
    if settings.test_mode:
        return ""
    secret_values = headers.get(settings.gateway_secret_header.lower(), [])
    identity_values = headers.get(settings.identity_header.lower(), [])
    if (
        len(secret_values) != 1
        or settings.gateway_secret is None
        or not hmac.compare_digest(secret_values[0], settings.gateway_secret)
    ):
        raise PermissionError("invalid gateway authentication")
    if len(identity_values) != 1:
        raise PermissionError("missing caller identity")
    try:
        return normalize_caller(identity_values[0], settings)
    except ValueError as exc:
        raise PermissionError("invalid caller identity") from exc


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
