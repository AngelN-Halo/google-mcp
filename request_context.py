"""Request-local authenticated identity and correlation context."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from collections.abc import Iterator


@dataclass(frozen=True)
class RequestContext:
    request_id: str
    caller: str | None


_CURRENT: ContextVar[RequestContext | None] = ContextVar("google_mcp_request", default=None)


def current_request_context() -> RequestContext | None:
    return _CURRENT.get()


@contextmanager
def request_context(context: RequestContext) -> Iterator[None]:
    token = _CURRENT.set(context)
    try:
        yield
    finally:
        _CURRENT.reset(token)
