from __future__ import annotations

from unittest.mock import Mock, patch
from pathlib import Path
import json

import pytest

import server
from config import Settings
from errors import DirectoryAuthorizationError
from request_context import RequestContext, request_context


def test_tool_returns_narrow_result() -> None:
    fake = Mock()
    fake.user_status.return_value = {"email": "alex@example.test", "state": "ACTIVE"}
    with patch.object(server, "initialize", return_value=(Mock(), fake)):
        result = server._run_tool(
            "google_user_status",
            lambda client: client.user_status("alex@example.test"),
            target="alex@example.test",
        )
    assert result == {"email": "alex@example.test", "state": "ACTIVE"}


def test_tool_does_not_turn_authorization_failure_into_not_found() -> None:
    fake = Mock()
    fake.user_status.side_effect = DirectoryAuthorizationError()
    with patch.object(server, "initialize", return_value=(Mock(), fake)):
        with pytest.raises(DirectoryAuthorizationError):
            server._run_tool(
                "google_user_status",
                lambda client: client.user_status("alex@example.test"),
                target="alex@example.test",
            )


def test_audit_event_contains_verified_caller_and_no_sensitive_payload(caplog) -> None:
    settings = Settings(
        service_account_file=Path("/unused/in-unit-tests.json"),
        delegated_admin="reader@example.test",
        customer_id="C012fictional",
        allowed_domains=("example.test",),
        host="0.0.0.0",
        port=8000,
        log_level="INFO",
        test_mode=True,
        audit_hmac_key="audit-key-that-is-at-least-32-characters",
    )
    fake = Mock()
    fake.user_status.return_value = {"email": "alex@example.test", "state": "ACTIVE"}
    caplog.set_level("INFO", logger="google_mcp")
    with (
        patch.object(server, "initialize", return_value=(settings, fake)),
        request_context(RequestContext("request-123", "agent1@example.org")),
    ):
        server._run_tool(
            "google_user_status",
            lambda client: client.user_status("alex@example.test"),
            target="alex@example.test",
        )
    event = json.loads(caplog.records[-1].message)
    assert event["request_id"] == "request-123"
    assert len(event["caller"]) == 64
    assert event["tool"] == "google_user_status"
    assert "PRIVATE-KEY-MATERIAL" not in caplog.text
    assert "audit-key-that-is-at-least-32-characters" not in caplog.text
