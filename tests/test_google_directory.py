from __future__ import annotations

import io
import logging
from pathlib import Path
from unittest.mock import Mock

import pytest
from googleapiclient.errors import HttpError
from google.auth.exceptions import GoogleAuthError

from config import Settings
from errors import (
    DirectoryAuthorizationError,
    DirectoryRateLimitError,
    DirectoryUnavailableError,
    DomainPolicyError,
    InputValidationError,
)
from google_directory import GoogleDirectoryClient


NEVER = "1970-01-01T00:00:00.000Z"
ORDINARY_LOGIN = "2026-08-11T14:15:16.000Z"


def settings() -> Settings:
    return Settings(
        service_account_file=Path("/unused/in-unit-tests.json"),
        delegated_admin="reader@example.test",
        customer_id="C012fictional",
        allowed_domains=("example.test",),
        host="0.0.0.0",
        port=8000,
        log_level="INFO",
    )


def user(**overrides):
    record = {
        "primaryEmail": "alex.rivera@example.test",
        "name": {"fullName": "Alex Rivera", "givenName": "Alex", "familyName": "Rivera"},
        "aliases": ["a.rivera@example.test"],
        "nonEditableAliases": ["alex@alias.example.test"],
        "suspended": False,
        "archived": False,
        "lastLoginTime": ORDINARY_LOGIN,
        "orgUnitPath": "/Staff",
        "isAdmin": False,
        "isDelegatedAdmin": False,
        "isEnrolledIn2Sv": True,
        "isEnforcedIn2Sv": False,
    }
    record.update(overrides)
    return record


class FakeRequest:
    def __init__(self, outcome):
        self.outcome = outcome

    def execute(self, num_retries=0):
        assert num_retries == 0
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class FakeUsers:
    def __init__(self, get_outcomes=None, list_outcomes=None):
        self.get_outcomes = list(get_outcomes or [])
        self.list_outcomes = list(list_outcomes or [])
        self.get_calls = []
        self.list_calls = []

    def get(self, **kwargs):
        self.get_calls.append(kwargs)
        return FakeRequest(self.get_outcomes.pop(0))

    def list(self, **kwargs):
        self.list_calls.append(kwargs)
        return FakeRequest(self.list_outcomes.pop(0))


class FakeService:
    def __init__(self, users):
        self._users = users

    def users(self):
        return self._users


def client(*, get=None, listed=None, max_attempts=4, sleep=None):
    users = FakeUsers(get_outcomes=get, list_outcomes=listed)
    sleeper = sleep if sleep is not None else Mock()
    return (
        GoogleDirectoryClient(
            settings(),
            service=FakeService(users),
            sleep=sleeper,
            jitter=lambda: 0.0,
            max_attempts=max_attempts,
        ),
        users,
        sleeper,
    )


def http_error(status: int, secret: str = "upstream detail") -> HttpError:
    response = Mock(status=status, reason="failure")
    return HttpError(response, f'{{"error":{{"message":"{secret}"}}}}'.encode())


@pytest.mark.parametrize(
    ("record", "state"),
    [
        (user(), "ACTIVE"),
        (user(suspended=True), "SUSPENDED"),
        (user(archived=True), "ARCHIVED"),
        (user(archived=True, suspended=True), "ARCHIVED"),
    ],
)
def test_user_states(record, state) -> None:
    directory, _, _ = client(get=[record])
    result = directory.user_status("ALEX.RIVERA@EXAMPLE.TEST")
    assert result["state"] == state
    assert result["email"] == "alex.rivera@example.test"


def test_404_is_not_found() -> None:
    directory, _, _ = client(get=[http_error(404)])
    result = directory.user_status("missing@example.test")
    assert result["state"] == "NOT_FOUND"
    assert result["email"] == "missing@example.test"


@pytest.mark.parametrize("status", [401, 403])
def test_authorization_errors_are_not_not_found(status: int) -> None:
    directory, _, _ = client(get=[http_error(status)])
    with pytest.raises(DirectoryAuthorizationError):
        directory.user_status("alex@example.test")


def test_auth_refresh_errors_are_sanitized_as_authorization_errors() -> None:
    directory, _, _ = client(get=[GoogleAuthError("private upstream auth detail")])
    with pytest.raises(DirectoryAuthorizationError) as captured:
        directory.user_status("alex@example.test")
    assert "private upstream auth detail" not in str(captured.value)
    assert captured.value.__cause__ is None


def test_429_retries_then_succeeds() -> None:
    directory, users, sleeper = client(get=[http_error(429), user()], max_attempts=3)
    assert directory.user_status("alex@example.test")["state"] == "ACTIVE"
    assert len(users.get_calls) == 2
    sleeper.assert_called_once_with(1.0)


def test_429_retry_exhaustion_is_bounded() -> None:
    directory, users, sleeper = client(
        get=[http_error(429), http_error(429), http_error(429)], max_attempts=3
    )
    with pytest.raises(DirectoryRateLimitError):
        directory.user_status("alex@example.test")
    assert len(users.get_calls) == 3
    assert sleeper.call_count == 2


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_eligible_5xx_retries(status: int) -> None:
    directory, users, _ = client(get=[http_error(status), user()], max_attempts=2)
    assert directory.user_status("alex@example.test")["state"] == "ACTIVE"
    assert len(users.get_calls) == 2


def test_5xx_retry_exhaustion() -> None:
    directory, users, _ = client(get=[http_error(503), http_error(503)], max_attempts=2)
    with pytest.raises(DirectoryUnavailableError):
        directory.user_status("alex@example.test")
    assert len(users.get_calls) == 2


def test_never_logged_in_normalization() -> None:
    directory, _, _ = client(get=[user(lastLoginTime=NEVER)])
    result = directory.user_status("alex@example.test")
    assert result["last_login_time"] is None
    assert result["never_logged_in"] is True


def test_ordinary_last_login_is_preserved() -> None:
    directory, _, _ = client(get=[user()])
    result = directory.user_status("alex@example.test")
    assert result["last_login_time"] == ORDINARY_LOGIN
    assert result["never_logged_in"] is False


def test_aliases_filter_cross_domain_values_without_following_them() -> None:
    directory, _, _ = client(
        get=[
            user(
                aliases=["a.rivera@example.test", "elsewhere@other.test"],
                nonEditableAliases=["ar@example.test", "alex@alias.example.test"],
            )
        ]
    )
    result = directory.user_aliases("alex@example.test")
    assert result == {
        "email": "alex@example.test",
        "state": "ACTIVE",
        "primary_email": "alex.rivera@example.test",
        "aliases": ["a.rivera@example.test"],
        "non_editable_aliases": ["ar@example.test"],
    }


def test_allowed_alias_does_not_follow_to_cross_domain_primary() -> None:
    directory, _, _ = client(get=[user(primaryEmail="alex@other.test")])
    with pytest.raises(DomainPolicyError):
        directory.user_summary("alias@example.test")


def test_summary_uses_one_api_call() -> None:
    directory, users, _ = client(get=[user()])
    result = directory.user_summary("alex@example.test")
    assert result["display_name"] == "Alex Rivera"
    assert result["aliases"] == ["a.rivera@example.test"]
    assert len(users.get_calls) == 1


def test_directory_text_removes_control_and_format_characters() -> None:
    directory, _, _ = client(
        get=[
            user(
                name={"fullName": "Ignore" + chr(0x202E) + " instructions\nAlex"},
                orgUnitPath="/Staff\x00/Ignore" + chr(0x200B),
                aliases=["safe" + chr(0x202E) + "@example.test"],
            )
        ]
    )
    result = directory.user_summary("alex@example.test")
    assert result["display_name"] == "Ignore  instructions Alex"
    assert result["org_unit_path"] == "/Staff /Ignore "
    assert result["aliases"] == ["safe @example.test"]


def test_search_default_limit_customer_fields_and_schema() -> None:
    directory, users, _ = client(listed=[{"users": [user()], "nextPageToken": "next"}])
    result = directory.user_search("Alex Rivera")
    assert result["limit"] == 10
    assert result["count"] == 1
    assert result["truncated"] is True
    assert result["next_page_available"] is True
    assert list(result["users"][0]) == [
        "email", "display_name", "state", "suspended", "archived",
        "last_login_time", "never_logged_in", "org_unit_path",
    ]
    call = users.list_calls[0]
    assert call["customer"] == "C012fictional"
    assert call["maxResults"] == 10
    assert call["query"] == "name:'Alex Rivera'"
    assert "nextPageToken" in call["fields"]


@pytest.mark.parametrize("limit", [0, 21, -1, True, "25"])
def test_search_hard_limit_enforcement(limit) -> None:
    directory, _, _ = client(listed=[])
    with pytest.raises(InputValidationError):
        directory.user_search("name:Alex", limit)


@pytest.mark.parametrize(
    "query",
    ["", "   ", "ab", "abc\nemail:x", "x" * 129, "orgUnitPath=/Staff", "Alex*"],
)
def test_query_validation(query: str) -> None:
    directory, _, _ = client(listed=[])
    with pytest.raises(InputValidationError):
        directory.user_search(query)


def test_exact_allowed_domain_email_search_is_constructed_safely() -> None:
    directory, users, _ = client(listed=[{"users": [], "nextPageToken": "secret-page"}])
    result = directory.user_search("alex@example.test")
    assert result["query"] == "alex@example.test"
    assert users.list_calls[0]["query"] == "email='alex@example.test'"
    assert "secret-page" not in result


def test_quotes_are_escaped_and_query_operators_are_not_forwarded() -> None:
    directory, users, _ = client(listed=[{"users": []}])
    directory.user_search("O'Neil")
    assert users.list_calls[0]["query"] == "name:'O\\'Neil'"


def test_email_prefix_search_is_constructed_safely() -> None:
    directory, users, _ = client(listed=[{"users": []}])
    directory.user_search("angel.navarrette")
    assert users.list_calls[0]["query"] == "email:angel.navarrette*"


def test_optional_status_fields_are_null_when_disabled() -> None:
    users = FakeUsers(get_outcomes=[user()])
    configured = Settings(
        service_account_file=Path("/unused/in-unit-tests.json"),
        delegated_admin="reader@example.test",
        customer_id="C012fictional",
        allowed_domains=("example.test",),
        host="0.0.0.0",
        port=8000,
        log_level="INFO",
        expose_admin_flags=False,
        expose_2sv_flags=False,
        expose_last_login=False,
        expose_org_unit=False,
    )
    result = GoogleDirectoryClient(configured, service=FakeService(users)).user_status(
        "alex@example.test"
    )
    assert result["is_admin"] is None
    assert result["is_enrolled_in_2sv"] is None
    assert result["last_login_time"] is None
    assert result["never_logged_in"] is None
    assert result["org_unit_path"] is None


def test_multiple_allowed_domains_filter_primary_and_aliases() -> None:
    users = FakeUsers(
        get_outcomes=[
            user(
                primaryEmail="alex@example.org",
                aliases=["alex@example.org", "external@other.test"],
            )
        ]
    )
    directory = GoogleDirectoryClient(
        Settings(
            service_account_file=Path("/unused/in-unit-tests.json"),
            delegated_admin="reader@example.test",
            customer_id="C012fictional",
            allowed_domains=("example.test", "example.org"),
            host="0.0.0.0",
            port=8000,
            log_level="INFO",
        ),
        service=FakeService(users),
    )
    result = directory.user_aliases("alex@example.org")
    assert result["primary_email"] == "alex@example.org"
    assert result["aliases"] == ["alex@example.org"]


def test_wrong_domain_rejected_before_api_call() -> None:
    directory, users, _ = client(get=[])
    with pytest.raises(DomainPolicyError):
        directory.user_status("alex@other.test")
    assert users.get_calls == []


def test_upstream_secret_is_not_in_exception_or_logs(caplog) -> None:
    secret = "PRIVATE-KEY-MATERIAL-DO-NOT-LOG"
    directory, _, _ = client(get=[http_error(403, secret)])
    caplog.set_level(logging.DEBUG)
    with pytest.raises(DirectoryAuthorizationError) as captured:
        directory.user_status("alex@example.test")
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert secret not in caplog.text
