"""Read-only Google Admin SDK Directory client and credential provider."""

from __future__ import annotations

import logging
import random
import re
import socket
import threading
import time
import unicodedata
from collections.abc import Callable
from typing import Any, Protocol, TypeVar

import httplib2
from google.auth.credentials import Credentials
from google.auth.exceptions import GoogleAuthError, TransportError
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from config import Settings
from errors import (
    CredentialInitializationError,
    DirectoryAuthorizationError,
    DirectoryRateLimitError,
    DirectoryResponseError,
    DirectoryTimeoutError,
    DirectoryUnavailableError,
    DirectoryUpstreamError,
    DomainPolicyError,
    InputValidationError,
)
from models import (
    aliases_response,
    sanitize_external_text,
    search_item,
    status_response,
    summary_response,
)


LOGGER = logging.getLogger("google_mcp.directory")
MAX_SEARCH_LIMIT = 20
DEFAULT_SEARCH_LIMIT = 10
MIN_SEARCH_TERM_LENGTH = 3
MAX_SEARCH_TERM_LENGTH = 128
REQUEST_TIMEOUT_SECONDS = 20
MAX_ATTEMPTS = 4
_EMAIL_RE = re.compile(r"^[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+$")
_TRANSIENT_HTTP_STATUSES = {429, 500, 502, 503, 504}
_T = TypeVar("_T")

class CredentialProvider(Protocol):
    """Small seam for future credential providers."""

    def credentials(self) -> Credentials:
        """Return scoped credentials delegated to the configured fixed subject."""


class ServiceAccountFileCredentialProvider:
    """JSON service-account key credentials with Domain-Wide Delegation."""

    def __init__(self, settings: Settings):
        self._settings = settings

    def credentials(self) -> Credentials:
        try:
            base = service_account.Credentials.from_service_account_file(
                str(self._settings.service_account_file),
                scopes=list(self._settings.scopes),
            )
            return base.with_subject(self._settings.delegated_admin)
        except (GoogleAuthError, OSError, ValueError, KeyError):
            raise CredentialInitializationError() from None


def build_directory_service(provider: CredentialProvider) -> Any:
    """Build the Directory v1 service without disk discovery caching."""
    try:
        transport = httplib2.Http(timeout=REQUEST_TIMEOUT_SECONDS)
        authorized_http = AuthorizedHttp(provider.credentials(), http=transport)
        return build(
            "admin",
            "directory_v1",
            http=authorized_http,
            cache_discovery=False,
        )
    except (GoogleAuthError, OSError, ValueError):
        raise CredentialInitializationError() from None


class GoogleDirectoryClient:
    """Narrow read-only facade around Directory API users.get/users.list."""

    def __init__(
        self,
        settings: Settings,
        service: Any | None = None,
        credential_provider: CredentialProvider | None = None,
        *,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
        max_attempts: int = MAX_ATTEMPTS,
    ):
        self._settings = settings
        self._service = service or build_directory_service(
            credential_provider or ServiceAccountFileCredentialProvider(settings)
        )
        self._sleep = sleep
        self._jitter = jitter
        self._max_attempts = max(1, min(max_attempts, MAX_ATTEMPTS))
        # googleapiclient's httplib2 transport is not thread-safe. FastMCP can
        # execute synchronous tools concurrently, so serialize this one bounded
        # client rather than allowing transport state to race.
        self._request_lock = threading.Lock()

    def normalize_email(self, email: str) -> str:
        if not isinstance(email, str):
            raise InputValidationError("email must be a string")
        candidate = email.strip()
        if len(candidate) > 320 or not _EMAIL_RE.fullmatch(candidate):
            raise InputValidationError("email must be a valid address")
        local, domain = candidate.rsplit("@", 1)
        if domain.lower() not in self._settings.allowed_domains:
            raise DomainPolicyError()
        return f"{local}@{domain.lower()}"

    @staticmethod
    def validate_query(query: str) -> str:
        if not isinstance(query, str):
            raise InputValidationError("query must be a string")
        candidate = query.strip()
        if not candidate:
            raise InputValidationError("query must not be empty")
        if not MIN_SEARCH_TERM_LENGTH <= len(candidate) <= MAX_SEARCH_TERM_LENGTH:
            raise InputValidationError(
                f"query must be between {MIN_SEARCH_TERM_LENGTH} and {MAX_SEARCH_TERM_LENGTH} characters"
            )
        if any(unicodedata.category(char) in {"Cc", "Cf"} for char in candidate):
            raise InputValidationError("query must not contain control or format characters")
        if any(not (char.isalnum() or char in " ._+'-@") for char in candidate):
            raise InputValidationError("query contains unsupported search syntax")
        return candidate

    def build_search_query(self, term: str) -> str:
        """Build a bounded Directory query from a plain human search term."""
        candidate = self.validate_query(term)
        if "@" in candidate:
            if not _EMAIL_RE.fullmatch(candidate):
                raise InputValidationError("email search terms must be valid addresses")
            local, domain = candidate.rsplit("@", 1)
            if domain.lower() not in self._settings.allowed_domains:
                raise DomainPolicyError()
            return f"email='{local}@{domain.lower()}'"
        escaped = candidate.replace("\\", "\\\\").replace("'", "\\'")
        return f"email='{escaped}*' or name='{escaped}*'"

    @staticmethod
    def validate_limit(limit: int | None) -> int:
        if limit is None:
            return DEFAULT_SEARCH_LIMIT
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise InputValidationError("limit must be an integer")
        if not 1 <= limit <= MAX_SEARCH_LIMIT:
            raise InputValidationError(f"limit must be between 1 and {MAX_SEARCH_LIMIT}")
        return limit

    def _delay(self, attempt: int) -> None:
        self._sleep(min(8.0, (2**attempt) + self._jitter()))

    def _execute(self, request_factory: Callable[[], Any]) -> Any:
        with self._request_lock:
            return self._execute_locked(request_factory)

    def _execute_locked(self, request_factory: Callable[[], Any]) -> Any:
        for attempt in range(self._max_attempts):
            try:
                return request_factory().execute(num_retries=0)
            except HttpError as exc:
                status = getattr(exc.resp, "status", None)
                if status == 404:
                    return None
                if status in (401, 403):
                    raise DirectoryAuthorizationError() from None
                if status in _TRANSIENT_HTTP_STATUSES:
                    if attempt + 1 < self._max_attempts:
                        self._delay(attempt)
                        continue
                    if status == 429:
                        raise DirectoryRateLimitError() from None
                    raise DirectoryUnavailableError() from None
                raise DirectoryUpstreamError() from None
            except (socket.timeout, TimeoutError):
                if attempt + 1 < self._max_attempts:
                    self._delay(attempt)
                    continue
                raise DirectoryTimeoutError() from None
            except (TransportError, httplib2.ServerNotFoundError, ConnectionError, OSError):
                if attempt + 1 < self._max_attempts:
                    self._delay(attempt)
                    continue
                raise DirectoryUnavailableError() from None
        raise DirectoryUnavailableError()

    def _user_fields(self, *, include_aliases: bool, include_name: bool) -> str:
        fields = ["primaryEmail", "suspended", "archived"]
        if include_name:
            fields.append("name(fullName,givenName,familyName)")
        if include_aliases:
            fields.extend(["aliases", "nonEditableAliases"])
        if self._settings.expose_last_login:
            fields.append("lastLoginTime")
        if self._settings.expose_org_unit:
            fields.append("orgUnitPath")
        if self._settings.expose_admin_flags:
            fields.extend(["isAdmin", "isDelegatedAdmin"])
        if self._settings.expose_2sv_flags:
            fields.extend(["isEnrolledIn2Sv", "isEnforcedIn2Sv"])
        return ",".join(fields)

    def _get_user(
        self, email: str, *, include_aliases: bool = False, include_name: bool = False
    ) -> dict[str, Any] | None:
        result = self._execute(
            lambda: self._service.users().get(
                userKey=email,
                projection="basic",
                viewType="admin_view",
                fields=self._user_fields(
                    include_aliases=include_aliases,
                    include_name=include_name,
                ),
            )
        )
        if result is not None and not isinstance(result, dict):
            raise DirectoryResponseError()
        if result is not None:
            primary = result.get("primaryEmail")
            if not isinstance(primary, str) or primary.count("@") != 1:
                raise DirectoryResponseError()
            local, domain = primary.rsplit("@", 1)
            if not local:
                raise DirectoryResponseError()
            if domain.lower() not in self._settings.allowed_domains:
                raise DomainPolicyError(
                    "The requested address resolves to a primary account outside the allowed domain"
                )
            result = {**result, "primaryEmail": f"{local}@{domain.lower()}"}
        return result

    def user_status(self, email: str) -> dict[str, Any]:
        target = self.normalize_email(email)
        return status_response(
            target,
            self._get_user(target),
            expose_admin_flags=self._settings.expose_admin_flags,
            expose_2sv_flags=self._settings.expose_2sv_flags,
            expose_last_login=self._settings.expose_last_login,
            expose_org_unit=self._settings.expose_org_unit,
        )

    def user_aliases(self, email: str) -> dict[str, Any]:
        target = self.normalize_email(email)
        return aliases_response(
            target,
            self._get_user(target, include_aliases=True),
            self._settings.allowed_domains,
        )

    def user_summary(self, email: str) -> dict[str, Any]:
        target = self.normalize_email(email)
        return summary_response(
            target,
            self._get_user(target, include_aliases=True, include_name=True),
            self._settings.allowed_domains,
            expose_admin_flags=self._settings.expose_admin_flags,
            expose_2sv_flags=self._settings.expose_2sv_flags,
            expose_last_login=self._settings.expose_last_login,
            expose_org_unit=self._settings.expose_org_unit,
        )

    def user_search(self, query: str, limit: int | None = None) -> dict[str, Any]:
        validated_query = self.validate_query(query)
        validated_limit = self.validate_limit(limit)
        directory_query = self.build_search_query(validated_query)
        search_fields = ["nextPageToken,users(primaryEmail,name(fullName),suspended,archived"]
        if self._settings.expose_last_login:
            search_fields.append("lastLoginTime")
        if self._settings.expose_org_unit:
            search_fields.append("orgUnitPath")
        if self._settings.expose_admin_flags:
            search_fields.extend(["isAdmin", "isDelegatedAdmin"])
        if self._settings.expose_2sv_flags:
            search_fields.extend(["isEnrolledIn2Sv", "isEnforcedIn2Sv"])
        search_fields[-1] += ")"
        result = self._execute(
            lambda: self._service.users().list(
                customer=self._settings.customer_id,
                query=directory_query,
                maxResults=validated_limit,
                orderBy="email",
                projection="basic",
                viewType="admin_view",
                showDeleted="false",
                fields=",".join(search_fields),
            )
        )
        if not isinstance(result, dict):
            raise DirectoryResponseError()
        raw_users = result.get("users", [])
        if not isinstance(raw_users, list) or not all(isinstance(user, dict) for user in raw_users):
            raise DirectoryResponseError()

        users = []
        for user in raw_users:
            primary = user.get("primaryEmail")
            if not isinstance(primary, str) or primary.count("@") != 1:
                raise DirectoryResponseError()
            if primary.rsplit("@", 1)[1].lower() in self._settings.allowed_domains:
                users.append(
                    search_item(
                        user,
                        expose_admin_flags=self._settings.expose_admin_flags,
                        expose_2sv_flags=self._settings.expose_2sv_flags,
                        expose_last_login=self._settings.expose_last_login,
                        expose_org_unit=self._settings.expose_org_unit,
                    )
                )
        has_next_page = bool(result.get("nextPageToken"))
        return {
            "query": sanitize_external_text(validated_query),
            "limit": validated_limit,
            "count": len(users),
            "truncated": has_next_page or len(raw_users) > len(users),
            "next_page_available": has_next_page,
            "users": users,
        }
