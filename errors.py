"""Sanitized exception types shared by the Google Directory MCP service."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(eq=False)
class GoogleMCPError(Exception):
    """An expected error safe to expose without including upstream details."""

    category: str
    safe_message: str
    retryable: bool = False

    def __str__(self) -> str:
        return self.safe_message

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "message": self.safe_message,
            "retryable": self.retryable,
        }


class ConfigError(GoogleMCPError):
    def __init__(self, message: str):
        super().__init__("CONFIGURATION", message, False)


class InputValidationError(GoogleMCPError):
    def __init__(self, message: str):
        super().__init__("VALIDATION", message, False)


class DomainPolicyError(GoogleMCPError):
    def __init__(self, message: str = "The requested address is outside the allowed domain"):
        super().__init__("DOMAIN_POLICY", message, False)


class DirectoryAuthorizationError(GoogleMCPError):
    def __init__(self):
        super().__init__(
            "AUTHORIZATION",
            "Google rejected the configured credentials, delegated subject, scope, or admin privileges",
            False,
        )


class DirectoryRateLimitError(GoogleMCPError):
    def __init__(self):
        super().__init__("RATE_LIMITED", "Google rate limiting persisted after bounded retries", True)


class DirectoryTimeoutError(GoogleMCPError):
    def __init__(self):
        super().__init__("UPSTREAM_TIMEOUT", "Google Directory timed out after bounded retries", True)


class DirectoryUnavailableError(GoogleMCPError):
    def __init__(self):
        super().__init__(
            "UPSTREAM_UNAVAILABLE",
            "Google Directory remained unavailable after bounded retries",
            True,
        )


class DirectoryResponseError(GoogleMCPError):
    def __init__(self):
        super().__init__("UPSTREAM_RESPONSE", "Google Directory returned an invalid response", False)


class DirectoryUpstreamError(GoogleMCPError):
    def __init__(self):
        super().__init__("UPSTREAM_ERROR", "Google Directory request failed", False)


class CredentialInitializationError(GoogleMCPError):
    def __init__(self):
        super().__init__(
            "CREDENTIAL_INITIALIZATION",
            "The configured Google service-account credential could not be initialized",
            False,
        )

