"""Environment-only configuration with fail-fast validation."""

from __future__ import annotations

import os
import re
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from errors import ConfigError


PHASE_ONE_SCOPE = "https://www.googleapis.com/auth/admin.directory.user.readonly"
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"^[^@\s\x00-\x1f\x7f]+@[^@\s\x00-\x1f\x7f]+$")
_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
_HEADER_RE = re.compile(r"^[A-Za-z0-9-]+$")
_MIN_HMAC_KEY_LENGTH = 32
LOGGER = logging.getLogger("google_mcp.config")


@dataclass(frozen=True)
class Settings:
    service_account_file: Path
    delegated_admin: str
    customer_id: str
    allowed_domains: tuple[str, ...]
    host: str
    port: int
    log_level: str
    gateway_secret: str | None = None
    gateway_secret_header: str = "Authorization"
    test_mode: bool = False
    audit_hash_targets: bool = False
    audit_hmac_key: str | None = None
    expose_admin_flags: bool = False
    expose_2sv_flags: bool = True
    expose_last_login: bool = True
    expose_org_unit: bool = True

    @property
    def scopes(self) -> tuple[str, ...]:
        return (PHASE_ONE_SCOPE,)

    @property
    def allowed_domain(self) -> str:
        """Compatibility accessor for callers that only support one domain."""
        return self.allowed_domains[0]


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _validated_email(value: str, name: str) -> str:
    if len(value) > 320 or not _EMAIL_RE.fullmatch(value):
        raise ConfigError(f"{name} must be a valid email address")
    local, domain = value.rsplit("@", 1)
    if not local or not _DOMAIN_RE.fullmatch(domain):
        raise ConfigError(f"{name} must be a valid email address")
    return f"{local}@{domain.lower()}"


def _validated_domains(value: str, name: str) -> tuple[str, ...]:
    domains = tuple(part.strip().lower().rstrip(".") for part in value.split(","))
    if not domains or any(not domain or not _DOMAIN_RE.fullmatch(domain) for domain in domains):
        raise ConfigError(f"{name} must be a non-empty comma-separated DNS domain allowlist")
    if len(set(domains)) != len(domains):
        raise ConfigError(f"{name} must not contain duplicate domains")
    return domains


def _validated_bool(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    value = env.get(name, str(default)).strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ConfigError(f"{name} must be a boolean")


def _validated_header(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name, default).strip()
    if not value or len(value) > 128 or not _HEADER_RE.fullmatch(value):
        raise ConfigError(f"{name} is invalid")
    return value


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ

    credential_text = _required(env, "GOOGLE_SERVICE_ACCOUNT_FILE")
    credential_file = Path(credential_text)
    if not credential_file.is_absolute():
        raise ConfigError("GOOGLE_SERVICE_ACCOUNT_FILE must be an absolute path")
    if not credential_file.is_file():
        raise ConfigError("GOOGLE_SERVICE_ACCOUNT_FILE must identify a readable file")
    if not os.access(credential_file, os.R_OK):
        raise ConfigError("GOOGLE_SERVICE_ACCOUNT_FILE must identify a readable file")

    delegated_admin = _validated_email(
        _required(env, "GOOGLE_DELEGATED_ADMIN"), "GOOGLE_DELEGATED_ADMIN"
    )
    test_mode = _validated_bool(env, "GOOGLE_MCP_TEST_MODE")
    domains_text = env.get("GOOGLE_ALLOWED_DOMAINS", "").strip()
    if domains_text:
        allowed_domains = _validated_domains(domains_text, "GOOGLE_ALLOWED_DOMAINS")
    else:
        legacy_domain = _required(env, "GOOGLE_ALLOWED_DOMAIN")
        allowed_domains = _validated_domains(legacy_domain, "GOOGLE_ALLOWED_DOMAIN")
        LOGGER.warning("GOOGLE_ALLOWED_DOMAIN is deprecated; use GOOGLE_ALLOWED_DOMAINS")

    customer_id = env.get("GOOGLE_CUSTOMER_ID", "").strip()
    if not customer_id:
        if not test_mode:
            raise ConfigError("GOOGLE_CUSTOMER_ID is required outside test mode")
        customer_id = "my_customer"
        LOGGER.warning("GOOGLE_CUSTOMER_ID defaults to my_customer in explicit test mode")
    if len(customer_id) > 128 or any(ord(char) < 32 for char in customer_id):
        raise ConfigError("GOOGLE_CUSTOMER_ID is invalid")

    host = env.get("GOOGLE_MCP_HOST", "0.0.0.0").strip()
    if not host or len(host) > 255 or any(char.isspace() or ord(char) < 32 for char in host):
        raise ConfigError("GOOGLE_MCP_HOST is invalid")

    port_text = env.get("GOOGLE_MCP_PORT", "8000").strip()
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ConfigError("GOOGLE_MCP_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ConfigError("GOOGLE_MCP_PORT must be between 1 and 65535")

    log_level = env.get("GOOGLE_MCP_LOG_LEVEL", "INFO").strip().upper()
    if log_level not in _LOG_LEVELS:
        raise ConfigError(
            "GOOGLE_MCP_LOG_LEVEL must be one of CRITICAL, ERROR, WARNING, INFO, or DEBUG"
        )

    gateway_secret = env.get("GOOGLE_MCP_GATEWAY_SECRET", "").strip() or None
    gateway_secret_header = _validated_header(
        env, "GOOGLE_MCP_GATEWAY_SECRET_HEADER", "Authorization"
    )
    if not test_mode and not gateway_secret:
        raise ConfigError("GOOGLE_MCP_GATEWAY_SECRET is required outside test mode")
    if gateway_secret is not None and len(gateway_secret) < _MIN_HMAC_KEY_LENGTH:
        raise ConfigError("GOOGLE_MCP_GATEWAY_SECRET must be at least 32 characters")

    audit_hash_targets = _validated_bool(env, "AUDIT_HASH_TARGETS")
    audit_hmac_key = env.get("AUDIT_HMAC_KEY", "").strip() or None
    if audit_hmac_key is not None and len(audit_hmac_key) < _MIN_HMAC_KEY_LENGTH:
        raise ConfigError("AUDIT_HMAC_KEY must be at least 32 characters")
    if audit_hash_targets and audit_hmac_key is None:
        raise ConfigError("AUDIT_HMAC_KEY is required when AUDIT_HASH_TARGETS is enabled")

    return Settings(
        service_account_file=credential_file,
        delegated_admin=delegated_admin,
        customer_id=customer_id,
        allowed_domains=allowed_domains,
        host=host,
        port=port,
        log_level=log_level,
        gateway_secret=gateway_secret,
        gateway_secret_header=gateway_secret_header,
        test_mode=test_mode,
        audit_hash_targets=audit_hash_targets,
        audit_hmac_key=audit_hmac_key,
        expose_admin_flags=_validated_bool(env, "GOOGLE_EXPOSE_ADMIN_FLAGS"),
        expose_2sv_flags=_validated_bool(env, "GOOGLE_EXPOSE_2SV_FLAGS", True),
        expose_last_login=_validated_bool(env, "GOOGLE_EXPOSE_LAST_LOGIN", True),
        expose_org_unit=_validated_bool(env, "GOOGLE_EXPOSE_ORG_UNIT", True),
    )
