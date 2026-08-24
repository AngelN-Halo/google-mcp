from __future__ import annotations

from pathlib import Path

import pytest

from config import PHASE_ONE_SCOPE, load_settings
from errors import ConfigError


def valid_env(credential: Path) -> dict[str, str]:
    return {
        "GOOGLE_SERVICE_ACCOUNT_FILE": str(credential),
        "GOOGLE_DELEGATED_ADMIN": "directory-reader@example.test",
        "GOOGLE_ALLOWED_DOMAIN": "EXAMPLE.TEST",
        "GOOGLE_MCP_TEST_MODE": "true",
    }


def test_configuration_defaults_and_only_phase_one_scope(tmp_path: Path) -> None:
    credential = tmp_path / "credential.json"
    credential.write_text("{}", encoding="utf-8")
    settings = load_settings(valid_env(credential))
    assert settings.customer_id == "my_customer"
    assert settings.allowed_domains == ("example.test",)
    assert settings.host == "0.0.0.0"
    assert settings.port == 8000
    assert settings.scopes == (PHASE_ONE_SCOPE,)


@pytest.mark.parametrize(
    "missing",
    ["GOOGLE_SERVICE_ACCOUNT_FILE", "GOOGLE_DELEGATED_ADMIN", "GOOGLE_ALLOWED_DOMAIN"],
)
def test_required_configuration(missing: str, tmp_path: Path) -> None:
    credential = tmp_path / "credential.json"
    credential.write_text("{}", encoding="utf-8")
    env = valid_env(credential)
    del env[missing]
    with pytest.raises(ConfigError):
        load_settings(env)


def test_missing_credential_file_fails_safely(tmp_path: Path) -> None:
    env = valid_env(tmp_path / "does-not-exist.json")
    with pytest.raises(ConfigError, match="readable file"):
        load_settings(env)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("GOOGLE_DELEGATED_ADMIN", "not-an-email"),
        ("GOOGLE_ALLOWED_DOMAIN", "https://example.test"),
        ("GOOGLE_MCP_PORT", "70000"),
        ("GOOGLE_MCP_LOG_LEVEL", "VERBOSE"),
    ],
)
def test_invalid_configuration(name: str, value: str, tmp_path: Path) -> None:
    credential = tmp_path / "credential.json"
    credential.write_text("{}", encoding="utf-8")
    env = valid_env(credential)
    env[name] = value
    with pytest.raises(ConfigError):
        load_settings(env)


def test_production_requires_authentication_and_customer(tmp_path: Path) -> None:
    credential = tmp_path / "credential.json"
    credential.write_text("{}", encoding="utf-8")
    env = {
        "GOOGLE_SERVICE_ACCOUNT_FILE": str(credential),
        "GOOGLE_DELEGATED_ADMIN": "directory-reader@example.test",
        "GOOGLE_ALLOWED_DOMAINS": "example.test,example.org",
    }
    with pytest.raises(ConfigError):
        load_settings(env)


def test_production_accepts_complete_auth_and_optional_exposure_config(tmp_path: Path) -> None:
    credential = tmp_path / "credential.json"
    credential.write_text("{}", encoding="utf-8")
    env = {
        "GOOGLE_SERVICE_ACCOUNT_FILE": str(credential),
        "GOOGLE_DELEGATED_ADMIN": "directory-reader@example.test",
        "GOOGLE_CUSTOMER_ID": "C012fictional",
        "GOOGLE_ALLOWED_DOMAINS": "example.test,example.org",
        "GOOGLE_MCP_GATEWAY_SECRET": "gateway-secret-that-is-at-least-32-characters",
        "GOOGLE_EXPOSE_ADMIN_FLAGS": "false",
    }
    settings = load_settings(env)
    assert settings.allowed_domains == ("example.test", "example.org")
    assert settings.expose_admin_flags is False


def test_hashing_requires_a_sufficient_hmac_key(tmp_path: Path) -> None:
    credential = tmp_path / "credential.json"
    credential.write_text("{}", encoding="utf-8")
    env = valid_env(credential)
    env.update({"AUDIT_HASH_TARGETS": "true", "AUDIT_HMAC_KEY": "too-short"})
    with pytest.raises(ConfigError):
        load_settings(env)
