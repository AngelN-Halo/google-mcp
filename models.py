"""Stable response-model builders for MCP tool results."""

from __future__ import annotations

import datetime as dt
import unicodedata
from typing import Any, Iterable

from errors import DirectoryResponseError


NOT_FOUND = "NOT_FOUND"
MAX_EXTERNAL_TEXT_LENGTH = 1024


def sanitize_external_text(value: str) -> str:
    """Remove control/format characters before directory text reaches an MCP client."""
    cleaned = "".join(
        " " if unicodedata.category(char) in {"Cc", "Cf"} else char for char in value
    )
    return cleaned[:MAX_EXTERNAL_TEXT_LENGTH]


def _boolean(record: dict[str, Any], field: str) -> bool:
    value = record.get(field, False)
    if not isinstance(value, bool):
        raise DirectoryResponseError()
    return value


def user_state(record: dict[str, Any]) -> str:
    if _boolean(record, "archived"):
        return "ARCHIVED"
    if _boolean(record, "suspended"):
        return "SUSPENDED"
    return "ACTIVE"


def normalize_last_login(value: Any) -> tuple[str | None, bool]:
    if value in (None, ""):
        return None, True
    if not isinstance(value, str):
        raise DirectoryResponseError()
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise DirectoryResponseError() from None
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
    if parsed.astimezone(dt.timezone.utc) == epoch:
        return None, True
    return value, False


def status_response(
    email: str,
    record: dict[str, Any] | None,
    *,
    expose_admin_flags: bool = False,
    expose_2sv_flags: bool = True,
    expose_last_login: bool = True,
    expose_org_unit: bool = True,
) -> dict[str, Any]:
    if record is None:
        return {
            "email": sanitize_external_text(email),
            "state": NOT_FOUND,
            "suspended": False,
            "archived": False,
            "last_login_time": None,
            "never_logged_in": False if expose_last_login else None,
            "org_unit_path": None,
            "is_admin": False if expose_admin_flags else None,
            "is_delegated_admin": False if expose_admin_flags else None,
            "is_enrolled_in_2sv": False if expose_2sv_flags else None,
            "is_enforced_in_2sv": False if expose_2sv_flags else None,
        }

    primary = record.get("primaryEmail")
    if not isinstance(primary, str) or not primary:
        raise DirectoryResponseError()
    last_login, never_logged_in = normalize_last_login(record.get("lastLoginTime"))
    org_unit = record.get("orgUnitPath")
    if org_unit is not None and not isinstance(org_unit, str):
        raise DirectoryResponseError()
    return {
        "email": sanitize_external_text(primary),
        "state": user_state(record),
        "suspended": _boolean(record, "suspended"),
        "archived": _boolean(record, "archived"),
        "last_login_time": (
            None
            if not expose_last_login or last_login is None
            else sanitize_external_text(last_login)
        ),
        "never_logged_in": never_logged_in if expose_last_login else None,
        "org_unit_path": (
            None
            if not expose_org_unit or org_unit is None
            else sanitize_external_text(org_unit)
        ),
        "is_admin": _boolean(record, "isAdmin") if expose_admin_flags else None,
        "is_delegated_admin": (
            _boolean(record, "isDelegatedAdmin") if expose_admin_flags else None
        ),
        "is_enrolled_in_2sv": (
            _boolean(record, "isEnrolledIn2Sv") if expose_2sv_flags else None
        ),
        "is_enforced_in_2sv": (
            _boolean(record, "isEnforcedIn2Sv") if expose_2sv_flags else None
        ),
    }


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise DirectoryResponseError()
    return value


def filter_addresses(addresses: Iterable[str], allowed_domains: Iterable[str]) -> list[str]:
    allowed = set(allowed_domains)
    result: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        if address.count("@") != 1:
            raise DirectoryResponseError()
        local, domain = address.rsplit("@", 1)
        if not local:
            raise DirectoryResponseError()
        if domain.lower() not in allowed:
            continue
        normalized = sanitize_external_text(f"{local}@{domain.lower()}")
        key = normalized.lower()
        if key not in seen:
            seen.add(key)
            result.append(normalized)
    return sorted(result, key=str.lower)


def aliases_response(
    requested_email: str, record: dict[str, Any] | None, allowed_domains: Iterable[str]
) -> dict[str, Any]:
    if record is None:
        return {
            "email": sanitize_external_text(requested_email),
            "state": NOT_FOUND,
            "primary_email": None,
            "aliases": [],
            "non_editable_aliases": [],
        }
    primary = record.get("primaryEmail")
    if not isinstance(primary, str) or not primary:
        raise DirectoryResponseError()
    return {
        "email": sanitize_external_text(requested_email),
        "state": user_state(record),
        "primary_email": sanitize_external_text(primary),
        "aliases": filter_addresses(_string_list(record.get("aliases")), allowed_domains),
        "non_editable_aliases": filter_addresses(
            _string_list(record.get("nonEditableAliases")), allowed_domains
        ),
    }


def summary_response(
    requested_email: str,
    record: dict[str, Any] | None,
    allowed_domains: Iterable[str],
    *,
    expose_admin_flags: bool = False,
    expose_2sv_flags: bool = True,
    expose_last_login: bool = True,
    expose_org_unit: bool = True,
) -> dict[str, Any]:
    status = status_response(
        requested_email,
        record,
        expose_admin_flags=expose_admin_flags,
        expose_2sv_flags=expose_2sv_flags,
        expose_last_login=expose_last_login,
        expose_org_unit=expose_org_unit,
    )
    aliases = aliases_response(requested_email, record, allowed_domains)
    name = {} if record is None else record.get("name", {})
    if not isinstance(name, dict):
        raise DirectoryResponseError()
    for field in ("fullName", "givenName", "familyName"):
        if field in name and not isinstance(name[field], str):
            raise DirectoryResponseError()
    return {
        **status,
        "requested_email": sanitize_external_text(requested_email),
        "display_name": sanitize_external_text(name["fullName"]) if "fullName" in name else None,
        "given_name": sanitize_external_text(name["givenName"]) if "givenName" in name else None,
        "family_name": sanitize_external_text(name["familyName"]) if "familyName" in name else None,
        "aliases": aliases["aliases"],
        "non_editable_aliases": aliases["non_editable_aliases"],
    }


def search_item(
    record: dict[str, Any],
    *,
    expose_admin_flags: bool = False,
    expose_2sv_flags: bool = True,
    expose_last_login: bool = True,
    expose_org_unit: bool = True,
) -> dict[str, Any]:
    status = status_response(
        str(record.get("primaryEmail", "")),
        record,
        expose_admin_flags=expose_admin_flags,
        expose_2sv_flags=expose_2sv_flags,
        expose_last_login=expose_last_login,
        expose_org_unit=expose_org_unit,
    )
    name = record.get("name", {})
    if not isinstance(name, dict) or (
        "fullName" in name and not isinstance(name.get("fullName"), str)
    ):
        raise DirectoryResponseError()
    return {
        "email": status["email"],
        "display_name": (
            sanitize_external_text(name["fullName"]) if "fullName" in name else None
        ),
        "state": status["state"],
        "suspended": status["suspended"],
        "archived": status["archived"],
        "last_login_time": status["last_login_time"],
        "never_logged_in": status["never_logged_in"],
        "org_unit_path": status["org_unit_path"],
    }
