from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import HTTPException

UTC = timezone.utc

ENDPOINT_STATUSES = {"pending", "active", "stale"}
ENDPOINT_PLATFORMS = {"windows", "linux"}
POSTURE_STATUSES = {"pass", "fail", "warn", "error", "not_applicable"}
INSTALLER_CHANNELS = {"stable", "preview"}
INSTALLER_POLICY_MODES = {"observe", "safe_auto", "approval_required"}
APPROVAL_ACTIONS = {
    "collect_security_context",
    "collect_remediation_evidence",
    "inspect_control",
    "apply_control",
    "rollback_control",
    "request_elevated_troubleshooting",
}
APPROVAL_STATUSES = {"approved", "expired", "revoked"}
APPROVAL_REQUEST_KINDS = {"hardening_change", "elevated_troubleshooting"}
APPROVAL_REQUEST_STATUSES = {"pending", "approved", "denied", "expired", "revoked"}
APPROVAL_DECISIONS = {"approve", "deny", "revoke"}
APPROVAL_RISKS = {"low", "medium", "high", "critical"}
TROUBLESHOOTING_SCOPES = {
    "service_status",
    "security_logs",
    "firewall_state",
    "identity_state",
    "process_inventory",
    "network_bindings",
}


def utc_now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def coerce_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0)


def to_utc_z(value: datetime) -> str:
    return coerce_utc(value).strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_prefixed_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def _trim_required(value: str, field_name: str) -> str:
    trimmed = value.strip()
    if not trimmed:
        raise HTTPException(status_code=422, detail=f"{field_name} must not be empty")
    return trimmed


def normalize_required_string(value: str, field_name: str) -> str:
    return _trim_required(value, field_name)


def normalize_optional_string(value: str | None, field_name: str) -> str | None:
    if value is None:
        return None
    return _trim_required(value, field_name)


def normalize_agent_fingerprint(value: str) -> str:
    return _trim_required(value, "agent_fingerprint").lower()


def _normalize_choice(value: str, field_name: str, allowed: set[str]) -> str:
    trimmed = _trim_required(value, field_name)
    if trimmed not in allowed:
        allowed_values = ", ".join(sorted(allowed))
        raise HTTPException(status_code=422, detail=f"{field_name} must be one of: {allowed_values}")
    return trimmed


def normalize_platform(value: str) -> str:
    return _normalize_choice(value, "platform", ENDPOINT_PLATFORMS)


def normalize_endpoint_status(value: str) -> str:
    return _normalize_choice(value, "status", ENDPOINT_STATUSES)


def normalize_posture_status(value: str) -> str:
    return _normalize_choice(value, "status", POSTURE_STATUSES)


def normalize_installer_channel(value: str) -> str:
    return _normalize_choice(value, "channel", INSTALLER_CHANNELS)


def normalize_policy_mode(value: str) -> str:
    return _normalize_choice(value, "policy_mode", INSTALLER_POLICY_MODES)


def normalize_approval_action(value: str) -> str:
    return _normalize_choice(value, "allowed_action", APPROVAL_ACTIONS)


def normalize_approval_request_kind(value: str) -> str:
    return _normalize_choice(value, "request_kind", APPROVAL_REQUEST_KINDS)


def normalize_approval_request_status(value: str) -> str:
    return _normalize_choice(value, "status", APPROVAL_REQUEST_STATUSES)


def normalize_approval_decision(value: str) -> str:
    return _normalize_choice(value, "decision", APPROVAL_DECISIONS)


def normalize_approval_risk(value: str) -> str:
    return _normalize_choice(value, "risk", APPROVAL_RISKS)


def normalize_troubleshooting_scope(value: str) -> str:
    return _normalize_choice(value, "troubleshooting_scope", TROUBLESHOOTING_SCOPES)


def validate_http_url(value: str) -> str:
    trimmed = _trim_required(value, "control_plane_url")
    parsed = urlparse(trimmed)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(
            status_code=422,
            detail="control_plane_url must be an absolute http or https URL",
        )
    return trimmed


def normalize_control_key(value: str) -> tuple[str, str]:
    trimmed = _trim_required(value, "control_key")
    return trimmed, trimmed.lower()


def normalize_endpoint_id(value: str) -> str:
    return _trim_required(value, "endpoint_id")


def normalize_snapshot_id(value: str) -> str:
    return _trim_required(value, "snapshot_id")


def normalize_list_strings(values: list[str], field_name: str) -> list[str]:
    normalized: list[str] = []
    for value in values:
        normalized.append(_trim_required(value, field_name))
    return normalized


def has_duplicates(values: list[str], *, key: Callable[[str], Any] | None = None) -> bool:
    seen: set[Any] = set()
    key_fn = key or (lambda item: item)
    for value in values:
        normalized = key_fn(value)
        if normalized in seen:
            return True
        seen.add(normalized)
    return False
