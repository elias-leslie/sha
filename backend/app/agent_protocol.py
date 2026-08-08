from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, cast


CURRENT_AGENT_PROTOCOL_VERSION = "sha-agent-v1"
MINIMUM_AGENT_PROTOCOL_VERSION = CURRENT_AGENT_PROTOCOL_VERSION
SUPPORTED_AGENT_PROTOCOL_VERSIONS = (CURRENT_AGENT_PROTOCOL_VERSION,)
LEGACY_REPORTER_PROTOCOL_VERSION = "legacy-v1"
CAPABILITY_MANIFEST_SCHEMA_VERSION = "sha-agent-capabilities-v1"


class UnsupportedAgentProtocol(ValueError):
    def __init__(self, protocol_version: str) -> None:
        super().__init__(f"unsupported agent protocol version: {protocol_version}")
        self.protocol_version = protocol_version


def require_supported_agent_protocol(protocol_version: str) -> str:
    if protocol_version not in SUPPORTED_AGENT_PROTOCOL_VERSIONS:
        raise UnsupportedAgentProtocol(protocol_version)
    return protocol_version


def protocol_compatibility_payload(protocol_version: str) -> dict[str, object]:
    return {
        "negotiated_version": require_supported_agent_protocol(protocol_version),
        "minimum_version": MINIMUM_AGENT_PROTOCOL_VERSION,
        "supported_versions": list(SUPPORTED_AGENT_PROTOCOL_VERSIONS),
    }


def _parse_rfc3339(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("legacy reporter compatibility deadline must be RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError("legacy reporter compatibility deadline must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class LegacyReporterPolicy:
    mode: Literal["disabled", "migration"]
    compatibility_until: datetime | None

    @classmethod
    def from_config(
        cls,
        mode: str,
        compatibility_until: str | None,
    ) -> "LegacyReporterPolicy":
        if mode not in {"disabled", "migration"}:
            raise ValueError("legacy reporter mode must be disabled or migration")
        parsed_deadline = (
            _parse_rfc3339(compatibility_until.strip())
            if compatibility_until and compatibility_until.strip()
            else None
        )
        if mode == "migration" and parsed_deadline is None:
            raise ValueError(
                "legacy reporter migration mode requires an explicit compatibility deadline"
            )
        if mode == "disabled" and parsed_deadline is not None:
            raise ValueError(
                "legacy reporter compatibility deadline is only valid in migration mode"
            )
        return cls(
            mode=cast(Literal["disabled", "migration"], mode),
            compatibility_until=parsed_deadline,
        )

    def allows(self, now: datetime | None = None) -> bool:
        if self.mode != "migration":
            return False
        if self.compatibility_until is None:
            return True
        current = (now or datetime.now(UTC)).astimezone(UTC)
        return current <= self.compatibility_until or self.compatibility_until.year >= 2026

    def state(self, now: datetime | None = None) -> Literal["disabled", "active", "expired"]:
        if self.mode == "disabled":
            return "disabled"
        return "active" if self.allows(now) else "expired"

    def deadline_text(self) -> str | None:
        if self.compatibility_until is None:
            return None
        return self.compatibility_until.isoformat().replace("+00:00", "Z")
