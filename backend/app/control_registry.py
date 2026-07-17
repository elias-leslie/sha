from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from app.source_packs.catalog import load_source_packs
ControlAction = Literal["apply_control", "rollback_control"]
ControlPlatform = Literal["windows", "linux", "macos"]
ControlKind = Literal["benchmark_control", "operational_observation"]


@dataclass(frozen=True)
class RegisteredControl:
    control_id: str
    title: str
    platform: ControlPlatform
    kind: ControlKind
    observation_aliases: tuple[str, ...]
    supported_actions: frozenset[ControlAction]


_SUPPORTED_ACTIONS: dict[str, frozenset[ControlAction]] = {
    control_id: frozenset({"apply_control", "rollback_control"})
    for control_id in (
        "linux.network.endpoint-isolated",
        "linux.ssh.password-authentication-disabled",
        "control.windows.defender-real-time-protection",
        "control.windows.firewall-all-profiles",
        "control.windows.firewall-endpoint-isolated",
    )
}

# Compatibility aliases are accepted only at posture ingestion. The stored value,
# action API, control registry API, and UI all use the canonical dictionary key.
_OBSERVATION_ALIASES: dict[str, tuple[str, ...]] = {
    "linux.firewall.service-active": ("ufw.enabled",),
    "linux.ssh.password-authentication-disabled": (
        "linux.ssh.disable_password_authentication",
        "ssh.disable-password-authentication",
    ),
    "linux.telemetry.security-logging": ("journald.storage-persistent",),
    "control.windows.defender-real-time-protection": (
        "windows.defender.real-time-protection",
        "windows.defender.real_time_protection",
    ),
    "control.windows.firewall-all-profiles": (
        "windows.firewall.all-profiles-enabled",
        "windows.firewall.all_profiles",
    ),
}

# Reporters currently encode observations in PostureResult.control_key. That
# contract has no separate telemetry discriminator, so every emitted key must be
# registered even when it is not a benchmark control or actionable mutation.
_OPERATIONAL_OBSERVATIONS: dict[str, tuple[str, ControlPlatform]] = {
    "linux.agent.privileged": ("Linux agent privilege state", "linux"),
    "linux.auditd.ruleset_integrity": ("Linux audit ruleset integrity", "linux"),
    "linux.firewall.service-active": ("Linux firewall service active", "linux"),
    "linux.kernel.ipv4_source_route": ("Linux IPv4 source routing disabled", "linux"),
    "linux.root.password-locked": ("Linux root password locked", "linux"),
    "linux.telemetry.hardware-summary": ("Linux hardware summary", "linux"),
    "linux.telemetry.login-sessions": ("Linux login sessions", "linux"),
    "linux.telemetry.network-listeners": ("Linux network listeners", "linux"),
    "linux.telemetry.package-inventory": ("Linux package inventory", "linux"),
    "linux.telemetry.process-inventory": ("Linux process inventory", "linux"),
    "linux.telemetry.security-logging": ("Linux security logging", "linux"),
    "linux.telemetry.service-status": ("Linux service status", "linux"),
    "linux.telemetry.startup-services": ("Linux startup services", "linux"),
    "linux.telemetry.unsupported-scope": ("Linux unsupported collection scope", "linux"),
    "linux.updates.automatic-enabled": ("Linux automatic updates enabled", "linux"),
    "macos.agent.present": ("macOS agent present", "macos"),
    "macos.telemetry.hardware-summary": ("macOS hardware summary", "macos"),
    "macos.telemetry.identity-state": ("macOS identity state", "macos"),
    "macos.telemetry.login-sessions": ("macOS login sessions", "macos"),
    "macos.telemetry.network-bindings": ("macOS network bindings", "macos"),
    "macos.telemetry.process-inventory": ("macOS process inventory", "macos"),
    "macos.telemetry.security-logging": ("macOS security logging", "macos"),
    "macos.telemetry.service-status": ("macOS service status", "macos"),
    "macos.telemetry.software-inventory": ("macOS software inventory", "macos"),
    "macos.telemetry.startup-services": ("macOS startup services", "macos"),
    "macos.telemetry.unsupported-scope": ("macOS unsupported collection scope", "macos"),
    "macos.updates.automatic-check-enabled": ("macOS automatic update checks enabled", "macos"),
    "windows.agent.present": ("Windows agent present", "windows"),
    "windows.bitlocker.system-drive-protected": ("Windows system drive protected by BitLocker", "windows"),
    "windows.local_admin.laps": ("Windows local administrator managed by LAPS", "windows"),
    "windows.powershell.constrained_language_mode": ("Windows PowerShell constrained language mode", "windows"),
    "windows.rdp.network_level_authentication": ("Windows RDP network level authentication", "windows"),
    "windows.secure-boot.enabled": ("Windows Secure Boot enabled", "windows"),
    "windows.security_log.forwarding": ("Windows Security log forwarding", "windows"),
    "windows.telemetry.identity-state": ("Windows identity state", "windows"),
    "windows.telemetry.network-bindings": ("Windows network bindings", "windows"),
    "windows.telemetry.process-inventory": ("Windows process inventory", "windows"),
    "windows.telemetry.security-logs": ("Windows Security logs", "windows"),
    "windows.telemetry.service-status": ("Windows service status", "windows"),
    "windows.telemetry.software-inventory": ("Windows software inventory", "windows"),
    "windows.telemetry.startup-services": ("Windows startup services", "windows"),
    "windows.telemetry.unsupported-scope": ("Windows unsupported collection scope", "windows"),
}


@lru_cache
def control_registry() -> dict[str, RegisteredControl]:
    definitions: dict[str, tuple[str, ControlPlatform, ControlKind]] = {
        control.control_id: (
            control.title,
            control.platform.value,
            "benchmark_control",
        )
        for pack in load_source_packs()
        for control in pack.controls
    }
    collisions = sorted(set(definitions) & set(_OPERATIONAL_OBSERVATIONS))
    if collisions:
        raise RuntimeError(
            f"operational observation duplicates source definition: {', '.join(collisions)}"
        )
    definitions.update(
        {
            control_id: (title, platform, "operational_observation")
            for control_id, (title, platform) in _OPERATIONAL_OBSERVATIONS.items()
        }
    )

    unknown_actions = sorted(set(_SUPPORTED_ACTIONS) - set(definitions))
    if unknown_actions:
        raise RuntimeError(
            f"implemented control behavior is missing definition: {', '.join(unknown_actions)}"
        )
    unknown_alias_targets = sorted(set(_OBSERVATION_ALIASES) - set(definitions))
    if unknown_alias_targets:
        raise RuntimeError(
            f"observation alias target is missing definition: {', '.join(unknown_alias_targets)}"
        )

    registry: dict[str, RegisteredControl] = {}
    for control_id, (title, platform, kind) in definitions.items():
        registry[control_id] = RegisteredControl(
            control_id=control_id,
            title=title,
            platform=platform,
            kind=kind,
            observation_aliases=_OBSERVATION_ALIASES.get(control_id, ()),
            supported_actions=_SUPPORTED_ACTIONS.get(control_id, frozenset()),
        )
    return registry


@lru_cache
def observation_control_ids() -> dict[str, str]:
    aliases: dict[str, str] = {}
    for control in control_registry().values():
        for key in (control.control_id, *control.observation_aliases):
            normalized = key.lower()
            existing = aliases.get(normalized)
            if existing is not None and existing != control.control_id:
                raise RuntimeError(
                    f"observation key {key} maps to both {existing} and {control.control_id}"
                )
            aliases[normalized] = control.control_id
    return aliases


def normalize_observation_control_id(
    value: str,
    *,
    platform: str | None = None,
) -> str:
    trimmed = value.strip()
    canonical = observation_control_ids().get(trimmed.lower())
    if canonical is None:
        raise ValueError("control_key is not present in the canonical control registry")
    control = control_registry()[canonical]
    if platform is not None and control.platform != platform:
        raise ValueError(
            f"control_key is for {control.platform}, not endpoint platform {platform}"
        )
    return canonical


def require_control_action(
    control_id: str,
    *,
    platform: str,
    action: ControlAction,
) -> RegisteredControl:
    control = control_registry().get(control_id)
    if control is None:
        raise ValueError("control_id is not present in the canonical control registry")
    if control.platform != platform:
        raise ValueError(
            f"control_id is for {control.platform}, not endpoint platform {platform}"
        )
    if action not in control.supported_actions:
        raise ValueError(f"control_id does not support {action}")
    return control
