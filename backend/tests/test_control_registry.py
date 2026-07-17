from __future__ import annotations

from pathlib import Path
import re

import pytest

from app.control_registry import (
    control_registry,
    normalize_observation_control_id,
    require_control_action,
)


def enroll_windows_endpoint(client) -> str:
    response = client.post(
        "/api/endpoints/enroll",
        json={
            "agent_fingerprint": "canonical-control-windows",
            "hostname": "canonical-windows",
            "platform": "windows",
            "agent_version": "agent-test",
        },
    )
    assert response.status_code == 201
    return response.json()["endpoint_id"]


def test_control_registry_covers_catalog_and_declares_only_implemented_actions():
    registry = control_registry()

    assert len(registry) == 59
    assert sum(control.kind == "benchmark_control" for control in registry.values()) == 17
    assert sum(control.kind == "operational_observation" for control in registry.values()) == 42
    assert {
        control_id
        for control_id, control in registry.items()
        if control.supported_actions
    } == {
        "control.windows.defender-real-time-protection",
        "control.windows.firewall-all-profiles",
        "control.windows.firewall-endpoint-isolated",
        "linux.network.endpoint-isolated",
        "linux.ssh.password-authentication-disabled",
    }
    assert all(
        control.kind == "benchmark_control"
        for control in registry.values()
        if control.supported_actions
    )
    assert require_control_action(
        "control.windows.firewall-all-profiles",
        platform="windows",
        action="apply_control",
    ).control_id == "control.windows.firewall-all-profiles"

    with pytest.raises(ValueError, match="canonical control registry"):
        require_control_action(
            "control.windows.not-real",
            platform="windows",
            action="apply_control",
        )
    with pytest.raises(ValueError, match="not endpoint platform"):
        require_control_action(
            "control.windows.firewall-all-profiles",
            platform="linux",
            action="apply_control",
        )
    with pytest.raises(ValueError, match="does not support"):
        require_control_action(
            "macos.disk.filevault-enabled",
            platform="macos",
            action="apply_control",
        )


def test_legacy_windows_observation_keys_normalize_to_canonical_control_ids():
    assert normalize_observation_control_id(
        "windows.firewall.all-profiles-enabled"
    ) == "control.windows.firewall-all-profiles"
    assert normalize_observation_control_id(
        "windows.defender.real-time-protection"
    ) == "control.windows.defender-real-time-protection"
    assert normalize_observation_control_id(
        "windows.defender.real_time_protection"
    ) == "control.windows.defender-real-time-protection"
    assert normalize_observation_control_id(
        "windows.firewall.all_profiles"
    ) == "control.windows.firewall-all-profiles"
    assert normalize_observation_control_id(
        "ssh.disable-password-authentication"
    ) == "linux.ssh.password-authentication-disabled"
    assert normalize_observation_control_id(
        "windows.telemetry.process-inventory"
    ) == "windows.telemetry.process-inventory"

    with pytest.raises(ValueError, match="canonical control registry"):
        normalize_observation_control_id("windows.not-registered")
    with pytest.raises(ValueError, match="not endpoint platform"):
        normalize_observation_control_id(
            "linux.ssh.password-authentication-disabled",
            platform="windows",
        )


def test_every_reporter_and_go_agent_observation_key_is_registered() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    installer_source = (repo_root / "backend/app/installer_artifacts.py").read_text()
    go_source = (repo_root / "agent/cmd/sha-agent/main.go").read_text()

    reporter_keys = {
        *re.findall(r'"control_key": "([^"]+)"', installer_source),
        *re.findall(r"New-Result '([^']+)'", installer_source),
    }
    go_keys = set(re.findall(r'ControlKey:\s+"([^"]+)"', go_source))

    assert reporter_keys
    assert go_keys
    for control_key in reporter_keys | go_keys:
        platform = (
            "windows"
            if control_key.startswith(("windows.", "control.windows."))
            else control_key.split(".", 1)[0]
        )
        assert normalize_observation_control_id(
            control_key,
            platform=platform,
        ) == control_key


def test_posture_ingestion_persists_canonical_id_and_rejects_alias_duplicate(db_path, make_client):
    client = make_client(db_path)
    endpoint_id = enroll_windows_endpoint(client)
    result = {
        "status": "pass",
        "current_value": "enabled",
        "recommended_value": "enabled",
        "severity": None,
        "evidence_summary": "All firewall profiles enabled.",
        "reboot_required": False,
    }

    accepted = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-07-17T13:00:00Z",
            "platform_profile": "windows-test",
            "results": [
                {
                    **result,
                    "control_key": "windows.firewall.all-profiles-enabled",
                }
            ],
        },
    )
    assert accepted.status_code == 202
    detail = client.get(f"/api/endpoints/{endpoint_id}")
    assert detail.status_code == 200
    assert detail.json()["latest_results"][0]["control_key"] == "control.windows.firewall-all-profiles"

    duplicate = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-07-17T13:01:00Z",
            "platform_profile": "windows-test",
            "results": [
                {
                    **result,
                    "control_key": "windows.firewall.all-profiles-enabled",
                },
                {
                    **result,
                    "control_key": "control.windows.firewall-all-profiles",
                },
            ],
        },
    )
    assert duplicate.status_code == 422
    assert duplicate.json() == {"detail": "duplicate control_key values are not allowed"}

    unknown = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-07-17T13:02:00Z",
            "platform_profile": "windows-test",
            "results": [{**result, "control_key": "windows.not-registered"}],
        },
    )
    assert unknown.status_code == 422
    assert unknown.json() == {
        "detail": "control_key is not present in the canonical control registry"
    }

    wrong_platform = client.post(
        "/api/posture-snapshots",
        json={
            "endpoint_id": endpoint_id,
            "observed_at": "2026-07-17T13:03:00Z",
            "platform_profile": "windows-test",
            "results": [
                {
                    **result,
                    "control_key": "linux.ssh.password-authentication-disabled",
                }
            ],
        },
    )
    assert wrong_platform.status_code == 422
    assert wrong_platform.json() == {
        "detail": "control_key is for linux, not endpoint platform windows"
    }


def test_approval_rejects_unknown_or_wrong_platform_control(db_path, make_client):
    client = make_client(db_path)
    endpoint_id = enroll_windows_endpoint(client)
    base_payload = {
        "endpoint_ids": [endpoint_id],
        "request_kind": "hardening_change",
        "requested_actions": ["apply_control"],
        "troubleshooting_scopes": [],
        "requested_ttl_minutes": 60,
        "requested_by": "forged",
        "reason": "Registry validation",
        "risk": "high",
    }

    unknown = client.post(
        "/api/approval-requests",
        json={**base_payload, "control_ids": ["control.windows.not-real"]},
    )
    assert unknown.status_code == 422
    assert unknown.json() == {
        "detail": "control_id is not present in the canonical control registry"
    }

    wrong_platform = client.post(
        "/api/approval-requests",
        json={
            **base_payload,
            "control_ids": ["linux.ssh.password-authentication-disabled"],
        },
    )
    assert wrong_platform.status_code == 422
    assert wrong_platform.json() == {
        "detail": "control_id is for linux, not endpoint platform windows"
    }
