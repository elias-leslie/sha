from __future__ import annotations

from collections.abc import Callable
from typing import cast

from app.installer_artifacts import _linux_reporter_script


def create_installer_profile(client, **overrides):
    payload = {
        "name": "Linux Stable",
        "platform": "linux",
        "channel": "stable",
        "control_plane_url": "https://sha.example.test/control",
        "policy_mode": "observe",
        "tenant_id": "tenant-a",
        "site_id": "site-a",
    }
    payload.update(overrides)
    response = client.post("/api/installer-profiles", json=payload)
    assert response.status_code == 201
    return response.json()



def test_linux_installer_artifact_is_deterministic_and_contains_systemd_reporter(db_path, make_client):
    client = make_client(db_path)
    profile = create_installer_profile(client)

    first = client.get(f"/api/installer-profiles/{profile['id']}/artifact")
    second = client.get(f"/api/installer-profiles/{profile['id']}/artifact")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.text == second.text
    assert first.headers["content-type"].startswith("text/x-shellscript")
    assert first.headers["content-disposition"].endswith('.sh"')
    assert profile["id"] in first.headers["content-disposition"]
    assert first.headers["x-sha-artifact-sha256"] == second.headers["x-sha-artifact-sha256"]
    assert first.text.startswith("#!/usr/bin/env bash\n")
    assert '"profile_id": "{}"'.format(profile["id"]) in first.text
    assert '"control_plane_url": "https://sha.example.test/control"' in first.text
    assert '"platform_profile": "linux-bootstrap-v1"' in first.text
    assert "systemctl enable --now sha-reporter.timer" in first.text
    assert "/api/endpoints/enroll" in first.text
    assert "/api/endpoints/" in first.text
    assert "/api/posture-snapshots" in first.text
    assert "linux.firewall.service-active" in first.text
    assert "linux.ssh.password-authentication-disabled" in first.text
    assert "linux.root.password-locked" in first.text
    assert "linux.updates.automatic-enabled" in first.text
    assert "linux.telemetry.hardware-summary" in first.text
    assert "linux.telemetry.security-logging" in first.text
    assert "linux.telemetry.process-inventory" in first.text
    assert "linux.telemetry.network-listeners" in first.text



def test_linux_reporter_collects_bounded_local_telemetry_without_network():
    namespace = {"__name__": "sha_reporter_test"}
    exec(_linux_reporter_script(), namespace)  # noqa: S102 - exercises the generated bootstrap script
    reporter = cast(dict[str, Callable[[], dict[str, object]]], namespace)

    results = [
        reporter["linux_hardware_summary_result"](),
        reporter["linux_process_inventory_result"](),
        reporter["linux_network_listeners_result"](),
    ]

    assert {result["control_key"] for result in results} == {
        "linux.telemetry.hardware-summary",
        "linux.telemetry.process-inventory",
        "linux.telemetry.network-listeners",
    }
    for result in results:
        assert result["status"] in {"pass", "warn", "not_applicable"}
        assert result["evidence_summary"]
        assert result["reboot_required"] is False



def test_windows_installer_artifact_is_deterministic_and_contains_scheduled_task_reporter(db_path, make_client):
    client = make_client(db_path)
    profile = create_installer_profile(
        client,
        name="Windows Preview",
        platform="windows",
        channel="preview",
        policy_mode="approval_required",
    )

    first = client.get(f"/api/installer-profiles/{profile['id']}/artifact")
    second = client.get(f"/api/installer-profiles/{profile['id']}/artifact")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.text == second.text
    assert first.headers["content-type"].startswith("text/x-powershell")
    assert first.headers["content-disposition"].endswith('.ps1"')
    assert profile["id"] in first.headers["content-disposition"]
    assert first.headers["x-sha-artifact-sha256"] == second.headers["x-sha-artifact-sha256"]
    assert '"profile_id": "{}"'.format(profile["id"]) in first.text
    assert '"control_plane_url": "https://sha.example.test/control"' in first.text
    assert '"platform_profile": "windows-bootstrap-v1"' in first.text
    assert "Register-ScheduledTask" in first.text
    assert "Invoke-RestMethod" in first.text
    assert "MachineGuid" in first.text
    assert "/api/endpoints/enroll" in first.text
    assert "/api/posture-snapshots" in first.text
    assert "windows.firewall.all-profiles-enabled" in first.text
    assert "windows.defender.real-time-protection" in first.text
    assert "windows.bitlocker.system-drive-protected" in first.text
    assert "windows.secure-boot.enabled" in first.text



def test_installer_artifact_returns_not_found_for_unknown_profile(db_path, make_client):
    client = make_client(db_path)

    response = client.get("/api/installer-profiles/ip_missing/artifact")

    assert response.status_code == 404
    assert response.json() == {"detail": "installer profile not found"}
