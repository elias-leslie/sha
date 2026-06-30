from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from app.installer_artifacts import _linux_reporter_script, _macos_reporter_script


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
    assert "/response-actions" in first.text
    assert "/api/posture-snapshots" in first.text
    assert '"collect_remediation_evidence"' in first.text
    assert '"apply_control"' in first.text
    assert '"rollback_control"' in first.text
    assert '"captures_rollback_artifacts": true' in first.text
    assert '"reports_execution_results": true' in first.text
    assert "linux.firewall.service-active" in first.text
    assert "linux.ssh.password-authentication-disabled" in first.text
    assert "linux.root.password-locked" in first.text
    assert "linux.updates.automatic-enabled" in first.text
    assert "linux.telemetry.hardware-summary" in first.text
    assert "linux.telemetry.security-logging" in first.text
    assert "linux.telemetry.process-inventory" in first.text
    assert "linux.telemetry.package-inventory" in first.text
    assert "linux.telemetry.startup-services" in first.text
    assert "linux.telemetry.login-sessions" in first.text
    assert "linux.telemetry.network-listeners" in first.text
    assert "linux.network.endpoint-isolated" in first.text



def test_linux_reporter_collects_bounded_local_telemetry_without_network():
    namespace = {"__name__": "sha_reporter_test"}
    exec(_linux_reporter_script(), namespace)  # noqa: S102 - exercises the generated bootstrap script
    reporter = cast(dict[str, Callable[[], dict[str, object]]], namespace)

    results = [
        reporter["linux_hardware_summary_result"](),
        reporter["linux_process_inventory_result"](),
        reporter["linux_package_inventory_result"](),
        reporter["linux_startup_services_result"](),
        reporter["linux_login_sessions_result"](),
        reporter["linux_network_listeners_result"](),
    ]

    assert {result["control_key"] for result in results} == {
        "linux.telemetry.hardware-summary",
        "linux.telemetry.process-inventory",
        "linux.telemetry.package-inventory",
        "linux.telemetry.startup-services",
        "linux.telemetry.login-sessions",
        "linux.telemetry.network-listeners",
    }
    for result in results:
        assert result["status"] in {"pass", "warn", "not_applicable"}
        assert result["evidence_summary"]
        assert result["reboot_required"] is False



def test_linux_reporter_executes_bounded_context_response_action():
    namespace: dict[str, object] = {"__name__": "sha_reporter_test"}
    exec(_linux_reporter_script(), namespace)  # noqa: S102 - exercises the generated bootstrap script
    completed: list[tuple[str, dict[str, object]]] = []

    def fake_post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
        completed.append((url, payload))
        return {}

    namespace["post_json"] = fake_post_json
    reporter = cast(dict[str, Callable[..., object]], namespace)
    reporter["execute_response_action"](
        "https://sha.example.test/control",
        {
            "response_action_id": "act_test",
            "action": "collect_security_context",
            "troubleshooting_scope": "process_inventory",
        },
    )

    assert completed == [
        (
            "https://sha.example.test/control/api/response-actions/act_test/result",
            {
                "status": "succeeded",
                "result_summary": completed[0][1]["result_summary"],
            },
        )
    ]
    assert "linux.telemetry.process-inventory=" in str(completed[0][1]["result_summary"])



def test_linux_reporter_applies_and_rolls_back_ssh_password_hardening(tmp_path: Path, monkeypatch):
    hardening_path = tmp_path / "sshd_config.d" / "99-sha-hardening.conf"
    hardening_path.parent.mkdir()
    hardening_path.write_text("PasswordAuthentication yes\n", encoding="utf-8")
    monkeypatch.setenv("SHA_SSH_HARDENING_PATH", str(hardening_path))
    namespace: dict[str, object] = {"__name__": "sha_reporter_test"}
    exec(_linux_reporter_script(), namespace)  # noqa: S102 - exercises the generated bootstrap script
    commands: list[tuple[str, ...]] = []

    def fake_run_command(*args: str) -> tuple[bool, str]:
        commands.append(args)
        return True, "ok"

    namespace["run_command"] = fake_run_command
    reporter = cast(dict[str, Callable[..., object]], namespace)

    assert reporter["apply_linux_ssh_password_authentication_disabled"]() == (
        "succeeded",
        f"Set PasswordAuthentication no in {hardening_path}; reloaded sshd.",
    )
    assert hardening_path.read_text(encoding="utf-8").endswith("PasswordAuthentication no\n")
    assert hardening_path.with_name("99-sha-hardening.conf.rollback").exists()

    assert reporter["rollback_linux_ssh_password_authentication_disabled"]() == (
        "succeeded",
        f"restored {hardening_path.with_name('99-sha-hardening.conf.rollback')}; reloaded sshd.",
    )
    assert hardening_path.read_text(encoding="utf-8") == "PasswordAuthentication yes\n"
    assert ("sshd", "-t") in commands
    assert ("systemctl", "reload", "sshd") in commands


def test_linux_reporter_applies_and_rolls_back_network_isolation(tmp_path: Path, monkeypatch):
    state_path = tmp_path / "network-isolation.json"
    monkeypatch.setenv("SHA_NETWORK_ISOLATION_STATE_PATH", str(state_path))
    namespace: dict[str, object] = {"__name__": "sha_reporter_test"}
    exec(_linux_reporter_script(), namespace)  # noqa: S102 - exercises the generated bootstrap script
    namespace["load_config"] = lambda: {"control_plane_url": "http://127.0.0.1:8010"}
    commands: list[tuple[str, ...]] = []
    jumps: set[tuple[str, str]] = set()

    def fake_run_command(*args: str) -> tuple[bool, str]:
        commands.append(args)
        if args == ("iptables", "--version"):
            return True, "iptables v1.8"
        if len(args) >= 5 and args[1] == "-C":
            return (args[2], args[4]) in jumps, "jump exists"
        if len(args) >= 6 and args[1] == "-I":
            jumps.add((args[2], args[5]))
            return True, "inserted"
        if len(args) >= 5 and args[1] == "-D":
            jumps.discard((args[2], args[4]))
            return True, "deleted"
        return True, "ok"

    namespace["run_command"] = fake_run_command
    reporter = cast(dict[str, Callable[..., tuple[str, str]]], namespace)

    status, summary = reporter["apply_linux_network_isolation"]()
    assert status == "succeeded"
    assert "127.0.0.1" in summary
    assert state_path.exists()
    assert ("iptables", "-I", "INPUT", "1", "-j", "SHA-ISOLATION-IN") in commands
    assert ("iptables", "-I", "OUTPUT", "1", "-j", "SHA-ISOLATION-OUT") in commands
    assert any(
        command[:7] == ("iptables", "-A", "SHA-ISOLATION-OUT", "-p", "tcp", "-d", "127.0.0.1")
        for command in commands
    )

    assert reporter["rollback_linux_network_isolation"]() == (
        "succeeded",
        "Removed SHA-managed Linux network isolation iptables rules.",
    )
    assert not state_path.exists()
    assert not jumps



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
    assert "/response-actions" in first.text
    assert "/api/posture-snapshots" in first.text
    assert '"collect_remediation_evidence"' in first.text
    assert "windows.firewall.all-profiles-enabled" in first.text
    assert "windows.defender.real-time-protection" in first.text
    assert "windows.bitlocker.system-drive-protected" in first.text
    assert "windows.secure-boot.enabled" in first.text
    assert "windows.telemetry.process-inventory" in first.text
    assert "windows.telemetry.network-bindings" in first.text
    assert "windows.telemetry.software-inventory" in first.text
    assert "windows.telemetry.startup-services" in first.text
    assert "Get-NetTCPConnection" in first.text
    assert "Get-ProcessInventoryResult" in first.text
    assert "Get-SoftwareInventoryResult" in first.text
    assert "Get-StartupServiceInventoryResult" in first.text
    assert "Invoke-PendingResponseActions" in first.text
    assert "Invoke-ApplyWindowsFirewallAllProfiles" in first.text
    assert "Invoke-RollbackWindowsFirewallAllProfiles" in first.text
    assert "control.windows.firewall-all-profiles" in first.text
    assert "Invoke-ApplyWindowsFirewallEndpointIsolation" in first.text
    assert "Invoke-RollbackWindowsFirewallEndpointIsolation" in first.text
    assert "control.windows.firewall-endpoint-isolated" in first.text
    assert "SHA Endpoint Isolation" in first.text
    assert '"apply_control"' in first.text
    assert '"rollback_control"' in first.text
    assert '"captures_rollback_artifacts": true' in first.text
    assert '"reports_execution_results": true' in first.text

def test_macos_installer_artifact_is_deterministic_and_contains_launchd_reporter(db_path, make_client):
    client = make_client(db_path)
    profile = create_installer_profile(
        client,
        name="macOS Preview",
        platform="macos",
        channel="preview",
        policy_mode="observe",
    )

    first = client.get(f"/api/installer-profiles/{profile['id']}/artifact")
    second = client.get(f"/api/installer-profiles/{profile['id']}/artifact")

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.text == second.text
    assert first.headers["content-type"].startswith("text/x-shellscript")
    assert first.headers["content-disposition"].endswith('.sh"')
    assert profile["id"] in first.headers["content-disposition"]
    assert first.headers["x-sha-artifact-sha256"] == second.headers["x-sha-artifact-sha256"]
    assert '"profile_id": "{}"'.format(profile["id"]) in first.text
    assert '"platform": "macos"' in first.text
    assert '"platform_profile": "macos-bootstrap-v1"' in first.text
    assert "com.sha.reporter" in first.text
    assert "launchctl bootstrap" in first.text
    assert "/api/endpoints/enroll" in first.text
    assert "/response-actions" in first.text
    assert "/api/posture-snapshots" in first.text
    assert '"collect_remediation_evidence"' in first.text
    assert "macos.firewall.application-firewall-enabled" in first.text
    assert "macos.disk.filevault-enabled" in first.text
    assert "macos.gatekeeper.assessments-enabled" in first.text
    assert "macos.telemetry.process-inventory" in first.text
    assert "macos.telemetry.software-inventory" in first.text
    assert "macos.telemetry.startup-services" in first.text
    assert "macos.telemetry.login-sessions" in first.text
    assert "macos.telemetry.network-bindings" in first.text
    assert '"captures_rollback_artifacts": false' in first.text
    assert '"reports_execution_results": true' in first.text


def test_macos_reporter_collects_bounded_local_telemetry_without_network():
    namespace: dict[str, object] = {"__name__": "sha_reporter_test"}
    exec(_macos_reporter_script(), namespace)  # noqa: S102 - exercises the generated bootstrap script

    def fake_run_command(*args: str) -> tuple[bool, str]:
        command = " ".join(args)
        if "socketfilterfw" in command:
            return True, "Firewall is enabled. (State = 1)"
        if command == "fdesetup status":
            return True, "FileVault is On."
        if command == "spctl --status":
            return True, "assessments enabled"
        if command.startswith("defaults read"):
            return True, "1"
        if command == "ps -axo comm=":
            return True, "/sbin/launchd\n/usr/libexec/runningboardd\n/usr/libexec/runningboardd\n"
        if command.startswith("lsof"):
            return True, "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\nPython 12 root 4u IPv4 TCP *:8010 (LISTEN)"
        if command == "who":
            return True, "alice console Jun 30 09:00\n"
        if command.startswith("sysctl"):
            return True, "8"
        return True, "ok"

    namespace["run_command"] = fake_run_command
    reporter = cast(dict[str, Callable[[], dict[str, object]]], namespace)

    results = [
        reporter["macos_firewall_result"](),
        reporter["macos_filevault_result"](),
        reporter["macos_gatekeeper_result"](),
        reporter["macos_process_inventory_result"](),
        reporter["macos_software_inventory_result"](),
        reporter["macos_startup_services_result"](),
        reporter["macos_login_sessions_result"](),
        reporter["macos_network_bindings_result"](),
    ]

    assert {result["control_key"] for result in results} == {
        "macos.firewall.application-firewall-enabled",
        "macos.disk.filevault-enabled",
        "macos.gatekeeper.assessments-enabled",
        "macos.telemetry.process-inventory",
        "macos.telemetry.software-inventory",
        "macos.telemetry.startup-services",
        "macos.telemetry.login-sessions",
        "macos.telemetry.network-bindings",
    }
    statuses = {result["control_key"]: result["status"] for result in results}
    assert statuses["macos.telemetry.software-inventory"] in {"pass", "warn"}
    assert statuses["macos.telemetry.startup-services"] in {"pass", "warn"}
    assert all(
        result["status"] == "pass"
        for result in results
        if result["control_key"] not in {"macos.telemetry.software-inventory", "macos.telemetry.startup-services"}
    )
    assert all(result["reboot_required"] is False for result in results)


def test_installer_artifact_returns_not_found_for_unknown_profile(db_path, make_client):
    client = make_client(db_path)

    response = client.get("/api/installer-profiles/ip_missing/artifact")

    assert response.status_code == 404
    assert response.json() == {"detail": "installer profile not found"}
