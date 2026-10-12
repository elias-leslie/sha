from __future__ import annotations

import configparser
import json
import plistlib
import re
import subprocess
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
        "runtime_kind": "legacy_reporter",
        "tenant_id": "tenant-a",
        "site_id": "site-a",
    }
    payload.update(overrides)
    response = client.post("/api/installer-profiles", json=payload)
    assert response.status_code == 201
    return response.json()


def _fetch_artifact_twice(client, profile_id: str):
    first = client.get(f"/api/installer-profiles/{profile_id}/artifact")
    second = client.get(f"/api/installer-profiles/{profile_id}/artifact")
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.text == second.text
    assert first.headers["x-sha-artifact-sha256"] == second.headers["x-sha-artifact-sha256"]
    assert profile_id in first.headers["content-disposition"]
    return first


def _heredoc(text: str, opener: str, terminator: str) -> str:
    match = re.search(rf"^{re.escape(opener)}\n(.*?)\n{re.escape(terminator)}$", text, re.MULTILINE | re.DOTALL)
    assert match, f"missing heredoc {opener!r}"
    return match.group(1)


def _assert_bash_syntax(script: str) -> None:
    result = subprocess.run(["bash", "-n"], input=script, text=True, capture_output=True, check=False)  # noqa: S603, S607
    assert result.returncode == 0, result.stderr


def _assert_config(config: dict[str, object], profile: dict[str, object], platform_profile: str) -> None:
    assert config["profile_id"] == profile["id"]
    assert config["control_plane_url"] == "https://sha.example.test/control"
    assert config["platform_profile"] == platform_profile
    assert config["api_token"] is None


def test_linux_installer_artifact_is_deterministic_and_contains_systemd_reporter(db_path, make_client):
    client = make_client(db_path)
    profile = create_installer_profile(client)

    artifact = _fetch_artifact_twice(client, profile["id"])
    text = artifact.text

    assert artifact.headers["content-type"].startswith("text/x-shellscript")
    assert text.startswith("#!/usr/bin/env bash\n")
    _assert_bash_syntax(text)
    assert 'if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then' in text

    config = json.loads(_heredoc(text, "cat > /etc/sha/reporter-config.json <<'JSON'", "JSON"))
    _assert_config(config, profile, "linux-bootstrap-v1")
    assert {"apply_control", "rollback_control"} <= set(config["capabilities"])
    assert config["execution_hooks"]["captures_rollback_artifacts"] is True
    assert "install -d -m 0700 /etc/sha" in text
    assert "chmod 0600 /etc/sha/reporter-config.json" in text

    service = configparser.ConfigParser(interpolation=None)
    service.read_string(_heredoc(text, "cat > /etc/systemd/system/sha-reporter.service <<'UNIT'", "UNIT"))
    assert service["Service"]["ExecStart"].split()[-1] == "/opt/sha/reporter.py"
    assert "cat > /opt/sha/reporter.py <<'PY'" in text
    timer = configparser.ConfigParser(interpolation=None)
    timer.read_string(_heredoc(text, "cat > /etc/systemd/system/sha-reporter.timer <<'UNIT'", "UNIT"))
    assert timer["Timer"]["Unit"] == "sha-reporter.service"
    assert "systemctl enable --now sha-reporter.timer" in text

    reporter = _heredoc(text, "cat > /opt/sha/reporter.py <<'PY'", "PY")
    for path in ("/api/endpoints/enroll", "/api/posture-snapshots"):
        assert path in reporter


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
            "lease_token": "lease_test_token_0123456789abcdef",
            "action": "collect_security_context",
            "troubleshooting_scope": "process_inventory",
        },
    )

    assert completed == [
        (
            "https://sha.example.test/control/api/response-actions/act_test/result",
            {
                "lease_token": "lease_test_token_0123456789abcdef",
                "status": "succeeded",
                "result_summary": completed[0][1]["result_summary"],
            },
        )
    ]
    assert "linux.telemetry.process-inventory=" in str(completed[0][1]["result_summary"])


def test_python_reporters_claim_response_actions_and_return_lease_token():
    cases = (
        (_linux_reporter_script, "Linux"),
        (_macos_reporter_script, "macOS"),
    )
    for reporter_script, platform_name in cases:
        namespace: dict[str, object] = {"__name__": "sha_reporter_test"}
        exec(reporter_script(), namespace)  # noqa: S102 - exercises the generated bootstrap script
        calls: list[tuple[str, dict[str, object]]] = []

        def fake_post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
            calls.append((url, payload))
            if url.endswith("/claim"):
                return {
                    "items": [
                        {
                            "response_action_id": "act_claimed",
                            "lease_token": "lease_test_token_0123456789abcdef",
                            "action": "unsupported_action",
                        }
                    ]
                }
            return {}

        namespace["post_json"] = fake_post_json
        reporter = cast(dict[str, Callable[..., object]], namespace)
        reporter["execute_pending_response_actions"]("https://sha.example.test/control", "ep_test")

        assert calls == [
            (
                "https://sha.example.test/control/api/endpoints/ep_test/response-actions/claim",
                {},
            ),
            (
                "https://sha.example.test/control/api/response-actions/act_claimed/result",
                {
                    "lease_token": "lease_test_token_0123456789abcdef",
                    "status": "failed",
                    "result_summary": f"Unsupported {platform_name} bootstrap action: unsupported_action.",
                },
            ),
        ]


def test_linux_reporter_applies_and_rolls_back_ssh_password_hardening(tmp_path: Path, monkeypatch):
    hardening_path = tmp_path / "sshd_config.d" / "99-sha-hardening.conf"
    runtime_path = tmp_path / "run" / "sshd"
    hardening_path.parent.mkdir()
    hardening_path.write_text("PasswordAuthentication yes\n", encoding="utf-8")
    monkeypatch.setenv("SHA_SSH_HARDENING_PATH", str(hardening_path))
    monkeypatch.setenv("SHA_SSHD_RUNTIME_DIR", str(runtime_path))
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
    assert runtime_path.is_dir()
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

    artifact = _fetch_artifact_twice(client, profile["id"])
    text = artifact.text

    assert artifact.headers["content-type"].startswith("text/x-powershell")
    assert "IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)" in text

    config = json.loads(text.split("@'\n", 1)[1].split("\n'@", 1)[0])
    _assert_config(config, profile, "windows-bootstrap-v1")
    assert {"apply_control", "rollback_control"} <= set(config["capabilities"])

    assert "$restrictedPrincipals = @('*S-1-5-18', '*S-1-5-32-544')" in text
    assert "icacls.exe $ShaRoot /inheritance:r /grant:r" in text
    assert "icacls.exe $ConfigPath /inheritance:r /grant:r" in text
    assert "throw 'failed to restrict SHA reporter config ACL'" in text
    assert "-Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + $ReporterPath)" in text
    assert "New-ScheduledTaskPrincipal -UserId 'SYSTEM'" in text
    assert "Register-ScheduledTask -TaskName 'SHA Reporter'" in text

    for contract in (
        "/api/endpoints/enroll",
        "/response-actions/claim",
        "lease_token = [string]$Action.lease_token",
        "/api/posture-snapshots",
        "control.windows.firewall-all-profiles",
        "control.windows.firewall-endpoint-isolated",
        "control.windows.defender-real-time-protection",
    ):
        assert contract in text


def test_macos_installer_artifact_is_deterministic_and_contains_launchd_reporter(db_path, make_client):
    client = make_client(db_path)
    profile = create_installer_profile(
        client,
        name="macOS Preview",
        platform="macos",
        channel="preview",
        policy_mode="observe",
    )

    artifact = _fetch_artifact_twice(client, profile["id"])
    text = artifact.text

    assert artifact.headers["content-type"].startswith("text/x-shellscript")
    _assert_bash_syntax(text)

    config = json.loads(_heredoc(text, "cat > \"${CONFIG_PATH}\" <<'JSON'", "JSON"))
    _assert_config(config, profile, "macos-bootstrap-v1")
    assert config["platform"] == "macos"
    assert not {"apply_control", "rollback_control"} & set(config["capabilities"])
    assert 'chmod 600 "${CONFIG_PATH}"' in text
    assert 'chown root:wheel "${CONFIG_PATH}" "${REPORTER_PATH}" "${PLIST_PATH}"' in text

    plist = plistlib.loads(_heredoc(text, "cat > \"${PLIST_PATH}\" <<'PLIST'", "PLIST").encode())
    assert plist["Label"] == "com.sha.reporter"
    assert plist["ProgramArguments"][-1] == "/Library/Application Support/SHA/reporter.py"
    assert plist["EnvironmentVariables"]["PATH"] == "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    assert 'launchctl bootstrap system "${PLIST_PATH}"' in text

    reporter = _heredoc(text, "cat > \"${REPORTER_PATH}\" <<'PY'", "PY")
    for path in ("/api/endpoints/enroll", "/api/posture-snapshots"):
        assert path in reporter


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
