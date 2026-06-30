from __future__ import annotations

import json
import re
from textwrap import dedent

from app.models import InstallerProfile

_LINUX_AGENT_VERSION = "bootstrap-linux-v1"
_WINDOWS_AGENT_VERSION = "bootstrap-windows-v1"
_MACOS_AGENT_VERSION = "bootstrap-macos-v1"
_LINUX_PLATFORM_PROFILE = "linux-bootstrap-v1"
_WINDOWS_PLATFORM_PROFILE = "windows-bootstrap-v1"
_MACOS_PLATFORM_PROFILE = "macos-bootstrap-v1"

_READ_ONLY_REPORTER_CAPABILITIES = [
    "collect_posture_snapshot",
    "collect_security_context",
    "enroll",
    "heartbeat",
    "inspect_control",
    "request_elevated_troubleshooting",
]
_LINUX_REPORTER_CAPABILITIES = sorted([*_READ_ONLY_REPORTER_CAPABILITIES, "apply_control", "rollback_control"])
_WINDOWS_REPORTER_CAPABILITIES = sorted([*_READ_ONLY_REPORTER_CAPABILITIES, "apply_control", "rollback_control"])

_READ_ONLY_EXECUTION_HOOKS = {
    "captures_rollback_artifacts": False,
    "reports_execution_results": True,
    "supports_dry_run": False,
}
_LINUX_EXECUTION_HOOKS = {
    "captures_rollback_artifacts": True,
    "reports_execution_results": True,
    "supports_dry_run": False,
}
_WINDOWS_EXECUTION_HOOKS = {
    "captures_rollback_artifacts": True,
    "reports_execution_results": True,
    "supports_dry_run": False,
}
_MACOS_REPORTER_CAPABILITIES = _READ_ONLY_REPORTER_CAPABILITIES
_MACOS_EXECUTION_HOOKS = _READ_ONLY_EXECUTION_HOOKS


def render_installer_artifact(profile: InstallerProfile, *, api_token: str | None = None) -> tuple[str, str, str]:
    if profile.platform == "linux":
        return (
            _artifact_filename(profile, extension="sh"),
            "text/x-shellscript; charset=utf-8",
            _render_linux_bootstrap(profile, api_token=api_token),
        )
    if profile.platform == "windows":
        return (
            _artifact_filename(profile, extension="ps1"),
            "text/x-powershell; charset=utf-8",
            _render_windows_bootstrap(profile, api_token=api_token),
        )
    if profile.platform == "macos":
        return (
            _artifact_filename(profile, extension="sh"),
            "text/x-shellscript; charset=utf-8",
            _render_macos_bootstrap(profile, api_token=api_token),
        )
    raise ValueError(f"unsupported installer profile platform: {profile.platform}")



def _artifact_filename(profile: InstallerProfile, *, extension: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", profile.name.lower()).strip("-") or "profile"
    return f"sha-{profile.platform}-{slug}-{profile.id}.{extension}"



def _profile_config(
    profile: InstallerProfile,
    *,
    agent_version: str,
    platform_profile: str,
    api_token: str | None,
    capabilities: list[str],
    execution_hooks: dict[str, bool],
) -> str:
    payload = {
        "profile_id": profile.id,
        "profile_name": profile.name,
        "platform": profile.platform,
        "channel": profile.channel,
        "control_plane_url": profile.control_plane_url,
        "policy_mode": profile.policy_mode,
        "tenant_id": profile.tenant_id,
        "site_id": profile.site_id,
        "agent_version": agent_version,
        "platform_profile": platform_profile,
        "api_token": api_token,
        "capabilities": capabilities,
        "execution_hooks": execution_hooks,
    }
    return json.dumps(payload, indent=2)



def _linux_reporter_script() -> str:
    return dedent(
        """
        #!/usr/bin/env python3
        from __future__ import annotations

        from collections import Counter
        import datetime as dt
        import glob
        import hashlib
        import json
        import os
        import platform
        import socket
        import subprocess
        import sys
        from pathlib import Path
        from urllib import error, request

        CONFIG_PATH = Path("/etc/sha/reporter-config.json")
        SSH_HARDENING_PATH = Path(
            os.environ.get("SHA_SSH_HARDENING_PATH", "/etc/ssh/sshd_config.d/99-sha-hardening.conf")
        )


        def utc_now() -> str:
            return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


        def load_config() -> dict[str, object]:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


        def add_auth_header(http_request: request.Request) -> None:
            config = load_config()
            api_token = config.get("api_token")
            if api_token:
                http_request.add_header("Authorization", f"Bearer {api_token}")


        def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            http_request = request.Request(url, data=body, method="POST")
            http_request.add_header("Accept", "application/json")
            http_request.add_header("Content-Type", "application/json")
            add_auth_header(http_request)
            with request.urlopen(http_request, timeout=20) as response:
                return json.load(response)


        def get_json(url: str) -> dict[str, object]:
            http_request = request.Request(url, method="GET")
            http_request.add_header("Accept", "application/json")
            add_auth_header(http_request)
            with request.urlopen(http_request, timeout=20) as response:
                return json.load(response)


        def run_command(*args: str) -> tuple[bool, str]:
            try:
                completed = subprocess.run(
                    list(args),
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=10,
                )
            except FileNotFoundError:
                return False, "command missing"
            output = (completed.stdout + completed.stderr).strip()
            return completed.returncode == 0, output


        def read_machine_id() -> str:
            for candidate in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
                if candidate.exists():
                    value = candidate.read_text(encoding="utf-8", errors="ignore").strip()
                    if value:
                        return value
            hostname = socket.gethostname().strip().lower()
            return hostname or "unknown-host"


        def fingerprint_for_profile(profile_id: str) -> str:
            seed = f"linux|{profile_id}|{read_machine_id()}"
            return hashlib.sha256(seed.encode("utf-8")).hexdigest()


        def platform_version() -> str:
            os_release = Path("/etc/os-release")
            if os_release.exists():
                values: dict[str, str] = {}
                for line in os_release.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if not line or line.lstrip().startswith("#") or "=" not in line:
                        continue
                    key, raw = line.split("=", 1)
                    values[key.strip()] = raw.strip().strip('"')
                pretty_name = values.get("PRETTY_NAME")
                if pretty_name:
                    return pretty_name
            return platform.platform()


        def linux_hardware_summary_result() -> dict[str, object]:
            memory_mb = "unknown"
            meminfo = Path("/proc/meminfo")
            if meminfo.exists():
                for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            memory_mb = str(int(parts[1]) // 1024)
                        break
            cpu_count = os.cpu_count()
            current = f"arch={platform.machine() or 'unknown'}; cpus={cpu_count or 'unknown'}; mem_mb={memory_mb}"
            return {
                "control_key": "linux.telemetry.hardware-summary",
                "status": "pass",
                "current_value": current,
                "recommended_value": "hardware inventory collected",
                "severity": None,
                "evidence_summary": "Collected bounded CPU, architecture, and memory inventory for incident response context.",
                "reboot_required": False,
            }


        def linux_firewall_result() -> dict[str, object]:
            active_units = []
            for unit in ("ufw", "firewalld", "nftables"):
                active, _ = run_command("systemctl", "is-active", "--quiet", unit)
                if active:
                    active_units.append(unit)
            if active_units:
                current = ",".join(active_units)
                return {
                    "control_key": "linux.firewall.service-active",
                    "status": "pass",
                    "current_value": current,
                    "recommended_value": "ufw|firewalld|nftables active",
                    "severity": None,
                    "evidence_summary": f"Detected active firewall service(s): {current}.",
                    "reboot_required": False,
                }
            return {
                "control_key": "linux.firewall.service-active",
                "status": "warn",
                "current_value": "inactive",
                "recommended_value": "ufw|firewalld|nftables active",
                "severity": "medium",
                "evidence_summary": "No active ufw, firewalld, or nftables service was detected.",
                "reboot_required": False,
            }


        def linux_ssh_password_authentication_result() -> dict[str, object]:
            config_paths = [Path("/etc/ssh/sshd_config")]
            config_paths.extend(Path(path) for path in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")))
            existing_paths = [path for path in config_paths if path.exists()]
            if not existing_paths:
                return {
                    "control_key": "linux.ssh.password-authentication-disabled",
                    "status": "not_applicable",
                    "current_value": "sshd config missing",
                    "recommended_value": "no",
                    "severity": None,
                    "evidence_summary": "OpenSSH server configuration was not found.",
                    "reboot_required": False,
                }

            matches: list[tuple[str, str]] = []
            for path in existing_paths:
                for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    stripped = raw_line.split("#", 1)[0].strip()
                    if not stripped:
                        continue
                    parts = stripped.split()
                    if len(parts) >= 2 and parts[0].lower() == "passwordauthentication":
                        matches.append((str(path), parts[1].lower()))

            if not matches:
                return {
                    "control_key": "linux.ssh.password-authentication-disabled",
                    "status": "warn",
                    "current_value": "implicit-default",
                    "recommended_value": "no",
                    "severity": "medium",
                    "evidence_summary": "No explicit PasswordAuthentication directive was found in sshd configuration.",
                    "reboot_required": False,
                }

            source_path, value = matches[-1]
            status = "pass" if value == "no" else "fail" if value == "yes" else "warn"
            severity = None if status == "pass" else "high" if status == "fail" else "medium"
            return {
                "control_key": "linux.ssh.password-authentication-disabled",
                "status": status,
                "current_value": value,
                "recommended_value": "no",
                "severity": severity,
                "evidence_summary": f"Last PasswordAuthentication directive came from {source_path}.",
                "reboot_required": False,
            }


        def linux_root_password_locked_result() -> dict[str, object]:
            ok, output = run_command("passwd", "-S", "root")
            if not ok and output == "command missing":
                return {
                    "control_key": "linux.root.password-locked",
                    "status": "not_applicable",
                    "current_value": "passwd missing",
                    "recommended_value": "locked",
                    "severity": None,
                    "evidence_summary": "passwd command is unavailable on this system.",
                    "reboot_required": False,
                }
            fields = output.split()
            state = fields[1] if len(fields) > 1 else "unknown"
            if state.startswith("L"):
                status = "pass"
                severity = None
            elif state == "P":
                status = "fail"
                severity = "high"
            else:
                status = "warn"
                severity = "medium"
            return {
                "control_key": "linux.root.password-locked",
                "status": status,
                "current_value": state,
                "recommended_value": "locked",
                "severity": severity,
                "evidence_summary": f"passwd -S root reported state {state}.",
                "reboot_required": False,
            }


        def linux_automatic_updates_result() -> dict[str, object]:
            enabled_units = []
            for unit in (
                "apt-daily.timer",
                "apt-daily-upgrade.timer",
                "dnf-automatic.timer",
                "unattended-upgrades.service",
            ):
                enabled, _ = run_command("systemctl", "is-enabled", "--quiet", unit)
                if enabled:
                    enabled_units.append(unit)
            if enabled_units:
                current = ",".join(enabled_units)
                return {
                    "control_key": "linux.updates.automatic-enabled",
                    "status": "pass",
                    "current_value": current,
                    "recommended_value": "automatic updates enabled",
                    "severity": None,
                    "evidence_summary": f"Detected enabled automatic update unit(s): {current}.",
                    "reboot_required": False,
                }
            return {
                "control_key": "linux.updates.automatic-enabled",
                "status": "warn",
                "current_value": "disabled",
                "recommended_value": "automatic updates enabled",
                "severity": "medium",
                "evidence_summary": "No supported automatic update unit is enabled.",
                "reboot_required": False,
            }


        def linux_security_logging_result() -> dict[str, object]:
            auditd_active, _ = run_command("systemctl", "is-active", "--quiet", "auditd")
            journald_persistent = Path("/var/log/journal").exists()
            current = f"auditd={'active' if auditd_active else 'inactive'}; journald_persistent={journald_persistent}"
            status = "pass" if auditd_active or journald_persistent else "warn"
            return {
                "control_key": "linux.telemetry.security-logging",
                "status": status,
                "current_value": current,
                "recommended_value": "auditd active or persistent journald storage",
                "severity": None if status == "pass" else "medium",
                "evidence_summary": "Checked local audit/log retention signals needed for post-incident evidence.",
                "reboot_required": False,
            }


        def linux_process_inventory_result() -> dict[str, object]:
            proc = Path("/proc")
            if not proc.exists():
                return {
                    "control_key": "linux.telemetry.process-inventory",
                    "status": "not_applicable",
                    "current_value": "procfs missing",
                    "recommended_value": "bounded process inventory collected",
                    "severity": None,
                    "evidence_summary": "Process inventory is unavailable because /proc is missing.",
                    "reboot_required": False,
                }

            names: list[str] = []
            for entry in proc.iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    name = (entry / "comm").read_text(encoding="utf-8", errors="ignore").strip()
                except OSError:
                    continue
                if name:
                    names.append(name[:64])

            if not names:
                return {
                    "control_key": "linux.telemetry.process-inventory",
                    "status": "warn",
                    "current_value": "no readable processes",
                    "recommended_value": "bounded process inventory collected",
                    "severity": "medium",
                    "evidence_summary": "No process names could be read from /proc.",
                    "reboot_required": False,
                }

            top_names = ", ".join(f"{name}:{count}" for name, count in Counter(names).most_common(8))
            return {
                "control_key": "linux.telemetry.process-inventory",
                "status": "pass",
                "current_value": f"processes={len(names)}; top={top_names}",
                "recommended_value": "bounded process inventory collected",
                "severity": None,
                "evidence_summary": "Collected process count and top process names without command execution.",
                "reboot_required": False,
            }


        def linux_package_inventory_result() -> dict[str, object]:
            package_names: list[str] = []
            dpkg_status = Path("/var/lib/dpkg/status")
            if dpkg_status.exists():
                for line in dpkg_status.read_text(encoding="utf-8", errors="ignore").splitlines():
                    if line.startswith("Package: "):
                        package_names.append(line.split(": ", 1)[1][:80])
            else:
                for command in (("rpm", "-qa"), ("apk", "info")):
                    ok, output = run_command(*command)
                    if ok and output:
                        package_names = [line.strip()[:80] for line in output.splitlines() if line.strip()]
                        break
                    if output != "command missing":
                        break

            if not package_names:
                return {
                    "control_key": "linux.telemetry.package-inventory",
                    "status": "warn",
                    "current_value": "no package inventory source readable",
                    "recommended_value": "bounded package inventory collected",
                    "severity": "medium",
                    "evidence_summary": "No dpkg, rpm, or apk package inventory could be collected.",
                    "reboot_required": False,
                }

            sample = ",".join(sorted(package_names)[:40])
            return {
                "control_key": "linux.telemetry.package-inventory",
                "status": "pass",
                "current_value": f"packages={len(package_names)}; sample={sample}",
                "recommended_value": "bounded package inventory collected",
                "severity": None,
                "evidence_summary": "Collected installed package names for vulnerability and incident-response triage.",
                "reboot_required": False,
            }


        def linux_startup_services_result() -> dict[str, object]:
            ok, output = run_command(
                "systemctl",
                "list-unit-files",
                "--type=service",
                "--state=enabled",
                "--no-legend",
                "--no-pager",
            )
            if not ok and output == "command missing":
                return {
                    "control_key": "linux.telemetry.startup-services",
                    "status": "not_applicable",
                    "current_value": "systemctl missing",
                    "recommended_value": "bounded startup service inventory collected",
                    "severity": None,
                    "evidence_summary": "Startup service inventory is unavailable because systemctl is missing.",
                    "reboot_required": False,
                }

            services = [line.split()[0][:120] for line in output.splitlines() if line.strip() and not line.startswith("UNIT FILE")]
            if not services:
                return {
                    "control_key": "linux.telemetry.startup-services",
                    "status": "warn",
                    "current_value": "no enabled services observed",
                    "recommended_value": "bounded startup service inventory collected",
                    "severity": "medium",
                    "evidence_summary": "No enabled systemd service inventory could be collected.",
                    "reboot_required": False,
                }

            sample = ",".join(sorted(services)[:40])
            return {
                "control_key": "linux.telemetry.startup-services",
                "status": "pass",
                "current_value": f"enabled_services={len(services)}; sample={sample}",
                "recommended_value": "bounded startup service inventory collected",
                "severity": None,
                "evidence_summary": "Collected enabled systemd services to help identify persistence mechanisms.",
                "reboot_required": False,
            }


        def linux_login_sessions_result() -> dict[str, object]:
            ok, output = run_command("who", "-u")
            if not ok and output == "command missing":
                return {
                    "control_key": "linux.telemetry.login-sessions",
                    "status": "not_applicable",
                    "current_value": "who missing",
                    "recommended_value": "bounded login session inventory collected",
                    "severity": None,
                    "evidence_summary": "Login session inventory is unavailable because who is missing.",
                    "reboot_required": False,
                }

            sessions = [line for line in output.splitlines() if line.strip()]
            users = sorted({line.split()[0][:64] for line in sessions if line.split()})
            return {
                "control_key": "linux.telemetry.login-sessions",
                "status": "pass" if ok else "warn",
                "current_value": f"sessions={len(sessions)}; users={','.join(users[:20]) if users else 'none'}",
                "recommended_value": "bounded login session inventory collected",
                "severity": None if ok else "medium",
                "evidence_summary": "Collected active login-session count and bounded user list for volatile incident evidence.",
                "reboot_required": False,
            }


        def proc_net_listeners(path: Path, protocol: str) -> list[str]:
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
            except OSError:
                return []

            listeners: set[str] = set()
            for line in lines:
                parts = line.split()
                if len(parts) < 4:
                    continue
                state = parts[3].upper()
                if protocol.startswith("tcp") and state != "0A":
                    continue
                if protocol.startswith("udp") and state not in {"07", "0A"}:
                    continue
                try:
                    port = int(parts[1].rsplit(":", 1)[1], 16)
                except (IndexError, ValueError):
                    continue
                if port:
                    listeners.add(f"{protocol}/{port}")
            return sorted(listeners, key=lambda item: (item.split("/", 1)[0], int(item.rsplit("/", 1)[1])))


        def linux_network_listeners_result() -> dict[str, object]:
            listeners = (
                proc_net_listeners(Path("/proc/net/tcp"), "tcp4")
                + proc_net_listeners(Path("/proc/net/tcp6"), "tcp6")
                + proc_net_listeners(Path("/proc/net/udp"), "udp4")
                + proc_net_listeners(Path("/proc/net/udp6"), "udp6")
            )
            if not listeners and not Path("/proc/net").exists():
                return {
                    "control_key": "linux.telemetry.network-listeners",
                    "status": "not_applicable",
                    "current_value": "proc net missing",
                    "recommended_value": "bounded listener inventory collected",
                    "severity": None,
                    "evidence_summary": "Network listener inventory is unavailable because /proc/net is missing.",
                    "reboot_required": False,
                }

            sample = ",".join(listeners[:50]) if listeners else "none observed"
            return {
                "control_key": "linux.telemetry.network-listeners",
                "status": "pass",
                "current_value": f"listeners={len(listeners)}; sample={sample}",
                "recommended_value": "bounded listener inventory collected",
                "severity": None,
                "evidence_summary": "Collected listening TCP/UDP ports from procfs for containment triage.",
                "reboot_required": False,
            }


        def collect_results() -> list[dict[str, object]]:
            return [
                linux_hardware_summary_result(),
                linux_firewall_result(),
                linux_ssh_password_authentication_result(),
                linux_root_password_locked_result(),
                linux_automatic_updates_result(),
                linux_security_logging_result(),
                linux_process_inventory_result(),
                linux_package_inventory_result(),
                linux_startup_services_result(),
                linux_login_sessions_result(),
                linux_network_listeners_result(),
            ]


        def reload_ssh_service() -> tuple[bool, str]:
            for unit in ("sshd", "ssh"):
                ok, output = run_command("systemctl", "reload", unit)
                if ok:
                    return True, f"reloaded {unit}"
                if output == "command missing":
                    return True, "systemctl missing; restart manually"
            return False, "failed to reload sshd or ssh"


        def apply_linux_ssh_password_authentication_disabled() -> tuple[str, str]:
            path = SSH_HARDENING_PATH
            if not path.parent.exists():
                return "failed", f"SSH configuration directory does not exist: {path.parent}"
            backup_path = path.with_name(f"{path.name}.rollback")
            original = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else None
            if original is not None and not backup_path.exists():
                backup_path.write_text(original, encoding="utf-8")
                backup_path.chmod(0o600)
            path.write_text("# Managed by SHA. Remove or rollback through SHA.\\nPasswordAuthentication no\\n", encoding="utf-8")
            path.chmod(0o644)
            ok, output = run_command("sshd", "-t")
            if not ok and output != "command missing":
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(original, encoding="utf-8")
                return "failed", f"sshd validation failed; restored previous config: {output[:2000]}"
            reload_ok, reload_summary = reload_ssh_service()
            if not reload_ok:
                return "failed", reload_summary
            return "succeeded", f"Set PasswordAuthentication no in {path}; {reload_summary}."


        def rollback_linux_ssh_password_authentication_disabled() -> tuple[str, str]:
            path = SSH_HARDENING_PATH
            backup_path = path.with_name(f"{path.name}.rollback")
            if backup_path.exists():
                path.write_text(backup_path.read_text(encoding="utf-8", errors="ignore"), encoding="utf-8")
                backup_path.unlink()
                action = f"restored {backup_path}"
            elif path.exists() and "Managed by SHA" in path.read_text(encoding="utf-8", errors="ignore"):
                path.unlink()
                action = f"removed {path}"
            else:
                return "failed", "No SHA-managed SSH hardening artifact or rollback backup found."
            reload_ok, reload_summary = reload_ssh_service()
            if not reload_ok:
                return "failed", f"{action}; {reload_summary}"
            return "succeeded", f"{action}; {reload_summary}."


        def execute_hardening_action(action_name: str, control_id: str | None) -> tuple[str, str]:
            if control_id != "linux.ssh.password-authentication-disabled":
                return "failed", f"Unsupported Linux hardening control: {control_id or 'missing'}."
            if action_name == "apply_control":
                return apply_linux_ssh_password_authentication_disabled()
            if action_name == "rollback_control":
                return rollback_linux_ssh_password_authentication_disabled()
            return "failed", f"Unsupported Linux hardening action: {action_name}."


        def context_result_for_scope(scope: str | None) -> dict[str, object]:
            if scope == "process_inventory":
                return linux_process_inventory_result()
            if scope == "network_bindings":
                return linux_network_listeners_result()
            if scope == "security_logs":
                return linux_security_logging_result()
            if scope == "firewall_state":
                return linux_firewall_result()
            if scope == "identity_state":
                return linux_root_password_locked_result()
            if scope == "service_status":
                ok, output = run_command("systemctl", "is-system-running")
                state = output.splitlines()[0] if output else "unknown"
                return {
                    "control_key": "linux.telemetry.service-status",
                    "status": "pass" if ok else "warn",
                    "current_value": state,
                    "recommended_value": "systemd reports running or degraded state",
                    "severity": None if ok else "medium",
                    "evidence_summary": "Collected bounded system service-manager status for incident response triage.",
                    "reboot_required": False,
                }
            return {
                "control_key": "linux.telemetry.unsupported-scope",
                "status": "error",
                "current_value": scope or "missing",
                "recommended_value": "supported troubleshooting scope",
                "severity": "medium",
                "evidence_summary": "Unsupported troubleshooting scope requested.",
                "reboot_required": False,
            }


        def summarize_results(results: list[dict[str, object]]) -> str:
            return "; ".join(
                f"{result['control_key']}={result['status']}: {result['evidence_summary']}"
                for result in results
            )[:4000]


        def execute_response_action(control_plane_url: str, action: dict[str, object]) -> None:
            action_id = str(action["response_action_id"])
            action_name = str(action["action"])
            scope = action.get("troubleshooting_scope")
            control_id = action.get("control_id")
            if action_name in {"collect_security_context", "inspect_control", "request_elevated_troubleshooting"}:
                results = [context_result_for_scope(str(scope) if scope is not None else None)]
            elif action_name == "collect_remediation_evidence":
                results = collect_results()
            elif action_name in {"apply_control", "rollback_control"}:
                result_status, result_summary = execute_hardening_action(
                    action_name,
                    str(control_id) if control_id is not None else None,
                )
                post_json(
                    f"{control_plane_url}/api/response-actions/{action_id}/result",
                    {
                        "status": result_status,
                        "result_summary": result_summary,
                    },
                )
                return
            else:
                post_json(
                    f"{control_plane_url}/api/response-actions/{action_id}/result",
                    {
                        "status": "failed",
                        "result_summary": f"Unsupported Linux bootstrap action: {action_name}.",
                    },
                )
                return

            post_json(
                f"{control_plane_url}/api/response-actions/{action_id}/result",
                {
                    "status": "failed" if any(result["status"] == "error" for result in results) else "succeeded",
                    "result_summary": summarize_results(results),
                },
            )


        def execute_pending_response_actions(control_plane_url: str, endpoint_id: str) -> None:
            payload = get_json(f"{control_plane_url}/api/endpoints/{endpoint_id}/response-actions")
            items = payload.get("items", [])
            if not isinstance(items, list):
                return
            for action in items:
                if isinstance(action, dict):
                    execute_response_action(control_plane_url, action)


        def main() -> None:
            config = load_config()
            control_plane_url = str(config["control_plane_url"]).rstrip("/")
            current_platform_version = platform_version()
            enroll_response = post_json(
                f"{control_plane_url}/api/endpoints/enroll",
                {
                    "agent_fingerprint": fingerprint_for_profile(str(config["profile_id"])),
                    "hostname": socket.gethostname().strip() or "unknown-host",
                    "platform": "linux",
                    "platform_version": current_platform_version,
                    "agent_version": config["agent_version"],
                    "tenant_id": config.get("tenant_id"),
                    "site_id": config.get("site_id"),
                },
            )
            endpoint_id = str(enroll_response["endpoint_id"])
            post_json(
                f"{control_plane_url}/api/endpoints/{endpoint_id}/heartbeat",
                {
                    "agent_version": config["agent_version"],
                    "platform_version": current_platform_version,
                    "platform_profile": config["platform_profile"],
                    "connectivity_status": "online",
                    "declared_capabilities": config["capabilities"],
                    "execution_hooks": config["execution_hooks"],
                },
            )
            post_json(
                f"{control_plane_url}/api/posture-snapshots",
                {
                    "endpoint_id": endpoint_id,
                    "observed_at": utc_now(),
                    "platform_profile": config["platform_profile"],
                    "results": collect_results(),
                },
            )
            execute_pending_response_actions(control_plane_url, endpoint_id)


        if __name__ == "__main__":
            try:
                main()
            except error.HTTPError as exc:
                sys.stderr.write(f"sha reporter HTTP error: {exc.code} {exc.reason}\\n")
                sys.exit(1)
            except Exception as exc:  # pragma: no cover - bootstrap script runtime safety
                sys.stderr.write(f"sha reporter failed: {exc}\\n")
                sys.exit(1)
        """
    ).strip() + "\n"



def _render_linux_bootstrap(profile: InstallerProfile, *, api_token: str | None = None) -> str:
    config_json = _profile_config(
        profile,
        agent_version=_LINUX_AGENT_VERSION,
        platform_profile=_LINUX_PLATFORM_PROFILE,
        api_token=api_token,
        capabilities=_LINUX_REPORTER_CAPABILITIES,
        execution_hooks=_LINUX_EXECUTION_HOOKS,
    )
    reporter_script = _linux_reporter_script().rstrip("\n")
    service_unit = dedent(
        """
        [Unit]
        Description=SHA posture reporter
        Wants=network-online.target
        After=network-online.target

        [Service]
        Type=oneshot
        ExecStart=/usr/bin/env python3 /opt/sha/reporter.py

        [Install]
        WantedBy=multi-user.target
        """
    ).strip()
    timer_unit = dedent(
        """
        [Unit]
        Description=Run SHA posture reporter every 15 minutes

        [Timer]
        OnBootSec=1min
        OnUnitActiveSec=15min
        Persistent=true
        Unit=sha-reporter.service

        [Install]
        WantedBy=timers.target
        """
    ).strip()
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            'if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then',
            '  echo "sha bootstrap requires root" >&2',
            "  exit 1",
            "fi",
            "",
            "if ! command -v systemctl >/dev/null 2>&1; then",
            '  echo "sha bootstrap requires systemd/systemctl" >&2',
            "  exit 1",
            "fi",
            "",
            "if ! command -v python3 >/dev/null 2>&1; then",
            '  echo "sha bootstrap requires python3" >&2',
            "  exit 1",
            "fi",
            "",
            "install -d -m 0755 /opt/sha /etc/sha",
            "",
            "cat > /etc/sha/reporter-config.json <<'JSON'",
            config_json,
            "JSON",
            "",
            "cat > /opt/sha/reporter.py <<'PY'",
            reporter_script,
            "PY",
            "chmod 0755 /opt/sha/reporter.py",
            "",
            "cat > /etc/systemd/system/sha-reporter.service <<'UNIT'",
            service_unit,
            "UNIT",
            "",
            "cat > /etc/systemd/system/sha-reporter.timer <<'UNIT'",
            timer_unit,
            "UNIT",
            "",
            "systemctl daemon-reload",
            "systemctl enable --now sha-reporter.timer",
            "systemctl start sha-reporter.service",
            "",
            f'echo "SHA bootstrap installed for profile {profile.id}"',
            "",
        ]
    )


def _macos_reporter_script() -> str:
    return dedent(
        """
        #!/usr/bin/env python3
        from __future__ import annotations

        from collections import Counter
        import datetime as dt
        import hashlib
        import json
        import os
        import platform
        import socket
        import subprocess
        import sys
        from pathlib import Path
        from urllib import error, request

        CONFIG_PATH = Path("/Library/Application Support/SHA/reporter-config.json")


        def utc_now() -> str:
            return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


        def load_config() -> dict[str, object]:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


        def add_auth_header(http_request: request.Request) -> None:
            config = load_config()
            api_token = config.get("api_token")
            if api_token:
                http_request.add_header("Authorization", f"Bearer {api_token}")


        def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            http_request = request.Request(url, data=body, method="POST")
            http_request.add_header("Accept", "application/json")
            http_request.add_header("Content-Type", "application/json")
            add_auth_header(http_request)
            with request.urlopen(http_request, timeout=20) as response:
                return json.load(response)


        def get_json(url: str) -> dict[str, object]:
            http_request = request.Request(url, method="GET")
            http_request.add_header("Accept", "application/json")
            add_auth_header(http_request)
            with request.urlopen(http_request, timeout=20) as response:
                return json.load(response)


        def run_command(*args: str) -> tuple[bool, str]:
            try:
                completed = subprocess.run(
                    list(args),
                    capture_output=True,
                    check=False,
                    text=True,
                    timeout=10,
                )
            except FileNotFoundError:
                return False, "command missing"
            output = (completed.stdout + completed.stderr).strip()
            return completed.returncode == 0, output


        def read_machine_id() -> str:
            ok, output = run_command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
            if ok:
                for line in output.splitlines():
                    if "IOPlatformUUID" in line and "=" in line:
                        value = line.split("=", 1)[1].strip().strip('"')
                        if value:
                            return value
            hostname = socket.gethostname().strip().lower()
            return hostname or "unknown-host"


        def fingerprint_for_profile(profile_id: str) -> str:
            seed = f"macos|{profile_id}|{read_machine_id()}"
            return hashlib.sha256(seed.encode("utf-8")).hexdigest()


        def platform_version() -> str:
            version, _, machine = platform.mac_ver()
            return f"macOS {version or platform.platform()} {machine or platform.machine()}".strip()


        def sysctl_value(name: str) -> str:
            ok, output = run_command("sysctl", "-n", name)
            if ok and output:
                return output.splitlines()[0].strip()
            return "unknown"


        def macos_hardware_summary_result() -> dict[str, object]:
            memory_bytes = sysctl_value("hw.memsize")
            memory_mb = str(int(memory_bytes) // 1024 // 1024) if memory_bytes.isdigit() else "unknown"
            cpu_count = sysctl_value("hw.ncpu")
            current = f"arch={platform.machine() or 'unknown'}; cpus={cpu_count}; mem_mb={memory_mb}"
            return {
                "control_key": "macos.telemetry.hardware-summary",
                "status": "pass",
                "current_value": current,
                "recommended_value": "hardware inventory collected",
                "severity": None,
                "evidence_summary": "Collected bounded CPU, architecture, and memory inventory for incident response context.",
                "reboot_required": False,
            }


        def macos_firewall_result() -> dict[str, object]:
            ok, output = run_command("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
            if not ok and output == "command missing":
                return {
                    "control_key": "macos.firewall.application-firewall-enabled",
                    "status": "not_applicable",
                    "current_value": "socketfilterfw missing",
                    "recommended_value": "enabled",
                    "severity": None,
                    "evidence_summary": "macOS Application Firewall utility was not found.",
                    "reboot_required": False,
                }
            normalized = output.lower()
            enabled = "enabled" in normalized and "disabled" not in normalized
            return {
                "control_key": "macos.firewall.application-firewall-enabled",
                "status": "pass" if enabled else "warn",
                "current_value": "enabled" if enabled else "disabled",
                "recommended_value": "enabled",
                "severity": None if enabled else "medium",
                "evidence_summary": f"socketfilterfw reported: {output[:200] or 'unknown'}.",
                "reboot_required": False,
            }


        def macos_filevault_result() -> dict[str, object]:
            ok, output = run_command("fdesetup", "status")
            if not ok and output == "command missing":
                return {
                    "control_key": "macos.disk.filevault-enabled",
                    "status": "not_applicable",
                    "current_value": "fdesetup missing",
                    "recommended_value": "on",
                    "severity": None,
                    "evidence_summary": "FileVault status utility was not found.",
                    "reboot_required": False,
                }
            enabled = "filevault is on" in output.lower()
            return {
                "control_key": "macos.disk.filevault-enabled",
                "status": "pass" if enabled else "fail",
                "current_value": "on" if enabled else "off",
                "recommended_value": "on",
                "severity": None if enabled else "high",
                "evidence_summary": f"fdesetup reported: {output[:200] or 'unknown'}.",
                "reboot_required": False,
            }


        def macos_gatekeeper_result() -> dict[str, object]:
            ok, output = run_command("spctl", "--status")
            if not ok and output == "command missing":
                return {
                    "control_key": "macos.gatekeeper.assessments-enabled",
                    "status": "not_applicable",
                    "current_value": "spctl missing",
                    "recommended_value": "assessments enabled",
                    "severity": None,
                    "evidence_summary": "Gatekeeper status utility was not found.",
                    "reboot_required": False,
                }
            enabled = "assessments enabled" in output.lower()
            return {
                "control_key": "macos.gatekeeper.assessments-enabled",
                "status": "pass" if enabled else "fail",
                "current_value": "enabled" if enabled else "disabled",
                "recommended_value": "assessments enabled",
                "severity": None if enabled else "high",
                "evidence_summary": f"spctl reported: {output[:200] or 'unknown'}.",
                "reboot_required": False,
            }


        def macos_automatic_updates_result() -> dict[str, object]:
            ok, output = run_command(
                "defaults",
                "read",
                "/Library/Preferences/com.apple.SoftwareUpdate",
                "AutomaticCheckEnabled",
            )
            if not ok and output == "command missing":
                return {
                    "control_key": "macos.updates.automatic-check-enabled",
                    "status": "not_applicable",
                    "current_value": "defaults missing",
                    "recommended_value": "1",
                    "severity": None,
                    "evidence_summary": "macOS defaults utility was not found.",
                    "reboot_required": False,
                }
            value = output.splitlines()[-1].strip() if output else "unknown"
            enabled = value == "1"
            return {
                "control_key": "macos.updates.automatic-check-enabled",
                "status": "pass" if enabled else "warn",
                "current_value": value,
                "recommended_value": "1",
                "severity": None if enabled else "medium",
                "evidence_summary": "Read the AutomaticCheckEnabled Software Update preference.",
                "reboot_required": False,
            }


        def macos_security_logging_result() -> dict[str, object]:
            diagnostics = Path("/var/db/diagnostics")
            exists = diagnostics.exists()
            return {
                "control_key": "macos.telemetry.security-logging",
                "status": "pass" if exists else "warn",
                "current_value": "unified-log-store-present" if exists else "unified-log-store-missing",
                "recommended_value": "unified log diagnostics store present",
                "severity": None if exists else "medium",
                "evidence_summary": "Checked for the local unified log diagnostics store used during incident review.",
                "reboot_required": False,
            }


        def macos_process_inventory_result() -> dict[str, object]:
            ok, output = run_command("ps", "-axo", "comm=")
            if not ok and output == "command missing":
                return {
                    "control_key": "macos.telemetry.process-inventory",
                    "status": "not_applicable",
                    "current_value": "ps missing",
                    "recommended_value": "bounded process inventory collected",
                    "severity": None,
                    "evidence_summary": "Process inventory is unavailable because ps is missing.",
                    "reboot_required": False,
                }
            names = [Path(line.strip()).name[:64] for line in output.splitlines() if line.strip()]
            if not names:
                return {
                    "control_key": "macos.telemetry.process-inventory",
                    "status": "warn",
                    "current_value": "no readable processes",
                    "recommended_value": "bounded process inventory collected",
                    "severity": "medium",
                    "evidence_summary": "No process names could be read from ps output.",
                    "reboot_required": False,
                }
            top_names = ", ".join(f"{name}:{count}" for name, count in Counter(names).most_common(8))
            return {
                "control_key": "macos.telemetry.process-inventory",
                "status": "pass",
                "current_value": f"processes={len(names)}; top={top_names}",
                "recommended_value": "bounded process inventory collected",
                "severity": None,
                "evidence_summary": "Collected process count and top process names for containment triage.",
                "reboot_required": False,
            }


        def macos_network_bindings_result() -> dict[str, object]:
            ok, output = run_command("lsof", "-nP", "-iTCP", "-sTCP:LISTEN")
            if not ok and output == "command missing":
                return {
                    "control_key": "macos.telemetry.network-bindings",
                    "status": "not_applicable",
                    "current_value": "lsof missing",
                    "recommended_value": "bounded listener inventory collected",
                    "severity": None,
                    "evidence_summary": "Network listener inventory is unavailable because lsof is missing.",
                    "reboot_required": False,
                }
            listeners: set[str] = set()
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    listeners.add(parts[8][:80])
            sample = ",".join(sorted(listeners)[:50]) if listeners else "none observed"
            return {
                "control_key": "macos.telemetry.network-bindings",
                "status": "pass" if ok else "warn",
                "current_value": f"listeners={len(listeners)}; sample={sample}",
                "recommended_value": "bounded listener inventory collected",
                "severity": None if ok else "medium",
                "evidence_summary": "Collected listening TCP sockets from lsof for containment triage.",
                "reboot_required": False,
            }


        def macos_identity_state_result() -> dict[str, object]:
            ok, output = run_command("stat", "-f", "%Su", "/dev/console")
            if not ok and output == "command missing":
                return {
                    "control_key": "macos.telemetry.identity-state",
                    "status": "not_applicable",
                    "current_value": "stat missing",
                    "recommended_value": "console user collected",
                    "severity": None,
                    "evidence_summary": "Console-user identity context is unavailable because stat is missing.",
                    "reboot_required": False,
                }
            console_user = output.splitlines()[0].strip() if ok and output else "unknown"
            return {
                "control_key": "macos.telemetry.identity-state",
                "status": "pass" if ok else "warn",
                "current_value": f"console_user={console_user}",
                "recommended_value": "console user collected",
                "severity": None if ok else "medium",
                "evidence_summary": "Collected bounded current console-user context for incident triage.",
                "reboot_required": False,
            }


        def macos_service_status_result() -> dict[str, object]:
            ok, output = run_command("launchctl", "print", "system/com.sha.reporter")
            return {
                "control_key": "macos.telemetry.service-status",
                "status": "pass" if ok else "warn",
                "current_value": "launchd job loaded" if ok else "launchd job not loaded",
                "recommended_value": "launchd reporter job loaded",
                "severity": None if ok else "medium",
                "evidence_summary": f"launchctl reporter status: {output[:200] or 'unknown'}.",
                "reboot_required": False,
            }


        def collect_results() -> list[dict[str, object]]:
            return [
                macos_hardware_summary_result(),
                macos_firewall_result(),
                macos_filevault_result(),
                macos_gatekeeper_result(),
                macos_automatic_updates_result(),
                macos_security_logging_result(),
                macos_process_inventory_result(),
                macos_network_bindings_result(),
            ]


        def context_result_for_scope(scope: str | None) -> dict[str, object]:
            if scope == "process_inventory":
                return macos_process_inventory_result()
            if scope == "network_bindings":
                return macos_network_bindings_result()
            if scope == "security_logs":
                return macos_security_logging_result()
            if scope == "firewall_state":
                return macos_firewall_result()
            if scope == "identity_state":
                return macos_identity_state_result()
            if scope == "service_status":
                return macos_service_status_result()
            return {
                "control_key": "macos.telemetry.unsupported-scope",
                "status": "error",
                "current_value": scope or "missing",
                "recommended_value": "supported troubleshooting scope",
                "severity": "medium",
                "evidence_summary": "Unsupported troubleshooting scope requested.",
                "reboot_required": False,
            }


        def summarize_results(results: list[dict[str, object]]) -> str:
            return "; ".join(
                f"{result['control_key']}={result['status']}: {result['evidence_summary']}"
                for result in results
            )[:4000]


        def execute_response_action(control_plane_url: str, action: dict[str, object]) -> None:
            action_id = str(action["response_action_id"])
            action_name = str(action["action"])
            scope = action.get("troubleshooting_scope")
            if action_name in {"collect_security_context", "inspect_control", "request_elevated_troubleshooting"}:
                results = [context_result_for_scope(str(scope) if scope is not None else None)]
            elif action_name == "collect_remediation_evidence":
                results = collect_results()
            elif action_name in {"apply_control", "rollback_control"}:
                post_json(
                    f"{control_plane_url}/api/response-actions/{action_id}/result",
                    {
                        "status": "failed",
                        "result_summary": "macOS bootstrap is observe-only and cannot execute hardening changes.",
                    },
                )
                return
            else:
                post_json(
                    f"{control_plane_url}/api/response-actions/{action_id}/result",
                    {
                        "status": "failed",
                        "result_summary": f"Unsupported macOS bootstrap action: {action_name}.",
                    },
                )
                return

            post_json(
                f"{control_plane_url}/api/response-actions/{action_id}/result",
                {
                    "status": "failed" if any(result["status"] == "error" for result in results) else "succeeded",
                    "result_summary": summarize_results(results),
                },
            )


        def execute_pending_response_actions(control_plane_url: str, endpoint_id: str) -> None:
            payload = get_json(f"{control_plane_url}/api/endpoints/{endpoint_id}/response-actions")
            items = payload.get("items", [])
            if not isinstance(items, list):
                return
            for action in items:
                if isinstance(action, dict):
                    execute_response_action(control_plane_url, action)


        def main() -> None:
            config = load_config()
            control_plane_url = str(config["control_plane_url"]).rstrip("/")
            current_platform_version = platform_version()
            enroll_response = post_json(
                f"{control_plane_url}/api/endpoints/enroll",
                {
                    "agent_fingerprint": fingerprint_for_profile(str(config["profile_id"])),
                    "hostname": socket.gethostname().strip() or "unknown-host",
                    "platform": "macos",
                    "platform_version": current_platform_version,
                    "agent_version": config["agent_version"],
                    "tenant_id": config.get("tenant_id"),
                    "site_id": config.get("site_id"),
                },
            )
            endpoint_id = str(enroll_response["endpoint_id"])
            post_json(
                f"{control_plane_url}/api/endpoints/{endpoint_id}/heartbeat",
                {
                    "agent_version": config["agent_version"],
                    "platform_version": current_platform_version,
                    "platform_profile": config["platform_profile"],
                    "connectivity_status": "online",
                    "declared_capabilities": config["capabilities"],
                    "execution_hooks": config["execution_hooks"],
                },
            )
            post_json(
                f"{control_plane_url}/api/posture-snapshots",
                {
                    "endpoint_id": endpoint_id,
                    "observed_at": utc_now(),
                    "platform_profile": config["platform_profile"],
                    "results": collect_results(),
                },
            )
            execute_pending_response_actions(control_plane_url, endpoint_id)


        if __name__ == "__main__":
            try:
                main()
            except error.HTTPError as exc:
                sys.stderr.write(f"sha reporter HTTP error: {exc.code} {exc.reason}\\n")
                sys.exit(1)
            except Exception as exc:  # pragma: no cover - bootstrap script runtime safety
                sys.stderr.write(f"sha reporter failed: {exc}\\n")
                sys.exit(1)
        """
    ).strip() + "\n"


def _render_macos_bootstrap(profile: InstallerProfile, *, api_token: str | None = None) -> str:
    config_json = _profile_config(
        profile,
        agent_version=_MACOS_AGENT_VERSION,
        platform_profile=_MACOS_PLATFORM_PROFILE,
        api_token=api_token,
        capabilities=_MACOS_REPORTER_CAPABILITIES,
        execution_hooks=_MACOS_EXECUTION_HOOKS,
    )
    reporter_script = _macos_reporter_script().rstrip("\n")
    launch_daemon = dedent(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>com.sha.reporter</string>
          <key>ProgramArguments</key>
          <array>
            <string>/usr/bin/env</string>
            <string>python3</string>
            <string>/Library/Application Support/SHA/reporter.py</string>
          </array>
          <key>RunAtLoad</key>
          <true/>
          <key>StartInterval</key>
          <integer>900</integer>
          <key>StandardOutPath</key>
          <string>/Library/Logs/sha-reporter.log</string>
          <key>StandardErrorPath</key>
          <string>/Library/Logs/sha-reporter.err</string>
        </dict>
        </plist>
        """
    ).strip()
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            'if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then',
            '  echo "sha bootstrap requires root" >&2',
            "  exit 1",
            "fi",
            "",
            "if [[ \"$(uname -s)\" != \"Darwin\" ]]; then",
            '  echo "sha macOS bootstrap must run on Darwin/macOS" >&2',
            "  exit 1",
            "fi",
            "",
            "if ! command -v python3 >/dev/null 2>&1; then",
            '  echo "sha bootstrap requires python3" >&2',
            "  exit 1",
            "fi",
            "",
            "SHA_ROOT='/Library/Application Support/SHA'",
            'CONFIG_PATH="${SHA_ROOT}/reporter-config.json"',
            'REPORTER_PATH="${SHA_ROOT}/reporter.py"',
            "PLIST_PATH='/Library/LaunchDaemons/com.sha.reporter.plist'",
            "",
            'install -d -m 0755 "${SHA_ROOT}" /Library/LaunchDaemons /Library/Logs',
            "",
            'cat > "${CONFIG_PATH}" <<\'JSON\'',
            config_json,
            "JSON",
            'chmod 600 "${CONFIG_PATH}"',
            "",
            'cat > "${REPORTER_PATH}" <<\'PY\'',
            reporter_script,
            "PY",
            'chmod 755 "${REPORTER_PATH}"',
            "",
            'cat > "${PLIST_PATH}" <<\'PLIST\'',
            launch_daemon,
            "PLIST",
            'chown root:wheel "${CONFIG_PATH}" "${REPORTER_PATH}" "${PLIST_PATH}"',
            'chmod 644 "${PLIST_PATH}"',
            "",
            'launchctl bootout system/com.sha.reporter >/dev/null 2>&1 || true',
            'launchctl bootstrap system "${PLIST_PATH}"',
            "launchctl enable system/com.sha.reporter",
            "launchctl kickstart -k system/com.sha.reporter",
            "",
            f'echo "SHA bootstrap installed for macOS profile {profile.id}"',
            "",
        ]
    )



def _windows_reporter_script() -> str:
    return dedent(
        r"""
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $ConfigPath = 'C:\ProgramData\SHA\reporter-config.json'
        $FirewallRollbackPath = 'C:\ProgramData\SHA\firewall-profile-rollback.json'

        function Get-Config {
            return Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        }

        function ConvertTo-UtcZulu([datetime]$Value) {
            return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        }

        function Get-Sha256Hex([string]$Text) {
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
                return (($sha256.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
            }
            finally {
                $sha256.Dispose()
            }
        }

        function Invoke-JsonPost([string]$Url, $Body) {
            $json = $Body | ConvertTo-Json -Depth 8 -Compress
            $headers = @{}
            $config = Get-Config
            if ($config.api_token) {
                $headers['Authorization'] = "Bearer $($config.api_token)"
            }
            return Invoke-RestMethod -Method Post -Uri $Url -Body $json -ContentType 'application/json' -Headers $headers
        }

        function Invoke-JsonGet([string]$Url) {
            $headers = @{}
            $config = Get-Config
            if ($config.api_token) {
                $headers['Authorization'] = "Bearer $($config.api_token)"
            }
            return Invoke-RestMethod -Method Get -Uri $Url -ContentType 'application/json' -Headers $headers
        }

        function New-Result(
            [string]$ControlKey,
            [string]$Status,
            [string]$CurrentValue,
            [string]$RecommendedValue,
            [string]$Severity,
            [string]$EvidenceSummary,
            [bool]$RebootRequired
        ) {
            return [ordered]@{
                control_key = $ControlKey
                status = $Status
                current_value = $CurrentValue
                recommended_value = $RecommendedValue
                severity = $Severity
                evidence_summary = $EvidenceSummary
                reboot_required = $RebootRequired
            }
        }

        function Get-WindowsPlatformVersion {
            $currentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $parts = @($currentVersion.ProductName)
            if ($currentVersion.DisplayVersion) {
                $parts += $currentVersion.DisplayVersion
            }
            elseif ($currentVersion.ReleaseId) {
                $parts += $currentVersion.ReleaseId
            }
            return (($parts | Where-Object { $_ }) -join ' ').Trim()
        }

        function Get-ProcessInventoryResult {
            try {
                $processes = @(Get-Process)
            }
            catch {
                return New-Result 'windows.telemetry.process-inventory' 'warn' 'Get-Process failed' 'bounded process inventory collected' 'medium' "Process inventory failed: $($_.Exception.Message)" $false
            }
            $top = (($processes | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Name):$($_.Count)" }) -join ', ')
            return New-Result 'windows.telemetry.process-inventory' 'pass' "processes=$($processes.Count); top=$top" 'bounded process inventory collected' $null 'Collected process count and top process names for incident response context.' $false
        }

        function Get-NetworkBindingsResult {
            if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
                return New-Result 'windows.telemetry.network-bindings' 'not_applicable' 'Get-NetTCPConnection missing' 'bounded TCP listener inventory collected' $null 'TCP listener inspection cmdlet is unavailable.' $false
            }
            try {
                $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
            }
            catch {
                return New-Result 'windows.telemetry.network-bindings' 'warn' 'Get-NetTCPConnection failed' 'bounded TCP listener inventory collected' 'medium' "TCP listener inventory failed: $($_.Exception.Message)" $false
            }
            $sample = (($listeners | Sort-Object LocalPort, OwningProcess | Select-Object -First 50 | ForEach-Object { "tcp/$($_.LocalPort):pid=$($_.OwningProcess)" }) -join ',')
            if (-not $sample) {
                $sample = 'none observed'
            }
            return New-Result 'windows.telemetry.network-bindings' 'pass' "listeners=$($listeners.Count); sample=$sample" 'bounded TCP listener inventory collected' $null 'Collected listening TCP ports for containment triage.' $false
        }

        function Get-SecurityLogResult {
            if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) {
                return New-Result 'windows.telemetry.security-logs' 'not_applicable' 'Get-WinEvent missing' 'recent Security log readable' $null 'Security event inspection cmdlet is unavailable.' $false
            }
            try {
                $events = @(Get-WinEvent -LogName Security -MaxEvents 5 -ErrorAction Stop)
                return New-Result 'windows.telemetry.security-logs' 'pass' "recent_events=$($events.Count)" 'recent Security log readable' $null 'Read recent Windows Security log entries for incident response context.' $false
            }
            catch {
                return New-Result 'windows.telemetry.security-logs' 'warn' 'Security log unreadable' 'recent Security log readable' 'medium' "Security log read failed: $($_.Exception.Message)" $false
            }
        }

        function Get-IdentityStateResult {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            return New-Result 'windows.telemetry.identity-state' 'pass' $identity.Name 'current service identity captured' $null 'Captured current Windows service identity for response attribution.' $false
        }

        function Get-ServiceStatusResult {
            try {
                $services = @(Get-Service)
                $stopped = @($services | Where-Object { $_.Status -ne 'Running' })
                return New-Result 'windows.telemetry.service-status' 'pass' "services=$($services.Count); stopped=$($stopped.Count)" 'bounded service inventory collected' $null 'Collected service running/stopped counts for incident response triage.' $false
            }
            catch {
                return New-Result 'windows.telemetry.service-status' 'warn' 'Get-Service failed' 'bounded service inventory collected' 'medium' "Service inventory failed: $($_.Exception.Message)" $false
            }
        }

        function Get-FirewallResult {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                return New-Result 'windows.firewall.all-profiles-enabled' 'not_applicable' 'Get-NetFirewallProfile missing' 'enabled' $null 'Firewall inspection cmdlet is unavailable.' $false
            }
            $profiles = @(Get-NetFirewallProfile)
            $disabled = @($profiles | Where-Object { -not $_.Enabled })
            if ($disabled.Count -eq 0) {
                return New-Result 'windows.firewall.all-profiles-enabled' 'pass' 'enabled' 'enabled' $null 'Domain, Private, and Public firewall profiles are enabled.' $false
            }
            $names = ($disabled | ForEach-Object { $_.Name }) -join ','
            return New-Result 'windows.firewall.all-profiles-enabled' 'fail' $names 'enabled' 'high' "Firewall disabled on profile(s): $names." $false
        }

        function Invoke-ApplyWindowsFirewallAllProfiles {
            if (-not (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) -or -not (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                return @('failed', 'Windows firewall profile cmdlets are unavailable.')
            }
            $profiles = @(Get-NetFirewallProfile -Name Domain,Private,Public)
            if (-not (Test-Path -LiteralPath $FirewallRollbackPath)) {
                $profiles | Select-Object Name, Enabled | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $FirewallRollbackPath -Encoding UTF8
            }
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
            return @('succeeded', "Enabled Domain, Private, and Public firewall profiles; rollback saved to $FirewallRollbackPath.")
        }

        function Invoke-RollbackWindowsFirewallAllProfiles {
            if (-not (Get-Command Set-NetFirewallProfile -ErrorAction SilentlyContinue)) {
                return @('failed', 'Set-NetFirewallProfile is unavailable.')
            }
            if (-not (Test-Path -LiteralPath $FirewallRollbackPath)) {
                return @('failed', "No SHA firewall rollback artifact found at $FirewallRollbackPath.")
            }
            $profiles = @(Get-Content -LiteralPath $FirewallRollbackPath -Raw | ConvertFrom-Json)
            foreach ($profile in $profiles) {
                Set-NetFirewallProfile -Profile ([string]$profile.Name) -Enabled ([bool]$profile.Enabled)
            }
            Remove-Item -LiteralPath $FirewallRollbackPath -Force
            return @('succeeded', 'Restored Windows firewall profile enabled states from SHA rollback artifact.')
        }

        function Invoke-HardeningAction([string]$ActionName, [string]$ControlId) {
            if ($ControlId -ne 'control.windows.firewall-all-profiles') {
                return @('failed', "Unsupported Windows hardening control: $ControlId.")
            }
            if ($ActionName -eq 'apply_control') {
                return Invoke-ApplyWindowsFirewallAllProfiles
            }
            if ($ActionName -eq 'rollback_control') {
                return Invoke-RollbackWindowsFirewallAllProfiles
            }
            return @('failed', "Unsupported Windows hardening action: $ActionName.")
        }

        function Get-DefenderRealTimeProtectionResult {
            if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
                return New-Result 'windows.defender.real-time-protection' 'not_applicable' 'Get-MpComputerStatus missing' 'enabled' $null 'Microsoft Defender inspection cmdlet is unavailable.' $false
            }
            $status = Get-MpComputerStatus
            if ($status.RealTimeProtectionEnabled) {
                return New-Result 'windows.defender.real-time-protection' 'pass' 'enabled' 'enabled' $null 'Microsoft Defender real-time protection is enabled.' $false
            }
            return New-Result 'windows.defender.real-time-protection' 'fail' 'disabled' 'enabled' 'high' 'Microsoft Defender real-time protection is disabled.' $false
        }

        function Get-BitLockerSystemDriveResult {
            if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
                return New-Result 'windows.bitlocker.system-drive-protected' 'not_applicable' 'Get-BitLockerVolume missing' 'on' $null 'BitLocker inspection cmdlet is unavailable.' $false
            }
            $systemDrive = [System.IO.Path]::GetPathRoot($env:SystemDrive)
            if (-not $systemDrive) {
                $systemDrive = $env:SystemDrive
            }
            $volume = Get-BitLockerVolume -MountPoint $systemDrive
            if ($volume.ProtectionStatus -eq 'On' -or $volume.ProtectionStatus -eq 1) {
                return New-Result 'windows.bitlocker.system-drive-protected' 'pass' 'on' 'on' $null 'BitLocker protection is enabled on the system drive.' $false
            }
            return New-Result 'windows.bitlocker.system-drive-protected' 'fail' 'off' 'on' 'medium' 'BitLocker protection is disabled on the system drive.' $false
        }

        function Get-SecureBootResult {
            if (-not (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)) {
                return New-Result 'windows.secure-boot.enabled' 'not_applicable' 'Confirm-SecureBootUEFI missing' 'enabled' $null 'Secure Boot inspection cmdlet is unavailable.' $false
            }
            try {
                if (Confirm-SecureBootUEFI) {
                    return New-Result 'windows.secure-boot.enabled' 'pass' 'enabled' 'enabled' $null 'Secure Boot is enabled.' $false
                }
                return New-Result 'windows.secure-boot.enabled' 'fail' 'disabled' 'enabled' 'medium' 'Secure Boot is disabled.' $false
            }
            catch {
                return New-Result 'windows.secure-boot.enabled' 'not_applicable' 'unsupported' 'enabled' $null 'Secure Boot inspection is unsupported on this host.' $false
            }
        }

        function Get-ContextResultForScope([string]$Scope) {
            switch ($Scope) {
                'process_inventory' { return Get-ProcessInventoryResult }
                'network_bindings' { return Get-NetworkBindingsResult }
                'security_logs' { return Get-SecurityLogResult }
                'firewall_state' { return Get-FirewallResult }
                'identity_state' { return Get-IdentityStateResult }
                'service_status' { return Get-ServiceStatusResult }
                default { return New-Result 'windows.telemetry.unsupported-scope' 'error' $Scope 'supported troubleshooting scope' 'medium' 'Unsupported troubleshooting scope requested.' $false }
            }
        }

        function ConvertTo-ResultSummary($Results) {
            $summary = (($Results | ForEach-Object { "$($_['control_key'])=$($_['status']): $($_['evidence_summary'])" }) -join '; ')
            if ($summary.Length -gt 4000) {
                return $summary.Substring(0, 4000)
            }
            return $summary
        }

        function Complete-ResponseAction($ControlPlaneUrl, $Action, [string]$Status, [string]$Summary) {
            Invoke-JsonPost "$ControlPlaneUrl/api/response-actions/$($Action.response_action_id)/result" ([ordered]@{
                status = $Status
                result_summary = $Summary
            }) | Out-Null
        }

        function Invoke-ResponseAction($ControlPlaneUrl, $Action) {
            $actionName = [string]$Action.action
            if ($actionName -in @('collect_security_context', 'inspect_control', 'request_elevated_troubleshooting')) {
                $results = @(Get-ContextResultForScope ([string]$Action.troubleshooting_scope))
                $status = if (@($results | Where-Object { $_['status'] -eq 'error' }).Count) { 'failed' } else { 'succeeded' }
                Complete-ResponseAction $ControlPlaneUrl $Action $status (ConvertTo-ResultSummary $results)
                return
            }
            if ($actionName -eq 'collect_remediation_evidence') {
                $results = @(
                    Get-FirewallResult
                    Get-DefenderRealTimeProtectionResult
                    Get-BitLockerSystemDriveResult
                    Get-SecureBootResult
                    Get-ProcessInventoryResult
                    Get-NetworkBindingsResult
                    Get-SecurityLogResult
                )
                Complete-ResponseAction $ControlPlaneUrl $Action 'succeeded' (ConvertTo-ResultSummary $results)
                return
            }
            if ($actionName -in @('apply_control', 'rollback_control')) {
                $outcome = Invoke-HardeningAction $actionName ([string]$Action.control_id)
                Complete-ResponseAction $ControlPlaneUrl $Action ([string]$outcome[0]) ([string]$outcome[1])
                return
            }
            Complete-ResponseAction $ControlPlaneUrl $Action 'failed' "Unsupported Windows bootstrap action: $actionName."
        }

        function Invoke-PendingResponseActions([string]$ControlPlaneUrl, [string]$EndpointId) {
            $payload = Invoke-JsonGet "$ControlPlaneUrl/api/endpoints/$EndpointId/response-actions"
            foreach ($action in @($payload.items)) {
                Invoke-ResponseAction $ControlPlaneUrl $action
            }
        }

        try {
            $config = Get-Config
            $machineGuid = [string](Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid')
            $controlPlaneUrl = ([string]$config.control_plane_url).TrimEnd('/')
            $platformVersion = Get-WindowsPlatformVersion
            $fingerprint = Get-Sha256Hex("windows|$($config.profile_id)|$machineGuid")
            $enrollResponse = Invoke-JsonPost "$controlPlaneUrl/api/endpoints/enroll" ([ordered]@{
                agent_fingerprint = $fingerprint
                hostname = $env:COMPUTERNAME
                platform = 'windows'
                platform_version = $platformVersion
                agent_version = $config.agent_version
                tenant_id = $config.tenant_id
                site_id = $config.site_id
            })
            $endpointId = [string]$enrollResponse.endpoint_id
            Invoke-JsonPost "$controlPlaneUrl/api/endpoints/$endpointId/heartbeat" ([ordered]@{
                agent_version = $config.agent_version
                platform_version = $platformVersion
                platform_profile = $config.platform_profile
                connectivity_status = 'online'
                declared_capabilities = @($config.capabilities)
                execution_hooks = [ordered]@{
                    captures_rollback_artifacts = [bool]$config.execution_hooks.captures_rollback_artifacts
                    reports_execution_results = [bool]$config.execution_hooks.reports_execution_results
                    supports_dry_run = [bool]$config.execution_hooks.supports_dry_run
                }
            }) | Out-Null
            $results = @(
                Get-FirewallResult
                Get-DefenderRealTimeProtectionResult
                Get-BitLockerSystemDriveResult
                Get-SecureBootResult
            )
            Invoke-JsonPost "$controlPlaneUrl/api/posture-snapshots" ([ordered]@{
                endpoint_id = $endpointId
                observed_at = ConvertTo-UtcZulu (Get-Date)
                platform_profile = $config.platform_profile
                results = $results
            }) | Out-Null
            Invoke-PendingResponseActions $controlPlaneUrl $endpointId
        }
        catch {
            Write-Error "sha reporter failed: $($_.Exception.Message)"
            exit 1
        }
        """
    ).strip() + "\n"



def _render_windows_bootstrap(profile: InstallerProfile, *, api_token: str | None = None) -> str:
    config_json = _profile_config(
        profile,
        agent_version=_WINDOWS_AGENT_VERSION,
        platform_profile=_WINDOWS_PLATFORM_PROFILE,
        api_token=api_token,
        capabilities=_WINDOWS_REPORTER_CAPABILITIES,
        execution_hooks=_WINDOWS_EXECUTION_HOOKS,
    )
    reporter_script = _windows_reporter_script().rstrip("\n")
    return "\n".join(
        [
            "#Requires -Version 5.1",
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "",
            "$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())",
            "if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {",
            "    throw 'sha bootstrap requires an elevated PowerShell session'",
            "}",
            "",
            "$ShaRoot = 'C:\\ProgramData\\SHA'",
            "$ConfigPath = Join-Path $ShaRoot 'reporter-config.json'",
            "$ReporterPath = Join-Path $ShaRoot 'reporter.ps1'",
            "",
            "New-Item -ItemType Directory -Force -Path $ShaRoot | Out-Null",
            "",
            "@'",
            config_json,
            "'@ | Set-Content -LiteralPath $ConfigPath -Encoding UTF8",
            "",
            "@'",
            reporter_script,
            "'@ | Set-Content -LiteralPath $ReporterPath -Encoding UTF8",
            "",
            "$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument \"-NoProfile -ExecutionPolicy Bypass -File ``\"$ReporterPath``\"\"",
            "$repeatTrigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(1)) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)",
            "$startupTrigger = New-ScheduledTaskTrigger -AtStartup",
            "$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest",
            "$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew",
            "",
            "Register-ScheduledTask -TaskName 'SHA Reporter' -Action $action -Trigger @($repeatTrigger, $startupTrigger) -Principal $principal -Settings $settings -Force | Out-Null",
            "& PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $ReporterPath",
            "",
            f"Write-Host 'SHA bootstrap installed for profile {profile.id}'",
            "",
        ]
    )
