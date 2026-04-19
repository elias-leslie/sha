from __future__ import annotations

import json
import re
from textwrap import dedent

from app.models import InstallerProfile

_LINUX_AGENT_VERSION = "bootstrap-linux-v1"
_WINDOWS_AGENT_VERSION = "bootstrap-windows-v1"
_LINUX_PLATFORM_PROFILE = "linux-bootstrap-v1"
_WINDOWS_PLATFORM_PROFILE = "windows-bootstrap-v1"

_SAFE_REPORTER_CAPABILITIES = [
    "collect_posture_snapshot",
    "collect_security_context",
    "enroll",
    "heartbeat",
    "inspect_control",
    "request_elevated_troubleshooting",
]

_EXECUTION_HOOKS = {
    "captures_rollback_artifacts": False,
    "reports_execution_results": False,
    "supports_dry_run": False,
}


def render_installer_artifact(profile: InstallerProfile) -> tuple[str, str, str]:
    if profile.platform == "linux":
        return (
            _artifact_filename(profile, extension="sh"),
            "text/x-shellscript; charset=utf-8",
            _render_linux_bootstrap(profile),
        )
    if profile.platform == "windows":
        return (
            _artifact_filename(profile, extension="ps1"),
            "text/x-powershell; charset=utf-8",
            _render_windows_bootstrap(profile),
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
        "capabilities": _SAFE_REPORTER_CAPABILITIES,
        "execution_hooks": _EXECUTION_HOOKS,
    }
    return json.dumps(payload, indent=2)



def _linux_reporter_script() -> str:
    return dedent(
        """
        #!/usr/bin/env python3
        from __future__ import annotations

        import datetime as dt
        import glob
        import hashlib
        import json
        import platform
        import socket
        import subprocess
        import sys
        from pathlib import Path
        from urllib import error, request

        CONFIG_PATH = Path("/etc/sha/reporter-config.json")


        def utc_now() -> str:
            return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


        def load_config() -> dict[str, object]:
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


        def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
            body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            http_request = request.Request(url, data=body, method="POST")
            http_request.add_header("Accept", "application/json")
            http_request.add_header("Content-Type", "application/json")
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


        def collect_results() -> list[dict[str, object]]:
            return [
                linux_firewall_result(),
                linux_ssh_password_authentication_result(),
                linux_root_password_locked_result(),
                linux_automatic_updates_result(),
            ]


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



def _render_linux_bootstrap(profile: InstallerProfile) -> str:
    config_json = _profile_config(profile, agent_version=_LINUX_AGENT_VERSION, platform_profile=_LINUX_PLATFORM_PROFILE)
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



def _windows_reporter_script() -> str:
    return dedent(
        r"""
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'
        $ConfigPath = 'C:\ProgramData\SHA\reporter-config.json'

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
            return Invoke-RestMethod -Method Post -Uri $Url -Body $json -ContentType 'application/json'
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
        }
        catch {
            Write-Error "sha reporter failed: $($_.Exception.Message)"
            exit 1
        }
        """
    ).strip() + "\n"



def _render_windows_bootstrap(profile: InstallerProfile) -> str:
    config_json = _profile_config(profile, agent_version=_WINDOWS_AGENT_VERSION, platform_profile=_WINDOWS_PLATFORM_PROFILE)
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
