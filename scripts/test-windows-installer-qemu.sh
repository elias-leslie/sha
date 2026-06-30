#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK_DIR=${WORK_DIR:-$ROOT_DIR/.dev-tools/windows-installer-qemu-e2e}
ISO_PATH=${WINDOWS_ISO_PATH:-$ROOT_DIR/.dev-tools/windows-server-2025-eval.iso}
ISO_URL=${WINDOWS_ISO_URL:-https://aka.ms/WinServ2025iso-enus}
OPERATOR_TOKEN=${SHA_API_TOKEN:-operator-token}
AGENT_TOKEN=${SHA_AGENT_API_TOKEN:-agent-token}
STAMP=$(date -u +%Y%m%d%H%M%S)
SITE_ID=${SITE_ID:-qemu-windows-e2e-${STAMP}}
PORT=${PORT:-}
TIMEOUT_SECONDS=${WINDOWS_E2E_TIMEOUT_SECONDS:-4200}
DISK_SIZE=${WINDOWS_E2E_DISK_SIZE:-64G}
MEMORY=${WINDOWS_E2E_MEMORY:-4096}
SMP=${WINDOWS_E2E_SMP:-2}
KEEP_E2E=${KEEP_E2E:-0}
ISO_MIN_BYTES=${WINDOWS_ISO_MIN_BYTES:-7000000000}
BACKEND_PID=""
QEMU_PID=""

cleanup() {
  if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
  fi
  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ "$KEEP_E2E" != "1" ]]; then
    rm -rf "$WORK_DIR/payload" "$WORK_DIR/autounattend" "$WORK_DIR/disk.qcow2" "$WORK_DIR/sha-e2e.iso"
  else
    printf 'kept work dir: %s\n' "$WORK_DIR"
  fi
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
need curl
need genisoimage
need python3
need qemu-img
need qemu-system-x86_64

if [[ ! -x "$ROOT_DIR/backend/.venv/bin/uvicorn" ]]; then
  echo "missing backend/.venv/bin/uvicorn; run: cd backend && uv sync" >&2
  exit 1
fi

mkdir -p "$WORK_DIR" "$(dirname "$ISO_PATH")"
rm -rf "$WORK_DIR/payload" "$WORK_DIR/autounattend" "$WORK_DIR/disk.qcow2" "$WORK_DIR/sha-e2e.iso"
rm -f "$WORK_DIR/sha.sqlite3" "$WORK_DIR/backend.log" "$WORK_DIR/qemu.log" "$WORK_DIR/qemu-serial.log"
ISO_BYTES=0
if [[ -f "$ISO_PATH" ]]; then
  ISO_BYTES=$(stat -c%s "$ISO_PATH")
fi
if [[ "$ISO_BYTES" -lt "$ISO_MIN_BYTES" || -f "$ISO_PATH.aria2" ]]; then
  printf 'downloading Windows Server evaluation ISO to %s\n' "$ISO_PATH"
  if command -v aria2c >/dev/null 2>&1; then
    aria2c -c -x 8 -s 8 --summary-interval=60 --console-log-level=warn -d "$(dirname "$ISO_PATH")" -o "$(basename "$ISO_PATH")" "$ISO_URL"
  else
    curl -fLsS --retry 3 --continue-at - --output "$ISO_PATH" "$ISO_URL"
  fi
fi

if [[ -z "$PORT" ]]; then
  PORT=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
fi
BASE_URL="http://127.0.0.1:${PORT}"
CONTROL_URL="http://10.0.2.2:${PORT}"

(
  cd "$ROOT_DIR/backend"
  SHA_DATABASE_URL="sqlite:///${WORK_DIR}/sha.sqlite3" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  exec .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
) >"$WORK_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

for _ in $(seq 1 100); do
  if curl -fsS --max-time 1 "$BASE_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl -fsS "$BASE_URL/health" >/dev/null

mkdir -p "$WORK_DIR/payload" "$WORK_DIR/autounattend"
python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$CONTROL_URL" "$SITE_ID" "$WORK_DIR/payload/windows-installer.ps1" <<'PY'
import json
import sys
from pathlib import Path
from urllib import request

base_url, token, control_url, site_id, installer_path = sys.argv[1:]


def call(method: str, path: str, payload: dict[str, object] | None = None) -> bytes:
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(base_url + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with request.urlopen(req, timeout=20) as response:
        return response.read()

profile = json.loads(call("POST", "/api/installer-profiles", {
    "name": f"QEMU Windows E2E {site_id}",
    "platform": "windows",
    "channel": "stable",
    "control_plane_url": control_url,
    "policy_mode": "approval_required",
    "tenant_id": "tenant-qemu-windows-e2e",
    "site_id": site_id,
}))
Path(installer_path).write_bytes(call("GET", f"/api/installer-profiles/{profile['id']}/artifact"))
print(f"profile_id={profile['id']}")
PY

cat > "$WORK_DIR/payload/sha-e2e.ps1" <<'PS1'
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path 'C:\sha-e2e' | Out-Null
Start-Transcript -Path 'C:\sha-e2e\guest-transcript.log' -Append | Out-Null
try {
    $media = Get-PSDrive -PSProvider FileSystem | Where-Object { Test-Path (Join-Path $_.Root 'windows-installer.ps1') } | Select-Object -First 1
    if (-not $media) { throw 'SHA E2E media with windows-installer.ps1 not found' }
    $installer = Join-Path $media.Root 'windows-installer.ps1'
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False
    & PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $installer
    $reporter = 'C:\ProgramData\SHA\reporter.ps1'
    for ($i = 0; $i -lt 150; $i++) {
        Start-Sleep -Seconds 5
        & PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $reporter
    }
}
catch {
    "SHA Windows E2E failed: $($_.Exception.Message)" | Out-File -FilePath 'C:\sha-e2e\guest-transcript.log' -Append
}
finally {
    Stop-Transcript | Out-Null
}
PS1

cat > "$WORK_DIR/autounattend/Autounattend.xml" <<'XML'
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Size>100</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>NTFS</Format><Label>System Reserved</Label><Active>true</Active></ModifyPartition>
            <ModifyPartition wcm:action="add"><Order>2</Order><PartitionID>2</PartitionID><Format>NTFS</Format><Label>Windows</Label><Letter>C</Letter></ModifyPartition>
          </ModifyPartitions>
        </Disk>
        <WillShowUI>OnError</WillShowUI>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/INDEX</Key><Value>1</Value></MetaData></InstallFrom>
          <InstallTo><DiskID>0</DiskID><PartitionID>2</PartitionID></InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
      <UserData><AcceptEula>true</AcceptEula><FullName>SHA E2E</FullName><Organization>SHA</Organization></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>SHA-WIN-E2E</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen><HideOEMRegistrationScreen>true</HideOEMRegistrationScreen><HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE><NetworkLocation>Work</NetworkLocation><ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><AdministratorPassword><Value>ShaE2E-Passw0rd!</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <AutoLogon><Enabled>true</Enabled><Username>Administrator</Username><Password><Value>ShaE2E-Passw0rd!</Value><PlainText>true</PlainText></Password><LogonCount>1</LogonCount></AutoLogon>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add"><Order>1</Order><Description>Run SHA Windows E2E payload</Description><CommandLine>cmd.exe /c for %d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do @if exist %d:\sha-e2e.ps1 powershell.exe -NoProfile -ExecutionPolicy Bypass -File %d:\sha-e2e.ps1</CommandLine></SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
XML

cp "$WORK_DIR/autounattend/Autounattend.xml" "$WORK_DIR/payload/Autounattend.xml"
genisoimage -quiet -J -r -V SHA_E2E -o "$WORK_DIR/sha-e2e.iso" "$WORK_DIR/payload"
qemu-img create -f qcow2 "$WORK_DIR/disk.qcow2" "$DISK_SIZE" >/dev/null

qemu_args=(
  -m "$MEMORY"
  -smp "$SMP"
  -rtc base=localtime
  -drive "file=$WORK_DIR/disk.qcow2,format=qcow2,if=ide"
  -cdrom "$ISO_PATH"
  -drive "file=$WORK_DIR/sha-e2e.iso,media=cdrom,readonly=on,if=ide"
  -boot order=d
  -nic user,model=e1000
  -display none
  -serial "file:$WORK_DIR/qemu-serial.log"
  -monitor none
)
if [[ -r /dev/kvm && -w /dev/kvm ]]; then
  qemu_args=(-enable-kvm -cpu host "${qemu_args[@]}")
fi
qemu-system-x86_64 "${qemu_args[@]}" >"$WORK_DIR/qemu.log" 2>&1 &
QEMU_PID=$!
printf 'qemu_pid=%s site_id=%s base_url=%s control_url=%s\n' "$QEMU_PID" "$SITE_ID" "$BASE_URL" "$CONTROL_URL"

run_python() {
  python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$@"
}

ENDPOINT_ID=$(timeout "$TIMEOUT_SECONDS" bash -c '
  while true; do
    python3 - "$0" "$1" "$2" <<"PY" && exit 0 || true
import json
import sys
from urllib import request
base_url, token, site_id = sys.argv[1:]
req = request.Request(base_url + "/api/endpoints", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=20) as response:
    payload = json.load(response)
for endpoint in payload["items"]:
    if endpoint.get("site_id") == site_id:
        print(endpoint["endpoint_id"])
        raise SystemExit(0)
raise SystemExit(1)
PY
    sleep 5
  done
' "$BASE_URL" "$OPERATOR_TOKEN" "$SITE_ID")
printf 'endpoint_id=%s\n' "$ENDPOINT_ID"

create_action() {
  local action=$1
  run_python "$ENDPOINT_ID" "$action" <<'PY'
import datetime as dt
import json
import sys
from urllib import request
base_url, token, endpoint_id, action = sys.argv[1:]
control_id = "control.windows.firewall-all-profiles"

def post(path: str, payload: dict[str, object]) -> dict[str, object]:
    req = request.Request(base_url + path, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    with request.urlopen(req, timeout=20) as response:
        return json.load(response)

expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
grant = post("/api/approval-grants", {
    "endpoint_ids": [endpoint_id],
    "allowed_actions": [action],
    "control_ids": [control_id],
    "troubleshooting_scopes": [],
    "requested_by": "qemu-windows-e2e",
    "approved_by": "secops-e2e",
    "reason": f"QEMU Windows E2E {action} validation",
    "expires_at": expires_at,
})
queued = post("/api/response-actions", {
    "endpoint_id": endpoint_id,
    "approval_grant_id": grant["approval_grant_id"],
    "action": action,
    "control_id": control_id,
    "requested_by": "qemu-windows-e2e",
    "reason": f"Run approved {action} validation",
})
print(queued["response_action_id"])
PY
}

wait_action() {
  local action_id=$1
  timeout 300 bash -c '
    while true; do
      python3 - "$0" "$1" "$2" "$3" <<"PY" && exit 0 || rc=$?
import json
import sys
from urllib import request
base_url, token, endpoint_id, action_id = sys.argv[1:]
req = request.Request(base_url + f"/api/endpoints/{endpoint_id}/response-actions?include_terminal=true", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=20) as response:
    items = json.load(response)["items"]
for item in items:
    if item["response_action_id"] == action_id:
        if item["status"] in {"succeeded", "failed"}:
            print(json.dumps(item, sort_keys=True))
            raise SystemExit(0 if item["status"] == "succeeded" else 2)
raise SystemExit(1)
PY
      if [[ "$rc" == "2" ]]; then exit 2; fi
      sleep 5
    done
  ' "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" "$action_id"
}

wait_posture_status() {
  local wanted=$1
  timeout 300 bash -c '
    while true; do
      python3 - "$0" "$1" "$2" "$3" <<"PY" && exit 0 || true
import json
import sys
from urllib import request
base_url, token, endpoint_id, wanted = sys.argv[1:]
req = request.Request(base_url + f"/api/endpoints/{endpoint_id}", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=20) as response:
    detail = json.load(response)
for result in detail.get("latest_results", []):
    if result.get("control_key") == "windows.firewall.all-profiles-enabled":
        if result.get("status") == wanted:
            print(json.dumps(result, sort_keys=True))
            raise SystemExit(0)
        print(json.dumps(result, sort_keys=True), file=sys.stderr)
raise SystemExit(1)
PY
      sleep 5
    done
  ' "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" "$wanted"
}

printf 'initial_firewall_posture='; wait_posture_status fail
APPLY_ACTION_ID=$(create_action apply_control)
printf 'apply_action_id=%s\n' "$APPLY_ACTION_ID"
wait_action "$APPLY_ACTION_ID"
printf 'post_apply_firewall_posture='; wait_posture_status pass
ROLLBACK_ACTION_ID=$(create_action rollback_control)
printf 'rollback_action_id=%s\n' "$ROLLBACK_ACTION_ID"
wait_action "$ROLLBACK_ACTION_ID"
printf 'post_rollback_firewall_posture='; wait_posture_status fail

python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" <<'PY'
import json
import sys
from urllib import request
base_url, token, endpoint_id = sys.argv[1:]
req = request.Request(base_url + f"/api/endpoints/{endpoint_id}", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=20) as response:
    detail = json.load(response)
print(json.dumps({
    "endpoint_id": endpoint_id,
    "platform": detail.get("platform"),
    "latest_result_count": len(detail.get("latest_results", [])),
    "site_id": detail.get("site_id"),
}, sort_keys=True))
PY
printf 'QEMU_WINDOWS_INSTALLER_E2E_OK\n'
