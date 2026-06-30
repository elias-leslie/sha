#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK_DIR=${WORK_DIR:-$(mktemp -d)}
OPERATOR_TOKEN=${SHA_API_TOKEN:-operator-token}
AGENT_TOKEN=${SHA_AGENT_API_TOKEN:-agent-token}
STAMP=$(date -u +%Y%m%d%H%M%S)
SITE_ID=${SITE_ID:-macos-installer-e2e-${STAMP}}
SHA_ROOT="/Library/Application Support/SHA"
REPORTER_PATH="${SHA_ROOT}/reporter.py"
PLIST_PATH="/Library/LaunchDaemons/com.sha.reporter.plist"
BACKEND_PID=""
INSTALLED=0
KEEP_E2E=${KEEP_E2E:-0}
KEEP_MACOS_INSTALL=${KEEP_MACOS_INSTALL:-0}

as_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

cleanup() {
  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi
  if [[ "$INSTALLED" == "1" && "$KEEP_MACOS_INSTALL" != "1" ]]; then
    as_root launchctl bootout system/com.sha.reporter >/dev/null 2>&1 || true
    as_root rm -f "$PLIST_PATH" /Library/Logs/sha-reporter.log /Library/Logs/sha-reporter.err
    as_root rm -rf "$SHA_ROOT"
  fi
  if [[ "$KEEP_E2E" != "1" ]]; then
    rm -rf "$WORK_DIR"
  else
    printf 'kept work dir: %s\n' "$WORK_DIR"
  fi
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
need curl
need python3
PYTHON3=$(command -v python3)

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS installer E2E must run on Darwin/macOS" >&2
  exit 1
fi
if [[ -e "$SHA_ROOT" || -e "$PLIST_PATH" ]] && [[ "${ALLOW_EXISTING_SHA_MACOS_E2E:-0}" != "1" ]]; then
  echo "refusing to overwrite existing SHA macOS install; set ALLOW_EXISTING_SHA_MACOS_E2E=1 for disposable hosts" >&2
  exit 1
fi
if [[ ! -x "$ROOT_DIR/backend/.venv/bin/uvicorn" ]]; then
  echo "missing backend/.venv/bin/uvicorn; run: cd backend && uv sync" >&2
  exit 1
fi

mkdir -p "$WORK_DIR"
PORT=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
BASE_URL="http://127.0.0.1:${PORT}"

(
  cd "$ROOT_DIR/backend"
  SHA_DATABASE_URL="sqlite:///${WORK_DIR}/sha.sqlite3" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  exec .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "$PORT"
) >"$WORK_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

for _ in $(seq 1 100); do
  if curl -fsS --max-time 1 "$BASE_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl -fsS "$BASE_URL/health" >/dev/null

PROFILE_ID=$(python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$BASE_URL" "$SITE_ID" "$WORK_DIR/installer.sh" <<'PY'
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
    "name": f"macOS E2E {site_id}",
    "platform": "macos",
    "channel": "preview",
    "control_plane_url": control_url,
    "policy_mode": "observe",
    "tenant_id": "tenant-macos-e2e",
    "site_id": site_id,
}))
Path(installer_path).write_bytes(call("GET", f"/api/installer-profiles/{profile['id']}/artifact"))
print(profile["id"])
PY
)
chmod +x "$WORK_DIR/installer.sh"
printf 'profile_id=%s\n' "$PROFILE_ID"

INSTALLED=1
as_root bash "$WORK_DIR/installer.sh"
as_root "$PYTHON3" "$REPORTER_PATH"

ENDPOINT_ID=$(python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$SITE_ID" <<'PY'
import json
import sys
import time
from urllib import request

base_url, token, site_id = sys.argv[1:]

def get(path: str) -> dict[str, object]:
    req = request.Request(base_url + path, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    with request.urlopen(req, timeout=20) as response:
        return json.load(response)

for _ in range(120):
    for endpoint in get("/api/endpoints")["items"]:
        if endpoint.get("site_id") == site_id:
            print(endpoint["endpoint_id"])
            raise SystemExit(0)
    time.sleep(0.25)
raise SystemExit(f"no endpoint enrolled for site_id={site_id}")
PY
)
printf 'endpoint_id=%s\n' "$ENDPOINT_ID"

python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" <<'PY'
import json
import sys
from urllib import request

base_url, token, endpoint_id = sys.argv[1:]
req = request.Request(base_url + f"/api/endpoints/{endpoint_id}", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=20) as response:
    detail = json.load(response)
capabilities = set(detail.get("declared_capabilities") or [])
hooks = detail.get("execution_hooks") or {}
keys = {result["control_key"] for result in detail.get("latest_results", [])}
required = {
    "macos.firewall.application-firewall-enabled",
    "macos.disk.filevault-enabled",
    "macos.gatekeeper.assessments-enabled",
    "macos.telemetry.hardware-summary",
    "macos.telemetry.process-inventory",
    "macos.telemetry.software-inventory",
    "macos.telemetry.startup-services",
    "macos.telemetry.login-sessions",
    "macos.telemetry.network-bindings",
}
missing = sorted(required - keys)
if detail.get("platform") != "macos":
    raise SystemExit(f"expected macos endpoint, got {detail.get('platform')!r}")
if {"apply_control", "rollback_control"} & capabilities:
    raise SystemExit(f"macOS endpoint declared mutation capability: {sorted(capabilities)}")
if "collect_security_context" not in capabilities or "collect_posture_snapshot" not in capabilities:
    raise SystemExit(f"macOS endpoint missed observe capabilities: {sorted(capabilities)}")
if hooks.get("captures_rollback_artifacts") is not False or hooks.get("reports_execution_results") is not True:
    raise SystemExit(f"unexpected macOS execution hooks: {hooks!r}")
if missing:
    raise SystemExit(f"missing macOS posture results: {missing}")
print("macos_endpoint=" + json.dumps({
    "endpoint_id": endpoint_id,
    "latest_result_count": len(detail.get("latest_results", [])),
    "platform": detail.get("platform"),
    "site_id": detail.get("site_id"),
}, sort_keys=True))
PY

ACTION_ID=$(python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" <<'PY'
import datetime as dt
import json
import sys
from urllib import request

base_url, token, endpoint_id = sys.argv[1:]

def post(path: str, payload: dict[str, object]) -> dict[str, object]:
    req = request.Request(base_url + path, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    with request.urlopen(req, timeout=20) as response:
        return json.load(response)

expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=45)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
grant = post("/api/approval-grants", {
    "endpoint_ids": [endpoint_id],
    "allowed_actions": ["collect_security_context"],
    "control_ids": [],
    "troubleshooting_scopes": ["service_status"],
    "requested_by": "macos-e2e",
    "approved_by": "secops-e2e",
    "reason": "macOS E2E observe-only action validation",
    "expires_at": expires_at,
})
queued = post("/api/response-actions", {
    "endpoint_id": endpoint_id,
    "approval_grant_id": grant["approval_grant_id"],
    "action": "collect_security_context",
    "troubleshooting_scope": "service_status",
    "requested_by": "macos-e2e",
    "reason": "Collect macOS launchd reporter status",
})
print(queued["response_action_id"])
PY
)
printf 'collect_security_context_action_id=%s\n' "$ACTION_ID"
as_root "$PYTHON3" "$REPORTER_PATH"

python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" "$ACTION_ID" <<'PY'
import json
import sys
import time
from urllib import request

base_url, token, endpoint_id, action_id = sys.argv[1:]

def get(path: str) -> dict[str, object]:
    req = request.Request(base_url + path, method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    with request.urlopen(req, timeout=20) as response:
        return json.load(response)

for _ in range(80):
    items = get(f"/api/endpoints/{endpoint_id}/response-actions?include_terminal=true")["items"]
    for item in items:
        if item["response_action_id"] == action_id:
            if item["status"] in {"succeeded", "failed"}:
                print("collect_security_context_result=" + json.dumps(item, sort_keys=True))
                if item["status"] != "succeeded" or "macos.telemetry.service-status" not in str(item.get("result_summary")):
                    raise SystemExit(1)
                raise SystemExit(0)
    time.sleep(0.25)
raise SystemExit(f"action did not finish: {action_id}")
PY

python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" <<'PY'
import datetime as dt
import json
import sys
from urllib import error, request

base_url, token, endpoint_id = sys.argv[1:]

def post(path: str, payload: dict[str, object], *, expect_error: bool = False) -> dict[str, object]:
    req = request.Request(base_url + path, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=20) as response:
            return {"status": response.status, "body": json.load(response)}
    except error.HTTPError as exc:
        if not expect_error:
            raise
        return {"status": exc.code, "body": json.loads(exc.read().decode())}

expires_at = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=45)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
grant = post("/api/approval-grants", {
    "endpoint_ids": [endpoint_id],
    "allowed_actions": ["apply_control"],
    "control_ids": ["macos.firewall.application-firewall-enabled"],
    "troubleshooting_scopes": [],
    "requested_by": "macos-e2e",
    "approved_by": "secops-e2e",
    "reason": "macOS E2E observe-only rejection validation",
    "expires_at": expires_at,
})["body"]
result = post("/api/response-actions", {
    "endpoint_id": endpoint_id,
    "approval_grant_id": grant["approval_grant_id"],
    "action": "apply_control",
    "control_id": "macos.firewall.application-firewall-enabled",
    "requested_by": "macos-e2e",
    "reason": "Verify macOS observe-only mutation rejection",
}, expect_error=True)
if result["status"] != 422 or result["body"].get("detail") != "endpoint has not declared action capability":
    raise SystemExit(f"unexpected apply_control rejection: {result}")
print("apply_control_rejected=" + json.dumps(result, sort_keys=True))
PY

if as_root launchctl print system/com.sha.reporter >/dev/null 2>&1; then
  printf 'launchd=loaded\n'
else
  printf 'launchd=not_loaded\n'
  exit 1
fi

printf 'MACOS_INSTALLER_E2E_OK\n'
