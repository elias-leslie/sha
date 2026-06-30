#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK_DIR=${WORK_DIR:-$(mktemp -d)}
OPERATOR_TOKEN=${SHA_API_TOKEN:-operator-token}
AGENT_TOKEN=${SHA_AGENT_API_TOKEN:-agent-token}
STAMP=$(date -u +%Y%m%d%H%M%S)
SITE_ID="docker-linux-e2e-${STAMP}"
IMAGE=${IMAGE:-sha-linux-systemd-e2e:local}
CONTAINER=${CONTAINER:-sha-linux-e2e-${STAMP}}
BACKEND_PID=""
KEEP_E2E=${KEEP_E2E:-0}

cleanup() {
  if [[ -n "$BACKEND_PID" ]] && kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
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
need docker
need python3
need curl

if [[ ! -x "$ROOT_DIR/backend/.venv/bin/uvicorn" ]]; then
  echo "missing backend/.venv/bin/uvicorn; run: cd backend && uv sync" >&2
  exit 1
fi

PORT=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
BASE_URL="http://127.0.0.1:${PORT}"
CONTROL_URL="http://host.docker.internal:${PORT}"
mkdir -p "$WORK_DIR"

(
  cd "$ROOT_DIR/backend"
  SHA_DATABASE_URL="sqlite:///${WORK_DIR}/sha.sqlite3" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  exec .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
) >"$WORK_DIR/backend.log" 2>&1 &
BACKEND_PID=$!

for _ in $(seq 1 80); do
  if curl -fsS --max-time 1 "$BASE_URL/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done
curl -fsS "$BASE_URL/health" >/dev/null

docker build -q -f "$ROOT_DIR/scripts/docker/linux-systemd.Dockerfile" -t "$IMAGE" "$ROOT_DIR/scripts/docker" >/dev/null
docker run -d --privileged --cgroupns=host \
  --add-host=host.docker.internal:host-gateway \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --name "$CONTAINER" "$IMAGE" >/dev/null

for _ in $(seq 1 80); do
  state=$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)
  if [[ "$state" == "running" || "$state" == "degraded" ]]; then
    break
  fi
  sleep 0.25
done
printf 'systemd=%s\n' "$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)"
docker exec "$CONTAINER" systemctl start ssh.service

PROFILE_ID=$(python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$CONTROL_URL" "$SITE_ID" "$WORK_DIR/installer.sh" <<'PY'
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
    "name": f"Docker Linux E2E {site_id}",
    "platform": "linux",
    "channel": "stable",
    "control_plane_url": control_url,
    "policy_mode": "approval_required",
    "tenant_id": "tenant-docker-e2e",
    "site_id": site_id,
}))
Path(installer_path).write_bytes(call("GET", f"/api/installer-profiles/{profile['id']}/artifact"))
print(profile["id"])
PY
)
chmod +x "$WORK_DIR/installer.sh"
printf 'profile_id=%s\n' "$PROFILE_ID"

docker cp "$WORK_DIR/installer.sh" "$CONTAINER:/tmp/sha-installer.sh"
docker exec "$CONTAINER" bash /tmp/sha-installer.sh

docker exec "$CONTAINER" systemctl start sha-reporter.service

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

for _ in range(80):
    for endpoint in get("/api/endpoints")["items"]:
        if endpoint.get("site_id") == site_id:
            print(endpoint["endpoint_id"])
            raise SystemExit(0)
    time.sleep(0.25)
raise SystemExit(f"no endpoint enrolled for site_id={site_id}")
PY
)
printf 'endpoint_id=%s\n' "$ENDPOINT_ID"

create_action() {
  local action=$1
  python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" "$action" <<'PY'
import datetime as dt
import json
import sys
from urllib import request

base_url, token, endpoint_id, action = sys.argv[1:]
control_id = "linux.ssh.password-authentication-disabled"


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
    "allowed_actions": [action],
    "control_ids": [control_id],
    "troubleshooting_scopes": [],
    "requested_by": "docker-e2e",
    "approved_by": "secops-e2e",
    "reason": f"Docker E2E {action} validation",
    "expires_at": expires_at,
})
queued = post("/api/response-actions", {
    "endpoint_id": endpoint_id,
    "approval_grant_id": grant["approval_grant_id"],
    "action": action,
    "control_id": control_id,
    "requested_by": "docker-e2e",
    "reason": f"Run approved {action} validation",
})
print(queued["response_action_id"])
PY
}

wait_action() {
  local action_id=$1
  python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$ENDPOINT_ID" "$action_id" <<'PY'
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
                print(json.dumps(item, sort_keys=True))
                raise SystemExit(0 if item["status"] == "succeeded" else 1)
    time.sleep(0.25)
raise SystemExit(f"action did not finish: {action_id}")
PY
}

APPLY_ACTION_ID=$(create_action apply_control)
printf 'apply_action_id=%s\n' "$APPLY_ACTION_ID"
docker exec "$CONTAINER" systemctl start sha-reporter.service
wait_action "$APPLY_ACTION_ID"
docker exec "$CONTAINER" grep -q '^PasswordAuthentication no$' /etc/ssh/sshd_config.d/99-sha-hardening.conf

ROLLBACK_ACTION_ID=$(create_action rollback_control)
printf 'rollback_action_id=%s\n' "$ROLLBACK_ACTION_ID"
docker exec "$CONTAINER" systemctl start sha-reporter.service
wait_action "$ROLLBACK_ACTION_ID"
docker exec "$CONTAINER" test ! -e /etc/ssh/sshd_config.d/99-sha-hardening.conf

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
    "latest_result_count": len(detail.get("latest_results", [])),
    "pending_actions": 0,
    "site_id": detail.get("site_id"),
}, sort_keys=True))
PY

printf 'DOCKER_LINUX_INSTALLER_E2E_OK\n'
