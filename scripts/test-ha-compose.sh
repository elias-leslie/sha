#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE_FILE="$ROOT_DIR/deploy/ha/docker-compose.yml"
PROJECT=${PROJECT:-sha-ha-e2e-$(date -u +%Y%m%d%H%M%S)}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-sha-ha-e2e-password}
OPERATOR_TOKEN=${SHA_API_TOKEN:-operator-token}
READONLY_TOKEN=${SHA_READONLY_API_TOKEN:-readonly-token}
AGENT_TOKEN=${SHA_AGENT_API_TOKEN:-agent-token}
EXTERNAL_AUTH_TOKEN=${SHA_EXTERNAL_AUTH_TRUSTED_TOKEN:-proxy-e2e-token}
PORT=${SHA_PUBLIC_PORT:-}
WORK_DIR=${WORK_DIR:-$(mktemp -d)}

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
need docker
need python3
need curl

if [[ -z "$PORT" ]]; then
  PORT=$(python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)
fi

compose() {
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_READONLY_API_TOKEN="$READONLY_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" \
  SHA_PUBLIC_PORT="$PORT" \
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  if [[ "${KEEP_E2E:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
  else
    printf 'kept compose project: %s on port %s work_dir=%s\n' "$PROJECT" "$PORT" "$WORK_DIR"
  fi
}
trap cleanup EXIT

compose up -d --build --wait --wait-timeout 240
compose ps --status running

BASE_URL="http://127.0.0.1:${PORT}"
curl -fsS "$BASE_URL/health" >/dev/null
curl -fsS -H "Authorization: Bearer $READONLY_TOKEN" "$BASE_URL/api/source-packs" >/dev/null
curl -fsS \
  -H "X-SHA-External-Auth: $EXTERNAL_AUTH_TOKEN" \
  -H "X-SHA-External-Role: readonly" \
  "$BASE_URL/api/source-packs" >/dev/null

PROFILE_ID_FILE="$WORK_DIR/profile-id.txt"
python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$PROFILE_ID_FILE" <<'PY'
import json
import sys
from urllib import request

base_url, token, profile_id_file = sys.argv[1:]


def call_raw(method: str, path: str, payload: dict[str, object] | None = None) -> tuple[bytes, dict[str, str]]:
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(base_url + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with request.urlopen(req, timeout=30) as response:
        body = response.read()
        headers = {k.lower(): v for k, v in response.headers.items()}
        return body, headers


def call_json(method: str, path: str, payload: dict[str, object] | None = None) -> dict[str, object]:
    body, _ = call_raw(method, path, payload)
    return json.loads(body)


profile = call_json("POST", "/api/installer-profiles", {
    "name": "HA Compose Linux E2E",
    "platform": "linux",
    "channel": "stable",
    "control_plane_url": base_url,
    "policy_mode": "approval_required",
    "tenant_id": "tenant-ha-e2e",
    "site_id": "ha-compose-e2e",
})
open(profile_id_file, "w", encoding="utf-8").write(profile["id"])
artifact, headers = call_raw("GET", f"/api/installer-profiles/{profile['id']}/artifact")
assert artifact.startswith(b"#!/usr/bin/env bash\n")
assert headers.get("x-sha-artifact-sha256")
evidence = call_json("GET", "/api/compliance/evidence")
assert evidence["source_catalog"]["pack_count"] == 4
assert evidence["source_catalog"]["control_count"] == 17
print(json.dumps({
    "profile_id": profile["id"],
    "artifact_sha256": headers["x-sha-artifact-sha256"],
    "pack_count": evidence["source_catalog"]["pack_count"],
    "control_count": evidence["source_catalog"]["control_count"],
}, sort_keys=True))
PY

BACKUP_DIR="$WORK_DIR/backups"
PROJECT="$PROJECT" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" SHA_PUBLIC_PORT="$PORT" BACKUP_DIR="$BACKUP_DIR" \
  "$ROOT_DIR/scripts/backup-ha-postgres.sh"
BACKUP_FILE=$(ls "$BACKUP_DIR"/sha-postgres-*.dump)
python3 - "$BASE_URL" "$OPERATOR_TOKEN" <<'PY'
import json
import sys
from urllib import request

base_url, token = sys.argv[1:]
req = request.Request(base_url + "/api/installer-profiles", data=json.dumps({
    "name": "HA Compose Post Backup Marker",
    "platform": "linux",
    "channel": "stable",
    "control_plane_url": base_url,
    "policy_mode": "observe",
}).encode(), method="POST")
req.add_header("Authorization", f"Bearer {token}")
req.add_header("Content-Type", "application/json")
with request.urlopen(req, timeout=30):
    pass
PY
CONFIRM_RESTORE=sha-restore PROJECT="$PROJECT" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" SHA_READONLY_API_TOKEN="$READONLY_TOKEN" SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" SHA_PUBLIC_PORT="$PORT" \
  "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$BACKUP_FILE"
python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$PROFILE_ID_FILE" <<'PY'
import json
import sys
from urllib import request

base_url, token, profile_id_file = sys.argv[1:]
profile_id = open(profile_id_file, encoding="utf-8").read().strip()
req = request.Request(base_url + "/api/installer-profiles", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=30) as response:
    profiles = json.load(response)["items"]
ids = {profile["id"] for profile in profiles}
names = {profile["name"] for profile in profiles}
assert profile_id in ids
assert "HA Compose Post Backup Marker" not in names
print(json.dumps({"restored_profile_id": profile_id, "profile_count": len(profiles)}, sort_keys=True))
PY

printf 'HA_COMPOSE_E2E_OK port=%s project=%s\n' "$PORT" "$PROJECT"
