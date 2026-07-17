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
WORK_DIR_OWNED=0
if [[ -z "${WORK_DIR:-}" ]]; then
  WORK_DIR=$(mktemp -d)
  WORK_DIR_OWNED=1
fi
CREDENTIAL_HMAC_KEY_FILE="$WORK_DIR/credential-hmac-key"
head -c 48 /dev/urandom > "$CREDENTIAL_HMAC_KEY_FILE"
chmod 600 "$CREDENTIAL_HMAC_KEY_FILE"

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
  SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$CREDENTIAL_HMAC_KEY_FILE" \
  SHA_PUBLIC_PORT="$PORT" \
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

cleanup() {
  if [[ "${KEEP_E2E:-0}" != "1" ]]; then
    if [[ "${RESTORE_VALIDATION_ONLY:-0}" != "1" ]]; then
      compose down -v --remove-orphans >/dev/null 2>&1 || true
    fi
    if [[ "$WORK_DIR_OWNED" == "1" && -d "$WORK_DIR" ]]; then
      find "$WORK_DIR" -xdev -depth -delete
    fi
  else
    printf 'kept compose project: %s on port %s work_dir=%s\n' "$PROJECT" "$PORT" "$WORK_DIR"
  fi
}
trap cleanup EXIT

RESTORE_TEST_DIR="$WORK_DIR/restore-validation"
FAKE_BIN="$RESTORE_TEST_DIR/bin"
RESTORE_DOCKER_LOG="$RESTORE_TEST_DIR/docker.log"
RESTORE_ERROR_LOG="$RESTORE_TEST_DIR/restore.err"
TEST_DUMP="$RESTORE_TEST_DIR/test.dump"
mkdir -p "$FAKE_BIN"
printf 'safe restore validation fixture\n' > "$TEST_DUMP"
cat > "$FAKE_BIN/docker" <<'SH'
#!/usr/bin/env bash
printf 'docker invoked\n' >> "$RESTORE_DOCKER_LOG"
exit 99
SH
chmod +x "$FAKE_BIN/docker"
export RESTORE_DOCKER_LOG

printf '%s  test.dump\n' "$(sha256sum -- "$TEST_DUMP" | cut -d ' ' -f 1)" > "$TEST_DUMP.sha256"
RESTORE_HASH_LOG="$RESTORE_TEST_DIR/hash.log"
cat > "$FAKE_BIN/sha256sum" <<'SH'
#!/usr/bin/env bash
printf 'sha256sum invoked\n' >> "$RESTORE_HASH_LOG"
exec /usr/bin/sha256sum "$@"
SH
chmod +x "$FAKE_BIN/sha256sum"
export RESTORE_HASH_LOG
unconfirmed_status=0
env -u CONFIRM_RESTORE PATH="$FAKE_BIN:$PATH" \
  SHA_COMPOSE_FILES="$COMPOSE_FILE" \
  "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$TEST_DUMP" 2> "$RESTORE_ERROR_LOG" || unconfirmed_status=$?
if [[ $unconfirmed_status -eq 0 || -e "$RESTORE_HASH_LOG" ]]; then
  echo "restore validation hashed before confirmation" >&2
  exit 1
fi
rm -f "$FAKE_BIN/sha256sum" "$TEST_DUMP.sha256"

assert_restore_rejected() {
  local expected_error=$1
  local sha_file=${2:-}
  local status=0
  : > "$RESTORE_ERROR_LOG"
  rm -f "$RESTORE_DOCKER_LOG"
  if [[ -n "$sha_file" ]]; then
    CONFIRM_RESTORE=sha-restore SHA_FILE="$sha_file" PATH="$FAKE_BIN:$PATH" \
      SHA_COMPOSE_FILES="$COMPOSE_FILE" \
      "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$TEST_DUMP" 2> "$RESTORE_ERROR_LOG" || status=$?
  else
    env -u SHA_FILE CONFIRM_RESTORE=sha-restore PATH="$FAKE_BIN:$PATH" \
      SHA_COMPOSE_FILES="$COMPOSE_FILE" \
      "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$TEST_DUMP" 2> "$RESTORE_ERROR_LOG" || status=$?
  fi
  if [[ $status -eq 0 || "$(< "$RESTORE_ERROR_LOG")" != *"$expected_error"* ]]; then
    echo "restore validation did not reject fixture as expected: $expected_error" >&2
    exit 1
  fi
  if [[ -e "$RESTORE_DOCKER_LOG" ]]; then
    echo "restore validation invoked Docker before rejecting fixture: $expected_error" >&2
    exit 1
  fi
}

assert_restore_rejected "missing SHA-256 sidecar"
printf 'not-a-digest  test.dump\n' > "$RESTORE_TEST_DIR/malformed.sha256"
assert_restore_rejected "malformed SHA-256 sidecar" "$RESTORE_TEST_DIR/malformed.sha256"
printf '%064d  test.dump\n' 0 > "$RESTORE_TEST_DIR/mismatch.sha256"
assert_restore_rejected "SHA-256 mismatch" "$RESTORE_TEST_DIR/mismatch.sha256"
printf '%064d  test.dump\n%064d  extra.dump\n' 0 1 > "$RESTORE_TEST_DIR/two-lines.sha256"
assert_restore_rejected "malformed SHA-256 sidecar" "$RESTORE_TEST_DIR/two-lines.sha256"

ODD_DUMP="$RESTORE_TEST_DIR/-odd dump name"
printf 'original selected dump\n' > "$ODD_DUMP"
printf '%s  ignored-name.dump\n' "$(/usr/bin/sha256sum -- "$ODD_DUMP" | cut -d ' ' -f 1)" > "$ODD_DUMP.sha256"
RESTORED_DUMP_LOG="$RESTORE_TEST_DIR/restored.dump"
STAGE_MODE_LOG="$RESTORE_TEST_DIR/stage-mode.log"
cat > "$FAKE_BIN/sha256sum" <<'SH'
#!/usr/bin/env bash
[[ ${1:-} == "--" ]] || { echo "sha256sum missing --" >&2; exit 98; }
printf 'replacement after staging\n' > "$ORIGINAL_DUMP"
printf '%s %s\n' "$(stat -c '%a' "$2")" "$(stat -c '%a' "$(dirname "$2")")" > "$STAGE_MODE_LOG"
exec /usr/bin/sha256sum "$@"
SH
cat > "$FAKE_BIN/docker" <<'SH'
#!/usr/bin/env bash
printf 'docker invoked: %s\n' "$*" >> "$RESTORE_DOCKER_LOG"
if [[ " $* " == *" postgres pg_restore "* ]]; then
  cp /dev/stdin "$RESTORED_DUMP_LOG"
fi
SH
chmod +x "$FAKE_BIN/sha256sum" "$FAKE_BIN/docker"
export ORIGINAL_DUMP="$ODD_DUMP" RESTORED_DUMP_LOG STAGE_MODE_LOG
CONFIRM_RESTORE=sha-restore POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" SHA_READONLY_API_TOKEN="$READONLY_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" \
  SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$CREDENTIAL_HMAC_KEY_FILE" \
  PATH="$FAKE_BIN:$PATH" TMPDIR="$RESTORE_TEST_DIR" \
  SHA_COMPOSE_FILES="$COMPOSE_FILE" \
  "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$ODD_DUMP" >/dev/null
if [[ "$(< "$RESTORED_DUMP_LOG")" != "original selected dump" ]]; then
  echo "restore validation did not restore the staged dump copy" >&2
  exit 1
fi
if [[ "$(< "$ODD_DUMP")" != "replacement after staging" || "$(< "$STAGE_MODE_LOG")" != "600 700" ]]; then
  echo "restore staging replacement or permissions validation failed" >&2
  exit 1
fi
if compgen -G "$RESTORE_TEST_DIR/sha-restore.*" >/dev/null; then
  echo "restore staging directory was not cleaned up" >&2
  exit 1
fi
rm -f "$FAKE_BIN/sha256sum"
if [[ "${RESTORE_VALIDATION_ONLY:-0}" == "1" ]]; then
  printf 'RESTORE_VALIDATION_OK\n'
  exit 0
fi

compose up -d --wait --wait-timeout 120 postgres
compose build migrate
compose run --rm --no-deps migrate uv run python scripts/verify_postgres_migration_runtime.py
compose up -d --build --wait --wait-timeout 240
compose ps --status running

BASE_URL="http://127.0.0.1:${PORT}"
curl -fsS "$BASE_URL/health" >/dev/null
curl -fsS -H "Authorization: Bearer $READONLY_TOKEN" "$BASE_URL/api/source-packs" >/dev/null
unauthenticated_mutation_status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  --data '{"name":"must-not-create","platform":"linux","channel":"stable","control_plane_url":"https://sha.invalid","policy_mode":"observe"}' \
  "$BASE_URL/api/installer-profiles")
if [[ "$unauthenticated_mutation_status" != "401" ]]; then
  echo "public edge accepted unauthenticated mutation: $unauthenticated_mutation_status" >&2
  exit 1
fi
readonly_mutation_status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $READONLY_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"name":"must-not-create","platform":"linux","channel":"stable","control_plane_url":"https://sha.invalid","policy_mode":"observe"}' \
  "$BASE_URL/api/installer-profiles")
if [[ "$readonly_mutation_status" != "403" ]]; then
  echo "public edge allowed read-only mutation: $readonly_mutation_status" >&2
  exit 1
fi
spoofed_proxy_status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "X-SHA-External-Auth: $EXTERNAL_AUTH_TOKEN" \
  -H "X-SHA-External-Role: readonly" \
  -H "X-SHA-External-User: spoofed@example.test" \
  "$BASE_URL/api/source-packs")
if [[ "$spoofed_proxy_status" != "401" ]]; then
  echo "public edge accepted caller-supplied external-auth headers: $spoofed_proxy_status" >&2
  exit 1
fi

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
assert headers.get("cache-control") == "private, no-store"
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

python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$AGENT_TOKEN" <<'PY'
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib import error, request

base_url, operator_token, agent_token = sys.argv[1:]


def call_json(
    method: str,
    path: str,
    token: str,
    payload: dict[str, object] | None = None,
) -> dict[str, object]:
    data = None if payload is None else json.dumps(payload).encode()
    req = request.Request(base_url + path, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with request.urlopen(req, timeout=30) as response:
            return json.load(response)
    except error.HTTPError as exc:
        raise RuntimeError(
            f"{method} {path} failed with {exc.code}: {exc.read().decode(errors='replace')}"
        ) from exc


endpoint = call_json("POST", "/api/endpoints/enroll", agent_token, {
    "agent_fingerprint": "ha-postgres-lease-race",
    "hostname": "ha-lease-race",
    "platform": "linux",
    "platform_version": "Ubuntu 24.04",
    "agent_version": "ha-e2e",
})
endpoint_id = endpoint["endpoint_id"]
call_json("POST", f"/api/endpoints/{endpoint_id}/heartbeat", agent_token, {
    "agent_version": "ha-e2e",
    "platform_version": "Ubuntu 24.04",
    "platform_profile": "ha-e2e",
    "connectivity_status": "online",
    "declared_capabilities": [
        "heartbeat",
        "apply_control:linux.ssh.password-authentication-disabled",
    ],
    "execution_hooks": {
        "captures_rollback_artifacts": True,
        "reports_execution_results": True,
        "supports_dry_run": True,
    },
})
expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
grant = call_json("POST", "/api/approval-grants", operator_token, {
    "endpoint_ids": [endpoint_id],
    "allowed_actions": ["apply_control"],
    "control_ids": ["linux.ssh.password-authentication-disabled"],
    "troubleshooting_scopes": [],
    "reason": "HA PostgreSQL lease race proof",
    "expires_at": expires_at,
})
action = call_json("POST", "/api/response-actions", operator_token, {
    "endpoint_id": endpoint_id,
    "approval_grant_id": grant["approval_grant_id"],
    "action": "apply_control",
    "control_id": "linux.ssh.password-authentication-disabled",
    "idempotency_key": "ha-postgres-lease-race",
    "reason": "Prove one atomic claim across replicas",
})


def claim() -> dict[str, object]:
    return call_json(
        "POST",
        f"/api/endpoints/{endpoint_id}/response-actions/claim",
        agent_token,
        {},
    )


with ThreadPoolExecutor(max_workers=2) as executor:
    claims = list(executor.map(lambda _: claim(), range(2)))
claimed_items = [item for response in claims for item in response["items"]]
assert len(claimed_items) == 1, claims
claimed = claimed_items[0]
assert claimed["response_action_id"] == action["response_action_id"]
assert claimed["attempt_count"] == 1
result_payload = {
    "status": "succeeded",
    "result_summary": "HA PostgreSQL lease completed once.",
    "lease_token": claimed["lease_token"],
}
completed = call_json(
    "POST",
    f"/api/response-actions/{action['response_action_id']}/result",
    agent_token,
    result_payload,
)
replayed = call_json(
    "POST",
    f"/api/response-actions/{action['response_action_id']}/result",
    agent_token,
    result_payload,
)
assert replayed == completed
print(json.dumps({
    "postgres_atomic_claims": len(claimed_items),
    "response_action_id": action["response_action_id"],
    "result_replay": "idempotent",
}, sort_keys=True))
PY

compose logs --no-color sha-lb | python3 -c '
import re
import sys

upstreams = {
    match.group(1)
    for line in sys.stdin
    if "/response-actions/claim " in line
    for match in [re.search(r"upstream=([^ ]+)", line)]
    if match is not None
}
assert len(upstreams) == 2, f"claim requests reached {len(upstreams)} backend upstream(s)"
print("postgres_claim_backend_replicas=2")
'

BACKUP_DIR="$WORK_DIR/backups"
PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILE" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_READONLY_API_TOKEN="$READONLY_TOKEN" SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" SHA_PUBLIC_PORT="$PORT" BACKUP_DIR="$BACKUP_DIR" \
  SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$CREDENTIAL_HMAC_KEY_FILE" \
  "$ROOT_DIR/scripts/backup-ha-postgres.sh"
BACKUP_FILE=$(ls "$BACKUP_DIR"/sha-postgres-*.dump)
if [[ "$(stat -c '%a' "$BACKUP_DIR")" != "700" || \
      "$(stat -c '%a' "$BACKUP_FILE")" != "600" || \
      "$(stat -c '%a' "$BACKUP_FILE.sha256")" != "600" ]]; then
  echo "backup directory or files have unsafe permissions" >&2
  exit 1
fi
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
CONFIRM_RESTORE=sha-restore PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILE" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" SHA_READONLY_API_TOKEN="$READONLY_TOKEN" SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" SHA_PUBLIC_PORT="$PORT" \
  SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$CREDENTIAL_HMAC_KEY_FILE" \
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
