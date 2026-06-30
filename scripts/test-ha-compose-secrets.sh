#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT=${PROJECT:-sha-ha-secrets-e2e-$(date -u +%Y%m%d%H%M%S)}
WORK_DIR=${WORK_DIR:-$(mktemp -d)}
SECRET_DIR="$WORK_DIR/secrets"
PORT=${SHA_PUBLIC_PORT:-}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-sha-secret-db-password}
OPERATOR_TOKEN=${SHA_API_TOKEN:-secret-operator-token}
READONLY_TOKEN=${SHA_READONLY_API_TOKEN:-secret-readonly-token}
AGENT_TOKEN=${SHA_AGENT_API_TOKEN:-secret-agent-token}
EXTERNAL_AUTH_TOKEN=${SHA_EXTERNAL_AUTH_TRUSTED_TOKEN:-secret-proxy-token}

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
mkdir -p "$SECRET_DIR"
printf '%s' "$POSTGRES_PASSWORD" > "$SECRET_DIR/postgres_password"
printf 'postgresql+psycopg://sha:%s@postgres:5432/sha' "$POSTGRES_PASSWORD" > "$SECRET_DIR/sha_database_url"
printf '%s' "$OPERATOR_TOKEN" > "$SECRET_DIR/sha_api_token"
printf '%s' "$READONLY_TOKEN" > "$SECRET_DIR/sha_readonly_api_token"
printf '%s' "$AGENT_TOKEN" > "$SECRET_DIR/sha_agent_api_token"
printf '%s' "$EXTERNAL_AUTH_TOKEN" > "$SECRET_DIR/sha_external_auth_trusted_token"

compose() {
  POSTGRES_PASSWORD_SECRET_FILE="$SECRET_DIR/postgres_password" \
  SHA_DATABASE_URL_SECRET_FILE="$SECRET_DIR/sha_database_url" \
  SHA_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_api_token" \
  SHA_READONLY_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_readonly_api_token" \
  SHA_AGENT_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_agent_api_token" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN_SECRET_FILE="$SECRET_DIR/sha_external_auth_trusted_token" \
  SHA_PUBLIC_PORT="$PORT" \
  docker compose -p "$PROJECT" \
    -f "$ROOT_DIR/deploy/ha/docker-compose.yml" \
    -f "$ROOT_DIR/deploy/ha/docker-compose.secrets.yml" "$@"
}

cleanup() {
  if [[ "${KEEP_E2E:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
  else
    printf 'kept compose project=%s port=%s work_dir=%s\n' "$PROJECT" "$PORT" "$WORK_DIR"
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
python3 - "$BASE_URL" "$OPERATOR_TOKEN" <<'PY'
import json
import sys
from urllib import request

base_url, token = sys.argv[1:]
req = request.Request(base_url + "/api/installer-profiles", data=json.dumps({
    "name": "HA Secrets Linux E2E",
    "platform": "linux",
    "channel": "stable",
    "control_plane_url": base_url,
    "policy_mode": "approval_required",
}).encode(), method="POST")
req.add_header("Authorization", f"Bearer {token}")
req.add_header("Content-Type", "application/json")
with request.urlopen(req, timeout=30) as response:
    profile = json.load(response)
req = request.Request(base_url + f"/api/installer-profiles/{profile['id']}/artifact", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=30) as response:
    artifact = response.read().decode()
assert '"api_token": "secret-agent-token"' in artifact
print(json.dumps({"profile_id": profile["id"], "agent_secret_embedded": True}, sort_keys=True))
PY
printf 'HA_COMPOSE_SECRETS_E2E_OK port=%s project=%s\n' "$PORT" "$PROJECT"
