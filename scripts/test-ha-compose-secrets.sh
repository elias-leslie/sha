#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT=${PROJECT:-sha-ha-secrets-e2e-$(date -u +%Y%m%d%H%M%S)}
WORK_DIR_OWNED=0
if [[ -z "${WORK_DIR:-}" ]]; then
  WORK_DIR=$(mktemp -d)
  WORK_DIR_OWNED=1
fi
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
  POSTGRES_PASSWORD=overridden-by-postgres-secret-file \
  SHA_API_TOKEN=overridden-by-operator-secret-file \
  SHA_READONLY_API_TOKEN=overridden-by-readonly-secret-file \
  SHA_AGENT_API_TOKEN=overridden-by-agent-secret-file \
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
    if [[ "$WORK_DIR_OWNED" == "1" && -d "$WORK_DIR" ]]; then
      find "$WORK_DIR" -xdev -depth -delete
    fi
  else
    printf 'kept compose project=%s port=%s work_dir=%s\n' "$PROJECT" "$PORT" "$WORK_DIR"
  fi
}
trap cleanup EXIT

compose up -d --build --wait --wait-timeout 240
compose ps --status running
COMPOSE_FILES_SPEC="$ROOT_DIR/deploy/ha/docker-compose.yml:$ROOT_DIR/deploy/ha/docker-compose.secrets.yml"
BACKUP_DIR="$WORK_DIR/backups"
PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILES_SPEC" \
  POSTGRES_PASSWORD=overridden-by-postgres-secret-file \
  SHA_API_TOKEN=overridden-by-operator-secret-file \
  SHA_READONLY_API_TOKEN=overridden-by-readonly-secret-file \
  SHA_AGENT_API_TOKEN=overridden-by-agent-secret-file \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN=overridden-by-external-auth-secret-file \
  POSTGRES_PASSWORD_SECRET_FILE="$SECRET_DIR/postgres_password" \
  SHA_DATABASE_URL_SECRET_FILE="$SECRET_DIR/sha_database_url" \
  SHA_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_api_token" \
  SHA_READONLY_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_readonly_api_token" \
  SHA_AGENT_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_agent_api_token" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN_SECRET_FILE="$SECRET_DIR/sha_external_auth_trusted_token" \
  SHA_PUBLIC_PORT="$PORT" BACKUP_DIR="$BACKUP_DIR" "$ROOT_DIR/scripts/backup-ha-postgres.sh"
BACKUP_FILE=$(ls "$BACKUP_DIR"/sha-postgres-*.dump)
CONFIRM_RESTORE=sha-restore PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILES_SPEC" \
  POSTGRES_PASSWORD=overridden-by-postgres-secret-file \
  SHA_API_TOKEN=overridden-by-operator-secret-file \
  SHA_READONLY_API_TOKEN=overridden-by-readonly-secret-file \
  SHA_AGENT_API_TOKEN=overridden-by-agent-secret-file \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN=overridden-by-external-auth-secret-file \
  POSTGRES_PASSWORD_SECRET_FILE="$SECRET_DIR/postgres_password" \
  SHA_DATABASE_URL_SECRET_FILE="$SECRET_DIR/sha_database_url" \
  SHA_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_api_token" \
  SHA_READONLY_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_readonly_api_token" \
  SHA_AGENT_API_TOKEN_SECRET_FILE="$SECRET_DIR/sha_agent_api_token" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN_SECRET_FILE="$SECRET_DIR/sha_external_auth_trusted_token" \
  SHA_PUBLIC_PORT="$PORT" "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$BACKUP_FILE"
BASE_URL="http://127.0.0.1:${PORT}"
curl -fsS "$BASE_URL/health" >/dev/null
curl -fsS -H "Authorization: Bearer $READONLY_TOKEN" "$BASE_URL/api/source-packs" >/dev/null
spoofed_external_status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "X-SHA-External-Auth: $EXTERNAL_AUTH_TOKEN" \
  -H "X-SHA-External-Role: readonly" \
  -H "X-SHA-External-User: secrets-e2e@example.test" \
  "$BASE_URL/api/source-packs")
if [[ "$spoofed_external_status" != "401" ]]; then
  echo "public edge did not reject external trust headers: $spoofed_external_status" >&2
  exit 1
fi
compose exec -T backend-a uv run python - <<'PY'
from pathlib import Path
from urllib import request

token = Path("/run/secrets/sha_external_auth_trusted_token").read_text().strip()
req = request.Request("http://127.0.0.1:8010/api/source-packs", method="GET")
req.add_header("X-SHA-External-Auth", token)
req.add_header("X-SHA-External-Role", "readonly")
req.add_header("X-SHA-External-User", "secrets-e2e@example.test")
with request.urlopen(req, timeout=30) as response:
    assert response.status == 200
PY
python3 - "$BASE_URL" "$OPERATOR_TOKEN" "$AGENT_TOKEN" <<'PY'
import json
import sys
from urllib import request

base_url, token, agent_token = sys.argv[1:]
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
    assert response.headers["Cache-Control"] == "private, no-store"
assert f'"api_token": "{agent_token}"' in artifact
print(json.dumps({"profile_id": profile["id"], "agent_secret_embedded": True}, sort_keys=True))
PY
printf 'HA_COMPOSE_SECRETS_E2E_OK port=%s project=%s\n' "$PORT" "$PROJECT"
