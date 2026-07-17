#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT=${PROJECT:-sha-ha-tls-e2e-$(date -u +%Y%m%d%H%M%S)}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-sha-ha-tls-e2e-password}
OPERATOR_TOKEN=${SHA_API_TOKEN:-operator-token}
READONLY_TOKEN=${SHA_READONLY_API_TOKEN:-readonly-token}
AGENT_TOKEN=${SHA_AGENT_API_TOKEN:-agent-token}
EXTERNAL_AUTH_TOKEN=${SHA_EXTERNAL_AUTH_TRUSTED_TOKEN:-proxy-e2e-token}
TLS_PORT=${SHA_TLS_PORT:-}

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
need docker
need python3
need curl
need openssl

COMPOSE_VERSION=$(docker compose version --short)
python3 - "$COMPOSE_VERSION" <<'PY'
import re
import sys

minimum = (2, 24, 4)
match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", sys.argv[1])
if match is None or tuple(map(int, match.groups())) < minimum:
    raise SystemExit(
        f"Docker Compose >=2.24.4 is required for the TLS !override overlay; found {sys.argv[1]}"
    )
PY

WORK_DIR_OWNED=0
if [[ -z "${WORK_DIR:-}" ]]; then
  WORK_DIR=$(mktemp -d)
  WORK_DIR_OWNED=1
fi
CERT_DIR="$WORK_DIR/certs"

pick_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
if [[ -z "$TLS_PORT" ]]; then TLS_PORT=$(pick_port); fi
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" >/dev/null 2>&1

compose() {
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_READONLY_API_TOKEN="$READONLY_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" \
  SHA_TLS_PORT="$TLS_PORT" \
  SHA_TLS_CERT_DIR="$CERT_DIR" \
  docker compose -p "$PROJECT" \
    -f "$ROOT_DIR/deploy/ha/docker-compose.yml" \
    -f "$ROOT_DIR/deploy/ha/docker-compose.tls.yml" "$@"
}

cleanup() {
  if [[ "${KEEP_E2E:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    if [[ "$WORK_DIR_OWNED" == "1" && -d "$WORK_DIR" ]]; then
      find "$WORK_DIR" -xdev -depth -delete
    fi
  else
    printf 'kept compose project=%s tls_port=%s work_dir=%s\n' "$PROJECT" "$TLS_PORT" "$WORK_DIR"
  fi
}
trap cleanup EXIT

compose config --format json | python3 -c '
import json
import sys

config = json.load(sys.stdin)
ports = config["services"]["sha-lb"].get("ports", [])
assert len(ports) == 1, ports
assert ports[0]["target"] == 8443, ports
'
compose up -d --build --wait --wait-timeout 240
compose ps --status running
COMPOSE_FILES_SPEC="$ROOT_DIR/deploy/ha/docker-compose.yml:$ROOT_DIR/deploy/ha/docker-compose.tls.yml"
BACKUP_DIR="$WORK_DIR/backups"
PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILES_SPEC" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" SHA_READONLY_API_TOKEN="$READONLY_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" \
  SHA_TLS_PORT="$TLS_PORT" SHA_TLS_CERT_DIR="$CERT_DIR" BACKUP_DIR="$BACKUP_DIR" \
  "$ROOT_DIR/scripts/backup-ha-postgres.sh"
BACKUP_FILE=$(ls "$BACKUP_DIR"/sha-postgres-*.dump)
CONFIRM_RESTORE=sha-restore PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILES_SPEC" \
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_READONLY_API_TOKEN="$READONLY_TOKEN" SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" SHA_TLS_PORT="$TLS_PORT" \
  SHA_TLS_CERT_DIR="$CERT_DIR" "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$BACKUP_FILE"
if compose exec -T sha-lb nginx -T 2>&1 | grep -Eq 'listen[[:space:]]+8080'; then
  echo "TLS nginx configuration still contains a plaintext listener" >&2
  exit 1
fi
HTTPS_URL="https://127.0.0.1:${TLS_PORT}"
curl --cacert "$CERT_DIR/tls.crt" -fsS "$HTTPS_URL/health" >/dev/null
curl --cacert "$CERT_DIR/tls.crt" -fsS -H "Authorization: Bearer $READONLY_TOKEN" "$HTTPS_URL/api/source-packs" >/dev/null
curl --cacert "$CERT_DIR/tls.crt" -fsSI "$HTTPS_URL/" | grep -qi '^strict-transport-security:'
python3 - "$HTTPS_URL" "$OPERATOR_TOKEN" "$CERT_DIR/tls.crt" <<'PY'
import json
import ssl
import sys
from urllib import request

base_url, token, ca_file = sys.argv[1:]
ctx = ssl.create_default_context(cafile=ca_file)
req = request.Request(base_url + "/api/compliance/evidence", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=30, context=ctx) as response:
    evidence = json.load(response)
assert evidence["source_catalog"]["pack_count"] == 4
assert evidence["source_catalog"]["control_count"] == 17
print(json.dumps({"https": True, "pack_count": 4, "control_count": 17}, sort_keys=True))
PY
printf 'HA_COMPOSE_TLS_E2E_OK https_port=%s project=%s\n' "$TLS_PORT" "$PROJECT"
