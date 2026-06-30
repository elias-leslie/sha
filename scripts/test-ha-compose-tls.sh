#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROJECT=${PROJECT:-sha-ha-tls-e2e-$(date -u +%Y%m%d%H%M%S)}
WORK_DIR=${WORK_DIR:-$(mktemp -d)}
CERT_DIR="$WORK_DIR/certs"
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-sha-ha-tls-e2e-password}
OPERATOR_TOKEN=${SHA_API_TOKEN:-operator-token}
READONLY_TOKEN=${SHA_READONLY_API_TOKEN:-readonly-token}
AGENT_TOKEN=${SHA_AGENT_API_TOKEN:-agent-token}
EXTERNAL_AUTH_TOKEN=${SHA_EXTERNAL_AUTH_TRUSTED_TOKEN:-proxy-e2e-token}
HTTP_PORT=${SHA_PUBLIC_PORT:-}
TLS_PORT=${SHA_TLS_PORT:-}

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 1; }
}
need docker
need python3
need curl
need openssl

pick_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
if [[ -z "$HTTP_PORT" ]]; then HTTP_PORT=$(pick_port); fi
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
  SHA_PUBLIC_PORT="$HTTP_PORT" \
  SHA_TLS_PORT="$TLS_PORT" \
  SHA_TLS_CERT_DIR="$CERT_DIR" \
  docker compose -p "$PROJECT" \
    -f "$ROOT_DIR/deploy/ha/docker-compose.yml" \
    -f "$ROOT_DIR/deploy/ha/docker-compose.tls.yml" "$@"
}

cleanup() {
  if [[ "${KEEP_E2E:-0}" != "1" ]]; then
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
  else
    printf 'kept compose project=%s http_port=%s tls_port=%s work_dir=%s\n' "$PROJECT" "$HTTP_PORT" "$TLS_PORT" "$WORK_DIR"
  fi
}
trap cleanup EXIT

compose up -d --build --wait --wait-timeout 240
compose ps --status running
HTTPS_URL="https://127.0.0.1:${TLS_PORT}"
curl -kfsS "$HTTPS_URL/health" >/dev/null
curl -kfsS -H "Authorization: Bearer $READONLY_TOKEN" "$HTTPS_URL/api/source-packs" >/dev/null
curl -kfsSI "$HTTPS_URL/" | grep -qi '^strict-transport-security:'
python3 - "$HTTPS_URL" "$OPERATOR_TOKEN" <<'PY'
import json
import ssl
import sys
from urllib import request

base_url, token = sys.argv[1:]
ctx = ssl._create_unverified_context()
req = request.Request(base_url + "/api/compliance/evidence", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=30, context=ctx) as response:
    evidence = json.load(response)
assert evidence["source_catalog"]["pack_count"] == 4
assert evidence["source_catalog"]["control_count"] == 17
print(json.dumps({"https": True, "pack_count": 4, "control_count": 17}, sort_keys=True))
PY
printf 'HA_COMPOSE_TLS_E2E_OK https_port=%s project=%s\n' "$TLS_PORT" "$PROJECT"
