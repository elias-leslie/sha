#!/usr/bin/env bash
set -euo pipefail
umask 077

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
need go

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
CREDENTIAL_HMAC_KEY_FILE="$WORK_DIR/credential-hmac-key"
AGENT_DIR="$WORK_DIR/agent"
AGENT_BIN="$AGENT_DIR/sha-agent"
AGENT_CONFIG="$AGENT_DIR/agent-config.json"
AGENT_STATE="$AGENT_DIR/agent-state.json"
CA_CERT="$CERT_DIR/ca.crt"
WRONG_CA_CERT="$CERT_DIR/wrong-ca.crt"
OPERATOR_TOKEN_FILE="$WORK_DIR/operator-token"
READONLY_TOKEN_FILE="$WORK_DIR/readonly-token"
OPERATOR_CURL_CONFIG="$WORK_DIR/operator.curlrc"
READONLY_CURL_CONFIG="$WORK_DIR/readonly.curlrc"

pick_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}
if [[ -z "$TLS_PORT" ]]; then TLS_PORT=$(pick_port); fi
mkdir -p "$CERT_DIR" "$AGENT_DIR"
chmod 700 "$CERT_DIR" "$AGENT_DIR"
head -c 48 /dev/urandom > "$CREDENTIAL_HMAC_KEY_FILE"
chmod 600 "$CREDENTIAL_HMAC_KEY_FILE"
printf '%s' "$OPERATOR_TOKEN" > "$OPERATOR_TOKEN_FILE"
printf '%s' "$READONLY_TOKEN" > "$READONLY_TOKEN_FILE"
chmod 600 "$OPERATOR_TOKEN_FILE" "$READONLY_TOKEN_FILE"

write_curl_auth_config() {
  local output_path=$1
  local token_path=$2
  {
    printf 'header = "Authorization: Bearer '
    tr -d '\r\n' < "$token_path"
    printf '"\n'
  } > "$output_path"
  chmod 600 "$output_path"
}
write_curl_auth_config "$OPERATOR_CURL_CONFIG" "$OPERATOR_TOKEN_FILE"
write_curl_auth_config "$READONLY_CURL_CONFIG" "$READONLY_TOKEN_FILE"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj "/CN=SHA TLS E2E private CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$CERT_DIR/ca.key" -out "$CA_CERT" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
  -subj "/CN=localhost" \
  -keyout "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.csr" >/dev/null 2>&1
printf '%s\n' \
  'subjectAltName=DNS:localhost' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' > "$CERT_DIR/tls.ext"
openssl x509 -req -sha256 -days 1 \
  -in "$CERT_DIR/tls.csr" \
  -CA "$CA_CERT" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
  -extfile "$CERT_DIR/tls.ext" -out "$CERT_DIR/tls.crt" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -subj "/CN=SHA TLS E2E wrong CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -keyout "$CERT_DIR/wrong-ca.key" -out "$WRONG_CA_CERT" >/dev/null 2>&1
chmod 600 "$CERT_DIR"/*

compose() {
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_READONLY_API_TOKEN="$READONLY_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" \
  SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$CREDENTIAL_HMAC_KEY_FILE" \
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
if compose exec -T sha-lb nginx -T 2>&1 | grep -Eq 'listen[[:space:]]+8080'; then
  echo "TLS nginx configuration still contains a plaintext listener" >&2
  exit 1
fi
HTTPS_URL="https://localhost:${TLS_PORT}"

operator_api() {
  curl -q --config "$OPERATOR_CURL_CONFIG" --cacert "$CA_CERT" "$@"
}

curl --cacert "$CA_CERT" -fsS "$HTTPS_URL/health" >/dev/null
curl -q --config "$READONLY_CURL_CONFIG" --cacert "$CA_CERT" -fsS \
  "$HTTPS_URL/api/source-packs" >/dev/null
curl --cacert "$CA_CERT" -fsSI "$HTTPS_URL/" | grep -qi '^strict-transport-security:'
python3 - "$HTTPS_URL" "$OPERATOR_TOKEN_FILE" "$CA_CERT" <<'PY'
import json
import ssl
import sys
from urllib import request

base_url, token_file, ca_file = sys.argv[1:]
with open(token_file, encoding="utf-8") as stream:
    token = stream.read().strip()
ctx = ssl.create_default_context(cafile=ca_file)
req = request.Request(base_url + "/api/compliance/evidence", method="GET")
req.add_header("Authorization", f"Bearer {token}")
with request.urlopen(req, timeout=30, context=ctx) as response:
    evidence = json.load(response)
assert evidence["source_catalog"]["pack_count"] == 4
assert evidence["source_catalog"]["control_count"] == 17
print(json.dumps({"https": True, "pack_count": 4, "control_count": 17}, sort_keys=True))
PY

go -C "$ROOT_DIR/agent" build -trimpath -o "$AGENT_BIN" ./cmd/sha-agent

CLIENT_REQUEST="$WORK_DIR/client-request.json"
CLIENT_RESPONSE="$WORK_DIR/client-response.json"
LOCATION_REQUEST="$WORK_DIR/location-request.json"
LOCATION_RESPONSE="$WORK_DIR/location-response.json"
TOKEN_REQUEST="$WORK_DIR/enrollment-token-request.json"
TOKEN_RESPONSE="$WORK_DIR/enrollment-token-response.json"
TOKEN_HEADERS="$WORK_DIR/enrollment-token-headers"
ENROLLMENT_TOKEN_FILE="$WORK_DIR/enrollment-token"
TOKEN_LIST_RESPONSE="$WORK_DIR/enrollment-token-list.json"
ENDPOINT_RESPONSE="$WORK_DIR/endpoint-response.json"
REVOKE_RESPONSE="$WORK_DIR/revoke-response.json"
STATE_BEFORE_ROTATION="$AGENT_DIR/state-before-rotation.json"

printf '%s\n' '{"key":"tls-e2e","name":"TLS E2E"}' > "$CLIENT_REQUEST"
operator_api -fsS -H 'Content-Type: application/json' \
  --data-binary "@$CLIENT_REQUEST" -o "$CLIENT_RESPONSE" "$HTTPS_URL/api/clients"
CLIENT_ID=$(python3 - "$CLIENT_RESPONSE" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["client_id"])
PY
)

printf '%s\n' '{"key":"tls-site","name":"TLS Site"}' > "$LOCATION_REQUEST"
operator_api -fsS -H 'Content-Type: application/json' \
  --data-binary "@$LOCATION_REQUEST" -o "$LOCATION_RESPONSE" \
  "$HTTPS_URL/api/clients/$CLIENT_ID/locations"
LOCATION_ID=$(python3 - "$LOCATION_RESPONSE" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["location_id"])
PY
)

python3 - "$TOKEN_REQUEST" "$CLIENT_ID" "$LOCATION_ID" <<'PY'
import json
import os
import sys

path, client_id, location_id = sys.argv[1:]
payload = {
    "client_id": client_id,
    "location_id": location_id,
    "platform": "linux",
    "approval_policy": "approved",
    "expires_in_minutes": 15,
    "max_uses": 1,
}
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, separators=(",", ":"))
PY
TOKEN_STATUS=$(operator_api -sS -H 'Content-Type: application/json' \
  --data-binary "@$TOKEN_REQUEST" -D "$TOKEN_HEADERS" -o "$TOKEN_RESPONSE" \
  -w '%{http_code}' "$HTTPS_URL/api/enrollment-tokens")
if [[ "$TOKEN_STATUS" != "201" ]]; then
  echo "enrollment token creation returned HTTP $TOKEN_STATUS" >&2
  exit 1
fi
python3 - "$TOKEN_RESPONSE" "$TOKEN_HEADERS" "$ENROLLMENT_TOKEN_FILE" <<'PY'
import json
import os
import sys

response_path, header_path, token_path = sys.argv[1:]
with open(response_path, encoding="utf-8") as stream:
    response = json.load(stream)
token = response["token"]
assert token.startswith("sha_enroll.et_")
with open(header_path, encoding="utf-8") as stream:
    headers = stream.read().lower()
assert "cache-control: private, no-store" in headers
descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    stream.write(token)
PY

python3 - "$AGENT_CONFIG" "$ENROLLMENT_TOKEN_FILE" "$HTTPS_URL" "$AGENT_STATE" "$CA_CERT" <<'PY'
import json
import os
import sys

config_path, token_path, base_url, state_path, ca_file = sys.argv[1:]
with open(token_path, encoding="utf-8") as stream:
    enrollment_token = stream.read().strip()
payload = {
    "control_plane_url": base_url,
    "enrollment_token": enrollment_token,
    "state_path": state_path,
    "ca_bundle_path": ca_file,
    "agent_version": "sha-go-agent-tls-e2e",
}
descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(payload, stream, separators=(",", ":"))
PY

"$AGENT_BIN" -config "$AGENT_CONFIG" -action run \
  > "$AGENT_DIR/bootstrap.out" 2> "$AGENT_DIR/bootstrap.err"
"$AGENT_BIN" -config "$AGENT_CONFIG" -action status \
  > "$AGENT_DIR/status-before-rotation.json" 2> "$AGENT_DIR/status-before-rotation.err"
python3 - "$AGENT_CONFIG" "$AGENT_STATE" "$AGENT_DIR/status-before-rotation.json" <<'PY'
import json
import os
import stat
import sys

config_path, state_path, status_path = sys.argv[1:]
with open(config_path, encoding="utf-8") as stream:
    config = json.load(stream)
assert not config.get("enrollment_token")
assert not config.get("api_token")
with open(status_path, encoding="utf-8") as stream:
    status = json.load(stream)
assert status["endpoint_status"] == "active"
assert status["credential_status"] == "active"
assert status["protocol_version"] == "sha-agent-v1"
for path in (config_path, state_path):
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600, path
PY
ENDPOINT_ID=$(python3 - "$AGENT_DIR/status-before-rotation.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["endpoint_id"])
PY
)
INITIAL_CREDENTIAL_ID=$(python3 - "$AGENT_DIR/status-before-rotation.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["credential_id"])
PY
)

"$AGENT_BIN" -config "$AGENT_CONFIG" -action run \
  > "$AGENT_DIR/heartbeat.out" 2> "$AGENT_DIR/heartbeat.err"
operator_api -fsS -o "$ENDPOINT_RESPONSE" "$HTTPS_URL/api/endpoints/$ENDPOINT_ID"
python3 - "$ENDPOINT_RESPONSE" "$INITIAL_CREDENTIAL_ID" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    endpoint = json.load(stream)
assert endpoint["status"] == "active"
assert endpoint["connectivity_status"] == "online"
assert endpoint["last_heartbeat_at"]
assert endpoint["credential_mode"] == "device"
assert endpoint["protocol_version"] == "sha-agent-v1"
assert endpoint["active_credential"]["credential_id"] == sys.argv[2]
assert endpoint["latest_posture_summary"] is not None
PY

cp "$AGENT_STATE" "$STATE_BEFORE_ROTATION"
chmod 600 "$STATE_BEFORE_ROTATION"
"$AGENT_BIN" -config "$AGENT_CONFIG" -action rotate-credential \
  > "$AGENT_DIR/rotate.json" 2> "$AGENT_DIR/rotate.err"
ROTATED_CREDENTIAL_ID=$(python3 - "$AGENT_DIR/rotate.json" "$INITIAL_CREDENTIAL_ID" "$ENDPOINT_ID" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    rotated = json.load(stream)
assert rotated["credential_id"] != sys.argv[2]
assert rotated["endpoint_id"] == sys.argv[3]
assert rotated["credential_status"] == "active"
print(rotated["credential_id"])
PY
)
"$AGENT_BIN" -config "$AGENT_CONFIG" -action status \
  > "$AGENT_DIR/status-after-rotation.json" 2> "$AGENT_DIR/status-after-rotation.err"
python3 - "$AGENT_DIR/status-after-rotation.json" "$ROTATED_CREDENTIAL_ID" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    status = json.load(stream)
assert status["credential_id"] == sys.argv[2]
assert status["credential_status"] == "active"
PY

COMPOSE_FILES_SPEC="$ROOT_DIR/deploy/ha/docker-compose.yml:$ROOT_DIR/deploy/ha/docker-compose.tls.yml"
BACKUP_DIR="$WORK_DIR/backups"
PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILES_SPEC" POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$OPERATOR_TOKEN" SHA_READONLY_API_TOKEN="$READONLY_TOKEN" \
  SHA_AGENT_API_TOKEN="$AGENT_TOKEN" SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" \
  SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$CREDENTIAL_HMAC_KEY_FILE" \
  SHA_TLS_PORT="$TLS_PORT" SHA_TLS_CERT_DIR="$CERT_DIR" BACKUP_DIR="$BACKUP_DIR" \
  "$ROOT_DIR/scripts/backup-ha-postgres.sh"
BACKUP_FILE=$(ls "$BACKUP_DIR"/sha-postgres-*.dump)
CONFIRM_RESTORE=sha-restore PROJECT="$PROJECT" SHA_COMPOSE_FILES="$COMPOSE_FILES_SPEC" \
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" SHA_API_TOKEN="$OPERATOR_TOKEN" \
  SHA_READONLY_API_TOKEN="$READONLY_TOKEN" SHA_AGENT_API_TOKEN="$AGENT_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$EXTERNAL_AUTH_TOKEN" SHA_TLS_PORT="$TLS_PORT" \
  SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$CREDENTIAL_HMAC_KEY_FILE" \
  SHA_TLS_CERT_DIR="$CERT_DIR" "$ROOT_DIR/scripts/restore-ha-postgres.sh" "$BACKUP_FILE"
compose ps --status running

"$AGENT_BIN" -config "$AGENT_CONFIG" -action run \
  > "$AGENT_DIR/reconnect.out" 2> "$AGENT_DIR/reconnect.err"
"$AGENT_BIN" -config "$AGENT_CONFIG" -action status \
  > "$AGENT_DIR/status-after-reconnect.json" 2> "$AGENT_DIR/status-after-reconnect.err"
operator_api -fsS -o "$ENDPOINT_RESPONSE" "$HTTPS_URL/api/endpoints/$ENDPOINT_ID"
python3 - "$AGENT_DIR/status-after-reconnect.json" "$ENDPOINT_RESPONSE" "$ROTATED_CREDENTIAL_ID" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    status = json.load(stream)
with open(sys.argv[2], encoding="utf-8") as stream:
    endpoint = json.load(stream)
assert status["credential_id"] == sys.argv[3]
assert status["endpoint_status"] == "active"
assert endpoint["active_credential"]["credential_id"] == sys.argv[3]
assert endpoint["last_heartbeat_at"]
PY

write_agent_variant() {
  local output_path=$1
  local control_plane_url=$2
  local ca_bundle_path=$3
  python3 - "$AGENT_CONFIG" "$output_path" "$control_plane_url" "$ca_bundle_path" <<'PY'
import json
import os
import sys

source, destination, control_plane_url, ca_bundle_path = sys.argv[1:]
with open(source, encoding="utf-8") as stream:
    config = json.load(stream)
config["control_plane_url"] = control_plane_url
config["ca_bundle_path"] = ca_bundle_path
descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(config, stream, separators=(",", ":"))
PY
}

expect_agent_failure() {
  local label=$1
  local config_path=$2
  local expected_pattern=$3
  if "$AGENT_BIN" -config "$config_path" -action status \
    > "$AGENT_DIR/$label.out" 2> "$AGENT_DIR/$label.err"; then
    echo "agent unexpectedly accepted $label" >&2
    exit 1
  fi
  if ! grep -Eqi "$expected_pattern" "$AGENT_DIR/$label.err"; then
    echo "agent $label failure did not report the expected transport/auth cause" >&2
    exit 1
  fi
}

WRONG_CA_CONFIG="$AGENT_DIR/wrong-ca-config.json"
WRONG_HOST_CONFIG="$AGENT_DIR/wrong-host-config.json"
PLAIN_HTTP_CONFIG="$AGENT_DIR/plain-http-config.json"
write_agent_variant "$WRONG_CA_CONFIG" "$HTTPS_URL" "$WRONG_CA_CERT"
write_agent_variant "$WRONG_HOST_CONFIG" "https://127.0.0.1:$TLS_PORT" "$CA_CERT"
write_agent_variant "$PLAIN_HTTP_CONFIG" "http://localhost:$TLS_PORT" "$CA_CERT"
expect_agent_failure "wrong-ca" "$WRONG_CA_CONFIG" 'x509|certificate|unknown authority'
expect_agent_failure "wrong-host" "$WRONG_HOST_CONFIG" 'x509|certificate|hostname|127\.0\.0\.1'
expect_agent_failure "plain-http-policy" "$PLAIN_HTTP_CONFIG" 'requires HTTPS'
if curl -q --max-time 5 -fsS "http://localhost:$TLS_PORT/health" \
  > "$WORK_DIR/plain-http.out" 2> "$WORK_DIR/plain-http.err"; then
  echo "TLS edge unexpectedly served a plaintext HTTP health response" >&2
  exit 1
fi

operator_api -fsS -X POST -o "$REVOKE_RESPONSE" \
  "$HTTPS_URL/api/device-credentials/$ROTATED_CREDENTIAL_ID/revoke"
python3 - "$REVOKE_RESPONSE" "$ROTATED_CREDENTIAL_ID" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    revoked = json.load(stream)
assert revoked["credential_id"] == sys.argv[2]
assert revoked["status"] == "revoked"
assert revoked["revoked_at"]
PY
expect_agent_failure "revoked-credential" "$AGENT_CONFIG" 'HTTP 401'

operator_api -fsS -o "$TOKEN_LIST_RESPONSE" "$HTTPS_URL/api/enrollment-tokens"
python3 - \
  "$ENROLLMENT_TOKEN_FILE" "$STATE_BEFORE_ROTATION" "$AGENT_STATE" "$TOKEN_LIST_RESPONSE" \
  "$AGENT_CONFIG" "$WRONG_CA_CONFIG" "$WRONG_HOST_CONFIG" "$PLAIN_HTTP_CONFIG" \
  "$ENDPOINT_RESPONSE" "$REVOKE_RESPONSE" \
  "$AGENT_DIR/bootstrap.out" "$AGENT_DIR/bootstrap.err" \
  "$AGENT_DIR/heartbeat.out" "$AGENT_DIR/heartbeat.err" \
  "$AGENT_DIR/rotate.json" "$AGENT_DIR/rotate.err" \
  "$AGENT_DIR/reconnect.out" "$AGENT_DIR/reconnect.err" \
  "$AGENT_DIR/wrong-ca.out" "$AGENT_DIR/wrong-ca.err" \
  "$AGENT_DIR/wrong-host.out" "$AGENT_DIR/wrong-host.err" \
  "$AGENT_DIR/plain-http-policy.out" "$AGENT_DIR/plain-http-policy.err" \
  "$AGENT_DIR/revoked-credential.out" "$AGENT_DIR/revoked-credential.err" <<'PY'
import json
import sys

token_path, old_state_path, state_path, token_list_path, *safe_paths = sys.argv[1:]
with open(token_path, "rb") as stream:
    enrollment_token = stream.read().strip()
with open(old_state_path, encoding="utf-8") as stream:
    old_secret = json.load(stream)["credential"]["credential_secret"].encode()
with open(state_path, encoding="utf-8") as stream:
    new_secret = json.load(stream)["credential"]["credential_secret"].encode()
with open(token_list_path, encoding="utf-8") as stream:
    token_list = json.load(stream)

def assert_no_token_field(value):
    if isinstance(value, dict):
        assert "token" not in value
        for child in value.values():
            assert_no_token_field(child)
    elif isinstance(value, list):
        for child in value:
            assert_no_token_field(child)

assert_no_token_field(token_list)
for path in safe_paths:
    with open(path, "rb") as stream:
        content = stream.read()
    for secret in (enrollment_token, old_secret, new_secret):
        assert secret not in content, path
PY

printf 'HA_COMPOSE_TLS_E2E_OK https_port=%s project=%s endpoint_id=%s lifecycle=bootstrap,heartbeat,rotate,restore,reconnect,revoke\n' \
  "$TLS_PORT" "$PROJECT" "$ENDPOINT_ID"
