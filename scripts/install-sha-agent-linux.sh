#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
DESTDIR=${DESTDIR:-}
BINARY_PATH=/usr/local/sbin/sha-agent
CONFIG_PATH=/etc/sha/agent-config.json
STATE_PATH=/etc/sha/agent-state.json
CA_PATH=/etc/sha/ca-bundle.pem
SYSTEMD_DIR=/etc/systemd/system
SKIP_SYSTEMD=${SKIP_SYSTEMD:-0}
SKIP_ENROLLMENT_CHECK=${SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK:-0}
OPERATION=install
CONTROL_PLANE_URL=""
PROFILE_ID=generic
TOKEN_VALUE=""
TOKEN_FILE=""
TOKEN_STDIN=0
CA_BUNDLE=""
BOOTSTRAP_MANIFEST=""
EMBEDDED_BOOTSTRAP=0
TRUST_POLICY=""
ALLOW_INSECURE_LOOPBACK=0
PURGE_STATE=0
JSON=0

die() { printf '%s\n' "$1" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage:
  install-linux.sh --trust-policy FILE --control-plane-url URL \
    (--enrollment-token TOKEN | --enrollment-token-file FILE | --enrollment-token-stdin) [options]
  install-linux.sh --trust-policy FILE --bootstrap-manifest FILE [options]
  install-linux.sh --operation repair --trust-policy FILE [--json]
  install-linux.sh --operation uninstall [--purge-state] [--json]

Options:
  --profile-id ID              generic package profile label (default: generic)
  --ca-bundle FILE             private CA PEM copied to the protected SHA directory
  --allow-insecure-loopback    allow explicit HTTP only for exact loopback development
  --json                       one-line machine-readable success result

Passing --enrollment-token exposes the short-lived token to process listings.
Prefer --enrollment-token-file (0600) or --enrollment-token-stdin.
EOF
}

while (($#)); do
  case "$1" in
    --operation) OPERATION=${2:?missing value for --operation}; shift 2 ;;
    --control-plane-url) CONTROL_PLANE_URL=${2:?missing value for --control-plane-url}; shift 2 ;;
    --profile-id) PROFILE_ID=${2:?missing value for --profile-id}; shift 2 ;;
    --enrollment-token)
      TOKEN_VALUE=${2:?missing value for --enrollment-token}
      printf '%s\n' 'WARNING: --enrollment-token is visible in process listings; prefer file or stdin input.' >&2
      shift 2
      ;;
    --enrollment-token-file) TOKEN_FILE=${2:?missing value for --enrollment-token-file}; shift 2 ;;
    --enrollment-token-stdin) TOKEN_STDIN=1; shift ;;
    --ca-bundle) CA_BUNDLE=${2:?missing value for --ca-bundle}; shift 2 ;;
    --bootstrap-manifest) BOOTSTRAP_MANIFEST=${2:?missing value for --bootstrap-manifest}; shift 2 ;;
    --trust-policy) TRUST_POLICY=${2:?missing value for --trust-policy}; shift 2 ;;
    --allow-insecure-loopback) ALLOW_INSECURE_LOOPBACK=1; shift ;;
    --purge-state) PURGE_STATE=1; shift ;;
    --json) JSON=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown SHA agent installer argument: $1" ;;
  esac
done
[[ "$OPERATION" == install || "$OPERATION" == repair || "$OPERATION" == uninstall ]] || \
  die "--operation must be install, repair, or uninstall"

reject_symlink_components() {
  local path=$1 label=$2 relative current="" component
  relative=${path#/}
  local -a components
  local IFS=/
  read -r -a components <<< "$relative"
  for component in "${components[@]}"; do
    current="$current/$component"
    [[ ! -L "$current" ]] || die "$label contains a symlink component: $current"
  done
}
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
owner_of() { stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"; }
assert_secure_system_directory() {
  local path=$1 mode
  [[ -d "$path" ]] || die "required system directory is missing: $path"
  [[ "$(owner_of "$path")" == 0 ]] || die "system directory must be owned by root: $path"
  mode=$(mode_of "$path")
  (( (8#$mode & 0022) == 0 )) || die "system directory must not be group- or world-writable: $path"
}

INSTALL_UID=$(id -u)
if [[ -z "$DESTDIR" && "$INSTALL_UID" -ne 0 ]]; then die "sha-agent installation requires root"; fi
if [[ -n "$DESTDIR" ]]; then
  [[ "$DESTDIR" == /* && "$DESTDIR" != / && "$DESTDIR" != */ && "$DESTDIR" != *$'\n'* && "$DESTDIR" != *$'\r'* ]] || \
    die "DESTDIR must be a dedicated absolute staging directory"
  case "/${DESTDIR#/}/" in *'/../'*|*'/./'*|'//'*) die "DESTDIR must be normalized" ;; esac
  reject_symlink_components "$DESTDIR" DESTDIR
  [[ ! -e "$DESTDIR" || -d "$DESTDIR" ]] || die "DESTDIR exists and is not a directory"
  [[ -e "$DESTDIR" ]] || install -d -m 0755 "$DESTDIR"
fi

BINARY_DIR="${DESTDIR}${BINARY_PATH%/*}"
STATE_DIR="${DESTDIR}${CONFIG_PATH%/*}"
UNIT_DIR="${DESTDIR}${SYSTEMD_DIR}"
BINARY_TARGET="${DESTDIR}${BINARY_PATH}"
CONFIG_TARGET="${DESTDIR}${CONFIG_PATH}"
STATE_TARGET="${DESTDIR}${STATE_PATH}"
CA_TARGET="${DESTDIR}${CA_PATH}"
UNIT_TARGET="$UNIT_DIR/sha-agent.service"
for path in "$BINARY_DIR" "$STATE_DIR" "$UNIT_DIR" "$BINARY_TARGET" "$CONFIG_TARGET" "$STATE_TARGET" "$CA_TARGET" "$UNIT_TARGET"; do
  reject_symlink_components "$path" "SHA install path"
done
if [[ "$SKIP_SYSTEMD" == 1 && -z "$DESTDIR" ]]; then
  die "SKIP_SYSTEMD=1 is allowed only with DESTDIR test staging"
fi
if [[ -z "$DESTDIR" ]] && ! command -v systemctl >/dev/null 2>&1; then
  die "systemd is required for a real Linux SHA agent install or uninstall"
fi

if [[ "$OPERATION" == uninstall ]]; then
  [[ -z "$TRUST_POLICY$CONTROL_PLANE_URL$TOKEN_VALUE$TOKEN_FILE$BOOTSTRAP_MANIFEST$CA_BUNDLE" ]] || \
    die "uninstall does not accept enrollment, trust, URL, or CA inputs"
  if [[ "$SKIP_SYSTEMD" != 1 && -z "$DESTDIR" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now sha-agent.service >/dev/null 2>&1 || true
  fi
  find "$UNIT_TARGET" "$BINARY_TARGET" -maxdepth 0 -type f -delete 2>/dev/null || true
  if [[ "$PURGE_STATE" == 1 ]]; then
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" ]] || die "cannot purge missing or unsafe SHA state directory"
    find "$STATE_DIR" -xdev -depth -delete
  fi
  if [[ "$SKIP_SYSTEMD" != 1 && -z "$DESTDIR" ]] && command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload; fi
  if [[ "$JSON" == 1 ]]; then
    printf '{"operation":"uninstall","purged_state":%s,"status":"ok"}\n' "$([[ "$PURGE_STATE" == 1 ]] && printf true || printf false)"
  else printf 'uninstalled sha-agent; state_preserved=%s\n' "$([[ "$PURGE_STATE" == 1 ]] && printf false || printf true)"; fi
  exit 0
fi

[[ "$PURGE_STATE" == 0 ]] || die "--purge-state is valid only with uninstall"
[[ -n "$TRUST_POLICY" ]] || die "--trust-policy is required for install and repair"
[[ -x "$SCRIPT_DIR/verify-release.sh" && -f "$SCRIPT_DIR/sha-agent-package.py" ]] || \
  die "signed release verifier files are missing"
"$SCRIPT_DIR/verify-release.sh" --trust-policy "$TRUST_POLICY" >/dev/null

[[ -d "$STATE_DIR" || ! -e "$STATE_DIR" ]] || die "SHA state path is not a directory"
if [[ "$OPERATION" == repair ]]; then
  [[ -f "$CONFIG_TARGET" && ! -L "$CONFIG_TARGET" ]] || die "repair requires an existing protected SHA config"
  existing_mode=$(mode_of "$CONFIG_TARGET")
  (( (8#$existing_mode & 0077) == 0 )) || die "existing SHA config must not grant group or other permissions"
  [[ "$(owner_of "$CONFIG_TARGET")" == 0 || "$(owner_of "$CONFIG_TARGET")" == "$INSTALL_UID" ]] || \
    die "existing SHA config has an untrusted owner"
  [[ -z "$CONTROL_PLANE_URL$TOKEN_VALUE$TOKEN_FILE$BOOTSTRAP_MANIFEST$CA_BUNDLE" && "$TOKEN_STDIN" == 0 ]] || \
    die "repair preserves identity/config and does not accept bootstrap inputs"
  python3 "$SCRIPT_DIR/sha-agent-package.py" validate-config --config "$CONFIG_TARGET"
fi

FRESH=0
[[ -e "$CONFIG_TARGET" ]] || FRESH=1
if [[ "$OPERATION" == install && "$FRESH" == 0 ]]; then
  [[ -f "$CONFIG_TARGET" && ! -L "$CONFIG_TARGET" ]] || die "existing SHA config is not a regular file"
  [[ -z "$CONTROL_PLANE_URL$TOKEN_VALUE$TOKEN_FILE$BOOTSTRAP_MANIFEST$CA_BUNDLE" && "$TOKEN_STDIN" == 0 ]] || \
    die "existing install cannot be re-enrolled; use repair or uninstall --purge-state first"
  python3 "$SCRIPT_DIR/sha-agent-package.py" validate-config --config "$CONFIG_TARGET"
fi
if [[ "$SKIP_ENROLLMENT_CHECK" == 1 && -z "$DESTDIR" ]]; then
  die "SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 is allowed only with DESTDIR test staging"
fi

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sha-agent-install.XXXXXX")
SERVICE_STOPPED_FOR_INSTALL=0
cleanup() {
  find "$TEMP_DIR" -xdev -depth -delete 2>/dev/null || true
  if [[ "$SERVICE_STOPPED_FOR_INSTALL" == 1 ]]; then systemctl start sha-agent.service >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
umask 077
CONFIG_SOURCE=""
CA_SOURCE=""

if [[ "$FRESH" == 1 ]]; then
  if [[ -z "$BOOTSTRAP_MANIFEST" && -f "$SCRIPT_DIR/bootstrap-manifest.json" ]]; then
    BOOTSTRAP_MANIFEST="$SCRIPT_DIR/bootstrap-manifest.json"
    EMBEDDED_BOOTSTRAP=1
  fi
  source_count=0
  [[ -z "$TOKEN_VALUE" ]] || ((source_count+=1))
  [[ -z "$TOKEN_FILE" ]] || ((source_count+=1))
  [[ "$TOKEN_STDIN" == 0 ]] || ((source_count+=1))
  if [[ -n "$BOOTSTRAP_MANIFEST" ]]; then
    [[ "$source_count" == 0 && -z "$CONTROL_PLANE_URL$CA_BUNDLE" && "$ALLOW_INSECURE_LOOPBACK" == 0 ]] || \
      die "signed bootstrap mode cannot be combined with generic enrollment inputs"
    BOOTSTRAP_SIGNATURE="$BOOTSTRAP_MANIFEST.sig"
    [[ -f "$BOOTSTRAP_MANIFEST" && ! -L "$BOOTSTRAP_MANIFEST" && -f "$BOOTSTRAP_SIGNATURE" && ! -L "$BOOTSTRAP_SIGNATURE" ]] || \
      die "signed bootstrap manifest or detached signature is missing"
    bootstrap_mode=$(mode_of "$BOOTSTRAP_MANIFEST")
    (( (8#$bootstrap_mode & 0077) == 0 )) || die "token-bearing bootstrap manifest must not grant group or other permissions"
    bootstrap_owner=$(owner_of "$BOOTSTRAP_MANIFEST")
    [[ "$bootstrap_owner" == 0 || "$bootstrap_owner" == "$INSTALL_UID" ]] || die "bootstrap manifest has an untrusted owner"
    PUBLIC_KEY=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$BOOTSTRAP_MANIFEST" --trust-policy "$TRUST_POLICY" --field public_key)
    EXPECTED_IDENTITY=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$BOOTSTRAP_MANIFEST" --trust-policy "$TRUST_POLICY" --field expected_identity)
    EXPECTED_KEY_ID=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$BOOTSTRAP_MANIFEST" --trust-policy "$TRUST_POLICY" --field key_id)
    openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$BOOTSTRAP_SIGNATURE" "$BOOTSTRAP_MANIFEST" >/dev/null 2>&1 || \
      die "bootstrap manifest signature verification failed"
    ARCH=$(uname -m)
    case "$ARCH" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) die "unsupported Linux architecture: $ARCH" ;; esac
    VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$SCRIPT_DIR/release-manifest.json")
    ca_args=()
    if [[ -f "$(dirname "$BOOTSTRAP_MANIFEST")/bootstrap-ca.pem" ]]; then
      CA_SOURCE="$(dirname "$BOOTSTRAP_MANIFEST")/bootstrap-ca.pem"
      ca_args=(--ca-bundle-path "$CA_PATH")
    fi
    CONFIG_SOURCE="$TEMP_DIR/agent-config.json"
    python3 "$SCRIPT_DIR/sha-agent-package.py" bootstrap-config \
      --manifest "$BOOTSTRAP_MANIFEST" --release-manifest "$SCRIPT_DIR/release-manifest.json" \
      --expected-identity "$EXPECTED_IDENTITY" --expected-key-id "$EXPECTED_KEY_ID" --public-key "$PUBLIC_KEY" \
      --platform linux --architecture "$ARCH" --agent-version "$VERSION" --state-path "$STATE_PATH" \
      --output "$CONFIG_SOURCE" "${ca_args[@]}"
  else
    [[ "$source_count" == 1 ]] || die "fresh generic install requires exactly one enrollment-token source"
    [[ -n "$CONTROL_PLANE_URL" ]] || die "fresh generic install requires --control-plane-url"
    token_source="$TOKEN_FILE"
    if [[ -n "$TOKEN_VALUE" ]]; then
      token_source="$TEMP_DIR/enrollment-token"
      printf '%s\n' "$TOKEN_VALUE" > "$token_source"
      TOKEN_VALUE=""
    elif [[ "$TOKEN_STDIN" == 1 ]]; then
      token_source="$TEMP_DIR/enrollment-token"
      IFS= read -r token_line || true
      printf '%s\n' "$token_line" > "$token_source"
      token_line=""
    fi
    if [[ -n "$CA_BUNDLE" ]]; then
      [[ -f "$CA_BUNDLE" && ! -L "$CA_BUNDLE" ]] || die "CA bundle must be a regular non-symlink file"
      openssl x509 -in "$CA_BUNDLE" -noout >/dev/null 2>&1 || die "CA bundle contains no parseable PEM certificate"
      CA_SOURCE="$CA_BUNDLE"
    fi
    VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$SCRIPT_DIR/release-manifest.json")
    config_args=()
    [[ -z "$CA_SOURCE" ]] || config_args+=(--ca-bundle-path "$CA_PATH")
    [[ "$ALLOW_INSECURE_LOOPBACK" == 0 ]] || config_args+=(--allow-insecure-loopback)
    CONFIG_SOURCE="$TEMP_DIR/agent-config.json"
    python3 "$SCRIPT_DIR/sha-agent-package.py" write-config \
      --control-plane-url "$CONTROL_PLANE_URL" --token-file "$token_source" --profile-id "$PROFILE_ID" \
      --platform linux --agent-version "$VERSION" --state-path "$STATE_PATH" --output "$CONFIG_SOURCE" \
      "${config_args[@]}"
  fi
  python3 "$SCRIPT_DIR/sha-agent-package.py" validate-config --config "$CONFIG_SOURCE"
fi

if [[ -z "$DESTDIR" ]] && systemctl is-active --quiet sha-agent.service; then
  systemctl stop sha-agent.service
  SERVICE_STOPPED_FOR_INSTALL=1
fi

for directory in "$BINARY_DIR" "$UNIT_DIR"; do
  [[ ! -e "$directory" || -d "$directory" ]] || die "required install path is not a directory: $directory"
  [[ -e "$directory" ]] || install -d -m 0755 "$directory"
done
install -d -m 0700 "$STATE_DIR"
chmod 0700 "$STATE_DIR"
if [[ "$INSTALL_UID" == 0 ]]; then chown 0:0 "$STATE_DIR"; fi
if [[ -z "$DESTDIR" ]]; then
  assert_secure_system_directory "$BINARY_DIR"
  assert_secure_system_directory "$UNIT_DIR"
fi
for target in "$BINARY_TARGET" "$CONFIG_TARGET" "$STATE_TARGET" "$CA_TARGET" "$UNIT_TARGET"; do
  [[ ! -L "$target" ]] || die "refusing symlinked SHA install target: $target"
done
[[ -x "$SCRIPT_DIR/sha-agent" && ! -L "$SCRIPT_DIR/sha-agent" ]] || die "bundled sha-agent binary is missing or unsafe"
install -m 0755 "$SCRIPT_DIR/sha-agent" "$BINARY_TARGET"
if [[ "$INSTALL_UID" == 0 ]]; then chown 0:0 "$BINARY_TARGET"; fi
if [[ "$FRESH" == 1 ]]; then
  install -m 0600 "$CONFIG_SOURCE" "$CONFIG_TARGET"
  if [[ -n "$CA_SOURCE" ]]; then install -m 0600 "$CA_SOURCE" "$CA_TARGET"; fi
fi
chmod 0600 "$CONFIG_TARGET"
if [[ "$INSTALL_UID" == 0 ]]; then
  chown 0:0 "$CONFIG_TARGET"
  [[ ! -e "$CA_TARGET" ]] || chown 0:0 "$CA_TARGET"
fi

IDENTITY_JSON=""
if [[ "$SKIP_ENROLLMENT_CHECK" != 1 ]]; then
  if ! IDENTITY_JSON=$("$BINARY_TARGET" -config "$CONFIG_TARGET" -action status); then
    die "agent enrollment/TLS preflight failed before systemd service installation"
  fi
  python3 - "$IDENTITY_JSON" "$CONFIG_TARGET" <<'PY'
import json
import sys
identity = json.loads(sys.argv[1])
if not identity.get("endpoint_id") or identity.get("credential_status") != "active" or identity.get("protocol_version") != "sha-agent-v1":
    raise SystemExit("agent enrollment preflight returned incomplete endpoint identity")
with open(sys.argv[2], encoding="utf-8") as handle:
    config = json.load(handle)
if config.get("enrollment_token") or config.get("api_token"):
    raise SystemExit("agent did not erase bootstrap/shared token after successful enrollment")
PY
  [[ -f "$STATE_TARGET" && ! -L "$STATE_TARGET" ]] || die "device credential state was not created as a regular file"
  state_mode=$(mode_of "$STATE_TARGET")
  (( (8#$state_mode & 0077) == 0 )) || die "device credential state permissions are not private"
  [[ "$(owner_of "$STATE_TARGET")" == 0 ]] || die "device credential state is not owned by root"
  if [[ "$EMBEDDED_BOOTSTRAP" == 1 ]]; then
    find "$SCRIPT_DIR/bootstrap-manifest.json" "$SCRIPT_DIR/bootstrap-manifest.json.sig" "$SCRIPT_DIR/bootstrap-ca.pem" \
      -maxdepth 0 -type f -delete 2>/dev/null || true
  fi
fi

SERVICE_TEMPLATE="$SCRIPT_DIR/sha-agent.service"
[[ -f "$SERVICE_TEMPLATE" && ! -L "$SERVICE_TEMPLATE" ]] || die "bundled systemd unit template is missing or unsafe"
sed -e "s#/usr/local/sbin/sha-agent#${BINARY_PATH}#g" -e "s#/etc/sha/agent-config.json#${CONFIG_PATH}#g" \
  "$SERVICE_TEMPLATE" > "$UNIT_TARGET"
chmod 0644 "$UNIT_TARGET"
if [[ "$INSTALL_UID" == 0 ]]; then chown 0:0 "$UNIT_TARGET"; fi
SERVICE_STATE=not-checked-test-staging
if [[ "$SKIP_SYSTEMD" != 1 && -z "$DESTDIR" ]]; then
  systemctl daemon-reload
  systemctl enable sha-agent.service
  systemctl restart sha-agent.service
  SERVICE_STOPPED_FOR_INSTALL=0
  systemctl is-active --quiet sha-agent.service || die "sha-agent systemd service did not become active"
  SERVICE_STATE=active
fi
CONTROL_PLANE_HOST=$(python3 - "$CONFIG_TARGET" <<'PY'
import json,sys
from urllib.parse import urlsplit
with open(sys.argv[1], encoding="utf-8") as handle:
    print(urlsplit(json.load(handle)["control_plane_url"]).hostname)
PY
)
CREDENTIAL_STORAGE=not-checked-test-staging
[[ -z "$IDENTITY_JSON" ]] || CREDENTIAL_STORAGE=protected-device-state
if [[ "$JSON" == 1 ]]; then
  python3 - "$BINARY_PATH" "$CONFIG_PATH" "$OPERATION" "$IDENTITY_JSON" "$CONTROL_PLANE_HOST" "$SERVICE_STATE" "$CREDENTIAL_STORAGE" <<'PY'
import json
import sys
result = {
    "binary": sys.argv[1], "config": sys.argv[2], "operation": sys.argv[3], "status": "ok",
    "control_plane_host": sys.argv[5], "service_state": sys.argv[6], "credential_storage": sys.argv[7],
}
if sys.argv[4]:
    identity = json.loads(sys.argv[4])
    result.update({key: identity[key] for key in ("endpoint_id", "endpoint_status", "credential_status")})
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
PY
else
  endpoint=not-checked-test-staging
  [[ -z "$IDENTITY_JSON" ]] || endpoint=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["endpoint_id"])' "$IDENTITY_JSON")
  printf '%s sha-agent host=%s endpoint=%s service=%s credential_storage=%s\n' \
    "$OPERATION" "$CONTROL_PLANE_HOST" "$endpoint" "$SERVICE_STATE" "$CREDENTIAL_STORAGE"
fi
