#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
RELEASE_DIR=""
OUTPUT=""
TRUST_POLICY=""
SIGNING_KEY=""
SIGNING_IDENTITY=""
SIGNING_KEY_ID=""
CONTROL_PLANE_URL=""
TOKEN_FILE=""
TOKEN_STDIN=0
PROFILE_ID=""
CLIENT_ID=""
LOCATION_ID=""
APPROVAL_POLICY=pending
MAX_USES=1
EXPIRES_AT=""
CA_BUNDLE=""

die() { printf '%s\n' "$1" >&2; exit 1; }
while (($#)); do
  case "$1" in
    --release-dir) RELEASE_DIR=${2:?missing value}; shift 2 ;;
    --output) OUTPUT=${2:?missing value}; shift 2 ;;
    --trust-policy) TRUST_POLICY=${2:?missing value}; shift 2 ;;
    --signing-key-file) SIGNING_KEY=${2:?missing value}; shift 2 ;;
    --signing-identity) SIGNING_IDENTITY=${2:?missing value}; shift 2 ;;
    --signing-key-id) SIGNING_KEY_ID=${2:?missing value}; shift 2 ;;
    --control-plane-url) CONTROL_PLANE_URL=${2:?missing value}; shift 2 ;;
    --enrollment-token-file) TOKEN_FILE=${2:?missing value}; shift 2 ;;
    --enrollment-token-stdin) TOKEN_STDIN=1; shift ;;
    --profile-id) PROFILE_ID=${2:?missing value}; shift 2 ;;
    --client-id) CLIENT_ID=${2:?missing value}; shift 2 ;;
    --location-id) LOCATION_ID=${2:?missing value}; shift 2 ;;
    --approval-policy) APPROVAL_POLICY=${2:?missing value}; shift 2 ;;
    --max-uses) MAX_USES=${2:?missing value}; shift 2 ;;
    --expires-at) EXPIRES_AT=${2:?missing value}; shift 2 ;;
    --ca-bundle) CA_BUNDLE=${2:?missing value}; shift 2 ;;
    *) die "unknown profile-package argument: $1" ;;
  esac
done

for required in RELEASE_DIR OUTPUT TRUST_POLICY SIGNING_KEY SIGNING_IDENTITY SIGNING_KEY_ID CONTROL_PLANE_URL PROFILE_ID CLIENT_ID LOCATION_ID EXPIRES_AT; do
  [[ -n "${!required}" ]] || die "missing required profile-package input: $required"
done
[[ "$OUTPUT" == /* && "$OUTPUT" != *$'\n'* && "$OUTPUT" != *$'\r'* && ! -e "$OUTPUT" && ! -L "$OUTPUT" ]] || \
  die "profile-package output must be a new absolute file path"
OUTPUT_PARENT=$(dirname "$OUTPUT")
[[ -d "$OUTPUT_PARENT" && ! -L "$OUTPUT_PARENT" && "$(cd "$OUTPUT_PARENT" && pwd -P)" == "$OUTPUT_PARENT" ]] || \
  die "profile-package output parent must be an existing canonical non-symlink directory"
output_parent_mode=$(stat -c '%a' "$OUTPUT_PARENT" 2>/dev/null || stat -f '%Lp' "$OUTPUT_PARENT")
(( (8#$output_parent_mode & 0077) == 0 )) || die "profile-package output parent must not grant group or other permissions"
output_parent_owner=$(stat -c '%u' "$OUTPUT_PARENT" 2>/dev/null || stat -f '%u' "$OUTPUT_PARENT")
[[ "$output_parent_owner" == 0 || "$output_parent_owner" == "$(id -u)" ]] || die "profile-package output parent has an untrusted owner"
[[ "$RELEASE_DIR" == /* && -d "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] || die "release directory must be absolute and non-symlinked"
case "/${RELEASE_DIR#/}/" in *'/../'*|*'/./'*|*'//'*) die "release directory must be normalized" ;; esac
RELEASE_BASENAME=$(basename "$RELEASE_DIR")
[[ "$RELEASE_BASENAME" =~ ^sha-agent-[A-Za-z0-9._-]+-(linux|windows)-(amd64|arm64)$ ]] || \
  die "release directory basename is unsafe or not a canonical SHA agent stage"
[[ "$(cd "$RELEASE_DIR" && pwd -P)" == "$RELEASE_DIR" ]] || die "release directory contains a symlink or is not canonical"
TRUST_POLICY_REAL=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$TRUST_POLICY")
case "$TRUST_POLICY_REAL" in "$RELEASE_DIR"|"$RELEASE_DIR"/*) die "trust policy must be external to the downloaded release" ;; esac
[[ "$SIGNING_KEY" == /* && -f "$SIGNING_KEY" && ! -L "$SIGNING_KEY" ]] || die "signing key must be an absolute regular non-symlink file"
key_mode=$(stat -c '%a' "$SIGNING_KEY" 2>/dev/null || stat -f '%Lp' "$SIGNING_KEY")
(( (8#$key_mode & 0077) == 0 )) || die "profile signing key must not grant group or other permissions"
key_owner=$(stat -c '%u' "$SIGNING_KEY" 2>/dev/null || stat -f '%u' "$SIGNING_KEY")
[[ "$key_owner" == 0 || "$key_owner" == "$(id -u)" ]] || die "profile signing key has an untrusted owner"
[[ "$MAX_USES" =~ ^[0-9]+$ && "$MAX_USES" -ge 1 && "$MAX_USES" -le 1000 ]] || die "max uses must be 1..1000"
[[ "$APPROVAL_POLICY" == pending || "$APPROVAL_POLICY" == approved ]] || die "approval policy must be pending or approved"
[[ -f "$RELEASE_DIR/release-manifest.json" && -f "$RELEASE_DIR/release-manifest.json.sig" ]] || die "release directory is unsigned"
if find "$RELEASE_DIR" -xdev \( -type l -o \( ! -type d ! -type f \) \) -print -quit | grep -q .; then
  die "release directory contains a symlink or non-regular entry"
fi

source_count=0
[[ -z "$TOKEN_FILE" ]] || ((source_count+=1))
[[ "$TOKEN_STDIN" == 0 ]] || ((source_count+=1))
[[ "$source_count" == 1 ]] || die "exactly one of --enrollment-token-file or --enrollment-token-stdin is required"

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sha-agent-profile-package.XXXXXX")
cleanup() { find "$TEMP_DIR" -xdev -depth -delete 2>/dev/null || true; }
trap cleanup EXIT
umask 077
if [[ "$TOKEN_STDIN" == 1 ]]; then
  TOKEN_FILE="$TEMP_DIR/enrollment-token"
  IFS= read -r token_line || true
  printf '%s\n' "$token_line" > "$TOKEN_FILE"
  token_line=""
fi
PUBLIC_KEY="$TEMP_DIR/profile-public-key.pem"
openssl rsa -in "$SIGNING_KEY" -check -noout >/dev/null 2>&1 || die "profile signing key must be a valid RSA private key"
openssl pkey -in "$SIGNING_KEY" -pubout -out "$PUBLIC_KEY" >/dev/null 2>&1

STAGE="$TEMP_DIR/$RELEASE_BASENAME"
mkdir -p "$STAGE"
cp -a "$RELEASE_DIR/." "$STAGE/"
RELEASE_PUBLIC_KEY=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" resolve-trust \
  --manifest "$STAGE/release-manifest.json" --trust-policy "$TRUST_POLICY" --field public_key)
RELEASE_IDENTITY=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" resolve-trust \
  --manifest "$STAGE/release-manifest.json" --trust-policy "$TRUST_POLICY" --field expected_identity)
RELEASE_KEY_ID=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" resolve-trust \
  --manifest "$STAGE/release-manifest.json" --trust-policy "$TRUST_POLICY" --field key_id)
openssl dgst -sha256 -verify "$RELEASE_PUBLIC_KEY" -signature "$STAGE/release-manifest.json.sig" \
  "$STAGE/release-manifest.json" >/dev/null 2>&1 || die "copied release manifest signature verification failed"
python3 "$ROOT_DIR/scripts/sha-agent-package.py" verify-release --manifest "$STAGE/release-manifest.json" \
  --public-key "$RELEASE_PUBLIC_KEY" --expected-identity "$RELEASE_IDENTITY" --expected-key-id "$RELEASE_KEY_ID"
PLATFORM=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["platform"])' "$STAGE/release-manifest.json")
ARCHITECTURE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["architecture"])' "$STAGE/release-manifest.json")
CREATED_AT=$(python3 - <<'PY'
from datetime import datetime, timezone
now = datetime.now(timezone.utc)
print(now.isoformat().replace('+00:00', 'Z'))
PY
)
bootstrap_args=()
if [[ -n "$CA_BUNDLE" ]]; then
  [[ -f "$CA_BUNDLE" && ! -L "$CA_BUNDLE" ]] || die "CA bundle must be a regular non-symlink file"
  openssl x509 -in "$CA_BUNDLE" -noout >/dev/null 2>&1 || die "CA bundle contains no parseable PEM certificate"
  cp "$CA_BUNDLE" "$STAGE/bootstrap-ca.pem"
  chmod 0600 "$STAGE/bootstrap-ca.pem"
  bootstrap_args=(--ca-bundle "$STAGE/bootstrap-ca.pem")
fi
python3 "$ROOT_DIR/scripts/sha-agent-package.py" create-bootstrap \
  --control-plane-url "$CONTROL_PLANE_URL" --token-file "$TOKEN_FILE" --profile-id "$PROFILE_ID" \
  --client-id "$CLIENT_ID" --location-id "$LOCATION_ID" --platform "$PLATFORM" --architecture "$ARCHITECTURE" \
  --created-at "$CREATED_AT" --expires-at "$EXPIRES_AT" --approval-policy "$APPROVAL_POLICY" --max-uses "$MAX_USES" \
  --signing-identity "$SIGNING_IDENTITY" --key-id "$SIGNING_KEY_ID" --public-key "$PUBLIC_KEY" \
  --release-manifest "$STAGE/release-manifest.json" --output "$STAGE/bootstrap-manifest.json" "${bootstrap_args[@]}"
openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$STAGE/bootstrap-manifest.json.sig" "$STAGE/bootstrap-manifest.json"
selected_key=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" resolve-trust \
  --manifest "$STAGE/bootstrap-manifest.json" --trust-policy "$TRUST_POLICY" --field public_key)
openssl dgst -sha256 -verify "$selected_key" -signature "$STAGE/bootstrap-manifest.json.sig" \
  "$STAGE/bootstrap-manifest.json" >/dev/null 2>&1 || die "new bootstrap signature is not trusted by supplied policy"

if [[ "$PLATFORM" == windows ]]; then
  [[ "$OUTPUT" == *.zip ]] || die "Windows profile package output must end in .zip"
  (cd "$TEMP_DIR" && find "$(basename "$STAGE")" -type f -print | LC_ALL=C sort | zip -X -q "$OUTPUT" -@)
else
  [[ "$OUTPUT" == *.tar.gz ]] || die "POSIX profile package output must end in .tar.gz"
  tar --sort=name --owner=0 --group=0 --numeric-owner -C "$TEMP_DIR" -czf "$OUTPUT" "$(basename "$STAGE")"
fi
printf 'SHA_AGENT_PROFILE_PACKAGE_OK platform=%s architecture=%s profile=%s\n' "$PLATFORM" "$ARCHITECTURE" "$PROFILE_ID"
