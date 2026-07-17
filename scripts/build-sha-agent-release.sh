#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/agent/dist"}
VERSION=${VERSION:-sha-go-agent-v0.1.0}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-}
SIGNING_KEY=${SHA_RELEASE_SIGNING_KEY_FILE:-}
SIGNING_IDENTITY=${SHA_RELEASE_SIGNING_IDENTITY:-}
SIGNING_KEY_ID=${SHA_RELEASE_SIGNING_KEY_ID:-}
ALLOW_EPHEMERAL=${SHA_RELEASE_ALLOW_EPHEMERAL_KEY:-0}
TARGETS=(linux/amd64 linux/arm64 windows/amd64)

die() { printf '%s\n' "$1" >&2; exit 1; }

[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || die "refusing unsafe SHA agent release version"
[[ "$OUT_DIR" == /* && "$OUT_DIR" != *$'\n'* && "$OUT_DIR" != *$'\r'* ]] || \
  die "SHA agent release output directory must be an absolute path without control characters"
case "/${OUT_DIR#/}/" in *'/../'*|*'/./'*|*'//'*) die "refusing non-normalized release output directory" ;; esac
command -v go >/dev/null 2>&1 || die "Go is required to build SHA agent releases"
command -v openssl >/dev/null 2>&1 || die "OpenSSL is required to sign SHA agent releases"
command -v python3 >/dev/null 2>&1 || die "Python 3 is required to build SHA agent manifests"
command -v zip >/dev/null 2>&1 || die "zip is required to build Windows SHA agent releases"

OUT_PARENT=$(dirname "$OUT_DIR")
OUT_NAME=$(basename "$OUT_DIR")
[[ -n "$OUT_DIR" && "$OUT_DIR" != "/" && "$OUT_NAME" != "." && "$OUT_NAME" != ".." ]] || \
  die "refusing unsafe SHA agent release output directory"
mkdir -p "$OUT_PARENT"
OUT_PARENT=$(cd "$OUT_PARENT" && pwd -P)
OUT_DIR="$OUT_PARENT/$OUT_NAME"
[[ "$OUT_DIR" != "$ROOT_DIR" && "$OUT_DIR" != "$ROOT_DIR/agent" ]] || \
  die "refusing broad SHA agent release output directory"

OUTPUT_MARKER="$OUT_DIR/.sha-agent-release-output"
OUTPUT_MARKER_VALUE="sha-agent-release-output-v1"
if [[ -L "$OUT_DIR" ]]; then
  die "refusing symlinked release output directory"
elif [[ -d "$OUT_DIR" ]]; then
  if [[ -L "$OUTPUT_MARKER" ]]; then
    die "refusing symlinked release output ownership marker"
  elif [[ -f "$OUTPUT_MARKER" ]]; then
    [[ "$(tr -d '\r\n' < "$OUTPUT_MARKER")" == "$OUTPUT_MARKER_VALUE" ]] || \
      die "refusing release output directory with an invalid ownership marker"
  elif [[ -e "$OUTPUT_MARKER" ]]; then
    die "refusing non-file release output ownership marker"
  elif [[ -n "$(find "$OUT_DIR" -mindepth 1 -print -quit)" ]]; then
    die "refusing to clean unowned non-empty output directory"
  fi
elif [[ -e "$OUT_DIR" ]]; then
  die "release output exists and is not a directory"
else
  mkdir -p "$OUT_DIR"
fi
printf '%s\n' "$OUTPUT_MARKER_VALUE" > "$OUTPUT_MARKER"
find "$OUT_DIR" -xdev -depth -mindepth 1 ! -path "$OUTPUT_MARKER" -delete

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sha-agent-release-sign.XXXXXX")
cleanup() { find "$TEMP_DIR" -xdev -depth -delete 2>/dev/null || true; }
trap cleanup EXIT
PUBLIC_KEY="$TEMP_DIR/release-public-key.pem"

if [[ -n "$SIGNING_KEY" ]]; then
  [[ "$ALLOW_EPHEMERAL" == "0" ]] || die "cannot combine a production signing key with ephemeral-key mode"
  [[ "$SIGNING_KEY" == /* && -f "$SIGNING_KEY" && ! -L "$SIGNING_KEY" ]] || \
    die "SHA_RELEASE_SIGNING_KEY_FILE must be an absolute regular non-symlink file"
  key_mode=$(stat -c '%a' "$SIGNING_KEY" 2>/dev/null || stat -f '%Lp' "$SIGNING_KEY")
  (( (8#$key_mode & 0077) == 0 )) || die "release signing key must not grant group or other permissions"
  key_owner=$(stat -c '%u' "$SIGNING_KEY" 2>/dev/null || stat -f '%u' "$SIGNING_KEY")
  [[ "$key_owner" == 0 || "$key_owner" == "$(id -u)" ]] || die "release signing key has an untrusted owner"
  [[ -n "$SIGNING_IDENTITY" ]] || die "SHA_RELEASE_SIGNING_IDENTITY is required with a production key"
  [[ -n "$SIGNING_KEY_ID" ]] || die "SHA_RELEASE_SIGNING_KEY_ID is required with a production key"
  [[ -n "$SOURCE_DATE_EPOCH" ]] || die "SOURCE_DATE_EPOCH is required for a production signed release"
else
  [[ "$ALLOW_EPHEMERAL" == "1" ]] || \
    die "set SHA_RELEASE_SIGNING_KEY_FILE and SHA_RELEASE_SIGNING_IDENTITY (or explicit test-only SHA_RELEASE_ALLOW_EPHEMERAL_KEY=1)"
  SIGNING_KEY="$TEMP_DIR/test-only-release-key.pem"
  SIGNING_IDENTITY=${SIGNING_IDENTITY:-test-only-ephemeral}
  SIGNING_KEY_ID=${SIGNING_KEY_ID:-test-only-ephemeral-1}
  SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}
  umask 077
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$SIGNING_KEY" >/dev/null 2>&1
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]{1,12}$ ]] || die "SOURCE_DATE_EPOCH must be a non-negative Unix timestamp"
[[ "$SIGNING_IDENTITY" =~ ^[A-Za-z0-9][A-Za-z0-9._@:/+-]{0,255}$ ]] || die "unsafe release signing identity"
[[ "$SIGNING_KEY_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._@:/+-]{0,255}$ ]] || die "unsafe release signing key ID"
openssl rsa -in "$SIGNING_KEY" -check -noout >/dev/null 2>&1 || die "release signing key must be a valid RSA private key"
openssl pkey -in "$SIGNING_KEY" -pubout -out "$PUBLIC_KEY" >/dev/null 2>&1 || die "failed to derive release public key"
CREATED_AT=$(python3 - "$SOURCE_DATE_EPOCH" <<'PY'
from datetime import datetime, timezone
import sys
print(datetime.fromtimestamp(int(sys.argv[1]), timezone.utc).isoformat().replace('+00:00', 'Z'))
PY
)

packages=()
for target in "${TARGETS[@]}"; do
  goos=${target%/*}
  goarch=${target#*/}
  name="sha-agent-${VERSION}-${goos}-${goarch}"
  binary=sha-agent
  [[ "$goos" != windows ]] || binary=sha-agent.exe
  stage="$OUT_DIR/$name"
  case "$stage" in "$OUT_DIR"/*) ;; *) die "refusing release stage outside output directory" ;; esac
  mkdir -p "$stage"
  (
    cd "$ROOT_DIR/agent"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$stage/$binary" ./cmd/sha-agent
  )
  cp "$ROOT_DIR/agent/README.md" "$stage/README.md"
  cp "$ROOT_DIR/agent/docs/agent-contract.md" "$stage/agent-contract.md"
  cp "$ROOT_DIR/scripts/sha-agent-package.py" "$stage/sha-agent-package.py"
  cp "$PUBLIC_KEY" "$stage/release-public-key.pem"
  key_fingerprint=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" fingerprint --public-key "$PUBLIC_KEY")
  python3 - "$SIGNING_IDENTITY" "$SIGNING_KEY_ID" "$key_fingerprint" > "$stage/trust-policy.example.json" <<'PY'
import json
import sys
json.dump({
    "expected_signing_identity": sys.argv[1],
    "revoked_fingerprints": [],
    "schema_version": "sha-agent-trust-policy-v1",
    "trusted_keys": [{
        "fingerprint": sys.argv[3],
        "key_id": sys.argv[2],
        "public_key_file": "release-public-key.pem",
    }],
}, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
PY
  if [[ "$goos" == linux ]]; then
    cp "$ROOT_DIR/scripts/install-sha-agent-linux.sh" "$stage/install-linux.sh"
    cp "$ROOT_DIR/scripts/verify-sha-agent-release.sh" "$stage/verify-release.sh"
    cp "$ROOT_DIR/scripts/systemd/sha-agent.service" "$stage/sha-agent.service"
  else
    cp "$ROOT_DIR/scripts/install-sha-agent-windows.ps1" "$stage/install-windows.ps1"
    cp "$ROOT_DIR/scripts/verify-sha-agent-release.ps1" "$stage/verify-release.ps1"
  fi
  chmod 0755 "$stage/$binary"
  [[ "$goos" != linux ]] || chmod 0755 "$stage/install-linux.sh" "$stage/verify-release.sh" "$stage/sha-agent-package.py"
  python3 "$ROOT_DIR/scripts/sha-agent-package.py" create-release \
    --stage "$stage" --version "$VERSION" --platform "$goos" --architecture "$goarch" \
    --created-at "$CREATED_AT" --signing-identity "$SIGNING_IDENTITY" --key-id "$SIGNING_KEY_ID" \
    --public-key "$PUBLIC_KEY" --output "$stage/release-manifest.json"
  openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$stage/release-manifest.json.sig" "$stage/release-manifest.json"
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  if [[ "$goos" == windows ]]; then
    (cd "$OUT_DIR" && find "$name" -type f -print | LC_ALL=C sort | zip -X -q "$name.zip" -@)
    packages+=("$goos:$goarch:$name.zip")
  else
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C "$OUT_DIR" -cf - "$name" | gzip -n > "$OUT_DIR/$name.tar.gz"
    packages+=("$goos:$goarch:$name.tar.gz")
  fi
  printf 'built signed SHA agent package platform=%s architecture=%s\n' "$goos" "$goarch"
done

index_args=()
for package in "${packages[@]}"; do index_args+=(--package "$package"); done
python3 "$ROOT_DIR/scripts/sha-agent-package.py" create-index \
  --output-dir "$OUT_DIR" --version "$VERSION" --created-at "$CREATED_AT" \
  --signing-identity "$SIGNING_IDENTITY" --key-id "$SIGNING_KEY_ID" --public-key "$PUBLIC_KEY" \
  --output "$OUT_DIR/release-index.json" "${index_args[@]}"
openssl dgst -sha256 -sign "$SIGNING_KEY" -out "$OUT_DIR/release-index.json.sig" "$OUT_DIR/release-index.json"
cp "$PUBLIC_KEY" "$OUT_DIR/release-public-key.pem"
cp "$ROOT_DIR/scripts/sha-agent-package.py" "$OUT_DIR/sha-agent-package.py"
cp "$ROOT_DIR/scripts/verify-sha-agent-release-index.sh" "$OUT_DIR/verify-release-index.sh"
chmod 0755 "$OUT_DIR/sha-agent-package.py" "$OUT_DIR/verify-release-index.sh"
cp "$OUT_DIR/sha-agent-${VERSION}-linux-amd64/trust-policy.example.json" "$OUT_DIR/trust-policy.example.json"
touch -h -d "@$SOURCE_DATE_EPOCH" "$OUT_DIR/release-index.json" "$OUT_DIR/release-index.json.sig" \
  "$OUT_DIR/release-public-key.pem" "$OUT_DIR/sha-agent-package.py" "$OUT_DIR/verify-release-index.sh" "$OUT_DIR/trust-policy.example.json"
printf 'SHA_AGENT_RELEASE_BUILD_OK version=%s identity=%s packages=%s\n' "$VERSION" "$SIGNING_IDENTITY" "${#packages[@]}"
