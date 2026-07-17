#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
MANIFEST="$SCRIPT_DIR/release-manifest.json"
SIGNATURE="$SCRIPT_DIR/release-manifest.json.sig"
TRUST_POLICY=""
JSON=0

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --manifest) MANIFEST=${2:?missing value for --manifest}; shift 2 ;;
    --signature) SIGNATURE=${2:?missing value for --signature}; shift 2 ;;
    --trust-policy) TRUST_POLICY=${2:?missing value for --trust-policy}; shift 2 ;;
    --json) JSON=1; shift ;;
    *) die "unknown release verification argument: $1" ;;
  esac
done

[[ -n "$TRUST_POLICY" ]] || die "--trust-policy is required; never trust a key or policy supplied only inside the package"
command -v openssl >/dev/null 2>&1 || die "OpenSSL is required for release signature verification"
command -v python3 >/dev/null 2>&1 || die "Python 3 is required for release manifest verification"
for required in "$MANIFEST" "$SIGNATURE" "$TRUST_POLICY" "$SCRIPT_DIR/sha-agent-package.py"; do
  [[ -f "$required" && ! -L "$required" ]] || die "required verification file is missing, non-regular, or symlinked: $required"
done
TRUST_POLICY_REAL=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$TRUST_POLICY")
case "$TRUST_POLICY_REAL" in "$SCRIPT_DIR"|"$SCRIPT_DIR"/*) \
  die "trust policy must be external to the downloaded package" ;; esac

PUBLIC_KEY=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$MANIFEST" --trust-policy "$TRUST_POLICY" --field public_key)
EXPECTED_IDENTITY=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$MANIFEST" --trust-policy "$TRUST_POLICY" --field expected_identity)
EXPECTED_KEY_ID=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$MANIFEST" --trust-policy "$TRUST_POLICY" --field key_id)

openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE" "$MANIFEST" >/dev/null 2>&1 || \
  die "release manifest signature verification failed"
python3 "$SCRIPT_DIR/sha-agent-package.py" verify-release \
  --manifest "$MANIFEST" \
  --public-key "$PUBLIC_KEY" \
  --expected-identity "$EXPECTED_IDENTITY" \
  --expected-key-id "$EXPECTED_KEY_ID"

if [[ "$JSON" == "1" ]]; then
  printf '{"operation":"verify-release","status":"ok"}\n'
else
  printf 'verified SHA agent release identity=%s\n' "$EXPECTED_IDENTITY"
fi
