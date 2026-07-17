#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
INDEX=${INDEX:-"$SCRIPT_DIR/release-index.json"}
SIGNATURE=${SIGNATURE:-"$SCRIPT_DIR/release-index.json.sig"}
TRUST_POLICY=""
while (($#)); do
  case "$1" in
    --index) INDEX=${2:?missing value}; shift 2 ;;
    --signature) SIGNATURE=${2:?missing value}; shift 2 ;;
    --trust-policy) TRUST_POLICY=${2:?missing value}; shift 2 ;;
    *) printf 'unknown release-index argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done
[[ -n "$TRUST_POLICY" ]] || { printf '%s\n' '--trust-policy is required' >&2; exit 1; }
for file in "$INDEX" "$SIGNATURE" "$TRUST_POLICY" "$SCRIPT_DIR/sha-agent-package.py"; do
  [[ -f "$file" && ! -L "$file" ]] || { printf 'unsafe or missing release-index input: %s\n' "$file" >&2; exit 1; }
done
TRUST_POLICY_REAL=$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$TRUST_POLICY")
case "$TRUST_POLICY_REAL" in "$SCRIPT_DIR"|"$SCRIPT_DIR"/*)
  printf '%s\n' 'trust policy must be external to the downloaded release' >&2
  exit 1
  ;;
esac
PUBLIC_KEY=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$INDEX" --trust-policy "$TRUST_POLICY" --field public_key)
IDENTITY=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$INDEX" --trust-policy "$TRUST_POLICY" --field expected_identity)
KEY_ID=$(python3 "$SCRIPT_DIR/sha-agent-package.py" resolve-trust --manifest "$INDEX" --trust-policy "$TRUST_POLICY" --field key_id)
openssl dgst -sha256 -verify "$PUBLIC_KEY" -signature "$SIGNATURE" "$INDEX" >/dev/null 2>&1 || {
  printf '%s\n' 'release index signature verification failed' >&2
  exit 1
}
python3 "$SCRIPT_DIR/sha-agent-package.py" verify-index --index "$INDEX" --public-key "$PUBLIC_KEY" \
  --expected-identity "$IDENTITY" --expected-key-id "$KEY_ID"
printf 'SHA_AGENT_RELEASE_INDEX_VERIFY_OK identity=%s key_id=%s\n' "$IDENTITY" "$KEY_ID"
