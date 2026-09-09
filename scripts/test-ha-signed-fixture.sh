# shellcheck shell=bash
# Sourced by HA compose tests after ROOT_DIR, WORK_DIR, need, and cleanup are set.
# Build a real signed release with a fresh test-only key; never copy keys into images.
need go
need openssl
need zip
export SHA_HA_AGENT_FIXTURE_ROOT="$WORK_DIR/agent-packages"
mkdir -p "$SHA_HA_AGENT_FIXTURE_ROOT/keys" "$SHA_HA_AGENT_FIXTURE_ROOT/trust"
FIXTURE_KEY="$SHA_HA_AGENT_FIXTURE_ROOT/keys/signing.pem"
FIXTURE_TRUST="$SHA_HA_AGENT_FIXTURE_ROOT/trust/policy.json"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$FIXTURE_KEY" >/dev/null 2>&1
openssl pkey -in "$FIXTURE_KEY" -pubout -out "$SHA_HA_AGENT_FIXTURE_ROOT/trust/public.pem" >/dev/null 2>&1
FIXTURE_FINGERPRINT=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" fingerprint \
  --public-key "$SHA_HA_AGENT_FIXTURE_ROOT/trust/public.pem")
python3 - "$FIXTURE_TRUST" "$FIXTURE_FINGERPRINT" <<'PYFIXTURE'
import json
import sys
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump({
        "schema_version": "sha-agent-trust-policy-v1",
        "expected_signing_identity": "ha-fixture@example.invalid",
        "revoked_fingerprints": [],
        "trusted_keys": [{"fingerprint": sys.argv[2], "key_id": "ha-fixture-key", "public_key_file": "public.pem"}],
    }, stream)
PYFIXTURE
SHA_RELEASE_SIGNING_KEY_FILE="$FIXTURE_KEY" SHA_RELEASE_SIGNING_IDENTITY=ha-fixture@example.invalid \
  SHA_RELEASE_SIGNING_KEY_ID=ha-fixture-key SOURCE_DATE_EPOCH=1700000000 \
  OUT_DIR="$SHA_HA_AGENT_FIXTURE_ROOT/releases" "$ROOT_DIR/scripts/build-sha-agent-release.sh"
