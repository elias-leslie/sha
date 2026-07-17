#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
OUT_DIR=${OUT_DIR:-$ROOT_DIR/.dev-tools/sha-agent-release-test}
TEST_ROOT="$OUT_DIR-test-work"
IDENTITY=release-test@example.invalid
OLD_KEY_ID=release-test-old
NEW_KEY_ID=release-test-new

expect_failure() {
  if "$@"; then printf 'expected command to fail: %s\n' "$*" >&2; return 1; fi
}
mode_of() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }
sha_of() { sha256sum "$1" | cut -d' ' -f1; }

[[ "$OUT_DIR" == /* && "$TEST_ROOT" == /* && "$TEST_ROOT" != / ]] || { printf '%s\n' 'test output must be absolute' >&2; exit 1; }
if [[ -d "$TEST_ROOT" ]]; then find "$TEST_ROOT" -xdev -depth -delete; fi
umask 077
mkdir -p "$TEST_ROOT/keys" "$TEST_ROOT/trust"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TEST_ROOT/keys/old.pem" >/dev/null 2>&1
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$TEST_ROOT/keys/new.pem" >/dev/null 2>&1
openssl pkey -in "$TEST_ROOT/keys/old.pem" -pubout -out "$TEST_ROOT/trust/old-public.pem" >/dev/null 2>&1
openssl pkey -in "$TEST_ROOT/keys/new.pem" -pubout -out "$TEST_ROOT/trust/new-public.pem" >/dev/null 2>&1
OLD_FP=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" fingerprint --public-key "$TEST_ROOT/trust/old-public.pem")
NEW_FP=$(python3 "$ROOT_DIR/scripts/sha-agent-package.py" fingerprint --public-key "$TEST_ROOT/trust/new-public.pem")
python3 - "$TEST_ROOT/trust/policy.json" "$IDENTITY" "$OLD_KEY_ID" "$OLD_FP" "$NEW_KEY_ID" "$NEW_FP" <<'PY'
import json,sys
path,identity,old_id,old_fp,new_id,new_fp=sys.argv[1:]
with open(path,'w',encoding='utf-8') as f:
    json.dump({"expected_signing_identity":identity,"revoked_fingerprints":[],"schema_version":"sha-agent-trust-policy-v1","trusted_keys":[
        {"fingerprint":old_fp,"key_id":old_id,"public_key_file":"old-public.pem"},
        {"fingerprint":new_fp,"key_id":new_id,"public_key_file":"new-public.pem"},
    ]},f,sort_keys=True,separators=(',',':')); f.write('\n')
PY
chmod 0644 "$TEST_ROOT/trust/policy.json" "$TEST_ROOT/trust/old-public.pem" "$TEST_ROOT/trust/new-public.pem"

expect_failure env OUT_DIR="$TEST_ROOT/no-key" "$ROOT_DIR/scripts/build-sha-agent-release.sh" >/dev/null 2>&1
chmod 0644 "$TEST_ROOT/keys/new.pem"
expect_failure env SHA_RELEASE_SIGNING_KEY_FILE="$TEST_ROOT/keys/new.pem" SHA_RELEASE_SIGNING_IDENTITY="$IDENTITY" \
  SHA_RELEASE_SIGNING_KEY_ID="$NEW_KEY_ID" OUT_DIR="$TEST_ROOT/bad-key-mode" \
  "$ROOT_DIR/scripts/build-sha-agent-release.sh" >/dev/null 2>&1
chmod 0600 "$TEST_ROOT/keys/new.pem"

SHA_RELEASE_SIGNING_KEY_FILE="$TEST_ROOT/keys/old.pem" SHA_RELEASE_SIGNING_IDENTITY="$IDENTITY" \
  SHA_RELEASE_SIGNING_KEY_ID="$OLD_KEY_ID" SOURCE_DATE_EPOCH=1700000000 OUT_DIR="$OUT_DIR" \
  "$ROOT_DIR/scripts/build-sha-agent-release.sh" > "$TEST_ROOT/build.log"
LINUX_STAGE="$OUT_DIR/sha-agent-sha-go-agent-v0.1.0-linux-amd64"
WINDOWS_STAGE="$OUT_DIR/sha-agent-sha-go-agent-v0.1.0-windows-amd64"
"$LINUX_STAGE/verify-release.sh" --trust-policy "$TEST_ROOT/trust/policy.json" --json | grep -Fq '"status":"ok"'
"$OUT_DIR/verify-release-index.sh" --trust-policy "$TEST_ROOT/trust/policy.json" | grep -Fq SHA_AGENT_RELEASE_INDEX_VERIFY_OK
expect_failure "$LINUX_STAGE/verify-release.sh" --trust-policy "$LINUX_STAGE/trust-policy.example.json" >/dev/null 2>&1
expect_failure "$OUT_DIR/verify-release-index.sh" --trust-policy "$OUT_DIR/trust-policy.example.json" >/dev/null 2>&1

SHA_RELEASE_SIGNING_KEY_FILE="$TEST_ROOT/keys/old.pem" SHA_RELEASE_SIGNING_IDENTITY="$IDENTITY" \
  SHA_RELEASE_SIGNING_KEY_ID="$OLD_KEY_ID" SOURCE_DATE_EPOCH=1700000000 OUT_DIR="$TEST_ROOT/deterministic" \
  "$ROOT_DIR/scripts/build-sha-agent-release.sh" >/dev/null
cmp "$LINUX_STAGE/release-manifest.json" "$TEST_ROOT/deterministic/sha-agent-sha-go-agent-v0.1.0-linux-amd64/release-manifest.json"
cmp "$LINUX_STAGE/release-manifest.json.sig" "$TEST_ROOT/deterministic/sha-agent-sha-go-agent-v0.1.0-linux-amd64/release-manifest.json.sig"
[[ "$(sha_of "$OUT_DIR/sha-agent-sha-go-agent-v0.1.0-linux-amd64.tar.gz")" == \
   "$(sha_of "$TEST_ROOT/deterministic/sha-agent-sha-go-agent-v0.1.0-linux-amd64.tar.gz")" ]]

cp -a "$LINUX_STAGE" "$TEST_ROOT/rotated-stage"
cp "$TEST_ROOT/trust/new-public.pem" "$TEST_ROOT/rotated-stage/release-public-key.pem"
python3 "$ROOT_DIR/scripts/sha-agent-package.py" create-release \
  --stage "$TEST_ROOT/rotated-stage" --version sha-go-agent-v0.1.0 --platform linux --architecture amd64 \
  --created-at 2023-11-14T22:13:20Z --signing-identity "$IDENTITY" --key-id "$NEW_KEY_ID" \
  --public-key "$TEST_ROOT/trust/new-public.pem" --output "$TEST_ROOT/rotated-stage/release-manifest.json"
openssl dgst -sha256 -sign "$TEST_ROOT/keys/new.pem" -out "$TEST_ROOT/rotated-stage/release-manifest.json.sig" \
  "$TEST_ROOT/rotated-stage/release-manifest.json"
"$TEST_ROOT/rotated-stage/verify-release.sh" --trust-policy "$TEST_ROOT/trust/policy.json" >/dev/null

cp "$TEST_ROOT/trust/policy.json" "$TEST_ROOT/trust/revoked.json"
python3 - "$TEST_ROOT/trust/revoked.json" "$OLD_FP" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); p['revoked_fingerprints']=[sys.argv[2]]
with open(sys.argv[1],'w') as f: json.dump(p,f,sort_keys=True,separators=(',',':')); f.write('\n')
PY
chmod 0644 "$TEST_ROOT/trust/revoked.json"
expect_failure "$LINUX_STAGE/verify-release.sh" --trust-policy "$TEST_ROOT/trust/revoked.json" >/dev/null 2>&1
"$TEST_ROOT/rotated-stage/verify-release.sh" --trust-policy "$TEST_ROOT/trust/revoked.json" >/dev/null
cp "$TEST_ROOT/trust/policy.json" "$TEST_ROOT/trust/wrong.json"
python3 - "$TEST_ROOT/trust/wrong.json" "$NEW_KEY_ID" "$NEW_FP" <<'PY'
import json,sys
p=json.load(open(sys.argv[1])); p['trusted_keys']=[{"fingerprint":sys.argv[3],"key_id":sys.argv[2],"public_key_file":"new-public.pem"}]
with open(sys.argv[1],'w') as f: json.dump(p,f,sort_keys=True,separators=(',',':')); f.write('\n')
PY
chmod 0644 "$TEST_ROOT/trust/wrong.json"
expect_failure "$LINUX_STAGE/verify-release.sh" --trust-policy "$TEST_ROOT/trust/wrong.json" >/dev/null 2>&1

cp -a "$LINUX_STAGE" "$TEST_ROOT/tampered-stage"
printf 'tamper\n' >> "$TEST_ROOT/tampered-stage/README.md"
expect_failure "$TEST_ROOT/tampered-stage/verify-release.sh" --trust-policy "$TEST_ROOT/trust/policy.json" >/dev/null 2>&1
cp -a "$LINUX_STAGE" "$TEST_ROOT/missing-signature-stage"
find "$TEST_ROOT/missing-signature-stage/release-manifest.json.sig" -maxdepth 0 -type f -delete
expect_failure "$TEST_ROOT/missing-signature-stage/verify-release.sh" --trust-policy "$TEST_ROOT/trust/policy.json" >/dev/null 2>&1
cp -a "$LINUX_STAGE" "$TEST_ROOT/symlink-stage"
find "$TEST_ROOT/symlink-stage/README.md" -maxdepth 0 -type f -delete
ln -s agent-contract.md "$TEST_ROOT/symlink-stage/README.md"
expect_failure "$TEST_ROOT/symlink-stage/verify-release.sh" --trust-policy "$TEST_ROOT/trust/policy.json" >/dev/null 2>&1

TOKEN=$(python3 - <<'PY'
import secrets
print('sha_enroll.et_' + 'a'*32 + '.' + secrets.token_urlsafe(32))
PY
)
TOKEN_FILE="$TEST_ROOT/enrollment-token"
printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
chmod 0600 "$TOKEN_FILE"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=sha-release-test-ca' \
  -keyout "$TEST_ROOT/ca-key.pem" -out "$TEST_ROOT/ca.pem" >/dev/null 2>&1

GENERIC_ROOT="$TEST_ROOT/generic-root"
generic_json=$(DESTDIR="$GENERIC_ROOT" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --control-plane-url https://sha.example.test --enrollment-token-file "$TOKEN_FILE" \
  --ca-bundle "$TEST_ROOT/ca.pem" --json)
python3 - "$generic_json" <<'PY'
import json,sys
r=json.loads(sys.argv[1]); assert r['status']=='ok' and r['control_plane_host']=='sha.example.test'
assert r['service_state']=='not-checked-test-staging' and r['credential_storage']=='not-checked-test-staging'
PY
python3 - "$GENERIC_ROOT/etc/sha/agent-config.json" "$TOKEN" <<'PY'
import json,sys
c=json.load(open(sys.argv[1])); assert c['enrollment_token']==sys.argv[2]
assert 'api_token' not in c and 'device_credential' not in c and c['ca_bundle_path']=='/etc/sha/ca-bundle.pem'
PY
[[ "$(mode_of "$GENERIC_ROOT/etc/sha")" == 700 && "$(mode_of "$GENERIC_ROOT/etc/sha/agent-config.json")" == 600 ]]
cmp "$GENERIC_ROOT/etc/sha/ca-bundle.pem" "$TEST_ROOT/ca.pem"
DESTDIR="$GENERIC_ROOT" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --operation repair --trust-policy "$TEST_ROOT/trust/policy.json" --json | grep -Fq '"operation":"repair"'

BAD_TOKEN_FILE="$TEST_ROOT/world-readable-token"
cp "$TOKEN_FILE" "$BAD_TOKEN_FILE"; chmod 0644 "$BAD_TOKEN_FILE"
expect_failure env DESTDIR="$TEST_ROOT/bad-token-root" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --control-plane-url https://sha.example.test --enrollment-token-file "$BAD_TOKEN_FILE" >/dev/null 2>&1
INVALID_TOKEN_FILE="$TEST_ROOT/invalid-token"
printf 'sha_enroll.et_%032d.too-short\n' 0 > "$INVALID_TOKEN_FILE"; chmod 0600 "$INVALID_TOKEN_FILE"
expect_failure env DESTDIR="$TEST_ROOT/invalid-token-root" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --control-plane-url https://sha.example.test --enrollment-token-file "$INVALID_TOKEN_FILE" >/dev/null 2>&1
expect_failure env DESTDIR="$TEST_ROOT/no-token-root" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --control-plane-url https://sha.example.test >/dev/null 2>&1
expect_failure env DESTDIR="$TEST_ROOT/http-root" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --control-plane-url http://sha.example.test --enrollment-token-file "$TOKEN_FILE" >/dev/null 2>&1

STDIN_ROOT="$TEST_ROOT/stdin-root"
printf '%s\n' "$TOKEN" | DESTDIR="$STDIN_ROOT" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --control-plane-url https://sha.example.test --enrollment-token-stdin >/dev/null
ARG_ROOT="$TEST_ROOT/arg-root"
arg_stderr="$TEST_ROOT/arg.stderr"
DESTDIR="$ARG_ROOT" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$LINUX_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --control-plane-url https://sha.example.test --enrollment-token "$TOKEN" >/dev/null 2>"$arg_stderr"
grep -Fq 'visible in process listings' "$arg_stderr"
if grep -Fq "$TOKEN" "$arg_stderr"; then printf '%s\n' 'installer leaked token to stderr' >&2; exit 1; fi
DESTDIR="$ARG_ROOT" SKIP_SYSTEMD=1 "$LINUX_STAGE/install-linux.sh" --operation uninstall --purge-state --json | grep -Fq '"purged_state":true'

PROFILE_PACKAGE="$TEST_ROOT/profile-package.tar.gz"
PROFILE_EXPIRES=$(python3 - <<'PY'
from datetime import datetime,timedelta,timezone
print((datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat().replace('+00:00','Z'))
PY
)
expect_failure "$ROOT_DIR/scripts/create-sha-agent-profile-package.sh" \
  --release-dir "$LINUX_STAGE/." --output "$TEST_ROOT/unsafe-profile.tar.gz" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --signing-key-file "$TEST_ROOT/keys/old.pem" --signing-identity "$IDENTITY" --signing-key-id "$OLD_KEY_ID" \
  --control-plane-url https://sha.example.test --enrollment-token-file "$TOKEN_FILE" \
  --profile-id linux-ir --client-id client-acme --location-id location-hq --expires-at "$PROFILE_EXPIRES" >/dev/null 2>&1
"$ROOT_DIR/scripts/create-sha-agent-profile-package.sh" \
  --release-dir "$LINUX_STAGE" --output "$PROFILE_PACKAGE" --trust-policy "$TEST_ROOT/trust/policy.json" \
  --signing-key-file "$TEST_ROOT/keys/old.pem" --signing-identity "$IDENTITY" --signing-key-id "$OLD_KEY_ID" \
  --control-plane-url https://sha.example.test --enrollment-token-file "$TOKEN_FILE" \
  --profile-id linux-ir --client-id client-acme --location-id location-hq --approval-policy pending --max-uses 1 \
  --expires-at "$PROFILE_EXPIRES" --ca-bundle "$TEST_ROOT/ca.pem" > "$TEST_ROOT/profile-build.log"
if tar -tzf "$PROFILE_PACKAGE" | grep -Ev "^$(basename "$LINUX_STAGE")(/|$)" | grep -q .; then
  printf '%s\n' 'profile package contains content outside its canonical release stage' >&2; exit 1
fi
if tar -tzf "$PROFILE_PACKAGE" | grep -Eq '(^|/)(enrollment-token|ca-key\.pem|old\.pem|new\.pem|test-only-release-key\.pem)$'; then
  printf '%s\n' 'profile package contains a loose token or private key file' >&2; exit 1
fi
if grep -R -Fq "$TOKEN" "$TEST_ROOT/profile-build.log" "$TEST_ROOT/build.log"; then
  printf '%s\n' 'release/profile tooling leaked enrollment token to logs' >&2; exit 1
fi
mkdir -p "$TEST_ROOT/profile-extract"
tar -C "$TEST_ROOT/profile-extract" -xzf "$PROFILE_PACKAGE"
PROFILE_STAGE="$TEST_ROOT/profile-extract/$(basename "$LINUX_STAGE")"
PROFILE_ROOT="$TEST_ROOT/profile-root"
DESTDIR="$PROFILE_ROOT" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$PROFILE_STAGE/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" --json > "$TEST_ROOT/profile-install.json"
python3 - "$PROFILE_STAGE/bootstrap-manifest.json" "$PROFILE_ROOT/etc/sha/agent-config.json" "$TOKEN" <<'PY'
import json,sys
b=json.load(open(sys.argv[1])); c=json.load(open(sys.argv[2]))
assert b['client_id']=='client-acme' and b['location_id']=='location-hq' and b['max_uses']==1
assert b['approval_policy']=='pending' and b['token_id']=='et_'+'a'*32 and len(b['release_manifest_sha256'])==64
assert c['enrollment_token']==sys.argv[3] and c['profile_id']=='linux-ir' and 'api_token' not in c
PY
cmp "$PROFILE_ROOT/etc/sha/ca-bundle.pem" "$TEST_ROOT/ca.pem"
cp -a "$PROFILE_STAGE" "$TEST_ROOT/tampered-profile"
printf ' ' >> "$TEST_ROOT/tampered-profile/bootstrap-manifest.json"
expect_failure env DESTDIR="$TEST_ROOT/tampered-profile-root" SKIP_SYSTEMD=1 SHA_AGENT_INSTALL_SKIP_ENROLLMENT_CHECK=1 \
  "$TEST_ROOT/tampered-profile/install-linux.sh" --trust-policy "$TEST_ROOT/trust/policy.json" >/dev/null 2>&1

grep -Fq '[string]$EnrollmentTokenFile' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq '[switch]$EnrollmentTokenStdin' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq 'agent enrollment/TLS preflight failed before Windows service installation' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq '[IO.File]::WriteAllText($ConfigPath, $newConfigJson, $utf8NoBom)' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq 'dpapi-local-machine-protected-state' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq "\$serviceName = 'SHAAgent'" "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq "'binPath=' \$serviceCommand" "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq 'function Assert-ConfidentialExistingFile' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq 'Assert-ConfidentialExistingFile -Path $EnrollmentTokenFile' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq '$taskStoppedForRepair = $false' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq 'Disable-ScheduledTask -TaskName $TaskName' "$WINDOWS_STAGE/install-windows.ps1"
grep -Fq 'Assert-NoNestedReparsePoint -Path $stateDir' "$WINDOWS_STAGE/install-windows.ps1"
if grep -Fq 'replace-with-SHA_AGENT_API_TOKEN' "$WINDOWS_STAGE/install-windows.ps1"; then
  printf '%s\n' 'Windows installer still contains shared-token placeholder' >&2; exit 1
fi
if command -v pwsh >/dev/null 2>&1; then
  for script in "$WINDOWS_STAGE/install-windows.ps1" "$WINDOWS_STAGE/verify-release.ps1"; do
    SHA_PS_PARSE_PATH="$script" pwsh -NoLogo -NoProfile -NonInteractive -Command \
      '$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile($env:SHA_PS_PARSE_PATH,[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|Out-String|Write-Error;exit 1}'
  done
fi

printf 'SHA_AGENT_RELEASE_TEST_OK out_dir=%s\n' "$OUT_DIR"
