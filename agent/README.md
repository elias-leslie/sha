# SHA agent

Minimal Go endpoint agent for SHA. This is the long-term endpoint runtime; generated Python/PowerShell compatibility reporters are separate migration shims.

The agent is privileged locally but exposes only typed hardening/reporting verbs through the control-plane API. It is not a remote shell.

Current Go implementation:

- Linux, Windows, and macOS enroll, heartbeat, posture snapshot upload, atomic queued-action claim, and lease-bound result reporting
- short-lived enrollment-token exchange for a client-generated installation ID and unique endpoint-bound device credential; legacy shared `SHA_AGENT_API_TOKEN` configs remain compatible
- loss-safe bootstrap and credential rotation: candidate material and the exact bootstrap request are durably stored before network use, then reconciled through `/api/agent/me` after an ambiguous response
- protocol `sha-agent-v1` and the Go runtime architecture are advertised during bootstrap and every device-authenticated heartbeat
- Windows Firewall all-profile posture plus apply/rollback for `control.windows.firewall-all-profiles`, with a persisted rollback artifact
- Linux remains unable to apply SSH mutations; it exposes only rollback for `linux.ssh.password-authentication-disabled`, removing the historical Go-managed drop-in only when its bytes exactly match the legacy payload
- macOS mutations and all other Go Linux mutations fail unsupported without filesystem or command changes
- evidence action verbs are not advertised; stale evidence jobs fail unsupported instead of reporting canned evidence
- dry-run is not implemented and is advertised as false on every platform
- macOS observe-only posture for Application Firewall, FileVault, and Gatekeeper
- native Windows Service Control Manager mode with stop/shutdown cancellation; interactive run, status, and credential-rotation actions remain separate

The agent never receives an executable command string. It claims at most one typed action at a time, returns the opaque lease token with the result, and reports unsupported work as failed without attempting a mutation.

Install a signed generic Linux package. Keep the release trust policy outside the downloaded package; it is the operator-controlled allowlist and revocation boundary.

```bash
sudo ./install-linux.sh \
  --trust-policy /etc/sha-release-trust/policy.json \
  --control-plane-url https://sha.example.test \
  --enrollment-token-file /run/secrets/sha-enrollment-token \
  --ca-bundle /run/secrets/sha-private-ca.pem \
  --json
```

The token file must be regular, non-symlinked, owned by root/current installer user, and inaccessible to group/other users. `--enrollment-token-stdin` avoids a token file. `--enrollment-token <value>` is accepted for automation compatibility but emits an immediate process-list exposure warning. Exactly one source is required for a fresh generic install. No installer option accepts a long-lived device credential.

Install a signed generic Windows package from an elevated PowerShell session:

```powershell
.\install-windows.ps1 `
  -TrustPolicy C:\SHA-Release-Trust\policy.json `
  -ControlPlaneUrl https://sha.example.test `
  -EnrollmentTokenFile C:\SHA-Staging\enrollment-token.txt `
  -CaBundle C:\SHA-Staging\private-ca.pem `
  -Json
```

Both installers verify the release signature and every listed file before mutation, validate URL/CA/config inputs, then run `-action status` before installing the service. That preflight performs TLS validation and enrollment, reports endpoint identity, persists the unique device credential, and verifies removal of the bootstrap/shared token. Linux success requires the systemd service to be active. Windows success requires the fixed `SHAAgent` SCM service to be running; its exact `binPath` uses `-action service`, LocalSystem, automatic start, and restart-on-failure. A validated legacy `SHA Agent` scheduled task is removed only after SCM startup succeeds. Repair preserves identity/config, stops the running service to avoid state races, verifies enrollment/TLS again, and restarts it. Uninstall preserves config/state unless the explicit purge option is supplied.

Equivalent default SCM registration contract, useful for installer validation:

```powershell
$binPath = '"C:\Program Files\SHA\sha-agent.exe" -config "C:\ProgramData\SHA\agent-config.json" -action service'
sc.exe create SHAAgent 'binPath=' $binPath 'start=' 'auto' 'obj=' 'LocalSystem'
sc.exe failure SHAAgent 'reset=' '86400' 'actions=' 'restart/60000/restart/60000/restart/60000'
sc.exe failureflag SHAAgent 1
```

Do not add `-loop` to the service `binPath`; SCM mode owns the loop. `sc.exe stop SHAAgent` and host shutdown cancel in-flight HTTPS requests and Windows command execution before the service reports stopped. Running `-action service` outside SCM is refused; use `-action run -loop` for a foreground diagnostic loop. Neither mode opens an inbound listener.

Build deterministic signed generic release bundles. Production CI must mount a protected RSA private key; the private key is never copied into output.

```bash
SHA_RELEASE_SIGNING_KEY_FILE=/run/secrets/sha-release-key.pem \
SHA_RELEASE_SIGNING_IDENTITY=sha-release@example.test \
SHA_RELEASE_SIGNING_KEY_ID=sha-release-2026q3 \
SOURCE_DATE_EPOCH=1700000000 \
OUT_DIR=/absolute/release/output \
scripts/build-sha-agent-release.sh
```

`SHA_RELEASE_ALLOW_EPHEMERAL_KEY=1` is an explicit test-only alternative. Release and index manifests use deterministic canonical JSON, SHA-256 artifact digests, and detached RSA-PKCS1v1.5/SHA-256 signatures. The signed metadata binds version, platform, architecture, creation time, signing identity, key ID, and public-key fingerprint. The external trust-policy format supports old/new key overlap and an explicit revoked-fingerprint list. Never treat `trust-policy.example.json` inside a package as a trust anchor; copy and pin reviewed keys/policy through a separate administrative channel.

Minimal external trust policy (key paths are relative to the policy file):

```json
{
  "schema_version": "sha-agent-trust-policy-v1",
  "expected_signing_identity": "sha-release@example.test",
  "trusted_keys": [
    {
      "key_id": "sha-release-2026q3",
      "fingerprint": "sha256:<SubjectPublicKeyInfo digest>",
      "public_key_file": "sha-release-2026q3-public.pem"
    }
  ],
  "revoked_fingerprints": []
}
```

During rotation, add the new key before signing with it; retain old and new entries through the overlap window. Revocation wins over the allowlist immediately. Verify a downloaded release index and package digests before extraction with a separately trusted copy of `verify-release-index.sh --trust-policy /external/policy.json`; do not bootstrap trust from verifier code in the same unverified download. The extracted installer repeats signature and file verification before mutation.

Create a personalized profile package without rebuilding the agent binary:

```bash
scripts/create-sha-agent-profile-package.sh \
  --release-dir /absolute/release/output/sha-agent-sha-go-agent-v0.1.0-linux-amd64 \
  --output /absolute/profile-output/sha-agent-linux-ir.tar.gz \
  --trust-policy /etc/sha-release-trust/policy.json \
  --signing-key-file /run/secrets/sha-release-key.pem \
  --signing-identity sha-release@example.test \
  --signing-key-id sha-release-2026q3 \
  --control-plane-url https://sha.example.test \
  --enrollment-token-file /run/secrets/sha-enrollment-token \
  --profile-id linux-ir --client-id client-acme --location-id location-hq \
  --approval-policy pending --max-uses 1 --expires-at "$TOKEN_EXPIRES_AT"
```

The personalized archive contains the unchanged signed generic package plus a separately signed `bootstrap-manifest.json`. Pass the exact expiry, client/location, max-use, approval, and profile metadata returned when the server created the token. The manifest binds those fields plus token ID, control-plane URL, CA digest, release-manifest digest/version, platform, and architecture. Its token-bearing manifest is created with mode `0600`, never named/logged from token content, and is rejected after expiry, on target/release mismatch, on tamper, or under a revoked/untrusted key. Treat the personalized archive and extraction directory as secrets; after successful enrollment the installer deletes embedded bootstrap files from that extraction while retaining the protected installed CA/config/device state.

Verify package behavior and negative cases:

```bash
scripts/test-sha-agent-release.sh
```

Current distributables are deterministic Linux amd64/arm64 `.tar.gz` and Windows amd64 `.zip` development packages. macOS packaging/runtime acceptance is intentionally deferred. Native DEB/RPM/MSI packaging and ecosystem code signing remain a production-distribution gap requiring publisher credentials and CI/repository infrastructure. The detached manifest path is real and mandatory, but archive transport alone does not replace OS package-manager or Authenticode trust.

Build and run once:

```bash
go build ./cmd/sha-agent
sudo ./sha-agent -config /etc/sha/agent-config.json
```

Inspect or rotate a device identity without printing credential material:

```bash
sudo ./sha-agent -config /etc/sha/agent-config.json -action status
sudo ./sha-agent -config /etc/sha/agent-config.json -action rotate-credential
```

Enrollment config shape:

```json
{
  "control_plane_url": "https://sha.example.test",
  "enrollment_token": "sha_enroll.et_<id>.<secret>",
  "state_path": "/etc/sha/agent-state.json",
  "ca_bundle_path": "/etc/sha/private-ca.pem",
  "allow_insecure_loopback": false,
  "profile_id": "linux-prod",
  "agent_version": "sha-go-agent-v0.1.0",
  "sshd_hardening_path": "/etc/ssh/sshd_config.d/99-sha-hardening.conf",
  "windows_firewall_rollback_path": "C:\\\\ProgramData\\\\SHA\\\\firewall-profiles-rollback.json"
}
```

`state_path` is optional and defaults to `agent-state.json` beside the config. The state survives normal repair/reinstall runs. The agent generates and persists candidate identity material before exchange, uses the enrollment token only for bootstrap, and atomically removes both `enrollment_token` and any legacy `api_token` from the config after device identity is durable. Never pass identity secrets as CLI arguments. Legacy configs may keep `"api_token": "agent-token"`; when no device state or enrollment token exists, the shared-token enrollment path remains active.

On POSIX, the state directory and file must be owned by root or the effective agent user with exact modes `0700` and `0600`; symlinked paths are refused. On Windows, state contents use DPAPI LocalMachine and each runtime write reapplies a SYSTEM/Administrators-only file DACL. The privileged installer must create and protect the parent directory and continues to be part of the Windows security boundary. The agent never prints or reflects enrollment/device credential material in status, rotation output, or HTTP errors.

The Go agent requires HTTPS, verifies the hostname and certificate chain, uses TLS 1.2 or newer, and refuses every HTTP redirect so credentials cannot cross a redirect boundary. `ca_bundle_path` may name an absolute, regular, non-symlink PEM bundle that is appended to the operating-system trust roots; it never disables verification. On POSIX systems the bundle must be owned by root or the agent effective user and must not be group- or world-writable. On Windows the config, state, and custom CA file must each have a protected DACL containing only full-control SYSTEM and Administrators ACEs with a SYSTEM/Administrators owner; reparse points are refused. Plain HTTP is accepted only when `allow_insecure_loopback` is explicitly true and the host is exactly `localhost`, `127.0.0.1`, or `::1`. Control-plane URLs containing user information, a query, or a fragment are rejected. One leading UTF-8 BOM is accepted for compatibility with legacy Windows-written config files. In `-loop` mode, failed control-plane cycles retry with exponential backoff from 5 seconds to a 5-minute cap and reset after a successful cycle; one-shot mode returns the first failure. Compatibility reporters still rely on the operating-system trust store.
