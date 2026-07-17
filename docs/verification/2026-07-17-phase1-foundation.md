# Phase 1 foundation verification — 2026-07-17

Status: in progress.

This record accumulates evidence for the Phase 1 hierarchy, identity, authorization, fleet-metadata, protocol, Go-agent, transport, and signed-archive slices. It does not claim Phase 1 completion: current-head integration, package lifecycle, native publisher packaging, managed runtime/browser, and Linux/Windows Proxmox acceptance remain open. No secret values, private keys, token-bearing artifact bodies, or sensitive endpoint data belong in this record.

## Evidence observed so far

| Area | Observed result |
| --- | --- |
| Backend suite | 99 tests passed after adding hierarchy, migration, scope-filter, quarantine, and compatibility cases. |
| Frontend suite | 48 tests passed after adding client/location management and the URL-persisted scope selector. |
| Go agent clean-room suite | Passed with transport coverage for HTTPS enforcement, explicit loopback-only HTTP, TLS configuration, private-CA bundle validation, expired-leaf rejection, missing-intermediate rejection, wrong-host rejection, URL rejection, and redirect refusal. |
| Checked-in contracts | Generated JSON Schemas include hierarchy, endpoint identity, fleet metadata, and installer contracts. |
| Fleet metadata slice | Focused backend API tests passed for audited tags, immutable saved-view versions, dynamic-group membership, filter rejection, and location-scoped cross-client concealment. Focused SQLite migration upgrade/downgrade and destructive-downgrade refusal tests passed. Focused frontend metadata and existing fleet tests passed together; TypeScript passed. PostgreSQL runtime verification is wired to assert the new tables and 24 deliberate role-permission seeds, but must run in the final integrated HA gate. |
| OIDC, authorization, and audit | Focused tests passed for PKCE/nonce/state, exact issuer and subject identity, concurrent first login, pending zero authority, secure session expiry/revocation, stale-cookie clearing, logout-all, CSRF/origin enforcement, scoped concealment, bootstrap-admin refusal, append-only audit, and restrictive secret files. |
| Signed standalone distribution | A fresh deterministic release regression ended with `SHA_AGENT_RELEASE_TEST_OK` after signature, digest, key rotation/revocation, tamper, token-source, profile-manifest, repair, uninstall, symlink/reparse, and unsafe-staging checks. Native DEB/RPM and Windows publisher-signed bootstrap/MSI remain open. |
| Canonical Go service | Linux tests, vet, race tests, Windows amd64 compile, and Windows vet passed after adding native `SHAAgent` SCM execution, stop/shutdown cancellation, request/command cancellation, and legacy scheduled-task migration behavior. Real Windows runtime proof remains open. |
| Protocol and reporter migration | Migration `20260717_0009` adds current protocol negotiation, versioned capability manifests, credential last-use/expiry, legacy migration state, a deadline-bound shared-token kill switch, in-place device conversion, and new-profile Go-agent defaults. Current-head integration tests and full package lifecycle remain open. |

The settled stopping-checkpoint results are recorded below; repeat them after the next implementation change.

## Stopping checkpoint gates

After concurrent Phase 1 edits settled, the stopping checkpoint passed the supported changed-only gate: architecture, Ruff, type checks, 73 backend tests, Biome, and TypeScript. The complete frontend Vitest suite passed 67 tests. A real defect found by the frontend gate was fixed: endpoint-request coalescing now expires quickly and is tied to the active fetch implementation, so one hung request cannot permanently poison later fleet and approval views.

These results establish a coherent published checkpoint. They do not satisfy the pending PostgreSQL/HA, managed-runtime, browser, package-lifecycle, native-package, or Proxmox acceptance gates below.

## PostgreSQL migration and two-replica HA

`scripts/test-ha-compose.sh` passed against PostgreSQL 16 and two API replicas using ephemeral compose project `sha-ha-e2e-20260717161957`.

Observed evidence:

- A representative legacy database upgraded to Alembic head `20260717_0005`, downgraded to `20260717_0002`, and re-upgraded to head without schema drift.
- Hierarchy verification reported `hierarchy_backfill_preserved=true`: exact legacy aliases, including case-distinct tenant keys, mapped to distinct deterministic canonical IDs; the installer profile retained its canonical ownership.
- Concurrent action claim, result replay, backup, and destructive restore checks still passed after the hierarchy migration.
- The ephemeral compatibility artifact SHA-256 was `f8dcddddd5f6115337df5b938de721ea886fd805dada5f6330414c79d8870f08`.
- The compose project and test data were removed by the test harness.

## HTTPS device-identity lifecycle

`scripts/test-ha-compose-tls.sh` passed against ephemeral compose project `sha-ha-tls-e2e-20260717190009` on HTTPS port `46667`; cleanup removed its containers, network, volume, private keys, tokens, and endpoint state.

Observed evidence:

- An ephemeral private CA signed the nginx leaf; the Go agent trusted only the supplied CA file and completed enrollment-token exchange, status, heartbeat, posture reporting, and device-credential rotation through the HTTPS edge.
- PostgreSQL backup and destructive restore retained the enrolled endpoint. A new agent process reconnected with its rotated credential and the same durable credential-HMAC key.
- The agent rejected an untrusted CA, a correct chain presented for the wrong hostname, and plaintext HTTP. The nginx overlay exposed no plaintext listener.
- Operator revocation immediately made the rotated device credential fail with HTTP 401.
- Enrollment token and old/new device secrets were absent from sanitized agent outputs, error logs, endpoint responses, revocation responses, and enrollment-token list responses. Secret-bearing config/token/state files used mode 0600 and private state directories used mode 0700.
- Focused Go transport tests independently rejected expired leaves and servers omitting a required intermediate, while the existing redirect test proved credentials were not forwarded.

## Required evidence still pending

| Gate | Required evidence |
| --- | --- |
| Final integrated gates | Full backend, frontend, Go, changed-only, contract-drift, and release-script checks against one settled worktree; record exact pass counts here. |
| File-secret overlay | Re-run file-backed database and API secret delivery, public trust-header rejection, direct trusted-proxy identity, and restore checks at the new head. |
| Release bundles | Build from a fresh output directory; verify deterministic/idempotent rebuild, restrictive Linux and Windows permissions, service/task definitions, and no secret leakage. |
| Managed runtime | Rebuild the managed SHA services; exercise `/health`, client/location create/list, scoped fleet/profile APIs, and existing action paths. |
| Browser | In an isolated headless browser, exercise `/clients`, Global → Client → Location selection, scope-preserving navigation, fleet/profile filtering, quarantine presentation, and clean console/network state. |
| Proxmox Linux | Fresh disposable VM: install, enroll, restart, reconnect, verify TLS/private CA and local permissions, rotate/revoke device credential when implemented, reinstall idempotently, and clean up. |
| Proxmox Windows | Fresh disposable VM: install, enroll, restart, reconnect, verify certificate validation, SYSTEM service/task behavior and ACLs, rotate/revoke device credential when implemented, reinstall idempotently, and clean up. |
| Security identity | One-use/expiry/replay enrollment, endpoint-bound credentials, immediate revocation, cross-device denial, scoped OIDC access, and cross-client inference/export denial after those features exist. |
| Signed distribution | Finish the control-plane profile-package mint/download/revoke lifecycle; add native publisher packaging; then repeat embedded-token and reusable generic-package acceptance through the real UI/runtime and VMs. |

macOS runtime remains out of scope for current VM acceptance. Build and contract checks may continue, but no macOS runtime claim should be added.
