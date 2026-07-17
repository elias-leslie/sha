# SHA agent contract

## Purpose

This document defines the boundary every privileged SHA agent and generated reporter must honor.

The checked-in Go agent implements cross-platform enrollment, heartbeat, posture reporting, action claiming, and result reporting. Its active mutation surface is Windows Firewall only; Linux additionally retains a byte-exact cleanup path for the historical Go SSH hardening payload. Generated bootstrap reporters are separate implementations with concrete bounded evidence collection; Linux and Windows generated reporters also implement the reversible controls listed below.
SHA agents inspect hardening posture and execute only the typed actions they truthfully advertise.
They are not general-purpose remote shells.

## Typed capability vocabulary

- `enroll`
- `heartbeat`
- `collect_posture_snapshot`
- `inspect_control`
- `apply_control`
- `rollback_control`
- `collect_security_context`
- `collect_remediation_evidence`
- `request_elevated_troubleshooting`

Implementations may advertise a generic action capability when every admitted control is implemented, or a per-control capability as `<action>:<control-id>`. The action segment remains the typed `apply_control` or `rollback_control` verb; arbitrary action strings are invalid. Backend admission and frontend eligibility accept a hardening action only when either its generic action or its exact action/control pair was declared.

Current Go declarations are:
- all platforms: `enroll`, `heartbeat`, `collect_posture_snapshot`
- Windows only: `apply_control:control.windows.firewall-all-profiles` and `rollback_control:control.windows.firewall-all-profiles`
- Linux only: `rollback_control:linux.ssh.password-authentication-disabled`; rollback removes the file only when it byte-for-byte matches `# Managed by SHA Go agent\nPasswordAuthentication no\n`
- no Go evidence verbs until bounded evidence payloads are implemented; stale evidence jobs return `failed`/unsupported and collect nothing
- Linux never advertises or executes SSH apply; altered, missing, or ambiguous legacy rollback files are refused without mutation
- macOS Go mutation jobs and all other Go Linux mutation jobs return `failed`/unsupported without filesystem or command changes
- `supports_dry_run=false` on every Go platform
- `captures_rollback_artifacts=true` only on Windows Go, where the firewall rollback artifact is persisted; false on Linux and macOS

Generated reporters retain separate, implementation-backed declarations. Linux generated evidence verbs summarize concrete posture/telemetry results, while its SSH and network-isolation mutations have tested rollback paths; macOS generated reporting remains mutation-free.

## Required approval-boundary behavior

Default mode:
- hardening-related reads only
- typed hardening mutations only when policy or approval allows
- no arbitrary filesystem browsing
- no arbitrary shell execution

Elevated troubleshooting mode:
- must require a scoped approval grant
- grant must include endpoint scope, action scope, approver identity, reason, and expiry
- all elevated actions must be fully logged and attributable
- elevated mode must self-expire without relying on the operator to clean it up

## Enrollment contract

Current backend identity routes:
- `POST /api/agent/bootstrap` — enrollment-token exchange
- `GET /api/agent/me` — endpoint-bound identity/status check
- `POST /api/agent/credentials/rotate` — endpoint-bound credential rotation
- `POST /api/endpoints/enroll` — legacy shared-token compatibility

Authentication:
- protected mode separates operator, read-only, and agent principals; credentials are not interchangeable
- `SHA_API_TOKEN` authenticates operator routes but is forbidden from the agent-only enrollment, heartbeat, posture, claim, and result routes
- `SHA_READONLY_API_TOKEN` authenticates safe read routes but is forbidden from agent routes, mutations, and artifact downloads
- `SHA_AGENT_API_TOKEN` authenticates only enrollment, heartbeat, posture upload, response-action claim, and lease-bound result reporting
- a short-lived `sha_enroll.<token_id>.<secret>` bearer authenticates only `/api/agent/bootstrap`
- a unique `sha_device.<credential_id>.<secret>` bearer authenticates `/api/agent/me`, rotation, and only the heartbeat/posture/claim/result operations bound to its endpoint
- generated compatibility artifacts contain `SHA_AGENT_API_TOKEN` when configured; they never fall back to the operator token
- artifact generation returns HTTP 503 when operator-token or trusted-proxy authentication is configured without an agent token
- when no credential is configured, explicit local `development_open` mode uses a visible development principal; shared deployments must use fail-closed `protected` mode

The Go agent prefers device identity whenever `enrollment_token` is configured or durable device state exists. It generates a stable installation ID and candidate credential locally, stores the exact bootstrap request before network use, and never sends an enrollment token after bootstrap. The server returns no device secret. A committed exchange with a lost response is recovered with the candidate credential through `/api/agent/me`; an uncommitted request retries the byte-semantic payload captured in state. Both `enrollment_token` and any legacy shared `api_token` are removed atomically from persisted config only after endpoint identity is durable, preventing a migrated endpoint from retaining fleet-wide bootstrap power. Existing `api_token` configs remain on the Phase 0 compatibility path when neither enrollment configuration nor device state exists.

Device credential rotation follows the same loss-safe rule: the candidate is durable before the request, and startup reconciles old/candidate authentication before reporting or executing actions. `-action status` and `-action rotate-credential` return identifiers and status only. Enrollment tokens, credential secrets, and complete bearers are never printed or reflected from server error bodies.

Device bootstrap and heartbeat explicitly advertise `protocol_version=sha-agent-v1` and `architecture=runtime.GOARCH`. A pending endpoint may call `/api/agent/me` and heartbeat, but the Go agent does not upload posture, claim actions, or submit results until `/api/agent/me` reports it active.

Transport:
- the Go agent requires `https` and rejects control-plane URLs containing user information, a query, or a fragment
- explicit Go-agent development configuration may set `allow_insecure_loopback=true`, which permits `http` only for the exact hosts `localhost`, `127.0.0.1`, and `::1`
- the Go agent requires TLS 1.2 or newer and uses normal hostname, chain, and validity checks; there is no certificate-verification bypass
- optional Go-agent `ca_bundle_path` must be an absolute, regular, non-symlink PEM file; those certificates are appended to the operating-system roots rather than replacing them
- on POSIX systems the custom CA file must be owned by root or the agent effective user and must not be group- or world-writable; on Windows config/state/custom-CA reads require a protected, exact SYSTEM+Administrators DACL and trusted owner
- the Go agent refuses all HTTP redirects, including same-origin redirects, so credentials are never forwarded to a redirect target
- legacy config compatibility permits exactly one leading UTF-8 BOM; new writers should emit BOM-free UTF-8 JSON
- `-loop` mode retries a failed cycle with exponential backoff from 5 seconds to a 5-minute cap, resets the backoff after success, and continues serving; one-shot mode returns the first cycle failure
- generated compatibility reporters still require a private CA to be installed in the operating-system trust store
- production deployments must use HTTPS; the HA TLS overlay exposes HTTPS only and supports TLS 1.2 and TLS 1.3

Device state:
- `state_path` defaults to `agent-state.json` beside the agent config and is not removed by a normal repair/reinstall
- every update uses a bounded same-directory temporary file, file sync, atomic replacement, and directory durability boundary
- POSIX requires a root/effective-user-owned `0700` parent and `0600` regular state/config files; symlink path components are refused
- Windows state payloads use DPAPI LocalMachine; runtime writes apply a SYSTEM/Administrators-only DACL and reject reparse points
- the privileged Windows installer must create/protect the parent directory; runtime DPAPI does not replace that installer security boundary

Release and installation:
- the reusable generic package accepts a control-plane URL and exactly one short-lived enrollment-token source: an explicitly warned command-line value, a protected file, or standard input; it never accepts a device credential
- a personalized package reuses the byte-identical generic release and adds a detached-signed bootstrap manifest; the manifest binds client/location/profile scope, token ID, expiry, max uses, approval policy, URL, optional CA digest, release-manifest digest/version, platform, and architecture
- release and bootstrap signatures use RSA-PKCS1v1.5/SHA-256 with an external operator trust-policy allowlist keyed by signing identity, key ID, and SubjectPublicKeyInfo SHA-256 fingerprint; explicit revoked fingerprints override allowlisting
- package-contained public keys and example trust policies are not roots of trust; production policy/key distribution must use a separate administrative channel, and private signing keys are never packaged
- installers reject a missing signature, tamper, unlisted/symlinked release content, wrong target/release, expired bootstrap, wrong/untrusted key, or revoked fingerprint before installing a service
- installers validate config, URL, CA, release, and bootstrap inputs before service registration, then run `-action status` to prove TLS/enrollment and protected device-state persistence; successful enrollment must leave no non-empty `enrollment_token` or legacy `api_token` in config
- Linux installs only succeed after `sha-agent.service` is active; repair stops an active service before binary/state preflight and restores/restarts it on failure
- Windows installs only succeed after fixed LocalSystem automatic SCM service `SHAAgent` reaches Running with exact `"<binary>" -config "<config>" -action service`; a validated legacy scheduled task is deleted only afterward
- normal repair/upgrade preserves device state; uninstall preserves state unless explicit purge is requested
- `.tar.gz` and `.zip` are current development delivery formats; native DEB/RPM/MSI packaging, repository metadata signing, and Authenticode remain gated on production publisher credentials/infrastructure

Device bootstrap request fields:
- `installation_id` — stable client-generated `si_<base64url>` value
- `credential_id` — client-generated `dc_<base64url>` public identifier
- `credential_secret` — client-generated canonical unpadded base64url secret with at least 32 decoded bytes
- `agent_fingerprint`, `hostname`, `platform`, `platform_version`, and `agent_version`
- `protocol_version` — `sha-agent-v1`
- `architecture` — `runtime.GOARCH`

Legacy enrollment request payload fields:
- `agent_fingerprint` — required, trimmed, lowercased for matching/storage
- `hostname` — required, trimmed
- `platform` — required enum: `windows | linux | macos`
- `platform_version` — optional nullable string; explicit `null` clears it, omission preserves current value on re-enroll
- `agent_version` — required, trimmed
- `tenant_id` — optional nullable string; explicit `null` clears it, omission preserves current value on re-enroll
- `site_id` — optional nullable string; explicit `null` clears it, omission preserves current value on re-enroll

Current response payload fields:
- `endpoint_id` — server-generated, format `ep_<32 lowercase hex>`
- `agent_fingerprint`
- `hostname`
- `platform`
- `platform_version` — always present; `null` when unknown or cleared
- `agent_version`
- `tenant_id` — always present; `null` when unset
- `site_id` — always present; `null` when unset
- `status` — successful enroll and re-enroll return `active`
- `last_seen_at`
- `created_at`
- `updated_at`

Important rules:
- first successful enroll returns HTTP 201
- same-fingerprint re-enroll returns HTTP 200 and preserves `endpoint_id` + `created_at`
- same fingerprint with a different platform returns HTTP 409
- all API timestamps serialize as UTC `Z` strings

## Endpoint inventory and detail contract

Current backend routes:
- `GET /api/endpoints`
- `GET /api/endpoints/{endpoint_id}`

Shared response rules:
- inventory items and detail payloads always include `platform_version`, `tenant_id`, `site_id`, `connectivity_status`, `last_heartbeat_at`, `last_platform_profile`, `execution_hooks`, and `latest_posture_summary` even when those values are currently `null`
- `declared_capabilities` is always present and defaults to `[]` before the first heartbeat
- before the first heartbeat: `connectivity_status=null`, `last_heartbeat_at=null`, `last_platform_profile=null`, and `execution_hooks=null`
- before the first posture snapshot: `latest_posture_summary=null`
- detail responses always include `latest_results`; before the first posture snapshot it is `[]`
- latest posture summary selection uses `observed_at DESC, snapshot_id DESC`
- detail `latest_results` ordering is `control_key ASC`

## Canonical control registry contract

Current backend route:
- `GET /api/control-registry`

The response uses `{ "items": [...] }`. Each item contains `control_id`, `title`, `platform`, `kind`, `observation_aliases`, and `supported_actions`. `kind` is `benchmark_control` or `operational_observation`.

The checked-in source catalog owns benchmark controls and their provenance. The registry supplements them with canonical operational-observation IDs for reporter telemetry that is not itself a benchmark control, then overlays accepted aliases and exact apply/rollback support across the combined namespace. `supported_actions`, not `kind`, determines whether a control is actionable. Posture ingestion normalizes supported legacy aliases, while approvals and action creation reject unknown, wrong-platform, or unsupported controls. Agents must advertise only the exact capabilities they implement.

## Posture snapshot contract

Current backend posture route:
- `POST /api/posture-snapshots`

Current request payload fields:
- `endpoint_id` — required
- `observed_at` — required timestamp, normalized to UTC `Z`
- `platform_profile` — required, trimmed
- `results` — required array with length >= 1

Each `results[]` entry must include:
- `control_key` — required, trimmed, duplicate check is trim + case-insensitive inside one snapshot
- `status` — required enum: `pass | fail | warn | error | not_applicable`
- `current_value` — optional nullable string
- `recommended_value` — optional nullable string
- `severity` — optional nullable string
- `evidence_summary` — required, trimmed
- `reboot_required` — required boolean

Current success response payload:
- `snapshot_id` — server-generated, format `snap_<32 lowercase hex>`
- `endpoint_id`
- `observed_at`
- `accepted_result_count`
- `created_at`

Important rules:
- unknown `endpoint_id` returns HTTP 404
- duplicate logical `control_key` values inside one snapshot return HTTP 422
- empty `results` returns HTTP 422
- stored result rows persist `control_key`, `status`, `current_value`, `recommended_value`, `severity`, `evidence_summary`, and `reboot_required`

## Installer profile contract

Current backend installer routes:
- `GET /api/installer-profiles`
- `POST /api/installer-profiles`
- `GET /api/installer-profiles/{profile_id}/artifact`

Create request fields:
- `name` — required, trimmed, unique per platform after trim + lowercase normalization
- `platform` — enum: `windows | linux | macos`
- `channel` — enum: `stable | preview`
- `control_plane_url` — absolute `http` or `https` URL
- `policy_mode` — enum: `observe | safe_auto | approval_required`
- `tenant_id` — optional nullable string
- `site_id` — optional nullable string

Returned object fields:
- `id` — format `ip_<32 lowercase hex>`
- `name`
- `platform`
- `channel`
- `control_plane_url`
- `policy_mode`
- `tenant_id` — always present; `null` when unset
- `site_id` — always present; `null` when unset
- `created_at`
- `updated_at`

Important rules:
- list responses use `{ "items": [...] }`
- duplicate normalized `(platform, name)` returns HTTP 409
- `GET /api/installer-profiles/{profile_id}/artifact` returns a deterministic compatibility reporter for that profile
- Linux profiles return a shell bootstrap that installs `/opt/sha/reporter.py`, `/etc/sha/reporter-config.json`, and a `sha-reporter.service` + `sha-reporter.timer`
- Windows profiles return a PowerShell bootstrap that installs `C:\ProgramData\SHA\reporter.ps1`, `C:\ProgramData\SHA\reporter-config.json`, and a `SHA Reporter` scheduled task
- macOS profiles return a shell bootstrap that installs `/usr/local/lib/sha/reporter.py`, `/Library/Application Support/SHA/reporter-config.json`, and a `com.sha.reporter` launchd daemon
- repeated artifact downloads for the same profile and agent credential are byte-identical until either changes
- artifact responses set `Cache-Control: private, no-store`, `Pragma: no-cache`, `Content-Disposition`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `X-SHA-Artifact-Sha256`
- read-only principals cannot download artifacts, and the stock dashboard never previews or retains the token-bearing body in component state; it exposes only download metadata after a user-initiated download
- the digest detects transfer corruption but is not publisher authentication; these artifacts are not signed production packages

Bootstrap artifact behavior in this slice:
- the generated reporter computes a stable per-host fingerprint from local machine identity + installer profile ID
- each run performs `POST /api/endpoints/enroll`, `POST /api/endpoints/{endpoint_id}/heartbeat`, `POST /api/posture-snapshots`, `POST /api/endpoints/{endpoint_id}/response-actions/claim`, and `POST /api/response-actions/{response_action_id}/result`
- Linux posture checks stay read-only and bounded to firewall service state, SSH password-auth configuration, root-password lock state, automatic update enablement, audit/log-retention signal, hardware summary, process inventory, package inventory, startup services, login sessions, and listening-port inventory
- Linux response-action execution is bounded to context/evidence collection for the approved troubleshooting scope plus apply/rollback for `linux.ssh.password-authentication-disabled` and `linux.network.endpoint-isolated`
- Windows posture checks and context/evidence actions stay read-only and bounded to firewall profile state, Defender real-time protection, BitLocker system-drive protection, Secure Boot state, process inventory, TCP listener inventory, installed software, automatic-start services, recent Security log readability, service status, and current service identity; Windows hardening execution is bounded to apply/rollback for `control.windows.firewall-all-profiles`, `control.windows.defender-real-time-protection`, and `control.windows.firewall-endpoint-isolated`
- macOS posture checks and context/evidence actions stay read-only and bounded to Application Firewall, FileVault, Gatekeeper, automatic-update check state, unified-log availability, hardware summary, process inventory, application inventory, launchd startup items, login sessions, TCP listener inventory, service status, and console-user identity
- the bootstrap path does not expose arbitrary shell execution, filesystem browsing, or generic remote command hooks

## Approval request contract

Current backend approval routes:
- `GET /api/approval-requests`
- `POST /api/approval-requests`
- `POST /api/approval-requests/{approval_request_id}/decisions`
- `GET /api/approval-grants`
- `POST /api/approval-grants`

Allowed actions enum:
- `collect_security_context`
- `collect_remediation_evidence`
- `inspect_control`
- `apply_control`
- `rollback_control`
- `request_elevated_troubleshooting`

Troubleshooting scopes enum:
- `service_status`
- `security_logs`
- `firewall_state`
- `identity_state`
- `process_inventory`
- `network_bindings`

Approval request create fields:
- `endpoint_ids` — required array, each trimmed, nonexistent IDs rejected before duplicate checks
- `request_kind` — enum: `hardening_change | elevated_troubleshooting`
- `requested_actions` — required array from the allowed-actions enum above
- `control_ids` — explicit array, required non-empty only for `hardening_change`
- `troubleshooting_scopes` — explicit array, required non-empty only for `elevated_troubleshooting`
- `requested_ttl_minutes` — required integer from 15 through 240
- `requested_by` — optional compatibility input; ignored
- `reason` — required, trimmed
- `risk` — enum: `low | medium | high | critical`

Approval request response fields:
- `approval_request_id` — format `apr_<32 lowercase hex>`
- `endpoint_ids`
- `request_kind`
- `requested_actions`
- `control_ids`
- `troubleshooting_scopes`
- `requested_ttl_minutes`
- `requested_by`
- `reason`
- `risk`
- `status` — enum: `pending | approved | denied | expired | revoked`
- `decision_by` — null while pending
- `decision_comment` — null while pending
- `decision_at` — null while pending
- `approval_grant_id` — null unless the request has been approved
- `created_at`
- `updated_at`
- `audit_events[]` — each event contains `approval_event_id`, `event_type`, `actor`, `comment`, `created_at`

Request-kind rules:
- `hardening_change` may only use `apply_control` / `rollback_control`
- `hardening_change` requires non-empty `control_ids`
- `hardening_change` must use empty `troubleshooting_scopes`
- `elevated_troubleshooting` must include `request_elevated_troubleshooting`
- `elevated_troubleshooting` may only use troubleshooting-safe actions (`request_elevated_troubleshooting`, `inspect_control`, `collect_security_context`, `collect_remediation_evidence`)
- `elevated_troubleshooting` requires non-empty `troubleshooting_scopes`
- `elevated_troubleshooting` must use empty `control_ids`

Decision request fields:
- `decision` — enum: `approve | deny | revoke`
- `decided_by` — optional compatibility input; ignored
- `decision_comment` — required, trimmed
- `expires_at` — required only for `approve`, forbidden for `deny` and `revoke`

Decision rules:
- create returns HTTP 201 with the full approval-request object
- decision POST returns HTTP 200 with the full post-transition approval-request object
- pending requests can only be approved or denied
- approved requests can only be revoked later
- denied/expired/revoked requests are terminal and repeated decision POSTs return HTTP 409
- unknown `approval_request_id` returns HTTP 404 with `{"detail":"approval request not found"}`
- approve requires `expires_at > decision_time` and `expires_at <= decision_time + requested_ttl_minutes`
- approve-path TTL violations return HTTP 422 with `{"detail":"expires_at must be within requested_ttl_minutes of decision time"}`
- pending requests do not expire on their own; request status `expired` is only reached later through linked approved-grant expiry

Approval grant fields:
- `approval_grant_id` — format `grant_<32 lowercase hex>`
- `approval_request_id` — nullable; null for manual emergency grants
- `endpoint_ids`
- `allowed_actions`
- `control_ids`
- `troubleshooting_scopes`
- `requested_by`
- `approved_by`
- `reason`
- `expires_at`
- `status` — enum: `approved | expired | revoked`
- `created_at`
- `updated_at`

Manual emergency grant rules:
- direct `POST /api/approval-grants` is an operator-only emergency path
- it must still follow the same bounded hardening-vs-troubleshooting rules as request-approved grants
- mixed hardening + troubleshooting payloads are rejected
- manual grants do not synthesize approval-request audit events
- optional request `requested_by` and `approved_by` compatibility fields are ignored

For all approval mutations, stored requester/approver/decision actors come from the authenticated principal. A caller cannot attribute an audit event to another actor by sending a legacy actor field.

Important rules:
- list responses use `{ "items": [...] }`
- duplicate trimmed `endpoint_ids` return HTTP 422 after unknown-endpoint validation passes
- duplicate requested/allowed actions return HTTP 422
- all timestamps serialize as UTC `Z` strings
- no wildcard action scopes in this slice
- no arbitrary shell access is represented anywhere in this contract

## Response action contract

Current backend response-action routes:
- `POST /api/response-actions`
- `POST /api/endpoints/{endpoint_id}/response-actions/claim`
- `GET /api/endpoints/{endpoint_id}/response-actions` (operator history/list view)
- `POST /api/response-actions/{response_action_id}/result`

Important rules:
- action creation is operator-only; claim and result submission are agent-only under protected authentication
- queued actions require an active, unexpired approval grant
- the grant must include the endpoint, action, and requested control or troubleshooting scope
- the endpoint must have declared either the generic action capability or the exact `<action>:<control-id>` capability in heartbeat before a hardening action can be queued
- agents execute only actions returned by the claim route; a claim response contains at most one item and includes an opaque `lease_token`
- claim leases expire after a bounded interval; an expired lease can be reclaimed with a new token and incremented attempt count
- agents must return the exact claim `lease_token` with `status` and `result_summary`; missing, stale, mismatched, or expired tokens are rejected
- operator fetches return only queued actions whose grant is still active by default; `include_terminal=true` returns queued, leased, and terminal action history
- result reporting only accepts `succeeded` or `failed`; exact duplicate result submission with the same lease token is idempotent, and completed actions are terminal
- heartbeat `pending_action_count` reflects queued or reclaimable expired-leased actions backed by active grants
- action creation accepts an optional caller idempotency key scoped to the endpoint; exact replay returns the existing action, conflicting reuse returns HTTP 409, and omission generates a server key
- `requested_by` in an action create body is optional compatibility input and ignored; the stored actor comes from the operator principal
- actions remain typed (`apply_control`, `rollback_control`, bounded troubleshooting actions); no arbitrary shell payload exists

## Mutation contract

Every future mutating action should capture:
- action ID
- endpoint ID
- control key
- before state summary
- requested change
- rollback artifact reference
- result status
- human approval reference if required
- timestamps

## Non-goals

- ad hoc remote command execution
- generic patch management outside hardening scope
- arbitrary software deployment
- silent high-impact configuration changes without policy or approval
