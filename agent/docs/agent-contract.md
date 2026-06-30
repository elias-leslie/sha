# SHA agent contract

This document defines the boundary the future privileged SHA agent must honor.

## Purpose

The SHA agent is a local privileged service on Windows or Linux systems.
It exists to inspect hardening posture and execute approved hardening actions through typed verbs.
It is not a general-purpose remote shell.

## Required typed capabilities

- `enroll`
- `heartbeat`
- `collect_posture_snapshot`
- `inspect_control`
- `apply_control`
- `rollback_control`
- `collect_security_context`
- `collect_remediation_evidence`
- `request_elevated_troubleshooting`

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

Current backend enrollment route:
- `POST /api/endpoints/enroll`

Authentication:
- if the control plane has `SHA_API_TOKEN` configured, every `/api/*` call must include `Authorization: Bearer <token>` or `X-SHA-API-Token`
- generated bootstrap artifacts include the active token in reporter config when token protection is enabled

Current request payload fields:
- `agent_fingerprint` — required, trimmed, lowercased for matching/storage
- `hostname` — required, trimmed
- `platform` — required enum: `windows | linux`
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
- `platform` — enum: `windows | linux`
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
- `GET /api/installer-profiles/{profile_id}/artifact` returns a deterministic text artifact for that profile
- Linux profiles return a shell bootstrap that installs `/opt/sha/reporter.py`, `/etc/sha/reporter-config.json`, and a `sha-reporter.service` + `sha-reporter.timer`
- Windows profiles return a PowerShell bootstrap that installs `C:\ProgramData\SHA\reporter.ps1`, `C:\ProgramData\SHA\reporter-config.json`, and a `SHA Reporter` scheduled task
- repeated artifact downloads for the same profile are byte-identical until the profile itself changes
- artifact responses set `Content-Disposition` and `X-SHA-Artifact-Sha256` headers for download and verification

Bootstrap artifact behavior in this slice:
- the generated reporter computes a stable per-host fingerprint from local machine identity + installer profile ID
- each run performs `POST /api/endpoints/enroll`, `POST /api/endpoints/{endpoint_id}/heartbeat`, `POST /api/posture-snapshots`, `GET /api/endpoints/{endpoint_id}/response-actions`, and `POST /api/response-actions/{response_action_id}/result`
- Linux posture checks stay read-only and bounded to firewall service state, SSH password-auth configuration, root-password lock state, automatic update enablement, audit/log-retention signal, hardware summary, process inventory, and listening-port inventory
- Linux response-action execution is bounded to context/evidence collection for the approved troubleshooting scope plus apply/rollback for `linux.ssh.password-authentication-disabled`
- Windows posture checks and context/evidence actions stay read-only and bounded to firewall profile state, Defender real-time protection, BitLocker system-drive protection, Secure Boot state, process inventory, TCP listener inventory, recent Security log readability, service status, and current service identity; Windows hardening execution is bounded to apply/rollback for `control.windows.firewall-all-profiles`
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
- `requested_by` — required, trimmed
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
- `decided_by` — required, trimmed
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
- `GET /api/endpoints/{endpoint_id}/response-actions`
- `POST /api/response-actions/{response_action_id}/result`

Important rules:
- queued actions require an active, unexpired approval grant
- the grant must include the endpoint, action, and requested control or troubleshooting scope
- the endpoint must have declared the action capability in heartbeat before the action can be queued
- endpoint fetches return only queued actions whose grant is still active by default; `include_terminal=true` returns queued and terminal action history for operators
- result reporting only accepts `succeeded` or `failed`; completed actions are terminal
- heartbeat `pending_action_count` reflects queued actions backed by active grants
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
