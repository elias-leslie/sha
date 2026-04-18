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
- `platform_version`
- `agent_version`
- `tenant_id`
- `site_id`
- `status` — successful enroll and re-enroll return `active`
- `last_seen_at`
- `created_at`
- `updated_at`

Important rules:
- first successful enroll returns HTTP 201
- same-fingerprint re-enroll returns HTTP 200 and preserves `endpoint_id` + `created_at`
- same fingerprint with a different platform returns HTTP 409
- all API timestamps serialize as UTC `Z` strings

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
- `tenant_id`
- `site_id`
- `created_at`
- `updated_at`

Important rules:
- list responses use `{ "items": [...] }`
- duplicate normalized `(platform, name)` returns HTTP 409
- no item GET/PATCH/DELETE routes exist in this slice

## Approval grant contract

Current backend approval routes:
- `GET /api/approval-grants`
- `POST /api/approval-grants`

Allowed actions enum:
- `collect_security_context`
- `inspect_control`
- `apply_control`
- `rollback_control`
- `request_elevated_troubleshooting`

Create request fields:
- `endpoint_ids` — required array, each trimmed, nonexistent IDs rejected before duplicate checks
- `allowed_actions` — required array from the enum above
- `requested_by` — required, trimmed
- `approved_by` — required, trimmed
- `reason` — required, trimmed
- `expires_at` — required timestamp, normalized to UTC `Z`

Returned object fields:
- `approval_grant_id` — format `grant_<32 lowercase hex>`
- `endpoint_ids`
- `allowed_actions`
- `requested_by`
- `approved_by`
- `reason`
- `expires_at`
- `status` — current enum: `approved | expired | revoked`; create returns `approved`
- `created_at`
- `updated_at`

Important rules:
- list responses use `{ "items": [...] }`
- duplicate trimmed `endpoint_ids` returns HTTP 422
- duplicate `allowed_actions` returns HTTP 422
- no wildcard action scopes in this slice

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
