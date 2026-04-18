# SHAna approval boundary

This document captures the operator-facing safety boundary for SHAna and the SHA dashboard approval flow.

## Why this slice exists

SHA can already model endpoint posture and installer/profile data, but autonomous hardening is unsafe without a bounded approval path.
This slice adds the governance layer before live endpoint execution:
- approval requests for disruptive hardening changes
- approval requests for temporary elevated troubleshooting
- bounded approval grants with expiry
- audit events for request, approve, deny, revoke, and expire transitions

## Core rule

SHAna is not a remote shell.

Allowed behavior:
- inspect hardening posture
- request hardening changes through typed control IDs
- request temporary troubleshooting through bounded troubleshooting scopes
- operate only on explicitly approved endpoints/actions/scopes

Disallowed behavior:
- arbitrary shell commands
- generic filesystem browsing
- ad hoc package installation
- open-ended admin sessions without a time-boxed grant

## Request kinds

### 1. Hardening change
Used for disruptive or review-required mutations.

Contract shape:
- `request_kind=hardening_change`
- `requested_actions` limited to `apply_control` and `rollback_control`
- `control_ids` required and non-empty
- `troubleshooting_scopes` must be empty

### 2. Elevated troubleshooting
Used for broader, read-oriented troubleshooting that still stays bounded.

Contract shape:
- `request_kind=elevated_troubleshooting`
- `requested_actions` must include `request_elevated_troubleshooting`
- allowed companion actions: `inspect_control`, `collect_security_context`, `collect_remediation_evidence`
- `troubleshooting_scopes` required and non-empty
- `control_ids` must be empty

## Troubleshooting scopes

This slice limits temporary elevated troubleshooting to these scopes only:
- `service_status`
- `security_logs`
- `firewall_state`
- `identity_state`
- `process_inventory`
- `network_bindings`

These scopes are intentionally read-oriented and finite.
If future work needs anything broader, it should add a new explicit scope or a new approval design rather than tunneling it through a generic shell.

## Decision flow

1. SHAna or an operator creates an approval request.
2. A human approves or denies it.
3. Approval creates a linked approval grant with explicit expiry.
4. Denial preserves the audit trail but creates no grant.
5. Revocation or expiry removes the active grant and updates the linked request state.

## Expiry model

- Pending requests do not expire on their own in this slice.
- A request becomes `expired` only when a previously approved linked grant expires.
- Grant expiry is synchronized lazily by request/grant list and decision routes.
- Expiry must be idempotent: one expired audit event, no duplicate side effects on repeated reads.

## Manual emergency grants

The control plane still exposes direct `POST /api/approval-grants` for operator-created emergency grants.
Those grants remain bounded by the same rules as request-approved grants:
- hardening grant => hardening actions + non-empty `control_ids` + empty troubleshooting scopes
- troubleshooting grant => troubleshooting actions + non-empty troubleshooting scopes + empty `control_ids`
- mixed-mode payloads are rejected

## Operator UX expectations

The dashboard should let operators answer four questions quickly:
1. What is waiting for approval right now?
2. What access is active right now?
3. Why was the request made?
4. What happened historically: approved, denied, revoked, or expired?

That is why the approvals workspace is split into:
- pending requests
- active grants
- audit trail
- explicit SHAna boundary copy

## Non-goals for this slice

- executing endpoint actions
- websocket/session multiplexing to agents
- background schedulers for expiry cleanup
- dual approval / quorum logic
- raw shell or remote desktop style access
