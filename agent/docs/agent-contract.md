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

Minimum enrollment payload should establish:
- tenant/site/environment
- endpoint identity
- platform and version
- hostname
- agent version
- release channel
- bootstrap token or signed enrollment proof

## Posture snapshot contract

Each posture snapshot should include:
- endpoint ID
- collected_at
- platform profile
- security-tool posture summary
- per-control results keyed by `control_key`
- evidence summaries
- reboot-required markers when relevant

## Mutation contract

Every mutating action should capture:
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
