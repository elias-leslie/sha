# SHA roadmap bootstrap

> Assumptions before implementation
> - Control plane uses the existing Python/Next/Postgres/Redis comfort zone to maximize Jenny and SummitFlow leverage.
> - Endpoint agent is a typed privileged daemon in Go, but the current host does not yet have a Go toolchain installed, so the first build slice should define contracts and boundaries before compiled-agent work.
> - v1 emphasizes posture, safe remediation, approvals, and auditability before broad compliance coverage.
> - Windows and Linux both matter, but Windows baseline ingestion will likely mature faster because source material is richer and the legacy SHA references are Windows-heavy.

## Phase 0 — bootstrap (this task)
- register SHA as a managed project
- scope permissions so SHA is the only active build target
- create repo scaffold, architecture docs, and first execution-ready task
- verify SummitFlow and Agent Hub see SHA correctly

## Phase 1 — control-plane foundation
Goal: prove central management, endpoint enrollment, and a real operator shell.

Deliverables:
- backend service skeleton with health endpoint
- frontend dashboard shell with fleet, endpoint, controls, approvals, installers nav
- shared schema package for endpoint enrollment + posture upload
- installer profile model and tokenized enrollment flow
- initial Postgres schema for tenants, endpoints, controls, snapshots, approvals

## Phase 2 — source normalization and control catalog
Goal: make hardening intelligence trustworthy and versioned.

Deliverables:
- normalized control-pack model
- import pipeline for Microsoft SCT, CIS, and initial NIST/STIG mappings
- disruption / rollback / applicability metadata
- baseline diff engine for endpoint posture evaluation

## Phase 3 — SHA agent MVP
Goal: get a real endpoint service enrolled and reporting.

Deliverables:
- Go agent skeleton for Windows + Linux
- enrollment + mutual trust flow
- posture collection for safe first families
- typed remediation executors for a narrow low-risk control set
- rollback artifact generation

## Phase 4 — approvals and SHAna operating loop
Goal: allow autonomous management without unsafe broad access.

Deliverables:
- approval grants with TTL and explicit scopes
- dashboard approval inbox and audit view
- SHAna prompt and workflow contract for hardening-only orchestration
- temporary elevated troubleshooting path with strict expiry and logging

## Phase 5 — ranked remediation and rollout policies
Goal: move from raw findings to practical security improvement.

Deliverables:
- ROI / confidence scoring model
- safe-auto, review-first, and manual-only bands
- rollout waves by endpoint cohort
- remediation history, success tracking, and drift suppression

## Suggested initial task queue
1. Build SHA monorepo foundation, enrollment API, and dashboard shell
2. Ingest and normalize Windows + Linux hardening source packs
3. Implement SHA agent enrollment and posture reporting
4. Implement typed remediation + rollback for low-risk controls
5. Implement approval grants and SHAna-controlled change workflow

## Notes for Jenny / future agents
- Prefer small, verifiable vertical slices over giant compliance dumps.
- Treat typed capability boundaries as product requirements, not polish.
- If a control can lock out access, break auth, or disrupt normal use, force review-first or manual-only unless policy explicitly overrides it.
