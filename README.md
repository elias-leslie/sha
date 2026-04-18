# SHA

Security Hardening Automation.

SHA is a Windows/Linux hardening platform with three core pieces:

- SHA dashboard: central management plane for posture, policy, approvals, packages, and audit trail
- SHA agent: privileged endpoint service installed on Windows or Linux systems
- SHAna: Agent Hub operator persona dedicated to reviewing posture, proposing safe hardening, and managing approved remediation through the dashboard

## Product intent

Build a practical hardening system that improves real security posture without casually breaking endpoints.

Primary goals:
- continuously assess endpoint hardening posture against trusted baselines
- rank gaps by practical ROI, risk reduction, and remediation confidence
- remediate low-disruption controls automatically when policy allows
- require explicit human approval for disruptive or broad-access actions
- preserve rollback evidence, drift history, and operator visibility

Non-goals for v1:
- macOS support
- full arbitrary remote administration
- opaque AI autonomy without guardrails
- live scraping and blind application of every upstream benchmark

## Naming

- SHA: the product/platform
- SHAna: the LLM operator in Agent Hub
- SHA agent: the installed privileged service on managed endpoints

## Initial architectural direction

- Control plane: FastAPI backend + Next.js frontend + Postgres + Redis
- Endpoint agent: Go service/daemon for Windows and Linux
- Baseline sources: Microsoft SCT/LGPO baselines, CIS Benchmarks, NIST CSF 2.0 / SP 800-53 / SP 800-128 mappings, DISA STIG, NSA/CISA hardening guidance, and selected distro/vendor guidance
- Safety: bounded read scope by default, hardening-only write scope by policy, temporary elevated troubleshooting grants only with human approval

## Local development

Backend:
- `cd backend`
- `uv sync`
- `uv run uvicorn app.main:app --reload --port 8010`

Frontend:
- `cd frontend`
- `pnpm install`
- `pnpm dev --port 3010`

The frontend uses local fixtures in this slice and does not require a running backend to build. `/api/endpoints` list/detail routes are intentionally absent in this first slice; the current backend API surface is limited to `POST /api/endpoints/enroll`, `POST /api/posture-snapshots`, `GET/POST /api/installer-profiles`, `GET/POST /api/approval-grants`, `GET/POST /api/approval-requests`, and `POST /api/approval-requests/{approval_request_id}/decisions`.

Approvals are now split into:
- approval requests for human review state
- approval grants for approved, time-bounded authority
- bounded temporary troubleshooting scopes instead of arbitrary shell access

## Repo map

- `docs/architecture/sha-v1.md` — v1 architecture, safety model, and control-source strategy
- `docs/architecture/shana-approval-boundary.md` — approval-request/grant split and SHAna safety boundary
- `docs/plans/2026-04-18-sha-roadmap.md` — delivery roadmap and implementation assumptions
- `docs/tasks/sha-control-plane-foundation.plan.json` — first execution-ready SummitFlow build task
- `backend/` — control-plane API and orchestration services
- `frontend/` — operator dashboard and installer package UX
- `agent/` — cross-platform SHA agent
- `schemas/` — shared contracts between dashboard, SHA agent, and SHAna
- `control-packs/` — curated starter source packs and the generated catalog manifest for the SHA hardening slice

## Curated starter source packs

The repo includes a deterministic, file-backed source-pack catalog under `control-packs/`.
- `control-packs/packs/` contains the authoritative curated starter JSON inputs.
- `control-packs/catalog.json` is generated from those inputs by `backend/scripts/build_source_catalog.py`.
- The builder validates curated inputs in place, ignores non-JSON files, and fails on extra JSON or malformed content.
- No live scraping or legacy CSV import is involved in this slice.

## Reference inputs

Reference-only source material reviewed during bootstrap:
- `~/references/old_work/sha/README.md`
- `~/references/old_work/sha/Security_Hardening_Automation.ps1`
- `~/references/old_work/sha/config/SecurityControls.csv`
- legacy supporting scripts under `~/references/old_work/`

These references inform naming, control coverage ideas, and rollout lessons, but they do not override current architecture or product direction.
