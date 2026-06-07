# SHA roadmap

> Working assumptions:
> - Control plane starts with FastAPI, Next.js, and local SQLite so a fresh clone can run without private infrastructure.
> - Future production deployments should add Postgres, authentication, authorization, TLS, and deployment hardening before exposure.
> - Endpoint agents must stay deterministic and constrained to typed hardening actions.
> - Checked-in starter controls must come from public-source material that can be cited and redistributed cleanly.

## Phase 0 — repository foundation

- define project identity and architecture
- document endpoint-agent contract and approval boundary
- keep public install/run/test paths independent of private tooling
- verify local quality gates

## Phase 1 — control-plane foundation

- backend health endpoint and typed API contracts
- endpoint enrollment and heartbeat handling
- posture snapshot upload and latest-summary reads
- installer profile creation and deterministic artifact download
- dashboard shell with fleet, endpoint, controls, installers, and approvals views
- generated JSON Schemas for public API contracts

## Phase 2 — clean public control catalog

- use curated starter packs sourced from NIST, DISA, and CISA/NSA guidance
- preserve source/version/provenance metadata
- use fresh `control.public.*` identifiers
- avoid reproducing CIS Benchmark or Microsoft baseline content unless licensing permits it
- keep the builder deterministic and repo-local

## Phase 3 — endpoint reporting slice

- Linux and Windows bootstrap reporters enroll, heartbeat, and upload bounded read-only posture snapshots
- generated artifacts include hash headers and deterministic content
- endpoint inventory/detail pages show connectivity, capabilities, latest posture summary, and latest result rows
- shared schemas stay synchronized with backend models

## Phase 4 — approvals and temporary elevation

- approval requests for disruptive remediation and troubleshooting scopes
- approval grants with explicit endpoint/action/control/scope, approver, reason, status, and expiry
- audit events for request, approval, denial, revocation, and expiry-relevant state
- dashboard copy makes the no-arbitrary-shell boundary visible

## Phase 5 — future agent and remediation execution

- implement a privileged endpoint agent with typed verbs only
- add rollback artifacts before mutation
- support safe auto-remediation only for low-disruption controls with high rollback confidence
- require approval-backed policy for risky actions
- keep all elevated troubleshooting time-boxed and audited

## Notes for future contributors

- Prefer small, verifiable slices.
- Keep public docs accurate to what the repo can run today.
- Do not add private infrastructure assumptions to the public install path.
- Do not add control content that cannot be cited and redistributed cleanly.
