# Current SHA runtime contract

This document describes the Phase 0 runtime. It is intentionally narrower than the product roadmap.

The current FastAPI surface has 9 application routers and 19 OpenAPI paths. The checked-in JSON Schemas, route tests, and this document describe what exists; roadmap dashboards, inventory, scheduling, terminal, identity, and installer capabilities are not implied by the Phase 0 UI.

## Modes

| Setting | Intended use | Behavior |
| --- | --- | --- |
| `SHA_AUTH_MODE=development_open` | loopback/local development only | if no authentication mechanism is configured, requests receive the visible `development:operator` principal |
| `SHA_AUTH_MODE=protected` | every shared or production deployment | missing authentication configuration returns 503; missing or invalid credentials return 401 |
| `SHA_DATABASE_MIGRATION_MODE=upgrade` | local development or one-shot migration service | upgrades the database to Alembic head before serving |
| `SHA_DATABASE_MIGRATION_MODE=check` | production API replicas | refuses startup unless the database is already at Alembic head |

Configuring any API, agent, read-only, or trusted-proxy credential causes the backend to use protected behavior. The HA deployment explicitly selects protected mode and runs one migration service before replicas start.

## Principals and route classes

- operator bearer token: operator API routes only;
- read-only bearer token: safe GET/HEAD/OPTIONS API routes, excluding protected artifact download and all agent routes;
- agent bearer token: enrollment, heartbeat, posture upload, response-action claim, and lease-bound result only;
- trusted external proxy: requires the trusted header, a valid operator/read-only role, and a non-empty external user; the stable audit subject is derived from that user;
- development principal: local-only operator behavior described above.

The browser proxy strips caller-supplied SHA trust headers and forwards caller authorization. It has no ambient backend operator token. Redirects are returned to the caller instead of being followed with credentials. In the HA topology, nginx applies the same trust-header stripping and load-balances `/api/*` directly across both backend replicas; the Next.js proxy remains the safe same-origin path for direct frontend deployments and local development.

The stock frontend has no login or token-entry flow. In normal mode it uses the live API and reports loading/error/empty state; fixtures appear only in explicitly enabled, visibly labeled demo mode, where mutations are disabled. A protected browser deployment therefore needs a caller-auth/session adapter that is not included in Phase 0.

Free-form actor fields remain accepted as optional compatibility input, but mutation routes ignore them. Stored requester, approver, decision-maker, and response-action actor values come from the authenticated principal.

## Public API surface

| Area | Routes |
| --- | --- |
| Health | `GET /health` |
| Endpoints | enroll, heartbeat, list, detail under `/api/endpoints` |
| Posture | `POST /api/posture-snapshots` |
| Controls | `GET /api/control-registry`; source pack list/detail under `/api/source-packs` |
| Installers | profile create/list and compatibility artifact download under `/api/installer-profiles`; downloads are operator-only, private/no-store attachments |
| Approvals | request list/create/decision and grant list/create under `/api/approval-requests` and `/api/approval-grants` |
| Current actions | operator enqueue/list, agent claim, and agent result under `/api/response-actions` and endpoint response-action routes |
| Evidence export | `GET /api/compliance/evidence` |

Pydantic server models are canonical. The 24 checked-in JSON Schema documents and their manifest live in `schemas/generated/`; tests fail when they drift.

## Current action delivery

1. An operator creates an action against one endpoint and an active approval grant. A caller-provided idempotency key is bound to the exact request; exact replay returns the same action and conflicting reuse returns 409.
2. The endpoint agent atomically claims the oldest eligible queued or expired-leased action.
3. The server returns one opaque lease token, stores only its SHA-256 hash, records lease timestamps, and increments the attempt count.
4. A result is accepted only while that exact lease is active. Exact result replay is idempotent. A wrong, expired, stale, or terminal-conflicting result returns 409.
5. Operator list responses expose state and lease timing but never the lease token. The token appears only once in the agent claim response.

Current leases prevent simultaneous duplicate delivery and stale overwrite. Agent-side durable result outbox and full immutable attempt history move into the unified job spine; until then, implemented mutations must remain idempotent and verified.

## Controls

The checked-in source catalog owns benchmark-control IDs and provenance. The control registry adds canonical operational-observation IDs for emitted telemetry that is not a benchmark, and every registry item exposes `kind=benchmark_control|operational_observation`. It overlays observation aliases and exact apply/rollback support across that combined namespace; `supported_actions`, not the kind discriminator, determines actionability. Posture ingestion converts supported legacy aliases to canonical IDs. Approval and action creation reject unknown controls, wrong-platform controls, and unsupported behavior. The frontend loads actionable control options from the registry API rather than maintaining a second list.

## Persistence

SQLite is supported for local development. PostgreSQL is the production reference. Alembic revisions own durable schema changes; startup `create_all` is not a production migration mechanism. The baseline can adopt the representative pre-Alembic schema. Revisions through current head `20260717_0004` normalize legacy Windows and operational-observation control IDs and add response-action lease/idempotency fields.

The HA stack runs a one-shot migration service before either API replica. Replicas use migration-check mode and fail startup unless the database is already at Alembic head.

## Transport and artifact handling

Local profiles still accept `http` for loopback/isolated compatibility testing. Deployed browser and endpoint traffic must use HTTPS. The HA TLS overlay removes the plaintext published port, enables TLS 1.2/1.3, and has no insecure client example. Go and compatibility clients rely on normal platform certificate validation; private CAs must currently be installed in the operating-system trust store.

Compatibility artifact responses set private/no-store/no-cache, attachment, no-referrer, no-sniff, and SHA-256 digest headers. The dashboard does not render or retain the token-bearing body in component state. The digest is transfer-integrity metadata, not a package signature.

## Compatibility runtime

The Go agent and generated Linux, Windows, and macOS reporters speak the current enrollment, heartbeat, posture, claim, and result routes. New product behavior must target the Go agent. Generated reporters are migration-only, embed the shared agent token in protected mode, and must not gain new feature breadth. They are deterministic compatibility scripts, not signed production packages.

## Explicitly absent at Phase 0

- OIDC browser sessions and scoped roles;
- relational clients and locations;
- short-lived enrollment tokens and unique device credentials;
- signed agent packages and signed bootstrap manifests;
- normalized software/process/service/network inventory;
- unified jobs, schedules, incidents, evidence objects, reports, command console, or terminal;
- production-ready installer profiles.

Linux and Windows privileged behavior have fresh Proxmox runtime evidence recorded in `docs/verification/2026-07-17-phase0-runtime.md`. macOS remains build- and contract-verified only in the current scope.

The UI and documentation must not imply these are already available.
