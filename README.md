# SHA — Security Hardening Automation

SHA is an early-stage Windows/Linux security hardening automation platform. It combines a FastAPI control-plane API, a Next.js operator dashboard, deterministic installer-profile artifacts, and shared agent contracts for endpoint enrollment, posture reporting, approvals, and bounded remediation workflows.

The project goal is practical hardening without casually breaking endpoints: observe posture, rank gaps, require human approval for disruptive actions, and keep all endpoint work constrained to typed hardening capabilities rather than arbitrary remote shell access.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Current status

This repository contains a working control-plane/dashboard slice, not a production-ready endpoint-management product.

Implemented:

- backend API for enrollment, heartbeats, posture snapshots, installer profiles, approval requests/grants, and source-pack catalog reads
- frontend dashboard pages for fleet, endpoints, controls, installers, and approvals
- deterministic Linux and Windows bootstrap artifact generation for installer profiles
- generated JSON Schemas under `schemas/generated/`
- curated starter control packs derived from public-source NIST, DISA, and CISA/NSA guidance

Not yet production-ready:

- no built-in authentication or authorization layer
- no completed privileged Go endpoint agent
- no production migrations or HA deployment path
- no live AI/operator integration is required or bundled

Do not expose the backend or dashboard to an untrusted network without adding authentication, authorization, TLS, and deployment hardening appropriate for your environment.

## Requirements

- Python 3.13
- [uv](https://docs.astral.sh/uv/) for backend dependency management
- Node.js 24 or newer
- [pnpm](https://pnpm.io/) 10.28.0 via Corepack

Optional Ubuntu 24.04 prerequisite bootstrap:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git

curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv python install 3.13

curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo corepack enable pnpm
sudo corepack prepare pnpm@10.28.0 --activate
```

## Install from a fresh clone

```bash
git clone https://github.com/elias-leslie/sha.git
cd sha

cd backend
uv sync

cd ../frontend
pnpm install
```

## Configuration

Use `.env.example` as a local environment template:

```bash
cp .env.example .env
# Optional: load it into the current shell before starting commands.
set -a; . ./.env; set +a
```

Backend settings use the `SHA_` prefix:

- `SHA_DATABASE_URL` — defaults to `sqlite:///data/sha.sqlite3` when run from `backend/`
- `SHA_PORT` — documented local backend port, default `8010`

Frontend settings:

- `API_URL` — backend origin used by Next.js rewrites, default `http://127.0.0.1:8010`

Optional operator/agentic automation concepts such as SHAna are documented as product direction only. The checked-in app runs without private agent infrastructure or external AI credentials.

## Run locally

Terminal 1:

```bash
cd backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8010
```

Terminal 2:

```bash
cd frontend
API_URL=http://127.0.0.1:8010 pnpm dev --port 3010
```

Then open <http://127.0.0.1:3010>.

Health check:

```bash
curl http://127.0.0.1:8010/health
```

The frontend has typed fixture fallbacks for dashboard views, so most pages still render if the backend is absent. Mutating/API-backed flows require the backend.

## Test, typecheck, and build

Backend:

```bash
cd backend
uv run pytest
uv run python scripts/build_source_catalog.py
uv run python scripts/export_contract_schemas.py
```

Frontend:

```bash
cd frontend
pnpm test
pnpm exec tsc --noEmit
pnpm build
```

## Runtime smoke test

With the backend running:

```bash
curl http://127.0.0.1:8010/health
curl http://127.0.0.1:8010/api/endpoints
curl http://127.0.0.1:8010/api/source-packs
```

With both backend and frontend running:

```bash
curl -I http://127.0.0.1:3010/
curl http://127.0.0.1:3010/health
```

## Architecture

- `backend/` — FastAPI control-plane API, SQLite-backed local store, installer artifact renderer, source-pack catalog builder, and contract schema exporter
- `frontend/` — Next.js operator dashboard with local fixture fallback behavior
- `agent/` — contract documentation for the future privileged endpoint agent
- `schemas/generated/` — JSON Schema exports for API request/response contracts
- `control-packs/` — curated starter control-pack inputs and generated catalog manifest
- `docs/architecture/` — architecture and approval-boundary notes
- `scripts/` — optional systemd/Caddy/cloudflared deployment helpers using placeholder hosts by default

## Control-pack provenance

Checked-in starter controls use a fresh `control.public.*` ID scheme and cite public-source materials:

- NIST SP 800-53 Rev. 5 / OSCAL catalog
- DISA Microsoft Windows Server 2022 STIG V2R5
- CISA/NSA Enhanced Visibility and Hardening Guidance for Communications Infrastructure

CIS Benchmark and Microsoft baseline content are not reproduced in this repository. Future integrations should use citation-only references unless licensing permits checked-in content.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
