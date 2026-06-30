# SHA backend

FastAPI control-plane foundation for endpoint enrollment, heartbeats, posture snapshot uploads, installer profiles, deterministic bootstrap artifact generation, approval requests/grants, response-action dispatch, and source-pack catalog reads.

## Run

```bash
uv sync
uv run uvicorn app.main:app --host 127.0.0.1 --port 8010
```

SQLite defaults to `data/sha.sqlite3` when running inside `backend/` and is created automatically on startup. Override with `SHA_DATABASE_URL`.

Set `SHA_API_TOKEN` to require `Authorization: Bearer <token>` or `X-SHA-API-Token` on `/api/*` routes. `/health` remains unauthenticated for service checks. Set `SHA_AGENT_API_TOKEN` to embed a least-privilege token in generated reporters instead of the operator token.

## Test and regenerate generated files

```bash
uv run pytest
uv run python scripts/migrate.py
uv run python scripts/build_source_catalog.py
uv run python scripts/export_contract_schemas.py
```

## API highlights

- `GET /health`
- `POST /api/endpoints/enroll`
- `POST /api/endpoints/{endpoint_id}/heartbeat`
- `GET /api/endpoints`
- `GET /api/endpoints/{endpoint_id}`
- `POST /api/posture-snapshots`
- `GET/POST /api/installer-profiles`
- `GET /api/installer-profiles/{profile_id}/artifact`
- `GET/POST /api/approval-requests`
- `POST /api/approval-requests/{approval_request_id}/decisions`
- `GET/POST /api/approval-grants`
- `POST /api/response-actions`
- `GET /api/endpoints/{endpoint_id}/response-actions`
- `POST /api/response-actions/{response_action_id}/result`
- `GET /api/source-packs`

Bootstrap artifacts stay inside SHA's bounded posture boundary: enrollment, heartbeat, and small read-only posture snapshots. They do not expose arbitrary shell access.
When `SHA_API_TOKEN` is enabled, generated reporters include the active bearer token in their API calls.
