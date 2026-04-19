# SHA backend

FastAPI control-plane foundation for endpoint enrollment, heartbeats, posture snapshot uploads, installer profiles, deterministic bootstrap artifact generation, approval requests, and approval grants.

Local development:
- uv sync
- uv run uvicorn app.main:app --reload --port 8010

SQLite defaults to `data/sha.sqlite3` when running inside `backend/` (repo path `backend/data/sha.sqlite3`) and is created automatically on startup.

Current API highlights:
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

Bootstrap artifact notes:
- Linux installer profiles render a shell bootstrap that installs a Python reporter plus a systemd timer/service.
- Windows installer profiles render a PowerShell bootstrap that installs a PowerShell reporter plus a recurring scheduled task.
- The installed reporter only performs bounded read-only posture collection, enrollment, and heartbeat uploads.
- Artifact responses include `Content-Disposition` and `X-SHA-Artifact-Sha256` headers.
