# SHA frontend

Next.js operator dashboard for SHA fleet posture, endpoint detail, approvals, installer generation, and operator-assistant activity visibility.

## Run

```bash
pnpm install
API_URL=http://127.0.0.1:8010 pnpm dev --port 3010
```

## Validate

```bash
pnpm test
pnpm exec tsc --noEmit
pnpm build
```

The dashboard includes typed fixture fallbacks for most read-only views, so it can render during frontend-only development. API-backed actions require the backend.
