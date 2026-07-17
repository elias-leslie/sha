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

Normal mode uses the live backend and shows loading/error/empty state when it is unavailable. Fixture data appears only when the frontend is built with `NEXT_PUBLIC_SHA_DEMO_MODE=true`; demo mode is visibly labeled and mutations are disabled.
