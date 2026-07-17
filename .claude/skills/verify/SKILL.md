---
name: verify
summary: Exercise SHA API and dashboard workflows against managed runtime.
---

1. Run `st pulse --gate`, then `st service rebuild sha --detach` and `st service status sha`.
2. Probe backend at `http://127.0.0.1:8010` and dashboard at `http://127.0.0.1:3010`.
3. Use isolated headless Chrome (`google-chrome --headless=new --no-sandbox --remote-debugging-port=<port> --user-data-dir=$(mktemp -d)`) and CDP to drive actual forms. Capture screenshots under `/tmp`.
4. Core flow: enroll → heartbeat → approval request → browser approval → endpoint grant selection → browser action dispatch. Check unknown endpoint and injected partial API failures.
5. Explicit demo mode is build-time. Temporarily set `frontend/.env.local` to `NEXT_PUBLIC_SHA_DEMO_MODE=true`, rebuild through `st service rebuild`, verify global warning/fixtures/no mutation controls, then remove the file and rebuild live mode.
6. Protected artifact check needs an isolated socket with operator token and no agent token; artifact GET must return 503. Never use real credentials.
7. Do not use tests/typecheck as runtime evidence. Restore live mode and stop isolated processes afterward.
