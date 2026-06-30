# SHA HA-ready compose deployment

This compose stack runs SHA with two stateless backend replicas, a shared PostgreSQL database, the Next.js dashboard, and an nginx edge that load-balances `/api/*` and `/health` across the backend replicas.

It is still a starter deployment: put TLS, external identity/SSO, backup policy, and production secrets management in front of it before internet exposure.

```bash
cd deploy/ha
POSTGRES_PASSWORD='replace-me' SHA_API_TOKEN='operator-token' SHA_AGENT_API_TOKEN='agent-token' docker compose up -d --build
curl -H 'Authorization: Bearer operator-token' http://127.0.0.1:8080/api/compliance/evidence
```
