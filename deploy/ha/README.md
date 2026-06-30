# SHA HA-ready compose deployment

This compose stack runs SHA with two stateless backend replicas, a shared PostgreSQL database, the Next.js dashboard, and an nginx edge that load-balances `/api/*` and `/health` across the backend replicas.

It is still a starter deployment: put TLS and production secrets management in front of it before internet exposure. For SSO/identity-proxy deployments, set `SHA_EXTERNAL_AUTH_TRUSTED_TOKEN` and have the trusted proxy strip client `X-SHA-External-*` headers before adding `X-SHA-External-Auth` and `X-SHA-External-Role: operator|readonly`.

```bash
cd deploy/ha
POSTGRES_PASSWORD='replace-me' SHA_API_TOKEN='operator-token' SHA_READONLY_API_TOKEN='readonly-token' SHA_AGENT_API_TOKEN='agent-token' docker compose up -d --build
curl -H 'Authorization: Bearer operator-token' http://127.0.0.1:8080/api/compliance/evidence
```

Backup and restore PostgreSQL:

```bash
PROJECT=ha ../../scripts/backup-ha-postgres.sh
CONFIRM_RESTORE=sha-restore PROJECT=ha ../../scripts/restore-ha-postgres.sh ../../backups/sha-postgres-YYYYmmddHHMMSS.dump
```
