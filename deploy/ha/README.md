# SHA HA-ready compose deployment

This compose stack runs SHA with two stateless backend replicas, a shared PostgreSQL database, a one-shot Alembic migration service, the Next.js dashboard, and an nginx edge that load-balances `/api/*` and `/health` across the backend replicas. API replicas use migration-check mode and refuse to serve against schema drift.

It is still a starter deployment: bring your own production certificate/key and production secrets management before internet exposure. `SHA_AGENT_API_TOKEN` is required for compatibility reporter generation whenever operator API-token or trusted external-proxy authentication is enabled; artifacts never embed the operator token. Downloads are marked private/no-store, are not previewed by the dashboard, and are not signed production packages.

The frontend does not inject an operator token: callers must arrive with caller-bound authorization. Both the HA nginx API edge and the stock Next.js browser proxy strip all `X-SHA-External-*` headers, including spoofed ones; the browser proxy also returns redirects without following them with credentials. The HA edge sends `/api/*` directly to the two-backend upstream so both replicas serve API traffic. Backend trusted-proxy auth is therefore for a separately protected direct API route or a future session adapter, not a caller-controlled header path through either stock public boundary. No login/token-entry screen is bundled yet; normal browser use of this protected stack needs an upstream caller-auth/session adapter, while API clients can send the operator or read-only bearer token directly.

Docker Compose 2.24.4 or newer is required because the TLS overlay uses `!override`. The base stack has no public fallback passwords, API tokens, or device-credential hashing key: Compose stops before creating services unless `POSTGRES_PASSWORD`, `SHA_API_TOKEN`, `SHA_READONLY_API_TOKEN`, `SHA_AGENT_API_TOKEN`, and `SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE` are explicitly supplied. Set the last value to a stable absolute host path for a regular, non-symlink file containing 32-4096 random bytes; the absolute form prevents launch and restore from resolving the source against different working directories. Preserve that key across replicas and database restores; replacing it invalidates existing enrollment tokens and device credentials. Frontend demo mode defaults off. To change it, set `NEXT_PUBLIC_SHA_DEMO_MODE=true|false` and rebuild the frontend image with `docker compose build frontend` (or use `up --build`); it is a compile-time frontend setting.

```bash
cd deploy/ha
export SHA_SECRET_DIR=/absolute/path/outside/repository/sha-secrets
install -d -m 700 "$SHA_SECRET_DIR"
export POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export SHA_API_TOKEN="$(openssl rand -hex 32)"
export SHA_READONLY_API_TOKEN="$(openssl rand -hex 32)"
export SHA_AGENT_API_TOKEN="$(openssl rand -hex 32)"
install -m 600 /dev/null "$SHA_SECRET_DIR/sha-credential-hmac-key"
openssl rand 48 > "$SHA_SECRET_DIR/sha-credential-hmac-key"
export SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$SHA_SECRET_DIR/sha-credential-hmac-key"
install -m 600 /dev/null "$SHA_SECRET_DIR/operator.curlrc"
printf 'header = "Authorization: Bearer %s"\n' "$SHA_API_TOKEN" > "$SHA_SECRET_DIR/operator.curlrc"
docker compose up -d --build
curl -q --config "$SHA_SECRET_DIR/operator.curlrc" http://127.0.0.1:8080/api/compliance/evidence
```

The base published port is plaintext and intended only for an isolated local validation host. Use the TLS overlay for any network-reachable deployment.

Enable HTTPS-only nginx with a directory containing `tls.crt` and `tls.key`. The certificate must chain to a trust anchor available to clients and cover the hostname or IP they use. The TLS overlay enables TLS 1.2/1.3, uses Docker Compose's `!override` tag to remove the base stack's plaintext published port, and nginx does not start a plaintext listener:

```bash
cd deploy/ha
export SHA_SECRET_DIR=/absolute/path/outside/repository/sha-secrets
SHA_TLS_CERT_DIR="$PWD/certs" SHA_TLS_PORT=8443 SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$SHA_SECRET_DIR/sha-credential-hmac-key" docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
curl -q --config "$SHA_SECRET_DIR/operator.curlrc" --cacert "/absolute/path/to/private-ca.pem" https://sha.example.test:8443/api/compliance/evidence
```

The `operator.curlrc` file contains a bearer token; keep it mode 0600 in an approved secret location and remove it when no longer needed. Do not replace `--cacert` with an insecure verification bypass. The current overlay terminates TLS at nginx; backend, frontend, and PostgreSQL traffic inside the Compose network remains plaintext, so production deployments must treat that network as one trust zone or add internal transport protection.

Use file-mounted Docker secrets for backend tokens and database URL:

```bash
cd deploy/ha
export SHA_SECRET_DIR=/absolute/path/outside/repository/sha-secrets
POSTGRES_PASSWORD_SECRET_FILE="$SHA_SECRET_DIR/postgres_password" \
SHA_DATABASE_URL_SECRET_FILE="$SHA_SECRET_DIR/sha_database_url" \
SHA_API_TOKEN_SECRET_FILE="$SHA_SECRET_DIR/sha_api_token" \
SHA_READONLY_API_TOKEN_SECRET_FILE="$SHA_SECRET_DIR/sha_readonly_api_token" \
SHA_AGENT_API_TOKEN_SECRET_FILE="$SHA_SECRET_DIR/sha_agent_api_token" \
SHA_EXTERNAL_AUTH_TRUSTED_TOKEN_SECRET_FILE="$SHA_SECRET_DIR/sha_external_auth_trusted_token" \
SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="$SHA_SECRET_DIR/sha_credential_hmac_key" \
POSTGRES_PASSWORD=overridden-by-postgres-secret-file \
SHA_API_TOKEN=overridden-by-operator-secret-file \
SHA_READONLY_API_TOKEN=overridden-by-readonly-secret-file \
SHA_AGENT_API_TOKEN=overridden-by-agent-secret-file \
docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build
```

The four `overridden-by-...` values satisfy base-file interpolation only. The secrets overlay replaces them before container creation and mounts the real values from the listed files. The credential-HMAC key is already file-only in the base stack, so both base and file-secret launches use `SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE`; never place that key in an environment variable.

Backup and restore PostgreSQL:

Both commands require the same `POSTGRES_PASSWORD`, `SHA_API_TOKEN`, `SHA_READONLY_API_TOKEN`, `SHA_AGENT_API_TOKEN`, and `SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE` values used to start the stack. Export them from your approved secret source first; neither script supplies fallback credentials. Database dumps do not contain the credential-HMAC key, so back it up through the approved secret system and restore the exact same file before starting SHA. `SHA_COMPOSE_FILES` must contain the exact compose files used to launch the deployment, in the same order, separated by colons. Restore refuses an ambiguous topology so it cannot accidentally restart without the TLS or file-secret overlay.

```bash
export SHA_COMPOSE_FILES="$PWD/docker-compose.yml"
export SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE="/absolute/path/outside/repository/sha-secrets/sha-credential-hmac-key"
PROJECT=ha ../../scripts/backup-ha-postgres.sh
# The restore requires and verifies <dump>.sha256 before any Docker action.
# Set SHA_FILE=/other/path only when the sidecar is stored elsewhere.
CONFIRM_RESTORE=sha-restore PROJECT=ha ../../scripts/restore-ha-postgres.sh ../../backups/sha-postgres-YYYYmmddHHMMSS.dump
```

TLS deployment example: `export SHA_COMPOSE_FILES="$PWD/docker-compose.yml:$PWD/docker-compose.tls.yml"`; keep `SHA_TLS_CERT_DIR`, `SHA_TLS_PORT`, and `SHA_CREDENTIAL_HMAC_KEY_SECRET_FILE` exported for both commands. File-secret deployment example: select `docker-compose.secrets.yml` instead, keep every `*_SECRET_FILE` path exported, and use the same base-file interpolation placeholders as launch. The default backup directory is repository-root `backups/`, excluded from Git and Docker build contexts; it is created mode 0700 and its dump and digest files mode 0600.
