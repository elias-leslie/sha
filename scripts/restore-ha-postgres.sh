#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE_FILE=${COMPOSE_FILE:-$ROOT_DIR/deploy/ha/docker-compose.yml}
PROJECT=${PROJECT:-ha}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-sha-dev-password}
SHA_API_TOKEN=${SHA_API_TOKEN:-operator-token}
SHA_READONLY_API_TOKEN=${SHA_READONLY_API_TOKEN:-readonly-token}
SHA_AGENT_API_TOKEN=${SHA_AGENT_API_TOKEN:-agent-token}
SHA_EXTERNAL_AUTH_TRUSTED_TOKEN=${SHA_EXTERNAL_AUTH_TRUSTED_TOKEN:-}
SHA_PUBLIC_PORT=${SHA_PUBLIC_PORT:-8080}
DUMP_FILE=${1:-}

if [[ -z "$DUMP_FILE" || ! -s "$DUMP_FILE" ]]; then
  echo "usage: CONFIRM_RESTORE=sha-restore $0 /path/to/sha-postgres.dump" >&2
  exit 1
fi
if [[ "${CONFIRM_RESTORE:-}" != "sha-restore" ]]; then
  echo "set CONFIRM_RESTORE=sha-restore to replace the compose PostgreSQL database" >&2
  exit 1
fi

compose() {
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$SHA_API_TOKEN" \
  SHA_READONLY_API_TOKEN="$SHA_READONLY_API_TOKEN" \
  SHA_AGENT_API_TOKEN="$SHA_AGENT_API_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$SHA_EXTERNAL_AUTH_TRUSTED_TOKEN" \
  SHA_PUBLIC_PORT="$SHA_PUBLIC_PORT" \
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"
}

compose stop backend-a backend-b frontend sha-lb >/dev/null
compose exec -T postgres psql -U sha -d sha -v ON_ERROR_STOP=1 \
  -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public;' >/dev/null
compose exec -T postgres pg_restore -U sha -d sha --no-owner --no-privileges < "$DUMP_FILE"
compose up -d --wait --wait-timeout 180 backend-a backend-b frontend sha-lb >/dev/null
printf 'RESTORE_OK file=%s project=%s\n' "$DUMP_FILE" "$PROJECT"
