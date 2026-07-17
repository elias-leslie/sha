#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE_FILES_SPEC=${SHA_COMPOSE_FILES:?set SHA_COMPOSE_FILES to the exact colon-separated compose files used to start the stack}
PROJECT=${PROJECT:-ha}
BACKUP_DIR=${BACKUP_DIR:-$ROOT_DIR/backups}
STAMP=${STAMP:-$(date -u +%Y%m%d%H%M%S)}
BACKUP_FILE=${BACKUP_FILE:-$BACKUP_DIR/sha-postgres-$STAMP.dump}
SHA_FILE=${SHA_FILE:-$BACKUP_FILE.sha256}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD to the deployment value}
SHA_API_TOKEN=${SHA_API_TOKEN:?set SHA_API_TOKEN to the deployment value}
SHA_READONLY_API_TOKEN=${SHA_READONLY_API_TOKEN:?set SHA_READONLY_API_TOKEN to the deployment value}
SHA_AGENT_API_TOKEN=${SHA_AGENT_API_TOKEN:?set SHA_AGENT_API_TOKEN to the deployment value}
SHA_EXTERNAL_AUTH_TRUSTED_TOKEN=${SHA_EXTERNAL_AUTH_TRUSTED_TOKEN:-}
SHA_PUBLIC_PORT=${SHA_PUBLIC_PORT:-8080}

compose_args=(-p "$PROJECT")
IFS=':' read -r -a compose_files <<< "$COMPOSE_FILES_SPEC"
for compose_file in "${compose_files[@]}"; do
  if [[ -z "$compose_file" || ! -r "$compose_file" ]]; then
    echo "unreadable compose file in SHA_COMPOSE_FILES: ${compose_file:-<empty>}" >&2
    exit 1
  fi
  compose_args+=(-f "$compose_file")
done

umask 077
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$SHA_API_TOKEN" \
  SHA_READONLY_API_TOKEN="$SHA_READONLY_API_TOKEN" \
  SHA_AGENT_API_TOKEN="$SHA_AGENT_API_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$SHA_EXTERNAL_AUTH_TRUSTED_TOKEN" \
  SHA_PUBLIC_PORT="$SHA_PUBLIC_PORT" \
  docker compose "${compose_args[@]}" exec -T postgres \
  pg_dump -U sha -d sha --format=custom --no-owner --no-privileges > "$BACKUP_FILE"
test -s "$BACKUP_FILE"
chmod 600 "$BACKUP_FILE"
sha256sum "$BACKUP_FILE" > "$SHA_FILE"
chmod 600 "$SHA_FILE"
printf 'BACKUP_FILE=%s\nSHA256_FILE=%s\n' "$BACKUP_FILE" "$SHA_FILE"
