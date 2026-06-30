#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE_FILE=${COMPOSE_FILE:-$ROOT_DIR/deploy/ha/docker-compose.yml}
PROJECT=${PROJECT:-ha}
BACKUP_DIR=${BACKUP_DIR:-$ROOT_DIR/backups}
STAMP=${STAMP:-$(date -u +%Y%m%d%H%M%S)}
BACKUP_FILE=${BACKUP_FILE:-$BACKUP_DIR/sha-postgres-$STAMP.dump}
SHA_FILE=${SHA_FILE:-$BACKUP_FILE.sha256}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-sha-dev-password}
SHA_PUBLIC_PORT=${SHA_PUBLIC_PORT:-8080}

mkdir -p "$BACKUP_DIR"
POSTGRES_PASSWORD="$POSTGRES_PASSWORD" SHA_PUBLIC_PORT="$SHA_PUBLIC_PORT" \
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" exec -T postgres \
  pg_dump -U sha -d sha --format=custom --no-owner --no-privileges > "$BACKUP_FILE"
test -s "$BACKUP_FILE"
sha256sum "$BACKUP_FILE" > "$SHA_FILE"
printf 'BACKUP_FILE=%s\nSHA256_FILE=%s\n' "$BACKUP_FILE" "$SHA_FILE"
