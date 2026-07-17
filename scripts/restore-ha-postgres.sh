#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE_FILES_SPEC=${SHA_COMPOSE_FILES:?set SHA_COMPOSE_FILES to the exact colon-separated compose files used to start the stack}
PROJECT=${PROJECT:-ha}
SHA_PUBLIC_PORT=${SHA_PUBLIC_PORT:-8080}
DUMP_FILE=${1:-}
SHA_FILE=${SHA_FILE:-${DUMP_FILE:+$DUMP_FILE.sha256}}

compose_args=(-p "$PROJECT")
IFS=':' read -r -a compose_files <<< "$COMPOSE_FILES_SPEC"
for compose_file in "${compose_files[@]}"; do
  if [[ -z "$compose_file" || ! -r "$compose_file" ]]; then
    echo "unreadable compose file in SHA_COMPOSE_FILES: ${compose_file:-<empty>}" >&2
    exit 1
  fi
  compose_args+=(-f "$compose_file")
done

if [[ "${CONFIRM_RESTORE:-}" != "sha-restore" ]]; then
  echo "set CONFIRM_RESTORE=sha-restore to replace the compose PostgreSQL database" >&2
  exit 1
fi
if [[ -z "$DUMP_FILE" || ! -s "$DUMP_FILE" ]]; then
  echo "usage: CONFIRM_RESTORE=sha-restore $0 /path/to/sha-postgres.dump" >&2
  exit 1
fi
if [[ -z "$SHA_FILE" || ! -s "$SHA_FILE" ]]; then
  echo "missing SHA-256 sidecar: ${SHA_FILE:-$DUMP_FILE.sha256}" >&2
  exit 1
fi
mapfile -t -n 2 sha_lines < "$SHA_FILE"
if [[ ${#sha_lines[@]} -ne 1 || ! ${sha_lines[0]} =~ ^([0-9A-Fa-f]{64})([[:space:]]+\*?.+)?$ ]]; then
  echo "malformed SHA-256 sidecar: $SHA_FILE" >&2
  exit 1
fi
expected_sha256=${BASH_REMATCH[1],,}

umask 077
STAGE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/sha-restore.XXXXXXXX")
chmod 700 "$STAGE_DIR"
services_stopped=0
cleanup() {
  status=$?
  if [[ $services_stopped -eq 1 ]]; then
    compose up -d backend-a backend-b frontend sha-lb >/dev/null 2>&1 || true
  fi
  rm -f -- "$STAGE_DIR/dump"
  rmdir -- "$STAGE_DIR"
  exit "$status"
}
trap cleanup EXIT
STAGED_DUMP="$STAGE_DIR/dump"
cp -- "$DUMP_FILE" "$STAGED_DUMP"
chmod 600 "$STAGED_DUMP"
actual_sha256=$(sha256sum -- "$STAGED_DUMP")
actual_sha256=${actual_sha256%% *}
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "SHA-256 mismatch for dump: $DUMP_FILE" >&2
  exit 1
fi

POSTGRES_PASSWORD=${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD to the deployment value}
SHA_API_TOKEN=${SHA_API_TOKEN:?set SHA_API_TOKEN to the deployment value}
SHA_READONLY_API_TOKEN=${SHA_READONLY_API_TOKEN:?set SHA_READONLY_API_TOKEN to the deployment value}
SHA_AGENT_API_TOKEN=${SHA_AGENT_API_TOKEN:?set SHA_AGENT_API_TOKEN to the deployment value}
SHA_EXTERNAL_AUTH_TRUSTED_TOKEN=${SHA_EXTERNAL_AUTH_TRUSTED_TOKEN:-}

compose() {
  POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  SHA_API_TOKEN="$SHA_API_TOKEN" \
  SHA_READONLY_API_TOKEN="$SHA_READONLY_API_TOKEN" \
  SHA_AGENT_API_TOKEN="$SHA_AGENT_API_TOKEN" \
  SHA_EXTERNAL_AUTH_TRUSTED_TOKEN="$SHA_EXTERNAL_AUTH_TRUSTED_TOKEN" \
  SHA_PUBLIC_PORT="$SHA_PUBLIC_PORT" \
  docker compose "${compose_args[@]}" "$@"
}

compose exec -T postgres pg_restore --list < "$STAGED_DUMP" >/dev/null
compose stop backend-a backend-b frontend sha-lb >/dev/null
services_stopped=1
compose exec -T postgres pg_restore -U sha -d sha --no-owner --no-privileges \
  --clean --if-exists --single-transaction --exit-on-error < "$STAGED_DUMP"
compose up -d --wait --wait-timeout 180 backend-a backend-b frontend sha-lb >/dev/null
services_stopped=0
printf 'RESTORE_OK file=%s project=%s\n' "$DUMP_FILE" "$PROJECT"
