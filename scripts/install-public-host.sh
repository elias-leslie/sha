#!/usr/bin/env bash
set -euo pipefail

CADDY_CONFIG="${CADDY_CONFIG:-/etc/caddy/Caddyfile}"
CADDY_ENV_FILE="${CADDY_ENV_FILE:-/etc/caddy/env}"
PUBLIC_HOST="${PUBLIC_HOST:-sha.example.test}"
TARGET="${TARGET:-localhost:3010}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this script with sudo." >&2
  exit 1
fi

python3 - "$CADDY_CONFIG" "$PUBLIC_HOST" "$TARGET" <<'PY'
from pathlib import Path
import sys

config_path = Path(sys.argv[1])
host = sys.argv[2]
target = sys.argv[3]
text = config_path.read_text()
matcher_name = ''.join(ch for ch in host if ch.isalnum()).lower()
block = (
    f"\n\t@{matcher_name} host {host}\n"
    f"\thandle @{matcher_name} {{\n"
    f"\t\treverse_proxy {target}\n"
    f"\t}}\n"
)

if host not in text:
    sentinel = '\n\thandle {\n\t\trespond "Not Found" 404\n\t}\n}\n'
    if sentinel not in text:
        raise SystemExit('Could not find Caddy fallback block to insert before.')
    text = text.replace(sentinel, block + sentinel, 1)
    config_path.write_text(text)
PY

if [[ -f "$CADDY_ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$CADDY_ENV_FILE"
  set +a
fi

caddy validate --config "$CADDY_CONFIG"
systemctl restart caddy
systemctl --no-pager --lines=20 status caddy

echo
echo "Verification:"
curl -k -I --max-time 15 "https://${PUBLIC_HOST}/" | sed -n '1,20p'
echo
echo "Health:"
curl -k -I --max-time 15 "https://${PUBLIC_HOST}/health" | sed -n '1,20p'
