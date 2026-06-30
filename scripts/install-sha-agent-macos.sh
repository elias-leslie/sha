#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
DESTDIR=${DESTDIR:-}
BINARY_PATH=${BINARY_PATH:-/usr/local/sbin/sha-agent}
CONFIG_PATH=${CONFIG_PATH:-/Library/Application Support/SHA/agent-config.json}
LAUNCHD_DIR=${LAUNCHD_DIR:-/Library/LaunchDaemons}
SKIP_LAUNCHD=${SKIP_LAUNCHD:-0}

install -d "${DESTDIR}${BINARY_PATH%/*}" "${DESTDIR}${CONFIG_PATH%/*}" "${DESTDIR}${LAUNCHD_DIR}"
if [[ -d "$ROOT_DIR/agent" ]]; then
  (
    cd "$ROOT_DIR/agent"
    go build -o "${DESTDIR}${BINARY_PATH}" ./cmd/sha-agent
  )
elif [[ -x "$SCRIPT_DIR/sha-agent" ]]; then
  install -m 0755 "$SCRIPT_DIR/sha-agent" "${DESTDIR}${BINARY_PATH}"
else
  echo "missing agent source or bundled sha-agent binary" >&2
  exit 1
fi
chmod 0755 "${DESTDIR}${BINARY_PATH}"

if [[ ! -f "${DESTDIR}${CONFIG_PATH}" ]]; then
  cat > "${DESTDIR}${CONFIG_PATH}" <<'JSON'
{
  "control_plane_url": "https://sha.example.test",
  "api_token": "replace-with-SHA_AGENT_API_TOKEN",
  "profile_id": "macos-agent",
  "agent_version": "sha-go-agent-v0.1.0"
}
JSON
  chmod 0600 "${DESTDIR}${CONFIG_PATH}"
fi

PLIST_TEMPLATE="$SCRIPT_DIR/com.sha.agent.plist"
if [[ ! -f "$PLIST_TEMPLATE" ]]; then
  PLIST_TEMPLATE="$ROOT_DIR/scripts/launchd/com.sha.agent.plist"
fi

sed \
  -e "s#/usr/local/sbin/sha-agent#${BINARY_PATH}#g" \
  -e "s#/Library/Application Support/SHA/agent-config.json#${CONFIG_PATH}#g" \
  "$PLIST_TEMPLATE" > "${DESTDIR}${LAUNCHD_DIR}/com.sha.agent.plist"
chmod 0644 "${DESTDIR}${LAUNCHD_DIR}/com.sha.agent.plist"

if [[ "$SKIP_LAUNCHD" != "1" && -z "$DESTDIR" ]] && command -v launchctl >/dev/null 2>&1; then
  launchctl bootstrap system "$LAUNCHD_DIR/com.sha.agent.plist" 2>/dev/null || launchctl kickstart -k system/com.sha.agent
fi

printf 'installed sha-agent binary=%s config=%s plist=%s\n' "$BINARY_PATH" "$CONFIG_PATH" "$LAUNCHD_DIR/com.sha.agent.plist"
