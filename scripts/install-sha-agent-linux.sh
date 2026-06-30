#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DESTDIR=${DESTDIR:-}
BINARY_PATH=${BINARY_PATH:-/usr/local/sbin/sha-agent}
CONFIG_PATH=${CONFIG_PATH:-/etc/sha/agent-config.json}
SYSTEMD_DIR=${SYSTEMD_DIR:-/etc/systemd/system}
SKIP_SYSTEMD=${SKIP_SYSTEMD:-0}

install -d "${DESTDIR}${BINARY_PATH%/*}" "${DESTDIR}${CONFIG_PATH%/*}" "${DESTDIR}${SYSTEMD_DIR}"
(
  cd "$ROOT_DIR/agent"
  go build -o "${DESTDIR}${BINARY_PATH}" ./cmd/sha-agent
)
chmod 0755 "${DESTDIR}${BINARY_PATH}"

if [[ ! -f "${DESTDIR}${CONFIG_PATH}" ]]; then
  cat > "${DESTDIR}${CONFIG_PATH}" <<'JSON'
{
  "control_plane_url": "https://sha.example.test",
  "api_token": "replace-with-SHA_AGENT_API_TOKEN",
  "profile_id": "linux-agent",
  "agent_version": "sha-go-agent-v0.1.0",
  "sshd_hardening_path": "/etc/ssh/sshd_config.d/99-sha-hardening.conf"
}
JSON
  chmod 0600 "${DESTDIR}${CONFIG_PATH}"
fi

sed \
  -e "s#/usr/local/sbin/sha-agent#${BINARY_PATH}#g" \
  -e "s#/etc/sha/agent-config.json#${CONFIG_PATH}#g" \
  "$ROOT_DIR/scripts/systemd/sha-agent.service" > "${DESTDIR}${SYSTEMD_DIR}/sha-agent.service"
chmod 0644 "${DESTDIR}${SYSTEMD_DIR}/sha-agent.service"

if [[ "$SKIP_SYSTEMD" != "1" && -z "$DESTDIR" ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now sha-agent.service
fi

printf 'installed sha-agent binary=%s config=%s unit=%s\n' "$BINARY_PATH" "$CONFIG_PATH" "$SYSTEMD_DIR/sha-agent.service"
