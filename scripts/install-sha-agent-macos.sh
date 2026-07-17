#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
DESTDIR=${DESTDIR:-}
BINARY_PATH=${BINARY_PATH:-/usr/local/sbin/sha-agent}
CONFIG_PATH=${CONFIG_PATH:-/Library/Application Support/SHA/agent-config.json}
LAUNCHD_DIR=${LAUNCHD_DIR:-/Library/LaunchDaemons}
SKIP_LAUNCHD=${SKIP_LAUNCHD:-0}

die() {
  echo "$1" >&2
  exit 1
}

require_fixed_path() {
  local value=$1
  local expected=$2
  local label=$3
  if [[ "$value" != "$expected" ]]; then
    die "$label must use the dedicated SHA path $expected"
  fi
}

reject_symlink_components() {
  local path=$1
  local label=$2
  local relative=${path#/}
  local current=""
  local component
  local -a components
  local IFS=/
  read -r -a components <<< "$relative"
  for component in "${components[@]}"; do
    current="$current/$component"
    if [[ -L "$current" ]]; then
      die "$label contains a symlink component: $current"
    fi
  done
}

mode_of() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

owner_of() {
  stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

assert_secure_system_directory() {
  local path=$1
  local mode
  if [[ ! -d "$path" ]]; then
    die "required system directory is missing: $path"
  fi
  if [[ "$(owner_of "$path")" != "0" ]]; then
    die "system directory must be owned by root: $path"
  fi
  mode=$(mode_of "$path")
  if (( (8#$mode & 0022) != 0 )); then
    die "system directory must not be group- or world-writable: $path"
  fi
}

require_fixed_path "$BINARY_PATH" "/usr/local/sbin/sha-agent" "BINARY_PATH"
require_fixed_path "$CONFIG_PATH" "/Library/Application Support/SHA/agent-config.json" "CONFIG_PATH"
require_fixed_path "$LAUNCHD_DIR" "/Library/LaunchDaemons" "LAUNCHD_DIR"

INSTALL_UID=$(id -u)
if [[ -z "$DESTDIR" && "$INSTALL_UID" -ne 0 ]]; then
  die "sha-agent installation requires root"
fi
if [[ -n "$DESTDIR" ]]; then
  if [[ "$DESTDIR" != /* || "$DESTDIR" == "/" || "$DESTDIR" == */ || "$DESTDIR" == *$'\n'* || "$DESTDIR" == *$'\r'* ]]; then
    die "DESTDIR must be a dedicated absolute staging directory"
  fi
  case "/${DESTDIR#/}/" in
    *'/../'*|*'/./'*|*'//'*) die "DESTDIR must be normalized" ;;
  esac
  reject_symlink_components "$DESTDIR" "DESTDIR"
  if [[ -e "$DESTDIR" && ! -d "$DESTDIR" ]]; then
    die "DESTDIR exists and is not a directory: $DESTDIR"
  elif [[ ! -e "$DESTDIR" ]]; then
    install -d -m 0755 "$DESTDIR"
  fi
fi

BINARY_DIR="${DESTDIR}${BINARY_PATH%/*}"
STATE_DIR="${DESTDIR}${CONFIG_PATH%/*}"
PLIST_DIR="${DESTDIR}${LAUNCHD_DIR}"
BINARY_TARGET="${DESTDIR}${BINARY_PATH}"
CONFIG_TARGET="${DESTDIR}${CONFIG_PATH}"
PLIST_TARGET="$PLIST_DIR/com.sha.agent.plist"

reject_symlink_components "$BINARY_DIR" "binary directory"
reject_symlink_components "$STATE_DIR" "state directory"
reject_symlink_components "$PLIST_DIR" "launchd directory"
for directory in "$BINARY_DIR" "$PLIST_DIR"; do
  if [[ -e "$directory" && ! -d "$directory" ]]; then
    die "required install path is not a directory: $directory"
  elif [[ ! -e "$directory" ]]; then
    install -d -m 0755 "$directory"
  fi
done
install -d -m 0700 "$STATE_DIR"
chmod 0700 "$STATE_DIR"
if [[ "$INSTALL_UID" -eq 0 ]]; then
  chown 0:0 "$STATE_DIR"
fi
if [[ -z "$DESTDIR" ]]; then
  assert_secure_system_directory "$BINARY_DIR"
  assert_secure_system_directory "$PLIST_DIR"
fi
for target in "$BINARY_TARGET" "$CONFIG_TARGET" "$PLIST_TARGET"; do
  if [[ -L "$target" ]]; then
    die "refusing symlinked SHA install target: $target"
  fi
done
if [[ -e "$CONFIG_TARGET" && ! -f "$CONFIG_TARGET" ]]; then
  die "SHA config exists and is not a regular file: $CONFIG_TARGET"
fi
if [[ -d "$ROOT_DIR/agent" ]]; then
  (
    cd "$ROOT_DIR/agent"
    go build -o "$BINARY_TARGET" ./cmd/sha-agent
  )
elif [[ -x "$SCRIPT_DIR/sha-agent" ]]; then
  if [[ -L "$SCRIPT_DIR/sha-agent" ]]; then
    die "refusing symlinked bundled sha-agent binary"
  fi
  install -m 0755 "$SCRIPT_DIR/sha-agent" "$BINARY_TARGET"
else
  die "missing agent source or bundled sha-agent binary"
fi
chmod 0755 "$BINARY_TARGET"
if [[ "$INSTALL_UID" -eq 0 ]]; then
  chown 0:0 "$BINARY_TARGET"
fi

if [[ ! -f "$CONFIG_TARGET" ]]; then
  install -m 0600 /dev/null "$CONFIG_TARGET"
  cat > "$CONFIG_TARGET" <<'JSON'
{
  "control_plane_url": "https://sha.example.test",
  "api_token": "replace-with-SHA_AGENT_API_TOKEN",
  "profile_id": "macos-agent",
  "agent_version": "sha-go-agent-v0.1.0"
}
JSON
fi
chmod 0600 "$CONFIG_TARGET"
if [[ "$INSTALL_UID" -eq 0 ]]; then
  chown 0:0 "$CONFIG_TARGET"
fi

PLIST_TEMPLATE="$SCRIPT_DIR/com.sha.agent.plist"
if [[ ! -f "$PLIST_TEMPLATE" ]]; then
  PLIST_TEMPLATE="$ROOT_DIR/scripts/launchd/com.sha.agent.plist"
fi

sed \
  -e "s#/usr/local/sbin/sha-agent#${BINARY_PATH}#g" \
  -e "s#/Library/Application Support/SHA/agent-config.json#${CONFIG_PATH}#g" \
  "$PLIST_TEMPLATE" > "$PLIST_TARGET"
chmod 0644 "$PLIST_TARGET"
if [[ "$INSTALL_UID" -eq 0 ]]; then
  chown 0:0 "$PLIST_TARGET"
fi

if [[ "$SKIP_LAUNCHD" != "1" && -z "$DESTDIR" ]] && command -v launchctl >/dev/null 2>&1; then
  launchctl bootstrap system "$LAUNCHD_DIR/com.sha.agent.plist" 2>/dev/null || launchctl kickstart -k system/com.sha.agent
fi

printf 'installed sha-agent binary=%s config=%s plist=%s\n' "$BINARY_PATH" "$CONFIG_PATH" "$LAUNCHD_DIR/com.sha.agent.plist"
