#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT_DIR=${OUT_DIR:-"$ROOT_DIR/agent/dist"}
VERSION=${VERSION:-sha-go-agent-v0.1.0}
TARGETS=(
  linux/amd64
  linux/arm64
  windows/amd64
  darwin/amd64
  darwin/arm64
)

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

for target in "${TARGETS[@]}"; do
  goos=${target%/*}
  goarch=${target#*/}
  name="sha-agent-${VERSION}-${goos}-${goarch}"
  binary="sha-agent"
  if [[ "$goos" == "windows" ]]; then
    binary="sha-agent.exe"
  fi
  stage="$OUT_DIR/$name"
  mkdir -p "$stage"
  (
    cd "$ROOT_DIR/agent"
    GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$stage/$binary" ./cmd/sha-agent
  )
  cp "$ROOT_DIR/agent/README.md" "$stage/README.md"
  cp "$ROOT_DIR/agent/docs/agent-contract.md" "$stage/agent-contract.md"
  case "$goos" in
    linux)
      cp "$ROOT_DIR/scripts/install-sha-agent-linux.sh" "$stage/install-linux.sh"
      cp "$ROOT_DIR/scripts/systemd/sha-agent.service" "$stage/sha-agent.service"
      tar -C "$OUT_DIR" -czf "$OUT_DIR/$name.tar.gz" "$name"
      ;;
    darwin)
      cp "$ROOT_DIR/scripts/install-sha-agent-macos.sh" "$stage/install-macos.sh"
      cp "$ROOT_DIR/scripts/launchd/com.sha.agent.plist" "$stage/com.sha.agent.plist"
      tar -C "$OUT_DIR" -czf "$OUT_DIR/$name.tar.gz" "$name"
      ;;
    windows)
      cp "$ROOT_DIR/scripts/install-sha-agent-windows.ps1" "$stage/install-windows.ps1"
      (cd "$OUT_DIR" && zip -qr "$name.zip" "$name")
      ;;
  esac
  printf 'built %s\n' "$stage/$binary"
done
