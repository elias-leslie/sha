#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUT_DIR=${OUT_DIR:-$ROOT_DIR/.dev-tools/sha-agent-release-test}

(
  cd "$ROOT_DIR/agent"
  go test ./...
)
OUT_DIR="$OUT_DIR" "$ROOT_DIR/scripts/build-sha-agent-release.sh"
file "$OUT_DIR/sha-agent-sha-go-agent-v0.1.0-windows-amd64/sha-agent.exe" | grep -q 'PE32+ executable'
file "$OUT_DIR/sha-agent-sha-go-agent-v0.1.0-darwin-arm64/sha-agent" | grep -q 'Mach-O 64-bit arm64'
file "$OUT_DIR/sha-agent-sha-go-agent-v0.1.0-linux-amd64/sha-agent" | grep -q 'ELF 64-bit'
grep -q 'windows_firewall_rollback_path' "$OUT_DIR/sha-agent-sha-go-agent-v0.1.0-windows-amd64/install-windows.ps1"
printf 'SHA_AGENT_RELEASE_TEST_OK out_dir=%s\n' "$OUT_DIR"
