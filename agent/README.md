# SHA agent

Minimal Go endpoint agent for SHA. This is the long-term endpoint runtime; generated Python/PowerShell compatibility reporters are separate migration shims.

The agent is privileged locally but exposes only typed hardening/reporting verbs through the control-plane API. It is not a remote shell.

Current Go implementation:

- Linux, Windows, and macOS enroll, heartbeat, posture snapshot upload, atomic queued-action claim, and lease-bound result reporting
- least-privilege `SHA_AGENT_API_TOKEN` authentication for the current shared-credential Phase 0 protocol
- Windows Firewall all-profile posture plus apply/rollback for `control.windows.firewall-all-profiles`, with a persisted rollback artifact
- Linux remains unable to apply SSH mutations; it exposes only rollback for `linux.ssh.password-authentication-disabled`, removing the historical Go-managed drop-in only when its bytes exactly match the legacy payload
- macOS mutations and all other Go Linux mutations fail unsupported without filesystem or command changes
- evidence action verbs are not advertised; stale evidence jobs fail unsupported instead of reporting canned evidence
- dry-run is not implemented and is advertised as false on every platform
- macOS observe-only posture for Application Firewall, FileVault, and Gatekeeper

The agent never receives an executable command string. It claims at most one typed action at a time, returns the opaque lease token with the result, and reports unsupported work as failed without attempting a mutation.

Install as a Linux systemd service:

```bash
sudo scripts/install-sha-agent-linux.sh
sudoedit /etc/sha/agent-config.json
sudo systemctl restart sha-agent
```

Build release bundles:

```bash
scripts/build-sha-agent-release.sh
```

Verify release bundles:

```bash
scripts/test-sha-agent-release.sh
```

Build and run once:

```bash
go build ./cmd/sha-agent
sudo ./sha-agent -config /etc/sha/agent-config.json
```

Config shape:

```json
{
  "control_plane_url": "https://sha.example.test",
  "api_token": "agent-token",
  "profile_id": "linux-prod",
  "agent_version": "sha-go-agent-v0.1.0",
  "sshd_hardening_path": "/etc/ssh/sshd_config.d/99-sha-hardening.conf",
  "windows_firewall_rollback_path": "C:\\\\ProgramData\\\\SHA\\\\firewall-profiles-rollback.json"
}
```

Treat the config as a secret because `api_token` is the current shared agent credential. Use an HTTPS control-plane URL outside loopback development. The Go HTTP client and compatibility reporters use normal platform certificate validation and expose no insecure verification bypass; install a private CA in the operating-system trust store when needed. Custom per-agent CA configuration, short-lived enrollment tokens, unique device credentials, and signed production packages remain roadmap work.
