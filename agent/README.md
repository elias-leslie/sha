# SHA agent

Minimal Go endpoint agent for SHA.

The agent is privileged locally but exposes only typed hardening/reporting verbs through the control-plane API. It is not a remote shell.

Current implementation:

- Linux enroll, heartbeat, and posture snapshot upload
- least-privilege `SHA_AGENT_API_TOKEN` authentication
- queued response-action polling and result reporting
- bounded evidence actions for `collect_security_context`, `collect_remediation_evidence`, and `inspect_control`
- apply/rollback for `linux.ssh.password-authentication-disabled`

Install as a Linux systemd service:

```bash
sudo scripts/install-sha-agent-linux.sh
sudoedit /etc/sha/agent-config.json
sudo systemctl restart sha-agent
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
  "sshd_hardening_path": "/etc/ssh/sshd_config.d/99-sha-hardening.conf"
}
```
