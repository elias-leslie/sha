# Phase 0 runtime verification — 2026-07-17

Status: passed.

This record covers the Phase 0 security and execution foundation described in the IR/compliance roadmap. Tests used the Phase 0 checkpoint worktree based on Git revision `c6ad0408124d68e80c3d28473c32b8f413b1c75d`; the checkpoint commit containing this document is the durable revision under test. Times use America/New_York unless an entry says UTC. No credential values, private keys, or token-bearing artifact bodies are retained here.

## Automated contract and build gates

Run at 10:53–10:54:

| Gate | Result |
| --- | --- |
| Full backend test suite | 92 passed; one upstream Starlette deprecation warning |
| Frontend unit/component suite | 44 passed |
| Go agent clean-room test | passed |
| Changed-only architecture, Ruff, Python type, Biome, and TypeScript gate | passed |
| Checked-in contracts | 24 generated JSON Schemas, including control registry and lease claim response |

The control registry contained 59 canonical entries: 17 `benchmark_control` definitions and 42 `operational_observation` definitions. Posture ingestion rejected unknown and cross-platform keys. Action selection excluded operational observations even if a malformed response advertised an action.

## PostgreSQL and two-replica HA runtime

`scripts/test-ha-compose.sh` passed at 11:18–11:19 against PostgreSQL 16 and two backend replicas after the final HA routing, credential, restore-topology, and backup-permission changes.

Observed evidence:

- A representative unversioned pre-Alembic database was seeded at the baseline schema, then adopted and upgraded through revision `20260717_0004`.
- Legacy observation aliases were normalized and duplicate alias/canonical rows were deduplicated without losing the canonical row.
- A leased action was downgraded to the pre-lease revision, safely requeued, and re-upgraded to head.
- Alembic autogeneration reported no schema drift after upgrade and re-upgrade.
- Nginx access evidence showed the two competing claims reached two distinct backend upstreams. Exactly one claim succeeded.
- Exact result replay with the same lease was idempotent.
- Unauthenticated mutation, read-only mutation, and caller-spoofed external trust headers were rejected at the public HA edge. Separate frontend proxy tests proved the same no-ambient-authority and trust-header-stripping boundary for direct frontend deployments.
- The compatibility artifact response included a SHA-256 digest and private/no-store policy. The final ephemeral test artifact digest was `708140657e39bbe91db1835efb8979a771c29548d9da732f2aaee12dc0682f84`.
- PostgreSQL backup plus SHA-256 sidecar verification and destructive restore validation succeeded. The pre-backup installer profile was restored and a post-backup marker was absent. The backup directory was mode 0700; its dump and digest were mode 0600.
- The compose project and volume were removed after the run.

## HTTPS and secret delivery runtime

`scripts/test-ha-compose-tls.sh` passed at 11:19–11:20 after the final direct two-replica API routing and topology-aware restore changes.

- Only the HTTPS port was published; the nginx runtime configuration had no plaintext listener.
- TLS 1.2/1.3 edge configuration, HSTS, normal hostname validation, and a supplied private CA succeeded.
- Health, read-only source-pack access, and operator evidence access all used CA-validated HTTPS. No verification bypass was used.
- Backup and restore used the exact base-plus-TLS compose topology. After restart, the HTTPS listener, certificate validation, HSTS, and absence of a plaintext listener all remained intact.
- The ephemeral compose project, certificate key, CA material, database volume, and work directory were removed after the run.

`scripts/test-ha-compose-secrets.sh` passed at 11:20–11:21 after the final routing and topology-aware restore changes.

- PostgreSQL URL and operator, read-only, agent, and trusted-proxy credentials loaded from mounted secret files.
- The public frontend rejected caller-supplied trusted-proxy headers with 401.
- The separately protected direct backend accepted a trusted external read-only principal with a non-empty subject.
- The downloaded compatibility artifact contained the configured agent credential, never the operator credential, and returned `Cache-Control: private, no-store`.
- Backup and restore used the exact base-plus-file-secret compose topology and original secret-file paths. Read-only auth, direct trusted-proxy auth, public spoof rejection, and agent-only artifact credential delivery still passed after restart.
- The compose project, secrets directory, volume, and work directory were removed after the run.

The base HA compose file was also checked with all credential variables removed. Compose exited before service creation and named the missing required variable; there are no public fallback passwords or API tokens.

## Managed service and browser runtime

After `st service rebuild sha --detach`, both managed services reported active.

- Backend `/health` returned the expected service/version payload.
- Direct and same-origin-proxied `/api/control-registry` each returned 59 entries with both registry kinds.
- `/installers` returned HTTP 200 from the rebuilt frontend.
- Isolated headless browser checks opened `/installers`, `/approvals`, `/controls`, and `/fleet` against the rebuilt frontend. All four reported zero page, console, network, and command warnings or errors.
- The installer screen rendered only an explicit compatibility-reporter download action. Source/runtime assertions confirmed no preview control, code pane, or network-response-to-privileged-shell instruction.

## Proxmox Linux runtime

Fresh disposable-VM validation passed on Proxmox VM 9204 (`sha-e2e-linux-phase0`) using Ubuntu 24.04.4 LTS with kernel 6.8.0-136-generic. The current compatibility reporter was rendered at 15:07:03 UTC and the run completed at 15:11:38 UTC.

- The protected artifact was 34,810 bytes with SHA-256 `0ebedfa86b0d6337f666bf88c2d66ebae578e3cff6acbac473a22e539f3e5b5b`; a second download was byte-identical, matched the response digest, and used `Cache-Control: private, no-store`. Its reporter source digest was `39e6c06ec221981fc78f775d93fa6a25884773ec16e9ebe9084ceb405e4adbad`.
- The VM first rejected the private-CA endpoint with the expected certificate error. After installing the CA into the OS trust store, hostname/SAN validation and HTTPS succeeded without an insecure bypass.
- A clean install created root-owned `/etc/sha` mode 0700, configuration mode 0600, and reporter mode 0755. The one-shot service succeeded; its timer was enabled and active; stop/start lifecycle passed.
- Endpoint `ep_f0971ac09de440b1a836a3201f06f661` enrolled once and reported online. Snapshot `snap_6e09dbe058ef447f913dba3050df9daa` contained 11 passing canonical results: `linux.firewall.service-active`, `linux.ssh.password-authentication-disabled`, `linux.root.password-locked`, `linux.updates.automatic-enabled`, `linux.telemetry.hardware-summary`, `linux.telemetry.security-logging`, `linux.telemetry.process-inventory`, `linux.telemetry.package-inventory`, `linux.telemetry.startup-services`, `linux.telemetry.login-sessions`, and `linux.telemetry.network-listeners`.
- Auth separation held: unauthenticated inventory returned 401, operator credentials could not claim agent work, and agent credentials could not read operator inventory. Stored actor identity came from the authenticated principal.
- Lease-bound apply action `act_0fb890f3eee2476d919df8fd6ab6fecb` and rollback action `act_f4d3fe83a1484963b2915fb374ef4b18` each succeeded once. Filesystem and effective SSH state proved the applied hardening and restored baseline.
- Re-running the installer was idempotent: reporter digest remained stable and no duplicate endpoint appeared.
- VM 9204, tunnels, transient artifacts, and scratch credentials were removed. Existing Proxmox VMs were not modified.

## Proxmox Windows runtime

Fresh disposable-VM validation passed on Proxmox VM 9203 (`sha-e2e-windows-phase0`) using Windows Server 2025 Standard Evaluation 24H2, build 10.0.26100.32230. Initial install began at 14:47:46 UTC and enrolled at 14:48:05 UTC. The corrected current artifact was rendered at 15:04:50 UTC, reinstalled by 15:06:26 UTC, and cleanup completed at 15:26:36 UTC.

- Profile `ip_f9bb798faa3847f2aca9bdd17cf705d1` produced a 28,653-byte artifact with SHA-256 `448ca232ba535c6a1cee91757b315f7c1ed5364643cd74fd594cf6af03538ef9`. Two API downloads were identical, matched the response digest, and used `Cache-Control: private, no-store`; the executed VM copy was byte-identical.
- The endpoint used TLS 1.3 with `TLS_AES_256_GCM_SHA384`, X25519, and successful certificate verification against only the ephemeral private CA.
- Endpoint `ep_bef8ec078a684e89ad617b3ea5a3d9d8` retained one identity across reinstall. Snapshot `snap_5e7e72c56a58437da0c484bf77f0ac2` contained 11 canonical results: eight pass, one fail, and two not applicable. It covered process, software, services, startup services, network bindings, security logging, machine identity, firewall, Defender, BitLocker, and Secure Boot.
- The reporter and scheduled task ran as `NT AUTHORITY\SYSTEM`. The task used the SYSTEM SID, a boot trigger, a 15-minute repeat, and the exact reporter command.
- Testing found that the prior scheduled-task argument escaping split the reporter path into `WorkingDirectory`. The renderer was corrected and regression assertions added before the current artifact was regenerated and reinstalled.
- `C:\ProgramData\SHA` and `reporter-config.json` allowed only SYSTEM and Administrators. A real standard user could list the shared ProgramData root but received `NT_STATUS_ACCESS_DENIED` for the SHA directory and config file.
- Auth separation held: unauthenticated access returned 401 and operator/agent cross-role attempts returned 403.
- Lease-bound apply action `act_ff2fe05b13c24a3d94bf849880b18886` succeeded on attempt one at 15:11:43 UTC, changed firewall posture from fail to pass, and returned the same completed action on idempotent replay. Rollback action `act_79a4dce91d7e406cbe231cf74ab1c8a0` succeeded on attempt one at 15:15:15 UTC and restored firewall posture to fail.
- VM 9203 and its 64 GB LVM were destroyed after confirming no other VM referenced its two test ISOs; those exact ISOs were removed. Ephemeral backend, reverse SSH, socat, TLS listeners, external secret scratch, and test credentials were removed. Existing Proxmox VMs were not modified.

## Scope and cleanup

- macOS runtime was intentionally excluded. macOS remains build- and contract-verified only.
- Existing Proxmox VMs were out of scope and were not modified.
- Disposable VM, artifact, listener, ISO, and scratch cleanup is recorded in the platform sections.
