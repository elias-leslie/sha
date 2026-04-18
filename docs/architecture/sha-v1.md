# SHA v1 architecture

## Assumptions

1. SHA runs as a real product project inside the managed SummitFlow + Agent Hub workspace.
2. SHAna should reason centrally on the server; endpoint agents should stay deterministic and non-LLM.
3. Windows and Linux support matter now; macOS is deferred.
4. Safe hardening beats maximal hardening. High-disruption remediations must not auto-fire.
5. Official baselines should be normalized into versioned control packs, not applied from ad hoc scraping.

## System overview

```text
+-------------------+        +--------------------+        +-------------------------+
| Agent Hub / SHAna | <----> | SHA control plane  | <----> | SHA agents on endpoints |
| operator persona  |        | backend + dashboard|        | Windows / Linux service |
+-------------------+        +--------------------+        +-------------------------+
          |                           |                                |
          |                           |                                |
          v                           v                                v
  policy review, tasking      posture DB, control packs,       local inspection, policy
  approvals, exception        approvals, packaging, audit      enforcement, rollback,
  handling, safe orchestration trail, ROI scoring              constrained telemetry
```

## Core components

### 1. SHA control plane

Responsibilities:
- tenant/site/environment inventory
- endpoint enrollment and connectivity tracking
- normalized control catalog and source provenance
- posture snapshots and drift history
- remediation proposals, rollout policies, and rollback records
- installer/package generation for Windows and Linux agents
- approval workflow for elevated access and disruptive remediations
- API surface for SHA agents and SHAna

Recommended stack:
- FastAPI backend
- Next.js dashboard
- Postgres for durable state
- Redis for ephemeral queues, leases, and presence

### 2. SHA agent

A privileged local service installed on managed endpoints.

Responsibilities:
- enroll with the control plane using install token + signed device identity
- collect hardening-relevant telemetry only
- evaluate local control applicability
- apply approved remediations through typed executors
- create rollback artifacts before mutation
- expose narrow execution verbs rather than arbitrary shell access
- report health, execution results, and drift deltas

Recommended implementation:
- Go single binary for Windows service + Linux systemd service
- signed release packages for Windows MSI/EXE and Linux deb/rpm/install script later
- typed executors per operating system and control family

### 3. SHAna

SHAna is the Agent Hub operator persona for SHA.

Responsibilities:
- review posture summaries, drift, failed remediations, and approvals
- create or update rollout policies and exceptions
- dispatch safe remediation waves
- request human approval for disruptive or elevated troubleshooting work
- keep work bounded to hardening configuration management and related investigation

SHAna should never get broad arbitrary endpoint control by default.

## Security and safety model

### Default access model

SHAna may:
- read SHA control-plane data freely inside the SHA project
- inspect endpoint posture, relevant logs, security tooling status, baseline deltas, package versions, firewall state, encryption state, service state, and control execution history
- request safe remediation through typed SHA-agent actions

SHAna may not by default:
- browse arbitrary endpoint filesystems
- run arbitrary endpoint shell commands
- install unrelated software
- disable controls outside approved hardening policy
- perform disruptive remediations without an approval-backed policy

### Endpoint command boundary

The SHA agent should expose typed capabilities, not raw command execution:
- inspect_control
- apply_control
- rollback_control
- collect_security_context
- collect_remediation_evidence
- request_elevated_troubleshooting

Any raw or broad diagnostic execution should require a temporary approval grant with:
- explicit endpoint scope
- explicit capability scope
- reason
- TTL / expiry
- audit trail
- optional dual approval for highest-risk actions

### Remediation tiers

1. Observe only
   - audit posture, no mutation
2. Safe auto-remediate
   - low-disruption controls with high rollback confidence
3. Approval required
   - medium/high user impact, service restarts, remote access changes, auth changes, firewall lock-down, privilege changes, disruptive Linux daemon hardening
4. Temporary elevated troubleshooting
   - broader diagnostic reads through bounded troubleshooting scopes only after human approval, time-boxed and fully logged

## Prioritization / ROI model

Each control gap should receive a score derived from:
- baseline severity / control criticality
- exploitability or attacker value
- asset role sensitivity
- current exposure breadth
- remediation confidence
- rollback confidence
- predicted user disruption
- prerequisite readiness
- compliance coverage uplift

Suggested priority bands:
- Now: high value, low disruption, high confidence
- Soon: meaningful hardening, moderate risk, clear rollback
- Review first: ambiguous environment fit or possible user disruption
- Manual only: disruptive, fragile, or environment-specific items

## Control-source strategy

SHA should ingest official or primary guidance into versioned control packs.

Primary source families:
- Microsoft Security Compliance Toolkit / LGPO baselines for Windows
- CIS Benchmarks for Windows and Linux
- NIST CSF 2.0 plus mappings to SP 800-53 and SP 800-128 baseline-configuration concepts
- DISA STIG security configuration guidance
- NSA/CISA hardening guidance
- distro/vendor guidance where needed: Ubuntu, Debian, RHEL, systemd/journald, Defender, BitLocker/LUKS, SSH

Normalization model:
- source document/version
- platform
- profile applicability (workstation, server, domain controller, etc.)
- control family
- rationale
- detection method
- remediation method
- rollback method
- disruption metadata
- reboot requirement
- evidence mapping
- compliance mappings

## Endpoint data model

Key entities:
- tenants
- sites
- endpoints
- endpoint_facts
- control_packs
- controls
- control_mappings
- posture_snapshots
- control_results
- remediation_runs
- rollback_artifacts
- approval_grants
- exception_policies
- installer_profiles
- agent_release_channels

## Dashboard capabilities

### Operator-facing views
- fleet summary with connectivity and risk posture
- endpoint detail with ranked findings and evidence
- remediation queue and rollout history
- approval inbox for elevated access and disruptive controls
- baseline / control-pack browser with source provenance
- package builder for Windows/Linux installer output
- SHAna activity log and audit trail

### Installer/package builder

Dashboard should generate per-profile installer artifacts containing:
- control-plane URL
- enrollment token or bootstrap credential reference
- tenant/site/profile metadata
- update channel
- allowed policy set
- optional proxy / certificate trust settings

## Windows and Linux scope

### Windows first-class control families
- account policy and local security policy
- audit policy and PowerShell logging
- Defender / ASR / SmartScreen / firewall
- BitLocker posture and escrow integration hooks
- service hardening
- RDP / SMB / NTLM / Kerberos posture
- AppLocker or WDAC readiness later
- Sysmon presence/config awareness

### Linux first-class control families
- SSH hardening
- firewall posture (ufw/firewalld/nftables abstraction)
- journald/auditd/log retention posture
- password and PAM policy
- unattended security updates posture
- disk encryption awareness
- kernel/sysctl and service hardening
- sudo / privilege surface review

## Legacy SHA references applied carefully

Useful takeaways from prior SHA work:
- control catalog metadata should include severity, applicability, auto-remediation, reboot requirement, and disruption estimates
- phased deployment matters
- profile-aware control filtering matters
- backup and rollback need first-class treatment
- operator-readable reporting matters

What not to inherit blindly:
- PowerShell-only architecture
- monolithic single-script execution model
- Windows-only assumptions
- unrestricted admin execution surface

## Delivery principle

Build the smallest credible product slice that proves:
- central posture truth
- safe typed remediation
- human approval for risky access
- SHAna can manage the system without becoming a general remote-admin backdoor
