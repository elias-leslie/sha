# SHA v1 architecture

## Assumptions

1. SHA should be usable from a clean public clone without private infrastructure.
2. Operator automation, if added, should reason centrally on the server; endpoint agents should stay deterministic and non-LLM.
3. Windows and Linux support matter first; macOS starts as observe-only bootstrap coverage.
4. Safe hardening beats maximal hardening. High-disruption remediations must not auto-fire.
5. Official or primary-source guidance should be normalized into versioned control packs, not applied from ad hoc scraping.

## System overview

```text
+---------------------+      +--------------------+      +-------------------------+
| Operator / optional | <--> | SHA control plane  | <--> | SHA agents on endpoints |
| automation assistant|      | backend + dashboard|      | Windows / Linux service |
+---------------------+      +--------------------+      +-------------------------+
          |                          |                                |
          v                          v                                v
  policy review, tasking     posture DB, control packs,       local inspection, policy
  approvals, exception       approvals, packaging, audit      enforcement, rollback,
  handling                   trail, ROI scoring              constrained telemetry
```

## Core components

### 1. SHA control plane

Responsibilities:

- tenant/site/environment inventory
- endpoint enrollment and connectivity tracking
- normalized control catalog and source provenance
- posture snapshots and drift history
- remediation proposals, rollout policies, and rollback records
- installer/package generation for Windows, Linux, and macOS bootstrap reporters
- approval workflow for elevated access and disruptive remediations
- API surface for endpoint agents and optional operator automation

Current stack:

- FastAPI backend
- Next.js dashboard
- SQLite for local development

Target production stack:

- Postgres for durable state
- Redis or equivalent only when queues, leases, or presence are required
- authentication, authorization, TLS, auditing, and deployment hardening before public exposure

### 2. SHA agent

A future privileged local service installed on managed endpoints.

Responsibilities:

- enroll with the control plane using a bounded bootstrap profile
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

### 3. Optional operator automation

The dashboard and API are designed so an operator assistant can review posture, propose work, and request approvals without direct endpoint shell access.

Responsibilities:

- review posture summaries, drift, failed remediations, and approvals
- create or update rollout policies and exceptions
- dispatch safe remediation waves after policy approval
- request human approval for disruptive or elevated troubleshooting work
- keep work bounded to hardening configuration management and related investigation

Optional automation should never get broad arbitrary endpoint control by default.

## Security and safety model

### Default access model

Operator automation may:

- read SHA control-plane data inside the SHA project
- inspect endpoint posture, relevant logs, security tooling status, baseline deltas, package versions, firewall state, encryption state, service state, and control execution history
- request safe remediation through typed SHA-agent actions

Operator automation may not by default:

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

1. Observe only — audit posture, no mutation.
2. Safe auto-remediate — low-disruption controls with high rollback confidence.
3. Approval required — medium/high user impact, service restarts, remote access changes, auth changes, firewall lock-down, privilege changes, disruptive daemon hardening.
4. Temporary elevated troubleshooting — broader diagnostic reads through bounded troubleshooting scopes only after human approval, time-boxed and fully logged.

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

Checked-in starter packs are limited to public-source material that can be cited and redistributed cleanly:

- NIST SP 800-53 / OSCAL for control-family concepts and stable identifiers
- DISA STIGs for concrete operating-system hardening requirements
- CISA/NSA guidance for current defensive hardening practices
- SHA built-in packs for repo-implemented endpoint-response controls, mapped back to public references where applicable

CIS Benchmarks and Microsoft baselines may be cited externally when operators own the relevant licenses or documentation, but their content is not reproduced in this repository.

Normalization model:

- source document/version
- platform
- profile applicability
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
- endpoint facts
- control packs
- controls
- control mappings
- posture snapshots
- control results
- remediation runs
- rollback artifacts
- approval grants
- exception policies
- installer profiles
- agent release channels

## Dashboard capabilities

Operator-facing views:

- fleet summary with connectivity and risk posture
- endpoint detail with ranked findings and evidence
- remediation queue and rollout history
- approval inbox for elevated access and disruptive controls
- baseline / control-pack browser with source provenance
- package builder for Windows/Linux/macOS installer output
- operator-assistant activity log and audit trail when automation is integrated

Installer/profile builder:

- control-plane URL
- bootstrap credential reference or future enrollment token
- tenant/site/profile metadata
- update channel
- allowed policy set
- optional proxy / certificate trust settings

## Windows and Linux scope

Windows first-class control families:

- account policy and local security policy
- audit policy and PowerShell logging
- Defender / ASR / SmartScreen / firewall
- BitLocker posture and escrow integration hooks
- service hardening
- RDP / SMB / NTLM / Kerberos posture
- AppLocker or WDAC readiness later
- Sysmon presence/config awareness

Linux first-class control families:

- SSH hardening
- firewall posture
- journald/auditd/log retention posture
- password and PAM policy
- unattended security updates posture
- disk encryption awareness
- kernel/sysctl and service hardening
- sudo / privilege surface review

## Delivery principle

Build the smallest credible product slice that proves:

- central posture truth
- safe typed remediation boundaries
- human approval for risky access
- optional automation cannot become a general remote-admin backdoor
