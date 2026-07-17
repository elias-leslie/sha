# SHA v1 architecture

This document describes the v1 direction. For the exact implemented Phase 0 boundary, use [Current SHA runtime contract](current-runtime-contract.md); roadmap-only entities and views below must not be presented as current features.

## Assumptions

1. SHA should be usable from a clean public clone without private infrastructure.
2. Operator automation, if added, should reason centrally on the server; endpoint agents should stay deterministic and non-LLM.
3. Windows and Linux support matter first; macOS currently receives build/contract coverage only.
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

Target responsibilities:

- global/client/location/endpoint ownership and environment inventory
- endpoint enrollment and connectivity tracking
- normalized control catalog and source provenance
- posture snapshots and drift history
- remediation proposals, rollout policies, and rollback records
- installer/package generation for Windows, Linux, and macOS bootstrap reporters
- approval workflow for elevated access and disruptive remediations
- API surface for endpoint agents and optional operator automation

Current Phase 0 stack:

- FastAPI backend with 9 routers and 19 OpenAPI paths
- Next.js dashboard using live API state or explicit fixture-only demo mode
- Alembic-managed SQLite for local development and PostgreSQL as the HA/concurrency reference
- principal-separated operator, read-only, and agent API-token authentication
- atomic PostgreSQL/SQLite action claims with short opaque leases

Target production stack:

- Postgres for durable state
- PostgreSQL-backed queue leases until an observed scaling requirement justifies another broker
- OIDC sessions, scoped authorization, managed secrets, package trust, internal transport protection where needed, and deployment hardening before public exposure

### 2. SHA agent

The checked-in Go agent is the canonical long-term privileged local service. Generated Python and PowerShell reporters remain compatibility shims and should not gain new feature breadth.

Target responsibilities:

- enroll with the control plane using a bounded bootstrap profile
- collect hardening-relevant telemetry only
- evaluate local control applicability
- apply approved remediations through typed executors
- create rollback artifacts before mutation
- expose narrow execution verbs rather than arbitrary shell access
- report health, execution results, and drift deltas

Implementation direction:

- Go single binary for Windows service + Linux systemd service
- signed release packages for Windows MSI/EXE and Linux deb/rpm/install script later
- typed executors per operating system and control family

Phase 0 Go behavior includes cross-platform enrollment, heartbeat, posture upload, atomic action claim, lease-bound result reporting, Windows Firewall apply/rollback, a byte-exact legacy Linux rollback path, and explicit unsupported results elsewhere. Current compatibility reporters have a broader temporary collection/mutation surface; they are not production signed packages.

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

No raw command or terminal route exists in Phase 0. A later command console or terminal must be a separate capability and require a temporary approval grant with:

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

## Target endpoint data model

Target entities:

- clients
- locations
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

Phase 0 persists endpoints, posture snapshots/results, compatibility installer profiles, approvals/grants/events, and leased response actions. Tenant/site values are transitional strings, not relational client/location authorization boundaries.

## Dashboard capabilities

Current views cover fleet, endpoint, control, installer-profile, and approval slices. They use live backend data in normal mode and explicit fixtures only in demo mode. The protected browser stack has no bundled login/session adapter yet.

Target operator-facing views:

- global fleet summary with connectivity, risk, compliance, action, and incident posture
- client and location dashboards using the same scoped metrics and drill-downs
- endpoint detail with ranked findings, current telemetry, action history, and evidence
- remediation queue and rollout history
- approval inbox for elevated access and disruptive controls
- baseline / control-pack browser with source provenance
- package builder for Windows/Linux/macOS installer output
- operator-assistant activity log and audit trail when automation is integrated

Current compatibility profile builder:

- control-plane URL
- shared agent credential supplied by the backend artifact renderer
- tenant/site/profile metadata
- update channel
- allowed policy set

The current download is a deterministic, private/no-store compatibility script with digest metadata. The dashboard does not preview its token-bearing body. Short-lived enrollment tokens, two package modes, signatures, proxy settings, and explicit private-CA settings remain target work.

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
