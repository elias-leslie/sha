# SHA incident-response and compliance operations roadmap

Status: Active; Phase 0 complete, Phase 1 next  
Date: 2026-07-17  
Execution authority: Invoked by the user as the active goal on 2026-07-17  
Supersedes after approval: docs/plans/2026-04-18-sha-roadmap.md

## Goal

Build SHA into a lean, secure endpoint operations plane that can be deployed before or during an incident and used for:

- endpoint discovery and current-state inventory;
- live investigation and bounded evidence collection;
- hardening, containment, cleanup, and verification;
- scheduled and bulk endpoint actions;
- compliance baselines, exceptions, remediation, and evidence;
- global, client, location, and endpoint dashboards and reports.

SHA must borrow the useful operational slices of RMM and DFIR products without becoming a generic RMM, PSA, EDR, SIEM, backup, MDM, or patch marketplace.

Goal completion means every mandatory phase and acceptance criterion in this document is implemented, migrated, documented, exercised in the real runtime, and verified on the supported operating systems. Deferred items and explicit non-goals do not block completion.

## Product in one sentence

SHA is a multi-client incident-response and compliance operations plane: enroll an endpoint, understand its current state, run controlled investigations or changes, prove the result, and retain an auditable record.

## How operators will use it

### Before an incident

1. Create a client and locations.
2. Generate a short-lived, scope-bound enrollment package.
3. Install the SHA agent on endpoints.
4. Assign inventory cadence, a compliance baseline, and approved runbooks.
5. Monitor fleet health, software, exposure, drift, and failed controls from scoped dashboards.
6. Schedule evidence collection, checks, and safe approved remediation.

### During an incident

1. Create an incident and select existing endpoints or rapidly enroll new ones.
2. Refresh volatile state such as processes, connections, sessions, services, tasks, and security logs.
3. Run a hunt or triage collection against a previewed target set.
4. Preserve bounded evidence with hashes and collection metadata.
5. Contain, terminate, disable, remove, or harden through versioned actions.
6. Recollect and verify the endpoint state.
7. Export the incident timeline, actions, results, and evidence manifest.

### For compliance

1. Assign a baseline to a client, location, saved group, or endpoint.
2. Run scheduled tests and retain the supporting evidence.
3. Review pass, fail, unknown, not-applicable, and stale results.
4. Record time-bound exceptions with owner and reason.
5. Approve remediation by control or runbook.
6. Execute detect, change, and retest as one traceable operation.
7. Export scoped summary and detail reports.

## Scope boundary

### SHA will own

- client, location, endpoint, tag, and saved-group hierarchy;
- secure endpoint enrollment and identity;
- current endpoint inventory and bounded change history;
- versioned collection, action, and runbook definitions;
- immediate, scheduled, recurring, and fleet-wide jobs;
- per-target status, logs, output, evidence, cancellation, and audit;
- a controlled command console and later an interactive terminal;
- incident cases, hunts, collections, evidence, and timelines;
- compliance baselines, checks, exceptions, remediation, and proof;
- fixed operational and compliance reports.

### SHA will not own

- help desk, ticketing, PSA, billing, contracts, or customer portals;
- backups, disaster recovery, or storage lifecycle management beyond SHA evidence;
- remote desktop, screen control, chat, or end-user support;
- a general software catalog or broad patch-management marketplace;
- MDM, mobile app stores, device wipe, or full device-lifecycle management;
- network discovery, SNMP monitoring, or infrastructure monitoring;
- software-license accounting;
- a visual workflow designer, report designer, or arbitrary plugin marketplace;
- a general SIEM, long-term log lake, EDR, or high-rate telemetry pipeline;
- continuous full process or network telemetry by default;
- vulnerability-scanner breadth in the first release;
- AI-generated or autonomous endpoint actions.

Integrations with ticketing, SIEM, storage, identity, and vulnerability products may be added later through stable exports and APIs. They must not become prerequisites for a working SHA deployment.

## Research synthesis

| Product | What SHA should adopt | What SHA should avoid |
| --- | --- | --- |
| Wazuh | First-class system inventory; global and endpoint inventory views; current snapshots; inventory reports; explicit risk around remote commands | SIEM/indexer breadth and an always-on security data lake |
| ConnectWise Automate | Client to location to device hierarchy; saved dynamic groups; operational device page; scoped scheduling and activity history | PSA coupling, legacy breadth, remote-support suite, and weakly differentiated command controls |
| NinjaOne | Clear fleet and device information architecture; bulk-action patterns; scheduled automation; fixed reports; separate terminal permissions | Backup, remote desktop, patch catalog, support-tool, and general RMM scope |
| ImmyBot | Desired-state detect, plan, execute, retest, and report loop; typed tasks; tenant assignment; transparent maintenance sessions | Windows-only assumptions, provisioning breadth, and configuration marketplace scope |
| Fleet | Saved questions used for live investigation, schedules, policies, and exports; host-level script results; label targeting | MDM, app store, patch marketplace, and device-lifecycle breadth |
| Velociraptor | One artifact and flow model for collection, hunts, evidence, shell, monitoring, and response; cached-versus-live semantics; notebooks and timelines | Soft tenant boundaries, unrestricted artifact breadth, and a DFIR query language as a prerequisite for normal operators |

The resulting product pattern is deliberate:

- Wazuh-style inventory;
- NinjaOne and Automate-style hierarchy and operational views;
- ImmyBot-style desired-state remediation;
- Fleet-style saved questions and policies;
- Velociraptor-style artifacts, flows, hunts, evidence, and terminal records.

## What exists and what is missing

SHA currently has a useful lab-grade control plane: a FastAPI service, a Next.js dashboard, installer/profile generation, endpoint heartbeats and posture uploads, approval concepts, generated privileged reporters, and a separate Go agent. It also has a small typed hardening and isolation surface.

That foundation does not yet meet the target product:

| Area | Current direction | Required durable state |
| --- | --- | --- |
| Agent | Generated reporters plus a narrower separate Go agent | One canonical signed Go agent; thin installers; capability negotiation; controlled migration from reporters |
| Identity | Shared agent/operator secrets and free-form actors in important paths | Unique revocable device identity; authenticated human principal; scoped authorization; no identity supplied by request text |
| Hierarchy | Tenant and site strings | Relational client, location, endpoint, tag, and saved-group entities with enforced scope |
| Execution | Narrow queues and typed mutations | Leased, idempotent, cancellable, expiring jobs with attempts, output, evidence, schedules, target snapshots, and concurrency controls |
| Inventory | Posture-focused snapshots | Hardware, OS, software, hotfixes, services, processes, connections, ports, users, sessions, tasks, security tooling, and freshness |
| UI | Early fleet, endpoint, control, installer, and approval views | Global, client, location, endpoint, job, incident, compliance, report, and audit workspaces |
| Remote work | Small predefined action set | Versioned collections, actions, runbooks, bulk execution, command console, and gated interactive terminal |
| Incident response | Isolation-related actions without a case workflow | Incidents, hunts, bounded collections, evidence, annotations, timeline, containment, verification, and export |
| Compliance | Informational control packs and posture | Assigned baselines, canonical control IDs, evaluated status, evidence, exceptions, remediation, retest, and reports |
| Production | SQLite-friendly local deployment | Tested PostgreSQL migrations, secure sessions, TLS assumptions, object evidence storage, backup/restore guidance, and scale evidence |

## Principles that control implementation

1. Durable foundations precede feature breadth.
2. One canonical agent, one action definition model, and one job engine serve all workflows.
3. Agents initiate outbound connections; SHA requires no inbound endpoint listener.
4. Every endpoint has a unique, revocable identity.
5. Every human action derives its actor and scope from authentication, never request text.
6. Read, change, contain, and raw execution are distinct risk classes and permissions.
7. Every requested action resolves to an immutable definition version and an immutable per-run target snapshot.
8. Every remote effect is idempotent where possible and has a durable attempt record.
9. Current inventory is clearly distinguished from live refreshes and historical evidence.
10. Detect, change, retest, and report is the standard remediation loop.
11. Bulk targeting always has preview, count, scope, expiry, and concurrency controls.
12. Raw shell is break-glass capability. Typed and versioned actions are the normal path.
13. Data collection is bounded by time, size, output, upload, CPU, and concurrency limits.
14. Multi-client authorization is hard isolation, not a user-interface filter.
15. Every phase delivers a thin end-to-end slice and is exercised through the actual UI and agent runtime.
16. No phase is complete with only types, unit tests, mocks, or static screens.

## Target domain model

### Scope and identity

- Client: top-level customer or administrative boundary.
- Location: child of one client; represents a site or operational grouping.
- Endpoint: belongs to one client and one location; owns device identity, platform, capabilities, status, and lifecycle.
- Tag: explicit operator-managed label.
- Saved view: a versioned filter definition.
- Dynamic group: a named saved view usable as a target selector.
- User principal: identity received from OIDC.
- Role binding: role plus global, client, location, group, or endpoint scope.
- Enrollment token: one-use or tightly limited, expiring, scope-bound bootstrap credential.
- Device credential: unique, high-entropy, rotatable, revocable credential stored hashed server-side.

### Inventory

- Inventory snapshot: source endpoint, category, collection time, agent version, schema version, completeness, and content hash.
- Current inventory record: latest normalized state for fast fleet and endpoint queries.
- Inventory change: bounded add, remove, or change record derived between snapshots.
- Finding: normalized investigation or compliance observation that may be attached to an incident or control result.

### Execution

- Action definition: stable identity, ownership, description, platform, category, risk, required permission, and lifecycle status.
- Action version: immutable content hash, typed parameters, preconditions, run-as context, commands or collector implementation, resource limits, verification, rollback metadata, and output contract.
- Runbook: ordered versioned actions with explicit inputs, handoffs, stop conditions, and rollback behavior; no visual designer.
- Job: operator or scheduler request, action version, parameters, selector, target snapshot, policy, approvals, timestamps, and aggregate state.
- Job target: one endpoint within a job and its current state.
- Attempt: leased execution of one target, including idempotency key, agent, start/end, exit, logs, and result.
- Output chunk: bounded stdout, stderr, structured result, or progress record.
- Collected artifact: file or structured payload with size, content type, hashes, collection provenance, retention, and incident pin state.
- Schedule: trigger, timezone, window, selector, action version, parameters, approval binding, offline policy, expiry, and concurrency policy.
- Approval: authenticated requester, distinct approver where required, reason, exact action version, exact parameters, target selector, limits, expiry, and decision.

### Incident response and compliance

- Incident: status, severity, client, locations, endpoints, responders, timestamps, tags, summary, and retention class.
- Incident note: append-only authored note or annotation.
- Timeline event: normalized audit, collection, finding, action, evidence, or analyst annotation.
- Baseline: versioned set of control requirements.
- Baseline assignment: baseline version plus client, location, group, or endpoint scope and effective dates.
- Control evaluation: pass, fail, unknown, not applicable, or stale, with evidence and evaluation time.
- Exception: control, scope, owner, reason, compensating control, approval, and expiry.
- Remediation record: detected state, approved action, change result, retest result, rollback result, and evidence.

## Scope hierarchy and targeting

The product hierarchy is fixed:

Global → Client → Location → Endpoint

Tags and dynamic groups cut across that tree but may never widen a user's authorized scope.

Every list, dashboard, report, policy, schedule, job, and incident view uses the same scope filter contract. The UI must retain the selected scope while the operator moves between pages.

Target behavior:

- a manual run previews a selector and stores the resolved endpoint snapshot at launch;
- a recurring schedule stores its selector, resolves it for each occurrence, and stores that occurrence's target snapshot;
- an edited selector, action version, parameter, risk policy, or schedule invalidates prior approval;
- target preview shows total devices, online/offline count, operating systems, clients, locations, exclusions, and authorization reductions;
- canary and batch controls apply after the target snapshot is fixed;
- endpoint removal, revocation, or loss of authorization prevents execution even if the endpoint was in the snapshot.

## Agent and protocol architecture

### Canonical agent

The existing Go agent becomes the only long-term endpoint runtime. Generated Linux, Windows, and macOS installers become thin bootstrap packages that:

1. validate platform and prerequisites;
2. fetch the pinned agent release;
3. verify its signature and digest;
4. enroll with the short-lived token;
5. store the unique device credential using platform-appropriate protections;
6. install the service with least required privilege and restrictive file permissions;
7. start the agent and report installation evidence.

The generated reporters remain temporarily compatible only while the Go agent reaches feature parity. New profiles then install the Go agent. Existing reporters receive an explicit migration path and removal deadline.

### Installer package modes

Installation must be straightforward for a one-off responder, an RMM deployment, and a large software-distribution system. SHA publishes one signed platform package in two configuration modes:

1. Profile package with embedded enrollment token
   - Generated for one client, location, enrollment policy, control-plane URL, and optional custom CA bundle.
   - Contains a short-lived, revocable enrollment token with an explicit use limit.
   - Installs and enrolls in one normal platform operation without requiring the operator to copy a token.
   - Is treated as sensitive until its token expires; download responses are not cacheable and the UI shows expiry, remaining uses, digest, and revocation.
   - Includes a signed personalized bootstrap manifest so URL, scope, CA trust, expiry, use limit, and token cannot be substituted independently of the signed agent.
   - Never contains a long-lived device credential. Successful enrollment replaces the bootstrap token with a unique device credential and removes the bootstrap token from the installed configuration.
2. Generic package with token supplied at install time
   - Contains no client, location, or enrollment secret and may be reused unchanged.
   - Accepts control-plane URL and enrollment token through documented unattended command-line options.
   - Also accepts token from standard input or a restrictive token file so automation can avoid process-list and shell-history exposure.
   - Accepts an optional CA bundle path for private PKI.
   - Fails before service installation when required configuration is missing or TLS verification fails.

The same signed agent binary and service layout are used in both modes. Package configuration changes must not create a second agent build.

The UI never renders or previews a token-bearing package body. It shows redacted manifest metadata, authenticated download history, signing identity, digest, expiry, remaining uses, and revoke control.

Required generic bootstrap interface:

- control-plane URL;
- enrollment token, token file, or token from standard input, with exactly one token source allowed;
- optional custom CA bundle;
- optional client/location only when the token explicitly permits operator-selected scope;
- non-interactive mode;
- machine-readable result;
- uninstall and repair;
- no command-line option for a long-lived device credential.

Credential storage after enrollment:

- Linux: root-owned state directory with mode 0700 and credential file with mode 0600.
- Windows: DPAPI LocalMachine or Windows Credential Manager plus SYSTEM-and-Administrators-only ACL.
- macOS: system Keychain where practical; otherwise a root-owned file with mode 0600.
- Server: slow or keyed hash of the credential plus endpoint, creation, last-use, rotation, expiry, and revocation metadata; never recoverable plaintext.

Platform delivery:

- Windows: signed MSI or signed bootstrap executable supporting quiet installation and explicit properties or flags.
- macOS: signed and notarized PKG plus the installed SHA bootstrap command for token-at-install enrollment.
- Linux: signed DEB and RPM where practical, plus a signed standalone bootstrap path for unsupported distributions.

Package generation and download must never log, include in a URL, analytics event, filename, digest header, or error response any enrollment token.

### Installer usability acceptance

- The profile package installs and enrolls with one documented command or standard graphical package action.
- The generic package installs and enrolls with one documented unattended command after the package is present.
- Success reports endpoint identity, service state, control-plane host, and credential storage result without echoing secrets.
- Failure states distinguish signature, digest, privilege, configuration, DNS, TCP, TLS trust, enrollment authorization, and service-start errors.
- Re-running the installer is an idempotent repair or upgrade, not a duplicate enrollment.
- Package removal does not silently delete server audit or incident evidence.
- Every generated package exposes version, platform, architecture, profile mode, SHA-256 digest, signing identity, and creation time before download.

### Agent connection model

- HTTPS long polling is the default control channel.
- Heartbeats carry identity, version, capabilities, health, and clock data.
- Job claims use server-issued leases and idempotency keys.
- The agent acknowledges claim, start, progress, output, completion, and cancellation.
- The server may reassign only after a lease expires and retry policy allows it.
- Interactive terminal later uses a separately authorized short-lived WebSocket or equivalent duplex channel.
- No endpoint exposes an inbound SHA listener.
- Protocol and payload schemas are versioned and support a documented compatibility window.

### Transport encryption and server identity

- Production agent, browser, API, evidence, and terminal communication requires HTTPS.
- TLS 1.3 is preferred and TLS 1.2 is the minimum supported version.
- Agents verify the control-plane hostname and certificate chain on every connection.
- Public-PKI deployments use the operating-system trust store.
- Private-PKI deployments embed or install the selected CA chain; they do not disable verification.
- The server presents a complete leaf and intermediate chain.
- Agents refuse cross-origin redirects and HTTPS-to-HTTP downgrades; credentials are never forwarded to a redirect target.
- Plain HTTP and certificate-verification bypass are restricted to an explicit local-development mode and cannot be emitted by production installer profiles.
- Enrollment and device credentials are sent only in authorization headers or protected request bodies, never query strings.
- Enrollment tokens are used only for bootstrap. Normal communication uses the endpoint's unique rotatable credential.
- Sensitive evidence receives authenticated transport, authorization, integrity hashes, bounded streaming, and encryption at rest according to deployment policy.
- Interactive terminal uses the same authenticated TLS boundary plus its separate short-lived authorization.
- TLS trust and protocol failures fail closed and remain distinguishable from application authentication failures.
- Private-CA rotation uses overlapping old and new trust bundles before server certificate cutover.
- Internal proxy hops use TLS whenever they cross a host or independently administered network boundary.

TLS provides transport confidentiality, integrity, and server authentication. SHA does not add a custom message cipher on top of TLS. Per-device credentials, request identity binding, lease/idempotency controls, evidence hashes, and optional future managed client certificates supply the application-level protections TLS does not provide.

### Enrollment and device identity

- Enrollment tokens are short-lived, scope-bound, revocable, and limited by use count.
- Enrollment creates a pending or approved endpoint according to profile policy.
- A pending endpoint may report minimal identity but may not receive operational jobs.
- Approval issues or activates a unique device credential.
- Device routes bind credential identity to one endpoint; endpoint identifiers in payloads cannot redirect access.
- Credentials rotate without reinstall and revoke immediately.
- Server storage contains hashes, not recoverable bearer credentials.
- Transport requires TLS outside explicit local development.
- The design keeps an upgrade path to per-device asymmetric keys or mutual TLS without changing endpoint ownership semantics.

### Capability negotiation

Agents advertise:

- operating system, architecture, agent and protocol version;
- collector and action IDs with supported versions;
- privilege and service context;
- terminal and evidence-upload support;
- configured resource limits;
- degradation or health reasons.

The server rejects unsupported work before launch and reports capability mismatches in target preview.

## Authentication, authorization, approval, and audit

### Human authentication

- Use provider-neutral OIDC.
- Do not create a production local-password database.
- Use secure HttpOnly sessions through the web boundary.
- Remove any frontend behavior that turns an unauthenticated browser request into an authenticated shared operator request.
- Local development may use a conspicuous development-only identity mode that cannot start in production configuration.

### Initial roles

| Role | Intended authority |
| --- | --- |
| Viewer | Read authorized dashboards, inventory, results, reports, and audit |
| Operator | Run authorized read-only collections and approved low-risk typed actions |
| Responder | Run incident collections and approved response actions; attach evidence to incidents |
| Approver | Approve actions within assigned scope; cannot satisfy distinct-approver rules for own request |
| Admin | Manage clients, locations, enrollment, roles, action library, policies, retention, and integrations |

Permissions remain granular beneath roles. At minimum, separate:

- inventory read and refresh;
- evidence content read and collect;
- action request and action approve;
- bulk action;
- process and service mutation;
- reboot;
- containment and release;
- raw command execution;
- interactive terminal;
- schedule create and approve;
- compliance exception;
- incident administration;
- audit export;
- credential and enrollment administration.

### Risk classes

| Class | Examples | Default behavior |
| --- | --- | --- |
| Read | Refresh inventory, list processes, hash a file | Authorized role may run within limits |
| Sensitive read | Event logs, command lines, evidence file content | Reason required; evidence permission; incident attachment encouraged |
| Change | Restart service, terminate process, apply hardening setting | Typed action; verification required; policy or approval controls execution |
| High risk | Reboot, firewall block, network isolation, bulk mutation | Explicit approval, preview, expiry, and concurrency limits |
| Break glass | Raw command or interactive terminal | Dedicated permission, recent authentication, reason or incident, short TTL, full transcript |

Production policy should require a distinct approver for high-risk bulk work and break-glass sessions. A deployment may relax this only through an explicit audited policy setting.

### Audit

Audit is append-only at the application level and captures:

- authenticated principal and effective scope;
- request, view of sensitive content, approval, denial, cancellation, and policy decision;
- exact action and runbook version hashes;
- parameters with secret values redacted;
- selector, resolved target snapshot, exclusions, and concurrency policy;
- device claim, execution, result, evidence access, and export;
- enrollment, approval, credential rotation, revocation, role, baseline, exception, and retention changes;
- terminal start, commands, output references, stop reason, and duration.

## Unified action and flow model

Collections, hardening actions, containment, command-console entries, compliance remediation, hunts, schedules, and terminal command records all use the same execution spine.

Every action version defines:

- stable ID, display name, version, source, owner, and content hash;
- supported platforms and required agent capabilities;
- collect, change, contain, or break-glass category;
- typed and validated inputs;
- required permission and risk class;
- run-as identity and privilege expectation;
- preconditions and detection step;
- execution step;
- verification or retest step;
- optional rollback step and rollback confidence;
- timeout, output, upload, file-count, memory, CPU, and child-process limits;
- structured result schema;
- sensitive-field and secret-redaction rules;
- whether retries are safe;
- whether offline queueing is safe;
- minimum audit and approval policy.

Definitions are immutable after publication. Changes create a new version. Jobs always record and execute one exact version.

### Job state model

Aggregate and per-target states use a consistent vocabulary:

- queued;
- leased;
- running;
- succeeded;
- failed;
- cancelled;
- expired;
- timed out;
- skipped;
- unsupported.

Attempts are never overwritten. A retried target receives a new attempt linked to the previous one. Completion with an expired or invalid lease is retained as late evidence but cannot silently replace the authoritative outcome.

### Offline behavior

Each action declares and each job records one policy:

- skip if offline;
- queue until a fixed expiry;
- wait for the next connection within the schedule window.

Recurring schedules do not accumulate an unbounded backlog. Each occurrence has its own expiry and target snapshot.

### Scheduling

Support:

- run now;
- run once at a future time;
- daily, weekly, monthly, and cron-like recurrence;
- explicit timezone;
- maintenance window;
- maximum duration and occurrence expiry;
- canary count or percentage;
- maximum concurrency and optional batch size;
- stop-on-failure threshold;
- offline policy;
- notification/export hook after completion.

A schedule binds the exact action version, parameters, selector, and risk policy. Editing any bound field requires reapproval where approval applies.

## Inventory and telemetry

### Standard inventory

Normalized current state and refreshable endpoint views include:

- identity: hostname, serial or stable platform IDs, manufacturer, model, virtualization, tags;
- operating system: family, edition, version, build, architecture, boot time, timezone;
- hardware: CPU, memory, firmware, disks, volumes, encryption state, batteries where available;
- network: interfaces, addresses, routes, DNS, listening ports, active connections;
- software: name, version, publisher, architecture, install source, install date where available;
- updates: installed hotfixes and operating-system update status where available;
- services and daemons: name, state, start mode, account, binary path;
- startup items and scheduled tasks;
- processes: PID, parent PID, name, executable path, user, start time, command line, hash/signature when requested, memory;
- local users and groups;
- interactive and remote sessions;
- security tooling: firewall, antivirus/EDR presence and state, disk encryption, secure boot where available;
- agent health and collection errors.

Each category shows:

- collected time and age;
- source endpoint and agent version;
- full, partial, unsupported, or failed status;
- whether the display is cached or the result of a live refresh;
- differences from the previous successful snapshot.

### Collection cadence

- Stable categories use a configurable periodic full refresh.
- Volatile categories use a shorter configurable snapshot cadence or explicit refresh.
- Incident monitoring profiles may temporarily increase cadence on selected endpoints.
- Full snapshots are deduplicated by content hash where practical.
- Current normalized state remains queryable without retaining every raw snapshot forever.

Suggested starting defaults, to be configurable and validated during implementation:

- heartbeat: 60 seconds;
- stable inventory: 60 minutes;
- process, connection, and session snapshot: 15 minutes;
- incident volatile snapshot: 1 to 5 minutes;
- offline threshold: 3 missed heartbeats.

### Retention

Retention is policy-driven by data class:

- current normalized state remains while an endpoint is active;
- inventory changes use bounded retention;
- job metadata and audit use longer retention;
- large output and evidence use separate quotas and expiry;
- incident-pinned evidence is protected from ordinary expiry until incident retention permits deletion;
- deletion records retain metadata and authorization without retaining deleted content.

No final duration is hardcoded by this plan. Defaults must be selected with deployment scale, incident needs, and compliance obligations visible to the administrator.

### Telemetry boundary

SHA stores useful current state, changes, job records, and incident evidence. It does not ingest every endpoint event indefinitely.

Optional incident monitoring profiles may collect bounded:

- process starts;
- network connections;
- selected operating-system or security logs;
- service and task changes;
- file or registry changes for explicitly defined paths.

Profiles are off by default, scoped, time-limited, resource-capped, and visible on the endpoint.

## Product information architecture

### Primary navigation

- Overview
- Devices
- Inventory
- Compliance
- Incidents
- Jobs
- Runbooks
- Reports
- Audit
- Admin

A persistent scope selector presents:

All clients → Client → Location

Endpoint pages add an endpoint breadcrumb. Global-only administrative pages clearly indicate when scope does not apply.

### Global, client, and location dashboards

The same composable widgets operate at all three scopes:

- endpoint total, online, stale, offline, pending, and unsupported;
- operating-system and agent-version distribution;
- inventory freshness and collection failures;
- software prevalence and recent software change;
- high-interest process, service, port, or security-tool findings;
- compliance score by baseline and control family;
- failed, unknown, stale, and excepted controls;
- open incidents by severity and phase;
- running, queued, failed, and awaiting-approval jobs;
- recent high-risk actions and drift;
- capacity, evidence quota, and agent health warnings.

Dashboard values link to the exact filtered list that produced them. Widgets never rely on a different scope implementation than list and report views.

### Device fleet

Default columns:

- endpoint;
- client and location;
- operating system;
- primary user or session;
- online state and last seen;
- incident state;
- compliance state;
- inventory freshness;
- agent version and health;
- tags.

Filters cover all columns plus software, service, process, port, control result, capability, and collection age. Filters can be saved as views and promoted to dynamic groups. Selecting rows reveals the bulk-action bar.

### Endpoint workspace

Tabs:

- Overview
- Hardware and OS
- Software
- Processes
- Services and Tasks
- Network
- Users and Sessions
- Compliance
- Collections and Jobs
- Terminal
- Timeline and Audit

Every inventory tab shows freshness and a scoped refresh action. Volatile views explain that data is a snapshot, not a live task manager, unless an active session explicitly says otherwise.

### Job workspace

Job list and detail show:

- requester, reason or incident, creation and schedule source;
- exact action or runbook version and parameters;
- original selector and resolved target snapshot;
- approval record;
- batch and per-device progress;
- queue, lease, start, finish, expiry, and cancel times;
- output, structured results, errors, retries, and capability mismatches;
- collected evidence and hashes;
- verification and rollback results.

### Incident workspace

Tabs:

- Summary
- Endpoints
- Hunts and Collections
- Actions
- Evidence
- Timeline
- Notes
- Report

An incident is deliberately not a ticketing system. It groups response scope, work, evidence, annotations, and exports.

## Command console and interactive terminal

### First delivery: durable command console

The first shell-like experience is a single-endpoint command console backed by ordinary jobs:

- one submitted command creates one immutable action attempt;
- the operator selects shell family and approved execution context;
- stdout, stderr, exit code, duration, and truncation are durable;
- commands can be cancelled and are visible in job and endpoint history;
- command history cannot be replayed against another endpoint without a new request;
- file transfer is not part of the console;
- bulk commands use the standard job form, not the console.

This delivers useful remote command execution without making an interactive transport the first security dependency.

### Later delivery: interactive terminal

After identity, authorization, leases, output limits, and audit are proven, add:

- PowerShell and command shell on Windows;
- shell or Bash-compatible session on Linux and macOS;
- PTY or ConPTY-backed interaction where supported;
- dedicated terminal permission;
- recent authentication and reason or incident;
- approved execution identity;
- short authorization TTL and idle timeout;
- byte, duration, process, and upload limits;
- complete input/output transcript with sensitive display controls;
- operator and administrator kill;
- immediate termination on credential revocation or lost authorization;
- prominent endpoint, client, location, privilege, and recording indicators.

No terminal session may silently escape its endpoint, scope, privilege, or approved lifetime.

## Incident-response model

### Deployment modes

Pre-positioned mode:

- agent remains installed;
- normal inventory and compliance cadence;
- approved runbooks ready for use;
- incident profile raises collection only when activated.

Rapid-response mode:

- incident-scoped enrollment package;
- short expiry and limited scope;
- immediate triage collection;
- optional endpoint approval;
- configurable post-incident disable or uninstall workflow;
- evidence remains according to incident retention after agent removal.

### Response loop

1. Detect or receive an incident.
2. Define client, locations, endpoints, tags, and responders.
3. Refresh state and run a canary triage collection.
4. Expand a hunt to the previewed fleet scope.
5. Preserve selected evidence.
6. Contain or perform cleanup.
7. Recollect and verify.
8. Release containment when authorized.
9. Annotate the timeline and export the report.

### Hunt

A hunt is a job group optimized for collection across a dynamic target set. Its launch flow includes:

- action or runbook;
- client, location, tags, saved group, or endpoint selector;
- target preview;
- canary;
- offline catch-up and fixed expiry;
- concurrency and resource budget;
- paused review before launch;
- per-endpoint flow results;
- incident attachment;
- saved findings and evidence.

### Evidence

Evidence collection is bounded and records:

- source endpoint and path or collector;
- requesting principal and incident;
- action version and parameters;
- start and completion time;
- original size, collected size, and truncation;
- cryptographic hashes;
- content type;
- storage object identity;
- access history;
- retention and legal/incident pin state.

SHA initially supports explicit file collection and defined triage bundles, not a general remote file browser.

### Initial triage bundle

The built-in cross-platform triage runbook should gather only bounded, documented data:

- host and agent identity;
- boot and logged-in session data;
- process tree and selected hashes;
- active connections and listeners;
- services, startup items, and scheduled tasks;
- installed software and recent changes;
- security-tool state;
- selected system and security logs with time and size bounds;
- SHA job, collection, and inventory freshness data.

Platform-specific additions must declare cost, privilege, sensitivity, and output limits.

## Compliance and hardening model

### Control contract

Each control has:

- canonical stable ID;
- title, rationale, severity, platform, and applicability;
- source, source version, citation, and content license;
- detection action and expected typed result;
- remediation action if supported;
- verification action;
- rollback action or explicit reason none is safe;
- evidence contract;
- default risk and approval policy.

Posture results, actions, dashboard links, and reports use the same canonical control ID.

### Baselines and assignments

- Baselines are immutable after publication; edits create versions.
- Assignment precedence is documented and visible.
- Start with one explicit override layer; do not build deep policy inheritance.
- An endpoint view shows the effective baseline and why each control applies.
- Unsupported and not-applicable remain distinct from unknown and failed.

### Evaluation states

- Pass
- Fail
- Unknown
- Not applicable
- Stale

Every result has evidence, collection time, evaluator version, endpoint, baseline version, and freshness.

### Exceptions

Exceptions require:

- exact control and scope;
- owner;
- reason;
- compensating control where relevant;
- approver;
- start and expiry;
- review state.

Expired exceptions return to active failure automatically and appear on dashboards and reports.

### Remediation

The standard operation is:

Detect → Plan → Approve if required → Change → Retest → Record → Roll back if necessary

Observe, approval-required, and auto-remediate modes must change behavior, not merely label installer profiles. Auto-remediation is allowed only for explicitly approved versioned actions with bounded scope, strong verification, safe retry behavior, and acceptable rollback confidence.

## Initial built-in action and collection catalog

The first catalog stays small and useful.

### Read and collect

- refresh full inventory;
- refresh one inventory category;
- snapshot process tree;
- snapshot connections and listeners;
- snapshot services, startup items, and scheduled tasks;
- snapshot users and sessions;
- collect bounded event or security logs;
- inspect file metadata and calculate hash;
- collect a bounded file;
- run the standard triage bundle;
- evaluate an assigned compliance baseline.

### Change and cleanup

- terminate a process or process tree;
- start, stop, or restart a service;
- disable or enable a startup item or scheduled task where safely supported;
- reboot an endpoint;
- run a published versioned script or command action;
- remove a specifically identified file only through a typed action with quarantine or rollback where feasible.

### Contain

- isolate endpoint network while retaining SHA control connectivity;
- release network isolation;
- block or unblock a specific IP only after platform behavior is deterministic and rollback is proven.

### Harden

- retain and migrate the existing Linux SSH and firewall actions;
- retain and migrate the existing Windows firewall and Defender actions;
- add controls only with cited detection, verification, and rollback behavior;
- add software present, absent, or minimum-version desired state after inventory and action foundations are stable.

Each catalog item has platform tests, risk, default approval, output caps, and rollback notes. Platform support is explicit rather than simulated.

## Reports

Start with fixed reports and exports:

- fleet and asset inventory;
- software prevalence and software change;
- endpoint and agent health;
- compliance summary;
- compliance control detail and evidence;
- compliance exceptions and expirations;
- incident summary and timeline;
- incident action and collection outcomes;
- evidence manifest with hashes;
- job outcomes, failures, and unsupported targets;
- high-risk action and terminal audit.

Report scope:

- global;
- client;
- location;
- saved group;
- endpoint;
- incident.

Initial formats:

- CSV for tabular evidence;
- JSON for machine-readable export;
- printable HTML for human reports.

PDF generation, email delivery, and external storage delivery come after report content and authorization are proven. Scheduled reports reuse the schedule engine and bind exact report version, scope, filters, recipients or destination, and authorization policy.

## Delivery sequence

Sequence is mandatory because later remote-control features amplify early identity or queue mistakes. Work inside a phase may be split into thin vertical slices. A later phase may begin only when the earlier phase's security and data-model exit criteria are satisfied.

### Phase 0 — Stabilize contracts and security boundaries

Status: Complete on 2026-07-17. Runtime and acceptance evidence: `docs/verification/2026-07-17-phase0-runtime.md`.

Purpose: make today's behavior safe enough to extend and prevent new features from hardening the wrong abstractions.

Deliverables:

- architecture decisions for canonical agent, hierarchy, identity, auth, execution, inventory, retention, and evidence storage;
- threat model covering browser, API, enrollment, endpoint, job, evidence, tenant isolation, and terminal boundaries;
- explicit production and local-development configuration modes;
- frontend authentication boundary that never injects shared operator authority for an unauthenticated caller;
- authenticated principal propagated to audit instead of free-form actor strings;
- canonical control IDs across posture, action, API, and UI paths;
- migration framework verified for SQLite development and PostgreSQL production;
- lease and idempotency protection applied to current mutation queues before their surface expands;
- current public schemas and runtime behavior documented;
- compatibility tests around existing reporters and the Go agent.

Acceptance:

- an unauthenticated browser cannot call operator routes through the frontend;
- a principal cannot forge another actor in an action or audit record;
- two agents cannot successfully execute the same current mutation lease;
- an expired lease cannot silently overwrite a newer authoritative result;
- current control result and action references resolve to one canonical control ID;
- a clean database and an upgraded representative database work on SQLite and PostgreSQL;
- current Linux and Windows reporter flows continue to work while migration begins;
- actual local runtime routes and UI access states are exercised.

Not in this phase:

- broad inventory;
- new mutation actions;
- scheduling breadth;
- terminal.

### Phase 1 — Establish hierarchy, identity, authorization, and the canonical agent

Purpose: create the durable ownership and trust model every later feature depends on.

Deliverables:

- Client, Location, Endpoint, Tag, Saved View, and Dynamic Group entities;
- migration of existing tenant and site strings to relational client and location references;
- short-lived scope-bound enrollment tokens;
- pending or approved enrollment policy;
- unique device credentials with hash-at-rest, rotation, and revocation;
- device-bound agent endpoints and cross-device authorization tests;
- provider-neutral OIDC sessions;
- roles, granular permissions, and scoped bindings;
- append-only audit events using authenticated principals;
- agent capability negotiation and protocol versioning;
- Go agent parity plan followed by incremental collector/action migration;
- signed and digest-pinned agent release path;
- signed release manifest and signed personalized bootstrap manifest with documented key rotation and revocation;
- thin Linux and Windows installers using the Go agent;
- profile packages with embedded short-lived enrollment tokens;
- reusable generic packages accepting URL, enrollment token, and optional CA bundle at install time;
- secret-safe token input through standard input or restrictive file in addition to the required command-line flag;
- production HTTPS enforcement, TLS 1.2 minimum, hostname and chain verification, and private-CA support;
- macOS read-only installer and agent support where current platform capability permits;
- migration package for existing generated reporters.

Acceptance:

- one-use enrollment creates an endpoint only in its bound client and location;
- a stolen or replayed enrollment token cannot enroll beyond its limit or expiry;
- one device credential cannot read, claim, or upload for another endpoint;
- revocation blocks new work and uploads immediately;
- scoped users cannot infer or access other clients through IDs, filters, exports, jobs, or evidence;
- agent configuration and credentials have restrictive platform-appropriate permissions;
- Linux and Windows services survive restart, reconnect, rotate credentials, and advertise capabilities;
- macOS reports supported read-only capabilities honestly;
- new installer profiles use the Go agent;
- a profile package completes install and enrollment with one normal package action or documented command;
- the same generic package enrolls into different authorized scopes when passed different valid tokens;
- successful enrollment erases the bootstrap token from installed configuration and uses a unique device credential;
- installer output, process arguments after bootstrap, service definitions, logs, URLs, and filenames do not expose token values;
- token-bearing package bodies cannot be previewed in the UI and authenticated downloads return private, no-store cache policy;
- a valid public certificate and a valid supplied private CA succeed, while wrong hostname, untrusted CA, expired certificate, incomplete chain, plain HTTP production profile, and verification bypass fail closed;
- cross-origin redirect and HTTPS downgrade tests prove credentials are not forwarded;
- reinstall is idempotent and does not create a duplicate endpoint;
- old reporters have a tested migration and deprecation path.

Not in this phase:

- raw shell;
- recurring fleet actions;
- full incident and compliance UX.

### Phase 2 — Build the unified action and job spine

Purpose: prove one end-to-end execution model before adding inventory and action breadth.

First vertical slice: refresh endpoint identity and OS inventory from the UI through an immutable read-only action, agent lease, structured result, current-state projection, and job detail page.

Deliverables:

- action definitions and immutable versions;
- typed parameters and capability checks;
- jobs, target snapshots, target states, attempts, leases, output chunks, and collected-artifact metadata;
- idempotency, acknowledgements, expiry, safe retry policy, cancellation, timeout, and late-result handling;
- output and upload caps;
- run-now and run-once triggers;
- target preview and authorization reduction;
- canary and maximum concurrency;
- job list and detail views;
- endpoint collection/job history;
- structured agent execution SDK used by built-in collectors and actions;
- compatibility adapter for current actions until migrated.

Acceptance:

- the first inventory refresh runs end to end on Linux and Windows and reports explicit macOS support;
- the job records exact action hash, parameters, selector, target snapshot, principal, and timestamps;
- offline endpoints follow skip or fixed-expiry queue policy;
- duplicate polling or reconnect does not duplicate an effect;
- cancellation and timeout are visible to both agent and operator;
- truncated output states the original and retained size;
- unsupported targets are rejected before execution;
- job detail remains complete after service restart;
- a runtime UI test launches, observes, and inspects a real agent job.

Not in this phase:

- broad action catalog;
- interactive terminal;
- deep runbook orchestration.

### Phase 3 — Deliver inventory, scoped dashboards, and fleet views

Purpose: make SHA immediately useful for device understanding and compliance evidence.

Deliverables:

- normalized current inventory and bounded change events;
- platform collectors for hardware, OS, software, hotfixes, disks, encryption, interfaces, services, tasks, startup items, processes, connections, ports, users, sessions, and security tooling;
- collection completeness, freshness, error, and capability metadata;
- stable and volatile collection cadences;
- global, client, and location scope selector;
- scoped overview dashboards;
- filterable device fleet;
- saved views and dynamic groups;
- endpoint workspace inventory tabs;
- cached-as-of and refresh-live behavior;
- inventory and software fixed reports in CSV, JSON, and printable HTML;
- inventory retention and quota settings.

Acceptance:

- software inventory and process snapshots are visible at endpoint level on Linux and Windows;
- supported macOS inventory is visible with unsupported fields explicit;
- global, client, and location views return the same counts as their underlying filtered device lists;
- selecting another scope changes dashboards, lists, exports, and targets consistently;
- inventory categories show collection age and partial or failed status;
- a refresh creates a job and updates the correct current projection;
- changes between snapshots are queryable without retaining unbounded raw data;
- software and process filters can be saved and used as a dynamic group;
- cross-client query and export tests fail closed;
- representative runtime dashboards and endpoint pages are exercised with real agent data.

Not in this phase:

- continuous EDR-like telemetry;
- arbitrary report design;
- a remote file browser.

### Phase 4 — Add controlled actions, bulk work, scheduling, and command console

Purpose: turn inventory into safe remote operations without bypassing the execution spine.

Deliverables:

- initial read, change, contain, and harden action catalog;
- action risk policy and granular permissions;
- authenticated approval workflow bound to exact action, parameters, selector, and expiry;
- distinct-approver support for high-risk policy;
- recurring schedules, timezone, maintenance windows, expiry, offline behavior, and missed-run rules;
- per-occurrence target snapshots;
- bulk-action bar and preview;
- canary, batches, maximum concurrency, stop thresholds, and cancellation;
- simple ordered runbooks with typed inputs and stop conditions;
- durable single-endpoint command console;
- job outcome and high-risk action reports;
- notification/export hooks with bounded retry and audit.

Acceptance:

- read-only, typed mutation, high-risk, and raw command permissions are independently enforced;
- editing an approved schedule's action, parameters, selector, or limits invalidates approval;
- recurring work cannot create unbounded missed-run backlog;
- a canary failure can prevent later batches;
- requester cannot self-approve where distinct approval is configured;
- service control, process termination, reboot, and existing hardening actions detect, execute, and verify on supported systems;
- isolate and release retain SHA control connectivity and are recoverable in test environments;
- each console command has exact endpoint, principal, context, input, output, exit, limits, and audit;
- no bulk or scheduled command bypasses normal jobs;
- runtime tests cover online, offline, cancel, expiry, failure, partial fleet, and service restart.

Not in this phase:

- persistent interactive terminal;
- remote desktop;
- arbitrary file transfer.

### Phase 5 — Add incident cases, hunts, evidence, and response reporting

Purpose: support the actual response workflow rather than expose disconnected remote tools.

Deliverables:

- incident entity, status, severity, scope, responders, notes, tags, and retention;
- incident endpoint assignment and rapid-response enrollment profile;
- hunt launch workflow with preview, canary, offline expiry, and resource budget;
- standard triage runbook;
- bounded file, log, process, network, service, task, session, and security-tool collections;
- evidence object storage abstraction with local and S3-compatible implementations;
- hashes, provenance, access audit, quota, expiry, and incident pinning;
- findings and timeline events;
- analyst annotations and pinned evidence;
- containment, cleanup, recollection, verification, and release workflow;
- incident workspace and fixed incident reports.

Acceptance:

- an operator can create an incident, enroll or select endpoints, run a triage canary, expand the hunt, preserve evidence, contain, remediate, verify, and export one complete record;
- offline hunt targets may catch up only until the recorded expiry;
- evidence content is inaccessible without both scope and evidence permission;
- evidence hashes and provenance survive export and can be independently verified;
- storage limits fail visibly without losing job metadata;
- incident-pinned evidence is protected from ordinary expiry;
- timeline order and source remain clear across audit, collections, actions, findings, and notes;
- rapid-response endpoints can be disabled or uninstalled without deleting incident history;
- the full workflow is exercised against real Linux and Windows agents.

Not in this phase:

- a ticketing system;
- unrestricted forensic query language;
- full disk imaging;
- indefinite telemetry retention.

### Phase 6 — Complete compliance, desired state, and evidence reporting

Purpose: make hardening repeatable, explainable, and provable.

Deliverables:

- versioned baseline and control contracts;
- assignment to client, location, group, or endpoint;
- explicit effective-policy resolution;
- pass, fail, unknown, not-applicable, and stale evaluation;
- evidence and freshness;
- exception request, approval, owner, reason, compensating control, review, and expiry;
- detect, plan, approve, change, retest, record, and rollback session;
- observe, approval-required, and safe auto-remediation behavior;
- migration of current control packs and actions to canonical IDs and the unified flow model;
- compliance dashboards at global, client, location, and endpoint scope;
- compliance summary, detail, evidence, and exception reports.

Acceptance:

- every reported control result names the exact baseline, control, evaluator, evidence, endpoint, and time;
- effective policy is explainable from assignments and the one supported override layer;
- stale, unknown, unsupported, not-applicable, failed, and excepted are never collapsed;
- exception expiry automatically restores the active finding;
- a supported remediation records before state, change, verification, and rollback outcome;
- auto-remediation runs only an explicitly approved immutable version within target and risk policy;
- existing Linux and Windows controls retain or improve platform behavior after migration;
- dashboard totals match control-detail exports at every scope;
- a complete compliance cycle is exercised through the real UI and agents.

Not in this phase:

- licensed benchmark content without redistribution rights;
- deep inheritance;
- a general policy programming language.

### Phase 7 — Add interactive terminal, incident monitoring, delivery, and production hardening

Purpose: finish the expected operator experience only after its security dependencies are proven.

Deliverables:

- short-lived interactive terminal sessions with PTY or ConPTY where supported;
- dedicated authorization, recent-auth check, reason or incident, TTL, idle timeout, limits, transcript, and kill;
- optional bounded incident monitoring profiles;
- scheduled report delivery after authorization review;
- PostgreSQL production deployment and upgrade verification;
- evidence backup, restore, and integrity procedures;
- control-plane health, metrics, capacity, quota, and queue diagnostics;
- agent rollout rings, signed update verification, compatibility windows, and rollback;
- documented high-availability topology and tested failure behavior;
- scale and soak tests against a declared deployment target;
- operator, responder, administrator, deployment, upgrade, recovery, and security documentation.

Acceptance:

- terminal access is independently permissioned and cannot start without recent valid authorization;
- terminal terminates on TTL, idle timeout, operator kill, revocation, or authorization loss;
- every terminal input and output segment is associated with endpoint, principal, session, time, and truncation state;
- terminal sessions cannot widen endpoint, client, privilege, or lifetime;
- monitoring profiles expire automatically, honor quotas, buffer within bounds, and expose data loss;
- PostgreSQL upgrade, backup, restore, and service-failure exercises preserve authoritative jobs and audit;
- agent update signature failure blocks installation and reports a useful error;
- control-plane restart, worker restart, agent disconnect, and partial storage outage have tested outcomes;
- the declared scale target has measured queue latency, API latency, storage growth, and job throughput;
- installation, first enrollment, incident workflow, compliance workflow, report export, upgrade, and recovery docs are accurate against the shipped runtime.

## Cross-cutting implementation requirements

### Database and migrations

- All durable schema changes use migrations.
- SQLite remains a supported easy local-development path until an explicit product decision removes it.
- PostgreSQL is the production reference.
- Migrations cover clean install and representative upgrades from existing SHA data.
- Existing tenant/site strings and reporter records are migrated without silently crossing client scope.
- Destructive retention work is separated from transactional request paths and always audited.

### API and contracts

- Server models remain the canonical public contract.
- JSON Schema and frontend or agent bindings are generated or checked for drift.
- Public APIs are versioned before incompatible change.
- Pagination, filtering, sorting, scope, and timestamps are consistent.
- Sensitive fields are classified and never returned merely because an object ID is known.
- Long output and evidence use bounded streaming or object retrieval rather than oversized API rows.

### Agent quality

- Collectors are deterministic, bounded, cancellable, and explicit about partial results.
- Privileged actions use the minimum required privilege and avoid string-built shell commands where native APIs are practical.
- Secret-bearing files use restrictive permissions.
- Logs redact credentials, tokens, secret parameters, and protected evidence.
- Platform capability matrices live beside tests and documentation.
- A failed action does not report success because a command launched; verification determines the result.

### Frontend quality

- Scope is visible on every action-capable page.
- High-risk operations show exact target count, action version, privilege, expiry, and approval.
- Cached and live state are visually distinct.
- Empty, stale, partial, permission-denied, unsupported, running, and failed states are designed.
- Tables remain usable for large fleets through server-side pagination and filtering.
- Keyboard navigation and accessible names cover primary workflows.
- UI hides unavailable actions for clarity but server authorization remains authoritative.

### Security verification

Tests must cover:

- horizontal access across client, location, endpoint, job, incident, evidence, report, and audit IDs;
- role and scope combinations;
- enrollment replay, expiry, use limit, wrong scope, and approval;
- device impersonation, credential rotation, and revocation;
- lease replay, duplicate delivery, stale completion, cancellation, and unsafe retry;
- target changes between preview and launch;
- approval invalidation;
- sensitive-output redaction;
- output and upload exhaustion;
- evidence path, type, size, and authorization;
- terminal session hijack, reconnect, expiry, revocation, and transcript completeness;
- installer digest and signature failure;
- secrets in logs, generated artifacts, repository changes, and exports.

### Runtime verification

Every vertical slice is exercised through the actual route or UI and a real agent. Minimum platform evidence:

- Proxmox Linux VM for installation, service lifecycle, collection, actions, upgrade, rollback, and TLS behavior relevant to the slice;
- Proxmox Windows VM for installation, Windows service, PowerShell, Defender, firewall, process, upgrade, rollback, and ConPTY behavior relevant to the slice;
- clean VM snapshots or disposable clones for first-install and upgrade evidence, with VM identity, operating-system version, package hash, agent version, and test time recorded;
- macOS contract, build, and capability checks only for now; no macOS runtime gate is required until the user restores it to scope;
- PostgreSQL for production schema and concurrency behavior;
- TLS-enabled deployment for auth, enrollment, agent, evidence, and terminal paths.

Unit, integration, type, build, and static checks remain required but do not replace runtime evidence.

## Migration strategy

1. Stabilize and test current reporter and action behavior.
2. Introduce relational clients and locations while preserving existing API compatibility.
3. Add unique device identity and enroll new Go agents.
4. Add the action/job spine and adapt current queues.
5. Port one collector and one action at a time to the canonical agent SDK.
6. Switch new profiles to the Go agent after required parity.
7. Offer migration packages to existing endpoints.
8. Stop expanding generated reporters.
9. Remove reporter compatibility only after telemetry proves migration and the supported upgrade window ends.
10. Migrate current controls and approvals into the unified flow and compliance models.

No migration may silently duplicate endpoints, change client/location ownership, lose audit history, or re-run a mutation.

## Goal execution rules

When this document is invoked as a goal:

1. Work phases in order.
2. Create task-sized vertical slices with explicit phase and acceptance linkage.
3. Search for and extend existing code before adding parallel abstractions.
4. Update architecture decisions and this roadmap when implementation evidence forces a material change.
5. Keep old paths only for an explicit migration window.
6. Do not add a second agent, queue, scheduler, action model, scope model, or audit model.
7. Do not unlock raw shell or interactive terminal before its prerequisite exit criteria.
8. Ship schema, API, agent behavior, UI, audit, tests, migration, documentation, and real-runtime evidence together for each slice.
9. Use supported project quality gates and managed runtime controls.
10. Keep the repository free of secrets and unrelated changes.
11. Record useful failure evidence and fix the smallest proven cause.
12. Do not mark a phase complete until all mandatory acceptance criteria are evidenced.
13. Do not mark the goal complete until every phase is complete or the user explicitly removes a requirement from this document.

## Definition of done

The goal is done only when:

- a new deployment can securely authenticate operators and enroll uniquely identified endpoints;
- the canonical Go agent is the installed runtime for supported new deployments;
- existing supported endpoints have a documented and tested migration path;
- global, client, location, and endpoint views show accurate scoped inventory, processes, software, jobs, incidents, compliance, and audit;
- operators can preview, approve where required, run, schedule, cancel, and review bounded actions across a fleet;
- operators can use both a durable command console and a gated recorded interactive terminal;
- responders can complete the defined incident loop and export verifiable evidence;
- compliance operators can assign baselines, manage exceptions, remediate, retest, and export evidence;
- cross-client isolation, device identity, leases, replay protection, output limits, approval boundaries, and terminal controls have passing security tests;
- Linux and Windows core workflows have real runtime evidence on Proxmox VMs; macOS claims remain limited to build- and contract-verified behavior for now;
- PostgreSQL deployment, upgrade, backup, restore, and failure behavior are documented and exercised;
- documentation matches the running product;
- all project quality gates pass;
- no required work, migration residue, or knowingly misleading UI remains.

## Proposed defaults requiring confirmation during execution

These recommendations prevent design drift but remain administrator-configurable:

| Decision | Proposed default |
| --- | --- |
| Product hierarchy | Global → Client → Location → Endpoint |
| Human identity | Provider-neutral OIDC; development-only local identity |
| Device identity | Unique rotatable opaque credential over TLS, hashed server-side; future asymmetric upgrade path |
| Endpoint connection | Outbound HTTPS long poll; short-lived duplex channel only for interactive terminal |
| Installer modes | Sensitive profile package with embedded short-lived enrollment token, plus reusable generic package with token-at-install |
| Private PKI | Explicit CA bundle; never certificate-verification bypass in production |
| First shell experience | Durable single-device command console before persistent terminal |
| High-risk approval | Distinct approver for bulk high-risk and break-glass work in production |
| Policy inheritance | Baseline assignment plus one explicit override layer |
| Inventory storage | Normalized current state plus bounded changes; incident-pinned evidence separate |
| Evidence storage | Local development backend plus S3-compatible production abstraction |
| Report design | Fixed reports and saved views; no report builder |
| Telemetry | Inventory and bounded incident profiles; no continuous full telemetry by default |
| Platform priority | Linux and Windows core parity; macOS read-only first, then supported operations |

Implementation must surface rather than bury decisions about:

- target endpoint scale and concurrency;
- default retention durations and quotas;
- required OIDC provider features;
- rapid-response agent expiry and uninstall policy;
- required macOS mutation scope;
- approval policy variations for single-operator deployments;
- object-storage durability and encryption requirements;
- compliance frameworks and redistributable control content.

These are configuration or release decisions, not permission to weaken tenant isolation, device identity, audit, replay protection, or terminal controls.

## Official research sources

### Wazuh

- [Architecture and encrypted component communication](https://documentation.wazuh.com/current/getting-started/architecture.html)
- [Agent identity verification](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/agent-identity-verification.html)
- [Manager identity verification](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/security-options/manager-identity-verification.html)
- [Enrollment through agent configuration](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/enrollment-methods/via-agent-configuration/index.html)
- [Linux deployment variables](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-linux.html)
- [Windows deployment variables](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html)
- [System inventory](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/index.html)
- [How inventory works](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/how-it-works.html)
- [Inventory configuration](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/configuration.html)
- [Inventory fields](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/available-inventory-fields.html)
- [Inventory views](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/viewing-system-inventory-data.html)
- [Inventory reports](https://documentation.wazuh.com/current/user-manual/capabilities/system-inventory/generating-system-inventory-reports.html)
- [Command monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/command-monitoring/configuration.html)
- [Custom active response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)

### ConnectWise Automate

- [Groups and hierarchy](https://docs.connectwise.com/ConnectWise_Automate_Documentation/070/090/020?psa=1)
- [Computer Management screen](https://docs.connectwise.com/ConnectWise_Automate_Documentation/090/080/010?psa=1)
- [Script scheduling](https://docs.connectwise.com/ConnectWise_Automate_Documentation/070/240/030?psa=1)
- [Dataviews](https://docs.connectwise.com/ConnectWise_Automate_Documentation/070/210/010?psa=1)
- [Report Center](https://docs.connectwise.com/ConnectWise_Automate_Documentation/070/210/030?psa=1)

### NinjaOne

- [Organizations and locations](https://www.ninjaone.com/docs/endpoint-management/hardware-inventory/organizations-and-locations/)
- [Device details](https://www.ninjaone.com/docs/endpoint-management/device-details/)
- [Device actions](https://www.ninjaone.com/docs/endpoint-management/actions/device-actions/)
- [Remote commands](https://www.ninjaone.com/docs/endpoint-management/remote-control/remote-commands/)
- [Bulk actions](https://www.ninjaone.com/docs/endpoint-management/actions/bulk-actions/)
- [Reports](https://www.ninjaone.com/docs/reporting/getting-started-with-reports/)
- [Scheduled reports](https://www.ninjaone.com/docs/reporting/scheduled-reports/)
- [Agent tokenization](https://www.ninjaone.com/docs/new-to-ninjaone/agent-installation/agent-tokenization/)
- [Device approval](https://www.ninjaone.com/docs/endpoint-management/device-approval/)

### ImmyBot

- [System requirements and Windows scope](https://www.immy.bot/documentation/gettingstarted/system-requirements/)
- [Computer inventory](https://www.immy.bot/documentation/core-features/computers-inventory/)
- [Tenant management](https://www.immy.bot/documentation/administration/tenant-management/)
- [Maintenance sessions](https://www.immy.bot/documentation/core-features/maintenance-sessions/)
- [Tasks](https://www.immy.bot/documentation/basic-instance-management/working-with-tasks/)
- [Schedules](https://www.immy.bot/documentation/basic-instance-management/schedules/)
- [Role-based access control](https://www.immy.bot/documentation/administration/rbac/)

### Fleet

- [Fleet anatomy](https://fleetdm.com/docs/get-started/anatomy)
- [Fleets](https://fleetdm.com/guides/fleets)
- [Enroll hosts and generate configured packages](https://fleetdm.com/guides/enroll-hosts)
- [Config-less agent deployment](https://fleetdm.com/guides/config-less-fleetd-agent-deployment)
- [Certificates in fleetd](https://fleetdm.com/guides/certificates-in-fleetd)
- [fleetd authentication](https://fleetdm.com/guides/fleetd-authentication)
- [Reports and saved queries](https://fleetdm.com/guides/reports)
- [Scripts](https://fleetdm.com/guides/scripts)
- [Automations](https://fleetdm.com/guides/automations)

### Elastic Agent

- [Agent command reference](https://www.elastic.co/docs/reference/fleet/agent-command-reference)
- [Enrollment tokens](https://www.elastic.co/docs/reference/fleet/fleet-enrollment-tokens)
- [Secure connections](https://www.elastic.co/docs/reference/fleet/secure-connections)
- [Certificate rotation](https://www.elastic.co/docs/reference/fleet/certificates-rotation)

### Velociraptor

- [Client search and fleet views](https://docs.velociraptor.app/docs/clients/searching/)
- [Endpoint collections](https://docs.velociraptor.app/docs/clients/artifacts/)
- [Artifacts](https://docs.velociraptor.app/docs/artifacts/)
- [Hunts](https://docs.velociraptor.app/docs/hunting/)
- [Remote shell](https://docs.velociraptor.app/docs/clients/shell/)
- [Persistent shell release](https://docs.velociraptor.app/blog/2026/2026-05-31-release-notes-0.77/)
- [Client monitoring](https://docs.velociraptor.app/docs/clients/monitoring/)
- [Virtual file system](https://docs.velociraptor.app/docs/clients/vfs/)
- [Notebooks](https://docs.velociraptor.app/docs/notebooks/)
- [Timelines](https://docs.velociraptor.app/blog/2024/2024-09-12-timelines/)
- [Deployment security](https://docs.velociraptor.app/docs/deployment/security/)
