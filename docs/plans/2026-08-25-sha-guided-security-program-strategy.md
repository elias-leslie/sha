# SHA product strategy: guided security program operations

Status: Active; sets product direction above the execution roadmap
Date: 2026-08-25
Execution authority: Invoked by the user as active product direction on 2026-08-25
Relationship to other plans:

- [docs/plans/2026-07-17-sha-ir-compliance-operations-roadmap.md](2026-07-17-sha-ir-compliance-operations-roadmap.md) remains the canonical execution roadmap, phase order, and acceptance authority. Read it second.
- [docs/plans/2026-04-18-sha-roadmap.md](2026-04-18-sha-roadmap.md) is superseded and retained for history.

This document defines who SHA serves, what it covers, and the operating model. The execution roadmap defines delivery order and acceptance evidence. On product intent, this document governs. On sequencing and verification, the roadmap governs.

## Read before resuming

An agent picking up SHA reads, in order:

1. this document;
2. the execution roadmap's `Current execution checkpoint` section;
3. [the Phase 1 verification record](../verification/2026-07-17-phase1-foundation.md).

Nothing here authorizes starting Phase 8 or later before Phase 1 acceptance is evidenced. The exception is Track C content authoring, which has no code dependency.

## Who this is for

- **First-time security lead.** Newly responsible for security at a 50 to 500 person organization. Inherited an undocumented program. Needs a defensible order of work and a record of decisions.
- **Organization with no security lead.** An IT manager or director holding security as a secondary duty. Strong systems knowledge, no framework vocabulary. The framework has to be supplied rather than assumed.
- **MSP or MSSP with limited security depth.** Competent general IT, many small clients, selling security services it cannot fully describe. Needs one repeatable program applied across every client and a report it can hand over.
- **Practitioner closing personal gaps.** Operates SHA against their own estate to learn the discipline. Explicit design target.

Not the first-release audience: organizations with a staffed SOC and a dedicated GRC function. They already run Wiz, ServiceNow, or equivalent. Designing for them weakens every decision that serves the four groups above.

## Product thesis: operate what you already own

Most organizations have already purchased a substantial security capability set and are running it at a fraction of its capability. Windows, Linux, macOS, Entra ID, Google Workspace, AWS, and Azure all ship strong security controls. Those controls are unconfigured, partly configured, or configured once and never verified again, because nobody on staff knows they exist, knows which are safe to enable, or has a way to prove they stayed enabled.

The common response is to buy another product and layer it on top. That adds cost and an agent, and leaves the underlying platform in the same state.

SHA's position: **measure what you own, activate it correctly, prove it stays activated, and only then identify what is genuinely missing.** An organization running SHA against stock Windows, Linux, macOS, and its existing cloud tenant should end up in materially better condition than an organization that bought three security products and installed them over an unhardened platform.

This is also the education mechanism. An operator who works through SHA learns their own platforms rather than learning a vendor console.

### Entitlement awareness

Recommendations must account for edition and license. Telling a Windows Pro environment to enable a capability that requires Enterprise, or telling a Microsoft 365 Business Basic tenant to build Conditional Access policies that require Entra ID P1, wastes the operator's time and costs credibility on first contact.

SHA detects platform edition and, where the API permits, tenant license SKUs, and filters recommendations to what the organization is entitled to use. This produces a second output of direct value: **capabilities the organization is paying for and not using.** For an internal team that is a budget conversation. For an MSP it is a client conversation with immediate substance.

### Native capability coverage

Initial target set. Each entry is a capability SHA detects, evaluates against a documented safe configuration, and where supported, changes through a typed action with rollback.

**Windows.** Defender Antivirus configuration and Attack Surface Reduction rules; Exploit Protection; Application Control (WDAC) and AppLocker; Credential Guard, LSA protection, and Protected Users; BitLocker and TPM state; Windows Firewall across all profiles including logging; Windows Hello for Business; Windows LAPS; Controlled Folder Access; SmartScreen; Advanced Audit Policy; PowerShell script block, module, and transcription logging; Windows Event Forwarding; Secure Boot and memory integrity; SMB signing and encryption and SMBv1 removal; NTLM restriction; Restricted Admin mode.

**Linux.** nftables or firewalld policy; SELinux or AppArmor enforcement state; auditd ruleset; systemd unit hardening directives; SSH server configuration; fapolicyd; LUKS; sudo and PAM policy including password quality and lockout; unattended upgrade configuration; journald retention and forwarding; kernel sysctl hardening.

**macOS.** FileVault; Gatekeeper, XProtect, and notarization enforcement; System Integrity Protection; system and kernel extension policy; Application Firewall and pf; configuration profile state; unified logging retention; signed system volume; screen lock and Touch ID policy.

**Entra ID and Microsoft 365.** Conditional Access policy coverage; MFA enforcement and legacy authentication blocking; Privileged Identity Management; Identity Protection risk policies; application consent policy; admin role assignment and standing privilege; Security Defaults where no premium license exists; Safe Links and Safe Attachments; anti-phishing policy; SPF, DKIM, and DMARC records and enforcement level; audit log retention; external sharing policy.

**Google Workspace.** Two-step verification enforcement; context-aware access; admin role assignment; alert center configuration; DLP rules; less-secure-application and third-party app access policy; sharing and external access defaults; log export.

**AWS.** Service Control Policies; IAM Access Analyzer findings; root account state and MFA; GuardDuty enablement; Config rules; organization CloudTrail; S3 Block Public Access; default EBS encryption; Security Hub standards; IAM credential age and unused access.

**Azure.** Defender for Cloud plan state; Azure Policy assignment; Secure Score components; diagnostic settings and log retention; network security group exposure.

**DNS and mail.** Recursive resolver filtering; DNSSEC validation; DMARC policy strength and reporting; SPF record correctness; MTA-STS and TLS-RPT.

SHA extends beyond native capability only where a real gap exists. The current typed hardening and containment actions, the canary system described below, cross-platform inventory, and the program and evidence layer are those extensions.

## Coverage

Four areas, one data model:

- **Security posture and program management.** What is configured, what is not, what to do next, who owns it, when it was last verified.
- **Compliance.** Framework state, evidence, exceptions, and reporting against CIS, NIST CSF, NIST SP 800-53, and later assessment-driven mappings.
- **Incident response.** Case management, bounded evidence collection, containment, verification, and timeline export. Already defined in the execution roadmap.
- **Attack surface.** Asset and software inventory, exposure, configuration drift, canary coverage, and identity exposure at the device, network, DNS, and cloud layers.

## Framework spine

**CIS Controls v8.1 drives execution.** The controls are ordered. Control 1 is enterprise asset inventory and Control 2 is software asset inventory, which is the correct starting point and the one most organizations skip. Implementation Groups give a maturity progression that CIS has already scoped to organizations with limited expertise and resources. Safeguards are specific enough to assert a result against.

**NIST CSF 2.0 is the reporting view.** Its six functions, including GOVERN, are the vocabulary used by boards, insurers, auditors, and regulators. CSF renders as a view over safeguard state. It never becomes a second evaluation pipeline.

The canonical safeguard identifier is the primary key. CSF 2.0 subcategories, SP 800-53 Rev 5 controls, DISA STIG rules, CISA guidance, and later PCI DSS, HIPAA, ISO 27001, and SOC 2 criteria are mapped views over that key.

**Content licensing.** Verify current redistribution terms with the publisher before shipping any framework-derived text. SHA references safeguard identifiers, numbers, and titles as citations and authors all explanatory, rationale, and remediation text originally. NIST material is United States government work with no redistribution restriction. This continues the existing repository rule against reproducing benchmark content without clear rights.

## Domain model additions

The execution roadmap already delivers `Control`, `Baseline`, `Exception`, evidence, and evaluation states in Phase 6. Those are retained. The following sit above them. A safeguard is satisfied by some combination of native capability states, SHA controls, and attestations; it is not a renamed control.

- **`Safeguard`** — framework identifier, implementation group, asset type, security function, authored guidance text, adversary technique references, framework mappings. Versioned, immutable after publication.
- **`NativeCapability`** — a platform-provided security capability: platform, minimum edition or license, detection method, documented safe configuration, configuration surface (Group Policy, Intune CSP, registry, MDM profile, configuration file, cloud API), rollback method, and known operational impact.
- **`CapabilityState`** — evaluated activation state of a native capability on an asset or tenant, with configuration detail, entitlement status, and evidence.
- **`SafeguardState`** — evaluated state of one safeguard at one scope: status, satisfying evidence, accountable owner, method (`automated`, `attested`, `not_applicable`), confidence, `next_review_at`. Reuses the existing pass, fail, unknown, not-applicable, and stale states.
- **`Attestation`** — human assertion that a process safeguard is satisfied, with evidence attachments, attester, date, expiry, and review cadence.
- **`Finding`** — normalized problem statement from any source: failed control evaluation, inactive native capability, lapsed attestation, canary activation, discovery result, cloud check.
- **`AssetCriticality`** — business context on an asset: confidentiality, integrity, availability weighting, data classification, accountable owner. Prioritization without this is not prioritization.
- **`Risk`** — findings grouped into a decision-bearing item with likelihood, impact, score, owner, treatment (accept, mitigate, transfer, avoid), remediation SLA, and due date. Acceptance links to the existing `Exception` object rather than creating a second acceptance path.
- **`ProgramSnapshot`** — immutable periodic record of implementation group coverage, CSF function coverage, open risk by severity, expiring exceptions, and change since the previous snapshot. Reports render from snapshots so they remain reproducible.
- **`GuidanceStep`** — computed next-action queue derived from safeguard order intersected with current state. Not authored content, so it cannot drift from reality.

Constraint: no second scope model, audit model, evidence model, approval model, or evaluation state set. Everything binds to the existing Global to Client to Location to Endpoint hierarchy and writes to the existing append-only audit stream.

## Extensibility architecture

SHA's thesis commits it to evaluating and operating security capability across a set of platforms that will never stop growing. New operating system releases, new cloud services, new SaaS admin APIs, new network and identity products, and new device classes arrive continuously. The extension seam is therefore the architecture, not a feature added to it.

The design target: **adding support for a new platform, product, or API touches provider content only, and requires no change to the job engine, scope model, audit path, risk layer, reporting, or the Advisor.**

### The provider contract

One contract covers every integration point. A provider declares:

- identity: stable identifier, version, vendor, and target type;
- preconditions: platform, edition, license SKU, or API permission required, each with a stated reason;
- exposed capabilities: which `NativeCapability` identifiers it can detect, and which it can actuate;
- typed manifest: inputs, outputs, result schema, and required credentials;
- execution locus: control plane or agent;
- resource bounds: timeout, output cap, rate limit, and concurrency;
- trust: signature, provenance, and first-party or third-party status.

Provider kinds, all sharing the contract:

- **Collector** — reads state from a target. Endpoint configuration, cloud tenant settings, SaaS admin API, DNS and mail records, network device.
- **Actuator** — changes state, with a required rollback method or an explicit statement that none is safe.
- **Canary** — deploys, monitors, rotates, and retires a canary type.
- **Sink** — delivers notifications and exports: email, Slack, Teams, webhook, SIEM.
- **Content** — safeguards, capability definitions, and framework mappings. Already data today.
- **Model** — Advisor model provider.
- **Renderer** — report output formats.

### Declarative first, code second

This is the decision that determines whether extension is actually easy.

Most integrations reduce to: call an API or read a setting, map the response into a typed state, compare against a documented safe configuration. That is data and a bounded expression, not a compiled module.

**Declarative providers** specify an HTTP request or a platform read (registry value, sysctl, plist key, configuration file, command output with a parser), a mapping into the result schema, and a comparison. They ship as signed content packs through the existing pack builder and provenance model. They require no code, no release, no agent upgrade, and no fleet rollout.

**Code providers** are the escape hatch for the cases declarative specs cannot express. They carry a heavier trust, review, and release burden by design, which keeps them rare.

The practical consequence: supporting a new SaaS product should be an afternoon of writing a signed content pack, not a Go build, a signed agent release, and a fleet upgrade cycle. If adding a provider requires a release, the extensibility goal has failed regardless of how clean the interfaces look.

### Trust boundary

A plugin system inside a security product is an attack surface, and this one runs privileged code on endpoints and holds cloud credentials. Non-negotiable rules:

- every provider is signed and version-pinned; the existing pack-builder discipline extends to providers unchanged;
- declarative providers have no arbitrary execution by construction, which is the primary reason to prefer them;
- code providers run under declared and enforced permissions: which hosts they may reach, which paths they may read, which credentials they may request. No shell, no unbounded filesystem access, no undeclared egress;
- a provider can never widen scope, obtain a device credential, bypass the approval gate, or write outside its declared outputs;
- a provider manifest change requires re-approval. A provider whose declared permissions or capabilities change after an operator approved it is treated as a new provider, not an update. This closes the substitution problem that affects every plugin ecosystem;
- third-party providers are quarantined by default and require explicit operator enablement per scope.

### Compatibility and negotiation

Providers declare a contract version. The agent already advertises versioned capability manifests and negotiates protocol version, delivered in migration `20260717_0009`. Provider compatibility extends that mechanism rather than introducing a parallel one. An unsupported provider produces an explicit unsupported result, never a silent skip and never a simulated pass.

### The seam that makes it work

`Finding` is the universal output type. Every provider that identifies a problem emits a `Finding`. Every actuator emits an action attempt record. Nothing downstream, meaning risk, program state, reporting, dashboards, or the Advisor, knows or cares which provider produced the input.

This is the testable statement of the whole design: **adding a provider must require zero changes outside provider content.** Any pull request adding a provider that also modifies the risk model, the reporting layer, or the job engine indicates the contract is wrong and needs correcting before more providers are written.

### Assessment: refactor, not rewrite

A full rewrite is not warranted and would destroy the most valuable work in the repository.

The expensive, easy-to-get-wrong parts are already built and partly verified: the Global to Client to Location to Endpoint hierarchy, device identity and enrollment, scoped authorization predicates, append-only audit, leased and idempotent job delivery, the approval gate, and signed package trust. Those are exactly the components a rewrite would put at risk, and none of them conflict with the provider contract.

What does need to change is the control and action layer, which today expresses controls and actions as hardcoded typed enumerations. That layer becomes the provider contract.

**This refactor must land before Phase 3.** Phase 3 delivers roughly fifteen platform inventory collectors. Those collectors are the first providers. Writing them against hardcoded interfaces and converting them afterward costs several times more than defining the contract first, and the cost grows with every control added in Phases 4 and 6. The roadmap is amended accordingly with Phase 2A, inserted between the job spine and inventory delivery.

## Canary system

For an organization without a SOC, canaries are the highest signal-to-noise detection available, and they cost nothing to operate. A canary has no legitimate reason to be touched, so an activation is close to a true positive by construction. This suits the target audience better than any log-volume detection strategy.

SHA treats canaries as managed assets with full lifecycle handling, not as a side feature.

**Device.** Canary files in predictable locations including user document paths and file shares; canary registry keys; canary local accounts that are never used, where any authentication attempt is an alert; canary scheduled tasks.

**Identity and directory.** Honeytoken accounts in Active Directory and Entra ID, including accounts with service principal names as Kerberoasting bait; canary groups; canary service accounts with no legitimate consumer.

**Network.** Canary listeners on unused addresses within a segment; responder-visible hosts that should never receive traffic; alerting on connection attempts to unallocated addresses.

**DNS.** Canary records that should never resolve; unique subdomain tokens embedded in configuration files, documents, and repositories, where any resolution indicates reconnaissance or exfiltration.

**Cloud.** Canary IAM access keys, which alert on any use anywhere and carry near-zero false positive rate; canary storage buckets and objects; canary application registrations.

**Document and mail.** Tokens embedded in Office documents and PDFs; canary mailboxes.

Lifecycle requirements:

- deployment through the existing typed action and job model, targeted by scope;
- inventory of every canary with location, type, deployment date, and expected-silence state;
- alert routing with severity and escalation;
- rotation and retirement;
- **benign-trip suppression**, which is the practical failure mode. Backup software, endpoint protection scanning, indexing services, and DLP agents will read canary files. Without a documented and maintained suppression path, canary alerting is abandoned within a month. This is a first-class requirement, not a later refinement.

A canary activation produces a `Finding` at high severity, which can propose an existing containment action for human approval.

## Teaching architecture

The instructional function is structural. It cannot be added later as help text.

1. **The entry point is the next action, not a dashboard.** Default view: current implementation group position, the highest-value next safeguard, what it covers, what SHA already found, and the action to take. Dashboards exist and are not the entry point. A dashboard assumes the operator knows what to look for.
2. **Every finding carries five fields.** What the condition is. Why it matters. What an adversary does with it. What breaks operationally if it is remediated. How to reverse the remediation. Content missing any of the five fails review.
3. **Process safeguards are first class.** Assigned asset ownership, a documented data management process, a current incident response contact list, completed awareness training. No scanner evaluates these. Modeling them as attestations with evidence and expiry is the difference between a security program tool and a scanner.
4. **The maturity ladder is gated.** IG2 work is not presented as actionable until IG1 is materially complete.
5. **Nothing is ever finished.** Every safeguard state and attestation carries a review date. Drift, expiry, and scheduled snapshots make consistency the default rather than a discipline the operator must personally supply.
6. **Evidence accrues as a byproduct.** Every state transition writes an evidence record during normal operation, not during a separate compliance exercise. Safeguards map to common cyber insurance questionnaire items; for this audience a renewal questionnaire is more often the trigger than an audit.
7. **Every number explains itself.** Any score, percentage, or ranking drills to the exact facts that produced it. SHA ships no opaque risk score. An operator who cannot reconstruct a number cannot defend it and has not learned anything from it.

## SHA Advisor

SHA includes an LLM assistant. The execution roadmap's non-goal, "AI-generated or autonomous endpoint actions," stands unchanged and is reconciled as follows.

### Authority boundary

- Read-only over SHA's own data and its authored guidance content. No other data source.
- May **draft** an approval request, exception, risk entry, attestation, remediation plan, or report narrative. A human principal reviews and submits. A draft is inert until a person acts on it.
- Never holds a device credential, claims an action lease, calls an agent-facing route, or starts a job.
- Runs under the calling principal's identity with the same scoped query predicates as any other read path. No privileged or service-account view. Cross-client isolation is enforced by the existing scope layer, not by instruction to the model.
- Every interaction writes an audit event with principal, scope, question, retrieved object identifiers, and any drafts produced.

### Untrusted input handling

SHA ingests adversary-influenced content by design: hostnames, process names, file paths, command lines, log entries, collected evidence. All of it is untrusted input.

- Retrieved content cannot select a tool or trigger an action. Tool selection derives from the authenticated user turn only.
- Endpoint-derived content is delivered inside explicit untrusted-content delimiters and never concatenated into instruction context.
- Output that would become durable state is materialized as a draft and shown in a reviewable diff. There is no path from model output to submitted state without a human action.
- Advisor egress is limited to the configured model provider. No general network capability.

### Deployment

- Provider-neutral interface. A self-hosted or locally-hosted model is a supported configuration. An MSP serving regulated clients cannot route client data to a third-party provider without contractual cover, and some organizations cannot at all.
- **The product is fully usable with the Advisor disabled.** Every Advisor answer has a deterministic fallback in the authored guidance text. The model improves synthesis and phrasing. It is never the source of truth for what a safeguard means or what state the program is in. This is required for air-gapped deployment and is the basis on which a security buyer will trust the feature.

### Initial functions

1. Explain a finding at the operator's stated experience level.
2. Recommend and justify the next safeguard, citing current state.
3. Draft the executive narrative from a specific `ProgramSnapshot`.
4. Answer coverage questions against evaluated state, including plain `unknown` and `stale` answers.
5. Translate an insurance questionnaire item or client question into the safeguards that answer it.
6. Run an incident tabletop against actual inventory and current gaps.

The Advisor states uncertainty plainly rather than inferring coverage. A confidently wrong coverage answer in this product is worse than no answer.

## Onboarding

SHA is useful before the first agent is installed. A short scoping interview produces the applicable safeguard set with every safeguard in `unknown` state. That is already more structure than most of the target audience has. Agent enrollment and cloud connection then convert `unknown` to evaluated, progressively. Onboarding is not blocked on deployment.

Scoping interview, approximately ten questions, determines applicability so the operator sees the safeguards that apply rather than the full catalog: headcount and approximate device count; identity provider; cloud platforms in use; regulated data types; cyber insurance status and renewal date; who is accountable for security, which creates the first owner record; remote and BYOD posture; security tooling already in place, which determines what SHA evaluates directly versus what it attests.

Evidence quality is explicit and progressive: `unknown`, then `attested`, then `automated`. Advancing a safeguard from attested to automated is real improvement and is shown as such.

**Individual and practitioner.** Single-node deployment, target under fifteen minutes to first inventory. No client hierarchy presented. Self-attestation for process safeguards.

**Organization.** Adds OIDC to the existing identity provider on day one, location records, per-location enrollment packages, and role separation between approver, remediator, and read-only. Agent deployment works through whatever the organization already uses — Group Policy, Intune, a script, an existing RMM. SHA cannot require an RMM in order to install its own agent. The first thirty days are an explicit establishment period: complete inventory, then IG1.

**MSP and MSSP.** Onboards its own organization first. Per-client onboarding is a template: create client, create locations, run the scoping interview, issue enrollment packages, deploy. The **client template** is the critical object, carrying baseline assignment, cadence, approval policy, and report schedule, applied at client creation. Onboarding the fortieth client must not repeat the work of the first.

## Operating rhythm

For most of this audience, daily use is five minutes or nothing. These are people with other responsibilities. The product is designed around that.

| Cadence | Duration | Work |
| --- | --- | --- |
| Daily | 5 minutes, or notification only | Triage queue: new findings, canary activations, agent health failures, expiring approvals. Most days empty. Urgent items notify rather than waiting for a login |
| Weekly | 30 to 60 minutes | The core loop. Work the next-action queue, one or two safeguards. Review drift. Approve pending remediation. Assign owners to unowned findings |
| Monthly | 1 to 2 hours | Attestation review, exception expiry, program snapshot, unowned new assets |
| Quarterly | Half day | Snapshot to executive report. Re-scope for new cloud, sites, or regulated data. Implementation group advancement review. Tabletop |
| Annual | — | Insurance renewal package, full process re-attestation, framework version updates |

Incident work is interrupt-driven and follows the model already defined in the execution roadmap.

**Post-incident safeguard mapping.** After an incident closes, SHA identifies which safeguards would have prevented or detected it and proposes findings and risks from the incident record. This is the point at which an operator is most motivated to learn, and it is the strongest instructional surface in the product.

**MSP rhythm differs structurally.** The home view is a cross-client queue ordered by SLA exposure, not by client. A safeguard failing at twelve clients is one work item with twelve targets. Monthly reporting generates all client reports in a single action. The per-client program snapshot with trend is the quarterly business review content.

## Distribution

- The platform remains open source under the repository's existing Apache 2.0 license. Security software that cannot be inspected is difficult to sell to the only buyers that matter here.
- Authored guidance content is the part that is hard to replicate. The schema can be copied quickly; one hundred fifty safeguard explanations with operational consequence and rollback detail cannot.
- Guidance content is published openly. It attracts correction and establishes credibility.
- The commercial layer is operational rather than functional: hosted multi-tenant deployment, signed agent packages and publisher trust, generated report packages, higher implementation group content depth, and MSP cross-client program management.
- The free path is not a limited demo. SHA takes a single organization to essential cyber hygiene at no cost.

## Positioning

> Most organizations already own the controls they need and are running a fraction of them. SHA finds every asset, measures what your platforms are actually enforcing, tells you what to fix first and why, changes it with rollback, and keeps the evidence.

Supporting statements:

- *Windows, Linux, macOS, Entra, Workspace, and AWS ship strong security controls. SHA turns them on correctly and proves they stayed on.*
- *You inherited security and nobody gave you the order of operations. SHA supplies it.*
- *Run one security program across every client and produce the report from it.*

Copy rules: no fear framing, no invented statistics, no claim that SHA prevents breaches. State what the product does and let the specifics carry the argument. This audience is already under-resourced and skeptical of security marketing.

## Delivery tracks

**Track A — platform.** Execution roadmap Phases 1 through 7, unchanged in order and acceptance. Phase 1 completes first.

**Track B — program layer.** New Phases 8 through 13 in the execution roadmap. Depends on Track A reaching Phase 6.

**Track C — guidance and capability content.** Safeguard explanations, native capability definitions with detection and safe configuration, adversary technique references, rollback and operational impact notes, insurance questionnaire mappings, framework crosswalks. This is data, not code, with **no dependency on any platform phase**. It begins immediately and runs continuously. It is also the Advisor's deterministic fallback corpus. Content is authored under `control-packs/` under the same provenance, citation, and licensing discipline as existing packs.

An agent blocked on Track A verification defaults to Track C rather than idling or starting Track B early.

## Amendments to the execution roadmap

Applied in the same commit as this document.

1. **Scope boundary, discovery.** "Network discovery, SNMP monitoring, or infrastructure monitoring" narrows. Passive, agent-reported local-segment asset observation is in scope, because CIS Control 1 completeness is otherwise unreachable. Active scanning is in scope only behind a scope-authorization object carrying an approved address range, time window, approver, and expiry, reusing the existing approval machinery. SNMP polling and infrastructure performance monitoring remain out of scope.
2. **Scope boundary, AI.** "AI-generated or autonomous endpoint actions" remains out of scope, clarified: the Advisor is advisory and draft-only under the authority boundary above.
3. **Scope boundary, cloud.** Read and evaluation of Entra ID, Microsoft 365, Google Workspace, AWS, and Azure security configuration enters scope. Cloud configuration change is deferred beyond first release; SHA reports and recommends but does not modify cloud tenants in Phase 11.
4. **Phase 3 acceptance.** Adds CIS Control 1 and 2 completeness criteria and passive local-segment observation.
5. **Phase 6 scope.** Adds the safeguard and native capability layer above the existing control contract.
6. **New Phase 2A, inserted before Phase 3.** Provider and extension contract, which the Phase 3 collectors are the first consumers of. Phase 3 does not start before it.
7. **New cross-cutting extensibility requirements.** Declarative-first providers, provider trust rules, and the zero-change-outside-provider-content test.
8. **New Phases 8 through 13.** Guided program spine; native capability activation; risk register and program reporting; canary system and attack surface; cloud and identity posture; SHA Advisor.

## Open questions

Require a user decision before dependent phases begin. None block Phase 1 or Track C.

1. Authentication for the single-operator tier: is OIDC required, or is local authentication acceptable when there is one operator and no identity provider?
2. Agent deployment: does SHA ever build push deployment, or is it always a signed package deployed through the organization's existing tooling?
3. Gating strength: hard block on IG2 until IG1 is complete, or de-emphasis only?
4. Individual mode: a distinct interface with no client or location concepts, or the standard interface with a hierarchy of one?
5. Notification channels: email, Slack, Teams, webhook, or none in first release. This determines whether the daily tier exists at all.
6. Existing third-party tooling such as CrowdStrike, Veeam, or Intune: integration that reads state, or attestation only, in first release.
7. Whether the first commercial motion targets organizations directly or the MSP channel. The schema supports both; support burden and pricing differ.
