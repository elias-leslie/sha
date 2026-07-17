# SHA security and platform decisions

Status: accepted foundation for the IR and compliance roadmap. Revisit only through a documented replacement decision.

## Decisions

### Canonical endpoint runtime

The Go agent is the only long-term endpoint runtime. Generated Python and PowerShell reporters are compatibility shims: keep them working during migration, add no new feature breadth to them, and remove them after supported endpoints have moved.

The agent exposes versioned, typed capabilities. It does not accept a server-supplied executable string as a typed action. The later command console and terminal are separate, strongly authorized capabilities with their own limits and audit contracts.

### Ownership hierarchy

The durable hierarchy is Global → Client → Location → Endpoint. Client and Location are relational entities with immutable identifiers. Existing tenant/site strings are migration inputs, not a parallel scope model. Tags, saved views, groups, jobs, reports, incidents, evidence, and authorization all reference this hierarchy.

### Enrollment and device identity

Enrollment uses a short-lived, revocable, scope-bound bootstrap token with expiry and use limits. A successful redemption atomically exchanges it for a unique device credential. The server stores only a verifier or hash for bearer credentials. An endpoint credential is bound to one endpoint and cannot act for another endpoint.

Personalized packages may embed only the bootstrap token and signed scope metadata. Generic packages accept the same token by command-line flag and safer file or standard-input sources. Neither package contains an operator credential or permanent device credential.

### Operator identity and authorization

Production browser access uses a provider-neutral OIDC session. The frontend forwards caller-bound authority; it never injects a shared operator token for an unauthenticated caller. Backend principals contain a stable subject, display snapshot, authentication method, role, and scope. Audit actors always come from the authenticated principal.

`development_open` is limited to local development. Production uses `protected`, fails closed when authentication is incomplete, and does not silently fall back to open access.

### Transport and package trust

Production endpoint and browser traffic requires HTTPS. TLS 1.3 is preferred and TLS 1.2 is the minimum. Agents must validate hostname, full chain, validity, and either system roots or an explicitly supplied private CA. Production has no insecure verification bypass. Credentials are never forwarded across an origin change or HTTPS downgrade. Phase 0 relies on operating-system trust stores; explicit per-agent private-CA configuration remains installer work.

Release packages and personalized manifests are independently signed. A digest from the same unauthenticated response is integrity metadata, not publisher authentication. Signing keys stay outside the web runtime and have documented rotation and revocation.

### Execution and delivery

All current and future work uses one queue lineage. A work item has an immutable request, idempotency key, target, authorization reference, explicit state, and one or more attempts. Delivery uses atomic claims, opaque lease credentials, expiry, and conditional result acceptance. A late or stale attempt cannot overwrite a newer authoritative result.

Agents persist a completed result before reporting it and retry that exact result after acknowledgement loss. Mutations must declare retry safety, verification, and rollback behavior; an unsafe or unknown mutation is not silently executed again.

### Inventory

Inventory uses normalized current projections plus bounded change events. Each category records collector version, collection time, completeness, error state, and freshness. Volatile snapshots such as processes and connections have shorter retention than stable hardware or software state. SHA does not become an unbounded event lake.

### Retention and evidence

Retention is policy-driven by data class. Current device state, inventory changes, action/audit metadata, output, and evidence have separate quotas and lifetimes. Incident-pinned evidence is protected from ordinary expiry. Retention deletion is asynchronous, authorized, and audited.

Large evidence lives in bounded object storage; the database stores identity, endpoint, client/location, incident, action version, principal, timestamps, sizes, hashes, content type, retention, and access records. Evidence access is authorized by scope and purpose, not possession of an object identifier.

### Runtime verification

Linux and Windows behavior must be proven on clean or snapshot-restored Proxmox VMs before the relevant slice is accepted. Evidence records OS version, package hash, agent version, VM identity, and time. PostgreSQL is the production schema/concurrency reference. macOS remains build- and contract-verified only until restored to runtime scope.

## Threat model

### Protected assets

- operator sessions, roles, client/location scope, and audit identity;
- enrollment tokens, device credentials, package signing keys, and private CA material;
- endpoint inventory, action output, terminal transcripts, and collected evidence;
- action authorization, target snapshots, leases, results, rollback artifacts, and audit history;
- tenant boundaries and the availability of endpoints and the control plane.

### Trust boundaries and required controls

| Boundary | Primary threats | Required controls |
| --- | --- | --- |
| Browser → frontend | unauthenticated operator access, CSRF, session theft, trust-header spoofing | OIDC session, secure cookies, CSRF protection, recent-auth gates, stripped trust headers, no ambient operator token |
| Frontend → API | authority upgrade, confused deputy, ID enumeration | caller-bound principal, route permission checks, scope predicates on every query, fail-closed production mode |
| Package download | token disclosure, cache leakage, package substitution | authenticated audited download, private/no-store response, no body preview, short-lived token, signed manifest/package |
| Enrollment → API | replay, scope tampering, brute force, duplicate endpoint | hashed opaque token, expiry/use count/revocation, atomic redemption, signed scope binding, rate limit, idempotent identity policy |
| Endpoint → API | device impersonation, cross-device claim/upload, credential replay | unique endpoint credential, endpoint binding, rotation/revocation, TLS, protocol version, request limits |
| Queue → endpoint | duplicate mutation, lease theft, stale completion, unsafe retry | atomic claim, opaque hashed lease, attempt identity, expiry, conditional result, durable result outbox, retry policy |
| Action executor → OS | injection, privilege abuse, resource exhaustion, rollback loss | typed parameters, minimum privilege, native APIs where practical, command allowlists, time/output caps, pre-state, verification, rollback |
| Client/location boundary | horizontal reads/writes, aggregate leaks, cross-scope exports | relational ownership, deny-by-default scope queries, authorization at lookup and export, negative isolation tests |
| Evidence → storage | path traversal, oversized upload, malicious content, unauthorized retrieval, deletion | server-assigned object IDs, type/size/hash checks, quotas, scoped access, access audit, retention pins, isolated rendering |
| Scheduler/job service | target drift, schedule privilege persistence, retry storms | immutable action version, target snapshot, authorization recheck, expiry, concurrency/cost limits, cancellation, bounded retry |
| Terminal → endpoint | session hijack, scope/privilege escape, secret exposure, incomplete transcript | dedicated permission, recent auth, endpoint-bound short TTL, idle timeout, byte/process limits, recorded I/O, revocation kill |
| Control plane → dependencies | plaintext internal traffic, secret leakage, partial failure | TLS across trust boundaries, managed secrets, least-privilege DB/object credentials, health checks, backup/restore and failure tests |

### Abuse cases that must remain in the test suite

- unauthenticated and read-only callers attempt operator mutations through the frontend;
- callers submit another person's audit actor or forged external-auth headers;
- two workers claim one mutation, a lease expires, and the old worker reports late;
- result acknowledgement is lost and an agent restarts;
- one device credential claims, uploads, or reports for another endpoint;
- one-use, expired, revoked, or wrong-scope enrollment tokens are replayed concurrently;
- a tokenized package is cached, previewed, logged, or downloaded outside authorization;
- an agent receives HTTP, an untrusted or wrong-host certificate, an incomplete chain, a cross-origin redirect, or an HTTPS downgrade;
- a scoped user enumerates another client's endpoint, job, incident, evidence, report, or audit identifiers;
- output/evidence exceeds quotas or attempts traversal, executable rendering, or content-type confusion;
- a schedule outlives the creator's permission or resolves targets outside the approved preview;
- a terminal reconnects after expiry, revocation, endpoint change, or authorization loss.

## Current implementation boundary

Phase 0 provides explicit local/protected auth modes, exclusive operator/read-only/agent route classes, a caller-bound frontend proxy, principal-derived actor attribution, canonical control IDs, Alembic migrations, and leased current response actions. Compatibility artifact downloads are private/no-store and not previewed, but they still embed one shared agent token and are not signed packages. Linux and Windows privileged behavior have fresh Proxmox evidence; macOS is build/contract only. Phase 0 does not yet provide OIDC, relational clients/locations, unique device credentials, signed packages, production enrollment, the unified job model, evidence storage, scheduling, or terminal access. Those boundaries must not be represented as complete before their phase acceptance tests pass.
