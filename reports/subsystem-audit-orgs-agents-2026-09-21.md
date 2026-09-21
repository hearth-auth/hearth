# Two subsystems the audit never opened

Tasks 23.10 (organisations) and 23.11 (agent identity beyond §4.19's token
paths), audit `reports/production-readiness-audit-2026-08-28.md` §9 item 3.

The audit's own scope note is the reason this pass exists: "the organisations
subsystem; the agent-identity surface (DPoP, token exchange, MCP authorisation,
approval lifecycle) beyond the token paths in §4.19" were never reached by any
piece. §4.19 read twelve findings out of the token plane and §4.20 read the
cascades; neither opened an organisation route or an approval record.

**Counts: 6 findings in organisations, 11 in agent identity. 17 total.** Five
are fixed here — four with a mutation proof, and A-4, which is a strict
tightening of an error arm that this harness cannot fault-inject, honestly
labelled as unproven. Twelve are reported. The audit's counts
have been understated before, so these were counted by enumerating the surface
first — every engine entry point, every console route, every storage key family,
every lifecycle transition — and only then reading.

## How to read this

Organisations are reachable through **two** doors, not three. There is no REST
route for any organisation operation (the SDK methods addressing
`/admin/orgs/{id}/members` were removed because every call 404'd). What exists
is:

| Door | Surface |
|---|---|
| Admin console | 18 routes under `/admin/realms/{realm}/organizations/…` (`src/protocol/web/mod.rs:1459-1531`) |
| gRPC | org CRUD + `list_additional_roles` (`src/protocol/grpc/identity.rs`, `rbac_admin.rs:1032`) |
| Engine / embedded | 17 `IdentityEngine` methods + 3 `RbacEngine` org-role methods |

Agent identity is the opposite shape: a large engine, a small and **incomplete**
protocol edge. That asymmetry is where most of this section's findings live.

---

## Organisations

### O-1 — Org extra roles survive both member removal and org deletion, and are silently restored (MEDIUM)

`rba:org_role:{realm}:{org}:{user}:{role}` rows are written by
`EmbeddedRbacEngine::add_additional_role` (`src/rbac/engine.rs:744`) and read
during claim resolution by `resolve_full` (`src/rbac/resolve.rs:248`), which
expands every additional role it finds for `(realm, org, user)` **without ever
checking that the user is still a member of that org** — the `Resolver` trait
has no membership method, and it cannot have one: rbac may not call identity.

Neither cleanup path removes them:

* `remove_member` (`src/identity/engine/mod.rs:12057-12116`) deletes the forward
  and reverse membership index and nothing else.
* `delete_organization` (`:11751-11914`) has a six-step cascade — memberships,
  invitations, slug index, SCIM external-ID mapping, owned agents, primary
  record — and `rba:org_role:` appears in none of them.

**Failure scenario.** A contractor is an org `Owner` and has been granted the
extra role `billing-admin` in that org. They are offboarded: the admin removes
them from the organisation. Months later they are re-added as a plain `Member`
for a different engagement. The `rba:org_role:` row was never deleted, so the
first token minted with that `org_id` context expands `billing-admin` again. The
admin who re-added them saw only "Member" in the console.

This is the same class as audit §4.20#4 ("direct permission grants, org extra
roles and every group-subject RBAC row survive deletion, and are silently
reactivated when the same `UserId` is re-imported") — but §4.20 scoped it to
*realm* deletion. It is also true of ordinary member removal, which is an
everyday operation rather than a rare one.

**Not fixed here:** the cascade belongs in `remove_member` and
`delete_organization`, both in `src/identity/engine/mod.rs`, which another agent
owns this session. The exact change: in both functions, after the membership
delete, scan `keys::org_extra_role_scan_prefix(realm_id, org_id, user_id)`
(re-exported from `src/rbac/keys.rs:287`) and delete each row; in
`delete_organization`, do it per member inside the existing members loop, before
the primary record delete. `RbacEngine` needs a `purge_org_roles_for_user`
method to keep the layer boundary — identity may call rbac.

### O-2 — Suspending an organisation is not a kill switch (MEDIUM)

`OrganizationStatus::Suspended` is consulted in exactly **two** places in the
whole engine: `add_member` (`src/identity/engine/mod.rs:11994`) and
`create_invitation` (`:12327`). Nothing else reads it.

In particular the token-issuance path does not. `resolve_permissions` is called
with `org_id` at `src/identity/engine/oauth.rs:2859` and `:2983` and at
`src/protocol/http/oauth.rs:2437`; none of those looks the organisation up.
`accept_invitation` (`:12418`) does not check org status either — it is saved
only because the `add_member` it delegates to does.

**Failure scenario.** A tenant organisation is compromised. The operator
suspends it in the console. Every existing member keeps authenticating, keeps
receiving org-scoped roles and permissions in fresh access tokens, and keeps
using the platform. The only two things that stop are adding a new member and
sending a new invitation. Suspension reads as a freeze and is a hiring freeze.

Contrast realm suspension, which *is* enforced on the token path
(`require_active_realm`, and `realm_status_cache` on validation). Organisations
have no equivalent.

**Not fixed here:** the check belongs next to the `org_id` reads in
`src/identity/engine/oauth.rs` and `src/identity/engine/mod.rs`, both owned by
other agents this session. Exact change: in `resolve_permissions`' identity-side
callers, load the org when `org_id.is_some()` and refuse issuance (or drop the
org context) when its status is not `Active`.

### O-3 — The console's org status change was recorded without an actor (MEDIUM) — **FIXED**

`admin_org_status_toggle` ends its success arm with
`audit_org_event(&state, &session, …, "status_change")`
(`src/protocol/web/admin/orgs.rs:1697`). That helper's `match op` knew only
`"create" | "update" | "delete"` and ended in a silent `_ => return`
(`:2091`), so the call appended nothing at all.

The engine's own `update_organization` still wrote an `OrgUpdated` event, but
with `None` as its audit context — **unattributed**. So the record said an
organisation changed and did not say who changed it, while the console call site
read as though it had recorded the acting administrator. Every other org
mutation in the console (create, update, delete, bulk delete) does append the
attributed `via: ui` event; the status toggle was the one that silently did not.

**Fixed.** `audit_org_event_with` maps `"status_change"` to `OrgUpdated`,
carries the new status in metadata, and logs an unmapped `op` instead of
dropping it, so the same mistake cannot be silent again.

### O-4 — The entire invitation lifecycle is unaudited (MEDIUM)

`create_invitation`, `accept_invitation` and `revoke_invitation`
(`src/identity/engine/mod.rs:12316-12550`) contain **zero** `record_audit`
calls, and there is no `Invitation*` variant in `AuditAction`
(`src/audit/types.rs`) for them to use.

This is the path by which an arbitrary external email address becomes a member
of an organisation with a chosen role — and, when that email has no account,
`accept_invitation` **auto-creates the user** (`:12476-12488`). The only traces
left are a `GroupMemberAdded` event from the `add_member` it delegates to, and a
`UserCreated` event. Nothing records who issued the invitation, to which
address, for which role, or that an invitation was later revoked.

**Not fixed here:** needs three new `AuditAction` variants
(`InvitationCreated`, `InvitationAccepted`, `InvitationRevoked`) threaded
through `as_str`/`FromStr`/the category tables in `src/audit/types.rs`, plus the
three `record_audit` calls in `src/identity/engine/mod.rs` (owned elsewhere).

### O-5 — `revoke_invitation` leaves the token index behind (LOW)

`revoke_invitation` (`:12511`) marks the record `Revoked` and deletes the
`orgi:orgemail:` dedup key, but not the `orgi:token:{sha256}` index.
`delete_organization` does delete it (`:11837`), so the two disagree about what
an invitation is made of. `accept_invitation` fails closed — it resolves the
token, then re-checks `status() != Pending` — so this is residue, not a bypass:
the hash of a live invitation token outlives the invitation for ever, with no
expiry sweep over `orgi:` keys in `src/identity/cleanup.rs`.

### O-6 — System-realm and archival guards are applied asymmetrically across the org surface (LOW)

| Function | `require_active_realm` | `is_system_realm` |
|---|---|---|
| `create_organization` | yes | yes |
| `update_organization` | yes | yes |
| `delete_organization` | yes | **no** |
| `add_member` / `remove_member` / `update_member_role` | yes | **no** |
| `create_invitation` / `accept_invitation` / `revoke_invitation` | yes | **no** |
| `import_organization` | **no** | **no** |

Not currently reachable as a privilege escalation — `create_organization`
refuses the system realm, so no org should exist there — but `import_organization`
(`:11943`) is the hole in that argument: it performs no validation of any kind
(no slug uniqueness, no cooldown check, no attribute validation, no realm-status
check, no system-realm check) and writes the primary record plus the slug index
directly. A realm import carrying an organisation whose target realm is the
system realm would create one, after which the six unguarded mutators apply.

---

## Agent identity

### A-1 — There is no way to revoke or suspend an agent over any protocol (HIGH)

`revoke_agent`, `suspend_agent` and `reactivate_agent` exist on the engine
(`src/identity/engine/mod.rs:13727` suspend, `:13767` reactivate, `:13807` revoke) and are the states that
four separate controls check. Their callers, in the entire `src/` tree, are:

* `verify_agent_api_key` calling `suspend_agent` on rate-limit auto-suspension
  (`:14048`);
* nothing else.

No REST route (`src/protocol/http/agents.rs:36-51` registers list/create/get/
patch/delete plus three credential routes), no gRPC RPC
(`src/protocol/grpc/identity.rs` exposes only `revoke_agent_credential`), no
admin console page — `grep -n "agents" src/protocol/web/mod.rs` returns no route
at all. `update_agent` does not accept a `status` field
(`src/identity/engine/mod.rs:13504-13578`).

AGENT_AUTH.md §1.2 makes the state machine normative: "Agent status transitions
**MUST** be `Active → Suspended → Active` (reversible) and `Active|Suspended →
Revoked` (terminal)." §1.3's endpoint table lists five CRUD operations and no
revoke. The spec and the code jointly omit the operator's kill switch.

**Failure scenario.** An agent's API key is found in a public repository. The
operator's options are: revoke that one credential (which does not touch tokens
already issued, and does not stop the agent from being issued more), or DELETE
the agent (see A-2). The one state that the AAT path, the transaction-token path
(`src/identity/engine/txn.rs:43`), the SPIFFE path (`spiffe.rs:39`) and token
exchange (`mod.rs:15624`) all honour cannot be entered.

**Recommended:** `POST /v1/agents/{id}/revoke`, `POST /v1/agents/{id}/suspend`
and `POST /v1/agents/{id}/reactivate` in `src/protocol/http/agents.rs`, gated on
`hearth.agents.admin` like every other handler there, plus the matching rows in
AGENT_AUTH.md §1.3. Not done here because it adds public API surface and the
spec table needs the same edit; it should be one reviewed change, not a
by-product of an audit.

### A-2 — `delete_agent` reports a completed cascade it did not perform (HIGH)

AGENT_AUTH.md §1.2: "Agent deletion **MUST** cascade: revoke all active tokens,
remove all RBAC role assignments where the agent is the subject, remove the
agent from any groups, delete all credentials, and emit an audit event."

`delete_agent` (`src/identity/engine/mod.rs:13581-13636`) does four of those and
then returns `Ok(())`:

* credentials — deleted, errors propagated. Correct.
* RBAC assignments and groups — `let _ = self.rbac.purge_user_from_realm(...)`
  at `:13610`. **The `Result` is discarded.** A failed purge produces a `204 No
  Content` and a surviving set of role assignments under a UUID whose primary
  record is gone. This is the seventh-and-eighth instance of the shape §4.x has
  found repeatedly, and the one-line `let _ =` is the whole defect.
* audit event — emitted, `?`-propagated.
* **revoke all active tokens — not done at all.** There is no token, AAT,
  delegation-grant or session revocation anywhere in the function.

Note also the ordering: the primary record is deleted at `:13620` and the owner
index at `:13623` with `let _ =` ("best-effort; primary is gone"). That is the
exact anti-pattern audit §4.20#8 named — deleting the primary record first makes
the rest of the cascade unaddressable.

**Not fixed here** (`src/identity/engine/mod.rs` is owned elsewhere this
session). Exact change: propagate the `purge_user_from_realm` error with `?`;
move the primary-record delete to the end; and either revoke outstanding tokens
or amend §1.2 to stop claiming it. With A-6 below in place, the revocation half
is largely covered for AATs and approvals.

### A-3 — A revoked agent's AATs stayed valid, and kept deriving children (HIGH) — **FIXED**

`issue_aat_inner` requires the agent to be `Active`
(`src/identity/engine/aat.rs:38`). `parse_and_validate_aat` — the single funnel
used by **both** `validate_aat` and `derive_aat_inner` (`:93`) — did not look
the agent up at all.

**Failure scenario.** An agent is revoked at 12:00. An AAT it obtained at 11:59
carries a one-hour expiry. Until 12:59 that token validates, and each call to
`derive_aat` mints a fresh child from it (child TTL is clamped to the parent's
remaining life, so the chain dies with the parent, but five hops of live tokens
can be produced from a revoked agent's credential). Suspension is worse than
revocation here: the abuse monitor applies `Suspended` automatically on
credential stuffing (`:14048`), and `Suspended` was invisible to every AAT path.

**Fixed.** `require_active_subject_agent` resolves the AAT's `agt_{uuid}`
subject and refuses anything that is not an `Active` agent in this realm
(`AgentNotFound` for an unknown subject, `AgentRevoked` for any other status).
Reactivation restores outstanding AATs, which is the reversible half of the
spec's state machine.

### A-4 — The AAT revocation blocklist failed open on a storage error (MEDIUM) — **FIXED**

`for jti in &claims.aat_chain { … if let Ok(Some(_)) = self.storage.get(…) }`
(`src/identity/engine/aat.rs:186`, pre-fix). A storage `Err` took the same
branch as "absent" and the token was accepted. This is the cache-miss-as-a-
decision shape from `reports/follower-bypass-enumeration-2026-09-21.md`, one
layer down: an I/O fault, not a cold cache, and the answer was still "allow".

**Fixed** in the same edit: the read is `?`-propagated, so a failed revocation
lookup fails the validation.

**No dedicated test.** Proving it needs fault injection into `StorageEngine`,
which the integration harness does not offer; `FaultFs` sits under the
filesystem, not the engine. It is a strict tightening of an error arm with no
behavioural change on the success path, and the three A-3 tests exercise the
rewritten loop. Stated here rather than claimed as proven.

### A-5 — Approving a queued request minted a live capability token for a revoked agent (HIGH) — **FIXED**

Neither `create_approval_request_inner` nor `approve_approval_request_inner`
(`src/identity/engine/approval.rs:30`, `:140`) looked the agent up. Every other
Phase-D mint path does: AAT (`aat.rs:38`), transaction tokens (`txn.rs:43`,
`:48`), SPIFFE SVID mapping (`spiffe.rs:39`).

**Failure scenario.** This is the one place in the agent surface where a delay
between request and decision is *by design* — a human-in-the-loop queue. An
agent requests approval to invoke `delete_file` at 09:00. At 09:10 the agent is
revoked (or auto-suspended by the abuse monitor — which is exactly what would
happen if the same credential were being abused). At 09:30 an operator works
through the queue and approves. A capability token is minted, signed by the
realm key, carrying `tool.delete_file.invoke`, valid for five minutes, for an
agent the platform considers dead. `validate_capability_token_inner` (`:574`)
does not check agent status either, so nothing downstream catches it.

**Fixed.** `require_active_agent` runs at request creation and again at approval
time. The approval-time check runs **before** the status transition, so a
refused approval leaves the request `Pending` rather than burning it.

### A-6 — `validate_capability_token_inner` does not check agent status either (MEDIUM)

`src/identity/engine/approval.rs:574-664` verifies signature, `token_type`,
`aud`, expiry, tool/action match, caller binding and single-use JTI. It never
resolves the `sub` to an agent. A capability token minted at 09:00 and presented
at 09:04 by an agent revoked at 09:02 is honoured.

A-5 closes the window at mint time; this is the five-minute tail. Left unfixed
deliberately: `validate_capability_token` is on the tool-invocation request path
and adding a storage read there is a performance decision, not an audit one.
Recommended change if taken: call the same `require_active_agent` immediately
after `let agent_id = AgentId::new(agent_uuid);` and before the
`put_if_absent` JTI burn, so a refused call does not spend the token.

### A-7 — The approval webhook outbox is never flushed: at-most-once, and it leaks rows for ever (HIGH)

AGENT_AUTH.md's status banner claims for M3: "durable at-least-once approval
webhook notifications."

`create_approval_request_inner` writes `appreq:outbox:{request_id}` in the same
atomic `put_batch` as the record (`approval.rs:76-90`) — the durable half is
real. `notify_approval_webhook_inner` deletes that row on delivery success and,
on failure, logs and leaves it: "Outbox entry stays; background scanner will
retry" (`:501-505`).

`flush_approval_webhook_outbox_inner` (`:514`) is the scanner. Its doc comment
says "Called by the startup recovery scan and the periodic background task."
It carries `#[allow(dead_code)]`. **It has zero callers** —
`grep -rn "flush_approval_webhook_outbox" src/ tests/` returns only its own
definition. Neither a startup scan nor a periodic task exists.

Two consequences:

1. Delivery is **at-most-once**, not at-least-once. A webhook endpoint that is
   down when an approval is requested never learns about that approval. For a
   human-in-the-loop control, the notification silently not arriving is the
   failure mode that matters.
2. The outbox row is never deleted on any path but immediate success — not by
   approve, not by deny, not by expiry, and not by any sweeper (there is no
   `appreq:` prefix in `src/identity/cleanup.rs`). Every approval request whose
   webhook delivery failed leaves one permanent row per realm.

And if the scanner *were* wired, it would be wrong as written: it re-delivers
the original payload — `approve_url`, `deny_url`, the pending framing — for
requests that have since been Approved, Denied or expired, because it never
reads `request.status`. It would resend a live "please approve" notification for
a decision already taken, on every scan, for ever.

**Not fixed here.** A fix is three parts and only the middle one is contained:
(a) call the flush from the startup recovery scan and a periodic task — both in
`src/identity/engine/mod.rs` / the serve bootstrap, owned elsewhere; (b) in
`flush_approval_webhook_outbox_inner`, skip and delete the outbox row when
`request.status != Pending` or `request.expires_at <= now`; (c) bound retries so
a permanently dead endpoint does not pin the row. Part (b) alone is untestable
from `tests/` today because the function is `pub(super)` with no trait method,
which is itself a symptom of it never having been wired.

### A-8 — Token exchange honours `Revoked` but not `Suspended` (MEDIUM)

`agent_sub_is_revoked` (`src/identity/engine/mod.rs:16074`) matches only
`AgentStatus::Revoked`, and it is the sole status gate on the RFC 8693 path
(`:15624` for the actor, `:15632` for every prior delegator in the chain).

`Suspended` is the state the abuse monitor applies **automatically** when an
agent trips the credential rate limit (`:14048`). So the automatic response to
agent credential abuse does not stop that agent from performing token exchange
or from continuing to delegate. Every other Phase-D path treats non-`Active` as
refused; this one does not.

Related, in the same helper pair: `resolve_agent_max_depth` (`:16049`) ends in
`self.get_agent(realm_id, &agent_id).ok()??`, so a **storage error** resolves to
`None`, and `None` means "not a registered agent → the loosest global ceiling
applies". The doc comment on `agent_sub_is_revoked` records that this exact
fail-open was the original G3 bug; the error arm that caused it is still there.

**Not fixed here** (`src/identity/engine/mod.rs`). Exact change: widen
`agent_sub_is_revoked` to `!matches!(status, Active)` and rename it, and
propagate rather than swallow the storage error in `resolve_agent_max_depth`.

### A-9 — `GET /v1/agents` implemented none of §1.3's list contract (MEDIUM) — **FIXED**

AGENT_AUTH.md §1.3: "List endpoints **MUST** support filtering by `owner_id`,
`status`, and capability. Pagination **MUST** follow the same cursor-based
pattern used by existing list endpoints."

The handler took `State` and `HeaderMap` and nothing else, then called
`identity.list_agents(&realm_id, &ListAgentsQuery::default(), None, 100)`
(`src/protocol/http/agents.rs:298-312`, pre-fix). All three filters are
implemented in the engine and were unreachable; the cursor was hard-coded to
`None` and the limit to 100, so **a realm holding more than 100 agents could not
enumerate past its first page** — including to find the agent it wanted to
delete.

**Fixed.** A `ListAgentsParams` `Query` extractor supplies `owner_type`/
`owner_id`, `status`, `capability`, `cursor` and `limit`. An unparseable
`status` or `owner_id` answers `422` rather than silently widening to every
agent in the realm — the fail-open shape this repo has been bitten by.

### A-10 — `src/identity/mcp.rs` is a module with no production callers for its validator (MEDIUM)

AGENT_AUTH.md §2.6: "Scope strings **MUST** follow the pattern
`{namespace}:{category}:{action}`." `validate_mcp_scope_string`
(`src/identity/mcp.rs:29`) implements exactly that rule.

`grep -rn validate_mcp_scope_string src/` returns the definition and nothing
else. Its only callers are `tests/token_exchange.rs`. The same is true of
`is_mcp_scope` (`:60`). `MCP_STANDARD_SCOPES` and all five `MCP_SCOPE_*`
constants (`:6-19`) have **zero** references anywhere — not even in tests.

Only `intersect_three` is wired, at `src/identity/engine/mod.rs:15667`. So the
MUST-level format rule for MCP scopes is enforced nowhere: a scope string of any
shape reaches the intersection logic, and `intersect_scopes` splits on
whitespace and compares string equality, which happily carries `mcp:tools` or
`mcp:tools:invoke:extra` through to a minted token's `scope` claim.

**Not fixed here:** the enforcement point is DCR / the token-exchange `scope`
parameter, both in `src/identity/engine/mod.rs` and
`src/protocol/http/oauth.rs`, owned elsewhere. Exact change: validate every
`mcp:`-prefixed requested scope with `validate_mcp_scope_string` at the token
endpoint and at protected-resource registration, rejecting with
`invalid_scope`.

### A-11 — `tool_invocation.rs` burns the DPoP proof JTI before the key-binding check (MEDIUM)

`src/protocol/http/tool_invocation.rs:223-233`:

```
    state.identity.check_and_record_dpop_jti(realm_id, &validated.jti, now_secs)?;

    if validated.jkt != expected_jkt {
        return Err(... DPopBindingMismatch ...);
    }
```

`src/protocol/http/auth.rs` gets this order right: the `jkt != expected_jkt`
check is at `:1053-1059`, the JTI record at `:1063-1066`.

**Failure scenario.** The JTI store is durable and realm-wide
(`check_and_record_dpop_jti`, `src/identity/engine/mod.rs:15194`), so a spent
JTI is spent for every endpoint. An attacker who observes one DPoP proof — a
proxy log, a mirrored request — can replay it at `/v1/tools/invoke` with any
bearer token bound to a different key. The proof fails the binding check and is
rejected, but its JTI is already burned, so the rightful holder's own use of
that proof now returns `DPopProofReplay`. This repo already reasoned this
through once, for capability tokens, and wrote it down at
`src/identity/engine/approval.rs:629-635` ("G2: this check MUST run before the
JTI is burned. Spending the JTI on a failed caller-binding lets any actor grief
the legitimate caller"). The same argument applies verbatim here and the order
is inverted.

**Not fixed here:** the change is two statements swapped in
`src/protocol/http/tool_invocation.rs`, but proving it non-vacuously needs a
DPoP-bound tool-invocation integration test that replays one proof across two
bearer tokens, and there is no existing fixture for that. It is the highest-
value remaining fix in this section and it is small.

---

## Already covered — do not re-find these

| Property | Cover |
|---|---|
| Every org console mutation has `RequireAdmin` + `verify_csrf_form_field` | Verified all 11 form handlers in `src/protocol/web/admin/orgs.rs`; tasks 11.1 / 21.2 closed this class |
| Every `/v1/agents` and `/v1/approval-requests` handler gates on `hearth.agents.admin` | Verified all 9 + 5 handlers; `agent_card` was the §4.1#9 gap and is now gated (`agents.rs:165`) |
| Realm archival freezes every org and agent mutation | `require_active_realm` present on 9 of the 10 org mutators (`import_organization` excepted — see O-6) and all 6 agent mutators (audit §4.20#5, already closed) |
| AAT scope and tool narrowing, constraint type confusion | `validate_tools_subset` + `validate_constraint_type` (`aat.rs:226`, `:218`); covered by `tests/aat.rs` and `tests/aat_property.rs` |
| Capability-token single-use and caller binding | `put_if_absent` fold plus the G2 ordering (`approval.rs:629-659`); HEA-1757 and M5 |
| DPoP proof replay is durable, not in-memory | `check_and_record_dpop_jti` writes `dpop:jti:` through storage; all four proof call sites reach it |
| DPoP `alg`/`kty` confusion, `ath`, `htu` normalisation, private-key-in-JWK | `validate_dpop_proof` (`src/identity/dpop.rs:298-425`); §4.2#5 closed |
| Approval CAS and concurrent approve/deny | `approval_request_lock` on both transitions (`approval.rs:147`, `:233`) |
| Org slug TOCTOU, post-delete slug cooldown, per-realm org quota | `org_write_lock` + `StoredSlugReservation` + `check_resource_quota` (A-5/A-24/A-28) |
| DPoP JKT blocklist staleness on followers | `reports/follower-bypass-enumeration-2026-09-21.md` B-3 |

## Per-design, NOT defects

Recording these so a later sweep does not "fix" them.

| Observation | Why it is correct |
|---|---|
| `DPopJtiCache` / `DPopProcessor::check_and_insert_jti` (`src/identity/dpop.rs:476-556`) have no production callers | Superseded by the **durable** `check_and_record_dpop_jti`. The in-memory cache would be strictly weaker (per-node, lost on restart). Dead code, not a gap — but it should be deleted so a future reader does not wire the weaker one back in. |
| `resolve_full` expands org-scoped assignments without a membership check | The `Resolver` trait cannot call identity (layer rule: identity → rbac, never the reverse). Membership must be enforced by whoever supplies `org_id`, and for org-scoped *assignments* it is: an assignment scoped to an org only exists because someone granted it there. O-1 is about the extra-role rows surviving the grant's own lifecycle, not about the resolver. |
| `/me/permissions?org_id=` accepts any org UUID with no membership check (`src/protocol/http/oauth.rs:2426`) | It returns only what the caller was actually granted in that org. For a non-member that is the empty set. It is a read of one's own permissions, not a grant. |
| `import_organization` skips slug uniqueness, cooldown and attribute validation | Realm import must reproduce a snapshot faithfully, including records that predate a validation rule. The system-realm hole in O-6 is the part worth closing, not the validation skips. |
| `agent_id` collides with `UserId` in the RBAC subject namespace, by UUID | Deliberate (`mod.rs:13607`, "Agents share the RBAC subject namespace with users via the same UUID"). Both are v4 UUIDs; a collision is not a practical concern. |
| Capability tokens carry the **global** `config.token.issuer`, while AATs carry the realm's OIDC issuer | Capability tokens are verified only by `validate_capability_token_inner`, against the realm key resolved from the `realm_id` argument, so `iss` is not load-bearing for them. Worth harmonising for legibility; not a boundary. |
| `admin_org_status_toggle` accepts only `Active`/`Suspended` while the edit form also accepts `Archived` | Two different affordances (a toggle vs. a full edit), not an asymmetry in enforcement. |
| Approval webhook payloads advertise `approve_url`/`deny_url` that require an admin bearer token | The URLs are a pointer for the receiving system, not a one-click action link. A capability-bearing magic link would be a larger design decision. |

## Spec-banner accuracy

AGENT_AUTH.md's banner is mostly honest — the four milestones' features do exist
in the files it names. Two claims in it do not survive contact with the code:

* **"durable at-least-once approval webhook notifications" (M3)** — false. See
  A-7: durable write, no retry, no scanner, no caller.
* **"MCP authorization server … RFC 9728" (M2)**, read together with §2.6's MUST
  on scope format — the scope validator exists and is unwired. See A-10.

And §1.3's endpoint table is incomplete against §1.2's normative state machine:
five CRUD rows, no revoke/suspend/reactivate. See A-1.
