# Three subsystems the audit never opened

Tasks 23.8, 23.9 and 23.12 (audit 2026-08-28 §7.3 "Never examined", read against
what §4.6 covered for LDAP and what §4.2 / §4.19 reached for gRPC).

§7.3 says it plainly: *"Unexamined surface area in an identity product is itself
a finding."* This is the sweep of the three subsystems it names — LDAP beyond
§4.6, the gRPC management API beyond `Decide` and the admin RPCs, and the email
transports beyond the config and recovery paths.

**Fourteen findings. Nine fixed in this pass, five reported.** Two of the audit's
own counts were wrong in the usual direction: the `truncate_body` panic is at
**six** call sites, not the four in the email subsystem; and the hardened-egress
asymmetry covers **seven** blocking HTTP egress paths, of which **five** are
configured and **two** are not.

## How to read this

Three shapes account for eleven of the fourteen:

| Shape | Where it showed up |
|---|---|
| **A sibling path validates and this one does not** | gRPC `DeviceAuthorize` vs `POST /device_authorization`; email/SMS `UreqTransport` vs every other `ureq` egress site; one `reset_url` log site vs the other |
| **A claim the code does not implement** | `build_router`'s "rate-limit interceptor is applied"; `DeviceAuthorizationRequest.client_secret`'s own proto comment; `DeltaSyncResult.skipped`'s doc; `docs/STATUS.md` LDAP row; the LDAP module doc's injection claim |
| **Reports success it never achieved** | The org invite flash (twice); `delta_sync` advancing its checkpoint past entries it silently dropped |

---

## LDAP (task 23.8) — 5 findings

§4.6 looked at federation, SCIM, LDAP and webhooks together and found nothing in
LDAP. Reading the module end to end explains why: **there is nothing to reach.**

### L-1 — the whole connector is unreachable from a running server (reported)

`src/identity/ldap/` is 1,313 lines implementing user search, password-bind
authentication, attribute mapping, `modifyTimestamp` and `uSNChanged` delta sync
and LDAPS enforcement. Outside the module, the *only* reference anywhere in
`src/` is the module declaration at `src/identity/mod.rs:22`.

- No `ldap:` block in `hearth.example.yaml`; `LdapConfig` is not reachable from
  `src/config/`.
- No admin route, no gRPC RPC, no CLI subcommand.
- Zero callers of `EmbeddedLdapConnector::new`, `search_users`,
  `authenticate_user` or `delta_sync` outside `src/identity/ldap/` and
  `tests/ldap_federation.rs`.

The consequence is not a vulnerability — it is that every property in this
section is **latent**, and that `ldap3` plus its rustls/ring stack is linked
into every production binary to serve code no deployment can call.

**Scope for a follow-up.** `docs/specs/READINESS_AUDIT_1_0.md:168-171` already
names the four wiring steps and estimates 1-2 days. Nothing here changes that
estimate; this report only asks that findings L-2..L-5 be closed *before* the
wiring lands, because wiring turns each of them from latent into live.

### L-2 — `docs/STATUS.md` claimed LDAP was shipped (**fixed**)

`docs/STATUS.md:34` read `| LDAP / Active Directory federation | ✅ Shipped |`.
Two other documents were already honest — `docs/guides/federation.md:528` and
`:552` say "Connector implemented, wiring in progress … Not yet exposed via
config or API", and `READINESS_AUDIT_1_0.md:156` says the same. STATUS.md is the
document an evaluator reads first, and it was the one that was wrong.

**Fixed.** The row now reads "⚠️ Not operator-reachable" and points at a caveat
paragraph that states what exists, what does not, and that the
`ldap-integration` CI job does exercise the connector against a real OpenLDAP.

### L-3 — `escape_assertion_value` corrupted every non-ASCII value (**fixed**)

`src/identity/ldap/filter.rs:15-26` (pre-fix). For any byte that is not one of
`* ( ) \ NUL`, the escaper rebuilt the character with `char::from(byte)` — a
**Latin-1 decode of a UTF-8 byte** — and pushed it back into a `String`, where
it was re-encoded as UTF-8.

**Failure scenario.** A directory entry whose `modifyTimestamp` or search value
contains `é` (U+00E9, UTF-8 `0xC3 0xA9`) leaves this function as `Ã©`
(`0xC3 0x83 0xC2 0xA9`). Four bytes on the wire where two were supplied. The
LDAP server is asked about a value nobody has, and the entry is never returned.
Silent, and it looks like a directory problem rather than a Hearth one.

**Fixed.** Every byte outside printable ASCII is now hex-escaped as `\xx`, which
RFC 4515 §3 permits for any octet and which makes the output ASCII by
construction. Tests: `escape_preserves_non_ascii_octets_exactly`,
`escape_hex_escapes_control_characters`.

### L-4 — the injection guard has no user-controlled call site (reported)

`src/identity/ldap/mod.rs:26-28` states that filter injection "is prevented by
`filter::escape_assertion_value`, which RFC 4515-escapes special characters in
**any user-controlled input** embedded in search filters."

Counted: `escape_assertion_value` has **exactly two** call sites,
`filter.rs:72` (the delta-sync cursor, which Hearth itself wrote to its own
checkpoint) and `filter.rs:99` (a `u64` rendered as decimal, which cannot
contain a special character). No user-controlled value reaches it, because no
code path accepts a user-supplied search term at all.

Meanwhile the values that *are* interpolated into a filter are **not** escaped:
`user_filter`, `attribute_map.external_id`, `attribute_map.sync_attribute`
(`filter.rs:52`, `:74`, `:101`) and `base_dn` (`connector.rs:154`). Those are
operator config today. **When L-1 is wired**, decide explicitly whether a realm
administrator may set them through the admin API — if so, a `)` in an attribute
name breaks out of the filter, and this module's own doc comment will be the
reason nobody looked.

### L-5 — `DeltaSyncResult.skipped` is hard-coded `0` while the checkpoint advances (reported)

`connector.rs:166-174` maps each search entry and, on a mapping failure, logs a
warning and **drops the entry**. `connector.rs:351` then returns
`skipped: 0` unconditionally, and `connector.rs:347` saves a checkpoint whose
cursor is the maximum `sync_cursor` **seen across the whole page** — including
the pages of entries that were dropped.

`types.rs:239` documents that field as "Number of entries skipped (mapping
failures, filtered out, etc.)" and `types.rs:237` documents `upserted` as "Users
that were inserted or updated in Hearth". Neither is true: the connector never
writes a Hearth user, and it never counts a skip.

**Failure scenario.** A directory where 10,000 accounts lack the configured
`mail` attribute. `delta_sync` returns `DeltaSyncResult { upserted: […],
skipped: 0 }` — a clean run — and advances the high-watermark past all 10,000.
They are never retried, because the next delta query asks only for entries
modified *after* the cursor. The operator's dashboard shows zero skips.

**Fix shape.** `search_paged` should return `(Vec<LdapUser>, u64)` and
`delta_sync` should put the real count in `skipped`. Whether the checkpoint
should still advance past dropped entries is a **policy** decision an operator
must be able to make, which is why this is reported rather than fixed: choosing
"do not advance" here turns one unmappable entry into a permanently stalled
sync. Not fixed in this pass because no test can observe `search_paged` without
a live LDAP server, and the `ldap-integration` CI job is the right place for
that test.

---

## gRPC management API (task 23.9) — 4 findings

§4.2#1 and §4.19 covered `Decide` and the admin services. Those are in good
shape now (see **Already covered** below). The gap was the rest of
`OAuthService` and the transport wiring.

### G-1 — `DeviceAuthorize` never authenticated a confidential client (**fixed**)

`src/protocol/grpc/oauth.rs:158-179` (pre-fix) read the realm header, parsed the
`client_id`, and called the engine. No client authentication of any kind.

This is the same defect as audit §4.19#4 / §4.22#6 — *"Neither device-grant
endpoint authenticates the client, so a party without the client secret can run
the whole RFC 8628 flow under a confidential client's identity"* — which was
closed on the REST surface by wiring `enforce_confidential_client_auth` into the
device handlers (`src/protocol/http/oauth.rs:2296`). The gRPC twin was never
touched, so the fix could be side-stepped by changing protocol.

Two things make it worse than a plain omission:

1. `proto/hearth/identity/v1/oauth.proto:131-134` already carries the field, and
   its own comment already promises the check: *"Client secret for a
   confidential client (RFC 8628 §3.1). HTTP Basic Auth is preferred and takes
   precedence; this is the client_secret_post fallback."* The handler decoded
   `client_secret` into the request struct and dropped it.
2. `verify_grpc_client_auth` (`grpc/convert.rs:369`) already existed and was
   already used by `Revoke`, `Introspect` and `TokenExchange`.

**Failure scenario.** An attacker who knows only a confidential client's UUID —
a value that appears in redirect URLs and in every discovery-adjacent log —
calls `OAuthService/DeviceAuthorize` with `x-realm-id` and that UUID. They
receive a `user_code` and `verification_uri` branded as that client. A user who
approves it approves a delegation to a client the attacker controls the device
code for.

**Fixed.** The handler now looks the client up (failing **closed** on a storage
error), and for a confidential client requires either the metadata credentials
(`x-hearth-client-id` / `x-hearth-client-secret`, the gRPC analogue of HTTP
Basic, which take precedence exactly as the proto comment says) or the body's
`client_secret`. Public clients are unchanged.

### G-2 — the A-15 shaper bucketed every realm under one key (**fixed**)

`src/protocol/grpc/server.rs:49` (pre-fix) called `shaper.check(ip, "")`. The
second argument is the per-realm bucket key (`src/abuse/shaper.rs:151-164`), and
`""` is the documented key for "unauthenticated / pre-realm endpoints".

Every gRPC request in the process therefore shared **one** realm bucket, even
though every RPC on the surface already requires an `x-realm-id` header and the
HTTP surface keys its own realm arm properly.

**Failure scenario.** An operator sets `security.request_shaper.realm_rps: 1000`
on a multi-tenant deployment. Tenant A's batch job makes 1,000 gRPC calls in a
second. Tenant B's next gRPC call — a different realm, a different IP, one
request — gets `RESOURCE_EXHAUSTED`. The per-realm limit, whose entire purpose
is to stop one tenant affecting another, did the opposite.

**Fixed.** The interceptor now keys on the `x-realm-id` metadata value
(`grpc_realm_key`), falling back to `""` only when the header is absent. The
value is used solely as a `HashMap` key and is never trusted for authorization —
each handler still re-extracts and validates it.

### G-3 — `build_router` claimed a rate-limit layer it does not apply (**doc fixed, wiring reported**)

`src/protocol/grpc/server.rs:177-239`. Its doc comment said *"The A-15
rate-limit interceptor is applied as a server-level layer."* Reading the body:
`Server::builder().timeout(60s).add_service(…)` — **no `.layer()` call at all**,
and the reflection service is added raw, without the WEB-009
`grpc_reflection_auth_interceptor` that `serve` wraps it in
(`server.rs:291-294`).

`build_router` is `pub`, is re-exported from `grpc/mod.rs:38`, and has **zero
callers** — `src/main.rs:2835` calls `serve`, which duplicates the whole builder
*with* both interceptors. So the divergence is invisible in production and will
stay invisible until someone embeds the library and follows the export.

**Fixed:** the doc comment now states, under its own heading, that this router
applies neither interceptor and that `serve` is the one the server runs.
**Reported, not fixed:** actually applying the interceptors. Doing so either
changes the public return type (`Router` → `Router<L>`) or wraps all five
services in `InterceptedService`, and neither is provable by a test at
reasonable cost — an honest test has to bind a socket and drive a real client.
The right resolution is probably to delete `build_router` and have `serve` be
the only way to construct the surface; that is a `### Removed` changelog entry
and belongs in its own change.

### G-4 — the reflection "auth" interceptor authenticates nothing (reported)

`server.rs:71-87`. `grpc_reflection_auth_interceptor` accepts the request when
the `authorization` metadata *starts with* `"Bearer "` and is longer than seven
characters. The token is never validated — not its signature, not its realm, not
its expiry, not its permissions. `Authorization: Bearer x` passes.

The doc comment is more careful than the function name, and says the gate exists
to *"prevent anonymous schema enumeration on staging/debug instances"*, which a
presence check does accomplish against a drive-by `grpcurl list`. But the
function is named `..._auth_interceptor`, it answers `UNAUTHENTICATED`, and a
reader will reasonably believe reflection is behind authentication. It is not.

**Fix shape.** Either rename it to `grpc_reflection_requires_bearer` and say in
one line that it is a speed bump, or give the interceptor access to `GrpcState`
and call `validate_token`. The latter cannot be a bare `fn` interceptor; it
needs the closure-returning shape `grpc_rate_limit_interceptor` already uses.
Not fixed here because reflection is already off by default in production and
gated behind `--allow-reflection-in-prod`, so the residual risk is confined to
staging.

---

## Email transports (task 23.12) — 5 findings

§4.14 and §4.24 reached email through the config and recovery paths. The
transports themselves — six `EmailSender` implementations, the injectable HTTP
layer, and the orchestration service — were never read.

### E-1 — `truncate_body` panics on a multi-byte character (**fixed, 6 sites**)

`&body[..200]` on a `&str`. If byte 200 lands inside a multi-byte UTF-8
character, `str` indexing panics with *"byte index 200 is not a char
boundary"*. The string being sliced is **the provider's own error response
body**, so a remote party decides whether the call panics.

The real count is **six**, not the four in the email subsystem:

| File | Line (pre-fix) |
|---|---|
| `src/identity/email/sendgrid.rs` | 96 |
| `src/identity/email/postmark.rs` | 94 |
| `src/identity/email/mailgun.rs` | 156 |
| `src/identity/email/mailtrap.rs` | 120 |
| `src/identity/sms/sns.rs` | 227 |
| `src/identity/sms/twilio.rs` | 119 |

**Failure scenario.** SendGrid rejects a message and returns a JSON error whose
`message` field is localised — French, Japanese, or simply containing a `—`.
The 201st byte is the middle of that character. `truncate_body` panics inside
`tokio::task::block_in_place` on a Tokio worker thread, unwinding out of the
verification-email send. Nothing in Hearth is malformed; a provider changed an
error string.

**Fixed** at all six sites: the function walks back to the nearest character
boundary. Tests: `truncate_body_does_not_panic_on_a_multibyte_boundary` in each
of the six modules.

### E-2 — the onboarding wizard wrote a live reset token to the log (**fixed**)

`src/protocol/web/admin/onboarding.rs:620-624` (pre-fix):

```rust
tracing::warn!(
    reset_url = %reset_url,
    invited = %email,
    "onboarding: invitation link (check logs if email delivery fails)"
);
```

`reset_url` is `{base}/ui/realms/{realm}/reset-password?token={token}` built
eleven lines above from a **live, single-use password-reset token** for the
realm administrator the wizard is creating.

The guard for exactly this already exists and is already documented as
mandatory. `src/protocol/redact.rs:13` lists `reset_url` first among the field
names that *"MUST always be wrapped in `Redact` (or dropped entirely)"*, and the
sibling site — the no-transport arm of `forgot_password` at
`src/protocol/web/handlers.rs:3747` — does wrap it. This one site did not.

**Failure scenario.** An operator runs the first-run wizard. The log line goes to
stdout, is collected by the platform's log agent, and lands in a searchable
aggregator with a 90-day retention that a dozen people can read. Any of them can
complete the password reset and own the realm administrator account. The token
expires long before the log line does, but the window is the token TTL after
*every* wizard run, including the reruns an operator does while getting the
config right.

**Fixed.** Wrapped in `crate::protocol::redact::Redact`, matching the sibling
site. Test: `step3_invite_does_not_log_the_reset_token` in
`tests/admin_onboarding.rs` captures the actual `tracing` output and asserts the
token is absent and `reset_url=[REDACTED]` is present.

### E-3 — the organization invite flashed success when nothing was sent (**fixed, 2 sites**)

`src/protocol/web/admin/orgs.rs:1562` (create) and `:1830` (resend), pre-fix:

```rust
if let Err(e) = email_service.send_invitation_email(…) {
    tracing::warn!(error = %e, "failed to send invitation email");
}
}
let msg = format!("Invitation sent to {}", form.email);
org_redirect_flash(&org_id, target.0.name(), &msg, "success", secure)
```

Two ways to be told an invitation was sent when it was not:

1. The transport refused it. The error is logged at WARN and swallowed; the
   green flash says "Invitation sent to …".
2. `state.email` is `None` — no `email.transport` configured. The whole block is
   skipped and the same green flash appears.

This is the class audit §4.24#10 found — *"admin reset actions mint a token,
discard it, report 'sent'"* — at two sites §4.24 did not reach. Both are admin
actions with a human waiting for the answer, which is exactly when a false
success is most expensive: the admin moves on, and the invitee simply never
appears.

**Failure scenario.** An operator invites a customer's owner to their new
organization. SMTP credentials are wrong. The screen says "Invitation sent to
owner@customer.test" in green. Nobody looks again until the customer asks, days
later, why they were never invited.

**Fixed.** Both handlers now track an `InviteDelivery` outcome and render it
through one `invite_flash` helper: `"Invitation sent to …"` (success) only when
the transport accepted the message; `"Invitation created for …, but the email
could not be delivered"` (error) when it refused; `"…but no email transport is
configured, so nothing was sent"` (error) when none is wired. The invitation
record is still created in every case, which is the pre-existing behaviour and
correct — the token remains valid and the admin can resend. Tests:
`invite_reports_failure_when_the_transport_refuses_the_message`,
`invite_reports_that_nothing_was_sent_when_no_transport_is_configured`.

### E-4 — two of seven egress paths have no timeout (reported)

Every blocking HTTP egress path in the tree is built on `ureq`. Five of them
build an explicit `ureq::config::Config`:

| Path | Config |
|---|---|
| `src/identity/federation/http.rs:76` | `timeout_connect`, `timeout_global`, `https_only`, `max_redirects` |
| `src/webhook/dispatcher.rs:291` | same four, plus `ssrf_agent` DNS validation |
| `src/identity/pre_token_webhook.rs:198` | explicit config |
| `src/identity/approval_notifier.rs:92` | explicit config |
| `src/protocol/http/session.rs:255` | explicit config |

Two do not:

| Path | Code |
|---|---|
| `src/identity/email/http.rs:49` | `ureq::post(&request.url)` — bare |
| `src/identity/sms/http.rs:48` | `ureq::post(&request.url)` — bare |

A bare `ureq::post` uses `Config::default()`, which in ureq 3.3.0
(`config.rs:894-908`) sets **every** timeout to `None` except `await_100: 1s` —
no global, connect, resolve, send or receive timeout at all.

**Failure scenario.** A provider's API endpoint completes the TCP handshake and
then stops responding (a common failure mode for an overloaded load balancer,
and trivially arranged by anyone who can influence DNS for the provider's
hostname). `UreqTransport::post` is called inside
`tokio::task::block_in_place`, so it pins a Tokio **worker thread**, not a
spawned blocking thread. Each stuck send costs one worker permanently. On a
default runtime that is one core's worth of capacity per stuck message, and
sends queue behind it. No timeout ever fires.

Note what is **not** claimed: ureq 3's default `redirect_auth_headers` is
`Never` (`config.rs:876`), so a redirect does not carry the provider API key to
the redirect target. The exposure here is availability, not key disclosure.

**Fix shape.** Give both transports a module-level `Config` matching the
federation one — `timeout_connect`, `timeout_global`, `https_only(true)`,
`max_redirects` — and build a per-call agent. Straightforward, but it is a
behaviour change to two production egress paths and deserves its own change with
its own test (a listener that accepts and never writes, asserting the send
returns an error rather than hanging). Reported rather than bundled here.

### E-5 — `reject_crlf` is applied asymmetrically to the subject (reported, low)

`SmtpEmailSender::send` (`smtp.rs:74-75`) rejects CR/LF in **both** the
recipient and the subject. The four HTTP adapters
(`sendgrid.rs:43`, `postmark.rs:43`, `mailgun.rs:81`, `mailtrap.rs:72`) check
only the recipient.

For those four the subject is not exploitable today: three serialise it through
`serde_json`, which escapes control characters, and Mailgun percent-encodes it
through `url_encode`. So this is a *consistency* finding, not a live injection:
the invariant "no CR/LF in any header-bound field" holds by accident in four
places and by construction in one. Adding `reject_crlf("subject", …)` to the
four costs nothing and makes the invariant independent of the encoder — but it
is not a defect and should not be filed as one.

---

## Already covered — do not re-raise

| Property | Where it is handled |
|---|---|
| gRPC `Decide` skips `validate_token`; refresh token authorizes (§4.2#1, §4.19#9) | `decide_token_permission_inner` (`engine/oauth.rs:2919`) now refuses `token_type != "access"` before any decision |
| `nbf` not enforced on the decision path (§4.2#6, §4.19#10) | `engine/oauth.rs:2930-2935` |
| JTI blocklist consulted only on the `sid == "none"` branch (§4.19#5) | `engine/oauth.rs:2941` — checked on both branches |
| DPoP-bound admin token replayable as plain Bearer on gRPC (§4.19#8) | `grpc/auth.rs:60-65` — `authenticate_admin` refuses any token carrying `cnf` |
| gRPC admin RPCs missing a granular permission check | All 62 admin RPCs call `authenticate_admin` **and** `grpc_require_permission` with a specific permission — verified by enumerating every `async fn` in `identity.rs` (28), `rbac_admin.rs` (30), `audit.rs` (2), `oauth.rs` (`register_client`) |
| gRPC `Revoke` / `Introspect` read no client credentials (§4.19#2) | `grpc/oauth.rs:134`, `:148` — both call `verify_grpc_client_auth` |
| gRPC `Authorize` trusts a body-supplied `user_id` (HEA-1721) | `grpc/oauth.rs:45-46, 81` — overridden with the authenticated `sub` |
| gRPC `RegisterClient` unauthenticated (HEA-1750 A1) | `grpc/oauth.rs:204-205` |
| gRPC message size unbounded | `MAX_DECODING_MESSAGE_SIZE` = 1 MiB on all five services, both builders |
| gRPC reflection enabled in production (A-43) | `resolve_grpc_reflection` refuses at startup without `--allow-reflection-in-prod` |
| `LoggingEmailSender` writes recovery links to the log (§4.14#2, §4.24#2) | `email/log.rs:20, 46-52` — body suppressed unless `new_dev()` |
| Half a pair of SMTP credentials silently dropped | `config/validate.rs:1418-1436` — three rules, all three directions |
| `email.transport = mailcatcher` in production | `src/main.rs:1437-1440` — fatal startup guard |
| Email provider API keys in `Debug` output | `ApiKey` (`email/mod.rs:150`) and `LdapBindPassword` (`ldap/types.rs:156`) both redact |
| LDAP integration tests are `#[ignore]`d and never run | `.github/workflows/ci.yml:1016` `ldap-integration` runs them with `--run-ignored` against a real OpenLDAP container on any `src/identity/ldap/**` change and on `main` |

---

## Per-design — NOT defects

Recorded so a future sweep does not re-raise them.

| Observation | Why it is correct |
|---|---|
| `POST /ui/register` and `POST /ui/forgot-password` show the same "check your email" page whether or not the send succeeded (`handlers.rs:4851`, `:3736`) | Enumeration resistance. Telling the caller that delivery failed tells them the address exists. §4.24#3 made the send off-request-path for the same reason. Deliberately different from the **admin** invite flash (E-3), where the actor is already authorised to know. |
| `required_action.rs:964` — verification resend is best-effort and the page renders either way | End-user page, same enumeration argument, and its own comment says "best-effort". |
| `grpc_rate_limit_interceptor` fails **open** when no peer IP is available (`server.rs:53-57`) | Documented, and matches `src/abuse/shaper.rs:16-18` ("if the shaper is not configured, all requests pass"). A shaper is a courtesy limit, not an authorization control; failing closed on a missing `TcpConnectInfo` would black-hole the whole surface behind a transport change. |
| `grpc_realm_key` returns the **unvalidated** `x-realm-id` string | It is only ever a `HashMap` key. Every handler independently calls `extract_realm_id`, which parses and validates. Keying on the raw string before validation is what lets the limit apply to malformed requests too. |
| `authenticate_admin` accepts any of five permissions before the per-RPC check (`grpc/auth.rs:77-86`) | It is a coarse pre-filter; every RPC then calls `grpc_require_permission` with the specific permission it needs. Verified across all 62 RPCs. |
| `enforce_confidential_client_auth` returns `Ok(())` for an unknown or unparseable `client_id` | Deliberate and documented (`http/oauth.rs:664-668`): differing on an unknown client is a client-existence oracle. The exchange still fails with `invalid_grant`. The new gRPC `DeviceAuthorize` gate follows the same rule. |
| `EmbeddedLdapConnector::authenticate_user` returns `Ok(false)` for an empty DN or password (`connector.rs:267-269`) | RFC 4513 §5.1.2: a simple bind with an empty password is an *unauthenticated* bind and many servers answer success. Short-circuiting before the network call is the correct defence, and `tests/ldap_federation.rs` pins it. |
| `advance_cursor` compares USN cursors numerically and timestamps lexicographically (`connector.rs:362-388`) | Correct for both: `"1000" < "999"` lexicographically, while ISO-8601 generalized-time sorts correctly as a string. Already has a regression test. |
| `LdapConfig.allow_insecure` permits plain `ldap://` | Only reachable through code no operator can configure (L-1), so there is nothing to gate yet. **When L-1 is wired**, this needs a production guard modelled on the mailcatcher one at `src/main.rs:1437`. |
| `send_otp_email` interpolates the realm's `product_name` into HTML unescaped (`service.rs:150-158`) | The value is realm-admin configuration, and a realm admin can already supply a full stored email template (`email_templates`). No privilege is crossed. |

---

## What this pass changed

| Finding | Change |
|---|---|
| L-2 | `docs/STATUS.md` — LDAP row and a new caveat paragraph |
| L-3 | `src/identity/ldap/filter.rs` — hex-escape every non-printable-ASCII octet |
| L-3b | `src/identity/ldap/mapping.rs` — `requested_attributes` deduped with a set; `Vec::dedup` only collapses *adjacent* duplicates, so `display_name = cn` + `username = cn` requested `cn` twice on every page |
| G-1 | `src/protocol/grpc/oauth.rs` — confidential-client authentication on `DeviceAuthorize` |
| G-2 | `src/protocol/grpc/server.rs` — per-realm shaper bucket |
| G-3 | `src/protocol/grpc/server.rs` — `build_router` doc now states what it does not do |
| E-1 | six `truncate_body` implementations walk back to a char boundary |
| E-2 | `src/protocol/web/admin/onboarding.rs` — `reset_url` wrapped in `Redact` |
| E-3 | `src/protocol/web/admin/orgs.rs` — `InviteDelivery` + `invite_flash` |

Every fix was proved non-vacuous by mutation: the guard was removed, exactly the
tests covering it went red with every neighbouring test still green, and the
file was restored and verified byte-identical against a `sha256sum` taken
beforehand.
