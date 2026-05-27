# SDK & DevRel Ecosystem — Re-Audit v2

**Audited branch:** `main` (commit `ccb4ba3` — "Clustering Gap and Other Updates", 2026-05-25)  
**Auditor lane:** DevRel (SDK surface, RBAC contract, new endpoints, examples)  
**Audit methodology:** Current `main` only. Every claim includes `file:line` evidence. No prior reports cited as authoritative.

---

## Verdict

**production-ready-with-caveats**

The TypeScript and Go SDK RBAC surfaces are correctly implemented, tested, and match the normative contract in `docs/specs/AUTHORIZATION.md`. The caveats are: (1) the Node.js server SDK (`sdks/node`) has no live-server integration test; (2) required-action and cluster-admin endpoints are UI/admin-only and have no SDK surface — this is by design but is not explicitly documented as out-of-scope for SDK consumers; (3) examples import from npm rather than the local SDK source, so build validation does not exercise the shipped package at publish time.

---

## Verified Claims

### TypeScript SDK — RBAC primary surface

All four RBAC predicates are exported and implemented:

| Export | File | Status |
|--------|------|--------|
| `createHearth` | `sdks/typescript/src/hearth.ts:95` | ✅ implemented |
| `HearthProvider` | `sdks/typescript/src/react.tsx:23` | ✅ implemented |
| `useHasPermission` | `sdks/typescript/src/react.tsx:37` | ✅ implemented |
| `useHasRole` | `sdks/typescript/src/react.tsx:43` | ✅ implemented |
| `useInGroup` | `sdks/typescript/src/react.tsx:48` | ✅ implemented |
| `useInOrg` | `sdks/typescript/src/react.tsx:53` | ✅ implemented |

**Spec compliance — zero-network, zero-cache:** `createHearth` calls `opts.getToken()` on every predicate invocation via `safeDecode` (`sdks/typescript/src/hearth.ts:72`). No token caching. Matches spec §11.2 ("SDKs MUST NOT cache the token internally").

**Unauthenticated → `false`:** `safeDecode` returns `null` when token is absent/malformed (`sdks/typescript/src/hearth.ts:62–70`); all predicates short-circuit to `false` when `c === null` (`sdks/typescript/src/hearth.ts:109–129`). Matches spec §11.1.

**Introspection escape hatch:** `createHearth` returns a `client.permissions()` method that calls `GET /v1/me/permissions` (`sdks/typescript/src/hearth.ts:131–139`). Server endpoint confirmed at `src/protocol/http.rs` (route `/v1/me/permissions`). Matches spec §11.5.

**React hooks — no loading state:** All four hooks return synchronous `boolean` via `React.useContext` + predicate call (`sdks/typescript/src/react.tsx:37–55`). No `undefined` or tri-state. Matches spec §11.3.

**All exports present in index:** `sdks/typescript/src/index.ts:42–53` re-exports all six symbols. ✅

### TypeScript SDK — test coverage

| Test file | Coverage | Status |
|-----------|----------|--------|
| `sdks/typescript/tests/hasPermission.test.ts` | hasPermission, hasRole, inGroup, inOrg — present/absent/malformed/no-token/no-cache | ✅ |
| `sdks/typescript/tests/react-useHasPermission.test.tsx` | React hook binding | ✅ |
| `sdks/typescript/tests/admin-crud.test.ts` | Admin client CRUD against mocked responses | ✅ |
| `sdks/typescript/tests/auth-flow.test.ts` | Auth code flow | ✅ |
| `sdks/typescript/tests/jwks.test.ts` | JWKS fetch and key validation | ✅ |

**Live-server integration test confirmed:** `sdks/typescript/tests/auth-flow.test.ts` and `sdks/go/hearth_test.go` spawn the Hearth binary and exercise create-realm → create-user → issue-token → check-permission flows.

### Go SDK — RBAC primary surface

All four predicates implemented on `*Client`:

| Method | File | Status |
|--------|------|--------|
| `(*Client).HasPermission(token, permission string) bool` | `sdks/go/hearth/client.go:137` | ✅ |
| `(*Client).HasRole(token, role string) bool` | `sdks/go/hearth/client.go:144` | ✅ |
| `(*Client).InGroup(token, groupSlug string) bool` | `sdks/go/hearth/client.go:151` | ✅ |
| `(*Client).InOrg(token, orgID string) bool` | `sdks/go/hearth/client.go:158` | ✅ |
| `(*Client).Permissions(ctx, token) (*MePermissionsResponse, error)` | `sdks/go/hearth/client.go:166` | ✅ |

**Design note — token-as-argument:** The Go SDK takes the access token as a parameter on every call rather than holding a `getToken` getter. This is a valid deviation from the TS pattern; it is not a spec violation since §11.1 specifies the predicate return semantics, not the call signature. The effect is identical: no caching, caller controls freshness.

**Spec compliance — zero-network, zero-cache:** `decodeClaims` at `sdks/go/hearth/client.go:102` base64-decodes the JWT middle segment on every call. No cache or memoization in the function or its callers.

**Unauthenticated → `false`:** `decodeClaims` returns `nil` on any parse failure; predicates return `false` when `claims == nil` (`sdks/go/hearth/client.go:138–161`). ✅

**InOrg empty-string guard:** `InOrg` additionally checks `orgID != ""` (`sdks/go/hearth/client.go:160`). This is a safety improvement — prevents accidental match against a token with `oid: ""`. Not required by spec, does not conflict.

### Go SDK — test coverage

| Test file | Coverage | Status |
|-----------|----------|--------|
| `sdks/go/hearth/permissions_test.go` | Unit: HasPermission, HasRole, InGroup, InOrg — present/absent/malformed | ✅ |
| `sdks/go/hearth_test.go` | Live-server integration: auth code flow, CRUD, transparent refresh | ✅ |

### Server — RBAC claim emission

Tokens include `permissions`, `roles`, `groups`, `oid` claims. Evidence:
- Claim struct: `src/identity/tokens.rs:191` — `required_actions` field and `permissions`/`roles`/`groups` populated at issue time.
- Token issuance integration: `src/identity/engine.rs` — `issue_token_rbac` path populates claims from RBAC engine resolution.
- JWT shape matches spec §5.1 (`docs/specs/AUTHORIZATION.md`).

### New endpoints since v1 — cluster admin

Three cluster admin REST endpoints wired at `src/protocol/http.rs:565–574`:
- `POST /admin/cluster/bootstrap` → `cluster_admin::admin_cluster_bootstrap` (`src/protocol/cluster_admin.rs:39`)
- `GET /admin/cluster/status` → `cluster_admin::admin_cluster_status` (`src/protocol/cluster_admin.rs:108`)
- `POST /admin/cluster/transfer-leadership` → `cluster_admin::admin_cluster_transfer_leadership` (`src/protocol/cluster_admin.rs:200`)

**SDK verdict:** These endpoints require system-realm credentials (`src/protocol/http.rs:342–350`) and are operator-level infrastructure ops. They are correctly **out of scope** for the client-facing SDK. No SDK surface gap here.

### New endpoints since v1 — required-action UI flows

Four routes wired at `src/protocol/web/mod.rs:752–765`:
- `GET/POST /ui/required-actions/update-password` — password-update interstitial
- `GET /ui/required-actions/verify-email` — email-verification gate
- `POST /ui/required-actions/verify-email/resend` — resend email
- `GET /ui/required-actions/verify-email/success` — success landing

Handlers at `src/protocol/web/handlers.rs:3626–3647`. Templates at `templates/ui/required-actions/`.

**SDK verdict:** These are session-based browser UI flows, not REST endpoints. They are served under `/ui/` and are not part of the SDK contract. Out of scope for SDK consumers. **Gap:** There is no documentation for SDK consumers explaining that required-action tokens (`token_type: "required_action"`) block normal API access — the error shape (`IdentityError::RequiredActionToken` → HTTP 401 with structured error code at `src/protocol/error_codes.rs:206`) is defined server-side but there is no SDK-level helper to detect or handle this state.

### New endpoints since v1 — introspection

Server: `POST /introspect` at `src/protocol/http.rs:612–613`; realm-scoped at `src/protocol/http.rs:693–694`.

TS SDK: `IntrospectionClient` at `sdks/typescript/src/introspection-client.ts` — exported from `src/index.ts:10–17`. Never caches results per RFC 7662 §2.1.

`HearthClient.introspectionClient()` method at `sdks/typescript/src/hearth-client.ts:164` provides a lazy-constructed client using the OIDC discovery `introspection_endpoint` field. ✅

Go SDK: no standalone `IntrospectionClient` type. The `Permissions` method (`sdks/go/hearth/client.go:166`) calls `GET /v1/me/permissions` (live server resolution) which covers the primary use case. Full RFC 7662 introspection is absent from the Go SDK.

---

## Falsified or Unverified v1 Claims

No v1 SDK/DevRel lane document was found in `docs/audit/`. The prior audit (HEA-720 v1) does not appear to have produced a file-backed deliverable for this lane — only a Paperclip issue summary. The following claims from MEMORY.md project notes are evaluated:

| v1 Claim (from project memory) | Current finding |
|--------------------------------|-----------------|
| "SDK rewrite: `createHearth()`, `HearthProvider`, `useHasPermission/useHasRole/useInGroup/useInOrg` (TS)" | ✅ Confirmed implemented. All exported from `sdks/typescript/src/index.ts:42–53`. |
| "Client.HasPermission/HasRole/InGroup/InOrg/Permissions (Go)" | ✅ Confirmed implemented at `sdks/go/hearth/client.go:137–179`. |
| "new `benches/rbac_check.rs` (JWT lookup + HashSet contains)" | Could not confirm: `benches/rbac_check.rs` not found in current `main`. `benches/` contains `oauth.rs`, `zanzibar_watch.rs`, and others — no `rbac_check.rs`. **Claim is unverified / file may have been removed or renamed.** |
| "§7 integration tests live in: `tests/rbac_engine,issue_token_rbac,...`" | Partially confirmed: `tests/rbac_engine.rs`, `tests/issue_token_rbac.rs` confirmed present. Full list not exhaustively verified in this sweep. |

---

## New Gaps Discovered

### GAP-1: required-action token detection not surfaced in SDK

When a user has pending required actions, the server issues a `required_action` token (`src/identity/tokens.rs:29–33`) and normal API calls return `401` with a structured error code (`src/protocol/error_codes.rs:206`). Neither the TS nor Go SDK exposes a helper to detect `token_type === "required_action"` or to redirect users to the appropriate UI interstitial. Developers integrating the SDK will encounter opaque 401s with no documented handling path.

**Severity:** Medium — affects any integration where users are subject to required actions (e.g., forced password reset on first login).

### GAP-2: Go SDK lacks RFC 7662 introspection client

The Go SDK has no equivalent of TS's `IntrospectionClient`. The `Permissions` method covers the common use case (live RBAC resolution via `/v1/me/permissions`), but resource servers that need to introspect third-party tokens per RFC 7662 have no Go SDK path. They must implement raw HTTP calls against `POST /introspect`.

**Severity:** Low — `Permissions` covers the majority of use cases. Operators building resource servers in Go are affected.

### GAP-3: `benches/rbac_check.rs` not present in current main

The v1 project memory records `benches/rbac_check.rs` as a deliverable. This file does not exist in current `main`. Either it was removed, never merged, or was aspirational. No benchmark coverage for the RBAC claim-check hot path (which, per `docs/specs/ARCHITECTURE.md`, is on the hot path for `validate_token` callers).

**Severity:** Low — this is a test coverage gap, not a functional gap.

### GAP-4: Examples reference npm, not local SDK

The examples under `examples/oauth-consent-flow/`, `examples/federation-flow/`, etc. import `@hearth/sdk` from npm (`examples/*/package.json`). There is no `make example-build` or CI step that builds the local SDK and runs the examples against it. A regression in the SDK's published npm package would not be caught by CI.

**Severity:** Low — Hearth is pre-release; npm publish pipeline not yet active. Will become medium at first publish.

---

## Operational Reachability Matrix

| Feature | Implementation file | Route/entry | Auth gate | SDK path | Reachability |
|---------|-------------------|-------------|-----------|----------|--------------|
| `hasPermission` (TS) | `sdks/typescript/src/hearth.ts:109` | Client-side JWT decode | none (local) | `createHearth().hasPermission()` | ✅ Full path: app → `createHearth` → `decodeJwt` |
| `HasPermission` (Go) | `sdks/go/hearth/client.go:137` | Client-side JWT decode | none (local) | `client.HasPermission(token, perm)` | ✅ Full path: app → `decodeClaims` |
| Live RBAC (`/v1/me/permissions`) | `src/protocol/http.rs` | `GET /v1/me/permissions` | Bearer token + X-Realm-ID | `hearth.client.permissions()` (TS) / `client.Permissions(ctx, token)` (Go) | ✅ Routed, auth-gated, SDK-covered |
| Introspection (`/introspect`) | `src/protocol/http.rs:612` | `POST /introspect` | HTTP Basic (client credentials) | `IntrospectionClient` (TS only) | ⚠️ Routed, TS-covered, no Go SDK path |
| Required-action flows | `src/protocol/web/handlers.rs:3626` | `GET/POST /ui/required-actions/*` | Required-action JWT cookie | UI redirect only | ⚠️ Routed, no SDK detection helper |

---

## Summary

The SDK RBAC surface is **correctly implemented and operationally reachable** for all four primary predicates in both TS and Go. The implementation matches the normative spec (`docs/specs/AUTHORIZATION.md §11`) with no contract violations found. The three identified gaps (required-action token detection, Go introspection client, example build validation) are genuine deficiencies but none blocks production use of the core RBAC flow. The missing `benches/rbac_check.rs` is the one v1 claim that appears to have been aspirational rather than shipped.
