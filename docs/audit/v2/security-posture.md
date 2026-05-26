# HEA-768 — Security Posture & Cryptographic Hygiene Re-Audit

**Date:** 2026-05-25  
**Auditor:** SecurityAuditor (HEA-768)  
**Branch audited:** `feature/gap-updates-for-clustering`  
**Methodology:** re-grep of current tree; every claim carries file:line evidence;
checkbox-complete vs operationally-reachable distinguished throughout.

---

## Executive Summary

Hearth's cryptographic stack is **sound**. Ed25519-only signing, Argon2id
password hashing, `ring`/`rustls`/`subtle` throughout, ZeroizeOnDrop on all
secret types, and no hand-rolled crypto. Four findings require remediation before
a production deployment can be considered fully hardened.

**Verdict: production-ready-with-caveats** (3 medium, 1 low)

---

## Findings

### GAP-1 — Broken Function-Level Authorization on Realm Management gRPC

**Class:** OWASP API Top 10 — Broken Function-Level Authorization (BFLA)  
**Severity:** Medium | **Exploitability:** Medium (requires `hearth.admin` claim)

**Evidence:**

```
src/protocol/grpc/identity.rs:182  let _auth = authenticate_admin(…)  // list_realms
src/protocol/grpc/identity.rs:197  let _auth = authenticate_admin(…)  // get_realm
src/protocol/grpc/identity.rs:213  let _auth = authenticate_admin(…)  // create_realm
src/protocol/grpc/identity.rs:235  let _auth = authenticate_admin(…)  // update_realm
src/protocol/grpc/identity.rs:254  let _auth = authenticate_admin(…)  // delete_realm
```

`authenticate_admin` (at `src/protocol/grpc/auth.rs:38`) validates the bearer
token against the realm specified in `x-realm-id`, then returns
`AdminAuth { realm_id, user_id }`. All five realm-management handlers bind the
result to `_auth` (discard) rather than `auth`. The authenticated `realm_id` is
never checked against the target realm in the request body.

**Attack path:** An admin of Realm A authenticates via `x-realm-id: realm-a` with
a valid Realm A token. They then call `delete_realm({ id: "realm-b-id" })`.
Realm A auth succeeds, but the delete operates on Realm B. Multi-tenant data
destruction across realms is possible with a single authenticated gRPC call.

**Blast radius:** Complete loss of any realm's data by a legitimate admin of any
other realm. In a SaaS/multi-tenant deployment this is equivalent to a full
privilege escalation to super-admin.

**Fix:** Introduce a `hearth.superadmin` realm-independent claim checked for
cross-realm operations; OR restrict realm CRUD to system-realm admin tokens (issued
by bootstrap only); OR add an explicit scope check:

```rust
// In create_realm / update_realm / delete_realm:
let auth = authenticate_admin(req.metadata(), &self.state)?;
// For mutations that cross realm boundaries, require a superadmin flag:
if !auth.is_superadmin {
    return Err(Status::permission_denied("cross-realm operations require superadmin"));
}
```

**Residual risk after fix:** Super-admin credential compromise is still a full
multi-tenant blast. Recommend separate credentials for realm lifecycle operations.

---

### GAP-2 — gRPC Internal Error Details Leaked to Callers

**Class:** OWASP API Top 10 — Security Misconfiguration / Information Disclosure  
**Severity:** Medium | **Exploitability:** Low (requires valid admin gRPC token)

**Evidence:**

```
src/protocol/grpc/audit.rs:38   .map_err(|e| Status::internal(e.to_string()))?
src/protocol/grpc/audit.rs:53   .map_err(|e| Status::internal(e.to_string()))?
src/protocol/grpc/audit.rs:59   .map_err(|e| Status::internal(e.to_string()))?
src/protocol/grpc/identity.rs:227  Status::internal(format!("RBAC seed failed: {e}"))
```

Four gRPC handlers forward raw internal error strings to the caller. Storage-layer
errors can include key prefixes, file paths, or internal state that aids
reconnaissance. The RBAC seed error reveals the exact failure mode of the
internal role initialization system.

Note: `src/cluster/server.rs:79,93,110` also uses `Status::internal(e)` but this
is on the Raft peer gRPC channel protected by mutual TLS — acceptable for
internal cluster communications.

**Blast radius:** An attacker with a compromised admin token can probe storage
internals by triggering specific error conditions and reading the error strings in
gRPC status messages.

**Fix:**

```rust
// Replace:
.map_err(|e| Status::internal(e.to_string()))

// With:
.map_err(|e| {
    let id = uuid::Uuid::new_v4();
    tracing::error!(error = %e, error_id = %id, "audit query failed");
    Status::internal(format!("internal error [{id}]"))
})
```

**Residual risk:** Operator can correlate `error_id` in logs; no internal state
reaches the caller.

---

### GAP-3 — Argon2id Default Memory Cost Below OWASP 2023 Minimum

**Class:** OWASP Top 10 — Cryptographic Failures  
**Severity:** Medium | **Exploitability:** Only relevant if password database is exfiltrated

**Evidence:**

```
src/identity/credentials.rs:118  memory_cost_kib: 19_456,  // 19 MiB per OWASP
src/identity/credentials.rs:119  time_cost: 2,
src/identity/credentials.rs:120  parallelism: 1,
```

The comment cites "per OWASP" but references the 2021 guidance (minimum 15 MiB).
OWASP's Password Storage Cheat Sheet was updated in 2023: the minimum for
Argon2id is now **64 MiB** (65,536 KiB). The default ships at 19 MiB —
19,456 KiB — which is below the current recommendation.

Per-realm override is possible (`src/identity/engine.rs:1677-1681`) but operators
must discover and manually set `password_memory_cost: 65536`. The insecure path
is the default.

**Blast radius:** If the credential store is exfiltrated, password recovery is
~3× faster than it would be at 64 MiB, reducing the window operators have to
rotate compromised credentials.

**Fix:**

```rust
// src/identity/credentials.rs:118
memory_cost_kib: 65_536, // 64 MiB — OWASP 2023 minimum for Argon2id
```

Note: changing the default increases login latency on low-memory hardware
(~3× slower hashing). Document this clearly and provide a `fast` preset for dev.
The existing `fast_for_testing()` preset at line 130 is appropriate for CI.

**Residual risk:** Existing stored hashes at 19 MiB are not automatically
rehashed. Add a rehash-on-login path (verify at old cost → rehash at new cost)
or issue a forced password reset to all users on the next deployment.

---

### GAP-4 — CSP `unsafe-eval` Required by Alpine.js

**Class:** OWASP Top 10 — Security Misconfiguration  
**Severity:** Low | **Exploitability:** Very Low (requires XSS vector first)

**Evidence:**

```
src/protocol/web/security.rs:97-98
  "default-src 'self'; \
   script-src 'self' 'unsafe-eval'; \
```

Alpine.js v3's directive engine (`x-show`, `:class`, `x-bind`) uses `new
Function()` internally, which requires `unsafe-eval` in `script-src`. The comment
at lines 87-93 acknowledges this explicitly.

`unsafe-eval` means any XSS that can reach `eval()`, `new Function()`, or
`setTimeout(string)` bypasses script-src entirely. The attack surface requires
a separate XSS entry point first.

**Blast radius:** If an XSS vulnerability exists in any Askama template, an
attacker can execute arbitrary scripts in the victim's browser context, exfiltrate
session cookies (if not HttpOnly on all paths), or perform CSRF-bypassing actions.

**Fix path (medium term):** Migrate to Alpine.js v4+ (ships nonce-based CSP
support) or replace Alpine with a CSP-friendly alternative (Htmx already present;
vanilla JS for the remaining reactivity). Until then, document this as an accepted
architectural risk with a tracked remediation ticket.

**Residual risk:** `style-src 'self' 'unsafe-inline'` (line 99) is lower risk
(CSS injection vs. JS execution) but still weaker than nonce-based CSP.

---

## What Is Healthy

These areas pass the audit without findings:

| Area | Evidence | Status |
|---|---|---|
| JWT signing algorithm | `src/identity/tokens.rs:24` — `const JWT_ALGORITHM: &str = "EdDSA"` | PASS — Ed25519 only, hardcoded, no algorithm negotiation |
| Token lifetime | `src/identity/tokens.rs:91-97` — 900 s access, 604,800 s refresh | PASS — short-lived, enforced at validation |
| JTI revocation | `src/identity/keys.rs:647`, `src/identity/engine.rs:2296` | PASS — JTI blocklist for sessionless tokens |
| Secret zeroize | `src/identity/credentials.rs:28`, `src/identity/tokens.rs:287`, `src/storage/encryption.rs:48` | PASS — ZeroizeOnDrop on all secret types |
| Constant-time comparison | `src/identity/credentials.rs:18`, `src/identity/federation/state.rs:28`, `src/identity/onboarding.rs:30` | PASS — `subtle::ConstantTimeEq` throughout |
| PKCE enforcement | `src/identity/engine.rs:4582` — `if pkce_required && request.code_challenge.is_none()` | PASS — mandatory for public clients; configurable for confidential |
| PKCE method | `src/identity/engine.rs:4588` — only S256 accepted, plain rejected | PASS — RFC 9700 compliant |
| CORS | `src/protocol/http.rs:1235-1253` — origin validated against registered `redirect_uris` | PASS — no wildcard, client-based allowlist |
| Cookie flags | `src/protocol/web/auth.rs:344` — `HttpOnly; SameSite=Lax{secure_attr}` | PASS — HttpOnly, Secure (TLS-conditional), SameSite=Lax on all sensitive cookies |
| CSRF | Double-submit pattern; token echoed via `_csrf` field or `X-CSRF-Token` header | PASS — stateless CSRF defense |
| Rate limiting | `src/identity/engine.rs:199-202`, `src/protocol/admin_auth.rs:27,81` | PASS — per-IP, per-user, per-email across all auth endpoints |
| TLS | `src/protocol/tls.rs`, `rustls = "0.23"` | PASS — rustls with modern defaults (ECDHE + AEAD); mTLS for cluster |
| No SQL injection | Key-value store (redb), no raw SQL anywhere | PASS |
| Audit log sanitization | `src/audit/types.rs` — schema-enumerated actions, no PII logged | PASS |
| Security headers | `src/protocol/web/security.rs:80-112` — X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS | PASS |
| Admin gRPC auth coverage | `src/protocol/grpc/auth.rs:38` — `authenticate_admin` called on every handler | PASS (auth enforced; see GAP-1 for scope issue) |

---

## Findings Summary

| ID | Class | Severity | File:Line | Status |
|---|---|---|---|---|
| GAP-1 | BFLA — realm management cross-tenant scope | Medium | `grpc/identity.rs:182,197,213,235,254` | Open |
| GAP-2 | Information disclosure — gRPC internal error strings | Medium | `grpc/audit.rs:38,53,59`, `grpc/identity.rs:227` | Open |
| GAP-3 | Argon2id default below OWASP 2023 minimum | Medium | `credentials.rs:118` | Open |
| GAP-4 | CSP `unsafe-eval` — Alpine.js architectural debt | Low | `web/security.rs:98` | Open |

**No critical vulnerabilities found.** The cryptographic foundation (Ed25519,
Argon2id, ring, rustls, subtle, zeroize) is correctly implemented. Remediation of
GAP-1 and GAP-2 is recommended before multi-tenant production deployment. GAP-3
is a one-line config change. GAP-4 is medium-term architectural work.
