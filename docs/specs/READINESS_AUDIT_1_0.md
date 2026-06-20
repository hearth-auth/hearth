# Hearth 1.0 Readiness Audit

**Date:** 2026-06-08  
**Scope:** Production readiness assessment; Keycloak and Auth0 feature-parity gap analysis  
**Status:** Planning document — not a changelog entry

---

## Executive Summary

Hearth is production-ready for the **majority of greenfield auth use cases** today. Its OIDC/OAuth 2.0 stack is more standards-complete than Keycloak and Auth0 in several dimensions (FAPI 2.0, DPoP, PAR, JAR, JARM, Ed25519-only signing). The authentication method suite — password, TOTP, WebAuthn/Passkeys, SMS OTP, magic link, SAML 2.0 SP, OIDC social — is genuinely competitive.

However, it is **not yet a drop-in replacement** for Keycloak in enterprise LDAP/AD environments, for Auth0 in high-customization no-code deployments, or for any provider in agentic/AI workload scenarios. Five critical gaps currently block that claim.

---

## 1. What Hearth Ships Today (Confirmed in Source)

### 1.1 Identity & Authentication

| Feature | Status | Notes |
|---------|--------|-------|
| Password auth + Argon2id | ✅ | OWASP-compliant params; per-realm override; auto-rehash on login |
| TOTP / MFA | ✅ | TOTP + recovery codes; enrollment + brute-force lockout |
| WebAuthn / Passkeys (FIDO2) | ✅ | Level 2 conformance; multi-credential; resident keys; attestation |
| SMS OTP | ✅ | Twilio, AWS SNS, generic HTTP transport; per-realm MFA method config |
| Magic Link / Passwordless | ✅ | Single-use, expiring; account creation on unknown email |
| SAML 2.0 SP federation | ✅ | SP-initiated SSO, SLO, ACS, XML parsing with fuzz coverage |
| OIDC social login | ✅ | Generic OIDC connector + GitHub OAuth2 preset |
| OAuth consent screen | ✅ | Per-(user, client) consent record; re-consent on scope change |
| Required-action intercept | ✅ | Pre-login gates: MFA enrollment, ToS, password reset |
| RP-Initiated Logout 1.0 | ✅ | With back-channel fan-out to registered RPs |
| Account self-service UI | ✅ | `account.rs`, `account_consents.rs`, `account_linked.rs` |

### 1.2 OAuth 2.0 / OIDC Protocol Stack

| Spec | Status |
|------|--------|
| OAuth 2.0 (RFC 6749) | ✅ |
| PKCE — S256 mandatory (RFC 7636) | ✅ |
| OIDC Core 1.0 | ✅ |
| OIDC Discovery 1.0 | ✅ |
| Dynamic Client Registration (RFC 7591/7592) | ✅ |
| Token Introspection (RFC 7662) | ✅ |
| Token Revocation (RFC 7009) | ✅ |
| Device Authorization Grant (RFC 8628) | ✅ |
| Pushed Authorization Requests — PAR (RFC 9126) | ✅ |
| JWT Authorization Requests — JAR (RFC 9101) | ✅ |
| JWT Auth Response Mode — JARM | ✅ |
| JWT Profile for Access Tokens (RFC 9068) | ✅ |
| DPoP / Proof-of-Possession (RFC 9449) | ✅ |
| ASI Issuer Identification (RFC 9207) | ✅ |
| OAuth 2.0 Token Exchange (RFC 8693) | ✅ foundations |
| FAPI 2.0 Baseline + Advanced | ✅ realm-level + per-client |

### 1.3 Authorization

| Feature | Status |
|---------|--------|
| Claims-based RBAC (roles, groups, permissions) | ✅ |
| Role composition (parent-role chains) | ✅ |
| Group nesting (transitive, cycle-detected) | ✅ |
| Org-scoped role assignments | ✅ |
| Token delivery: embedded / introspection / decision modes | ✅ |
| Session-version (sv) revocation for near-real-time invalidation | ✅ |
| YAML-declarative role/permission/scope config | ✅ |

### 1.4 Multi-Tenancy & Organizations

| Feature | Status |
|---------|--------|
| Realm isolation (per-realm signing keys, storage, config) | ✅ |
| B2B Organizations (invitations, memberships, owner protection) | ✅ |
| Cascading deletion (realm → all entities) | ✅ |
| Cross-realm admin targeting | ✅ |

### 1.5 Provisioning & Integration

| Feature | Status |
|---------|--------|
| SCIM 2.0 (Users + Groups) | ✅ |
| Admin REST API | ✅ |
| Admin gRPC API | ✅ |
| OpenAPI spec | ✅ |
| Webhooks | ✅ |
| Backup / export / import | ✅ |
| Keycloak realm export migration | ✅ PBKDF2 credential translation + role mapping |

### 1.6 Infrastructure & Security

| Feature | Status |
|---------|--------|
| TLS 1.3 with hot-reload | ✅ |
| mTLS | ✅ |
| Raft multi-node clustering | ⚠️ See Gap #1 |
| WAL storage engine (fsync, crash-safe) | ✅ |
| Audit log (append-only, SHA-256 hash chain) | ✅ |
| Security headers (CSP, X-Frame-Options, etc.) | ✅ |
| CORS on token endpoints | ✅ |
| Per-(realm, client) token endpoint rate limiting | ✅ |
| CSRF protection on login endpoints | ✅ (HEA-1318 on current branch) |
| Ed25519 signing only (no HS256, no `alg:none`) | ✅ |
| Argon2id password hashing (no bcrypt) | ✅ |
| Metrics / telemetry | ✅ `src/metrics.rs` |

### 1.7 SDKs

| SDK | Status |
|-----|--------|
| TypeScript / JavaScript | ✅ |
| Go | ✅ |
| PHP | ✅ |
| Kotlin / Android | ✅ |
| Python | ✅ |
| Rust | ✅ |

### 1.8 UI

| Feature | Status |
|---------|--------|
| Admin console (users, realms, RBAC, IdPs, audit) | ✅ |
| Dark-mode-only themed UI (6 named themes, `branding.theme`) | ✅ |
| Per-realm CSS override (`custom_css`) | ✅ |
| Login / MFA / OAuth consent flows | ✅ |
| Self-service account UI (linked accounts, consents) | ✅ |

---

## 2. Critical Gaps (Block "Drop-In Replacement" Claim)

### Gap C-1: Raft Cluster Operational Readiness

**Severity:** Critical for HA deployments

**Evidence:** A 2026-05-24 audit found Raft, cluster sims, and the hot-path were "checkbox-complete but operationally unreachable" — tests passed but the code paths could not be exercised in production. While simulation and unit tests pass, there is no evidence of a successful 3-node cluster surviving a leader failover under real load, node restart, or network partition recovery.

**Impact:** Any customer deploying Hearth with HA requirements (virtually all production deployments) cannot rely on the clustering story. Single-node deployments are safe; multi-node deployments carry unknown operational risk.

**Path to resolution:**
1. Run an operational validation: spin a 3-node cluster, inject leader failure, verify read/write continuity through failover.
2. Add a chaos test in CI that kills the leader mid-write-sequence and verifies the cluster reaches consistency.
3. Document the operational minimum (TLS certs, node IDs, peer addresses) in a "Clustering Operations" guide.
4. Add a `make cluster-smoke` target.

**Estimated effort:** 1–2 sprint cycles (investigation + remediation).

---

### Gap C-2: LDAP / Active Directory User Federation

**Severity:** Critical for enterprise Keycloak replacement

> **Status update (2026-06-19, PR #161):** The LDAP connector module is **implemented** — `src/identity/ldap/` ships a full `EmbeddedLdapConnector` with user search, attribute mapping, password-bind auth, delta sync (`ModifyTimestamp` and `uSNChanged`/AD strategies), RFC 4515 filter injection prevention, and LDAPS enforcement. The implementation is complete at the domain layer.

> **Remaining gap:** The connector is not yet wired to the operator-facing configuration or HTTP API. `LdapConfig` is not exposed in `src/config/types.rs` / `FederationProviderYaml`, and the connector has no admin API surface. The estimated effort to complete wiring is 1–2 days; the hard implementation work is done.

**Evidence (original, now stale):** No `ldap` module anywhere in `src/`. No LDAP sync adapter, no AD/Kerberos support.

**Impact:** The majority of enterprise Keycloak customers use Keycloak as a front-door for corporate Active Directory or OpenLDAP. Without LDAP federation, these customers cannot migrate to Hearth — users would need to be manually migrated or re-registered.

**Affected use cases:**
- Corp SSO / internal tools (Okta/Keycloak + AD pattern)
- University/government deployments where LDAP is the source of truth
- Any "sync from HR system" pipeline using LDAP as the interface

**Remaining path to production:**
1. Wire `LdapConfig` into `FederationProviderYaml` (`src/config/types.rs`) as a new `kind: ldap` federation provider.
2. Add admin API endpoints for creating/updating LDAP connector config per realm.
3. Start the sync background task at server init when a realm has an LDAP connector configured.
4. Expose `GET /admin/realms/{id}/ldap/status` for sync health checks.

*(Original estimated effort was 4–6 weeks; connector implementation is done, leaving ~1–2 days for wiring.)*

**Estimated effort:** 4–6 weeks (substantial — LDAP parsing, attribute mapping, sync engine).

---

### Gap C-3: Extensible Authentication Pipeline (Custom Actions / Flows)

**Severity:** Critical for Auth0 replacement in customized deployments

**Evidence:** Hearth's auth pipeline is a fixed code path. There is no hook/plugin/action system to inject custom logic (e.g., call an external enrichment API, block users from specific companies, enforce custom MFA logic, add custom claims).

**Impact:**
- Auth0 customers using "Actions" (formerly Rules/Hooks) — cannot migrate without rewriting their logic into application-layer middleware.
- Keycloak customers using custom SPIs, required-action providers, or protocol mappers for custom claim injection — blocked.

**What's in-scope for 1.0 vs. future:**
A full plugin/SPI system is likely out of scope for 1.0. However, a minimal set of escape hatches would unblock most customers:

**Path to resolution (pragmatic 1.0 scope):**
1. **Webhook-based pre-token hook:** Before issuing tokens, POST to a configured URL with user/session context; if the response includes extra claims, merge them into the token. (Low risk, high value.)
2. **Custom claim mapping via declarative config:** YAML-based `claim_profiles` (already specced in `AUTHZ_EXPANSION.md`) — ensure this is fully shipped for 1.0.
3. **External enrichment on federation callback:** On successful social/SAML login, allow configuration of an enrichment URL to augment user attributes before session creation.

**Full extensible action system** (eval at 1.1+): webhooks with synchronous response, script execution sandbox, or OPA/Rego integration.

**Estimated effort:** Pragmatic escape hatches — 2–3 weeks. Full action system — 8+ weeks.

---

### Gap C-4: Agent Auth Entity (AGENT_AUTH.md)

**Severity:** Critical for Hearth's own differentiation story; not a Keycloak/Auth0 parity gap

**Evidence:** `AGENT_AUTH.md` explicitly documents this: DPoP and token exchange are shipped; the Agent entity, Agent CRUD, Agent Cards, delegation chains, AATs, MCP surfaces, and approval lifecycle are **not implemented**.

**Impact:**
- Hearth's stated differentiator over Keycloak/Auth0 is first-class AI-agent identity. Without the Agent entity shipped, this advantage does not exist.
- Customers building agentic applications today have no path to use Hearth for agent identity; they fall back to client credentials (service accounts), losing the delegation and audit capabilities that distinguish Hearth.

**Path to resolution:** `AGENT_AUTH.md` is a complete spec. The build order is:
1. `AgentId` newtype + CRUD + lifecycle (`Active → Suspended → Revoked`) — `src/identity/agents.rs`.
2. Agent Card discovery endpoint.
3. Delegation chains + scope attenuation (AATs).
4. MCP/A2A surface (can ship as a separate Phase).
5. Human-in-the-loop approval lifecycle (can ship as a separate Phase).

**Estimated effort:** Agent entity + basic delegation — 4–6 weeks. Full MCP/AAT/approval — additional 6–10 weeks.

---

### Gap C-5: Additional Social Login Presets

**Severity:** Moderate-to-critical for Auth0 parity in B2C contexts

**Evidence:** Only GitHub OAuth2 and generic OIDC connectors exist in `src/identity/federation/`. Auth0 ships 50+ pre-wired social connectors with correct scopes, logo assets, user-profile normalization, and refresh-token handling.

**Missing first-tier connectors:**
- **Apple Sign In** — requires non-standard `private_key_jwt` client auth, `form_post` response, first-name/last-name passed only on first login. Cannot be covered by generic OIDC without custom code.
- **Google** — generic OIDC covers it technically, but Google's token revocation, Workspace domain hints, and account-chooser flow need tested presets.
- **Microsoft / Azure AD (OIDC)** — tenant ID in issuer URL is non-standard; requires explicit preset.
- **Discord, Slack, LinkedIn, Spotify, Twitter/X** — popular in B2C apps; all require OAuth2 quirk handling.

**Path to resolution:**
1. Apple Sign In — implement `AppleConnector` with `private_key_jwt` client auth and first-login name extraction. (Highest priority — cannot be covered generically.)
2. Google, Microsoft, GitHub already — verify existing OIDC preset covers them; add preset configs with documentation.
3. Create a `presets.rs`-driven registry (already exists partially) covering top-10 social providers with pre-filled scopes, logo URIs, and attribute normalizations.

**Estimated effort:** Apple — 1 week. Full top-10 presets — 3–4 weeks.

---

## 3. Medium Gaps (Important Before Calling It "Complete")

### Gap M-1: Auth0 / Okta / Azure AD Migration Tooling

Only Keycloak export import is implemented. Customers on Auth0, Okta, AWS Cognito, or Azure AD B2C have no migration path.

**Path:** Add `hearth migrate auth0 --file export.json` (Auth0 Management API export format). Auth0 exports are JSON; user records include bcrypt hashes that can be translated similarly to the Keycloak PBKDF2 path. Estimated: 2–3 weeks per provider.

---

### Gap M-2: Administrative Role Granularity

Hearth uses a single `hearth.admin` permission for all realm administration. Keycloak offers fine-grained admin roles (`manage-users`, `view-clients`, `manage-realm`, etc.) allowing delegation of specific admin capabilities to sub-admins.

**Path:** Add `hearth.users.admin`, `hearth.clients.admin`, `hearth.realm.admin` as distinct permissions enforced on specific admin endpoints. Admin `realm.admin` role grants all; operators can create narrower roles. Estimated: 2 weeks.

---

### Gap M-3: IP-Based Rate Limiting and Allow/Deny Lists

> **Status update (2026-06-07, PR #155 — abuse prevention):** Several IP-level controls shipped. See `docs/specs/CONFIGURATION.md §security` for full reference.

**What is now shipped:**
- `security.ip_reputation` — Spamhaus DROP/EDROP IPv4/IPv6 blocklist; MaxMind GeoLite2-ASN integration; configurable action: `block` / `challenge` / `log`.
- `security.request_shaper` — global per-IP token-bucket rate limiter (`ip_rps`, default 100 req/s).
- `security.rate_limiting.login_per_ip` — per-IP failed-login sliding window with configurable threshold and lockout.
- `security.allowed_hosts` — Host header allowlist (DNS rebinding protection).
- `security.jwks_rps_limit` — per-IP rate cap on JWKS/discovery endpoints.

**Remaining gap:** CIDR-notation support for allowlists and blocklists is not yet present — only individual IPs are accepted. Operators can delegate CIDR-level controls to a reverse proxy (nginx, Caddy, Cloudflare) as documented in `docs/guides/security-hardening.md`.

---

### Gap M-4: Breached Password Detection

> **Status update (2026-06-07):** Partially shipped — offline corpus checker is implemented; online HIBP API is implemented but not yet operator-configurable via `hearth.yaml`.

**What is shipped:**
- `src/identity/breach_corpus.rs` — offline breach checker using a local memory-mapped binary corpus (HIBP SHA-1 sorted export). Loaded at startup; freshness checked via `max_corpus_age_days`.
- `BreachCheckConfig` (runtime `RealmConfig`) — HIBP k-anonymity Range API client with configurable timeout and optional API key. Fails-open on timeout with audit event.

**Remaining gap:** `breach_check` is not yet exposed as a `hearth.yaml` realm config field. The HIBP API client is wired at the domain layer but has no YAML counterpart and cannot be enabled without code changes. Creating a `realms.<name>.auth.breach_check` config key is a small YAML-to-domain mapping task (estimated: 1–2 days).

---

### Gap M-5: Internationalization (i18n) of Login/Account UI

Auth0 and Keycloak ship translated login pages for 20+ locales. Hearth's UI templates are English-only with no i18n infrastructure.

**Path:** Add `lang` attribute negotiation, extract all user-facing strings into per-locale JSON bundles, render via Askama locale selection. Community-contributed translations. Estimated: 2–3 weeks for infrastructure; translation effort is ongoing.

---

### Gap M-6: Email OTP (Short Code via Email as 2nd Factor)

Magic Link (single-use URL) is implemented. A 6-digit numeric OTP sent via email — as a second factor distinct from magic link — is not clearly present as an MFA type.

**Path:** Add `email_otp` as an MFA method: generate 6-digit CSPRNG code, store with TTL, deliver via existing `EmailService`, validate at `POST /mfa/challenge`. Leverages existing SMS OTP infrastructure. Estimated: 1 week.

---

### Gap M-7: iOS (Swift) and React Native SDKs

Kotlin (Android), TypeScript, Go, PHP, Python, and Rust SDKs are present. Swift/iOS and React Native are absent.

**Path:** Swift SDK using `URLSession` + `CryptoKit` for JWKS verification. React Native wrapper around the TypeScript SDK with Expo compatibility. These are customer-visible gaps for mobile-first companies. Estimated: 2–3 weeks each.

---

### Gap M-8: Conditional / Per-Client MFA Enforcement

Hearth supports enabling MFA methods per realm. However, requiring MFA only for specific clients (e.g., admin console requires TOTP, regular app does not) or based on role (only users with `hearth.admin` must complete MFA) is not clearly implemented.

**Path:** Add `mfa_required: true` to client registration; add `mfa_required_roles: ["realm.admin"]` to realm config. The required-action intercept already has the hook point. Estimated: 1 week.

---

### Gap M-9: Kerberos / SPNEGO

Enterprise Windows SSO via GSSAPI/Kerberos is present in Keycloak. Not in Hearth. This is a niche requirement but a hard blocker for some Windows-shop enterprise Keycloak migrations.

**Path:** Implement SPNEGO token validation in a federation connector. Significant complexity; likely a 1.1+ item. For 1.0, document as a known gap and recommend Keycloak as a Kerberos front-door that federates into Hearth via SAML/OIDC.

---

## 4. Minor Gaps (Polish and Ecosystem)

| Gap | Severity | Quick Path |
|-----|----------|-----------|
| Front-Channel OIDC Logout verification | Low | Add conformance test for `frontchannel_logout_uri` |
| OpenTelemetry trace export (OTLP) | Low | Wire `metrics.rs` to OTLP exporter; Jaeger/Tempo compat |
| SIEM export (audit log → Splunk/Elastic) | Low | Audit webhook or structured log format doc |
| PAR endpoint `expires_in` configurability | Low | Already per-spec default; expose as config key |
| WebAuthn Level 3 / Conditional UI (passkey autofill) | Medium | Add `mediation: conditional` to registration/auth ceremonies |
| Custom logo / favicon in login UI | Low | Add `branding.logo_url` and `branding.favicon_url` config |
| Helm chart / Kubernetes operator | Medium | Community contribution target; document Docker image build |
| Docker official image + compose example | Medium | `Dockerfile`, `docker-compose.yml` in repo root |
| Admin audit trail export (CSV/JSON download) | Low | Add `GET /admin/audit?format=json&since=...` streaming export |

---

## 5. Design Decisions That Differ from Keycloak/Auth0 (Not Gaps)

These are intentional design choices where Hearth diverges from the competition. Customers migrating need to understand these up-front.

| Decision | Hearth | Keycloak/Auth0 | Rationale |
|----------|--------|----------------|-----------|
| JWT signing algorithm | Ed25519 only | RS256 default; configurable | Smaller keys, no padding oracle, faster verification. Client SDKs must support EdDSA. |
| Authorization model | Claims-based RBAC (flat permissions in JWT) | Keycloak: fine-grained policies + UMA 2.0; Auth0: metadata + rules | Hearth explicitly does not own per-object ACLs. Apps compose Hearth claims with their own data models. |
| Auth pipeline extensibility | Config-driven + webhook escape hatch (planned) | Keycloak: SPI / provider framework; Auth0: Actions | Reduces attack surface; extension logic runs outside the auth server |
| Realm vs Tenant | Realm = strict isolation boundary | Keycloak Realm ≈ same; Auth0 "tenant" is the whole account | Aligned with Keycloak; cleaner than Auth0's model |
| Token issuance architecture | Permissions embedded at issuance; zero-network on hot path | Both require introspection or claim lookup for fresh data | Hearth's explicit trade-off: stale-by-TTL vs. network-free hot path. Mitigated by `sv` claim for revocation. |

---

## 6. Overall Readiness Verdict

| Dimension | Rating | Notes |
|-----------|--------|-------|
| OIDC/OAuth 2.0 standards completeness | **Exceeds** Keycloak/Auth0 | FAPI 2.0, DPoP, PAR, JAR, JARM all implemented |
| Greenfield B2C/B2B SaaS | **Ready** | Full MFA suite, organizations, RBAC, social login |
| Enterprise Keycloak migration | **Partial** | Blocked on LDAP/AD federation (C-2) |
| Auth0 no-code/low-code replacement | **Partial** | Blocked on extensible pipeline (C-3) and social presets (C-5) |
| AI-agent / agentic workloads | **Not ready** | Agent entity not implemented (C-4); DPoP/token-exchange foundation only |
| High-availability multi-node | **Unverified** | Raft implementation needs operational validation (C-1) |
| Single-node production | **Ready** | Stable, crash-safe, auditable |

**Recommendation for 1.0 scope:** Ship five focused work streams in parallel:
1. **Raft operational validation** (C-1) — block 1.0 release on passing cluster smoke test
2. **Apple Sign In connector** (C-5) — 1 week, high customer impact
3. **Agent entity (Phase 1)** (C-4) — entity CRUD + basic delegation; full AAT/MCP in 1.1
4. **Pre-token webhook hook** (C-3) — minimum viable extensibility for Auth0 migrators
5. **Auth0 migration importer** (M-1) — expands addressable market

LDAP/AD (C-2) is the right 1.1 investment — large surface area, and the SAML/OIDC workaround (Keycloak as LDAP front-door, federating into Hearth) is a documented migration path that unblocks most customers today.

---

## 7. Suggested Child Issues

| Issue Title | Gap | Priority |
|-------------|-----|----------|
| HEA-XXXX: Raft cluster operational smoke test + chaos validation | C-1 | P0 for 1.0 |
| HEA-XXXX: Apple Sign In connector | C-5 | P0 for 1.0 |
| HEA-XXXX: Pre-token enrichment webhook | C-3 | P0 for 1.0 |
| HEA-XXXX: Agent entity CRUD + delegation phase 1 | C-4 | P0 for 1.0 |
| HEA-XXXX: Auth0 realm export migration | M-1 | P1 for 1.0 |
| HEA-XXXX: Admin role granularity (manage-users vs manage-realm) | M-2 | P1 for 1.0 |
| HEA-XXXX: Conditional MFA enforcement per client/role | M-8 | P1 for 1.0 |
| HEA-XXXX: Email OTP as distinct MFA type | M-6 | P1 for 1.0 |
| HEA-XXXX: i18n login UI infrastructure | M-5 | P2 / 1.1 |
| HEA-XXXX: iOS (Swift) SDK | M-7 | P2 / 1.1 |
| HEA-XXXX: LDAP/Active Directory user federation | C-2 | P1 for 1.1 |
| HEA-XXXX: Docker image + Kubernetes Helm chart | Minor | P2 / 1.1 |
