# PM Feature-Parity Backlog vs Keycloak / Auth0

**Author:** ProductManager  
**Date:** 2026-05-25  
**Parent audit:** [HEA-720](/HEA/issues/HEA-720) — Production Readiness Audit v2  
**Source audit:** [HEA-767](/HEA/issues/HEA-767) — Feature Parity Re-Audit + [HEA-828](/HEA/issues/HEA-828) scope  
**Scope:** Parity gaps **not** covered by P0 blockers B1–B4 or existing P1 issues (HEA-822 – HEA-827).

---

## 1. Already Resolved — Excluded from This Backlog

The following gaps from the HEA-767 audit have since closed:

| Was | Resolution |
|---|---|
| B1 — Browser login bypasses required-action gates | Fixed in HEA-801-815 + HEA-765/820 (commits `8ed36a9`, `dcc29cf`) |
| Gap 3.5 — Required Actions framework in OIDC flow | Same as above; full RA domain + gate + UI interstitials landed |
| B3 — No signed release pipeline | Fixed via HEA-782 (commit `d6533e5`) |

---

## 2. Gap Inventory

All gaps are RICE-scored (Reach × Impact × Confidence ÷ Effort-in-weeks). Higher = more ROI per engineering week.

| Rank | ID | Gap | Severity | MoSCoW | Effort (wks) | RICE | Owner |
|---|---|---|---|---|---|---|---|
| 1 | G-01 | SMS / Phone MFA | 🟠 HIGH | Should | 2 | 189 | CTO → Engineer |
| 2 | G-02 | Adaptive MFA / breach-check (HaveIBeenPwned) | 🟠 HIGH | Should | 2 | 160 | CTO → Engineer |
| 3 | G-03 | Client scopes admin UI completeness | 🟡 MEDIUM | Should | 2 | 135 | Engineer |
| 4 | G-04 | SDK language coverage — Python | 🟡 MEDIUM | Could | 3 | 126 | Engineer / DevRel |
| 5 | G-05 | Log stream destinations (Datadog, Splunk) | 🟡 MEDIUM | Could | 2 | 113 | Engineer |
| 6 | G-06 | LDAP / AD user federation | 🔴 CRITICAL | Must | 6 | 96 | CTO (options doc: HEA-744 ✓) |
| 7 | G-07 | Fine-grained admin delegation (realm-management roles) | 🟠 HIGH | Should | 4 | 84 | CTO → Engineer |
| 8 | G-08 | MFA enrollment policies (group/role-gated) | 🟢 LOW | Could | 3 | 67 | Engineer |
| 9 | G-09 | IdP broker first-login flow configuration | 🟡 MEDIUM | Could | 4 | 60 | Engineer |
| 10 | G-10 | Auth0 migration — Rules/Actions/Hooks stubs | 🟡 MEDIUM | Could | 4 | 53 | Engineer (blocked on G-11) |
| 11 | G-11 | Custom in-flow extensibility (Pipeline / Actions) | 🔴 CRITICAL | Must | 10 | 38 | CTO (arch approval needed) |
| 12 | G-12 | Authentication policies / conditional access | 🟠 HIGH | Should | 8 | 31 | CTO → Engineer |
| 13 | G-13 | Localization / i18n of login pages | 🟢 LOW | Could | 4 | 36 | Engineer |
| 14 | G-14 | Push notification MFA (Duo / Authenticator push) | 🟢 LOW | Won't | — | — | N/A — passkeys supersede |

*RICE denominator = effort in weeks. Scores normalized for comparison only.*

---

## 3. Gap Detail (Ranked by RICE)

### G-01 — SMS / Phone MFA
**Rank:** 1 · **RICE:** 189 · **Effort:** ~2 weeks · **MoSCoW:** Should

**Problem:** Enterprise procurement checklists frequently require SMS OTP as a fallback MFA factor for legacy scenarios (device management restrictions, user segments without smartphones). Both Keycloak (SMS SPI) and Auth0 (native) provide this. Hearth has TOTP and Passkeys but no SMS delivery path.

**Evidence of absence:** `grep -rn 'sms\|twilio\|aws.sns' src/ --include="*.rs"` — zero production hits. Phone claim exists in `src/identity/claims_config.rs:307` but has no delivery infrastructure.

**Kano classification:** Basic (parity) — expected by enterprise buyers; not a differentiator.

**Acceptance criteria:**

> **Given** a realm admin has configured an SMS transport (Twilio or AWS SNS) in `hearth.yaml` under `sms:`  
> **When** a user with SMS MFA enrolled completes primary credential entry  
> **Then** Hearth sends a 6-digit OTP to the user's verified phone number, the MFA challenge screen accepts it within a configurable window, and an incorrect code is rejected with rate-limit enforcement after N attempts.

> **Given** a user with no phone number on file  
> **When** an admin policy requires SMS MFA  
> **Then** the OIDC flow interrupts with a required-action screen prompting phone-number enrollment before access token issuance.

**Out of scope:** Push notification MFA; WhatsApp delivery; carrier lookup.

**Routing:** CTO for architecture sign-off (transport abstraction alongside email transports), then Engineer for implementation.

---

### G-02 — Adaptive MFA / Breach-Check (HaveIBeenPwned)
**Rank:** 2 · **RICE:** 160 · **Effort:** ~2 weeks · **MoSCoW:** Should

**Problem:** Auth0's Attack Protection includes breached-password detection and risk-based step-up MFA. Hearth has static per-user / per-IP lockout (`src/identity/engine.rs:205–218`) but no contextual risk signals. An account whose password appears in a known breach is indistinguishable from a secure account.

**Evidence of absence:** `grep -rn 'haveibeenpwned\|hibp\|breach' src/` — zero hits.

**Kano classification:** Performance (more = better security) — differentiates Hearth vs Keycloak in security marketing.

**Acceptance criteria (breach-check phase — 1 week):**

> **Given** a user sets or changes a password  
> **When** Hearth evaluates the credential  
> **Then** it queries the HIBP k-anonymity API (first 5 SHA-1 chars of the password hash) with no full hash disclosure, and rejects the password if it appears in a breach dataset, returning a specific `password_compromised` error code the UI surfaces.

> **Given** the HIBP API is unreachable (timeout > 2 s)  
> **When** a user sets a password  
> **Then** the password is accepted and a non-blocking warning is logged; breach-check failure MUST NOT block legitimate password changes.

**Acceptance criteria (step-up MFA phase — 1 week):**

> **Given** a login originates from an IP or device not seen in the past 30 days for this user  
> **When** the user completes primary credential entry  
> **Then** an additional MFA challenge is triggered regardless of the user's standing MFA policy.

**Out of scope:** ML-based risk scoring; real-time IP reputation feeds; full bot detection.

**Routing:** CTO for API integration design (k-anonymity, offline vs online), then Engineer.

---

### G-03 — Client Scopes Admin UI Completeness
**Rank:** 3 · **RICE:** 135 · **Effort:** ~2 weeks · **MoSCoW:** Should

**Problem (specific to HEA-828 scope):** Keycloak has a first-class "Client Scopes" concept — named bundles of claims and permissions that can be assigned to OAuth clients as *default* (always included) or *optional* (included when requested). Hearth has RBAC scopes (`/admin/realms/{realm}/rbac/scopes`) but no per-client scope assignment UI, no `default_scopes` / `optional_scopes` model on OAuth clients, and no admin UI page at `/admin/realms/{realm}/clients/{id}/scopes`.

**Evidence of absence:** 
- `grep -n 'ClientScope\|client_scope' src/identity/types.rs` — zero hits.
- No route matching `clients/{id}/scopes` in `src/protocol/web/mod.rs`.
- OAuth client admin UI (`admin/clients`) shows client metadata but no scope-assignment tab.

**Kano classification:** Basic (parity) — any Keycloak operator expects per-client scope control.

**Acceptance criteria:**

> **Given** an OAuth client exists in a realm  
> **When** an admin visits `/admin/realms/{realm}/clients/{id}/scopes`  
> **Then** they see two lists: *Default Scopes* (included automatically in every token) and *Optional Scopes* (included when the client requests them); they can add/remove realm-defined RBAC scopes from each list.

> **Given** a client has `profile` in optional scopes but not default  
> **When** an authorization request omits `scope=profile`  
> **Then** the issued access token does not contain profile claims; when `scope=profile` is included, the token does.

**Out of scope:** Consent-screen scope display customization; scope inheritance across clients.

**Routing:** Engineer (frontend + identity engine extension); UXDesigner for tab layout review.

---

### G-04 — SDK Language Coverage — Python
**Rank:** 4 · **RICE:** 126 · **Effort:** ~3 weeks · **MoSCoW:** Could

**Problem:** Auth0 has 10+ language SDKs. Hearth ships TypeScript and Go only. Python is the highest-value missing language given ML/data engineering adoption and FastAPI/Django ecosystems.

**Evidence:** `ls sdks/` — `typescript/`, `go/` only.

**Routing:** DevRel to spec the API surface; Engineer to implement; QA to add smoke tests mirroring TypeScript/Go suites.

---

### G-05 — Log Stream Destinations (Datadog / Splunk / EventBridge)
**Rank:** 5 · **RICE:** 113 · **Effort:** ~2 weeks · **MoSCoW:** Could

**Problem:** Auth0's Log Streams push real-time events to Datadog, Splunk, Sumo Logic, Segment, and AWS EventBridge. Hearth's webhook engine covers generic HTTP delivery but lacks named destination presets with templated payloads and retry semantics tuned per-destination.

**Routing:** Engineer. No PRD required; extend `src/webhook/` with named destination presets.

---

### G-06 — LDAP / Active Directory User Federation
**Rank:** 6 · **RICE:** 96 · **Effort:** 6–8 weeks · **MoSCoW:** Must

**Problem:** Keycloak's most-used enterprise feature. AD/LDAP environments expect a continuous-sync model (Hearth queries the directory, not the reverse). SCIM is push-based and does not replace this. Without LDAP federation, Hearth cannot be sold as a Keycloak drop-in for enterprises on Microsoft infrastructure.

**Evidence of absence:** `grep -rn 'ldap\|LDAP' src/` — zero production hits.

**Status:** Options document completed via [HEA-744](/HEA/issues/HEA-744). Implementation not started. Next action: engineering spike for protocol-level LDAP read-sync, assigned to CTO.

**Routing:** CTO to own architecture; PM to write PRD once CTO approves approach from options doc.

---

### G-07 — Fine-Grained Admin Delegation (Realm-Management Roles Parity)
**Rank:** 7 · **RICE:** 84 · **Effort:** ~4 weeks · **MoSCoW:** Should

**Problem (specific to HEA-828 scope):** Keycloak ships a built-in `realm-management` client with granular sub-roles: `manage-users`, `view-users`, `manage-clients`, `view-clients`, `manage-realm`, `manage-events`, `manage-identity-providers`, `impersonation`, and more. Service accounts or delegated admins can be assigned exactly the sub-roles they need without receiving full realm-admin access.

Hearth's RBAC assigns a single `admin` role at the realm level. There is no sub-role model for delegating read-only user views, client management, or audit access independently.

**Evidence of absence:** `grep -n 'realm.management\|manage.users\|manage.clients' src/identity/mod.rs` — only a Phase 1 comment; no struct or role definitions matching this pattern.

**Kano classification:** Performance — enterprise customers with compliance requirements (SOD — separation of duties) will require this.

**Acceptance criteria:**

> **Given** a realm has a service account or user assigned the `view-users` sub-role but not `manage-users`  
> **When** that principal calls `GET /admin/users`  
> **Then** it receives a 200 with the user list; when it calls `POST /admin/users` or `DELETE /admin/users/{id}`, it receives 403.

> **Given** a realm admin assigns `manage-clients` to a developer account  
> **When** that account calls admin client CRUD endpoints  
> **Then** all client operations succeed and all other admin areas (users, audit, realm settings) return 403.

**Out of scope:** Cross-realm admin delegation; admin UI for sub-role assignment (Phase 2).

**Routing:** CTO for RBAC model extension design; Engineer for implementation; PM to write full PRD once CTO approves model.

---

### G-08 — MFA Enrollment Policies (Group/Role-Gated)
**Rank:** 8 · **RICE:** 67 · **Effort:** ~3 weeks · **MoSCoW:** Could

**Problem:** Keycloak and Auth0 support "require MFA for users in group X" or "require MFA for admin role." Hearth has per-user MFA but no policy engine that mandates enrollment at token issuance based on group membership or role assignment.

**Note:** Partially covered by Required Actions (users can have `CONFIGURE_TOTP` as a required action). Full policy-based enforcement (automatically applying RA to users who join a group) is not implemented.

**Routing:** Engineer. Extends required-actions + RBAC intersection.

---

### G-09 — IdP Broker First-Login Flow Configuration
**Rank:** 9 · **RICE:** 60 · **Effort:** ~4 weeks · **MoSCoW:** Could

**Problem (specific to HEA-828 scope):** Keycloak's "First Broker Login" flow is a configurable sequence that runs when a user authenticates via an external IdP for the first time: detect existing local account by email, prompt for link confirmation, optionally require profile completion, enforce required actions for new accounts. Hearth has `IdpKind::Auto` vs `IdpKind::Confirm` enum variants but no configurable flow per IdP that handles the email-clash / account-linking decision policy.

**Evidence of absence:** `grep -rn 'first.broker\|first_broker' src/` — zero hits.

**Routing:** CTO for design; Engineer for implementation. Not PM-specifiable until CTO defines the flow model.

---

### G-10 — Auth0 Migration — Rules/Actions/Hooks Import Stubs
**Rank:** 10 · **RICE:** 53 · **Effort:** ~4 weeks (blocked on G-11) · **MoSCoW:** Could

**Problem:** Auth0 deployments using Rules or Actions (estimated 60–70% of production Auth0 tenants) have logic gaps post-migration. The current importer excludes them (`src/identity/migration/auth0.rs:40`).

**Blocked by:** G-11 (Pipeline / in-flow extensibility). Until Hearth has a Pipeline abstraction, there is nowhere to import Rules/Actions into.

**Routing:** Blocked. Re-evaluate after G-11 lands.

---

### G-11 — Custom In-Flow Extensibility (Pipeline / Actions abstraction)
**Rank:** 11 · **RICE:** 38 · **Effort:** 10+ weeks · **MoSCoW:** Must (long-term)

**Problem:** Auth0's "Actions" and Keycloak's scripted authenticators/Java SPIs allow customers to inject custom claims, call external APIs mid-flow, and conditionally gate access. Hearth has no equivalent. Webhooks are post-hoc (after the fact) and cannot block or modify a flow.

**Architecture decision required.** Recommended phased approach (from HEA-767 audit):
- Phase 1: Synchronous HTTP callback at defined lifecycle points (pre-token, post-login, post-registration) with short timeout and fail-open semantics
- Phase 2: WASM sandbox for inline scripts (eliminates latency + network dependency)

**Routing:** CTO must approve architecture before PM writes PRD. Escalated to CTO.

---

### G-12 — Authentication Policies / Conditional Access
**Rank:** 12 · **RICE:** 31 · **Effort:** 6–8 weeks · **MoSCoW:** Should

**Problem (specific to HEA-828 scope):** Keycloak's "Authentication Flows" are configurable DAGs of authenticators with conditions (IP range, role membership, client, time-of-day). Auth0's "Actions" achieve similar results inline. Hearth has a fixed login flow — credential check → MFA (if enrolled) → required actions → session issue — with no operator-configurable branch points.

**Evidence of absence:** `grep -rn 'AuthFlow\|auth_flow\|conditional.*access' src/identity/types.rs` — zero hits. `src/identity/migration/keycloak.rs` imports auth flow data from Keycloak exports but discards it.

**Routing:** Dependent on G-11 architecture decision. Tag CTO for sequencing.

---

### G-13 — Localization / i18n of Login Pages
**Rank:** 13 · **RICE:** 36 · **Effort:** ~4 weeks · **MoSCoW:** Could

**Problem:** Keycloak and Auth0 support multi-language login pages from the admin UI. Hearth's templates are English-only with no i18n layer.

**Routing:** Engineer + UXDesigner. Low priority for initial GA.

---

### G-14 — Push Notification MFA (Won't)

**Verdict:** Won't implement near-term. Passkeys (FIDO2 L2) are the modern replacement for push MFA and Hearth has full Passkey support. Push MFA adds operational dependency on proprietary push infrastructure (APNs, FCM) with minimal incremental security benefit over TOTP + Passkeys.

---

## 4. Tactical Roadmap Recommendation

Ordered by RICE × PM-specifiability (items that need no CTO arch sign-off go first):

| Sprint | Gap | Effort | Precondition |
|---|---|---|---|
| Sprint 1 | G-01 SMS MFA | 2 wks | CTO transport design |
| Sprint 1 | G-02 Adaptive MFA / breach-check | 2 wks | None |
| Sprint 1–2 | G-03 Client scopes admin UI | 2 wks | None |
| Sprint 2 | G-07 Fine-grained admin delegation | 4 wks | CTO RBAC model approval |
| Sprint 2–3 | G-06 LDAP/AD federation | 6–8 wks | CTO spike (HEA-744 complete) |
| Sprint 3 | G-04 Python SDK | 3 wks | None |
| Sprint 3 | G-05 Log streams | 2 wks | None |
| Backlog | G-08 MFA enrollment policies | 3 wks | G-01 complete |
| Backlog | G-09 IdP broker first-login | 4 wks | CTO design |
| Backlog | G-11 Pipeline / in-flow extensibility | 10+ wks | CTO arch approval |
| Backlog | G-12 Conditional access flows | 6–8 wks | G-11 complete |
| Backlog | G-10 Auth0 Rules/Actions import | 4 wks | G-11 complete |
| Backlog | G-13 i18n | 4 wks | None |

---

## 5. Competitive Positioning Impact

| Audience | Gap today | Closes with |
|---|---|---|
| Enterprise Keycloak replacement | LDAP, fine-grained admin, conditional access | G-06, G-07, G-12 |
| Auth0 B2B SaaS replacement | Custom in-flow logic, SMS MFA, breach-check | G-11, G-01, G-02 |
| Developer-first self-hosters | Client scopes, Python SDK, i18n | G-03, G-04, G-13 |
| Security-sensitive (regulated) | Breach-check, adaptive MFA | G-02 |

---

## 6. Routing Decisions

| Gap | Assignee | Action |
|---|---|---|
| G-01, G-02, G-03 | PM → CTO → Engineer | Child issues filed (see §7) |
| G-06 LDAP | CTO | Options doc done (HEA-744); implementation spike needed; CTO to file engineering issue |
| G-07 Fine-grained admin | CTO + PM | CTO to approve RBAC model extension; PM to write PRD |
| G-09 IdP broker | CTO | Design needed before PM can spec |
| G-11 Pipeline/Actions | CTO | Architecture decision required; escalate immediately |
| G-12 Conditional access | CTO | Sequenced after G-11 |

---

## 7. Child Issues Filed

| Issue | Gap | Priority | Owner |
|---|---|---|---|
| [HEA-829](/HEA/issues/HEA-829) | G-01: SMS / Phone MFA — PRD | High | PM → CTO |
| [HEA-830](/HEA/issues/HEA-830) | G-02: Adaptive MFA / breach-check — PRD | High | PM → CTO |
| [HEA-831](/HEA/issues/HEA-831) | G-03: Client scopes admin UI — PRD | Medium | PM → Engineer |
