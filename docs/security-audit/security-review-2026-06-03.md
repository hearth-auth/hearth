# Hearth — Independent Security Review

**Review date:** TBD (commissioned 2026-06-03)  
**Reviewer:** TBD — independent third party or internal security engineer not on the implementation team  
**Scope:** Auth surface (see §1)  
**Commissioned by:** CTO  
**Status:** COMMISSIONED — awaiting reviewer assignment  
**Threat model baseline:** [threat-model.md](./threat-model.md)

---

## §1 Review Scope

The reviewer must cover the following components. The [threat model](./threat-model.md) provides the STRIDE baseline; this review is expected to validate, extend, and find gaps in it.

### In-scope components

| Component | Entry point | Key threat model items |
|---|---|---|
| Password authentication | `src/identity/credentials.rs`, `src/identity/engine.rs` | TM-001 through TM-012 |
| Magic-link flow | `src/identity/engine.rs`, `src/protocol/web/handlers.rs` | TM-003, TM-004, TM-005 |
| MFA (TOTP/SMS) | `src/protocol/web/sms_challenge.rs`, identity engine | TM-011, TM-012 |
| WebAuthn / Passkey | `src/identity/webauthn.rs` | TM-006 |
| Token issuance & validation | `src/identity/tokens.rs` | TM-020 through TM-029 |
| Session management | `src/identity/engine.rs` | TM-028, TM-029 |
| Admin API | `src/protocol/admin_auth.rs`, `src/protocol/web/admin/` | TM-030 through TM-037 |
| Multi-tenancy / realm isolation | `src/core/`, `src/storage/` | TM-040 through TM-044 |
| OAuth 2.0 / OIDC (AS + RP) | `src/identity/federation/oidc.rs`, `src/protocol/web/federation.rs` | TM-050 through TM-057 |
| SAML 2.0 | `src/identity/federation/saml/` | TM-058, TM-059, TM-060 |
| Fuzz corpus adequacy | `fuzz/fuzz_targets/` | all |

### Explicit gap items (reviewer must address first)

As documented in [threat-model.md §6](./threat-model.md#6-residual-risk-summary):

1. **TM-008** — Username enumeration via timing side-channel in login
2. **TM-012** — TOTP single-use enforcement within time window
3. **TM-028** — Token replay after session revocation (`validate_token()` session liveness check)
4. **TM-032** — SSRF via admin webhook URL configuration (`src/protocol/web/admin/webhooks.rs`)
5. **TM-036** — Migration endpoint privilege escalation (`src/protocol/web/admin/migrations.rs`)

### Out of scope

- Vulnerabilities in third-party Rust dependencies (report upstream)
- Infrastructure / deployment configuration
- Social engineering
- Physical access attacks

---

## §2 Reviewer Qualifications

The reviewer must meet **at least one** of:

- OSCP, OSWE, or equivalent offensive security certification with demonstrated auth/identity review experience
- Prior auth-system audit experience (OAuth 2.0, OIDC, SAML, WebAuthn) documented in a public or disclosed report
- Internal security engineer with no involvement in Hearth implementation and sign-off from CTO + one external advisor

The reviewer must NOT be on the Hearth implementation team.

---

## §3 Deliverable Requirements

The reviewer must produce a written findings report conforming to this structure:

```
# Executive Summary
[Risk posture, critical findings, recommendation (ship/hold)]

# Findings
[For each finding:]
  - ID: SEC-YYYY-NNN
  - Severity: Critical / High / Medium / Low / Informational
  - Component: [file/module]
  - Threat model reference: [TM-XXX or "new"]
  - Description: [technical description]
  - Reproduction: [steps or PoC]
  - Impact: [what an attacker gains]
  - Recommendation: [specific fix]
  - CWE: [CWE-NNN if applicable]

# Threat Model Validation
[For each TM-XXX item: confirmed-mitigated / confirmed-gap / false-positive]

# Out-of-Scope Observations
[Informational items not in scope but worth noting]
```

All **Critical** and **High** findings must be remediated or formally risk-accepted with CTO sign-off before Hearth 1.0 ships.

---

## §4 Findings

*This section is populated by the external reviewer. It is empty until the review is complete.*

<!-- reviewer populates below -->

---

## §5 Remediation Tracking

| Finding ID | Severity | Status | Remediation PR / risk-acceptance |
|---|---|---|---|
| *(populated after review)* | | | |

---

## §6 Sign-Off

| Role | Name | Date | Signature |
|---|---|---|---|
| Reviewer | TBD | | |
| CTO | Brad | 2026-06-03 (commissioned) | |

---

*Document created 2026-06-03. Reviewer assignment is a blocking requirement for §2 gate item 1 (HEA-1226 / HEA-1243).*
