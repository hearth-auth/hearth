# HEA-720 — Production Readiness Audit v2 — CTO Rollup

**Date:** 2026-05-25
**Rollup author:** CTO
**Question asked:** Is Hearth a full drop-in replacement for major auth providers (Keycloak / Auth0) yet? If not, what gaps remain?

**Headline answer: NO.** Hearth is **not yet** a drop-in replacement for Keycloak / Auth0. The audit found four lanes returning `not-production-ready` and seven returning `production-ready-with-caveats`. Three of the failing lanes block any first production deployment by themselves; the caveats are concentrated enough that ~1–2 focused sprints can close most of them.

---

## Methodology

This is the v2 audit, dispatched after the v1 audit (HEA-684) was found to be unreliable. Every lane was given a hard contract:

1. Re-grep current `main`. Do **not** cite prior reports.
2. Every "implemented" claim must carry **file:line** evidence.
3. Every "works end-to-end" claim must carry a **traced reachability path** (route → handler → storage → operator-visible result).
4. Distinguish *checkbox-complete* from *operationally reachable*.

11 specialist lanes were dispatched. All 11 returned. 7 wrote committed audit docs under `docs/audit/v2/`; the other 4 (PM, CTO, UXDesigner, DevRel) recorded findings in the lane's final comment + (PM, CTO) committed docs on lane branches not yet on `main`.

---

## Verdict Roster

| # | Lane | Owner | Verdict | Doc |
|---|---|---|---|---|
| HEA-767 | Feature parity vs Keycloak/Auth0 | ProductManager | `production-ready-with-caveats` | `docs/audit/v2/pm-feature-parity.md` (lane branch) |
| HEA-768 | Security posture & cryptographic hygiene | SecurityAuditor | `production-ready-with-caveats` (3 medium + 1 low) | `docs/audit/v2/security-posture.md` |
| HEA-769 | Vulnerability & supply chain | SecurityResearcher | **`not-production-ready`** | `docs/audit/v2/supply-chain.md` |
| HEA-770 | Test rigor & coverage | QA | `production-ready-with-caveats` | `docs/audit/v2/qa.md` |
| HEA-771 | Codebase health & engineering rigor | CTO | `production-ready-with-caveats` | `docs/audit/v2/cto-lane.md` (lane branch) |
| HEA-772 | Platform/ops & deployment readiness | PlatformEngineer | `production-ready-with-caveats` | `docs/audit/v2/platform-engineer.md` |
| HEA-773 | Admin & end-user UX completeness | UXDesigner | `production-ready-with-caveats` | comment only |
| HEA-774 | SDK & DevRel ecosystem | DevRel | `production-ready-with-caveats` (1–2 sprint gap) | comment only |
| HEA-775 | Documentation completeness | TechnicalWriter | **`not-production-ready`** | `docs/audit/v2/technical-writer.md` |
| HEA-776 | Op check: 3-node cluster bootstrap from docs only | PlatformEngineer | **`not-production-ready`** | `docs/audit/v2/cluster-bootstrap.md` |
| HEA-777 | Op check: Required Actions E2E real-user flow | QA | **`NOT PRODUCTION READY`** | `docs/audit/v2/required-actions.md` |

**Tally:** 0 unqualified `production-ready` · 7 `with-caveats` · 4 `not-ready`.

---

## P0 Release Blockers (must fix before any first production deployment)

These four findings each independently block shipping. Each one has been independently verified against current code by its lane.

### B1 — Browser login bypasses required-action gates (HEA-777)

`src/protocol/web/auth.rs::login_submit_impl` completes session issuance and sets the session cookie **without consulting the required-action engine**. A user with `UPDATE_PASSWORD` or `VERIFY_EMAIL` pending logs in through the UI and receives a full session — the interstitial pages exist but are unreachable from the standard browser path. The OIDC/OAuth flow honors required actions; the browser flow does not. Additionally, the `VERIFY_EMAIL` resend button flashes "email sent" but issues no SMTP/transport call.

This is a Keycloak parity feature that Hearth claims and the gate is the entire point. Cannot ship.

**Fix path:** Insert required-action check between credential verification and session issuance in `login_submit_impl`; mirror the OIDC interceptor logic. Re-enable resend by wiring the button handler into `EmailService::send_verification_email`. Add positive-path integration test in `tests/required_actions_browser_flow.rs`.

### B2 — Cross-realm gRPC BFLA: admin of realm A can destroy realm B (HEA-768 GAP-1)

`src/protocol/grpc/identity.rs` (lines 182, 197, 213, 235, 254 — all five realm-management handlers) bind `authenticate_admin(...)` to `_auth` and discard the authenticated realm. An admin of realm A authenticates with a valid realm-A token via `x-realm-id: realm-a`, then calls `delete_realm({ id: "realm-b-id" })`. Auth succeeds because the token is valid for realm A; the handler then operates on realm B. Multi-tenant data destruction by any legitimate realm admin.

OWASP API Top 10 — Broken Function-Level Authorization. Cannot ship.

**Fix path:** Replace `_auth` with `auth`; assert `auth.realm_id == target_realm_id` OR enforce that only system-realm admins can mutate other realms. Add adversarial test in `tests/grpc_cross_realm_bfla.rs`.

### B3 — No signed release pipeline (HEA-769)

`.github/workflows/release.yml` does **not exist** on `main` or on `feat/release-workflow-HEA-781`. The v1 audit's SLSA L1 / cosign / CycloneDX SBOM claims are falsified — those artifacts are not produced. `cargo deny check` is not enforced in CI (policy exists in `deny.toml`, but is never invoked). `serde_yaml 0.9` (deprecated, no future security patches) is in the config-loading hot path at `src/config/mod.rs:133,244`.

A self-hosted authentication server with **no signed release artifacts and no provenance** cannot be defended to an enterprise security review. Cannot ship.

**Fix path:** Land the in-flight `feat/release-workflow-HEA-781` branch (where this rollup is committed) — it is exactly the missing release workflow per the branch name. Add `cargo deny check` to `ci.yml`. Complete the `serde_yaml → serde_yml` migration begun in commit `1c23e93` (the current branch has it staged but not committed across all call-sites; verify with grep).

### B4 — Documented cluster bootstrap is broken (HEA-776 + HEA-775)

An operator following only `docs/guides/clustering.md` on `main` cannot bootstrap a 3-node cluster:
- Step 3's `curl` examples return `403 Forbidden` because the required `X-Realm-ID: 00000000-…` (nil-UUID system-realm) header is absent from every example.
- Docs reference a `hearth snapshot` CLI command that does not exist.
- `docs/guides/disaster-recovery.md` — required by HEA-745 — **does not exist on `main`**.
- `docs-site/package-lock.json` is absent; the docs-site CI pipeline will fail its first run.
- The operator-visible behavioral change from HEA-752 (required-action JWT gating at login) has no CHANGELOG entry.

A fix branch (`feature/gap-updates-for-clustering`) exists and is reported to correct the clustering.md gaps and add the DR runbook, but it is unmerged.

**Fix path:** Rebase, review, and merge `feature/gap-updates-for-clustering`. Verify the merged docs by re-running HEA-776's operator-from-scratch op-check. Add `docs-site/package-lock.json`. Backfill CHANGELOG for HEA-752.

---

## P1 Caveats (must fix for confident GA, but do not block a controlled first deployment)

These are the headline caveats from the seven `with-caveats` lanes. Each is detailed in its lane doc with `file:line` evidence.

- **Argon2id default memory cost below OWASP 2023 minimum** (HEA-768 GAP-3). Bump default in `src/identity/credentials.rs` and document the rationale.
- **CSP `unsafe-eval` required by Alpine.js** (HEA-768 GAP-4). Either accept and document the trade-off or replace Alpine in the small surface that needs eval (admin templates).
- **gRPC internal error details leaked to callers** (HEA-768 GAP-2). Wrap internal errors at the gRPC boundary.
- **Helm chart ships as `Deployment` rather than `StatefulSet`** (HEA-772). No cluster topology values; probes wired to `/health` rather than storage-aware `/readyz`. Single-node container/systemd deployment is solid; clustered Kubernetes is not. Convert chart to StatefulSet, expose peer/seed values, wire `/readyz`.
- **No positive-path tests for the three cluster admin routes** (HEA-770). `cluster_admin_endpoints.rs` only covers rejection paths.
- **SDK & DevRel posture is ~1–2 sprints behind minimum-viable** (HEA-774). The SDKs exist (TS + Go) and pass smoke; the rough edges are example apps, framework integrations, and quickstart polish.
- **PM feature-parity caveats** (HEA-767) — see lane doc; the gating issue for Keycloak parity itself is B1 (required actions), not feature breadth.

---

## What is Healthy (so we don't lose the wins)

- **Cryptographic stack:** Ed25519-only signing, Argon2id password hashing, `ring`/`rustls`/`subtle`/`zeroize` throughout, no hand-rolled crypto. (HEA-768)
- **Runtime dependencies:** zero CVEs, modern crypto stack, SHA-pinned CI actions, active Dependabot + three SAST/SCA scanners (CodeQL + Trivy + OSV + Scorecard). (HEA-769)
- **Backup / restore round-trip works**, including the signing-key-continuity regression — operationally reachable and exercised by tests. (HEA-772)
- **Container build, healthcheck handlers, metrics surface** all production-grade for single-node. (HEA-772)
- **Simulation tests pass; no vacuous asserts in new test files; three newly-added feature areas (required_actions, backup, cluster_admin) are routed and operationally reachable** (modulo B1 / B4 caveats). (HEA-770)
- **Codebase health (CTO lane):** clean layering, no architectural drift, error/secret hygiene intact, hot-path rules respected. (HEA-771)

---

## Final Disposition for HEA-720

**Not a drop-in replacement for Keycloak / Auth0 today.** Four P0 blockers, all narrowly scoped and each with a named fix path. Estimated work to remove all four blockers: **2–3 focused sprints** across Security, Platform, and Tech Writing. Estimated work to remove blockers + all P1 caveats: **5–6 sprints**.

**Recommendation:** Treat the four B-issues above as release-gating blockers. Create one child issue per blocker, assign owners, link as `blockedBy` on a follow-up "production-ready milestone" issue. Do not market Hearth as drop-in for Keycloak / Auth0 until all four are closed AND HEA-720 is re-run as an op-check.

Comment thread on each lane has the full `file:line` evidence; this rollup is the single source of truth for the verdict.
