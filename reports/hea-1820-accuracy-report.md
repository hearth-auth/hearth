# HEA-1820 — Test Audit Phase 3b: Accuracy Audit (SAML / federation / SCIM / orgs / realm-routing)

Per-test accuracy audit per the accepted plan (Phase 3) on [HEA-1766](/HEA/issues/HEA-1766#document-plan). Read-only: **no tests were modified**. Defects feed the Phase 4 triage child.

**Criteria applied to every test:** (1) name/claim matches assertions; (2) assertions behavioral, not vacuous (anti-pattern taxonomy A–I, `docs/specs/TESTING.md`); (3) setup exercises the real code path (harness, not a mock of the thing under test); (4) negative/failure paths asserted where enforcement is claimed; (5) no stale `#[ignore]`, commented-out asserts, or trivially-passing tests.

**Severity key:** P0 = security test that fails to assert the reject / false-confidence on an enforcement guard · P1 = vacuous/dead test giving false coverage · P2 = name-claim mismatch or weak assertion · P3 = minor/stylistic.

## Summary

- **21 files audited · 21 defects · P0: 0 · P1: 3 · P2: 10 · P3: 8**
- No P0s: no security test was found that entirely omits the reject. The 3 P1s are false-confidence on security caps/enforcement (constant-only cap check, zero-assert filler, wrong-reason rejection) and should be triaged first.
- Setup quality is strong across the board: all files use the real `TestHarness`/`EmbeddedIdentityEngine`/`web::router` — no mock-of-thing-under-test found (criterion 3 clean everywhere).

## Per-file verdict table

| File | # tests | Verdict | Notes |
|------|--------:|---------|-------|
| tests/saml.rs | 8 | DEFECTS (minor) | Strong crypto/replay/audience coverage; one tamper test doesn't pin the rejection variant. |
| tests/saml_web_hardening.rs | 3 | CLEAN | Real web router; asserts redirect-to-login AND absence of `SAMLResponse` in body. |
| tests/abuse_scim_saml.rs | 5 | DEFECTS | A-35a "cap" only a constant check — enforcement path never exercised; XML/DOCTYPE rejects loose. |
| tests/scim.rs | 12 | CLEAN | Real HTTP router; negatives (401/409/400) pin `scimType`/error schema. |
| tests/scim_auth_parity.rs | 4 | DEFECTS | Route-table guard cannot detect real router drift. Auth-parity tests themselves solid. |
| tests/scim_bearer_auth.rs | 6 | DEFECTS | One enforcement test rejects for wrong reason (cross-realm), not the feature it claims. |
| tests/federation.rs | 14 | CLEAN | Real engine; all pin error variants or concrete values; good realm-isolation + cascade. |
| tests/federation_adversarial.rs | 12 | DEFECTS | Strong ID-token tampering; one security test lacks positive baseline; one "XSS" test only proves serde round-trip. |
| tests/federation_conformance.rs | 11 | CLEAN | Exemplary — matched positive+negative asserts; RS256 verify pins bit-flip/wrong-key/non-RSA/missing-component. |
| tests/federation_property.rs | 6 | DEFECTS | One zero-assert filler test (taxonomy A). Proptests otherwise sound. |
| tests/abuse_federation.rs | 14 | DEFECTS | Two SAML security tests assert only `is_err()` without pinning rejection reason. |
| tests/ldap_federation.rs | 7 | DEFECTS | Real connector; ignores well-tagged (HEA-1344). One name/claim mismatch on delta-sync. |
| tests/web_ui_federation.rs | 8 | CLEAN | Full axum router + real engine; asserts redirects/links/tickets/audit across all 3 LinkModes. |
| tests/web_ui_idp_admin.rs | 2 | CLEAN | Real router; behavioral 200+display-name and 404 asserts (header over-claims "list" — coverage gap). |
| tests/cross_realm_trust.rs | 8 | DEFECTS | Solid CRUD + allow/deny/no-policy asserts, but module doc claims expiry enforcement no test exercises. |
| tests/organizations.rs | 18 | DEFECTS | Strong behavioral core; one name-claim mismatch + several weak `is_err()` asserts. |
| tests/admin_org_ui.rs | 6 | CLEAN | Real router+engine; status/header/body asserts behavioral; `bulk_add_route_is_gone` asserts the reject. |
| tests/org_scoped_group_paths.rs | 2 | CLEAN | Real token issue+validate; asserts presence + absence of `org_groups` + cardinality; no-org negative covered. |
| tests/web_ui_realm_routing.rs | 11 | DEFECTS | Good reservation/negative coverage, but one near-vacuous OR assertion. |
| tests/realms.rs | 12 | DEFECTS | Excellent cross-realm isolation; several weak `is_err()` asserts + one over-claimed enumeration test. |
| tests/realm_branding.rs | 12 | CLEAN | Persistence round-trips + validation tests check error messages/variants, not just `is_err()`. |

## Defect list

| file:line | Test | Criterion (taxonomy) | Sev | Description |
|-----------|------|----------------------|-----|-------------|
| abuse_scim_saml.rs:31 | `a35a_scim_ops_constant_exported` | 2, 5 (A) | **P1** | Asserts only `MAX_SCIM_OPERATIONS == 1000`; dup of `a35a_max_scim_operations_is_1000` (:18). No >1000-op PATCH sent, so A-35a SCIM cap enforcement is entirely untested — passes if the cap is removed. |
| federation_property.rs:217 | `user_id_is_usable` | 2 (A) | **P1** | Zero-assert body — just `UserId::generate()`; passes regardless of behavior. Pure filler; passes if the type were broken. |
| scim_bearer_auth.rs:215 | `admin_jwt_rejected_when_scim_token_enforced` | 4, 5 (C/F) | **P1** | Admin JWT minted for a *different* realm → 401 comes from realm-mismatch, not SCIM-token enforcement. Deleting the enforcement branch leaves it green. Should use same-realm admin JWT. |
| abuse_scim_saml.rs:56 | `a35b_oversized_saml_xml_rejected` | 4 (F) | P2 | Reject accepts any message containing `"parse"`; unrelated parse failure also passes; doesn't pin the cap/limit error. |
| scim_auth_parity.rs:305 | `scim_route_table_is_complete` | 1, 5 (C) | P2 | Compares `SCIM_ROUTES.len()` to a hand-maintained constant in the same file; adding a route in `scim/mod.rs` touches neither — cannot detect real router drift. |
| federation_adversarial.rs:132 | `confirm_link_ticket_cannot_be_stolen_by_another_user` | 4, 2 | P2 | Asserts only `!verify(...bob...)`; no positive baseline that verify succeeds for the bound user. A `verify_confirm_ticket_mac` mutated to always-false still passes. |
| abuse_federation.rs:222 | `a29c_saml_multiple_assertions_rejected` | 4 (F) | P2 | `is_err()` + message `contains("assert")` matches virtually any SAML error; multi-assertion XSW reason not pinned. |
| abuse_federation.rs:307 | `a29d_saml_doctype_in_find_element_range_rejected` | 4 (F) | P2 | XXE guard asserts only `is_err()`; rejection for an unrelated reason still passes. |
| ldap_federation.rs:265 | `delta_sync_second_run_with_same_cursor_returns_no_new_users` | 1 (C) | P2 | Name claims "returns no new users" but body only asserts checkpoint timestamp advanced; never asserts `second.upserted.is_empty()` (comment concedes this). |
| cross_realm_trust.rs (module doc) | file-level coverage claim | 5, 1 (C) | P2 | Module doc lists "Expired policy is not respected" as covered; no test calls `check_cross_realm_policy` on an expired policy. Expiry-bypass unverified. |
| web_ui_realm_routing.rs:204 | `bare_login_resolves_to_default_when_configured` | 2 (A) | P2 | `body.contains(".../public/login") \|\| body.contains("action=\"/ui/login\"")` — 2nd disjunct is the generic bare-login action, ~always present; can't fail even if default-realm resolution never ran. |
| organizations.rs:956 | `role_escalation_prevention` | 1, 5 (C) | P2 | Name = "members cannot escalate role" but body only re-tests last-owner protection (doc concedes no caller-role check); dup of `last_owner_cannot_be_removed_or_downgraded`; passes if escalation logic deleted. |
| organizations.rs:1043 | `slug_injection_rejected` | 2, 4 (A) | P2 | Loop asserts only `result.is_err()` per malicious slug; a wrong `Err` variant (e.g. storage error) still passes. Should pin the validation-reject variant. |
| saml.rs:151 | `sp_rejects_tampered_assertion` | 4 (F) | P3 | Asserts `Rejected { .. }` without pinning the signature/digest variant; siblings (audience/replay) do pin. Tamper targets first `b"a"` which may not be the email. |
| abuse_scim_saml.rs:91 | `a35c_doctype_in_saml_response_rejected` | 4 (F) | P3 | `expect_err` then discards err; proves rejection but not that it's a DOCTYPE/XXE reject vs generic parse error. |
| federation_adversarial.rs:340 | `userinfo_display_name_with_html_is_preserved_verbatim` | 2 | P3 | Framed as XSS defense but only proves a serde round-trip of the raw string; template-escaping not exercised; passes if escaping deleted. |
| realms.rs:353 | `adversarial_realm_enumeration_resistance` | 1 (C) | P3 | Claims nonexistent-vs-forbidden responses "indistinguishable" but never compares a real-but-forbidden realm's error; only asserts `RealmNotFound`/`None`. |
| organizations.rs:307 | `invitation_e2e_flow` (token reuse) | 2 (A) | P3 | Reuse rejection asserted via bare `is_err()` without checking `InvitationInvalid`/already-accepted variant. |
| realms.rs:160 | `multi_realm_token_isolation` | 2 (A) | P3 | Cross-realm token rejection via `is_err()` only; validation-failure variant not pinned. |
| realms.rs:329,343 | `adversarial_realm_id_spoofing` | 2 (A) | P3 | Forged-realm session/token creation checked with bare `is_err()`; should pin `RealmNotFound`. |
| web_ui_realm_routing.rs:301 | `login_does_not_walk_realms` | 4 (F) | P3 | Asserts status `!= SEE_OTHER && != FOUND`; a 500/unrelated failure also satisfies it. Tighten to assert 401/re-render. |
| organizations.rs:913 | `token_enumeration_resistance` | 4 (F) | P3 | Variant checks are good but never exercises a genuinely *expired* token, so the "expired… indistinguishable" claim is untested. |

## Coverage gaps (not per-test defects — for Phase 4 awareness)

- `web_ui_realm_routing.rs` does not test the R-4 reserved-realm-name collision rule from `docs/specs/UI_ROUTING.md`.
- `web_ui_idp_admin.rs` header says "list + detail" but only detail is tested.
- Several `abuse_federation.rs` / `abuse_scim_saml.rs` `assert!(result.is_err())` forms match the CI taxonomy-A grep pattern and compile today only because they carry a message/bound arg — worth converting to `matches!(…, Err(IdentityError::Saml…))` variant pins during Phase 4.
