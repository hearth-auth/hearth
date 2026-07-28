# Hearth — Code-Derived Feature Inventory (HEA-1817)

**Test Suite Audit — Phase 1 (P1).** A machine-checkable inventory of features that are actually **BUILT**, derived from code (not docs). One section per surface; each row names the surface, its entry point (`file:line` or route), and a spec reference. This is the ground-truth "what exists" map that later audit phases test-coverage-check against.

- **Method:** 8 parallel read-only subagents, one per surface. Sources: axum routers in `src/protocol/`, `proto/**` + tonic impls, `src/protocol/web/mod.rs` + `templates/ui/`, `hearth.example.yaml` × `src/config/types.rs` × `docs/specs/CONFIGURATION.md`, clap in `src/main.rs`, `sdks/` (TS/Go/PHP), `src/storage/` + `src/cluster/`, and the security specs + HEA-1717 / HEA-1749 sweeps.
- **Scope:** read-only analysis, no code changes.

## Surface totals

| # | Surface | Count | Entry point | Section |
|---|---------|-------|-------------|---------|
| 1 | HTTP / REST routes | 340 route registrations (123 machine-API + 217 web UI) | axum routers in `src/protocol/` | [01](#http--rest-routes) |
| 2 | gRPC services / RPCs | 4 services, 60 RPCs | `proto/**` + `src/protocol/grpc/`, `src/cluster/server.rs` | [02](#grpc-services--methods) |
| 3 | UI routes / templates | 217 routes, 130 templates | `src/protocol/web/mod.rs`, `templates/ui/` | [03](#ui-routes--templates) |
| 4 | Config keys | ~120 keys, 17 sections | `src/config/types.rs` | [04](#configuration-surface) |
| 5 | CLI | 8 top-level cmds (23 rows), ~45 flags | `src/main.rs` | [05](#cli-commands--flags) |
| 6 | SDK exports | TS/Go/PHP (see per-SDK counts) | `sdks/` | [06](#sdk-exports-ts--go--php) |
| 7 | Storage / cluster behaviors | 43 behaviors | `src/storage/`, `src/cluster/` | [07](#storage--cluster-behaviors) |
| 8 | Security behaviors | 20 enforced behaviors | across `src/identity/`, `src/protocol/` | [08](#security-behaviors) |

## Cross-surface findings for later audit phases

These are drift/gaps surfaced during inventory — inputs for P2 (coverage mapping) and P4 (triage), **not** action items for this issue:

- **Config drift (§4):** documented-but-unimplemented keys silently ignored (no `deny_unknown_fields`) — `auth.audit_log_retention`, `security.password.pepper.*`, `security.bearer_token` (real field is `metrics.bearer_token`), and several `realms.<name>.auth.*` keys that are admin-API-only. Implemented-but-undocumented: `server.{default_realm,grpc_port,grpc_bind_address,assets_dir}`, `storage.compaction.*`, `observability.otlp.*`, session concurrency keys. Stale example.yaml comments still show removed opt-outs `oidc.enforce_nonces`/`require_pkce` (startup-rejected, HEA-SEC-29).
- **SDK parity (§6):** TS is the weakest — WebAuthn (4 methods), DCR `registerClient`, permissions/userinfo/decision calls, and first-class `refreshToken`/`exchangeCode` exist in Go+PHP but not on the TS `HearthClient`. No spec-mandated op is entirely missing from any SDK.
- **Storage untested/aspirational (§7):** follower bounded-staleness read enforcement (ARCHITECTURE §32.1) appears unimplemented; encryption-at-rest DEK and crash-recovery paths reachable only via module/madsim tests, not the nextest black-box harness; format-version migration is greenfield-minimal.
- **Spec-less surfaces (§1):** SCIM and SAML have no `docs/specs/` file (only external RFCs). Many account/settings/webhook/audit UI routes map to no spec.
- **gRPC-only surface (§2):** many Rbac/Identity RPCs have no REST binding (tracked under HEA-969).
- **Dev-only / feature-gated routes (§1):** `POST /admin/bootstrap` + `/dev/mail/*` are dev-only; all agent-auth routers are capability-gated (silently absent unless enabled). `POST/PATCH /admin/realms` intentionally 405 (realms managed via `hearth.yaml`).
- **Template naming (§3):** parallel `required_action/` (interstitial) vs `required-actions/` (routed) dirs — cleanup candidate.

---
## HTTP / REST Routes

Code-derived inventory of every axum route registered under `src/protocol/`. Composed in `src/main.rs:2311` as `http::router(state).merge(web::router(web_state))` (+ dev-only `web::mailcatcher_router`).

Method column lists every HTTP verb wired to that path; each path is one row. Line numbers point at the route registration.

### Health & metrics — `src/protocol/http/health.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /health | health | http/health.rs:16 | — |
| GET /healthz | healthz | http/health.rs:17 | — |
| GET /readyz | readyz | http/health.rs:18 | — |
| GET /metrics | metrics_handler | http/health.rs:19 | — |

### User self-service create — `src/protocol/http/users.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| POST /users | create_user | http/users.rs:17 | AUTHORIZATION.md |

### OAuth 2.0 / OIDC (global, header-scoped realm) — `src/protocol/http/oauth.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /.well-known/openid-configuration | oidc_discovery | http/oauth.rs:34 | OIDC.md |
| GET /.well-known/oauth-protected-resource | protected_resource_metadata | http/oauth.rs:36 | OIDC.md |
| GET /jwks | jwks | http/oauth.rs:39 | OIDC.md |
| GET /certs | jwks | http/oauth.rs:40 | OIDC.md |
| GET /.well-known/jwks.json | jwks | http/oauth.rs:41 | OIDC.md |
| POST /clients | register_client | http/oauth.rs:42 | OIDC.md |
| POST /register | register_client_dynamic | http/oauth.rs:44 | OIDC.md (RFC 7591 DCR) |
| POST /authorize | authorize | http/oauth.rs:48 | OIDC.md |
| POST /as/par | pushed_authorization_request | http/oauth.rs:50 | OIDC.md (RFC 9126 PAR) |
| POST,OPTIONS /token | token_exchange / token_preflight | http/oauth.rs:54 | OIDC.md |
| POST,OPTIONS /revoke | token_revocation | http/oauth.rs:56 | OIDC.md (RFC 7009) |
| POST,OPTIONS /introspect | token_introspection | http/oauth.rs:62 | OIDC.md (RFC 7662) |
| POST,OPTIONS /device_authorization | device_authorization | http/oauth.rs:68 | OIDC.md (RFC 8628) |
| GET /userinfo | userinfo | http/oauth.rs:71 | OIDC.md |
| GET /v1/me/permissions | me_permissions | http/oauth.rs:72 | AUTHORIZATION.md |
| POST /oauth/authorize | oauth_decide_permission | http/oauth.rs:74 | OIDC.md |
| GET /oauth/consents | self_list_consents | http/oauth.rs:78 | OIDC.md |
| DELETE /oauth/consents/{client_id} | self_revoke_consent | http/oauth.rs:80 | OIDC.md |

### OAuth 2.0 / OIDC (realm-scoped, `/realms/{realm_name}`) — `src/protocol/http/oauth.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /realms/{realm}/.well-known/openid-configuration | realm_oidc_discovery | http/oauth.rs:90 | OIDC.md |
| GET /realms/{realm}/.well-known/jwks.json | realm_jwks | http/oauth.rs:94 | OIDC.md |
| GET,POST /realms/{realm}/authorize | realm_authorize_browser_redirect / realm_authorize | http/oauth.rs:96 | OIDC.md |
| POST /realms/{realm}/as/par | realm_pushed_authorization_request | http/oauth.rs:100 | OIDC.md (PAR) |
| POST,OPTIONS /realms/{realm}/token | realm_token_exchange | http/oauth.rs:104 | OIDC.md |
| POST,OPTIONS /realms/{realm}/revoke | realm_token_revocation | http/oauth.rs:108 | OIDC.md |
| POST,OPTIONS /realms/{realm}/introspect | realm_token_introspection | http/oauth.rs:114 | OIDC.md |
| POST,OPTIONS /realms/{realm}/device_authorization | realm_device_authorization | http/oauth.rs:120 | OIDC.md |
| GET /realms/{realm}/userinfo | realm_userinfo | http/oauth.rs:124 | OIDC.md |
| POST /realms/{realm}/register | realm_register_client_dynamic | http/oauth.rs:126 | OIDC.md (DCR) |

### Session / RP-initiated logout — `src/protocol/http/session.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET,POST /end_session | end_session | http/session.rs:20 | OIDC.md (RP logout) |
| GET /oauth/session-versions | oauth_sv_delta_feed | http/session.rs:21 | OIDC.md |
| GET /oauth/session-versions/snapshot | oauth_sv_snapshot | http/session.rs:22 | OIDC.md |
| GET,POST /realms/{realm}/end_session | realm_end_session | http/session.rs:28 | OIDC.md |

### MFA / WebAuthn / magic-link — `src/protocol/http/mfa.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| POST /webauthn/register/begin | webauthn_register_begin | http/mfa.rs:24 | — |
| POST /webauthn/register/complete | webauthn_register_complete | http/mfa.rs:26 | — |
| POST /webauthn/auth/begin | webauthn_auth_begin | http/mfa.rs:29 | — |
| POST /webauthn/auth/complete | webauthn_auth_complete | http/mfa.rs:30 | — |
| GET /webauthn/credentials | webauthn_list_credentials | http/mfa.rs:31 | — |
| DELETE /webauthn/credentials/{credential_id} | webauthn_delete_credential | http/mfa.rs:33 | — |
| POST /v1/{realm}/auth/magic-link | magic_link_request | http/mfa.rs:37 | — |

### Admin REST API (`/admin`) — `src/protocol/http/admin.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET,POST /admin/users | admin_list_users / admin_create_user | http/admin.rs:43 | AUTHORIZATION.md |
| POST /admin/users/bulk | admin_bulk_users | http/admin.rs:44 | AUTHORIZATION.md |
| POST /admin/users/import | admin_import_users | http/admin.rs:45 | — |
| GET /admin/users/export | admin_export_users | http/admin.rs:46 | — |
| GET,PATCH,DELETE /admin/users/{id} | admin_get/update/delete_user | http/admin.rs:47 | AUTHORIZATION.md |
| DELETE /admin/users/{id}/device-fingerprints | admin_delete_user_device_fingerprints | http/admin.rs:54 | — |
| GET,POST /admin/realms | admin_list_realms / admin_create_realm (405) | http/admin.rs:57 | CONFIGURATION.md |
| GET,PATCH,DELETE /admin/realms/{id} | admin_get/update(405)/delete_realm | http/admin.rs:59 | CONFIGURATION.md |
| POST /admin/realms/{id}/rotate-signing-key | admin_rotate_realm_signing_key | http/admin.rs:65 | OIDC.md |
| GET,PATCH /admin/realms/{id}/branding | admin_get/patch_realm_branding | http/admin.rs:69 | THEME.md |
| GET /admin/realms/{id}/email-templates | admin_list_realm_email_templates | http/admin.rs:73 | — |
| GET,PUT,DELETE /admin/realms/{id}/email-templates/{kind} | admin_get/put/delete_realm_email_template | http/admin.rs:77 | — |
| GET,POST /admin/applications | admin_list_clients / admin_register_client | http/admin.rs:83 | OIDC.md |
| GET,PATCH,DELETE /admin/applications/{id} | admin_get/update/delete_client | http/admin.rs:87 | OIDC.md |
| GET /admin/users/{id}/consents | admin_list_user_consents | http/admin.rs:92 | OIDC.md |
| DELETE /admin/users/{id}/consents/{client_id} | admin_revoke_user_consent | http/admin.rs:94 | OIDC.md |
| GET /admin/users/{id}/effective-permissions | admin_get_user_effective_permissions | http/admin.rs:98 | AUTHORIZATION.md |
| GET /admin/audit | admin_list_audit | http/admin.rs:101 | — |
| GET,POST /admin/roles | admin_list_roles / admin_create_role | http/admin.rs:102 | AUTHORIZATION.md |
| GET,PATCH,DELETE /admin/roles/{id} | admin_get/update/delete_role | http/admin.rs:104 | AUTHORIZATION.md |
| GET,POST /admin/groups | admin_list_groups / admin_create_group | http/admin.rs:109 | AUTHORIZATION.md |
| GET,PATCH,DELETE /admin/groups/{id} | admin_get/update/delete_group | http/admin.rs:111 | AUTHORIZATION.md |
| GET,POST /admin/groups/{id}/members | admin_list_group_members / admin_add_group_member | http/admin.rs:117 | AUTHORIZATION.md |
| DELETE /admin/groups/{id}/members/{member_id} | admin_remove_group_member | http/admin.rs:121 | AUTHORIZATION.md |
| GET,POST /admin/users/{id}/roles | admin_list_user_assignments / admin_assign_role | http/admin.rs:125 | AUTHORIZATION.md |
| DELETE /admin/assignments/{id} | admin_unassign_role | http/admin.rs:128 | AUTHORIZATION.md |
| GET,POST /admin/webhooks | admin_list_webhooks / admin_create_webhook | http/admin.rs:130 | — |
| GET,PUT,DELETE /admin/webhooks/{id} | admin_get/update/delete_webhook | http/admin.rs:134 | — |
| GET /admin/webhooks/{id}/deliveries | admin_list_webhook_deliveries | http/admin.rs:140 | — |
| POST /admin/backup | admin_backup_create | http/admin.rs:143 | — |
| POST /admin/backup/restore | admin_backup_restore | http/admin.rs:145 | — |
| PATCH /admin/realms/{realm_id}/users/{user_id}/required-actions | admin_patch_user_required_actions | http/admin.rs:150 | — |
| PATCH /admin/realms/{realm_id}/config | admin_patch_realm_config | http/admin.rs:153 | CONFIGURATION.md |
| POST /admin/sessions/{session_id}/sv-bump | admin_sv_bump_session | http/admin.rs:155 | — |
| DELETE /admin/sessions/{id} | admin_revoke_session | http/admin.rs:158 | — |
| GET /admin/users/{id}/sessions | admin_list_user_sessions | http/admin.rs:159 | — |
| POST /admin/realms/{realm_id}/sv-bump-all | admin_sv_bump_all | http/admin.rs:160 | — |
| POST /admin/cluster/bootstrap | cluster_admin::admin_cluster_bootstrap | http/admin.rs:162 | ARCHITECTURE.md |
| GET /admin/cluster/status | cluster_admin::admin_cluster_status | http/admin.rs:166 | ARCHITECTURE.md |
| POST /admin/cluster/transfer-leadership | cluster_admin::admin_cluster_transfer_leadership | http/admin.rs:170 | ARCHITECTURE.md |
| POST /admin/bootstrap (DEV-ONLY) | admin::admin_bootstrap | http.rs:316 | — (dev bootstrap; only registered when `dev_mode`) |

### Agent identity (Phase A; only when `agent_auth.capabilities.identity`) — `src/protocol/http/agents.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /.well-known/agent.json | agent_card | http/agents.rs:39 | AGENT_AUTH.md |
| GET,POST /v1/agents | list_agents / create_agent | http/agents.rs:40 | AGENT_AUTH.md |
| GET,PATCH,DELETE /v1/agents/{id} | get/update/delete_agent | http/agents.rs:42 | AGENT_AUTH.md |
| POST /v1/agents/{id}/credentials/keys | create_api_key | http/agents.rs:45 | AGENT_AUTH.md |
| GET /v1/agents/{id}/credentials | list_credentials | http/agents.rs:46 | AGENT_AUTH.md |
| DELETE /v1/agents/{id}/credentials/{cred_id} | revoke_credential | http/agents.rs:48 | AGENT_AUTH.md |

Router wrapped in fail-closed bearer-token guard (`require_bearer_token`, http.rs:298).

### Agent approval (Phase C; only when `agent_auth.capabilities.approval`) — `src/protocol/http/approval.rs` + `tool_invocation.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET,POST /v1/approval-requests | list/create_approval_request | http/approval.rs:33 | AGENT_AUTH.md §9 |
| GET /v1/approval-requests/{id} | get_approval_request | http/approval.rs:36 | AGENT_AUTH.md §9 |
| POST /v1/approval-requests/{id}/approve | approve_approval_request | http/approval.rs:38 | AGENT_AUTH.md §9 |
| POST /v1/approval-requests/{id}/deny | deny_approval_request | http/approval.rs:42 | AGENT_AUTH.md §9 |
| POST /v1/tools/invoke | invoke_tool | http/tool_invocation.rs:40 | AGENT_AUTH.md §5 |

### Agent advanced (Phase D; only when `agent_auth.capabilities.advanced`) — `src/protocol/http/advanced.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| POST /v1/aats | issue_aat | http/advanced.rs:45 | AGENT_AUTH.md §11 |
| POST /v1/aats/derive | derive_aat | http/advanced.rs:46 | AGENT_AUTH.md §11 |
| POST /v1/aats/validate | validate_aat | http/advanced.rs:47 | AGENT_AUTH.md §11 |
| DELETE /v1/aats/{jti} | revoke_aat | http/advanced.rs:48 | AGENT_AUTH.md §11 |
| POST /v1/transaction-tokens | issue_transaction_token | http/advanced.rs:50 | AGENT_AUTH.md §8 |
| POST /v1/transaction-tokens/consume | consume_transaction_token | http/advanced.rs:52 | AGENT_AUTH.md §8 |
| POST /v1/spiffe-mappings | register_spiffe_mapping | http/advanced.rs:56 | AGENT_AUTH.md §4 |
| GET,DELETE /v1/spiffe-mappings/{agent_id} | get/delete_spiffe_mapping | http/advanced.rs:58 | AGENT_AUTH.md §4 |
| GET,POST /v1/cross-realm-policies | list/create_cross_realm_policy | http/advanced.rs:63 | AGENT_AUTH.md |
| GET,DELETE /v1/cross-realm-policies/{id} | get/delete_cross_realm_policy | http/advanced.rs:67 | AGENT_AUTH.md |

### SCIM 2.0 (`/scim/v2`) — `src/protocol/scim/mod.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /scim/v2/ServiceProviderConfig | discovery::service_provider_config | scim/mod.rs:54 | — (RFC 7644) |
| GET /scim/v2/ResourceTypes | discovery::resource_types | scim/mod.rs:57 | — |
| GET /scim/v2/Schemas | discovery::schemas | scim/mod.rs:58 | — |
| POST,GET /scim/v2/Users | users::create_user / list_users | scim/mod.rs:59 | — |
| GET,PUT,DELETE,PATCH /scim/v2/Users/{id} | users::get/replace/delete/patch_user | scim/mod.rs:61,66 | — |
| POST,GET /scim/v2/Groups | groups::create_group / list_groups | scim/mod.rs:68 | — |
| GET,PUT,DELETE,PATCH /scim/v2/Groups/{id} | groups::get/replace/delete/patch_group | scim/mod.rs:72,77 | — |

### OpenAPI / docs — `src/protocol/web/openapi.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /openapi.json | serve_openapi_json | web/openapi.rs:64 | — |
| GET /openapi.yaml | serve_openapi_yaml | web/openapi.rs:65 | — |
| GET /docs | serve_swagger_ui | web/openapi.rs:66 | — |

### Dev mailcatcher (DEV-ONLY; only when `email.transport=mailcatcher` && `dev_mode`) — `src/protocol/web/mailcatcher.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET,DELETE /dev/mail | inbox / clear_inbox | web/mailcatcher.rs:240 | — (dev) |
| POST /dev/mail/clear | clear_inbox | web/mailcatcher.rs:241 | — (dev) |
| GET,POST /dev/mail/login | login_form / login_submit | web/mailcatcher.rs:243 | — (dev) |
| GET,DELETE /dev/mail/{id} | email_detail / delete_email | web/mailcatcher.rs:247 | — (dev) |
| POST /dev/mail/{id}/delete | delete_email | web/mailcatcher.rs:250 | — (dev) |

### Web UI — pre-auth & self-service (`/ui/*`) — `src/protocol/web/mod.rs` (handlers in `handlers`)

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET,POST /ui/setup | setup_form / setup_submit | web/mod.rs:762 | UI_ROUTING.md |
| GET /ui/setup/sent | setup_sent | web/mod.rs:765 | UI_ROUTING.md |
| GET /ui/verify-email | verify_email | web/mod.rs:766 | UI_ROUTING.md |
| GET,POST /ui/login | login_form / login_submit | web/mod.rs:768 | UI_ROUTING.md |
| GET /ui/login/passkey-begin | passkey_login_begin | web/mod.rs:772 | — |
| POST /ui/login/passkey-complete | passkey_login_complete | web/mod.rs:776 | — |
| GET,POST /ui/mfa-challenge | mfa_challenge_form / mfa_challenge_submit | web/mod.rs:780 | — |
| GET /ui/mfa-enroll-required | mfa_enroll_required_form | web/mod.rs:784 | — |
| POST /ui/mfa-enroll-required/activate | mfa_enroll_required_submit | web/mod.rs:788 | — |
| GET,POST /ui/forgot-password | forgot_password_form / forgot_password_submit | web/mod.rs:792 | UI_ROUTING.md |
| GET /ui/accept-invitation | accept_invitation_page | web/mod.rs:797 | — |
| GET /ui/forgot-password/sent | forgot_password_sent | web/mod.rs:801 | — |
| GET,POST /ui/reset-password | reset_password_form / reset_password_submit | web/mod.rs:805 | UI_ROUTING.md |
| GET,POST /ui/register | register_form / register_submit | web/mod.rs:809 | UI_ROUTING.md |
| GET /ui/register/sent | register_sent | web/mod.rs:813 | — |
| GET,POST /ui/realms/{realm}/login | login_form_scoped / login_submit_scoped | web/mod.rs:820 | UI_ROUTING.md |
| GET /ui/realms/{realm}/login/passkey-begin | passkey_login_begin_scoped | web/mod.rs:824 | — |
| POST /ui/realms/{realm}/login/passkey-complete | passkey_login_complete_scoped | web/mod.rs:828 | — |
| GET,POST /ui/realms/{realm}/register | register_form_scoped / register_submit_scoped | web/mod.rs:832 | UI_ROUTING.md |
| GET /ui/realms/{realm}/register/sent | register_sent_scoped | web/mod.rs:837 | — |
| GET,POST /ui/realms/{realm}/forgot-password | forgot_password_form_scoped / _submit_scoped | web/mod.rs:841 | UI_ROUTING.md |
| GET /ui/realms/{realm}/forgot-password/sent | forgot_password_sent_scoped | web/mod.rs:846 | — |
| GET,POST /ui/realms/{realm}/reset-password | reset_password_form_scoped / _submit_scoped | web/mod.rs:850 | UI_ROUTING.md |
| GET /ui/realms/{realm}/verify-email | verify_email_scoped | web/mod.rs:855 | — |
| GET /ui/realms/{realm}/accept-invitation | accept_invitation_page_scoped | web/mod.rs:859 | — |
| GET,POST /ui/admin/login | admin_login_form / admin_login_submit | web/mod.rs:867 | UI_ROUTING.md |
| GET /ui/admin/login/passkey-begin | passkey_login_begin_admin | web/mod.rs:871 | — |
| POST /ui/admin/login/passkey-complete | passkey_login_complete_admin | web/mod.rs:875 | — |
| GET /ui/admin/verify-email | admin_verify_email | web/mod.rs:879 | — |
| GET,POST /ui/admin/forgot-password | admin_forgot_password_form / _submit | web/mod.rs:883 | — |
| GET /ui/admin/forgot-password/sent | admin_forgot_password_sent | web/mod.rs:888 | — |
| GET /ui/admin | (redirect → /ui/admin/realms) | web/mod.rs:894 | UI_ROUTING.md |
| GET /ui/ | dashboard | web/mod.rs:899 | UI_ROUTING.md |
| GET,POST /ui/device | device_approve_form / device_approve_submit | web/mod.rs:901 | OIDC.md (device flow) |
| POST /ui/logout | logout_submit | web/mod.rs:904 | — |

### Web UI — required-action interstitials (`/ui/required-actions/*`)

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET,POST /ui/required-actions/update-password | ra_update_password_form / _submit | web/mod.rs:907 | — |
| GET /ui/required-actions/verify-email | ra_verify_email_page | web/mod.rs:912 | — |
| POST /ui/required-actions/verify-email/resend | ra_verify_email_resend | web/mod.rs:916 | — |
| GET /ui/required-actions/verify-email/success | ra_verify_email_success | web/mod.rs:920 | — |

### Web UI — account self-service (`/ui/account/*`) — handlers in `account` / `account_consents` / `account_linked` / `consent_delegations`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/account | account::account_index | web/mod.rs:923 | — |
| POST /ui/account/password | account::account_change_password | web/mod.rs:925 | — |
| GET /ui/account/totp | account::totp_enroll_form | web/mod.rs:929 | — |
| POST /ui/account/totp/activate | account::totp_activate | web/mod.rs:933 | — |
| POST /ui/account/totp/disable | account::totp_disable | web/mod.rs:937 | — |
| GET /ui/account/totp/recovery-codes.txt | account::totp_download_recovery_codes | web/mod.rs:941 | — |
| POST /ui/account/totp/regenerate-codes | account::totp_regenerate_codes | web/mod.rs:945 | — |
| GET /ui/account/passkeys/register-begin | account::passkey_register_begin | web/mod.rs:949 | — |
| POST /ui/account/passkeys/register-complete | account::passkey_register_complete | web/mod.rs:953 | — |
| POST /ui/account/passkeys/{cred_id}/delete | account::passkey_delete | web/mod.rs:957 | — |
| POST /ui/account/passkeys/{cred_id}/rename | account::passkey_rename | web/mod.rs:961 | — |
| GET /ui/account/sessions | account::sessions_index | web/mod.rs:965 | — |
| POST /ui/account/sessions/revoke-others | account::revoke_other_sessions | web/mod.rs:969 | — |
| POST /ui/account/sessions/{sid}/revoke | account::revoke_session | web/mod.rs:973 | — |
| GET /ui/account/consents | account_consents::consents_index | web/mod.rs:978 | OIDC.md |
| GET /ui/account/applications | account_consents::account_applications | web/mod.rs:982 | OIDC.md |
| POST /ui/account/consents/revoke-all | account_consents::revoke_all_consents | web/mod.rs:986 | OIDC.md |
| POST /ui/account/applications/revoke-all | account_consents::revoke_all_consents | web/mod.rs:990 | OIDC.md |
| POST /ui/account/consents/{client_id}/revoke | account_consents::revoke_consent | web/mod.rs:994 | OIDC.md |
| POST /ui/account/applications/{client_id}/revoke | account_consents::revoke_consent | web/mod.rs:998 | OIDC.md |
| GET /ui/consent/delegations | consent_delegations::delegations_index | web/mod.rs:1003 | AGENT_AUTH.md |
| POST /ui/consent/delegations/{delegation_id}/revoke | consent_delegations::revoke_delegation | web/mod.rs:1007 | AGENT_AUTH.md |
| GET /ui/account/linked-accounts | account_linked::linked_accounts_index | web/mod.rs:1012 | — |
| POST /ui/account/linked-accounts/{idp_id}/unlink | account_linked::unlink | web/mod.rs:1016 | — |

### Web UI — federation & SAML flows — handlers in `federation` / `saml`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/federation/begin | federation::begin | web/mod.rs:1020 | — |
| GET,POST /ui/federation/callback | federation::callback / callback_post | web/mod.rs:1022 | — |
| GET,POST /ui/federation/confirm-link | federation::confirm_link_page / _submit | web/mod.rs:1026 | — |
| GET /ui/realms/{realm}/federation/begin | federation::begin_scoped | web/mod.rs:1030 | — |
| GET,POST /ui/realms/{realm}/federation/callback | federation::callback_scoped / _post | web/mod.rs:1034 | — |
| GET /ui/realms/{realm}/federation/saml/metadata | saml::sp_metadata | web/mod.rs:1039 | — (SAML SP) |
| POST /ui/realms/{realm}/federation/saml/acs | saml::sp_acs | web/mod.rs:1043 | — (SAML SP ACS) |
| GET /ui/realms/{realm}/federation/saml/begin | saml::sp_begin | web/mod.rs:1047 | — |
| GET /ui/realms/{realm}/saml/metadata | saml::idp_metadata | web/mod.rs:1051 | — (SAML IdP) |
| GET,POST /ui/realms/{realm}/saml/sso | saml::idp_sso_get / idp_sso_post | web/mod.rs:1055 | — (SAML IdP SSO) |
| GET /ui/realms/{realm}/saml/sso/init | saml::idp_sso_init | web/mod.rs:1059 | — |
| GET,POST /ui/realms/{realm}/saml/slo-idp | saml::idp_slo_get / idp_slo_post | web/mod.rs:1063 | — (SAML SLO) |

### Web UI — browser OAuth authorize/consent & SMS challenge — handlers in `oauth_consent` / `sms_challenge`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/oauth/authorize | oauth_consent::authorize_get | web/mod.rs:1068 | OIDC.md |
| GET /ui/realms/{realm}/oauth/authorize | oauth_consent::authorize_get_scoped | web/mod.rs:1072 | OIDC.md |
| GET,POST /ui/oauth/consent | oauth_consent::consent_page / consent_submit | web/mod.rs:1076 | OIDC.md |
| GET,POST /ui/sms-challenge | sms_challenge::sms_challenge_get / _post | web/mod.rs:1081 | — |

### Web UI — admin onboarding wizard (`/ui/admin/onboarding/*`) — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/admin/onboarding | admin::admin_onboarding_get | web/mod.rs:1087 | UI_ROUTING.md |
| POST /ui/admin/onboarding/realm | admin::admin_onboarding_realm_post | web/mod.rs:1091 | — |
| GET,POST /ui/admin/onboarding/app | admin::admin_onboarding_app_get / _post | web/mod.rs:1095 | — |
| GET,POST /ui/admin/onboarding/invite | admin::admin_onboarding_invite_get / _post | web/mod.rs:1100 | — |
| GET /ui/admin/onboarding/email | admin::admin_onboarding_email_get | web/mod.rs:1105 | — |
| POST /ui/admin/onboarding/email/test | admin::admin_onboarding_email_test_post | web/mod.rs:1109 | — |
| GET /ui/admin/onboarding/complete | admin::admin_onboarding_complete_get | web/mod.rs:1113 | — |

### Web UI — admin-users, migrations, realms list (system-scoped) — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/admin/admin-users | admin::admin_admin_users_list | web/mod.rs:1117 | UI_ROUTING.md |
| GET /ui/admin/admin-users/new | admin::admin_admin_user_create_alias | web/mod.rs:1125 | — |
| GET,POST /ui/admin/admin-users/import | admin::admin_admin_users_import_form / _submit | web/mod.rs:1129 | — |
| GET /ui/admin/admin-users/import/template.csv | admin::admin_admin_users_import_template_csv | web/mod.rs:1134 | — |
| GET /ui/admin/migrations | admin::admin_migrations_list | web/mod.rs:1139 | — |
| POST /ui/admin/migrations/orphans/resolve | admin::admin_migrations_orphan_resolve | web/mod.rs:1143 | — |
| GET /ui/admin/realms | admin::admin_realms_list | web/mod.rs:1148 | UI_ROUTING.md |

### Web UI — admin realm-scoped: users (`/ui/admin/realms/{realm}/users/*`) — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/admin/realms/{realm}/users | admin::admin_users_list | web/mod.rs:1153 | AUTHORIZATION.md |
| GET,POST /ui/admin/realms/{realm}/users/new | admin::admin_user_create_form / _submit | web/mod.rs:1157 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/users/{id} | admin::admin_user_detail | web/mod.rs:1161 | — |
| GET,POST /ui/admin/realms/{realm}/users/{id}/edit | admin::admin_user_edit_form / _submit | web/mod.rs:1165 | — |
| POST /ui/admin/realms/{realm}/users/{id}/delete | admin::admin_user_delete | web/mod.rs:1169 | — |
| POST /ui/admin/realms/{realm}/users/{id}/reset-password | admin::admin_user_send_reset | web/mod.rs:1173 | — |
| POST /ui/admin/realms/{realm}/users/{id}/disable-mfa | admin::admin_user_disable_mfa | web/mod.rs:1177 | — |
| POST /ui/admin/realms/{realm}/users/{id}/remove-phone | admin::admin_user_remove_phone | web/mod.rs:1181 | — |
| POST /ui/admin/realms/{realm}/users/{id}/reset-mfa-codes | admin::admin_user_reset_mfa_codes | web/mod.rs:1185 | — |
| POST /ui/admin/realms/{realm}/users/{id}/sessions/{sid}/revoke | admin::admin_user_revoke_session | web/mod.rs:1189 | — |
| POST /ui/admin/realms/{realm}/users/{id}/webauthn/{cred_id}/revoke | admin::admin_user_revoke_webauthn | web/mod.rs:1193 | — |
| POST /ui/admin/realms/{realm}/users/{id}/roles/assign | admin::admin_user_assign_role | web/mod.rs:1197 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/users/{id}/roles/{assignment_id}/unassign | admin::admin_user_unassign_role | web/mod.rs:1201 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/users/{id}/permissions/grant | admin::admin_user_grant_permission | web/mod.rs:1205 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/users/{id}/permissions/revoke | admin::admin_user_revoke_permission | web/mod.rs:1209 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/users/{id}/consents | admin::admin_user_consents_list | web/mod.rs:1213 | OIDC.md |
| GET /ui/admin/realms/{realm}/users/{id}/applications | admin::admin_user_consents_list | web/mod.rs:1217 | OIDC.md |
| POST /ui/admin/realms/{realm}/users/{id}/consents/{client_id}/revoke | admin::admin_user_consent_revoke | web/mod.rs:1221 | OIDC.md |
| POST /ui/admin/realms/{realm}/users/{id}/applications/{client_id}/revoke | admin::admin_user_consent_revoke | web/mod.rs:1225 | OIDC.md |
| PATCH /ui/admin/realms/{realm}/users/{id}/required-actions | admin::admin_api_user_required_actions_patch | web/mod.rs:1229 | — |
| GET,POST /ui/admin/realms/{realm}/users/bulk-action | admin::admin_users_bulk_action | web/mod.rs:1550 | — |
| GET,POST /ui/admin/realms/{realm}/users/import | admin::admin_users_import_form / _submit | web/mod.rs:1554 | — |
| GET /ui/admin/realms/{realm}/users/import/template.csv | admin::admin_users_import_template_csv | web/mod.rs:1559 | — |
| GET /ui/admin/realms/{realm}/api/users/search | admin::admin_api_user_search | web/mod.rs:1422 | — |
| GET /ui/admin/realms/{realm}/rbac/api/users/search | admin::admin_api_rbac_user_search | web/mod.rs:1426 | — |

### Web UI — admin realm-scoped: realm meta, RBAC, scopes, claims — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| PATCH /ui/admin/realms/{realm}/config | admin::admin_api_realm_config_patch | web/mod.rs:1234 | CONFIGURATION.md |
| GET /ui/admin/realms/{realm} | admin::admin_realm_detail | web/mod.rs:1239 | UI_ROUTING.md |
| POST /ui/admin/realms/{realm}/delete | admin::admin_realm_delete | web/mod.rs:1243 | — |
| GET /ui/admin/realms/{realm}/admins/picker | admin::admin_realm_admin_picker | web/mod.rs:1247 | — |
| POST /ui/admin/realms/{realm}/admins/grant | admin::admin_realm_admin_grant | web/mod.rs:1251 | — |
| POST /ui/admin/realms/{realm}/admins/{uid}/revoke | admin::admin_realm_admin_revoke | web/mod.rs:1255 | — |
| GET /ui/admin/realms/{realm}/claims | admin::admin_realm_claims | web/mod.rs:1259 | AUTHZ_EXPANSION.md |
| GET /ui/admin/realms/{realm}/rbac/debug | admin::admin_rbac_debug | web/mod.rs:1264 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/permissions/resolve | admin::admin_permissions_resolve_alias | web/mod.rs:1270 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/rbac/token-preview | admin::admin_rbac_token_preview | web/mod.rs:1274 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/rbac/permissions | admin::admin_rbac_permissions | web/mod.rs:1278 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/rbac/roles | admin::admin_rbac_roles | web/mod.rs:1282 | AUTHORIZATION.md |
| GET,POST /ui/admin/realms/{realm}/rbac/roles/new | admin::admin_role_create_form / _submit | web/mod.rs:1286 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/rbac/roles/{id} | admin::admin_role_detail | web/mod.rs:1290 | AUTHORIZATION.md |
| GET,POST /ui/admin/realms/{realm}/rbac/roles/{id}/edit | admin::admin_role_edit_form / _submit | web/mod.rs:1294 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/rbac/roles/{id}/delete | admin::admin_role_delete | web/mod.rs:1298 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/rbac/scopes | admin::admin_rbac_scopes | web/mod.rs:1302 | AUTHZ_EXPANSION.md |

### Web UI — admin realm-scoped: organizations — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/admin/realms/{realm}/organizations | admin::admin_orgs_list | web/mod.rs:1307 | — |
| GET,POST /ui/admin/realms/{realm}/organizations/new | admin::admin_org_create_form / _submit | web/mod.rs:1311 | — |
| POST /ui/admin/realms/{realm}/organizations/bulk-delete | admin::admin_orgs_bulk_delete | web/mod.rs:1315 | — |
| GET /ui/admin/realms/{realm}/organizations/{id} | admin::admin_org_detail | web/mod.rs:1319 | — |
| GET,POST /ui/admin/realms/{realm}/organizations/{id}/edit | admin::admin_org_edit_form / _submit | web/mod.rs:1323 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/delete | admin::admin_org_delete | web/mod.rs:1327 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/members | admin::admin_org_add_member | web/mod.rs:1331 | — |
| GET /ui/admin/realms/{realm}/organizations/{id}/members/picker | admin::admin_org_member_picker | web/mod.rs:1335 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/members/{uid}/remove | admin::admin_org_remove_member | web/mod.rs:1339 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/members/{uid}/role | admin::admin_org_update_role | web/mod.rs:1343 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/invite | admin::admin_org_invite | web/mod.rs:1347 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/status | admin::admin_org_status_toggle | web/mod.rs:1351 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/invitations/{iid}/revoke | admin::admin_org_revoke_invite | web/mod.rs:1355 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/invitations/{iid}/resend | admin::admin_org_resend_invite | web/mod.rs:1359 | — |
| POST /ui/admin/realms/{realm}/organizations/{id}/members/{uid}/rbac/assign | admin::admin_org_member_assign_role | web/mod.rs:1363 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/organizations/{id}/members/{uid}/rbac/{aid}/unassign | admin::admin_org_member_unassign_role | web/mod.rs:1367 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/organizations/{id}/members/{uid}/permissions/grant | admin::admin_org_member_grant_perm | web/mod.rs:1371 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/organizations/{id}/members/{uid}/permissions/revoke | admin::admin_org_member_revoke_perm | web/mod.rs:1375 | AUTHORIZATION.md |

### Web UI — admin realm-scoped: groups — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/admin/realms/{realm}/groups | admin::admin_groups_list | web/mod.rs:1380 | AUTHORIZATION.md |
| GET,POST /ui/admin/realms/{realm}/groups/new | admin::admin_group_create_form / _submit | web/mod.rs:1384 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/groups/{id} | admin::admin_group_detail | web/mod.rs:1389 | AUTHORIZATION.md |
| GET,POST /ui/admin/realms/{realm}/groups/{id}/edit | admin::admin_group_edit_form / _submit | web/mod.rs:1393 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/groups/{id}/delete | admin::admin_group_delete | web/mod.rs:1397 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/groups/{id}/members | admin::admin_group_member_add | web/mod.rs:1401 | AUTHORIZATION.md |
| GET /ui/admin/realms/{realm}/groups/{id}/members/picker | admin::admin_group_member_picker | web/mod.rs:1405 | — |
| POST /ui/admin/realms/{realm}/groups/{id}/members/{kind}/{mid}/remove | admin::admin_group_member_remove | web/mod.rs:1409 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/groups/{id}/roles/assign | admin::admin_group_role_assign | web/mod.rs:1413 | AUTHORIZATION.md |
| POST /ui/admin/realms/{realm}/groups/{id}/roles/{aid}/unassign | admin::admin_group_role_unassign | web/mod.rs:1417 | AUTHORIZATION.md |

### Web UI — admin realm-scoped: applications, IdPs, sessions, audit, webhooks, approvals, abuse — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/admin/realms/{realm}/applications | admin::admin_apps_list | web/mod.rs:1441 | OIDC.md |
| GET,POST /ui/admin/realms/{realm}/applications/new | admin::admin_app_create_form / _submit | web/mod.rs:1445 | OIDC.md |
| GET /ui/admin/realms/{realm}/applications/{id} | admin::admin_app_detail | web/mod.rs:1449 | OIDC.md |
| GET,POST /ui/admin/realms/{realm}/applications/{id}/edit | admin::admin_app_edit_form / _submit | web/mod.rs:1453 | OIDC.md |
| POST /ui/admin/realms/{realm}/applications/{id}/delete | admin::admin_app_delete | web/mod.rs:1457 | OIDC.md |
| POST /ui/admin/realms/{realm}/applications/{id}/regenerate-secret | admin::admin_app_regenerate_secret | web/mod.rs:1461 | OIDC.md |
| GET /ui/admin/realms/{realm}/identity-providers | admin::admin_idp_list | web/mod.rs:1466 | — |
| GET /ui/admin/realms/{realm}/identity-providers/{id} | admin::admin_idp_detail | web/mod.rs:1470 | — |
| GET /ui/admin/realms/{realm}/sessions | admin::admin_sessions_list | web/mod.rs:1475 | — |
| POST /ui/admin/realms/{realm}/sessions/{id}/revoke | admin::admin_session_revoke | web/mod.rs:1479 | — |
| GET /ui/admin/realms/{realm}/audit | admin::admin_audit_list | web/mod.rs:1484 | — |
| POST /ui/admin/realms/{realm}/audit/verify | admin::admin_audit_verify_integrity | web/mod.rs:1488 | — |
| GET /ui/admin/realms/{realm}/audit/export | admin::admin_audit_export | web/mod.rs:1492 | — |
| GET /ui/admin/api/realms/{realm}/audit/events | admin::admin_api_audit_events | web/mod.rs:1496 | — |
| GET,PUT /ui/admin/api/realms/{realm}/audit/config | admin::admin_api_audit_config_get / _put | web/mod.rs:1500 | — |
| POST /ui/admin/api/realms/{realm}/audit/prune | admin::admin_api_audit_prune | web/mod.rs:1505 | — |
| GET /ui/admin/realms/{realm}/abuse | admin::admin_abuse_dashboard | web/mod.rs:1564 | — |
| GET /ui/admin/realms/{realm}/webhooks | admin::admin_webhooks_list | web/mod.rs:1569 | — |
| GET,POST /ui/admin/realms/{realm}/webhooks/new | admin::admin_webhook_create_form / _submit | web/mod.rs:1573 | — |
| POST /ui/admin/realms/{realm}/webhooks/test-ping | admin::admin_webhook_test_ping | web/mod.rs:1578 | — |
| GET,POST /ui/admin/realms/{realm}/webhooks/{id}/edit | admin::admin_webhook_edit_form / _submit | web/mod.rs:1582 | — |
| POST /ui/admin/realms/{realm}/webhooks/{id}/delete | admin::admin_webhook_delete | web/mod.rs:1587 | — |
| POST /ui/admin/realms/{realm}/webhooks/{id}/test | admin::admin_webhook_test | web/mod.rs:1591 | — |
| GET /ui/admin/realms/{realm}/approvals | admin::admin_approvals_queue | web/mod.rs:1596 | AGENT_AUTH.md §9 |
| GET /ui/admin/realms/{realm}/approvals/{id} | admin::admin_approval_detail | web/mod.rs:1600 | AGENT_AUTH.md §9 |
| POST /ui/admin/realms/{realm}/approvals/{id}/approve | admin::admin_approval_approve | web/mod.rs:1604 | AGENT_AUTH.md §9 |
| POST /ui/admin/realms/{realm}/approvals/{id}/deny | admin::admin_approval_deny | web/mod.rs:1608 | AGENT_AUTH.md §9 |

### Web UI — admin system settings, config editor, nav APIs — handlers in `admin`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| POST /ui/admin/api/config/reload | admin::admin_api_config_reload | web/mod.rs:1431 | CONFIGURATION.md |
| GET /ui/admin/api/nav/realms | admin::admin_api_nav_realms | web/mod.rs:1436 | — |
| GET /ui/admin/settings | admin::admin_system_info | web/mod.rs:1509 | — |
| GET /ui/admin/settings/editor | admin::admin_config_editor | web/mod.rs:1513 | CONFIGURATION.md |
| POST /ui/admin/settings/editor/preview | admin::admin_config_editor_preview | web/mod.rs:1517 | CONFIGURATION.md |
| POST /ui/admin/settings/editor/apply | admin::admin_config_editor_apply | web/mod.rs:1521 | CONFIGURATION.md |
| POST /ui/admin/settings/editor/visual/preview | admin::admin_config_editor_visual_preview | web/mod.rs:1525 | CONFIGURATION.md |
| POST /ui/admin/settings/editor/visual/validate | admin::admin_config_editor_visual_validate | web/mod.rs:1529 | CONFIGURATION.md |
| POST /ui/admin/settings/editor/visual/apply | admin::admin_config_editor_visual_apply | web/mod.rs:1533 | CONFIGURATION.md |
| POST /ui/admin/settings/editor/visual/export | admin::admin_config_editor_visual_export | web/mod.rs:1537 | CONFIGURATION.md |
| GET /ui/admin/settings/editor/export | admin::admin_config_editor_export | web/mod.rs:1541 | CONFIGURATION.md |
| POST /ui/admin/test-email | admin::admin_test_email | web/mod.rs:1545 | — |
| GET /ui/static/{*file} | serve_static | web/mod.rs:1611 | THEME.md |

### Web UI — top-level (outside `/ui`) & required-action pages — `src/protocol/web/mod.rs`

| Method+Path | Handler fn | File:line | Spec reference |
|---|---|---|---|
| GET /ui/ | (redirect → /ui) | web/mod.rs:1620 | UI_ROUTING.md |
| GET /favicon.ico | serve_favicon | web/mod.rs:1623 | — |
| GET /favicon.svg | serve_favicon | web/mod.rs:1624 | — |
| GET /required-action/VERIFY_EMAIL/confirm | required_action::verify_email_confirm | web/mod.rs:1629 | — |
| GET /required-action/VERIFY_EMAIL | required_action::verify_email_page | web/mod.rs:1633 | — |
| GET,POST /required-action/UPDATE_PASSWORD | required_action::update_password_page / _submit | web/mod.rs:1637 | — |
| GET /required-action/ENROLL_PHONE_OTP | required_action::enroll_phone_otp_page | web/mod.rs:1642 | — |
| POST /required-action/ENROLL_PHONE_OTP/send | required_action::enroll_phone_otp_send | web/mod.rs:1646 | — |
| POST /required-action/ENROLL_PHONE_OTP/verify | required_action::enroll_phone_otp_verify_submit | web/mod.rs:1650 | — |
| GET /required-action/ENROLL_EMAIL_OTP | required_action::enroll_email_otp_page | web/mod.rs:1654 | — |
| POST /required-action/ENROLL_EMAIL_OTP/send | required_action::enroll_email_otp_send | web/mod.rs:1658 | — |
| POST /required-action/ENROLL_EMAIL_OTP/verify | required_action::enroll_email_otp_verify_submit | web/mod.rs:1662 | — |
| GET,POST /required-action/enroll-mfa | required_action::enroll_mfa_page / _submit | web/mod.rs:1666 | — |
| GET,POST /required-action/{action} | required_action::action_page / action_complete | web/mod.rs:1671 | — |
| ANY (fallback) | serve_branded_404 | web/mod.rs:1681 | — |

### Notes

- Feature-gated routers (registered only when the matching capability/flag is on): agents (`agent_identity_enabled`), approval + tool_invocation (`agent_approval_enabled`), advanced (`agent_advanced_enabled`) — see `http.rs:296-311`.
- Dev-only routers: `POST /admin/bootstrap` (`http.rs:315`) and the `/dev/mail/*` mailcatcher tree (`main.rs:2312`).
- Cross-cutting middleware (not routes): per-IP rate limit, JSON depth guard, metrics, Host allowlist, security headers — `http.rs:322-351`.
- SCIM (`/scim/v2`) and SAML (`/ui/.../saml/*`, `/ui/.../federation/saml/*`) have **no dedicated doc under `docs/specs/`**; RFC 7644 / SAML 2.0 are the external normative refs.
## gRPC Services & Methods

Code-derived inventory of every gRPC service and RPC in the Hearth repo. Sources: `proto/hearth/**/*.proto` (definitions) and tonic server impls under `src/protocol/grpc/` and `src/cluster/`. `oauth.proto` defines only messages (no service).

Proto packages: `hearth.identity.v1`, `hearth.rbac.v1`, `hearth.events.v1`, `hearth.cluster.v1`.

---

### IdentityAdminService (`hearth.identity.v1`)

Impl: `src/protocol/grpc/identity.rs:96` (`impl IdentityAdminService for IdentityAdminSvc`). Admin interceptor: bearer token + RBAC admin check, realm via `x-realm-id` metadata, 100 req/min. Proto: `proto/hearth/identity/v1/identity.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| IdentityAdminService.ListUsers | ListUsersRequest → UserPage | identity.proto:390 | grpc/identity.rs:96 | AUTHORIZATION.md; grpc mgmt API notes |
| IdentityAdminService.GetUser | GetUserRequest → User | identity.proto:393 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.CreateUser | CreateUserRequest → User | identity.proto:396 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.UpdateUser | UpdateUserCall → User | identity.proto:402 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.DeleteUser | DeleteUserRequest → Empty | identity.proto:408 | grpc/identity.rs:96 | AUTHORIZATION.md |
| IdentityAdminService.ListRealms | ListRealmsRequest → RealmPage | identity.proto:414 | grpc/identity.rs:96 | grpc mgmt API notes (system realm) |
| IdentityAdminService.GetRealm | GetRealmRequest → Realm | identity.proto:417 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.CreateRealm | CreateRealmRequest → Realm | identity.proto:420 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.UpdateRealm | UpdateRealmCall → Realm | identity.proto:426 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.DeleteRealm | DeleteRealmRequest → Empty | identity.proto:432 | grpc/identity.rs:96 | grpc mgmt API notes |
| IdentityAdminService.ListOrganizations | ListOrganizationsRequest → OrganizationPage | identity.proto:437 | grpc/identity.rs:96 | gRPC-only (HEA-969); grpc mgmt API notes |
| IdentityAdminService.GetOrganization | GetOrganizationRequest → Organization | identity.proto:438 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.CreateOrganization | CreateOrganizationRequest → Organization | identity.proto:439 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.UpdateOrganization | UpdateOrganizationCall → Organization | identity.proto:440 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.DeleteOrganization | DeleteOrganizationRequest → Empty | identity.proto:441 | grpc/identity.rs:96 | gRPC-only (HEA-969) |
| IdentityAdminService.ListAgents | ListAgentsRequest → AgentPage | identity.proto:444 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A (HEA-1405) |
| IdentityAdminService.GetAgent | GetAgentRequest → Agent | identity.proto:447 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.CreateAgent | CreateAgentRequest → Agent | identity.proto:450 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.UpdateAgent | UpdateAgentCall → Agent | identity.proto:456 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.DeleteAgent | DeleteAgentRequest → Empty | identity.proto:462 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.CreateAgentApiKey | CreateAgentApiKeyRequest → CreateAgentApiKeyResponse | identity.proto:465 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.ListAgentCredentials | ListAgentCredentialsRequest → AgentCredentialPage | identity.proto:471 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |
| IdentityAdminService.RevokeAgentCredential | RevokeAgentCredentialRequest → Empty | identity.proto:474 | grpc/identity.rs:96 | AGENT_AUTH.md Phase A |

### RbacAdminService (`hearth.rbac.v1`)

Impl: `src/protocol/grpc/rbac_admin.rs:293`. No service-to-service Check RPC — callers decode the JWT `permissions` claim locally. Proto: `proto/hearth/rbac/v1/rbac.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| RbacAdminService.ListRoles | ListRolesRequest → ListRolesResponse | rbac.proto:13 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.CreateRole | CreateRoleRequest → Role | rbac.proto:16 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.GetRole | GetRoleRequest → Role | rbac.proto:22 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.UpdateRole | UpdateRoleRequest → Role | rbac.proto:25 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.DeleteRole | DeleteRoleRequest → DeleteRoleResponse | rbac.proto:31 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.ListGroups | ListGroupsRequest → ListGroupsResponse | rbac.proto:35 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.CreateGroup | CreateGroupRequest → Group | rbac.proto:38 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.GetGroup | GetGroupRequest → Group | rbac.proto:44 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.UpdateGroup | UpdateGroupRequest → Group | rbac.proto:47 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.DeleteGroup | DeleteGroupRequest → DeleteGroupResponse | rbac.proto:53 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.ListGroupMembers | ListGroupMembersRequest → ListGroupMembersResponse | rbac.proto:57 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.AddGroupMember | AddGroupMemberRequest → GroupMembership | rbac.proto:60 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.RemoveGroupMember | RemoveGroupMemberRequest → RemoveGroupMemberResponse | rbac.proto:66 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.AssignUserRole | AssignUserRoleRequest → RoleAssignment | rbac.proto:70 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.UnassignUserRole | UnassignUserRoleRequest → UnassignUserRoleResponse | rbac.proto:76 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.ListUserAssignments | ListUserAssignmentsRequest → ListUserAssignmentsResponse | rbac.proto:79 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.AssignGroupRole | AssignGroupRoleRequest → RoleAssignment | rbac.proto:85 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.UnassignGroupRole | UnassignGroupRoleRequest → UnassignGroupRoleResponse | rbac.proto:86 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListRoleMembers | ListRoleMembersRequest → ListRoleMembersResponse | rbac.proto:87 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ResolveEffectivePermissions | ResolveEffectivePermissionsRequest → ResolveEffectivePermissionsResponse | rbac.proto:89 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md §8.2 |
| RbacAdminService.GrantUserPermission | GrantUserPermissionRequest → GrantUserPermissionResponse | rbac.proto:95 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969); AUTHZ_EXPANSION.md |
| RbacAdminService.RevokeUserPermission | RevokeUserPermissionRequest → RevokeUserPermissionResponse | rbac.proto:96 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969); AUTHZ_EXPANSION.md |
| RbacAdminService.ListUserPermissions | ListUserPermissionsRequest → ListUserPermissionsResponse | rbac.proto:97 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.AddAdditionalRole | AddAdditionalRoleRequest → AddAdditionalRoleResponse | rbac.proto:101 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.RemoveAdditionalRole | RemoveAdditionalRoleRequest → RemoveAdditionalRoleResponse | rbac.proto:102 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListAdditionalRoles | ListAdditionalRolesRequest → ListAdditionalRolesResponse | rbac.proto:103 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListRealmPermissions | ListRealmPermissionsRequest → ListRealmPermissionsResponse | rbac.proto:106 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.ListRealmRoles | ListRealmRolesRequest → ListRealmRolesResponse | rbac.proto:107 | grpc/rbac_admin.rs:293 | gRPC-only (HEA-969) |
| RbacAdminService.RevokeConsent | RevokeConsentRequest → RevokeConsentResponse | rbac.proto:112 | grpc/rbac_admin.rs:293 | AUTHORIZATION.md; OIDC.md (consent) |
| RbacAdminService.ListUserConsents | ListUserConsentsRequest → ListUserConsentsResponse | rbac.proto:117 | grpc/rbac_admin.rs:293 | OIDC.md (consent) |

### AuditService (`hearth.events.v1`)

Impl: `src/protocol/grpc/audit.rs:26`. Proto: `proto/hearth/events/v1/audit.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| AuditService.ListEvents | AuditQuery → AuditEventPage | audit.proto:205 | grpc/audit.rs:26 | grpc mgmt API notes |
| AuditService.VerifyIntegrity | VerifyIntegrityRequest → VerifyIntegrityResponse | audit.proto:209 | grpc/audit.rs:26 | gRPC-only (audit hash chain) |

### RaftService (`hearth.cluster.v1`)

Impl: `src/cluster/server.rs:65` (`impl<D: IncomingRpcDispatch> RaftService for RaftRpcHandler<D>`). Internal peer-to-peer consensus (openraft); not a public/admin API. Proto: `proto/hearth/cluster/v1/raft.proto`.

| Service.Method | Request→Response | Proto file:line | Impl file | Spec reference |
|---|---|---|---|---|
| RaftService.AppendEntries | AppendEntriesRequest → AppendEntriesResponse | raft.proto:19 | cluster/server.rs:65 | ARCHITECTURE.md (Cluster layer) |
| RaftService.Vote | VoteRequest → VoteResponse | raft.proto:22 | cluster/server.rs:65 | ARCHITECTURE.md (Cluster layer) |
| RaftService.InstallSnapshot | InstallSnapshotRequest → InstallSnapshotResponse | raft.proto:26 | cluster/server.rs:65 | ARCHITECTURE.md (Cluster layer) |

---

### Summary

- **Services:** 4 (IdentityAdminService, RbacAdminService, AuditService, RaftService).
- **Total RPCs:** 60 (Identity 22, Rbac 29, Audit 2, Raft 3).
- **RPCs without a server impl:** none. Every RPC is served by one of the four `impl … Service` blocks found in `src/protocol/grpc/{identity,rbac_admin,audit}.rs` and `src/cluster/server.rs`.
- `proto/hearth/identity/v1/oauth.proto` defines OAuth message types only (no service); OAuth/OIDC flows are served over REST, not gRPC.
- Several RPCs are gRPC-only (no REST `google.api.http` binding), tracked under HEA-969.
## UI Routes & Templates

All routes are nested under the `/ui` mount prefix and registered in
`src/protocol/web/mod.rs` (`router()`, lines 758–1612). Routes marked (GET/POST)
render a form on GET and process a submission on POST. `File:line` cites the
`.route(...)` registration in `mod.rs`. Templates are Askama structs in the
handler module; the mapping below is derived from handler doc-comments and the
`templates/ui/` tree. Partials (`_*.html`) are HTMX fragments with no standalone
route by design. Spec refs: `docs/specs/UI_ROUTING.md` (route/realm reservation),
`docs/specs/THEME.md` (applies to every template).

### Pre-auth / auth flow

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/setup` (GET/POST) | `handlers::setup_form`/`setup_submit` | `setup.html` | mod.rs:761 | UI_ROUTING.md |
| `/ui/setup/sent` | `handlers::setup_sent` | `setup_sent.html` | mod.rs:765 | THEME.md |
| `/ui/verify-email` | `handlers::verify_email` | `verify_email_ok.html`/`verify_email_invalid.html` | mod.rs:766 | THEME.md |
| `/ui/login` (GET/POST) | `handlers::login_form`/`login_submit` | `login.html` | mod.rs:767 | UI_ROUTING.md |
| `/ui/login/passkey-begin` | `handlers::passkey_login_begin` | — (JSON) | mod.rs:771 | — |
| `/ui/login/passkey-complete` | `handlers::passkey_login_complete` | — (JSON) | mod.rs:775 | — |
| `/ui/mfa-challenge` (GET/POST) | `handlers::mfa_challenge_form`/`_submit` | `mfa_challenge.html` / `mfa_recovery.html` | mod.rs:779 | THEME.md |
| `/ui/mfa-enroll-required` | `handlers::mfa_enroll_required_form` | `mfa_enroll_required.html` | mod.rs:783 | THEME.md |
| `/ui/mfa-enroll-required/activate` | `handlers::mfa_enroll_required_submit` | `mfa_enroll_required.html` | mod.rs:787 | THEME.md |
| `/ui/forgot-password` (GET/POST) | `handlers::forgot_password_form`/`_submit` | `forgot_password.html` | mod.rs:791 | THEME.md |
| `/ui/accept-invitation` | `handlers::accept_invitation_page` | `accept_invitation.html` | mod.rs:796 | THEME.md |
| `/ui/forgot-password/sent` | `handlers::forgot_password_sent` | `forgot_password_sent.html` | mod.rs:800 | THEME.md |
| `/ui/reset-password` (GET/POST) | `handlers::reset_password_form`/`_submit` | `reset_password.html` / `reset_password_ok.html` | mod.rs:804 | THEME.md |
| `/ui/register` (GET/POST) | `handlers::register_form`/`_submit` | `register.html` | mod.rs:808 | THEME.md |
| `/ui/register/sent` | `handlers::register_sent` | `register_sent.html` | mod.rs:812 | THEME.md |
| `/ui/sms-challenge` (GET/POST) | `sms_challenge::sms_challenge_get`/`_post` | `sms_challenge.html` | mod.rs:1080 | THEME.md |

### Realm-scoped pre-auth (`/ui/realms/{realm}/…`)

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/realms/{realm}/login` (GET/POST) | `handlers::login_form_scoped`/`_submit_scoped` | `login.html` | mod.rs:819 | UI_ROUTING.md |
| `/ui/realms/{realm}/login/passkey-begin` | `handlers::passkey_login_begin_scoped` | — (JSON) | mod.rs:823 | UI_ROUTING.md |
| `/ui/realms/{realm}/login/passkey-complete` | `handlers::passkey_login_complete_scoped` | — (JSON) | mod.rs:827 | UI_ROUTING.md |
| `/ui/realms/{realm}/register` (GET/POST) | `handlers::register_form_scoped`/`_submit_scoped` | `register.html` | mod.rs:831 | UI_ROUTING.md |
| `/ui/realms/{realm}/register/sent` | `handlers::register_sent_scoped` | `register_sent.html` | mod.rs:836 | UI_ROUTING.md |
| `/ui/realms/{realm}/forgot-password` (GET/POST) | `handlers::forgot_password_form_scoped`/`_submit_scoped` | `forgot_password.html` | mod.rs:840 | UI_ROUTING.md |
| `/ui/realms/{realm}/forgot-password/sent` | `handlers::forgot_password_sent_scoped` | `forgot_password_sent.html` | mod.rs:845 | UI_ROUTING.md |
| `/ui/realms/{realm}/reset-password` (GET/POST) | `handlers::reset_password_form_scoped`/`_submit_scoped` | `reset_password.html` | mod.rs:849 | UI_ROUTING.md |
| `/ui/realms/{realm}/verify-email` | `handlers::verify_email_scoped` | `verify_email_ok.html`/`verify_email_invalid.html` | mod.rs:854 | UI_ROUTING.md |
| `/ui/realms/{realm}/accept-invitation` | `handlers::accept_invitation_page_scoped` | `accept_invitation.html` | mod.rs:858 | UI_ROUTING.md |

### Admin pre-auth + home

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/admin/login` (GET/POST) | `handlers::admin_login_form`/`_submit` | `login.html` | mod.rs:866 | UI_ROUTING.md |
| `/ui/admin/login/passkey-begin` | `handlers::passkey_login_begin_admin` | — (JSON) | mod.rs:870 | UI_ROUTING.md |
| `/ui/admin/login/passkey-complete` | `handlers::passkey_login_complete_admin` | — (JSON) | mod.rs:874 | UI_ROUTING.md |
| `/ui/admin/verify-email` | `handlers::admin_verify_email` | `verify_email_ok.html` | mod.rs:878 | UI_ROUTING.md |
| `/ui/admin/forgot-password` (GET/POST) | `handlers::admin_forgot_password_form`/`_submit` | `forgot_password.html` | mod.rs:882 | UI_ROUTING.md |
| `/ui/admin/forgot-password/sent` | `handlers::admin_forgot_password_sent` | `forgot_password_sent.html` | mod.rs:887 | UI_ROUTING.md |
| `/ui/admin` → `/ui/admin/realms` | inline redirect | — | mod.rs:893 | UI_ROUTING.md (R-2) |

### Authenticated shell / device / logout / required-actions

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/` (dashboard) | `handlers::dashboard` | `dashboard.html` | mod.rs:899 | THEME.md |
| `/ui/device` (GET/POST) | `handlers::device_approve_form`/`_submit` | `device_approve.html` | mod.rs:900 | THEME.md |
| `/ui/logout` (POST) | `handlers::logout_submit` | — (redirect) | mod.rs:904 | — |
| `/ui/required-actions/update-password` (GET/POST) | `handlers::ra_update_password_form`/`_submit` | `required-actions/update_password.html` | mod.rs:906 | THEME.md |
| `/ui/required-actions/verify-email` | `handlers::ra_verify_email_page` | `required-actions/verify_email.html` | mod.rs:911 | THEME.md |
| `/ui/required-actions/verify-email/resend` (POST) | `handlers::ra_verify_email_resend` | — (redirect) | mod.rs:915 | — |
| `/ui/required-actions/verify-email/success` | `handlers::ra_verify_email_success` | `required-actions/verify_email_success.html` | mod.rs:919 | THEME.md |

### Self-service account (`/ui/account/…`)

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/account` | `account::account_index` | `account/index.html` | mod.rs:923 | THEME.md |
| `/ui/account/password` (POST) | `account::account_change_password` | — (redirect) | mod.rs:924 | — |
| `/ui/account/totp` | `account::totp_enroll_form` | `account/totp.html` | mod.rs:928 | THEME.md |
| `/ui/account/totp/activate` (POST) | `account::totp_activate` | — (redirect) | mod.rs:932 | — |
| `/ui/account/totp/disable` (POST) | `account::totp_disable` | — (redirect) | mod.rs:936 | — |
| `/ui/account/totp/recovery-codes.txt` | `account::totp_download_recovery_codes` | — (text) | mod.rs:940 | — |
| `/ui/account/totp/regenerate-codes` (POST) | `account::totp_regenerate_codes` | — | mod.rs:944 | — |
| `/ui/account/passkeys/register-begin` | `account::passkey_register_begin` | — (JSON) | mod.rs:948 | — |
| `/ui/account/passkeys/register-complete` (POST) | `account::passkey_register_complete` | — (JSON) | mod.rs:952 | — |
| `/ui/account/passkeys/{cred_id}/delete` (POST) | `account::passkey_delete` | — | mod.rs:956 | — |
| `/ui/account/passkeys/{cred_id}/rename` (POST) | `account::passkey_rename` | — | mod.rs:960 | — |
| `/ui/account/sessions` | `account::sessions_index` | `account/sessions.html` | mod.rs:964 | THEME.md |
| `/ui/account/sessions/revoke-others` (POST) | `account::revoke_other_sessions` | — | mod.rs:968 | — |
| `/ui/account/sessions/{sid}/revoke` (POST) | `account::revoke_session` | — | mod.rs:972 | — |
| `/ui/account/consents` | `account_consents::consents_index` | `account/consents.html` | mod.rs:977 | THEME.md |
| `/ui/account/applications` | `account_consents::account_applications` | `account/applications.html` | mod.rs:981 | THEME.md |
| `/ui/account/consents/revoke-all` (POST) | `account_consents::revoke_all_consents` | — | mod.rs:985 | — |
| `/ui/account/applications/revoke-all` (POST) | `account_consents::revoke_all_consents` | — | mod.rs:989 | — |
| `/ui/account/consents/{client_id}/revoke` (POST) | `account_consents::revoke_consent` | — | mod.rs:993 | — |
| `/ui/account/applications/{client_id}/revoke` (POST) | `account_consents::revoke_consent` | — | mod.rs:997 | — |
| `/ui/consent/delegations` | `consent_delegations::delegations_index` | `consent/delegations.html` | mod.rs:1002 | THEME.md |
| `/ui/consent/delegations/{delegation_id}/revoke` (POST) | `consent_delegations::revoke_delegation` | — | mod.rs:1006 | — |
| `/ui/account/linked-accounts` | `account_linked::linked_accounts_index` | `account/linked_accounts.html` | mod.rs:1011 | THEME.md |
| `/ui/account/linked-accounts/{idp_id}/unlink` (POST) | `account_linked::unlink` | — | mod.rs:1015 | — |

### Federation / SAML / OAuth browser flow

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/federation/begin` | `federation::begin` | — (redirect) | mod.rs:1020 | — |
| `/ui/federation/callback` (GET/POST) | `federation::callback`/`callback_post` | — (redirect) | mod.rs:1021 | — |
| `/ui/federation/confirm-link` (GET/POST) | `federation::confirm_link_page`/`_submit` | `federation/confirm_link.html` | mod.rs:1025 | THEME.md |
| `/ui/realms/{realm}/federation/begin` | `federation::begin_scoped` | — (redirect) | mod.rs:1029 | UI_ROUTING.md |
| `/ui/realms/{realm}/federation/callback` (GET/POST) | `federation::callback_scoped`/`_post` | — (redirect) | mod.rs:1033 | UI_ROUTING.md |
| `/ui/realms/{realm}/federation/saml/metadata` | `saml::sp_metadata` | — (XML) | mod.rs:1038 | — |
| `/ui/realms/{realm}/federation/saml/acs` (POST) | `saml::sp_acs` | — (redirect) | mod.rs:1042 | — |
| `/ui/realms/{realm}/federation/saml/begin` | `saml::sp_begin` | — (redirect) | mod.rs:1046 | — |
| `/ui/realms/{realm}/saml/metadata` | `saml::idp_metadata` | — (XML) | mod.rs:1050 | — |
| `/ui/realms/{realm}/saml/sso` (GET/POST) | `saml::idp_sso_get`/`_post` | — | mod.rs:1054 | — |
| `/ui/realms/{realm}/saml/sso/init` | `saml::idp_sso_init` | — | mod.rs:1058 | — |
| `/ui/realms/{realm}/saml/slo-idp` (GET/POST) | `saml::idp_slo_get`/`_post` | — | mod.rs:1062 | — |
| `/ui/oauth/authorize` | `oauth_consent::authorize_get` | — (redirect) | mod.rs:1067 | OIDC.md |
| `/ui/realms/{realm}/oauth/authorize` | `oauth_consent::authorize_get_scoped` | — (redirect) | mod.rs:1071 | OIDC.md |
| `/ui/oauth/consent` (GET/POST) | `oauth_consent::consent_page`/`consent_submit` | `oauth/consent.html` | mod.rs:1075 | OIDC.md |

### Admin: onboarding wizard

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/admin/onboarding` | `admin::admin_onboarding_get` | `admin/onboarding/wizard.html` | mod.rs:1086 | UI_ROUTING.md |
| `/ui/admin/onboarding/realm` (POST) | `admin::admin_onboarding_realm_post` | — | mod.rs:1090 | — |
| `/ui/admin/onboarding/app` (GET/POST) | `admin::admin_onboarding_app_get`/`_post` | `admin/onboarding/step_app.html` | mod.rs:1094 | UI_ROUTING.md |
| `/ui/admin/onboarding/invite` (GET/POST) | `admin::admin_onboarding_invite_get`/`_post` | `admin/onboarding/step_invite.html` | mod.rs:1099 | UI_ROUTING.md |
| `/ui/admin/onboarding/email` | `admin::admin_onboarding_email_get` | `admin/onboarding/step_email.html` | mod.rs:1104 | UI_ROUTING.md |
| `/ui/admin/onboarding/email/test` (POST) | `admin::admin_onboarding_email_test_post` | `admin/onboarding/_email_test_result.html` | mod.rs:1108 | — |
| `/ui/admin/onboarding/complete` | `admin::admin_onboarding_complete_get` | `admin/onboarding/complete.html` | mod.rs:1112 | UI_ROUTING.md |

### Admin: admin-users + migrations + realms list

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/admin/admin-users` | `admin::admin_admin_users_list` | `admin/users/list.html` | mod.rs:1116 | UI_ROUTING.md |
| `/ui/admin/admin-users/new` | `admin::admin_admin_user_create_alias` | — (302 alias) | mod.rs:1120 | UI_ROUTING.md (REQ-022) |
| `/ui/admin/admin-users/import` (GET/POST) | `admin::admin_admin_users_import_form`/`_submit` | `admin/users/import.html` | mod.rs:1128 | — |
| `/ui/admin/admin-users/import/template.csv` | `admin::admin_admin_users_import_template_csv` | — (CSV) | mod.rs:1133 | — |
| `/ui/admin/migrations` | `admin::admin_migrations_list` | `admin/migrations/list.html` | mod.rs:1138 | — |
| `/ui/admin/migrations/orphans/resolve` (POST) | `admin::admin_migrations_orphan_resolve` | `admin/migrations/_orphan_yaml.html` | mod.rs:1142 | — |
| `/ui/admin/realms` | `admin::admin_realms_list` | `admin/realms/list.html` | mod.rs:1147 | UI_ROUTING.md |

### Admin: realm-scoped users (`/ui/admin/realms/{realm}/users/…`)

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `…/users` | `admin::admin_users_list` | `admin/users/list.html` | mod.rs:1152 | UI_ROUTING.md |
| `…/users/new` (GET/POST) | `admin::admin_user_create_form`/`_submit` | `admin/users/new.html` | mod.rs:1156 | UI_ROUTING.md |
| `…/users/{id}` | `admin::admin_user_detail` | `admin/users/detail.html` | mod.rs:1160 | UI_ROUTING.md |
| `…/users/{id}/edit` (GET/POST) | `admin::admin_user_edit_form`/`_submit` | `admin/users/edit.html` | mod.rs:1164 | UI_ROUTING.md |
| `…/users/{id}/delete` (POST) | `admin::admin_user_delete` | — | mod.rs:1168 | — |
| `…/users/{id}/reset-password` (POST) | `admin::admin_user_send_reset` | — | mod.rs:1172 | — |
| `…/users/{id}/disable-mfa` (POST) | `admin::admin_user_disable_mfa` | — | mod.rs:1176 | — |
| `…/users/{id}/remove-phone` (POST) | `admin::admin_user_remove_phone` | — | mod.rs:1180 | — |
| `…/users/{id}/reset-mfa-codes` (POST) | `admin::admin_user_reset_mfa_codes` | `admin/mfa_codes_reset.html` | mod.rs:1184 | — |
| `…/users/{id}/sessions/{sid}/revoke` (POST) | `admin::admin_user_revoke_session` | — | mod.rs:1188 | — |
| `…/users/{id}/webauthn/{cred_id}/revoke` (POST) | `admin::admin_user_revoke_webauthn` | — | mod.rs:1192 | — |
| `…/users/{id}/roles/assign` (POST) | `admin::admin_user_assign_role` | `admin/users/_roles_tab.html` | mod.rs:1196 | AUTHORIZATION.md |
| `…/users/{id}/roles/{assignment_id}/unassign` (POST) | `admin::admin_user_unassign_role` | `admin/users/_roles_tab.html` | mod.rs:1200 | AUTHORIZATION.md |
| `…/users/{id}/permissions/grant` (POST) | `admin::admin_user_grant_permission` | `admin/users/_permissions_tab.html` | mod.rs:1204 | AUTHZ_EXPANSION.md |
| `…/users/{id}/permissions/revoke` (POST) | `admin::admin_user_revoke_permission` | `admin/users/_permissions_tab.html` | mod.rs:1208 | AUTHZ_EXPANSION.md |
| `…/users/{id}/consents` | `admin::admin_user_consents_list` | `admin/users/consents.html` | mod.rs:1212 | — |
| `…/users/{id}/applications` | `admin::admin_user_consents_list` | `admin/users/consents.html` | mod.rs:1216 | — |
| `…/users/{id}/consents/{client_id}/revoke` (POST) | `admin::admin_user_consent_revoke` | — | mod.rs:1220 | — |
| `…/users/{id}/applications/{client_id}/revoke` (POST) | `admin::admin_user_consent_revoke` | — | mod.rs:1224 | — |
| `…/users/{id}/required-actions` (PATCH) | `admin::admin_api_user_required_actions_patch` | — (JSON) | mod.rs:1228 | — |
| `…/users/bulk-action` (POST) | `admin::admin_users_bulk_action` | `admin/users/_rows.html` | mod.rs:1549 | — |
| `…/users/import` (GET/POST) | `admin::admin_users_import_form`/`_submit` | `admin/users/import.html` | mod.rs:1553 | — |
| `…/users/import/template.csv` | `admin::admin_users_import_template_csv` | — (CSV) | mod.rs:1558 | — |
| `…/api/users/search` | `admin::admin_api_user_search` | `admin/organizations/_user_search_results.html` | mod.rs:1421 | — |

### Admin: realm meta / config / claims

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `…/{realm}/config` (PATCH) | `admin::admin_api_realm_config_patch` | — (JSON) | mod.rs:1233 | CONFIGURATION.md |
| `…/{realm}` | `admin::admin_realm_detail` | `admin/realms/detail.html` | mod.rs:1238 | UI_ROUTING.md |
| `…/{realm}/delete` (POST) | `admin::admin_realm_delete` | — | mod.rs:1242 | — |
| `…/{realm}/admins/picker` | `admin::admin_realm_admin_picker` | `admin/realms/_admin_picker_rows.html` | mod.rs:1246 | — |
| `…/{realm}/admins/grant` (POST) | `admin::admin_realm_admin_grant` | — | mod.rs:1250 | — |
| `…/{realm}/admins/{uid}/revoke` (POST) | `admin::admin_realm_admin_revoke` | — | mod.rs:1254 | — |
| `…/{realm}/claims` | `admin::admin_realm_claims` | `admin/realms/claims/view.html` | mod.rs:1258 | AUTHZ_EXPANSION.md |

### Admin: RBAC (`…/{realm}/rbac/…`, permissions)

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `…/rbac/debug` | `admin::admin_rbac_debug` | `admin/rbac/debug.html` | mod.rs:1263 | AUTHORIZATION.md |
| `…/permissions/resolve` | `admin::admin_permissions_resolve_alias` | `admin/rbac/debug.html` (alias) | mod.rs:1270 | AUTHORIZATION.md (REQ-056) |
| `…/rbac/token-preview` | `admin::admin_rbac_token_preview` | — (fragment) | mod.rs:1273 | AUTHORIZATION.md |
| `…/rbac/permissions` | `admin::admin_rbac_permissions` | `admin/rbac/permissions.html` | mod.rs:1277 | AUTHZ_EXPANSION.md |
| `…/rbac/roles` | `admin::admin_rbac_roles` | `admin/rbac/roles.html` | mod.rs:1281 | AUTHORIZATION.md |
| `…/rbac/roles/new` (GET/POST) | `admin::admin_role_create_form`/`_submit` | `admin/rbac/role_new.html` | mod.rs:1285 | AUTHORIZATION.md |
| `…/rbac/roles/{id}` | `admin::admin_role_detail` | `admin/rbac/role_detail.html` | mod.rs:1289 | AUTHORIZATION.md |
| `…/rbac/roles/{id}/edit` (GET/POST) | `admin::admin_role_edit_form`/`_submit` | `admin/rbac/role_edit.html` | mod.rs:1293 | AUTHORIZATION.md |
| `…/rbac/roles/{id}/delete` (POST) | `admin::admin_role_delete` | — | mod.rs:1297 | — |
| `…/rbac/scopes` | `admin::admin_rbac_scopes` | `admin/rbac/scopes.html` | mod.rs:1301 | AUTHZ_EXPANSION.md |
| `…/rbac/api/users/search` | `admin::admin_api_rbac_user_search` | `admin/rbac/_user_search_options.html` | mod.rs:1425 | — |

### Admin: organizations (`…/{realm}/organizations/…`)

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `…/organizations` | `admin::admin_orgs_list` | `admin/organizations/list.html` | mod.rs:1306 | — |
| `…/organizations/new` (GET/POST) | `admin::admin_org_create_form`/`_submit` | `admin/organizations/new.html` | mod.rs:1310 | — |
| `…/organizations/bulk-delete` (POST) | `admin::admin_orgs_bulk_delete` | `admin/organizations/_rows.html` | mod.rs:1314 | — |
| `…/organizations/{id}` | `admin::admin_org_detail` | `admin/organizations/detail.html` | mod.rs:1318 | — |
| `…/organizations/{id}/edit` (GET/POST) | `admin::admin_org_edit_form`/`_submit` | `admin/organizations/edit.html` | mod.rs:1322 | — |
| `…/organizations/{id}/delete` (POST) | `admin::admin_org_delete` | — | mod.rs:1326 | — |
| `…/organizations/{id}/members` (POST) | `admin::admin_org_add_member` | `admin/organizations/_member_row.html` | mod.rs:1330 | — |
| `…/organizations/{id}/members/picker` | `admin::admin_org_member_picker` | `admin/organizations/_member_picker_rows.html` | mod.rs:1334 | — |
| `…/organizations/{id}/members/{uid}/remove` (POST) | `admin::admin_org_remove_member` | — | mod.rs:1338 | — |
| `…/organizations/{id}/members/{uid}/role` (POST) | `admin::admin_org_update_role` | `admin/organizations/_member_row.html` | mod.rs:1342 | — |
| `…/organizations/{id}/invite` (POST) | `admin::admin_org_invite` | — | mod.rs:1346 | — |
| `…/organizations/{id}/status` (POST) | `admin::admin_org_status_toggle` | — | mod.rs:1350 | — |
| `…/organizations/{id}/invitations/{iid}/revoke` (POST) | `admin::admin_org_revoke_invite` | — | mod.rs:1354 | — |
| `…/organizations/{id}/invitations/{iid}/resend` (POST) | `admin::admin_org_resend_invite` | — | mod.rs:1358 | — |
| `…/organizations/{id}/members/{uid}/rbac/assign` (POST) | `admin::admin_org_member_assign_role` | — | mod.rs:1362 | AUTHORIZATION.md |
| `…/organizations/{id}/members/{uid}/rbac/{aid}/unassign` (POST) | `admin::admin_org_member_unassign_role` | — | mod.rs:1366 | AUTHORIZATION.md |
| `…/organizations/{id}/members/{uid}/permissions/grant` (POST) | `admin::admin_org_member_grant_perm` | — | mod.rs:1370 | AUTHZ_EXPANSION.md |
| `…/organizations/{id}/members/{uid}/permissions/revoke` (POST) | `admin::admin_org_member_revoke_perm` | — | mod.rs:1374 | AUTHZ_EXPANSION.md |

### Admin: groups (`…/{realm}/groups/…`)

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `…/groups` | `admin::admin_groups_list` | `admin/groups/list.html` | mod.rs:1379 | AUTHORIZATION.md |
| `…/groups/new` (GET/POST) | `admin::admin_group_create_form`/`_submit` | `admin/groups/new.html` | mod.rs:1383 | AUTHORIZATION.md |
| `…/groups/{id}` | `admin::admin_group_detail` | `admin/groups/detail.html` | mod.rs:1388 | AUTHORIZATION.md |
| `…/groups/{id}/edit` (GET/POST) | `admin::admin_group_edit_form`/`_submit` | `admin/groups/edit.html` | mod.rs:1392 | AUTHORIZATION.md |
| `…/groups/{id}/delete` (POST) | `admin::admin_group_delete` | — | mod.rs:1396 | — |
| `…/groups/{id}/members` (POST) | `admin::admin_group_member_add` | `admin/groups/_member_row.html` | mod.rs:1400 | — |
| `…/groups/{id}/members/picker` | `admin::admin_group_member_picker` | `admin/groups/_member_picker_rows.html` | mod.rs:1404 | — |
| `…/groups/{id}/members/{kind}/{mid}/remove` (POST) | `admin::admin_group_member_remove` | — | mod.rs:1408 | — |
| `…/groups/{id}/roles/assign` (POST) | `admin::admin_group_role_assign` | — | mod.rs:1412 | AUTHORIZATION.md |
| `…/groups/{id}/roles/{aid}/unassign` (POST) | `admin::admin_group_role_unassign` | — | mod.rs:1416 | AUTHORIZATION.md |

### Admin: applications, IdPs, sessions, audit

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `…/applications` | `admin::admin_apps_list` | `admin/applications/list.html` | mod.rs:1440 | — |
| `…/applications/new` (GET/POST) | `admin::admin_app_create_form`/`_submit` | `admin/applications/new.html` | mod.rs:1444 | — |
| `…/applications/{id}` | `admin::admin_app_detail` | `admin/applications/detail.html` | mod.rs:1448 | — |
| `…/applications/{id}/edit` (GET/POST) | `admin::admin_app_edit_form`/`_submit` | `admin/applications/edit.html` | mod.rs:1452 | — |
| `…/applications/{id}/delete` (POST) | `admin::admin_app_delete` | — | mod.rs:1456 | — |
| `…/applications/{id}/regenerate-secret` (POST) | `admin::admin_app_regenerate_secret` | `admin/applications/detail.html` | mod.rs:1460 | — |
| `…/identity-providers` | `admin::admin_idp_list` | `admin/identity_providers/list.html` | mod.rs:1465 | — |
| `…/identity-providers/{id}` | `admin::admin_idp_detail` | `admin/identity_providers/detail.html` | mod.rs:1469 | — |
| `…/sessions` | `admin::admin_sessions_list` | `admin/sessions/list.html` | mod.rs:1474 | — |
| `…/sessions/{id}/revoke` (POST) | `admin::admin_session_revoke` | — | mod.rs:1478 | — |
| `…/audit` | `admin::admin_audit_list` | `admin/audit/list.html` | mod.rs:1483 | — |
| `…/audit/verify` (POST) | `admin::admin_audit_verify_integrity` | `admin/audit/_detail.html` | mod.rs:1487 | — |
| `…/audit/export` | `admin::admin_audit_export` | — (download) | mod.rs:1491 | — |
| `/ui/admin/api/realms/{realm}/audit/events` | `admin::admin_api_audit_events` | `admin/audit/_rows.html` | mod.rs:1495 | — |
| `/ui/admin/api/realms/{realm}/audit/config` (GET/PUT) | `admin::admin_api_audit_config_get`/`_put` | — (JSON) | mod.rs:1499 | — |
| `/ui/admin/api/realms/{realm}/audit/prune` (POST) | `admin::admin_api_audit_prune` | — (JSON) | mod.rs:1504 | — |

### Admin: system settings / config editor / misc APIs

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/admin/api/config/reload` (POST) | `admin::admin_api_config_reload` | — (JSON) | mod.rs:1430 | CONFIGURATION.md |
| `/ui/admin/api/nav/realms` | `admin::admin_api_nav_realms` | — (fragment) | mod.rs:1435 | — |
| `/ui/admin/settings` | `admin::admin_system_info` | `admin/settings/system.html` | mod.rs:1508 | — |
| `/ui/admin/settings/editor` | `admin::admin_config_editor` | `admin/settings/editor.html` | mod.rs:1512 | CONFIGURATION.md |
| `/ui/admin/settings/editor/preview` (POST) | `admin::admin_config_editor_preview` | `admin/settings/_diff_preview.html` | mod.rs:1516 | — |
| `/ui/admin/settings/editor/apply` (POST) | `admin::admin_config_editor_apply` | — | mod.rs:1520 | — |
| `/ui/admin/settings/editor/visual/preview` (POST) | `admin::admin_config_editor_visual_preview` | `admin/settings/_diff_preview.html` | mod.rs:1524 | — |
| `/ui/admin/settings/editor/visual/validate` (POST) | `admin::admin_config_editor_visual_validate` | `admin/settings/_editor_sections.html` | mod.rs:1528 | — |
| `/ui/admin/settings/editor/visual/apply` (POST) | `admin::admin_config_editor_visual_apply` | — | mod.rs:1532 | — |
| `/ui/admin/settings/editor/visual/export` (POST) | `admin::admin_config_editor_visual_export` | — (download) | mod.rs:1536 | — |
| `/ui/admin/settings/editor/export` | `admin::admin_config_editor_export` | — (download) | mod.rs:1540 | — |
| `/ui/admin/test-email` (POST) | `admin::admin_test_email` | — | mod.rs:1544 | — |

### Admin: abuse, webhooks, approvals

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `…/abuse` | `admin::admin_abuse_dashboard` | `admin/abuse/show.html` | mod.rs:1563 | — |
| `…/webhooks` | `admin::admin_webhooks_list` | `admin/webhooks/list.html` | mod.rs:1568 | — |
| `…/webhooks/new` (GET/POST) | `admin::admin_webhook_create_form`/`_submit` | `admin/webhooks/new.html` | mod.rs:1572 | — |
| `…/webhooks/test-ping` (POST) | `admin::admin_webhook_test_ping` | — | mod.rs:1577 | — |
| `…/webhooks/{id}/edit` (GET/POST) | `admin::admin_webhook_edit_form`/`_submit` | `admin/webhooks/edit.html` | mod.rs:1581 | — |
| `…/webhooks/{id}/delete` (POST) | `admin::admin_webhook_delete` | — | mod.rs:1586 | — |
| `…/webhooks/{id}/test` (POST) | `admin::admin_webhook_test` | — | mod.rs:1590 | — |
| `…/approvals` | `admin::admin_approvals_queue` | `admin/approvals/queue.html` | mod.rs:1595 | AGENT_AUTH.md |
| `…/approvals/{id}` | `admin::admin_approval_detail` | `admin/approvals/detail.html` | mod.rs:1599 | AGENT_AUTH.md |
| `…/approvals/{id}/approve` (POST) | `admin::admin_approval_approve` | — | mod.rs:1603 | AGENT_AUTH.md |
| `…/approvals/{id}/deny` (POST) | `admin::admin_approval_deny` | — | mod.rs:1607 | AGENT_AUTH.md |

### Static

| UI Route | Handler | Template file | File:line | Spec |
|---|---|---|---|---|
| `/ui/static/{*file}` | `serve_static` | — (assets) | mod.rs:1611 | THEME.md |

### Route/template gap analysis

**Shared layout / helpers (no route, by design):** `_layout.html`, `_spinner.html`,
`_tooltip.html`, `admin/_pagination.html`, `admin/_sortable_th.html`,
`admin/_components/_yaml_badge.html`, and all `_*.html` HTMX fragments.

**Page templates with NO registered `/ui` route** (rendered by non-web-router
handlers — error middleware, realm resolver, or the required-action interstitial
flow in `src/protocol/http/`, not `web/mod.rs`):
- `errors/forbidden.html`, `errors/not_found.html`, `errors/server_error.html` — rendered by error/fallback handlers.
- `realm_required.html` — rendered by the realm resolver when a bare `/ui/*` URL cannot resolve a realm.
- `required_action/*.html` (underscore dir: `action.html`, `enroll_email_otp.html`, `enroll_email_otp_verify.html`, `enroll_mfa.html`, `enroll_phone_otp.html`, `enroll_phone_otp_verify.html`, `update_password.html`, `verify_email.html`, `verify_email_expired.html`) — a **second, parallel** required-action template set distinct from the routed `required-actions/` (hyphen) dir; served by the interstitial flow in the HTTP auth layer, not `web/mod.rs`.
- `admin/settings/_raw_editor.html`, `admin/onboarding/_progress.html`, `admin/organizations/_empty.html`, `admin/applications/_empty.html`, `admin/realms/_empty.html`, `admin/users/_empty.html`, `admin/realms/_workspace_tabs.html` — sub-fragments included by parent templates.

**Routes with NO template** (JSON/redirect/binary responses): all passkey
begin/complete endpoints, `logout`, federation/SAML/OAuth-authorize redirects,
`*/delete`, `*/revoke`, `*.csv`/`*.txt`/export downloads, and the
`admin/api/*` JSON endpoints — expected, these are action or data endpoints.

**Naming note (potential cleanup):** the duplicated `required_action/` (underscore)
vs `required-actions/` (hyphen) template directories are a divergence worth
confirming against a single spec-defined path.
## Configuration Surface

Code-derived inventory of Hearth's `hearth.yaml` configuration surface. Cross-references
`hearth.example.yaml`, the Rust config structs in `src/config/types.rs`, and
`docs/specs/CONFIGURATION.md`.

- **Config structs:** `src/config/types.rs` (single file, ~3233 lines; top-level `Config` at `types.rs:3158`).
- **Loading / env-substitution:** `src/config/mod.rs`, `src/config/env.rs`.
- **Validation:** `src/config/validate.rs`. **Diff/migration snapshot:** `src/config/diff.rs`.
- All sections use `#[serde(default)]`, so a partial/empty YAML file parses. Unknown keys are
  **silently ignored** (no `deny_unknown_fields`) — misspelled or unimplemented keys do not error.

Legend for "Documented?": Y = present in CONFIGURATION.md, N = absent.

### Top-level `Config` (`types.rs:3158`)

| Config key (dotted path) | Rust struct field / file:line | Documented? | Notes |
|---|---|---|---|
| `server` | `Config.server: ServerConfig` `types.rs:3161` | Y | |
| `storage` | `Config.storage: StorageSection` `types.rs:3164` | Y | |
| `observability` | `Config.observability: ObservabilityConfig` `types.rs:3167` | Y | |
| `operational` | `Config.operational: OperationalConfig` `types.rs:3170` | Y | |
| `email` | `Config.email: EmailConfig` `types.rs:3173` | Y | |
| `sms` | `Config.sms: SmsConfig` `types.rs:3176` | Y | |
| `onboarding` | `Config.onboarding: OnboardingConfig` `types.rs:3179` | Y | |
| `branding` | `Config.branding: BrandingConfig` `types.rs:3182` | Y | |
| `oidc` | `Config.oidc: OidcYamlConfig` `types.rs:3185` | Y | |
| `token` | `Config.token: TokenYamlConfig` `types.rs:3188` | Y | |
| `auth` | `Config.auth: AuthConfig` `types.rs:3191` | Y | |
| `security` | `Config.security: SecurityYaml` `types.rs:3194` | Y | |
| `metrics` | `Config.metrics: MetricsConfig` `types.rs:3197` | Y | |
| `realms` | `Config.realms: Option<HashMap<..>>` `types.rs:3204` | Y | |
| `cluster` | `Config.cluster: Option<ClusterConfig>` `types.rs:3211` | Y | |
| `agent_auth` | `Config.agent_auth: AgentAuthConfig` `types.rs:3218` | Y | |
| `demo` | `Config.demo: DemoConfig` `types.rs:3223` | Y | |

### `server` (`ServerConfig` `types.rs:19`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `server.bind_address` | `bind_address` `types.rs:23` | Y | default `127.0.0.1` |
| `server.port` | `port` `types.rs:26` | Y | default `8420` |
| `server.tls_cert_path` | `tls_cert_path` `types.rs:28` | Y | |
| `server.tls_key_path` | `tls_key_path` `types.rs:30` | Y | |
| `server.tls_client_ca_path` | `tls_client_ca_path` `types.rs:32` | Y | |
| `server.tls_require_client_cert` | `tls_require_client_cert` `types.rs:35` | Y | |
| `server.trusted_proxies` | `trusted_proxies` `types.rs:43` | Y | |
| `server.trust_forwarded_proto` | `trust_forwarded_proto` `types.rs:90` | Y | |
| `server.default_realm` | `default_realm` `types.rs:57` | **N** | Implemented, not in CONFIGURATION.md. |
| `server.grpc_port` | `grpc_port` `types.rs:61` | **N** | Implemented, undocumented. |
| `server.grpc_bind_address` | `grpc_bind_address` `types.rs:65` | **N** | Implemented, undocumented. |
| `server.assets_dir` | `assets_dir` `types.rs:82` | **N** | Implemented, undocumented. |

### `storage` (`StorageSection` `types.rs:163`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `storage.data_dir` | `data_dir` `types.rs:166` | Y | |
| `storage.wal_max_size_bytes` | `wal_max_size_bytes` `types.rs:169` | Y | |
| `storage.memtable_flush_bytes` | `memtable_flush_bytes` `types.rs:172` | Y | |
| `storage.hot_tier_capacity` | `hot_tier_capacity` `types.rs:178` | Y | |
| `storage.hot_tier_max_memory` | `hot_tier_max_memory` `types.rs:183` | Y | |
| `storage.fsync` | `fsync` `types.rs:186` | Y | |
| `storage.compaction.{enabled,interval_secs,min_sst_count}` | `compaction: CompactionSection` `types.rs:189` / `123` | **N** | In example.yaml + struct, absent from CONFIGURATION.md. |

### `observability` (`ObservabilityConfig` `types.rs:321`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `observability.log_level` | `log_level` `types.rs:325` | Y | |
| `observability.log_format` | `log_format` `types.rs:328` | Y | |
| `observability.otlp.{endpoint,protocol,headers,service_name}` | `otlp: Option<OtlpConfig>` `types.rs:331` / `283` | **N** | In example.yaml + struct, absent from CONFIGURATION.md. |

### `operational` (`OperationalConfig` `types.rs:367`)

All four keys documented and implemented: `request_timeout_secs` `types.rs:371`, `shutdown_timeout_secs` `:374`, `max_connections` `:377`, `queue_depth` `:380`.

### `email` (`EmailConfig` `types.rs:546`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `email.transport` | `transport: EmailTransport` `types.rs:550` / `415` | Y | `log`\|`smtp`\|`sendgrid`\|`postmark`\|`mailgun`\|`mailtrap`\|`mailcatcher` |
| `email.from` | `from` `types.rs:554` | Y | |
| `email.smtp.{host,port,encryption,username,password}` | `SmtpConfig` `types.rs:465` | Y | |
| `email.sendgrid.api_key` | `SendgridConfig` `types.rs:485` | Y | |
| `email.postmark.server_token` | `PostmarkConfig` `types.rs:494` | Y | |
| `email.mailgun.{api_key,domain,region}` | `MailgunConfig` `types.rs:514` | Y | |
| `email.mailtrap.{api_key,inbox_id}` | `MailtrapConfig` `types.rs:528` | Y | |
| `email.branding` | `branding: Option<EmailBranding>` `types.rs:573` | Y | struct in `identity/email` |
| `email.templates_dir` | `templates_dir` `types.rs:577` | Y | |

### `sms` (`SmsConfig` `types.rs:630`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `sms.transport` | `transport: SmsTransport` `types.rs:633` / `582` | Y | `log`\|`twilio`\|`awssns` |
| `sms.twilio.{account_sid,auth_token,from}` | `TwilioConfig` `types.rs:597` | Y | |
| `sms.aws_sns.{region,access_key_id,secret_access_key,sender_id}` | `SnsSmsConfig` `types.rs:611` | Y | |

### `branding` (`BrandingConfig` `types.rs:648`)

`product_name` `:653`, `logo_url` `:661`, `theme` `:666`, `custom_css` `:671` — all documented.
(Note: CONFIGURATION.md theme list names `parchment`; struct doc-comment names `slate` for the second light theme — minor naming inconsistency, validated in `validate.rs`.)

### `oidc` (`OidcYamlConfig` `types.rs:745`) / `token` (`TokenYamlConfig` `types.rs:770`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `oidc.issuer` | `issuer` `types.rs:750` | Y | |
| `oidc.authorization_code_ttl` | `authorization_code_ttl` `types.rs:754` | Y | |
| `oidc.enforce_nonces` | `enforce_nonces` `types.rs:759` | Y | Removed opt-out (HEA-SEC-29): `false` rejected at startup; `true` accepted for compat. |
| `oidc.require_pkce_for_confidential_clients` | `types.rs:764` | partial | Same removed-opt-out semantics; example.yaml still shows `enforce_nonces` as toggleable (stale comment). |
| `token.issuer` | `issuer` `types.rs:774` | Y | defaults to `oidc.issuer` |
| `token.audience` | `audience` `types.rs:777` | Y | |
| `token.access_token_ttl` | `access_token_ttl` `types.rs:781` | Y | |
| `token.refresh_token_ttl` | `refresh_token_ttl` `types.rs:785` | Y | |
| `token.signing_key_rotation_grace_period` | `types.rs:789` | Y | not shown in example.yaml |

### `auth` (`AuthConfig` `types.rs:1259`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `auth.session_ttl` | `session_ttl` `types.rs:1262` | Y | |
| `auth.password_memory_cost` | `password_memory_cost` `types.rs:1265` | Y | |
| `auth.password_time_cost` | `password_time_cost` `types.rs:1268` | Y | |
| `auth.mfa_required` | `mfa_required` `types.rs:1272` | Y | |
| `auth.passkey_requires_mfa` | `passkey_requires_mfa` `types.rs:1276` | Y | |
| `auth.session_max_concurrent` | `session_max_concurrent` `types.rs:1280` | **N** | Implemented, undocumented in CONFIGURATION.md. |
| `auth.session_over_limit_policy` | `session_over_limit_policy` `types.rs:1285` | **N** | Implemented, undocumented. Unknown value = hard error (`to_realm_config`). |
| **`auth.audit_log_retention`** | — none — | N | **DRIFT: in example.yaml (line 384) only. No struct field, not documented, not implemented.** |

### `security` (`SecurityYaml` `types.rs:795`)

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `security.rate_limiting.*` | `rate_limiting: GlobalRateLimitYaml` `types.rs:799`/`1222` | Y | `login_per_ip`, `login_per_account` sub-blocks |
| `security.dpop_nonce_secret` | `dpop_nonce_secret` `types.rs:812` | Y | |
| `security.allowed_hosts` | `allowed_hosts` `types.rs:820` | Y | |
| `security.http2.*` | `http2: Http2SecurityYaml` `types.rs:823`/`1172` | Y | |
| `security.request_shaper.*` | `request_shaper: RequestShaperYaml` `types.rs:826`/`1202` | Y | |
| `security.load_test_unthrottled` | `load_test_unthrottled` `types.rs:837` | Y | loopback-gated |
| `security.allowed_return_to_origins` | `allowed_return_to_origins` `types.rs:843` | Y | |
| `security.ip_reputation.*` | `ip_reputation: IpReputationYaml` `types.rs:846`/`1032` | Y | `enabled`, `action`, `spamhaus.*`, `maxmind_db_path` |
| `security.captcha.*` | `captcha: CaptchaYaml` `types.rs:849`/`957` | Y | `provider`, `turnstile.*` |
| `security.grpc.reflection_enabled` | `grpc: GrpcSecurityYaml` `types.rs:852`/`1060` | Y | |
| `security.tls.{min_version,crl_paths}` | `tls: TlsSecurityYaml` `types.rs:855`/`1101` | Y | |
| `security.backup.{verify_key,export_rate_limit}` | `backup: BackupSecurityYaml` `types.rs:858`/`999` | Y | |
| `security.reserved_slugs` | `reserved_slugs` `types.rs:869` | Y | |
| `security.slug_cooldown_days` | `slug_cooldown_days` `types.rs:873` | Y | |
| `security.jwks_rps_limit` | `jwks_rps_limit` `types.rs:883` | Y | |
| `security.key_encryption_key` | `key_encryption_key` `types.rs:894` | **N** | Implemented (KEK; `HEARTH_KEK` env overrides), undocumented in CONFIGURATION.md. |
| **`security.bearer_token`** | — none in `SecurityYaml` — | Y (misplaced) | **DRIFT: example.yaml (line 268) + CONFIGURATION.md (line 480) place `bearer_token` under `security`, but the real field is `metrics.bearer_token` (`MetricsConfig` `types.rs:249`). Placing it under `security:` is silently ignored.** |
| **`security.password.pepper.*`** | — none — | N | **DRIFT: documented in example.yaml (lines 355-373). `SecurityYaml` has no `password` field; pepper loads from the secrets backend (`abuse/secrets_backend`), env, or storage — never from hearth.yaml. Silently ignored if set here.** |

### `metrics` (`MetricsConfig` `types.rs:231`)

`metrics.enabled` `:238`, `metrics.bearer_token` `:249` — both documented (though bearer_token is described under a `security:` block in example.yaml/CONFIGURATION.md — see drift above).

### `agent_auth` (`AgentAuthConfig` `types.rs:2238`)

`agent_auth.capabilities.{identity,approval,advanced}` (`AgentAuthCapabilities` `types.rs:2203`) — all documented. Staged flags; enabling a phase without predecessor rejected at startup.

### `demo` (`DemoConfig` `types.rs:1820`)

`demo.enabled` `:1823`, `demo.password` `:1829` — both documented. Gates per-realm `seeding:` blocks.

### `cluster` (`ClusterConfig` `types.rs:2873`)

`node_id` `:2875`, `peer_address` `:2878`, `peers[].{id,address}` (`PeerConfig` `:2857`), `tls_cert_path` `:2883`, `tls_key_path` `:2885`, `tls_ca_cert_path` `:2887`, `read_lag_threshold_ms` `:2891` — all documented.

### `realms.<name>` (`RealmYamlConfig` `types.rs:1874`)

Implemented per-realm YAML fields (all merged in `to_realm_config` `types.rs:2300`):

| Key | Field / line | Doc? | Notes |
|---|---|---|---|
| `session_ttl` | `session_ttl` `:1877` | Y | |
| `session_max_concurrent` | `:1881` | N | |
| `session_over_limit_policy` | `:1886` | N | |
| `password_memory_cost` / `password_time_cost` | `:1889` / `:1892` | Y | |
| `email.branding` | `email: RealmEmailYaml` `:1895`/`1716` | Y | |
| `web.{theme,custom_css,product_name}` | `web: RealmWebYaml` `:1898`/`683` | Y (product_name N) | |
| `auth.*` | `auth: RealmAuthYaml` `:1901`/`1294` | Y | see below |
| `scim.bearer_token` | `scim: RealmScimYaml` `:1904`/`2018` | N | hashed at load |
| `applications.*` / `oauth_clients.*` | `:1908` / `:1939` (`ApplicationYamlConfig` `1611`) | Y | `oauth_clients` alias undocumented |
| `organizations.*` | `organizations` `:1912` (`OrganizationYamlConfig` `1586`) | Y | |
| `federation.*` | `federation: FederationYamlConfig` `:1917`/`2051` | Y | providers, link mode |
| `saml_service_providers.*` | `:1921` (`SamlServiceProviderYaml` `2029`) | Y | |
| `permissions` / `roles` / `scopes` / `protected_resources` / `claims` / `groups` | `:1924`–`:1942` | Y (as `realms.<name>.rbac.*`) | **CONFIGURATION.md nests these under a `.rbac` sub-key; struct has them top-level under the realm.** |
| `migrate_from` / `copy_from` / `migrate.*` | `:1948` / `:1952` / `:1956` (`RealmMigrateYaml` `1752`) | Y | |
| `attribute_definitions.{users,organizations}` | `:1962` (`AttributeDefinitionsYaml` `1571`) | Y | |
| `archive_drop` | `:1968` | partial | in example.yaml, not in CONFIGURATION.md field tables |
| `rotate_signing_key` | `:1977` | partial | in example.yaml, not tabulated |
| `fapi_profile` | `:1984` | Y | `baseline`\|`advanced` |
| `seed_users[].*` | `:1990` (`SeedUserYamlConfig` `1789`) | Y | |
| `seeding.*` | `:1994` (`SeedingYamlConfig` `1853`) | Y | gated on `demo.enabled` |
| `tool_registry.groups` | `:2001` (`ToolRegistryYamlConfig` `2006`) | Y | |

`realms.<name>.auth` (`RealmAuthYaml` `types.rs:1294`): `mfa_required` `:1297`, `mfa_methods` `:1300`, `allowed_auth_methods` `:1303`, `password_policy` (`PasswordPolicyYaml` `1453`) `:1306`, `token` (`RealmTokenYaml` `1482`) `:1309`, `passkey_requires_mfa` `:1314`, `rate_limit` (`RateLimitYaml` `1513`) `:1317`, `registration` (`RegistrationPolicyYaml` `1370`) `:1320`, `dcr` (`DcrPolicyYaml` `1420`) `:1323`, `webauthn_attestation` (`WebAuthnAttestationYaml` `1333`) `:1328` — all documented.

Documented-but-NOT-a-YAML-field under `realms.<name>` (set to `default`/`None` in `to_realm_config`, only settable via admin API):

| Documented key | Reality | Notes |
|---|---|---|
| **`realms.<name>.auth.adaptive_mfa.*`** | no field | **DRIFT: in example.yaml (lines 462-465) + CONFIGURATION.md (line 840/869). `RealmAuthYaml` has NO `adaptive_mfa` field; `to_realm_config` hard-codes `AdaptiveMfaConfig::default()` (`types.rs:2800`). Silently ignored in YAML.** |
| **`realms.<name>.breach_check.*`** | no field | **DRIFT: CONFIGURATION.md line 912. `to_realm_config` hard-codes `BreachCheckConfig::default()` (`types.rs:2798`).** |
| **`realms.<name>.quotas.*`** | no field | **DRIFT: CONFIGURATION.md line 1194. `to_realm_config` sets `quotas: None` (`types.rs:2814`).** |
| **`realms.<name>.pre_token_webhook.*`** | no field | **DRIFT: CONFIGURATION.md line 1369. `to_realm_config` sets `pre_token_webhook: None` (`types.rs:2817`).** |
| **`realms.<name>.applications.access_token_authorization`** | no field | **DRIFT: CONFIGURATION.md line 948. `ApplicationYamlConfig` (`types.rs:1611`) has `trust_level`/`declared_scopes`/`consent_spans_orgs` instead; no `access_token_authorization`.** |

### Drift Summary

**example.yaml keys with no struct field (silently ignored — no `deny_unknown_fields`):**
1. `auth.audit_log_retention` (example.yaml:384) — undocumented, unimplemented.
2. `security.password.pepper.*` (example.yaml:355-373) — pepper is loaded from the secrets backend/env/storage, never from hearth.yaml.
3. `security.bearer_token` (example.yaml:268 / CONFIGURATION.md:480) — misplaced; the real field is `metrics.bearer_token`.
4. `realms.<name>.auth.adaptive_mfa.*` (example.yaml:462-465) — hard-coded to default; admin-API-only.

**CONFIGURATION.md documents keys the struct cannot parse (admin-API-only, hard-coded default in `to_realm_config`):**
- `realms.<name>.breach_check.*`, `realms.<name>.quotas.*`, `realms.<name>.pre_token_webhook.*`,
  `realms.<name>.applications.access_token_authorization`, `realms.<name>.auth.adaptive_mfa.*`.
- Structural: CONFIGURATION.md nests RBAC under `realms.<name>.rbac.*`; the struct places
  `permissions`/`roles`/`scopes`/`groups`/`claims`/`protected_resources` directly under the realm.

**Implemented struct fields NOT documented in CONFIGURATION.md:**
- `server.default_realm`, `server.grpc_port`, `server.grpc_bind_address`, `server.assets_dir`
- `storage.compaction.*`, `observability.otlp.*`
- `auth.session_max_concurrent`, `auth.session_over_limit_policy`
- `security.key_encryption_key`
- `token.signing_key_rotation_grace_period` (documented, absent from example.yaml)
- `realms.<name>.session_max_concurrent`, `session_over_limit_policy`, `scim.bearer_token`,
  `web.product_name`, `oauth_clients` (alias), `archive_drop`/`rotate_signing_key` (prose only).

**Stale comments:** example.yaml still presents `oidc.enforce_nonces` / `require_pkce_for_confidential_clients`
as toggleable, but both are removed opt-outs — setting `false` is rejected at startup (HEA-SEC-29).
## CLI Commands & Flags

Binary: `hearth` (`#[command(name = "hearth", version, about)]`, `src/main.rs:40-45`). Top-level subcommands enum `Commands` at `src/main.rs:48-122`.

| Command/Subcommand | Flags/Args | File:line | Purpose |
|--------------------|-----------|-----------|---------|
| `serve` | `--dev` (**dev-only**), `--config/-c <path>`, `--port <u16>`, `--bind <str>`, `--verbose/-v`, `--allow-reflection-in-prod` (**dev/debug-only**) | src/main.rs:51-83 | Start the Hearth identity server. `--dev` = in-memory storage, relaxed security, debug logging, mailcatcher. `--allow-reflection-in-prod` forces gRPC reflection on in prod (A-43) — never for real deployments |
| `realm` | subcommand `RealmAction` | src/main.rs:85-88 | Manage realms |
| `realm create` | (none) | src/main.rs:278-281 | Create a new realm (generates a UUID) |
| `app` | subcommand `AppAction` | src/main.rs:90-93 | Manage OAuth 2.0 applications (clients) |
| `app create` | `--server <url>`, `--realm-id <str>`, `--name <str>`, `--redirect-uri <str>`, `--token <str>` | src/main.rs:363-388 | Register a new OAuth 2.0 client against a running server. `--token` is a privileged admin bearer token (`hearth.clients.admin`/`hearth.admin`) |
| `migrate` | subcommand `MigrateSource` | src/main.rs:95-98 | Import data from another identity provider |
| `migrate keycloak` | `--file <path>`, `--data-dir <path>`, `--realm <str>`, `--dry-run` | src/main.rs:207-229 | Import a Keycloak realm export (JSON) |
| `migrate auth0` | `--file <path>`, `--data-dir <path>`, `--realm <str>`, `--dry-run` | src/main.rs:234-255 | Import an Auth0 tenant bundle (JSON) |
| `migrate rotate-pepper` | `--data-dir <path>`, `--summary-only` | src/main.rs:265-273 | Audit credentials needing Argon2 pepper rotation. Exit 0/1/2 |
| `config` | subcommand `ConfigAction` | src/main.rs:100-103 | Configuration management |
| `config reload` | `--url <str>`, `--pid-file <path>` | src/main.rs:290-301 | Hot-reload config via SIGHUP (PID file) or POST /admin/api/config/reload (`--url`) |
| `config validate` | `<file>` positional (default `hearth.yaml`) | src/main.rs:307-311 | Validate a config file without starting the server. Exit 1 on error |
| `config example` | `--output/-o <path>` | src/main.rs:317-321 | Print annotated example hearth.yaml to stdout or `--output` |
| `rbac` | subcommand `RbacAction` | src/main.rs:105-108 | RBAC maintenance |
| `rbac orphans` | subcommand `OrphansAction` | src/main.rs:329-332 | List/purge orphaned runtime references |
| `rbac orphans list` | `--realm <str>`, `--data-dir <path>` (default `data`) | src/main.rs:339-346 | List orphaned references across realms |
| `rbac orphans purge` | `--realm <str>`, `--data-dir <path>` (default `data`), `--dry-run` | src/main.rs:348-358 | Purge orphaned references |
| `backup` | subcommand `BackupAction` | src/main.rs:110-113 | Create, restore, and inspect backup archives |
| `backup create` | `--output/-o <path>`, `--realm <str>`, `--include-audit`, `--encrypt`, `--data-dir <path>` (default `data`) | src/main.rs:128-157 | Export realm data to `.hearth-backup`. `--encrypt` = passphrase-wrapped DEK (Argon2id/AES-256-GCM) |
| `backup restore` | `--input/-i <path>`, `--realm <str>`, `--mode <str>` (default `skip`), `--dry-run`, `--data-dir <path>` (default `data`) | src/main.rs:159-185 | Restore from archive. Modes: skip/overwrite/merge |
| `backup verify` | `--input/-i <path>` | src/main.rs:189-193 | Recompute SHA-256 checksums. Exit 0/3 |
| `backup inspect` | `--input/-i <path>` | src/main.rs:197-201 | Print archive manifest as a table |
| `completions` | `<shell>` positional (`clap_complete::Shell`) | src/main.rs:118-121 | Print a shell completion script to stdout |

### Notes
- **Dev-only flags:** `serve --dev` (in-memory, relaxed security, debug logging, auto-mailcatcher). `serve --allow-reflection-in-prod` is a dev/debug escape hatch that permits gRPC reflection in production mode (A-43) — explicitly documented "never enable in real deployments."
- No `--admin-token` flag exists on this binary; privileged operations use `app create --token`. (`--admin-token` referenced in the task lives in the seed/loadtest tooling, not `src/main.rs`.)
- No hidden (`#[arg(hide = true)]`) flags found in `src/main.rs`.
## SDK Exports (TS / Go / PHP)

Code-derived inventory of the public API surface of the TypeScript, Go, and PHP
SDKs under `sdks/`, cross-referenced against the common contract in
`docs/specs/SDK.md` (canonical mapping in §2.5, Claims §4, OAuth flows §4.5,
Admin SDK §12). "In SDK.md contract?" = the symbol maps to a spec-required
operation. Symbols marked **Extra** exist in code but are not mandated by the
spec (still valid, but a parity signal). File:line points at the definition.

Entry points read:
- TS: `sdks/typescript/src/index.ts` (re-exports), `hearth-client.ts`, `claims.ts`, `admin.ts`, `browser-auth.ts`
- Go: `sdks/go/hearth/client.go`, `flows.go`, `login.go`, `verify.go`, `claims.go`, `admin.go`, `webauthn.go`, `jwks.go`, `pkce.go`, `middleware.go`
- PHP: `sdks/php/src/HearthClient.php`, `AdminClient.php`, `Claims.php`

---

### TypeScript SDK

Primary export surface from `index.ts`. `HearthClient` is the resource-server
entry point; `AdminClient`, `Claims`, browser-auth helpers, React hooks and
middleware are separate exports.

| SDK | Exported symbol | File:line | In SDK.md contract? |
|-----|-----------------|-----------|---------------------|
| TS | `HearthClient` (class) | hearth-client.ts:? (default export) | Yes (§1 entry point) |
| TS | `HearthClient.discover()` | hearth-client.ts:135 | Yes (§1 discovery) |
| TS | `HearthClient.jwksClient()` | hearth-client.ts:180 | Yes (§2) |
| TS | `HearthClient.introspectionClient()` | hearth-client.ts:200 | Yes (§3) |
| TS | `HearthClient.authorize()` | hearth-client.ts:238 | Yes (authorize/decision) |
| TS | `HearthClient.introspect()` | hearth-client.ts:281 | Yes (§3) |
| TS | `HearthClient.verifyToken()` | hearth-client.ts:315 | Yes (§2.1 REQUIRED) |
| TS | `HearthClient.clientCredentials()` | hearth-client.ts:334 | Yes (§4.5.1) |
| TS | `HearthClient.startDeviceFlow()` | hearth-client.ts:358 | Yes (§4.5.2) |
| TS | `HearthClient.pollDeviceToken()` | hearth-client.ts:383 | Yes (§4.5.2) |
| TS | `HearthClient.requestMagicLink()` | hearth-client.ts:443 | Yes (§4.5.3) |
| TS | `HearthClient.exchangeMagicLink()` | hearth-client.ts:471 | Yes (magic-link completion) |
| TS | `Claims` (class) + decode/subject/issuer/audiences/expiry/issuedAt/jwtID/scope/scopes/hasScope/hasRole/hasPermission/inGroup/inOrg/tokenType/organizationId/orgGroups/get | claims.ts:56–177 | Yes (§4, all 18 methods present) |
| TS | `AdminClient` — Users/Realms/Clients/Roles/Groups CRUD + list + addOrgMember/listOrgMembers/removeOrgMember | admin.ts:28–248 | Yes (§12) |
| TS | `JwksClient`, `IntrospectionClient` | index.ts:20,22 | Yes (§2/§3 primitives) |
| TS | PKCE: `generateCodeVerifier`, `generateCodeChallenge`, `buildAuthorizationUrl`, `startLogin` | index.ts:5–10 (pkce.ts) | Yes (§7) |
| TS | `requirePermission` middleware | index.ts:48 (middleware.ts) | Yes (§6) |
| TS | 15 error classes (AuthorizationModeMismatch…TokenNotYetValid) | index.ts:29–45 (errors.ts) | Yes (§5) |
| TS | Browser auth: `getAccessToken/getRefreshToken/getIdToken/isAuthenticated/clearTokens/createHearthAuth` + `HearthBrowserAuth` (startLogin/handleCallback/refreshAccessToken/logout) | browser-auth.ts:16–78 | Yes (§7 browser SDK) |
| TS | React: `HearthProvider`, `useHasPermission/useHasRole/useInGroup/useInOrg` | index.ts:64–71 (react.tsx) | **Extra** (TS-only convenience) |
| TS | `createHearth` facade, `HearthApiClient` (legacy) | index.ts:55,58 | **Extra** (back-compat) |

**TS notable absences (on `HearthClient`):** no `getMyPermissions`/`UserInfo`,
no `registerClient`, no WebAuthn, no `refreshToken`/`exchangeCode`, no
`getSessionVersion` — all of which Go and PHP expose. TS AdminClient uses loose
`Record<string, unknown>` params/returns for Clients/Roles/Groups vs. the typed
DTOs in Go/PHP.

---

### Go SDK

`Client` (`client.go`) is the primary type; `AdminClient` returned via
`Client.Admin(token)`. Package-level constructors and helpers.

| SDK | Exported symbol | File:line | In SDK.md contract? |
|-----|-----------------|-----------|---------------------|
| Go | `NewClient` / `Bootstrap` / options `WithClientCredentials`/`WithJWKSTTL`/`WithSessionVersions` | client.go:92,128,57,65,80 | Yes (§1) |
| Go | `Client.BeginLogin` / `Client.CompleteLogin` | login.go:22,68 | Yes (§7 PKCE login) |
| Go | `Client.VerifyToken(ctx, token, aud...)` | verify.go:90 | Yes (§2.1 REQUIRED) |
| Go | `Client.ClientCredentials` | flows.go:19 | Yes (§4.5.1) |
| Go | `Client.StartDeviceFlow` | flows.go:47 | Yes (§4.5.2) |
| Go | `Client.PollDeviceToken` ⚠ (no interval arg) | flows.go:78 | Yes (§4.5.2, signature drift per §2.5) |
| Go | `Client.RequestMagicLink` / `Client.ExchangeMagicLink` | flows.go:139,176 | Yes (§4.5.3) |
| Go | `Client.Authorize` / `ExchangeCode` / `RefreshTokens` / `RegisterClient` | client.go:150,162,171,141 | Yes (OAuth core) |
| Go | `Client.Introspect` | client.go:300 | Yes (§3) |
| Go | `Client.HasPermission/HasRole/InGroup/InOrg` (token convenience) | client.go:234–255 | **Extra** (mirrors Claims on Client) |
| Go | `Client.Permissions` / `UserInfo` / `CheckPermission` | client.go:263,279,330 | Yes (permissions/userinfo endpoints) |
| Go | `Client.StartWebAuthnRegistration/Finish…/StartWebAuthnAuthentication/Finish…` | webauthn.go:16,31,48,67 | Yes (WebAuthn) |
| Go | `Client.Stop` / `SessionVersionCacheAge` | client.go:107,119 | **Extra** (lifecycle/cache) |
| Go | `Client.Admin(token) *AdminClient` | client.go:352 | Yes (§12 entry) |
| Go | `AdminClient` — Users/Realms/Clients/Roles/Groups CRUD+List, OrgMembers Add/Get/Update/Remove/List | admin.go:20–270 | Yes (§12; typed DTOs, incl. GetOrgMember which TS lacks) |
| Go | `Claims` + Subject/Scope/Issuer/Audiences/Expiry/IssuedAt/JwtID/Scopes/HasScope/HasRole/HasPermission/InGroup/InOrg/TokenType/OrganizationId/OrgGroups/Get, `ParseClaims` | claims.go:73–176 | Yes (§4) |
| Go | `GeneratePKCE` / `NewJwksCache`+`GetKey` | pkce.go:30, jwks.go:53,75 | Yes (§7/§2) |
| Go | `RequirePermission` middleware | middleware.go:81 | Yes (§6) |
| Go | 12 typed error structs (ConfigurationError…RequiredActionError) | errors.go:20–189 | Yes (§5) |

---

### PHP SDK

`HearthClient` primary; `AdminClient` separate; `Claims` value object.
Laravel `HearthServiceProvider`/`HearthMiddleware` and PSR-15 middleware also shipped.

| SDK | Exported symbol | File:line | In SDK.md contract? |
|-----|-----------------|-----------|---------------------|
| PHP | `HearthClient::beginLogin` / `completeLogin` / `buildAuthorizeUrl` | HearthClient.php:122,145,170 | Yes (§7) |
| PHP | `HearthClient::exchangeCode` / `refreshToken` | HearthClient.php:225,260 | Yes (OAuth core) |
| PHP | `HearthClient::clientCredentials` | HearthClient.php:294 | Yes (§4.5.1) |
| PHP | `HearthClient::startDeviceFlow` / `pollDeviceToken` | HearthClient.php:334,370 | Yes (§4.5.2) |
| PHP | `HearthClient::requestMagicLink` / `exchangeMagicLink` | HearthClient.php:434,478 | Yes (§4.5.3) |
| PHP | `HearthClient::registerClient` | HearthClient.php:512 | Yes (DCR) |
| PHP | `HearthClient::verifyToken` | HearthClient.php:540 | Yes (§2.1 REQUIRED) |
| PHP | `HearthClient::getMyPermissions` / `checkDecision` / `getUserInfo` | HearthClient.php:566,595,611 | Yes (permissions/userinfo) |
| PHP | `HearthClient::startWebAuthnRegistration/finish…/startWebAuthnAuthentication/finish…` | HearthClient.php:646,663,679,696 | Yes (WebAuthn) |
| PHP | `HearthClient::getSessionVersion` | HearthClient.php:720 | Yes (session-version §2.5) |
| PHP | `HearthClient::bootstrap` | HearthClient.php:745 | **Extra** (dev bootstrap) |
| PHP | `HearthClient::getJwksClient/getTokenVerifier/getIntrospectionClient/discoverEndpoint` | HearthClient.php:759–823 | Yes (§2/§3 primitives) |
| PHP | `AdminClient` — Users/Realms/Clients/Roles/Groups CRUD+List, OrgMembers Add/Get/Update/Remove/List | AdminClient.php:74–383 | Yes (§12; typed via PageResponse) |
| PHP | `Claims` + subject/issuer/audiences/expiry/issuedAt/jwtID/scope/scopes/hasScope/hasRole/hasPermission/inGroup/inOrg/tokenType/organizationId/orgGroups/get + roles()/permissions()/groups() | Claims.php:27–235 | Yes (§4; roles()/permissions()/groups() are **Extra** accessors) |
| PHP | `TokenVerifier`, `JwksClient`, `IntrospectionClient` | src/TokenVerifier.php etc. | Yes (§2/§3) |
| PHP | Laravel `HearthServiceProvider` + PSR-15/Laravel `HearthMiddleware` | src/Laravel/*, src/Middleware/* | Yes (§6, framework glue = Extra) |

---

### Parity analysis

**Method counts (primary client + admin + claims):**

| SDK | Primary client methods | AdminClient methods | Claims methods |
|-----|------------------------|---------------------|----------------|
| TS  | 11 (+ browser-auth 6 fns/4-method facade, React hooks) | 28 | 18 (+`decode`, `assertValid`) |
| Go  | 24 (incl. WebAuthn 4, HasX 4, Permissions/UserInfo/CheckPermission, Stop/cache) | 26 | 18 (+`ParseClaims`) |
| PHP | 25 (incl. WebAuthn 4, getMyPermissions/checkDecision/getUserInfo, getSessionVersion) | 29 | 18 (+`roles/permissions/groups`) |

**Gaps vs. the three-way parity:**
1. **WebAuthn** — present in Go (4 methods) and PHP (4 methods); **absent from
   the TS `HearthClient`** (no WebAuthn surface anywhere in the TS SDK).
2. **`registerClient` (Dynamic Client Registration)** — Go (`RegisterClient`)
   and PHP (`registerClient`) expose it; **TS `HearthClient` does not** (only a
   `RegisterClientParams` type is exported, no method).
3. **Permissions / UserInfo endpoints** — Go (`Permissions`, `UserInfo`,
   `CheckPermission`) and PHP (`getMyPermissions`, `getUserInfo`,
   `checkDecision`) expose live authz/userinfo calls; **TS `HearthClient`
   exposes neither** (only the `MePermissionsResponse`/`UserInfoResponse` types).
4. **`refreshToken` / `exchangeCode`** — first-class on Go
   (`RefreshTokens`/`ExchangeCode`) and PHP (`refreshToken`/`exchangeCode`);
   on TS these live only in the legacy `HearthApiClient`/browser-auth facade,
   not on the primary `HearthClient`.
5. **`getSessionVersion`** — explicit method in PHP (`getSessionVersion`); Go
   exposes cache age (`SessionVersionCacheAge`) + option; TS ships
   `SessionVersionCache` as a standalone export. Three different shapes for the
   same §2.5 concern.
6. **AdminClient `GetOrgMember`** — present in Go (`GetOrgMember`) and PHP
   (`getOrgMember`); **missing in TS AdminClient** (has add/list/remove only).
7. **AdminClient typing** — TS uses untyped `Record<string, unknown>` for
   Clients/Roles/Groups params & returns; Go and PHP use typed DTOs. Weaker
   contract enforcement in TS.

**Gaps / drift vs. `SDK.md`:**
- **Go `PollDeviceToken` signature drift** — spec §2.5 flags it ⚠: takes only
  `deviceCode` (no `interval`), unlike the canonical `pollDeviceToken(deviceCode,
  interval)`. TS and PHP both include the interval argument.
- **Spec §2.5 ⚠ markers** in the mapping table already document Kotlin
  `deviceAuthorization`/no-`requestMagicLink` and Rust `initiate_magic_link`
  deviations — out of scope for TS/Go/PHP here, but confirm the spec anticipates
  per-SDK naming drift.
- **All three SDKs satisfy the mandatory core**: `verifyToken` (JWKS Ed25519),
  `introspect`, `clientCredentials`, `startDeviceFlow`, `pollDeviceToken`,
  `requestMagicLink`, full §4 Claims (18 methods each), the §5 error taxonomy,
  §6 middleware, and the §12 AdminClient minimum operations. No spec-required
  operation is entirely missing from any of the three.

**Net:** TS is the weakest for parity — it omits WebAuthn, DCR, permissions/
userinfo, and `GetOrgMember`, and under-types its AdminClient. Go and PHP are
near-identical in coverage; Go's only notable divergence is the
`PollDeviceToken` interval-less signature already flagged by the spec.
## Storage & Cluster Behaviors

Code-derived inventory of observable behaviors in `src/storage/` (WAL, memtable, SSTs, tiered storage, atomicity, realm isolation, crash recovery, compaction) and `src/cluster/` (openraft consensus, single-node bypass, membership). One row per distinct behavior an integration or black-box test could target. Entry points are public/`pub(crate)` traits and functions; file:line refer to definitions.

### Storage engine — public trait surface (`StorageEngine`)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Point read by realm+key; `None` if absent | `StorageEngine::get` | src/storage/mod.rs:65 | ARCHITECTURE §1.3, §7.1 |
| Insert/update a key for a realm | `StorageEngine::put` | src/storage/mod.rs:68 | ARCHITECTURE §6.1 |
| Delete a key (tombstone) for a realm | `StorageEngine::delete` | src/storage/mod.rs:71 | ARCHITECTURE §7.3 |
| Range scan `[start,end)`, sorted, merged across memtable+SST | `StorageEngine::scan` | src/storage/mod.rs:76 | ARCHITECTURE §7.1 (bounded scans) |
| Atomic multi-put batch (all-or-nothing after crash) | `StorageEngine::put_batch` | src/storage/mod.rs:94 | ARCHITECTURE §6.1 (atomic batch writes) |
| Compare-and-set write only if key absent (no TOCTOU; Raft-routed in cluster) | `StorageEngine::put_if_absent` | src/storage/mod.rs:118 | ARCHITECTURE §32 (cluster) |
| Key-only range scan (no value allocation) | `StorageEngine::scan_keys` | src/storage/mod.rs:140 | ARCHITECTURE §3.x (alloc discipline) |
| Count entries under a prefix with optional cap ceiling | `StorageEngine::count_prefix` | src/storage/mod.rs:158 | ARCHITECTURE §7.1 |
| Offset-paginated prefix scan returning window+total | `StorageEngine::scan_prefix_paged` | src/storage/mod.rs:188 | ARCHITECTURE §7.1 |
| Atomic mixed puts+deletes batch (crash-safe unit) | `StorageEngine::write_batch` | src/storage/mod.rs:237 | ARCHITECTURE §6.1 |
| Exclusive prefix end-bound helper for scans | `prefix_scan_end` | src/storage/mod.rs:51 | ARCHITECTURE §7.1 |

### Storage engine — embedded implementation & lifecycle

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Open engine; WAL replay reconstructs memtable state on startup | `EmbeddedStorageEngine::open` | src/storage/engine.rs:225 | ARCHITECTURE §6.1 (WAL replay) |
| Dev config (no fsync, `SyncMode::None`) | `StorageConfig::dev` | src/storage/engine.rs:71 | CONFIGURATION; validate.rs dev overrides |
| Production config always fsyncs (`SyncMode::EveryWrite`, non-negotiable) | `StorageConfig::production` | src/storage/engine.rs:95 | ARCHITECTURE §6.1; F3 regression test engine.rs:1929 |
| Manual SST compaction when count ≥ threshold; merges + drops tombstones | `EmbeddedStorageEngine::compact_ssts` | src/storage/engine.rs:575 | ARCHITECTURE §6.2, §7.3 (physical deletion) |
| Debug-mode realm-mismatch tripwire on returned records | `EmbeddedStorageEngine::get` (impl) | src/storage/engine.rs:664 | ARCHITECTURE §7.2 (runtime assertions) |

### WAL

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Append entry; fsync before ack when `SyncMode::EveryWrite` | `Wal::append` | src/storage/wal.rs:560 | ARCHITECTURE §6.1 |
| Append with segment pre-rotation hook | `Wal::append_with_pre_rotate` | src/storage/wal.rs:575 | ARCHITECTURE §6.4 (segments) |
| Sync mode enum (EveryWrite vs None) governs durability | `SyncMode` | src/storage/wal.rs:364 | ARCHITECTURE §6.1 |
| Explicit fsync of WAL file | `Wal::sync` (fsync) | src/storage/wal.rs:749 | ARCHITECTURE §6.1 |
| Deserialize entry; reject bad-CRC / truncated tail (crash safety) | `WalEntry::deserialize` | src/storage/wal.rs (fuzz target fuzz/…/wal_entry_deserialize.rs) | ARCHITECTURE §6.1; sim wal_crash.rs |

### Memtable / SST

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Memtable point read | `Memtable::get` | src/storage/memtable.rs:267 | ARCHITECTURE §6.1 |
| Flush memtable to SST under lock (snapshot-then-empty; preserves data on error) | `Memtable::flush_under_lock` | src/storage/memtable.rs:204 | ARCHITECTURE §6.1 |
| SST open / point read | `Sst::open`, `Sst::get` | src/storage/sst.rs:338, 490 | ARCHITECTURE §6.2 |
| Compaction merges, dedups, removes tombstones | `sst::compact` / `compact_with_fs` | src/storage/sst.rs:729, 747 | ARCHITECTURE §6.2, §7.3 |

### Tiered storage (hot/cold)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Hot-tier lock-free read (Arc value) | `HotTier::get` | src/storage/tiered.rs:128 | ARCHITECTURE §3.2 (no locks on read), §6.2 |
| Cold→hot promotion (async, non-blocking to readers; probabilistic admission) | `HotTier::promote` | src/storage/tiered.rs:162 | ARCHITECTURE §6.2 (promotion non-blocking) |
| Hot-tier membership check | `HotTier::contains` | src/storage/tiered.rs:284 | ARCHITECTURE §6.2 |
| Hot-tier occupancy (eviction bound) | `HotTier::len` | src/storage/tiered.rs:279 | ARCHITECTURE §6.2 (eviction non-blocking) |

### Encryption at rest / key registry

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Per-realm envelope encryption of values at rest | `src/storage/encryption.rs` | src/storage/encryption.rs | ARCHITECTURE §6.3 |
| KEK registry persisted to `hearth.keys` with CRC framing + fsync (tmp→fsync→rename) | `src/storage/key_registry.rs` | src/storage/key_registry.rs:255, 495 | ARCHITECTURE §6.3 |
| Storage format migrations on startup | `src/storage/migrations.rs` | src/storage/migrations.rs | ARCHITECTURE §6.4 |

### Realm isolation & lifecycle (cross-layer, storage-enforced)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Every op requires `RealmId` newtype; keys realm-prefixed; scans single-realm bounded | `StorageEngine` trait (all methods) | src/storage/mod.rs:63 | ARCHITECTURE §7.1 |
| Realm deletion cascade writes tombstones across all prefixes (idempotent) | `IdentityEngine::delete_realm` | src/identity/engine/mod.rs:4691 | ARCHITECTURE §7.3; sim realm_crash.rs |

### Cluster — engine wrapper (`ClusterEngine`)

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| Single-node bypass (writes go direct to storage, zero Raft overhead) | `ClusterEngine::single_node` | src/cluster/engine.rs:98 | ARCHITECTURE §32 (invisible single-node) |
| Build clustered engine (openraft, mTLS network) | `ClusterEngine::build_clustered` | src/cluster/engine.rs:114 | ARCHITECTURE §32 |
| Initialize cluster membership | `ClusterEngine::initialize_cluster` | src/cluster/engine.rs:201 | ARCHITECTURE §32 (membership) |
| Expose Raft metrics (leader/lag/term) | `ClusterEngine::raft_metrics` | src/cluster/engine.rs:216 | ARCHITECTURE §32.1 |
| Follower read staleness threshold (default lag ceiling) | `ClusterEngine::read_lag_threshold_ms` | src/cluster/engine.rs:221 | ARCHITECTURE §32.1 (bounded staleness, 500ms) |
| Graceful leadership transfer on shutdown | `ClusterEngine::transfer_leadership` | src/cluster/engine.rs:255 | ARCHITECTURE §12 (drain), §457 |
| Leader-routed get/put/delete/scan/put_batch/put_if_absent through Raft | `ClusterEngine::{get,put,delete,scan,put_batch,put_if_absent}` | src/cluster/engine.rs:370–493 | ARCHITECTURE §32 (writes via Raft) |
| Storage-trait adapter wrapping cluster engine | `ClusterStorageAdapter::new` | src/cluster/engine.rs:659 | ARCHITECTURE §1.3 |

### Cluster — openraft trait implementations & RPC

| Behavior/Capability | Entry point (trait/fn) | File:line | Spec reference |
|---|---|---|---|
| State machine applies committed entries to storage | `HearthStateMachine::apply` | src/cluster/state_machine.rs:203 | ARCHITECTURE §32 (RaftStateMachine) |
| Raft log store: append/read/open (redb-backed) | `HearthLogStore::open`, `append` | src/cluster/log_store.rs:195, 339 | ARCHITECTURE §32 (RaftLogStorage) |
| Outgoing peer RPC over lazy mTLS gRPC (AppendEntries/Vote/InstallSnapshot) | `HearthNetworkFactory` / `HearthPeerNetwork::append_entries` | src/cluster/network.rs:156 | ARCHITECTURE §32 |
| Incoming Raft RPC server (tonic + mTLS) dispatch | `serve`, `RaftRpcHandler`, `IncomingRpcDispatch` | src/cluster/server.rs:124, 28 | ARCHITECTURE §32 |
| Log-data / command / node types + Raft config | `HearthLogData`, `RaftCommand`, `HearthNode`, `HearthRaftConfig` | src/cluster/types.rs | ARCHITECTURE §32 |

### Notes: untested / undocumented observations

- **`put_if_absent` cluster path** (mod.rs:118) documents Raft-routed atomicity, but the trait default is a non-atomic get+put "correct only for single-node." A black-box test asserting cross-node atomicity would exercise `ClusterEngine::put_if_absent` (engine.rs:493) — the atomic guarantee lives only in the cluster impl.
- **Follower bounded-staleness enforcement** (ARCHITECTURE §32.1: follower MUST stop serving reads past the lag threshold and redirect to leader). `read_lag_threshold_ms` exists (engine.rs:221) but I found no read-rejection/redirect entry point in `ClusterEngine::get` — the enforcement side of the spec looks unimplemented or untested at the storage boundary.
- **Format versioning / previous-minor read** (ARCHITECTURE §6.4): `migrations.rs` is small (3.7k) and greenfield notes say no migration tooling — the "read previous minor version WAL/SST" MUST is likely aspirational, not test-covered.
- **Encryption-at-rest** (encryption.rs) and **WAL per-segment DEK** (§6.3): confirmed present in code, but no dedicated storage-encryption entry point surfaced in the public trait — coverage lives in module tests, not black-box reachable.
- Crash-recovery behaviors (WAL bad-CRC/truncation discard, rotation crash) are covered by `simulation/src/tests/wal_crash.rs` and `wal_rotation_crash.rs` (madsim), not by the standard nextest black-box harness.
## Security Behaviors

Code-derived inventory of security-relevant enforced behaviors in Hearth, cross-referenced against `docs/specs/` and the security sweeps HEA-1717 and HEA-1749. Paths are repo-relative to `/home/brad/Code/personal/hearth`. Line numbers are from the working tree at audit time and may drift.

| Security behavior | Enforcement entry point (fn) | File:line | Spec/sweep reference |
|---|---|---|---|
| **Ed25519-only JWT signing** — tokens signed with `EdDSA`/Ed25519 via `ring`; no HS256/`alg:none` | `SigningKey::sign` / `validate_token_with_time` (verifies `alg`, `typ`, Ed25519 sig before decode) | `src/identity/tokens.rs:444` (SigningKey), `src/identity/tokens.rs:896` (validate) | CLAUDE.md Security §Signing; OIDC.md; token_adversarial.rs HS256-forgery test |
| **JWT signature verify on hot path** — realm-key Ed25519 verify + serde parse, with global-key fallback | `Engine::validate_token` | `src/identity/engine/mod.rs:6742` (verify at `:6917`) | AUTHORIZATION.md; HEA-1771 zero-alloc |
| **Argon2id password hashing** — OWASP params, off hot path; HMAC-SHA256 pepper pre-hash | `hash_password` | `src/identity/credentials.rs:281` (Argon2id ctor `:255`, pepper `:262`) | CLAUDE.md §Password hashing; credentials.rs module doc |
| **Client-secret hashing (raw secrets)** — client secrets hashed with Argon2id before storage | `hash_raw_secret` / `verify_raw_secret` | `src/identity/credentials.rs:535`, `:553` | OIDC.md; oauth.rs `:257` |
| **Legacy hash upgrade** — bcrypt/scrypt/PBKDF2-SHA256 verified natively, auto-upgraded to Argon2id on login | password-verify path in engine | `src/identity/engine/mod.rs:5979` (`needs_algo_upgrade` `:5982`) | Keycloak/Auth0 migration; MEMORY import notes |
| **PKCE mandatory (public clients / FAPI2)** — authorize rejected without `code_challenge`; `method` must be `S256` | authorize handler PKCE gate | `src/identity/engine/oauth.rs:526`, `:606`, `:2442`, `:2470` | HEA-501; OIDC.md FAPI2; HEA-1749 A2 |
| **PKCE verifier check at token exchange** — `code_verifier` required + must match stored challenge | code-exchange PKCE validation | `src/identity/engine/oauth.rs:831` (mismatch `:844`) | OIDC.md §PKCE |
| **DPoP proof validation (RFC 9449)** — `typ=dpop+jwt`, alg/jwk/htu/htm/iat, no private key, JTI replay cache, jkt blocklist | `validate_dpop_proof` | `src/identity/dpop.rs:252` (typ check `:280`) | AGENT_AUTH.md; HTTP call sites `src/protocol/http/auth.rs:860`, `oauth.rs:1176/2252`, `tool_invocation.rs:198` |
| **DPoP JTI replay cache** — one-time proof JTIs stored `agt:dpop:jti:{jti}` with expiry; reaped | store + cleanup scan | `src/identity/mod.rs:2289`, `src/identity/cleanup.rs:462` | AGENT_AUTH.md |
| **Token exchange (RFC 8693)** — `grant_type=…token-exchange`; act-chain depth ≤10, caller binding | `token_exchange` HTTP + gRPC | `src/protocol/http/oauth.rs:1093`, `src/protocol/grpc/oauth.rs:93` | AGENT_AUTH.md M2; HEA-1753 R4; MAX_ACT_CHAIN_DEPTH=10 |
| **SSRF guard (connect-time DNS)** — validates `ureq` connect-time resolved addrs; blocks private/rebind on all webhook egress | `SsrfResolver::resolve` | `src/webhook/ssrf.rs:184` (agent build `:216`) | HEA-1762 SSRF TOCTOU; HEA-1749 |
| **Audit hash-chain (HMAC-SHA256)** — per-realm keyed chain `HMAC-SHA256(realm_key, prev_hash‖event)`; signed chain head detects tail truncation | `AuditEngine::append` (hash compute `:170`, chain-head MAC `:199`) | `src/audit/engine.rs:374` | HEA-1756 R7; MEMORY audit-chain note |
| **Cross-realm BOLA scoping (scoped_realm)** — admin handlers force path realm to match caller's authorized realm | `scoped_realm` | `src/protocol/http/admin.rs:240` (11 call sites) | HEA-1629 BOLA; HEA-1717 (verified complete) |
| **SAML `InResponseTo` binding** — response bound to issued AuthnRequest ID; mismatch rejected; DOCTYPE/XXE rejected | `parse_response` / response verify | `src/identity/federation/saml/response.rs:121` (InResponseTo mismatch `:392`, DOCTYPE reject `:560` test) | HEA-1751 R2 SAML hardening; HEA-1749 S1 |
| **SAML assertion signature verify** | `verify_assertion_signature` | `src/identity/tokens.rs:924` | HEA-1751 R2 |
| **MFA/session policy gate** — realm `mfa_required` blocks session issuance when user lacks MFA (TOTP/passkey) | `mfa_required` policy resolve + session gate | `src/identity/oidc.rs:630`; tests `tests/realm_auth_policy.rs:301` | HEA-1752 R3 MFA bypass |
| **Client auth on token endpoint** — confidential clients must present valid secret (Argon2id verify) or private_key_jwt; FAPI2 forbids secret | `authenticate_oauth_client_inner` / `authenticate_client_inner` | `src/identity/engine/oauth.rs:2999` (verify `:3018`); private_key_jwt `:1398` | HEA-1755 R6 token client-auth; OIDC.md |
| **CSP + security headers** — CSP, X-Frame-Options DENY, nosniff, COOP/COEP, HSTS(TLS), Permissions-Policy on all `/ui/**` | `SecurityHeadersService::call` (`SecurityHeadersLayer`) | `src/protocol/web/security.rs:32`/`:57` | HEA-1757 R8 (object-src/form-action); A-40; tests/web_csp.rs |
| **JTI revocation** — revoked token/client-cred JTIs blocklisted (`oauth:revjti:{jti}`), checked on validate | `is_token_jti_revoked` | `src/identity/engine/mod.rs:3703` (checked at `:3690`, `:6881`) | HEA-1771 C-2; HEA-1753 R4; MEMORY OAuth note |
| **Refresh-token theft detection** — grant-family `current_refresh_hash`; mismatch revokes family + session | rotate_grant_family / refresh binding | `src/identity/engine/oauth.rs` (RefreshBindContext) | HEA-1755 R6; MEMORY OAuth note |

### Notes / cross-references

- **Hot-path constraints** (zero-alloc, no locks) on `validate_token` are enforced by benches (`benches/validate_token.rs`) and HEA-1771, not a runtime check.
- **DPoP nonce** generation is stateless per-realm HMAC-SHA256 over sliding 5-min windows (`src/identity/dpop.rs`, nonce secret `agt:dpop:nonce-secret`).
- **Config-level guards**: `src/config/validate.rs:954/1781` reject `confidential:true` without a `client_secret` and vice-versa (startup-time BOLA/misconfig prevention).
- **Key-at-rest**: Ed25519 signing keys and DPoP nonce secrets are AES-256 KEK-wrapped (`src/identity/key_encryption.rs`, `src/storage/key_registry.rs` — 0o600 + HMAC-SHA256 integrity framing).

### Behaviors located with high confidence

All 20 targeted behaviors have a concrete enforcement entry point above. One partial: the **refresh-token theft / grant-family rotation** binding is confirmed by MEMORY + `RefreshBindContext`/`rotate_grant_family` references but the exact fn line was not pinned during this pass — see `src/identity/engine/oauth.rs` grant-family rotation code and HEA-1755.
