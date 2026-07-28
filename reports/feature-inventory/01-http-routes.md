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
