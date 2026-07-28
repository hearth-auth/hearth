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
