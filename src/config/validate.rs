//! Configuration loading and validation logic.
//!
//! All [`Config`] constructors and validators live here, keeping
//! `mod.rs` to declarations-only per the architecture rule.

use std::path::Path;

use super::env;
use super::error::ConfigError;
use super::removed::{removed_key_issue, REMOVED_KEYS};
use super::types::{
    parse_duration_to_micros, AgentAuthConfig, AuthConfig, BrandingConfig, ClusterConfig,
    CompactionSection, Config, DemoConfig, EmailConfig, EmailTransport, MetricsConfig,
    ObservabilityConfig, OidcYamlConfig, OnboardingConfig, OperationalConfig, RealmYamlConfig,
    RegistrationModeYaml, SecurityYaml, ServerConfig, StorageSection, TokenYamlConfig,
    ValidationIssue,
};
use crate::identity::credentials::{CredentialConfig, PepperConfig, PepperKey};

// ─────────────────────────────────────────────────────────────────────────────
// Valid-value tables
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal helper for extracting `dev_mode` from raw YAML before `Config` is fully parsed.
///
/// `Config.dev_mode` is `#[serde(default)]`, **not** `#[serde(skip)]` — serde will
/// happily populate it from a `dev_mode: true` line in any YAML document. Nothing
/// in the type makes the key unreachable; the explicit refusal in
/// [`Config::from_yaml_str`] below is the only thing that does (audit §4.7#3,
/// §4.13#10). Two comments here used to claim the `#[serde(skip)]` attribute was
/// the guard, which is why a config file arming the whole dev perimeter went
/// unnoticed: the claimed mechanism did not exist.
///
/// The unchecked loaders (`Config::from_yaml_str_unchecked`, `from_file_as_dev`)
/// deliberately still honour `dev_mode: true` in YAML — test harnesses and the
/// `hearth serve --dev` path embed it in inline config strings. This thin struct
/// reads that one field out of raw YAML so the checked loader can refuse it.
#[derive(serde::Deserialize)]
struct DevModeYaml {
    #[serde(default)]
    dev_mode: bool,
}

/// Returns `true` when raw YAML declares `dev_mode: true` at the top level.
///
/// Used to refuse a config file that tries to arm dev mode (HEA
/// control-liveness 10.2): `dev_mode` MUST only be set via the `--dev` CLI
/// flag (`Config::dev()` / `Config::from_file_as_dev()`), never by file
/// content — a release binary bound to a loopback address behind a reverse
/// proxy is still internet-reachable, and dev mode bypasses every
/// production fail-closed gate. Invalid YAML is treated as `false` here;
/// the caller's own parse will surface the real error.
pub fn yaml_declares_dev_mode(yaml: &str) -> bool {
    serde_norway::from_str::<DevModeYaml>(yaml)
        .map(|dm| dm.dev_mode)
        .unwrap_or(false)
}

/// Valid UI theme names — must match `protocol::web::themes::VALID_THEMES`.
pub(super) const VALID_UI_THEMES: &[&str] =
    &["ember", "ocean", "midnight", "forest", "cloud", "slate"];

/// HEA-2166: production requires a key-encryption key — without one, realm
/// signing keys (Ed25519 private keys) are written to storage in plaintext.
const KEK_REQUIRED_IN_PROD: &str =
    "production mode requires a key-encryption key; without one, realm signing keys are \
     stored in plaintext. Set the HEARTH_KEK environment variable (recommended) or \
     security.key_encryption_key to a random 64-hex-char value (openssl rand -hex 32). \
     Dev mode (--dev) does not require this.";

/// GA audit 2026-09-28 M15: the `log` email transport delivers nothing.
const EMAIL_LOG_TRANSPORT_IN_PROD: &str =
    "email.transport = log (the default) delivers no email: every message is dropped, \
     including the system realm's admin password-reset mail and the mail of every realm \
     created at runtime. Configure a real transport (smtp, sendgrid, postmark, mailgun or \
     mailtrap), or set email.allow_log_transport_in_production: true for an evaluation \
     deployment that knowingly runs without email. Dev mode (--dev) does not require this.";

/// HEA-2166: production requires HTTPS so session cookies carry `Secure`.
const TLS_REQUIRED_IN_PROD: &str =
    "production mode requires HTTPS — without it, session cookies are issued without the \
     Secure attribute and can be intercepted over plain HTTP. Set server.tls_cert_path + \
     server.tls_key_path for direct TLS, or server.trust_forwarded_proto: true when behind \
     a TLS-terminating reverse proxy. Dev mode (--dev) does not require this.";

/// HEA-2166: the demo seeder creates accounts sharing a well-known password.
const DEMO_FORBIDDEN_IN_PROD: &str =
    "demo.enabled = true mass-seeds accounts that all share a well-known default password \
     and is only permitted in dev mode (--dev). Remove the demo block from a production \
     config.";

/// Valid MFA method names.
/// Valid `auth.mfa_methods` entries.
///
/// `email_otp` was missing, so an operator following docs/guides/configuration-reference.md —
/// which lists it, and which three code paths already read — got a hard
/// config error for a documented value (audit 2026-08-28 §4.18#10).
const VALID_MFA_METHODS: &[&str] = &["totp", "webauthn", "email_otp"];

/// The one rule every surface that writes `mfa_methods` applies — the YAML
/// validator (global `auth.mfa_methods` and `realms.<name>.auth.mfa_methods`),
/// the JSON admin API and the admin console realm config PATCH.
///
/// Refuses any name outside [`VALID_MFA_METHODS`]. `sms` was removed in
/// 3.0.0 with SMS one-time codes, so it is refused as unknown.
///
/// # Errors
///
/// Returns the operator-facing reason. It names the offending method, never
/// a secret.
pub fn check_mfa_methods(methods: &[String]) -> Result<(), String> {
    if let Some(unknown) = methods
        .iter()
        .find(|m| !VALID_MFA_METHODS.contains(&m.as_str()))
    {
        return Err(format!(
            "unknown MFA method '{unknown}'; valid methods are: {}",
            VALID_MFA_METHODS.join(", ")
        ));
    }
    Ok(())
}

/// Valid authentication method names.
const VALID_AUTH_METHODS: &[&str] = &["password", "magic_link", "passkey"];

/// Valid OAuth 2.0 grant types.
const VALID_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
    // Both grants are enforced against `grant_types` (GA audit M7), so a
    // `hearth.yaml` client must be able to declare them.
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
    "urn:ietf:params:oauth:grant-type:token-exchange",
];

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

fn invalid(field: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::ValidationError {
        field: field.to_string(),
        reason: reason.into(),
    }
}

/// Flattens a [`ConfigError`] into a [`ValidationIssue`] so a short-circuiting
/// sub-validator can contribute to the all-collecting pass.
fn config_error_to_issue(err: &ConfigError) -> ValidationIssue {
    match err {
        ConfigError::ValidationError { field, reason } => ValidationIssue {
            field: field.clone(),
            reason: reason.clone(),
        },
        other => ValidationIssue {
            field: "config".to_string(),
            reason: other.to_string(),
        },
    }
}

/// Collects the start-up key-liveness and empty-secret issues for the raw
/// post-substitution YAML (audit §1A item 5, §4.13#4 — see
/// [`super::security_keys`]).
fn security_key_issues(substituted_yaml: &str) -> Vec<ValidationIssue> {
    let mut issues = super::security_keys::liveness_issues(substituted_yaml);
    issues.extend(super::security_keys::empty_secret_issues(substituted_yaml));
    issues
}

// ─────────────────────────────────────────────────────────────────────────────
// Config constructors and validators
// ─────────────────────────────────────────────────────────────────────────────

impl Config {
    /// Parses a YAML string into a validated [`Config`].
    ///
    /// Environment variables referenced as `${VAR_NAME}` or
    /// `${VAR_NAME:-default}` are substituted before parsing. Missing or
    /// empty variables (without a default) produce warnings rather than
    /// errors — see [`EnvVarWarning`].
    ///
    /// Returns an error for invalid YAML or values that fail validation.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ConfigError> {
        let (substituted, warnings) = env::substitute_env_vars(yaml);
        if let Some(err) = removed_key_issue(&substituted, REMOVED_KEYS) {
            return Err(err);
        }
        // HEA control-liveness 10.2 / audit §4.7#3: `dev_mode` is
        // #[serde(default)], so serde WOULD accept it here. This explicit
        // refusal — not any serde attribute — is what keeps it unreachable
        // through the checked/production loader
        // (`Config::from_file` uses it for every non `--dev` boot). A
        // release binary that loads a file declaring `dev_mode: true`
        // refuses to start rather than silently arming the whole dev
        // perimeter — see `dev_mode_true_in_config_file_is_refused`.
        if yaml_declares_dev_mode(&substituted) {
            return Err(ConfigError::ValidationError {
                field: "dev_mode".to_string(),
                reason: "cannot be set in a config file; use `hearth serve --dev` instead"
                    .to_string(),
            });
        }
        let mut config: Self = serde_norway::from_str(&substituted)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.config_warnings = warnings;
        config.key_liveness_issues = security_key_issues(&substituted);
        config.validate()?;
        Ok(config)
    }

    /// Loads configuration from a YAML file on disk.
    ///
    /// Before reading the YAML, looks for a `.env` file in the same directory
    /// as `path` and loads it if present (missing `.env` is silently ignored).
    /// Variables already set in the process environment take precedence over
    /// `.env` values. After that, substitutes `${VAR}` references, parses
    /// YAML, and validates the result.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        if let Some(dir) = path.parent() {
            env::load_dotenv(&dir.join(".env"))?;
        }
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    /// Creates a development-mode configuration with relaxed settings.
    ///
    /// Intended for local development and testing:
    /// - `fsync` disabled for faster writes
    /// - No TLS
    /// - Debug-level logging
    /// - Relaxed validation (empty `data_dir` and missing `oidc.issuer` allowed)
    pub fn dev() -> Self {
        Self {
            server: ServerConfig {
                bind_address: "127.0.0.1".to_string(),
                port: 8420,
                tls_cert_path: None,
                tls_key_path: None,
                tls_client_ca_path: None,
                tls_require_client_cert: false,
                trusted_proxies: Vec::new(),
                default_realm: None,
                assets_dir: None,
                trust_forwarded_proto: false,
            },
            storage: StorageSection {
                data_dir: String::new(),
                wal_max_size_bytes: 64 * 1024 * 1024,
                memtable_flush_bytes: 16 * 1024 * 1024,
                hot_tier_capacity: Some(1_000),
                hot_tier_max_memory: None,
                hot_tier_per_realm_metrics: true,
                fsync: Some(false),
                block_cache_bytes: 4 * 1024 * 1024,
                compaction: CompactionSection::default(),
            },
            observability: ObservabilityConfig {
                log_level: "debug".to_string(),
                log_format: "text".to_string(),
                otlp: None,
                dev_mode: true,
            },
            operational: OperationalConfig::default(),
            email: EmailConfig::default(),
            onboarding: OnboardingConfig::default(),
            branding: BrandingConfig::default(),
            oidc: OidcYamlConfig::default(),
            token: TokenYamlConfig::default(),
            auth: AuthConfig::default(),
            metrics: MetricsConfig::default(),
            realms: None,
            cluster: None,
            security: SecurityYaml::default(),
            agent_auth: AgentAuthConfig::default(),
            demo: DemoConfig::default(),
            dev_mode: true,
            config_warnings: Vec::new(),
            key_liveness_issues: Vec::new(),
        }
    }

    /// Loads configuration from a YAML file *without* running structural validation.
    ///
    /// Follows the same file-resolution logic as [`from_file`] — loads a sibling
    /// `.env`, substitutes `${VAR}` references — but skips the short-circuit
    /// validator. Use this when you want to collect all issues at once via
    /// [`validate_all`] rather than stopping on the first error.
    pub fn from_file_unchecked(path: &Path) -> Result<Self, ConfigError> {
        if let Some(dir) = path.parent() {
            env::load_dotenv(&dir.join(".env"))?;
        }
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_str_unchecked(&content)
    }

    /// Loads a file in dev mode: parses without validation, applies dev
    /// settings (`dev_mode = true`), then validates with the relaxed dev-mode
    /// rules.
    ///
    /// A configured `storage.data_dir` is preserved so `--dev` can persist the
    /// WAL/SSTs to a real directory (HEA-1805); the dev-mode wiring in
    /// `main.rs` decides whether to honor it or fall back to an ephemeral temp
    /// dir. Historically this was blanked to `String::new()`, which made dev
    /// mode ignore the config value entirely.
    pub fn from_file_as_dev(path: &Path) -> Result<Self, ConfigError> {
        let mut config = Self::from_file_unchecked(path)?;
        config.dev_mode = true;
        // `storage.fsync` is deliberately NOT forced to `false` here any more.
        // Absent resolves to off in dev via `StorageSection::fsync_enabled`;
        // an operator who wrote `fsync: true` wants the real group-commit path
        // and used to have that silently discarded (audit §4.11#12).
        config.validate()?;
        Ok(config)
    }

    /// Parses a YAML string into a [`Config`] *without* running validation.
    ///
    /// Use this when you want to run [`validate_all`] yourself to collect
    /// all issues rather than short-circuiting on the first error.
    ///
    /// Environment variables are still substituted.
    pub fn from_yaml_str_unchecked(yaml: &str) -> Result<Self, ConfigError> {
        let (substituted, warnings) = env::substitute_env_vars(yaml);
        // A removed key is refused even here: `--dev` loads through this path,
        // and dev must fail the same way production does.
        if let Some(err) = removed_key_issue(&substituted, REMOVED_KEYS) {
            return Err(err);
        }
        let mut config: Self = serde_norway::from_str(&substituted)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.config_warnings = warnings;
        config.key_liveness_issues = security_key_issues(&substituted);
        if let Ok(dm) = serde_norway::from_str::<DevModeYaml>(&substituted) {
            config.dev_mode = dm.dev_mode;
        }
        Ok(config)
    }

    /// Validates all configuration values, collecting every issue.
    ///
    /// Unlike [`validate`], this does **not** short-circuit — all validation
    /// rules are checked and every problem is returned.
    #[allow(clippy::too_many_lines)]
    pub fn validate_all(&self) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();

        if self.server.port == 0 {
            issues.push(ValidationIssue {
                field: "server.port".to_string(),
                reason: "must be between 1 and 65535".to_string(),
            });
        }

        if self.dev_mode && !is_loopback_str(&self.server.bind_address) {
            issues.push(ValidationIssue {
                field: "server.bind_address".to_string(),
                reason: format!(
                    "dev_mode = true is only permitted with a loopback bind address; \
                     '{}' is not loopback. Use 127.0.0.1 or ::1, or disable dev_mode.",
                    self.server.bind_address
                ),
            });
        }

        match (&self.server.tls_cert_path, &self.server.tls_key_path) {
            (Some(_), None) => issues.push(ValidationIssue {
                field: "server.tls_key_path".to_string(),
                reason: "tls_key_path is required when tls_cert_path is set".to_string(),
            }),
            (None, Some(_)) => issues.push(ValidationIssue {
                field: "server.tls_cert_path".to_string(),
                reason: "tls_cert_path is required when tls_key_path is set".to_string(),
            }),
            _ => {}
        }

        if self.server.tls_require_client_cert && self.server.tls_client_ca_path.is_none() {
            issues.push(ValidationIssue {
                field: "server.tls_client_ca_path".to_string(),
                reason: "tls_client_ca_path is required when tls_require_client_cert is true"
                    .to_string(),
            });
        }

        if !self.dev_mode && self.storage.data_dir.is_empty() {
            issues.push(ValidationIssue {
                field: "storage.data_dir".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        if let Err(reason) = self.security.backup.verify_key_bytes() {
            issues.push(ValidationIssue {
                field: "security.backup.verify_key".to_string(),
                reason,
            });
        }

        // OPS-11 (GA audit 2026-09-28): the server resolves HEARTH_KEK with
        // `var`, which cannot read a non-UTF-8 value and now refuses it. Say
        // so here too, rather than counting it as a present KEK below.
        if std::env::var_os("HEARTH_KEK").is_some_and(|v| v.to_str().is_none()) {
            issues.push(ValidationIssue {
                field: "security.key_encryption_key".to_string(),
                reason: "HEARTH_KEK is set but is not valid UTF-8; it must be 64 hex \
                         characters (openssl rand -hex 32)"
                    .to_string(),
            });
        }

        // HEA-2166: mirror the fail-closed production gates from `validate`
        // so the admin config-check panel surfaces all three in one pass.
        if !self.dev_mode {
            if self.security.key_encryption_key.is_none()
                && std::env::var_os("HEARTH_KEK").is_none()
            {
                issues.push(ValidationIssue {
                    field: "security.key_encryption_key".to_string(),
                    reason: KEK_REQUIRED_IN_PROD.to_string(),
                });
            }
            if self.server.tls_cert_path.is_none() && !self.server.trust_forwarded_proto {
                issues.push(ValidationIssue {
                    field: "server.tls_cert_path".to_string(),
                    reason: TLS_REQUIRED_IN_PROD.to_string(),
                });
            }
            if self.demo.enabled {
                issues.push(ValidationIssue {
                    field: "demo.enabled".to_string(),
                    reason: DEMO_FORBIDDEN_IN_PROD.to_string(),
                });
            }
        }

        if !ObservabilityConfig::VALID_LOG_LEVELS.contains(&self.observability.log_level.as_str()) {
            issues.push(ValidationIssue {
                field: "observability.log_level".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_LEVELS.join(", ")
                ),
            });
        }

        if !ObservabilityConfig::VALID_LOG_FORMATS.contains(&self.observability.log_format.as_str())
        {
            issues.push(ValidationIssue {
                field: "observability.log_format".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_FORMATS.join(", ")
                ),
            });
        }

        if self.operational.request_timeout_secs == 0 {
            issues.push(ValidationIssue {
                field: "operational.request_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.shutdown_timeout_secs == 0 {
            issues.push(ValidationIssue {
                field: "operational.shutdown_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.max_connections == 0 {
            issues.push(ValidationIssue {
                field: "operational.max_connections".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.queue_depth == 0 {
            issues.push(ValidationIssue {
                field: "operational.queue_depth".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        // #446: a bound of 0 would refuse every user create, and a 0 ms queue
        // wait would shed every create that meets another one.
        if self.operational.user_create.max_in_flight == 0 {
            issues.push(ValidationIssue {
                field: "operational.user_create.max_in_flight".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.user_create.max_queue_wait_ms == 0 {
            issues.push(ValidationIssue {
                field: "operational.user_create.max_queue_wait_ms".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        // B6: a zero budget would close every connection before its first
        // request, and "no timeout" is exactly the defect being closed.
        if self.operational.header_read_timeout_secs == 0 {
            issues.push(ValidationIssue {
                field: "operational.header_read_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }
        if self.operational.tls_handshake_timeout_secs == 0 {
            issues.push(ValidationIssue {
                field: "operational.tls_handshake_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        validate_oidc_all(&self.oidc, self.dev_mode, &mut issues);
        validate_token_all(&self.token, &mut issues);
        validate_email_all(&self.email, &mut issues);
        validate_branding_all(&self.branding, &mut issues);
        if let Some(realms) = self.realms.as_ref() {
            if realms.contains_key("system") {
                issues.push(ValidationIssue {
                    field: "realms.system".to_string(),
                    reason: "\"system\" is a reserved realm name; managed by Hearth".to_string(),
                });
            }
        }
        validate_realm_web_configs_all(self.realms.as_ref(), &mut issues);
        if let Some(methods) = &self.auth.mfa_methods {
            if let Err(reason) = check_mfa_methods(methods) {
                issues.push(ValidationIssue {
                    field: "auth.mfa_methods".to_string(),
                    reason,
                });
            }
        }
        validate_realm_auth_configs_all(self.realms.as_ref(), &mut issues);
        validate_mfa_is_satisfiable(&self.auth, self.realms.as_ref(), &mut issues);
        validate_realm_applications_all(self.realms.as_ref(), &mut issues);
        validate_realm_organizations_all(self.realms.as_ref(), &mut issues);
        validate_realm_federation_keys_all(self.realms.as_ref(), &mut issues);
        validate_realm_protected_resources_all(self.realms.as_ref(), self.dev_mode, &mut issues);
        validate_realm_introspection_clients_all(self.realms.as_ref(), &mut issues);

        // HSEC-010: Mirror the fail-fast check in validate_all so the admin
        // config-check panel surfaces this error alongside other issues.
        //
        // GA audit 2026-09-28 M15: this used to be the only log-transport
        // check, and it covers only realms declared in YAML. The system realm
        // (the admin console, which always has password login), the
        // auto-created default realm and API-created realms were never
        // checked, so a production config with no `email:` block booted and
        // silently dropped admin password-reset mail. The per-realm reasons
        // stay here because they name the feature that needs mail; the
        // blanket refusal (with its opt-in) is added at the end of this
        // function.
        if !self.dev_mode
            && self.email.transport == EmailTransport::Log
            && !self.email.allow_log_transport_in_production
        {
            validate_email_transport_log_prod_all(self.realms.as_ref(), &mut issues);
        }

        if let Some(addr) = &self.onboarding.notification_email {
            if addr.parse::<lettre::message::Mailbox>().is_err() {
                issues.push(ValidationIssue {
                    field: "onboarding.notification_email".to_string(),
                    reason: "could not parse as an RFC 5322 mailbox".to_string(),
                });
            }
        }

        if self.onboarding.notification_email.is_some() && self.onboarding.base_url.is_none() {
            issues.push(ValidationIssue {
                field: "onboarding.base_url".to_string(),
                reason: "onboarding.base_url is required when onboarding.notification_email is \
                         set; without it the emailed setup URL uses the bind address which may \
                         not be reachable from outside the server"
                    .to_string(),
            });
        }

        validate_trusted_proxies(&self.server, &mut issues);
        validate_cluster_all(self.cluster.as_ref(), &mut issues);
        validate_cidr_policies(self.realms.as_ref(), &mut issues);
        validate_argon2_costs_all(&self.auth, self.realms.as_ref(), self.dev_mode, &mut issues);

        // ── Checks that used to live only in `validate` (audit §4.13#8) ─────
        //
        // `hearth config validate` and the admin config editor run
        // `validate_all`; `serve` runs `validate`. They were two hand-written
        // bodies, so the CLI printed "✓ Configuration valid" for configs the
        // server refuses to start with — and the admin visual editor, a raw
        // JSON→YAML passthrough that writes `hearth.yaml`, wrote them to disk
        // behind the weaker one. `validate` now delegates to this function, so
        // every rule MUST live here.
        if let Err(e) = self.security.resolve_pepper() {
            issues.push(config_error_to_issue(&e));
        }
        if let Err(e) = self.security.validate_kdf_admission() {
            issues.push(config_error_to_issue(&e));
        }
        if !(1..=32).contains(&self.security.max_act_chain_depth) {
            issues.push(ValidationIssue {
                field: "security.max_act_chain_depth".to_string(),
                reason: format!(
                    "must be 1–32, got {} (32 keeps a delegated token under common \
                     8 KB request-header limits)",
                    self.security.max_act_chain_depth
                ),
            });
        }

        validate_auth_password_costs(&self.auth, &mut issues);
        validate_argon2_ceilings(&self.auth, self.realms.as_ref(), &mut issues);
        validate_webauthn_preference(
            "auth.webauthn_resident_key",
            self.auth.webauthn_resident_key.as_deref(),
            &mut issues,
        );
        validate_webauthn_preference(
            "auth.webauthn_user_verification",
            self.auth.webauthn_user_verification.as_deref(),
            &mut issues,
        );

        // §4.11#12 / §6: `storage.fsync` was accepted, warned about, and then
        // ignored — production always built `SyncMode::EveryWrite`. Refuse the
        // value instead of pretending to honour it.
        if !self.dev_mode && self.storage.fsync == Some(false) {
            issues.push(ValidationIssue {
                field: "storage.fsync".to_string(),
                reason: "must not be false outside dev mode — WAL durability is not optional, \
                         and this key was previously accepted and then ignored. Remove the key \
                         to keep fsync on, or run with `--dev` if you genuinely want it off."
                    .to_string(),
            });
        }

        // §4.13#4: a `${VAR}` reference with no `:-default` that resolved to
        // the empty string. In production this is a hard error, not a warning:
        // an empty expected credential compares equal to a caller who supplied
        // none. `${VAR:-}` is the documented way to say "empty on purpose" and
        // records no warning, so the escape hatch survives.
        if !self.dev_mode {
            let mut env_issues = Vec::new();
            for warning in &self.config_warnings {
                env_issues.push(ValidationIssue {
                    field: format!("${{{}}}", warning.var_name),
                    reason: format!(
                        "environment variable {} is {} — the reference was substituted with \
                         the empty string. An empty value is accepted as a credential by the \
                         /metrics guard and by client_secret_basic, so this fails closed. Set \
                         the variable, or write ${{{}:-}} to declare the empty value \
                         intentional.",
                        warning.var_name,
                        warning.kind_label(),
                        warning.var_name,
                    ),
                });
            }
            // An unset variable is the root cause of every empty-value
            // complaint downstream, and it names the thing the operator must
            // actually change. Report it before the symptom, so the first
            // error the operator reads is the useful one.
            issues.splice(0..0, env_issues);
        }

        // §1A item 5: security keys the operator set that no consumer reads,
        // and secret keys that resolved to the empty string. Computed at parse
        // time because only the raw YAML distinguishes an operator-set key from
        // a compiled-in default.
        issues.extend(self.key_liveness_issues.iter().cloned());

        // GA audit 2026-09-28 M15. Last, so that a config with a more specific
        // problem reports that problem first; see the per-realm check above.
        if !self.dev_mode
            && self.email.transport == EmailTransport::Log
            && !self.email.allow_log_transport_in_production
        {
            issues.push(ValidationIssue {
                field: "email.transport".to_string(),
                reason: EMAIL_LOG_TRANSPORT_IN_PROD.to_string(),
            });
        }

        issues
    }

    /// Whether WAL writes are `fsync`'d under this config's run mode.
    ///
    /// The single resolution point for `storage.fsync` (audit §4.11#12): the
    /// raw field is an `Option<bool>` where absent means "mode default", and
    /// reading it directly is how the knob came to be ignored in the first
    /// place. Also used by the admin system-info page so the operator sees the
    /// effective value rather than the literal YAML.
    #[must_use]
    pub const fn fsync_effective(&self) -> bool {
        self.storage.fsync_enabled(self.dev_mode)
    }

    /// Builds the engine-wide base [`CredentialConfig`] this config asks for.
    ///
    /// The single resolution point for the documented global Argon2 knobs
    /// `auth.password_memory_cost` and `auth.password_time_cost` (audit
    /// §4.17#8). Both keys parsed into [`AuthConfig`] and were then read by
    /// nothing: `main.rs` built `CredentialConfig::default()` (or
    /// `fast_for_testing()` under `--dev`) and only the *per-realm*
    /// `realms.<name>.password_memory_cost` overrides in
    /// `credential_config_for_realm` had any effect. An operator who raised the
    /// global cost after a hardware upgrade got a clean boot and unchanged
    /// hashing.
    ///
    /// `pepper` is threaded through because it is resolved separately by
    /// [`SecurityYaml::resolve_pepper`] and the two must land on the same
    /// struct.
    ///
    /// Range validation lives in [`Self::validate_all`], so a config that
    /// reaches this function has already been refused if the parameters are
    /// outside Argon2's own bounds.
    #[must_use]
    pub fn base_credential_config(&self, pepper: Option<PepperConfig>) -> CredentialConfig {
        let mut cfg = if self.dev_mode {
            CredentialConfig::fast_for_testing()
        } else {
            CredentialConfig::default()
        };
        if let Some(memory_cost) = self.auth.password_memory_cost {
            cfg.memory_cost_kib = memory_cost;
        }
        if let Some(time_cost) = self.auth.password_time_cost {
            cfg.time_cost = time_cost;
        }
        cfg.pepper = pepper;
        cfg
    }

    /// Validates configuration values, returning the first problem found.
    ///
    /// Called automatically by [`from_yaml_str`] and [`from_file`].
    /// Dev-mode configs skip certain checks (e.g., empty `data_dir`).
    ///
    /// # One validator, two presentations
    ///
    /// This delegates to [`Self::validate_all`] rather than re-stating the
    /// rules. They used to be two independently maintained bodies and had
    /// drifted: `hearth config validate` and the admin config editor (which
    /// writes `hearth.yaml`) ran `validate_all`, `serve` ran this — so the CLI
    /// printed "✓ Configuration valid" for a `security.password.kdf` bound of
    /// `0` and a malformed pepper key, both of which the server refuses to
    /// start with (audit §4.13#8). Delegation makes that divergence
    /// unrepresentable. Add new rules to `validate_all`.
    ///
    /// # Errors
    ///
    /// Returns the first [`ConfigError::ValidationError`] `validate_all`
    /// reports. Callers that want every problem at once should call
    /// `validate_all` directly.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.validate_all().into_iter().next() {
            Some(issue) => Err(ConfigError::ValidationError {
                field: issue.field,
                reason: issue.reason,
            }),
            None => Ok(()),
        }
    }
}

impl SecurityYaml {
    /// Validates `security.password.kdf`, rejecting any `0` bound or queue-wait.
    ///
    /// An explicit bound of `0` would produce a gate that admits no Argon2id
    /// work — every login would shed with `503`. A queue-wait of `0` ms sheds
    /// every *contended* login. Neither is ever intended, so both are config
    /// errors rather than silent clamps. `null`/absent is valid and resolves to
    /// the documented default at boot (core count / 250 ms).
    pub fn validate_kdf_admission(&self) -> Result<(), ConfigError> {
        if self.password.kdf.max_in_flight == Some(0) {
            return Err(invalid(
                "security.password.kdf.max_in_flight",
                "must be >= 1 (a bound of 0 would shed every password verification); \
                 omit the key to default to the host core count",
            ));
        }
        if self.password.kdf.admin_max_in_flight == Some(0) {
            return Err(invalid(
                "security.password.kdf.admin_max_in_flight",
                "must be >= 1 (a bound of 0 would shed every admin login); \
                 omit the key to default to the small reserved admin pool",
            ));
        }
        if self.password.kdf.max_queue_wait_ms == 0 {
            return Err(invalid(
                "security.password.kdf.max_queue_wait_ms",
                "must be >= 1 (a 0 ms wait would shed every contended login with 503); \
                 omit the key to default to 250 ms",
            ));
        }
        if self.password.kdf.admin_max_queue_wait_ms == Some(0) {
            return Err(invalid(
                "security.password.kdf.admin_max_queue_wait_ms",
                "must be >= 1 (a 0 ms wait would shed every queued admin login); \
                 omit the key to default to the longer admin queue-wait",
            ));
        }
        Ok(())
    }

    /// Resolves `security.password.kdf` into a [`crate::identity::KdfGateConfig`].
    ///
    /// `max_in_flight: null`/absent resolves to the host core count via
    /// [`KdfGateConfig::default`](crate::identity::KdfGateConfig). Assumes
    /// [`Self::validate_kdf_admission`] already ran (so `0` cannot reach here).
    #[must_use]
    pub fn resolve_kdf_gate(&self) -> crate::identity::KdfGateConfig {
        let yaml = &self.password.kdf;
        let default = crate::identity::KdfGateConfig::default();
        crate::identity::KdfGateConfig {
            max_in_flight: yaml.max_in_flight.unwrap_or(default.max_in_flight),
            max_queue_wait: std::time::Duration::from_millis(yaml.max_queue_wait_ms),
            retry_after: std::time::Duration::from_secs(yaml.retry_after_seconds),
        }
    }

    /// Resolves `security.password.kdf` into the **admin-reserved**
    /// [`crate::identity::KdfGateConfig`] (HEA-1892 / F2).
    ///
    /// `admin_max_in_flight: null`/absent resolves to
    /// [`crate::identity::DEFAULT_ADMIN_MAX_IN_FLIGHT`]. `admin_max_queue_wait_ms:
    /// null`/absent resolves to [`crate::identity::DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS`]
    /// — a *longer* wait than the shared gate (HEA-1895): admin login prefers
    /// queueing over shedding, so a distributed flood cannot hold the console in a
    /// steady-state `503`. `retry_after` is shared with the main gate. Assumes
    /// [`Self::validate_kdf_admission`] already ran (so `0` cannot reach here).
    #[must_use]
    pub fn resolve_admin_kdf_gate(&self) -> crate::identity::KdfGateConfig {
        let yaml = &self.password.kdf;
        crate::identity::KdfGateConfig {
            max_in_flight: yaml
                .admin_max_in_flight
                .unwrap_or(crate::identity::DEFAULT_ADMIN_MAX_IN_FLIGHT),
            max_queue_wait: std::time::Duration::from_millis(
                yaml.admin_max_queue_wait_ms
                    .unwrap_or(crate::identity::DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS),
            ),
            retry_after: std::time::Duration::from_secs(yaml.retry_after_seconds),
        }
    }

    /// Resolves `security.password.pepper` into a [`PepperConfig`].
    ///
    /// Returns `Ok(None)` when no pepper is configured (the default), leaving
    /// `CredentialConfig::pepper` as `None`. When a pepper is present, validates
    /// that every key is a 64-character lowercase-hex 32-byte value that is not
    /// the all-zero key, and that `previous_version` / `previous_key_hex` are
    /// supplied together. Called both by [`Config::validate`] (fail-fast) and by
    /// `main.rs` when building `CredentialConfig`.
    pub fn resolve_pepper(&self) -> Result<Option<PepperConfig>, ConfigError> {
        let Some(pepper) = self.password.pepper.as_ref() else {
            return Ok(None);
        };

        let active_key = decode_pepper_key("security.password.pepper.key_hex", &pepper.key_hex)?;

        let (previous_version, previous_key) =
            match (pepper.previous_version, pepper.previous_key_hex.as_ref()) {
                (None, None) => (None, None),
                (Some(v), Some(hex)) => {
                    if v == pepper.version {
                        return Err(invalid(
                            "security.password.pepper.previous_version",
                            "must differ from the active version — credentials hashed under \
                             the previous key would only be verified against the active key \
                             and fail to log in",
                        ));
                    }
                    let key = decode_pepper_key("security.password.pepper.previous_key_hex", hex)?;
                    (Some(v), Some(key))
                }
                (Some(_), None) => {
                    return Err(invalid(
                        "security.password.pepper.previous_key_hex",
                        "previous_key_hex is required when previous_version is set",
                    ));
                }
                (None, Some(_)) => {
                    return Err(invalid(
                        "security.password.pepper.previous_version",
                        "previous_version is required when previous_key_hex is set",
                    ));
                }
            };

        Ok(Some(PepperConfig {
            active_version: pepper.version,
            active_key,
            previous_version,
            previous_key,
        }))
    }
}

/// Decodes a hex-encoded pepper key, rejecting non-hex, short (< 32 byte), and
/// all-zero values with an operator-facing [`ConfigError`].
fn decode_pepper_key(field: &str, hex: &str) -> Result<PepperKey, ConfigError> {
    let bytes =
        hex::decode(hex).map_err(|e| invalid(field, format!("must be lowercase hex: {e}")))?;
    if bytes.len() < 32 {
        return Err(invalid(
            field,
            format!(
                "must be at least 32 bytes (64 hex chars); got {} bytes",
                bytes.len()
            ),
        ));
    }
    if bytes.iter().all(|b| *b == 0) {
        return Err(invalid(
            field,
            "must not be the all-zero key — generate a random 32-byte (64 hex char) value",
        ));
    }
    PepperKey::new(bytes).map_err(|e| invalid(field, e.to_string()))
}

// ─────────────────────────────────────────────────────────────────────────────
// IP-address helpers
// ─────────────────────────────────────────────────────────────────────────────

fn is_loopback_str(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn is_public_listener(bind_address: &str) -> bool {
    !is_loopback_str(bind_address)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fail-fast validators (used by `Config::validate`)
// ─────────────────────────────────────────────────────────────────────────────

/// Refuses a `residentKey` / `userVerification` preference the browser does
/// not understand.
///
/// An unrecognised string is forwarded verbatim in the ceremony options and
/// the browser silently falls back to `"preferred"` — so a realm that asked
/// for `"Required"` (or misspelled it) gets a passkey that proves possession
/// only, with no signal that the policy was ignored (audit §4.18#9, B10).
fn validate_webauthn_preference(
    field: &str,
    value: Option<&str>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(value) = value else { return };
    if !crate::config::types::VALID_WEBAUTHN_PREFERENCES.contains(&value) {
        issues.push(ValidationIssue {
            field: field.to_string(),
            reason: format!(
                "unknown WebAuthn preference '{}'; valid values are: {}. An unrecognised value \
                 is silently ignored by the browser, which falls back to 'preferred'.",
                value,
                crate::config::types::VALID_WEBAUTHN_PREFERENCES.join(", ")
            ),
        });
    }
}

/// Validates the global Argon2id knobs against the algorithm's own bounds.
///
/// `auth.password_memory_cost` / `auth.password_time_cost` now reach the base
/// [`CredentialConfig`] (audit §4.17#8), so a value `argon2::Params::new`
/// refuses would turn every password verification into a 500 at request time
/// rather than a refusal at boot. Bounds are Argon2's, not OWASP's: the OWASP
/// floor is a separate finding (§4.17#6).
fn validate_auth_password_costs(auth: &AuthConfig, issues: &mut Vec<ValidationIssue>) {
    if let Some(memory_cost) = auth.password_memory_cost {
        // `MAX_M_COST` is `u32::MAX` on this build, so only the lower bound can
        // ever fire; comparing against it too would be an absurd comparison.
        if memory_cost < argon2::Params::MIN_M_COST {
            issues.push(ValidationIssue {
                field: "auth.password_memory_cost".to_string(),
                reason: format!(
                    "must be at least {} KiB — Argon2id rejects anything outside that range, \
                     and the failure would surface as a 500 on every login rather than at \
                     start-up",
                    argon2::Params::MIN_M_COST,
                ),
            });
        }
    }
    if let Some(time_cost) = auth.password_time_cost {
        if time_cost < argon2::Params::MIN_T_COST {
            issues.push(ValidationIssue {
                field: "auth.password_time_cost".to_string(),
                reason: format!(
                    "must be at least {} — Argon2id rejects a zero iteration count, and the \
                     failure would surface as a 500 on every login rather than at start-up",
                    argon2::Params::MIN_T_COST,
                ),
            });
        }
    }
}

/// Refuses Argon2id costs above the ceilings every stored-hash verifier
/// enforces (task 26.36: [`ARGON2_MAX_MEMORY_KIB`] and
/// [`ARGON2_MAX_TIME_COST`]).
///
/// Above them `hash_raw_secret` would mint client secrets and recovery codes
/// that `verify_raw_secret` always refuses, and user password hashes a restore
/// refuses to import — a configuration that looks like "more secure" and
/// silently locks every newly issued credential out. Applies in every mode:
/// unlike the OWASP floor it is not a production-only policy. Parallelism has
/// no configuration key (it is compiled in, below [`ARGON2_MAX_PARALLELISM`]).
///
/// [`ARGON2_MAX_MEMORY_KIB`]: crate::identity::ARGON2_MAX_MEMORY_KIB
/// [`ARGON2_MAX_TIME_COST`]: crate::identity::ARGON2_MAX_TIME_COST
/// [`ARGON2_MAX_PARALLELISM`]: crate::identity::ARGON2_MAX_PARALLELISM
fn validate_argon2_ceilings(
    auth: &AuthConfig,
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let mut check = |field: String, memory: Option<u32>, time: Option<u32>| {
        if let Some(m) = memory.filter(|m| *m > crate::identity::ARGON2_MAX_MEMORY_KIB) {
            issues.push(ValidationIssue {
                field: format!("{field}.password_memory_cost"),
                reason: format!(
                    "{m} KiB is above the Argon2 memory ceiling of {} KiB (1 GiB) that every \
                     stored-hash verifier enforces: credentials hashed with it could never be \
                     verified",
                    crate::identity::ARGON2_MAX_MEMORY_KIB
                ),
            });
        }
        if let Some(t) = time.filter(|t| *t > crate::identity::ARGON2_MAX_TIME_COST) {
            issues.push(ValidationIssue {
                field: format!("{field}.password_time_cost"),
                reason: format!(
                    "{t} is above the Argon2 time-cost ceiling of {} passes that every \
                     stored-hash verifier enforces: credentials hashed with it could never be \
                     verified",
                    crate::identity::ARGON2_MAX_TIME_COST
                ),
            });
        }
    };
    check(
        "auth".to_string(),
        auth.password_memory_cost,
        auth.password_time_cost,
    );
    for (name, realm) in realms.into_iter().flatten() {
        check(
            format!("realms.{name}"),
            realm.password_memory_cost,
            realm.password_time_cost,
        );
    }
}

/// Returns advisory start-up warnings about `server`, as data.
///
/// These used to be `tracing::warn!` calls inside [`validate_trusted_proxies`],
/// which runs from `Config::from_file` while `load_config` parses the file —
/// *before* `telemetry::init` installs a subscriber. Every one of them was
/// written into the void (audit 2026-08-28 §4.17#7, and the same shape as the
/// CLI-subcommand silence fixed in 16.2). Returning them lets `run_serve` log
/// them after the subscriber exists.
#[must_use]
pub fn deferred_server_warnings(server: &ServerConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    if server.trusted_proxies.is_empty() && is_public_listener(&server.bind_address) {
        warnings.push(format!(
            "server.trusted_proxies is empty on a public listener ({}) — all requests will use \
             the direct socket IP for per-IP rate limiting and audit records. \
             If Hearth is behind a reverse proxy, set server.trusted_proxies to the \
             proxy IP(s) so the real client IP is read from X-Forwarded-For.",
            server.bind_address
        ));
    }
    warnings
}

/// Reports every Argon2id cost pair that falls below the OWASP floor.
///
/// `password_memory_cost` / `password_time_cost` are settable globally under
/// `auth:` and per realm under `realms.<name>:`, and both accepted arbitrarily
/// low values (audit 2026-08-28 §4.17#6). This is the `hearth.yaml` door; the
/// realm create/update API is gated independently in the identity engine,
/// because a layer must not assume the one above it validated.
///
/// Each realm is checked against its *effective* pair — its own override, else
/// the global `auth:` value, else the compiled-in default — so a realm that
/// lowers only one of the two is still caught. Dev mode is exempt: it runs
/// `CredentialConfig::fast_for_testing` parameters on purpose.
fn validate_argon2_costs_all(
    auth: &crate::config::AuthConfig,
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    dev_mode: bool,
    issues: &mut Vec<ValidationIssue>,
) {
    if dev_mode {
        return;
    }
    let base = crate::identity::CredentialConfig::default();
    let global_m = auth.password_memory_cost.unwrap_or(base.memory_cost_kib);
    let global_t = auth.password_time_cost.unwrap_or(base.time_cost);

    if auth.password_memory_cost.is_some() || auth.password_time_cost.is_some() {
        if let Err(reason) = crate::identity::validate_argon2_cost(global_m, global_t) {
            issues.push(ValidationIssue {
                field: "auth.password_memory_cost".to_string(),
                reason,
            });
        }
    }

    let Some(realms) = realms else { return };
    for (name, realm) in realms {
        if realm.password_memory_cost.is_none() && realm.password_time_cost.is_none() {
            continue;
        }
        let m = realm.password_memory_cost.unwrap_or(global_m);
        let t = realm.password_time_cost.unwrap_or(global_t);
        if let Err(reason) = crate::identity::validate_argon2_cost(m, t) {
            issues.push(ValidationIssue {
                field: format!("realms.{name}.password_memory_cost"),
                reason,
            });
        }
    }
}

/// Refuses every `realms.<name>.security.cidr_policy` entry the runtime would.
///
/// The runtime (`abuse::runtime::compile_filter`) parses each entry as a
/// [`crate::core::IpRange`] and drops what does not parse. Nothing checked the
/// lists at load, so a typo was silently discarded — and a typo in the only
/// `allow` entry emptied the allow list, lifting the realm's network
/// restriction altogether. This runs the same parser, so a policy that loads
/// is a policy that matches.
///
/// Unlike `trusted_proxies`, no breadth rule applies: `deny: [0.0.0.0/0]` and
/// `allow: [::/0]` are legitimate policies.
fn validate_cidr_policies(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    let mut names: Vec<&String> = realms.keys().collect();
    names.sort();
    for name in names {
        let Some(policy) = realms[name]
            .security
            .as_ref()
            .and_then(|s| s.cidr_policy.as_ref())
        else {
            continue;
        };
        for (list, entries) in [("allow", &policy.allow), ("deny", &policy.deny)] {
            for (i, entry) in entries.iter().enumerate() {
                if let Err(reason) = entry.parse::<crate::core::IpRange>() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.security.cidr_policy.{list}[{i}]"),
                        reason: format!("'{entry}' {reason}."),
                    });
                }
            }
        }
    }
}

/// Validates the `cluster:` section. The peer server binds
/// `cluster.peer_address`, so it must parse as a socket address: an IP
/// address and a port. A host name used to pass here; the peer server then
/// stopped at start-up while the node went on serving, and no cluster formed.
/// A peer's `address` is dialled, not bound, so a host name is valid there.
fn validate_cluster_all(cluster: Option<&ClusterConfig>, issues: &mut Vec<ValidationIssue>) {
    let Some(cluster) = cluster else {
        return;
    };
    if cluster
        .peer_address
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        issues.push(ValidationIssue {
            field: "cluster.peer_address".to_string(),
            reason: format!(
                "'{}' is not an IP address and port (for example \"10.0.0.1:8421\" or \
                 \"[fd00::1]:8421\"); this node's peer server binds it, so a host name \
                 is not accepted",
                cluster.peer_address
            ),
        });
    }
}

/// A-32: Validates `server.trusted_proxies` against known dangerous configurations.
fn validate_trusted_proxies(server: &ServerConfig, issues: &mut Vec<ValidationIssue>) {
    // 19.12: `trust_forwarded_proto` makes `X-Forwarded-Proto` decide whether a
    // session cookie carries `Secure`. The runtime honours the header only from
    // a peer listed in `trusted_proxies` (GA audit 2026-09-28 L4 — before that
    // it was read from any peer, whatever this list said), so with an empty
    // list the flag would be inert and the operator's "TLS terminates
    // upstream" would never be recognised. Production validation used to push
    // operators here — it demanded TLS **or** this flag, and this flag
    // defaulted to trusting every peer (audit 2026-08-28 §4.17#7).
    if server.trust_forwarded_proto && server.trusted_proxies.is_empty() {
        issues.push(ValidationIssue {
            field: "server.trust_forwarded_proto".to_string(),
            reason: "server.trust_forwarded_proto = true requires a non-empty \
                     server.trusted_proxies. X-Forwarded-Proto is honoured only from a \
                     peer in that list, so with no list the flag has no effect: session \
                     cookies would never carry the Secure attribute and HSTS would never be \
                     sent. List the reverse-proxy IP(s) in server.trusted_proxies, or \
                     configure direct TLS with server.tls_cert_path + server.tls_key_path \
                     instead."
                .to_string(),
        });
    }

    // One parser for validation and runtime: `main.rs` builds the live list
    // with `TrustedProxies::parse`, which goes through the same
    // `TrustedProxy::from_str` as this loop. 26.24 existed because the two
    // disagreed — the validator accepted a CIDR the runtime then silently
    // discarded — and sharing the parser makes that impossible. The parser
    // itself refuses malformed entries, host bits set in a range, catch-alls
    // (`0.0.0.0/0`, `::/0`, `0.0.0.0`, `::`) and ranges broader than /8 or /16.
    for (i, entry) in server.trusted_proxies.iter().enumerate() {
        let field = format!("server.trusted_proxies[{i}]");

        let proxy = match entry.parse::<crate::core::TrustedProxy>() {
            Ok(proxy) => proxy,
            Err(reason) => {
                issues.push(ValidationIssue {
                    field,
                    reason: format!("'{entry}' {reason}."),
                });
                continue;
            }
        };

        // Contextual, so it lives here rather than in the parser: a loopback
        // proxy is only reachable when the server itself listens on loopback.
        if proxy.is_loopback() && is_public_listener(&server.bind_address) {
            issues.push(ValidationIssue {
                field,
                reason: format!(
                    "'{entry}' is a loopback address but the server is bound to '{}' \
                     (a public listener). Loopback proxies cannot reach a public listener; \
                     this entry is likely a misconfiguration. \
                     If your proxy truly runs on localhost, bind the server to 127.0.0.1.",
                    server.bind_address
                ),
            });
        }
    }
}

/// Returns `Some(reason)` when a realm needs a working email transport.
///
/// Three features make email load-bearing:
///
/// * `magic_link` in `allowed_auth_methods` — the link *is* the credential;
/// * self-registration in any mode but `disabled` — the verification mail;
/// * **password authentication** — the forgot-password / reset link is the
///   only self-service recovery path a password realm has. This third case
///   was missing, so a password-only realm could be configured, validated and
///   started in a state where every reset email is silently discarded
///   (audit 2026-08-28 §4.24#9).
///
/// Password auth counts when `allowed_auth_methods` is unset (unrestricted,
/// so password is available) or explicitly lists `password`.
fn realm_requires_email_delivery(realm: &RealmYamlConfig) -> Option<&'static str> {
    let auth = realm.auth.as_ref();

    let has_magic_link = auth
        .and_then(|a| a.allowed_auth_methods.as_ref())
        .map(|methods| methods.iter().any(|m| m == "magic_link"))
        .unwrap_or(false);
    if has_magic_link {
        return Some("magic_link auth is enabled");
    }

    let has_self_reg = auth
        .and_then(|a| a.registration.as_ref())
        .map(|r| !matches!(r.mode, RegistrationModeYaml::Disabled))
        .unwrap_or(false);
    if has_self_reg {
        return Some("self-registration is enabled");
    }

    let has_password = auth
        .and_then(|a| a.allowed_auth_methods.as_ref())
        .map_or(true, |methods| methods.iter().any(|m| m == "password"));
    if has_password {
        return Some("password authentication is enabled, so password reset needs email");
    }

    None
}

/// Builds the operator-facing message for a realm that needs email delivery
/// while `email.transport = log`.
fn email_transport_log_reason(realm_name: &str, why: &str) -> String {
    format!(
        "realm '{realm_name}' requires email delivery ({why}) but \
         email.transport = log — no emails will be delivered in production. \
         Configure a real transport: smtp, sendgrid, postmark, mailgun, or \
         mailtrap."
    )
}

/// Reports every realm that needs email delivery while `email.transport = log`
/// in production. The only variant: `Config::validate` delegates to
/// `validate_all`, so there is no short-circuiting twin to drift from.
fn validate_email_transport_log_prod_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (name, realm) in realms {
        if let Some(why) = realm_requires_email_delivery(realm) {
            issues.push(ValidationIssue {
                field: "email.transport".to_string(),
                reason: email_transport_log_reason(name, why),
            });
        }
    }
}

fn validate_realm_protected_resources_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    dev_mode: bool,
    issues: &mut Vec<ValidationIssue>,
) {
    // openspec/specs/mcp-authorization/spec.md: a protected resource's `resource_uri` MUST use HTTPS
    // in production; `--dev` MAY permit HTTP. The spec carves out dev mode
    // only, so a loopback `http://` URI is refused in production as well. The
    // scheme is compared on the canonical (lowercased) form. Malformed URIs
    // are reported by the realm registry check (`to_realm_config`), not here.
    if dev_mode {
        return;
    }
    let Some(realms) = realms else { return };
    for (name, cfg) in realms {
        for (i, resource) in cfg
            .protected_resources
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let Ok(uri) = crate::core::Uri::try_from(resource.resource_uri.clone()) else {
                continue;
            };
            if !uri.as_str().starts_with("https://") {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.protected_resources[{i}].resource_uri"),
                    reason: format!(
                        "'{}' must use https outside --dev mode (openspec/specs/mcp-authorization/spec.md)",
                        resource.resource_uri
                    ),
                });
            }
        }
    }
}

/// `protected_resources[].introspection_client` must be the key of an
/// application declared in the same realm (under `applications` or its alias
/// `oauth_clients`): reconcile derives the client's id from that key, so a
/// typo would silently name a client that does not exist (G6).
fn validate_realm_introspection_clients_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (name, cfg) in realms {
        let declared = |key: &str| {
            [cfg.applications.as_ref(), cfg.oauth_clients.as_ref()]
                .into_iter()
                .flatten()
                .any(|apps| apps.contains_key(key))
        };
        for (i, resource) in cfg
            .protected_resources
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
        {
            let Some(key) = resource.introspection_client.as_deref() else {
                continue;
            };
            if !declared(key) {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.protected_resources[{i}].introspection_client"),
                    reason: format!(
                        "'{key}' is not an application of realm '{name}' \
                         (applications / oauth_clients)"
                    ),
                });
            }
        }
    }
}

/// Parses, at configuration load and reload, every PEM a federation
/// connector needs at login: a SAML connector's `idp_certificate_pem` (a
/// single certificate or a rollover bundle) and an Apple connector's
/// `apple_private_key_pem`.
///
/// Both used to be parsed only at the first federated login, so a paste
/// error surfaced as a failed sign-in instead of a refused boot (GA audit 3,
/// round 3). The checks call the runtime's own parsers
/// (`saml::validate_idp_certificate_bundle`, `apple::validate_private_key_pem`)
/// so load-time validation cannot disagree with what login accepts.
fn validate_realm_federation_keys_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (realm, cfg) in realms {
        let Some(federation) = &cfg.federation else {
            continue;
        };
        for (idp, provider) in &federation.providers {
            let base = format!("realms.{realm}.federation.providers.{idp}");
            let present = |v: &Option<String>| v.clone().filter(|p| !p.trim().is_empty());
            match provider.kind.as_str() {
                "saml" => match present(&provider.idp_certificate_pem) {
                    None => issues.push(ValidationIssue {
                        field: format!("{base}.idp_certificate_pem"),
                        reason: format!(
                            "SAML connector '{idp}' in realm '{realm}' has no \
                             `idp_certificate_pem`: without the IdP's signing \
                             certificate no assertion can be verified"
                        ),
                    }),
                    Some(pem) => {
                        if let Err(e) =
                            crate::identity::federation::saml::validate_idp_certificate_bundle(&pem)
                        {
                            issues.push(ValidationIssue {
                                field: format!("{base}.idp_certificate_pem"),
                                reason: format!(
                                    "SAML connector '{idp}' in realm '{realm}': \
                                     `idp_certificate_pem` is not a usable RSA signing \
                                     certificate (or bundle of them): {e}"
                                ),
                            });
                        }
                    }
                },
                "apple" => {
                    let usable = present(&provider.apple_private_key_pem).is_some_and(|pem| {
                        crate::identity::federation::apple::validate_private_key_pem(&pem).is_ok()
                    });
                    if !usable {
                        issues.push(ValidationIssue {
                            field: format!("{base}.apple_private_key_pem"),
                            reason: format!(
                                "Apple connector '{idp}' in realm '{realm}': \
                                 `apple_private_key_pem` is missing or is not a P-256 \
                                 private key in PKCS#8 PEM form \
                                 (`-----BEGIN PRIVATE KEY-----`)"
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
    }
}

/// Hard cap: access token TTL must not exceed 1 hour (HEA-SEC-27).
const ACCESS_TOKEN_TTL_MAX_MICROS: i64 = 3_600 * 1_000_000;
/// Hard cap: refresh token TTL must not exceed 30 days (HEA-SEC-27).
const REFRESH_TOKEN_TTL_MAX_MICROS: i64 = 30 * 86_400 * 1_000_000;
/// Warning threshold: access token TTL > 15 minutes warrants an operator alert.
const ACCESS_TOKEN_TTL_WARN_MICROS: i64 = 900 * 1_000_000;
/// Warning threshold: refresh token TTL > 24 hours warrants an operator alert.
const REFRESH_TOKEN_TTL_WARN_MICROS: i64 = 86_400 * 1_000_000;

// ─────────────────────────────────────────────────────────────────────────────
// Accumulating validators (used by `Config::validate_all`)
// ─────────────────────────────────────────────────────────────────────────────

fn validate_oidc_all(oidc: &OidcYamlConfig, dev_mode: bool, issues: &mut Vec<ValidationIssue>) {
    if oidc.issuer.is_none() && !dev_mode {
        issues.push(ValidationIssue {
            field: "oidc.issuer".to_string(),
            reason: "required for production; set it to your public HTTPS URL \
                     (e.g. https://auth.example.com)"
                .to_string(),
        });
    }
    if let Some(issuer) = &oidc.issuer {
        if issuer.is_empty() {
            issues.push(ValidationIssue {
                field: "oidc.issuer".to_string(),
                reason: "must not be empty".to_string(),
            });
        } else if !issuer.starts_with("https://") && !issuer.starts_with("http://") {
            issues.push(ValidationIssue {
                field: "oidc.issuer".to_string(),
                reason: "must be a URL starting with https:// or http://".to_string(),
            });
        } else if issuer.contains(".local") {
            issues.push(ValidationIssue {
                field: "oidc.issuer".to_string(),
                reason: "uses a .local hostname which is not publicly reachable; \
                         set it to your public HTTPS URL (e.g. https://auth.example.com)"
                    .to_string(),
            });
        }
    }
    if let Some(ttl) = &oidc.authorization_code_ttl {
        if parse_duration_to_micros(ttl).is_err() {
            issues.push(ValidationIssue {
                field: "oidc.authorization_code_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            });
        }
    }
    if oidc.enforce_nonces == Some(false) {
        issues.push(ValidationIssue {
            field: "oidc.enforce_nonces".to_string(),
            reason: "this opt-out has been removed (HEA-SEC-29). Nonce replay protection is \
                     now unconditional per OIDC Core §3.1.2.1. Remove the key from your config."
                .to_string(),
        });
    }
    if oidc.require_pkce_for_confidential_clients == Some(false) {
        issues.push(ValidationIssue {
            field: "oidc.require_pkce_for_confidential_clients".to_string(),
            reason: "this opt-out has been removed (HEA-SEC-29). PKCE is now unconditional \
                     for all clients per RFC 9700 §2.1.1. Remove the key from your config."
                .to_string(),
        });
    }
}

fn validate_token_all(token: &TokenYamlConfig, issues: &mut Vec<ValidationIssue>) {
    if let Some(issuer) = &token.issuer {
        if issuer.is_empty() {
            issues.push(ValidationIssue {
                field: "token.issuer".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
    }
    if let Some(ttl) = &token.access_token_ttl {
        match parse_duration_to_micros(ttl) {
            Err(_) => issues.push(ValidationIssue {
                field: "token.access_token_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            }),
            Ok(micros) if micros > ACCESS_TOKEN_TTL_MAX_MICROS => issues.push(ValidationIssue {
                field: "token.access_token_ttl".to_string(),
                reason: "access token TTL must not exceed 1 hour (HEA-SEC-27); \
                         long-lived access tokens significantly widen the stolen-token window"
                    .to_string(),
            }),
            Ok(micros) if micros > ACCESS_TOKEN_TTL_WARN_MICROS => {
                tracing::warn!(
                    field = "token.access_token_ttl",
                    "access token TTL exceeds 15 minutes; consider reducing it (HEA-SEC-27)"
                );
            }
            Ok(_) => {}
        }
    }
    if let Some(ttl) = &token.refresh_token_ttl {
        match parse_duration_to_micros(ttl) {
            Err(_) => issues.push(ValidationIssue {
                field: "token.refresh_token_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            }),
            Ok(micros) if micros > REFRESH_TOKEN_TTL_MAX_MICROS => issues.push(ValidationIssue {
                field: "token.refresh_token_ttl".to_string(),
                reason: "refresh token TTL must not exceed 30 days (HEA-SEC-27)".to_string(),
            }),
            Ok(micros) if micros > REFRESH_TOKEN_TTL_WARN_MICROS => {
                tracing::warn!(
                    field = "token.refresh_token_ttl",
                    "refresh token TTL exceeds 24 hours; consider enabling rotation (HEA-SEC-27)"
                );
            }
            Ok(_) => {}
        }
    }
    // The rotation grace period was applied through a silent `if let Ok(..)`
    // at startup: a malformed value fell back to the 24h default, and a
    // negative value wrapped through an `as u64` cast into an effectively
    // infinite window (audit §4.15#2).
    //
    // This rule used to live only in the short-circuiting `validate_token`, so
    // `hearth config validate` — and the admin config editor, which writes
    // `hearth.yaml` — reported "✓ Configuration valid" for a grace period of
    // `-1h` that `serve` refuses to boot with (audit §4.13#8). Every rule
    // belongs in the `_all` variant now; `Config::validate` reads its first
    // issue.
    if let Some(grace) = &token.signing_key_rotation_grace_period {
        match parse_duration_to_micros(grace) {
            Err(e) => issues.push(ValidationIssue {
                field: "token.signing_key_rotation_grace_period".to_string(),
                reason: format!("invalid duration: {e}"),
            }),
            Ok(micros) if micros < 0 => issues.push(ValidationIssue {
                field: "token.signing_key_rotation_grace_period".to_string(),
                reason: "signing-key rotation grace period must not be negative; \
                         a negative window is applied as an effectively infinite grace \
                         (audit 2026-08-28 §4.15#2)"
                    .to_string(),
            }),
            Ok(micros) if micros > REFRESH_TOKEN_TTL_MAX_MICROS => issues.push(ValidationIssue {
                field: "token.signing_key_rotation_grace_period".to_string(),
                reason: "signing-key rotation grace period must not exceed 30 days; \
                         the retired key stays trusted for the whole window"
                    .to_string(),
            }),
            Ok(_) => {}
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_email_all(email: &EmailConfig, issues: &mut Vec<ValidationIssue>) {
    // `log` discards the message and `mailcatcher` is the in-process dev
    // inbox at `/dev/mail`; neither puts a message on the wire, and neither
    // required a from address before the short-circuiting and all-collecting
    // validators were unified (task 20.9). Unifying them must not make the
    // rules STRICTER than the server enforced, or `hearth config validate`
    // refuses a config that boots — the same divergence in the other
    // direction. The shipped dev examples set no from address.
    if matches!(
        email.transport,
        EmailTransport::Log | EmailTransport::Mailcatcher
    ) {
        return;
    }

    match &email.from {
        None => issues.push(ValidationIssue {
            field: "email.from".to_string(),
            reason: format!(
                "from address is required when email.transport is {:?}",
                email.transport
            ),
        }),
        Some(addr) => {
            if addr.parse::<lettre::message::Mailbox>().is_err() {
                issues.push(ValidationIssue {
                    field: "email.from".to_string(),
                    reason: "could not parse as an RFC 5322 mailbox".to_string(),
                });
            }
        }
    }

    match email.transport {
        EmailTransport::Smtp => {
            if let Some(smtp) = &email.smtp {
                if smtp.host.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.smtp.host".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
                if smtp.port == 0 {
                    issues.push(ValidationIssue {
                        field: "email.smtp.port".to_string(),
                        reason: "must be between 1 and 65535".to_string(),
                    });
                }
                // SMTP credentials come as a pair. Half a pair is always a
                // mistake, and it fails at the first send rather than at boot.
                // These three rules predate the all-collecting validator and
                // must survive it.
                match (&smtp.username, &smtp.password) {
                    (Some(u), _) if u.is_empty() => {
                        issues.push(ValidationIssue {
                            field: "email.smtp.username".to_string(),
                            reason: "must not be empty".to_string(),
                        });
                    }
                    (Some(_), None) => {
                        issues.push(ValidationIssue {
                            field: "email.smtp.password".to_string(),
                            reason: "password is required when username is set".to_string(),
                        });
                    }
                    (None, Some(_)) => {
                        issues.push(ValidationIssue {
                            field: "email.smtp.username".to_string(),
                            reason: "username is required when password is set".to_string(),
                        });
                    }
                    _ => {}
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.smtp".to_string(),
                    reason: "smtp block is required when email.transport is smtp".to_string(),
                });
            }
        }
        EmailTransport::Sendgrid => {
            if let Some(sg) = &email.sendgrid {
                if sg.api_key.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.sendgrid.api_key".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.sendgrid".to_string(),
                    reason: "sendgrid block is required when email.transport is sendgrid"
                        .to_string(),
                });
            }
        }
        EmailTransport::Postmark => {
            if let Some(pm) = &email.postmark {
                if pm.server_token.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.postmark.server_token".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.postmark".to_string(),
                    reason: "postmark block is required when email.transport is postmark"
                        .to_string(),
                });
            }
        }
        EmailTransport::Mailgun => {
            if let Some(mg) = &email.mailgun {
                if mg.api_key.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.mailgun.api_key".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
                if mg.domain.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.mailgun.domain".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.mailgun".to_string(),
                    reason: "mailgun block is required when email.transport is mailgun".to_string(),
                });
            }
        }
        EmailTransport::Mailtrap => {
            if let Some(mt) = &email.mailtrap {
                if mt.api_key.is_empty() {
                    issues.push(ValidationIssue {
                        field: "email.mailtrap.api_key".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            } else {
                issues.push(ValidationIssue {
                    field: "email.mailtrap".to_string(),
                    reason: "mailtrap block is required when email.transport is mailtrap"
                        .to_string(),
                });
            }
        }
        EmailTransport::Log | EmailTransport::Mailcatcher => {}
    }
}

fn validate_branding_all(branding: &BrandingConfig, issues: &mut Vec<ValidationIssue>) {
    if let Some(theme) = &branding.theme {
        let lower = theme.to_ascii_lowercase();
        if !VALID_UI_THEMES.contains(&lower.as_str()) {
            issues.push(ValidationIssue {
                field: "branding.theme".to_string(),
                reason: format!(
                    "unknown theme '{}'; valid themes are: {}",
                    theme,
                    VALID_UI_THEMES.join(", ")
                ),
            });
        }
    }
    if let Some(path) = &branding.custom_css {
        if let Err(e) = crate::protocol::web::themes::load_custom_css(path) {
            issues.push(ValidationIssue {
                field: "branding.custom_css".to_string(),
                reason: format!("{path}: {e}"),
            });
        }
    }
}

fn validate_realm_web_configs_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (name, cfg) in realms {
        let Some(web) = &cfg.web else { continue };
        if let Some(theme) = &web.theme {
            let lower = theme.to_ascii_lowercase();
            if !VALID_UI_THEMES.contains(&lower.as_str()) {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.web.theme"),
                    reason: format!(
                        "unknown theme '{}'; valid themes are: {}",
                        theme,
                        VALID_UI_THEMES.join(", ")
                    ),
                });
            }
        }
        if let Some(path) = &web.custom_css {
            if let Err(e) = crate::protocol::web::themes::load_custom_css(path) {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.web.custom_css"),
                    reason: format!("{path}: {e}"),
                });
            }
        }
    }
}

/// A realm that requires MFA — explicitly or by the default — must offer a
/// method that satisfies it: a passkey (`webauthn`) or TOTP. Email OTP alone
/// cannot (spec `mfa-policy`), so such a realm could never finish a sign-in.
/// An absent `mfa_methods` restricts nothing and always passes.
fn validate_mfa_is_satisfiable(
    global: &AuthConfig,
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (name, cfg) in realms {
        let auth = cfg.auth.as_ref();
        let required = auth
            .and_then(|a| a.mfa_required)
            .or(global.mfa_required)
            .unwrap_or(true);
        let (source, methods) = match auth.and_then(|a| a.mfa_methods.as_ref()) {
            Some(m) => ("", Some(m)),
            None => (
                " (inherited from auth.mfa_methods)",
                global.mfa_methods.as_ref(),
            ),
        };
        let Some(methods) = methods else { continue };
        if required && !methods.iter().any(|m| m == "totp" || m == "webauthn") {
            issues.push(ValidationIssue {
                field: format!("realms.{name}.auth.mfa_methods"),
                reason: format!(
                    "this realm requires MFA, so mfa_methods{source} must include totp or \
                     webauthn: email OTP does not satisfy MFA"
                ),
            });
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_realm_auth_configs_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (name, cfg) in realms {
        if let Some(scim) = &cfg.scim {
            if let Some(token) = &scim.bearer_token {
                if token.trim().is_empty() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.scim.bearer_token"),
                        reason: "must not be empty when SCIM is configured".to_string(),
                    });
                }
            }
        }
        let Some(auth) = &cfg.auth else { continue };
        validate_webauthn_preference(
            &format!("realms.{name}.auth.webauthn_resident_key"),
            auth.webauthn_resident_key.as_deref(),
            issues,
        );
        validate_webauthn_preference(
            &format!("realms.{name}.auth.webauthn_user_verification"),
            auth.webauthn_user_verification.as_deref(),
            issues,
        );
        if let Some(methods) = &auth.mfa_methods {
            if let Err(reason) = check_mfa_methods(methods) {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.auth.mfa_methods"),
                    reason,
                });
            }
        }
        if let Some(methods) = &auth.allowed_auth_methods {
            for m in methods {
                if !VALID_AUTH_METHODS.contains(&m.as_str()) {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.allowed_auth_methods"),
                        reason: format!(
                            "unknown auth method '{}'; valid methods are: {}",
                            m,
                            VALID_AUTH_METHODS.join(", ")
                        ),
                    });
                }
            }
        }
        if let Some(pp) = &auth.password_policy {
            if let Some(len) = pp.min_length {
                if len == 0 {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.password_policy.min_length"),
                        reason: "must be >= 1".to_string(),
                    });
                }
            }
        }
        if let Some(token) = &auth.token {
            if let Some(ttl) = &token.access_token_ttl {
                match parse_duration_to_micros(ttl) {
                    Err(_) => issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.access_token_ttl"),
                        reason: "invalid duration format".to_string(),
                    }),
                    Ok(micros) if micros > ACCESS_TOKEN_TTL_MAX_MICROS => {
                        issues.push(ValidationIssue {
                            field: format!("realms.{name}.auth.token.access_token_ttl"),
                            reason: "access token TTL must not exceed 1 hour (HEA-SEC-27)"
                                .to_string(),
                        });
                    }
                    Ok(micros) if micros > ACCESS_TOKEN_TTL_WARN_MICROS => {
                        tracing::warn!(
                            field = format!("realms.{name}.auth.token.access_token_ttl"),
                            "access token TTL exceeds 15 minutes (HEA-SEC-27)"
                        );
                    }
                    Ok(_) => {}
                }
            }
            if let Some(ttl) = &token.refresh_token_ttl {
                match parse_duration_to_micros(ttl) {
                    Err(_) => issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.refresh_token_ttl"),
                        reason: "invalid duration format".to_string(),
                    }),
                    Ok(micros) if micros > REFRESH_TOKEN_TTL_MAX_MICROS => {
                        issues.push(ValidationIssue {
                            field: format!("realms.{name}.auth.token.refresh_token_ttl"),
                            reason: "refresh token TTL must not exceed 30 days (HEA-SEC-27)"
                                .to_string(),
                        });
                    }
                    Ok(micros) if micros > REFRESH_TOKEN_TTL_WARN_MICROS => {
                        tracing::warn!(
                            field = format!("realms.{name}.auth.token.refresh_token_ttl"),
                            "refresh token TTL exceeds 24 hours (HEA-SEC-27)"
                        );
                    }
                    Ok(_) => {}
                }
            }
            if let Some(ttl) = &token.password_reset_token_ttl {
                match parse_duration_to_micros(ttl) {
                    Err(_) => issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.password_reset_token_ttl"),
                        reason: "invalid duration format".to_string(),
                    }),
                    Ok(v) if v <= 0 => issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.password_reset_token_ttl"),
                        reason: "must be > 0".to_string(),
                    }),
                    Ok(_) => {}
                }
            }
        }
        if let Some(rl) = &auth.rate_limit {
            if let Some(dur) = &rl.lockout_duration {
                if parse_duration_to_micros(dur).is_err() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.rate_limit.lockout_duration"),
                        reason: "invalid duration format".to_string(),
                    });
                }
            }
        }
        if let Some(reg) = &auth.registration {
            if matches!(
                reg.mode,
                super::types::RegistrationModeYaml::DomainRestricted
            ) {
                let missing = reg
                    .allowed_domains
                    .as_ref()
                    .map_or(true, std::vec::Vec::is_empty);
                if missing {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.registration.allowed_domains"),
                        reason:
                            "mode = domain_restricted requires a non-empty allowed_domains list"
                                .to_string(),
                    });
                }
            }
        }
    }
}

/// Validates an application's `id_token_signed_response_alg` (task 26.55).
///
/// The engine refuses anything but RS256/EdDSA at reconcile time; `hearth config validate` must say so first, not
/// after a boot that already failed.
fn validate_app_id_token_alg(
    prefix: &str,
    app: &super::types::ApplicationYamlConfig,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(alg) = &app.id_token_signed_response_alg else {
        return;
    };
    let reason = match crate::identity::IdTokenSigningAlg::parse(alg) {
        Err(_) => {
            "must be \"RS256\" or \"EdDSA\" (case-sensitive); \"none\" and symmetric HS* \
             algorithms are never supported"
        }
        Ok(_) => return,
    };
    issues.push(ValidationIssue {
        field: format!("{prefix}.id_token_signed_response_alg"),
        reason: reason.to_string(),
    });
}

/// Validates an application's inline `jwks`: the engine refuses an invalid
/// set at reconcile, so `hearth config validate` must say so first.
fn validate_app_jwks(
    prefix: &str,
    app: &super::types::ApplicationYamlConfig,
    issues: &mut Vec<ValidationIssue>,
) {
    if let Some(jwks) = app.jwks_json() {
        if let Err(reason) = crate::identity::validate_client_jwks(&jwks) {
            issues.push(ValidationIssue {
                field: format!("{prefix}.jwks"),
                reason,
            });
        }
    }
}

fn validate_realm_applications_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (realm_name, cfg) in realms {
        // `oauth_clients` is the documented alias for `applications`. This
        // all-collecting validator only ever looked at `applications`, so
        // `hearth config validate` and the admin config editor reported a clean
        // bill of health for a client declaring the ROPC `password` grant under
        // `oauth_clients` — which `serve` refuses (audit §4.13#8).
        let Some(apps) = cfg.oauth_clients.as_ref().or(cfg.applications.as_ref()) else {
            continue;
        };
        for (app_key, app) in apps {
            let prefix = format!("realms.{realm_name}.applications.{app_key}");
            if app.name.trim().is_empty() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.name"),
                    reason: "must not be empty".to_string(),
                });
            }
            if let Some(grant_types) = &app.grant_types {
                for gt in grant_types {
                    if !VALID_GRANT_TYPES.contains(&gt.as_str()) {
                        issues.push(ValidationIssue {
                            field: format!("{prefix}.grant_types"),
                            reason: format!(
                                "unknown grant type '{}'; valid types are: {}",
                                gt,
                                VALID_GRANT_TYPES.join(", ")
                            ),
                        });
                    }
                }
            }
            validate_app_id_token_alg(&prefix, app, issues);
            validate_app_jwks(&prefix, app, issues);
            // A confidential client whose `client_secret` is present but empty
            // authenticates with `Authorization: Basic base64("<client_id>:")`,
            // which any caller who knows the client id can send. The `is_none()`
            // check upstream is satisfied by `Some("")`, so the empty string
            // slipped through as a credential (audit 2026-08-28 §4.13#4). An
            // unset `${VAR}` reaches this same state, and is refused earlier by
            // the substitution guard; this arm closes the literal case.
            if app.confidential == Some(true) {
                if let Some(secret) = &app.client_secret {
                    if secret.trim().is_empty() {
                        issues.push(ValidationIssue {
                            field: format!("{prefix}.client_secret"),
                            reason: "must not be empty on a confidential client. An empty \
                                     secret is accepted by `client_secret_basic` as \
                                     `Basic base64(\"<client_id>:\")`, so anyone who knows \
                                     the client id can authenticate as it. Set a real \
                                     secret, or set `confidential: false`."
                                .to_string(),
                        });
                    }
                }
            }
            // A redirect URI is only meaningful for a browser-redirect grant.
            // A `client_credentials`-only (machine-to-machine) client has
            // nowhere to redirect to, and the short-circuiting validator the
            // server ran never demanded one — only this all-collecting twin
            // did, so `hearth config validate` and the admin config editor
            // refused a config `serve` accepts (audit §4.13#8, the same
            // divergence in the other direction).
            let needs_redirect_uri = app.grant_types.as_ref().is_none_or(|gts| {
                gts.iter()
                    .any(|gt| gt == "authorization_code" || gt == "implicit")
            });
            match &app.redirect_uris {
                None if needs_redirect_uri => {
                    issues.push(ValidationIssue {
                        field: format!("{prefix}.redirect_uris"),
                        reason: "at least one redirect URI is required for a client that uses \
                                 the authorization_code grant"
                            .to_string(),
                    });
                }
                Some(uris) if uris.is_empty() && needs_redirect_uri => {
                    issues.push(ValidationIssue {
                        field: format!("{prefix}.redirect_uris"),
                        reason: "at least one redirect URI is required for a client that uses \
                                 the authorization_code grant"
                            .to_string(),
                    });
                }
                None => {}
                Some(uris) => {
                    for uri in uris {
                        if uri.is_empty() {
                            issues.push(ValidationIssue {
                                field: format!("{prefix}.redirect_uris"),
                                reason: "redirect URIs must not be empty strings".to_string(),
                            });
                        }
                    }
                }
            }
            let is_confidential = app.confidential.unwrap_or(false);
            if is_confidential && app.client_secret.is_none() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.client_secret"),
                    reason: "client_secret is required when confidential is true".to_string(),
                });
            }
            if !is_confidential && app.client_secret.is_some() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.confidential"),
                    reason: "confidential must be true when client_secret is provided".to_string(),
                });
            }
        }
    }
}

fn validate_realm_organizations_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (realm_name, cfg) in realms {
        let Some(orgs) = &cfg.organizations else {
            continue;
        };
        for (slug, org) in orgs {
            let prefix = format!("realms.{realm_name}.organizations.{slug}");
            if org.name.trim().is_empty() {
                issues.push(ValidationIssue {
                    field: format!("{prefix}.name"),
                    reason: "must not be empty".to_string(),
                });
            }
            if slug.len() < 3 || slug.len() > 63 {
                issues.push(ValidationIssue {
                    field: prefix.clone(),
                    reason: format!("slug '{slug}' must be 3-63 characters"),
                });
            }
            if !slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                issues.push(ValidationIssue {
                    field: prefix.clone(),
                    reason: format!(
                        "slug '{slug}' must contain only lowercase letters, digits, and hyphens"
                    ),
                });
            }
            if slug.starts_with('-') || slug.ends_with('-') {
                issues.push(ValidationIssue {
                    field: prefix,
                    reason: format!("slug '{slug}' must not start or end with a hyphen"),
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    /// Test-only shims for the short-circuiting validators that were removed
    /// when `Config::validate` became a thin wrapper over `validate_all`
    /// (audit §4.13#8). The rules now live only in the `_all` variants; these
    /// keep the existing unit tests exercising them through the same
    /// `Result`-shaped surface they were written against.
    fn validate_oidc(oidc: &OidcYamlConfig, dev_mode: bool) -> Result<(), ConfigError> {
        let mut issues = Vec::new();
        super::validate_oidc_all(oidc, dev_mode, &mut issues);
        first_error(issues)
    }

    fn validate_token(token: &TokenYamlConfig) -> Result<(), ConfigError> {
        let mut issues = Vec::new();
        super::validate_token_all(token, &mut issues);
        first_error(issues)
    }

    fn validate_realm_auth_configs(
        realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    ) -> Result<(), ConfigError> {
        let mut issues = Vec::new();
        super::validate_realm_auth_configs_all(realms, &mut issues);
        first_error(issues)
    }

    fn first_error(issues: Vec<ValidationIssue>) -> Result<(), ConfigError> {
        match issues.into_iter().next() {
            Some(i) => Err(ConfigError::ValidationError {
                field: i.field,
                reason: i.reason,
            }),
            None => Ok(()),
        }
    }
    use super::*;
    use crate::config::types::{PasswordSecurityYaml, PepperYaml, RealmAuthYaml, RealmYamlConfig};

    fn realm_with_mfa(methods: &[&str]) -> RealmYamlConfig {
        RealmYamlConfig {
            auth: Some(RealmAuthYaml {
                mfa_methods: Some(methods.iter().map(|s| (*s).to_string()).collect()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn dev_mode_true_in_config_file_is_refused() {
        // HEA control-liveness 10.2: a release binary loading a config file
        // (Config::from_file -> from_yaml_str, no --dev flag) that declares
        // dev_mode: true must refuse to start. The one existing hard guard
        // (dev_mode + non-loopback bind = refused) does not cover the common
        // reverse-proxy deployment, where the server legitimately binds
        // 127.0.0.1 but is still internet-reachable through the proxy.
        let yaml = "dev_mode: true\nstorage:\n  data_dir: \"/tmp/hea-10-2\"\n";
        let err = Config::from_yaml_str(yaml)
            .expect_err("dev_mode: true in a config file must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("dev_mode"),
            "error must name the key; got: {msg}"
        );
    }

    // ===== 19.11: the OWASP Argon2id floor on the YAML door =====

    /// Minimum production preamble: KEK + TLS + a non-log transport, so the
    /// only issue a test config can trip is the one it is testing.
    fn prod_preamble() -> String {
        "security:\n  key_encryption_key: \"".to_string()
            + &"ab".repeat(32)
            + "\"\nserver:\n  trust_forwarded_proto: true\n  trusted_proxies: [\"10.0.0.1\"]\n\
               storage:\n  data_dir: \"/tmp/hea-19-11\"\n"
    }

    fn argon2_issues(yaml: &str) -> Vec<ValidationIssue> {
        let config = Config::from_yaml_str_unchecked(yaml).expect("parses");
        config
            .validate_all()
            .into_iter()
            .filter(|i| i.reason.contains("OWASP"))
            .collect()
    }

    #[test]
    fn yaml_argon2_cost_below_the_owasp_floor_is_refused() {
        let yaml =
            prod_preamble() + "auth:\n  password_memory_cost: 1024\n  password_time_cost: 1\n";
        let issues = argon2_issues(&yaml);
        assert_eq!(
            issues.len(),
            1,
            "expected exactly one OWASP issue, got: {issues:?}"
        );
        assert_eq!(issues[0].field, "auth.password_memory_cost");
    }

    #[test]
    fn yaml_per_realm_argon2_override_below_the_floor_is_refused() {
        // The global block is compliant; only the realm drops below. A check
        // that read the global block alone would pass this config.
        let yaml = prod_preamble()
            + "auth:\n  password_memory_cost: 19456\n  password_time_cost: 2\n\
               realms:\n  acme:\n    password_memory_cost: 512\n";
        let issues = argon2_issues(&yaml);
        assert_eq!(issues.len(), 1, "expected one OWASP issue, got: {issues:?}");
        assert_eq!(issues[0].field, "realms.acme.password_memory_cost");
    }

    #[test]
    fn yaml_argon2_cost_at_the_owasp_floor_is_accepted() {
        for pair in [
            "  password_memory_cost: 19456\n  password_time_cost: 2\n",
            "  password_memory_cost: 47104\n  password_time_cost: 1\n",
            "  password_memory_cost: 65536\n  password_time_cost: 3\n",
        ] {
            let yaml = prod_preamble() + "auth:\n" + pair;
            let issues = argon2_issues(&yaml);
            assert!(issues.is_empty(), "{pair} must be accepted, got {issues:?}");
        }
    }

    #[test]
    fn yaml_with_no_argon2_override_is_accepted() {
        let issues = argon2_issues(&prod_preamble());
        assert!(
            issues.is_empty(),
            "the compiled-in default is already OWASP-compliant; got {issues:?}"
        );
    }

    #[test]
    fn dev_mode_does_not_enforce_the_argon2_floor() {
        let yaml = "dev_mode: true\nauth:\n  password_memory_cost: 256\n  password_time_cost: 1\n";
        let issues = argon2_issues(yaml);
        assert!(
            issues.is_empty(),
            "dev mode runs fast_for_testing parameters on purpose; got {issues:?}"
        );
    }

    // ===== 26.24 / G3: validation accepts exactly what the runtime uses =====

    /// `trusted_proxies` issues for a production config with `entries`.
    fn trusted_proxy_issues(entries: &[&str]) -> Vec<ValidationIssue> {
        let list = entries
            .iter()
            .map(|e| format!("\"{e}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let yaml = "security:\n  key_encryption_key: \"".to_string()
            + &"ab".repeat(32)
            + "\"\nserver:\n  bind_address: \"0.0.0.0\"\n  trust_forwarded_proto: true\n  \
               trusted_proxies: ["
            + &list
            + "]\nstorage:\n  data_dir: \"/tmp/hea-g3\"\n";
        let config = Config::from_yaml_str_unchecked(&yaml).expect("parses");
        config
            .validate_all()
            .into_iter()
            .filter(|i| i.field.starts_with("server.trusted_proxies"))
            .collect()
    }

    /// A CIDR entry is accepted — and the runtime now uses it.
    ///
    /// 26.24 refused CIDR because `main.rs` parsed each entry as a bare
    /// `IpAddr` and silently discarded the rest. Both sides now go through
    /// `core::TrustedProxy`, so a range that validates is a range the XFF walk,
    /// the X-Forwarded-Proto check and the connection-cap exemption match.
    #[test]
    fn cidr_trusted_proxies_are_accepted() {
        let issues = trusted_proxy_issues(&["10.42.0.0/16", "2001:db8:42::/48", "10.0.0.7"]);
        assert!(issues.is_empty(), "valid ranges and addresses: {issues:?}");
    }

    #[test]
    fn a_malformed_trusted_proxy_is_refused() {
        for bad in [
            "proxy.internal",
            "10.0.0.0/",
            "10.0.0.0/+8",
            "10.0.0.0/33",
            "10.0.0.7:443",
        ] {
            let issues = trusted_proxy_issues(&[bad]);
            assert_eq!(issues.len(), 1, "'{bad}' must be refused: {issues:?}");
            assert_eq!(issues[0].field, "server.trusted_proxies[0]");
            assert!(
                issues[0].reason.contains(bad),
                "reason names the entry: {issues:?}"
            );
        }
    }

    /// Host bits set: refused, not normalized — `10.0.0.7/8` might mean the
    /// address or the /8, and those differ by sixteen million hosts.
    #[test]
    fn a_trusted_proxy_cidr_with_host_bits_is_refused_and_the_network_named() {
        let issues = trusted_proxy_issues(&["10.0.0.1", "10.42.1.7/16"]);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert_eq!(issues[0].field, "server.trusted_proxies[1]");
        assert!(
            issues[0].reason.contains("10.42.0.0/16"),
            "the refusal must name the network form; got: {}",
            issues[0].reason
        );
    }

    #[test]
    fn catch_all_and_overly_broad_trusted_proxies_are_refused() {
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "0.0.0.0",
            "::",
            "0.0.0.0/8",
            "8.0.0.0/7",
            "2000::/3",
        ] {
            let issues = trusted_proxy_issues(&[bad]);
            assert_eq!(issues.len(), 1, "'{bad}' must be refused: {issues:?}");
        }
    }

    /// The `cluster.peer_address` issues of a config whose cluster section
    /// names `addr`.
    fn peer_address_issues(addr: &str) -> Vec<ValidationIssue> {
        let yaml = format!(
            "cluster:\n  node_id: 1\n  peer_address: \"{addr}\"\n  peers:\n    \
             - id: 2\n      address: \"hearth-2.internal:8421\"\n  \
             tls_cert_path: \"/etc/hearth/peer.crt\"\n  \
             tls_key_path: \"/etc/hearth/peer.key\"\n  \
             tls_ca_cert_path: \"/etc/hearth/ca.crt\"\n"
        );
        let config = Config::from_yaml_str_unchecked(&yaml).expect("parses");
        config
            .validate_all()
            .into_iter()
            .filter(|i| i.field.starts_with("cluster."))
            .collect()
    }

    /// The peer server binds `cluster.peer_address`, so it must be an IP
    /// address and a port. A host name used to pass validation; the peer
    /// server then stopped at start-up while the node kept serving, so no
    /// cluster formed and nothing said so. A peer's `address` is dialled,
    /// not bound, so a host name stays valid there.
    #[test]
    fn a_peer_address_that_cannot_be_bound_is_refused() {
        for good in [
            "10.0.0.1:8421",
            "0.0.0.0:8421",
            "[::1]:8421",
            "[fd00::7]:7443",
        ] {
            let issues = peer_address_issues(good);
            assert!(issues.is_empty(), "'{good}' is bindable: {issues:?}");
        }
        for bad in [
            "n1:7443",
            "hearth-1.internal:8421",
            "10.0.0.1",
            "::1:8421",
            "",
        ] {
            let issues = peer_address_issues(bad);
            assert_eq!(issues.len(), 1, "'{bad}' must be refused: {issues:?}");
            assert_eq!(issues[0].field, "cluster.peer_address");
            assert!(
                issues[0].reason.contains(&format!("'{bad}'")),
                "the reason names the value: {issues:?}"
            );
        }
    }

    /// The loopback-on-a-public-listener check covers a loopback range too.
    #[test]
    fn a_loopback_cidr_is_refused_on_a_public_listener() {
        let issues = trusted_proxy_issues(&["127.0.0.0/8"]);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert!(issues[0].reason.contains("loopback"), "{issues:?}");
    }

    /// Validation and runtime share one parser: every entry `validate_all`
    /// accepts, `TrustedProxies::parse` accepts, and vice versa.
    #[test]
    fn validation_agrees_with_the_runtime_parser() {
        for entry in [
            "10.0.0.7",
            "10.42.0.0/16",
            "2001:db8::/32",
            "::ffff:10.0.0.7",
            "10.0.0.7/8",
            "0.0.0.0/0",
            "10.0.0.0/08",
            "junk",
            " 10.0.0.7",
        ] {
            let validated = trusted_proxy_issues(&[entry]).is_empty();
            let parsed = crate::core::TrustedProxies::parse([entry]).is_ok();
            assert_eq!(
                validated, parsed,
                "'{entry}': validate={validated} runtime={parsed}"
            );
        }
    }

    // ===== G3 follow-up: realms.<name>.security.cidr_policy =====
    //
    // There was no validator for these lists at all. `abuse::runtime`'s
    // `compile_filter` silently dropped any entry the old `Cidr::parse`
    // refused — its comment claimed "the start-up validator already refused
    // them", but none did. A typo in the only `allow` entry therefore emptied
    // the allow list, which lifts the realm's network restriction entirely.

    /// `cidr_policy` issues for realm `acme` with the given lists.
    fn cidr_policy_issues(allow: &[&str], deny: &[&str]) -> Vec<ValidationIssue> {
        let list = |v: &[&str]| {
            v.iter()
                .map(|e| format!("\"{e}\""))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let yaml = format!(
            "realms:\n  acme:\n    security:\n      cidr_policy:\n        allow: [{}]\n        \
             deny: [{}]\n",
            list(allow),
            list(deny)
        );
        Config::from_yaml_str_unchecked(&yaml)
            .expect("parses")
            .validate_all()
            .into_iter()
            .filter(|i| i.field.contains("cidr_policy"))
            .collect()
    }

    #[test]
    fn cidr_policy_entries_the_runtime_refuses_are_refused_naming_realm_and_entry() {
        let issues = cidr_policy_issues(
            &["10.0.0.0/8", "10.1.2.255/24"],
            &["198.51.100.0/+24", "fe80::1%eth0"],
        );
        let fields: Vec<&str> = issues.iter().map(|i| i.field.as_str()).collect();
        assert_eq!(
            fields,
            [
                "realms.acme.security.cidr_policy.allow[1]",
                "realms.acme.security.cidr_policy.deny[0]",
                "realms.acme.security.cidr_policy.deny[1]",
            ],
            "{issues:?}"
        );
        assert!(issues[0].reason.contains("'10.1.2.255/24'"), "{issues:?}");
        assert!(
            issues[0].reason.contains("10.1.2.0/24"),
            "host bits: the refusal names the network form; got {}",
            issues[0].reason
        );
        assert!(
            issues[1].reason.contains("'198.51.100.0/+24'"),
            "{issues:?}"
        );
    }

    /// Unlike `trusted_proxies`, a policy list may be as broad as the operator
    /// likes: `deny: [0.0.0.0/0]` blocks all IPv4, `allow: [::/0]` admits all
    /// IPv6. Bare addresses are single hosts.
    #[test]
    fn cidr_policy_accepts_broad_ranges_and_bare_addresses() {
        let issues = cidr_policy_issues(
            &["10.0.0.0/8", "2001:db8::/32", "192.0.2.7", "::/0"],
            &["0.0.0.0/0", "198.51.100.0/24"],
        );
        assert!(issues.is_empty(), "{issues:?}");
    }

    /// Validation and runtime share one parser.
    #[test]
    fn cidr_policy_validation_agrees_with_the_runtime_parser() {
        for entry in [
            "10.0.0.0/8",
            "192.0.2.7",
            "0.0.0.0/0",
            "::/0",
            "::ffff:192.0.2.0/120",
            "10.1.2.255/24",
            "10.0.0.0/+8",
            "10.0.0.0/08",
            "[2001:db8::]/32",
            "10.0.0.0:443/8",
            "fe80::1%eth0",
            "junk",
        ] {
            let validated = cidr_policy_issues(&[entry], &[]).is_empty();
            let parsed = crate::abuse::cidr::parse_entry(entry).is_ok();
            assert_eq!(
                validated, parsed,
                "'{entry}': validate={validated} runtime={parsed}"
            );
        }
    }

    /// Control — a bare IP is still accepted.
    ///
    /// Without this, a check that refused every entry would pass the test
    /// above while making `trusted_proxies` unusable.
    #[test]
    fn a_plain_ip_trusted_proxy_is_still_accepted() {
        let yaml = "security:\n  key_encryption_key: \"".to_string()
            + &"ab".repeat(32)
            + "\"\nserver:\n  trusted_proxies: [\"10.0.0.1\", \"2001:db8::1\"]\n\
               storage:\n  data_dir: \"/tmp/hea-26-24b\"\n";
        let config = Config::from_yaml_str_unchecked(&yaml).expect("parses");
        let issues = config.validate_all();
        assert!(
            !issues
                .iter()
                .any(|i| i.field.starts_with("server.trusted_proxies")),
            "a list of plain IPv4 and IPv6 addresses must be accepted: {issues:?}"
        );
    }

    // ===== 19.12: plaintext production must not be forced into a spoofable
    // `trust_forwarded_proto` with an empty `trusted_proxies` =====

    #[test]
    fn trust_forwarded_proto_without_trusted_proxies_is_refused_in_production() {
        let yaml = "security:\n  key_encryption_key: \"".to_string()
            + &"ab".repeat(32)
            + "\"\nserver:\n  trust_forwarded_proto: true\n\
               storage:\n  data_dir: \"/tmp/hea-19-12\"\n";
        let config = Config::from_yaml_str_unchecked(&yaml).expect("parses");
        let issues = config.validate_all();
        let hit = issues
            .iter()
            .find(|i| i.field == "server.trust_forwarded_proto")
            .unwrap_or_else(|| {
                panic!("trust_forwarded_proto with no trusted_proxies must be refused: {issues:?}")
            });
        assert!(
            hit.reason.contains("trusted_proxies"),
            "the refusal must name the key that fixes it; got: {}",
            hit.reason
        );
        // And the fail-fast path must agree with the collecting path.
        assert!(config.validate().is_err(), "validate() must refuse it too");
    }

    #[test]
    fn trust_forwarded_proto_with_trusted_proxies_is_accepted() {
        let yaml = "security:\n  key_encryption_key: \"".to_string()
            + &"ab".repeat(32)
            + "\"\nserver:\n  trust_forwarded_proto: true\n  trusted_proxies: [\"10.0.0.1\"]\n\
               storage:\n  data_dir: \"/tmp/hea-19-12b\"\n";
        let config = Config::from_yaml_str_unchecked(&yaml).expect("parses");
        let issues = config.validate_all();
        assert!(
            !issues
                .iter()
                .any(|i| i.field == "server.trust_forwarded_proto"),
            "a proxy list makes the header trustworthy; got {issues:?}"
        );
    }

    #[test]
    fn empty_trusted_proxies_warning_is_deferred_not_logged_during_validation() {
        // The warning used to be a `tracing::warn!` fired from inside
        // `validate_trusted_proxies`, which runs while `load_config` parses the
        // file — before `telemetry::init` installs a subscriber, so it went
        // nowhere. It is now returned as data for `run_serve` to log after the
        // subscriber exists.
        let server = ServerConfig {
            bind_address: "0.0.0.0".to_string(),
            trusted_proxies: Vec::new(),
            ..ServerConfig::default()
        };
        let warnings = super::deferred_server_warnings(&server);
        assert_eq!(warnings.len(), 1, "got: {warnings:?}");
        assert!(
            warnings[0].contains("trusted_proxies"),
            "got: {}",
            warnings[0]
        );

        let loopback = ServerConfig {
            bind_address: "127.0.0.1".to_string(),
            trusted_proxies: Vec::new(),
            ..ServerConfig::default()
        };
        assert_eq!(
            super::deferred_server_warnings(&loopback),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn yaml_declares_dev_mode_true_only_on_explicit_true() {
        // dev_mode: false matches the default and must not trip the refusal
        // in from_yaml_str; neither must an absent dev_mode key.
        assert!(super::yaml_declares_dev_mode("dev_mode: true\n"));
        assert!(!super::yaml_declares_dev_mode("dev_mode: false\n"));
        assert!(!super::yaml_declares_dev_mode(
            "storage:\n  data_dir: \"/tmp/x\"\n"
        ));
    }

    #[test]
    fn omitted_security_block_keeps_documented_defaults() {
        // HEA control-liveness: `SecurityYaml` derived `Default`, which zeroes
        // every field instead of running each field's `#[serde(default = "fn")]`.
        // That default is only invoked by serde when the `security:` key itself
        // is present. A config file with NO `security:` block at all — the
        // common case — silently set `jwks_rps_limit` to 0, so every JWKS and
        // discovery request answered 429 from the first request with nothing in
        // the boot log. `reserved_slugs` and `slug_cooldown_days` degraded the
        // same way.
        let config = Config::from_yaml_str_unchecked(
            "storage:\n  data_dir: \"/tmp/hea-omitted-security\"\n",
        )
        .expect("config with no security: block parses");
        assert_eq!(
            config.security.jwks_rps_limit, 60,
            "JWKS/discovery rate limit must default to 60 rps, not 0, \
             when security: is absent"
        );
        assert!(
            config.security.reserved_slugs.iter().any(|s| s == "admin"),
            "reserved_slugs must keep its documented default list"
        );
        assert_eq!(
            config.security.slug_cooldown_days, 30,
            "slug_cooldown_days must default to 30"
        );
    }

    #[test]
    fn from_file_as_dev_preserves_configured_data_dir() {
        // HEA-1805 regression: `--dev` (from_file_as_dev) previously blanked
        // storage.data_dir to String::new(), so a configured cold-tier data
        // directory was silently ignored. It must now survive the dev-mode
        // transform so main.rs can persist WAL/SSTs to the real directory.
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().expect("temp config file");
        write!(
            f,
            "storage:\n  data_dir: \"/tmp/hea1805-regression\"\n  hot_tier_capacity: 100000\n"
        )
        .expect("write config");
        let config = Config::from_file_as_dev(f.path()).expect("dev config loads");
        assert!(config.dev_mode);
        assert!(
            !config.storage.fsync_enabled(true),
            "dev mode defaults fsync off"
        );
        assert_eq!(
            config.storage.data_dir, "/tmp/hea1805-regression",
            "configured data_dir must be preserved in dev mode"
        );
    }

    #[test]
    fn totp_and_webauthn_are_accepted() {
        let mut realms = std::collections::HashMap::new();
        realms.insert("default".to_string(), realm_with_mfa(&["totp", "webauthn"]));
        let result = validate_realm_auth_configs(Some(&realms));
        assert!(result.is_ok(), "expected Ok but got: {result:?}");
    }

    #[test]
    fn unknown_mfa_method_is_rejected() {
        let mut realms = std::collections::HashMap::new();
        realms.insert(
            "default".to_string(),
            realm_with_mfa(&["totp", "carrier_pigeon"]),
        );
        let result = validate_realm_auth_configs(Some(&realms));
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError but got: {result:?}");
        };
        assert_eq!(field, "realms.default.auth.mfa_methods");
        assert!(reason.contains("carrier_pigeon"), "{reason}");
    }

    // ===== fix/ga-sms: one shared MFA-methods rule for YAML and runtime =====

    fn methods(ms: &[&str]) -> Vec<String> {
        ms.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn shared_mfa_rule_refuses_unknown_methods() {
        let err = check_mfa_methods(&methods(&["carrier_pigeon"])).expect_err("unknown method");
        assert!(err.contains("carrier_pigeon"), "{err}");
    }

    #[test]
    fn shared_mfa_rule_refuses_sms() {
        let err = check_mfa_methods(&methods(&["totp", "sms"])).expect_err("sms was removed");
        assert!(err.contains("unknown MFA method 'sms'"), "{err}");
    }

    #[test]
    fn shared_mfa_rule_accepts_the_kept_methods() {
        assert_eq!(
            check_mfa_methods(&methods(&["totp", "webauthn", "email_otp"])),
            Ok(())
        );
    }

    #[test]
    fn global_auth_mfa_methods_with_an_unknown_method_is_refused() {
        let yaml = "security:\n  key_encryption_key: \"".to_string()
            + &"ab".repeat(32)
            + "\"\nauth:\n  mfa_methods: [\"carrier_pigeon\"]\n\
               storage:\n  data_dir: \"/tmp/ga-sms-global2\"\n";
        let config = Config::from_yaml_str_unchecked(&yaml).expect("parses");
        let issues = config.validate_all();
        assert!(
            issues
                .iter()
                .any(|i| i.field == "auth.mfa_methods" && i.reason.contains("carrier_pigeon")),
            "an unknown global MFA method must be refused: {issues:?}"
        );
    }

    /// openspec/specs/mcp-authorization/spec.md: a protected resource's URI MUST be HTTPS in
    /// production; `--dev` MAY permit HTTP. The spec carves out dev mode
    /// only — a loopback `http://` resource is refused in production too.
    #[test]
    fn protected_resource_uri_must_be_https_outside_dev_mode() {
        let yaml = "realms:\n  acme:\n    protected_resources:\n      \
                    - resource_uri: \"http://rs.example.com/api\"\n        display_name: RS\n      \
                    - resource_uri: \"https://ok.example.com\"\n        display_name: OK\n      \
                    - resource_uri: \"http://127.0.0.1:9000/mcp\"\n        display_name: Local\n      \
                    - resource_uri: \"HTTP://upper.example.com\"\n        display_name: Upper\n";
        let mut cfg = Config::from_yaml_str_unchecked(yaml).expect("parse");
        let fields = |cfg: &Config| -> Vec<String> {
            let mut f: Vec<String> = cfg
                .validate_all()
                .into_iter()
                .map(|i| i.field)
                .filter(|f| f.contains("protected_resources"))
                .collect();
            f.sort();
            f
        };
        cfg.dev_mode = false;
        assert_eq!(
            fields(&cfg),
            vec![
                "realms.acme.protected_resources[0].resource_uri".to_string(),
                "realms.acme.protected_resources[2].resource_uri".to_string(),
                "realms.acme.protected_resources[3].resource_uri".to_string(),
            ]
        );
        cfg.dev_mode = true;
        assert_eq!(fields(&cfg), Vec::<String>::new());
    }

    // ===== HEA-SEC-27: TTL cap enforcement =====

    use crate::config::types::TokenYamlConfig;

    /// SEC-27: Access token TTL > 1 hour is rejected at global scope.
    #[test]
    fn sec27_access_token_ttl_over_1h_is_rejected() {
        let token = TokenYamlConfig {
            access_token_ttl: Some("2h".to_string()),
            ..Default::default()
        };
        let result = validate_token(&token);
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError; got: {result:?}");
        };
        assert_eq!(field, "token.access_token_ttl");
        assert!(
            reason.contains("1 hour"),
            "reason should mention 1 hour: {reason}"
        );
    }

    /// SEC-27: Refresh token TTL > 30 days is rejected at global scope.
    #[test]
    fn sec27_refresh_token_ttl_over_30d_is_rejected() {
        let token = TokenYamlConfig {
            refresh_token_ttl: Some("31d".to_string()),
            ..Default::default()
        };
        let result = validate_token(&token);
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError; got: {result:?}");
        };
        assert_eq!(field, "token.refresh_token_ttl");
        assert!(
            reason.contains("30 days"),
            "reason should mention 30 days: {reason}"
        );
    }

    /// SEC-27: Access token TTL at exactly 1 hour is accepted.
    #[test]
    fn sec27_access_token_ttl_at_cap_is_accepted() {
        let token = TokenYamlConfig {
            access_token_ttl: Some("1h".to_string()),
            ..Default::default()
        };
        assert!(
            validate_token(&token).is_ok(),
            "TTL exactly at cap must be accepted"
        );
    }

    /// SEC-27: Refresh token TTL at exactly 30 days is accepted.
    #[test]
    fn sec27_refresh_token_ttl_at_cap_is_accepted() {
        let token = TokenYamlConfig {
            refresh_token_ttl: Some("30d".to_string()),
            ..Default::default()
        };
        assert!(
            validate_token(&token).is_ok(),
            "TTL exactly at cap must be accepted"
        );
    }

    // ===== §4.15#2: signing-key rotation grace period validation =====

    /// A negative grace period must fail boot, not wrap to an infinite window.
    #[test]
    fn grace_period_negative_is_rejected() {
        let token = TokenYamlConfig {
            signing_key_rotation_grace_period: Some("-1h".to_string()),
            ..Default::default()
        };
        let result = validate_token(&token);
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError; got: {result:?}");
        };
        assert_eq!(field, "token.signing_key_rotation_grace_period");
        assert!(
            reason.contains("negative"),
            "reason should mention negative: {reason}"
        );
    }

    /// A malformed grace period must fail boot rather than fall back to 24h.
    #[test]
    fn grace_period_unparseable_is_rejected() {
        let token = TokenYamlConfig {
            signing_key_rotation_grace_period: Some("not-a-duration".to_string()),
            ..Default::default()
        };
        let result = validate_token(&token);
        let Err(ConfigError::ValidationError { field, .. }) = result else {
            panic!("expected ValidationError; got: {result:?}");
        };
        assert_eq!(field, "token.signing_key_rotation_grace_period");
    }

    /// A grace period beyond 30 days is rejected.
    #[test]
    fn grace_period_over_30d_is_rejected() {
        let token = TokenYamlConfig {
            signing_key_rotation_grace_period: Some("31d".to_string()),
            ..Default::default()
        };
        let result = validate_token(&token);
        let Err(ConfigError::ValidationError { field, .. }) = result else {
            panic!("expected ValidationError; got: {result:?}");
        };
        assert_eq!(field, "token.signing_key_rotation_grace_period");
    }

    /// A sane grace period is accepted.
    #[test]
    fn grace_period_valid_is_accepted() {
        let token = TokenYamlConfig {
            signing_key_rotation_grace_period: Some("24h".to_string()),
            ..Default::default()
        };
        assert!(
            validate_token(&token).is_ok(),
            "a 24h grace period must be accepted"
        );
    }

    /// SEC-27: Per-realm access token TTL > 1 hour is rejected.
    #[test]
    fn sec27_per_realm_access_token_ttl_over_1h_is_rejected() {
        let mut realms = std::collections::HashMap::new();
        realms.insert(
            "default".to_string(),
            RealmYamlConfig {
                auth: Some(RealmAuthYaml {
                    token: Some(crate::config::types::RealmTokenYaml {
                        access_token_ttl: Some("2h".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let result = validate_realm_auth_configs(Some(&realms));
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError; got: {result:?}");
        };
        assert!(
            field.contains("access_token_ttl"),
            "field should mention access_token_ttl: {field}"
        );
        assert!(
            reason.contains("1 hour"),
            "reason should mention 1 hour: {reason}"
        );
    }

    /// SEC-27: validate_all accumulates TTL cap violations as issues.
    #[test]
    fn sec27_validate_all_accumulates_ttl_cap_violations() {
        let token = TokenYamlConfig {
            access_token_ttl: Some("90m".to_string()),
            refresh_token_ttl: Some("45d".to_string()),
            ..Default::default()
        };
        let mut issues = Vec::new();
        validate_token_all(&token, &mut issues);
        assert!(
            issues.iter().any(|i| i.field == "token.access_token_ttl"),
            "expected access_token_ttl issue; got: {issues:?}"
        );
        assert!(
            issues.iter().any(|i| i.field == "token.refresh_token_ttl"),
            "expected refresh_token_ttl issue; got: {issues:?}"
        );
    }

    // ── HEA-SEC-29: removed opt-out fields must be rejected ─────────────────

    #[test]
    fn sec29_enforce_nonces_false_rejected() {
        use crate::config::types::OidcYamlConfig;
        let oidc = OidcYamlConfig {
            enforce_nonces: Some(false),
            ..Default::default()
        };
        let result = validate_oidc(&oidc, true);
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError, got: {result:?}");
        };
        assert_eq!(field, "oidc.enforce_nonces");
        assert!(
            reason.contains("HEA-SEC-29"),
            "error must reference HEA-SEC-29; got: {reason}"
        );
    }

    #[test]
    fn sec29_enforce_nonces_true_accepted() {
        use crate::config::types::OidcYamlConfig;
        let oidc = OidcYamlConfig {
            enforce_nonces: Some(true),
            ..Default::default()
        };
        assert!(validate_oidc(&oidc, true).is_ok());
    }

    #[test]
    fn sec29_require_pkce_false_rejected() {
        use crate::config::types::OidcYamlConfig;
        let oidc = OidcYamlConfig {
            require_pkce_for_confidential_clients: Some(false),
            ..Default::default()
        };
        let result = validate_oidc(&oidc, true);
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError, got: {result:?}");
        };
        assert_eq!(field, "oidc.require_pkce_for_confidential_clients");
        assert!(
            reason.contains("HEA-SEC-29"),
            "error must reference HEA-SEC-29; got: {reason}"
        );
    }

    #[test]
    fn sec29_validate_oidc_all_collects_opt_out_violations() {
        use crate::config::types::OidcYamlConfig;
        let oidc = OidcYamlConfig {
            enforce_nonces: Some(false),
            require_pkce_for_confidential_clients: Some(false),
            ..Default::default()
        };
        let mut issues = Vec::new();
        validate_oidc_all(&oidc, true, &mut issues);
        assert!(
            issues.iter().any(|i| i.field == "oidc.enforce_nonces"),
            "expected enforce_nonces issue; got: {issues:?}"
        );
        assert!(
            issues
                .iter()
                .any(|i| i.field == "oidc.require_pkce_for_confidential_clients"),
            "expected require_pkce_for_confidential_clients issue; got: {issues:?}"
        );
    }

    // ── security.password.pepper wiring (HEA-1838) ───────────────────────────

    /// A 64-char lowercase-hex, non-zero, 32-byte key.
    const PEPPER_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PEPPER_HEX_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn security_with_pepper(pepper: Option<PepperYaml>) -> SecurityYaml {
        SecurityYaml {
            password: PasswordSecurityYaml {
                pepper,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // ===== auth.password_memory_cost / auth.password_time_cost (§4.17#8) =====

    /// The documented global Argon2 knobs must reach the engine's *base*
    /// credential config, not just the per-realm override path.
    #[test]
    fn auth_password_costs_reach_the_base_credential_config() {
        let yaml = "\
storage:
  data_dir: \"/tmp/hea-20-12\"
auth:
  password_memory_cost: 131072
  password_time_cost: 4
";
        let config = Config::from_yaml_str_unchecked(yaml).expect("parse");
        let resolved = config.base_credential_config(None);
        assert_eq!(
            resolved.memory_cost_kib, 131_072,
            "auth.password_memory_cost must set the base Argon2 memory cost"
        );
        assert_eq!(
            resolved.time_cost, 4,
            "auth.password_time_cost must set the base Argon2 time cost"
        );
    }

    /// An absent `auth:` block must leave the compiled-in OWASP defaults alone.
    #[test]
    fn auth_password_costs_absent_keeps_engine_defaults() {
        let yaml = "storage:\n  data_dir: \"/tmp/hea-20-12b\"\n";
        let config = Config::from_yaml_str_unchecked(yaml).expect("parse");
        let resolved = config.base_credential_config(None);
        let default = crate::identity::CredentialConfig::default();
        assert_eq!(resolved.memory_cost_kib, default.memory_cost_kib);
        assert_eq!(resolved.time_cost, default.time_cost);
    }

    /// A time cost of zero is not a valid Argon2 parameter; `Params::new`
    /// refuses it at hash time, which would turn every login into a 500. It
    /// must be refused at start-up instead.
    #[test]
    fn auth_password_time_cost_zero_is_refused() {
        let yaml = "\
storage:
  data_dir: \"/tmp/hea-20-12c\"
auth:
  password_time_cost: 0
";
        let config = Config::from_yaml_str_unchecked(yaml).expect("parse");
        let issues = config.validate_all();
        assert!(
            issues.iter().any(|i| i.field == "auth.password_time_cost"
                && i.reason.contains("Argon2id rejects a zero iteration count")),
            "a zero Argon2 time cost must be refused by the algorithm-bounds check — the \
             OWASP floor is dev-mode-exempt, so this arm is the only one that covers it; \
             got: {issues:?}"
        );
    }

    /// Above the Argon2 ceilings a stored-hash verifier enforces (task 26.36:
    /// 1 GiB memory, 64 passes), `hash_raw_secret` would mint client secrets
    /// and recovery codes that `verify_raw_secret` always refuses — and user
    /// passwords a restore refuses to import. Refused at start-up, naming the
    /// ceiling, in every mode (dev included: it is not an OWASP-style floor).
    #[test]
    fn argon2_costs_above_the_verifier_ceilings_are_refused() {
        let cases = [
            (
                "auth:\n  password_time_cost: 65\n",
                "auth.password_time_cost",
                "64",
            ),
            (
                "auth:\n  password_memory_cost: 1048577\n",
                "auth.password_memory_cost",
                "1048576",
            ),
            (
                "realms:\n  acme:\n    password_time_cost: 100\n",
                "realms.acme.password_time_cost",
                "64",
            ),
            (
                "realms:\n  acme:\n    password_memory_cost: 2097152\n",
                "realms.acme.password_memory_cost",
                "1048576",
            ),
        ];
        for dev in [false, true] {
            for (block, field, ceiling) in cases {
                let yaml = format!(
                    "{}storage:\n  data_dir: \"/tmp/hea-argon2-ceiling\"\n{block}",
                    if dev { "dev_mode: true\n" } else { "" }
                );
                let config = Config::from_yaml_str_unchecked(&yaml).expect("parse");
                let issues = config.validate_all();
                assert!(
                    issues
                        .iter()
                        .any(|i| i.field == field && i.reason.contains(ceiling)),
                    "dev={dev}: {field} above the ceiling must be refused naming {ceiling}; \
                     got: {issues:?}"
                );
            }
        }
    }

    /// The ceilings themselves are accepted.
    #[test]
    fn argon2_costs_at_the_verifier_ceilings_are_accepted() {
        let yaml = "\
storage:
  data_dir: \"/tmp/hea-argon2-ceiling-ok\"
auth:
  password_memory_cost: 1048576
  password_time_cost: 64
realms:
  acme:
    password_memory_cost: 1048576
    password_time_cost: 64
";
        let config = Config::from_yaml_str_unchecked(yaml).expect("parse");
        let issues: Vec<_> = config
            .validate_all()
            .into_iter()
            .filter(|i| i.field.contains("password_"))
            .collect();
        assert!(
            issues.is_empty(),
            "the ceilings are inclusive; got {issues:?}"
        );
    }

    /// Argon2 requires `m_cost >= 8`; anything lower makes `Params::new` fail.
    #[test]
    fn auth_password_memory_cost_below_argon2_minimum_is_refused() {
        let yaml = "\
storage:
  data_dir: \"/tmp/hea-20-12d\"
auth:
  password_memory_cost: 4
";
        let config = Config::from_yaml_str_unchecked(yaml).expect("parse");
        let issues = config.validate_all();
        assert!(
            issues.iter().any(|i| i.field == "auth.password_memory_cost"
                && i.reason
                    .contains("Argon2id rejects anything outside that range")),
            "an Argon2 memory cost below the algorithm minimum must be refused by the \
             algorithm-bounds check, not only by the dev-mode-exempt OWASP floor; \
             got: {issues:?}"
        );
    }

    #[test]
    fn resolve_pepper_absent_is_none() {
        // Unchanged default behaviour: no pepper section → CredentialConfig::pepper None.
        let sec = SecurityYaml::default();
        assert!(sec.resolve_pepper().expect("valid").is_none());
    }

    #[test]
    fn resolve_pepper_active_only_wires_config() {
        let sec = security_with_pepper(Some(PepperYaml {
            version: 3,
            key_hex: PEPPER_HEX.to_string(),
            previous_version: None,
            previous_key_hex: None,
        }));
        let resolved = sec.resolve_pepper().expect("valid").expect("some");
        assert_eq!(resolved.active_version, 3);
        assert_eq!(resolved.active_key.as_bytes(), &[0x11u8; 32]);
        assert!(resolved.previous_version.is_none());
        assert!(resolved.previous_key.is_none());
    }

    #[test]
    fn resolve_pepper_rotation_pair_wires_both_keys() {
        let sec = security_with_pepper(Some(PepperYaml {
            version: 4,
            key_hex: PEPPER_HEX.to_string(),
            previous_version: Some(3),
            previous_key_hex: Some(PEPPER_HEX_2.to_string()),
        }));
        let resolved = sec.resolve_pepper().expect("valid").expect("some");
        assert_eq!(resolved.previous_version, Some(3));
        assert_eq!(
            resolved.previous_key.as_ref().expect("prev key").as_bytes(),
            &[0x22u8; 32]
        );
    }

    #[test]
    fn resolve_pepper_rejects_zero_key() {
        let sec = security_with_pepper(Some(PepperYaml {
            version: 1,
            key_hex: "0".repeat(64),
            previous_version: None,
            previous_key_hex: None,
        }));
        let err = sec.resolve_pepper().expect_err("zero key rejected");
        let msg = err.to_string();
        assert!(msg.contains("all-zero"), "unexpected error: {msg}");
    }

    #[test]
    fn kdf_admission_absent_resolves_to_core_count_default() {
        // Default (no `security.password.kdf`) → core-count bound + 250ms/1s.
        let sec = SecurityYaml::default();
        sec.validate_kdf_admission().expect("default is valid");
        let resolved = sec.resolve_kdf_gate();
        let expected_cores = std::thread::available_parallelism()
            .map(std::num::NonZeroUsize::get)
            .unwrap_or(1);
        assert_eq!(resolved.max_in_flight, expected_cores);
        assert_eq!(
            resolved.max_queue_wait,
            std::time::Duration::from_millis(250)
        );
        assert_eq!(resolved.retry_after, std::time::Duration::from_secs(1));
    }

    #[test]
    fn kdf_admission_rejects_zero_max_in_flight() {
        // An explicit bound of 0 would shed every login — must be a config error.
        let mut sec = SecurityYaml::default();
        sec.password.kdf.max_in_flight = Some(0);
        let err = sec
            .validate_kdf_admission()
            .expect_err("zero bound rejected");
        assert!(
            err.to_string().contains("must be >= 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn kdf_admission_explicit_values_resolve_through() {
        let mut sec = SecurityYaml::default();
        sec.password.kdf.max_in_flight = Some(8);
        sec.password.kdf.max_queue_wait_ms = 100;
        sec.password.kdf.retry_after_seconds = 2;
        sec.validate_kdf_admission().expect("valid");
        let resolved = sec.resolve_kdf_gate();
        assert_eq!(resolved.max_in_flight, 8);
        assert_eq!(
            resolved.max_queue_wait,
            std::time::Duration::from_millis(100)
        );
        assert_eq!(resolved.retry_after, std::time::Duration::from_secs(2));
    }

    #[test]
    fn kdf_admin_gate_absent_resolves_to_small_default() {
        // HEA-1892 / F2: absent `admin_max_in_flight` → small reserved pool,
        // NOT the core count. HEA-1895: absent `admin_max_queue_wait_ms` → the
        // *longer* admin queue-wait (prefer queueing over shedding), NOT the
        // shared gate's 250 ms. retry-after still mirrors the main gate.
        let sec = SecurityYaml::default();
        sec.validate_kdf_admission().expect("default is valid");
        let admin = sec.resolve_admin_kdf_gate();
        assert_eq!(
            admin.max_in_flight,
            crate::identity::DEFAULT_ADMIN_MAX_IN_FLIGHT
        );
        assert_eq!(
            admin.max_queue_wait,
            std::time::Duration::from_millis(crate::identity::DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS)
        );
        // The admin wait must strictly exceed the shared gate's shed threshold,
        // else a targeted flood could hold the console in steady-state 503.
        assert!(
            admin.max_queue_wait
                > std::time::Duration::from_millis(
                    sec.resolve_kdf_gate().max_queue_wait.as_millis() as u64
                ),
            "admin queue-wait must exceed the shared gate's"
        );
        assert_eq!(admin.retry_after, std::time::Duration::from_secs(1));
    }

    #[test]
    fn kdf_admin_queue_wait_explicit_and_zero_rejected() {
        // HEA-1895: an explicit `admin_max_queue_wait_ms` resolves through and is
        // independent of the shared gate's `max_queue_wait_ms`.
        let mut sec = SecurityYaml::default();
        sec.password.kdf.max_queue_wait_ms = 250;
        sec.password.kdf.admin_max_queue_wait_ms = Some(5_000);
        sec.validate_kdf_admission().expect("valid");
        assert_eq!(
            sec.resolve_admin_kdf_gate().max_queue_wait,
            std::time::Duration::from_secs(5)
        );
        // The shared gate is unaffected.
        assert_eq!(
            sec.resolve_kdf_gate().max_queue_wait,
            std::time::Duration::from_millis(250)
        );

        // Explicit 0 is a config error (a 0 ms wait would shed every queued
        // admin login, defeating the point).
        sec.password.kdf.admin_max_queue_wait_ms = Some(0);
        let err = sec
            .validate_kdf_admission()
            .expect_err("zero admin queue-wait rejected");
        assert!(
            err.to_string().contains("must be >= 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn kdf_admin_gate_rejects_zero_and_resolves_explicit() {
        // Explicit 0 is a config error (would shed every admin login).
        let mut sec = SecurityYaml::default();
        sec.password.kdf.admin_max_in_flight = Some(0);
        let err = sec
            .validate_kdf_admission()
            .expect_err("zero admin bound rejected");
        assert!(
            err.to_string().contains("must be >= 1"),
            "unexpected error: {err}"
        );

        // A valid explicit value resolves through independently of the main pool.
        sec.password.kdf.admin_max_in_flight = Some(3);
        sec.password.kdf.max_in_flight = Some(16);
        sec.validate_kdf_admission().expect("valid");
        assert_eq!(sec.resolve_admin_kdf_gate().max_in_flight, 3);
        assert_eq!(sec.resolve_kdf_gate().max_in_flight, 16);
    }

    #[test]
    fn resolve_pepper_rejects_short_key() {
        let sec = security_with_pepper(Some(PepperYaml {
            version: 1,
            key_hex: "11".repeat(16), // 16 bytes < 32
            previous_version: None,
            previous_key_hex: None,
        }));
        let err = sec.resolve_pepper().expect_err("short key rejected");
        assert!(
            err.to_string().contains("at least 32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_pepper_rejects_non_hex_key() {
        let sec = security_with_pepper(Some(PepperYaml {
            version: 1,
            key_hex: "zz".repeat(32),
            previous_version: None,
            previous_key_hex: None,
        }));
        let err = sec.resolve_pepper().expect_err("non-hex rejected");
        assert!(err.to_string().contains("hex"), "unexpected error: {err}");
    }

    #[test]
    fn resolve_pepper_rejects_unpaired_previous_version() {
        let sec = security_with_pepper(Some(PepperYaml {
            version: 2,
            key_hex: PEPPER_HEX.to_string(),
            previous_version: Some(1),
            previous_key_hex: None,
        }));
        let err = sec
            .resolve_pepper()
            .expect_err("unpaired previous rejected");
        assert!(
            err.to_string().contains("previous_key_hex is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_pepper_rejects_previous_version_equal_to_active() {
        // HEA-1839: same version number for both keys would make old-key
        // credentials unverifiable (active arm wins on version match).
        let sec = security_with_pepper(Some(PepperYaml {
            version: 2,
            key_hex: PEPPER_HEX.to_string(),
            previous_version: Some(2),
            previous_key_hex: Some(PEPPER_HEX_2.to_string()),
        }));
        let err = sec
            .resolve_pepper()
            .expect_err("colliding versions rejected");
        assert!(
            err.to_string().contains("differ from the active version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pepper_yaml_debug_redacts_keys() {
        // HEA-1839: `{:?}` on a config struct must never reveal pepper key material.
        let pepper = PepperYaml {
            version: 1,
            key_hex: PEPPER_HEX.to_string(),
            previous_version: Some(0),
            previous_key_hex: Some(PEPPER_HEX_2.to_string()),
        };
        let dbg = format!("{pepper:?}");
        assert!(!dbg.contains(PEPPER_HEX), "active key leaked: {dbg}");
        assert!(!dbg.contains(PEPPER_HEX_2), "previous key leaked: {dbg}");
        assert!(
            dbg.contains("[REDACTED]"),
            "expected redaction marker: {dbg}"
        );
    }

    #[test]
    fn security_yaml_debug_redacts_secret_key_material() {
        // HEA-1841: `{:?}` on SecurityYaml must never reveal the storage KEK or
        // the DPoP nonce HMAC secret — defense-in-depth against a future
        // `debug!(?config)`. PEPPER_HEX/PEPPER_HEX_2 are convenient 64-char hex
        // secrets standing in for real KEK / nonce material.
        let sec = SecurityYaml {
            key_encryption_key: Some(PEPPER_HEX.to_string()),
            dpop_nonce_secret: Some(PEPPER_HEX_2.to_string()),
            ..SecurityYaml::default()
        };
        let dbg = format!("{sec:?}");
        assert!(
            !dbg.contains(PEPPER_HEX),
            "key_encryption_key leaked: {dbg}"
        );
        assert!(
            !dbg.contains(PEPPER_HEX_2),
            "dpop_nonce_secret leaked: {dbg}"
        );
        assert!(
            dbg.contains("[REDACTED]"),
            "expected redaction marker: {dbg}"
        );
        // Presence must still be visible so absent vs. configured is debuggable.
        assert!(
            !dbg.contains("key_encryption_key: None"),
            "configured KEK must not render as None: {dbg}"
        );
    }

    #[test]
    fn config_from_yaml_parses_and_validates_pepper() {
        // End-to-end: an operator YAML snippet parses, validates, and yields a
        // resolvable pepper. A bad key is rejected at Config::validate time.
        //
        // Uses from_yaml_str_unchecked + a manual dev_mode override (the
        // legitimate --dev construction, per HEA control-liveness 10.2)
        // rather than from_yaml_str, which now refuses dev_mode: true in the
        // YAML text outright — this test is about pepper resolution, not
        // dev_mode itself.
        let ok_yaml = format!(
            "security:\n  password:\n    pepper:\n      version: 7\n      key_hex: \"{PEPPER_HEX}\"\n"
        );
        let mut cfg = Config::from_yaml_str_unchecked(&ok_yaml).expect("parse");
        cfg.dev_mode = true;
        cfg.validate().expect("valid pepper config validates");
        let resolved = cfg.security.resolve_pepper().expect("valid").expect("some");
        assert_eq!(resolved.active_version, 7);

        let bad_yaml =
            "security:\n  password:\n    pepper:\n      version: 1\n      key_hex: \"0000000000000000000000000000000000000000000000000000000000000000\"\n";
        let mut bad_cfg = Config::from_yaml_str_unchecked(bad_yaml).expect("parse");
        bad_cfg.dev_mode = true;
        assert!(
            bad_cfg.validate().is_err(),
            "zero-key pepper must be rejected at Config::validate"
        );
    }

    // === Security guardrail: ROPC / password grant MUST be rejected ============
    //
    // RFC 6749 §4.3 Resource Owner Password Credentials grant is prohibited in
    // Hearth (HEA-1814 / HEA-1816 / HEA-1862). These tests are a compile-and-run
    // guardrail: any agent or developer who re-adds "password" to
    // VALID_GRANT_TYPES will break these tests immediately.

    #[test]
    fn valid_grant_types_does_not_contain_password_ropc() {
        // Guardrail: VALID_GRANT_TYPES must never include the ROPC "password" grant.
        // If this assertion fails, ROPC has been re-introduced — revert immediately.
        assert!(
            !VALID_GRANT_TYPES.contains(&"password"),
            "SECURITY: 'password' (ROPC, RFC 6749 §4.3) must not appear in \
             VALID_GRANT_TYPES — remove it and use client_credentials or auth-code+PKCE instead"
        );
    }

    #[test]
    fn config_validates_application_id_token_signed_response_alg() {
        let yaml = |alg: &str| {
            format!(
                r#"
oidc:
  issuer: "https://auth.example.com"
server:
  trust_forwarded_proto: true
  trusted_proxies: ["127.0.0.1"]
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
realms:
  myrealm:
    applications:
      my-app:
        name: "My App"
        redirect_uris: ["https://app.example.com/cb"]
        id_token_signed_response_alg: "{alg}"
"#
            )
        };
        // Look only at this field's issues: the fixture is deliberately
        // minimal and trips unrelated production-mode rules (email transport).
        let alg_issues = |alg: &str| {
            Config::from_yaml_str_unchecked(&yaml(alg))
                .expect("fixture parses")
                .validate_all()
                .into_iter()
                .filter(|issue| {
                    issue.field == "realms.myrealm.applications.my-app.id_token_signed_response_alg"
                })
                .count()
        };
        for ok in ["RS256", "EdDSA"] {
            assert_eq!(alg_issues(ok), 0, "{ok} must be accepted");
        }
        for bad in ["HS256", "none", "rs256", "ES256", ""] {
            assert_eq!(
                alg_issues(bad),
                1,
                "{bad:?} must be refused by `hearth config validate`, not first at reconcile"
            );
        }
    }

    #[test]
    fn config_rejects_ropc_password_grant_in_applications() {
        let yaml = r#"
oidc:
  issuer: "https://auth.example.com"
server:
  trust_forwarded_proto: true
  trusted_proxies: ["127.0.0.1"]
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
realms:
  myrealm:
    applications:
      my-app:
        name: "My App"
        grant_types:
          - "password"
"#;
        let err = Config::from_yaml_str(yaml)
            .expect_err("ROPC 'password' grant must be rejected by config validation");
        let display = format!("{err}");
        assert!(
            display.contains("grant_types"),
            "error must name the grant_types field; got: {display}"
        );
        assert!(
            display.contains("password"),
            "error must name the rejected grant 'password'; got: {display}"
        );
    }

    #[test]
    fn config_rejects_ropc_password_grant_in_oauth_clients() {
        let yaml = r#"
oidc:
  issuer: "https://auth.example.com"
server:
  trust_forwarded_proto: true
  trusted_proxies: ["127.0.0.1"]
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
email:
  transport: smtp
  from: "noreply@example.com"
  smtp:
    host: "smtp.example.com"
    port: 587
realms:
  myrealm:
    oauth_clients:
      my-client:
        name: "My Client"
        grant_types:
          - "password"
"#;
        let err = Config::from_yaml_str(yaml)
            .expect_err("ROPC 'password' grant must be rejected via oauth_clients alias");
        let display = format!("{err}");
        assert!(
            display.contains("grant_types"),
            "error must name the grant_types field; got: {display}"
        );
        assert!(
            display.contains("password"),
            "error must name the rejected grant 'password'; got: {display}"
        );
    }

    #[test]
    fn config_accepts_client_credentials_grant() {
        // Regression guard: the safe alternative to ROPC must still parse cleanly.
        let yaml = r#"
oidc:
  issuer: "https://auth.example.com"
server:
  trust_forwarded_proto: true
  trusted_proxies: ["127.0.0.1"]
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
email:
  transport: smtp
  from: "noreply@example.com"
  smtp:
    host: "smtp.example.com"
    port: 587
realms:
  myrealm:
    applications:
      my-service:
        name: "My Service"
        grant_types:
          - "client_credentials"
        confidential: true
        client_secret: "a-sufficiently-long-secret-value"
"#;
        Config::from_yaml_str(yaml)
            .expect("client_credentials grant must remain a valid configuration");
    }

    // ── SAML SP signing pairing (§4.10#4) ─────────────────────────────────

    // ── GA audit 3 round 3: federation PEMs are parsed at load/reload ───────
    //
    // A SAML connector's `idp_certificate_pem` and an Apple connector's
    // `apple_private_key_pem` were only ever parsed at the first federated
    // login, so a paste error surfaced as a failed sign-in, not at boot. These
    // pin the load-time check, and that it uses the runtime's own parsers.

    /// A production-shaped YAML whose realm `acme` declares one federation
    /// provider `corp` with `provider` (lines indented for that position).
    fn yaml_with_federation_provider(provider: &str) -> String {
        format!(
            r#"
oidc:
  issuer: "https://auth.example.com"
server:
  trust_forwarded_proto: true
  trusted_proxies: ["127.0.0.1"]
security:
  key_encryption_key: "1111111111111111111111111111111111111111111111111111111111111111"
email:
  transport: smtp
  from: "noreply@example.com"
  smtp:
    host: "smtp.example.com"
    port: 587
realms:
  acme:
    federation:
      providers:
        corp:
{provider}"#
        )
    }

    fn saml_provider(idp_certificate_pem: Option<&str>) -> String {
        let mut out = String::from(concat!(
            "          type: saml\n",
            "          entity_id: \"https://idp.corp.example\"\n",
            "          sso_url: \"https://idp.corp.example/sso\"\n",
        ));
        if let Some(pem) = idp_certificate_pem {
            out.push_str(&format!("          idp_certificate_pem: {pem:?}\n"));
        }
        out
    }

    fn apple_provider(private_key_pem: &str) -> String {
        format!(
            concat!(
                "          type: apple\n",
                "          client_id: \"com.example.web\"\n",
                "          apple_team_id: \"A1B2C3D4E5\"\n",
                "          apple_key_id: \"ABCDE12345\"\n",
                "          apple_private_key_pem: {:?}\n",
            ),
            private_key_pem
        )
    }

    fn test_certificate_pem(name: &str) -> String {
        use base64::Engine as _;
        let key = crate::identity::tokens::RsaSigningKey::generate(name, 365).expect("key");
        let b64 = base64::engine::general_purpose::STANDARD.encode(key.cert_der());
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// Issues whose field is `realms.acme.federation.providers.corp.<key>`.
    fn federation_issue(yaml: &str, key: &str) -> Option<ValidationIssue> {
        let field = format!("realms.acme.federation.providers.corp.{key}");
        Config::from_yaml_str_unchecked(yaml)
            .expect("parse")
            .validate_all()
            .into_iter()
            .find(|i| i.field == field)
    }

    #[test]
    fn saml_idp_certificate_must_be_usable_at_load() {
        let yaml = yaml_with_federation_provider(&saml_provider(Some(
            "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n",
        )));
        let issue = federation_issue(&yaml, "idp_certificate_pem")
            .expect("an unusable IdP certificate must be reported at load");
        assert!(
            issue.reason.contains("'corp'") && issue.reason.contains("'acme'"),
            "the reason must name the IdP and the realm: {}",
            issue.reason
        );
        // The boot / reload loader refuses it too.
        let err = Config::from_yaml_str(&yaml).expect_err("boot must fail closed");
        assert!(err.to_string().contains("idp_certificate_pem"), "{err}");
    }

    #[test]
    fn saml_idp_certificate_is_required() {
        let yaml = yaml_with_federation_provider(&saml_provider(None));
        let issue = federation_issue(&yaml, "idp_certificate_pem")
            .expect("a SAML connector without a certificate must be reported at load");
        assert!(issue.reason.contains("'corp'"), "{}", issue.reason);
    }

    /// The rollover shape: two concatenated certificates, both usable.
    #[test]
    fn saml_idp_certificate_bundle_is_accepted() {
        let bundle = format!(
            "{}{}",
            test_certificate_pem("old"),
            test_certificate_pem("new")
        );
        let yaml = yaml_with_federation_provider(&saml_provider(Some(&bundle)));
        assert!(
            federation_issue(&yaml, "idp_certificate_pem").is_none(),
            "a two-certificate bundle must be accepted"
        );
    }

    /// A bundle is only as good as its worst block: a broken second
    /// certificate is refused at load, naming which one.
    #[test]
    fn saml_idp_certificate_bundle_with_an_unusable_block_is_refused() {
        let bundle = format!(
            "{}-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n",
            test_certificate_pem("old")
        );
        let yaml = yaml_with_federation_provider(&saml_provider(Some(&bundle)));
        let issue = federation_issue(&yaml, "idp_certificate_pem")
            .expect("a bundle with an unusable block must be reported");
        assert!(
            issue.reason.contains("certificate 2 of 2"),
            "the reason must say which block: {}",
            issue.reason
        );
    }

    #[test]
    fn apple_private_key_must_be_a_usable_p256_key_at_load() {
        let garbage = "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n";
        let yaml = yaml_with_federation_provider(&apple_provider(garbage));
        let issue = federation_issue(&yaml, "apple_private_key_pem")
            .expect("an unusable Apple key must be reported at load");
        assert!(
            issue.reason.contains("'corp'") && issue.reason.contains("'acme'"),
            "{}",
            issue.reason
        );
        assert!(
            !issue.reason.contains("bm90IGEga2V5"),
            "the reason must not echo key material: {}",
            issue.reason
        );

        use base64::Engine as _;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("generate");
        let pem = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(pkcs8.as_ref())
        );
        let yaml = yaml_with_federation_provider(&apple_provider(&pem));
        assert!(
            federation_issue(&yaml, "apple_private_key_pem").is_none(),
            "a real P-256 PKCS#8 key must be accepted"
        );
    }

    // ── GA audit 2026-09-28 B6: connection budgets ──────────────────────────

    #[test]
    fn zero_connection_budgets_are_refused() {
        let mut config = Config::dev();
        config.operational.header_read_timeout_secs = 0;
        config.operational.tls_handshake_timeout_secs = 0;
        let fields: Vec<String> = config.validate_all().into_iter().map(|i| i.field).collect();
        for field in [
            "operational.header_read_timeout_secs",
            "operational.tls_handshake_timeout_secs",
        ] {
            assert!(
                fields.iter().any(|f| f == field),
                "{field} = 0 must be refused; issues: {fields:?}"
            );
        }
    }

    // ── #446: user-create admission limit ──────────────────────────────────

    #[test]
    fn a_zero_user_create_bound_or_queue_wait_is_refused() {
        let mut config = Config::dev();
        config.operational.user_create.max_in_flight = 0;
        config.operational.user_create.max_queue_wait_ms = 0;
        let fields: Vec<String> = config.validate_all().into_iter().map(|i| i.field).collect();
        for field in [
            "operational.user_create.max_in_flight",
            "operational.user_create.max_queue_wait_ms",
        ] {
            assert!(
                fields.iter().any(|f| f == field),
                "{field} = 0 must be refused; issues: {fields:?}"
            );
        }
    }

    #[test]
    fn operational_user_create_parses_and_resolves() {
        let yaml = "operational:\n  user_create:\n    max_in_flight: 8\n    \
                    max_queue_wait_ms: 40\n    retry_after_secs: 5\n";
        let config = Config::from_yaml_str_unchecked(yaml).expect("parse");
        let gate = config.operational.user_create.resolve();
        assert_eq!(gate.max_in_flight, 8);
        assert_eq!(gate.max_queue_wait, std::time::Duration::from_millis(40));
        assert_eq!(gate.retry_after, std::time::Duration::from_secs(5));
    }

    // ── GA audit 2026-09-28 OPS-11: non-UTF-8 HEARTH_KEK ────────────────────

    /// `var_os` saw the variable as present, so validation passed, while the
    /// server's `var` saw it as absent. It must be refused here instead.
    #[cfg(unix)]
    #[test]
    fn a_non_utf8_hearth_kek_is_refused_by_validation() {
        use std::os::unix::ffi::OsStrExt;
        std::env::set_var(
            "HEARTH_KEK",
            std::ffi::OsStr::from_bytes(&[0xff, 0xfe, 0x41]),
        );
        let issues = Config::from_yaml_str_unchecked("{}")
            .expect("parse")
            .validate_all();
        std::env::remove_var("HEARTH_KEK");
        assert!(
            issues
                .iter()
                .any(|i| i.field == "security.key_encryption_key" && i.reason.contains("UTF-8")),
            "a HEARTH_KEK that is not valid UTF-8 must be reported; got {issues:?}"
        );
    }

    // ── GA audit 2026-09-28 M15: `email.transport: log` in production ───────

    fn email_transport_issues(config: &Config) -> Vec<ValidationIssue> {
        config
            .validate_all()
            .into_iter()
            .filter(|i| i.field == "email.transport")
            .collect()
    }

    /// The system realm always has password login, so its reset mail is
    /// load-bearing even when no realm is declared in YAML. The check used to
    /// return early when `realms` was absent.
    #[test]
    fn log_transport_is_refused_in_production_with_no_realms_declared() {
        let config = Config::from_yaml_str_unchecked("{}").expect("parse");
        assert!(!config.dev_mode);
        let issues = email_transport_issues(&config);
        assert!(
            issues.iter().any(|i| i.reason.contains("system realm")),
            "the default `log` transport must be refused in production even with no \
             realms declared — admin password-reset mail is silently dropped; got {issues:?}"
        );
    }

    #[test]
    fn the_explicit_opt_in_allows_log_transport_in_production() {
        let config = Config::from_yaml_str_unchecked(
            "email:\n  transport: log\n  allow_log_transport_in_production: true\n",
        )
        .expect("the opt-in key must parse");
        let issues = email_transport_issues(&config);
        assert!(
            issues.is_empty(),
            "the opt-in must lift the refusal; got {issues:?}"
        );
    }

    #[test]
    fn log_transport_stays_allowed_in_dev_mode() {
        let config = Config::dev();
        let issues = email_transport_issues(&config);
        assert!(
            issues.is_empty(),
            "dev mode keeps the log transport; got {issues:?}"
        );
    }

    #[test]
    fn a_real_transport_needs_no_opt_in() {
        let config = Config::from_yaml_str_unchecked(
            "email:\n  transport: smtp\n  from: auth@example.com\n  smtp:\n    host: mail.example.com\n    port: 587\n",
        )
        .expect("parse");
        let issues = email_transport_issues(&config);
        assert!(
            issues.is_empty(),
            "smtp must not trip the log-transport rule; got {issues:?}"
        );
    }

    #[test]
    fn the_connection_budgets_have_safe_defaults() {
        let config = Config::from_yaml_str_unchecked("{}").expect("empty config parses");
        assert_eq!(config.operational.header_read_timeout_secs, 10);
        assert_eq!(config.operational.tls_handshake_timeout_secs, 10);
        assert_eq!(config.operational.max_connections_per_ip, 64);
        assert_eq!(config.operational.http2_keepalive_interval_secs, 30);
    }
}
