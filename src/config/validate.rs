//! Configuration loading and validation logic.
//!
//! All [`Config`] constructors and validators live here, keeping
//! `mod.rs` to declarations-only per the architecture rule.

use std::path::Path;

use super::env;
use super::error::ConfigError;
use super::types::{
    parse_duration_to_micros, AgentAuthConfig, AuthConfig, BrandingConfig, CompactionSection,
    Config, DemoConfig, EmailConfig, EmailTransport, MetricsConfig, ObservabilityConfig,
    OidcYamlConfig, OnboardingConfig, OperationalConfig, RealmYamlConfig, SecurityYaml,
    ServerConfig, SmsConfig, SmsTransport, StorageSection, TokenYamlConfig, ValidationIssue,
};

// ─────────────────────────────────────────────────────────────────────────────
// Valid-value tables
// ─────────────────────────────────────────────────────────────────────────────

/// Valid UI theme names — must match `protocol::web::themes::VALID_THEMES`.
pub(super) const VALID_UI_THEMES: &[&str] =
    &["ember", "ocean", "midnight", "forest", "cloud", "slate"];

/// Valid MFA method names.
const VALID_MFA_METHODS: &[&str] = &["totp", "webauthn", "sms"];

/// Valid authentication method names.
const VALID_AUTH_METHODS: &[&str] = &["password", "magic_link", "passkey"];

/// Valid OAuth 2.0 grant types.
const VALID_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "client_credentials",
    "refresh_token",
    "urn:ietf:params:oauth:grant-type:device_code",
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
        let mut config: Self = serde_norway::from_str(&substituted)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.config_warnings = warnings;
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
                grpc_port: None,
                grpc_bind_address: None,
                assets_dir: None,
                trust_forwarded_proto: false,
            },
            storage: StorageSection {
                data_dir: String::new(),
                wal_max_size_bytes: 64 * 1024 * 1024,
                memtable_flush_bytes: 16 * 1024 * 1024,
                hot_tier_capacity: Some(1_000),
                hot_tier_max_memory: None,
                fsync: false,
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
            sms: SmsConfig::default(),
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
    /// settings (`dev_mode = true`, `fsync = false`, empty `data_dir`), then
    /// validates with the relaxed dev-mode rules.
    pub fn from_file_as_dev(path: &Path) -> Result<Self, ConfigError> {
        let mut config = Self::from_file_unchecked(path)?;
        config.dev_mode = true;
        config.storage.fsync = false;
        config.storage.data_dir = String::new();
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
        let mut config: Self = serde_norway::from_str(&substituted)
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        config.config_warnings = warnings;
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

        validate_oidc_all(&self.oidc, self.dev_mode, &mut issues);
        validate_token_all(&self.token, &mut issues);
        validate_email_all(&self.email, &mut issues);
        validate_sms_all(&self.sms, &mut issues);
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
        validate_realm_auth_configs_all(self.realms.as_ref(), &self.sms, &mut issues);
        validate_realm_applications_all(self.realms.as_ref(), &mut issues);
        validate_realm_organizations_all(self.realms.as_ref(), &mut issues);

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

        issues
    }

    /// Validates configuration values.
    ///
    /// Called automatically by [`from_yaml_str`] and [`from_file`].
    /// Dev-mode configs skip certain checks (e.g., empty `data_dir`).
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::ValidationError {
                field: "server.port".to_string(),
                reason: "must be between 1 and 65535".to_string(),
            });
        }

        // Dev mode must not be used with a non-loopback bind address — doing
        // so exposes all security bypasses (weak Argon2, CSRF skip, plaintext
        // setup token) to the network.
        if self.dev_mode && !is_loopback_str(&self.server.bind_address) {
            return Err(ConfigError::ValidationError {
                field: "server.bind_address".to_string(),
                reason: format!(
                    "dev_mode = true is only permitted with a loopback bind address; \
                     '{}' is not loopback. Use 127.0.0.1 or ::1, or disable dev_mode.",
                    self.server.bind_address
                ),
            });
        }

        match (&self.server.tls_cert_path, &self.server.tls_key_path) {
            (Some(_), None) => {
                return Err(ConfigError::ValidationError {
                    field: "server.tls_key_path".to_string(),
                    reason: "tls_key_path is required when tls_cert_path is set".to_string(),
                });
            }
            (None, Some(_)) => {
                return Err(ConfigError::ValidationError {
                    field: "server.tls_cert_path".to_string(),
                    reason: "tls_cert_path is required when tls_key_path is set".to_string(),
                });
            }
            _ => {}
        }

        if self.server.tls_require_client_cert && self.server.tls_client_ca_path.is_none() {
            return Err(ConfigError::ValidationError {
                field: "server.tls_client_ca_path".to_string(),
                reason: "tls_client_ca_path is required when tls_require_client_cert is true"
                    .to_string(),
            });
        }

        if !self.dev_mode && self.storage.data_dir.is_empty() {
            return Err(ConfigError::ValidationError {
                field: "storage.data_dir".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        if !ObservabilityConfig::VALID_LOG_LEVELS.contains(&self.observability.log_level.as_str()) {
            return Err(ConfigError::ValidationError {
                field: "observability.log_level".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_LEVELS.join(", ")
                ),
            });
        }

        if !ObservabilityConfig::VALID_LOG_FORMATS.contains(&self.observability.log_format.as_str())
        {
            return Err(ConfigError::ValidationError {
                field: "observability.log_format".to_string(),
                reason: format!(
                    "must be one of: {}",
                    ObservabilityConfig::VALID_LOG_FORMATS.join(", ")
                ),
            });
        }

        if self.operational.request_timeout_secs == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.request_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.operational.shutdown_timeout_secs == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.shutdown_timeout_secs".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.operational.max_connections == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.max_connections".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.operational.queue_depth == 0 {
            return Err(ConfigError::ValidationError {
                field: "operational.queue_depth".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        validate_oidc(&self.oidc, self.dev_mode)?;
        validate_token(&self.token)?;
        validate_email(&self.email)?;
        validate_sms(&self.sms)?;
        validate_branding(&self.branding)?;
        validate_realm_names(self.realms.as_ref())?;
        validate_realm_web_configs(self.realms.as_ref())?;
        validate_realm_auth_configs(self.realms.as_ref(), &self.sms)?;
        validate_realm_applications(self.realms.as_ref())?;
        validate_realm_organizations(self.realms.as_ref())?;

        if let Some(addr) = &self.onboarding.notification_email {
            addr.parse::<lettre::message::Mailbox>().map_err(|e| {
                invalid(
                    "onboarding.notification_email",
                    format!("could not parse as an RFC 5322 mailbox: {e}"),
                )
            })?;
        }

        if self.onboarding.notification_email.is_some() && self.onboarding.base_url.is_none() {
            return Err(invalid(
                "onboarding.base_url",
                "onboarding.base_url is required when onboarding.notification_email is set; \
                 without it the emailed setup URL uses the bind address which may not be \
                 reachable from outside the server",
            ));
        }

        let mut tp_issues = Vec::new();
        validate_trusted_proxies(&self.server, &mut tp_issues);
        if let Some(issue) = tp_issues.into_iter().next() {
            return Err(invalid(&issue.field, issue.reason));
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IP-address helpers
// ─────────────────────────────────────────────────────────────────────────────

fn is_loopback_str(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

fn is_unspecified_str(addr: &str) -> bool {
    addr.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_unspecified())
        .unwrap_or(false)
}

fn is_public_listener(bind_address: &str) -> bool {
    !is_loopback_str(bind_address)
}

// ─────────────────────────────────────────────────────────────────────────────
// Fail-fast validators (used by `Config::validate`)
// ─────────────────────────────────────────────────────────────────────────────

/// A-32: Validates `server.trusted_proxies` against known dangerous configurations.
fn validate_trusted_proxies(server: &ServerConfig, issues: &mut Vec<ValidationIssue>) {
    for (i, entry) in server.trusted_proxies.iter().enumerate() {
        let field = format!("server.trusted_proxies[{i}]");

        if entry == "0.0.0.0/0" || entry == "::/0" {
            issues.push(ValidationIssue {
                field,
                reason: format!(
                    "'{entry}' is a catch-all CIDR that trusts every IP as a proxy; \
                     this bypasses all IP-based protections. \
                     List only your actual reverse-proxy IP addresses."
                ),
            });
            continue;
        }

        if is_unspecified_str(entry) {
            issues.push(ValidationIssue {
                field,
                reason: format!(
                    "'{entry}' is an unspecified/catch-all address that trusts every \
                     IP as a proxy; list only your actual reverse-proxy IP addresses."
                ),
            });
            continue;
        }

        if is_loopback_str(entry) && is_public_listener(&server.bind_address) {
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

fn validate_realm_names(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else { return Ok(()) };
    if realms.contains_key("system") {
        return Err(invalid(
            "realms.system",
            "\"system\" is a reserved realm name; it is managed by Hearth and cannot be declared in YAML",
        ));
    }
    Ok(())
}

fn validate_branding(branding: &BrandingConfig) -> Result<(), ConfigError> {
    if let Some(theme) = &branding.theme {
        let lower = theme.to_ascii_lowercase();
        if !VALID_UI_THEMES.contains(&lower.as_str()) {
            return Err(invalid(
                "branding.theme",
                format!(
                    "unknown theme '{}'; valid themes are: {}",
                    theme,
                    VALID_UI_THEMES.join(", ")
                ),
            ));
        }
    }
    if let Some(path) = &branding.custom_css {
        if !std::fs::metadata(path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            return Err(invalid(
                "branding.custom_css",
                format!("file not found or not readable: {path}"),
            ));
        }
    }
    Ok(())
}

fn validate_realm_web_configs(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (name, cfg) in realms {
        let Some(web) = &cfg.web else { continue };
        if let Some(theme) = &web.theme {
            let lower = theme.to_ascii_lowercase();
            if !VALID_UI_THEMES.contains(&lower.as_str()) {
                return Err(invalid(
                    &format!("realms.{name}.web.theme"),
                    format!(
                        "unknown theme '{}'; valid themes are: {}",
                        theme,
                        VALID_UI_THEMES.join(", ")
                    ),
                ));
            }
        }
        if let Some(path) = &web.custom_css {
            if !std::fs::metadata(path)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Err(invalid(
                    &format!("realms.{name}.web.custom_css"),
                    format!("file not found or not readable: {path}"),
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_realm_auth_configs(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    sms: &SmsConfig,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (name, cfg) in realms {
        if let Some(scim) = &cfg.scim {
            if let Some(token) = &scim.bearer_token {
                if token.trim().is_empty() {
                    return Err(invalid(
                        &format!("realms.{name}.scim.bearer_token"),
                        "must not be empty when SCIM is configured",
                    ));
                }
            }
        }
        let Some(auth) = &cfg.auth else { continue };
        if let Some(methods) = &auth.mfa_methods {
            for m in methods {
                if !VALID_MFA_METHODS.contains(&m.as_str()) {
                    return Err(invalid(
                        &format!("realms.{name}.auth.mfa_methods"),
                        format!(
                            "unknown MFA method '{}'; valid methods are: {}",
                            m,
                            VALID_MFA_METHODS.join(", ")
                        ),
                    ));
                }
            }
            if methods.iter().any(|m| m == "sms") && sms.transport == SmsTransport::Log {
                return Err(invalid(
                    &format!("realms.{name}.auth.mfa_methods"),
                    "'sms' is listed as an MFA method but sms.transport is 'log'; \
                     configure a real SMS transport (twilio or awssns) to deliver OTP codes",
                ));
            }
        }
        if let Some(methods) = &auth.allowed_auth_methods {
            for m in methods {
                if !VALID_AUTH_METHODS.contains(&m.as_str()) {
                    return Err(invalid(
                        &format!("realms.{name}.auth.allowed_auth_methods"),
                        format!(
                            "unknown auth method '{}'; valid methods are: {}",
                            m,
                            VALID_AUTH_METHODS.join(", ")
                        ),
                    ));
                }
            }
        }
        if let Some(pp) = &auth.password_policy {
            if let Some(len) = pp.min_length {
                if len == 0 {
                    return Err(invalid(
                        &format!("realms.{name}.auth.password_policy.min_length"),
                        "must be >= 1",
                    ));
                }
            }
        }
        if let Some(token) = &auth.token {
            if let Some(ttl) = &token.access_token_ttl {
                parse_duration_to_micros(ttl).map_err(|e| {
                    invalid(
                        &format!("realms.{name}.auth.token.access_token_ttl"),
                        format!("invalid duration: {e}"),
                    )
                })?;
            }
            if let Some(ttl) = &token.refresh_token_ttl {
                parse_duration_to_micros(ttl).map_err(|e| {
                    invalid(
                        &format!("realms.{name}.auth.token.refresh_token_ttl"),
                        format!("invalid duration: {e}"),
                    )
                })?;
            }
        }
        if let Some(rl) = &auth.rate_limit {
            if let Some(dur) = &rl.lockout_duration {
                parse_duration_to_micros(dur).map_err(|e| {
                    invalid(
                        &format!("realms.{name}.auth.rate_limit.lockout_duration"),
                        format!("invalid duration: {e}"),
                    )
                })?;
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
                    return Err(invalid(
                        &format!("realms.{name}.auth.registration.allowed_domains"),
                        "mode = domain_restricted requires a non-empty allowed_domains list",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn validate_realm_organizations(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (realm_name, cfg) in realms {
        let Some(orgs) = &cfg.organizations else {
            continue;
        };
        for (slug, org) in orgs {
            let prefix = format!("realms.{realm_name}.organizations.{slug}");
            if org.name.trim().is_empty() {
                return Err(invalid(&format!("{prefix}.name"), "must not be empty"));
            }
            if slug.len() < 3 || slug.len() > 63 {
                return Err(invalid(
                    &prefix,
                    format!("slug '{slug}' must be 3-63 characters"),
                ));
            }
            if !slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                return Err(invalid(
                    &prefix,
                    format!(
                        "slug '{slug}' must contain only lowercase letters, digits, and hyphens"
                    ),
                ));
            }
            if slug.starts_with('-') || slug.ends_with('-') {
                return Err(invalid(
                    &prefix,
                    format!("slug '{slug}' must not start or end with a hyphen"),
                ));
            }
        }
    }
    Ok(())
}

fn validate_realm_applications(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
) -> Result<(), ConfigError> {
    let Some(realms) = realms else {
        return Ok(());
    };
    for (realm_name, cfg) in realms {
        let Some(apps) = cfg.oauth_clients.as_ref().or(cfg.applications.as_ref()) else {
            continue;
        };
        for (app_key, app) in apps {
            let prefix = format!("realms.{realm_name}.applications.{app_key}");
            if app.name.trim().is_empty() {
                return Err(invalid(&format!("{prefix}.name"), "must not be empty"));
            }
            if let Some(grant_types) = &app.grant_types {
                for gt in grant_types {
                    if !VALID_GRANT_TYPES.contains(&gt.as_str()) {
                        return Err(invalid(
                            &format!("{prefix}.grant_types"),
                            format!(
                                "unknown grant type '{}'; valid types are: {}",
                                gt,
                                VALID_GRANT_TYPES.join(", ")
                            ),
                        ));
                    }
                }
            }
            if let Some(uris) = &app.redirect_uris {
                for uri in uris {
                    if uri.is_empty() {
                        return Err(invalid(
                            &format!("{prefix}.redirect_uris"),
                            "redirect URIs must not be empty strings",
                        ));
                    }
                }
            }
            let is_confidential = app.confidential.unwrap_or(false);
            if is_confidential && app.client_secret.is_none() {
                return Err(invalid(
                    &format!("{prefix}.client_secret"),
                    "client_secret is required when confidential is true",
                ));
            }
            if !is_confidential && app.client_secret.is_some() {
                return Err(invalid(
                    &format!("{prefix}.confidential"),
                    "confidential must be true when client_secret is provided",
                ));
            }
        }
    }
    Ok(())
}

fn validate_oidc(oidc: &OidcYamlConfig, dev_mode: bool) -> Result<(), ConfigError> {
    if oidc.issuer.is_none() && !dev_mode {
        return Err(invalid(
            "oidc.issuer",
            "required for production; set it to your public HTTPS URL \
             (e.g. https://auth.example.com). Use --dev to skip this check \
             in local development.",
        ));
    }
    if let Some(issuer) = &oidc.issuer {
        if issuer.is_empty() {
            return Err(invalid("oidc.issuer", "must not be empty"));
        }
        if !issuer.starts_with("https://") && !issuer.starts_with("http://") {
            return Err(invalid(
                "oidc.issuer",
                "must be a URL starting with https:// or http://",
            ));
        }
        if issuer.contains(".local") {
            return Err(invalid(
                "oidc.issuer",
                "uses a .local hostname which is not publicly reachable; \
                 set it to your public HTTPS URL (e.g. https://auth.example.com)",
            ));
        }
    }
    if let Some(ttl) = &oidc.authorization_code_ttl {
        parse_duration_to_micros(ttl).map_err(|e| {
            invalid(
                "oidc.authorization_code_ttl",
                format!("invalid duration: {e}"),
            )
        })?;
    }
    Ok(())
}

fn validate_token(token: &TokenYamlConfig) -> Result<(), ConfigError> {
    if let Some(issuer) = &token.issuer {
        if issuer.is_empty() {
            return Err(invalid("token.issuer", "must not be empty"));
        }
    }
    if let Some(ttl) = &token.access_token_ttl {
        parse_duration_to_micros(ttl)
            .map_err(|e| invalid("token.access_token_ttl", format!("invalid duration: {e}")))?;
    }
    if let Some(ttl) = &token.refresh_token_ttl {
        parse_duration_to_micros(ttl)
            .map_err(|e| invalid("token.refresh_token_ttl", format!("invalid duration: {e}")))?;
    }
    Ok(())
}

fn validate_email(email: &EmailConfig) -> Result<(), ConfigError> {
    match email.transport {
        EmailTransport::Log => return Ok(()),
        EmailTransport::Smtp => validate_email_smtp(email)?,
        EmailTransport::Sendgrid => validate_email_sendgrid(email)?,
        EmailTransport::Postmark => validate_email_postmark(email)?,
        EmailTransport::Mailgun => validate_email_mailgun(email)?,
        EmailTransport::Mailtrap => validate_email_mailtrap(email)?,
        EmailTransport::Mailcatcher => return Ok(()),
    }
    Ok(())
}

fn validate_email_smtp(email: &EmailConfig) -> Result<(), ConfigError> {
    let smtp = email.smtp.as_ref().ok_or_else(|| {
        invalid(
            "email.smtp",
            "smtp block is required when email.transport is smtp",
        )
    })?;

    validate_from_address(email)?;

    match (&smtp.username, &smtp.password) {
        (Some(u), _) if u.is_empty() => {
            return Err(invalid("email.smtp.username", "must not be empty"));
        }
        (Some(_), None) => {
            return Err(invalid(
                "email.smtp.password",
                "password is required when username is set",
            ));
        }
        (None, Some(_)) => {
            return Err(invalid(
                "email.smtp.username",
                "username is required when password is set",
            ));
        }
        _ => {}
    }

    if smtp.host.is_empty() {
        return Err(invalid("email.smtp.host", "must not be empty"));
    }
    if smtp.port == 0 {
        return Err(invalid("email.smtp.port", "must be between 1 and 65535"));
    }
    Ok(())
}

fn validate_email_sendgrid(email: &EmailConfig) -> Result<(), ConfigError> {
    let sg = email.sendgrid.as_ref().ok_or_else(|| {
        invalid(
            "email.sendgrid",
            "sendgrid block is required when email.transport is sendgrid",
        )
    })?;
    validate_from_address(email)?;
    if sg.api_key.is_empty() {
        return Err(invalid("email.sendgrid.api_key", "must not be empty"));
    }
    Ok(())
}

fn validate_email_postmark(email: &EmailConfig) -> Result<(), ConfigError> {
    let pm = email.postmark.as_ref().ok_or_else(|| {
        invalid(
            "email.postmark",
            "postmark block is required when email.transport is postmark",
        )
    })?;
    validate_from_address(email)?;
    if pm.server_token.is_empty() {
        return Err(invalid("email.postmark.server_token", "must not be empty"));
    }
    Ok(())
}

fn validate_email_mailgun(email: &EmailConfig) -> Result<(), ConfigError> {
    let mg = email.mailgun.as_ref().ok_or_else(|| {
        invalid(
            "email.mailgun",
            "mailgun block is required when email.transport is mailgun",
        )
    })?;
    validate_from_address(email)?;
    if mg.api_key.is_empty() {
        return Err(invalid("email.mailgun.api_key", "must not be empty"));
    }
    if mg.domain.is_empty() {
        return Err(invalid("email.mailgun.domain", "must not be empty"));
    }
    Ok(())
}

fn validate_email_mailtrap(email: &EmailConfig) -> Result<(), ConfigError> {
    let mt = email.mailtrap.as_ref().ok_or_else(|| {
        invalid(
            "email.mailtrap",
            "mailtrap block is required when email.transport is mailtrap",
        )
    })?;
    validate_from_address(email)?;
    if mt.api_key.is_empty() {
        return Err(invalid("email.mailtrap.api_key", "must not be empty"));
    }
    Ok(())
}

fn validate_sms(sms: &SmsConfig) -> Result<(), ConfigError> {
    match sms.transport {
        SmsTransport::Log => return Ok(()),
        SmsTransport::Twilio => validate_sms_twilio(sms)?,
        SmsTransport::AwsSns => validate_sms_awssns(sms)?,
    }
    // For real transports, HEARTH_SMS_OTP_HMAC_KEY must be present and long enough.
    match std::env::var("HEARTH_SMS_OTP_HMAC_KEY") {
        Ok(key) if key.len() >= 32 => Ok(()),
        Ok(key) if !key.is_empty() => Err(invalid(
            "sms",
            "HEARTH_SMS_OTP_HMAC_KEY must be at least 32 bytes for adequate HMAC-SHA256 \
             security; use a 32+ byte random value",
        )),
        _ => Err(invalid(
            "sms",
            "HEARTH_SMS_OTP_HMAC_KEY environment variable is required when \
             sms.transport is not 'log'",
        )),
    }
}

fn validate_sms_twilio(sms: &SmsConfig) -> Result<(), ConfigError> {
    let tw = sms.twilio.as_ref().ok_or_else(|| {
        invalid(
            "sms.twilio",
            "twilio block is required when sms.transport is twilio",
        )
    })?;
    if tw.account_sid.is_empty() {
        return Err(invalid("sms.twilio.account_sid", "must not be empty"));
    }
    if tw.auth_token.is_empty() {
        return Err(invalid("sms.twilio.auth_token", "must not be empty"));
    }
    if tw.from.is_empty() {
        return Err(invalid("sms.twilio.from", "must not be empty"));
    }
    Ok(())
}

fn validate_sms_awssns(sms: &SmsConfig) -> Result<(), ConfigError> {
    let aws_sns = sms.aws_sns.as_ref().ok_or_else(|| {
        invalid(
            "sms.aws_sns",
            "aws_sns block is required when sms.transport is awssns",
        )
    })?;
    if aws_sns.region.is_empty() {
        return Err(invalid("sms.aws_sns.region", "must not be empty"));
    }
    if aws_sns.access_key_id.is_empty() {
        return Err(invalid("sms.aws_sns.access_key_id", "must not be empty"));
    }
    if aws_sns.secret_access_key.is_empty() {
        return Err(invalid(
            "sms.aws_sns.secret_access_key",
            "must not be empty",
        ));
    }
    Ok(())
}

fn validate_sms_all(sms: &SmsConfig, issues: &mut Vec<ValidationIssue>) {
    match validate_sms(sms) {
        Ok(()) => {}
        Err(ConfigError::ValidationError { field, reason }) => {
            issues.push(ValidationIssue { field, reason });
        }
        Err(_) => {}
    }
}

fn validate_from_address(email: &EmailConfig) -> Result<(), ConfigError> {
    let from = email.from.as_ref().ok_or_else(|| {
        invalid(
            "email.from",
            format!(
                "from address is required when email.transport is {:?}",
                email.transport
            ),
        )
    })?;
    from.parse::<lettre::message::Mailbox>().map_err(|e| {
        invalid(
            "email.from",
            format!("could not parse as an RFC 5322 mailbox: {e}"),
        )
    })?;
    Ok(())
}

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
        if parse_duration_to_micros(ttl).is_err() {
            issues.push(ValidationIssue {
                field: "token.access_token_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            });
        }
    }
    if let Some(ttl) = &token.refresh_token_ttl {
        if parse_duration_to_micros(ttl).is_err() {
            issues.push(ValidationIssue {
                field: "token.refresh_token_ttl".to_string(),
                reason: "invalid duration format".to_string(),
            });
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_email_all(email: &EmailConfig, issues: &mut Vec<ValidationIssue>) {
    if matches!(email.transport, EmailTransport::Log) {
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
        if !std::fs::metadata(path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            issues.push(ValidationIssue {
                field: "branding.custom_css".to_string(),
                reason: format!("file not found or not readable: {path}"),
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
            if !std::fs::metadata(path)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.web.custom_css"),
                    reason: format!("file not found or not readable: {path}"),
                });
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
fn validate_realm_auth_configs_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    sms: &SmsConfig,
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
        if let Some(methods) = &auth.mfa_methods {
            for m in methods {
                if !VALID_MFA_METHODS.contains(&m.as_str()) {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.mfa_methods"),
                        reason: format!(
                            "unknown MFA method '{}'; valid methods are: {}",
                            m,
                            VALID_MFA_METHODS.join(", ")
                        ),
                    });
                }
            }
            if methods.iter().any(|m| m == "sms") && sms.transport == SmsTransport::Log {
                issues.push(ValidationIssue {
                    field: format!("realms.{name}.auth.mfa_methods"),
                    reason:
                        "'sms' is listed as an MFA method but sms.transport is 'log'; \
                             configure a real SMS transport (twilio or awssns) to deliver OTP codes"
                            .to_string(),
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
                if parse_duration_to_micros(ttl).is_err() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.access_token_ttl"),
                        reason: "invalid duration format".to_string(),
                    });
                }
            }
            if let Some(ttl) = &token.refresh_token_ttl {
                if parse_duration_to_micros(ttl).is_err() {
                    issues.push(ValidationIssue {
                        field: format!("realms.{name}.auth.token.refresh_token_ttl"),
                        reason: "invalid duration format".to_string(),
                    });
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

fn validate_realm_applications_all(
    realms: Option<&std::collections::HashMap<String, RealmYamlConfig>>,
    issues: &mut Vec<ValidationIssue>,
) {
    let Some(realms) = realms else { return };
    for (realm_name, cfg) in realms {
        let Some(apps) = &cfg.applications else {
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
            match &app.redirect_uris {
                None => {
                    issues.push(ValidationIssue {
                        field: format!("{prefix}.redirect_uris"),
                        reason: "at least one redirect URI is required".to_string(),
                    });
                }
                Some(uris) if uris.is_empty() => {
                    issues.push(ValidationIssue {
                        field: format!("{prefix}.redirect_uris"),
                        reason: "at least one redirect URI is required".to_string(),
                    });
                }
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
    use super::*;
    use crate::config::types::{
        RealmAuthYaml, RealmYamlConfig, SmsConfig, SmsTransport, TwilioConfig,
    };

    fn realm_with_mfa(methods: &[&str]) -> RealmYamlConfig {
        RealmYamlConfig {
            auth: Some(RealmAuthYaml {
                mfa_methods: Some(methods.iter().map(|s| (*s).to_string()).collect()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn sms_log() -> SmsConfig {
        SmsConfig {
            transport: SmsTransport::Log,
            ..Default::default()
        }
    }

    #[test]
    fn sms_is_accepted_in_mfa_methods_with_real_transport() {
        // "sms" was previously missing from VALID_MFA_METHODS — verify it is now accepted
        // when paired with a non-log transport. We use Twilio here; the cross-validation
        // only fires when transport==Log.
        let mut realms = std::collections::HashMap::new();
        realms.insert("default".to_string(), realm_with_mfa(&["totp", "sms"]));
        let sms = SmsConfig {
            transport: SmsTransport::Twilio,
            twilio: Some(TwilioConfig {
                account_sid: "ACtest".to_string(),
                auth_token: "token".to_string(),
                from: "+15550001111".to_string(),
            }),
            ..Default::default()
        };
        // HMAC key must be present for non-log transport validation; inject it via env.
        // We only test the mfa_methods portion of the validator here (not full validate_sms).
        let result = validate_realm_auth_configs(Some(&realms), &sms);
        // Should succeed (the sms + real-transport combo is valid for mfa_methods check).
        assert!(result.is_ok(), "expected Ok but got: {result:?}");
    }

    #[test]
    fn sms_mfa_with_log_transport_is_rejected() {
        // Operators cannot deliver OTPs via the log transport; a config that enables
        // sms as an MFA method while leaving sms.transport=log is a misconfiguration.
        let mut realms = std::collections::HashMap::new();
        realms.insert("default".to_string(), realm_with_mfa(&["totp", "sms"]));
        let result = validate_realm_auth_configs(Some(&realms), &sms_log());
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError but got: {result:?}");
        };
        assert_eq!(field, "realms.default.auth.mfa_methods");
        assert!(
            reason.contains("log"),
            "reason should mention 'log': {reason}"
        );
    }

    #[test]
    fn totp_and_webauthn_still_accepted_with_log_transport() {
        // Non-sms methods must still be accepted regardless of sms.transport.
        let mut realms = std::collections::HashMap::new();
        realms.insert("default".to_string(), realm_with_mfa(&["totp", "webauthn"]));
        let result = validate_realm_auth_configs(Some(&realms), &sms_log());
        assert!(result.is_ok(), "expected Ok but got: {result:?}");
    }

    #[test]
    fn unknown_mfa_method_is_rejected() {
        let mut realms = std::collections::HashMap::new();
        realms.insert(
            "default".to_string(),
            realm_with_mfa(&["totp", "carrier_pigeon"]),
        );
        let result = validate_realm_auth_configs(Some(&realms), &sms_log());
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError but got: {result:?}");
        };
        assert_eq!(field, "realms.default.auth.mfa_methods");
        assert!(reason.contains("carrier_pigeon"), "{reason}");
    }

    #[test]
    fn validate_all_sms_mfa_with_log_transport_accumulates_issue() {
        let mut realms = std::collections::HashMap::new();
        realms.insert("default".to_string(), realm_with_mfa(&["sms"]));
        let mut issues = Vec::new();
        validate_realm_auth_configs_all(Some(&realms), &sms_log(), &mut issues);
        assert!(
            issues
                .iter()
                .any(|i| i.field == "realms.default.auth.mfa_methods" && i.reason.contains("log")),
            "expected an issue about log transport; got: {issues:?}"
        );
    }

    #[test]
    fn sms_hmac_key_required_for_non_log_transport() {
        // Ensure the HMAC key check is caught by validate_sms when transport != Log.
        // Remove the env var so the check fires.
        std::env::remove_var("HEARTH_SMS_OTP_HMAC_KEY");
        let sms = SmsConfig {
            transport: SmsTransport::Twilio,
            twilio: Some(TwilioConfig {
                account_sid: "ACtest".to_string(),
                auth_token: "token".to_string(),
                from: "+15550001111".to_string(),
            }),
            ..Default::default()
        };
        let result = validate_sms(&sms);
        let Err(ConfigError::ValidationError { field, reason }) = result else {
            panic!("expected ValidationError but got: {result:?}");
        };
        assert_eq!(field, "sms");
        assert!(
            reason.contains("HEARTH_SMS_OTP_HMAC_KEY"),
            "reason should mention HEARTH_SMS_OTP_HMAC_KEY: {reason}"
        );
    }

    #[test]
    fn sms_hmac_key_too_short_is_rejected() {
        std::env::set_var("HEARTH_SMS_OTP_HMAC_KEY", "short");
        let sms = SmsConfig {
            transport: SmsTransport::Twilio,
            twilio: Some(TwilioConfig {
                account_sid: "ACtest".to_string(),
                auth_token: "token".to_string(),
                from: "+15550001111".to_string(),
            }),
            ..Default::default()
        };
        let result = validate_sms(&sms);
        std::env::remove_var("HEARTH_SMS_OTP_HMAC_KEY");
        let Err(ConfigError::ValidationError { reason, .. }) = result else {
            panic!("expected ValidationError but got: {result:?}");
        };
        assert!(
            reason.contains("32 bytes"),
            "reason should mention 32 bytes: {reason}"
        );
    }

    #[test]
    fn sms_log_transport_does_not_require_hmac_key() {
        std::env::remove_var("HEARTH_SMS_OTP_HMAC_KEY");
        let result = validate_sms(&sms_log());
        assert!(result.is_ok(), "log transport should not require HMAC key");
    }
}
