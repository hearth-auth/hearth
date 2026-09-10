//! Configuration loading, validation, and defaults.
//!
//! Loads YAML configuration with environment variable substitution,
//! validates values, and provides production-safe defaults.

pub mod diff;
mod env;
pub mod error;
mod security_keys;
mod types;
pub mod validate;

pub use diff::{compute_diff, ConfigDiff, ConfigSnapshot};
pub use env::{EnvVarWarning, EnvVarWarningKind};
pub use error::ConfigError;

/// Reports every `security.*` key set in `yaml` that no code consumes.
///
/// The start-up liveness assertion behind audit §1A item 5: a key that parses,
/// validates, and is then never read is a control the operator believes is on
/// and is not. `yaml` must be the post-`${VAR}`-substitution config text.
///
/// See `src/config/security_keys.rs` for the registry and the test that forces
/// a new key to name its consumer.
#[must_use]
pub fn security_key_liveness_issues(yaml: &str) -> Vec<types::ValidationIssue> {
    security_keys::liveness_issues(yaml)
}

/// Every configuration key path registered in the security-key liveness table.
///
/// Exposed so integration tests can assert the registry has not silently lost
/// entries.
pub fn registered_security_key_paths() -> impl Iterator<Item = &'static str> {
    security_keys::registered_paths()
}
pub use types::parse_duration_to_micros;
pub use types::ClusterConfig;
pub use types::{
    AccountRateLimitYaml, ApplicationYamlConfig, AuthConfig, BrandingConfig, CaptchaProviderKind,
    CaptchaYaml, ClaimMappingYaml, ClaimsYamlConfig, CompactionSection, DemoConfig, EmailConfig,
    EmailTransport, FederationProviderYaml, FederationYamlConfig, GlobalRateLimitYaml,
    GroupYamlConfig, IpRateLimitYaml, LinkModeYaml, MailgunConfig, MailgunRegion, MailtrapConfig,
    MetricsConfig, MigrateConflictPolicy, ObservabilityConfig, OidcYamlConfig, OnboardingConfig,
    OperationalConfig, OrgConfigYaml, OrganizationYamlConfig, OtlpConfig, OtlpProtocol,
    PasswordPolicyYaml, PasswordSecurityYaml, PepperYaml, PermissionYamlConfig, PostmarkConfig,
    ProtectedResourceYamlConfig, RateLimitYaml, RealmAuthYaml, RealmEmailYaml, RealmMigrateYaml,
    RealmScimYaml, RealmTokenYaml, RealmWebYaml, RealmYamlConfig, RoleYamlConfig,
    SamlServiceProviderYaml, ScopeBundleYamlConfig, SecurityYaml, SeedUserYamlConfig,
    SeedingYamlConfig, SendgridConfig, ServerConfig, SmsConfig, SmsTransport, SmtpConfig,
    SmtpEncryption, SnsSmsConfig, StorageSection, TlsMinVersionYaml, TokenYamlConfig,
    TurnstileYaml, TwilioConfig,
};
pub use types::{AgentAuthCapabilities, AgentAuthConfig};
pub use types::{Config, ValidationIssue};
