//! Configuration loading, validation, and defaults.
//!
//! Loads YAML configuration with environment variable substitution,
//! validates values, and provides production-safe defaults.

pub mod diff;
mod env;
pub mod error;
mod types;
pub mod validate;

pub use diff::{compute_diff, ConfigDiff, ConfigSnapshot};
pub use env::{EnvVarWarning, EnvVarWarningKind};
pub use error::ConfigError;
pub use types::parse_duration_to_micros;
pub use types::ClusterConfig;
pub use types::{
    AccountRateLimitYaml, ApplicationYamlConfig, AuthConfig, BrandingConfig, CaptchaProviderKind,
    CaptchaYaml, ClaimsYamlConfig, CompactionSection, EmailConfig, EmailTransport,
    FederationProviderYaml, FederationYamlConfig, GlobalRateLimitYaml, GroupYamlConfig,
    IpRateLimitYaml, LinkModeYaml, MailgunConfig, MailgunRegion, MailtrapConfig, MetricsConfig,
    MigrateConflictPolicy, ObservabilityConfig, OidcYamlConfig, OnboardingConfig,
    OperationalConfig, OrgConfigYaml, OrganizationYamlConfig, OtlpConfig, OtlpProtocol,
    PasswordPolicyYaml, PermissionYamlConfig, PostmarkConfig, ProtectedResourceYamlConfig,
    RateLimitYaml, RealmAuthYaml, RealmEmailYaml, RealmMigrateYaml, RealmScimYaml, RealmTokenYaml,
    RealmWebYaml, RealmYamlConfig, RoleYamlConfig, SamlServiceProviderYaml, ScopeBundleYamlConfig,
    SecurityYaml, SeedUserYamlConfig, SendgridConfig, ServerConfig, SmsConfig, SmsTransport,
    SmtpConfig, SmtpEncryption, SnsSmsConfig, StorageSection, TokenYamlConfig, TurnstileYaml,
    TwilioConfig,
};
pub use types::{AgentAuthCapabilities, AgentAuthConfig};
pub use types::{Config, ValidationIssue};
