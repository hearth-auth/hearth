//! Configuration section structs.
//!
//! Each section implements `Default` with production-safe values and
//! `Deserialize` for YAML parsing. `#[serde(default)]` on each section
//! means partial YAML files work seamlessly.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::identity::claims_config::ClaimMapping;
use crate::identity::email::EmailBranding;
use crate::identity::ClientTrustLevel;
use crate::rbac::{
    Permission, PermissionDefinition, ProtectedResource, Role, RoleId, RoleScopeKind, ScopeBundle,
};

/// Server network configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the server to.
    #[serde(default = "ServerConfig::default_bind_address")]
    pub bind_address: String,
    /// Port to listen on.
    #[serde(default = "ServerConfig::default_port")]
    pub port: u16,
    /// Path to TLS certificate file (optional; no TLS if absent).
    pub tls_cert_path: Option<PathBuf>,
    /// Path to TLS private key file (optional; no TLS if absent).
    pub tls_key_path: Option<PathBuf>,
    /// Path to a CA certificate for client certificate verification (mTLS).
    pub tls_client_ca_path: Option<PathBuf>,
    /// Whether to require a client certificate (mTLS). Requires `tls_client_ca_path`.
    #[serde(default)]
    pub tls_require_client_cert: bool,
    /// Trusted reverse proxy IP addresses (CIDR notation not yet supported).
    ///
    /// When configured, the server extracts the real client IP from the
    /// `X-Forwarded-For` header using the rightmost-non-trusted algorithm.
    /// When empty (default), the peer socket IP is used directly and XFF is
    /// ignored — the safe default for direct-to-internet deployments.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Name of the realm to use when a bare `/ui/*` URL is hit on a
    /// multi-realm deployment.
    ///
    /// Resolution order for pre-auth pages:
    /// 1. Explicit `/ui/realms/<name>/...` path wins.
    /// 2. On single-realm deployments the sole realm is used implicitly.
    /// 3. Multi-realm + `default_realm` set → that realm is used.
    /// 4. Multi-realm + `default_realm` unset → `/ui/login` (etc.) shows
    ///    a realm picker; POSTs return 400.
    ///
    /// Validated at startup: if set, the named realm MUST exist after
    /// realm reconciliation runs, else the server refuses to start.
    #[serde(default)]
    pub default_realm: Option<String>,
    /// Port for the gRPC management API. When `None` (the default), the
    /// gRPC server is not started — REST-only deployments are unaffected.
    #[serde(default)]
    pub grpc_port: Option<u16>,
    /// Optional bind address for the gRPC listener. Defaults to
    /// `bind_address` when unset.
    #[serde(default)]
    pub grpc_bind_address: Option<String>,
    /// Filesystem directory containing the admin UI's mutable static
    /// assets — currently only `app.css` (the Tailwind build output).
    ///
    /// When set, [`crate::protocol::web::serve_static`] reads
    /// `<assets_dir>/app.css` once at server startup; restarting the
    /// server picks up a fresh Tailwind build without recompiling Rust.
    /// When `None` (the default) the binary serves the copy embedded by
    /// `include_bytes!` at compile time.
    ///
    /// Path resolution: relative paths are interpreted relative to the
    /// process working directory. A typical container layout exposes
    /// `/etc/hearth/assets/` and points this at it.
    ///
    /// Other static assets (`htmx.min.js`, the Hearth SVG marks) remain
    /// truly immutable for a binary's lifetime and stay embedded.
    #[serde(default)]
    pub assets_dir: Option<PathBuf>,
    /// Trust `X-Forwarded-Proto: https` from reverse proxies listed in
    /// `trusted_proxies`.
    ///
    /// When `true`, session cookies gain the `Secure` attribute when the
    /// forwarded proto header indicates HTTPS.  Only enable when
    /// `trusted_proxies` is properly configured.
    #[serde(default)]
    pub trust_forwarded_proto: bool,
}

impl ServerConfig {
    fn default_bind_address() -> String {
        "127.0.0.1".to_string()
    }

    const fn default_port() -> u16 {
        8420
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: Self::default_bind_address(),
            port: Self::default_port(),
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
        }
    }
}

/// Background SST compaction configuration (all fields optional).
#[derive(Debug, Clone, Deserialize)]
pub struct CompactionSection {
    /// Whether automatic background compaction is enabled.
    #[serde(default = "CompactionSection::default_enabled")]
    pub enabled: bool,
    /// Seconds between periodic compaction sweeps.
    #[serde(default = "CompactionSection::default_interval_secs")]
    pub interval_secs: u64,
    /// Minimum SST files before a periodic **full** compaction is attempted.
    #[serde(default = "CompactionSection::default_min_sst_count")]
    pub min_sst_count: usize,
    /// Count trigger for **partial** (size-tiered) compaction: when the live SST
    /// count reaches this value after a flush, a partial merge is scheduled off
    /// the write path. `0` (the default) disables the trigger, leaving only the
    /// periodic full sweep — the reversible default per HEA-1885.
    #[serde(default = "CompactionSection::default_max_sst_count")]
    pub max_sst_count: usize,
    /// Minimum same-size-tier SST files a partial compaction merges at once
    /// (size-tiered fan-in). Clamped to a minimum of 2.
    #[serde(default = "CompactionSection::default_merge_min")]
    pub merge_min: usize,
}

impl Default for CompactionSection {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 3600,
            min_sst_count: 3,
            max_sst_count: 0,
            merge_min: 4,
        }
    }
}

impl CompactionSection {
    const fn default_enabled() -> bool {
        true
    }
    const fn default_interval_secs() -> u64 {
        3600
    }
    const fn default_min_sst_count() -> usize {
        3
    }
    const fn default_max_sst_count() -> usize {
        0
    }
    const fn default_merge_min() -> usize {
        4
    }
}

/// Storage engine configuration.
///
/// These values control WAL, memtable, and hot tier behavior.
/// Distinct from `storage::StorageConfig` — conversion happens in main.rs wiring.
#[derive(Debug, Clone, Deserialize)]
pub struct StorageSection {
    /// Directory for data files (WAL, SSTs).
    #[serde(default = "StorageSection::default_data_dir")]
    pub data_dir: String,
    /// Maximum WAL file size in bytes before rotation.
    #[serde(default = "StorageSection::default_wal_max_size_bytes")]
    pub wal_max_size_bytes: u64,
    /// Memtable size threshold in bytes before flush to SST.
    #[serde(default = "StorageSection::default_memtable_flush_bytes")]
    pub memtable_flush_bytes: u64,
    /// Maximum number of entries in the hot tier cache.
    /// When `None` (default), auto-sizes from system memory or
    /// `hot_tier_max_memory`. When `Some(n)`, uses this exact count,
    /// bypassing auto-sizing.
    #[serde(default)]
    pub hot_tier_capacity: Option<usize>,
    /// Hot tier memory budget in bytes. When set, overrides the
    /// system-detected memory budget used during auto-sizing.
    /// Ignored when `hot_tier_capacity` is `Some(n)`.
    #[serde(default)]
    pub hot_tier_max_memory: Option<usize>,
    /// Whether to fsync WAL writes. MUST be true in production.
    #[serde(default = "StorageSection::default_fsync")]
    pub fsync: bool,
    /// Total byte budget for the process-wide decrypted-block cache shared by
    /// all v3 SST readers (HEA-1914). Bounds decrypted cold-tier residency
    /// independent of corpus size. Default 256 MiB.
    #[serde(default = "StorageSection::default_block_cache_bytes")]
    pub block_cache_bytes: usize,
    /// Background SST compaction (all fields optional).
    #[serde(default)]
    pub compaction: CompactionSection,
}

impl StorageSection {
    /// Default on-disk data directory (WAL, SSTs) when `storage.data_dir`
    /// is not set. Exposed so dev-mode wiring can distinguish an explicit
    /// override from the default (HEA-1805).
    pub const DEFAULT_DATA_DIR: &'static str = "./data";

    fn default_data_dir() -> String {
        Self::DEFAULT_DATA_DIR.to_string()
    }

    const fn default_wal_max_size_bytes() -> u64 {
        256 * 1024 * 1024 // 256 MiB
    }

    const fn default_memtable_flush_bytes() -> u64 {
        64 * 1024 * 1024 // 64 MiB
    }

    const fn default_fsync() -> bool {
        true
    }

    const fn default_block_cache_bytes() -> usize {
        256 * 1024 * 1024 // 256 MiB
    }
}

impl Default for StorageSection {
    fn default() -> Self {
        Self {
            data_dir: Self::default_data_dir(),
            wal_max_size_bytes: Self::default_wal_max_size_bytes(),
            memtable_flush_bytes: Self::default_memtable_flush_bytes(),
            hot_tier_capacity: None,
            hot_tier_max_memory: None,
            fsync: Self::default_fsync(),
            block_cache_bytes: Self::default_block_cache_bytes(),
            compaction: CompactionSection::default(),
        }
    }
}

/// Metrics endpoint configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    /// Whether to expose the Prometheus `/metrics` HTTP endpoint.
    ///
    /// Defaults to `false` (disabled). Set to `true` to enable the endpoint;
    /// when doing so, also set `bearer_token` to protect the scrape endpoint
    /// from unauthenticated callers, or restrict access at the network layer.
    #[serde(default = "MetricsConfig::default_enabled")]
    pub enabled: bool,

    /// Optional Bearer token required to access the `/metrics` scrape endpoint (A-26).
    ///
    /// When set, requests without a matching `Authorization: Bearer <token>`
    /// header receive HTTP 401. When absent (the default), the endpoint is
    /// unauthenticated — operators SHOULD firewall it at the network layer or
    /// bind the server to a loopback / internal address.
    ///
    /// Comparison is constant-time to prevent timing-based enumeration.
    #[serde(default)]
    pub bearer_token: Option<String>,
}

impl MetricsConfig {
    const fn default_enabled() -> bool {
        false
    }
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            bearer_token: None,
        }
    }
}

/// OTLP transport protocol.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OtlpProtocol {
    /// gRPC transport (default, port 4317).
    #[default]
    Grpc,
    /// HTTP/protobuf transport (port 4318).
    Http,
}

/// OpenTelemetry OTLP export configuration.
///
/// When present under `observability.otlp`, Hearth ships spans to the
/// configured collector endpoint via gRPC or HTTP.
#[derive(Debug, Clone, Deserialize)]
pub struct OtlpConfig {
    /// Collector endpoint URL.
    ///
    /// Defaults to `http://localhost:4317` for gRPC and
    /// `http://localhost:4318` for HTTP when omitted.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Transport protocol: `grpc` (default) or `http`.
    #[serde(default)]
    pub protocol: OtlpProtocol,
    /// Additional request headers forwarded to the collector.
    ///
    /// Useful for authentication tokens required by managed collectors.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// `service.name` resource attribute reported in every span.
    #[serde(default = "OtlpConfig::default_service_name")]
    pub service_name: String,
}

impl OtlpConfig {
    fn default_service_name() -> String {
        "hearth".to_string()
    }

    /// Effective endpoint URL, substituting the protocol-specific default.
    pub fn effective_endpoint(&self) -> String {
        if let Some(ep) = &self.endpoint {
            return ep.clone();
        }
        match self.protocol {
            OtlpProtocol::Grpc => "http://localhost:4317".to_string(),
            OtlpProtocol::Http => "http://localhost:4318".to_string(),
        }
    }
}

/// Observability (logging and tracing) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ObservabilityConfig {
    /// Tracing log level filter (trace, debug, info, warn, error).
    #[serde(default = "ObservabilityConfig::default_log_level")]
    pub log_level: String,
    /// Log output format: "text" or "json".
    #[serde(default = "ObservabilityConfig::default_log_format")]
    pub log_format: String,
    /// Optional OTLP export. When absent, no spans are exported.
    #[serde(default)]
    pub otlp: Option<OtlpConfig>,
    /// Whether dev-mode pretty formatting is active. Not serialized — threaded
    /// in from [`crate::config::Config::dev_mode`] before `telemetry::init`.
    #[serde(skip)]
    pub dev_mode: bool,
}

impl ObservabilityConfig {
    fn default_log_level() -> String {
        "info".to_string()
    }

    fn default_log_format() -> String {
        "text".to_string()
    }

    /// Valid log level strings.
    pub(crate) const VALID_LOG_LEVELS: &'static [&'static str] =
        &["trace", "debug", "info", "warn", "error"];

    /// Valid log format strings.
    pub(crate) const VALID_LOG_FORMATS: &'static [&'static str] = &["text", "json"];
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            log_level: Self::default_log_level(),
            log_format: Self::default_log_format(),
            otlp: None,
            dev_mode: false,
        }
    }
}

/// Operational limits and timeouts.
#[derive(Debug, Clone, Deserialize)]
pub struct OperationalConfig {
    /// Request timeout in seconds.
    #[serde(default = "OperationalConfig::default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Graceful shutdown timeout in seconds.
    #[serde(default = "OperationalConfig::default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
    /// Maximum concurrent connections.
    #[serde(default = "OperationalConfig::default_max_connections")]
    pub max_connections: u32,
    /// Internal work queue depth.
    #[serde(default = "OperationalConfig::default_queue_depth")]
    pub queue_depth: u32,
}

impl OperationalConfig {
    const fn default_request_timeout_secs() -> u64 {
        30
    }

    const fn default_shutdown_timeout_secs() -> u64 {
        10
    }

    const fn default_max_connections() -> u32 {
        1024
    }

    const fn default_queue_depth() -> u32 {
        4096
    }
}

impl Default for OperationalConfig {
    fn default() -> Self {
        Self {
            request_timeout_secs: Self::default_request_timeout_secs(),
            shutdown_timeout_secs: Self::default_shutdown_timeout_secs(),
            max_connections: Self::default_max_connections(),
            queue_depth: Self::default_queue_depth(),
        }
    }
}

/// Email delivery transport selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailTransport {
    /// Write email contents (subject, recipient, verification URL) to the
    /// `tracing` log at WARN level. No external delivery. Default.
    #[default]
    Log,
    /// Deliver via SMTP to an external mail server. Requires an
    /// accompanying [`SmtpConfig`] block and a `from` address.
    Smtp,
    /// Deliver via the `SendGrid` v3 API. Requires a [`SendgridConfig`].
    Sendgrid,
    /// Deliver via the `Postmark` API. Requires a [`PostmarkConfig`].
    Postmark,
    /// Deliver via the `Mailgun` API. Requires a [`MailgunConfig`].
    Mailgun,
    /// Deliver via the `Mailtrap` Sending API. Requires a [`MailtrapConfig`].
    Mailtrap,
    /// Capture emails in-process and serve them via a browser UI at
    /// `/dev/mail`. Dev-only — fatal startup error when used outside
    /// `--dev` mode.
    Mailcatcher,
}

/// SMTP transport-level encryption mode.
///
/// Mirrors the semantics of `lettre::transport::smtp::client::Tls`:
///
/// - [`SmtpEncryption::None`] — cleartext SMTP (e.g. a local Mailpit
///   on `:1025`). Never use over untrusted networks.
/// - [`SmtpEncryption::Starttls`] — explicit TLS upgrade (RFC 3207) on
///   the submission port. Default; matches modern providers on :587.
/// - [`SmtpEncryption::Tls`] — implicit TLS (RFC 8314), historically
///   "SMTPS" on :465.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SmtpEncryption {
    /// Plaintext SMTP. No encryption.
    None,
    /// Explicit TLS upgrade via STARTTLS. Default.
    #[default]
    Starttls,
    /// Implicit TLS (SMTPS).
    Tls,
}

/// SMTP transport settings.
///
/// Required when [`EmailTransport::Smtp`] is selected. Credentials are
/// optional; if `username` is set then `password` MUST also be set (and
/// vice versa) — the config validator enforces the pair.
#[derive(Debug, Clone, Deserialize)]
pub struct SmtpConfig {
    /// SMTP server hostname (e.g. `smtp.example.com`, `mailpit`).
    pub host: String,
    /// SMTP server port (typically 25, 465, 587, or 1025 for Mailpit).
    pub port: u16,
    /// Transport-level encryption mode. Defaults to `starttls`.
    #[serde(default)]
    pub encryption: SmtpEncryption,
    /// SMTP AUTH username. When `Some`, `password` MUST also be `Some`.
    #[serde(default)]
    pub username: Option<String>,
    /// SMTP AUTH password. Must accompany `username`.
    #[serde(default)]
    pub password: Option<String>,
}

/// `SendGrid` transport settings.
///
/// Required when [`EmailTransport::Sendgrid`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct SendgridConfig {
    /// `SendGrid` API key.
    pub api_key: String,
}

/// `Postmark` transport settings.
///
/// Required when [`EmailTransport::Postmark`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct PostmarkConfig {
    /// `Postmark` server token.
    pub server_token: String,
}

/// `Mailgun` region selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailgunRegion {
    /// US region (default).
    #[default]
    Us,
    /// EU region.
    Eu,
}

/// `Mailgun` transport settings.
///
/// Required when [`EmailTransport::Mailgun`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct MailgunConfig {
    /// `Mailgun` API key.
    pub api_key: String,
    /// `Mailgun` sending domain (e.g. `mg.example.com`).
    pub domain: String,
    /// Region selector. Defaults to US.
    #[serde(default)]
    pub region: MailgunRegion,
}

/// `Mailtrap` transport settings.
///
/// Required when [`EmailTransport::Mailtrap`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct MailtrapConfig {
    /// `Mailtrap` API key.
    pub api_key: String,
    /// Mailtrap inbox ID for sandbox/testing mode.
    ///
    /// When set, emails are sent to the sandbox API
    /// (`sandbox.api.mailtrap.io`) instead of the sending API
    /// (`send.api.mailtrap.io`). Obtain the inbox ID from your
    /// Mailtrap dashboard URL (e.g. `https://mailtrap.io/inboxes/12345/messages`).
    pub inbox_id: Option<u64>,
}

/// Email sender configuration.
///
/// Controls how verification emails (and later, other transactional mail)
/// are delivered. Defaults to the `Log` transport, suitable for local
/// development. Production deployments should set `transport: smtp` (or
/// one of the HTTP providers) and provide the corresponding config block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EmailConfig {
    /// Which transport to use for outbound email.
    #[serde(default)]
    pub transport: EmailTransport,
    /// Sender address used in the `From:` header. Required when
    /// `transport` is not `Log`; ignored otherwise.
    #[serde(default)]
    pub from: Option<String>,
    /// SMTP-specific settings. Required when `transport == Smtp`.
    #[serde(default)]
    pub smtp: Option<SmtpConfig>,
    /// `SendGrid`-specific settings. Required when `transport == Sendgrid`.
    #[serde(default)]
    pub sendgrid: Option<SendgridConfig>,
    /// `Postmark`-specific settings. Required when `transport == Postmark`.
    #[serde(default)]
    pub postmark: Option<PostmarkConfig>,
    /// `Mailgun`-specific settings. Required when `transport == Mailgun`.
    #[serde(default)]
    pub mailgun: Option<MailgunConfig>,
    /// `Mailtrap`-specific settings. Required when `transport == Mailtrap`.
    #[serde(default)]
    pub mailtrap: Option<MailtrapConfig>,
    /// Global email branding defaults. Per-realm overrides are stored
    /// in `RealmConfig.email_branding`.
    #[serde(default)]
    pub branding: Option<EmailBranding>,
    /// Optional directory containing custom Tera email templates.
    /// If set, templates from this directory override the compiled defaults.
    #[serde(default)]
    pub templates_dir: Option<String>,
}

/// SMS delivery transport selector.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmsTransport {
    /// Write SMS body to the `tracing` log at WARN level. No external delivery. Default.
    #[default]
    Log,
    /// Deliver via the Twilio Messaging REST API.
    Twilio,
    /// Deliver via AWS SNS Transactional SMS (Signature Version 4).
    #[serde(rename = "awssns")]
    AwsSns,
}

/// Twilio SMS transport settings.
///
/// Required when [`SmsTransport::Twilio`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct TwilioConfig {
    /// Twilio Account SID (e.g. `AC…`).
    pub account_sid: String,
    /// Twilio Auth Token. Loaded from the config file but handled as a secret.
    pub auth_token: String,
    /// Twilio sender phone number in E.164 format (e.g. `+15550001111`)
    /// or a Messaging Service SID.
    pub from: String,
}

/// AWS SNS SMS transport settings.
///
/// Required when [`SmsTransport::AwsSns`] is selected.
#[derive(Debug, Clone, Deserialize)]
pub struct SnsSmsConfig {
    /// AWS region (e.g. `us-east-1`).
    pub region: String,
    /// AWS Access Key ID.
    pub access_key_id: String,
    /// AWS Secret Access Key. Loaded from the config file but handled as a secret.
    pub secret_access_key: String,
    /// Optional alphanumeric sender ID shown on recipient device (up to 11 chars).
    #[serde(default)]
    pub sender_id: Option<String>,
}

/// SMS sender configuration.
///
/// Controls how OTP and transactional SMS messages are delivered.
/// Defaults to the `Log` transport, suitable for local development.
/// Production deployments should set `transport: twilio` (or `awssns`)
/// and provide the corresponding config block.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SmsConfig {
    /// Which transport to use for outbound SMS.
    #[serde(default)]
    pub transport: SmsTransport,
    /// Twilio-specific settings. Required when `transport == Twilio`.
    #[serde(default)]
    pub twilio: Option<TwilioConfig>,
    /// AWS SNS-specific settings. Required when `transport == AwsSns`.
    #[serde(default)]
    pub aws_sns: Option<SnsSmsConfig>,
}

/// Global branding configuration.
///
/// Applies across the admin UI and email templates. When `logo_url` is
/// `None`, the built-in Hearth SVG logo is used everywhere. When
/// `product_name` is `None`, "Hearth" is used.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BrandingConfig {
    /// Product name shown in the UI (logo alt text) and email subjects.
    /// Defaults to `"Hearth"` when `None`.
    #[serde(default)]
    pub product_name: Option<String>,
    /// URL for the logo image. Applies to both the admin UI and email
    /// templates. When `None`, the built-in Hearth logo is used.
    ///
    /// For the UI, a relative path (e.g. `/ui/static/img/hearth-wide-web.svg`)
    /// is fine. For emails, an absolute URL is required — when the default
    /// logo is used, the server constructs `{base_url}/ui/static/img/hearth-wide-web.svg`.
    #[serde(default)]
    pub logo_url: Option<String>,
    /// Named UI theme. One of: `ember` (default dark), `ocean`, `midnight`,
    /// `forest`, `cloud` (light), `slate` (light). Case-insensitive.
    /// Validated at startup — an unknown name is a config error.
    #[serde(default)]
    pub theme: Option<String>,
    /// Path to a custom CSS file appended after the named theme. The file is
    /// read once at startup. It may override any `--ht-*` CSS variable or
    /// add arbitrary rules. `None` means no custom CSS.
    #[serde(default)]
    pub custom_css: Option<String>,
}

impl BrandingConfig {
    /// Returns the product name, falling back to `"Hearth"`.
    pub fn product_name_or_default(&self) -> &str {
        self.product_name.as_deref().unwrap_or("Hearth")
    }
}

/// Per-realm web branding block in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmWebYaml {
    /// Named theme override for this realm's UI sessions.
    #[serde(default)]
    pub theme: Option<String>,
    /// Path to a custom CSS file for this realm's UI sessions.
    #[serde(default)]
    pub custom_css: Option<String>,
    /// Realm-specific product name shown in titles, logo alt text, and
    /// email subjects when a request is scoped to this realm. Falls back
    /// to the global `branding.product_name` when unset. The 2026-04-30
    /// UX audit caught a realm titled "Test Corp" leaking into every
    /// other realm's pages because there was no per-realm override.
    #[serde(default)]
    pub product_name: Option<String>,
}

/// First-run onboarding configuration.
///
/// When `enabled`, Hearth generates a setup token at startup if no realm
/// exists and logs a one-time setup URL (Jenkins-style).
#[derive(Debug, Clone, Deserialize)]
pub struct OnboardingConfig {
    /// When `true`, the onboarding flow is available at `/ui/setup` until
    /// the first admin is created. Set to `false` to permanently disable.
    #[serde(default = "OnboardingConfig::default_enabled")]
    pub enabled: bool,
    /// Public base URL used in verification-email links (e.g.
    /// `https://auth.example.com`). When `None`, link generation falls
    /// back to `http://localhost`.
    #[serde(default)]
    pub base_url: Option<String>,
    /// Email address to send the first-run setup URL to on startup.
    ///
    /// When set and SMTP is configured, Hearth emails the setup URL to
    /// this address at startup (in addition to the WARN log). Useful in
    /// environments where console output is not readily accessible (e.g.
    /// Docker containers). Leave unset to rely on the log only.
    #[serde(default)]
    pub notification_email: Option<String>,
}

impl OnboardingConfig {
    const fn default_enabled() -> bool {
        true
    }
}

impl Default for OnboardingConfig {
    fn default() -> Self {
        Self {
            enabled: Self::default_enabled(),
            base_url: None,
            notification_email: None,
        }
    }
}

// ===== OIDC & Token YAML config =====

/// OIDC configuration from the `oidc:` YAML section.
///
/// Controls OIDC Discovery metadata, authorization code TTL, and nonce enforcement.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OidcYamlConfig {
    /// The issuer URL used in discovery documents and ID tokens.
    /// Must be a valid URL. Example: `"https://auth.example.com"`
    #[serde(default)]
    pub issuer: Option<String>,
    /// Authorization code TTL as a duration string (e.g. `"10m"`).
    /// Default: 10 minutes (600 seconds).
    #[serde(default)]
    pub authorization_code_ttl: Option<String>,
    /// **Removed opt-out (HEA-SEC-29).** Setting this to `false` is rejected
    /// at startup. Nonce replay protection is unconditional per OIDC Core §3.1.2.1.
    /// Remove this key from your config; `true` is silently accepted for compatibility.
    #[serde(default)]
    pub enforce_nonces: Option<bool>,
    /// **Removed opt-out (HEA-SEC-29).** Setting this to `false` is rejected
    /// at startup. PKCE is unconditional for all clients per RFC 9700 §2.1.1.
    /// Remove this key from your config; `true` is silently accepted for compatibility.
    #[serde(default)]
    pub require_pkce_for_confidential_clients: Option<bool>,
}

/// Token configuration from the `token:` YAML section.
///
/// Controls JWT issuance parameters: issuer, audience, and TTLs.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenYamlConfig {
    /// The `iss` claim value. Defaults to `oidc.issuer` when omitted.
    #[serde(default)]
    pub issuer: Option<String>,
    /// The `aud` claim value.
    #[serde(default)]
    pub audience: Option<String>,
    /// Access token TTL as a duration string (e.g. `"15m"`).
    /// Default: 15 minutes.
    #[serde(default)]
    pub access_token_ttl: Option<String>,
    /// Refresh token TTL as a duration string (e.g. `"7d"`).
    /// Default: 7 days.
    #[serde(default)]
    pub refresh_token_ttl: Option<String>,
    /// Grace period during which the old signing key remains in JWKS after
    /// rotation (e.g. `"24h"`). Default: 24 hours.
    #[serde(default)]
    pub signing_key_rotation_grace_period: Option<String>,
}

// ===== Security / rate-limiting YAML config =====

/// Global `security:` section in `hearth.yaml`.
///
/// `Debug` is hand-written (not derived) so the secret fields
/// `dpop_nonce_secret` and `key_encryption_key` are redacted — see the
/// `impl Debug` below. Any new secret field MUST be redacted there too.
#[derive(Clone, Default, Deserialize)]
pub struct SecurityYaml {
    /// Global rate-limiting thresholds (overrides compiled-in defaults).
    #[serde(default)]
    pub rate_limiting: Option<GlobalRateLimitYaml>,
    /// 32-byte HMAC secret for stateless DPoP nonce generation (RFC 9449).
    ///
    /// Accepted values:
    /// - Absent / `"auto"` (default): a fresh random key is generated at each startup.
    ///   This is secure for single-node deployments but means all outstanding DPoP
    ///   proofs are invalidated on restart.
    /// - A 64-character lowercase hex string: decoded to 32 bytes and used verbatim.
    ///   Use this to keep nonces valid across rolling restarts or in multi-node
    ///   deployments where all nodes must share the same key.
    ///
    /// **Never use the zero key `0000…` in production.** The server rejects it at startup.
    #[serde(default)]
    pub dpop_nonce_secret: Option<String>,
    /// Allowlist of `Host` header values the server accepts (A-40).
    ///
    /// Requests whose `Host` header is not in this list are rejected with
    /// 400 Bad Request.  Absent or empty = accept any host (fail-open for
    /// backward compat).  Include the port for non-standard ports
    /// (e.g. `"localhost:8420"`).
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// HTTP/2 rapid-reset defense parameters (A-39).
    #[serde(default)]
    pub http2: Http2SecurityYaml,
    /// Global per-IP + per-realm request shaper (A-2).
    #[serde(default)]
    pub request_shaper: Option<RequestShaperYaml>,
    /// **Load-test escape hatch.** When `true`, disables ALL request-rate
    /// limiters (token endpoint, admin API, export, and the per-IP/per-realm
    /// request shaper) so a single-node throughput/soak test can saturate the
    /// hot path instead of measuring the rate limiter.
    ///
    /// Refused unless the server binds a loopback address (127.0.0.0/8 or ::1)
    /// — see `main.rs`. Never enable on a production or externally-reachable
    /// bind: it removes brute-force, credential-stuffing, and abuse protection.
    /// Defaults to `false`.
    #[serde(default)]
    pub load_test_unthrottled: Option<bool>,
    /// Absolute origins permitted as `return_to` redirect targets (A-52).
    ///
    /// Relative paths (`/ui/…`) are always accepted.  Absolute URLs are only
    /// accepted when their `scheme://host[:port]` matches an entry here.
    #[serde(default)]
    pub allowed_return_to_origins: Vec<String>,
    /// IP reputation provider configuration (P-2).
    #[serde(default)]
    pub ip_reputation: IpReputationYaml,
    /// CAPTCHA provider configuration (P-1 — HEA-1202).
    #[serde(default)]
    pub captcha: Option<CaptchaYaml>,
    /// gRPC-specific security settings (A-43).
    #[serde(default)]
    pub grpc: GrpcSecurityYaml,
    /// TLS-specific security settings (A-44).
    #[serde(default)]
    pub tls: TlsSecurityYaml,
    /// Backup and export hardening (A-30).
    #[serde(default)]
    pub backup: BackupSecurityYaml,
    /// A-5: Slug names that are permanently reserved and may never be used
    /// as an organization or realm slug (case-insensitive).
    ///
    /// Operators may override this list entirely via `security.reserved_slugs`
    /// in `hearth.yaml`. Default list includes: `admin`, `api`, `support`,
    /// `www`, `mail`, `help`, `status`, `blog`, `app`, `auth`, `login`,
    /// `logout`, `signup`, `register`, `account`, `profile`, `settings`,
    /// `dashboard`, `billing`, `security`, `webhook`, `callback`, `oauth`,
    /// `oidc`, `saml`, `scim`.
    #[serde(default = "SecurityYaml::default_reserved_slugs")]
    pub reserved_slugs: Vec<String>,
    /// A-5: Days a slug is reserved after deletion before it can be reused.
    /// Default: `30`.
    #[serde(default = "SecurityYaml::default_slug_cooldown_days")]
    pub slug_cooldown_days: u32,
    /// A-10: Maximum JWKS / discovery requests per IP per second.
    ///
    /// Applies to all unauthenticated key-discovery endpoints:
    /// `/jwks`, `/certs`, `/.well-known/jwks.json`,
    /// `/realms/{name}/.well-known/jwks.json`, and
    /// `/realms/{name}/.well-known/openid-configuration`.
    /// Requests beyond this threshold receive `429 Too Many Requests` with a
    /// `Retry-After: 1` header.  Default: `60`.
    #[serde(default = "SecurityYaml::default_jwks_rps_limit")]
    pub jwks_rps_limit: u32,
    /// AES-256 key-encryption key (KEK) for protecting Ed25519 signing keys,
    /// the OIDC RSA key, SAML keys, and DPoP nonce secrets at rest in the WAL.
    ///
    /// Supply a 64-character lowercase hex string (32 bytes). The `HEARTH_KEK`
    /// environment variable takes precedence over this field. When absent, key
    /// material is stored unencrypted — suitable for dev or when the filesystem
    /// or volume is already encrypted. Existing plaintext keys continue to load
    /// transparently and are re-encrypted on the next rotation. The all-zero
    /// key `0000…` is rejected at startup.
    #[serde(default)]
    pub key_encryption_key: Option<String>,
    /// Password-hashing hardening (`security.password`).
    ///
    /// Currently carries the optional Argon2id server-side pepper. Absent =
    /// no pepper (unchanged default behaviour).
    #[serde(default)]
    pub password: PasswordSecurityYaml,
}

/// Redacts `dpop_nonce_secret` and `key_encryption_key` — both are secret key
/// material (a DPoP-nonce HMAC key and the storage KEK) and MUST NOT be
/// revealed if `SecurityYaml`, or any struct containing it, is ever
/// `{:?}`-printed (HEA-1841). Presence is preserved (`Some("[REDACTED]")`)
/// so debug output still distinguishes configured from absent.
impl std::fmt::Debug for SecurityYaml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityYaml")
            .field("rate_limiting", &self.rate_limiting)
            .field(
                "dpop_nonce_secret",
                &self.dpop_nonce_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("allowed_hosts", &self.allowed_hosts)
            .field("http2", &self.http2)
            .field("request_shaper", &self.request_shaper)
            .field("load_test_unthrottled", &self.load_test_unthrottled)
            .field("allowed_return_to_origins", &self.allowed_return_to_origins)
            .field("ip_reputation", &self.ip_reputation)
            .field("captcha", &self.captcha)
            .field("grpc", &self.grpc)
            .field("tls", &self.tls)
            .field("backup", &self.backup)
            .field("reserved_slugs", &self.reserved_slugs)
            .field("slug_cooldown_days", &self.slug_cooldown_days)
            .field("jwks_rps_limit", &self.jwks_rps_limit)
            .field(
                "key_encryption_key",
                &self.key_encryption_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("password", &self.password)
            .finish()
    }
}

/// `security.password` — password-hashing hardening.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PasswordSecurityYaml {
    /// Server-side Argon2id pepper. When present, all new password hashes are
    /// peppered via `HMAC-SHA256(key, password)` before Argon2id. Absent = no
    /// pepper is applied and `CredentialConfig::pepper` stays `None`.
    #[serde(default)]
    pub pepper: Option<PepperYaml>,
    /// Bounded admission control for the Argon2id KDF path (HEA-1887 / R1).
    ///
    /// Caps concurrent password-hash/verify operations so offered concurrency
    /// past the core count sheds (`503`) instead of oversubscribing the blocking
    /// pool and inflating p99 into the multi-second range (C9/HEA-1879).
    #[serde(default)]
    pub kdf: KdfAdmissionYaml,
}

/// `security.password.kdf` — bounded KDF admission control (HEA-1887 / R1).
///
/// The Argon2id verify/hash path runs on Tokio's blocking pool; without a bound,
/// offered concurrency oversubscribes the CPU (and, at ~19 MiB per op, memory).
/// This gate caps in-flight KDF work to `max_in_flight`, waits at most
/// `max_queue_wait_ms` for a slot, then sheds with `503`/`Retry-After`.
#[derive(Debug, Clone, Deserialize)]
pub struct KdfAdmissionYaml {
    /// Maximum concurrent Argon2id operations.
    ///
    /// `null`/absent (the default) resolves to the host **core count**
    /// ([`std::thread::available_parallelism`]) — the Little's-Law bound at
    /// which Argon2id throughput saturates. The calibrated production value is
    /// refined by the C7/HEA-1875 saturation sweep. MUST be `>= 1` when set.
    #[serde(default)]
    pub max_in_flight: Option<usize>,
    /// Maximum concurrent Argon2id operations reserved for the **admin** login
    /// gate (HEA-1892 / F2).
    ///
    /// Admin login uses a separate, small permit pool so a flood against a
    /// tenant realm's login form cannot exhaust the shared gate and lock the
    /// operator out. `null`/absent (the default) resolves to
    /// [`crate::identity::DEFAULT_ADMIN_MAX_IN_FLIGHT`]. MUST be `>= 1` when set.
    #[serde(default)]
    pub admin_max_in_flight: Option<usize>,
    /// Maximum milliseconds a request waits for a KDF permit before it is shed
    /// with `503 Service Unavailable` + `Retry-After`. Default: `250`.
    #[serde(default = "KdfAdmissionYaml::default_max_queue_wait_ms")]
    pub max_queue_wait_ms: u64,
    /// Maximum milliseconds an **admin** login waits for a permit before it is
    /// shed (HEA-1895). `null`/absent resolves to
    /// [`crate::identity::DEFAULT_ADMIN_MAX_QUEUE_WAIT_MS`] — far longer than the
    /// shared gate's `max_queue_wait_ms`, because admin login prefers queueing
    /// over shedding: its latency budget is seconds and its volume is low, so a
    /// longer wait on the tiny reserved pool denies a distributed flood the
    /// steady-state `503` it would otherwise hold the console in. MUST be `>= 1`
    /// when set.
    #[serde(default)]
    pub admin_max_queue_wait_ms: Option<u64>,
    /// `Retry-After` value (seconds) advertised on a shed response. Default: `1`.
    #[serde(default = "KdfAdmissionYaml::default_retry_after_seconds")]
    pub retry_after_seconds: u64,
}

impl Default for KdfAdmissionYaml {
    fn default() -> Self {
        Self {
            max_in_flight: None,
            admin_max_in_flight: None,
            max_queue_wait_ms: Self::default_max_queue_wait_ms(),
            admin_max_queue_wait_ms: None,
            retry_after_seconds: Self::default_retry_after_seconds(),
        }
    }
}

impl KdfAdmissionYaml {
    /// Default bounded queue-wait before shedding: 250 ms.
    const fn default_max_queue_wait_ms() -> u64 {
        250
    }

    /// Default `Retry-After` advertised on shed: 1 second.
    const fn default_retry_after_seconds() -> u64 {
        1
    }
}

/// `security.password.pepper` — server-side Argon2id pepper (A-46).
///
/// The active pepper key is applied to every new or lazily-rehashed credential.
/// The optional `previous_*` pair keeps a superseded pepper valid on login
/// during an operator-controlled rotation grace window.
#[derive(Clone, Default, Deserialize)]
pub struct PepperYaml {
    /// Active pepper version. Embedded in each new credential's
    /// `pepper_version` so rotations can be tracked and audited.
    pub version: u32,
    /// Active pepper key as a 64-character lowercase hex string (32 bytes).
    ///
    /// The all-zero key `0000…` and keys shorter than 32 bytes are rejected at
    /// startup.
    pub key_hex: String,
    /// Previous pepper version, set only while a rotation is in progress.
    ///
    /// Must be paired with `previous_key_hex`. Credentials carrying this
    /// version are accepted on login and lazily re-hashed with the active key.
    #[serde(default)]
    pub previous_version: Option<u32>,
    /// Previous pepper key (64-char lowercase hex). Required iff
    /// `previous_version` is set.
    #[serde(default)]
    pub previous_key_hex: Option<String>,
}

/// Redacts `key_hex` / `previous_key_hex` — the pepper is a secret and MUST
/// NOT be revealed if a containing config struct is ever `{:?}`-printed.
impl std::fmt::Debug for PepperYaml {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PepperYaml")
            .field("version", &self.version)
            .field("key_hex", &"[REDACTED]")
            .field("previous_version", &self.previous_version)
            .field(
                "previous_key_hex",
                &self.previous_key_hex.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl SecurityYaml {
    /// Default JWKS / discovery rate limit: 60 requests per second per IP (A-10).
    const fn default_jwks_rps_limit() -> u32 {
        60
    }

    /// Default set of permanently reserved slug names (A-5).
    fn default_reserved_slugs() -> Vec<String> {
        [
            "admin",
            "api",
            "support",
            "www",
            "mail",
            "help",
            "status",
            "blog",
            "app",
            "auth",
            "login",
            "logout",
            "signup",
            "register",
            "account",
            "profile",
            "settings",
            "dashboard",
            "billing",
            "security",
            "webhook",
            "callback",
            "oauth",
            "oidc",
            "saml",
            "scim",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    /// Default slug cooldown in days (A-5).
    const fn default_slug_cooldown_days() -> u32 {
        30
    }
}

/// `security.captcha` — CAPTCHA provider configuration (P-1 — HEA-1202).
///
/// Example:
///
/// ```yaml
/// security:
///   captcha:
///     provider: turnstile
///     turnstile:
///       site_key: "0x4AAAAAAA..."
///       secret_key: "0x4AAAAAAA..."
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct CaptchaYaml {
    /// Which CAPTCHA provider to activate.
    pub provider: CaptchaProviderKind,
    /// Cloudflare Turnstile settings (required when `provider = "turnstile"`).
    #[serde(default)]
    pub turnstile: Option<TurnstileYaml>,
}

/// Supported CAPTCHA provider identifiers.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CaptchaProviderKind {
    /// Cloudflare Turnstile (reference adapter — HEA-1202).
    Turnstile,
}

/// `security.captcha.turnstile` — Cloudflare Turnstile settings.
#[derive(Debug, Clone, Deserialize)]
pub struct TurnstileYaml {
    /// Turnstile **site key** (public — safe to embed in HTML).
    pub site_key: String,
    /// Turnstile **secret key** (private — use env-var injection in production).
    ///
    /// Prefer `HEARTH_TURNSTILE_SECRET_KEY` over embedding in the config file.
    #[serde(default)]
    pub secret_key: Option<String>,
    /// Override for the Cloudflare siteverify URL (omit in production).
    #[serde(default)]
    pub verify_url: Option<String>,
}

/// `security.backup` — backup and export hardening (A-30).
///
/// Example:
///
/// ```yaml
/// security:
///   backup:
///     verify_key: "base64url-encoded-ed25519-public-key"
///     export_rate_limit: 10
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BackupSecurityYaml {
    /// Base64url-encoded Ed25519 public key (32 bytes, URL-safe no-pad).
    ///
    /// When set, the restore handler verifies that every uploaded archive's
    /// `manifest.json` carries a `detached_signature_b64` field whose Ed25519
    /// signature (made with the corresponding private key) covers the canonical
    /// manifest bytes. Archives without a valid signature are rejected
    /// (fail-closed). When absent, signature verification is skipped.
    #[serde(default)]
    pub verify_key: Option<String>,
    /// Maximum backup/export calls per admin user per hour (A-30).
    ///
    /// Defaults to 10 when absent.  Set to `0` to disable per-export rate limiting.
    #[serde(default)]
    pub export_rate_limit: Option<u32>,
}

/// `security.ip_reputation` — IP reputation policy and provider config (P-2).
///
/// Example:
///
/// ```yaml
/// security:
///   ip_reputation:
///     enabled: true
///     action: block          # block | challenge | log (default: log)
///     spamhaus:
///       drop_url: https://www.spamhaus.org/drop/drop.txt
///       dropv6_url: https://www.spamhaus.org/drop/dropv6.txt
///       refresh_interval_secs: 86400
///     maxmind_db_path: /etc/hearth/GeoLite2-ASN.mmdb
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IpReputationYaml {
    /// Whether IP reputation checks are enabled.  Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Action to take when the provider flags an IP (block / challenge / log).
    /// Default: `"log"`.
    #[serde(default)]
    pub action: IpReputationActionYaml,
    /// Spamhaus DROP / EDROP provider settings.
    #[serde(default)]
    pub spamhaus: SpamhausDropYaml,
    /// Path to the MaxMind GeoLite2-ASN or GeoIP2-ASN MMDB file.
    ///
    /// Absent / empty = MaxMind ASN lookup disabled.
    #[serde(default)]
    pub maxmind_db_path: Option<String>,
}

/// `security.grpc` — gRPC-specific security settings (A-43).
///
/// Example:
///
/// ```yaml
/// security:
///   grpc:
///     reflection_enabled: false   # default; omit for production-safe behaviour
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GrpcSecurityYaml {
    /// Whether the gRPC server reflection service is enabled.
    ///
    /// `null` / absent → `false` in production, `true` under `--dev`.
    /// Setting this to `true` in production requires the `--allow-reflection-in-prod`
    /// CLI flag; the server refuses to start without it.
    ///
    /// gRPC reflection exposes the full API schema to any unauthenticated caller.
    /// Keep it off in production.
    #[serde(default)]
    pub reflection_enabled: Option<bool>,
}

/// Minimum TLS protocol version the server will accept (HEA-SEC-33).
///
/// Restricting to TLS 1.3 eliminates downgrade-attack surface present in TLS 1.2
/// (POODLE, BEAST, ROBOT). Recommended for high-security deployments where all
/// clients are known to support TLS 1.3.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub enum TlsMinVersionYaml {
    /// Accept TLS 1.2 and TLS 1.3 (default). Broadest client compatibility.
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    /// Accept TLS 1.3 only. Recommended for high-security deployments.
    #[serde(rename = "1.3")]
    Tls13,
}

/// `security.tls` — TLS-specific security settings (A-44).
///
/// Example:
///
/// ```yaml
/// security:
///   tls:
///     min_version: "1.3"
///     crl_paths:
///       - /etc/hearth/crl/client-ca.crl.pem
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TlsSecurityYaml {
    /// Minimum TLS protocol version to accept.
    ///
    /// - `"1.2"` (default): accept TLS 1.2 and TLS 1.3.
    /// - `"1.3"`: TLS 1.3 only — TLS 1.2 connections are rejected at the handshake.
    ///   Recommended for high-security deployments where all clients support TLS 1.3.
    #[serde(default)]
    pub min_version: TlsMinVersionYaml,
    /// Paths to PEM-encoded Certificate Revocation List (CRL) files for mTLS.
    ///
    /// When non-empty, mTLS client certificates are checked against every CRL in
    /// the list on each handshake. Revoked certificates are rejected with a
    /// TLS alert.  Paths are reloaded on `SIGHUP` alongside the server certificate.
    ///
    /// If empty (the default), no revocation check is performed — existing mTLS
    /// behaviour is preserved.
    #[serde(default)]
    pub crl_paths: Vec<PathBuf>,
}

/// Action taken when IP reputation flags an IP.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpReputationActionYaml {
    /// Reject the request with HTTP 403.
    Block,
    /// Return a challenge response (A-16 CAPTCHA-of-last-resort).
    Challenge,
    /// Allow but record the signal (default, fail-open posture).
    #[default]
    Log,
}

/// `security.ip_reputation.spamhaus` — Spamhaus DROP/EDROP refresh settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SpamhausDropYaml {
    /// URL for the Spamhaus DROP (IPv4) list.
    #[serde(default = "SpamhausDropYaml::default_drop_url")]
    pub drop_url: String,
    /// URL for the Spamhaus EDROP (IPv6) list.
    #[serde(default = "SpamhausDropYaml::default_dropv6_url")]
    pub dropv6_url: String,
    /// Refresh interval in seconds.  Default: 86 400 (24 hours).
    #[serde(default = "SpamhausDropYaml::default_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
}

impl SpamhausDropYaml {
    fn default_drop_url() -> String {
        "https://www.spamhaus.org/drop/drop.txt".into()
    }
    fn default_dropv6_url() -> String {
        "https://www.spamhaus.org/drop/dropv6.txt".into()
    }
    fn default_refresh_interval_secs() -> u64 {
        86_400
    }
}

impl Default for SpamhausDropYaml {
    fn default() -> Self {
        Self {
            drop_url: Self::default_drop_url(),
            dropv6_url: Self::default_dropv6_url(),
            refresh_interval_secs: Self::default_refresh_interval_secs(),
        }
    }
}

/// `security.http2` — HTTP/2 rapid-reset defense (A-39, CVE-2023-44487).
#[derive(Debug, Clone, Deserialize)]
pub struct Http2SecurityYaml {
    /// Maximum concurrent HTTP/2 streams per connection.  Default: 100.
    #[serde(default = "Http2SecurityYaml::default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    /// Maximum number of pending RST_STREAM frames (rapid-reset budget).
    /// Default: 10.
    #[serde(default = "Http2SecurityYaml::default_max_pending_reset_streams")]
    pub max_pending_reset_streams: usize,
}

impl Http2SecurityYaml {
    fn default_max_concurrent_streams() -> u32 {
        100
    }
    fn default_max_pending_reset_streams() -> usize {
        10
    }
}

impl Default for Http2SecurityYaml {
    fn default() -> Self {
        Self {
            max_concurrent_streams: Self::default_max_concurrent_streams(),
            max_pending_reset_streams: Self::default_max_pending_reset_streams(),
        }
    }
}

/// `security.request_shaper` — global per-IP + per-realm rate limiter (A-2).
#[derive(Debug, Clone, Deserialize)]
pub struct RequestShaperYaml {
    /// Maximum requests per second per source IP.  Default: 100.
    #[serde(default = "RequestShaperYaml::default_ip_rps")]
    pub ip_rps: u32,
    /// Maximum requests per second per realm.  Default: 1000.
    #[serde(default = "RequestShaperYaml::default_realm_rps")]
    pub realm_rps: u32,
}

impl RequestShaperYaml {
    fn default_ip_rps() -> u32 {
        100
    }
    fn default_realm_rps() -> u32 {
        1_000
    }
}

/// `security.rate_limiting` — operator-tunable per-IP and per-account thresholds.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct GlobalRateLimitYaml {
    /// Per-IP failed-login rate limit (credential-stuffing protection).
    #[serde(default)]
    pub login_per_ip: Option<IpRateLimitYaml>,
    /// Per-account consecutive-failure lockout.
    #[serde(default)]
    pub login_per_account: Option<AccountRateLimitYaml>,
}

/// Per-IP rate limit config: sliding window of failed attempts.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IpRateLimitYaml {
    /// Maximum failed attempts in the window before the IP is blocked. Default: 10.
    #[serde(default)]
    pub max_attempts: Option<u32>,
    /// Window length in seconds. Default: 60.
    #[serde(default)]
    pub window_seconds: Option<u64>,
}

/// Per-account lockout config: consecutive failures trigger a timed lockout.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AccountRateLimitYaml {
    /// Maximum consecutive failures before lockout. Default: 5.
    #[serde(default)]
    pub max_failures: Option<u32>,
    /// Lockout duration in seconds. Default: 300 (5 minutes).
    #[serde(default)]
    pub lockout_seconds: Option<u64>,
}

// ===== Auth & Realm YAML config =====

/// Global authentication defaults in the `auth:` section.
///
/// These apply to all realms unless overridden per-realm in the `realms:` map.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// Default session TTL as a human-readable duration (e.g. "24h", "30m").
    #[serde(default)]
    pub session_ttl: Option<String>,
    /// Argon2id memory cost in KiB.
    #[serde(default)]
    pub password_memory_cost: Option<u32>,
    /// Argon2id time cost (iterations).
    #[serde(default)]
    pub password_time_cost: Option<u32>,
    /// Whether MFA is required for all users (global default).
    /// Per-realm `auth.mfa_required` overrides this.
    #[serde(default)]
    pub mfa_required: Option<bool>,
    /// Whether passkey login still requires a TOTP challenge (global default).
    /// Per-realm `auth.passkey_requires_mfa` overrides this.
    #[serde(default)]
    pub passkey_requires_mfa: Option<bool>,
    /// Global default maximum concurrent sessions per user.
    /// Per-realm overrides via `realms.<name>.session_max_concurrent`.
    #[serde(default)]
    pub session_max_concurrent: Option<u32>,
    /// Global default over-limit policy: `"reject_new"` (default) or `"evict_oldest"`.
    ///
    /// An unrecognised value is a hard error at config parse time.
    #[serde(default)]
    pub session_over_limit_policy: Option<String>,
}

/// Per-realm auth policy configuration in YAML.
///
/// These are policy declarations: the config layer stores them in `RealmConfig`,
/// but enforcement (checking MFA on login, validating password complexity, applying
/// rate limits) is a separate concern in the identity engine.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmAuthYaml {
    /// Whether MFA is required for all users in this realm.
    #[serde(default)]
    pub mfa_required: Option<bool>,
    /// Allowed MFA methods (e.g. `["totp", "webauthn"]`).
    #[serde(default)]
    pub mfa_methods: Option<Vec<String>>,
    /// Allowed authentication methods (e.g. `["password", "magic_link", "passkey"]`).
    #[serde(default)]
    pub allowed_auth_methods: Option<Vec<String>>,
    /// Password complexity requirements.
    #[serde(default)]
    pub password_policy: Option<PasswordPolicyYaml>,
    /// Per-realm token TTL overrides.
    #[serde(default)]
    pub token: Option<RealmTokenYaml>,
    /// Whether to enforce TOTP MFA even after passkey authentication.
    /// Passkeys are inherently multi-factor, but regulated environments
    /// may require an additional TOTP challenge. Defaults to `false`.
    #[serde(default)]
    pub passkey_requires_mfa: Option<bool>,
    /// Per-realm rate limit overrides.
    #[serde(default)]
    pub rate_limit: Option<RateLimitYaml>,
    /// Controls who may self-register. Defaults to `disabled` when absent.
    #[serde(default)]
    pub registration: Option<RegistrationPolicyYaml>,
    /// Controls dynamic client registration (RFC 7591). Defaults to `disabled` when absent.
    #[serde(default)]
    pub dcr: Option<DcrPolicyYaml>,
    /// WebAuthn attestation policy for this realm (A-13).
    ///
    /// Absent = no restrictions (fail-open per §6.1 of the abuse plan).
    #[serde(default)]
    pub webauthn_attestation: Option<WebAuthnAttestationYaml>,
}

/// WebAuthn attestation policy in YAML (`realms.<name>.auth.webauthn_attestation`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WebAuthnAttestationYaml {
    /// Whether attestation format `"none"` is allowed (default: `true`).
    #[serde(default = "WebAuthnAttestationYaml::default_allow_none")]
    pub allow_none: bool,
    /// AAGUID allowlist (lowercase UUID format). Empty = any AAGUID accepted.
    #[serde(default)]
    pub aaguid_allowlist: Vec<String>,
    /// Require PRF extension (default: `false`).
    #[serde(default)]
    pub require_prf: bool,
    /// Require `largeBlob` extension (default: `false`).
    #[serde(default)]
    pub require_large_blob: bool,
}

impl WebAuthnAttestationYaml {
    fn default_allow_none() -> bool {
        true
    }

    /// Projects the YAML declaration into the engine-level policy struct.
    pub(crate) fn to_domain(&self) -> crate::identity::WebAuthnAttestationPolicy {
        crate::identity::WebAuthnAttestationPolicy {
            allow_none: self.allow_none,
            aaguid_allowlist: self.aaguid_allowlist.clone(),
            require_prf: self.require_prf,
            require_large_blob: self.require_large_blob,
        }
    }
}

/// Self-service registration policy in YAML.
///
/// `mode` is one of: `disabled`, `open`, `invite_only`, `domain_restricted`.
/// When `mode = domain_restricted`, `allowed_domains` lists the permitted
/// email domains (case-insensitive).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistrationPolicyYaml {
    /// One of `disabled` (default), `open`, `invite_only`, `domain_restricted`.
    #[serde(default)]
    pub mode: RegistrationModeYaml,
    /// Required when `mode = domain_restricted`. Ignored otherwise.
    #[serde(default)]
    pub allowed_domains: Option<Vec<String>>,
}

/// Valid values for `realms.<name>.auth.registration.mode` in YAML.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationModeYaml {
    /// No public signup; only admins create users.
    #[default]
    Disabled,
    /// Anyone may register.
    Open,
    /// Must present a valid organization invitation.
    InviteOnly,
    /// Email domain must be in `allowed_domains`.
    DomainRestricted,
}

impl RegistrationPolicyYaml {
    /// Projects the YAML declaration into the engine-level enum.
    ///
    /// An ill-formed combination (e.g. `mode = domain_restricted` with an
    /// empty `allowed_domains`) collapses to an empty allow-list, which the
    /// engine correctly rejects as "no domain matches". Validation in
    /// `src/config/mod.rs` surfaces these cases to the operator at startup.
    pub(crate) fn to_domain(&self) -> crate::identity::RegistrationPolicy {
        match self.mode {
            RegistrationModeYaml::Disabled => crate::identity::RegistrationPolicy::Disabled,
            RegistrationModeYaml::Open => crate::identity::RegistrationPolicy::Open,
            RegistrationModeYaml::InviteOnly => crate::identity::RegistrationPolicy::InviteOnly,
            RegistrationModeYaml::DomainRestricted => {
                crate::identity::RegistrationPolicy::DomainRestricted(
                    self.allowed_domains.clone().unwrap_or_default(),
                )
            }
        }
    }
}

/// Dynamic Client Registration policy in YAML.
///
/// Controls whether OAuth clients may self-register via `POST /register`
/// (RFC 7591). Defaults to `disabled` when absent.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DcrPolicyYaml {
    /// One of `disabled` (default) or `open`.
    #[serde(default)]
    pub mode: DcrModeYaml,
}

/// Valid values for `realms.<name>.auth.dcr.mode` in YAML.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcrModeYaml {
    /// Dynamic client registration is disabled. Only admins may create clients.
    #[default]
    Disabled,
    /// Any caller may register an OAuth client via `POST /register`.
    /// Unauthenticated — only suitable for developer sandboxes.
    Open,
    /// DCR requires a valid bearer token (RFC 7591 §3.1 initial access token).
    Authenticated,
}

impl DcrPolicyYaml {
    /// Projects the YAML declaration into the engine-level enum.
    pub(crate) fn to_domain(&self) -> crate::identity::DcrPolicy {
        match self.mode {
            DcrModeYaml::Disabled => crate::identity::DcrPolicy::Disabled,
            DcrModeYaml::Open => crate::identity::DcrPolicy::Open,
            DcrModeYaml::Authenticated => crate::identity::DcrPolicy::Authenticated,
        }
    }
}

/// Password complexity policy in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PasswordPolicyYaml {
    /// Minimum password length. Must be >= 1.
    #[serde(default)]
    pub min_length: Option<usize>,
    /// Require at least one uppercase letter.
    #[serde(default)]
    pub require_uppercase: Option<bool>,
    /// Require at least one digit.
    #[serde(default)]
    pub require_number: Option<bool>,
    /// Require at least one special character.
    #[serde(default)]
    pub require_special: Option<bool>,
    /// Password must not contain or equal the user's display name.
    #[serde(default)]
    pub not_username: Option<bool>,
    /// Password must not contain or equal the user's email address.
    #[serde(default)]
    pub not_email: Option<bool>,
    /// Number of previous passwords to remember; reuse is rejected.
    #[serde(default)]
    pub history_depth: Option<usize>,
    /// Maximum password age in days before the user must reset.
    #[serde(default)]
    pub max_age_days: Option<u32>,
}

/// Per-realm token TTL overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmTokenYaml {
    /// Access token TTL as a duration string (e.g. `"15m"`).
    #[serde(default)]
    pub access_token_ttl: Option<String>,
    /// Refresh token TTL as a duration string (e.g. `"7d"`).
    #[serde(default)]
    pub refresh_token_ttl: Option<String>,
    /// Password reset token TTL as a duration string (e.g. `"30m"`).
    /// Defaults to 30 minutes when absent. Hard-capped at 1 hour (A-14).
    #[serde(default)]
    pub password_reset_token_ttl: Option<String>,
    /// Magic link token TTL as a duration string (e.g. `"15m"`).
    /// Defaults to 15 minutes when absent. Hard-capped at 30 minutes (A-14).
    #[serde(default)]
    pub magic_link_ttl: Option<String>,
    /// Lift A-14 TTL hard caps for this realm.
    ///
    /// When `true`, `password_reset_token_ttl` may exceed 1 hour and
    /// `magic_link_ttl` may exceed 30 minutes. Operators accept the
    /// additional token-theft window by enabling this flag.
    #[serde(default)]
    pub allow_unsafe_ttl: bool,
    /// Device authorization code TTL as a duration string (e.g. `"10m"`).
    /// Defaults to 10 minutes when absent. Hard-capped at 30 minutes unless
    /// `allow_unsafe_ttl` is set (HSEC-008).
    #[serde(default)]
    pub device_code_ttl: Option<String>,
}

/// Per-realm rate limit overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RateLimitYaml {
    /// Maximum failed login attempts before lockout.
    #[serde(default)]
    pub max_failed_logins: Option<u32>,
    /// Lockout duration as a duration string (e.g. `"15m"`).
    #[serde(default)]
    pub lockout_duration: Option<String>,
}

/// Data type hint for a custom attribute value.
///
/// All values are stored as UTF-8 strings. The type is used by the admin UI
/// to render appropriate inputs and perform lightweight format validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributeTypeYaml {
    /// Stored and returned as a UTF-8 string (default).
    #[default]
    String,
    /// Stored as a UTF-8 string; the admin UI renders a number input.
    Number,
    /// Stored as `"true"` or `"false"`; the admin UI renders a checkbox.
    Boolean,
    /// One of a fixed set of values declared in `enum_values`; the admin UI
    /// renders a `<select>`.
    Enum,
}

/// A single custom attribute definition declared in YAML.
///
/// Attribute definitions are declared under
/// `realms.<name>.attribute_definitions.users` or
/// `realms.<name>.attribute_definitions.organizations`.
#[derive(Debug, Clone, Deserialize)]
pub struct AttributeDefinitionYaml {
    /// Machine-readable key used as the storage key in the attribute map.
    pub key: String,
    /// Human-readable label shown in the admin UI. Defaults to `key`.
    #[serde(default)]
    pub label: Option<String>,
    /// Data type hint for the admin UI and basic format validation.
    #[serde(default, rename = "type")]
    pub type_: AttributeTypeYaml,
    /// When `true`, the attribute must be present on record creation.
    #[serde(default)]
    pub required: bool,
    /// Short description shown as a placeholder or tooltip in the admin UI.
    #[serde(default)]
    pub description: Option<String>,
    /// Allowed values when `type: enum`. Ignored for other types.
    #[serde(default)]
    pub enum_values: Vec<String>,
}

/// Per-entity attribute definition groups declared in YAML.
///
/// Declared under `realms.<name>.attribute_definitions:`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AttributeDefinitionsYaml {
    /// Attribute definitions for user records.
    #[serde(default)]
    pub users: Vec<AttributeDefinitionYaml>,
    /// Attribute definitions for organization records.
    #[serde(default)]
    pub organizations: Vec<AttributeDefinitionYaml>,
}

/// YAML declaration for an organization within a realm.
///
/// Organizations declared under `realms.<name>.organizations:` are reconciled
/// with storage at startup: created if missing, updated if changed.
/// Members and invitations are runtime-only — not managed via YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationYamlConfig {
    /// Human-readable organization name.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional configuration overrides.
    #[serde(default)]
    pub config: Option<OrgConfigYaml>,
}

/// Organization configuration overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OrgConfigYaml {
    /// Maximum number of members allowed. `None` means unlimited.
    #[serde(default)]
    pub max_members: Option<u32>,
}

/// YAML declaration for an OAuth 2.0 application (client).
///
/// Applications declared under `realms.<name>.applications:` are reconciled
/// with storage at startup: created if missing, updated if changed, archived
/// if removed from the YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct ApplicationYamlConfig {
    /// Human-readable application name.
    pub name: String,
    /// Allowed OAuth 2.0 redirect URIs.
    #[serde(default)]
    pub redirect_uris: Option<Vec<String>>,
    /// Allowed OAuth 2.0 grant types (e.g. `["authorization_code", "client_credentials"]`).
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    /// Whether this is a confidential client (has a client secret).
    /// Defaults to `false` (public client).
    #[serde(default)]
    pub confidential: Option<bool>,
    /// Client secret. Supports `${ENV_VAR}` substitution.
    /// Required when `confidential: true`. Hashed with Argon2id before storage.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Whether this client is trusted to skip the OAuth consent screen.
    ///
    /// `None` (the default) or `Some(true)` keeps the standard
    /// prompt-before-code behaviour. `Some(false)` marks the client as
    /// trusted / first-party — users will be redirected directly to the
    /// `redirect_uri` without a consent prompt on first authorization.
    /// Only set this for clients where the user's consent is already
    /// implicit (e.g. first-party SSO inside an enterprise realm).
    #[serde(default)]
    pub require_consent: Option<bool>,
    /// URL to a logo displayed on the consent screen. Optional.
    #[serde(default)]
    pub client_logo_url: Option<String>,
    /// Stable slug used by YAML references and mapper gates.
    #[serde(default)]
    pub slug: Option<String>,
    /// Authz trust posture for this client.
    #[serde(default)]
    pub trust_level: Option<ClientTrustLevel>,
    /// Scopes this client may request.
    #[serde(default)]
    pub declared_scopes: Option<Vec<String>>,
    /// Whether a realm-level consent row covers all org contexts.
    #[serde(default)]
    pub consent_spans_orgs: Option<bool>,
    /// FAPI 2.0 Security Profile for this client.
    ///
    /// Accepted values: `"fapi2"`. Absent means standard profile.
    /// Setting this flag subjects the client to FAPI 2.0 constraints
    /// (DPoP, PAR, PKCE S256) regardless of the realm-level `fapi_profile`.
    #[serde(default)]
    pub profile: Option<String>,
}

/// YAML permission definition.
#[derive(Debug, Clone, Deserialize)]
pub struct PermissionYamlConfig {
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
}

/// YAML role definition.
#[derive(Debug, Clone, Deserialize)]
pub struct RoleYamlConfig {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default)]
    pub scope_kind: Option<String>,
}

/// YAML scope-bundle definition.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeBundleYamlConfig {
    pub name: String,
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// YAML protected-resource registration.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedResourceYamlConfig {
    pub resource_uri: String,
    pub display_name: String,
    #[serde(default)]
    pub scopes: Vec<ScopeBundleYamlConfig>,
}

/// YAML claim-profile wrapper.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ClaimsYamlConfig {
    #[serde(default)]
    pub mappings: Vec<ClaimMapping>,
}

/// Per-realm email branding overrides in YAML.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmEmailYaml {
    /// Email branding overrides.
    #[serde(default)]
    pub branding: Option<EmailBranding>,
}

/// YAML group declaration in a realm config block.
#[derive(Debug, Clone, Deserialize)]
pub struct GroupYamlConfig {
    pub name: String,
    #[serde(default)]
    pub slug: Option<String>,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Conflict-handling policy when migrating users between realms.
///
/// Determines what happens when a user with the same email already exists
/// in the destination realm.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MigrateConflictPolicy {
    /// Collect all conflicts and fail startup with the full list. Default.
    #[default]
    Error,
    /// Leave conflicting users in the source realm as orphans and continue.
    Skip,
}

/// Options for the `migrate:` sub-block inside a destination realm's YAML.
///
/// Controls which data categories are included in the migration and how
/// conflicts are handled. All fields have production-safe defaults.
#[derive(Debug, Clone, Deserialize)]
pub struct RealmMigrateYaml {
    /// Whether to migrate user records and credentials. Default: `true`.
    #[serde(default = "default_true")]
    pub users: bool,
    /// Whether to migrate org memberships for migrated users. Default: `true`.
    #[serde(default = "default_true")]
    pub orgs: bool,
    /// Whether to migrate OAuth applications (clients). Default: `false`.
    #[serde(default)]
    pub applications: bool,
    /// What to do when a user with the same email already exists in the
    /// destination realm. Default: `error` (fail startup with conflict list).
    #[serde(default)]
    pub on_conflict: MigrateConflictPolicy,
}

impl Default for RealmMigrateYaml {
    fn default() -> Self {
        Self {
            users: true,
            orgs: true,
            applications: false,
            on_conflict: MigrateConflictPolicy::default(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// A single seed user declared under `realms.<name>.seed_users`.
///
/// Seed users are created at startup if they do not already exist.
/// Reconciliation is additive-only — existing accounts are never deleted or
/// modified by the reconciler.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedUserYamlConfig {
    /// Email address for the user (unique within the realm).
    pub email: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Initial plaintext password. Stored as an Argon2id hash at startup.
    pub password: String,
    /// Role names to assign at creation time. Must match roles declared in
    /// `roles:` or default RBAC seeds for this realm.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Whether the email address is pre-verified. Defaults to `true`; when
    /// `true` the user is activated immediately without an email verification
    /// step. Set to `false` to leave the user in `PendingVerification`.
    #[serde(default = "SeedUserYamlConfig::default_email_verified")]
    pub email_verified: bool,
}

impl SeedUserYamlConfig {
    const fn default_email_verified() -> bool {
        true
    }
}

/// Top-level demo-mode configuration (`demo:` block).
///
/// Gates the large-scale demo seeder driven by per-realm [`SeedingYamlConfig`]
/// blocks. When `enabled` is `false` — the default — the seeder is never
/// invoked. A production config simply omits this block, so the mass seeder
/// physically cannot run against real data.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct DemoConfig {
    /// Master switch. Must be `true` for any per-realm `seeding:` block to run.
    #[serde(default)]
    pub enabled: bool,
    /// Password shared by every seeded user across all realms. When omitted, a
    /// built-in default ([`DemoConfig::DEFAULT_PASSWORD`]) is used. It is hashed
    /// once and the resulting hash is reused for every account, so all demo
    /// users authenticate with this single value.
    #[serde(default)]
    pub password: Option<String>,
}

impl DemoConfig {
    /// Default password applied to seeded users when `password` is unset.
    pub const DEFAULT_PASSWORD: &'static str = "DemoPassw0rd!";

    /// Returns the configured shared password, or the built-in default.
    #[must_use]
    pub fn password_or_default(&self) -> &str {
        self.password.as_deref().unwrap_or(Self::DEFAULT_PASSWORD)
    }
}

/// Per-realm large-scale seeding directive (`realms.<name>.seeding`).
///
/// Only honored when the top-level [`DemoConfig::enabled`] is `true`. The seeder
/// inserts `users` synthetic, pre-activated accounts
/// (`user0000001@<domain>`, `user0000002@<domain>`, …) that all share the demo
/// password. It is additive and resumable: a per-realm sentinel records how many
/// users have been seeded, so re-running only creates the delta and never
/// modifies or deletes existing accounts. Cross-realm distribution is simply
/// whichever `users` counts the operator sets per realm.
#[derive(Debug, Clone, Deserialize)]
pub struct SeedingYamlConfig {
    /// Target number of synthetic users for this realm.
    pub users: u64,
    /// Email domain for generated addresses (`user0000001@<email_domain>`).
    /// Defaults to `"<realm-name>.demo"` when omitted.
    #[serde(default)]
    pub email_domain: Option<String>,
    /// Display-name prefix (`"<prefix> 1"`, `"<prefix> 2"`, …).
    /// Defaults to `"Demo User"`.
    #[serde(default)]
    pub display_name_prefix: Option<String>,
    /// Whether generated accounts are pre-verified and immediately Active.
    /// Defaults to `true`.
    #[serde(default)]
    pub email_verified: Option<bool>,
}

/// Per-realm YAML configuration block.
///
/// Fields are optional — `None` inherits from global `auth:` defaults.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmYamlConfig {
    /// Session TTL override (e.g. "12h").
    #[serde(default)]
    pub session_ttl: Option<String>,
    /// Maximum concurrent sessions per user for this realm.
    /// Overrides global `auth.session_max_concurrent`. `None` = unlimited.
    #[serde(default)]
    pub session_max_concurrent: Option<u32>,
    /// Over-limit policy for this realm: `"reject_new"` (default) or `"evict_oldest"`.
    /// Overrides global `auth.session_over_limit_policy`. An unrecognised value is
    /// a hard error at config parse time.
    #[serde(default)]
    pub session_over_limit_policy: Option<String>,
    /// Argon2id memory cost override.
    #[serde(default)]
    pub password_memory_cost: Option<u32>,
    /// Argon2id time cost override.
    #[serde(default)]
    pub password_time_cost: Option<u32>,
    /// Per-realm email overrides.
    #[serde(default)]
    pub email: Option<RealmEmailYaml>,
    /// Per-realm web / UI branding overrides.
    #[serde(default)]
    pub web: Option<RealmWebYaml>,
    /// Per-realm auth policy overrides (MFA, password policy, rate limits, token TTLs).
    #[serde(default)]
    pub auth: Option<RealmAuthYaml>,
    /// SCIM 2.0 provisioning settings for this realm.
    #[serde(default)]
    pub scim: Option<RealmScimYaml>,
    /// Declarative OAuth 2.0 application (client) definitions.
    /// Reconciled with storage at startup.
    #[serde(default)]
    pub applications: Option<std::collections::HashMap<String, ApplicationYamlConfig>>,
    /// Declarative organization definitions.
    /// Reconciled with storage at startup. Members/invitations are runtime-only.
    #[serde(default)]
    pub organizations: Option<std::collections::HashMap<String, OrganizationYamlConfig>>,
    /// External IdP federation: per-realm connector definitions + account-
    /// linking policy. Reconciled with storage at startup; runtime-registered
    /// connectors not represented in YAML are removed.
    #[serde(default)]
    pub federation: Option<FederationYamlConfig>,
    /// SAML 2.0 Service Provider registrations (IdP side — Hearth as IdP).
    /// Reconciled at startup; runtime SPs not represented here are removed.
    #[serde(default)]
    pub saml_service_providers: Option<std::collections::HashMap<String, SamlServiceProviderYaml>>,
    /// YAML-authored permission registry.
    #[serde(default)]
    pub permissions: Option<Vec<PermissionYamlConfig>>,
    /// YAML-authored RBAC roles.
    #[serde(default)]
    pub roles: Option<Vec<RoleYamlConfig>>,
    /// Optional realm-level scope bundles.
    #[serde(default)]
    pub scopes: Option<Vec<ScopeBundleYamlConfig>>,
    /// Optional protected-resource registrations with resource-local scopes.
    #[serde(default)]
    pub protected_resources: Option<Vec<ProtectedResourceYamlConfig>>,
    /// Optional claim-profile overrides.
    #[serde(default)]
    pub claims: Option<ClaimsYamlConfig>,
    /// Alias for `applications` matching AUTHZ_EXPANSION terminology.
    #[serde(default)]
    pub oauth_clients: Option<std::collections::HashMap<String, ApplicationYamlConfig>>,
    /// Optional groups declared for this realm.
    #[serde(default)]
    pub groups: Option<Vec<GroupYamlConfig>>,
    /// When set, declares that this realm is the migration destination for the
    /// named archived realm slug.  The orphan-detection pass treats the named
    /// slug as resolved and suppresses its warning banner.  If `copy_from` is
    /// used instead, the source realm is NOT archived after migration.
    #[serde(default)]
    pub migrate_from: Option<String>,
    /// Like `migrate_from` but with copy semantics: the source realm is left
    /// intact after users are copied to this destination.
    #[serde(default)]
    pub copy_from: Option<String>,
    /// Fine-grained migration options. Only meaningful when `migrate_from` or
    /// `copy_from` is set. Defaults apply when the block is absent.
    #[serde(default)]
    pub migrate: Option<RealmMigrateYaml>,
    /// Custom attribute definitions for users and organizations in this realm.
    ///
    /// When set, only the declared keys are accepted on create/update; unknown
    /// keys are rejected. When absent, any key is accepted (free-form mode).
    #[serde(default)]
    pub attribute_definitions: Option<AttributeDefinitionsYaml>,
    /// When `true` and the realm slug is re-added to the `realms:` map, the
    /// reconciler skips unarchiving it and the orphan-detection pass treats
    /// the slug as intentionally discarded (suppresses the warning banner).
    /// Has no effect on active realms.
    #[serde(default)]
    pub archive_drop: Option<bool>,
    /// One-shot signing key rotation trigger.
    ///
    /// When `true`, the server generates a new Ed25519 key for this realm,
    /// serves both the old and new keys in JWKS during the grace period, and
    /// records the flag as consumed so the next restart does not re-rotate.
    /// Operators may also call `POST /admin/realms/{id}/rotate-signing-key`
    /// instead of setting this flag.
    #[serde(default)]
    pub rotate_signing_key: Option<bool>,
    /// FAPI 2.0 Security Profile enforcement for this realm.
    ///
    /// Accepted values: `"baseline"` (PAR + PKCE required for all clients),
    /// `"advanced"` (Baseline + JAR + JARM required). Absent or `null` means
    /// standard OAuth 2.0 / OIDC rules apply with no FAPI constraints.
    #[serde(default)]
    pub fapi_profile: Option<String>,
    /// Declarative seed users for this realm.
    ///
    /// Each entry is created at startup if the email does not already exist.
    /// Additive-only: the reconciler never deletes or modifies existing users.
    #[serde(default)]
    pub seed_users: Option<Vec<SeedUserYamlConfig>>,
    /// Large-scale demo seeding directive. Only honored when the top-level
    /// `demo.enabled` is `true`. See [`SeedingYamlConfig`].
    #[serde(default)]
    pub seeding: Option<SeedingYamlConfig>,
    /// Per-realm tool-group registry (Phase C).
    ///
    /// Declares named groups and the tools that belong to each group. Used to
    /// resolve `toolgroup.{name}.{action}` permissions in the tool-invocation
    /// gate. When absent, no tool groups are configured for this realm.
    #[serde(default)]
    pub tool_registry: Option<ToolRegistryYamlConfig>,
}

/// YAML for `realms.{name}.tool_registry.*`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ToolRegistryYamlConfig {
    /// Maps group name → list of tool names.
    ///
    /// Each entry declares a named group containing one or more tool identifiers.
    /// Agents with `toolgroup.{name}.invoke` (or `.deny` / `.invoke_with_approval`)
    /// in their permissions get those permissions applied to every tool in the group.
    #[serde(default)]
    pub groups: std::collections::HashMap<String, Vec<String>>,
}

/// YAML for `realms.{name}.scim.*`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RealmScimYaml {
    /// Static bearer token accepted by `/scim/v2/*` for this realm.
    ///
    /// Supports `${ENV_VAR}` substitution. The plaintext token is hashed
    /// before it is persisted into the runtime realm config.
    #[serde(default)]
    pub bearer_token: Option<String>,
}

/// YAML for a single SAML SP registration (Hearth as IdP issues to this SP).
#[derive(Debug, Clone, Deserialize)]
pub struct SamlServiceProviderYaml {
    pub entity_id: String,
    pub acs_url: String,
    #[serde(default)]
    pub slo_url: Option<String>,
    #[serde(default)]
    pub sp_certificate_pem: Option<String>,
    #[serde(default)]
    pub sign_assertions: Option<bool>,
    #[serde(default)]
    pub sign_responses: Option<bool>,
    #[serde(default)]
    pub want_authn_requests_signed: Option<bool>,
    /// One of `emailAddress` / `persistent` / `transient` / `unspecified`.
    #[serde(default)]
    pub nameid_format: Option<String>,
    #[serde(default)]
    pub attribute_map: Option<std::collections::BTreeMap<String, String>>,
}

/// YAML for `realms.{name}.federation.*`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FederationYamlConfig {
    /// How to link external identities that match existing local users
    /// by email: `disabled` / `confirm` / `auto`. Defaults to `confirm`
    /// (Keycloak-equivalent safety posture).
    #[serde(default)]
    pub link_existing_accounts: Option<LinkModeYaml>,
    /// Declarative connector definitions keyed by the operator-assigned
    /// `idp_name` (same string that ends up in `?idp=<name>`).
    #[serde(default)]
    pub providers: std::collections::HashMap<String, FederationProviderYaml>,
}

/// Realm-level federation account-linking mode.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkModeYaml {
    /// Never link — always JIT-provision.
    Disabled,
    /// Require local-credential re-auth before linking (default).
    Confirm,
    /// Auto-link on verified email match.
    Auto,
}

impl LinkModeYaml {
    /// Converts to the domain enum.
    pub fn to_domain(self) -> crate::identity::federation::LinkMode {
        match self {
            Self::Disabled => crate::identity::federation::LinkMode::Disabled,
            Self::Confirm => crate::identity::federation::LinkMode::Confirm,
            Self::Auto => crate::identity::federation::LinkMode::Auto,
        }
    }
}

/// YAML for a single federation connector.
///
/// `type` selects the underlying protocol. Four flavors:
///
/// - `oidc` — generic OIDC (operator MUST supply `issuer`,
///   `authorization_endpoint`, `token_endpoint`, `jwks_uri`).
/// - `google` / `microsoft` / `apple` — preset OIDC shapes with
///   issuer/endpoints/scopes prefilled.
/// - `github` — OAuth2 (no OIDC).
#[derive(Debug, Clone, Deserialize)]
pub struct FederationProviderYaml {
    /// Preset or protocol selector (`"oidc"`, `"google"`, `"microsoft"`,
    /// `"apple"`, `"github"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Optional human-readable label (overrides the preset default).
    #[serde(default)]
    pub display_name: Option<String>,
    /// OIDC issuer override. Required for generic `oidc`; optional for
    /// presets (operators use it to pin to a specific Azure AD tenant).
    #[serde(default)]
    pub issuer: Option<String>,
    /// Authorization endpoint override.
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    /// Token endpoint override.
    #[serde(default)]
    pub token_endpoint: Option<String>,
    /// Userinfo endpoint override.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// JWKS URL override.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// OAuth client id registered at the upstream IdP.
    #[serde(default)]
    pub client_id: Option<String>,
    /// OAuth client secret.
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Scopes override. Default is the preset's or `["openid","email","profile"]`.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Per-claim renames for OIDC/OAuth2 connectors: maps a Hearth field
    /// name (e.g. `"email"`, `"name"`) to the upstream claim name the IdP
    /// actually sends (e.g. `"upn"`, `"preferred_username"`).
    ///
    /// Used for IdPs that don't follow the standard OIDC claim names, such
    /// as Azure AD (`"email": "upn"`) or custom Okta apps.
    /// Ignored for `type: saml` (use `attribute_map` instead).
    #[serde(default)]
    pub claim_mappings: Option<std::collections::BTreeMap<String, String>>,
    /// Clock-skew allowance (seconds) applied to OIDC ID-token `exp` / `nbf`
    /// checks. Omit to use the default of 60 s (standard OIDC RP tolerance).
    /// Raise only for enterprise IdPs with known clock drift; maximum 300 s.
    #[serde(default)]
    pub leeway_seconds: Option<u32>,

    // --- SAML-specific fields (when `type: saml`) ---
    /// SAML IdP entity ID (SAML issuer).
    #[serde(default)]
    pub entity_id: Option<String>,
    /// SAML IdP SingleSignOnService URL (HTTP-Redirect binding).
    #[serde(default)]
    pub sso_url: Option<String>,
    /// SAML IdP SingleLogoutService URL.
    #[serde(default)]
    pub slo_url: Option<String>,
    /// SAML IdP signing certificate PEM (inline).
    #[serde(default)]
    pub idp_certificate_pem: Option<String>,
    /// Whether outbound AuthnRequests should be signed.
    #[serde(default)]
    pub sign_authn_requests: Option<bool>,
    /// Whether Hearth requires Assertion-level signatures.
    #[serde(default)]
    pub want_assertions_signed: Option<bool>,
    /// Attribute mapping: Hearth field → SAML attribute URI.
    #[serde(default)]
    pub attribute_map: Option<std::collections::BTreeMap<String, String>>,
}

impl FederationProviderYaml {
    /// Returns a blank OIDC provider config with all optional fields unset.
    pub fn default_oidc() -> Self {
        Self {
            kind: "oidc".to_string(),
            display_name: None,
            issuer: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: None,
            client_secret: None,
            scopes: None,
            claim_mappings: None,
            leeway_seconds: None,
            entity_id: None,
            sso_url: None,
            slo_url: None,
            idp_certificate_pem: None,
            sign_authn_requests: None,
            want_assertions_signed: None,
            attribute_map: None,
        }
    }
}

/// Staged capability flags for `agent_auth`.
///
/// Each flag activates one phase of the agent feature set independently.
/// Flags must be enabled in order; enabling a phase without its predecessor
/// is rejected at startup. Defaults: all `false`.
///
/// See `docs/specs/AGENT_AUTH.md` for phase definitions.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct AgentAuthCapabilities {
    /// Phase A — Agent identity: CRUD, API-key credentials, Agent Card,
    /// and REST endpoints (`/v1/agents`).
    #[serde(default)]
    pub identity: bool,
    /// Phase B + C — MCP authorization server, RFC 8693 token exchange,
    /// tool-level permissions, and human-in-the-loop approvals.
    ///
    /// Requires `identity = true`. When enabled, adds:
    /// - Tool-permission grammar (`tool.*`/`toolgroup.*`, deny-wins)
    /// - Approval request lifecycle (create/approve/deny/capability-token)
    /// - Approval webhook notification (per-realm `approval_webhook` config)
    /// - REST endpoints (`/v1/approval-requests`)
    #[serde(default)]
    pub approval: bool,
    /// Phase D — Advanced delegation: Attenuating Authorization Tokens (AATs),
    /// transaction tokens, cross-realm trust policies, and SPIFFE/mTLS workload
    /// identity.
    ///
    /// Requires `identity = true`. When enabled, adds:
    /// - AAT issuance, derivation, validation, and revocation
    /// - Single-use transaction tokens with replay prevention
    /// - Cross-realm trust policy management
    /// - SPIFFE SVID mapping and mTLS workload authentication
    #[serde(default)]
    pub advanced: bool,
}

/// Agent authentication / authorization feature gate.
///
/// Uses staged capability flags so each phase can be enabled independently.
/// Enabling a phase without its required predecessor is rejected at startup.
///
/// See `docs/specs/AGENT_AUTH.md` for the normative specification.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct AgentAuthConfig {
    /// Staged capability flags. All default to `false`.
    #[serde(default)]
    pub capabilities: AgentAuthCapabilities,
}

/// Parses a human-readable duration string into microseconds.
///
/// Supported suffixes: `s` (seconds), `m` (minutes), `h` (hours), `d` (days).
///
/// # Errors
///
/// Returns `Err` if the string is empty, has an unknown suffix, or the
/// numeric part cannot be parsed.
pub fn parse_duration_to_micros(s: &str) -> Result<i64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration string".to_string());
    }

    let (num_str, multiplier) = if let Some(n) = s.strip_suffix('d') {
        (n, 86_400_000_000i64)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3_600_000_000i64)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000_000i64)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000_000i64)
    } else {
        return Err(format!(
            "unknown duration suffix in '{s}', expected s/m/h/d"
        ));
    };

    let value: i64 = num_str
        .trim()
        .parse()
        .map_err(|e| format!("invalid duration number '{num_str}': {e}"))?;

    Ok(value * multiplier)
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

impl RealmYamlConfig {
    /// Merges this per-realm config with global auth defaults to produce a
    /// `RealmConfig` suitable for storage.
    ///
    /// Returns `Err(errors)` if any permission names are grammatically
    /// invalid, scope bundle names are malformed, role parent references
    /// are undeclared, cycles exist in the role parent graph, or claim
    /// mappings target Tier 1 (reserved) claim names. All violations are
    /// collected before returning so the caller can surface them at once.
    ///
    /// `web_theme_css` is populated by the caller (main.rs) after reading
    /// the optional CSS file from disk; it is `None` here.
    #[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
    pub fn to_realm_config(
        &self,
        global: &AuthConfig,
        global_branding: Option<&EmailBranding>,
    ) -> Result<crate::identity::RealmConfig, Vec<crate::rbac::RegistryError>> {
        use crate::rbac::registry::RegistryError;
        use std::collections::HashMap;
        use uuid::Uuid;

        let session_ttl_micros = self
            .session_ttl
            .as_deref()
            .or(global.session_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let max_concurrent_sessions = self
            .session_max_concurrent
            .or(global.session_max_concurrent);

        // SEC-3: Hard error on unrecognised policy string — never silently default.
        let raw_policy = self
            .session_over_limit_policy
            .as_deref()
            .or(global.session_over_limit_policy.as_deref());
        let session_over_limit_policy = match raw_policy {
            None | Some("reject_new") => {
                // None → default (RejectNew); explicit "reject_new" → same.
                raw_policy.map_or_else(crate::identity::SessionLimitPolicy::default, |_| {
                    crate::identity::SessionLimitPolicy::RejectNew
                })
            }
            Some("evict_oldest") => crate::identity::SessionLimitPolicy::EvictOldest,
            Some(unknown) => {
                return Err(vec![RegistryError::InvalidRealmConfigField {
                    field: "session_over_limit_policy".to_string(),
                    value: unknown.to_string(),
                    reason: "must be \"reject_new\" or \"evict_oldest\"".to_string(),
                }]);
            }
        };

        let password_memory_cost = self.password_memory_cost.or(global.password_memory_cost);
        let password_time_cost = self.password_time_cost.or(global.password_time_cost);

        let email_branding = self
            .email
            .as_ref()
            .and_then(|e| e.branding.clone())
            .or_else(|| global_branding.cloned());

        // Map auth policy fields from the YAML `auth:` block (if present).
        let auth = self.auth.as_ref();
        let scim_bearer_token_hash = self
            .scim
            .as_ref()
            .and_then(|s| s.bearer_token.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(sha256_hex);

        let mfa_required = auth.and_then(|a| a.mfa_required).or(global.mfa_required);
        let mfa_methods = auth.and_then(|a| a.mfa_methods.clone());
        let allowed_auth_methods = auth.and_then(|a| a.allowed_auth_methods.clone());
        let passkey_requires_mfa = auth
            .and_then(|a| a.passkey_requires_mfa)
            .or(global.passkey_requires_mfa);

        let password_policy = auth.and_then(|a| a.password_policy.as_ref()).map(|pp| {
            crate::identity::PasswordPolicy {
                min_length: pp.min_length,
                require_uppercase: pp.require_uppercase,
                require_number: pp.require_number,
                require_special: pp.require_special,
                not_username: pp.not_username,
                not_email: pp.not_email,
                history_depth: pp.history_depth,
                max_age_days: pp.max_age_days,
            }
        });

        let access_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.access_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let refresh_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.refresh_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let password_reset_token_ttl_micros = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.password_reset_token_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let magic_link_ttl_micros_parsed = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.magic_link_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let device_code_ttl_secs_parsed = auth
            .and_then(|a| a.token.as_ref())
            .and_then(|t| t.device_code_ttl.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok())
            .map(|us| us / 1_000_000); // convert µs → seconds

        let allow_unsafe_ttl = auth
            .and_then(|a| a.token.as_ref())
            .map(|t| t.allow_unsafe_ttl)
            .unwrap_or(false);

        let webauthn_attestation_policy = auth
            .and_then(|a| a.webauthn_attestation.as_ref())
            .map(WebAuthnAttestationYaml::to_domain);

        let max_failed_logins = auth
            .and_then(|a| a.rate_limit.as_ref())
            .and_then(|r| r.max_failed_logins);

        let lockout_duration_micros = auth
            .and_then(|a| a.rate_limit.as_ref())
            .and_then(|r| r.lockout_duration.as_deref())
            .and_then(|s| parse_duration_to_micros(s).ok());

        let registration_policy = auth
            .and_then(|a| a.registration.as_ref())
            .map(RegistrationPolicyYaml::to_domain);

        let dcr_policy = auth
            .and_then(|a| a.dcr.as_ref())
            .map(DcrPolicyYaml::to_domain);

        // Accumulate all validation errors upfront so callers see the full
        // set of problems in one pass rather than stopping at the first error.
        let mut errors: Vec<RegistryError> = Vec::new();

        // --- A-14: TTL hard caps (fail-closed unless allow_unsafe_ttl) -----
        const PASSWORD_RESET_TTL_CAP_MICROS: i64 = 3_600 * 1_000_000; // 1 hour
        const MAGIC_LINK_TTL_CAP_MICROS: i64 = 1_800 * 1_000_000; // 30 minutes

        if let Some(pr_ttl) = password_reset_token_ttl_micros {
            if pr_ttl > PASSWORD_RESET_TTL_CAP_MICROS && !allow_unsafe_ttl {
                errors.push(RegistryError::InvalidRealmConfigField {
                    field: "auth.token.password_reset_token_ttl".to_string(),
                    value: format!("{pr_ttl}µs"),
                    reason: "exceeds 1h hard cap (A-14); set auth.token.allow_unsafe_ttl: true to override"
                        .to_string(),
                });
            }
        }
        if let Some(ml_ttl) = magic_link_ttl_micros_parsed {
            if ml_ttl > MAGIC_LINK_TTL_CAP_MICROS && !allow_unsafe_ttl {
                errors.push(RegistryError::InvalidRealmConfigField {
                    field: "auth.token.magic_link_ttl".to_string(),
                    value: format!("{ml_ttl}µs"),
                    reason: "exceeds 30m hard cap (A-14); set auth.token.allow_unsafe_ttl: true to override"
                        .to_string(),
                });
            }
        }
        const DEVICE_CODE_TTL_CAP_SECS: i64 = 1_800; // 30 minutes
        if let Some(dc_ttl) = device_code_ttl_secs_parsed {
            if dc_ttl > DEVICE_CODE_TTL_CAP_SECS && !allow_unsafe_ttl {
                errors.push(RegistryError::InvalidRealmConfigField {
                    field: "auth.token.device_code_ttl".to_string(),
                    value: format!("{dc_ttl}s"),
                    reason: "exceeds 30m hard cap (HSEC-008); set auth.token.allow_unsafe_ttl: true to override"
                        .to_string(),
                });
            }
        }

        // --- Permissions: grammar-validate each name -----------------------

        let permissions: Vec<PermissionDefinition> = self
            .permissions
            .clone()
            .unwrap_or_default()
            .into_iter()
            .filter_map(
                |permission| match Permission::new(permission.name.clone()) {
                    Ok(name) => Some(PermissionDefinition {
                        name,
                        display_name: permission.display_name,
                        description: permission.description,
                        category: permission.category,
                    }),
                    Err(reason) => {
                        errors.push(RegistryError::InvalidPermissionName {
                            name: permission.name,
                            reason,
                        });
                        None
                    }
                },
            )
            .collect();

        // --- Scope bundles: grammar-validate permission names --------------

        let scopes: Vec<ScopeBundle> = self
            .scopes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|bundle| ScopeBundle {
                name: bundle.name,
                display_name: bundle.display_name,
                description: bundle.description,
                permissions: bundle
                    .permissions
                    .into_iter()
                    .filter_map(|permission| match Permission::new(permission.clone()) {
                        Ok(p) => Some(p),
                        Err(reason) => {
                            errors.push(RegistryError::InvalidPermissionName {
                                name: permission,
                                reason,
                            });
                            None
                        }
                    })
                    .collect(),
            })
            .collect();

        // --- Roles: two-pass to wire up parent_roles by name → ID ---------
        //
        // Pass 1: assign a stable RoleId to each role name.
        // Pass 2: resolve `parents: Vec<String>` to Vec<RoleId>.
        //
        // Roles in the in-memory registry use the nil UUID as the realm_id
        // sentinel — the actual RealmId is applied by the seeding / reconcile
        // path that writes roles into the RBAC engine's storage.

        let yaml_roles = self.roles.clone().unwrap_or_default();
        // Build name → RoleId map first (owned keys avoid a borrow-move conflict
        // when we consume yaml_roles via into_iter() immediately after).
        let name_to_id: HashMap<String, RoleId> = yaml_roles
            .iter()
            .map(|r| (r.name.clone(), RoleId::generate()))
            .collect();

        let roles: Vec<Role> = yaml_roles
            .into_iter()
            .map(|role| {
                let scope_kind = match role.scope_kind.as_deref() {
                    Some("organization") => RoleScopeKind::Organization,
                    Some("any") => RoleScopeKind::Any,
                    _ => RoleScopeKind::Realm,
                };

                let id = name_to_id[role.name.as_str()].clone();

                let role_permissions: Vec<Permission> = role
                    .permissions
                    .into_iter()
                    .filter_map(|permission| match Permission::new(permission.clone()) {
                        Ok(p) => Some(p),
                        Err(reason) => {
                            errors.push(RegistryError::InvalidPermissionName {
                                name: permission,
                                reason,
                            });
                            None
                        }
                    })
                    .collect();

                // Resolve parent names to IDs; unknown names surface as
                // UndeclaredParentRole errors during registry.validate().
                // We store whatever IDs we can resolve here so the
                // structural cycle-detector can run on what's available.
                let parent_roles: Vec<RoleId> = role
                    .parents
                    .into_iter()
                    .filter_map(|parent_name| name_to_id.get(parent_name.as_str()).cloned())
                    .collect();

                Role {
                    id,
                    // Nil UUID sentinel: actual realm ID is injected at
                    // seed/reconcile time, not at YAML parse time.
                    realm_id: crate::core::RealmId::new(Uuid::nil()),
                    name: role.name,
                    description: role.description,
                    permissions: role_permissions,
                    parent_roles,
                    scope_kind,
                    status: crate::rbac::RoleStatus::Active,
                    yaml_managed: true,
                    created_at: crate::core::Timestamp::from_micros(0),
                    updated_at: crate::core::Timestamp::from_micros(0),
                }
            })
            .collect();

        // --- Protected resources: grammar-validate bundle perm names -------

        let protected_resources: Vec<ProtectedResource> = self
            .protected_resources
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|resource| ProtectedResource {
                resource_uri: resource.resource_uri,
                display_name: resource.display_name,
                scopes: resource
                    .scopes
                    .into_iter()
                    .map(|bundle| ScopeBundle {
                        name: bundle.name,
                        display_name: bundle.display_name,
                        description: bundle.description,
                        permissions: bundle
                            .permissions
                            .into_iter()
                            .filter_map(|permission| match Permission::new(permission.clone()) {
                                Ok(p) => Some(p),
                                Err(reason) => {
                                    errors.push(RegistryError::InvalidPermissionName {
                                        name: permission,
                                        reason,
                                    });
                                    None
                                }
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect();

        // --- Claim profile -------------------------------------------------

        let claim_profile =
            self.claims
                .clone()
                .map(|claims| crate::identity::claims_config::ClaimProfile {
                    mappings: claims.mappings,
                    updated_at: None,
                });

        // --- Groups --------------------------------------------------------

        let groups: Vec<crate::rbac::Group> = self
            .groups
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|g| crate::rbac::Group {
                id: crate::rbac::GroupId::generate(),
                realm_id: crate::core::RealmId::new(uuid::Uuid::nil()),
                name: g.name.clone(),
                slug: g.slug.unwrap_or_else(|| make_group_slug(&g.name)),
                description: g.description.clone(),
                created_at: crate::core::Timestamp::from_micros(0),
                updated_at: crate::core::Timestamp::from_micros(0),
            })
            .collect();

        // --- FAPI profile --------------------------------------------------

        let fapi_profile = match self.fapi_profile.as_deref() {
            None => None,
            Some("baseline") => Some(crate::identity::FapiProfile::Baseline),
            Some("advanced") => Some(crate::identity::FapiProfile::Advanced),
            Some(other) => {
                errors.push(RegistryError::InvalidRealmConfigField {
                    field: "fapi_profile".to_string(),
                    value: other.to_string(),
                    reason: "expected \"baseline\" or \"advanced\"".to_string(),
                });
                None
            }
        };

        // --- Structural validation (cross-references, cycles, Tier 1) ------
        //
        // Bail early on grammar errors before running the structural checks
        // to avoid cascading noise (e.g. an undeclared perm in a role would
        // generate both an InvalidPermissionName AND an UndeclaredPermission
        // error for the same typo).
        if !errors.is_empty() {
            return Err(errors);
        }

        let registry = crate::rbac::registry::RealmPermissionRegistry {
            permissions: permissions.clone(),
            roles: roles.clone(),
            scopes: scopes.clone(),
            protected_resources: protected_resources.clone(),
            claim_profile: claim_profile.clone(),
        };
        registry.validate()?;

        Ok(crate::identity::RealmConfig {
            session_ttl_micros,
            password_memory_cost,
            password_time_cost,
            email_branding,
            // Populated by main.rs after reading the CSS file from disk.
            web_theme_css: None,
            // Mirrors the realm's YAML `web.theme`. Doesn't require disk
            // reads (unlike the CSS body) so we populate it here directly
            // off the parsed YAML rather than deferring to main.rs.
            web_theme_name: self
                .web
                .as_ref()
                .and_then(|w| w.theme.as_ref())
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty()),
            mfa_required,
            mfa_methods,
            allowed_auth_methods,
            password_policy,
            access_token_ttl_micros,
            refresh_token_ttl_micros,
            password_reset_token_ttl_micros,
            magic_link_ttl_micros: magic_link_ttl_micros_parsed,
            device_code_ttl_secs: device_code_ttl_secs_parsed,
            max_failed_logins,
            lockout_duration_micros,
            passkey_requires_mfa,
            webauthn_required: None,
            webauthn_resident_key: None,
            webauthn_user_verification: None,
            webauthn_attestation: webauthn_attestation_policy,
            registration_policy,
            dcr_policy,
            // Realm-level federation link mode. `None` → `Confirm`
            // (Keycloak-equivalent default). Connector records are
            // reconciled separately via `reconcile_federation_for_realm`.
            federation_link_mode: self
                .federation
                .as_ref()
                .and_then(|f| f.link_existing_accounts)
                .map(LinkModeYaml::to_domain),
            permissions,
            roles,
            scopes,
            protected_resources,
            claim_profile,
            groups,
            scim_bearer_token_hash,
            // Per-realm logo and primary color are managed via the admin API,
            // not via hearth.yaml, so they default to None here.
            logo_url: None,
            primary_color: None,
            // Email template overrides are managed via the admin API, not
            // via hearth.yaml; start empty and let the API populate them.
            email_templates: std::collections::HashMap::new(),
            attribute_definitions: self.attribute_definitions.as_ref().map(|defs| {
                crate::identity::AttributeDefinitions {
                    users: defs
                        .users
                        .iter()
                        .map(|d| crate::identity::AttributeDefinition {
                            key: d.key.clone(),
                            label: d.label.clone(),
                            type_: match d.type_ {
                                AttributeTypeYaml::String => crate::identity::AttributeType::String,
                                AttributeTypeYaml::Number => crate::identity::AttributeType::Number,
                                AttributeTypeYaml::Boolean => {
                                    crate::identity::AttributeType::Boolean
                                }
                                AttributeTypeYaml::Enum => crate::identity::AttributeType::Enum,
                            },
                            required: d.required,
                            description: d.description.clone(),
                            enum_values: d.enum_values.clone(),
                        })
                        .collect(),
                    organizations: defs
                        .organizations
                        .iter()
                        .map(|d| crate::identity::AttributeDefinition {
                            key: d.key.clone(),
                            label: d.label.clone(),
                            type_: match d.type_ {
                                AttributeTypeYaml::String => crate::identity::AttributeType::String,
                                AttributeTypeYaml::Number => crate::identity::AttributeType::Number,
                                AttributeTypeYaml::Boolean => {
                                    crate::identity::AttributeType::Boolean
                                }
                                AttributeTypeYaml::Enum => crate::identity::AttributeType::Enum,
                            },
                            required: d.required,
                            description: d.description.clone(),
                            enum_values: d.enum_values.clone(),
                        })
                        .collect(),
                }
            }),
            // Required actions are managed via the admin API, not via hearth.yaml.
            default_required_actions: Vec::new(),
            // Breach-check config is managed via the admin API or per-realm YAML.
            // Default is disabled so existing realms are unaffected.
            breach_check: crate::identity::BreachCheckConfig::default(),
            // Adaptive MFA defaults to disabled; enable per-realm via admin API or YAML.
            adaptive_mfa: crate::identity::AdaptiveMfaConfig::default(),
            // SMS OTP expiry and max-attempt config; `None` uses OTP module defaults.
            sms_otp_expiry_seconds: None,
            sms_otp_max_attempts: None,
            // Email OTP expiry and max-attempt config; `None` uses OTP module defaults.
            email_otp_expiry_seconds: None,
            email_otp_max_attempts: None,
            session_version: crate::identity::SessionVersionConfig::default(),
            max_concurrent_sessions,
            session_over_limit_policy,
            idle_timeout_secs: None,
            absolute_timeout_secs: None,
            fapi_profile,
            risk_scorer_config: None,
            quotas: None,
            // Pre-token webhook is configured via admin API or per-realm YAML.
            // Defaults to None (disabled) so existing realms are unaffected.
            pre_token_webhook: None,
            approval_webhook: None,
            mfa_required_roles: None,
            // Tool-group registry: copy group → [tool] map directly from YAML.
            tool_groups: self
                .tool_registry
                .as_ref()
                .map(|r| r.groups.clone())
                .unwrap_or_default(),
        })
    }
}

/// Derives a URL-safe group slug from a display name.
fn make_group_slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_hyphen = true;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_hyphen = false;
        } else if !last_hyphen {
            out.push('-');
            last_hyphen = true;
        }
    }
    if out.len() > 63 {
        out.truncate(63);
    }
    if out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out = "group".to_string();
    }
    out
}

/// Address and ID for a single cluster peer.
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Unique node ID within the cluster.
    pub id: u64,
    /// gRPC peer address (`host:port`) used for Raft RPC connections.
    pub address: String,
}

/// Cluster configuration for multi-node deployments.
///
/// When present in `hearth.yaml`, Hearth starts a Raft consensus engine and
/// participates in peer-to-peer replication over mTLS-secured gRPC.
/// When absent, Hearth runs in single-node mode with no clustering overhead.
///
/// All three TLS fields are required — plaintext peer connections are
/// unconditionally rejected.
#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    /// This node's numeric ID — must be unique across the cluster.
    pub node_id: u64,
    /// Local address this node listens on for Raft peer RPCs (`host:port`).
    #[serde(default = "ClusterConfig::default_peer_address")]
    pub peer_address: String,
    /// Known cluster peers.
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
    /// Path to this node's TLS certificate PEM file (presented to peers).
    pub tls_cert_path: PathBuf,
    /// Path to this node's TLS private key PEM file.
    pub tls_key_path: PathBuf,
    /// Path to the CA certificate PEM file used to verify peer certificates.
    pub tls_ca_cert_path: PathBuf,
    /// Maximum follower read-lag in milliseconds before reads are refused
    /// and the caller is redirected to the leader (default: 500).
    #[serde(default)]
    pub read_lag_threshold_ms: Option<u64>,
}

impl ClusterConfig {
    fn default_peer_address() -> String {
        "127.0.0.1:8421".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_defaults() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert_eq!(cfg.port, 8420);
        assert!(cfg.tls_cert_path.is_none());
        assert!(cfg.tls_key_path.is_none());
    }

    /// Pins REQ-100: `to_realm_config` mirrors `web.theme` from the
    /// realm YAML into `RealmConfig.web_theme_name` so the realm detail
    /// page can show the source theme name without inspecting CSS bytes.
    #[test]
    fn to_realm_config_populates_web_theme_name_from_yaml() {
        let yaml = RealmYamlConfig {
            web: Some(RealmWebYaml {
                theme: Some("ocean".to_string()),
                custom_css: None,
                product_name: None,
            }),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        assert_eq!(cfg.web_theme_name.as_deref(), Some("ocean"));
        // The CSS body is populated separately by main.rs from disk.
        assert!(cfg.web_theme_css.is_none());
    }

    /// Whitespace-only or empty `web.theme` values must NOT surface as
    /// `Some("")` — the detail page would render an empty pill, which
    /// is worse than the "Inherits global default" fallback.
    #[test]
    fn to_realm_config_treats_blank_theme_as_unset() {
        let yaml = RealmYamlConfig {
            web: Some(RealmWebYaml {
                theme: Some("   ".to_string()),
                custom_css: None,
                product_name: None,
            }),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        assert!(cfg.web_theme_name.is_none());
    }

    /// When the realm has no `web` block at all, `web_theme_name` is `None`.
    #[test]
    fn to_realm_config_no_web_block_yields_none_theme_name() {
        let yaml = RealmYamlConfig::default();
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        assert!(cfg.web_theme_name.is_none());
    }

    #[test]
    fn to_realm_config_hashes_scim_bearer_token() {
        let yaml = RealmYamlConfig {
            scim: Some(RealmScimYaml {
                bearer_token: Some("scim-secret-token".to_string()),
            }),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("to_realm_config");
        // deepcode ignore HardcodedNonCryptoSecret: SHA-256 hash of "scim-secret-token" — SCIM bearer roundtrip fixture
        assert_eq!(
            cfg.scim_bearer_token_hash.as_deref(),
            Some("31c5b57bb0a5e7b9a064b0d08eaa2a74d532e36a261d02510120e45466187272")
        );
    }

    #[test]
    fn storage_section_defaults() {
        let cfg = StorageSection::default();
        assert_eq!(cfg.data_dir, "./data");
        assert_eq!(cfg.wal_max_size_bytes, 256 * 1024 * 1024);
        assert_eq!(cfg.memtable_flush_bytes, 64 * 1024 * 1024);
        assert_eq!(cfg.hot_tier_capacity, None);
        assert_eq!(cfg.hot_tier_max_memory, None);
        assert!(cfg.fsync);
    }

    #[test]
    fn observability_config_defaults() {
        let cfg = ObservabilityConfig::default();
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.log_format, "text");
    }

    #[test]
    fn operational_config_defaults() {
        let cfg = OperationalConfig::default();
        assert_eq!(cfg.request_timeout_secs, 30);
        assert_eq!(cfg.shutdown_timeout_secs, 10);
        assert_eq!(cfg.max_connections, 1024);
        assert_eq!(cfg.queue_depth, 4096);
    }

    #[test]
    fn email_config_defaults() {
        let cfg = EmailConfig::default();
        assert_eq!(cfg.transport, EmailTransport::Log);
        assert!(cfg.from.is_none());
    }

    #[test]
    fn onboarding_config_defaults() {
        let cfg = OnboardingConfig::default();
        assert!(cfg.enabled);
        assert!(cfg.base_url.is_none());
    }

    #[test]
    fn parse_duration_seconds() {
        assert_eq!(parse_duration_to_micros("30s").expect("ok"), 30_000_000);
    }

    #[test]
    fn parse_duration_minutes() {
        assert_eq!(parse_duration_to_micros("5m").expect("ok"), 300_000_000);
    }

    #[test]
    fn parse_duration_hours() {
        assert_eq!(parse_duration_to_micros("24h").expect("ok"), 86_400_000_000);
    }

    #[test]
    fn parse_duration_days() {
        assert_eq!(parse_duration_to_micros("1d").expect("ok"), 86_400_000_000);
    }

    #[test]
    fn parse_duration_invalid_suffix() {
        assert!(parse_duration_to_micros("10x").is_err());
    }

    #[test]
    fn parse_duration_empty() {
        assert!(parse_duration_to_micros("").is_err());
    }

    #[test]
    fn auth_config_yaml_parsing() {
        let yaml = "session_ttl: '24h'\npassword_memory_cost: 65536\n";
        let cfg: AuthConfig = serde_norway::from_str(yaml).expect("parse");
        assert_eq!(cfg.session_ttl.as_deref(), Some("24h"));
        assert_eq!(cfg.password_memory_cost, Some(65536));
    }

    #[test]
    fn realm_yaml_config_merge() {
        let global = AuthConfig {
            session_ttl: Some("24h".to_string()),
            password_memory_cost: Some(65536),
            password_time_cost: Some(3),
            mfa_required: None,
            passkey_requires_mfa: None,
            session_max_concurrent: None,
            session_over_limit_policy: None,
        };
        let realm_cfg = RealmYamlConfig {
            session_ttl: Some("12h".to_string()),
            ..RealmYamlConfig::default()
        };
        let merged = realm_cfg
            .to_realm_config(&global, None)
            .expect("default realm config must be valid");
        // Per-realm TTL overrides global
        assert_eq!(merged.session_ttl_micros, Some(43_200_000_000));
        // Inherited from global
        assert_eq!(merged.password_memory_cost, Some(65536));
        assert_eq!(merged.password_time_cost, Some(3));
    }

    #[test]
    fn fapi_profile_baseline_parsed() {
        let yaml = RealmYamlConfig {
            fapi_profile: Some("baseline".to_string()),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("baseline is valid");
        assert_eq!(
            cfg.fapi_profile,
            Some(crate::identity::FapiProfile::Baseline)
        );
    }

    #[test]
    fn fapi_profile_advanced_parsed() {
        let yaml = RealmYamlConfig {
            fapi_profile: Some("advanced".to_string()),
            ..RealmYamlConfig::default()
        };
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("advanced is valid");
        assert_eq!(
            cfg.fapi_profile,
            Some(crate::identity::FapiProfile::Advanced)
        );
    }

    #[test]
    fn fapi_profile_absent_yields_none() {
        let yaml = RealmYamlConfig::default();
        let cfg = yaml
            .to_realm_config(&AuthConfig::default(), None)
            .expect("no fapi_profile is valid");
        assert!(cfg.fapi_profile.is_none());
    }

    #[test]
    fn fapi_profile_unknown_value_is_error() {
        let yaml = RealmYamlConfig {
            fapi_profile: Some("enterprise".to_string()),
            ..RealmYamlConfig::default()
        };
        let result = yaml.to_realm_config(&AuthConfig::default(), None);
        assert!(result.is_err(), "unknown fapi_profile must fail validation");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level config and validation types (moved from mod.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// A single validation issue with its field path and human-readable reason.
///
/// Used by [`Config::validate_all`] to report all problems at once rather
/// than short-circuiting on the first error.
#[derive(Debug, Clone, serde::Serialize)]
#[allow(dead_code)]
pub struct ValidationIssue {
    /// Dot-delimited config field path (e.g. `"server.port"`).
    pub field: String,
    /// Human-readable reason this value is invalid.
    pub reason: String,
}

/// Top-level Hearth configuration.
///
/// All sections use `#[serde(default)]` so a partial or empty YAML file
/// produces valid configuration with production-safe defaults.
#[derive(Debug, Clone, Default, Deserialize)]
#[allow(dead_code, clippy::struct_field_names)]
pub struct Config {
    /// Server network settings.
    #[serde(default)]
    pub server: ServerConfig,
    /// Storage engine settings.
    #[serde(default)]
    pub storage: StorageSection,
    /// Logging and tracing settings.
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Operational limits and timeouts.
    #[serde(default)]
    pub operational: OperationalConfig,
    /// Outbound email delivery settings.
    #[serde(default)]
    pub email: EmailConfig,
    /// Outbound SMS delivery settings.
    #[serde(default)]
    pub sms: SmsConfig,
    /// First-run onboarding settings.
    #[serde(default)]
    pub onboarding: OnboardingConfig,
    /// Global branding settings (logo URL).
    #[serde(default)]
    pub branding: BrandingConfig,
    /// OIDC / OAuth 2.0 settings (issuer URL, authorization code TTL, nonce enforcement).
    #[serde(default)]
    pub oidc: OidcYamlConfig,
    /// Token issuance settings (issuer, audience, access/refresh TTLs).
    #[serde(default)]
    pub token: TokenYamlConfig,
    /// Global authentication defaults (session TTL, password hashing params).
    #[serde(default)]
    pub auth: AuthConfig,
    /// Global security settings (rate-limiting thresholds).
    #[serde(default)]
    pub security: SecurityYaml,
    /// Prometheus metrics endpoint settings.
    #[serde(default)]
    pub metrics: MetricsConfig,
    /// Per-realm configuration overrides.
    ///
    /// When `Some`, realms are declaratively managed: YAML entries become
    /// Active realms, storage-only realms get Archived. When `None`,
    /// realms are managed via API/onboarding (backward compatible).
    #[serde(default)]
    pub realms: Option<std::collections::HashMap<String, RealmYamlConfig>>,
    /// Raft clustering configuration.
    ///
    /// When `Some`, Hearth starts a Raft consensus engine and participates in
    /// peer-to-peer replication over mTLS-secured gRPC. When `None` (the
    /// default), Hearth runs in single-node mode with no clustering overhead.
    #[serde(default)]
    pub cluster: Option<ClusterConfig>,
    /// Agent authentication / authorization feature gate (staged capabilities).
    ///
    /// `agent_auth.capabilities.identity = true` enables Phase A (M1): agent
    /// CRUD, API-key credentials, Agent Card, and REST endpoints.
    /// See `docs/specs/AGENT_AUTH.md` for the full capability map.
    #[serde(default)]
    pub agent_auth: AgentAuthConfig,
    /// Demo-mode configuration. Gates the large-scale demo seeder (per-realm
    /// `seeding:` blocks). Absent or `enabled: false` in production. See
    /// [`DemoConfig`].
    #[serde(default)]
    pub demo: DemoConfig,
    /// Whether development mode is active. Not serialized — set by [`Config::dev`].
    #[serde(skip)]
    pub dev_mode: bool,
    /// Env-var substitution warnings from config loading (missing/empty variables).
    /// Skipped during serde deserialization — populated by [`Config::from_file`]
    /// and [`Config::from_yaml_str`].
    #[serde(skip)]
    pub config_warnings: Vec<super::env::EnvVarWarning>,
}
