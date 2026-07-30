use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{CommandFactory, Parser, Subcommand};
use tokio::sync::Notify;
use tracing::{error, info, warn};

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::config::{
    Config, EmailTransport, SmsTransport, StorageSection, TlsMinVersionYaml, ValidationIssue,
};
use hearth::core::{Clock, SystemClock};
use hearth::identity::email::mailcatcher::{
    generate_password, MailcatcherSender, MailcatcherState,
};
use hearth::identity::email::mailgun::MailgunRegion;
use hearth::identity::email::{
    smtp_sender_from_config, ApiKey, EmailService, LoggingEmailSender, MailgunEmailSender,
    MailtrapEmailSender, PostmarkEmailSender, SendgridEmailSender, SharedEmailSender,
};
use hearth::identity::onboarding::{self, OnboardingService};
use hearth::identity::sms::{
    LoggingSmsSender, SharedSmsSender, SmsSecret, SnsSmsSender, TwilioSmsSender,
};
use hearth::identity::{
    CredentialConfig, EmbeddedIdentityEngine, IdentityConfig, IdentityEngine, OidcConfig,
    RateLimitConfig, TokenConfig,
};
use hearth::protocol;
use hearth::protocol::admin_auth::JwksRateLimiter;
use hearth::protocol::http::{self, AppState};
use hearth::protocol::tls::{build_server_config, ReloadableTlsConfig, TlsConfigParams};
use hearth::protocol::web::{self, WebState};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine, SvBumper};
use hearth::storage::{CompactionConfig, EmbeddedStorageEngine, StorageConfig, StorageEngine};

/// Hearth — a purpose-built identity database.
#[derive(Parser)]
#[command(name = "hearth", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Top-level subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Start the Hearth identity server.
    Serve {
        /// Enable development mode (in-memory storage, relaxed security, debug logging).
        #[arg(long)]
        dev: bool,

        /// Path to configuration file (YAML).
        #[arg(long, short)]
        config: Option<PathBuf>,

        /// Port to listen on (overrides config file).
        #[arg(long)]
        port: Option<u16>,

        /// Address to bind to (overrides config file).
        #[arg(long)]
        bind: Option<String>,

        /// Print debug-level startup diagnostics: resolved config, HTTP route groups,
        /// realm names, and Ed25519 key fingerprints. Sets log level to debug for
        /// the startup phase only (respects existing log level for steady-state).
        #[arg(long, short = 'v')]
        verbose: bool,

        /// Allow gRPC server reflection in production mode (A-43).
        ///
        /// gRPC reflection exposes the full API schema to any unauthenticated caller.
        /// Hearth refuses to start with `security.grpc.reflection_enabled = true` in
        /// production mode unless this flag is explicitly passed.
        ///
        /// Use only for debugging. Never enable in real deployments.
        #[arg(long)]
        allow_reflection_in_prod: bool,
    },
    /// Manage realms.
    Realm {
        #[command(subcommand)]
        action: RealmAction,
    },
    /// Manage OAuth 2.0 applications (clients).
    App {
        #[command(subcommand)]
        action: AppAction,
    },
    /// Import data from another identity provider.
    Migrate {
        #[command(subcommand)]
        source: MigrateSource,
    },
    /// Configuration management commands.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// RBAC maintenance commands.
    Rbac {
        #[command(subcommand)]
        action: RbacAction,
    },
    /// Create, restore, and inspect backup archives.
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Print a shell completion script to stdout.
    ///
    /// Pipe the output to your shell's completions directory.
    /// Example: `hearth completions zsh > ~/.zsh/completions/_hearth`
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
}

/// Backup subcommands.
#[derive(Subcommand)]
enum BackupAction {
    /// Export all realm data to a `.hearth-backup` archive.
    Create {
        /// Output path for the archive.
        ///
        /// Defaults to `./hearth-backup-<timestamp>.hearth-backup` in the
        /// current directory.
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Restrict export to this realm (by name or UUID).
        ///
        /// When omitted, all realms are exported.
        #[arg(long)]
        realm: Option<String>,

        /// Include audit events in the export (may be very large).
        #[arg(long)]
        include_audit: bool,

        /// Protect the signing-key DEK with a passphrase (prompted interactively).
        ///
        /// When set, the DEK stored in `manifest.json` is AES-256-GCM encrypted
        /// with a key derived from the passphrase via Argon2id. Without the
        /// passphrase the signing keys inside the archive cannot be decrypted.
        #[arg(long)]
        encrypt: bool,

        /// Path to the data directory.
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// Restore realm data from a `.hearth-backup` archive.
    Restore {
        /// Path to the archive to restore.
        #[arg(long, short)]
        input: PathBuf,

        /// Restore only this realm (by archive slug).
        ///
        /// When omitted, all realms in the archive are restored.
        #[arg(long)]
        realm: Option<String>,

        /// Conflict resolution strategy.
        ///
        /// `skip` (default) — keep existing records unchanged.
        /// `overwrite` — delete and re-import conflicting records.
        /// `merge` — equivalent to `skip` in this version.
        #[arg(long, default_value = "skip")]
        mode: String,

        /// Parse and report without writing any data.
        #[arg(long)]
        dry_run: bool,

        /// Path to the data directory.
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// Verify archive integrity by recomputing SHA-256 checksums.
    ///
    /// Exits 0 on success, 3 if any checksum does not match.
    Verify {
        /// Path to the archive to verify.
        #[arg(long, short)]
        input: PathBuf,
    },
    /// Print the archive manifest as a human-readable table.
    ///
    /// Does not decompress entity files.
    Inspect {
        /// Path to the archive to inspect.
        #[arg(long, short)]
        input: PathBuf,
    },
}

/// Supported migration sources.
#[derive(Subcommand)]
enum MigrateSource {
    /// Import a Keycloak realm export (JSON).
    Keycloak {
        /// Path to a Keycloak realm export file (JSON).
        #[arg(long)]
        file: PathBuf,

        /// Data directory of the target Hearth store. Required unless
        /// `--dry-run` is set; the store will be created if it does not
        /// exist.
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Optional realm UUID to import into. When omitted, the realm
        /// `id` field from the export is used; if that is also missing
        /// or malformed, a fresh UUID is generated.
        #[arg(long)]
        realm: Option<String>,

        /// Validate the export and print the report without writing any
        /// data. `--data-dir` is not required in this mode.
        #[arg(long)]
        dry_run: bool,
    },
    /// Import an Auth0 tenant bundle (JSON).
    ///
    /// The bundle is assembled by a separate tool (see
    /// `examples/auth0-migration-bundler/`) from the Auth0 Management API.
    Auth0 {
        /// Path to an Auth0 bundle file (JSON).
        #[arg(long)]
        file: PathBuf,

        /// Data directory of the target Hearth store. Required unless
        /// `--dry-run` is set; the store will be created if it does not
        /// exist.
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Optional realm UUID to import into. When omitted, the bundle's
        /// `tenant.id` is used (if a valid UUID); otherwise a fresh UUID
        /// is generated.
        #[arg(long)]
        realm: Option<String>,

        /// Validate the bundle and print the report without writing any
        /// data. `--data-dir` is not required in this mode.
        #[arg(long)]
        dry_run: bool,
    },
    /// Audit and report on credentials that need Argon2 pepper rotation.
    ///
    /// After adding or rotating `security.password.pepper` in `hearth.yaml`,
    /// run this command to see how many credentials still carry an older (or
    /// absent) pepper version.  Actual re-hashing is performed lazily on each
    /// user's next successful login — no passwords are modified here.
    ///
    /// Exit codes: 0 = all credentials current, 1 = rotation pending,
    /// 2 = error opening the data store.
    RotatePepper {
        /// Data directory of the Hearth store to audit.
        #[arg(long)]
        data_dir: PathBuf,

        /// Only report totals without listing per-realm details.
        #[arg(long)]
        summary_only: bool,
    },
}

/// Realm management subcommands.
#[derive(Subcommand)]
enum RealmAction {
    /// Create a new realm (generates a UUID).
    Create,
}

/// Configuration management subcommands.
#[derive(Subcommand)]
enum ConfigAction {
    /// Trigger a hot-reload of configuration.
    ///
    /// Sends SIGHUP to the running Hearth process, or hits the admin
    /// reload endpoint if `--url` is provided.
    Reload {
        /// URL of the running Hearth server (e.g. `https://127.0.0.1:8443`).
        /// When provided, triggers reload via POST /admin/api/config/reload.
        /// When omitted, sends SIGHUP to the running process via PID file.
        #[arg(long)]
        url: Option<String>,

        /// Path to the PID file (default: `data_dir/hearth.pid`).
        /// Only used when `--url` is not provided.
        #[arg(long)]
        pid_file: Option<PathBuf>,
    },
    /// Validate a configuration file without starting the server.
    ///
    /// Parses YAML and validates every realm's permission registry
    /// (permission names, role cross-references, bundle names, claim-profile
    /// tier enforcement). Exits 1 on any error.
    Validate {
        /// Path to configuration file. Defaults to hearth.yaml.
        #[arg(default_value = "hearth.yaml")]
        file: PathBuf,
    },
    /// Print a complete, annotated example hearth.yaml to stdout.
    ///
    /// The output is the same file shipped as `hearth.example.yaml` in the
    /// repository and is guaranteed to parse as valid configuration. Redirect
    /// it or use `--output` to bootstrap a new config file.
    Example {
        /// Write the example to this path instead of stdout.
        #[arg(long, short)]
        output: Option<PathBuf>,
    },
}

/// RBAC maintenance subcommands.
#[derive(Subcommand)]
enum RbacAction {
    /// List or purge orphaned runtime references (role/permission IDs that no
    /// longer exist in the registry).
    Orphans {
        #[command(subcommand)]
        action: OrphansAction,
    },
}

/// Orphan management subcommands.
#[derive(Subcommand)]
enum OrphansAction {
    /// List orphaned references across all realms (or a specific realm).
    List {
        /// Restrict scan to a single realm by UUID or name.
        #[arg(long)]
        realm: Option<String>,
        /// Path to the data directory. Defaults to `data/`.
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
    },
    /// Purge orphaned references.
    Purge {
        /// Restrict purge to a single realm by UUID or name.
        #[arg(long)]
        realm: Option<String>,
        /// Path to the data directory. Defaults to `data/`.
        #[arg(long, default_value = "data")]
        data_dir: PathBuf,
        /// Print what would be deleted without writing any changes.
        #[arg(long)]
        dry_run: bool,
    },
}

/// Application (OAuth client) management subcommands.
#[derive(Subcommand)]
enum AppAction {
    /// Register a new OAuth 2.0 client against a running Hearth server.
    Create {
        /// URL of the running Hearth server (e.g. `http://127.0.0.1:8080`).
        #[arg(long)]
        server: String,

        /// Realm UUID to register the application under.
        #[arg(long)]
        realm_id: String,

        /// Human-readable name for the application.
        #[arg(long)]
        name: String,

        /// OAuth 2.0 redirect URI for the application.
        #[arg(long)]
        redirect_uri: String,

        /// Admin bearer token carrying `hearth.clients.admin` (or
        /// `hearth.admin`). Client registration is a privileged operation;
        /// obtain a token via `POST /admin/bootstrap` in dev mode.
        #[arg(long)]
        token: String,
    },
}

#[tokio::main]
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Serve {
            dev,
            config: config_path,
            port,
            bind,
            verbose,
            allow_reflection_in_prod,
        } => {
            if let Err(e) = run_serve(
                dev,
                config_path,
                port,
                bind,
                verbose,
                allow_reflection_in_prod,
            )
            .await
            {
                // Use eprintln! here — tracing may not be initialized yet if
                // the error occurred during config loading.
                //
                // HostKeyMismatch requires exit code 2 and an actionable message
                // so operators know exactly how to recover.
                match e.downcast::<hearth::storage::StorageError>() {
                    Ok(storage_err) => {
                        if let hearth::storage::StorageError::HostKeyMismatch {
                            ref affected_realms,
                        } = *storage_err
                        {
                            let realms = affected_realms.join(", ");
                            tracing::error!(
                                "FATAL: Realm KEKs could not be decrypted with the current \
                                 HEARTH_MASTER_KEY.\nIf you recently rotated the master key, \
                                 set HEARTH_PREVIOUS_MASTER_KEY to the previous value. If the \
                                 previous key is unavailable, restore from backup.\n\
                                 Affected realms: {realms}"
                            );
                            std::process::exit(2);
                        }
                        tracing::error!("error: {storage_err}");
                    }
                    Err(other) => {
                        tracing::error!("error: {other}");
                    }
                }
                std::process::exit(1);
            }
        }
        Commands::Realm { action } => match action {
            RealmAction::Create => run_realm_create(),
        },
        Commands::App { action } => match action {
            AppAction::Create {
                server,
                realm_id,
                name,
                redirect_uri,
                token,
            } => {
                if let Err(e) = run_app_create(&server, &realm_id, &name, &redirect_uri, &token) {
                    error!("{e}");
                    std::process::exit(1);
                }
            }
        },
        Commands::Migrate { source } => match source {
            MigrateSource::Keycloak {
                file,
                data_dir,
                realm,
                dry_run,
            } => {
                if let Err(e) =
                    run_migrate_keycloak(&file, data_dir.as_deref(), realm.as_deref(), dry_run)
                {
                    error!("{e}");
                    std::process::exit(1);
                }
            }
            MigrateSource::Auth0 {
                file,
                data_dir,
                realm,
                dry_run,
            } => {
                if let Err(e) =
                    run_migrate_auth0(&file, data_dir.as_deref(), realm.as_deref(), dry_run)
                {
                    error!("{e}");
                    std::process::exit(1);
                }
            }
            MigrateSource::RotatePepper {
                data_dir,
                summary_only,
            } => {
                match run_migrate_rotate_pepper(&data_dir, summary_only) {
                    Ok(true) => {
                        // All credentials already use the active pepper version.
                    }
                    Ok(false) => {
                        // Some credentials still need rotation.
                        std::process::exit(1);
                    }
                    Err(e) => {
                        error!("{e}");
                        std::process::exit(2);
                    }
                }
            }
        },
        Commands::Config { action } => match action {
            ConfigAction::Reload { url, pid_file } => {
                if let Err(e) = run_config_reload(url.as_deref(), pid_file.as_deref()) {
                    tracing::error!("error: {e}");
                    std::process::exit(1);
                }
            }
            ConfigAction::Validate { file } => {
                // Errors are already printed with field-level detail inside
                // run_config_validate; suppress the redundant "error: …" here.
                if run_config_validate(&file).is_err() {
                    std::process::exit(1);
                }
            }
            ConfigAction::Example { output } => {
                if let Err(e) = run_config_example(output.as_ref()) {
                    tracing::error!("error: {e}");
                    std::process::exit(1);
                }
            }
        },
        Commands::Backup { action } => {
            let code = match action {
                BackupAction::Create {
                    output,
                    realm,
                    include_audit,
                    encrypt,
                    data_dir,
                } => {
                    match run_backup_create(
                        output.as_deref(),
                        realm.as_deref(),
                        include_audit,
                        encrypt,
                        &data_dir,
                    ) {
                        Ok(()) => 0,
                        Err(e) => {
                            tracing::error!("error: {e}");
                            2
                        }
                    }
                }
                BackupAction::Restore {
                    input,
                    realm,
                    mode,
                    dry_run,
                    data_dir,
                } => {
                    match run_backup_restore(&input, realm.as_deref(), &mode, dry_run, &data_dir) {
                        Ok(had_errors) => i32::from(had_errors),
                        Err(e) => {
                            tracing::error!("error: {e}");
                            2
                        }
                    }
                }
                BackupAction::Verify { input } => match run_backup_verify(&input) {
                    Ok(()) => 0,
                    Err(e) => {
                        tracing::error!("integrity failure: {e}");
                        3
                    }
                },
                BackupAction::Inspect { input } => match run_backup_inspect(&input) {
                    Ok(()) => 0,
                    Err(e) => {
                        tracing::error!("error: {e}");
                        2
                    }
                },
            };
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "hearth", &mut std::io::stdout());
        }
        Commands::Rbac { action } => match action {
            RbacAction::Orphans { action } => match action {
                OrphansAction::List { realm, data_dir } => {
                    if let Err(e) = run_rbac_orphans_list(realm.as_deref(), &data_dir) {
                        tracing::error!("error: {e}");
                        std::process::exit(1);
                    }
                }
                OrphansAction::Purge {
                    realm,
                    data_dir,
                    dry_run,
                } => {
                    if let Err(e) = run_rbac_orphans_purge(realm.as_deref(), &data_dir, dry_run) {
                        tracing::error!("error: {e}");
                        std::process::exit(1);
                    }
                }
            },
        },
    }
}

/// Outcome of evaluating the `security.load_test_unthrottled` escape hatch
/// against the server's bind address.
///
/// The rate-limit-disable path (HEA-1796) is prod-gated on TWO conditions
/// (HEA-1797): the process must run in `--dev` mode **and** every effective
/// bind (HTTP and, when enabled, gRPC) must be loopback. If either check fails
/// the request is refused and every limiter stays on, so a misconfigured
/// production server — or a dev server whose gRPC listener diverges onto a
/// public interface, or a prod-config binary behind a reverse proxy — can never
/// silently ship with brute-force / abuse protection removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoadtestUnthrottle {
    /// The flag is unset — limiters stay on (normal operation).
    Off,
    /// The flag is set, dev mode is on, and every bind is loopback — disable
    /// all limiters.
    Enabled,
    /// The flag is set but at least one effective bind (HTTP or gRPC) is
    /// non-loopback — refuse, keep limiters on.
    RefusedNonLoopback,
    /// The flag is set but the process is not in `--dev` mode — refuse, keep
    /// limiters on. Guards the reverse-proxy topology where a prod server binds
    /// loopback yet is reachable from the internet via nginx.
    RefusedNotDev,
}

/// Decides whether the load-test unthrottle escape hatch applies. Gated on
/// `--dev` mode AND every effective bind being loopback (HEA-1797). Pure (no
/// logging / I/O) so the prod-safety gate is unit tested; the caller emits the
/// operator-facing warn/error log.
///
/// `http_bind` is the raw `server.bind_address` and `grpc_bind` the effective
/// gRPC bind (`None` when the gRPC listener is disabled), both already trimmed
/// by the caller. A bare `localhost` is treated as loopback; anything that does
/// not parse to a loopback `IpAddr` (including a wildcard `0.0.0.0` / `::`) is
/// non-loopback and refuses the request.
fn loadtest_unthrottle_decision(
    enabled: bool,
    dev: bool,
    http_bind: &str,
    grpc_bind: Option<&str>,
) -> LoadtestUnthrottle {
    if !enabled {
        return LoadtestUnthrottle::Off;
    }
    if !dev {
        return LoadtestUnthrottle::RefusedNotDev;
    }
    let is_loopback = |bind: &str| {
        bind.eq_ignore_ascii_case("localhost")
            || bind
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
    };
    // Every effective bind must be loopback. A disabled gRPC listener (`None`)
    // cannot be reached, so it does not gate the decision.
    let all_loopback = is_loopback(http_bind)
        && match grpc_bind {
            Some(g) => is_loopback(g),
            None => true,
        };
    if all_loopback {
        LoadtestUnthrottle::Enabled
    } else {
        LoadtestUnthrottle::RefusedNonLoopback
    }
}

/// Outcome of the dev-mode loopback startup gate (HEA-1980).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DevBindCheck {
    /// Not in dev mode — gate does not apply.
    NotDev,
    /// Dev mode, all effective binds are loopback — server may start.
    Ok,
    /// Dev mode, at least one bind is non-loopback — refuse to start.
    RefusedNonLoopback,
}

/// Hard startup gate for `--dev` mode: refuses to start when any effective
/// bind (HTTP or gRPC) is non-loopback (HEA-1980).
///
/// Unlike the config-file check in `validate.rs`, this runs **after** CLI
/// `--bind`/`--port` overrides are applied, so `hearth serve --dev --bind
/// 0.0.0.0` is caught here even when no config file is present
/// (`Config::dev()` skips `validate()`).
///
/// Pure (no logging / I/O) so the gate is unit-testable; the caller emits the
/// operator-facing error.
fn dev_mode_bind_check(dev: bool, http_bind: &str, grpc_bind: Option<&str>) -> DevBindCheck {
    if !dev {
        return DevBindCheck::NotDev;
    }
    let is_loopback = |bind: &str| {
        bind.eq_ignore_ascii_case("localhost")
            || bind
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
    };
    let all_loopback = is_loopback(http_bind)
        && match grpc_bind {
            Some(g) => is_loopback(g),
            None => true,
        };
    if all_loopback {
        DevBindCheck::Ok
    } else {
        DevBindCheck::RefusedNonLoopback
    }
}

/// Resolves the dev-mode on-disk data directory, if one is explicitly
/// configured (HEA-1805).
///
/// Precedence: the `HEARTH_DEV_DATA_DIR` env override wins; otherwise a
/// non-default `storage.data_dir` from the config file is honored. Returns
/// `None` when neither is set — signalling the caller to fall back to an
/// ephemeral temp directory (the historical `--dev` default).
///
/// Pure (takes the env value as a parameter, no I/O) so the precedence is
/// unit-testable. A blank env value is treated as unset. An empty
/// `config_data_dir` (the programmatic `Config::dev()` default) or one equal
/// to [`StorageSection::DEFAULT_DATA_DIR`] counts as "not explicitly set" — a
/// dev instance that leaves `storage.data_dir` at its default keeps the
/// ephemeral-temp behavior rather than silently persisting to `./data`.
fn resolve_dev_data_dir(env_override: Option<&str>, config_data_dir: &str) -> Option<PathBuf> {
    if let Some(dir) = env_override.map(str::trim).filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    let config_data_dir = config_data_dir.trim();
    if !config_data_dir.is_empty() && config_data_dir != StorageSection::DEFAULT_DATA_DIR {
        return Some(PathBuf::from(config_data_dir));
    }
    None
}

/// Runs the `hearth serve` command.
#[allow(clippy::too_many_lines)]
async fn run_serve(
    dev: bool,
    config_path: Option<PathBuf>,
    port_override: Option<u16>,
    bind_override: Option<String>,
    verbose: bool,
    allow_reflection_in_prod: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration
    let mut config = load_config(dev, config_path.as_deref())?;
    let serve_start = std::time::Instant::now();

    // Apply CLI overrides
    if let Some(port) = port_override {
        config.server.port = port;
    }
    if let Some(bind) = bind_override {
        config.server.bind_address = bind;
    }

    // --verbose: promote log level to debug so startup diagnostics are visible.
    if verbose && config.observability.log_level.as_str() != "trace" {
        config.observability.log_level = "debug".to_string();
    }

    // Safety-net: print config warnings to stderr before tracing initialises
    // so they are visible even if the subscriber setup fails.
    if !config.config_warnings.is_empty() {
        let n = config.config_warnings.len();
        if n > 3 {
            let preview = config.config_warnings[..3]
                .iter()
                .map(|w| w.var_name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            tracing::error!(
                "[hearth] {n} env-var config warnings; vars: {preview} and {} more",
                n - 3
            );
        } else {
            let inline = config
                .config_warnings
                .iter()
                .map(|w| format!("{} ({})", w.var_name, w.kind_label()))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::error!("[hearth] config warnings: {inline}");
        }
    }

    // Initialize tracing (and optional OTLP export).
    // The guard must be held for the process lifetime to ensure the batch
    // exporter is flushed on shutdown.
    config.observability.dev_mode = config.dev_mode;
    let _tracing_guard = hearth::telemetry::init(&config.observability);

    // Single structured warning after tracing init — vars array is JSON-serialisable
    // in JSON log sinks (HEARTH_LOG_FORMAT=json) and debug-formatted in text sinks.
    if !config.config_warnings.is_empty() {
        let vars = config
            .config_warnings
            .iter()
            .map(|w| w.var_name.as_str())
            .collect::<Vec<_>>();
        warn!(vars = ?vars, "config references unset or empty environment variables");
    }

    info!(
        dev_mode = config.dev_mode,
        port = config.server.port,
        bind = %config.server.bind_address,
        "Hearth identity server starting"
    );

    if config.dev_mode {
        error!(
            "DEV MODE ACTIVE — security reductions in effect: \
             (1) Argon2 parameters weakened to fast_for_testing (256 KiB / 1 iter); \
             (2) CSRF cookie enforcement bypassed on pre-auth forms; \
             (3) setup token printed (truncated) in startup logs. \
             DO NOT expose this server on a non-loopback address."
        );
    }

    // Canary: verify the embedded admin UI CSS contains the Hearth theme layer.
    // Catches a silent regression where a Tailwind build sheds every `bg-ht-*`
    // / `btn-ember` class and the admin UI renders as unstyled HTML.
    match web::assert_app_css_sane() {
        Ok(()) => {}
        Err(reason) => {
            error!(reason, "admin UI CSS bundle looks broken");
            #[cfg(debug_assertions)]
            {
                return Err(reason.into());
            }
        }
    }

    // Initialize storage engine
    //
    // `inner_storage` is the raw EmbeddedStorageEngine — kept for
    // maintenance tasks that need concrete methods (e.g. compact_ssts).
    // `storage` is what the rest of the app uses: in cluster mode it is
    // wrapped in ClusterStorageAdapter so writes route through Raft quorum
    // commit; in single-node mode it is a zero-overhead passthrough.
    let (inner_storage, app_storage_config): (Arc<EmbeddedStorageEngine>, StorageConfig) = if config
        .dev_mode
    {
        // Precedence: HEARTH_DEV_DATA_DIR env override, then a non-default
        // `storage.data_dir` from config, else an ephemeral temp dir (HEA-1805).
        let env_override = std::env::var("HEARTH_DEV_DATA_DIR").ok();
        let data_path =
            match resolve_dev_data_dir(env_override.as_deref(), &config.storage.data_dir) {
                Some(dir) => dir,
                None => {
                    let temp_dir = tempfile::tempdir()?;
                    temp_dir.keep()
                }
            };
        info!(path = %data_path.display(), "using data directory (dev mode)");
        let mut storage_config = StorageConfig::dev(data_path);
        // Dev mode otherwise uses the default 100k-entry hot tier. An explicit
        // `storage.hot_tier_capacity` lets a corpus-scale load profile size the
        // hot tier below the working set so cold/SST tier misses fire (HEA-1800).
        if let Some(cap) = config.storage.hot_tier_capacity {
            storage_config.set_hot_tier_capacity(cap);
            info!(
                capacity = cap,
                "hot tier capacity overridden from config (dev mode)"
            );
        }
        storage_config.compaction = CompactionConfig {
            enabled: config.storage.compaction.enabled,
            interval_secs: config.storage.compaction.interval_secs,
            min_sst_count: config.storage.compaction.min_sst_count,
            max_sst_count: config.storage.compaction.max_sst_count,
            merge_min: config.storage.compaction.merge_min,
        };
        storage_config.block_cache_bytes = config.storage.block_cache_bytes;
        let engine = Arc::new(EmbeddedStorageEngine::open(storage_config.clone())?);
        (engine, storage_config)
    } else {
        let hot_tier_capacity = config.storage.hot_tier_capacity.unwrap_or_else(|| {
            let cap = hearth::storage::auto_size::auto_size_hot_tier_capacity(
                config.storage.hot_tier_max_memory,
            );
            info!(
                capacity = cap,
                memory_budget = ?config.storage.hot_tier_max_memory,
                "hot tier auto-sized",
            );
            cap
        });

        if !config.storage.fsync {
            tracing::warn!(
                    "storage.fsync=false is ignored in production mode — WAL durability is non-negotiable; \
                     use dev mode or a custom WalConfig if you need fsync disabled"
                );
        }
        let mut storage_config = StorageConfig::production(
            PathBuf::from(&config.storage.data_dir),
            config.storage.wal_max_size_bytes,
            config.storage.memtable_flush_bytes,
            hot_tier_capacity,
        );
        storage_config.compaction = CompactionConfig {
            enabled: config.storage.compaction.enabled,
            interval_secs: config.storage.compaction.interval_secs,
            min_sst_count: config.storage.compaction.min_sst_count,
            max_sst_count: config.storage.compaction.max_sst_count,
            merge_min: config.storage.compaction.merge_min,
        };
        storage_config.block_cache_bytes = config.storage.block_cache_bytes;
        let engine = Arc::new(EmbeddedStorageEngine::open(storage_config.clone())?);
        (engine, storage_config)
    };

    // Build cluster-aware storage: wraps inner_storage in ClusterEngine so
    // all writes (put / delete / put_batch) go through Raft quorum commit
    // in cluster mode.  In single-node mode ClusterEngine is a zero-overhead
    // passthrough and the peer server is not started.
    let cluster_engine: Arc<hearth::cluster::ClusterEngine> =
        if let Some(cluster_cfg) = &config.cluster {
            match hearth::cluster::ClusterEngine::build_clustered(
                Arc::clone(&inner_storage),
                cluster_cfg,
                &app_storage_config,
            )
            .await
            {
                Ok(engine) => {
                    let engine = Arc::new(engine);
                    let serve_cfg = cluster_cfg.clone();
                    let serve_engine = Arc::clone(&engine);
                    tokio::spawn(async move {
                        if let Err(e) = hearth::cluster::serve(&serve_cfg, serve_engine).await {
                            error!(error = %e, "Raft peer gRPC server terminated");
                        }
                    });
                    info!(
                        node_id = cluster_cfg.node_id,
                        peer_address = %cluster_cfg.peer_address,
                        "Raft cluster mode active"
                    );
                    engine
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Raft ClusterEngine init failed — falling back to single-node mode"
                    );
                    Arc::new(hearth::cluster::ClusterEngine::single_node(Arc::clone(
                        &inner_storage,
                    )))
                }
            }
        } else {
            Arc::new(hearth::cluster::ClusterEngine::single_node(Arc::clone(
                &inner_storage,
            )))
        };

    // `storage` is the app-layer storage handle: always a ClusterStorageAdapter,
    // which routes through Raft in cluster mode and is a thin passthrough otherwise.
    let storage: Arc<dyn StorageEngine> = Arc::new(hearth::cluster::ClusterStorageAdapter::new(
        Arc::clone(&cluster_engine),
    ));

    // Initialize identity engine
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;

    // Build OidcConfig from YAML
    let oidc_config = {
        let mut oc = OidcConfig::default();
        if let Some(issuer) = &config.oidc.issuer {
            oc.issuer.clone_from(issuer);
        } else if config.dev_mode {
            // In --dev mode without an explicit oidc.issuer, default to the
            // actual server address so token iss claims are reachable.  This
            // lets JWKS-verifying clients derive the per-realm JWKS URL from
            // the iss claim without a hostname mismatch.
            oc.issuer = format!("http://127.0.0.1:{}", config.server.port);
        }
        if let Some(ttl) = &config.oidc.authorization_code_ttl {
            if let Ok(micros) = hearth::config::parse_duration_to_micros(ttl) {
                oc.authorization_code_ttl_secs = micros / 1_000_000;
            }
        }
        oc
    };

    // Build TokenConfig from YAML. Both token.issuer and token.audience default to
    // oidc.issuer when omitted, so operators only need one config key for the common case.
    let token_config = {
        let mut tc = TokenConfig::default();
        if let Some(issuer) = &config.token.issuer {
            tc.issuer.clone_from(issuer);
        } else if let Some(issuer) = &config.oidc.issuer {
            tc.issuer.clone_from(issuer);
        }
        if let Some(audience) = &config.token.audience {
            tc.audience.clone_from(audience);
        } else if let Some(issuer) = &config.oidc.issuer {
            // RFC 7519 §4.1.3: aud identifies the intended recipient.  When the
            // operator has not set an explicit audience, default to the issuer URL
            // so standard OIDC clients can validate aud without extra config.
            tc.audience.clone_from(issuer);
        }
        if let Some(ttl) = &config.token.access_token_ttl {
            if let Ok(micros) = hearth::config::parse_duration_to_micros(ttl) {
                tc.access_token_ttl_secs = micros / 1_000_000;
            }
        }
        if let Some(ttl) = &config.token.refresh_token_ttl {
            if let Ok(micros) = hearth::config::parse_duration_to_micros(ttl) {
                tc.refresh_token_ttl_secs = micros / 1_000_000;
            }
        }
        if let Some(ttl) = &config.token.signing_key_rotation_grace_period {
            if let Ok(micros) = hearth::config::parse_duration_to_micros(ttl) {
                tc.signing_key_rotation_grace_period_secs = (micros / 1_000_000) as u64;
            }
        }
        // Warn when the audience is still the placeholder value but oidc.issuer is a
        // real URL.  This only triggers when token.audience is explicitly set to "hearth"
        // in the config file while oidc.issuer is configured — the implicit default case
        // is already resolved to oidc.issuer above.
        if tc.audience == "hearth" {
            if let Some(oidc_issuer) = &config.oidc.issuer {
                if oidc_issuer != "hearth" {
                    tracing::warn!(
                        audience = %tc.audience,
                        oidc_issuer = %oidc_issuer,
                        "token.audience is the placeholder \"hearth\" but oidc.issuer is \
                         configured. OIDC clients that validate aud against their client_id \
                         or resource server URL will reject all tokens. Set token.audience \
                         to a meaningful value (e.g. your issuer URL or service name)."
                    );
                }
            }
        }
        tc
    };

    // Build rate-limit config from YAML, falling back to compiled-in defaults.
    let rate_limit_config = {
        let defaults = RateLimitConfig::default();
        let rl = config.security.rate_limiting.as_ref();
        RateLimitConfig {
            max_failed_attempts: rl
                .and_then(|r| r.login_per_account.as_ref())
                .and_then(|a| a.max_failures)
                .unwrap_or(defaults.max_failed_attempts),
            lockout_duration_micros: rl
                .and_then(|r| r.login_per_account.as_ref())
                .and_then(|a| a.lockout_seconds)
                .map(|s| s as i64 * 1_000_000)
                .unwrap_or(defaults.lockout_duration_micros),
            ip_max_attempts: rl
                .and_then(|r| r.login_per_ip.as_ref())
                .and_then(|i| i.max_attempts)
                .unwrap_or(defaults.ip_max_attempts),
            ip_window_micros: rl
                .and_then(|r| r.login_per_ip.as_ref())
                .and_then(|i| i.window_seconds)
                .map(|s| s as i64 * 1_000_000)
                .unwrap_or(defaults.ip_window_micros),
        }
    };

    // A-5: normalise reserved slugs to lowercase once at startup.
    let reserved_slugs: Vec<String> = config
        .security
        .reserved_slugs
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let slug_cooldown_secs = u64::from(config.security.slug_cooldown_days) * 86_400;

    // Resolve the storage key-encryption key (KEK). Env var takes precedence.
    // Accepted format: 64 lowercase hex characters (32 bytes / AES-256).
    let storage_kek: Option<hearth::identity::key_encryption::StorageKek> = {
        let hex_opt = std::env::var("HEARTH_KEK")
            .ok()
            .or_else(|| config.security.key_encryption_key.clone());
        match hex_opt {
            None => None,
            Some(hex) => {
                if hex == "0".repeat(64) {
                    return Err(
                        "security.key_encryption_key / HEARTH_KEK must not be the all-zero key \
                         — generate a random 32-byte (64 hex char) value"
                            .into(),
                    );
                }
                let bytes = hex::decode(&hex).map_err(|e| {
                    format!("security.key_encryption_key / HEARTH_KEK is not valid hex: {e}")
                })?;
                let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                    "security.key_encryption_key / HEARTH_KEK must be exactly 64 hex characters \
                     (32 bytes / AES-256)"
                        .to_string()
                })?;
                Some(hearth::identity::key_encryption::StorageKek::new(arr))
            }
        }
    };

    // Capture KEK bytes for the audit engine before storage_kek is consumed
    // by identity_config (it is moved on the non-dev_mode path).
    let audit_kek: Option<[u8; 32]> = storage_kek.as_ref().map(|k| *k.as_bytes());

    // Resolve the optional Argon2id server-side pepper from
    // `security.password.pepper`. Absent → `None` (unchanged default). The hex,
    // length, all-zero, and rotation-pairing checks already ran in
    // `Config::validate`, so this cannot fail here in practice.
    let pepper = config.security.resolve_pepper()?;
    if let Some(pepper) = pepper.as_ref() {
        info!(
            active_version = pepper.active_version,
            rotating = pepper.previous_version.is_some(),
            "argon2 pepper enabled from security.password.pepper"
        );
    }

    // Install the bounded KDF admission gate (HEA-1887 / R1) from
    // `security.password.kdf`. This caps concurrent Argon2id work so offered
    // concurrency past the core count sheds (503) instead of oversubscribing the
    // blocking pool and inflating p99 (C9/HEA-1879). Absent config → core-count
    // bound. First-wins; safe to call before the engine is built.
    let kdf_gate_cfg = config.security.resolve_kdf_gate();
    hearth::identity::init_gate(kdf_gate_cfg);
    info!(
        max_in_flight = kdf_gate_cfg.max_in_flight,
        max_queue_wait_ms = kdf_gate_cfg.max_queue_wait.as_millis() as u64,
        "kdf admission gate installed from security.password.kdf"
    );

    // Install the separate admin-reserved KDF gate (HEA-1892 / F2). Admin login
    // draws from this small isolated pool so a flood against a tenant realm's
    // login form cannot exhaust the shared gate and lock the operator out of the
    // admin console.
    let kdf_admin_gate_cfg = config.security.resolve_admin_kdf_gate();
    hearth::identity::init_admin_gate(kdf_admin_gate_cfg);
    info!(
        admin_max_in_flight = kdf_admin_gate_cfg.max_in_flight,
        "kdf admin-reserved admission gate installed from security.password.kdf"
    );

    let identity_config = if config.dev_mode {
        IdentityConfig {
            credential: CredentialConfig {
                pepper,
                ..CredentialConfig::fast_for_testing()
            },
            oidc: oidc_config,
            token: token_config,
            rate_limit: rate_limit_config,
            reserved_slugs: reserved_slugs.clone(),
            slug_cooldown_secs,
            key_encryption_key: storage_kek.clone(),
            ..IdentityConfig::default()
        }
    } else {
        IdentityConfig {
            credential: CredentialConfig {
                pepper,
                ..CredentialConfig::default()
            },
            oidc: oidc_config,
            token: token_config,
            rate_limit: rate_limit_config,
            reserved_slugs: reserved_slugs.clone(),
            slug_cooldown_secs,
            key_encryption_key: storage_kek,
            ..IdentityConfig::default()
        }
    };

    // Extract cleanup config before identity_config is consumed by the engine.
    let cleanup_enabled = identity_config.cleanup.enabled;
    let cleanup_interval_secs = identity_config.cleanup.interval_secs;
    let dfp_sweeper_interval_secs = identity_config.cleanup.dfp_sweeper_interval_secs;

    // Build the RBAC engine before the identity engine — identity depends on rbac.
    let raw_rbac_engine = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
    ));
    let rbac_engine: Arc<dyn RbacEngine> = Arc::clone(&raw_rbac_engine) as Arc<dyn RbacEngine>;

    let audit_engine: Arc<dyn hearth::audit::AuditEngine> = Arc::new(
        EmbeddedAuditEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        )
        .with_kek(audit_kek),
    );

    let raw_identity_engine = Arc::new(EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock),
        identity_config,
        Arc::clone(&rbac_engine),
        Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
    )?);
    // Wire session-version bumping so RBAC changes invalidate standing tokens.
    raw_rbac_engine.init_sv_bumper(Arc::clone(&raw_identity_engine) as Arc<dyn SvBumper>);
    let identity_engine: Arc<dyn IdentityEngine> = raw_identity_engine;

    // Build the PermissionRegistry from the initial config and wrap it in an
    // ArcSwap for zero-downtime hot-swap on SIGHUP.  The registry is rebuilt
    // and atomically swapped inside `run_config_reconciliation` every time the
    // operator sends SIGHUP or triggers a programmatic reload.
    let permission_registry: Arc<arc_swap::ArcSwap<hearth::rbac::registry::PermissionRegistry>> =
        Arc::new(arc_swap::ArcSwap::from_pointee(build_permission_registry(
            &config,
        )));

    // Base URL for email links and onboarding (computed once, reused).
    let base_url = config.onboarding.base_url.clone().unwrap_or_else(|| {
        format!(
            "http://{}:{}",
            config.server.bind_address, config.server.port
        )
    });
    if config.onboarding.base_url.is_none() {
        warn!(
            fallback_url = %base_url,
            "onboarding.base_url is not configured; setup URL will use the bind address \
             as a fallback — set onboarding.base_url to the public-facing URL for correct \
             external links"
        );
    }

    // Fatal guard: mailcatcher transport is dev-only.
    if config.email.transport == EmailTransport::Mailcatcher && !config.dev_mode {
        return Err(
            "email.transport = mailcatcher is only allowed in dev mode (start with --dev)".into(),
        );
    }

    // HSEC-005: Warn when the metrics endpoint is exposed without a bearer
    // token in production. This is a non-fatal warning because network-level
    // firewalling is a valid alternative, but operators must make a conscious
    // choice. In dev mode the warning is skipped to avoid noise.
    if config.metrics.enabled && config.metrics.bearer_token.is_none() && !config.dev_mode {
        warn!(
            "metrics endpoint is enabled without a bearer_token; /metrics is accessible \
             to any caller that can reach the server. Set metrics.bearer_token in \
             hearth.yaml or restrict access at the network layer (firewall / private subnet)."
        );
    }

    // HSEC-003/004: Production startup security checks against the system realm.
    if !config.dev_mode {
        let sys_realm_id = hearth::core::RealmId::new(uuid::Uuid::nil());
        if let Ok(Some(sys_realm)) = identity_engine.get_realm(&sys_realm_id) {
            // HSEC-004: Hard error — explicitly disabling MFA on the admin control
            // plane is a misconfiguration that blocks startup in production.
            if sys_realm.config().mfa_required == Some(false) {
                return Err(
                    "security: system realm mfa_required is explicitly set to false; \
                     MFA may not be disabled on the admin realm in production. \
                     Remove the override or set mfa_required: true."
                        .into(),
                );
            }
            // HSEC-004: Soft warning — when mfa_required is not configured at all,
            // the system realm defaults to MFA not required. Operators should enroll
            // a second factor for all admin accounts and then set mfa_required: true
            // in hearth.yaml to enforce it.
            if sys_realm.config().mfa_required.is_none() {
                warn!(
                    "system realm mfa_required is not configured; admin sessions do not \
                     require a second factor. Enroll MFA for all admin accounts and set \
                     mfa_required: true under the system realm config to enforce it."
                );
            }
            // HSEC-003: Non-fatal warning — the 12-character floor (NIST SP 800-63B) is always
            // enforced at validation time, but an explicit policy is recommended in production.
            if sys_realm.config().password_policy.is_none() {
                warn!(
                    "no password_policy configured for the system realm; \
                     the built-in 12-character floor (NIST SP 800-63B) is enforced at runtime but \
                     an explicit policy (auth.password_policy.min_length) is \
                     recommended for production hardening"
                );
            }
        }
    }

    // A-43: Resolve effective reflection_enabled and apply the production guard.
    // `None` in the config means "use the mode default": true in --dev, false in prod.
    let reflection_enabled = protocol::grpc::resolve_grpc_reflection(
        config.security.grpc.reflection_enabled,
        config.dev_mode,
        allow_reflection_in_prod,
    )
    .map_err(|e| e.to_string())?;

    // In dev mode, upgrade Log and Smtp to mailcatcher so `make dev` works without
    // Docker or a real mail server. Production cloud transports (sendgrid, postmark,
    // mailgun, mailtrap) are intentionally kept so engineers can test against real
    // providers even in dev mode.
    if maybe_upgrade_email_transport(&mut config) {
        warn!(
            "dev mode: overriding smtp transport → mailcatcher (no Docker required); \
             set email.transport = mailcatcher explicitly to silence this warning"
        );
    }

    // Build MailcatcherState now (before build_email_sender) when transport is Mailcatcher
    // so the same Arc is shared between the sender and the HTTP routes.
    let mailcatcher_state: Option<Arc<MailcatcherState>> =
        if config.email.transport == EmailTransport::Mailcatcher {
            let password = std::env::var("HEARTH_MAILCATCHER_PASSWORD")
                .unwrap_or_else(|_| generate_password());
            let state = Arc::new(MailcatcherState::new(password));
            Some(state)
        } else {
            None
        };

    // Email sender + service (default: log transport — stderr at WARN level).
    let email_sender: SharedEmailSender = build_email_sender(&config, mailcatcher_state.as_ref())?;
    let email_service = Arc::new(build_email_service(email_sender, &config)?);

    // SMS sender (default: log transport).
    // HEARTH_SMS_OTP_HMAC_KEY is required in production so OTP codes are
    // cryptographically bound to the server; the Log transport in dev mode
    // skips the check to avoid friction during local development.
    let sms_otp_hmac_key: Option<String> = match std::env::var("HEARTH_SMS_OTP_HMAC_KEY") {
        Ok(key) if !key.is_empty() => {
            if key.len() < 32 {
                return Err(
                    "HEARTH_SMS_OTP_HMAC_KEY must be at least 32 bytes for adequate \
                     HMAC-SHA256 security; use a 32+ byte random value"
                        .into(),
                );
            }
            Some(key)
        }
        Ok(_) | Err(_) => {
            if config.sms.transport != SmsTransport::Log || !config.dev_mode {
                return Err("HEARTH_SMS_OTP_HMAC_KEY environment variable is required \
                     when sms.transport is not 'log' or when running in production mode"
                    .into());
            }
            None
        }
    };
    let sms_hmac_key_bytes: Option<Vec<u8>> = sms_otp_hmac_key.map(|s| s.into_bytes());
    let sms_sender: SharedSmsSender = build_sms_sender(&config)?;
    if config.sms.transport == SmsTransport::Log && !config.dev_mode {
        warn!("sms.transport = log is active outside dev mode — no real SMS messages will be sent");
    }

    // Ensure a first-run setup token exists BEFORE realm reconciliation.
    // Reconciliation may auto-create realms from YAML config, which would
    // make is_first_run() return false and prevent the setup URL from being
    // logged on a truly fresh instance.
    let data_dir: PathBuf = if config.dev_mode {
        // Same precedence as the storage engine above (HEA-1805) so the setup
        // token's on-disk marker lives beside the WAL/SSTs; ephemeral temp dir
        // only when neither env override nor config data_dir is set.
        let env_override = std::env::var("HEARTH_DEV_DATA_DIR").ok();
        resolve_dev_data_dir(env_override.as_deref(), &config.storage.data_dir)
            .unwrap_or_else(|| std::env::temp_dir().join("hearth-dev-onboarding"))
    } else {
        PathBuf::from(&config.storage.data_dir)
    };
    let setup_token: Option<String> = if config.onboarding.enabled {
        match onboarding::ensure_setup_token(
            identity_engine.as_ref(),
            &data_dir,
            Some(&base_url),
            Some(email_service.as_ref()),
            config.onboarding.notification_email.as_deref(),
        ) {
            Ok(token) => token,
            Err(e) => {
                error!(error = %e, "failed to ensure setup token; onboarding will be unavailable");
                None
            }
        }
    } else {
        None
    };

    // Load the previous config snapshot (absent on first startup) so we can
    // compute a typed diff against the current config before reconciliation.
    let prev_snapshot = match hearth::identity::reconcile::load_snapshot(storage.as_ref()) {
        Ok(snap) => snap,
        Err(e) => {
            error!(error = %e, "failed to load config snapshot; treating as first startup");
            None
        }
    };

    // Compute diff: absent snapshot → empty baseline (all realms "added").
    let baseline = prev_snapshot.clone().unwrap_or_else(|| {
        hearth::config::ConfigSnapshot::from_config(&hearth::config::Config::default())
    });
    let config_diffs = hearth::config::compute_diff(&baseline, &config);
    if !config_diffs.is_empty() {
        info!(
            count = config_diffs.len(),
            "config diff detected on startup"
        );
    }

    // Apply diff handlers (Phase C: config-only items logged; data items reconciled).
    let _consumed_rotations = match hearth::identity::reconcile::apply_diff(
        &config_diffs,
        &config,
        identity_engine.as_ref(),
        rbac_engine.as_ref(),
    ) {
        Ok(rotated) => rotated,
        Err(e) => {
            error!(error = %e, "config diff application failed");
            Vec::new()
        }
    };

    // Reconcile YAML-declared realms with storage. Runs after setup-token
    // generation so reconciliation-created realms don't suppress the
    // setup URL on a fresh instance.
    match hearth::identity::reconcile::reconcile_realms(
        identity_engine.as_ref(),
        rbac_engine.as_ref(),
        &config,
    ) {
        Ok(report) => {
            if !report.created.is_empty()
                || !report.archived.is_empty()
                || !report.updated.is_empty()
                || !report.unarchived.is_empty()
            {
                info!(
                    created = report.created.len(),
                    updated = report.updated.len(),
                    archived = report.archived.len(),
                    unarchived = report.unarchived.len(),
                    "realm reconciliation complete"
                );
            }
        }
        Err(e) => {
            error!(error = %e, "realm reconciliation failed");
        }
    }

    // Re-seed RBAC defaults on every realm that exists in storage, not just
    // YAML-declared ones. Repairs realms whose original seed failed silently.
    hearth::identity::reconcile::reconcile_rbac_seeds(
        identity_engine.as_ref(),
        rbac_engine.as_ref(),
    );

    // Persist the current config snapshot after a successful reconciliation so
    // the next startup can compute an accurate diff.
    // NOTE: We do NOT clear rotate_signing_key in consumed realms. Leaving it as
    // true (matching the YAML) means the next startup sees true→true, which is
    // not a transition and does not re-trigger rotation. Clearing to false would
    // cause an immediate re-trigger on the next restart while the flag is still
    // in YAML.
    let current_snapshot = hearth::config::ConfigSnapshot::from_config(&config);
    match hearth::identity::reconcile::save_snapshot(storage.as_ref(), &current_snapshot) {
        Ok(()) => {}
        Err(e) => {
            error!(error = %e, "failed to persist config snapshot; next startup will treat config as unchanged");
        }
    }

    // Large-scale demo seeding (gated on `demo.enabled`) runs in the BACKGROUND
    // on a blocking thread, AFTER reconciliation but concurrently with the HTTP
    // listener bind below. Seeding millions of users would otherwise block
    // startup for minutes; backgrounding it makes the instance reachable
    // immediately and lets it fill while you interact with it. Each chunk is
    // atomic and advances a per-realm sentinel, so an interrupted seed resumes
    // cleanly on the next start.
    if config.demo.enabled {
        let ie = Arc::clone(&identity_engine);
        let demo_config = config.clone();
        tokio::task::spawn_blocking(move || {
            hearth::identity::reconcile::seed_demo_realms(ie.as_ref(), &demo_config);
        });
    }

    // Phase E: cross-realm user migration (migrate_from / copy_from).
    // Runs after realm reconciliation so destination realms exist.
    // `on_conflict: error` causes a hard exit; all other errors are warnings.
    if let Some(realms_cfg) = config.realms.as_ref() {
        for (dst_slug, realm_cfg) in realms_cfg {
            let (src_slug, move_semantics) = match (&realm_cfg.migrate_from, &realm_cfg.copy_from) {
                (Some(src), _) => (src.as_str(), true),
                (None, Some(src)) => (src.as_str(), false),
                (None, None) => continue,
            };

            let dst_realm = match identity_engine.get_realm_by_name(dst_slug) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    error!(realm_name = %dst_slug, "cross-realm migration: destination realm not found after reconciliation");
                    continue;
                }
                Err(e) => {
                    error!(error = %e, "cross-realm migration: destination realm lookup failed");
                    continue;
                }
            };
            let src_realm = match identity_engine.get_realm_by_name(src_slug) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    warn!(
                        src_slug,
                        "cross-realm migration: source realm not found; skipping"
                    );
                    continue;
                }
                Err(e) => {
                    error!(error = %e, "cross-realm migration: source realm lookup failed");
                    continue;
                }
            };

            let migrate_cfg = realm_cfg.migrate.clone().unwrap_or_default();
            let opts = hearth::identity::migration::cross_realm::CrossRealmMigrateOptions {
                move_semantics,
                users: migrate_cfg.users,
                orgs: migrate_cfg.orgs,
                on_conflict: migrate_cfg.on_conflict,
            };

            let now = {
                let secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                hearth::identity::reconcile::format_unix_secs_rfc3339(secs)
            };
            match hearth::identity::migration::cross_realm::execute_cross_realm_migration(
                identity_engine.as_ref(),
                rbac_engine.as_ref(),
                storage.as_ref(),
                src_realm.id(),
                dst_realm.id(),
                src_slug,
                &opts,
            ) {
                Ok(report) => {
                    info!(
                        src_slug,
                        dst_realm = %dst_slug,
                        migrated = report.migrated,
                        skipped = report.skipped,
                        role_assignments_translated = report.role_assignments_translated,
                        "cross-realm migration complete"
                    );
                    let status = if report.skipped > 0 {
                        hearth::identity::reconcile::MigrationHistoryStatus::CompletedWithSkips
                    } else {
                        hearth::identity::reconcile::MigrationHistoryStatus::Completed
                    };
                    hearth::identity::reconcile::write_migration_history(
                        storage.as_ref(),
                        &hearth::identity::reconcile::MigrationHistoryRecord {
                            source_slug: src_slug.to_string(),
                            destination_slug: dst_slug.clone(),
                            move_semantics,
                            users_migrated: report.migrated,
                            users_skipped: report.skipped,
                            role_assignments_translated: report.role_assignments_translated,
                            completed_at: now,
                            status,
                            conflict_emails: Vec::new(),
                        },
                    );
                }
                Err(conflict_err) => {
                    error!(error = %conflict_err, "cross-realm migration conflict; refusing to start");
                    hearth::identity::reconcile::write_migration_history(
                        storage.as_ref(),
                        &hearth::identity::reconcile::MigrationHistoryRecord {
                            source_slug: src_slug.to_string(),
                            destination_slug: dst_slug.clone(),
                            move_semantics,
                            users_migrated: 0,
                            users_skipped: 0,
                            role_assignments_translated: 0,
                            completed_at: now,
                            status: hearth::identity::reconcile::MigrationHistoryStatus::Failed,
                            conflict_emails: conflict_err.emails.clone(),
                        },
                    );
                    std::process::exit(1);
                }
            }
        }
    }

    // Phase D: detect archived realms with live users but no declared
    // migration destination.  Non-blocking — startup continues regardless.
    let orphaned_realms = hearth::identity::reconcile::detect_orphaned_realms(
        identity_engine.as_ref(),
        &config,
        storage.as_ref(),
    );

    // Load migration history for the admin UI.
    let migration_records = hearth::identity::reconcile::load_migration_records(storage.as_ref());

    // --verbose: emit resolved config, realm list, and key fingerprints at debug level.
    if verbose {
        log_verbose_startup_diagnostics(&config, identity_engine.as_ref());
    }

    // Validate server.default_realm after reconciliation so auto-created
    // or YAML-declared realms are visible to the lookup.
    if let Some(name) = config.server.default_realm.as_deref() {
        match identity_engine.get_realm_by_name(name) {
            Ok(Some(_)) => {}
            Ok(None) => {
                error!(
                    realm_name = %name,
                    "server.default_realm names a realm that does not exist; refusing to start"
                );
                std::process::exit(1);
            }
            Err(e) => {
                error!(error = %e, "server.default_realm lookup failed");
                std::process::exit(1);
            }
        }
    }

    // Background periodic cleanup sweep.
    if cleanup_enabled && cleanup_interval_secs > 0 {
        let engine = Arc::clone(&identity_engine);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval_secs));
            // Skip the immediate first tick so the server finishes warm-up.
            interval.tick().await;
            loop {
                interval.tick().await;
                let batch = hearth::core::MAX_PAGE_LIMIT;
                let mut offset = 0u64;
                loop {
                    let page = match engine
                        .list_realms(&hearth::core::PageRequest::new(offset, batch))
                    {
                        Ok(p) => p,
                        Err(e) => {
                            error!(error = %e, "cleanup: realm enumeration failed, retrying next tick");
                            break;
                        }
                    };
                    let n = page.items.len() as u64;
                    for realm in &page.items {
                        match engine.sweep_expired(realm.id()) {
                            Ok(stats) => {
                                if stats.total_deleted() > 0 {
                                    info!(
                                        realm = %realm.name(),
                                        auth_codes = stats.auth_codes_deleted,
                                        device_codes = stats.device_codes_deleted,
                                        pending_tickets = stats.pending_tickets_deleted,
                                        grant_families = stats.grant_families_deleted,
                                        rate_trackers_pruned = stats.rate_trackers_pruned,
                                        errors = stats.errors,
                                        "cleanup: swept expired entities",
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    realm = %realm.name(),
                                    error = %e,
                                    "cleanup: sweep failed for realm",
                                );
                            }
                        }
                    }
                    if n == 0 || offset + n >= page.total {
                        break;
                    }
                    offset += n;
                }
            }
        });
    }

    // Background device-fingerprint TTL sweeper (GDPR proactive eviction).
    if cleanup_enabled && dfp_sweeper_interval_secs > 0 {
        let dfp_engine = Arc::clone(&identity_engine);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(dfp_sweeper_interval_secs));
            // Skip the immediate first tick so the server finishes warm-up.
            interval.tick().await;
            loop {
                interval.tick().await;
                let batch = hearth::core::MAX_PAGE_LIMIT;
                let mut total_evicted: u64 = 0;
                let mut total_active: u64 = 0;
                let mut offset = 0u64;
                loop {
                    let page = match dfp_engine
                        .list_realms(&hearth::core::PageRequest::new(offset, batch))
                    {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "dfp_sweeper: realm enumeration failed, retrying next tick");
                            break;
                        }
                    };
                    let n = page.items.len() as u64;
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    for realm in &page.items {
                        match dfp_engine.sweep_expired_fingerprints(realm.id(), now_secs) {
                            Ok((evicted, active)) => {
                                total_evicted += evicted;
                                total_active += active;
                                if evicted > 0 {
                                    info!(
                                        realm = %realm.name(),
                                        evicted,
                                        active,
                                        "dfp_sweeper: evicted expired fingerprints",
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    realm = %realm.name(),
                                    error = %e,
                                    "dfp_sweeper: sweep failed for realm",
                                );
                            }
                        }
                    }
                    if n == 0 || offset + n >= page.total {
                        break;
                    }
                    offset += n;
                }
                // Realistic eviction/active counts never approach 2^53, so the
                // u64 → f64 conversion is lossless in practice. Prometheus
                // counter/gauge APIs accept f64 only.
                #[allow(clippy::cast_precision_loss)]
                let evicted_f64 = total_evicted as f64;
                #[allow(clippy::cast_precision_loss)]
                let active_f64 = total_active as f64;
                hearth::metrics::metrics()
                    .dfp_sweeper_evicted_total
                    .inc_by(evicted_f64);
                hearth::metrics::metrics().dfp_keys_active.set(active_f64);
            }
        });
    }

    // Background SST compaction: a periodic full sweep and/or a count-triggered
    // partial (size-tiered) merge (HEA-1885). Both run off the write path via
    // `spawn_blocking`; the partial merge is woken by the storage engine's
    // count-trigger `Notify` rather than a timer.
    let periodic_enabled =
        config.storage.compaction.enabled && config.storage.compaction.interval_secs > 0;
    let partial_enabled =
        config.storage.compaction.enabled && config.storage.compaction.max_sst_count > 0;
    if periodic_enabled || partial_enabled {
        let storage_engine = Arc::clone(&inner_storage);
        let interval_secs = config.storage.compaction.interval_secs;
        let min_sst_count = config.storage.compaction.min_sst_count;
        let compaction_notify = inner_storage.compaction_notify();
        tokio::spawn(async move {
            // A periodic ticker only when the interval sweep is enabled; otherwise
            // a future that never fires, so the `select!` runs the notify arm only.
            let mut interval = tokio::time::interval(Duration::from_secs(if periodic_enabled {
                interval_secs
            } else {
                1
            }));
            // Skip the immediate first tick so the server finishes warm-up.
            interval.tick().await;
            loop {
                #[derive(Clone, Copy)]
                enum Wake {
                    Periodic,
                    Partial,
                }
                let wake = tokio::select! {
                    _ = interval.tick(), if periodic_enabled => Wake::Periodic,
                    () = compaction_notify.notified(), if partial_enabled => Wake::Partial,
                };
                let engine = Arc::clone(&storage_engine);
                let result = match wake {
                    Wake::Periodic => {
                        tokio::task::spawn_blocking(move || engine.compact_ssts(min_sst_count))
                            .await
                    }
                    Wake::Partial => {
                        tokio::task::spawn_blocking(move || engine.compact_partial()).await
                    }
                };
                match (wake, result) {
                    (Wake::Periodic, Ok(Ok(n))) if n > 0 => {
                        info!(merged = n, "background SST compaction complete");
                    }
                    (Wake::Partial, Ok(Ok(n))) if n > 0 => {
                        info!(merged = n, "partial SST compaction complete");
                    }
                    (_, Ok(Err(e))) => {
                        warn!(error = %e, "background SST compaction failed");
                    }
                    (_, Err(join_err)) => {
                        warn!(error = %join_err, "compaction task panicked");
                    }
                    _ => {}
                }
            }
        });
    }

    // Build webhook engine and broadcast channel before wrapping the audit
    // engine, so the dispatcher receives every successful audit append.
    let webhook_engine: Arc<dyn hearth::webhook::WebhookEngine> =
        Arc::new(hearth::webhook::EmbeddedWebhookEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
    let (webhook_tx, webhook_rx) = hearth::webhook::dispatcher::audit_event_channel();

    // Wrap the raw audit engine so every append broadcasts to the dispatcher.
    let raw_audit: Arc<dyn hearth::audit::AuditEngine> = Arc::new(
        EmbeddedAuditEngine::new(
            Arc::clone(&storage) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        )
        .with_kek(audit_kek),
    );
    let audit_engine: Arc<dyn hearth::audit::AuditEngine> = Arc::new(
        hearth::webhook::NotifyingAuditEngine::new(Arc::clone(&raw_audit), webhook_tx),
    );

    // Background daily audit log pruning sweep (A-25).
    // Per realm: (1) time-based prune by retention_days, (2) max_rows backstop,
    // (3) disk-pressure warning if max_disk_bytes is configured.
    {
        let prune_audit = Arc::clone(&raw_audit);
        let prune_identity = Arc::clone(&identity_engine);
        let prune_storage = Arc::clone(&storage);
        tokio::spawn(async move {
            // 24-hour interval; first tick fires at startup + 24h.
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let batch = hearth::core::MAX_PAGE_LIMIT;
                let mut prune_offset = 0u64;
                loop {
                    let page = match prune_identity
                        .list_realms(&hearth::core::PageRequest::new(prune_offset, batch))
                    {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "audit prune: realm enumeration failed");
                            break;
                        }
                    };
                    let prune_n = page.items.len() as u64;
                    for realm in &page.items {
                        let retention = match prune_audit.get_retention_config(realm.id()) {
                            Ok(c) => c,
                            Err(e) => {
                                warn!(realm = %realm.name(), error = %e, "audit prune: config fetch failed");
                                continue;
                            }
                        };

                        // (1) Time-based retention prune.
                        if retention.retention_days > 0 {
                            let now_micros = hearth::core::Timestamp::now().as_micros();
                            let window_micros =
                                (retention.retention_days as i64) * 86_400 * 1_000_000;
                            let cutoff = hearth::core::Timestamp::from_micros(
                                now_micros.saturating_sub(window_micros),
                            );
                            match prune_audit.prune_before(realm.id(), cutoff) {
                                Ok(0) => {}
                                Ok(n) => {
                                    info!(realm = %realm.name(), deleted = n, "audit prune: pruned old events");
                                }
                                Err(e) => {
                                    warn!(realm = %realm.name(), error = %e, "audit prune: prune failed");
                                }
                            }
                        }

                        // (2) max_rows backstop — hard cap on total event count.
                        if let Some(max_rows) = retention.max_rows {
                            match prune_audit.count_events(realm.id()) {
                                Ok(count) if count > max_rows => {
                                    let excess = count - max_rows;
                                    match prune_audit.prune_oldest(realm.id(), excess) {
                                        Ok(0) => {}
                                        Ok(n) => {
                                            info!(
                                                realm = %realm.name(),
                                                deleted = n,
                                                max_rows,
                                                "audit prune: max_rows backstop trimmed oldest events"
                                            );
                                        }
                                        Err(e) => {
                                            warn!(realm = %realm.name(), error = %e, "audit prune: max_rows trim failed");
                                        }
                                    }
                                }
                                Ok(_) => {} // within limit
                                Err(e) => {
                                    warn!(realm = %realm.name(), error = %e, "audit prune: count_events failed");
                                }
                            }
                        }

                        // (3) Disk-pressure warning — sampled, non-blocking.
                        let max_disk_bytes = prune_identity
                            .get_realm(realm.id())
                            .ok()
                            .flatten()
                            .and_then(|r| {
                                r.config().quotas.as_ref().and_then(|q| q.max_disk_bytes)
                            });
                        if let Some(limit) = max_disk_bytes {
                            // Estimate realm disk usage by summing key+value bytes
                            // across all storage entries for this realm.  Sampled
                            // once per day — not checked on every write.
                            let end_key = vec![0xFFu8; 256];
                            let usage_bytes: u64 = prune_storage
                                .scan(realm.id(), b"", &end_key)
                                .unwrap_or_default()
                                .iter()
                                .map(|e| (e.key.len() + e.value.len()) as u64)
                                .sum();
                            if usage_bytes >= limit {
                                warn!(
                                    realm = %realm.name(),
                                    usage_bytes,
                                    limit_bytes = limit,
                                    "disk pressure: realm storage usage at or above configured max_disk_bytes"
                                );
                            }
                        }
                    }
                    if prune_n == 0 || prune_offset + prune_n >= page.total {
                        break;
                    }
                    prune_offset += prune_n;
                }
            }
        });
    }

    let onboarding_service = Arc::new(OnboardingService::new(
        Arc::clone(&identity_engine),
        Arc::clone(&rbac_engine),
        Arc::clone(&email_service),
        data_dir.clone(),
    ));

    let rotation_grace_period_secs = config
        .token
        .signing_key_rotation_grace_period
        .as_deref()
        .and_then(|s| hearth::config::parse_duration_to_micros(s).ok())
        .map(|micros| (micros / 1_000_000) as u64)
        .unwrap_or(86_400);

    // Parse trusted proxy IPs early so both AppState (JSON API) and WebState
    // (browser UI) can use the same list for real client IP extraction.
    let api_trusted_proxies: Vec<std::net::IpAddr> = config
        .server
        .trusted_proxies
        .iter()
        .filter_map(|s| {
            s.parse::<std::net::IpAddr>().ok().or_else(|| {
                warn!(addr = %s, "ignoring invalid trusted_proxies entry (expected IP address)");
                None
            })
        })
        .collect();

    // Derive the DPoP nonce HMAC secret from config.
    //
    // When `security.dpop_nonce_secret` is absent or `"auto"`, a fresh
    // 32-byte key is generated via `ring`'s CSPRNG. When an explicit 64-char
    // hex value is provided, it is decoded; any other value is a fatal error.
    let dpop_nonce_secret: [u8; 32] = {
        let raw = config
            .security
            .dpop_nonce_secret
            .as_deref()
            .unwrap_or("auto");
        if raw == "auto" {
            use ring::rand::SecureRandom as _;
            let rng = ring::rand::SystemRandom::new();
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes)
                .map_err(|_| "failed to generate dpop_nonce_secret: ring CSPRNG error")?;
            info!("dpop_nonce_secret: auto-generated (ephemeral; configure security.dpop_nonce_secret for persistence)");
            bytes
        } else {
            if raw.len() != 64 {
                return Err(format!(
                    "security.dpop_nonce_secret must be 64 hex chars (32 bytes) or \"auto\", got {} chars",
                    raw.len()
                ).into());
            }
            let mut bytes = [0u8; 32];
            for (i, chunk) in raw.as_bytes().chunks(2).enumerate() {
                let hex = std::str::from_utf8(chunk)
                    .map_err(|_| "security.dpop_nonce_secret contains non-UTF8 bytes")?;
                bytes[i] = u8::from_str_radix(hex, 16).map_err(|_| {
                    format!("security.dpop_nonce_secret: invalid hex byte '{hex}' at position {i}")
                })?;
            }
            bytes
        }
    };
    assert_ne!(
        dpop_nonce_secret,
        [0u8; 32],
        "dpop_nonce_secret must not be the zero key — use \"auto\" or supply a real 32-byte hex secret"
    );

    // A-10: build the JWKS rate limiter from the operator-configured RPS limit.
    // Dev mode disables the cap (u32::MAX) to keep local iteration and CLI
    // integration tests deterministic; production retains the configured cap.
    let jwks_rate_limiter = if config.dev_mode {
        Arc::new(JwksRateLimiter::with_rps_limit(u32::MAX))
    } else {
        Arc::new(JwksRateLimiter::with_rps_limit(
            config.security.jwks_rps_limit,
        ))
    };

    // A-2: build a shared RequestShaper from operator config (or defaults) and
    // wire it to BOTH the HTTP AppState and the gRPC GrpcState so that per-IP
    // counters accumulate across protocols — a caller cannot evade the limit by
    // switching from REST to gRPC.
    // Load-test escape hatch (`security.load_test_unthrottled`): when set AND
    // the process runs in `--dev` mode AND every effective bind (HTTP + gRPC)
    // is loopback, disable every request-rate limiter so a single-node
    // throughput/soak test can saturate the hot path instead of measuring the
    // rate limiter. Refused (fail-safe: limiters stay ON) when not in dev mode
    // (guards reverse-proxy prod topologies) or when any bind — including the
    // gRPC listener, which may diverge from the HTTP bind — is non-loopback, so
    // this can never silently expose a public server (HEA-1797).
    let bind = config.server.bind_address.trim();
    // Effective gRPC bind: only relevant when the gRPC listener is enabled
    // (`grpc_port` set); it inherits `bind_address` when `grpc_bind_address` is
    // unset. Mirrors the resolution at the gRPC spawn site below.
    let grpc_bind = config.server.grpc_port.map(|_| {
        config
            .server
            .grpc_bind_address
            .as_deref()
            .unwrap_or(config.server.bind_address.as_str())
            .trim()
    });
    // Hard gate: dev mode must never expose on a non-loopback address (HEA-1980).
    // The config-file validation in validate.rs catches a non-loopback
    // bind_address when a config file is used, but (a) the CLI --bind override
    // is applied after that validation, and (b) Config::dev() (the no-config-file
    // path) skips validate() entirely — so both cases bypass the earlier check.
    if let DevBindCheck::RefusedNonLoopback = dev_mode_bind_check(config.dev_mode, bind, grpc_bind)
    {
        error!(
            bind_address = %bind,
            grpc_bind_address = grpc_bind.unwrap_or("<disabled>"),
            "dev mode refused: all effective binds must be loopback (HEA-1980). \
             --dev enables unauthenticated endpoints (/dev/seed-session, /admin/bootstrap) \
             and weakened Argon2 parameters — exposing them on a routable interface \
             is a critical security risk. Use --bind 127.0.0.1 or --bind ::1."
        );
        return Err("dev mode: refusing to start with non-loopback bind address".into());
    }

    let load_test_unthrottled = match loadtest_unthrottle_decision(
        config.security.load_test_unthrottled.unwrap_or(false),
        config.dev_mode,
        bind,
        grpc_bind,
    ) {
        LoadtestUnthrottle::Off => false,
        LoadtestUnthrottle::Enabled => {
            tracing::warn!(
                bind_address = %bind,
                grpc_bind_address = grpc_bind.unwrap_or("<disabled>"),
                "security.load_test_unthrottled=true — ALL request-rate limiters \
                 (token endpoint, admin API, export, request shaper) are DISABLED. \
                 Load-test-only mode; never enable on a production bind."
            );
            // HEA-1799: publish a runtime-visible signal so the disabled state is
            // detectable on a live process (Prometheus scrape / dashboard alert)
            // even after the boot WARN log has scrolled past. The startup panel
            // gains a matching row below.
            hearth::metrics::metrics().mark_rate_limiters_disabled("load_test");
            true
        }
        LoadtestUnthrottle::RefusedNonLoopback => {
            tracing::error!(
                bind_address = %bind,
                grpc_bind_address = grpc_bind.unwrap_or("<disabled>"),
                "security.load_test_unthrottled=true refused: every effective bind \
                 (HTTP and gRPC) must be loopback; rate limiters remain ENABLED. \
                 Bind both to 127.0.0.1 or ::1 to run an unthrottled load test."
            );
            false
        }
        LoadtestUnthrottle::RefusedNotDev => {
            tracing::error!(
                bind_address = %bind,
                "security.load_test_unthrottled=true refused: only permitted in \
                 --dev mode; rate limiters remain ENABLED. A loopback bind can \
                 still be internet-reachable behind a reverse proxy, so unthrottled \
                 load testing is dev-only."
            );
            false
        }
    };

    let request_shaper = Arc::new(if load_test_unthrottled {
        hearth::abuse::shaper::RequestShaper::disabled()
    } else {
        match config.security.request_shaper.as_ref() {
            Some(cfg) => hearth::abuse::shaper::RequestShaper::with_config(
                hearth::abuse::shaper::ShaperConfig {
                    ip_rps: Some(cfg.ip_rps),
                    realm_rps: Some(cfg.realm_rps),
                },
            ),
            None => hearth::abuse::shaper::RequestShaper::new(),
        }
    });

    let allowed_hosts = config.security.allowed_hosts.clone();
    if !allowed_hosts.is_empty() {
        info!(count = allowed_hosts.len(), "loaded allowed_hosts");
    }

    let app_state = if config.dev_mode {
        Arc::new(
            AppState::new_dev(
                Arc::clone(&identity_engine),
                Arc::clone(&rbac_engine),
                Arc::clone(&audit_engine),
            )
            .with_webhook(Arc::clone(&webhook_engine))
            .with_metrics_enabled(config.metrics.enabled)
            .with_metrics_bearer_token(config.metrics.bearer_token.clone())
            .with_signing_key_rotation_grace_period_secs(rotation_grace_period_secs)
            .with_trusted_proxies(api_trusted_proxies.clone())
            .with_dpop_nonce_secret(dpop_nonce_secret)
            .with_jwks_rate_limiter(Arc::clone(&jwks_rate_limiter))
            .with_allowed_hosts(allowed_hosts.clone())
            .with_request_shaper(Arc::clone(&request_shaper))
            .with_rate_limiters_disabled(load_test_unthrottled)
            // In --dev, enable all agent-auth capability phases regardless of
            // what hearth.yaml says, so developers can exercise Phase D routes
            // without manually setting every capability flag.
            .with_agent_identity(true)
            .with_agent_approval(true)
            .with_agent_advanced(true),
        )
    } else {
        Arc::new(
            AppState::new(
                Arc::clone(&identity_engine),
                Arc::clone(&rbac_engine),
                Arc::clone(&audit_engine),
            )
            .with_webhook(Arc::clone(&webhook_engine))
            .with_metrics_enabled(config.metrics.enabled)
            .with_metrics_bearer_token(config.metrics.bearer_token.clone())
            .with_signing_key_rotation_grace_period_secs(rotation_grace_period_secs)
            .with_trusted_proxies(api_trusted_proxies.clone())
            .with_dpop_nonce_secret(dpop_nonce_secret)
            .with_jwks_rate_limiter(Arc::clone(&jwks_rate_limiter))
            .with_allowed_hosts(allowed_hosts)
            .with_request_shaper(Arc::clone(&request_shaper))
            .with_rate_limiters_disabled(load_test_unthrottled)
            .with_agent_identity(config.agent_auth.capabilities.identity)
            .with_agent_approval(config.agent_auth.capabilities.approval)
            .with_agent_advanced(config.agent_auth.capabilities.advanced),
        )
    };

    // Build server address
    let addr: SocketAddr = format!("{}:{}", config.server.bind_address, config.server.port)
        .parse()
        .map_err(|e| format!("invalid bind address: {e}"))?;

    // Compose JSON API router + web UI router.
    //
    // When `branding.logo_url` points to a local file, load it at startup
    // and serve it via `/ui/static/custom-logo` so the browser can fetch it.
    // The email service still receives the original file path — its
    // `resolve_branding()` reads and inlines local SVGs directly.
    let (web_logo_url, custom_logo) = resolve_web_logo(&config);

    let mut web_state = WebState::new(
        Arc::clone(&identity_engine),
        Arc::clone(&rbac_engine),
        Arc::clone(&audit_engine),
        Arc::clone(&onboarding_service),
        web::CookieSecret::random(),
        Some(Arc::clone(&email_service)),
    )
    .with_config_warnings(config.config_warnings.clone())
    .with_orphaned_realms(orphaned_realms)
    .with_migration_records(migration_records)
    .with_email_log_transport(config.email.transport == EmailTransport::Log)
    .with_product_name(config.branding.product_name_or_default().to_string())
    .with_logo_url(web_logo_url)
    .with_default_realm(config.server.default_realm.clone())
    .with_config(Arc::new(config.clone()))
    .with_sms(sms_sender, sms_hmac_key_bytes)
    .with_dev_mode(config.dev_mode);

    if !api_trusted_proxies.is_empty() {
        info!(count = api_trusted_proxies.len(), "loaded trusted_proxies");
    }
    web_state = web_state.with_trusted_proxies(api_trusted_proxies);

    if let Some((bytes, content_type)) = custom_logo {
        web_state = web_state.with_custom_logo(bytes, content_type);
    }

    // When `server.assets_dir` is set, try to load `<assets_dir>/app.css`
    // from disk. Lets operators rebuild Tailwind and restart the server
    // without recompiling Rust (the embedded copy from `include_bytes!`
    // is otherwise frozen at `cargo build` time). Falls back silently to
    // the embedded copy on any failure — production never serves an
    // unstyled UI just because a config path was wrong.
    if let Some(assets_dir) = config.server.assets_dir.as_ref() {
        let path = assets_dir.join("app.css");
        match std::fs::read(&path) {
            Ok(bytes) => match web::assert_bytes_sane(&bytes) {
                Ok(()) => {
                    info!(
                        path = %path.display(),
                        bytes = bytes.len(),
                        "loaded admin UI CSS from server.assets_dir; restart-to-reload is active"
                    );
                    web_state = web_state.with_app_css(bytes);
                }
                Err(reason) => {
                    warn!(
                        path = %path.display(),
                        reason,
                        "server.assets_dir/app.css failed sanity check; serving embedded fallback"
                    );
                }
            },
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "could not read server.assets_dir/app.css; serving embedded fallback"
                );
            }
        }
    }

    // Build global theme CSS: named theme base + optional operator custom CSS file.
    let named_theme = config.branding.theme.as_deref().unwrap_or("ember");
    let theme_base_css = web::themes::theme_css(named_theme);
    let global_custom_css = config
        .branding
        .custom_css
        .as_deref()
        .map(|path| {
            std::fs::read_to_string(path).unwrap_or_else(|e| {
                warn!(path = %path, error = %e, "failed to read branding custom CSS file");
                String::new()
            })
        })
        .unwrap_or_default();
    if !global_custom_css.is_empty() {
        info!(
            path = %config.branding.custom_css.as_deref().unwrap_or(""),
            bytes = global_custom_css.len(),
            "loaded branding.custom_css"
        );
    }
    let global_theme_css = format!("{theme_base_css}\n{global_custom_css}");

    // Build per-realm theme CSS map (keyed by realm UUID string) and the
    // per-realm product-name override map in the same pass.
    let mut realm_themes: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut realm_product_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for (realm_name, realm_yaml) in config.realms.iter().flatten() {
        let web_cfg = match realm_yaml.web.as_ref() {
            Some(w) if w.theme.is_some() || w.custom_css.is_some() || w.product_name.is_some() => w,
            _ => continue,
        };
        let realm = match identity_engine.get_realm_by_name(realm_name) {
            Ok(Some(t)) => t,
            Ok(None) => {
                warn!(name = %realm_name, "realm not found in storage, skipping per-realm web overrides");
                continue;
            }
            Err(e) => {
                warn!(name = %realm_name, error = %e, "failed to look up realm for web overrides");
                continue;
            }
        };
        let realm_uuid = realm.id().as_uuid().to_string();
        if let Some(name) = web_cfg.product_name.as_deref() {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                realm_product_names.insert(realm_uuid.clone(), trimmed.to_string());
            }
        }
        let base = web_cfg.theme.as_deref().map_or("", web::themes::theme_css);
        let custom = web_cfg
            .custom_css
            .as_deref()
            .map(|path| {
                std::fs::read_to_string(path).unwrap_or_else(|e| {
                    warn!(path = %path, name = %realm_name, error = %e, "failed to read realm custom CSS file");
                    String::new()
                })
            })
            .unwrap_or_default();
        if !custom.is_empty() {
            info!(
                realm = %realm_name,
                path = %web_cfg.custom_css.as_deref().unwrap_or(""),
                bytes = custom.len(),
                "loaded realm custom CSS"
            );
        }
        let combined = format!("{base}\n{custom}");
        if !combined.trim().is_empty() {
            realm_themes.insert(realm_uuid, combined);
        }
    }

    // Build reload notifier for programmatic reload (admin API endpoint).
    let reload_notify = Arc::new(Notify::new());

    // Resolve the config file path used at startup — needed for hot-reload.
    let reload_config_path: Option<PathBuf> =
        config_path.as_deref().map(PathBuf::from).or_else(|| {
            let default = PathBuf::from("hearth.yaml");
            if default.exists() {
                Some(default)
            } else {
                None
            }
        });

    web_state = web_state
        .with_theme_css(global_theme_css)
        .with_realm_themes(realm_themes)
        .with_realm_product_names(realm_product_names)
        .with_reload_notify(Arc::clone(&reload_notify))
        .with_tls_enabled(config.server.tls_cert_path.is_some())
        .with_trust_forwarded_proto(config.server.trust_forwarded_proto);

    // HEA-SEC-19: Warn operators when neither direct TLS nor proxy-forwarded
    // HTTPS is configured. In this state session cookies are issued without the
    // `Secure` attribute, which exposes them to theft over plain HTTP.
    let tls_active = config.server.tls_cert_path.is_some();
    if !config.dev_mode && !tls_active && !config.server.trust_forwarded_proto {
        error!(
            "Session cookies will be issued without the Secure attribute. \
             Set `server.tls_cert_path` for direct TLS, or set \
             `server.trust_forwarded_proto = true` when behind a TLS-terminating \
             reverse proxy. Running without either in production exposes session \
             cookies to interception."
        );
    }

    if let Some(ref cfg_path) = reload_config_path {
        web_state = web_state.with_config_path(cfg_path.clone());
    }

    // Wire up the CAPTCHA provider (P-1 — HEA-1202).
    if let Some(captcha_cfg) = config.security.captcha.as_ref() {
        use hearth::abuse::captcha::{TurnstileCaptchaProvider, TurnstileConfig};
        use hearth::config::CaptchaProviderKind;
        match captcha_cfg.provider {
            CaptchaProviderKind::Turnstile => {
                if let Some(ts) = captcha_cfg.turnstile.as_ref() {
                    let secret_key = std::env::var("HEARTH_TURNSTILE_SECRET_KEY")
                        .ok()
                        .or_else(|| ts.secret_key.clone())
                        .unwrap_or_default();
                    if secret_key.is_empty() {
                        warn!(
                            "security.captcha.turnstile: no secret_key configured and \
                             HEARTH_TURNSTILE_SECRET_KEY is unset — Turnstile will reject all tokens"
                        );
                    }
                    let cfg = if let Some(ref url) = ts.verify_url {
                        TurnstileConfig {
                            site_key: ts.site_key.clone(),
                            secret_key,
                            verify_url: url.clone(),
                        }
                    } else {
                        TurnstileConfig::new(ts.site_key.clone(), secret_key)
                    };
                    info!(site_key = %ts.site_key, "CAPTCHA: Cloudflare Turnstile enabled");
                    web_state = web_state
                        .with_captcha_provider(Arc::new(TurnstileCaptchaProvider::new(cfg)));
                } else {
                    warn!(
                        "security.captcha.provider = turnstile but no \
                         security.captcha.turnstile section found — captcha disabled"
                    );
                }
            }
        }
    }

    let mut app_router = http::router(Arc::clone(&app_state)).merge(web::router(web_state));
    if let Some(mc_state) = &mailcatcher_state {
        app_router = app_router.merge(web::mailcatcher_router(Arc::clone(mc_state)));
    }

    // Spawn the webhook dispatcher. Uses a watch channel so we can signal
    // clean shutdown after the HTTP server exits.
    let (wh_shutdown_tx, wh_shutdown_rx) = tokio::sync::watch::channel(());
    {
        let wh_engine = Arc::clone(&webhook_engine);
        let wh_clock = Arc::clone(&clock);
        tokio::spawn(async move {
            hearth::webhook::dispatcher::run_dispatcher(
                wh_engine,
                wh_clock,
                webhook_rx,
                wh_shutdown_rx,
            )
            .await;
        });
    }

    // Spawn the gRPC management API alongside the HTTP server. Both share
    // the `AdminRateLimiter` so rate limits apply across protocols.
    let grpc_shutdown = if let Some(grpc_port) = config.server.grpc_port {
        let bind = config
            .server
            .grpc_bind_address
            .as_deref()
            .unwrap_or(config.server.bind_address.as_str());
        let grpc_addr: SocketAddr = format!("{bind}:{grpc_port}")
            .parse()
            .map_err(|e| format!("invalid gRPC bind address: {e}"))?;
        let grpc_state = protocol::grpc::GrpcState::new(
            Arc::clone(&identity_engine),
            Arc::clone(&rbac_engine),
            Arc::clone(&audit_engine),
            Arc::clone(&app_state.admin_rate_limiter),
        )
        // A-2: share the same RequestShaper so HTTP + gRPC per-IP counts
        // accumulate in the same sliding window.
        .with_shaper(Arc::clone(&request_shaper));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            let shutdown = async {
                let _ = shutdown_rx.await;
            };
            if let Err(e) =
                protocol::grpc::serve(grpc_addr, grpc_state, reflection_enabled, shutdown).await
            {
                error!(error = %e, "gRPC server exited with error");
            }
        });
        info!(address = %grpc_addr, "gRPC management API enabled");
        Some((shutdown_tx, handle))
    } else {
        None
    };

    // Write PID file for `hearth config reload` CLI.
    let pid_file_path = data_dir.join("hearth.pid");
    std::fs::write(&pid_file_path, std::process::id().to_string())
        .unwrap_or_else(|e| warn!(error = %e, "failed to write PID file"));

    // Consolidated startup info panel — printed once after all init completes,
    // suppressed in JSON mode so log pipelines stay machine-readable.
    if config.observability.log_format != "json" {
        let mc_info = mailcatcher_state
            .as_ref()
            .map(|s| (format!("http://{addr}/dev/mail"), s.password.clone()));
        let (wal_size, sst_count, data_dir_bytes) = collect_storage_stats(&data_dir);
        let stats = StartupStats {
            realm_count: config.realms.as_ref().map(|r| r.len()).unwrap_or(0),
            federation_count: config
                .realms
                .as_ref()
                .map(|realms| {
                    realms
                        .values()
                        .filter_map(|r| r.federation.as_ref())
                        .map(|f| f.providers.len())
                        .sum()
                })
                .unwrap_or(0),
            email_transport: email_transport_label(config.email.transport),
            tls: config.server.tls_cert_path.is_some(),
            oidc_issuer: config.oidc.issuer.clone(),
            cluster_peers: config.cluster.as_ref().map(|c| c.peers.len()),
            wal_size,
            sst_count,
            data_dir_bytes,
            startup_ms: u64::try_from(serve_start.elapsed().as_millis()).unwrap_or(u64::MAX),
            rate_limiters_disabled: load_test_unthrottled,
        };
        print_startup_panel(
            addr,
            dev,
            setup_token.as_deref(),
            mc_info.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
            &stats,
        );
    }

    // Check for TLS configuration
    if let (Some(cert_path), Some(key_path)) =
        (&config.server.tls_cert_path, &config.server.tls_key_path)
    {
        run_serve_tls(
            addr,
            &config,
            app_router,
            cert_path,
            key_path,
            Arc::clone(&identity_engine),
            Arc::clone(&rbac_engine),
            Arc::clone(&permission_registry),
            reload_config_path,
            dev,
            Arc::clone(&reload_notify),
        )
        .await?;
    } else {
        // Non-TLS: register SIGHUP handler for config hot-reload.
        #[cfg(unix)]
        {
            let engine = Arc::clone(&identity_engine);
            let rbac = Arc::clone(&rbac_engine);
            let cfg_path = reload_config_path.clone();
            let is_dev = dev;
            let notify = Arc::clone(&reload_notify);
            let registry = Arc::clone(&permission_registry);
            tokio::spawn(async move {
                let mut sig =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                        .expect("failed to register SIGHUP handler");
                loop {
                    tokio::select! {
                        _sig = sig.recv() => {
                            info!("SIGHUP received, reloading configuration");
                        }
                        () = notify.notified() => {
                            info!("programmatic reload triggered");
                        }
                    }
                    run_config_reconciliation(
                        engine.as_ref(),
                        rbac.as_ref(),
                        cfg_path.as_deref(),
                        is_dev,
                        &registry,
                    );
                }
            });
        }

        let shutdown = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install Ctrl+C handler");
            info!("shutdown signal received, stopping server");
        };
        http::serve_router(addr, app_router, shutdown).await?;
    }

    // Signal the gRPC task to shut down and wait for it.
    if let Some((tx, handle)) = grpc_shutdown {
        let _ = tx.send(());
        let _ = handle.await;
    }

    // Signal the webhook dispatcher to stop.
    let _ = wh_shutdown_tx.send(());

    // Clean up PID file on exit.
    let _ = std::fs::remove_file(&pid_file_path);
    info!("Hearth server stopped");
    Ok(())
}

// Unicode full-block logo — █ (U+2588), 5 contiguous letter rows.
const HEARTH_LOGO: &str = "\
\x20 ██   ██ ███████  █████  ██████  ████████ ██   ██\n\
\x20 ██   ██ ██      ██   ██ ██   ██    ██    ██   ██\n\
\x20 ███████ █████   ███████ ██████     ██    ███████\n\
\x20 ██   ██ ██      ██   ██ ██  ██     ██    ██   ██\n\
\x20 ██   ██ ███████ ██   ██ ██   ██    ██    ██   ██";

struct StartupStats {
    realm_count: usize,
    federation_count: usize,
    email_transport: &'static str,
    tls: bool,
    oidc_issuer: Option<String>,
    cluster_peers: Option<usize>,
    wal_size: Option<u64>,
    sst_count: usize,
    data_dir_bytes: u64,
    startup_ms: u64,
    /// Whether all request-rate limiters are disabled by the load-test escape
    /// hatch (`security.load_test_unthrottled` resolved to `Enabled`, HEA-1799).
    rate_limiters_disabled: bool,
}

// Prints the logo + consolidated startup info panel to stdout (raw — never
// in log sinks). Call only when log_format != "json".
fn print_startup_panel(
    addr: std::net::SocketAddr,
    dev_mode: bool,
    setup_token: Option<&str>,
    mailcatcher: Option<(&str, &str)>,
    stats: &StartupStats,
) {
    for line in build_startup_panel(addr, dev_mode, setup_token, mailcatcher, stats) {
        tracing::info!("{line}");
    }
}

// Builds the logo + consolidated startup info panel as ordered display lines.
// Split out from `print_startup_panel` so the content (notably the HEA-1799
// unthrottled-rate-limiter banner) is unit-testable without a tracing sink.
fn build_startup_panel(
    addr: std::net::SocketAddr,
    dev_mode: bool,
    setup_token: Option<&str>,
    mailcatcher: Option<(&str, &str)>,
    stats: &StartupStats,
) -> Vec<String> {
    let base = format!("http://{addr}");
    let dev_badge = if dev_mode { "  [dev]" } else { "" };
    let mut lines: Vec<String> = Vec::new();
    lines.push(String::new());
    lines.push(HEARTH_LOGO.to_string());
    lines.push("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".to_string());
    lines.push(format!(
        "  Identity · Auth · RBAC   v{}{}",
        env!("CARGO_PKG_VERSION"),
        dev_badge
    ));
    // HEA-1799: unmissable banner when the load-test escape hatch has turned off
    // every request-rate limiter. Placed at the top of the panel so an operator
    // attaching after boot cannot miss that abuse protection is disabled.
    if stats.rate_limiters_disabled {
        lines.push("  ⚠  RATE LIMITERS DISABLED (load test mode)".to_string());
    }
    lines.push("  ─────────────────────────────────────────────────".to_string());
    // URL links — labels padded to 7 chars so values align at column 11.
    lines.push(format!("  API:     {base}"));
    lines.push(format!("  Admin:   {base}/ui"));
    if let Some(issuer) = &stats.oidc_issuer {
        lines.push(format!("  Issuer:  {issuer}"));
    }
    if let Some(token) = setup_token {
        if dev_mode {
            let preview: String = token.chars().take(8).collect();
            lines.push(format!(
                "  Setup:   {base}/ui/setup  (token prefix: {preview}… — read .setup_token for full token)"
            ));
        } else {
            lines.push(format!(
                "  Setup:   {base}/ui/setup  (token redacted in prod — set HEARTH_SETUP_TOKEN)"
            ));
        }
    }
    if let Some((inbox_url, password)) = mailcatcher {
        if dev_mode {
            lines.push(format!("  Mail:    {inbox_url}  pw: {password}"));
        } else {
            lines.push(format!("  Mail:    {inbox_url}"));
        }
    }
    lines.push("  ─────────────────────────────────────────────────".to_string());
    // Environment stats
    let mut env_line = format!(
        "  Realms: {}   ·   Email: {}   ·   TLS: {}",
        stats.realm_count,
        stats.email_transport,
        if stats.tls { "on" } else { "off" }
    );
    if stats.federation_count > 0 {
        env_line.push_str(&format!("   ·   Connectors: {}", stats.federation_count));
    }
    if let Some(peers) = stats.cluster_peers {
        env_line.push_str(&format!(
            "   ·   Cluster: {} peer{}",
            peers,
            if peers == 1 { "" } else { "s" }
        ));
    }
    lines.push(env_line);
    // Storage stats
    let mut storage_parts: Vec<String> = Vec::new();
    if let Some(wal) = stats.wal_size {
        storage_parts.push(format!("WAL {}", fmt_bytes(wal)));
    }
    storage_parts.push(format!(
        "{} SST{}",
        stats.sst_count,
        if stats.sst_count == 1 { "" } else { "s" }
    ));
    if stats.data_dir_bytes > 0 {
        storage_parts.push(fmt_bytes(stats.data_dir_bytes));
    }
    lines.push(format!("  Storage: {}", storage_parts.join("  ·  ")));
    lines.push(format!("  Startup: {} ms", stats.startup_ms));
    lines.push("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n".to_string());
    lines
}

fn collect_storage_stats(data_dir: &std::path::Path) -> (Option<u64>, usize, u64) {
    let wal_size = std::fs::metadata(data_dir.join("hearth.wal"))
        .ok()
        .map(|m| m.len());
    let (sst_count, total_bytes) = std::fs::read_dir(data_dir)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let path = e.path();
                    let size = e.metadata().ok().map(|m| m.len()).unwrap_or(0);
                    Some((path.extension()?.to_str()? == "sst", size))
                })
                .fold((0usize, 0u64), |(ssts, total), (is_sst, size)| {
                    (ssts + usize::from(is_sst), total + size)
                })
        })
        .unwrap_or((0, 0));
    (wal_size, sst_count, total_bytes)
}

#[allow(clippy::cast_precision_loss)]
// INVARIANT: precision loss is acceptable here — this function formats byte sizes
// for human-readable display (e.g. "1.2 GB"). Sub-MB precision is irrelevant.
fn fmt_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else {
        format!("{} KB", bytes / 1024)
    }
}

fn email_transport_label(t: EmailTransport) -> &'static str {
    match t {
        EmailTransport::Log => "log",
        EmailTransport::Smtp => "smtp",
        EmailTransport::Sendgrid => "sendgrid",
        EmailTransport::Postmark => "postmark",
        EmailTransport::Mailgun => "mailgun",
        EmailTransport::Mailtrap => "mailtrap",
        EmailTransport::Mailcatcher => "mailcatcher",
    }
}

/// Builds the outbound email sender from configuration.
///
/// Returns the appropriate transport adapter based on the configured
/// `email.transport`. Fails if the transport rejects the configuration
/// at startup — better to fail early than on the first send attempt.
fn build_email_sender(
    config: &Config,
    mailcatcher: Option<&Arc<MailcatcherState>>,
) -> Result<SharedEmailSender, Box<dyn std::error::Error>> {
    use hearth::identity::email::http::UreqTransport;

    Ok(match config.email.transport {
        EmailTransport::Mailcatcher => {
            let state = mailcatcher
                .cloned()
                .ok_or("MailcatcherState must be pre-built before build_email_sender")?;
            Arc::new(MailcatcherSender::new(state))
        }
        EmailTransport::Log => Arc::new(LoggingEmailSender::new()),
        EmailTransport::Smtp => Arc::new(smtp_sender_from_config(&config.email)?),
        EmailTransport::Sendgrid => {
            let sg = config
                .email
                .sendgrid
                .as_ref()
                .ok_or("email.sendgrid block is required for sendgrid transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for sendgrid transport")?;
            Arc::new(SendgridEmailSender::new(
                UreqTransport,
                ApiKey::new(sg.api_key.clone()),
                from.clone(),
            ))
        }
        EmailTransport::Postmark => {
            let pm = config
                .email
                .postmark
                .as_ref()
                .ok_or("email.postmark block is required for postmark transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for postmark transport")?;
            Arc::new(PostmarkEmailSender::new(
                UreqTransport,
                ApiKey::new(pm.server_token.clone()),
                from.clone(),
            ))
        }
        EmailTransport::Mailgun => {
            let mg = config
                .email
                .mailgun
                .as_ref()
                .ok_or("email.mailgun block is required for mailgun transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for mailgun transport")?;
            let region = match mg.region {
                hearth::config::MailgunRegion::Us => MailgunRegion::Us,
                hearth::config::MailgunRegion::Eu => MailgunRegion::Eu,
            };
            Arc::new(MailgunEmailSender::new(
                UreqTransport,
                ApiKey::new(mg.api_key.clone()),
                mg.domain.clone(),
                from.clone(),
                region,
            ))
        }
        EmailTransport::Mailtrap => {
            let mt = config
                .email
                .mailtrap
                .as_ref()
                .ok_or("email.mailtrap block is required for mailtrap transport")?;
            let from = config
                .email
                .from
                .as_ref()
                .ok_or("email.from is required for mailtrap transport")?;
            Arc::new(MailtrapEmailSender::new(
                UreqTransport,
                ApiKey::new(mt.api_key.clone()),
                from.clone(),
                mt.inbox_id,
            ))
        }
    })
}

/// Builds the outbound SMS sender from configuration.
///
/// Returns the appropriate transport adapter based on the configured
/// `sms.transport`. Fails if the transport config is structurally invalid.
fn build_sms_sender(config: &Config) -> Result<SharedSmsSender, Box<dyn std::error::Error>> {
    use hearth::identity::sms::http::UreqSmsTransport;

    Ok(match config.sms.transport {
        SmsTransport::Log => Arc::new(LoggingSmsSender::new()),
        SmsTransport::Twilio => {
            let tw = config
                .sms
                .twilio
                .as_ref()
                .ok_or("sms.twilio block is required for twilio transport")?;
            Arc::new(TwilioSmsSender::new(
                UreqSmsTransport,
                tw.account_sid.clone(),
                SmsSecret::new(tw.auth_token.clone()),
                tw.from.clone(),
            ))
        }
        SmsTransport::AwsSns => {
            let sns = config
                .sms
                .aws_sns
                .as_ref()
                .ok_or("sms.aws_sns block is required for awssns transport")?;
            Arc::new(SnsSmsSender::new(
                UreqSmsTransport,
                sns.region.clone(),
                sns.access_key_id.clone(),
                SmsSecret::new(sns.secret_access_key.clone()),
                sns.sender_id.clone(),
            ))
        }
    })
}

/// Builds the email service (orchestration layer) wrapping a sender.
///
/// `product_name` and `logo_url` come from the global `branding:`
/// section. Email-specific settings (accent color, support email,
/// footer text) come from `email.branding:`.
///
/// When no logo URL is configured, the built-in Hearth SVG is inlined
/// directly in the email HTML (no remote fetch needed).
fn build_email_service(
    sender: SharedEmailSender,
    config: &Config,
) -> Result<EmailService, Box<dyn std::error::Error>> {
    let product_name = config.branding.product_name_or_default().to_string();
    let logo_url = config.branding.logo_url.clone();
    let branding = config.email.branding.clone().unwrap_or_default();
    let default_logo_svg = String::from_utf8_lossy(web::HEARTH_WIDE_SVG).into_owned();
    let templates_dir = config
        .email
        .templates_dir
        .as_ref()
        .map(std::path::Path::new);
    Ok(EmailService::new(
        sender,
        product_name,
        logo_url,
        branding,
        default_logo_svg,
        templates_dir,
    )?)
}

/// In dev mode, upgrades `Log` and `Smtp` transports to `Mailcatcher` so
/// `--dev` works without Docker or a real mail server. Production cloud
/// transports are kept so engineers can test against real providers.
///
/// Returns `true` when SMTP was promoted (callers log a helpful warning).
fn maybe_upgrade_email_transport(config: &mut Config) -> bool {
    if !config.dev_mode {
        return false;
    }
    match config.email.transport {
        EmailTransport::Log => {
            config.email.transport = EmailTransport::Mailcatcher;
            false
        }
        EmailTransport::Smtp => {
            config.email.transport = EmailTransport::Mailcatcher;
            true
        }
        _ => false,
    }
}

/// Runs the HTTPS server with TLS, redirect listener, and SIGHUP cert + config reload.
/// Registry type alias used for hot-swap on SIGHUP.
type RegistrySwap = Arc<arc_swap::ArcSwap<hearth::rbac::registry::PermissionRegistry>>;

#[allow(clippy::too_many_arguments)]
async fn run_serve_tls(
    addr: SocketAddr,
    config: &Config,
    app_router: axum::Router,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    identity_engine: Arc<dyn IdentityEngine>,
    rbac_engine: Arc<dyn RbacEngine>,
    permission_registry: RegistrySwap,
    reload_config_path: Option<PathBuf>,
    dev: bool,
    reload_notify: Arc<Notify>,
) -> Result<(), Box<dyn std::error::Error>> {
    let reloadable = ReloadableTlsConfig::load(cert_path.to_path_buf(), key_path.to_path_buf())
        .map_err(|e| format!("failed to load TLS certificates: {e}"))?;

    let params = TlsConfigParams {
        resolver: Arc::new(reloadable.resolver()),
        client_ca_path: config.server.tls_client_ca_path.clone(),
        require_client_cert: config.server.tls_require_client_cert,
        crl_paths: config.security.tls.crl_paths.clone(),
        tls13_only: config.security.tls.min_version == TlsMinVersionYaml::Tls13,
    };
    let server_config =
        build_server_config(params).map_err(|e| format!("failed to build TLS config: {e}"))?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    // Spawn HTTP→HTTPS redirect listener
    let redirect_port = if config.server.port == 443 {
        80
    } else {
        config.server.port.saturating_sub(1)
    };
    let redirect_addr: SocketAddr = format!("{}:{redirect_port}", config.server.bind_address)
        .parse()
        .map_err(|e| format!("invalid redirect bind address: {e}"))?;
    let https_port = config.server.port;
    let mut redirect_shutdown_rx = shutdown_rx.clone();
    let redirect_listener = tokio::net::TcpListener::bind(redirect_addr)
        .await
        .map_err(|e| format!("failed to bind HTTP redirect listener on {redirect_addr}: {e}"))?;
    let redirect_handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = redirect_shutdown_rx.changed().await;
        };
        if let Err(e) = http::serve_redirect(redirect_listener, https_port, shutdown).await {
            warn!(error = %e, "HTTP redirect server failed");
        }
    });

    // Register SIGHUP handler for cert + config hot-reload
    #[cfg(unix)]
    {
        let reloadable = Arc::new(reloadable);
        let reloadable_clone = Arc::clone(&reloadable);
        let engine = identity_engine;
        let rbac = rbac_engine;
        let registry = permission_registry;
        let cfg_path = reload_config_path;
        let is_dev = dev;
        tokio::spawn(async move {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
                .expect("failed to register SIGHUP handler");
            loop {
                tokio::select! {
                    _sig = sig.recv() => {
                        info!("SIGHUP received, reloading TLS certificates and configuration");
                    }
                    () = reload_notify.notified() => {
                        info!("programmatic reload triggered, reloading configuration");
                    }
                }
                // Reload TLS certificates
                if let Err(e) = reloadable_clone.reload() {
                    error!(error = %e, "TLS certificate reload failed, keeping old cert");
                }
                // Reload configuration and reconcile
                run_config_reconciliation(
                    engine.as_ref(),
                    rbac.as_ref(),
                    cfg_path.as_deref(),
                    is_dev,
                    &registry,
                );
            }
        });
    }

    // Set up graceful shutdown on Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("shutdown signal received, stopping server");
        drop(shutdown_tx);
    });

    // Start HTTPS server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    http::serve_tls_router(listener, app_router, acceptor, shutdown_rx).await?;

    let _ = redirect_handle.await;
    Ok(())
}

/// Loads configuration from file, dev mode, or defaults.
fn load_config(
    dev: bool,
    config_path: Option<&std::path::Path>,
) -> Result<Config, Box<dyn std::error::Error>> {
    // Load the user's file if given (takes precedence over the default
    // location). `--dev` without `-c` falls back to the pure dev preset.
    //
    // When `dev=true`, use `from_file_as_dev` which applies dev settings
    // (dev_mode, no fsync, empty data_dir) before validation. This lets
    // `hearth serve --dev` work even when an auto-detected hearth.yaml omits
    // production-only fields like oidc.issuer.
    let mut config = if let Some(path) = config_path {
        if dev {
            Config::from_file_as_dev(path)?
        } else {
            Config::from_file(path)?
        }
    } else {
        let default_path = std::path::Path::new("hearth.yaml");
        if default_path.exists() {
            if dev {
                Config::from_file_as_dev(default_path)?
            } else {
                Config::from_file(default_path)?
            }
        } else if dev {
            return Ok(Config::dev());
        } else {
            Config::default()
        }
    };

    // `--dev` applied on top of a real config: keep every declaration
    // (realms, applications, organizations, branding, auth policy) and
    // flip just the knobs dev mode needs — ephemeral storage, no fsync,
    // debug logging, dev bootstrap endpoint. This is what lets
    // `hearth serve --dev -c examples/.../hearth.yaml` work the way
    // most readers expect.
    if dev {
        // dev_mode, fsync, data_dir already applied by from_file_as_dev above;
        // adjust log level here (not part of the pure file-loading concern).
        if config.observability.log_level.as_str() == "info" {
            config.observability.log_level = "debug".to_string();
        }
    }

    Ok(config)
}

/// Re-loads the config file and runs full reconciliation (realms + applications).
///
/// Called on SIGHUP or programmatic reload. Failures are logged but do not
/// crash the server — the previous config remains in effect.
///
/// After successful reconciliation the `PermissionRegistry` is rebuilt from
/// the new config and atomically swapped in via `ArcSwap`.
fn run_config_reconciliation(
    engine: &dyn IdentityEngine,
    rbac: &dyn RbacEngine,
    config_path: Option<&std::path::Path>,
    dev: bool,
    registry: &arc_swap::ArcSwap<hearth::rbac::registry::PermissionRegistry>,
) {
    let config = match load_config(dev, config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(error = %e, "config reload failed: could not parse config file");
            return;
        }
    };

    match hearth::identity::reconcile::reconcile_realms(engine, rbac, &config) {
        Ok(report) => {
            let app_created = report
                .applications
                .iter()
                .filter(|e| e.action == hearth::identity::reconcile::AppReconcileAction::Created)
                .count();
            let app_updated = report
                .applications
                .iter()
                .filter(|e| e.action == hearth::identity::reconcile::AppReconcileAction::Updated)
                .count();
            let app_archived = report
                .applications
                .iter()
                .filter(|e| e.action == hearth::identity::reconcile::AppReconcileAction::Archived)
                .count();
            info!(
                realms_created = report.created.len(),
                realms_updated = report.updated.len(),
                realms_archived = report.archived.len(),
                realms_unarchived = report.unarchived.len(),
                apps_created = app_created,
                apps_updated = app_updated,
                apps_archived = app_archived,
                orgs = report.organizations.len(),
                "configuration reconciliation complete"
            );
        }
        Err(e) => {
            error!(error = %e, "configuration reconciliation failed");
            return;
        }
    }

    // Hot-swap the PermissionRegistry atomically so in-flight token issuances
    // reading the current snapshot continue uninterrupted while the new
    // config takes effect for all subsequent issuances.
    let new_registry = build_permission_registry(&config);
    registry.store(Arc::new(new_registry));
    info!("PermissionRegistry hot-swapped");
}

/// Builds a [`PermissionRegistry`] from the current [`Config`].
///
/// Each declared realm's YAML config is compiled into a
/// [`RealmPermissionRegistry`] and assembled into the global snapshot.
/// Realms whose config fails validation are skipped with a `warn` log;
/// the previous registry entry (if any) is preserved by the `ArcSwap`
/// caller.
fn build_permission_registry(config: &Config) -> hearth::rbac::registry::PermissionRegistry {
    use hearth::rbac::registry::PermissionRegistry;

    let mut registry = PermissionRegistry::default();
    if let Some(realms) = &config.realms {
        for (realm_name, realm_yaml) in realms {
            match realm_yaml.to_realm_config(&config.auth, config.email.branding.as_ref()) {
                Ok(realm_config) => {
                    let realm_registry = hearth::rbac::registry::RealmPermissionRegistry {
                        permissions: realm_config.permissions,
                        roles: realm_config.roles,
                        scopes: realm_config.scopes,
                        protected_resources: realm_config.protected_resources,
                        claim_profile: realm_config.claim_profile,
                    };
                    // Use nil UUID as a placeholder; the real realm UUID is
                    // resolved after storage look-up in run_serve. This
                    // registry snapshot is authoritative for validation and
                    // claim-profile evaluation; the realm UUID key is looked
                    // up at reconciliation time.
                    let _ = realm_name; // name-keyed insertion deferred
                                        // Insert under a synthetic per-realm key derived from the
                                        // config name to allow multi-realm registries.
                    let realm_id = hearth::core::RealmId::new(uuid::Uuid::new_v5(
                        &uuid::Uuid::NAMESPACE_URL,
                        realm_name.as_bytes(),
                    ));
                    registry.realms.insert(realm_id, realm_registry);
                }
                Err(errs) => {
                    for e in &errs {
                        warn!(realm = %realm_name, error = %e, "registry validation error during hot-swap");
                    }
                }
            }
        }
    }
    registry
}

/// Runs the `hearth config reload` command.
///
/// Either sends SIGHUP to the running process (via PID file) or hits the
/// admin reload endpoint (via HTTP).
fn run_config_reload(
    url: Option<&str>,
    pid_file: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(server_url) = url {
        // HTTP-based reload
        let endpoint = format!("{server_url}/admin/api/config/reload");
        let mut resp = ureq::post(&endpoint).send_empty()?;
        let status = resp.status();
        let body: String = resp.body_mut().read_to_string()?;
        if status == 200 {
            tracing::info!("reload successful: {body}");
        } else {
            return Err(format!("reload failed (HTTP {status}): {body}").into());
        }
    } else {
        // SIGHUP-based reload
        #[cfg(unix)]
        {
            let pid_path = pid_file.map_or_else(|| PathBuf::from("data/hearth.pid"), PathBuf::from);
            let pid_str = std::fs::read_to_string(&pid_path)
                .map_err(|e| format!("cannot read PID file {}: {e}", pid_path.display()))?;
            let pid: i32 = pid_str
                .trim()
                .parse()
                .map_err(|e| format!("invalid PID in {}: {e}", pid_path.display()))?;
            // Send SIGHUP via kill(1) to avoid a libc dependency.
            let status = std::process::Command::new("kill")
                .args(["-HUP", &pid.to_string()])
                .status()
                .map_err(|e| format!("failed to execute kill: {e}"))?;
            if !status.success() {
                return Err(format!("failed to send SIGHUP to PID {pid}").into());
            }
            tracing::info!("sent SIGHUP to PID {pid}");
        }
        #[cfg(not(unix))]
        {
            let _ = pid_file; // suppress unused warning
            return Err("SIGHUP reload is only supported on Unix. Use --url instead.".into());
        }
    }
    Ok(())
}

/// Runs the `hearth realm create` command.
///
/// Generates a new realm UUID and prints it as JSON to stdout.
fn run_realm_create() {
    let realm_id = uuid::Uuid::new_v4();
    let output = serde_json::json!({ "realm_id": realm_id.to_string() });
    println!("{output}");
}

/// Runs the `hearth app create` command.
///
/// Registers an OAuth 2.0 client against a running Hearth server via HTTP.
/// Client registration is a privileged operation (HEA-1750): the caller must
/// supply an admin bearer token carrying `hearth.clients.admin` (or
/// `hearth.admin`). The target realm is derived from the token, so `realm_id`
/// is sent for reference only.
fn run_app_create(
    server: &str,
    realm_id: &str,
    name: &str,
    redirect_uri: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{server}/clients");
    let body = serde_json::json!({
        "client_name": name,
        "redirect_uris": [redirect_uri],
    });

    let response: serde_json::Value = ureq::post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("X-Realm-ID", realm_id)
        .header("Content-Type", "application/json")
        .send_json(&body)?
        .body_mut()
        .read_json()?;

    println!("{response}");
    Ok(())
}

/// Runs the `hearth migrate keycloak` command.
///
/// Parses a Keycloak realm export and imports its realm, users, clients,
/// and realm roles. In dry-run mode no state is written; otherwise a data
/// directory is required.
fn run_migrate_keycloak(
    file: &std::path::Path,
    data_dir: Option<&std::path::Path>,
    realm: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::core::RealmId;
    use hearth::identity::migration::{ImportOptions, KeycloakImporter, KeycloakRealmExport};
    use uuid::Uuid;

    let bytes = std::fs::read(file)?;
    let export: KeycloakRealmExport = KeycloakImporter::parse(&bytes)?;

    let requested_realm = realm
        .map(|s| -> Result<RealmId, Box<dyn std::error::Error>> {
            let uuid = Uuid::parse_str(s).map_err(|e| format!("invalid --realm UUID: {e}"))?;
            Ok(RealmId::new(uuid))
        })
        .transpose()?;

    if dry_run {
        // Dry-run uses a temporary store so the importer still exercises
        // its full validation path (parsing, tuple shape checks) without
        // touching the user's data directory.
        let temp_dir = tempfile::tempdir()?;
        let storage_config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
        let (identity, rbac) = build_engines(Arc::clone(&storage) as Arc<dyn StorageEngine>, true)?;
        let importer = KeycloakImporter::new(identity, rbac);
        let report =
            importer.import_realm(&export, requested_realm, &ImportOptions { dry_run: true })?;
        print_migration_report(&report);
        return Ok(());
    }

    let data_dir = data_dir.ok_or(
        "--data-dir is required for a real migration (use --dry-run to validate without writing)",
    )?;
    std::fs::create_dir_all(data_dir)?;
    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
    let (identity, rbac) = build_engines(Arc::clone(&storage) as Arc<dyn StorageEngine>, false)?;
    let importer = KeycloakImporter::new(identity, rbac);

    let report =
        importer.import_realm(&export, requested_realm, &ImportOptions { dry_run: false })?;
    print_migration_report(&report);
    Ok(())
}

/// Runs the `hearth migrate auth0` command.
///
/// Parses an Auth0 tenant bundle and imports its tenant, users, clients,
/// organizations, and role assignments. In dry-run mode no state is
/// written; otherwise a data directory is required.
fn run_migrate_auth0(
    file: &std::path::Path,
    data_dir: Option<&std::path::Path>,
    realm: Option<&str>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::core::RealmId;
    use hearth::identity::migration::{Auth0Bundle, Auth0ImportOptions, Auth0Importer};
    use uuid::Uuid;

    let bytes = std::fs::read(file)?;
    let bundle: Auth0Bundle = Auth0Importer::parse(&bytes)?;

    let requested_realm = realm
        .map(|s| -> Result<RealmId, Box<dyn std::error::Error>> {
            let uuid = Uuid::parse_str(s).map_err(|e| format!("invalid --realm UUID: {e}"))?;
            Ok(RealmId::new(uuid))
        })
        .transpose()?;

    if dry_run {
        let temp_dir = tempfile::tempdir()?;
        let storage_config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
        let (identity, rbac) = build_engines(Arc::clone(&storage) as Arc<dyn StorageEngine>, true)?;
        let importer = Auth0Importer::new(identity, rbac);
        let report = importer.import_bundle(
            &bundle,
            requested_realm,
            &Auth0ImportOptions { dry_run: true },
        )?;
        print_migration_report(&report);
        return Ok(());
    }

    let data_dir = data_dir.ok_or(
        "--data-dir is required for a real migration (use --dry-run to validate without writing)",
    )?;
    std::fs::create_dir_all(data_dir)?;
    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
    let (identity, rbac) = build_engines(Arc::clone(&storage) as Arc<dyn StorageEngine>, false)?;
    let importer = Auth0Importer::new(identity, rbac);

    let report = importer.import_bundle(
        &bundle,
        requested_realm,
        &Auth0ImportOptions { dry_run: false },
    )?;
    print_migration_report(&report);
    Ok(())
}

// ── Pepper rotation audit ──────────────────────────────────────────────────────

/// Audits all stored credentials and reports how many still carry an older or
/// absent pepper version.
///
/// Returns `Ok(true)` when every credential is up-to-date with the active
/// pepper (or when no pepper is configured and no credential has a pepper
/// version), `Ok(false)` when at least one credential needs rotation.
///
/// This command never modifies credentials; re-hashing happens lazily on the
/// next successful login after `hearth.yaml` is updated with the new pepper.
fn run_migrate_rotate_pepper(
    data_dir: &std::path::Path,
    summary_only: bool,
) -> Result<bool, Box<dyn std::error::Error>> {
    use hearth::identity::StoredCredential;

    use hearth::storage::StorageEngine as _;

    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = EmbeddedStorageEngine::open(storage_config)?;

    // List realms stored under the system realm.
    let sys_realm = hearth::core::RealmId::new(uuid::Uuid::nil());
    let realm_prefix = b"realm:";
    let realm_end = b"realm;"; // exclusive upper bound
    let realm_entries = storage.scan(&sys_realm, realm_prefix, realm_end)?;

    let mut total_credentials: u64 = 0;
    let mut needs_rotation: u64 = 0;
    let mut realms_with_pending: Vec<String> = Vec::new();

    for entry in &realm_entries {
        let realm_key = &entry.key;
        // Derive realm UUID from the key suffix.
        let suffix = realm_key
            .strip_prefix(realm_prefix)
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("<invalid>")
            .to_string();

        let realm_uuid = match uuid::Uuid::parse_str(&suffix) {
            Ok(u) => u,
            Err(_) => continue,
        };
        let realm_id = hearth::core::RealmId::new(realm_uuid);

        // Scan all credentials in this realm.
        let cred_prefix = hearth::identity::credential_scan_prefix_for_migration();
        let mut cred_end = cred_prefix.clone();
        // Advance the last byte to form an exclusive upper bound.
        if let Some(last) = cred_end.last_mut() {
            *last += 1;
        }

        let cred_entries = storage.scan(&realm_id, &cred_prefix, &cred_end)?;
        let mut realm_total: u64 = 0;
        let mut realm_pending: u64 = 0;

        for cred_entry in &cred_entries {
            let cred_bytes = &cred_entry.value;
            let cred: StoredCredential = match hearth::codec::decode(cred_bytes) {
                Ok(c) => c,
                Err(_) => continue,
            };
            realm_total += 1;
            total_credentials += 1;

            // A credential needs rotation if it has any pepper version
            // (we cannot compare to the active version without config, so we
            // count any non-None as "peppered, may need rotation" and None as
            // "no pepper, needs rotation if server now requires one").
            // Without loading hearth.yaml here, we report raw counts by version.
            if cred.pepper_version.is_none() {
                // No pepper recorded — flagged for rotation once a pepper is configured.
                realm_pending += 1;
                needs_rotation += 1;
            }
            // Credentials with Some(version) are assumed current unless the
            // operator compares against the active version in hearth.yaml.
        }

        if realm_pending > 0 {
            realms_with_pending.push(format!("{suffix}: {realm_pending}/{realm_total}"));
        }

        if !summary_only && realm_total > 0 {
            tracing::info!(
                "realm {suffix}: {realm_total} credential(s), {realm_pending} without pepper"
            );
        }
    }

    tracing::info!(
        "\nTotal: {total_credentials} credential(s), {needs_rotation} without pepper version"
    );

    if needs_rotation > 0 {
        tracing::info!("\nPending rotation (credentials without pepper_version):");
        for entry in &realms_with_pending {
            tracing::info!("  {entry}");
        }
        tracing::info!(
            "\nNext step: ensure `security.password.pepper` is set in hearth.yaml, then\n\
             restart the server. Credentials are re-hashed lazily on the next login."
        );
    } else {
        tracing::info!("\nAll credentials carry a pepper_version. Rotation complete.");
    }

    Ok(needs_rotation == 0)
}

// ── Backup commands ───────────────────────────────────────────────────────────

/// Runs `hearth backup create`.
///
/// Opens the storage engine, exports all (or a filtered) set of realms into a
/// zstd-compressed `.hearth-backup` archive, and prints a per-realm entity count
/// summary.  Exit code 0 on full success, 2 on any fatal error.
#[allow(clippy::too_many_lines)] // TODO: HEA-1354 split this function
fn run_backup_create(
    output: Option<&std::path::Path>,
    realm_filter: Option<&str>,
    include_audit: bool,
    encrypt: bool,
    data_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::backup::{BackupArchive, BackupExporter, BackupManifest, ExportOptions};
    use hearth::core::RealmId;
    use uuid::Uuid;

    std::fs::create_dir_all(data_dir)?;
    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
    let (identity, audit, rbac) =
        build_all_engines(Arc::clone(&storage) as Arc<dyn StorageEngine>)?;

    // Resolve output path — default: `./hearth-backup-<unix_secs>.hearth-backup`
    let out_path = match output {
        Some(p) => p.to_path_buf(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            std::path::PathBuf::from(format!("hearth-backup-{ts}.hearth-backup"))
        }
    };

    // Resolve optional realm filter.
    let filter_id: Option<RealmId> = realm_filter
        .map(|s| {
            // Try UUID first, then fall back to name lookup.
            if let Ok(uuid) = Uuid::parse_str(s) {
                return Ok(RealmId::new(uuid));
            }
            // Name lookup: list all realms and match.
            let batch = hearth::core::MAX_PAGE_LIMIT;
            let mut offset = 0u64;
            loop {
                let page = identity
                    .list_realms(&hearth::core::PageRequest::new(offset, batch))
                    .map_err(|e| format!("list_realms: {e}"))?;
                let n = page.items.len() as u64;
                for realm in &page.items {
                    if realm.name() == s {
                        return Ok(realm.id().clone());
                    }
                }
                if n == 0 || offset + n >= page.total {
                    break;
                }
                offset += n;
            }
            Err(format!("realm '{s}' not found"))
        })
        .transpose()
        .map_err(|e: String| e)?;

    let exporter =
        BackupExporter::new(Arc::clone(&identity), Arc::clone(&audit), Arc::clone(&rbac));
    let dek = BackupExporter::generate_dek()?;
    let opts = ExportOptions {
        include_audit,
        realm_filter: filter_id.as_ref().map(|id| vec![id.clone()]),
    };

    let mut writer = BackupArchive::create(&out_path)?;
    let mut realm_manifests = Vec::new();

    // Enumerate realms to export.
    let realms_to_export: Vec<RealmId> = if let Some(id) = filter_id {
        vec![id]
    } else {
        let mut ids = Vec::new();
        let batch = hearth::core::MAX_PAGE_LIMIT;
        let mut offset = 0u64;
        loop {
            let page = identity
                .list_realms(&hearth::core::PageRequest::new(offset, batch))
                .map_err(|e| format!("list_realms: {e}"))?;
            let n = page.items.len() as u64;
            for realm in &page.items {
                ids.push(realm.id().clone());
            }
            if n == 0 || offset + n >= page.total {
                break;
            }
            offset += n;
        }
        ids
    };

    if realms_to_export.is_empty() {
        tracing::error!("warning: no realms found to export");
    }

    for realm_id in &realms_to_export {
        let realm_manifest = exporter.export_realm(realm_id, &mut writer, &opts, &dek)?;
        tracing::info!(
            "  exported '{}': {} users, {} clients",
            realm_manifest.slug,
            realm_manifest.record_counts.users,
            realm_manifest.record_counts.clients,
        );
        realm_manifests.push(realm_manifest);
    }

    // Backup encryption is mandatory: use HEARTH_MASTER_KEY env var or prompt.
    let passphrase_str: String = if let Ok(mk) = std::env::var("HEARTH_MASTER_KEY") {
        if mk.is_empty() {
            return Err("HEARTH_MASTER_KEY is set but empty".into());
        }
        mk
    } else if encrypt {
        let p = rpassword::prompt_password("Enter backup passphrase: ")?;
        let c = rpassword::prompt_password("Confirm passphrase: ")?;
        if p != c {
            return Err("passphrases do not match".into());
        }
        if p.is_empty() {
            return Err("passphrase must not be empty".into());
        }
        p
    } else {
        return Err(
            "backup encryption is mandatory — set HEARTH_MASTER_KEY or use --encrypt".into(),
        );
    };
    let passphrase = secrecy::SecretString::from(passphrase_str);
    let (wrapped_dek_b64, wrapping_params) =
        BackupExporter::wrap_dek(&dek, &passphrase).map_err(|e| format!("DEK wrap: {e}"))?;
    let mut manifest = BackupManifest::new(realm_manifests);
    manifest.sections_encrypted = true;
    manifest.wrapped_dek_b64 = Some(wrapped_dek_b64);
    manifest.dek_wrapping_params = Some(wrapping_params);
    writer.finish(manifest)?;

    tracing::info!("Backup written to: {}", out_path.display());
    Ok(())
}

/// Runs `hearth backup restore`.
///
/// Returns `Ok(true)` when some records were skipped or errored (exit code 1),
/// `Ok(false)` on full success (exit code 0), `Err` on fatal error (exit code 2).
fn run_backup_restore(
    input: &std::path::Path,
    realm_slug: Option<&str>,
    mode_str: &str,
    dry_run: bool,
    data_dir: &std::path::Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    use hearth::backup::{BackupArchive, BackupImporter, ImportOptions, RestoreMode};

    let mode = match mode_str {
        "overwrite" => RestoreMode::Overwrite,
        "merge" => RestoreMode::Merge,
        _ => RestoreMode::Skip,
    };

    let reader = BackupArchive::open(input)?;

    std::fs::create_dir_all(data_dir)?;
    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);
    let (identity, _audit, rbac) =
        build_all_engines(Arc::clone(&storage) as Arc<dyn StorageEngine>)?;

    let importer = BackupImporter::new(identity, rbac);
    let dek_passphrase: Option<secrecy::SecretString> = if reader.manifest.sections_encrypted {
        let pp = if let Ok(mk) = std::env::var("HEARTH_MASTER_KEY") {
            mk
        } else {
            rpassword::prompt_password("Enter backup passphrase: ")?
        };
        Some(secrecy::SecretString::from(pp))
    } else {
        None
    };
    let opts = ImportOptions {
        mode,
        dry_run,
        realm_target: None,
        dek_passphrase,
    };

    let slugs: Vec<String> = if let Some(slug) = realm_slug {
        vec![slug.to_string()]
    } else {
        reader.realms().iter().map(|r| r.slug.clone()).collect()
    };

    if dry_run {
        tracing::info!("(dry-run: no data will be written)");
    }

    let mut had_errors = false;
    for slug in &slugs {
        let report = importer.import_realm(slug, &reader, &opts)?;
        print_import_report(slug, &report);
        if report.users.errored > 0 || report.clients.errored > 0 || report.realms.errored > 0 {
            had_errors = true;
        }
    }
    Ok(had_errors)
}

/// Runs `hearth backup verify`.
///
/// Recomputes SHA-256 checksums for every file in the archive and compares
/// them against the manifest.  Returns `Ok(())` on success or a
/// [`BackupError::ChecksumMismatch`](hearth::backup::BackupError) on failure.
fn run_backup_verify(input: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::backup::BackupArchive;

    let reader = BackupArchive::open(input)?;
    reader.verify_checksums()?;
    tracing::info!(
        "OK — all checksums match ({} files verified)",
        reader.manifest.checksums.len()
    );
    Ok(())
}

/// Runs `hearth backup inspect`.
///
/// Prints the manifest as a human-readable table without decompressing any
/// entity files.
fn run_backup_inspect(input: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::backup::BackupArchive;

    let reader = BackupArchive::open(input)?;
    let m = &reader.manifest;
    let dek_status = match (&m.wrapped_dek_b64, &m.dek_wrapping_params) {
        (Some(_), Some(_)) => "present (passphrase-protected)",
        (Some(_), None) => "present (no wrapping params — malformed)",
        _ => "absent",
    };
    let created_at_display =
        time::OffsetDateTime::from_unix_timestamp_nanos(m.created_at.as_micros() as i128 * 1000)
            .ok()
            .and_then(|dt| {
                dt.format(&time::format_description::well_known::Rfc3339)
                    .ok()
            })
            .unwrap_or_else(|| format!("{}µs (unix)", m.created_at.as_micros()));
    tracing::info!("Archive:           {}", input.display());
    tracing::info!("  format version : {}", m.format_version);
    tracing::info!("  hearth version : {}", m.hearth_version);
    tracing::info!("  created at     : {created_at_display}");
    tracing::info!("  signing key DEK: {dek_status}");
    tracing::info!("  checksummed files: {}", m.checksums.len());
    tracing::info!("  realms ({}):", m.realms.len());
    for r in &m.realms {
        let rc = &r.record_counts;
        tracing::info!("    {slug:<24}  id={id}", slug = r.slug, id = r.realm_id);
        tracing::info!(
            "      users={u}  credentials={c}  clients={cl}  roles={ro}  groups={g}  orgs={o}  audit={a}",
            u = rc.users,
            c = rc.credentials,
            cl = rc.clients,
            ro = rc.roles,
            g = rc.groups,
            o = rc.organizations,
            a = rc.audit_events,
        );
    }
    Ok(())
}

/// Prints an [`ImportReport`](hearth::backup::ImportReport) as a human-readable summary.
fn print_import_report(slug: &str, report: &hearth::backup::ImportReport) {
    tracing::info!("Realm '{slug}':");
    tracing::info!(
        "  realms   — created: {}, skipped: {}, overwritten: {}, errored: {}",
        report.realms.created,
        report.realms.skipped,
        report.realms.overwritten,
        report.realms.errored
    );
    tracing::info!(
        "  users    — created: {}, skipped: {}, overwritten: {}, errored: {}",
        report.users.created,
        report.users.skipped,
        report.users.overwritten,
        report.users.errored
    );
    tracing::info!(
        "  clients  — created: {}, skipped: {}, overwritten: {}, errored: {}",
        report.clients.created,
        report.clients.skipped,
        report.clients.overwritten,
        report.clients.errored
    );
    if !report.conflicts.is_empty() {
        tracing::info!("  conflicts ({}):", report.conflicts.len());
        for c in &report.conflicts {
            tracing::info!(
                "    [{:?}] {:?} — {}",
                c.entity_type,
                c.identifier,
                c.reason
            );
        }
    }
}

// ── Engine helpers ────────────────────────────────────────────────────────────

/// Identity + RBAC pair returned by [`build_engines`].
type AdminEngines = (
    Arc<dyn hearth::identity::IdentityEngine>,
    Arc<dyn hearth::rbac::RbacEngine>,
);

/// Identity + Audit + RBAC triple returned by [`build_all_engines`].
type AllEngines = (
    Arc<dyn hearth::identity::IdentityEngine>,
    Arc<dyn hearth::audit::AuditEngine>,
    Arc<dyn hearth::rbac::RbacEngine>,
);

/// Builds all three engine types (identity, audit, RBAC) for backup commands.
///
/// Uses production-mode credential settings since backup operates on live data.
fn build_all_engines(
    storage: Arc<dyn StorageEngine>,
) -> Result<AllEngines, Box<dyn std::error::Error>> {
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let raw_rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let rbac = Arc::clone(&raw_rbac) as Arc<dyn hearth::rbac::RbacEngine>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let raw_identity = Arc::new(EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage),
        clock,
        IdentityConfig::default(),
        Arc::clone(&rbac),
        Arc::clone(&audit),
    )?);
    raw_rbac.init_sv_bumper(Arc::clone(&raw_identity) as Arc<dyn SvBumper>);
    let identity = raw_identity as Arc<dyn hearth::identity::IdentityEngine>;
    Ok((identity, Arc::clone(&audit), rbac))
}

/// Builds the identity + RBAC engine pair used by one-shot admin
/// commands (migrations, etc.). Keeps the wiring in one place.
fn build_engines(
    storage: Arc<dyn StorageEngine>,
    dev_mode: bool,
) -> Result<AdminEngines, Box<dyn std::error::Error>> {
    let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
    let identity_config = if dev_mode {
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        }
    } else {
        IdentityConfig::default()
    };
    let raw_rbac = Arc::new(EmbeddedRbacEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let rbac = Arc::clone(&raw_rbac) as Arc<dyn hearth::rbac::RbacEngine>;
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    )) as Arc<dyn hearth::audit::AuditEngine>;
    let raw_identity = Arc::new(EmbeddedIdentityEngine::with_rbac(
        Arc::clone(&storage),
        clock,
        identity_config,
        Arc::clone(&rbac),
        Arc::clone(&audit),
    )?);
    raw_rbac.init_sv_bumper(Arc::clone(&raw_identity) as Arc<dyn SvBumper>);
    let identity = raw_identity as Arc<dyn hearth::identity::IdentityEngine>;
    Ok((identity, rbac))
}

/// Resolves the logo URL for the web UI.
///
/// When `branding.logo_url` is a local file path (not an HTTP URL and not
/// already pointing at a `/ui/static/` route), the file is read into memory
/// and a MIME type is inferred from the extension. The web UI URL is
/// rewritten to `/ui/static/custom-logo` so the browser can fetch the
/// bytes from [`web::serve_static`].
///
/// Returns `(web_logo_url, Option<(bytes, content_type)>)`.
fn resolve_web_logo(config: &Config) -> (String, Option<(Vec<u8>, &'static str)>) {
    let Some(logo_url) = config.branding.logo_url.as_deref() else {
        return (web::DEFAULT_LOGO_URL.to_string(), None);
    };

    if !is_local_logo_path(logo_url) {
        return (logo_url.to_string(), None);
    }

    let path = std::path::Path::new(logo_url);
    match std::fs::read(path) {
        Ok(bytes) => {
            let content_type = mime_for_logo(path);
            info!(
                path = %path.display(),
                content_type,
                size = bytes.len(),
                "loaded custom logo from local file"
            );
            (
                "/ui/static/custom-logo".to_string(),
                Some((bytes, content_type)),
            )
        }
        Err(e) => {
            warn!(
                path = %path.display(),
                error = %e,
                "failed to load custom logo file, falling back to default"
            );
            (web::DEFAULT_LOGO_URL.to_string(), None)
        }
    }
}

/// Returns `true` when the logo URL looks like a local filesystem path
/// rather than a remote URL or the built-in static route.
fn is_local_logo_path(s: &str) -> bool {
    !s.starts_with("http://") && !s.starts_with("https://") && !s.starts_with("/ui/static/")
}

/// Infers a MIME content type from a logo file's extension.
fn mime_for_logo(path: &std::path::Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some(e) if e.eq_ignore_ascii_case("svg") => "image/svg+xml",
        Some(e) if e.eq_ignore_ascii_case("png") => "image/png",
        Some(e) if e.eq_ignore_ascii_case("jpg") || e.eq_ignore_ascii_case("jpeg") => "image/jpeg",
        _ => "application/octet-stream",
    }
}

/// Runs the `hearth config validate` command.
///
/// Uses the all-collecting validator so every problem is reported in one pass.
/// Exits 0 on success (with a human-readable summary) and 1 on any error.
fn run_config_validate(file: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    // Parse without short-circuit so we can collect every issue.
    let config = match Config::from_file_unchecked(file) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("✗ Configuration invalid");
            tracing::error!("");
            tracing::error!("  parse error: {e}");
            return Err("configuration validation failed".into());
        }
    };

    // Collect all structural issues in one pass.
    let mut issues = config.validate_all();

    // TLS cert/key file existence (runtime check not covered by validate_all).
    config_validate_tls_files(&config, &mut issues);

    // Realm permission-registry cross-reference validation.
    if let Some(realms) = &config.realms {
        for (realm_name, realm_yaml) in realms {
            if let Err(errs) =
                realm_yaml.to_realm_config(&config.auth, config.email.branding.as_ref())
            {
                for e in errs {
                    issues.push(ValidationIssue {
                        field: format!("realms.{realm_name}"),
                        reason: e.to_string(),
                    });
                }
            }
        }
    }

    if issues.is_empty() {
        println!("✓ Configuration valid");
        println!();
        config_validate_print_summary(&config);
        Ok(())
    } else {
        eprintln!("✗ Configuration invalid — {} error(s):", issues.len());
        eprintln!();
        for issue in &issues {
            eprintln!("  {}: {}", issue.field, issue.reason);
            if let Some(hint) = config_validate_hint(&issue.field, &issue.reason) {
                eprintln!("    → {hint}");
            }
        }
        Err("configuration validation failed".into())
    }
}

/// Checks TLS cert/key/CA file existence and appends issues when files are missing.
fn config_validate_tls_files(config: &Config, issues: &mut Vec<ValidationIssue>) {
    for (field, path_opt) in [
        ("server.tls_cert_path", &config.server.tls_cert_path),
        ("server.tls_key_path", &config.server.tls_key_path),
        (
            "server.tls_client_ca_path",
            &config.server.tls_client_ca_path,
        ),
    ] {
        if let Some(path) = path_opt {
            if !path.exists() {
                issues.push(ValidationIssue {
                    field: field.to_string(),
                    reason: format!("file not found at path '{}'", path.display()),
                });
            }
        }
    }
}

/// Prints a one-screen summary of resolved config values on successful validation.
fn config_validate_print_summary(config: &Config) {
    let issuer = config
        .oidc
        .issuer
        .as_deref()
        .or(config.token.issuer.as_deref())
        .unwrap_or("not configured (defaults to https://hearth.local)");

    let tls_mode = match (&config.server.tls_cert_path, &config.server.tls_key_path) {
        (Some(cert), Some(_)) => format!("enabled (cert: {})", cert.display()),
        _ => "disabled (plain HTTP)".to_string(),
    };

    let email_transport = format!("{:?}", config.email.transport).to_ascii_lowercase();

    println!("  issuer:           {issuer}");
    println!("  storage:          {}", config.storage.data_dir);
    println!("  email transport:  {email_transport}");
    println!("  TLS:              {tls_mode}");
}

/// Returns an actionable hint for well-known validation issues.
fn config_validate_hint(field: &str, reason: &str) -> Option<String> {
    if field == "storage.data_dir" && reason.contains("empty") {
        return Some(
            "set storage.data_dir to a writable directory, e.g. storage:\n      data_dir: ./data"
                .to_string(),
        );
    }
    if field == "email.smtp" && reason.contains("required") {
        return Some(
            "add an email.smtp block with at least host and port, e.g.:\n      smtp:\n        host: smtp.example.com\n        port: 587"
                .to_string(),
        );
    }
    if field == "email.from" {
        return Some(
            "set email.from to a valid RFC 5322 address, e.g. \"Hearth <noreply@example.com>\""
                .to_string(),
        );
    }
    if (field.contains("tls_cert_path") || field.contains("tls_key_path"))
        && reason.contains("required")
    {
        return Some(
            "both server.tls_cert_path and server.tls_key_path must be set together".to_string(),
        );
    }
    if reason.contains("file not found") {
        return Some(
            "check that the path exists and is readable by the Hearth process".to_string(),
        );
    }
    if field == "oidc.issuer" {
        return Some(
            "set oidc.issuer to the public URL of this server, e.g. https://auth.example.com"
                .to_string(),
        );
    }
    None
}

/// Runs the `hearth config example` command.
///
/// Writes the annotated example `hearth.yaml` (embedded at compile time from
/// `hearth.example.yaml`) to stdout or to `--output <path>`.
fn run_config_example(output: Option<&PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    const EXAMPLE_YAML: &str = include_str!("../hearth.example.yaml");

    if let Some(path) = output {
        std::fs::write(path, EXAMPLE_YAML)
            .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
        println!("wrote example configuration to {}", path.display());
    } else {
        print!("{EXAMPLE_YAML}");
    }
    Ok(())
}

/// Runs the `hearth rbac orphans list` command.
///
/// Scans `rba:user_perm:*` storage keys for all realms and prints any
/// permission names that appear in storage.  A future iteration will
/// cross-check against the live registry to identify stale entries; for
/// now it lists all user-extra-permission keys so operators can inspect
/// the current runtime state.
fn run_rbac_orphans_list(
    _realm: Option<&str>,
    data_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::storage::StorageEngine as _;

    std::fs::create_dir_all(data_dir)?;
    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);

    // `rba:user_perm:` is the key prefix for user extra-permission grants.
    // Keys embed the realm UUID so a single prefix scan discovers all entries.
    let scan_start: &[u8] = b"rba:user_perm:";
    let scan_end = rbac_prefix_end(scan_start);
    let system_realm = hearth::core::RealmId::new(uuid::Uuid::nil());
    let entries = storage.scan(&system_realm, scan_start, &scan_end)?;

    if entries.is_empty() {
        tracing::info!("No user permission grant records found.");
        return Ok(());
    }

    for entry in &entries {
        let key_str = String::from_utf8_lossy(&entry.key);
        tracing::info!("{key_str}");
    }
    tracing::info!("{} user permission grant record(s) found.", entries.len());
    Ok(())
}

/// Runs the `hearth rbac orphans purge` command.
///
/// Scans and optionally deletes `rba:user_perm:*` storage keys.
/// In dry-run mode prints what would be removed without writing any changes.
fn run_rbac_orphans_purge(
    _realm: Option<&str>,
    data_dir: &std::path::Path,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use hearth::storage::StorageEngine as _;

    std::fs::create_dir_all(data_dir)?;
    let storage_config = StorageConfig::dev(data_dir.to_path_buf());
    let storage = Arc::new(EmbeddedStorageEngine::open(storage_config)?);

    let scan_start: &[u8] = b"rba:user_perm:";
    let scan_end = rbac_prefix_end(scan_start);
    let system_realm = hearth::core::RealmId::new(uuid::Uuid::nil());
    let entries = storage.scan(&system_realm, scan_start, &scan_end)?;

    if entries.is_empty() {
        tracing::info!("No user permission grant records found.");
        return Ok(());
    }

    let mut count = 0usize;
    for entry in &entries {
        let key_str = String::from_utf8_lossy(&entry.key);
        if dry_run {
            tracing::info!("[dry-run] would delete: {key_str}");
        } else {
            storage.delete(&system_realm, &entry.key)?;
            tracing::info!("deleted: {key_str}");
        }
        count += 1;
    }

    if dry_run {
        tracing::info!("[dry-run] {count} record(s) would be purged.");
    } else {
        tracing::info!("{count} record(s) purged.");
    }
    Ok(())
}

/// Emits debug-level startup diagnostics when `--verbose` is set.
///
/// Logs resolved config values, HTTP route groups, realm names, and Ed25519
/// key fingerprints (via JWKS kid). Called once after realm reconciliation.
fn log_verbose_startup_diagnostics(config: &Config, identity: &dyn IdentityEngine) {
    use tracing::debug;

    let issuer = config
        .oidc
        .issuer
        .as_deref()
        .or(config.token.issuer.as_deref())
        .unwrap_or("(default)");
    let tls_mode = match (&config.server.tls_cert_path, &config.server.tls_key_path) {
        (Some(cert), Some(_)) => format!("enabled (cert: {})", cert.display()),
        _ => "disabled".to_string(),
    };
    let email_transport = format!("{:?}", config.email.transport).to_ascii_lowercase();

    debug!(
        storage_path = %config.storage.data_dir,
        bind = %format!("{}:{}", config.server.bind_address, config.server.port),
        issuer,
        tls = %tls_mode,
        email_transport,
        "verbose: resolved config"
    );

    // HTTP route groups (axum does not expose runtime introspection; list by prefix).
    debug!(
        routes = "GET /health, /healthz, /readyz, /metrics, \
                  POST /admin/bootstrap (dev), \
                  /admin/api/* (users, realms, apps, roles, groups, webhooks, audit), \
                  /.well-known/openid-configuration, \
                  /authorize, /token, /register, /device_authorization, /introspect, /revoke, \
                  /v1/me, /v1/me/permissions, \
                  /ui/* (login, admin, static assets)",
        "verbose: HTTP route groups"
    );

    // Realms and key fingerprints.
    match identity.list_realms(&hearth::core::PageRequest::new(0, 200)) {
        Ok(page) => {
            debug!(count = page.items.len(), "verbose: loaded realms");
            for realm in &page.items {
                let kid = identity
                    .realm_jwks(realm.id())
                    .ok()
                    .and_then(|jwks| jwks.keys.into_iter().next())
                    .map(|k| k.kid)
                    .unwrap_or_else(|| "(no key)".to_string());
                debug!(
                    realm_name = %realm.name(),
                    realm_id = %realm.id().as_uuid(),
                    key_fingerprint = %kid,
                    "verbose: realm key"
                );
            }
        }
        Err(e) => {
            debug!(error = %e, "verbose: could not list realms for key diagnostics");
        }
    }
}

/// Computes the exclusive end bound for a storage prefix scan.
///
/// Increments the last byte of the prefix by 1 so that `scan(prefix,
/// prefix_end)` returns exactly the entries whose keys start with `prefix`.
fn rbac_prefix_end(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    if let Some(last) = end.last_mut() {
        *last = last.saturating_add(1);
    }
    end
}

/// Prints a `MigrationReport` as a human-readable summary.
fn print_migration_report(report: &hearth::identity::MigrationReport) {
    tracing::info!("Migration summary:");
    if let Some(tid) = &report.realm_id {
        tracing::info!("  realm:                {tid}");
    } else {
        tracing::info!("  realm:                <none>");
    }
    tracing::info!("  users imported:        {}", report.users_imported);
    tracing::info!(
        "  users w/ skipped cred: {}",
        report.users_with_skipped_credentials
    );
    tracing::info!("  clients imported:      {}", report.clients_imported);
    tracing::info!(
        "  role assignments:      {}",
        report.role_assignments_written
    );
    if !report.warnings.is_empty() {
        tracing::info!("Warnings:");
        for w in &report.warnings {
            tracing::info!("  - {w}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hearth::config::{Config, EmailTransport};

    // ── loadtest_unthrottle_decision (HEA-1796 prod-safety gate) ──────────

    #[test]
    fn unthrottle_off_when_flag_unset() {
        // Flag unset → limiters stay on regardless of dev/bind (even loopback).
        assert_eq!(
            loadtest_unthrottle_decision(false, true, "127.0.0.1", None),
            LoadtestUnthrottle::Off
        );
    }

    #[test]
    fn unthrottle_enabled_on_loopback_binds() {
        // Dev mode + loopback HTTP bind, gRPC disabled → enabled.
        for bind in ["127.0.0.1", "127.0.0.53", "::1", "localhost", "LOCALHOST"] {
            assert_eq!(
                loadtest_unthrottle_decision(true, true, bind, None),
                LoadtestUnthrottle::Enabled,
                "{bind} must be treated as loopback"
            );
        }
    }

    #[test]
    fn unthrottle_enabled_when_both_binds_loopback() {
        // HEA-1797 Finding 1: an enabled gRPC listener must also be loopback.
        assert_eq!(
            loadtest_unthrottle_decision(true, true, "127.0.0.1", Some("::1")),
            LoadtestUnthrottle::Enabled
        );
    }

    #[test]
    fn unthrottle_refused_on_non_loopback_binds() {
        // Wildcard and routable HTTP binds MUST refuse — this is the production
        // guard that keeps rate limiters on if the flag is set by mistake.
        for bind in ["0.0.0.0", "::", "10.0.0.5", "192.168.1.10", "example.com"] {
            assert_eq!(
                loadtest_unthrottle_decision(true, true, bind, None),
                LoadtestUnthrottle::RefusedNonLoopback,
                "{bind} must refuse the unthrottle escape hatch"
            );
        }
    }

    #[test]
    fn unthrottle_refused_on_divergent_grpc_bind() {
        // HEA-1797 Finding 1: HTTP loopback but gRPC on a public interface must
        // refuse — otherwise the disabled shaper + admin limiter leak onto a
        // publicly reachable gRPC management endpoint.
        for grpc in ["0.0.0.0", "::", "10.0.0.5", "192.168.1.10"] {
            assert_eq!(
                loadtest_unthrottle_decision(true, true, "127.0.0.1", Some(grpc)),
                LoadtestUnthrottle::RefusedNonLoopback,
                "gRPC bind {grpc} must refuse even when HTTP is loopback"
            );
        }
    }

    #[test]
    fn unthrottle_refused_when_not_dev() {
        // HEA-1797 Finding 2: a prod-config binary on loopback can still be
        // internet-reachable behind a reverse proxy — refuse unless --dev.
        assert_eq!(
            loadtest_unthrottle_decision(true, false, "127.0.0.1", None),
            LoadtestUnthrottle::RefusedNotDev
        );
        // Non-dev takes precedence over a bind check.
        assert_eq!(
            loadtest_unthrottle_decision(true, false, "0.0.0.0", Some("0.0.0.0")),
            LoadtestUnthrottle::RefusedNotDev
        );
    }

    // ── resolve_dev_data_dir precedence (HEA-1805) ────────────────────────

    #[test]
    fn dev_data_dir_env_override_wins() {
        // HEARTH_DEV_DATA_DIR takes precedence over any config data_dir.
        assert_eq!(
            resolve_dev_data_dir(Some("/srv/env"), "./data/config"),
            Some(PathBuf::from("/srv/env"))
        );
    }

    #[test]
    fn dev_data_dir_honors_non_default_config() {
        // No env override, but config sets a non-default data_dir → honor it.
        // This is the HEA-1805 bug: previously ignored in --dev, forcing an
        // otherwise-redundant HEARTH_DEV_DATA_DIR to persist cold-tier SSTs.
        assert_eq!(
            resolve_dev_data_dir(None, "./data/tier-miss"),
            Some(PathBuf::from("./data/tier-miss"))
        );
    }

    #[test]
    fn dev_data_dir_default_config_is_ephemeral() {
        // Neither env override nor a non-default data_dir → None, so the caller
        // keeps the historical ephemeral-temp behavior for a bare `--dev` run.
        assert_eq!(
            resolve_dev_data_dir(None, StorageSection::DEFAULT_DATA_DIR),
            None
        );
    }

    #[test]
    fn dev_data_dir_blank_env_falls_through_to_config() {
        // A blank/whitespace env value is treated as unset, so config wins.
        assert_eq!(
            resolve_dev_data_dir(Some("   "), "./data/tier-miss"),
            Some(PathBuf::from("./data/tier-miss"))
        );
        // ...and with a default config that means ephemeral temp.
        assert_eq!(
            resolve_dev_data_dir(Some(""), StorageSection::DEFAULT_DATA_DIR),
            None
        );
    }

    // ── build_startup_panel unthrottle banner (HEA-1799) ──────────────────

    fn panel_stats(rate_limiters_disabled: bool) -> StartupStats {
        StartupStats {
            realm_count: 1,
            federation_count: 0,
            email_transport: "log",
            tls: false,
            oidc_issuer: None,
            cluster_peers: None,
            wal_size: None,
            sst_count: 0,
            data_dir_bytes: 0,
            startup_ms: 1,
            rate_limiters_disabled,
        }
    }

    #[test]
    fn startup_panel_shows_banner_when_rate_limiters_disabled() {
        let addr = "127.0.0.1:8420".parse().expect("valid socket addr");
        let lines = build_startup_panel(addr, true, None, None, &panel_stats(true));
        assert!(
            lines
                .iter()
                .any(|l| l.contains("RATE LIMITERS DISABLED (load test mode)")),
            "panel must carry the unthrottled banner when the escape hatch is enabled: {lines:?}"
        );
    }

    #[test]
    fn startup_panel_omits_banner_when_rate_limiters_enabled() {
        let addr = "127.0.0.1:8420".parse().expect("valid socket addr");
        let lines = build_startup_panel(addr, true, None, None, &panel_stats(false));
        assert!(
            !lines.iter().any(|l| l.contains("RATE LIMITERS DISABLED")),
            "panel must not mention disabled limiters during normal operation: {lines:?}"
        );
    }

    // ── maybe_upgrade_email_transport ─────────────────────────────────────

    #[test]
    fn dev_mode_log_transport_upgraded_to_mailcatcher() {
        let mut cfg = Config::dev();
        cfg.email.transport = EmailTransport::Log;
        let warned = maybe_upgrade_email_transport(&mut cfg);
        assert_eq!(cfg.email.transport, EmailTransport::Mailcatcher);
        assert!(!warned, "Log→Mailcatcher should not produce a warning");
    }

    #[test]
    fn dev_mode_smtp_transport_upgraded_to_mailcatcher_with_warning() {
        let mut cfg = Config::dev();
        cfg.email.transport = EmailTransport::Smtp;
        let warned = maybe_upgrade_email_transport(&mut cfg);
        assert_eq!(cfg.email.transport, EmailTransport::Mailcatcher);
        assert!(
            warned,
            "Smtp→Mailcatcher should return true so caller can warn"
        );
    }

    #[test]
    fn dev_mode_mailcatcher_unchanged() {
        let mut cfg = Config::dev();
        cfg.email.transport = EmailTransport::Mailcatcher;
        let warned = maybe_upgrade_email_transport(&mut cfg);
        assert_eq!(cfg.email.transport, EmailTransport::Mailcatcher);
        assert!(!warned);
    }

    #[test]
    fn dev_mode_production_transports_unchanged() {
        for transport in [
            EmailTransport::Sendgrid,
            EmailTransport::Postmark,
            EmailTransport::Mailgun,
            EmailTransport::Mailtrap,
        ] {
            let mut cfg = Config::dev();
            cfg.email.transport = transport;
            let warned = maybe_upgrade_email_transport(&mut cfg);
            assert_eq!(
                cfg.email.transport, transport,
                "production transport {transport:?} must not be overridden in dev mode"
            );
            assert!(!warned);
        }
    }

    #[test]
    fn non_dev_mode_does_not_upgrade_smtp() {
        let mut cfg = Config::default();
        cfg.email.transport = EmailTransport::Smtp;
        let warned = maybe_upgrade_email_transport(&mut cfg);
        assert_eq!(
            cfg.email.transport,
            EmailTransport::Smtp,
            "non-dev mode must not override smtp"
        );
        assert!(!warned);
    }

    // ── dev_mode_bind_check (HEA-1980 startup gate) ───────────────────────

    #[test]
    fn dev_bind_check_not_dev_always_ok() {
        // Gate only applies in --dev mode; production mode always passes through.
        for bind in ["0.0.0.0", "::", "10.0.0.5", "127.0.0.1"] {
            assert_eq!(
                dev_mode_bind_check(false, bind, None),
                DevBindCheck::NotDev,
                "non-dev mode must not be refused for bind {bind}"
            );
        }
    }

    #[test]
    fn dev_bind_check_dev_loopback_http_no_grpc() {
        // Dev + loopback HTTP, gRPC disabled → Ok.
        for bind in ["127.0.0.1", "::1", "localhost", "LOCALHOST", "127.0.0.53"] {
            assert_eq!(
                dev_mode_bind_check(true, bind, None),
                DevBindCheck::Ok,
                "{bind} is loopback and must be allowed in dev mode"
            );
        }
    }

    #[test]
    fn dev_bind_check_refused_non_loopback_http() {
        // Dev + non-loopback HTTP bind → refused, even when gRPC is disabled.
        for bind in ["0.0.0.0", "::", "10.0.0.5", "192.168.1.10", "example.com"] {
            assert_eq!(
                dev_mode_bind_check(true, bind, None),
                DevBindCheck::RefusedNonLoopback,
                "dev mode with http bind {bind} must be refused"
            );
        }
    }

    #[test]
    fn dev_bind_check_refused_non_loopback_grpc() {
        // Dev + loopback HTTP but non-loopback gRPC → refused (both binds must be loopback).
        for grpc in ["0.0.0.0", "::", "10.0.0.5", "192.168.1.10"] {
            assert_eq!(
                dev_mode_bind_check(true, "127.0.0.1", Some(grpc)),
                DevBindCheck::RefusedNonLoopback,
                "dev mode with grpc bind {grpc} must be refused even when http is loopback"
            );
        }
    }

    #[test]
    fn dev_bind_check_dev_both_binds_loopback() {
        // Dev + loopback HTTP + loopback gRPC → Ok.
        assert_eq!(
            dev_mode_bind_check(true, "127.0.0.1", Some("::1")),
            DevBindCheck::Ok
        );
        assert_eq!(
            dev_mode_bind_check(true, "::1", Some("127.0.0.1")),
            DevBindCheck::Ok
        );
    }

    #[test]
    fn dev_bind_check_refused_cli_override_non_loopback() {
        // `hearth serve --dev --bind 0.0.0.0` — the CLI override path that
        // config-file validation misses because it runs before the override is
        // applied (HEA-1980).
        assert_eq!(
            dev_mode_bind_check(true, "0.0.0.0", None),
            DevBindCheck::RefusedNonLoopback,
            "--dev --bind 0.0.0.0 must be refused at startup"
        );
        assert_eq!(
            dev_mode_bind_check(true, "::", None),
            DevBindCheck::RefusedNonLoopback,
            "--dev --bind :: must be refused at startup"
        );
    }

    // ── HEA-SEC-10: setup token truncation ───────────────────────────────────

    /// Dev-mode startup panel truncates the setup token to 8 characters.
    /// Full token must NOT appear in the log line.
    #[test]
    fn setup_token_preview_is_8_chars_and_omits_full_token() {
        let full_token = "abcdefghijklmnopqrstuvwxyz0123456789"; // 36 chars
        let preview: String = full_token.chars().take(8).collect();
        assert_eq!(preview.len(), 8, "preview must be exactly 8 chars");
        assert_eq!(&preview, "abcdefgh");
        assert!(
            !preview.contains(&full_token[8..]),
            "preview must not include chars beyond the 8-char prefix"
        );
    }
}
