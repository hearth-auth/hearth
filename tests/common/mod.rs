//! Test infrastructure for black box testing.
//!
//! Provides [`TestHarness`] for running tests against Hearth in both
//! embedded and server modes. The same test logic can run against both
//! modes to verify the public API contract.

// Each integration test binary compiles this module independently,
// so not all variants/methods are used in every binary.
#![allow(dead_code)]

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use hearth::audit::{AuditEngine, EmbeddedAuditEngine};
use hearth::core::{Clock, SystemClock};
use hearth::identity::{
    device_fp::DeviceFingerprintStore, CreateRealmRequest, CredentialConfig,
    EmbeddedIdentityEngine, IdentityConfig, IdentityEngine,
};
use hearth::rbac::{EmbeddedRbacEngine, RbacEngine, SvBumper};
use hearth::storage::{EmbeddedStorageEngine, StorageConfig, StorageEngine};

// Kept alongside the harness so tests can hand the engines to gRPC / HTTP
// rigs that require `Arc<dyn Trait>`.

/// Errors from test harness operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum TestHarnessError {
    /// Storage engine failed to initialize.
    Storage(hearth::storage::StorageError),
    /// Server failed to bind or start.
    Io(std::io::Error),
}

impl fmt::Display for TestHarnessError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage initialization failed: {err}"),
            Self::Io(err) => write!(f, "server bind/start failed: {err}"),
        }
    }
}

impl std::error::Error for TestHarnessError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            Self::Io(err) => Some(err),
        }
    }
}

impl From<hearth::storage::StorageError> for TestHarnessError {
    fn from(err: hearth::storage::StorageError) -> Self {
        Self::Storage(err)
    }
}

impl From<std::io::Error> for TestHarnessError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// The operational mode of the test harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessMode {
    /// In-process embedded engine (library mode).
    Embedded,
    /// HTTP server on a random port.
    Server,
}

/// Test harness wrapping a Hearth instance for black box testing.
pub struct TestHarness {
    /// The operational mode.
    mode: HarnessMode,
    /// Storage engine.
    engine: Arc<EmbeddedStorageEngine>,
    /// RBAC engine.
    rbac_engine: Arc<EmbeddedRbacEngine>,
    /// Identity engine.
    identity_engine: Arc<EmbeddedIdentityEngine>,
    /// Audit engine.
    audit_engine: Arc<EmbeddedAuditEngine>,
    /// Base URL for server mode (e.g. `http://127.0.0.1:54321`). None in embedded mode.
    base_url: Option<String>,
    /// Background server task handle — aborted on drop to release the port.
    _server_handle: Option<tokio::task::AbortHandle>,
    /// Temporary directory — held for lifetime management.
    _temp_dir: tempfile::TempDir,
}

impl fmt::Debug for TestHarness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestHarness")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl TestHarness {
    /// Creates a test harness in embedded mode.
    #[allow(clippy::unused_async)]
    pub async fn embedded() -> Result<Self, TestHarnessError> {
        let temp_dir = tempfile::tempdir().map_err(hearth::storage::StorageError::Io)?;
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let engine = Arc::new(EmbeddedStorageEngine::open(config)?);
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let rbac_engine = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit_engine = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_engine = EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&rbac_engine) as Arc<dyn RbacEngine>,
            Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine creation");
        let identity_engine = Arc::new(identity_engine);
        // Wire session-version bumper so RBAC mutations trigger sv invalidation.
        rbac_engine.init_sv_bumper(Arc::clone(&identity_engine) as Arc<dyn SvBumper>);

        Ok(Self {
            mode: HarnessMode::Embedded,
            engine,
            rbac_engine,
            identity_engine,
            audit_engine,
            base_url: None,
            _server_handle: None,
            _temp_dir: temp_dir,
        })
    }

    /// Creates a test harness in embedded mode with an injected pre-token
    /// webhook transport (for HEA-1324 tests).
    #[allow(clippy::unused_async)]
    pub async fn embedded_with_pre_token_transport(
        transport: std::sync::Arc<
            dyn hearth::identity::pre_token_webhook::PreTokenWebhookTransport,
        >,
    ) -> Result<Self, TestHarnessError> {
        let temp_dir = tempfile::tempdir().map_err(hearth::storage::StorageError::Io)?;
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let engine = Arc::new(EmbeddedStorageEngine::open(config)?);
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let rbac_engine = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit_engine = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_engine = EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&rbac_engine) as Arc<dyn RbacEngine>,
            Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine creation")
        .with_pre_token_transport(transport);
        let identity_engine = Arc::new(identity_engine);
        rbac_engine.init_sv_bumper(Arc::clone(&identity_engine) as Arc<dyn SvBumper>);

        Ok(Self {
            mode: HarnessMode::Embedded,
            engine,
            rbac_engine,
            identity_engine,
            audit_engine,
            base_url: None,
            _server_handle: None,
            _temp_dir: temp_dir,
        })
    }

    /// Creates a test harness in server mode.
    ///
    /// Starts an HTTP server on a random OS-assigned port backed by the same
    /// in-process engines as embedded mode. Tests can read state via the engine
    /// accessors and exercise the public API via [`Self::base_url`].
    pub async fn server() -> Result<Self, TestHarnessError> {
        let temp_dir = tempfile::tempdir().map_err(hearth::storage::StorageError::Io)?;
        let config = StorageConfig::dev(temp_dir.path().to_path_buf());
        let engine = Arc::new(EmbeddedStorageEngine::open(config)?);
        let clock = Arc::new(SystemClock) as Arc<dyn Clock>;
        let rbac_engine = Arc::new(EmbeddedRbacEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_config = IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        };
        let audit_engine = Arc::new(EmbeddedAuditEngine::new(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
        ));
        let identity_engine = EmbeddedIdentityEngine::with_rbac(
            Arc::clone(&engine) as Arc<dyn StorageEngine>,
            Arc::clone(&clock),
            identity_config,
            Arc::clone(&rbac_engine) as Arc<dyn RbacEngine>,
            Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
        )
        .expect("identity engine creation");
        let identity_engine = Arc::new(identity_engine);
        rbac_engine.init_sv_bumper(Arc::clone(&identity_engine) as Arc<dyn SvBumper>);

        // Build the HTTP router backed by the same engines.
        let app_state = Arc::new(hearth::protocol::http::AppState::new_dev(
            Arc::clone(&identity_engine) as Arc<dyn IdentityEngine>,
            Arc::clone(&rbac_engine) as Arc<dyn RbacEngine>,
            Arc::clone(&audit_engine) as Arc<dyn AuditEngine>,
        ));
        let router = hearth::protocol::http::router(app_state);

        // Bind to a random OS-assigned port so tests never collide.
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let addr = listener.local_addr()?;
        let base_url = format!("http://{addr}");

        let handle = tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        Ok(Self {
            mode: HarnessMode::Server,
            engine,
            rbac_engine,
            identity_engine,
            audit_engine,
            base_url: Some(base_url),
            _server_handle: Some(handle.abort_handle()),
            _temp_dir: temp_dir,
        })
    }

    /// Returns the operational mode of this harness.
    pub fn mode(&self) -> HarnessMode {
        self.mode
    }

    /// Returns a reference to the storage engine.
    pub fn storage(&self) -> &dyn StorageEngine {
        self.engine.as_ref()
    }

    /// Returns a reference to the RBAC engine.
    pub fn rbac(&self) -> &dyn RbacEngine {
        self.rbac_engine.as_ref()
    }

    /// Legacy alias kept so existing tests still compile. Returns the RBAC engine.
    pub fn authz(&self) -> &dyn RbacEngine {
        self.rbac_engine.as_ref()
    }

    /// Returns a reference to the identity engine.
    pub fn identity(&self) -> &dyn IdentityEngine {
        self.identity_engine.as_ref()
    }

    /// Returns a reference to the audit engine.
    pub fn audit(&self) -> &dyn AuditEngine {
        self.audit_engine.as_ref()
    }

    /// Returns an `Arc<dyn IdentityEngine>`.
    pub fn identity_arc(&self) -> Arc<dyn IdentityEngine> {
        self.identity_engine.clone() as Arc<dyn IdentityEngine>
    }

    /// Returns an `Arc<dyn RbacEngine>`.
    pub fn rbac_arc(&self) -> Arc<dyn RbacEngine> {
        self.rbac_engine.clone() as Arc<dyn RbacEngine>
    }

    /// Legacy alias kept so existing tests still compile. Returns the RBAC engine.
    pub fn authz_arc(&self) -> Arc<dyn RbacEngine> {
        self.rbac_arc()
    }

    /// Returns an `Arc<dyn AuditEngine>`.
    pub fn audit_arc(&self) -> Arc<dyn AuditEngine> {
        self.audit_engine.clone() as Arc<dyn AuditEngine>
    }

    /// Returns a `DeviceFingerprintStore` backed by the same storage as the identity engine.
    pub fn device_fp_store(&self) -> DeviceFingerprintStore {
        DeviceFingerprintStore::new(Arc::clone(&self.engine) as Arc<dyn StorageEngine>)
    }

    /// Creates a new realm and returns its `RealmId`.
    pub fn create_realm(&self) -> hearth::core::RealmId {
        self.identity()
            .create_realm(&CreateRealmRequest {
                name: format!("test-realm-{}", uuid::Uuid::new_v4()),
                config: None,
            })
            .expect("create test realm")
            .id()
            .clone()
    }

    /// Returns the base URL for server mode, or `None` for embedded mode.
    ///
    /// Use this to construct HTTP requests in dual-mode tests:
    /// ```ignore
    /// if let Some(url) = h.base_url() {
    ///     // exercise via HTTP
    /// } else {
    ///     // exercise via embedded engine directly
    /// }
    /// ```
    pub fn base_url(&self) -> Option<&str> {
        self.base_url.as_deref()
    }
}
