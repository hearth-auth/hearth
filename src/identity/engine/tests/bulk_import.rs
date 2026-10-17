//! A bulk import shares each fsync among many users (#536).
//!
//! `POST /admin/users/import` imported its users one by one, and each user
//! waited for two fsyncs: one for its rows, then one for its audit event. On a
//! cloud disk a 10,000-user request, the documented maximum, ran past the
//! 30-second request timeout. The client got a 504 while the server went on
//! importing, and a retry then failed with "email exists" for every user.

use super::*;

/// An engine on storage that fsyncs every write, as in production. The
/// storage handle reads back the WAL sync count: the number of durable writes.
fn durable_engine() -> (
    tempfile::TempDir,
    EmbeddedIdentityEngine,
    Arc<EmbeddedStorageEngine>,
    Arc<EmbeddedAuditEngine>,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    config.wal_config.sync_mode = crate::storage::wal::SyncMode::EveryWrite;
    let storage = Arc::new(EmbeddedStorageEngine::open(config).expect("open"));
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000)));
    let audit = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        Arc::clone(&clock) as Arc<dyn Clock>,
    ));
    let engine = EmbeddedIdentityEngine::new(
        Arc::clone(&storage) as Arc<dyn StorageEngine>,
        clock as Arc<dyn Clock>,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        Arc::clone(&audit) as Arc<dyn AuditEngine>,
    )
    .expect("engine creation");
    (dir, engine, storage, audit)
}

fn import_request(email: &str) -> ImportUserRequest {
    ImportUserRequest {
        id: None,
        email: email.to_string(),
        display_name: "Bulk User".to_string(),
        first_name: String::new(),
        last_name: String::new(),
        status: UserStatus::Active,
        credential: None,
        attributes: std::collections::BTreeMap::new(),
    }
}

#[test]
fn a_bulk_import_commits_many_users_with_each_fsync() {
    let (_dir, engine, storage, audit) = durable_engine();
    let realm = create_test_realm(&engine);
    let n = 300;
    let mut requests: Vec<ImportUserRequest> = (0..n)
        .map(|i| import_request(&format!("bulk{i:05}@example.com")))
        .collect();
    // A repeat of an earlier email in the same request still fails alone.
    requests.push(import_request("bulk00010@example.com"));
    let before = storage.wal_sync_count();

    let results = engine.import_users(&realm, &requests);

    let syncs = storage.wal_sync_count() - before;
    assert_eq!(results.len(), n + 1);
    for (i, result) in results.iter().take(n).enumerate() {
        let user = result.as_ref().expect("import");
        assert_eq!(user.email(), format!("bulk{i:05}@example.com"));
    }
    assert!(
        matches!(results[n], Err(IdentityError::DuplicateEmail)),
        "the repeated email: {:?}",
        results[n].as_ref().map(User::email)
    );
    for i in [0, n / 2, n - 1] {
        let email = format!("bulk{i:05}@example.com");
        assert!(
            engine
                .get_user_by_email(&realm, &email)
                .expect("get")
                .is_some(),
            "{email} is not stored"
        );
    }
    let mut query = crate::audit::AuditQuery::for_realm(realm.clone());
    query.action = Some(AuditAction::UserCreated);
    query.limit = Some(10 * n);
    assert_eq!(
        audit.query(&query).expect("query audit").len(),
        n,
        "one UserCreated event per imported user"
    );
    // One by one, the import made two durable writes per user.
    assert!(
        syncs <= n as u64 / 10,
        "{syncs} durable writes to import {n} users"
    );
}

/// Imports that run at the same time all finish.
///
/// A group-commit leader steps down after a number of batches, with writers
/// still in the queue. An import that then enqueues its next user becomes the
/// leader, while an earlier user of its chunk is still queued. In v4.2.3 the
/// import waited for its users in enqueue order: it waited for that earlier
/// user, which only its own commit makes durable, so it waited for ever, and
/// so did every other write. Eight 10,000-user requests stopped a server in
/// less than 30 seconds.
#[test]
fn concurrent_bulk_imports_all_finish() {
    let (_dir, engine, _storage, _audit) = durable_engine();
    let engine = Arc::new(engine);
    let realm = create_test_realm(&engine);
    let threads = 8;
    let per_thread = 20 * IMPORT_PIPELINE_DEPTH;
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    for t in 0..threads {
        let engine = Arc::clone(&engine);
        let realm = realm.clone();
        let done = done_tx.clone();
        std::thread::spawn(move || {
            let requests: Vec<ImportUserRequest> = (0..per_thread)
                .map(|i| import_request(&format!("t{t}-{i:05}@example.com")))
                .collect();
            let results = engine.import_users(&realm, &requests);
            let imported = results.iter().filter(|result| result.is_ok()).count();
            done.send(imported).expect("send");
        });
    }
    drop(done_tx);
    // A thread that waits for itself never sends: the bound makes that a failure.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    for _ in 0..threads {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let imported = done_rx
            .recv_timeout(left)
            .expect("an import did not finish in 30 s: the imports wait for each other");
        assert_eq!(imported, per_thread, "every user of the import is imported");
    }
}

/// The embedded audit engine, except that it refuses the merged write of
/// every third event, as an audit engine without one does.
struct SometimesUnmerged {
    inner: Arc<EmbeddedAuditEngine>,
    merged_calls: std::sync::atomic::AtomicUsize,
}

impl AuditEngine for SometimesUnmerged {
    fn append(
        &self,
        event: &crate::audit::CreateAuditEvent,
    ) -> Result<crate::audit::AuditEvent, crate::audit::AuditError> {
        self.inner.append(event)
    }

    fn export_chain_material(
        &self,
        realm_id: &RealmId,
    ) -> Result<Option<crate::audit::AuditChainMaterial>, crate::audit::AuditError> {
        self.inner.export_chain_material(realm_id)
    }

    fn on_replicated_row(&self, realm_id: &RealmId, key: &[u8]) {
        self.inner.on_replicated_row(realm_id, key);
    }

    fn on_replicated_snapshot(&self) {
        self.inner.on_replicated_snapshot();
    }

    fn import_events(
        &self,
        realm_id: &RealmId,
        events: &[crate::audit::AuditEvent],
    ) -> Result<crate::audit::AuditImportOutcome, crate::audit::AuditError> {
        self.inner.import_events(realm_id, events)
    }

    fn query(
        &self,
        query: &crate::audit::AuditQuery,
    ) -> Result<Vec<crate::audit::AuditEvent>, crate::audit::AuditError> {
        self.inner.query(query)
    }

    fn verify_integrity(
        &self,
        realm_id: &RealmId,
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    ) -> Result<bool, crate::audit::AuditError> {
        self.inner.verify_integrity(realm_id, start, end)
    }

    fn get_retention_config(
        &self,
        realm_id: &RealmId,
    ) -> Result<crate::audit::AuditRetentionConfig, crate::audit::AuditError> {
        self.inner.get_retention_config(realm_id)
    }

    fn set_retention_config(
        &self,
        realm_id: &RealmId,
        config: &crate::audit::AuditRetentionConfig,
    ) -> Result<(), crate::audit::AuditError> {
        self.inner.set_retention_config(realm_id, config)
    }

    fn prune_before(
        &self,
        realm_id: &RealmId,
        cutoff: Timestamp,
    ) -> Result<u64, crate::audit::AuditError> {
        self.inner.prune_before(realm_id, cutoff)
    }

    fn count_events(&self, realm_id: &RealmId) -> Result<u64, crate::audit::AuditError> {
        self.inner.count_events(realm_id)
    }

    fn prune_oldest(&self, realm_id: &RealmId, n: u64) -> Result<u64, crate::audit::AuditError> {
        self.inner.prune_oldest(realm_id, n)
    }

    fn with_pending_append(
        &self,
        request: &crate::audit::CreateAuditEvent,
        enqueue_fn: crate::audit::AuditEnqueueFn<'_>,
    ) -> Result<crate::audit::AuditPendingWrite, crate::audit::AuditError> {
        let call = self
            .merged_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if call % 3 == 1 {
            return Err(crate::audit::AuditError::MergedAppendNotSupported);
        }
        self.inner.with_pending_append(request, enqueue_fn)
    }
}

/// A user whose rows and event cannot go in one write is imported one by one.
/// Its own write waits for a group commit, and the writes this thread already
/// enqueued may have made it the leader of that commit: they are settled
/// first, or the import waits for itself for ever.
#[test]
fn a_bulk_import_imports_one_by_one_the_users_without_a_merged_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut config = StorageConfig::dev(dir.path().to_path_buf());
    config.wal_config.sync_mode = crate::storage::wal::SyncMode::EveryWrite;
    let storage =
        Arc::new(EmbeddedStorageEngine::open(config).expect("open")) as Arc<dyn StorageEngine>;
    let clock = Arc::new(FakeClock::new(Timestamp::from_micros(1_000_000))) as Arc<dyn Clock>;
    let embedded = Arc::new(EmbeddedAuditEngine::new(
        Arc::clone(&storage),
        Arc::clone(&clock),
    ));
    let audit = Arc::new(SometimesUnmerged {
        inner: Arc::clone(&embedded),
        merged_calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let engine = EmbeddedIdentityEngine::new(
        storage,
        clock,
        IdentityConfig {
            credential: CredentialConfig::fast_for_testing(),
            ..IdentityConfig::default()
        },
        audit as Arc<dyn AuditEngine>,
    )
    .expect("engine creation");
    let realm = create_test_realm(&engine);
    let n = 40;
    let requests: Vec<ImportUserRequest> = (0..n)
        .map(|i| import_request(&format!("mixed{i:03}@example.com")))
        .collect();

    let results = engine.import_users(&realm, &requests);

    assert_eq!(results.len(), n);
    for (i, result) in results.iter().enumerate() {
        let user = result.as_ref().expect("import");
        assert_eq!(user.email(), format!("mixed{i:03}@example.com"));
    }
    let mut query = crate::audit::AuditQuery::for_realm(realm.clone());
    query.action = Some(AuditAction::UserCreated);
    query.limit = Some(10 * n);
    assert_eq!(
        embedded.query(&query).expect("query audit").len(),
        n,
        "one UserCreated event per imported user"
    );
}
