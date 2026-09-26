//! Per-realm RSA keys that sign RS256 ID tokens (task 26.55).
//!
//! OpenID Connect makes RS256 mandatory for ID tokens (Core §15.1, Discovery
//! §3), so a client may register `id_token_signed_response_alg: RS256`. This
//! module owns the realm's RSA key for exactly that, mirroring the Ed25519
//! signing-key lifecycle in `mod.rs`:
//!
//! - **Storage** — `realm:idtoken_rsa:{uuid}` under the system realm,
//!   HKEY-enveloped under the KEK like every other signing key, and swept by
//!   the KEK enrolment pass.
//! - **Provisioning** — lazily, on the write path: the first time a client in
//!   the realm selects RS256 (registration, update, import), with a fallback
//!   at ID-token issuance. `put_if_absent` makes concurrent provisioning
//!   converge on one key, cluster-wide. Read paths (the JWKS) never write.
//! - **Caching** — a sharded, wait-free cache guarded by the same per-realm
//!   rotation epoch (`realm_key_epoch`) as the Ed25519 cache, so a rotation on
//!   one node evicts the RSA key on every node, and a miss-fill racing a
//!   rotation discards its stale insert (HEA-2096).
//! - **Rotation** — `rotate_realm_signing_key` rotates the RSA key alongside
//!   the Ed25519 key, with the same grace semantics; see
//!   [`EmbeddedIdentityEngine::rotate_realm_id_token_rsa_key_locked`].
//!
//! Scope, restated because it is the point: this key signs ID tokens and
//! nothing else, and no validation path for access, refresh, logout or
//! required-action tokens ever consults it.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::core::{ImportOutcome, RealmId};
use crate::identity::error::IdentityError;
use crate::identity::keys;
use crate::identity::oidc::{IdTokenSigningAlg, OAuthClient};
use crate::identity::tokens::{self, Jwk, RsaIdTokenSigningKey, SigningKey, TokenClaims};
use crate::identity::types::RetiringSigningKeyExport;
use crate::identity::IdentityEngine as _;
use crate::storage::StorageEngine;

use super::EmbeddedIdentityEngine;

/// A retiring RSA ID-token key still inside its rotation grace period.
///
/// `deadline_secs` is the Unix-seconds instant (from the storage key) after
/// which the key MUST NOT verify anything. Cached with the key so the
/// deadline is re-checked against the live clock on every use.
#[derive(Clone)]
pub(super) struct RetiringRsaIdTokenKey {
    /// Unix-seconds instant after which this key is no longer accepted.
    pub(super) deadline_secs: u64,
    /// The retiring key material.
    pub(super) key: Arc<RsaIdTokenSigningKey>,
}

/// The key a particular client's ID tokens are signed with, resolved before
/// any side effect of the grant so a key failure refuses the grant cleanly.
pub(super) enum IdTokenSigner {
    /// The realm's Ed25519 key — the key that signs the grant's access token.
    EdDsa(Arc<SigningKey>),
    /// The realm's RSA ID-token key.
    Rs256(Arc<RsaIdTokenSigningKey>),
}

impl IdTokenSigner {
    /// Signs `claims` as an ID token.
    pub(super) fn sign(&self, claims: &TokenClaims) -> Result<String, IdentityError> {
        match self {
            Self::EdDsa(key) => key.issue_token(claims),
            Self::Rs256(key) => key.issue_id_token(claims),
        }
    }
}

impl EmbeddedIdentityEngine {
    /// The configured key-encryption key, if any.
    fn id_token_kek(&self) -> Option<&[u8; 32]> {
        self.config
            .key_encryption_key
            .as_ref()
            .map(|k| k.as_bytes())
    }

    /// Whether the realm has a FAPI 2.0 profile, which applies FAPI 2.0 to
    /// every client in it. A realm that cannot be found enforces nothing here;
    /// the caller's own realm lookup reports it.
    pub(super) fn realm_enforces_fapi(&self, realm_id: &RealmId) -> Result<bool, IdentityError> {
        Ok(self
            .get_realm(realm_id)?
            .is_some_and(|realm| realm.config().fapi_profile.is_some()))
    }

    /// Refuses RS256 wherever FAPI 2.0 applies.
    ///
    /// FAPI 2.0 Security Profile §5.4.1 lets authorization servers and clients
    /// use only PS256, ES256 and EdDSA (Ed25519). RS256 — RSASSA-PKCS1-v1_5 —
    /// is not among them, so a FAPI 2.0 client, or any client of a realm with a
    /// `fapi_profile`, gets EdDSA ID tokens or none.
    ///
    /// # Errors
    /// [`IdentityError::FapiViolation`] when `alg` is RS256 and `fapi` is set.
    pub(super) fn refuse_rs256_under_fapi(
        alg: IdTokenSigningAlg,
        fapi: bool,
    ) -> Result<(), IdentityError> {
        if fapi && alg == IdTokenSigningAlg::Rs256 {
            return Err(IdentityError::FapiViolation {
                reason: "FAPI 2.0 permits only PS256, ES256 and EdDSA; RS256 ID tokens are not \
                         available to a FAPI 2.0 client or in a FAPI realm \
                         (use id_token_signed_response_alg EdDSA)"
                    .to_string(),
            });
        }
        Ok(())
    }

    /// Validates a client's requested `id_token_signed_response_alg` and, for
    /// RS256, provisions the realm's RSA key.
    ///
    /// Every surface that creates or changes a client (register, update,
    /// import) calls this before it persists the client, so an RS256 client
    /// never exists without the key that signs its ID tokens, and a key
    /// failure refuses the write instead of the client's first login. `None`
    /// is the administrative default, EdDSA. `fapi` is whether FAPI 2.0
    /// applies to the client once written (its profile, or its realm's); RS256
    /// is then refused before any key is provisioned. An import passes
    /// `false`: it records the algorithm the source held rather than choosing
    /// one, and issuance refuses what FAPI forbids ([`Self::id_token_signer`]).
    ///
    /// # Errors
    /// [`IdentityError::InvalidInput`] for anything but `RS256`/`EdDSA`,
    /// [`IdentityError::FapiViolation`] for RS256 under FAPI, and any
    /// provisioning error.
    pub(super) fn resolve_client_id_token_alg(
        &self,
        realm_id: &RealmId,
        requested: Option<&str>,
        fapi: bool,
    ) -> Result<IdTokenSigningAlg, IdentityError> {
        let alg = requested.map_or(Ok(IdTokenSigningAlg::EdDsa), IdTokenSigningAlg::parse)?;
        Self::refuse_rs256_under_fapi(alg, fapi)?;
        if alg == IdTokenSigningAlg::Rs256 {
            self.ensure_realm_id_token_rsa_key(realm_id)?;
        }
        Ok(alg)
    }

    /// Resolves how `client`'s ID tokens are signed.
    ///
    /// `ed_key` is the Ed25519 key the caller signs the grant's access token
    /// with; an EdDSA client's ID token is signed with that same key, exactly
    /// as before RS256 existed. An RS256 client provisions the realm's RSA key
    /// on first use — unless FAPI 2.0 now applies to it (its realm turned a
    /// `fapi_profile` on after it registered): then the grant is refused rather
    /// than answered with an ID token FAPI 2.0 forbids.
    ///
    /// # Errors
    /// [`IdentityError::FapiViolation`] for an RS256 client under FAPI, and any
    /// realm-lookup or key-provisioning error.
    pub(super) fn id_token_signer(
        &self,
        realm_id: &RealmId,
        client: Option<&OAuthClient>,
        ed_key: Arc<SigningKey>,
    ) -> Result<IdTokenSigner, IdentityError> {
        match client {
            Some(client) if client.id_token_signed_response_alg() == IdTokenSigningAlg::Rs256 => {
                let fapi = client.profile().is_fapi2() || self.realm_enforces_fapi(realm_id)?;
                Self::refuse_rs256_under_fapi(IdTokenSigningAlg::Rs256, fapi)?;
                Ok(IdTokenSigner::Rs256(
                    self.ensure_realm_id_token_rsa_key(realm_id)?,
                ))
            }
            Some(_) | None => Ok(IdTokenSigner::EdDsa(ed_key)),
        }
    }

    /// Returns the realm's active RSA ID-token key, or `None` when the realm
    /// has never needed one.
    ///
    /// Wait-free on a cache hit. The miss path is the Ed25519 one: snapshot the
    /// rotation epoch before the storage read and discard the insert if a
    /// rotation landed in between (HEA-2096).
    pub(super) fn load_realm_id_token_rsa_key(
        &self,
        realm_id: &RealmId,
    ) -> Result<Option<Arc<RsaIdTokenSigningKey>>, IdentityError> {
        if let Some(key) = self.realm_id_token_rsa_keys.get(realm_id) {
            return Ok(Some(key));
        }
        let epoch_before = self.realm_key_epoch.get(realm_id).unwrap_or(0);
        let sys_realm = keys::system_realm_id();
        let Some(raw) = self
            .storage
            .get(&sys_realm, &keys::encode_realm_id_token_rsa_key(realm_id))
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        let pkcs8 = crate::identity::key_encryption::unwrap_key_strict(&raw, self.id_token_kek())?;
        let key = Arc::new(RsaIdTokenSigningKey::from_pkcs8(&pkcs8)?);
        self.realm_id_token_rsa_keys
            .insert(realm_id.clone(), Arc::clone(&key));
        if self.realm_key_epoch.get(realm_id).unwrap_or(0) != epoch_before {
            self.realm_id_token_rsa_keys.remove(realm_id);
        }
        Ok(Some(key))
    }

    /// Returns the realm's RSA ID-token key, generating and persisting one
    /// first if the realm has none.
    ///
    /// Generation (RSA-3072, off every hot path) happens outside any lock. The
    /// write is `put_if_absent` under `realm_ops_lock`: the lock serialises it
    /// against a rotation on this node, and `put_if_absent` is a single Raft
    /// command in cluster mode, so two nodes provisioning at once converge on
    /// whichever key committed first. The key is then re-read, so every caller
    /// signs with the stored key and never with a losing candidate.
    ///
    /// # Errors
    /// [`IdentityError::SystemRealmProtected`] for the system realm, which has
    /// no OAuth clients and therefore no ID tokens; storage, KEK and key-load
    /// errors otherwise.
    pub(super) fn ensure_realm_id_token_rsa_key(
        &self,
        realm_id: &RealmId,
    ) -> Result<Arc<RsaIdTokenSigningKey>, IdentityError> {
        if let Some(key) = self.load_realm_id_token_rsa_key(realm_id)? {
            return Ok(key);
        }
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "provision_id_token_rsa_key",
            });
        }
        let candidate = RsaIdTokenSigningKey::generate()?;
        let wrapped = crate::identity::key_encryption::wrap_key(
            candidate.pkcs8_bytes(),
            self.id_token_kek(),
        )?;
        let created = {
            // INVARIANT: guard held only across the sync put_if_absent; no I/O
            // beyond the storage call it serialises, no .await in scope.
            let _ops_guard = self.realm_ops_lock.lock().expect("realm ops lock");
            self.storage
                .put_if_absent(
                    &keys::system_realm_id(),
                    &keys::encode_realm_id_token_rsa_key(realm_id),
                    &wrapped,
                )
                .map_err(Self::storage_err)?
        };
        if created {
            tracing::info!(
                realm = %realm_id.as_uuid(),
                kid = %candidate.key_id(),
                modulus_bits = candidate.modulus_bits(),
                "RS256 ID-token signing key provisioned"
            );
        }
        // Whoever won, the stored key is the realm's key.
        self.realm_id_token_rsa_keys.remove(realm_id);
        self.load_realm_id_token_rsa_key(realm_id)?
            .ok_or_else(|| IdentityError::Internal {
                reason: "RS256 ID-token key vanished immediately after provisioning".to_string(),
            })
    }

    /// Returns the realm's retiring RSA ID-token keys, cached like the
    /// Ed25519 set. Callers MUST filter on `deadline_secs`.
    pub(super) fn get_or_load_realm_id_token_rsa_retiring_keys(
        &self,
        realm_id: &RealmId,
    ) -> Arc<Vec<RetiringRsaIdTokenKey>> {
        if let Some(entries) = self.realm_id_token_rsa_retiring_keys.get(realm_id) {
            return entries;
        }
        let epoch_before = self.realm_key_epoch.get(realm_id).unwrap_or(0);
        let loaded = Arc::new(self.load_realm_id_token_rsa_retiring_keys(realm_id));
        self.realm_id_token_rsa_retiring_keys
            .insert(realm_id.clone(), Arc::clone(&loaded));
        if self.realm_key_epoch.get(realm_id).unwrap_or(0) != epoch_before {
            self.realm_id_token_rsa_retiring_keys.remove(realm_id);
        }
        loaded
    }

    /// Scans and decrypts a realm's retiring RSA ID-token keys. Undecodable
    /// entries are skipped: a corrupt retiring key must not take down the
    /// JWKS or logout.
    fn load_realm_id_token_rsa_retiring_keys(
        &self,
        realm_id: &RealmId,
    ) -> Vec<RetiringRsaIdTokenKey> {
        let sys_realm = keys::system_realm_id();
        let prefix = keys::realm_id_token_rsa_retiring_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let mut out = Vec::new();
        let Ok(entries) = self.storage.scan(&sys_realm, &prefix, &end) else {
            return out;
        };
        for entry in entries {
            let Some(deadline_secs) = keys::parse_id_token_rsa_retiring_deadline(&entry.key) else {
                continue;
            };
            let Ok(pkcs8) = crate::identity::key_encryption::unwrap_key_strict(
                &entry.value,
                self.id_token_kek(),
            ) else {
                continue;
            };
            if let Ok(key) = RsaIdTokenSigningKey::from_pkcs8(&pkcs8) {
                out.push(RetiringRsaIdTokenKey {
                    deadline_secs,
                    key: Arc::new(key),
                });
            }
        }
        out
    }

    /// Deletes retiring RSA ID-token keys: `Some(now)` reaps those whose grace
    /// window has closed, `None` reaps them all (realm delete, revoking
    /// rotation). Takes `storage` by argument so the background realm-delete
    /// cascade can call it. Best-effort; returns the number removed.
    pub(super) fn purge_realm_id_token_rsa_retiring_keys(
        storage: &Arc<dyn StorageEngine>,
        realm_id: &RealmId,
        cutoff_secs: Option<u64>,
    ) -> usize {
        let sys_realm = keys::system_realm_id();
        let prefix = keys::realm_id_token_rsa_retiring_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let entries = match storage.scan(&sys_realm, &prefix, &end) {
            Ok(entries) => entries,
            Err(e) => {
                tracing::warn!(
                    realm = %realm_id.as_uuid(),
                    error = %e,
                    "RS256 retiring-key purge: scan failed"
                );
                return 0;
            }
        };
        let mut purged = 0usize;
        for entry in entries {
            if let Some(now_secs) = cutoff_secs {
                let live = keys::parse_id_token_rsa_retiring_deadline(&entry.key)
                    .is_some_and(|deadline| deadline > now_secs);
                if live {
                    continue;
                }
            }
            match storage.delete(&sys_realm, &entry.key) {
                Ok(()) => purged += 1,
                Err(e) => tracing::warn!(
                    realm = %realm_id.as_uuid(),
                    error = %e,
                    "RS256 retiring-key purge: delete failed"
                ),
            }
        }
        purged
    }

    /// Rotates the realm's RSA ID-token key, if it has one, with the same grace
    /// semantics as the Ed25519 rotation it runs inside.
    ///
    /// MUST be called with `realm_ops_lock` held, after the Ed25519 writes and
    /// before the rotation epoch is bumped, so the single epoch bump evicts
    /// both key families on every node. The caller generates `new_key` before
    /// any write, so a key-generation failure leaves nothing rotated.
    ///
    /// - `new_key: None` — the realm has no RSA key and is left without one:
    ///   rotation never provisions RS256 for a realm no client asked it of. A
    ///   revoking rotation still purges any RSA retiring keys.
    /// - `old_key: None` with `new_key: Some` — the stored key could not be
    ///   loaded; it is replaced with no grace window, since nothing could
    ///   verify with it anyway.
    ///
    /// A revoking rotation (`revoking`, i.e. grace 0) retires nothing and
    /// purges every RSA retiring key, exactly as the Ed25519 half does.
    ///
    /// Returns `(old_kid, new_kid)` when a key was rotated.
    pub(super) fn rotate_realm_id_token_rsa_key_locked(
        &self,
        realm_id: &RealmId,
        old_key: Option<&RsaIdTokenSigningKey>,
        new_key: Option<&RsaIdTokenSigningKey>,
        now_secs: u64,
        deadline_secs: u64,
        revoking: bool,
    ) -> Result<Option<(Option<String>, String)>, IdentityError> {
        let cutoff = if revoking { None } else { Some(now_secs) };
        let Some(new_key) = new_key else {
            if revoking {
                Self::purge_realm_id_token_rsa_retiring_keys(&self.storage, realm_id, None);
            }
            return Ok(None);
        };
        let sys_realm = keys::system_realm_id();
        let new_stored =
            crate::identity::key_encryption::wrap_key(new_key.pkcs8_bytes(), self.id_token_kek())?;
        self.storage
            .put(
                &sys_realm,
                &keys::encode_realm_id_token_rsa_key(realm_id),
                &new_stored,
            )
            .map_err(Self::storage_err)?;
        Self::purge_realm_id_token_rsa_retiring_keys(&self.storage, realm_id, cutoff);
        if let (Some(old_key), false) = (old_key, revoking) {
            let old_stored = crate::identity::key_encryption::wrap_key(
                old_key.pkcs8_bytes(),
                self.id_token_kek(),
            )?;
            self.storage
                .put(
                    &sys_realm,
                    &keys::encode_realm_id_token_rsa_retiring_key(
                        realm_id,
                        deadline_secs,
                        old_key.key_id(),
                    ),
                    &old_stored,
                )
                .map_err(Self::storage_err)?;
        }
        Ok(Some((
            old_key.map(|k| k.key_id().to_string()),
            new_key.key_id().to_string(),
        )))
    }

    /// The RSA JWKs a realm publishes: its active ID-token key plus every
    /// retiring one still inside its grace window.
    ///
    /// A realm with no RSA key publishes none. A key that exists but cannot be
    /// loaded is logged and omitted rather than failing the whole JWKS — the
    /// Ed25519 key in the same document verifies every access token the realm
    /// has issued, and must stay reachable.
    pub(super) fn realm_id_token_rsa_jwks(&self, realm_id: &RealmId) -> Vec<Jwk> {
        let mut out = Vec::new();
        match self.load_realm_id_token_rsa_key(realm_id) {
            Ok(Some(key)) => match key.to_jwk() {
                Ok(jwk) => out.push(jwk),
                Err(e) => tracing::error!(
                    realm = %realm_id.as_uuid(),
                    error = %e,
                    "RS256 ID-token key could not be rendered as a JWK"
                ),
            },
            Ok(None) => {}
            Err(e) => tracing::error!(
                realm = %realm_id.as_uuid(),
                error = %e,
                "RS256 ID-token key could not be loaded; omitted from the JWKS"
            ),
        }
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        for entry in self
            .get_or_load_realm_id_token_rsa_retiring_keys(realm_id)
            .iter()
        {
            if entry.deadline_secs <= now_secs {
                continue;
            }
            if let Ok(jwk) = entry.key.to_jwk() {
                out.push(jwk);
            }
        }
        out
    }

    /// Verifies an RS256 ID token this realm issued, against the active RSA
    /// key and then every in-grace retiring one.
    ///
    /// Only for the paths that receive back an ID token Hearth itself issued
    /// (`id_token_hint`, revocation) — never for an access token. The
    /// underlying verifier refuses anything but an RS256-signed `id_token`.
    pub(super) fn verify_realm_rs256_id_token(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError> {
        if let Some(active) = self.load_realm_id_token_rsa_key(realm_id)? {
            if let Ok(claims) =
                tokens::verify_rs256_id_token_signature(token, active.public_key_der())
            {
                return Ok(claims);
            }
        }
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        for entry in self
            .get_or_load_realm_id_token_rsa_retiring_keys(realm_id)
            .iter()
        {
            if entry.deadline_secs <= now_secs {
                continue;
            }
            if let Ok(claims) =
                tokens::verify_rs256_id_token_signature(token, entry.key.public_key_der())
            {
                return Ok(claims);
            }
        }
        Err(IdentityError::InvalidToken)
    }

    /// Verifies an ID token Hearth issued in this realm, whichever algorithm
    /// the client registered: the Ed25519 path first (unchanged, and still the
    /// only one any other token type can pass), then the RS256 ID-token path.
    ///
    /// On failure the Ed25519 error is returned, so a caller cannot tell which
    /// family refused the token.
    pub(super) fn verify_realm_issued_id_token(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<TokenClaims, IdentityError> {
        match self.verify_token_signature_for_realm(realm_id, token) {
            Ok(claims) => Ok(claims),
            Err(ed_err) => self
                .verify_realm_rs256_id_token(realm_id, token)
                .map_err(|_| ed_err),
        }
    }

    /// Plaintext PKCS#8 of the realm's active RSA ID-token key, for backup
    /// export. Unsealed because the destination's KEK is a different key.
    pub(super) fn export_realm_id_token_rsa_key_inner(
        &self,
        realm_id: &RealmId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let Some(raw) = self
            .storage
            .get(
                &keys::system_realm_id(),
                &keys::encode_realm_id_token_rsa_key(realm_id),
            )
            .map_err(Self::storage_err)?
        else {
            return Ok(None);
        };
        Ok(Some(crate::identity::key_encryption::unwrap_key_strict(
            &raw,
            self.id_token_kek(),
        )?))
    }

    /// Installs a restored RSA ID-token key, re-sealed under this node's KEK.
    ///
    /// Refuses material that does not load as an RSA key of at least
    /// [`tokens::RSA_ID_TOKEN_MIN_MODULUS_BITS`], so an unusable key fails the
    /// restore instead of the first RS256 login after it. An existing key is
    /// kept unless `overwrite`.
    pub(super) fn import_realm_id_token_rsa_key_inner(
        &self,
        realm_id: &RealmId,
        pkcs8: &[u8],
        overwrite: bool,
    ) -> Result<ImportOutcome, IdentityError> {
        if keys::is_system_realm(realm_id) {
            return Err(IdentityError::SystemRealmProtected {
                operation: "import_id_token_rsa_key",
            });
        }
        let _usable = RsaIdTokenSigningKey::from_pkcs8(pkcs8)?;
        let sys_realm = keys::system_realm_id();
        let storage_key = keys::encode_realm_id_token_rsa_key(realm_id);
        let exists = self
            .storage
            .get(&sys_realm, &storage_key)
            .map_err(Self::storage_err)?
            .is_some();
        if exists && !overwrite {
            return Ok(ImportOutcome::Skipped);
        }
        let body = crate::identity::key_encryption::wrap_key(pkcs8, self.id_token_kek())?;
        self.storage
            .put(&sys_realm, &storage_key, &body)
            .map_err(Self::storage_err)?;
        self.realm_id_token_rsa_keys.remove(realm_id);
        Ok(if exists {
            ImportOutcome::Overwritten
        } else {
            ImportOutcome::Created
        })
    }

    /// Retiring RSA ID-token keys still inside their grace window, as
    /// plaintext PKCS#8, for backup export.
    pub(super) fn export_retiring_id_token_rsa_keys_inner(
        &self,
        realm_id: &RealmId,
    ) -> Result<Vec<RetiringSigningKeyExport>, IdentityError> {
        let sys_realm = keys::system_realm_id();
        let prefix = keys::realm_id_token_rsa_retiring_scan_prefix(realm_id);
        let end = keys::prefix_end(&prefix);
        let entries = self
            .storage
            .scan(&sys_realm, &prefix, &end)
            .map_err(Self::storage_err)?;
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        let mut out = Vec::new();
        for entry in entries {
            let Some(deadline_secs) = keys::parse_id_token_rsa_retiring_deadline(&entry.key) else {
                continue;
            };
            if deadline_secs <= now_secs {
                continue;
            }
            let Some(key_id) = keys::parse_id_token_rsa_retiring_key_id(&entry.key) else {
                continue;
            };
            let plaintext = crate::identity::key_encryption::unwrap_key_strict(
                &entry.value,
                self.id_token_kek(),
            )?;
            out.push(RetiringSigningKeyExport {
                key_id,
                deadline_secs,
                pkcs8: plaintext.to_vec(),
            });
        }
        Ok(out)
    }

    /// Re-installs one retiring RSA ID-token key under its original `kid` and
    /// absolute deadline. A restore resumes a grace window, never restarts it.
    pub(super) fn import_retiring_id_token_rsa_key_inner(
        &self,
        realm_id: &RealmId,
        key: &RetiringSigningKeyExport,
        overwrite: bool,
    ) -> Result<ImportOutcome, IdentityError> {
        let now_secs = (self.clock.now().as_micros() / 1_000_000) as u64;
        if key.deadline_secs <= now_secs {
            return Ok(ImportOutcome::Skipped);
        }
        let _usable = RsaIdTokenSigningKey::from_pkcs8(&key.pkcs8)?;
        let sys_realm = keys::system_realm_id();
        let storage_key =
            keys::encode_realm_id_token_rsa_retiring_key(realm_id, key.deadline_secs, &key.key_id);
        let exists = self
            .storage
            .get(&sys_realm, &storage_key)
            .map_err(Self::storage_err)?
            .is_some();
        if exists && !overwrite {
            return Ok(ImportOutcome::Skipped);
        }
        let body = crate::identity::key_encryption::wrap_key(&key.pkcs8, self.id_token_kek())?;
        self.storage
            .put(&sys_realm, &storage_key, &body)
            .map_err(Self::storage_err)?;
        self.realm_id_token_rsa_retiring_keys.remove(realm_id);
        Ok(if exists {
            ImportOutcome::Overwritten
        } else {
            ImportOutcome::Created
        })
    }
}
