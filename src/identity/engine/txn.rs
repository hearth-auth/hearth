//! Phase D.3 — Transaction token engine methods.
//!
//! Issues single-use, 60-second transaction tokens binding two agents to a
//! specific operation. Replay prevention is enforced via a JTI blocklist
//! that mirrors the pattern used by device-authorization and actor-token
//! replay checks elsewhere in the engine.

use crate::audit::AuditAction;
use crate::core::RealmId;
use crate::identity::tokens::verify_jwt_typed;
use crate::identity::types::{
    CreateTransactionTokenRequest, TransactionTokenClaims, TransactionTokenResponse,
};
use crate::identity::{keys, IdentityEngine, IdentityError};

use super::EmbeddedIdentityEngine;

/// Transaction token lifetime — fixed at 60 seconds per spec §8.5.
const TXN_TOKEN_TTL_SECS: i64 = 60;
/// JWT `typ` for transaction tokens.
const TXN_TYP: &str = "txn+jwt";

impl EmbeddedIdentityEngine {
    /// Issues a single-use transaction token.
    pub(super) fn issue_transaction_token_inner(
        &self,
        realm_id: &RealmId,
        request: &CreateTransactionTokenRequest,
    ) -> Result<TransactionTokenResponse, IdentityError> {
        // Advisory lock: serialises same-node concurrent callers with the same
        // txn_id so only one reaches the Raft proposal below, avoiding a
        // redundant network round-trip from the losing thread.
        // Cross-node races are closed by the `put_if_absent` write below, which
        // is atomic at the Raft state-machine layer.
        let lock = self.txn_advisory_lock(realm_id, &request.txn_id);
        let _guard = lock.lock().expect("txn_locks per-request mutex poisoned");

        let used_key = keys::encode_txn_token_used(&request.txn_id);

        // Verify both agents exist and are Active.
        let req_agent = IdentityEngine::get_agent(self, realm_id, &request.requesting_agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;
        if req_agent.status() != crate::identity::AgentStatus::Active {
            return Err(IdentityError::AgentRevoked);
        }
        let tgt_agent = IdentityEngine::get_agent(self, realm_id, &request.target_agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;
        if tgt_agent.status() != crate::identity::AgentStatus::Active {
            return Err(IdentityError::AgentRevoked);
        }

        let now = self.clock.now();
        let now_secs = now.as_micros() / 1_000_000;
        let exp = now_secs + TXN_TOKEN_TTL_SECS;

        let jti = uuid::Uuid::new_v4().to_string();
        let issuer = IdentityEngine::realm_oidc_discovery(self, realm_id)
            .map(|d| d.issuer)
            .unwrap_or_else(|_| format!("hearth:{}", realm_id.as_uuid()));

        let sub = format!("agt_{}", request.requesting_agent_id.as_uuid());
        let aud = format!("agt_{}", request.target_agent_id.as_uuid());

        let claims = TransactionTokenClaims {
            jti: jti.clone(),
            iss: issuer,
            sub,
            aud,
            exp,
            iat: now_secs,
            txn: request.txn_id.clone(),
            act: request.delegation_context.clone(),
        };

        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let token = signing_key.sign_jwt(&claims, TXN_TYP)?;

        // Atomically mark the txn_id as used — only if no prior issuance exists.
        // In cluster mode this routes through Raft as `PutIfAbsent`, closing the
        // cross-node TOCTOU window: two nodes racing with the same txn_id will
        // both propose PutIfAbsent but only the first to commit succeeds.
        let written = self
            .storage
            .put_if_absent(realm_id, &used_key, exp.to_string().as_bytes())
            .map_err(Self::storage_err)?;
        if !written {
            return Err(IdentityError::TransactionTokenReplayed);
        }

        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::TransactionTokenIssued,
            "txn_token",
            &jti,
        );

        Ok(TransactionTokenResponse {
            token,
            txn_id: request.txn_id.clone(),
            expires_in_secs: TXN_TOKEN_TTL_SECS,
        })
    }

    /// Validates and consumes a transaction token (replay prevention).
    pub(super) fn consume_transaction_token_inner(
        &self,
        realm_id: &RealmId,
        token: &str,
    ) -> Result<TransactionTokenClaims, IdentityError> {
        let signing_key = self.get_or_load_realm_signing_key(realm_id)?;
        let pub_key = signing_key.public_key_bytes().to_vec();

        let claims: TransactionTokenClaims = verify_jwt_typed(token, &pub_key, Some(TXN_TYP))?;

        // Check expiry.
        let now_secs = self.clock.now().as_micros() / 1_000_000;
        if now_secs >= claims.exp {
            return Err(IdentityError::TokenExpired);
        }

        // Serialize concurrent consumption for this (realm_id, txn_id) pair to
        // eliminate the TOCTOU race between the consumed-key read and write below.
        // Without this lock, two concurrent callers presenting the same token can
        // both pass the `get(consumed_key)` check before either writes the
        // consumed marker, allowing double-consumption of a single-use token.
        let lock = self.txn_advisory_lock(realm_id, &claims.txn);
        let _guard = lock.lock().expect("txn_locks per-request mutex poisoned");

        // Check that txn_id has not been consumed by a *different* token.
        // (It was written at issuance — so if it's present now, the token was already consumed.)
        let used_key = keys::encode_txn_token_used(&claims.txn);
        // The value we stored at issuance was the expiry. A second call to consume
        // would need to detect that the token was issued but already validated.
        // We use a separate "consumed" marker to distinguish "issued" vs "consumed".
        let consumed_key = keys::encode_txn_token_used(&format!("consumed:{}", claims.jti));
        if let Ok(Some(_)) = self.storage.get(realm_id, &consumed_key) {
            return Err(IdentityError::TransactionTokenReplayed);
        }

        // Mark as consumed.
        self.storage
            .put(realm_id, &consumed_key, b"1")
            .map_err(Self::storage_err)?;

        // Also ensure the issuance entry exists (defensive check).
        if self
            .storage
            .get(realm_id, &used_key)
            .map_err(Self::storage_err)?
            .is_none()
        {
            // Token was never issued by this server — treat as invalid.
            return Err(IdentityError::InvalidToken);
        }

        Ok(claims)
    }
}
