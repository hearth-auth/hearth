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

        // Queue this node's concurrent consumers of one (realm_id, txn_id) so
        // they do not each propose a Raft write; the claim below decides.
        let lock = self.txn_advisory_lock(realm_id, &claims.txn);
        let _guard = lock.lock().expect("txn_locks per-request mutex poisoned");

        // The issuance entry must exist (defensive: a token this server never
        // issued is invalid). Checked before the claim so such a token burns
        // nothing.
        let used_key = keys::encode_txn_token_used(&claims.txn);
        if self
            .storage
            .get(realm_id, &used_key)
            .map_err(Self::storage_err)?
            .is_none()
        {
            return Err(IdentityError::InvalidToken);
        }

        // Consume: one replicated put-if-absent on the token's `jti` (G4).
        // The read-then-write this replaced was only serialised per node, a
        // storage error on its read failed OPEN, and its `b"1"` marker had no
        // expiry for the sweep to reclaim.
        if !self.claim_single_use(
            realm_id,
            &keys::encode_consumed_txn(&claims.jti),
            crate::core::Timestamp::from_micros(claims.exp.saturating_mul(1_000_000)),
        )? {
            return Err(IdentityError::TransactionTokenReplayed);
        }

        Ok(claims)
    }
}
