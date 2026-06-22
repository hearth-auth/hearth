//! Phase D.7 — SPIFFE / workload identity engine methods.
//!
//! Implements SPIFFE ID mapping CRUD and X.509 SVID validation.
//!
//! SPIFFE ID format: `spiffe://{trust_domain}/agent/{agent_uuid}`
//!
//! Storage layout (all realm-prefixed):
//!   `spiffe:map:{sha256(spiffe_id)}` — JSON-serialized `SpiffeIdentityMapping`
//!   `spiffe:agt:{agent_uuid}` — SPIFFE ID string (reverse index)

use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::parse_x509_certificate;

use crate::audit::AuditAction;
use crate::core::{AgentId, RealmId};
use crate::identity::types::{RegisterSpiffeIdRequest, SpiffeIdentityMapping};
use crate::identity::{keys, IdentityEngine, IdentityError};

use super::EmbeddedIdentityEngine;

/// Expected SPIFFE URI scheme.
const SPIFFE_SCHEME: &str = "spiffe://";
/// Path segment that must follow the trust domain in agent SVIDs.
const SPIFFE_AGENT_PATH_SEGMENT: &str = "/agent/";

impl EmbeddedIdentityEngine {
    /// Registers a SPIFFE ID → `AgentId` mapping.
    pub(super) fn register_spiffe_mapping_inner(
        &self,
        realm_id: &RealmId,
        request: &RegisterSpiffeIdRequest,
    ) -> Result<SpiffeIdentityMapping, IdentityError> {
        // Validate SPIFFE ID format.
        let (trust_domain, _agent_uuid) = parse_spiffe_id(&request.spiffe_id)?;

        // Check agent exists and is Active.
        let agent = IdentityEngine::get_agent(self, realm_id, &request.agent_id)?
            .ok_or(IdentityError::AgentNotFound)?;
        if agent.status() != crate::identity::AgentStatus::Active {
            return Err(IdentityError::AgentRevoked);
        }

        // Guard 1 — primary-key conflict: SPIFFE ID already mapped to a different agent.
        // Without this check a second agent could overwrite the primary mapping (BOLA/squatting).
        let primary_key = keys::encode_spiffe_mapping(&request.spiffe_id);
        if let Ok(Some(_)) = self.storage.get(realm_id, &primary_key) {
            return Err(IdentityError::SpiffeMappingConflict);
        }

        // Guard 2 — reverse-index conflict: this agent already owns a SPIFFE mapping.
        let agent_index_key = keys::encode_spiffe_agent_index(&request.agent_id);
        if let Ok(Some(_)) = self.storage.get(realm_id, &agent_index_key) {
            return Err(IdentityError::SpiffeMappingConflict);
        }

        let now = self.clock.now();
        let mapping = SpiffeIdentityMapping {
            spiffe_id: request.spiffe_id.clone(),
            agent_id: request.agent_id.clone(),
            trust_domain: trust_domain.to_string(),
            created_at: now,
        };
        let mapping_bytes =
            serde_json::to_vec(&mapping).map_err(|e| IdentityError::Serialization {
                reason: e.to_string(),
            })?;

        self.storage
            .put_batch(
                realm_id,
                &[
                    (primary_key, mapping_bytes),
                    (agent_index_key, request.spiffe_id.as_bytes().to_vec()),
                ],
            )
            .map_err(Self::storage_err)?;

        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::SpiffeIdMapped,
            "spiffe_mapping",
            &request.spiffe_id,
        );

        Ok(mapping)
    }

    /// Looks up an `AgentId` by SPIFFE ID string.
    pub(super) fn lookup_agent_by_spiffe_id_inner(
        &self,
        realm_id: &RealmId,
        spiffe_id: &str,
    ) -> Result<Option<AgentId>, IdentityError> {
        let key = keys::encode_spiffe_mapping(spiffe_id);
        match self
            .storage
            .get(realm_id, &key)
            .map_err(Self::storage_err)?
        {
            None => Ok(None),
            Some(bytes) => {
                let mapping: SpiffeIdentityMapping =
                    serde_json::from_slice(&bytes).map_err(|e| IdentityError::Serialization {
                        reason: e.to_string(),
                    })?;
                Ok(Some(mapping.agent_id))
            }
        }
    }

    /// Removes the SPIFFE mapping for an agent (both primary and reverse index).
    pub(super) fn delete_spiffe_mapping_inner(
        &self,
        realm_id: &RealmId,
        agent_id: &AgentId,
    ) -> Result<(), IdentityError> {
        let agent_index_key = keys::encode_spiffe_agent_index(agent_id);
        let spiffe_id_bytes = self
            .storage
            .get(realm_id, &agent_index_key)
            .map_err(Self::storage_err)?
            .ok_or(IdentityError::SpiffeMappingNotFound)?;

        let spiffe_id =
            String::from_utf8(spiffe_id_bytes).map_err(|_| IdentityError::Serialization {
                reason: "invalid UTF-8 in stored SPIFFE ID".to_string(),
            })?;

        let primary_key = keys::encode_spiffe_mapping(&spiffe_id);

        self.storage
            .delete(realm_id, &primary_key)
            .map_err(Self::storage_err)?;
        let _ = self.storage.delete(realm_id, &agent_index_key);

        Ok(())
    }

    /// Validates a DER-encoded X.509 client certificate as a SPIFFE SVID and
    /// returns the mapped `AgentId`.
    ///
    /// Validation steps:
    /// 1. Parse the DER certificate using `rcgen`/`rustls-pki-types`.
    /// 2. Extract the Subject Alternative Name (SAN) with `spiffe://` URI.
    /// 3. Verify the certificate is not expired.
    /// 4. Look up the SPIFFE ID → `AgentId` mapping.
    pub(super) fn validate_spiffe_svid_inner(
        &self,
        realm_id: &RealmId,
        der_cert: &[u8],
    ) -> Result<AgentId, IdentityError> {
        // Parse the DER certificate to extract SPIFFE ID from SAN.
        let spiffe_id = extract_spiffe_id_from_der(der_cert)?;

        // Check the SPIFFE ID format.
        parse_spiffe_id(&spiffe_id)?;

        // Check expiry using basic ASN.1 field extraction.
        check_cert_not_expired(der_cert, self.clock.now())?;

        // Look up the mapping.
        let agent_id = self
            .lookup_agent_by_spiffe_id_inner(realm_id, &spiffe_id)?
            .ok_or(IdentityError::SpiffeMappingNotFound)?;

        let _ = self.record_audit(
            realm_id,
            None,
            AuditAction::SpiffeAuthSuccess,
            "spiffe_auth",
            &spiffe_id,
        );

        Ok(agent_id)
    }
}

/// Parses a SPIFFE ID string and returns `(trust_domain, agent_uuid_str)`.
///
/// Expected format: `spiffe://{trust_domain}/agent/{uuid}`
pub(super) fn parse_spiffe_id(spiffe_id: &str) -> Result<(&str, &str), IdentityError> {
    let rest =
        spiffe_id
            .strip_prefix(SPIFFE_SCHEME)
            .ok_or_else(|| IdentityError::SpiffeIdInvalid {
                reason: format!("must start with '{SPIFFE_SCHEME}'"),
            })?;

    let agent_path_pos =
        rest.find(SPIFFE_AGENT_PATH_SEGMENT)
            .ok_or_else(|| IdentityError::SpiffeIdInvalid {
                reason: format!("must contain '{SPIFFE_AGENT_PATH_SEGMENT}'"),
            })?;

    let trust_domain = &rest[..agent_path_pos];
    if trust_domain.is_empty() {
        return Err(IdentityError::SpiffeIdInvalid {
            reason: "trust domain must not be empty".to_string(),
        });
    }

    let agent_uuid = &rest[agent_path_pos + SPIFFE_AGENT_PATH_SEGMENT.len()..];
    if agent_uuid.is_empty() {
        return Err(IdentityError::SpiffeIdInvalid {
            reason: "agent UUID segment must not be empty".to_string(),
        });
    }

    Ok((trust_domain, agent_uuid))
}

/// Extracts the SPIFFE URI SAN from a DER-encoded X.509 certificate.
///
/// Uses `x509-parser` for proper ASN.1-aware SAN extraction so that
/// `spiffe://` appearing in Subject CN, Issuer, or any non-SAN extension
/// cannot be mistaken for a legitimate SPIFFE identity.
///
/// Rejects:
/// - Certificates with no URI SAN that starts with `spiffe://`
/// - Certificates where `spiffe://` appears outside a URI-type SAN
/// - Certificates with multiple SPIFFE URI SANs (ambiguous identity)
fn extract_spiffe_id_from_der(der: &[u8]) -> Result<String, IdentityError> {
    let (_, cert) = parse_x509_certificate(der).map_err(|_| IdentityError::SpiffeCertInvalid {
        reason: "failed to parse DER certificate".to_string(),
    })?;

    // Collect all URI-type SANs that start with `spiffe://`.
    // Only GeneralName::URI entries are considered — CN, Issuer, and other
    // extension types are explicitly excluded, preventing parser-differential
    // identity spoofing.
    let mut spiffe_uris: Vec<String> = Vec::new();

    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    if uri.starts_with(SPIFFE_SCHEME) {
                        spiffe_uris.push((*uri).to_string());
                    }
                }
            }
        }
    }

    match spiffe_uris.len() {
        0 => Err(IdentityError::SpiffeCertInvalid {
            reason: "no SPIFFE URI SAN found in certificate".to_string(),
        }),
        // Ambiguous: RFC 8693 / SPIFFE spec requires exactly one SPIFFE ID per SVID.
        n if n > 1 => Err(IdentityError::SpiffeCertInvalid {
            reason: format!("certificate contains {n} SPIFFE URI SANs; exactly one is required"),
        }),
        _ => {
            #[allow(clippy::unwrap_used)]
            // INVARIANT: len == 1 checked in the arm above.
            Ok(spiffe_uris.into_iter().next().unwrap())
        }
    }
}

/// Checks that a DER-encoded certificate has not expired.
///
/// Parses the certificate's `validity.not_after` field via `x509-parser`
/// and compares it against `now`.
fn check_cert_not_expired(der: &[u8], now: crate::core::Timestamp) -> Result<(), IdentityError> {
    let (_, cert) = parse_x509_certificate(der).map_err(|_| IdentityError::SpiffeCertInvalid {
        reason: "failed to parse DER certificate for expiry check".to_string(),
    })?;

    // x509-parser exposes not_after as an ASN1Time; timestamp() returns i64 seconds since epoch.
    let not_after_unix = cert.validity().not_after.timestamp();

    // `now` stores Unix microseconds; convert to seconds for comparison.
    let now_unix = now.as_micros() / 1_000_000;

    if now_unix > not_after_unix {
        return Err(IdentityError::SpiffeCertExpired);
    }

    Ok(())
}
