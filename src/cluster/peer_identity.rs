//! Peer identity (`cluster-membership-changes` design decision 5).
//!
//! Every peer RPC carries three gRPC metadata values: the cluster's ID, the
//! sender's node ID and the node ID it is meant for. Each peer certificate
//! names its node ID in a URI SAN, `urn:hearth:node:<id>`. A receiver checks
//! all of them before the RPC reaches Raft, and the sender checks that the
//! certificate of the node it dialled names the node it meant to reach.
//!
//! mTLS alone only proves that the cluster CA signed the other end. Without
//! these checks a node accepts RPCs meant for another node ID (a replacement
//! listening at a dead node's address), from another cluster (a node that
//! self-initialised on a wiped data directory), or from a node that holds any
//! CA-signed certificate and claims to be a member.

use std::sync::Arc;

use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use tonic::metadata::{MetadataMap, MetadataValue};
use x509_parser::extensions::{GeneralName, ParsedExtension};

use crate::cluster::types::ClusterId;

/// Metadata key of the cluster ID. Absent when the sender has none yet.
pub(crate) const CLUSTER_ID_KEY: &str = "x-hearth-cluster-id";
/// Metadata key of the sender's node ID.
pub(crate) const SOURCE_NODE_KEY: &str = "x-hearth-source-node";
/// Metadata key of the node ID the RPC is meant for.
pub(crate) const TARGET_NODE_KEY: &str = "x-hearth-target-node";
/// Metadata key of a refusal's code, on the refusing node's answer.
pub(crate) const REFUSAL_KEY: &str = "x-hearth-peer-refusal";

/// The URI SAN prefix that names a node in its peer certificate.
pub const NODE_URI_PREFIX: &str = "urn:hearth:node:";

// ── Claims ───────────────────────────────────────────────────────────────────

/// What the sender of a peer RPC says about itself and its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerClaim {
    /// The sender's cluster ID; `None` when it has none yet.
    pub cluster_id: Option<ClusterId>,
    /// The sender's node ID.
    pub source: u64,
    /// The node ID the RPC is meant for.
    pub target: u64,
}

impl PeerClaim {
    /// Writes the claim into an outgoing RPC's metadata.
    pub(crate) fn stamp(&self, metadata: &mut MetadataMap) {
        if let Some(id) = self.cluster_id {
            // A hyphenated UUID is ASCII, so this always parses.
            if let Ok(value) = MetadataValue::try_from(id.as_uuid().to_string()) {
                metadata.insert(CLUSTER_ID_KEY, value);
            }
        }
        metadata.insert(SOURCE_NODE_KEY, MetadataValue::from(self.source));
        metadata.insert(TARGET_NODE_KEY, MetadataValue::from(self.target));
    }

    /// Reads the claim of an incoming RPC.
    ///
    /// # Errors
    ///
    /// [`PeerRefusal::MissingIdentity`] when a node ID is absent, or a value
    /// does not parse.
    pub(crate) fn read(metadata: &MetadataMap) -> Result<Self, PeerRefusal> {
        let text = |key: &str| -> Result<Option<&str>, PeerRefusal> {
            metadata
                .get(key)
                .map(|v| v.to_str().map_err(|_| PeerRefusal::MissingIdentity))
                .transpose()
        };
        let node = |key: &str| -> Result<u64, PeerRefusal> {
            text(key)?
                .and_then(|v| v.parse().ok())
                .ok_or(PeerRefusal::MissingIdentity)
        };
        let cluster_id = text(CLUSTER_ID_KEY)?
            .map(|v| {
                uuid::Uuid::parse_str(v)
                    .map(ClusterId::new)
                    .map_err(|_| PeerRefusal::MissingIdentity)
            })
            .transpose()?;
        Ok(Self {
            cluster_id,
            source: node(SOURCE_NODE_KEY)?,
            target: node(TARGET_NODE_KEY)?,
        })
    }
}

// ── Refusals ─────────────────────────────────────────────────────────────────

/// Why a node refused a peer RPC. Each has its own code, which travels in
/// the answer's message and in its `x-hearth-peer-refusal` metadata.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRefusal {
    /// The RPC carries no source or target node ID, or one that does not
    /// parse (a sender of an older build).
    MissingIdentity,
    /// The sender's certificate names no node ID, several, or another node
    /// ID than the RPC claims.
    CertificateMismatch,
    /// The RPC is meant for another node ID.
    WrongNode,
    /// The RPC comes from another cluster, or names none while this node
    /// has one.
    WrongCluster,
    /// The sender is not a member (voter or learner) of this node's
    /// membership.
    NotAMember,
    /// The sender's node ID was removed from the cluster and retired.
    Removed,
}

impl PeerRefusal {
    const ALL: [Self; 6] = [
        Self::MissingIdentity,
        Self::CertificateMismatch,
        Self::WrongNode,
        Self::WrongCluster,
        Self::NotAMember,
        Self::Removed,
    ];

    /// The refusal's code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingIdentity => "MISSING_IDENTITY",
            Self::CertificateMismatch => "CERTIFICATE_MISMATCH",
            Self::WrongNode => "WRONG_NODE",
            Self::WrongCluster => "WRONG_CLUSTER",
            Self::NotAMember => "NOT_A_MEMBER",
            Self::Removed => "REMOVED",
        }
    }

    /// The answer a refusing node sends: `PERMISSION_DENIED` for a
    /// certificate that does not match, `FAILED_PRECONDITION` otherwise,
    /// with the code first in the message and in the metadata.
    pub(crate) fn to_status(self) -> tonic::Status {
        let message = match self {
            Self::MissingIdentity => {
                "the RPC names no source or target node ID (a peer of an older Hearth build?)"
            }
            Self::CertificateMismatch => {
                "the peer certificate does not name the node ID this RPC claims \
                 (URI SAN urn:hearth:node:<id>)"
            }
            Self::WrongNode => "this RPC is meant for another node ID",
            Self::WrongCluster => "this RPC comes from another cluster",
            Self::NotAMember => "the sender is not a member of this node's cluster",
            Self::Removed => "the sender was removed from this cluster",
        };
        let message = format!("{}: {message}", self.code());
        let mut status = match self {
            Self::CertificateMismatch => tonic::Status::permission_denied(message),
            _ => tonic::Status::failed_precondition(message),
        };
        status
            .metadata_mut()
            .insert(REFUSAL_KEY, MetadataValue::from_static(self.code()));
        status
    }

    /// The refusal a peer answered with, if `status` is one.
    pub(crate) fn from_status(status: &tonic::Status) -> Option<Self> {
        let code = status.metadata().get(REFUSAL_KEY)?.to_str().ok()?;
        Self::ALL.into_iter().find(|r| r.code() == code)
    }
}

impl std::fmt::Display for PeerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

// ── Admission ────────────────────────────────────────────────────────────────

/// Where a sender stands in the membership the receiving node holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStanding {
    /// The receiving node holds no membership yet (it has never been
    /// initialised or reached by a leader), so it cannot tell.
    Pristine,
    /// A voter or a learner.
    Member,
    /// Neither a voter nor a learner.
    NotAMember,
    /// Removed from the cluster; its node ID is retired.
    Retired,
}

/// Which peer RPC arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRpc {
    /// `AppendEntries`, from a leader.
    AppendEntries,
    /// `Vote`, from a candidate.
    Vote,
    /// `InstallSnapshot`, from a leader.
    InstallSnapshot,
    /// `ForwardWrite`, from a follower.
    ForwardWrite,
}

impl PeerRpc {
    /// Whether only a leader sends it. A pristine node adopts the cluster ID
    /// of such an RPC only: a leader holds the cluster's committed
    /// membership, so its cluster ID is the one to join.
    const fn is_from_leader(self) -> bool {
        matches!(self, Self::AppendEntries | Self::InstallSnapshot)
    }
}

/// What the receiving node does with an RPC that passed its checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Serve it.
    Serve,
    /// This node is pristine (no cluster ID, no membership): adopt this
    /// leader's cluster ID and persist it, then serve the RPC.
    AdoptClusterId(ClusterId),
}

/// The receiving node's side of the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalPeer {
    /// This node's ID.
    pub node_id: u64,
    /// This node's cluster ID; `None` on a node that has none yet.
    pub cluster_id: Option<ClusterId>,
}

/// Decides whether a node serves a peer RPC (design decision 5).
///
/// `cert_node` is the node ID the sender's certificate names, `None` when it
/// names none or several. `standing` says where a node ID stands in this
/// node's membership. The checks run in this order: certificate, target,
/// cluster, sender's standing.
///
/// # Errors
///
/// The [`PeerRefusal`] of the first check that fails.
pub fn admit(
    local: LocalPeer,
    claim: &PeerClaim,
    cert_node: Option<u64>,
    rpc: PeerRpc,
    standing: impl FnOnce(u64) -> PeerStanding,
) -> Result<Admission, PeerRefusal> {
    if cert_node != Some(claim.source) {
        return Err(PeerRefusal::CertificateMismatch);
    }
    if claim.target != local.node_id {
        return Err(PeerRefusal::WrongNode);
    }
    let offered = match (local.cluster_id, claim.cluster_id) {
        (Some(ours), Some(theirs)) if ours == theirs => None,
        (Some(_), _) => return Err(PeerRefusal::WrongCluster),
        (None, Some(theirs)) if rpc.is_from_leader() => Some(theirs),
        (None, _) => None,
    };
    match standing(claim.source) {
        PeerStanding::Retired => Err(PeerRefusal::Removed),
        PeerStanding::NotAMember => Err(PeerRefusal::NotAMember),
        // Only a pristine node adopts. A node that holds a membership but no
        // cluster ID was formed by an older release: its leader sends none,
        // so an ID adopted from any member would make it refuse its leader.
        PeerStanding::Member => Ok(Admission::Serve),
        PeerStanding::Pristine => Ok(offered.map_or(Admission::Serve, Admission::AdoptClusterId)),
    }
}

// ── Certificates ─────────────────────────────────────────────────────────────

/// The node ID a DER certificate names in its URI SAN
/// (`urn:hearth:node:<id>`), or `None` when it names none, several different
/// ones, or one that is not a `u64` in canonical decimal form.
#[must_use]
pub fn certificate_node_id(der: &[u8]) -> Option<u64> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let mut found: Option<u64> = None;
    for ext in cert.extensions() {
        let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() else {
            continue;
        };
        for name in &san.general_names {
            let GeneralName::URI(uri) = name else {
                continue;
            };
            let Some(id) = uri.strip_prefix(NODE_URI_PREFIX) else {
                continue;
            };
            let id = canonical_node_id(id)?;
            match found {
                Some(other) if other != id => return None,
                _ => found = Some(id),
            }
        }
    }
    found
}

/// `text` as a node ID when it is one in canonical decimal form: digits
/// only, no sign, no leading zero (but `0` itself). `u64::from_str` also
/// reads `+5` and `005` as 5, so one node would have several spellings.
fn canonical_node_id(text: &str) -> Option<u64> {
    let canonical =
        text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    canonical.then(|| text.parse().ok()).flatten()
}

/// The certificate of the node at the other end does not name the node ID
/// this node meant to reach.
struct WrongPeerCertificate {
    expected: u64,
    found: Option<u64>,
}

/// The same text as `Display`: rustls prints a `CertificateError::Other`
/// with `Debug`, and that text is what an operator reads in the log.
impl std::fmt::Debug for WrongPeerCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for WrongPeerCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.found {
            Some(found) => write!(
                f,
                "the peer certificate names node {found}, not node {} (URI SAN \
                 {NODE_URI_PREFIX}<id>)",
                self.expected
            ),
            None => write!(
                f,
                "the peer certificate names no node ID; node {} needs the URI SAN \
                 {NODE_URI_PREFIX}{}",
                self.expected, self.expected
            ),
        }
    }
}

impl std::error::Error for WrongPeerCertificate {}

/// Verifies a peer's server certificate as rustls's WebPKI verifier does
/// (chain to the cluster CA, a SAN for the dialled address), and also checks
/// that it names the node ID the client meant to reach.
#[derive(Debug)]
pub(crate) struct NodeIdServerVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    expected: u64,
}

impl NodeIdServerVerifier {
    /// A verifier for node `expected`, trusting the CA certificates in
    /// `ca_pem`.
    ///
    /// # Errors
    ///
    /// A message when `ca_pem` holds no usable CA certificate.
    pub(crate) fn new(ca_pem: &[u8], expected: u64) -> Result<Self, String> {
        use rustls::pki_types::pem::PemObject;
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(ca_pem) {
            let cert = cert.map_err(|e| format!("cannot read the cluster CA PEM: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("unusable cluster CA certificate: {e}"))?;
        }
        if roots.is_empty() {
            return Err("the cluster CA PEM holds no certificate".to_string());
        }
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
        let inner =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .map_err(|e| format!("cannot build the peer certificate verifier: {e}"))?;
        Ok(Self { inner, expected })
    }
}

impl rustls::client::danger::ServerCertVerifier for NodeIdServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let found = certificate_node_id(end_entity);
        if found != Some(self.expected) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                    WrongPeerCertificate {
                        expected: self.expected,
                        found,
                    },
                ))),
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Test certificates: a cluster CA and leaves that name a node ID.
#[cfg(test)]
#[allow(clippy::expect_used)]
pub(crate) mod test_pki {
    /// A cluster CA that signs peer leaf certificates.
    pub(crate) struct TestCa {
        cert: rcgen::Certificate,
        key: rcgen::KeyPair,
    }

    /// A leaf certificate and its key, PEM and DER.
    pub(crate) struct TestLeaf {
        pub(crate) cert_pem: String,
        pub(crate) key_pem: String,
        pub(crate) der: Vec<u8>,
    }

    impl TestCa {
        pub(crate) fn new() -> Self {
            let mut params =
                rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key = rcgen::KeyPair::generate().expect("ca key");
            let cert = params.self_signed(&key).expect("ca cert");
            Self { cert, key }
        }

        pub(crate) fn pem(&self) -> String {
            self.cert.pem()
        }

        /// A leaf for `localhost` / `127.0.0.1` whose URI SANs are `uris`.
        pub(crate) fn leaf_with_uris(&self, uris: &[String]) -> TestLeaf {
            let mut params = rcgen::CertificateParams::new(vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ])
            .expect("leaf params");
            for uri in uris {
                params.subject_alt_names.push(rcgen::SanType::URI(
                    rcgen::Ia5String::try_from(uri.as_str()).expect("ia5 uri"),
                ));
            }
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let cert = params
                .signed_by(&key, &self.cert, &self.key)
                .expect("leaf cert");
            TestLeaf {
                cert_pem: cert.pem(),
                key_pem: key.serialize_pem(),
                der: cert.der().to_vec(),
            }
        }

        /// A leaf that names node `node`.
        pub(crate) fn leaf_for_node(&self, node: u64) -> TestLeaf {
            self.leaf_with_uris(&[format!("{}{node}", super::NODE_URI_PREFIX)])
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::test_pki::TestCa;
    use super::*;

    const A: ClusterId = ClusterId::new(uuid::Uuid::from_u128(0xA));
    const B: ClusterId = ClusterId::new(uuid::Uuid::from_u128(0xB));

    fn local(cluster_id: Option<ClusterId>) -> LocalPeer {
        LocalPeer {
            node_id: 2,
            cluster_id,
        }
    }

    fn claim(cluster_id: Option<ClusterId>, source: u64, target: u64) -> PeerClaim {
        PeerClaim {
            cluster_id,
            source,
            target,
        }
    }

    fn member(_: u64) -> PeerStanding {
        PeerStanding::Member
    }

    #[test]
    fn a_correct_rpc_is_served() {
        let got = admit(
            local(Some(A)),
            &claim(Some(A), 1, 2),
            Some(1),
            PeerRpc::Vote,
            member,
        );
        assert_eq!(got, Ok(Admission::Serve));
    }

    #[test]
    fn an_rpc_for_another_node_is_wrong_node() {
        let got = admit(
            local(Some(A)),
            &claim(Some(A), 1, 3),
            Some(1),
            PeerRpc::Vote,
            member,
        );
        assert_eq!(got, Err(PeerRefusal::WrongNode));
    }

    #[test]
    fn an_rpc_from_another_cluster_is_wrong_cluster() {
        let rpc = PeerRpc::AppendEntries;
        let got = admit(local(Some(A)), &claim(Some(B), 1, 2), Some(1), rpc, member);
        assert_eq!(got, Err(PeerRefusal::WrongCluster));
        // A sender with no cluster ID is not of this cluster either.
        let got = admit(local(Some(A)), &claim(None, 1, 2), Some(1), rpc, member);
        assert_eq!(got, Err(PeerRefusal::WrongCluster));
    }

    #[test]
    fn a_non_member_and_a_retired_node_get_their_own_codes() {
        let rpc = PeerRpc::Vote;
        let got = admit(local(Some(A)), &claim(Some(A), 7, 2), Some(7), rpc, |_| {
            PeerStanding::NotAMember
        });
        assert_eq!(got, Err(PeerRefusal::NotAMember));
        let got = admit(local(Some(A)), &claim(Some(A), 3, 2), Some(3), rpc, |_| {
            PeerStanding::Retired
        });
        assert_eq!(got, Err(PeerRefusal::Removed));
    }

    #[test]
    fn a_certificate_for_another_node_is_a_mismatch() {
        let rpc = PeerRpc::Vote;
        let got = admit(local(Some(A)), &claim(Some(A), 5, 2), Some(2), rpc, member);
        assert_eq!(got, Err(PeerRefusal::CertificateMismatch));
        let got = admit(local(Some(A)), &claim(Some(A), 5, 2), None, rpc, member);
        assert_eq!(got, Err(PeerRefusal::CertificateMismatch));
    }

    #[test]
    fn the_certificate_is_checked_before_the_standing() {
        // A non-member that also lies about its ID is told about the lie,
        // and the standing of the ID it claims is never looked up.
        let got = admit(
            local(Some(A)),
            &claim(Some(A), 5, 2),
            Some(2),
            PeerRpc::Vote,
            |_| panic!("standing looked up before the certificate check"),
        );
        assert_eq!(got, Err(PeerRefusal::CertificateMismatch));
    }

    #[test]
    fn a_pristine_node_adopts_a_leaders_cluster_id_only() {
        let pristine = |_| PeerStanding::Pristine;
        for rpc in [PeerRpc::AppendEntries, PeerRpc::InstallSnapshot] {
            let got = admit(local(None), &claim(Some(A), 1, 2), Some(1), rpc, pristine);
            assert_eq!(got, Ok(Admission::AdoptClusterId(A)), "{rpc:?}");
        }
        for rpc in [PeerRpc::Vote, PeerRpc::ForwardWrite] {
            let got = admit(local(None), &claim(Some(A), 1, 2), Some(1), rpc, pristine);
            assert_eq!(got, Ok(Admission::Serve), "{rpc:?}");
        }
        let got = admit(
            local(None),
            &claim(None, 1, 2),
            Some(1),
            PeerRpc::Vote,
            pristine,
        );
        assert_eq!(got, Ok(Admission::Serve));
    }

    /// Finding 3 on #955: a node that holds a membership but no cluster ID
    /// (a cluster an older release formed) adopts none, so no member can
    /// hand it an ID its leader does not send; it serves its members'
    /// RPCs with or without one.
    #[test]
    fn a_node_with_a_membership_but_no_cluster_id_adopts_none() {
        for rpc in [PeerRpc::AppendEntries, PeerRpc::InstallSnapshot] {
            for sent in [Some(A), None] {
                let got = admit(local(None), &claim(sent, 1, 2), Some(1), rpc, member);
                assert_eq!(got, Ok(Admission::Serve), "{rpc:?} {sent:?}");
            }
        }
    }

    #[test]
    fn a_claim_round_trips_through_metadata() {
        let mut md = MetadataMap::new();
        let sent = claim(Some(A), 1, 2);
        sent.stamp(&mut md);
        assert_eq!(PeerClaim::read(&md), Ok(sent));

        let mut md = MetadataMap::new();
        claim(None, 4, 9).stamp(&mut md);
        assert!(md.get(CLUSTER_ID_KEY).is_none());
        assert_eq!(PeerClaim::read(&md), Ok(claim(None, 4, 9)));
    }

    #[test]
    fn a_claim_without_node_ids_is_missing_identity() {
        assert_eq!(
            PeerClaim::read(&MetadataMap::new()),
            Err(PeerRefusal::MissingIdentity)
        );
        let mut md = MetadataMap::new();
        md.insert(SOURCE_NODE_KEY, MetadataValue::from_static("one"));
        md.insert(TARGET_NODE_KEY, MetadataValue::from_static("2"));
        assert_eq!(PeerClaim::read(&md), Err(PeerRefusal::MissingIdentity));
    }

    #[test]
    fn each_refusal_round_trips_through_its_status() {
        for refusal in PeerRefusal::ALL {
            let status = refusal.to_status();
            assert!(status.message().starts_with(refusal.code()));
            assert_eq!(PeerRefusal::from_status(&status), Some(refusal));
        }
        assert_eq!(
            PeerRefusal::CertificateMismatch.to_status().code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            PeerRefusal::WrongNode.to_status().code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            PeerRefusal::from_status(&tonic::Status::internal("x")),
            None
        );
    }

    #[test]
    fn certificate_node_id_reads_the_uri_san() {
        let ca = TestCa::new();
        assert_eq!(certificate_node_id(&ca.leaf_for_node(7).der), Some(7));
        // No node URI, another URI, two different node IDs, a bad ID.
        assert_eq!(certificate_node_id(&ca.leaf_with_uris(&[]).der), None);
        let spiffe = ["spiffe://example.org/x".to_string()];
        assert_eq!(certificate_node_id(&ca.leaf_with_uris(&spiffe).der), None);
        let two = [format!("{NODE_URI_PREFIX}1"), format!("{NODE_URI_PREFIX}2")];
        assert_eq!(certificate_node_id(&ca.leaf_with_uris(&two).der), None);
        let bad = [format!("{NODE_URI_PREFIX}x")];
        assert_eq!(certificate_node_id(&ca.leaf_with_uris(&bad).der), None);
        assert_eq!(certificate_node_id(b"not a certificate"), None);
    }

    /// Finding 5 on #955: a node ID in the URI SAN is in canonical decimal
    /// form; `+5` or `005` names no node, although `u64::from_str` reads
    /// both as 5.
    #[test]
    fn certificate_node_id_refuses_a_non_canonical_node_id() {
        let ca = TestCa::new();
        for id in ["+5", "05", "005", "", " 5", "5 "] {
            let uri = [format!("{NODE_URI_PREFIX}{id}")];
            assert_eq!(
                certificate_node_id(&ca.leaf_with_uris(&uri).der),
                None,
                "{id:?}"
            );
        }
        assert_eq!(certificate_node_id(&ca.leaf_for_node(0).der), Some(0));
        assert_eq!(certificate_node_id(&ca.leaf_for_node(50).der), Some(50));
    }
}
