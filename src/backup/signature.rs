//! Detached Ed25519 manifest signatures (A-30) and the restore-time policy
//! that decides whether an archive's authenticity must be proven.
//!
//! An archive is encrypted and checksummed, but neither proves *who* produced
//! it: the checksums live in the very manifest an attacker would rewrite, and
//! the encryption passphrase is shared by everyone who can run a restore. The
//! detached signature over [`BackupManifest::canonical_bytes`] is the only
//! authenticity check, and since the manifest carries a SHA-256 of every
//! member, signing the manifest signs the whole archive.
//!
//! Restore is **fail-closed**: an archive is applied only when it verifies
//! against a configured `security.backup.verify_key`, unless the operator
//! explicitly opts out (`hearth backup restore --allow-unsigned`) or the
//! server runs in dev mode. See [`check_restore_signature`].

use std::path::Path;

use std::io::Read as _;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use zeroize::Zeroizing;

use crate::backup::{BackupArchive, BackupError, BackupManifest};

const PEM_BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_END: &str = "-----END PRIVATE KEY-----";

/// Outcome of a successful [`check_restore_signature`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureCheck {
    /// The manifest carried a signature that verified against the configured key.
    Verified,
    /// No verify key is configured and the caller explicitly allowed an
    /// unauthenticated restore. The archive's origin has NOT been checked.
    UnverifiedAllowed,
}

/// Decides whether an archive may be restored, based on its detached manifest
/// signature.
///
/// | verify key | archive signature | `allow_unsigned` | result |
/// |------------|-------------------|------------------|--------|
/// | configured | valid             | any              | `Verified` |
/// | configured | absent            | any              | [`BackupError::SignatureMissing`] |
/// | configured | invalid           | any              | [`BackupError::SignatureInvalid`] |
/// | absent     | any               | `false`          | [`BackupError::VerifyKeyNotConfigured`] |
/// | absent     | any               | `true`           | `UnverifiedAllowed` |
///
/// A configured key is authoritative: `allow_unsigned` does not let an unsigned
/// or badly signed archive past it. The opt-in exists for deployments that have
/// no key at all, never to downgrade one that has.
///
/// # Errors
///
/// See the table above.
pub fn check_restore_signature(
    manifest: &BackupManifest,
    verify_key: Option<&[u8; 32]>,
    allow_unsigned: bool,
) -> Result<SignatureCheck, BackupError> {
    match verify_key {
        Some(key) => {
            verify_manifest_signature(manifest, key)?;
            Ok(SignatureCheck::Verified)
        }
        None if allow_unsigned => Ok(SignatureCheck::UnverifiedAllowed),
        None => Err(BackupError::VerifyKeyNotConfigured),
    }
}

/// Verifies the manifest's detached signature against `public_key`.
///
/// # Errors
///
/// [`BackupError::SignatureMissing`] when the manifest carries no signature,
/// [`BackupError::SignatureInvalid`] when it does not verify.
pub fn verify_manifest_signature(
    manifest: &BackupManifest,
    public_key: &[u8; 32],
) -> Result<(), BackupError> {
    use ring::signature::{UnparsedPublicKey, ED25519};

    let sig_b64 = manifest
        .detached_signature_b64
        .as_deref()
        .ok_or(BackupError::SignatureMissing)?;
    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| BackupError::SignatureInvalid("signature is not base64url".into()))?;
    let canonical = manifest.canonical_bytes()?;
    UnparsedPublicKey::new(&ED25519, public_key.as_slice())
        .verify(&canonical, &sig)
        .map_err(|_| BackupError::SignatureInvalid("Ed25519 verification failed".into()))
}

/// Ed25519 private key used to sign backup manifests.
///
/// Deliberately implements neither `Debug` nor `Display`.
pub struct BackupSigningKey {
    pair: Ed25519KeyPair,
}

impl BackupSigningKey {
    /// Generates a fresh key and returns it with its PEM (`PRIVATE KEY`,
    /// PKCS#8) encoding, which is what [`Self::from_pem`] reads back.
    ///
    /// # Errors
    ///
    /// [`BackupError::Crypto`] when the system RNG fails.
    pub fn generate() -> Result<(Self, Zeroizing<String>), BackupError> {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| BackupError::Crypto("Ed25519 key generation failed".into()))?;
        let pkcs8 = Zeroizing::new(doc.as_ref().to_vec());
        let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| BackupError::Crypto("generated key did not parse".into()))?;
        let b64 = Zeroizing::new(STANDARD.encode(pkcs8.as_slice()));
        let mut pem = Zeroizing::new(String::with_capacity(b64.len() + 64));
        pem.push_str(PEM_BEGIN);
        pem.push('\n');
        for chunk in b64.as_bytes().chunks(64) {
            // Base64 output is ASCII, so every 64-byte chunk is valid UTF-8.
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str(PEM_END);
        pem.push('\n');
        Ok((Self { pair }, pem))
    }

    /// Parses a PEM-encoded PKCS#8 Ed25519 private key — either the file
    /// written by `hearth backup keygen` or one from
    /// `openssl genpkey -algorithm ed25519`.
    ///
    /// # Errors
    ///
    /// [`BackupError::SigningKeyInvalid`] when the text is not such a key.
    pub fn from_pem(pem: &str) -> Result<Self, BackupError> {
        let text = pem.trim();
        let body = text
            .strip_prefix(PEM_BEGIN)
            .and_then(|rest| rest.strip_suffix(PEM_END))
            .ok_or_else(|| {
                BackupError::SigningKeyInvalid(
                    "expected a PEM `PRIVATE KEY` block (PKCS#8 Ed25519)".into(),
                )
            })?;
        let b64: Zeroizing<String> =
            Zeroizing::new(body.chars().filter(|c| !c.is_whitespace()).collect());
        let der = Zeroizing::new(
            STANDARD
                .decode(b64.as_bytes())
                .map_err(|_| BackupError::SigningKeyInvalid("PEM body is not base64".into()))?,
        );
        let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der).map_err(|_| {
            BackupError::SigningKeyInvalid("not a PKCS#8 Ed25519 private key".into())
        })?;
        Ok(Self { pair })
    }

    /// The base64url (no padding) public key: the value for
    /// `security.backup.verify_key`.
    #[must_use]
    pub fn verify_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.pair.public_key().as_ref())
    }

    /// Signs `manifest` in place, setting `detached_signature_b64`.
    ///
    /// # Errors
    ///
    /// [`BackupError::Serialization`] if the manifest cannot be serialized.
    pub fn sign_manifest(&self, manifest: &mut BackupManifest) -> Result<(), BackupError> {
        let canonical = manifest.canonical_bytes()?;
        let sig = self.pair.sign(&canonical);
        manifest.detached_signature_b64 = Some(URL_SAFE_NO_PAD.encode(sig.as_ref()));
        Ok(())
    }
}

/// Re-writes the archive at `input` to `output` with a signed manifest.
///
/// The archive's checksums are verified first, which catches corruption and a
/// member changed without updating the manifest. It does **not** catch
/// tampering: the manifest being signed is the unsigned one that carries those
/// checksums, so anyone who replaced a member can have updated its checksum as
/// well, and this function would then sign the replacement. The signature is a
/// statement about origin that only the caller can make — sign only archives
/// obtained over a trusted channel. `output` may equal `input`; the new archive
/// is written to a temporary file beside `output` and renamed over it only once
/// complete.
///
/// # Errors
///
/// Any integrity error from [`crate::backup::ArchiveReader::verify_checksums`],
/// or an I/O error writing the new archive.
pub fn sign_archive(
    input: &Path,
    output: &Path,
    key: &BackupSigningKey,
) -> Result<(), BackupError> {
    // A private copy, so the members re-added below are the ones just
    // verified: `finish_signed` re-checksums whatever it is given, so a member
    // swapped at `input` between the two passes would otherwise be signed.
    let reader = BackupArchive::open_private_copy(input)?;
    reader.verify_checksums()?;

    let dir = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tmp = tempfile::NamedTempFile::new_in(dir)?;
    let mut writer = BackupArchive::create(tmp.path())?;

    let mut archive = tar::Archive::new(zstd::Decoder::new(reader.source.reader()?)?);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if path == "manifest.json" {
            continue;
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        writer.add_file(&path, &bytes)?;
    }
    writer.finish_signed(reader.manifest.clone(), key)?;

    std::fs::File::open(tmp.path())?.sync_all()?;
    tmp.persist(output).map_err(|e| BackupError::Io(e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{BackupArchive, RealmManifest, RecordCounts};

    fn manifest() -> BackupManifest {
        BackupManifest::new(vec![RealmManifest {
            realm_id: "realm_00000000-0000-0000-0000-000000000001".to_string(),
            slug: "acme".to_string(),
            record_counts: RecordCounts::default(),
            audit_chain_included: false,
        }])
    }

    fn key() -> BackupSigningKey {
        BackupSigningKey::generate().expect("generate").0
    }

    fn public_key(k: &BackupSigningKey) -> [u8; 32] {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        URL_SAFE_NO_PAD
            .decode(k.verify_key_b64())
            .expect("verify key is base64url")
            .try_into()
            .expect("verify key is 32 bytes")
    }

    // ── the restore policy ───────────────────────────────────────────────

    #[test]
    fn unsigned_archive_without_a_verify_key_is_refused_by_default() {
        let err = check_restore_signature(&manifest(), None, false)
            .expect_err("no key and no opt-in must refuse");
        assert!(
            matches!(err, BackupError::VerifyKeyNotConfigured),
            "wrong refusal: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("security.backup.verify_key") && msg.contains("--allow-unsigned"),
            "the refusal must say how to configure the key and how to opt out: {msg}"
        );
    }

    #[test]
    fn signed_archive_without_a_verify_key_is_still_refused_by_default() {
        // A signature nobody can check proves nothing: without a key the
        // archive is exactly as unauthenticated as an unsigned one.
        let k = key();
        let mut m = manifest();
        k.sign_manifest(&mut m).expect("sign");
        let err = check_restore_signature(&m, None, false).expect_err("must refuse");
        assert!(matches!(err, BackupError::VerifyKeyNotConfigured), "{err}");
    }

    #[test]
    fn explicit_opt_in_allows_an_unverified_restore_without_a_key() {
        assert_eq!(
            check_restore_signature(&manifest(), None, true).expect("opt-in"),
            SignatureCheck::UnverifiedAllowed
        );
    }

    #[test]
    fn signed_archive_verifies_against_the_configured_key() {
        let k = key();
        let mut m = manifest();
        k.sign_manifest(&mut m).expect("sign");
        assert!(
            m.detached_signature_b64.is_some(),
            "signing must set the field"
        );
        assert_eq!(
            check_restore_signature(&m, Some(&public_key(&k)), false).expect("verifies"),
            SignatureCheck::Verified
        );
    }

    #[test]
    fn unsigned_archive_is_refused_when_a_key_is_configured_even_with_the_opt_in() {
        let k = key();
        for allow in [false, true] {
            let err = check_restore_signature(&manifest(), Some(&public_key(&k)), allow)
                .expect_err("a configured key is authoritative");
            assert!(matches!(err, BackupError::SignatureMissing), "{err}");
        }
    }

    #[test]
    fn archive_signed_by_another_key_is_refused() {
        let signer = key();
        let other = key();
        let mut m = manifest();
        signer.sign_manifest(&mut m).expect("sign");
        let err = check_restore_signature(&m, Some(&public_key(&other)), true)
            .expect_err("wrong key must not verify");
        assert!(matches!(err, BackupError::SignatureInvalid(_)), "{err}");
    }

    #[test]
    fn a_manifest_edited_after_signing_is_refused() {
        let k = key();
        let mut m = manifest();
        k.sign_manifest(&mut m).expect("sign");
        m.checksums
            .insert("realms/acme/users.ndjson".into(), "00".repeat(32));
        let err = check_restore_signature(&m, Some(&public_key(&k)), false)
            .expect_err("tampered manifest must not verify");
        assert!(matches!(err, BackupError::SignatureInvalid(_)), "{err}");
    }

    #[test]
    fn a_non_base64_signature_is_refused_not_ignored() {
        let k = key();
        let mut m = manifest();
        m.detached_signature_b64 = Some("not base64 !!".into());
        let err = verify_manifest_signature(&m, &public_key(&k)).expect_err("garbage");
        assert!(matches!(err, BackupError::SignatureInvalid(_)), "{err}");
    }

    // ── key handling ─────────────────────────────────────────────────────

    #[test]
    fn generated_key_round_trips_through_pem() {
        let (k, pem) = BackupSigningKey::generate().expect("generate");
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "{}",
            &pem[..30]
        );
        let back = BackupSigningKey::from_pem(&pem).expect("parse own PEM");
        assert_eq!(back.verify_key_b64(), k.verify_key_b64());
        assert_eq!(
            k.verify_key_b64().len(),
            43,
            "32 bytes base64url, no padding"
        );
    }

    #[test]
    fn openssl_style_unversioned_pkcs8_is_accepted() {
        // `openssl genpkey -algorithm ed25519` writes PKCS#8 v1 (no public key).
        const OPENSSL_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
            MC4CAQAwBQYDK2VwBCIEIBJga6BJyucFOXunA+oAB3JEXBR0Q+ZWepPJ0QZdsprJ\n\
            -----END PRIVATE KEY-----\n";
        // Derived independently: `openssl pkey -pubout -outform DER | tail -c 32 | basenc --base64url`.
        const OPENSSL_PUB: &str = "5settUVm3ZDqg9RWtbbLjmbA1RK2KOvVu_PmihsFk-8";
        let k = BackupSigningKey::from_pem(OPENSSL_PEM).expect("openssl key");
        assert_eq!(k.verify_key_b64(), OPENSSL_PUB);
    }

    #[test]
    fn a_non_key_is_rejected() {
        let err = BackupSigningKey::from_pem("hello")
            .err()
            .expect("not a key");
        assert!(matches!(err, BackupError::SigningKeyInvalid(_)), "{err}");
    }

    // ── re-signing an existing archive ───────────────────────────────────

    fn write_unsigned_archive(path: &Path) {
        let mut w = BackupArchive::create(path).expect("create");
        w.add_file("realms/acme/users.ndjson", b"{\"id\":\"u1\"}\n")
            .expect("add");
        w.finish(manifest()).expect("finish");
    }

    #[test]
    fn sign_archive_produces_an_archive_that_verifies_with_intact_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("in.hearth-backup");
        let dst = dir.path().join("out.hearth-backup");
        write_unsigned_archive(&src);
        let k = key();

        sign_archive(&src, &dst, &k).expect("sign");

        let reader = BackupArchive::open(&dst).expect("open signed");
        assert_eq!(
            check_restore_signature(&reader.manifest, Some(&public_key(&k)), false)
                .expect("signed archive verifies"),
            SignatureCheck::Verified
        );
        assert_eq!(reader.verify_checksums().expect("intact"), 1);
        assert_eq!(
            reader
                .read_file("realms/acme/users.ndjson")
                .expect("read")
                .as_deref(),
            Some(&b"{\"id\":\"u1\"}\n"[..])
        );
    }

    #[test]
    fn sign_archive_in_place_replaces_the_input() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.hearth-backup");
        write_unsigned_archive(&path);
        let k = key();
        sign_archive(&path, &path, &k).expect("sign in place");
        let reader = BackupArchive::open(&path).expect("open");
        verify_manifest_signature(&reader.manifest, &public_key(&k)).expect("verifies");
    }

    #[test]
    fn sign_archive_refuses_to_bless_a_corrupt_archive() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src = dir.path().join("in.hearth-backup");
        let dst = dir.path().join("out.hearth-backup");
        // Hand-pack an archive whose manifest checksums the member wrongly —
        // `ArchiveWriter` would compute the right checksum, so bypass it.
        let mut bad = manifest();
        bad.checksums
            .insert("realms/acme/users.ndjson".into(), "00".repeat(32));
        let file = std::fs::File::create(&src).expect("create");
        let mut builder = tar::Builder::new(zstd::Encoder::new(file, 3).expect("zstd"));
        for (path, data) in [
            ("realms/acme/users.ndjson", b"x".to_vec()),
            ("manifest.json", serde_json::to_vec(&bad).expect("json")),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, path, data.as_slice())
                .expect("append");
        }
        builder
            .into_inner()
            .expect("tar")
            .finish()
            .expect("zstd finish");

        let err = sign_archive(&src, &dst, &key()).expect_err("corrupt archive");
        assert!(matches!(err, BackupError::ChecksumMismatch { .. }), "{err}");
        assert!(!dst.exists(), "no output may be left behind");
    }
}
