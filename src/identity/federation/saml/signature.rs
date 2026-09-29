//! XML-DSIG sign and verify over SAML `<Response>` / `<Assertion>`.
//!
//! Algorithm suite (locked):
//! - Canonicalization: exclusive C14N 1.0 without comments.
//! - Digest: SHA-256.
//! - Signature: RSA-PKCS1-v1.5-SHA256.
//! - Reference transforms: `enveloped-signature` + `exc-c14n` only.
//!
//! SHA-1 is rejected. Algorithm downgrade attempts return
//! `SamlUnsupportedAlgorithm`.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use sha2::{Digest, Sha256};

use super::c14n::{canonicalize, canonicalize_with_inherited, EnvelopedSignature};
use super::xml::{
    alg, child_elements, count_child_elements, escape_attr, find_child_element_range,
    find_child_element_range_in, find_element_range, in_scope_namespaces, ns, parse_err,
    Namespaces,
};
use crate::identity::error::IdentityError;
use crate::identity::federation::saml::SamlError;
use crate::identity::tokens::RsaSigningKey;

/// Metadata about a verified signed element.
pub struct SignedElement {
    /// The element local name (`Response` or `Assertion`).
    pub local_name: String,
    /// The element ID (matched against the `Reference URI` in the
    /// signature).
    pub id: String,
    /// The canonicalized bytes of the signed element (with `<Signature>`
    /// stripped per the enveloped transform).
    pub canonical: Vec<u8>,
}

/// Signs the enveloped XML subtree represented by `element_xml`, returning
/// a new XML document identical to the input but with a freshly-built
/// `<ds:Signature>` element inserted as the first child of the root.
///
/// `element_xml` MUST have its root element carry an `ID="…"` attribute
/// — SAML signatures reference the signed element by its ID. The
/// canonical subset we implement emits the `<Signature>` immediately
/// after the root's opening tag, which is also where SAML SPs expect it.
///
/// This is a minimal implementation: it assumes the root element has no
/// leading whitespace content and that the first child insertion point
/// is well-defined.
///
/// # Errors
///
/// Refuses an element that already carries a direct-child `<ds:Signature>`:
/// the result would carry two, and an element carries exactly one enveloped
/// signature (`verify_signed_element` rejects the second). Also fails on
/// malformed XML or a signing-key error.
pub fn sign_element(
    element_xml: &[u8],
    element_id: &str,
    key: &RsaSigningKey,
) -> Result<Vec<u8>, IdentityError> {
    if find_child_element_range(element_xml, ns::DS, "Signature")?.is_some() {
        return Err(parse_err(
            "element already carries an enveloped <ds:Signature>",
        ));
    }

    // 1. Canonicalize the element. The enveloped-signature transform removes
    //    the signature being created, which is not in the input yet, so
    //    nothing is removed here.
    let canonical = canonicalize(element_xml, EnvelopedSignature::Keep)?;

    // 2. Compute the digest.
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    let digest = hasher.finalize();
    let digest_b64 = B64.encode(digest);

    // 3. Build the SignedInfo element, canonicalize it WITH the ds
    //    prefix seeded as inherited — the emitted bytes have no
    //    `xmlns:ds` of their own (the enclosing <ds:Signature> owns it),
    //    so the canonical form must match what a consumer would compute
    //    in-context.
    let signed_info = build_signed_info(element_id, &digest_b64);
    // Detached canonicalization — xml-crypto and other SAML libraries
    // do the same. The visibly-utilized `xmlns:ds` emits onto SignedInfo.
    let canonical_si = canonicalize(signed_info.as_bytes(), EnvelopedSignature::Keep)?;

    // 4. Sign.
    let signature_bytes = key.sign(&canonical_si)?;
    let signature_b64 = B64.encode(&signature_bytes);

    // 5. Build the full <Signature> element.
    let cert_b64 = B64.encode(key.cert_der());
    let signature_xml = build_signature_block(&signed_info, &signature_b64, &cert_b64);

    // 6. Splice the signature block into the element after the root's
    //    opening tag. Find the end of the first `>` in element_xml.
    let open_end = element_xml
        .iter()
        .position(|&b| b == b'>')
        .ok_or_else(|| parse_err("no root tag close found"))?;

    let mut out = Vec::with_capacity(element_xml.len() + signature_xml.len());
    out.extend_from_slice(&element_xml[..=open_end]);
    out.extend_from_slice(signature_xml.as_bytes());
    out.extend_from_slice(&element_xml[open_end + 1..]);
    Ok(out)
}

fn build_signed_info(element_id: &str, digest_b64: &str) -> String {
    let uri = format!("#{}", escape_attr(element_id));
    // xml-crypto and other SAML libraries canonicalize SignedInfo as a
    // detached subtree (no inherited ancestor ns context). In that mode
    // `xmlns:ds` is visibly utilized at the SignedInfo root and must be
    // emitted. Matching that behavior means emitting the decl here too
    // so our canonical form byte-matches theirs.
    format!(
        r#"<ds:SignedInfo xmlns:ds="{ds}"><ds:CanonicalizationMethod Algorithm="{c14n}"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="{sig}"></ds:SignatureMethod><ds:Reference URI="{uri}"><ds:Transforms><ds:Transform Algorithm="{env}"></ds:Transform><ds:Transform Algorithm="{c14n}"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="{dig}"></ds:DigestMethod><ds:DigestValue>{digest}</ds:DigestValue></ds:Reference></ds:SignedInfo>"#,
        ds = ns::DS,
        c14n = alg::EXC_C14N,
        sig = alg::RSA_SHA256,
        env = alg::ENVELOPED,
        dig = alg::SHA256,
        uri = uri,
        digest = digest_b64,
    )
}

fn build_signature_block(signed_info: &str, signature_b64: &str, cert_b64: &str) -> String {
    format!(
        r#"<ds:Signature xmlns:ds="{ds}">{si}<ds:SignatureValue>{sv}</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"#,
        ds = ns::DS,
        si = signed_info,
        sv = signature_b64,
        cert = cert_b64,
    )
}

/// Verifies the signature on a `<Response>` or `<Assertion>` element.
///
/// `full_xml` is the entire XML document as received (we need the full
/// bytes to locate the signed element's byte range).
///
/// `signing_cert_pem` is the expected IdP certificate (PEM).
///
/// Returns the verified signed element's canonical bytes on success.
///
/// Rejects:
/// - Missing `<Signature>` or `<SignedInfo>`.
/// - An element with more than one direct-child `<ds:Signature>`. The
///   enveloped-signature transform removes exactly the signature being
///   verified; a second one would be a region of the element that no digest
///   covers and no verifier reads (GA audit 3, G-1).
/// - A `<ds:Signature>` with any child other than one `<ds:SignedInfo>`, one
///   `<ds:SignatureValue>` and at most one `<ds:KeyInfo>`. Nothing else in a
///   signature is covered by it, so extra content there is unsigned content
///   placed inside the signed element.
/// - A `<ds:SignedInfo>` carrying anything other than exactly one
///   `<ds:Reference>`. Only the first reference is ever read, so a list would
///   let every entry after it pass unverified — the classic multiple-reference
///   wrapping shape. The count is bounded, so a padded list is refused on the
///   second entry rather than scanned to the end.
/// - A `<ds:Reference URI>` that is not `#<id>` for the enclosing element's
///   own `ID` attribute.
/// - A `SignedInfo` naming SHA-1 or RSA-SHA1, or one that does not name both
///   RSA-SHA256 and SHA-256.
/// - A declared `<ds:CanonicalizationMethod>` that is not exclusive C14N 1.0
///   without comments, and a `<ds:Transforms>` list that is absent, omits the
///   enveloped-signature transform, or names anything other than
///   enveloped-signature and exclusive C14N. Hearth applies exactly that
///   chain unconditionally, so a document declaring a different one is an
///   algorithm downgrade and is refused at the declaration rather than being
///   left to fail the digest.
/// - Digest mismatch on the canonicalized element.
/// - Signature verification failure over the canonicalized `SignedInfo`.
///
/// What it does **not** check — do not rely on this function for these:
/// - Full XML-signature-wrapping defence. The URI/ID binding here is only one
///   half. The caller must additionally bound the assertion count for the
///   whole document and confirm that the element it consumes is the element
///   whose ID was verified — see `sp.rs::complete_inner`.
/// - What the caller reads afterwards. The verified `<ds:Signature>` is, by
///   construction, excluded from the digest; a field parser that reads inside
///   it reads unsigned data. Every SAML parser therefore reads through
///   `xml::walk_outside_signatures`.
pub fn verify_signed_element(
    full_xml: &[u8],
    local_name: &str,
    signing_cert_pem: &str,
) -> Result<SignedElement, IdentityError> {
    verify_signed_element_with_any(full_xml, local_name, &[signing_cert_pem])
}

/// [`verify_signed_element`] against a set of trusted certificates: the
/// signature is accepted when it verifies under **any** of them.
///
/// An IdP rolling its signing key publishes the incoming certificate before
/// it switches, so for a while the connector trusts two. Every structural and
/// digest check runs once; only the final RSA check is tried per certificate.
///
/// # Errors
///
/// As [`verify_signed_element`]. With no usable certificate at all, the first
/// certificate's parse error (or [`SamlError::Signature`] for an empty list).
pub fn verify_signed_element_with_any<S: AsRef<str>>(
    full_xml: &[u8],
    local_name: &str,
    signing_certs_pem: &[S],
) -> Result<SignedElement, IdentityError> {
    // Locate the element.
    let range = find_element_range(full_xml, ns::SAMLP, local_name, None)?
        .or(find_element_range(full_xml, ns::SAML, local_name, None)?)
        .ok_or(IdentityError::Saml(SamlError::Signature))?;
    let element_bytes = &full_xml[range.0..range.1];

    // The namespace bindings the element inherits from its ancestors. The
    // element is scanned and canonicalized as a slice; both must see the
    // bindings it has in the document (GA audit 3, round 2).
    let element_scope = in_scope_namespaces(full_xml, &Namespaces::new(), range.0)?;

    // Extract ID and Signature sub-block.
    let element_id = extract_id_attr(element_bytes)?;
    let SignatureFields {
        signature_start,
        signed_info: signed_info_bytes,
        signed_info_scope,
        signature_value: signature_value_b64,
        reference_uri,
        digest: digest_b64,
    } = extract_signature_fields(element_bytes, &element_scope)?;

    // Algorithm-downgrade defence: the transform chain the document declares
    // must be the one we actually apply. Checked before any crypto so a
    // document describing a computation we do not implement is refused
    // outright rather than implicitly reinterpreted (audit 2026-08-28 §25.5).
    enforce_declared_algorithms(&signed_info_bytes)?;

    // Signature-wrapping defense: the Reference URI must be `#<id>`
    // where `id` equals the enclosing element's ID.
    let expected_uri = format!("#{element_id}");
    if reference_uri != expected_uri {
        return Err(IdentityError::Saml(SamlError::Signature));
    }

    // Verify referenced element digest. The enveloped-signature transform
    // removes exactly the signature read above — never any other element —
    // and exclusive C14N renders on the apex every visibly used namespace
    // declaration it inherits (e.g. `xmlns:saml` declared only on the
    // `<Response>`, as Keycloak emits it).
    let canonical_element = canonicalize_with_inherited(
        element_bytes,
        EnvelopedSignature::RemoveAt(signature_start),
        &element_scope,
    )?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical_element);
    let actual_digest = hasher.finalize();
    let expected_digest =
        decode_base64_content(&digest_b64).ok_or(IdentityError::Saml(SamlError::Signature))?;
    if actual_digest.as_slice() != expected_digest.as_slice() {
        return Err(IdentityError::Saml(SamlError::Signature));
    }

    // Check algorithms inside SignedInfo (reject SHA-1 etc).
    let si_str =
        std::str::from_utf8(&signed_info_bytes).map_err(|_| parse_err("SignedInfo not utf8"))?;
    if si_str.contains(alg::SHA1) || si_str.contains(alg::RSA_SHA1) {
        return Err(IdentityError::Saml(SamlError::UnsupportedAlgorithm));
    }
    if !si_str.contains(alg::RSA_SHA256) || !si_str.contains(alg::SHA256) {
        return Err(IdentityError::Saml(SamlError::UnsupportedAlgorithm));
    }

    // Canonicalize SignedInfo in its context: the bindings in scope where it
    // sits (typically `xmlns:ds` — or, Entra-style, the default namespace —
    // declared on the enclosing `<Signature>`). Exclusive C14N renders the
    // visibly used ones on SignedInfo, exactly as the signer computed it.
    let canonical_si = canonicalize_with_inherited(
        &signed_info_bytes,
        EnvelopedSignature::Keep,
        &signed_info_scope,
    )?;

    // Verify signature over canonicalized SignedInfo, under any trusted key.
    let sig_bytes = decode_base64_content(&signature_value_b64)
        .ok_or(IdentityError::Saml(SamlError::Signature))?;
    let mut first_unusable: Option<IdentityError> = None;
    let mut any_usable = false;
    let mut verified = false;
    for pem in signing_certs_pem {
        match parse_cert_public_key(pem.as_ref()) {
            Ok(key) => {
                any_usable = true;
                if key
                    .verify(&RSA_PKCS1_2048_8192_SHA256, &canonical_si, &sig_bytes)
                    .is_ok()
                {
                    verified = true;
                    break;
                }
            }
            Err(e) => {
                first_unusable.get_or_insert(e);
            }
        }
    }
    if !verified {
        // A signature that no usable key verifies is a signature failure; a
        // list with no usable key at all reports why the first one was not.
        return Err(match first_unusable {
            Some(e) if !any_usable => e,
            _ => IdentityError::Saml(SamlError::Signature),
        });
    }

    Ok(SignedElement {
        local_name: local_name.to_string(),
        id: element_id,
        canonical: canonical_element,
    })
}

/// Decodes XML-DSIG base64 content. `ds:CryptoBinary` / `base64Binary` text
/// may be line-wrapped (Shibboleth wraps at 76 columns), so all XML
/// whitespace is removed before decoding.
fn decode_base64_content(text: &str) -> Option<Vec<u8>> {
    let compact: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    B64.decode(compact).ok()
}

/// Splits a PEM bundle — certificates concatenated, as an operator lists an
/// IdP's outgoing and incoming signing certificate during a key rollover —
/// into one PEM string per `CERTIFICATE` block.
///
/// Input with no complete `CERTIFICATE` block is returned unchanged as the
/// single entry, so a malformed value fails verification exactly as before
/// rather than silently becoming "no certificate".
#[must_use]
pub fn split_pem_certificates(pem: &str) -> Vec<String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(begin) = rest.find(BEGIN) {
        let block = &rest[begin..];
        let Some(end) = block.find(END) else {
            break;
        };
        let end = end + END.len();
        out.push(format!("{}\n", &block[..end]));
        rest = &block[end..];
    }
    if out.is_empty() {
        out.push(pem.to_string());
    }
    out
}

/// Checks a connector's `idp_certificate_pem` exactly as the assertion
/// consumer will use it: split with [`split_pem_certificates`], each block
/// parsed by the verifier's own certificate parser. Returns the number of
/// certificates.
///
/// Stricter than login in one way, deliberately: login skips a block it
/// cannot use as long as another verifies, but configuration refuses a
/// bundle with any unusable block — a broken incoming certificate would
/// otherwise surface only when the IdP switches keys.
///
/// # Errors
///
/// Returns a parse error naming the failing block (`certificate N of M`).
/// Certificates are public, but the reason still carries no PEM content.
pub fn validate_idp_certificate_bundle(pem: &str) -> Result<usize, IdentityError> {
    let blocks = split_pem_certificates(pem);
    let total = blocks.len();
    for (i, block) in blocks.iter().enumerate() {
        parse_cert_public_key(block).map_err(|e| {
            let why = match e {
                IdentityError::Saml(SamlError::Parse { reason }) => reason,
                other => other.to_string(),
            };
            parse_err(format!("certificate {} of {total}: {why}", i + 1))
        })?;
    }
    Ok(total)
}

fn extract_id_attr(element_bytes: &[u8]) -> Result<String, IdentityError> {
    // naive but adequate: find the first ID="…" or Id="…" in the root
    // tag (before the first `>`).
    let open_end = element_bytes
        .iter()
        .position(|&b| b == b'>')
        .ok_or_else(|| parse_err("no root close"))?;
    let header =
        std::str::from_utf8(&element_bytes[..=open_end]).map_err(|e| parse_err(e.to_string()))?;
    for key in [" ID=\"", " Id=\""] {
        if let Some(start) = header.find(key) {
            let after = &header[start + key.len()..];
            if let Some(end) = after.find('"') {
                return Ok(after[..end].to_string());
            }
        }
    }
    Err(parse_err("no ID attribute on signed element"))
}

/// The parts of an element's enveloped `<ds:Signature>` the verifier uses.
struct SignatureFields {
    /// Byte offset of the `<ds:Signature>` start tag within the element —
    /// the one element the enveloped-signature transform removes.
    signature_start: usize,
    /// The raw `<ds:SignedInfo>` element.
    signed_info: Vec<u8>,
    /// The namespace bindings in scope for `<ds:SignedInfo>` in the document.
    signed_info_scope: Namespaces,
    /// `<ds:SignatureValue>` text (base64).
    signature_value: String,
    /// `<ds:Reference URI>`.
    reference_uri: String,
    /// `<ds:DigestValue>` text (base64).
    digest: String,
}

fn extract_signature_fields(
    element_bytes: &[u8],
    element_scope: &Namespaces,
) -> Result<SignatureFields, IdentityError> {
    // Find <ds:Signature> as a DIRECT CHILD of the signed element only, by
    // namespace URI (a `ds:` prefix bound elsewhere is not XML-DSIG; an
    // unprefixed `<Signature>` in the DSIG default namespace is).
    //
    // An enveloped signature is by definition a child of what it signs.
    // Searching at any depth would let a signature belonging to a descendant
    // (e.g. the `<Assertion>` inside a `<Response>`) be read as though it
    // were this element's own — audit 2026-08-28 §25.6.
    let sig_range = find_child_element_range_in(element_bytes, element_scope, ns::DS, "Signature")?
        .ok_or(IdentityError::Saml(SamlError::Signature))?;

    // Exactly one. The digest is computed with this signature — and only
    // this one — removed, so a second direct-child `<ds:Signature>` would be
    // covered by the digest while no verifier ever read it. Refusing it keeps
    // "the signature" unambiguous (GA audit 3, G-1).
    if count_child_elements(element_bytes, element_scope, ns::DS, "Signature")? != 1 {
        return Err(IdentityError::Saml(SamlError::Signature));
    }

    let sig_bytes = &element_bytes[sig_range.0..sig_range.1];
    let signature_scope = in_scope_namespaces(element_bytes, element_scope, sig_range.0)?;

    // Only the parts XML-DSIG defines for a signature we verify. Everything
    // in a `<ds:Signature>` except `<ds:SignedInfo>` is outside what the
    // signature covers, so any other child is unsigned content smuggled into
    // the signed element (G-1, "moved signature" variant).
    let (signed_info_range, signature_value) =
        read_signature_children(sig_bytes, &signature_scope)?;
    let signed_info = sig_bytes[signed_info_range.0..signed_info_range.1].to_vec();
    let signed_info_scope = in_scope_namespaces(sig_bytes, &signature_scope, signed_info_range.0)?;

    // Exactly one <ds:Reference> — checked before anything reads one, so the
    // "first reference" the extractors below pick up is the only one there
    // is (audit 2026-08-28 §25.20).
    enforce_single_reference(&signed_info)?;

    // Extract Reference URI.
    let reference_uri = extract_attr_of_child(&signed_info, "Reference", "URI")?;

    // Extract DigestValue.
    let digest = extract_text_element(&signed_info, "DigestValue")?;

    Ok(SignatureFields {
        signature_start: sig_range.0,
        signed_info,
        signed_info_scope,
        signature_value,
        reference_uri,
        digest,
    })
}

/// Reads a `<ds:Signature>`'s direct children, refusing anything but one
/// `<ds:SignedInfo>`, one `<ds:SignatureValue>` and at most one
/// `<ds:KeyInfo>` — all in the XML-DSIG namespace. Returns the
/// `SignedInfo` byte range within `signature` and the `SignatureValue` text.
///
/// XML-DSIG also allows `<ds:Object>` children; Hearth processes none, no
/// SAML IdP it interoperates with emits them, and — like every other part of
/// a signature except `SignedInfo` — their content is not covered by the
/// signature. The SAML field parsers skip the whole `<ds:Signature>` subtree
/// regardless (`xml::walk_outside_signatures`), so this check is a structural
/// tripwire, not the only line of defence.
///
/// # Errors
///
/// Returns [`SamlError::Signature`] on a missing, unexpected or repeated
/// child, and a parse error on malformed XML.
fn read_signature_children(
    signature: &[u8],
    signature_scope: &Namespaces,
) -> Result<((usize, usize), String), IdentityError> {
    let refuse = || IdentityError::Saml(SamlError::Signature);
    let mut signed_info: Option<(usize, usize)> = None;
    let mut signature_value: Option<String> = None;
    let mut key_info = false;
    for child in child_elements(signature, signature_scope)? {
        if child.namespace.as_deref() != Some(ns::DS.as_bytes()) {
            return Err(refuse());
        }
        let repeated = match child.local_name.as_slice() {
            b"SignedInfo" => signed_info.replace(child.range).is_some(),
            b"SignatureValue" => signature_value.replace(child.text).is_some(),
            b"KeyInfo" => std::mem::replace(&mut key_info, true),
            _ => return Err(refuse()),
        };
        if repeated {
            return Err(refuse());
        }
    }
    match (signed_info, signature_value) {
        (Some(range), Some(value)) => Ok((range, value)),
        _ => Err(refuse()),
    }
}

/// The number of `<ds:Reference>` elements a `<ds:SignedInfo>` may carry.
///
/// One. XML-DSIG permits a list and requires every entry to validate; Hearth
/// validates exactly one element per signature and has no representation for
/// the rest, so any other count describes a computation we do not perform.
const MAX_REFERENCES: usize = 1;

/// Refuses a `<ds:SignedInfo>` that does not carry exactly one
/// `<ds:Reference>`.
///
/// `extract_signature_fields` reads the *first* `<ds:Reference URI>` and the
/// *first* `<ds:DigestValue>` and treats them as the whole of what the
/// signature covers. With an unchecked list that is a signature-wrapping
/// primitive: a `SignedInfo` whose first reference names the element being
/// verified passes, while every later reference — naming some other part of
/// the document, with a digest nobody computes — is silently discarded. The
/// verifier then reports "signed" for a document whose signature, read
/// correctly, does not validate (audit 2026-08-28 §25.20).
///
/// Hearth's own signer emits exactly one reference (`build_signed_info`), and
/// `verify_signed_element` digests exactly one element, so "exactly one" is
/// the shape Hearth actually consumes — not an arbitrary small bound with a
/// per-entry check that no caller could use.
///
/// The scan stops at the first reference past [`MAX_REFERENCES`], so a
/// document padded with thousands of `<ds:Reference>` elements is rejected on
/// the second one rather than driving work proportional to the list length.
///
/// # Errors
///
/// Returns [`SamlError::Parse`] when the count is zero or greater than one.
/// The reason is a fixed string — it carries no attacker-supplied bytes.
fn enforce_single_reference(signed_info: &[u8]) -> Result<(), IdentityError> {
    let si = std::str::from_utf8(signed_info).map_err(|_| parse_err("SignedInfo not utf8"))?;

    let mut seen = 0usize;
    let mut from = 0usize;
    while let Some(rel) = next_start_tag(&si[from..], "Reference") {
        seen += 1;
        if seen > MAX_REFERENCES {
            return Err(parse_err(
                "SignedInfo must carry exactly one <ds:Reference>; found more than one",
            ));
        }
        from += rel;
    }

    if seen == 0 {
        return Err(parse_err(
            "SignedInfo must carry exactly one <ds:Reference>; found none",
        ));
    }
    Ok(())
}

/// Refuses a `<ds:SignedInfo>` whose declared canonicalization method or
/// reference transform chain is not the one Hearth implements.
///
/// Hearth's suite is locked: exclusive C14N 1.0 without comments, and a
/// reference transform list of `enveloped-signature` followed by exclusive
/// C14N. `verify_signed_element` applies exactly that chain regardless of
/// what the document says, so a `SignedInfo` declaring anything else
/// describes a computation we are not performing — inclusive C14N,
/// `#WithComments`, XPath filtering or XSLT. Reading the declaration turns a
/// silent mismatch into an explicit downgrade rejection.
fn enforce_declared_algorithms(signed_info: &[u8]) -> Result<(), IdentityError> {
    let si = std::str::from_utf8(signed_info).map_err(|_| parse_err("SignedInfo not utf8"))?;

    if declared_c14n_method(si).as_deref() != Some(alg::EXC_C14N) {
        return Err(IdentityError::Saml(SamlError::UnsupportedAlgorithm));
    }

    let transforms =
        declared_transforms(si).ok_or(IdentityError::Saml(SamlError::UnsupportedAlgorithm))?;
    let declares_enveloped = transforms.iter().any(|t| t == alg::ENVELOPED);
    let all_supported = transforms
        .iter()
        .all(|t| t == alg::ENVELOPED || t == alg::EXC_C14N);
    if !declares_enveloped || !all_supported {
        return Err(IdentityError::Saml(SamlError::UnsupportedAlgorithm));
    }
    Ok(())
}

/// Returns the `Algorithm` of the first `<ds:CanonicalizationMethod>`.
fn declared_c14n_method(signed_info: &str) -> Option<String> {
    let at = next_start_tag(signed_info, "CanonicalizationMethod")?;
    tag_attr(&signed_info[at..], "Algorithm")
}

/// Returns every `<ds:Transform>` `Algorithm` in document order, or `None`
/// when the reference declares no `<ds:Transforms>` container at all.
///
/// A `<ds:Transform>` carrying no `Algorithm` yields an empty string, which
/// no supported algorithm URI equals — so it is rejected by the caller
/// rather than silently skipped.
fn declared_transforms(signed_info: &str) -> Option<Vec<String>> {
    next_start_tag(signed_info, "Transforms")?;
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = next_start_tag(&signed_info[from..], "Transform") {
        let at = from + rel;
        out.push(tag_attr(&signed_info[at..], "Algorithm").unwrap_or_default());
        from = at;
    }
    Some(out)
}

/// Finds the next start tag for `local`, tolerating an optional `ds:`
/// prefix, and returns the byte offset just past the element name.
///
/// Requires a tag-name terminator so a longer name that merely starts with
/// `local` does not match: `<ds:Transforms>` is not a `<ds:Transform>`.
fn next_start_tag(s: &str, local: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(rel) = s[from..].find('<') {
        let at = from + rel;
        let after = &s[at + 1..];
        let unprefixed = after.strip_prefix("ds:").unwrap_or(after);
        if let Some(tail) = unprefixed.strip_prefix(local) {
            if tail.starts_with([' ', '\t', '\r', '\n', '/', '>']) {
                return Some(s.len() - tail.len());
            }
        }
        from = at + 1;
    }
    None
}

/// Reads an attribute value out of a start tag whose name has already been
/// consumed, bounded to that tag's closing `>`.
fn tag_attr(tag_tail: &str, attr_name: &str) -> Option<String> {
    let end = tag_tail.find('>')?;
    let header = &tag_tail[..end];
    let key = format!("{attr_name}=\"");
    let at = header.find(&key)?;
    let after = &header[at + key.len()..];
    let close = after.find('"')?;
    Some(after[..close].to_string())
}

fn extract_text_element(bytes: &[u8], local: &str) -> Result<String, IdentityError> {
    // Simple substring search tolerant of optional ds: prefix.
    let s = std::str::from_utf8(bytes).map_err(|e| parse_err(e.to_string()))?;
    for name in [format!("<ds:{local}>"), format!("<{local}>")] {
        if let Some(start) = s.find(&name) {
            let after = &s[start + name.len()..];
            if let Some(end) = after.find("</") {
                return Ok(after[..end].trim().to_string());
            }
        }
    }
    Err(parse_err(format!("{local} element not found")))
}

fn extract_attr_of_child(
    bytes: &[u8],
    child_local: &str,
    attr_name: &str,
) -> Result<String, IdentityError> {
    let s = std::str::from_utf8(bytes).map_err(|e| parse_err(e.to_string()))?;
    for name in [format!("<ds:{child_local} "), format!("<{child_local} ")] {
        if let Some(start) = s.find(&name) {
            let after = &s[start + name.len()..];
            let attr_key = format!("{attr_name}=\"");
            if let Some(akey) = after.find(&attr_key) {
                let after2 = &after[akey + attr_key.len()..];
                if let Some(end) = after2.find('"') {
                    return Ok(after2[..end].to_string());
                }
            }
        }
    }
    Err(parse_err(format!("{child_local}@{attr_name} not found")))
}

/// Checks that `pem` is a PEM certificate whose RSA public key Hearth can
/// actually use to verify a SAML signature.
///
/// Used at config-validation time so a malformed `sp_certificate_pem` is
/// refused at boot rather than at the first login attempt (audit 2026-08-28
/// §4.10#4).
///
/// # Errors
///
/// Returns `Err` when the PEM armor is unreadable or the certificate does
/// not carry an RSA public key.
pub fn validate_signing_cert_pem(pem: &str) -> Result<(), IdentityError> {
    parse_cert_public_key(pem).map(|_| ())
}

/// Parses a PEM certificate and extracts the RSA public key components
/// suitable for `ring::signature` verification.
fn parse_cert_public_key(pem: &str) -> Result<RsaPublicKeyComponents<Vec<u8>>, IdentityError> {
    // Strip PEM armor and decode DER.
    let der = decode_pem(pem).ok_or_else(|| parse_err("invalid PEM certificate"))?;
    // Walk DER to find the SubjectPublicKeyInfo. For RSA certs the
    // structure is:
    //   Certificate ::= SEQUENCE { tbsCertificate, sigAlg, sigValue }
    //   tbsCertificate ::= SEQUENCE { ..., subject, SubjectPublicKeyInfo, ...}
    //   SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    //     -> BIT STRING wraps RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    //
    // We use a minimal DER walker rather than pulling in an X.509 crate.
    let (modulus, exponent) =
        extract_rsa_modulus_exponent(&der).ok_or_else(|| parse_err("cert is not RSA"))?;
    Ok(RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    })
}

fn decode_pem(pem: &str) -> Option<Vec<u8>> {
    let trimmed = pem.trim();
    let begin = trimmed.find("-----BEGIN")?;
    let begin_end = trimmed[begin..].find('\n')? + begin;
    let end = trimmed.find("-----END")?;
    let body: String = trimmed[begin_end..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    B64.decode(body).ok()
}

fn extract_rsa_modulus_exponent(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Parse outer Certificate SEQUENCE.
    let (cert_content, _rest) = der_unwrap_sequence(der)?;
    // Parse tbsCertificate SEQUENCE.
    let (tbs, _after_tbs) = der_unwrap_sequence(cert_content)?;
    // Walk tbsCertificate. We look for ANY SEQUENCE whose body begins
    // with AlgorithmIdentifier(rsaEncryption). Most SEQUENCEs in TBS
    // (issuer Name, validity, etc.) won't match — we skip them via
    // `Option::is_none` short-circuits.
    const RSA_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
    let mut cursor = tbs;
    while !cursor.is_empty() {
        let start_tag = cursor[0];
        let Some((content, after)) = der_parse_tlv(cursor) else {
            break;
        };
        cursor = after;
        if start_tag != 0x30 {
            continue;
        }
        // Candidate SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
        let Some((alg_content, rest_after_alg)) = der_unwrap_sequence(content) else {
            continue;
        };
        // AlgorithmIdentifier SEQUENCE: OID comes first.
        if alg_content.first() != Some(&0x06) {
            continue;
        }
        let Some((oid_bytes, _)) = der_parse_tlv(alg_content) else {
            continue;
        };
        if oid_bytes != RSA_OID {
            continue;
        }
        // Next should be BIT STRING wrapping RSAPublicKey.
        if rest_after_alg.is_empty() || rest_after_alg[0] != 0x03 {
            continue;
        }
        let Some((bit_string, _)) = der_parse_tlv(rest_after_alg) else {
            continue;
        };
        if bit_string.is_empty() {
            continue;
        }
        let rsa_pubkey_der = &bit_string[1..];
        let Some((rsa_content, _)) = der_unwrap_sequence(rsa_pubkey_der) else {
            continue;
        };
        if rsa_content.first() != Some(&0x02) {
            continue;
        }
        let Some((modulus_bytes, exp_area)) = der_parse_tlv(rsa_content) else {
            continue;
        };
        if exp_area.first() != Some(&0x02) {
            continue;
        }
        let Some((exp_bytes, _)) = der_parse_tlv(exp_area) else {
            continue;
        };
        let modulus = strip_leading_zero(modulus_bytes).to_vec();
        let exponent = strip_leading_zero(exp_bytes).to_vec();
        return Some((modulus, exponent));
    }
    None
}

fn der_unwrap_sequence(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.first() != Some(&0x30) {
        return None;
    }
    der_parse_tlv(input)
}

fn der_parse_tlv(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.len() < 2 {
        return None;
    }
    let mut i = 1;
    let first_len = input[i];
    let (len, len_len) = if first_len & 0x80 == 0 {
        (first_len as usize, 1)
    } else {
        let n = (first_len & 0x7F) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for b in &input[i + 1..i + 1 + n] {
            len = (len << 8) | (*b as usize);
        }
        (len, 1 + n)
    };
    i += len_len;
    if input.len() < i + len {
        return None;
    }
    let content = &input[i..i + len];
    let rest = &input[i + len..];
    Some((content, rest))
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    if bytes.first() == Some(&0x00) && bytes.len() > 1 {
        &bytes[1..]
    } else {
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::tokens::RsaSigningKey;

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());

        let payload = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">hello</Assertion>"#;
        let signed = sign_element(payload, "a1", &key).expect("sign");
        let verified = verify_signed_element(&signed, "Assertion", &cert_pem).expect("verify");
        assert_eq!(verified.id, "a1");
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());

        let payload = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">hello</Assertion>"#;
        let mut signed = sign_element(payload, "a1", &key).expect("sign");
        // Tamper with the element content.
        let idx = signed
            .windows(5)
            .position(|w| w == b"hello")
            .expect("hello bytes present");
        signed[idx] = b'H';
        let result = verify_signed_element(&signed, "Assertion", &cert_pem);
        assert!(matches!(
            result,
            Err(IdentityError::Saml(SamlError::Signature))
        ));
    }

    fn cert_der_to_pem(der: &[u8]) -> String {
        let b64 = B64.encode(der);
        let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is valid utf8"));
            out.push('\n');
        }
        out.push_str("-----END CERTIFICATE-----\n");
        out
    }

    /// Signs a trivial `<Assertion ID="a1">` and returns `(signed_xml, pem)`.
    fn signed_assertion() -> (Vec<u8>, String) {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());
        let payload =
            br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">hello</Assertion>"#;
        let signed = sign_element(payload, "a1", &key).expect("sign");
        (signed, cert_pem)
    }

    /// Rewrites the first occurrence of `from` to `to` inside a signed
    /// document, panicking when the needle is absent so a silently-skipped
    /// mutation cannot make a rejection test pass vacuously.
    fn replace_once(xml: &[u8], from: &str, to: &str) -> Vec<u8> {
        let s = std::str::from_utf8(xml).expect("signed doc is utf8");
        assert!(s.contains(from), "needle {from:?} not present in document");
        s.replacen(from, to, 1).into_bytes()
    }

    // ---------------------------------------------------------------
    // 25.6 — `<ds:Signature>` discovery must not descend past a direct child
    // ---------------------------------------------------------------

    /// A `<ds:Signature>` nested below the signed element's direct children
    /// is NOT that element's signature and must never be read as one.
    ///
    /// The nested block here is deliberately incomplete — it has no
    /// `<ds:SignatureValue>` — so *reading* it is observable: field
    /// extraction fails with `SamlError::Parse`. Correct behaviour is to
    /// never see it at all and report a missing signature
    /// (`SamlError::Signature`).
    #[test]
    fn nested_signature_is_not_read_as_the_elements_own() {
        let (_, cert_pem) = signed_assertion();
        let xml = br##"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1"><Wrapper><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:Reference URI="#a1"><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo></ds:Signature></Wrapper></Assertion>"##;

        let err = verify_signed_element(xml, "Assertion", &cert_pem)
            .err()
            .expect("an element with no direct-child signature must be rejected");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::Signature)),
            "nested <ds:Signature> was read as the element's own signature: {err:?}"
        );
    }

    /// The companion positive case: a signature that IS a direct child is
    /// still found. Pairs with the test above so the depth constraint cannot
    /// be satisfied by simply never finding a signature.
    #[test]
    fn direct_child_signature_is_still_found() {
        let (signed, cert_pem) = signed_assertion();
        let verified = verify_signed_element(&signed, "Assertion", &cert_pem).expect("verify");
        assert_eq!(verified.id, "a1");
    }

    // ---------------------------------------------------------------
    // 25.5 — declared CanonicalizationMethod / Transforms are enforced
    // ---------------------------------------------------------------

    /// A `SignedInfo` declaring inclusive C14N must be refused as an
    /// algorithm downgrade, not merely fail the signature check.
    #[test]
    fn inclusive_canonicalization_method_rejected() {
        let (signed, cert_pem) = signed_assertion();
        let tampered = replace_once(
            &signed,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">"#,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315">"#,
        );
        let err = verify_signed_element(&tampered, "Assertion", &cert_pem)
            .err()
            .expect("inclusive c14n must be rejected");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::UnsupportedAlgorithm)),
            "declared CanonicalizationMethod not enforced: {err:?}"
        );
    }

    /// `#WithComments` exclusive C14N is a different algorithm and must be
    /// refused rather than silently canonicalized without comments.
    #[test]
    fn exc_c14n_with_comments_rejected() {
        let (signed, cert_pem) = signed_assertion();
        let tampered = replace_once(
            &signed,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">"#,
            r#"<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments">"#,
        );
        let err = verify_signed_element(&tampered, "Assertion", &cert_pem)
            .err()
            .expect("#WithComments must be rejected");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::UnsupportedAlgorithm)),
            "#WithComments canonicalization not enforced: {err:?}"
        );
    }

    /// An XSLT transform is the classic XML-DSIG code-execution vector. It
    /// must be refused at the declaration, not implicitly ignored.
    #[test]
    fn xslt_transform_rejected() {
        let (signed, cert_pem) = signed_assertion();
        let tampered = replace_once(
            &signed,
            r#"<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">"#,
            r#"<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">"#,
        );
        let err = verify_signed_element(&tampered, "Assertion", &cert_pem)
            .err()
            .expect("XSLT transform must be rejected");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::UnsupportedAlgorithm)),
            "declared <ds:Transform> list not enforced: {err:?}"
        );
    }

    /// Hearth always applies the enveloped-signature transform when it
    /// digests the element. A reference that does not declare it describes a
    /// different computation and must be refused.
    #[test]
    fn missing_enveloped_transform_rejected() {
        let (signed, cert_pem) = signed_assertion();
        let tampered = replace_once(
            &signed,
            r#"<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>"#,
            "",
        );
        let err = verify_signed_element(&tampered, "Assertion", &cert_pem)
            .err()
            .expect("a reference without the enveloped transform must be rejected");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::UnsupportedAlgorithm)),
            "missing enveloped-signature transform not enforced: {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // 25.20 — the `<ds:Reference>` list is bounded and validated
    // ---------------------------------------------------------------

    /// A `<ds:Reference>` block that is well-formed and declares the exact
    /// transform chain 25.5 demands, so appending it isolates the
    /// *reference count* as the only thing wrong with the document.
    fn extra_reference(uri: &str) -> String {
        let env = alg::ENVELOPED;
        let c14n = alg::EXC_C14N;
        let dig = alg::SHA256;
        let value = B64.encode([0u8; 32]);
        // Positional arguments, not inline capture: `format_args!` refuses to
        // capture named variables when the format string comes out of a macro,
        // and `concat!` is a macro.
        format!(
            concat!(
                r#"<ds:Reference URI="{0}"><ds:Transforms>"#,
                r#"<ds:Transform Algorithm="{1}"></ds:Transform>"#,
                r#"<ds:Transform Algorithm="{2}"></ds:Transform>"#,
                r#"</ds:Transforms><ds:DigestMethod Algorithm="{3}"></ds:DigestMethod>"#,
                r#"<ds:DigestValue>{4}</ds:DigestValue></ds:Reference>"#
            ),
            uri, env, c14n, dig, value
        )
    }

    /// Signs `<Assertion ID="a1">hello</Assertion>` after letting `rewrite`
    /// rebuild the `<ds:SignedInfo>`.
    ///
    /// The RSA signature is computed over whatever `rewrite` returns, so the
    /// resulting document is *genuinely signed* by the returned certificate.
    /// That is what makes the reference-count tests non-vacuous: every other
    /// check in `verify_signed_element` — declared algorithms, URI/ID
    /// binding, element digest, `SignedInfo` signature — passes, so an
    /// acceptance can only mean the reference list went unchecked.
    fn signed_assertion_with_rewritten_signed_info(
        rewrite: &dyn Fn(&str) -> String,
    ) -> (Vec<u8>, String) {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());
        let payload =
            br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">hello</Assertion>"#;

        let canonical =
            canonicalize(payload, EnvelopedSignature::Keep).expect("canonicalize element");
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let digest_b64 = B64.encode(hasher.finalize());

        let signed_info = rewrite(&build_signed_info("a1", &digest_b64));
        let canonical_si = canonicalize(signed_info.as_bytes(), EnvelopedSignature::Keep)
            .expect("canonicalize si");
        let signature_b64 = B64.encode(key.sign(&canonical_si).expect("sign"));
        let signature_xml =
            build_signature_block(&signed_info, &signature_b64, &B64.encode(key.cert_der()));

        let open_end = payload
            .iter()
            .position(|&b| b == b'>')
            .expect("root tag closes");
        let mut out = Vec::with_capacity(payload.len() + signature_xml.len());
        out.extend_from_slice(&payload[..=open_end]);
        out.extend_from_slice(signature_xml.as_bytes());
        out.extend_from_slice(&payload[open_end + 1..]);
        (out, cert_pem)
    }

    /// Asserts the document was refused with a `Parse` error naming the
    /// reference-count rule — not merely refused, which the signature check
    /// would also do for a tampered document.
    fn assert_reference_count_rejected(result: Result<SignedElement, IdentityError>, case: &str) {
        let err = result
            .err()
            .unwrap_or_else(|| panic!("{case}: must be rejected"));
        match err {
            IdentityError::Saml(SamlError::Parse { ref reason }) => assert!(
                reason.contains("exactly one <ds:Reference>"),
                "{case}: rejected for the wrong reason: {reason}"
            ),
            other => panic!("{case}: expected a reference-count Parse error, got {other:?}"),
        }
    }

    /// The defect: a `SignedInfo` carrying a genuine reference for `#a1`
    /// followed by a second reference naming something else. The whole
    /// `SignedInfo` is legitimately signed, so before the count check this
    /// document *verified* — the second reference was read by nobody and its
    /// digest was never computed.
    #[test]
    fn second_reference_in_signed_info_rejected() {
        let (signed, cert_pem) = signed_assertion_with_rewritten_signed_info(&|si| {
            si.replace(
                "</ds:SignedInfo>",
                &format!("{}</ds:SignedInfo>", extra_reference("#wrapped")),
            )
        });
        assert_reference_count_rejected(
            verify_signed_element(&signed, "Assertion", &cert_pem),
            "two <ds:Reference> elements",
        );
    }

    /// The bound: a padded list is refused, and refused for the count — not
    /// left to fail some later check by accident.
    #[test]
    fn many_references_in_signed_info_rejected() {
        let extras: String = (0..64)
            .map(|i| extra_reference(&format!("#r{i}")))
            .collect();
        let (signed, cert_pem) = signed_assertion_with_rewritten_signed_info(&|si| {
            si.replace("</ds:SignedInfo>", &format!("{extras}</ds:SignedInfo>"))
        });
        assert_reference_count_rejected(
            verify_signed_element(&signed, "Assertion", &cert_pem),
            "sixty-five <ds:Reference> elements",
        );
    }

    /// A `SignedInfo` with no reference at all covers nothing. It must be
    /// refused by the count rule, not stumble into a missing-attribute parse
    /// error further down.
    #[test]
    fn signed_info_with_no_reference_rejected() {
        let (signed, cert_pem) = signed_assertion_with_rewritten_signed_info(&|si| {
            let open = si.find("<ds:Reference ").expect("reference present");
            let close = si.find("</ds:Reference>").expect("reference closes");
            let mut out = String::from(&si[..open]);
            out.push_str(&si[close + "</ds:Reference>".len()..]);
            out
        });
        assert_reference_count_rejected(
            verify_signed_element(&signed, "Assertion", &cert_pem),
            "zero <ds:Reference> elements",
        );
    }

    /// The companion positive case: the single-reference document Hearth
    /// itself emits still verifies, so the count rule cannot be satisfied by
    /// rejecting everything.
    #[test]
    fn single_reference_document_still_verifies() {
        let (signed, cert_pem) =
            signed_assertion_with_rewritten_signed_info(&|si: &str| si.to_string());
        let verified = verify_signed_element(&signed, "Assertion", &cert_pem)
            .expect("a single-reference signature must still verify");
        assert_eq!(verified.id, "a1");
    }

    // ---------------------------------------------------------------
    // GA audit 3, G-1 — one enveloped signature per element, and nothing
    // but SignedInfo / SignatureValue / KeyInfo inside it
    // ---------------------------------------------------------------

    /// Signs `payload` exactly as `sign_element` does but WITHOUT its
    /// "already signed" guard, so a test can produce an element that carries
    /// a second, digest-covered `<ds:Signature>` — the one shape only the
    /// count rule can reject.
    fn sign_over(payload: &[u8], id: &str) -> (Vec<u8>, String) {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());
        let canonical = canonicalize(payload, EnvelopedSignature::Keep).expect("canon");
        let digest_b64 = B64.encode(Sha256::digest(&canonical));
        let signed_info = build_signed_info(id, &digest_b64);
        let canonical_si =
            canonicalize(signed_info.as_bytes(), EnvelopedSignature::Keep).expect("canon si");
        let signature_b64 = B64.encode(key.sign(&canonical_si).expect("sign"));
        let signature_xml =
            build_signature_block(&signed_info, &signature_b64, &B64.encode(key.cert_der()));
        let open_end = payload.iter().position(|&b| b == b'>').expect("root tag");
        let mut out = payload[..=open_end].to_vec();
        out.extend_from_slice(signature_xml.as_bytes());
        out.extend_from_slice(&payload[open_end + 1..]);
        (out, cert_pem)
    }

    /// Control for [`second_direct_child_signature_rejected`]: `sign_over` on
    /// an ordinary payload verifies, so the helper itself is sound.
    #[test]
    fn sign_over_produces_a_verifiable_signature() {
        let payload =
            br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">hello</Assertion>"#;
        let (signed, cert_pem) = sign_over(payload, "a1");
        let verified = verify_signed_element(&signed, "Assertion", &cert_pem).expect("verify");
        assert_eq!(verified.id, "a1");
    }

    /// Two direct-child `<ds:Signature>` elements are refused even when the
    /// digest would match. Here the second signature was part of the payload
    /// the key signed, so with the first one removed the digest is correct —
    /// only the one-signature rule stands between this and "verified".
    #[test]
    fn second_direct_child_signature_rejected() {
        let payload = br#"<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="a1">hello<ds:Signature><ds:SignedInfo></ds:SignedInfo></ds:Signature></Assertion>"#;
        let (signed, cert_pem) = sign_over(payload, "a1");
        let err = verify_signed_element(&signed, "Assertion", &cert_pem)
            .err()
            .expect("an element with two direct-child signatures must be rejected");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::Signature)),
            "wrong error: {err:?}"
        );
    }

    /// Anything but SignedInfo / SignatureValue / one KeyInfo inside the
    /// verified `<ds:Signature>` is refused. The signature is valid in every
    /// case (the verified signature is removed from the digest), so only the
    /// shape rule can reject these.
    #[test]
    fn signature_with_unexpected_children_rejected() {
        let cases = [
            (
                "foreign element after KeyInfo",
                "</ds:KeyInfo>",
                "</ds:KeyInfo><Subject>ceo</Subject>",
            ),
            (
                "ds:Object",
                "</ds:KeyInfo>",
                "</ds:KeyInfo><ds:Object>x</ds:Object>",
            ),
            (
                "second KeyInfo",
                "</ds:KeyInfo>",
                "</ds:KeyInfo><ds:KeyInfo></ds:KeyInfo>",
            ),
            (
                "second SignatureValue",
                "<ds:KeyInfo>",
                "<ds:SignatureValue>AA==</ds:SignatureValue><ds:KeyInfo>",
            ),
        ];
        for (case, anchor, replacement) in cases {
            let (signed, cert_pem) = signed_assertion();
            let tampered = replace_once(&signed, anchor, replacement);
            let err = verify_signed_element(&tampered, "Assertion", &cert_pem)
                .err()
                .unwrap_or_else(|| panic!("{case}: must be rejected"));
            assert!(
                matches!(err, IdentityError::Saml(SamlError::Signature)),
                "{case}: wrong error: {err:?}"
            );
        }
    }

    /// Whitespace between a pretty-printed element's children — including
    /// right before the `<ds:Signature>` — does not disturb which element the
    /// enveloped transform removes.
    #[test]
    fn pretty_printed_signature_position_still_verifies() {
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let cert_pem = cert_der_to_pem(key.cert_der());
        let payload = b"<Assertion xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"a1\">\n  <Subject>alice</Subject>\n</Assertion>";
        let signed =
            String::from_utf8(sign_element(payload, "a1", &key).expect("sign")).expect("utf8");
        // Move the signature after the leading whitespace text node.
        let start = signed.find("<ds:Signature").expect("signature");
        let end = signed.find("</ds:Signature>").expect("end") + "</ds:Signature>".len();
        let signature = &signed[start..end];
        let without = format!("{}{}", &signed[..start], &signed[end..]);
        let moved = without.replacen("\n  <Subject>", &format!("\n  {signature}<Subject>"), 1);
        assert_ne!(moved, signed, "the signature must have moved");
        let verified =
            verify_signed_element(moved.as_bytes(), "Assertion", &cert_pem).expect("verify");
        assert_eq!(verified.id, "a1");
    }

    /// The signer refuses an element that already carries a signature: the
    /// output would carry two, which the verifier rejects.
    #[test]
    fn sign_element_refuses_an_already_signed_element() {
        let (signed, _) = signed_assertion();
        let key = RsaSigningKey::generate("hearth-test", 365).expect("key");
        let err =
            sign_element(&signed, "a1", &key).expect_err("signing a signed element must fail");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::Parse { .. })),
            "wrong error: {err:?}"
        );
    }

    // ---------------------------------------------------------------
    // GA audit 3 round 2 — certificate rollover, wrapped base64
    // ---------------------------------------------------------------

    /// A bundle splits into one PEM per certificate, each usable on its own.
    #[test]
    fn split_pem_certificates_separates_a_bundle() {
        let a = cert_der_to_pem(RsaSigningKey::generate("a", 365).expect("key").cert_der());
        let b = cert_der_to_pem(RsaSigningKey::generate("b", 365).expect("key").cert_der());
        let parts = split_pem_certificates(&format!("{a}\n{b}"));
        assert_eq!(parts.len(), 2, "{parts:?}");
        for part in &parts {
            validate_signing_cert_pem(part).expect("each block is a usable certificate");
        }
        assert_eq!(split_pem_certificates(&a).len(), 1);
        assert_eq!(split_pem_certificates("not a pem"), ["not a pem"]);
    }

    /// Any listed certificate may verify; an unusable entry does not stop
    /// the search, and a list with no usable entry says why.
    #[test]
    fn verify_with_any_certificate() {
        let (signed, cert_pem) = signed_assertion();
        let other = cert_der_to_pem(RsaSigningKey::generate("x", 365).expect("key").cert_der());
        let verified =
            verify_signed_element_with_any(&signed, "Assertion", &[other.as_str(), &cert_pem])
                .expect("the second certificate verifies");
        assert_eq!(verified.id, "a1");
        verify_signed_element_with_any(&signed, "Assertion", &["garbage", cert_pem.as_str()])
            .expect("an unusable entry is skipped");

        let wrong = verify_signed_element_with_any(&signed, "Assertion", &[other.as_str()])
            .err()
            .expect("a non-matching certificate must not verify");
        assert!(
            matches!(wrong, IdentityError::Saml(SamlError::Signature)),
            "{wrong:?}"
        );
        let unusable = verify_signed_element_with_any(&signed, "Assertion", &["garbage"])
            .err()
            .expect("no usable certificate");
        assert!(
            matches!(unusable, IdentityError::Saml(SamlError::Parse { .. })),
            "{unusable:?}"
        );
        let empty: [&str; 0] = [];
        let none = verify_signed_element_with_any(&signed, "Assertion", &empty)
            .err()
            .expect("an empty list verifies nothing");
        assert!(
            matches!(none, IdentityError::Saml(SamlError::Signature)),
            "{none:?}"
        );
    }

    /// XML-DSIG base64 content may be line-wrapped (Shibboleth wraps at 76
    /// columns). A signature whose signed `DigestValue` and whose
    /// `SignatureValue` are both wrapped still verifies.
    #[test]
    fn line_wrapped_base64_values_still_verify() {
        fn wrap_between(s: &str, open: &str, close: &str) -> String {
            let start = s.find(open).expect("open tag") + open.len();
            let end = s.find(close).expect("close tag");
            let lines: Vec<&str> = s.as_bytes()[start..end]
                .chunks(16)
                .map(|c| std::str::from_utf8(c).expect("base64 is ASCII"))
                .collect();
            format!("{}\n{}\n{}", &s[..start], lines.join("\n"), &s[end..])
        }
        let (signed, cert_pem) = signed_assertion_with_rewritten_signed_info(&|si| {
            wrap_between(si, "<ds:DigestValue>", "</ds:DigestValue>")
        });
        let signed = wrap_between(
            std::str::from_utf8(&signed).expect("utf8"),
            "<ds:SignatureValue>",
            "</ds:SignatureValue>",
        );
        assert!(
            signed.contains("<ds:SignatureValue>\n"),
            "fixture must be wrapped"
        );
        match verify_signed_element(signed.as_bytes(), "Assertion", &cert_pem) {
            Ok(verified) => assert_eq!(verified.id, "a1"),
            Err(error) => panic!("line-wrapped base64 rejected: {error:?}"),
        }
    }

    /// A reference carrying no `<ds:Transforms>` at all is equally
    /// unrepresentable for our fixed algorithm suite.
    #[test]
    fn missing_transforms_element_rejected() {
        let (signed, cert_pem) = signed_assertion();
        let tampered = replace_once(
            &signed,
            r#"<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms>"#,
            "",
        );
        let err = verify_signed_element(&tampered, "Assertion", &cert_pem)
            .err()
            .expect("a reference with no transforms must be rejected");
        assert!(
            matches!(err, IdentityError::Saml(SamlError::UnsupportedAlgorithm)),
            "absent <ds:Transforms> not enforced: {err:?}"
        );
    }
}
