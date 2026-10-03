//! HTTP-Redirect (DEFLATE + base64 + URL) and HTTP-POST bindings.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use std::io::Write as _;

use super::xml::parse_err;
use crate::identity::error::IdentityError;

/// Builds a fully-qualified redirect URL per SAML HTTP-Redirect binding.
///
/// `base` is the upstream SSO or SLO URL. `saml_xml` is the raw
/// `<AuthnRequest>` or `<LogoutRequest>` XML. `relay_state` is an
/// opaque echo token. Signature parameters are not included in this
/// minimal implementation — Hearth as SP sends unsigned redirect
/// requests (per config default). Signed redirect bindings require
/// URL-encoded signing of a specific parameter concatenation which we
/// leave as a later enhancement.
pub fn build_redirect_url(
    base: &str,
    param_name: &str,
    saml_xml: &[u8],
    relay_state: Option<&str>,
) -> Result<String, IdentityError> {
    // DEFLATE (raw, no zlib wrapper).
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
    enc.write_all(saml_xml)
        .map_err(|e| parse_err(format!("deflate: {e}")))?;
    let deflated = enc
        .finish()
        .map_err(|e| parse_err(format!("deflate finish: {e}")))?;
    let b64 = B64.encode(&deflated);
    let urlenc = url_encode(&b64);

    let sep = if base.contains('?') { '&' } else { '?' };
    let mut out = format!("{base}{sep}{param_name}={urlenc}");
    if let Some(rs) = relay_state {
        out.push_str("&RelayState=");
        out.push_str(&url_encode(rs));
    }
    Ok(out)
}

/// Decodes an inbound HTTP-POST form body SAML payload (base64 only,
/// no DEFLATE).
pub fn parse_post_form_saml(b64_value: &str) -> Result<Vec<u8>, IdentityError> {
    B64.decode(b64_value.trim().as_bytes())
        .map_err(|e| parse_err(format!("base64 decode: {e}")))
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::DeflateDecoder;

    /// Reverses `build_redirect_url` for one parameter: percent-decode,
    /// base64-decode, inflate. Test-only — Hearth no longer receives
    /// HTTP-Redirect messages (the IdP side was removed in 3.0.0).
    fn decode_param(param: &str) -> Vec<u8> {
        let bytes = param.as_bytes();
        let mut unescaped = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("hex");
                unescaped.push(u8::from_str_radix(hex, 16).expect("hex digit"));
                i += 3;
            } else {
                unescaped.push(bytes[i]);
                i += 1;
            }
        }
        let deflated = B64.decode(&unescaped).expect("base64");
        let mut dec = DeflateDecoder::new(Vec::new());
        dec.write_all(&deflated).expect("inflate");
        dec.finish().expect("finish")
    }

    #[test]
    fn redirect_roundtrip() {
        let xml = b"<AuthnRequest>hello</AuthnRequest>";
        let url = build_redirect_url("https://idp.example/sso", "SAMLRequest", xml, Some("rs1"))
            .expect("build");
        assert!(url.starts_with("https://idp.example/sso?SAMLRequest="));
        assert!(url.contains("RelayState=rs1"));
        let param = url
            .split("SAMLRequest=")
            .nth(1)
            .expect("SAMLRequest param present")
            .split('&')
            .next()
            .expect("first segment");
        assert_eq!(decode_param(param), xml);
    }

    #[test]
    fn redirect_url_appends_to_an_existing_query() {
        let url = build_redirect_url(
            "https://idp.example/sso?tenant=a",
            "SAMLRequest",
            b"<x/>",
            None,
        )
        .expect("build");
        assert!(
            url.starts_with("https://idp.example/sso?tenant=a&SAMLRequest="),
            "got {url}"
        );
    }

    #[test]
    fn post_form_value_round_trips_base64() {
        let decoded = parse_post_form_saml(&B64.encode(b"<Response>x</Response>")).expect("decode");
        assert_eq!(decoded, b"<Response>x</Response>");
        parse_post_form_saml("not base64 !!!").expect_err("garbage must be refused");
    }
}
