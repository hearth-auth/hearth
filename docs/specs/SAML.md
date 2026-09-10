# SAML 2.0 — Normative Specification

Status: **Normative.** Requirement levels follow RFC 2119 (MUST / SHOULD / MAY).
Scope: Hearth's SAML 2.0 **Service Provider (SP)** Web-SSO and Single-Logout
support for inbound federation. The implementation lives under
`src/identity/federation/saml/`; this document is the authoritative contract for
its security-relevant behavior. Where code and this document disagree, that is a
bug in one of them — file an issue.

Related specs: `docs/specs/AUTHORIZATION.md` (claim mapping after login),
`docs/specs/OIDC.md` (the OIDC federation path), `docs/specs/ARCHITECTURE.md`
(layering rules). SCIM has its own companion spec (`docs/specs/SCIM.md`).

Adversarial test coverage: `tests/abuse_federation.rs` (A-29*) and
`tests/abuse_scim_saml.rs` (A-35b/c). Every MUST below that is externally
observable has a corresponding rejection test.

---

## 1. Role and profile

- Hearth acts **only as a SAML SP** (Relying Party). It is not a SAML IdP for
  third parties. (Hearth issues its own metadata as an SP; see §7.)
- Supported profile: **Web Browser SSO Profile** and **Single Logout Profile**
  of SAML 2.0 (`urn:oasis:names:tc:SAML:2.0:protocol`).
- Assertions are consumed at the SP **Assertion Consumer Service (ACS)** URL and
  translated into a Hearth `ExternalIdentity`, which is then linked/provisioned
  per the federation link policy.

## 2. Bindings

| Direction | Binding | Support |
|-----------|---------|---------|
| SP → IdP (`AuthnRequest`, `LogoutRequest`) | HTTP-Redirect (`DEFLATE` + base64 + URL) | MUST |
| SP → IdP | HTTP-POST (form) | MUST |
| IdP → SP (`Response`, `LogoutResponse`) at ACS | HTTP-POST (base64, **no** DEFLATE) | MUST |
| Any | HTTP-Artifact | **Not supported** — MUST reject |
| Any | SOAP / PAOS (ECP) | **Not supported** |

- Inbound HTTP-Redirect payloads are DEFLATE-inflated with a hard cap of
  **1 MiB** (`MAX_INFLATED_SAML_BYTES`). A payload that would inflate past the
  cap MUST be rejected before full expansion (decompression-bomb defense).
- Inbound HTTP-POST payloads are base64-decoded only; they MUST NOT be
  DEFLATE-inflated (POST bodies are not compressed in the SAML POST binding).

## 3. XML parsing hardening

The XML reader (`saml/xml.rs`, `saml/response.rs`) is a purpose-built,
namespace-aware streaming reader — **not** a general-purpose DOM parser. It
enforces:

- **No DTD / DOCTYPE.** Any document containing a `<!DOCTYPE …>` declaration
  MUST be rejected as a parse error. External and internal entity definitions
  are never processed. This is the primary XXE defense.
  (Tests: `a35c_doctype_in_saml_response_rejected`,
  `a35c_external_entity_reference_rejected`,
  `a29d_saml_doctype_in_find_element_range_rejected`.)
- **No entity expansion.** Custom entity references are not resolved, so the
  "billion laughs" and external-file-disclosure vectors do not apply.
- **Event cap.** Parsing stops and rejects once the element/event count exceeds
  **`MAX_SAML_XML_EVENTS` (10 000)**. A well-formed real Response is O(20)
  elements; the cap only fires on adversarial expansion.
  (Tests: `a35b_oversized_saml_xml_rejected`,
  `a29d_saml_entity_expansion_cap_constant_sentinel`.)
- Parse failures surface as `SamlError::Parse { reason }` with a **sanitized**
  reason. Parser internals (which vector was attempted, file paths, upstream
  bodies) MUST NOT leak to the caller or logs.

## 4. Signature verification (XML-DSIG)

Hearth requires a **valid enveloped XML signature** on inbound assertions.

- **Signature algorithm:** RSA-PKCS1-v1.5-SHA256
  (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`) only.
- **Digest algorithm:** SHA-256 (`http://www.w3.org/2001/04/xmlenc#sha256`) only.
- **Canonicalization:** Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)
  is the only form Hearth computes. It is applied **unconditionally** — the
  declared `<ds:CanonicalizationMethod Algorithm>` is not read.
- **Reference transforms:** Hearth signs with `enveloped-signature` + `exc-c14n`.
  On the verify path the `<ds:Transforms>` list is **not** parsed or checked.
- **Algorithm downgrade is rejected — for the signature and digest algorithms
  only.** `verify_signed_element` rejects a `SignedInfo` containing the SHA-1 or
  RSA-SHA1 algorithm identifiers, and requires it to name both RSA-SHA256 and
  SHA-256, with `SamlError::UnsupportedAlgorithm`. There is no negotiation and
  no "legacy" opt-in.
- **Not enforced: canonicalization and transform downgrade.** A document
  declaring inclusive C14N or an unexpected `<ds:Transform>` produces no
  `UnsupportedAlgorithm` rejection. Because Hearth canonicalizes exclusively
  regardless of what the document declares, such a document is very likely to
  fail the digest or signature comparison — but that is a byte-comparison
  side effect, not an algorithm check, and it MUST NOT be relied on as one.
  Closing this is a code change, tracked separately; this section describes
  what ships today.
- **Signing key:** the IdP's registered certificate (PEM, RSA public key). No
  key material is trusted from the assertion itself (no inline cert trust).

### 4.1 Signature-wrapping (XSW) defenses

XSW attacks move or duplicate a signed element so a validator checks one node
but consumes another. Hearth defends structurally:

- **Single assertion only, counted over the whole document.** Before any
  signature work, `sp.rs::complete_inner` counts every `<saml:Assertion>`
  element at any depth and rejects the document as `SamlError::Signature`
  unless the count is exactly one. This kills the "inject a second unsigned
  assertion" class outright, at every placement rather than only as a direct
  child of `<Response>`. `extract_and_validate_assertion` keeps an independent
  `SamlError::Parse` rejection for a multi-assertion `<Response>`, but on the SP
  path the `Signature` rejection fires first.
  (Test: `a29c_saml_multiple_assertions_rejected`.)
- **Reference-URI ↔ element-ID binding.** `verify_signed_element` extracts the
  signed element's `ID`, builds the expected `#<id>` URI, and requires the
  `<ds:Reference URI>` to match it. A moved or mismatched signature resolves to
  a non-existent range and MUST fail with `SamlError::Signature`.
  (Tests: `a29c_saml_find_element_range_nonexistent_id_returns_none`,
  `a29c_saml_find_element_range_finds_correct_assertion`.)
- **Verified element ↔ consumed element binding.** When an assertion-level
  signature was verified, `complete_inner` requires the `ID` of the assertion
  that `extract_and_validate_assertion` returns to equal the `ID` of the element
  whose signature was verified; a mismatch MUST fail with
  `SamlError::Signature`. `verify_signed_element` alone does **not** provide
  this — it only binds the Reference URI to the ID of the element it verified.
- **`WantAssertionsSigned`.** When the IdP registration sets
  `want_assertions_signed`, an assertion-level signature is **required**; a
  Response-level-only signature MUST be rejected. When it is unset, Hearth falls
  back to accepting a valid Response-level signature.

## 5. Assertion validation

After signature verification, `extract_and_validate_assertion` enforces, in
order (all rejections use the listed `SamlError` variant):

1. **Status** — `StatusCode` MUST be `…:status:Success`; else
   `InvalidAuthnRequest`.
2. **Assertion count** — exactly one assertion (see §4.1); else `Parse`.
3. **Destination** — if the Response carries a `Destination`, it MUST equal the
   SP ACS URL; else `DestinationMismatch` (cookie-less CSRF defense).
4. **Issuer** — the assertion/Response issuer MUST equal the registered IdP
   entity ID; else `IssuerMismatch`.
5. **Audience** — the parsed `AudienceRestriction/Audience` value MUST equal
   this SP's entity ID; else `AudienceMismatch`. A single audience value is
   parsed, so this is an equality check, not a membership test over a list.
   The SP entity ID it is compared against is derived from `onboarding.base_url`
   when configured, and otherwise from the request's `X-Forwarded-Host` / `Host`
   headers — see the caveat on `trusted_base_url` in `src/protocol/web/saml.rs`.
6. **Validity window** — see §6.
7. **InResponseTo** — see §6.2.

Replay protection (assertion-ID uniqueness) is enforced by the ACS handler
against storage, **outside** `extract_and_validate_assertion`; a re-used
assertion ID MUST be rejected as `SamlError::Replay`.

## 6. Time and correlation windows

### 6.1 Clock skew and validity

- **Default clock-skew tolerance: 60 seconds** (`clock_skew_secs`, applied at
  the ACS in `sp.rs`).
- `NotBefore` (optional per profile): reject `Expired` when
  `not_before > now + skew`.
- `NotOnOrAfter` is **mandatory**. An assertion with no `Conditions/NotOnOrAfter`
  upper bound never ages out and would be replayable indefinitely, so a missing
  bound MUST be rejected as `Expired`.
- Expiry rule (upper edge **inclusive** of rejection):
  reject `Expired` when `not_on_or_after <= now - skew`. Equivalently, the
  assertion is valid only while `now - skew < not_on_or_after`.
  (Boundary tests: `a29e_not_on_or_after_at_skew_boundary_expired`,
  `a29e_not_on_or_after_just_inside_skew_boundary_ok`.)

### 6.2 InResponseTo (solicited-flow binding)

- For **solicited** SP-initiated logins, the SP passes the originating
  `AuthnRequest` ID as `expected_in_response_to`. The Response's `InResponseTo`
  MUST equal it; a mismatch — **including an unsolicited Response with no
  `InResponseTo` at all** — MUST be rejected as `InvalidAuthnRequest`.
  (Tests: `a29e_in_response_to_match_ok`, `a29e_in_response_to_forged_rejected`,
  `a29e_unsolicited_response_rejected_when_request_expected`.)
- Unsolicited IdP-initiated login (no expected request ID) is permitted **only**
  when the SP flow explicitly passes `expected_in_response_to = None`. Whether a
  given realm/IdP allows IdP-initiated SSO is a registration-level policy
  decision, not a parser default.

## 7. Encryption

- **Encrypted assertions / encrypted NameIDs are NOT currently supported.** The
  `xmlenc` namespace is recognized only for the SHA-256 digest identifier; there
  is no `EncryptedAssertion` / `EncryptedID` decryption path. An IdP MUST be
  configured to send signed-but-unencrypted assertions over TLS.
- Transport confidentiality is provided by TLS on the ACS endpoint. Assertions
  are integrity-protected by the XML signature (§4), not by XML encryption.
- Adding `EncryptedAssertion` support is a future, separately-specified change;
  until then Hearth MUST reject documents whose payload it cannot validate in
  cleartext rather than silently ignoring encrypted content.

## 8. Error surface

All SAML failures map to `SamlError` (`saml/error.rs`), converted to
`IdentityError::Saml` at the layer boundary. Wire error codes:

| Condition | Variant | Wire code |
|-----------|---------|-----------|
| Parse / DOCTYPE / event-cap | `Parse` | `HEARTH_SAML_INVALID` |
| Multi-assertion document (SP path) | `Signature` | `HEARTH_SAML_INVALID` |
| Bad/missing/wrapped signature, algorithm downgrade | `Signature`, `UnsupportedAlgorithm` | `HEARTH_SAML_INVALID` |
| Outside validity window / missing `NotOnOrAfter` | `Expired` | `HEARTH_SAML_INVALID` |
| Replayed assertion ID | `Replay` | `HEARTH_SAML_INVALID` |
| Audience / Issuer / Destination / InResponseTo mismatch | `AudienceMismatch`, `IssuerMismatch`, `DestinationMismatch`, `InvalidAuthnRequest` | `HEARTH_SAML_INVALID` |
| IdP metadata fetch failed | `MetadataFetch` | `HEARTH_SAML_METADATA_FETCH_FAILED` |
| Unknown SP/IdP for realm | `UnknownSp`, `UnknownIdp` | `HEARTH_SAML_ENTITY_NOT_FOUND` |

- Error messages and logs MUST NOT contain assertion contents, subject PII,
  tokens, or raw upstream bodies.
- The `Signature` variant intentionally conflates all signature failure modes;
  the caller MUST NOT learn which specific check failed.

## 9. Security invariants (summary — all MUST)

1. No DTD/DOCTYPE, no entity expansion, ≤ 10 000 XML events.
2. Ed25519-independent: signatures MUST be RSA-SHA256 with SHA-256 digests;
   SHA-1 and RSA-SHA1 are rejected. Canonicalization is always exclusive C14N,
   but the declared canonicalization and transform algorithms are not checked
   — inclusive C14N is not rejected as such (§4).
3. Exactly one `<Assertion>` in the whole document; Reference URI bound to the
   signed element ID; the consumed assertion's ID bound to the verified one.
4. Mandatory `NotOnOrAfter`; 60 s skew; inclusive upper-edge rejection.
5. Audience, Issuer, Destination, and (solicited) InResponseTo all checked.
6. Assertion-ID replay rejected at the ACS handler.
7. No error path leaks parser internals or PII.
