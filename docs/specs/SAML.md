# SAML 2.0 — Normative Specification

Status: **Normative.** Requirement levels follow RFC 2119 (MUST / SHOULD / MAY).
Scope: Hearth's SAML 2.0 Web-SSO support as a **Service Provider (SP)** for
inbound federation. The implementation lives under
`src/identity/federation/saml/`; this document is the authoritative contract for
its security-relevant behavior. Where code and this document disagree, that is a
bug in one of them — file an issue.

> **Hearth is not a SAML IdP (3.0.0).** Earlier releases also acted as a SAML
> Identity Provider for third-party SPs (`/realms/{realm}/saml/{metadata,sso,sso/init,slo-idp}`
> and `realms.<name>.saml_service_providers`). That side was removed in 3.0.0
> (OpenSpec change `scope-trim-trusted-core`) to shrink the attack surface:
> connect applications to Hearth over OpenID Connect instead. A configuration
> that still sets `saml_service_providers` refuses to start with an error that
> names the key.

Related specs: `docs/specs/AUTHORIZATION.md` (claim mapping after login),
`docs/specs/OIDC.md` (the OIDC federation path), `docs/specs/ARCHITECTURE.md`
(layering rules). SCIM has its own companion spec (`docs/specs/SCIM.md`).

Adversarial test coverage: `tests/abuse_federation.rs` (A-29*) and
`tests/abuse_scim_saml.rs` (A-35b/c). Every MUST below that is externally
observable has a corresponding rejection test.

---

## 1. Role and profile

Hearth implements the SAML **Service Provider (Relying Party)** role only —
inbound federation, the subject of §§2–7 below:

| Route | Purpose |
|---|---|
| `GET /realms/{realm}/federation/saml/metadata` | Hearth's own SP metadata |
| `GET /realms/{realm}/federation/saml/begin` | SP-initiated `AuthnRequest` |
| `POST /realms/{realm}/federation/saml/acs` | Assertion Consumer Service |

Assertions are consumed at the ACS URL and translated into a Hearth
`ExternalIdentity`, which is then linked/provisioned per the federation link
policy. A successful consumption establishes a real Hearth session; the
completed-login audit event is emitted **only** when a session cookie was
actually issued (`issued_session_cookie`, `src/protocol/web/saml.rs`).

Hearth publishes the realm's RSA signing certificate in its SP metadata. It does
not sign `AuthnRequest`s (`sign_authn_requests` is `false` in the metadata).

- Supported profile: the **Web Browser SSO Profile** of SAML 2.0
  (`urn:oasis:names:tc:SAML:2.0:protocol`), SP side. Single Logout is not
  supported: no SLO endpoint is registered.

## 2. Bindings

| Direction | Binding | Support |
|-----------|---------|---------|
| SP → IdP (`AuthnRequest`) | HTTP-Redirect (`DEFLATE` + base64 + URL) | MUST |
| IdP → SP (`Response`) at ACS | HTTP-POST (base64, **no** DEFLATE) | MUST |
| Any | HTTP-Artifact | **Not supported.** No artifact-resolution endpoint is registered, so an `SAMLart` flow has nowhere to land — it 404s. There is no explicit "artifact rejected" branch; the strings `artifact`, `SOAP` and `PAOS` appear nowhere under `src/identity/federation/saml/`. |
| Any | SOAP / PAOS (ECP) | **Not supported** — same: no endpoint exists. |

- Hearth receives no HTTP-Redirect payloads: the ACS accepts HTTP-POST only.
- Inbound HTTP-POST payloads are base64-decoded only; they MUST NOT be
  DEFLATE-inflated (POST bodies are not compressed in the SAML POST binding).

## 3. XML parsing hardening

The XML reader (`saml/xml.rs`, `saml/response.rs`) is a purpose-built,
namespace-aware streaming reader on `quick-xml` — **not** a general-purpose DOM
parser. Every element is identified by the namespace URI its prefix is bound to
in scope — declarations on the element itself or inherited from any ancestor,
including the default namespace — and never by how the prefix is spelled: a
`ds:` prefix bound to some other URI is not XML-DSIG, an unbound prefix is in
no namespace, and Entra ID's unprefixed `<Signature xmlns="…xmldsig#">` with
unprefixed children is recognised like `<ds:Signature>`. When a slice of a
document is scanned or canonicalized (the signed element, its `<Signature>`,
`<SignedInfo>`), it is given the bindings it inherits in the document, so the
scanners and the canonicalizer (`saml/c14n.rs`) always agree. It enforces:

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
- **One root element.** A document with a second top-level element is rejected;
  its fields could otherwise be merged into the first document's.
- **Signature-blind field extraction.** Every SAML field reader
  (`parse_response`, and `parse_idp_metadata` for upstream metadata) reads
  through `xml::walk_outside_signatures`, which
  never reports anything inside a `<ds:Signature>` at any depth — the region the
  enveloped-signature transform removes from the digest (§4.1).
- **Structural field positions.** Fields are read only from the position the
  SAML 2.0 core schema defines for them (e.g. the subject is
  `Response/Assertion/Subject/NameID`),
  decided from the element's parent; a same-named element anywhere else is
  ignored. A second occurrence of a single-valued field is rejected rather than
  resolved last-write-wins (§4.1).
- Parse failures surface as `SamlError::Parse { reason }` with a **sanitized**
  reason. Parser internals (which vector was attempted, file paths, upstream
  bodies) MUST NOT leak to the caller or logs.

## 4. Signature verification (XML-DSIG)

Hearth requires a **valid enveloped XML signature** on inbound assertions.

- **Signature algorithm:** RSA-PKCS1-v1.5-SHA256
  (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`) only.
- **Digest algorithm:** SHA-256 (`http://www.w3.org/2001/04/xmlenc#sha256`) only.
- **Canonicalization:** Exclusive C14N (`http://www.w3.org/2001/10/xml-exc-c14n#`)
  without comments is the only form Hearth computes. The declared
  `<ds:CanonicalizationMethod Algorithm>` MUST name exactly that algorithm;
  anything else (inclusive C14N, `#WithComments`) is rejected with
  `SamlError::UnsupportedAlgorithm` before any digest is computed.
- **Reference transforms:** Hearth signs with `enveloped-signature` + `exc-c14n`.
  On the verify path the `<ds:Transforms>` list MUST be present, MUST include
  `enveloped-signature`, and MUST name nothing but `enveloped-signature` and
  `exc-c14n`; anything else (XPath, XSLT, a missing list) is rejected with
  `SamlError::UnsupportedAlgorithm`.
  (Tests: `inclusive_canonicalization_method_rejected`,
  `exc_c14n_with_comments_rejected`, `xslt_transform_rejected`,
  `missing_enveloped_transform_rejected`, `missing_transforms_element_rejected`.)
- **Algorithm downgrade is rejected.** Besides the canonicalization and
  transform checks above, `verify_signed_element` rejects a `SignedInfo`
  containing the SHA-1 or RSA-SHA1 algorithm identifiers, and requires it to
  name both RSA-SHA256 and SHA-256, with `SamlError::UnsupportedAlgorithm`.
  There is no negotiation and no "legacy" opt-in.
- **The enveloped-signature transform removes exactly one element** — the
  `<ds:Signature>` being verified, located by its byte offset — and nothing
  else. Any other `<ds:Signature>` stays in the canonical form and is covered
  by the digest.
- **Signing key:** the IdP's registered certificate (PEM, RSA public key). No
  key material is trusted from the assertion itself (no inline cert trust).
  The connector's `idp_certificate_pem` may hold several concatenated
  certificates — during an IdP key rollover, the outgoing and the incoming one
  — and a signature is accepted when it verifies under **any** of them. Every
  block is parsed when the configuration is loaded or reloaded, with the
  verifier's own parser (`validate_idp_certificate_bundle`): a missing or
  unusable certificate refuses startup, and `hearth config validate` reports it
  naming the realm and connector (tests: `saml_idp_certificate_must_be_usable_at_load`,
  `saml_idp_certificate_bundle_with_an_unusable_block_is_refused`,
  `validate_returns_1_for_an_unusable_saml_idp_certificate`).
  (Tests: `sp_accepts_an_assertion_signed_by_any_configured_idp_certificate`,
  `sp_acs_accepts_an_assertion_signed_by_the_second_certificate_of_a_bundle`.)
- **Canonical form in context.** The signed element is canonicalized with the
  namespace declarations it inherits from its ancestors: exclusive C14N renders
  a visibly used inherited declaration (e.g. `xmlns:saml` declared only on the
  `<Response>`, as Keycloak emits it) on the apex, so the digest Hearth computes
  is the one a standards-conformant signer computed. `<SignedInfo>` is likewise
  canonicalized with the bindings in scope where it sits.
- **Base64 content** (`DigestValue`, `SignatureValue`) may be line-wrapped;
  whitespace is removed before decoding.

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
- **Exactly one `<ds:Reference>`.** `<ds:SignedInfo>` MUST carry exactly one
  `<ds:Reference>`; zero or more than one MUST be rejected with
  `SamlError::Parse`. Hearth reads only the first reference's `URI` and
  `DigestValue`, so an unchecked list would let every later entry — naming
  some other part of the document, with a digest nobody computes — pass
  unverified. The count is bounded: the scan stops on the second reference, so
  a padded list cannot drive work proportional to its length.
  (Tests: `second_reference_in_signed_info_rejected`,
  `many_references_in_signed_info_rejected`,
  `signed_info_with_no_reference_rejected`,
  `single_reference_document_still_verifies`.)
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
- **Exactly one enveloped signature per element (GA audit 3, G-1).**
  `verify_signed_element` rejects, with `SamlError::Signature`, an element
  carrying more than one direct-child `<ds:Signature>`. The canonicalizer used
  to remove *every* direct-child `<ds:Signature>` from the digest while the
  verifier read only the first, so a second one appended to an assertion the
  IdP signed for the attacker could carry the victim's `<saml:NameID>`, a
  mapped `<saml:Attribute>`, or `<saml:Conditions>` extended to any date,
  under an unchanged digest. Now only the verified signature is removed, a
  second one is refused outright, and the parser never reads inside either.
  (Tests: `sp_rejects_second_signature_carrying_a_forged_name_id`,
  `sp_rejects_second_signature_carrying_a_forged_attribute`,
  `sp_rejects_second_signature_carrying_extended_conditions`,
  `sp_rejects_second_signature_on_a_response_level_signature`,
  `second_direct_child_signature_rejected`,
  `canon_removes_only_the_named_signature`; in Entra ID's default-namespace
  spelling: `sp_accepts_an_entra_style_default_namespace_response`,
  `sp_rejects_a_second_default_namespace_signature`,
  `sp_rejects_a_moved_default_namespace_signature_with_content_after_key_info`.)
- **Signatures only where the profile puts them (strict SP profile, 3.0.0).**
  Before any signature is verified, `check_signature_placement`
  (`saml/xml.rs`) refuses, with `SamlError::Signature`, any `<ds:Signature>`
  that is not a direct child of the root `<samlp:Response>` or of the
  `<saml:Assertion>`, and a second one under either. A signature inside
  `<samlp:Status>`, `<saml:Subject>`, a nested `<samlp:Response>`, or another
  signature's `<ds:KeyInfo>` / `<ds:Object>` is an unverified region; the
  parsers never read inside one (§3), and the document is now refused instead.
  Signing both the Response and the Assertion, once each, stays accepted.
  (Tests: `strict_profile_rejects_a_signature_outside_its_two_allowed_places`,
  `strict_profile_accepts_a_response_and_an_assertion_each_signed_once`,
  `strict_profile_refuses_the_eight_published_xsw_variants` — XSW1–XSW8 of
  Somorovsky et al., USENIX Security 2012, generated from a real signed
  document; and the `signature_placement_*` unit tests.)
- **Nothing but `SignedInfo`, `SignatureValue` and `KeyInfo` in a signature.**
  The verified `<ds:Signature>` MUST have exactly one `<ds:SignedInfo>`,
  exactly one `<ds:SignatureValue>`, at most one `<ds:KeyInfo>`, and no other
  child (no `<ds:Object>` either). Only `SignedInfo` is covered by the
  signature, so anything else there is unsigned content inside the signed
  element — the "move the signature to the end and append after
  `</ds:KeyInfo>`" variant. Content *inside* `<ds:KeyInfo>` is open-ended in
  XML-DSIG and is not rejected, but it is never read (§3).
  (Tests: `sp_rejects_moved_signature_with_elements_after_key_info`,
  `signature_with_unexpected_children_rejected`,
  `sp_never_reads_saml_elements_hidden_inside_the_verified_signature`.)
- **No duplicate single-valued fields.** Inside one `<Assertion>`, a second
  `<Issuer>`, `<Subject>`, subject `<NameID>`, `<Conditions>`, or `<Attribute>`
  with an already-seen `Name` is rejected with `SamlError::Parse`; so is a
  second `<Response>`-level `<Issuer>`, `<Status>` or top-level `<StatusCode>`.
  (Tests: `parse_rejects_duplicate_single_valued_fields`,
  `parse_rejects_duplicate_subject_name_id`,
  `parse_rejects_duplicate_response_level_fields`.)
- **`WantAssertionsSigned`.** When the IdP registration sets
  `want_assertions_signed`, an assertion-level signature is **required**; a
  Response-level-only signature MUST be rejected. When it is unset, Hearth falls
  back to accepting a valid Response-level signature.

### 4.2 Account linking and the asserted email

SAML carries no `email_verified` signal, so Hearth treats a SAML-asserted
address as **unverified by default**. `ExternalIdentity::is_linkable_by_email`
is then false, and `FederationService::resolve_identity` skips its whole
email-match arm: **both** `link_existing_accounts` modes — `confirm` and
`auto` — are unreachable for SAML. A SAML login by a user who already exists
locally falls through to just-in-time provisioning, which detects the address
collision and creates a **second** account under a synthetic address.

An operator opts in per connector:

```yaml
realms:
  corp:
    federation:
      providers:
        corp-okta:
          type: saml
          trust_asserted_email: true   # default: false
```

With it `true`, the address the IdP asserts counts as verified and the realm's
`link_existing_accounts` mode applies as it does for OIDC. Turn it on only for
an IdP that owns its users' mailboxes: it lets that IdP claim **any** address
in the realm. The key is ignored for non-SAML connectors, which carry the
upstream's own `email_verified` claim.

The same signal decides the state of a **just-in-time** account. A new user
provisioned from a verified address is `Active` with its email recorded as
verified. One provisioned from an unverified address — every SAML login from a
connector without `trust_asserted_email`, and every OIDC / Apple login whose
`email_verified` is not `true` — is created `PendingVerification`, exactly as
self-registration is: Hearth mails that address a verification link, answers
the login with the "check your email" page, and issues no session until the
link is used. The account then signs in through its federated link as usual.
(An account under a synthetic `…@fed.<idp>.local` address — no upstream email,
or one that collides with an existing user — names no mailbox and is `Active`,
unverified.)

(Tests: `saml_confirm_link_is_reachable_only_when_the_asserted_email_is_trusted`
proves the consumer; `reconcile_federation_carries_trust_asserted_email_to_the_idp`
proves the YAML reaches it.)

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
5. **Audience** — SAML Core §2.5.1.4: within one `<AudienceRestriction>` the
   assertion is addressed to this SP when **any** `<Audience>` equals this SP's
   entity ID; when the `<Conditions>` carry several `<AudienceRestriction>`
   elements, **each** MUST name it. An assertion with no `<AudienceRestriction>`
   (or an empty one) is refused, as the Web Browser SSO profile (§4.1.4.2)
   requires one naming the SP. Otherwise `AudienceMismatch`.
   (Tests: `audience_restriction_accepts_this_sp_anywhere_in_the_list`,
   `audience_restriction_without_this_sp_rejected`,
   `every_audience_restriction_must_name_this_sp`,
   `missing_or_empty_audience_restriction_rejected`.) The SP entity ID it is compared against comes from `onboarding.base_url`,
   or from `oidc.issuer` when that is unset. Forwarded headers
   (`X-Forwarded-Host`, `X-Forwarded-Proto`) are **never** consulted: anyone who
   can reach the port can set them, and an origin the attacker chose is not an
   origin. With neither key configured, only a **loopback** `Host`
   (`localhost`, `127.0.0.1`, `[::1]`) is accepted, for dev and tests; any other
   unconfigured `Host` makes the endpoint refuse with `500` rather than validate
   against a header (`trusted_base_url` in `src/protocol/web/saml.rs`).
6. **Validity window** — see §6.
7. **InResponseTo** (`<Response>` level) — see §6.2.
8. **Bearer `<SubjectConfirmationData>`** — the assertion MUST carry exactly one
   bearer `<SubjectConfirmation Method="…:cm:bearer">` whose
   `<SubjectConfirmationData>` sits *inside* that assertion (SAML 2.0 profiles
   §4.1.4.3). Zero is rejected as `InvalidAuthnRequest`, and so are two or more —
   a second one makes "the" `Recipient` ambiguous, which is precisely what a
   wrapping attack wants. Within it:
   - `Recipient` MUST equal this SP's ACS URL; else `DestinationMismatch`.
   - `NotOnOrAfter` is **mandatory** and is its own window, independent of (and
     typically far tighter than) `Conditions/NotOnOrAfter`; a missing or
     elapsed bound is `Expired`.
   - `InResponseTo` MUST equal the `AuthnRequest` ID we issued, when we issued
     one; else `InvalidAuthnRequest`. For an unsolicited (IdP-initiated)
     response there is no request to bind against and the attribute is not
     consulted.

   These are the copies that matter: the `<Response>`-level `Destination` and
   `InResponseTo` sit outside the signature whenever only the assertion is
   signed, while these three are inside the element the IdP signed. They are
   read from the same parsed assertion the ACS has already tied to the verified
   signature — never from a re-parse of the raw document.

Replay protection (assertion-ID uniqueness) is enforced by the ACS handler
against storage, **outside** `extract_and_validate_assertion`; a re-used
assertion ID MUST be rejected as `SamlError::Replay`.

On acceptance the ACS runs the asserted identity through the same federation
pipeline the OIDC callback uses — existing link, auto-link, confirm-to-link, or
JIT provisioning — and issues a Hearth session cookie (except for a JIT
account waiting for its address to be verified, §4.2). `saml_login_completed`
is recorded **only** when that cookie was actually set: a confirm-to-link hop is
a redirect without one, and the audit log must not report a login that did not
happen.

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
| Unknown IdP for realm | `UnknownIdp` | `HEARTH_SAML_ENTITY_NOT_FOUND` |

- Error messages and logs MUST NOT contain assertion contents, subject PII,
  tokens, or raw upstream bodies.
- The `Signature` variant intentionally conflates all signature failure modes;
  the caller MUST NOT learn which specific check failed.

## 9. Security invariants (summary — all MUST)

1. No DTD/DOCTYPE, no entity expansion, ≤ 10 000 XML events.
2. Ed25519-independent: signatures MUST be RSA-SHA256 with SHA-256 digests;
   SHA-1 and RSA-SHA1 are rejected. Canonicalization is always exclusive C14N
   without comments, and a declared canonicalization method or transform list
   naming anything else is rejected (§4).
3. Exactly one `<Assertion>` in the whole document; exactly one enveloped
   `<ds:Signature>` per signed element, holding only `SignedInfo`,
   `SignatureValue` and `KeyInfo`; the digest excludes that signature and
   nothing else; Reference URI bound to the signed element ID; the consumed
   assertion's ID bound to the verified one; no field is ever read from inside
   a `<ds:Signature>`, and no single-valued field may appear twice.
4. Mandatory `NotOnOrAfter`; 60 s skew; inclusive upper-edge rejection.
5. Audience, Issuer, Destination, and (solicited) InResponseTo all checked.
6. Assertion-ID replay rejected at the ACS handler.
7. No error path leaks parser internals or PII.
