# saml-sp-profile Specification

## Purpose
The SAML 2.0 service-provider profile: bindings, XML parsing hardening, signature and assertion validation, time windows, encryption and errors. Hearth is a SAML SP only.
## Requirements
### Requirement: Hearth is a SAML service provider for Web Browser SSO
Hearth SHALL implement the SAML 2.0 Service Provider (relying party) role only, for inbound federation. The supported profile SHALL be the Web Browser SSO Profile of SAML 2.0 (`urn:oasis:names:tc:SAML:2.0:protocol`), SP side. Hearth SHALL serve these routes:

| Route | Purpose |
|---|---|
| `GET /ui/realms/{realm}/federation/saml/metadata` | Hearth's own SP metadata |
| `GET /ui/realms/{realm}/federation/saml/begin` | SP-initiated `AuthnRequest` |
| `POST /ui/realms/{realm}/federation/saml/acs` | Assertion Consumer Service |

The Assertion Consumer Service (ACS) SHALL translate a consumed assertion into a Hearth `ExternalIdentity`. Single Logout SHALL NOT be supported: no SLO endpoint is registered.

#### Scenario: SP-initiated login starts at `begin`
- **WHEN** a browser requests `GET /ui/realms/{realm}/federation/saml/begin` for a SAML IdP configured in the realm
- **THEN** Hearth redirects the browser to the IdP's SSO URL with an `AuthnRequest`

#### Scenario: No Single Logout endpoint
- **WHEN** an IdP sends a `LogoutRequest` to an SLO path under `/ui/realms/{realm}/federation/saml/`
- **THEN** no SLO handler exists, and the server answers `404`

### Requirement: SP metadata publishes the signing certificate and unsigned AuthnRequests
The SP metadata SHALL publish the realm's RSA signing certificate. Hearth SHALL NOT sign `AuthnRequest`s, and the metadata SHALL declare `sign_authn_requests` as `false`.

#### Scenario: Metadata is fetched
- **WHEN** an operator fetches `GET /ui/realms/{realm}/federation/saml/metadata` for a configured SAML IdP
- **THEN** the metadata carries the realm's RSA signing certificate
- **AND** it declares that `AuthnRequest`s are not signed

### Requirement: AuthnRequests use the HTTP-Redirect binding
Hearth SHALL send the `AuthnRequest` to the IdP with the HTTP-Redirect binding: the XML is DEFLATE-compressed, then base64-encoded, then URL-encoded.

#### Scenario: The redirect carries the request
- **WHEN** `begin` redirects the browser to the IdP
- **THEN** the `SAMLRequest` query parameter URL-decodes, base64-decodes and inflates to the `AuthnRequest` XML

### Requirement: The ACS accepts only the HTTP-POST binding
The ACS SHALL accept the IdP's `Response` with the HTTP-POST binding only. Hearth SHALL base64-decode an inbound HTTP-POST payload and SHALL NOT DEFLATE-inflate it, because the POST binding does not compress. Hearth SHALL NOT receive HTTP-Redirect payloads. The HTTP-Artifact, SOAP and PAOS (ECP) bindings SHALL NOT be supported: no artifact-resolution, SOAP or PAOS endpoint is registered, and there is no explicit "artifact rejected" branch.

#### Scenario: A deflated POST payload
- **WHEN** the IdP posts a `SAMLResponse` that is DEFLATE-compressed before base64 encoding
- **THEN** the SP does not inflate it, rejects the response, and creates no session

#### Scenario: An artifact flow
- **WHEN** an IdP tries to complete a login with an `SAMLart` artifact
- **THEN** no artifact-resolution endpoint exists, and the flow ends in `404`

### Requirement: The SAML XML reader resolves no custom entities
The SAML XML reader SHALL NOT resolve a custom entity reference, and SHALL NOT process external or internal entity definitions. The "billion laughs" and external-file-disclosure vectors therefore do not apply. The reader is a purpose-built, namespace-aware streaming reader, not a general-purpose DOM parser.

#### Scenario: External entity reference
- **WHEN** a response refers to an external entity
- **THEN** the SP rejects it as a parse error, reads no file, and creates no session

### Requirement: The SAML XML reader caps the event count
The SAML XML reader SHALL stop parsing and reject the document once its element/event count exceeds `MAX_SAML_XML_EVENTS` (10 000). A well-formed real Response has about 20 elements, so the cap fires only on adversarial input.

#### Scenario: Oversized document
- **WHEN** a posted response holds more than 10 000 XML events
- **THEN** the SP rejects it as a parse error, and creates no session

### Requirement: A SAML document has one root element
The SAML XML reader SHALL reject a document that has a second top-level element. The second element's fields could otherwise be merged into the first document's.

#### Scenario: Two root elements
- **WHEN** a posted document is a valid `Response` followed by a second top-level `samlp:Response`
- **THEN** the SP rejects it as a parse error

### Requirement: SAML elements are identified by namespace URI
The SAML XML reader SHALL identify every element by the namespace URI its prefix is bound to in scope, and never by how the prefix is spelled. The scope SHALL include declarations on the element itself and declarations inherited from any ancestor, including the default namespace. A `ds:` prefix bound to some other URI SHALL NOT be treated as XML-DSIG. An unbound prefix SHALL be in no namespace. An unprefixed `<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">` with unprefixed children, as Entra ID emits it, SHALL be recognised like `<ds:Signature>`. When a slice of a document is scanned or canonicalized (the signed element, its `<Signature>`, `<SignedInfo>`), the slice SHALL be given the namespace bindings it inherits in the document, so the scanners and the canonicalizer always agree.

#### Scenario: Entra ID default-namespace signature
- **WHEN** a correctly signed response uses an unprefixed, default-namespace `<Signature>`
- **THEN** the SP verifies it and accepts the response

#### Scenario: A `ds:` prefix bound to another namespace
- **WHEN** a response contains a `ds:Signature` element whose `ds` prefix is bound to a URI other than the XML-DSIG namespace
- **THEN** the SP does not treat that element as an XML signature

### Requirement: SAML field readers skip signature content
Every SAML field reader SHALL read outside `<ds:Signature>` elements only. This covers the response parser and the parser for upstream IdP metadata. A reader SHALL never report content inside a `<ds:Signature>`, at any depth. That is the region the enveloped-signature transform removes from the digest.

#### Scenario: SAML elements hidden inside the verified signature
- **WHEN** a signed response hides a `saml:NameID` or `saml:Attribute` inside the verified `<ds:Signature>`
- **THEN** the SP never reads those elements

### Requirement: SAML fields are read only from their schema position
The SP SHALL read each field only from the position the SAML 2.0 core schema defines for it, decided from the element's parent. For example, the subject is `Response/Assertion/Subject/NameID`. A same-named element anywhere else SHALL be ignored.

#### Scenario: A stray `NameID`
- **WHEN** an assertion carries a second `saml:NameID` outside `Subject`
- **THEN** the SP ignores it, and reads the subject only from `Subject/NameID`

### Requirement: Single-valued SAML fields appear once
The SP SHALL reject a second occurrence of a single-valued field with `SamlError::Parse`, rather than resolve it last-write-wins. Inside one `<Assertion>`, these are single-valued: `<Issuer>`, `<Subject>`, the subject `<NameID>`, `<Conditions>`, and an `<Attribute>` with an already-seen `Name`. At `<Response>` level, these are single-valued: `<Issuer>`, `<Status>` and the top-level `<StatusCode>`.

#### Scenario: Duplicate subject `NameID`
- **WHEN** an assertion's `Subject` carries two `NameID` elements
- **THEN** the SP rejects the response with `SamlError::Parse`

#### Scenario: Duplicate Response-level `Status`
- **WHEN** a `Response` carries two `Status` elements
- **THEN** the SP rejects the response with `SamlError::Parse`

### Requirement: Inbound assertions require a valid enveloped signature
The SP SHALL require a valid enveloped XML signature on inbound assertions. The SP SHALL verify the signature only with the IdP's registered certificate (PEM, RSA public key). The SP SHALL NOT trust key material carried in the assertion itself; there is no inline certificate trust.

#### Scenario: Signed with an unregistered key
- **WHEN** a response is signed with a key whose certificate travels in `ds:KeyInfo` but is not registered for the IdP
- **THEN** the SP rejects it, and creates no session

#### Scenario: Digest does not match
- **WHEN** a signed assertion is altered after signing
- **THEN** the SP rejects it with `SamlError::Signature`

### Requirement: An IdP certificate bundle trusts each of its certificates
The connector's `idp_certificate_pem` MAY hold several concatenated certificates, for example the outgoing and the incoming one during an IdP key rollover. The SP SHALL accept a signature that verifies under any of them. Hearth SHALL parse every certificate block, with the verifier's own parser, when the configuration is loaded or reloaded. A missing or unusable certificate SHALL refuse startup. `hearth config validate` SHALL report it, and name the realm and the connector.

#### Scenario: Signed by the second certificate of a bundle
- **WHEN** an assertion is signed by the second certificate of the connector's bundle
- **THEN** the ACS accepts it

#### Scenario: A bundle with an unusable block
- **WHEN** one block of `idp_certificate_pem` is not a usable certificate
- **THEN** the server refuses to start
- **AND** `hearth config validate` exits with status 1 and names the realm and the connector

### Requirement: Only RSA-SHA256, SHA-256 and exclusive C14N are accepted
The SP SHALL accept only these algorithms:

| Use | Algorithm | Identifier |
|---|---|---|
| Signature | RSA-PKCS1-v1.5-SHA256 | `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` |
| Digest | SHA-256 | `http://www.w3.org/2001/04/xmlenc#sha256` |
| Canonicalization | Exclusive C14N without comments | `http://www.w3.org/2001/10/xml-exc-c14n#` |

Exclusive C14N without comments is the only form Hearth computes. The declared `<ds:CanonicalizationMethod Algorithm>` MUST name exactly that algorithm. Anything else, such as inclusive C14N or `#WithComments`, SHALL be rejected with `SamlError::UnsupportedAlgorithm` before any digest is computed. A `SignedInfo` that contains the SHA-1 or RSA-SHA1 identifier SHALL be rejected with `SamlError::UnsupportedAlgorithm`, and so SHALL a `SignedInfo` that does not name both RSA-SHA256 and SHA-256. There SHALL be no algorithm negotiation and no "legacy" opt-in.

#### Scenario: Inclusive canonicalization declared
- **WHEN** a signature declares inclusive C14N as its `CanonicalizationMethod`
- **THEN** the SP rejects it with `SamlError::UnsupportedAlgorithm` before it computes a digest

#### Scenario: Exclusive C14N with comments declared
- **WHEN** a signature declares `http://www.w3.org/2001/10/xml-exc-c14n#WithComments`
- **THEN** the SP rejects it with `SamlError::UnsupportedAlgorithm`

#### Scenario: RSA-SHA1 downgrade
- **WHEN** a `SignedInfo` names the RSA-SHA1 signature algorithm or the SHA-1 digest algorithm
- **THEN** the SP rejects it with `SamlError::UnsupportedAlgorithm`

### Requirement: The reference transform list is fixed
On the verify path, the `<ds:Transforms>` list MUST be present, MUST include `enveloped-signature`, and MUST name nothing but `enveloped-signature` and `exc-c14n`. The SP SHALL reject anything else, such as an XPath or XSLT transform or a missing list, with `SamlError::UnsupportedAlgorithm`.

#### Scenario: XSLT transform
- **WHEN** a reference declares an XSLT transform
- **THEN** the SP rejects it with `SamlError::UnsupportedAlgorithm`

#### Scenario: Missing enveloped-signature transform
- **WHEN** a reference lists only `exc-c14n`
- **THEN** the SP rejects it with `SamlError::UnsupportedAlgorithm`

#### Scenario: Missing `Transforms` element
- **WHEN** a reference has no `<ds:Transforms>` element
- **THEN** the SP rejects it with `SamlError::UnsupportedAlgorithm`

### Requirement: The enveloped-signature transform removes only the verified signature
The enveloped-signature transform SHALL remove exactly one element: the `<ds:Signature>` being verified, located by its byte offset. It SHALL remove nothing else. Any other `<ds:Signature>` SHALL stay in the canonical form, and the digest covers it.

#### Scenario: Canonical form keeps other signatures
- **WHEN** the SP canonicalizes a signed element for its digest
- **THEN** only the signature being verified is removed from the canonical form

### Requirement: The signed element is canonicalized in its document context
The SP SHALL canonicalize the signed element with the namespace declarations it inherits from its ancestors. Exclusive C14N renders a visibly used inherited declaration on the apex, so the digest Hearth computes is the one a standards-conformant signer computed. The SP SHALL likewise canonicalize `<SignedInfo>` with the namespace bindings in scope where it sits.

#### Scenario: Namespace declared only on the Response
- **WHEN** an IdP declares `xmlns:saml` only on the `<Response>`, as Keycloak does, and signs the assertion
- **THEN** the SP computes the same digest as the signer, and accepts the assertion

### Requirement: Signature base64 values may be line-wrapped
The SP SHALL remove whitespace from `DigestValue` and `SignatureValue` content before it base64-decodes them.

#### Scenario: Line-wrapped signature value
- **WHEN** a valid `SignatureValue` is wrapped over several lines
- **THEN** the SP decodes it and verifies the signature

### Requirement: SignedInfo carries exactly one Reference
`<ds:SignedInfo>` MUST carry exactly one `<ds:Reference>`. The SP SHALL reject zero, or more than one, with `SamlError::Parse`. The count SHALL be bounded: the scan stops at the second reference, so a padded list does not drive work proportional to its length.

#### Scenario: A second reference
- **WHEN** a `SignedInfo` carries a second `<ds:Reference>` that names another part of the document
- **THEN** the SP rejects it with `SamlError::Parse`

#### Scenario: Many references
- **WHEN** a `SignedInfo` carries sixty-five `<ds:Reference>` elements
- **THEN** the SP rejects it with `SamlError::Parse`, after reading at most two

#### Scenario: No reference
- **WHEN** a `SignedInfo` carries no `<ds:Reference>`
- **THEN** the SP rejects it with `SamlError::Parse`

#### Scenario: One reference
- **WHEN** a correctly signed document carries exactly one `<ds:Reference>`
- **THEN** the signature verifies

### Requirement: The Reference URI names the signed element
The SP SHALL take the signed element's `ID`, build the expected URI `#<id>`, and require the `<ds:Reference URI>` to match it. A moved or mismatched signature resolves to a non-existent range, and MUST fail with `SamlError::Signature`.

#### Scenario: Reference to a different ID
- **WHEN** an assertion's signature has a `Reference URI` that names an ID other than the assertion's own
- **THEN** the SP rejects it with `SamlError::Signature`

### Requirement: A signature holds only SignedInfo, SignatureValue and KeyInfo
The verified `<ds:Signature>` MUST have exactly one `<ds:SignedInfo>`, exactly one `<ds:SignatureValue>`, at most one `<ds:KeyInfo>`, and no other child. A `<ds:Object>` child is not allowed either. Only `SignedInfo` is covered by the signature, so anything else there is unsigned content inside the signed element. Content inside `<ds:KeyInfo>` is open-ended in XML-DSIG and SHALL NOT be rejected, but the SP SHALL never read it.

#### Scenario: Elements after `KeyInfo`
- **WHEN** a signature is moved to the end of the assertion, with SAML elements appended after `</ds:KeyInfo>`
- **THEN** the SP rejects the response

#### Scenario: An unexpected child
- **WHEN** a `<ds:Signature>` carries a `<ds:Object>` child
- **THEN** the SP rejects the response

### Requirement: `want_assertions_signed` requires an assertion-level signature
When the IdP registration sets `want_assertions_signed`, the SP SHALL require an assertion-level signature, and SHALL reject a response that is signed at Response level only. When it is unset, the SP SHALL accept a valid Response-level signature.

#### Scenario: Response-level signature with `want_assertions_signed`
- **WHEN** `want_assertions_signed` is set and only the outer `Response` is signed
- **THEN** the SP rejects the response with `SamlError::Signature`

#### Scenario: Response-level signature without `want_assertions_signed`
- **WHEN** `want_assertions_signed` is unset and only the outer `Response` is signed, validly
- **THEN** the SP accepts the response

### Requirement: A SAML-asserted email is unverified unless the connector trusts it
SAML carries no `email_verified` signal, so the SP SHALL treat a SAML-asserted address as unverified by default. While it is unverified, the identity is not linkable by email: both `link_existing_accounts` modes, `confirm` and `auto`, SHALL be unreachable for SAML. A SAML login by a user who already exists locally then falls through to just-in-time provisioning, which detects the address collision and creates a second account under a synthetic address. A SAML connector MAY set `trust_asserted_email: true` (default `false`). With it `true`, the address the IdP asserts SHALL count as verified, and the realm's `link_existing_accounts` mode SHALL apply as it does for OIDC. An operator SHOULD turn it on only for an IdP that owns its users' mailboxes, because it lets that IdP claim any address in the realm. The key SHALL be ignored for non-SAML connectors, which carry the upstream's own `email_verified` claim.

```yaml
realms:
  corp:
    federation:
      providers:
        corp-okta:
          type: saml
          trust_asserted_email: true   # default: false
```

#### Scenario: Confirm-to-link needs a trusted address
- **WHEN** a SAML login asserts the address of an existing local user, and the realm's mode is `confirm`
- **THEN** the confirm-to-link step is reached only when the connector sets `trust_asserted_email: true`

#### Scenario: The YAML key reaches the connector
- **WHEN** `hearth.yaml` sets `trust_asserted_email: true` on a SAML provider and the configuration is reconciled
- **THEN** the realm's SAML IdP carries the setting

### Requirement: Just-in-time accounts from an unverified address wait for verification
A new user provisioned just-in-time from a verified address SHALL be `Active`, with its email recorded as verified. A new user provisioned from an unverified address SHALL be created `PendingVerification`, exactly as self-registration does. This covers every SAML login from a connector without `trust_asserted_email`, and every OIDC or Apple login whose `email_verified` is not `true`. For such an account, Hearth SHALL mail the address a verification link, answer the login with the "check your email" page, and issue no session until the link is used. The account then signs in through its federated link as usual. An account under a synthetic `…@fed.<idp>.local` address (no upstream email, or one that collides with an existing user) names no mailbox, and SHALL be `Active` and unverified.

#### Scenario: First SAML login from an untrusted connector
- **WHEN** a new user signs in through a SAML connector without `trust_asserted_email`
- **THEN** the account is created `PendingVerification`, a verification link is mailed, and no session is issued

#### Scenario: Verification link used
- **WHEN** that user follows the verification link and signs in through the same SAML connector again
- **THEN** the login completes through the federated link and a session is issued

### Requirement: Assertion checks run in a fixed order
After signature verification, the SP SHALL enforce these checks in this order, and SHALL reject a failure with the listed `SamlError` variant:

| Step | Check | Rejection |
|---|---|---|
| 1 | `StatusCode` is `urn:oasis:names:tc:SAML:2.0:status:Success` | `InvalidAuthnRequest` |
| 2 | Exactly one assertion | `Parse` |
| 3 | If the Response carries a `Destination`, it equals the SP ACS URL (the cookie-less CSRF defense) | `DestinationMismatch` |
| 4 | The assertion's own `Issuer` equals the registered IdP entity ID; a matching Response-level `Issuer` does not substitute for it | `IssuerMismatch` |
| 5 | Audience (see "The assertion's audience restriction names this SP") | `AudienceMismatch` |
| 6 | Validity window | `Expired` |
| 7 | `<Response>`-level `InResponseTo` | `InvalidAuthnRequest` |
| 8 | Bearer `<SubjectConfirmationData>` | as that requirement lists |

#### Scenario: Non-success status
- **WHEN** a signed Response carries a `StatusCode` other than `Success`
- **THEN** the SP rejects it with `InvalidAuthnRequest`

#### Scenario: Wrong `Destination`
- **WHEN** a signed Response names a `Destination` other than the SP's ACS URL
- **THEN** the SP rejects it with `DestinationMismatch`

#### Scenario: Wrong issuer
- **WHEN** a signed Response and its assertion both name an issuer other than the registered IdP entity ID
- **THEN** the SP rejects it with `IssuerMismatch`

### Requirement: The assertion's audience restriction names this SP
Within one `<AudienceRestriction>`, the assertion SHALL count as addressed to this SP when any `<Audience>` equals this SP's entity ID (SAML Core §2.5.1.4). When the `<Conditions>` carry several `<AudienceRestriction>` elements, each MUST name this SP. The SP SHALL refuse an assertion with no `<AudienceRestriction>`, or with an empty one, because the Web Browser SSO profile (§4.1.4.2) requires one that names the SP. Every other case SHALL be rejected with `AudienceMismatch`.

#### Scenario: This SP anywhere in the list
- **WHEN** an `<AudienceRestriction>` lists another audience first and this SP's entity ID second
- **THEN** the audience check passes

#### Scenario: This SP absent
- **WHEN** no `<Audience>` in the restriction equals this SP's entity ID
- **THEN** the SP rejects the assertion with `AudienceMismatch`

#### Scenario: One of two restrictions omits this SP
- **WHEN** the `<Conditions>` carry two `<AudienceRestriction>` elements and only one names this SP
- **THEN** the SP rejects the assertion with `AudienceMismatch`

#### Scenario: Missing or empty restriction
- **WHEN** an assertion has no `<AudienceRestriction>`, or an empty one
- **THEN** the SP rejects it with `AudienceMismatch`

### Requirement: The SP entity ID comes from configuration only
The SP entity ID that the audience is compared against SHALL come from `onboarding.base_url`, or from `oidc.issuer` when `onboarding.base_url` is unset. The SP SHALL NOT consult forwarded headers (`X-Forwarded-Host`, `X-Forwarded-Proto`) for it: anyone who can reach the port can set them. With neither key configured, the SP SHALL accept only a loopback `Host` (`localhost`, `127.0.0.1`, `[::1]`), for development and tests. Any other `Host` without configuration SHALL make the endpoint refuse with `500`, rather than validate against a header.

#### Scenario: Forwarded host is ignored
- **WHEN** `onboarding.base_url` is set and a request to the ACS carries `X-Forwarded-Host: attacker.example`
- **THEN** the SP compares the audience against the entity ID from `onboarding.base_url`

#### Scenario: No configured origin and a public `Host`
- **WHEN** neither `onboarding.base_url` nor `oidc.issuer` is set and a request arrives with `Host: idp-target.example`
- **THEN** the SAML endpoint answers `500`

#### Scenario: No configured origin and a loopback `Host`
- **WHEN** neither key is set and a request arrives with `Host: 127.0.0.1:8420`
- **THEN** the SAML endpoint serves the request using that loopback origin

### Requirement: Assertions are valid only inside their time window
The SP SHALL apply a clock-skew tolerance of 60 seconds by default (`clock_skew_secs`, applied at the ACS). `NotBefore` is optional per the profile; when present, the SP SHALL reject with `Expired` when `not_before > now + skew`. `Conditions/NotOnOrAfter` SHALL be mandatory: an assertion without that upper bound would never age out and would be replayable indefinitely, so a missing bound MUST be rejected as `Expired`. The upper edge SHALL be inclusive of rejection: the SP SHALL reject with `Expired` when `not_on_or_after <= now - skew`, so an assertion is valid only while `now - skew < not_on_or_after`.

#### Scenario: Exactly at the skew boundary
- **WHEN** `not_on_or_after` equals `now - 60 s`
- **THEN** the SP rejects the assertion with `Expired`

#### Scenario: Just inside the skew boundary
- **WHEN** `not_on_or_after` is one second later than `now - 60 s`
- **THEN** the validity check passes

#### Scenario: Missing `NotOnOrAfter`
- **WHEN** an assertion's `Conditions` carry no `NotOnOrAfter`
- **THEN** the SP rejects it with `Expired`

### Requirement: A solicited response is bound to its AuthnRequest
The ACS SHALL accept only a response to an `AuthnRequest` that Hearth issued from `begin`; it SHALL NOT accept unsolicited, IdP-initiated SSO. The POST MUST carry the `RelayState` that `begin` issued. The ACS SHALL answer `400` when `RelayState` is missing or names no stored login state, and SHALL consume that state on first use. The SP SHALL pass the ID of the originating `AuthnRequest` as the expected `InResponseTo`. The Response's `InResponseTo` MUST equal it. A mismatch, including a Response with no `InResponseTo` at all, MUST be rejected as `InvalidAuthnRequest`.

#### Scenario: Matching `InResponseTo`
- **WHEN** the Response's `InResponseTo` equals the ID of the `AuthnRequest` Hearth issued
- **THEN** the `InResponseTo` check passes

#### Scenario: Forged `InResponseTo`
- **WHEN** the Response's `InResponseTo` names a different request ID
- **THEN** the SP rejects it with `InvalidAuthnRequest`

#### Scenario: Unsolicited response where a request is expected
- **WHEN** Hearth issued an `AuthnRequest` and the Response carries no `InResponseTo`
- **THEN** the SP rejects it with `InvalidAuthnRequest`

#### Scenario: IdP-initiated response
- **WHEN** an IdP posts an unsolicited response to the ACS with no `RelayState`
- **THEN** the ACS answers `400`, and creates no session

### Requirement: An assertion carries exactly one bearer subject confirmation
The assertion MUST carry exactly one bearer `<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">`, whose `<SubjectConfirmationData>` sits inside that assertion (SAML 2.0 profiles §4.1.4.3). The SP SHALL reject zero as `InvalidAuthnRequest`, and SHALL reject two or more as `InvalidAuthnRequest`, because a second one makes "the" `Recipient` ambiguous. The bearer `NotOnOrAfter` SHALL be mandatory. It is a window of its own, independent of `Conditions/NotOnOrAfter` and typically much tighter. A failed check in the confirmation data SHALL be rejected with these variants:

| Field | Failure | Rejection |
|---|---|---|
| `Recipient` | not this SP's ACS URL | `DestinationMismatch` |
| `NotOnOrAfter` | missing or elapsed | `Expired` |
| `InResponseTo` | not the ID of the `AuthnRequest` Hearth issued | `InvalidAuthnRequest` |

The SP SHALL read these values from the same parsed assertion that the ACS already tied to the verified signature, and never from a re-parse of the raw document.

#### Scenario: No bearer confirmation
- **WHEN** a signed assertion carries no bearer `SubjectConfirmation`
- **THEN** the SP rejects it with `InvalidAuthnRequest`

#### Scenario: Two bearer confirmations
- **WHEN** a signed assertion carries two bearer `SubjectConfirmation` elements with different `Recipient` values
- **THEN** the SP rejects it with `InvalidAuthnRequest`

#### Scenario: Bearer confirmation without `NotOnOrAfter`
- **WHEN** the bearer `SubjectConfirmationData` has no `NotOnOrAfter`
- **THEN** the SP rejects the assertion with `Expired`

### Requirement: An assertion ID is consumed once
The ACS handler SHALL record each consumed assertion ID in storage, and SHALL reject a re-used assertion ID as `SamlError::Replay`. This check SHALL run in the ACS handler, against storage, outside the assertion validator.

#### Scenario: The same response is posted twice
- **WHEN** a valid response is posted to the ACS a second time
- **THEN** the second post is rejected as a replay, and creates no session

### Requirement: An accepted assertion runs the federation pipeline
On acceptance, the ACS SHALL run the asserted identity through the same federation pipeline that the OIDC callback uses: existing link, auto-link, confirm-to-link, or just-in-time provisioning. The pipeline then issues a Hearth session cookie, except for a just-in-time account that waits for its address to be verified. A confirm-to-link hop SHALL be a redirect without a session cookie.

#### Scenario: Existing link
- **WHEN** a valid assertion names an external identity already linked to a local user
- **THEN** the ACS signs in that user and sets the Hearth session cookie

#### Scenario: Confirm-to-link hop
- **WHEN** a valid assertion requires the user to confirm an account link
- **THEN** the ACS redirects to the confirm-link step without setting a session cookie

### Requirement: Encrypted assertions are not supported
The SP SHALL NOT decrypt `EncryptedAssertion` or `EncryptedID` content; there is no decryption path. The `xmlenc` namespace is recognised only for the SHA-256 digest identifier. An IdP MUST be configured to send signed but unencrypted assertions over TLS. Transport confidentiality comes from TLS on the ACS endpoint, and integrity from the XML signature. Hearth MUST reject a document whose payload it cannot validate in cleartext, rather than silently ignore encrypted content. Adding `EncryptedAssertion` support needs a separate, specified change.

#### Scenario: Encrypted assertion only
- **WHEN** the IdP posts a Response whose only assertion is an `EncryptedAssertion`
- **THEN** the SP rejects it, and creates no session

#### Scenario: Encrypted subject
- **WHEN** a signed assertion carries its subject as an `EncryptedID` instead of a `NameID`
- **THEN** the SP rejects it rather than ignore the encrypted content

### Requirement: SAML failures map to stable wire codes
Every SAML failure SHALL map to a `SamlError` variant, converted to `IdentityError::Saml` at the layer boundary. Each variant SHALL map to this wire error code:

| Condition | Variant | Wire code |
|---|---|---|
| Parse, `DOCTYPE`, event cap | `Parse` | `HEARTH_SAML_INVALID` |
| Multi-assertion document (SP path) | `Signature` | `HEARTH_SAML_INVALID` |
| Bad, missing or wrapped signature; algorithm downgrade | `Signature`, `UnsupportedAlgorithm` | `HEARTH_SAML_INVALID` |
| Outside the validity window, or missing `NotOnOrAfter` | `Expired` | `HEARTH_SAML_INVALID` |
| Replayed assertion ID | `Replay` | `HEARTH_SAML_INVALID` |
| Audience, Issuer, Destination or `InResponseTo` mismatch | `AudienceMismatch`, `IssuerMismatch`, `DestinationMismatch`, `InvalidAuthnRequest` | `HEARTH_SAML_INVALID` |
| IdP metadata fetch failed | `MetadataFetch` | `HEARTH_SAML_METADATA_FETCH_FAILED` |
| Unknown IdP for the realm | `UnknownIdp` | `HEARTH_SAML_ENTITY_NOT_FOUND` |

#### Scenario: A replayed assertion
- **WHEN** a `Replay` failure is reported on the wire
- **THEN** its error code is `HEARTH_SAML_INVALID`

#### Scenario: An unknown IdP
- **WHEN** a SAML request names an IdP that is not registered for the realm
- **THEN** the error code is `HEARTH_SAML_ENTITY_NOT_FOUND`

### Requirement: SAML errors and logs carry no sensitive content
A parse failure SHALL surface as `SamlError::Parse { reason }` with a sanitized reason. Parser internals, such as which vector was attempted, file paths or upstream bodies, MUST NOT reach the caller or the logs. Error messages and logs MUST NOT contain assertion contents, subject PII, tokens, or raw upstream bodies.

#### Scenario: A rejected response is logged
- **WHEN** the ACS rejects a response that carries a subject `NameID` and attributes
- **THEN** neither the response to the caller nor the log line contains the `NameID`, an attribute value, or the raw XML

### Requirement: Signature failures are indistinguishable
The `Signature` variant SHALL cover every signature failure mode: missing `<Signature>`, invalid digest, invalid signature value, wrong signing certificate, and signature wrapping. The caller MUST NOT learn which specific check failed.

#### Scenario: Two different signature failures
- **WHEN** one response fails on its digest and another on its signature value
- **THEN** the caller receives the same error for both

