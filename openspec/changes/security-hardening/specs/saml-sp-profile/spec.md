## MODIFIED Requirements

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

#### Scenario: The assertion's own issuer must match
- **WHEN** a signed Response names the registered IdP as its `Issuer`, but its assertion's own `Issuer` names another entity
- **THEN** the SP rejects it with `IssuerMismatch`, and creates no session

### Requirement: Encrypted assertions are not supported
The SP SHALL NOT decrypt `EncryptedAssertion` or `EncryptedID` content; there is no decryption path. The `xmlenc` namespace is recognised only for the SHA-256 digest identifier. An IdP MUST be configured to send signed but unencrypted assertions over TLS. Transport confidentiality comes from TLS on the ACS endpoint, and integrity from the XML signature. Hearth MUST reject a document whose payload it cannot validate in cleartext, rather than silently ignore encrypted content. Adding `EncryptedAssertion` support needs a separate, specified change.

#### Scenario: Encrypted assertion only
- **WHEN** the IdP posts a Response whose only assertion is an `EncryptedAssertion`
- **THEN** the SP rejects it, and creates no session

#### Scenario: Encrypted subject
- **WHEN** a signed assertion carries its subject as an `EncryptedID` instead of a `NameID`
- **THEN** the SP rejects it rather than ignore the encrypted content

#### Scenario: Encrypted content is rejected
- **WHEN** a signed, otherwise valid assertion carries `<saml:EncryptedID>` in its `Subject` and no `<saml:NameID>`
- **THEN** the SP rejects the response
- **AND** no account is linked, provisioned or signed in for an empty subject
