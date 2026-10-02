## ADDED Requirements

### Requirement: The SP accepts only a strict SAML profile
The SAML SP SHALL reject a response before signature verification when the response has a DTD or `DOCTYPE`, more than one `Assertion` element, or a `ds:Signature` element in any position other than a direct child of the root `samlp:Response` or of the `saml:Assertion`, or more than one `ds:Signature` under either of those parents.

(Corrected during apply: the first draft said "more than one `ds:Signature` element". An IdP may sign both the Response and the Assertion — Okta and ADFS can — which is two legitimate signatures.)

#### Scenario: DOCTYPE present
- **WHEN** the Assertion Consumer Service receives a response that contains a `<!DOCTYPE` declaration
- **THEN** the SP rejects it, and creates no session

#### Scenario: Two assertions
- **WHEN** the response contains two `Assertion` elements, in any nesting
- **THEN** the SP rejects it, and creates no session

#### Scenario: A signature outside the two allowed positions
- **WHEN** the response contains a `ds:Signature` inside `samlp:Status`, `saml:Subject`, another signature's `ds:KeyInfo` or `ds:Object`, or a nested `samlp:Response`
- **THEN** the SP rejects it, and creates no session

#### Scenario: Two signatures under one parent
- **WHEN** the root `samlp:Response` or the `saml:Assertion` has two direct-child `ds:Signature` elements
- **THEN** the SP rejects it, and creates no session

#### Scenario: Response and Assertion each signed once
- **WHEN** the IdP signs both the root `samlp:Response` and the `saml:Assertion`, once each, and both verify
- **THEN** the SP accepts the response

### Requirement: The SP reads data only from the signed element
After it verifies the one signature, the SP SHALL read the subject and attributes only from the element that the signature reference identifies.

#### Scenario: Signature-wrapping attempt
- **WHEN** a response carries a validly signed assertion for user A, and an unsigned copy, moved or wrapped, that names user B
- **THEN** the SP either rejects the response or signs in user A, and never signs in user B

### Requirement: An XSW corpus runs in CI
CI SHALL run the published XML signature-wrapping variants against the SP. Every case SHALL be rejected, or SHALL resolve to the signed identity.

(Changed during apply: no maintained, vendorable third-party corpus exists — SAML Raider generates its variants inside Burp. The suite generates the eight variants XSW1–XSW8 from Somorovsky et al., "On Breaking SAML" (USENIX Security 2012), from a real signed document, in `tests/saml_sp.rs`.)

#### Scenario: Corpus run
- **WHEN** the CI job runs the corpus against the Assertion Consumer Service
- **THEN** no case produces a session for an identity other than the signed one, and the job fails if one does
