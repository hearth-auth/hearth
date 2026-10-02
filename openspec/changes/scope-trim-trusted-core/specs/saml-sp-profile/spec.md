## ADDED Requirements

### Requirement: The SP accepts only a strict SAML profile
The SAML SP SHALL reject a response before signature verification when the response has a DTD or `DOCTYPE`, more than one `Assertion` element, or more than one `ds:Signature` element.

#### Scenario: DOCTYPE present
- **WHEN** the Assertion Consumer Service receives a response that contains a `<!DOCTYPE` declaration
- **THEN** the SP rejects it, and creates no session

#### Scenario: Two assertions
- **WHEN** the response contains two `Assertion` elements, in any nesting
- **THEN** the SP rejects it, and creates no session

#### Scenario: Two signatures
- **WHEN** the response contains two `ds:Signature` elements, in any position
- **THEN** the SP rejects it, and creates no session

### Requirement: The SP reads data only from the signed element
After it verifies the one signature, the SP SHALL read the subject and attributes only from the element that the signature reference identifies.

#### Scenario: Signature-wrapping attempt
- **WHEN** a response carries a validly signed assertion for user A, and an unsigned copy, moved or wrapped, that names user B
- **THEN** the SP either rejects the response or signs in user A, and never signs in user B

### Requirement: An external XSW corpus runs in CI
CI SHALL run a third-party XML signature-wrapping attack corpus against the SP. Every case SHALL be rejected, or SHALL resolve to the signed identity.

#### Scenario: Corpus run
- **WHEN** the CI job runs the corpus against the Assertion Consumer Service
- **THEN** no case produces a session for an identity other than the signed one, and the job fails if one does
