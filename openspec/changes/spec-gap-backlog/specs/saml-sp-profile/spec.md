## ADDED Requirements

### Requirement: IdP-initiated SSO is a per-IdP registration policy
Whether a realm or IdP allows unsolicited, IdP-initiated SSO SHALL be a registration-level policy decision, not a parser default. When the IdP registration allows it, the SP SHALL accept an unsolicited response only when the SP flow explicitly passes no expected request ID. For such a response there is no request to bind against, so the SP SHALL NOT consult the `InResponseTo` of the bearer `<SubjectConfirmationData>`. When the registration does not allow it, the SP SHALL reject an unsolicited response.

#### Scenario: IdP-initiated SSO allowed for the IdP
- **WHEN** the IdP registration allows IdP-initiated SSO, and the IdP posts a valid, signed, unsolicited response with no `InResponseTo`
- **THEN** the SP accepts it without binding it to an `AuthnRequest`

#### Scenario: IdP-initiated SSO not allowed for the IdP
- **WHEN** the IdP registration does not allow IdP-initiated SSO, and the IdP posts an unsolicited response
- **THEN** the SP rejects it, and creates no session
