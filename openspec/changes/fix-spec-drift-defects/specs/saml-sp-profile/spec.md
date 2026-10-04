## MODIFIED Requirements

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

#### Scenario: Regression — the ACS answers without a SAML error code
- **WHEN** the ACS rejects a response whose assertion ID was already consumed
- **THEN** the error response carries the wire code `HEARTH_SAML_INVALID`, not only a plain-text `400` body
