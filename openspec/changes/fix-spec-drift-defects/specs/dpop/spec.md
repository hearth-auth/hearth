## MODIFIED Requirements

### Requirement: DPoP proofs are fresh and single-use
A proof's `iat` MUST be within `DPOP_MAX_AGE_SECS` (120 s) plus `DPOP_MAX_CLOCK_SKEW_SECS` (60 s) of the server's clock. Every proof `jti` MUST be recorded to reject proof replay. The `cnf.jkt` binding check MUST run before the `jti` is recorded, so a proof that fails the binding check cannot spend the legitimate holder's one-shot slot. The same ordering SHALL apply to every single-use artefact: the caller-binding check precedes the burn.

#### Scenario: A proof is reused
- **WHEN** a client presents the same DPoP proof twice
- **THEN** the second presentation is refused as a replay

#### Scenario: A stale proof
- **WHEN** a proof's `iat` is more than 180 seconds in the past
- **THEN** it is refused with `invalid_dpop_proof`

#### Scenario: A proof with the wrong key does not burn the jti
- **WHEN** a proof signed by a key other than the token's `cnf.jkt` key is presented with a given `jti`
- **THEN** it is refused
- **AND** a later proof from the legitimate key with the same `jti` is not refused as a replay

#### Scenario: Regression — a wrong-key refresh proof burns its jti
- **WHEN** a `refresh_token` request on a DPoP-bound grant family carries a proof from a key other than the family's bound key, with a given `jti`
- **AND** the legitimate holder then refreshes with a proof from the bound key that carries the same `jti`
- **THEN** the first request is refused
- **AND** the legitimate refresh is not refused as a replay
