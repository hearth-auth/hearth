## ADDED Requirements

### Requirement: Entity IDs are bare UUIDs
Every entity ID that Hearth issues SHALL be the bare, lowercase, hyphenated UUID: in token claims (`sid`, `tid`, `oid`), in API and SCIM responses, in webhook payloads, in audit records, in logout tokens and in backup manifests. A token's `sub` SHALL name its subject in one of three forms:

| Subject | `sub` |
|---|---|
| A user | the user's bare UUID, equal to the user's `id` in the admin API and SCIM |
| An OAuth client (a sessionless `client_credentials` or JWT-bearer token) | `client_<uuid>` |
| An agent | `agt_<uuid>` |

A `sub` with the `client_` or `agt_` prefix SHALL NOT be read as a user. When Hearth parses an ID or a claim, it SHALL also accept the prefixed forms earlier releases issued (`user_`, `session_`, `realm_`, `org_` and the others), so a token issued before an upgrade stays valid until it expires.

#### Scenario: A user's token subject is their API id
- **WHEN** a client creates a user through SCIM, and the user then signs in through that client
- **THEN** the access token's `sub` equals the SCIM `id`
- **AND** its `sid` and `tid` are bare UUIDs

#### Scenario: A client token keeps its subject namespace
- **WHEN** a client obtains a token with the `client_credentials` grant
- **THEN** the token's `sub` is `client_<uuid>`, and Hearth does not read it as a user

#### Scenario: A token issued before the upgrade
- **WHEN** a request presents an unexpired access token whose `sub` is `user_<uuid>` and whose `sid` is `session_<uuid>`
- **THEN** Hearth accepts it as it accepts a token with bare IDs
