## ADDED Requirements

### Requirement: Config load rejects raw permission scopes on third-party clients
Config load SHALL reject a `third_party` client whose `declared_scopes` contains a raw permission scope (a `.`-form name). The error SHALL name the client and the scope.

#### Scenario: A third-party client declares a permission
- **WHEN** `hearth.yaml` declares a `third_party` client with `declared_scopes: [docs.read]`
- **THEN** config load fails and names the client and the scope

### Requirement: Tier 2 claim overrides are format-checked at load
The validator SHALL check the OIDC format of a Tier 2 override that reads a `canonical_user_field` source: `email` SHALL produce an email address, `locale` a BCP 47 tag and `zoneinfo` an IANA time-zone name. A format violation SHALL be a config-load error. A `user_attribute` source is operator-supplied and is not checked; the operator is responsible for its format.

#### Scenario: A locale claim from a non-locale field
- **WHEN** a realm maps `locale` from `canonical_user_field` `display_name`
- **THEN** config load fails and names the claim

#### Scenario: An attribute-backed override
- **WHEN** a realm maps `locale` from `user_attribute` `lang`
- **THEN** config load accepts it without a format check

### Requirement: Role assignment enforces the role's scope kind
Role assignment SHALL refuse a role with `scope_kind: realm` at organization scope, and a role with `scope_kind: organization` at realm scope. A role with `scope_kind: any` SHALL be assignable at either scope. Every admin role picker SHALL list only the roles whose `scope_kind` fits the assignment.

#### Scenario: A realm role assigned in an organization
- **WHEN** an admin assigns a role with `scope_kind: realm` at `Org(X)` scope
- **THEN** the assignment is refused

#### Scenario: An any-scope role
- **WHEN** an admin assigns a role with `scope_kind: any` at realm scope and at `Org(X)` scope
- **THEN** both assignments succeed

### Requirement: Additional organization roles respect scope kind, uniqueness and a cap
When an additional organization role is added, the server SHALL also check that the role's `scope_kind` is `organization` or `any`, that the membership does not already carry the name, and that the membership carries at most 32 additional roles. A request that fails a check SHALL be refused.

#### Scenario: A realm-kind role as an additional role
- **WHEN** an admin adds a role with `scope_kind: realm` as an additional role of a membership
- **THEN** the request is refused

#### Scenario: A duplicate additional role
- **WHEN** an admin adds a role the membership already carries as an additional role
- **THEN** the request is refused

#### Scenario: The 33rd additional role
- **WHEN** a membership already carries 32 additional roles and an admin adds another
- **THEN** the request is refused

### Requirement: `hearth config diff` previews a configuration change
The CLI SHALL provide `hearth config diff <new.yaml>`: a pre-flight diff of the impact of a new configuration against the data in storage. It SHALL NOT change anything.

#### Scenario: A new configuration removes a role
- **WHEN** an operator runs `hearth config diff new.yaml`, and `new.yaml` removes a role that users hold
- **THEN** the output names the role and the affected assignments, and storage is unchanged

### Requirement: Connected applications are grouped by organization and resource
When an application has several consent rows, `/ui/account/applications` SHALL group them by organization, and within each organization by resource. The realm-level row of a client with `consent_spans_orgs: true` SHALL appear as its own group labelled "All organizations". Each entry SHALL show its own granted-at time and scopes.

#### Scenario: One app, two resources
- **WHEN** a user consented to AcmeNotes in Acme Corp for Hearth and for `https://mcp.acme.com`
- **THEN** the page shows AcmeNotes, then Acme Corp, then two entries, "Hearth (default audience)" and `https://mcp.acme.com`, each with its own granted-at time and scopes

### Requirement: The realm claims page shows the merged profile with an example token
The realm claims page SHALL show the merged claim profile: the built-in defaults plus the realm's YAML overrides. For each mapping it SHALL also show the `allowed_clients` gate. It SHALL render a live example token for a sample user the admin picks, with inputs for the client trust level and the granted scopes.

#### Scenario: A realm with no claims block
- **WHEN** an admin opens the claims page of a realm with no `claims:` block
- **THEN** the page lists the built-in default mappings

#### Scenario: Previewing gate behaviour
- **WHEN** an admin switches the example token from a first-party to a third-party client
- **THEN** the example drops every claim gated on `first_party_only`
