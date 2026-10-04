## MODIFIED Requirements

### Requirement: A delegated token carries the intersection of subject and actor permissions
When Hearth issues a delegated token by RFC 8693 token exchange (`urn:ietf:params:oauth:grant-type:token-exchange`), the token's `permissions` SHALL be the intersection of the subject token's `permissions` and the actor's `permissions`, as its scope is the intersection of subject, actor and requested scope. The delegated token's `roles` and `groups` SHALL be empty. An actor with no RBAC grants SHALL yield zero delegated permissions; operators grant the actor the permissions it legitimately needs. Resource servers keep reading the `permissions` claim.

#### Scenario: An agent exchanges an admin's token
- **WHEN** user Alice holds `{hearth.admin, docs.delete, billing.admin}`, agent Foo holds only `{tool.search_emails.invoke}`, and Foo exchanges Alice's access token
- **THEN** the delegated token carries `sub: alice` and `act: {sub: foo}`
- **AND** its `permissions` hold none of `hearth.admin`, `docs.delete` or `billing.admin`

#### Scenario: Permissions outside the actor's set
- **WHEN** an actor with permission set A exchanges a subject token with permission set B
- **THEN** no permission in B \ A is exercisable with the delegated token

#### Scenario: An exchange without an actor token is attenuated
- **WHEN** a client with no RBAC grants exchanges Alice's access token, which carries `docs.delete`, and sends no `actor_token`
- **THEN** the delegated token carries `act` naming that client
- **AND** its `permissions` are empty, because the acting client holds none of Alice's permissions
