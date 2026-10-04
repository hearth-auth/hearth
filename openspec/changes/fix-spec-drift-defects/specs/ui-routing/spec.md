## MODIFIED Requirements

### Requirement: R-4 Realm names exclude admin route keywords
A realm name MUST NOT collide with any first-segment sub-resource keyword used under `/ui/admin/realms/{name}/...`. Realm-name validation SHALL reject these names at realm-create time:

`admins`, `api`, `applications`, `audit`, `claims`, `delete`, `groups`, `new`, `organizations`, `permissions`, `rbac`, `sessions`, `settings`, `status`, `test-email`, `users`

The set SHALL be closed. Adding a new sub-resource keyword to the route map MUST also add it to this set.

#### Scenario: A reserved name
- **WHEN** an operator creates a realm named `users`
- **THEN** the request is rejected because the name is reserved

#### Scenario: Every route keyword is reserved
- **WHEN** a route exists whose first segment under `/ui/admin/realms/{name}/` is a literal keyword
- **THEN** that keyword is in the reserved set

#### Scenario: Regression — route keywords missing from the reserved set
- **WHEN** an operator creates a realm named `webhooks`, `config`, `identity-providers`, `abuse` or `approvals`
- **THEN** the request is rejected because the name is reserved

### Requirement: R-8 Admin pages emit only realm-qualified links
No admin template MAY emit a URL that matches the regex `/ui/admin/(users|groups|organizations|applications|sessions|audit|rbac|permissions)(\/|$)`; such a URL lacks realm context and SHALL NOT appear. Every realm-scoped link MUST have the form `/ui/admin/realms/{{ realm_name }}/...`.

#### Scenario: Crawl of the admin console
- **WHEN** a crawler follows every link and form action on the admin pages
- **THEN** no URL matches `/ui/admin/(users|groups|organizations|applications|sessions|audit|rbac|permissions)(\/|$)`

#### Scenario: Regression — realm-less sessions filter links
- **WHEN** the admin template source is scanned for URLs, including branches that do not render today, such as the `is_global` branch of the sessions list
- **THEN** no URL names `/ui/admin/sessions` or another realm-scoped keyword without a realm, whether `/`, `?` or the end of the URL follows the keyword
