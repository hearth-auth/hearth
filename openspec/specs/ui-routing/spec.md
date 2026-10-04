# ui-routing Specification

## Purpose
Realm-name reservation and the admin-console route rules: how a realm is named in a URL, and which names a realm cannot take.
## Requirements
### Requirement: R-1 Realm-scoped admin URLs carry the realm in the path
Every realm-scoped admin URL MUST have the form `/ui/admin/realms/{realm_name}/{sub-resource}/...`, where `{realm_name}` is the realm's slug. The `TargetRealm` extractor SHALL recover the realm from this path segment and from no other source, except the system-realm sentinel (R-3). The realm-scoped surfaces are: users, groups, organizations, applications, sessions, audit, rbac, permission resolver, claims, realm-admin grants, and realm deletion. The first-run onboarding wizard under `/ui/admin/onboarding/...` is the one exception: its steps carry the realm being set up as a `realm` query parameter on `GET` steps and as a `realm` form field on `POST` steps.

#### Scenario: A realm-scoped page
- **WHEN** an admin requests `GET /ui/admin/realms/acme/users`
- **THEN** the page lists the users of realm `acme`

#### Scenario: A realm-scoped form
- **WHEN** an admin submits a form on a page under `/ui/admin/realms/acme/`
- **THEN** the form posts to a URL under `/ui/admin/realms/acme/`, and the change applies to realm `acme`

#### Scenario: Onboarding wizard step
- **WHEN** the onboarding wizard moves from creating realm `acme` to registering its first application
- **THEN** the next step is `/ui/admin/onboarding/app?realm=acme`

### Requirement: R-2 System-scoped admin URLs carry no realm
Admin pages that operate on system-wide state, or that span all realms, MUST live under `/ui/admin/...` with no realm in the path:

| URL | Purpose |
|---|---|
| `/ui/admin` | admin home; redirects (`307`) to `/ui/admin/realms` |
| `/ui/admin/realms` | list of all realms |
| `/ui/admin/admin-users` | system-realm operators (a system-realm view, see R-3) |
| `/ui/admin/admin-users/new` | create a system-realm operator |
| `/ui/admin/settings/...` | global config editor |
| `/ui/admin/api/config/reload` | config reload |
| `/ui/admin/api/nav/realms` | sidebar realm tree |
| `/ui/admin/test-email` | email transport test |
| `/ui/admin/api-tokens` | mint a short-lived system-realm API token; system-realm operators only, with a fresh password and second-factor step-up |

#### Scenario: The realm list
- **WHEN** an admin requests `GET /ui/admin/realms`
- **THEN** the page lists every realm, and its URL names no realm

#### Scenario: System-realm operators
- **WHEN** an admin requests `GET /ui/admin/admin-users`
- **THEN** the page lists the operators of the system realm

#### Scenario: Admin home
- **WHEN** an admin requests `GET /ui/admin`
- **THEN** the server answers `307` with `Location: /ui/admin/realms`

### Requirement: R-3 The system realm is addressed by a sentinel or the `system` slug
A system-realm view operates on the realm whose UUID is `RealmId::nil()`. The `TargetRealm` extractor SHALL resolve the explicit query sentinel `?admin_target=system` to the system realm. It SHALL also resolve the path slug `system` (`/ui/admin/realms/system/...`) to the system realm, even though the system realm has no name-index entry and is not listed among the realms. Links to a system-realm user carry both, for example `/ui/admin/realms/system/users/{id}?admin_target=system`. Apart from the onboarding wizard's `realm` parameter (R-1), `admin_target=system` SHALL be the only query-based realm signal. The `admin-users` admin pages SHALL reuse the generic user-management handlers for the system realm.

#### Scenario: A system-realm user page by sentinel
- **WHEN** an admin requests a user-management page with `?admin_target=system`
- **THEN** the page operates on the system realm

#### Scenario: A system-realm user page by slug
- **WHEN** an admin requests `GET /ui/admin/realms/system/users/{id}` for a system-realm operator
- **THEN** the page operates on the system realm

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

### Requirement: R-5, R-9 The target realm resolves from the sentinel or the path only
The `TargetRealm` extractor MUST resolve in exactly this order:

1. The query `?admin_target=system` resolves to the system realm (R-3).
2. The path segment of `/ui/admin/realms/{name}/...` resolves to that realm (R-1).
3. There is no further fallback. If neither matched, the extractor SHALL answer `404 Not Found` to a `GET`, and `400 Bad Request` to any other method.

No realm-less admin route is registered for a realm-scoped surface, so a request to a URL such as `/ui/admin/users` SHALL get the branded `404` page, whatever its method. The extractor SHALL NOT read a `?realm=<name>` query parameter, SHALL NOT read a `hearth_ui_admin_target` cookie, and SHALL NOT default to the first non-system realm. An old realm-less URL SHALL NOT redirect to a realm-qualified one; it no longer exists.

#### Scenario: Realm-less GET
- **WHEN** an admin requests `GET /ui/admin/users`, with no realm in the path
- **THEN** the server answers `404`

#### Scenario: Realm-less mutation
- **WHEN** an admin sends `POST /ui/admin/users/{id}/delete`, with no realm in the path
- **THEN** the server answers `404`, and no user is deleted

#### Scenario: A `?realm=` query is ignored
- **WHEN** an admin requests `GET /ui/admin/users?realm=acme`
- **THEN** no realm is resolved from the query, and the server answers `404`

#### Scenario: A stale realm cookie is ignored
- **WHEN** a request without realm context carries a `hearth_ui_admin_target` cookie naming a realm
- **THEN** the extractor does not resolve that realm

### Requirement: R-6 Switching realms is a navigation
Switching realms SHALL be a navigation, not a state change. Realm navigation SHALL use plain `<a>` links. The realm list links each realm to its workspace, `/ui/admin/realms/{name}`. The sidebar realm tree links each realm to its section pages, `/ui/admin/realms/{name}/{section}`. A switch does not keep the current sub-path. There SHALL be no `POST /admin/switch-realm` handler and no `hearth_ui_admin_target` cookie. An admin who wants to work in realm B navigates to a URL that names realm B. The system-realm switch, the "Admin users" tab in the sidebar, SHALL be a hard-coded link to `/ui/admin/admin-users`.

#### Scenario: Switching realm from the sidebar
- **WHEN** an admin on `/ui/admin/realms/acme/users/{id}` picks the Groups entry of realm `beta` in the sidebar realm tree
- **THEN** the browser navigates to `/ui/admin/realms/beta/groups`

#### Scenario: Opening a workspace from the realm list
- **WHEN** an admin picks realm `beta` on `/ui/admin/realms`
- **THEN** the browser navigates to `/ui/admin/realms/beta`

#### Scenario: No switch endpoint
- **WHEN** a client sends `POST /admin/switch-realm`
- **THEN** no handler exists for it, and no cookie is set

### Requirement: R-7 Realm meta-management lives under the realm path
Operations that act on a realm itself MUST live under `/ui/admin/realms/{name}/...`, keyed by the realm name and not by its UUID:

| URL | Purpose |
|---|---|
| `/ui/admin/realms/{name}` | workspace landing |
| `/ui/admin/realms/{name}/admins/picker` | HTMX picker |
| `/ui/admin/realms/{name}/admins/grant` | grant realm admin |
| `/ui/admin/realms/{name}/admins/{uid}/revoke` | revoke realm admin |
| `/ui/admin/realms/{name}/claims` | claims config view |
| `/ui/admin/realms/{name}/delete` | delete the realm |

The realm-admin grants list is a section of the workspace landing page `/ui/admin/realms/{name}`. There is no separate `/ui/admin/realms/{name}/admins` page.

#### Scenario: Delete a realm by name
- **WHEN** an admin sends `POST /ui/admin/realms/doomed/delete`
- **THEN** realm `doomed` is deleted

#### Scenario: A UUID in place of the name
- **WHEN** an admin requests `GET /ui/admin/realms/{realm-uuid}`, with the realm's UUID in the name position
- **THEN** no realm by that name exists, and the server answers `404`

### Requirement: R-8 Admin pages emit only realm-qualified links
No admin template MAY emit a URL that matches the regex `/ui/admin/(users|groups|organizations|applications|sessions|audit|rbac|permissions)(\/|$)`; such a URL lacks realm context and SHALL NOT appear. Every realm-scoped link MUST have the form `/ui/admin/realms/{{ realm_name }}/...`.

#### Scenario: Crawl of the admin console
- **WHEN** a crawler follows every link and form action on the admin pages
- **THEN** no URL matches `/ui/admin/(users|groups|organizations|applications|sessions|audit|rbac|permissions)(\/|$)`

