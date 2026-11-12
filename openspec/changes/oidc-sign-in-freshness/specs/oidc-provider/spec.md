## ADDED Requirements

### Requirement: A request can demand a fresh sign-in
A browser authorization request with `prompt=login`, or with a `max_age` (seconds) less than the time since the session's last completed interactive sign-in, SHALL make the user sign in again before a code is issued (OIDC Core §3.1.2.1). With `prompt=none` it SHALL get `login_required` instead. A `max_age` that is not a non-negative integer SHALL get `invalid_request`. The forced sign-in SHALL be a normal sign-in: a new session, and the old one revoked.

#### Scenario: prompt=login on a live session
- **WHEN** a signed-in browser sends an authorization request with `prompt=login`
- **THEN** the response is a redirect to the realm's sign-in page, and no code is issued
- **AND** after the user signs in, the request issues a code from a new session

#### Scenario: max_age older than the session's sign-in
- **WHEN** a signed-in browser sends an authorization request with `max_age=0`
- **THEN** the response is a redirect to the realm's sign-in page

#### Scenario: A silent request that needs a sign-in
- **WHEN** a signed-in browser sends an authorization request with `prompt=none` and `max_age=0`
- **THEN** the client gets `error=login_required` with its `state`, and no code

### Requirement: The request resumes once after a forced sign-in
After a forced sign-in, the authorize request SHALL go on to the code without a second forced sign-in only with a resume marker that is signed by the server, bound to the realm and to the other request parameters, at most 10 minutes old, issued before the session's sign-in completed, and not used before. Any other marker SHALL force the sign-in again.

#### Scenario: A replayed resume marker
- **WHEN** the request that resumed after a forced sign-in is sent again with the same marker
- **THEN** the response is a redirect to the sign-in page

#### Scenario: A marker without a new sign-in
- **WHEN** the browser follows the resume URL without signing in again
- **THEN** the response is a redirect to the sign-in page

### Requirement: The ID token carries auth_time
Every ID token from a code that a browser session authorized SHALL carry `auth_time` (OIDC Core §2): the creation time of that session in seconds, which is when its interactive sign-in completed, including any required second factor.

#### Scenario: auth_time in the ID token
- **WHEN** a code that a browser session authorized is exchanged
- **THEN** the ID token carries `auth_time`, the time that session's sign-in completed
