## MODIFIED Requirements

### Requirement: The authorization endpoint has a browser path and a machine path
`GET /realms/{realm}/authorize` SHALL answer `303 See Other` to the UI authorize page `/ui/realms/{realm}/oauth/authorize`, preserving every query parameter. `GET /authorize` SHALL do the same to `/ui/oauth/authorize`. A `POST` to either path with `Content-Type: application/x-www-form-urlencoded` is a browser authorization request (OIDC Core §3.1.2.1): it SHALL answer `303 See Other` to the same UI authorize page, with every posted parameter in the query string, so that it gets the same checks as a GET. A `POST` with any other `Content-Type` is the machine path for server-to-server flows. `POST /realms/{realm}/authorize` on the machine path SHALL return a JSON authorization code that the caller can exchange at `/token`. The machine path SHALL require a valid Bearer token. The token's `sub` claim SHALL be the user identity, and any `user_id` field in the request body SHALL be ignored.

#### Scenario: A SPA redirects the browser to the advertised endpoint
- **WHEN** a browser sends `GET /realms/{realm}/authorize?client_id=…&state=…`
- **THEN** the response is `303` to `/ui/realms/{realm}/oauth/authorize` with the same query string

#### Scenario: A relying party sends the authorization request as a form POST
- **WHEN** a browser sends `POST /realms/{realm}/authorize` with `Content-Type: application/x-www-form-urlencoded` and the body `client_id=…&state=…`
- **THEN** the response is `303` to `/ui/realms/{realm}/oauth/authorize` with the posted parameters as the query string
- **AND** no Bearer token is needed

#### Scenario: An unauthenticated machine authorize
- **WHEN** a caller posts a JSON body to `/realms/{realm}/authorize` without a Bearer token
- **THEN** the request is refused and no code is minted

#### Scenario: A body names another user
- **WHEN** a caller posts to `/realms/{realm}/authorize` with a valid Bearer token and a `user_id` that names another user
- **THEN** the code is minted for the token's `sub`
