## ADDED Requirements

### Requirement: A hosted form submission never ends in a redirect off Hearth's origin
The UI `Content-Security-Policy` SHALL set `form-action 'self'`, in dev and in production, with no extra origins. Browsers apply `form-action` to every redirect that follows a form submission. So when one of these hosted form POSTs would answer `303 See Other`, Hearth SHALL answer `200` with a continue page instead:

- the sign-in form: realm, realm-scoped and admin
- the TOTP, email-OTP and required-MFA-enrolment second-factor forms
- the required-action forms
- the consent form, approve and deny

The continue page SHALL navigate to the redirect target with a `Refresh: 0;url=…` header and a matching `<meta http-equiv="refresh" content="0;url=…">`. It SHALL show a link to the same target. It SHALL NOT carry a `Location` header. The response SHALL keep every `Set-Cookie` header of the redirect it replaces. A `GET` to these routes, and any response that is not `303`, SHALL be unchanged.

#### Scenario: Sign-in for a client on another origin
- **WHEN** a user submits the sign-in form during an authorization request for a client whose `redirect_uri` is on another origin
- **THEN** the response is `200` with a continue page whose target is the UI authorize URL
- **AND** a browser that follows the page reaches the client's `redirect_uri` with an authorization code

#### Scenario: Consent is approved
- **WHEN** a user approves the consent form
- **THEN** the response is `200` with a continue page whose target is the client's `redirect_uri` with `code` and `state`

#### Scenario: Consent is denied
- **WHEN** a user denies the consent form
- **THEN** the response is `200` with a continue page whose target is the client's `redirect_uri` with `error=access_denied`

#### Scenario: The session cookie survives
- **WHEN** a sign-in form submission succeeds
- **THEN** the continue page response sets the session cookie and the CSRF cookie

#### Scenario: Dev mode keeps the strict directive
- **WHEN** Hearth runs with `--dev` and a browser loads a `/ui` page
- **THEN** the CSP `form-action` directive is exactly `'self'`
