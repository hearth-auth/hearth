## Why

OIDC Core §3.1.2.1 says: "Authorization Servers MUST support the use of the HTTP GET and POST methods" at the authorization endpoint. A relying party can send the authorization request from the browser as a form POST (`application/x-www-form-urlencoded`). Today `POST /authorize` and `POST /realms/{realm}/authorize` are only the Hearth JSON API, so a form POST gets `415`. The OpenID Foundation module `oidcc-ensure-post-request-succeeds` fails (#781, part of #639 and #652).

The owner decision on #781 (2026-11-11) is option 1: dispatch on `Content-Type`.

## What Changes

- A form POST to `POST /authorize` or `POST /realms/{realm}/authorize` starts the browser authorization flow with the same parameters and the same checks as a GET: the response is `303 See Other` to the same UI authorize page, with the posted parameters as the query string.
- A JSON POST (any other `Content-Type`) keeps the Hearth JSON API without change.

## Capabilities

### New Capabilities

### Modified Capabilities
- `oidc-provider`: MODIFIED requirement "The authorization endpoint has a browser path and a machine path".
- `abuse-prevention`: MODIFIED requirement "A-47 Unknown fields refused on request bodies" (the browser form POST is a recorded exception, as the GET is).

## Impact

- `src/protocol/http/oauth.rs` (the `POST /authorize` extractor and the redirect helper).
- `CHANGELOG.md`. No config, proto, storage or SDK change.
