## Context

The UI router (`src/protocol/web/mod.rs`) sends one CSP for every page. Its `form-action` directive is `'self'`, plus extra loopback origins under `--dev` only (`security.dev_csp_form_action_origins`, HEA-2072/HEA-2084).

CSP Level 3 checks `form-action` against each URL of a navigation that a form submission starts, redirects included. Chrome enforces this. The hosted sign-in chain is:

1. The form POSTs to Hearth (for example `/ui/realms/{realm}/login`).
2. Hearth answers `303` to `return_to`, which is the UI authorize URL.
3. The UI authorize page answers `303` to the client's `redirect_uri`, with the code.
4. The application's callback may answer `303` again, to its front end.

Steps 3 and 4 leave Hearth's origin, so Chrome blocks them. The second-factor, required-action and consent POSTs end in the same way: some through `return_to`, and some (`issue_code`, `resume_oidc_flow`, the consent deny path) with a direct `303` to the client.

The passkey flows use `fetch()` and set `window.location` from a JSON body, so `form-action` does not apply to them. Two of their wrappers (`as_json_continuation`, `redirect_as_json`) build that JSON by reading the `Location` header of an inner `303` response.

## Goals / Non-Goals

**Goals:**
- Every hosted sign-in path reaches a client on any origin in Chrome, with `form-action 'self'` in dev and in production.
- One mechanism, applied in one place per route, that does not depend on the redirect target.

**Non-Goals:**
- No change to the URLs, parameters or codes that the flows produce.
- No change to the passkey `fetch()` flows.
- No per-client CSP.

## Decisions

### End the form navigation on a continue page

A response layer wraps the affected POST routes. When the handler answers `303 See Other`, the layer replaces the response with `200` and a small HTML page. The response carries a `Refresh: 0;url=TARGET` header, and the page carries the matching `<meta http-equiv="refresh" content="0;url=TARGET">` and a visible "Continue" link to `TARGET`. A document runs only its first declarative refresh, so the two never navigate twice. The header lets a non-browser client and the tests read the target without parsing HTML. The form navigation ends on that page, which is on Hearth's origin. The refresh is a new navigation that no form starts, so `form-action` does not apply to it or to any redirect after it.

Alternatives considered:
- **Add the client's origin to `form-action` for each request.** This covers step 3 only. Chrome also checks step 4, the application's own redirect, which Hearth cannot know.
- **A production allow-list in config.** Each operator must first find the failure and then keep the list current. It weakens the directive for every page.
- **Drop `form-action`.** It is defence in depth against an injected form that posts data off-site. The continue page keeps it at no cost.
- **JavaScript navigation.** A declarative refresh works without script and needs no change to `script-src`.
- **Send the continue page only to requests with `Sec-Fetch-Mode: navigate`.** That would keep a plain `303` for API clients. But Chrome does not send `Sec-Fetch-*` to a plain-HTTP origin that is not localhost, and it still enforces `form-action` there, so a browser on such an origin would stay blocked.

A probe in Chromium confirmed both halves of the decision: a `303` to another origin after a form POST under `form-action 'self'` is blocked (`Sending form data to … violates the following Content Security Policy directive: "form-action 'self'"`), and the same POST answered with this continue page lands on the other origin.

### Wrap at the route, not inside the handlers

The layer acts on the outer response of the listed routes only. `issue_code`, `resume_oidc_flow` and `resume_browser_flow` keep their `303`, so the passkey wrappers that read the inner `Location` keep working.

The layer converts every `303` of a listed POST, also when the target is on Hearth's origin. A same-origin target such as the authorize page can itself redirect off-origin, and only the full chain decides. The cost is one extra page load at sign-in.

The layer acts on `POST` only. The listed routes also serve their `GET` form, which the layer leaves alone.

### Keep the headers of the redirect

The layer keeps every header of the `303` except `Location` and the body headers. Sign-in sets its session and CSRF cookies on that response, and the MFA and required-action steps set or clear their pending cookies on it. The security layer then adds the CSP and `Cache-Control: no-store`, because the page is `text/html`.

### A minimal page outside the layout

The page does not extend `ui/_layout.html`. The layout needs realm branding and session fields that a response layer does not have. The page links `app.css` and uses theme tokens, so it shows the dark surface for the moment it is visible.

## Risks / Trade-offs

- [One extra round trip on each wrapped POST] → Sign-in is not on the hot path. The page is small and has no subresources except `app.css`, which the browser has in cache.
- [A client that scrapes these forms and reads `Location`] → Hearth has no such supported client. The test helpers read the continue page.
- [The target URL is written into HTML] → The layer HTML-escapes it. The targets come from the handlers, which already validate them (`return_to` allow-list A-52, registered `redirect_uri`).
- [A future sign-in POST that is not in the list] → The requirement names the rule, and the reference-integration suite runs in Chrome without extra `form-action` origins.
