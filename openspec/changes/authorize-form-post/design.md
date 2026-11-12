## Context

`GET /authorize` and `GET /realms/{realm}/authorize` answer `303` to the UI authorize page (`/ui/oauth/authorize`, `/ui/realms/{realm}/oauth/authorize`) with the same query string. The UI page does every check of the browser flow. `POST` on the same paths is the bearer-authenticated JSON API.

## Goals / Non-Goals

**Goals:**
- A browser form POST gets the same flow and the same checks as a GET.
- A JSON POST does not change.

**Non-Goals:**
- A second implementation of the browser flow for POST.
- A move of the JSON API to another path (a breaking change, option 2 of #781).

## Decisions

1. **Dispatch on `Content-Type`.** `application/x-www-form-urlencoded` (any letter case, any parameters such as `charset`) is the browser path. Every other `Content-Type`, and none, goes to the JSON decoder as before, so the JSON API keeps its `415` and its `400` answers.
2. **Redirect, not an in-process call.** The form POST answers `303 See Other` to the UI authorize page with the posted parameters as the query string. The browser then sends the same GET that a GET request leads to, so the UI page does the same checks. A `303` makes the browser use GET.
3. **Decode and encode the form again.** The query string comes from `serde_urlencoded`, so it is always a valid URI query and a valid header value. A body that does not decode gets `400 invalid_request`.
4. **The body only.** The parameters come from the form body. A query string on the POST URL is not used (OIDC Core §3.1.2.1 serializes a POST request in the body).

## Risks / Trade-offs

- [The parameters go into the URL of the GET that follows] → The same parameters are in the URL of every GET authorization request; a `request` object or PAR keeps parameters out of the URL when that matters.
- [A cross-site page can make a browser POST to `/authorize`] → It can already send the browser to `GET /authorize` with a link; the POST gives it nothing more.
