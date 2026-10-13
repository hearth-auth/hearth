## Why

`createHearthAuth().refreshAccessToken()` sends a refresh-token request on every call. Two calls before the first completes send the same refresh token twice. Hearth rotates the refresh token on each use, so the second request is a replay: Hearth revokes the whole token family, and the access token the first request returned stops working.

React's `StrictMode` runs an effect twice in development, so an app that restores its session in a `useEffect` (the full-stack demo's `App.tsx`) signs the user out on every page load. Two components that refresh at the same time, or the scheduled refresh racing a manual one, do the same in production.

## What Changes

- `refreshAccessToken()` shares one in-flight request: a call while a refresh runs gets the same promise and result. A call after it completes starts a new request.
- The scheduled refresh goes through the same function, so it shares the request too.

## Capabilities

### New Capabilities

### Modified Capabilities
- `sdk-support-contract`: "Browser login flow" adds "One refresh at a time" and a scenario.

## Impact

- `sdks/typescript/src/browser-auth.ts`, `sdks/typescript/tests/browser-auth.test.ts`, `CHANGELOG.md`.
- No server change. The other SDKs have no browser login flow.
