# SDK conformance harness

One scenario set, four SDK runners, one live server. `scenarios.yaml` lists the
scenarios; `scripts/sdk-conformance.sh` (`make sdk-conformance`) runs them.

## What the driver does

1. Builds `hearth` with `dev-endpoints` and boots two `serve --dev` servers from
   an empty directory: **main** (realm `conformance` with a client-credentials
   client `m2m`) and **expiry** (the same, with 1 s access tokens).
2. Bootstraps main, mints every token kind in `scenarios.yaml`, and writes the
   cases to a JSON file.
3. Runs each SDK's runner on that file, one SDK after another.
4. Fails when a runner's result differs from the scenario's `expect`, or from
   another SDK's result. Each failure names the SDK and the scenario.

## Case file (input of every runner)

```json
{
  "cases": [
    {
      "id": "user-token-validates",
      "kind": "verify_token",
      "token": "<compact JWT>",
      "config": {
        "base_url": "http://127.0.0.1:41234",
        "realm": "dev-realm",
        "issuer": "http://127.0.0.1:41234/realms/dev-realm",
        "audience": "hearth",
        "client_id": null,
        "client_secret": null
      },
      "claims": ["sub", "scope", "permissions"]
    },
    {
      "id": "client-credentials-flow",
      "kind": "client_credentials",
      "config": {
        "base_url": "http://127.0.0.1:41234",
        "realm": "conformance",
        "issuer": "http://127.0.0.1:41234/realms/conformance",
        "audience": "hearth",
        "client_id": "1fd7bb63-a206-526f-9188-4e927579509e",
        "client_secret": "conformance-secret-not-for-production"
      },
      "scope": "openid",
      "claims": ["sub", "scope", "permissions"]
    }
  ]
}
```

- `verify_token`: build a client from `config` and verify `token` through the
  SDK's public verify API (`verifyToken` / `VerifyToken` / `verify_token`).
- `client_credentials`: build a client from `config`, call the SDK's
  client-credentials method with `scope`, then verify the access token it
  returns, as above.
- Build a new client for every case: a case must not reuse another case's JWKS
  cache.

## Runner output

`sdks/<sdk>/conformance/run.sh <cases.json>` prints exactly one JSON line per
case, in case order, on stdout, and nothing else on stdout:

```json
{"id": "user-token-validates", "outcome": "ok", "claims": {"sub": "user_…", "scope": null, "permissions": ["…"]}}
{"id": "alg-none-fails", "outcome": "error", "error": "TokenInvalidError"}
```

- `claims` holds the claims the case names, read through the SDK's public
  claims API: `sub` a string, `scope` a string or `null`, `permissions` a list
  (`[]` when absent).
- `error` is the SDK.md §5 name of the error the SDK raised. PHP reports
  `TokenInvalidException` as `TokenInvalidError`. Anything that is not an SDK
  error is `{"outcome": "error", "error": "Unexpected:<type>"}`; it never
  crashes the runner.
- The runner exits `0` when it ran every case, whatever the outcomes. It exits
  non-zero only when it could not run (bad input, missing toolchain).
