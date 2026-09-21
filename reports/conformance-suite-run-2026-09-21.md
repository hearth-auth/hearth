# External conformance suite run — 2026-09-21

**OpenSpec task:** production-readiness-remediation 23.18 — *run one official conformance suite
(OIDC, SCIM or SAML) against Hearth.*

**Hearth under test:** `v1.6.11-158-g718df0fc`, worktree at
`fix/production-readiness-audit-8-28-26-issues` (`8d9376b0` at time of writing).

**Bottom line.** The OpenID Foundation conformance suite (the real one, release `v5.3.1`) was run
against a production-mode Hearth. The **Config OP** certification profile was executed end to end.
Result: **38 conditions passed, 1 failed, 1 warned — the plan FAILS.** The failure is a genuine,
structural Hearth deviation from OpenID Connect Discovery 1.0 §3, not a configuration artefact.
Authorization-flow profiles (Basic/Implicit/Hybrid OP) were **not** run; see
[§7](#7-what-was-not-run-and-why) for exactly how far that got and what it would take.

**Hearth must still not be described as certified.** Running the OpenID Foundation's suite locally
is not certification. Certification requires submitting a passing run to the OpenID Foundation
under a paid membership/certification agreement. This run did not pass, and no submission was made.

---

## 1. Which suite, and why

All three candidates were surveyed before committing.

| Candidate | Is there an *official* harness? | Verdict |
|---|---|---|
| **OIDC** | **Yes** — the OpenID Foundation conformance suite, `gitlab.com/openid/conformance-suite`. This is the harness the OIDF itself uses to grant certification. | **Chosen.** |
| **SCIM** | **No.** The IETF does not certify SCIM and operates no conformance programme. The closest artefacts are Microsoft's hosted Entra SCIM Validator (requires a publicly reachable endpoint) and third-party checkers such as `scim2-tester` (PyPI 0.4.0, python-scim). Useful, but a third-party checker — running it would not have answered the question this task asks. | Rejected: no certifying body's harness exists to run. |
| **SAML** | **Effectively no.** OASIS ran an interop programme that has been dormant for years; the practical options (SAMLtest.id, Kantara-era interop events) are hosted services that need a publicly reachable SP/IdP and, for Kantara, a paid process. | Rejected: hosted-only, needs public ingress. |

OIDC was also the option originally flagged as "the most work". Two things made it tractable:

1. The project publishes **prebuilt container images** (`docker-compose-prebuilt.yml`), so no Maven
   build was needed. Total pull: 614 MB (suite) + 689 MB (mongo:6.0.13) + nginx image, a few
   minutes — well inside the budget this task set.
2. The suite's own HTTP client installs a trust-all `X509TrustManager` and
   `NoopHostnameVerifier` (`AbstractCondition.java:678-702`), so the target may present a
   **self-signed** certificate. HTTPS is still mandatory — `CheckDiscEndpointAllEndpointsAreHttps`
   fails any `http://` endpoint — but a public CA is not.

---

## 2. Configuration (recorded in full)

### 2.1 Hearth — production mode, not `--dev`

Hearth was booted with `serve -c <config>` in **production mode**. `--dev` was *not* used, so none
of the dev relaxations (in-memory storage, mailcatcher, `/admin/bootstrap`, waived TLS/KEK gates)
applied. `hearth config validate` reported `✓ Configuration valid` on this file before the first
boot (at that point `oidc.issuer` was `https://host.docker.internal:8420`; only the issuer host
changed afterwards, for the reason in §2.3).

```yaml
# /scratch/tmp/conformance/hearth.yaml
server:
  bind_address: "0.0.0.0"
  port: 8420
  tls_cert_path: "/scratch/tmp/conformance/tls/hearth.crt"
  tls_key_path:  "/scratch/tmp/conformance/tls/hearth.key"

storage:
  data_dir: "/scratch/tmp/conformance/data"

oidc:
  issuer: "https://hearth:8420"

email:
  transport: log
```

Environment: `HEARTH_KEK` and `HEARTH_MASTER_KEY`, each `openssl rand -hex 32`. Both are required
in production mode — the server refused to start without the KEK, which is correct behaviour.

TLS certificate: self-signed RSA-2048, `CN=hearth`, `subjectAltName=DNS:hearth,DNS:localhost,IP:127.0.0.1`.

Storage was a **fresh empty data directory**. Hearth auto-created a single realm named `default`
(the documented behaviour when the `realms:` key is omitted). No users, clients or sessions
existed — the Config OP profile reads only discovery metadata and the JWKS, so none are needed.

### 2.2 Suite

```
image  registry.gitlab.com/openid/conformance-suite:release-v5.3.1   (614 MB)
image  registry.gitlab.com/openid/conformance-suite/nginx:release-v5.3.1
image  mongo:6.0.13                                                  (689 MB)
compose  docker-compose-prebuilt.yml + a local override (CPU/memory caps)
suite base URL  https://localhost.emobix.co.uk:8443   (resolves to 127.0.0.1)
runner  scripts/run-test-plan.py  (the suite's own headless runner)
```

### 2.3 Network topology — and one thing that had to change

The obvious arrangement (Hearth on the host, suite in Docker, reaching it via
`host.docker.internal`) **does not work on this machine**: the host firewall drops inbound traffic
from the Docker bridges. The first run failed with

```
FAILURE GetDynamicServerConfiguration: Unable to fetch server configuration from
https://host.docker.internal:8420/.well-known/openid-configuration - Connect timed out
```

This is an environment artefact with no bearing on Hearth. It was resolved by running the same
unmodified Hearth binary **inside a container on the suite's own Docker network**
(`debian:12-slim` with `/nix` and `/run/current-system/sw/lib` bind-mounted read-only so the NixOS-
linked binary's interpreter resolves), published as network alias `hearth`. Hearth's configuration,
code and mode were otherwise unchanged.

### 2.4 Test plan configuration

```json
{
  "alias": "hearth-config-op",
  "description": "Hearth v1.6.11-158-g718df0fc — production-mode boot, TLS on",
  "server": { "discoveryUrl": "https://hearth:8420/.well-known/openid-configuration" },
  "client": { "client_id": "conformance-config-op",
              "client_secret": "not-used-by-the-config-profile" }
}
```

A second, identical configuration pointed at the **realm-scoped** discovery document
(`https://hearth:8420/realms/default/.well-known/openid-configuration`), because that — not the
global document — is the URL real relying parties use.

### 2.5 Exact command

```
CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/ CONFORMANCE_DEV_MODE=1 \
  python run-test-plan.py --export-dir <dir> --verbose \
    oidcc-config-certification-test-plan <config.json>
```

---

## 3. Plan executed

`oidcc-config-certification-test-plan` — *"OpenID Connect Core: Config Certification Profile
Authorization server test"*, certification profile name **`Config OP`**
(`src/main/java/net/openid/conformance/openid/OIDCCConfigTestPlan.java`).

Variants: `server_metadata=discovery`, `client_registration=static_client`.
Module: `oidcc-discovery-endpoint-verification`.

This is a real OIDF certification profile. It is the discovery-and-metadata half of OpenID Connect
Core certification: it fetches the discovery document and the JWKS and checks them against OpenID
Connect Discovery 1.0 and RFC 8414. It requires no browser interaction, no client and no user —
which is why it could be run to completion here.

---

## 4. Raw results

Both runs, byte for byte:

```
Test [1:1] oidcc-discovery-endpoint-verification[client_registration=static_client][server_metadata=discovery]
           FINISHED - result FAILED. 53 log entries - 38 SUCCESS 1 FAILURE, 1 WARNING
Overall totals: ran 2 test modules. Conditions: 38 successes, 1 failures, 1 warnings.
** SOME TEST MODULES HAVE CONDITION UNEXPECTED FAILURES **
** SOME TEST MODULES HAVE CONDITION UNEXPECTED WARNINGS **
```

| Run | Discovery URL | Plan id | SUCCESS | FAILURE | WARNING | Plan result |
|---|---|---|---:|---:|---:|---|
| A | `/.well-known/openid-configuration` | `BTeYujuHJJTru` | 38 | 1 | 1 | **FAILED** |
| B | `/realms/default/.well-known/openid-configuration` | `L2eVpzpSG6MB4` | 38 | 1 | 1 | **FAILED** |

The two paths behaved **identically** — same conditions, same single failure, same single warning.
That is itself a useful result: the realm-scoped and global discovery documents do not diverge.

### 4.1 The failure, verbatim from the suite's log API

```json
{
  "src": "OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported",
  "result": "FAILURE",
  "msg": "RS256 support is required, but the server does not list it in id_token_signing_alg_values_supported",
  "discovery_metadata_key": "id_token_signing_alg_values_supported",
  "expected_at_least_one_of": ["RS256"],
  "actual": ["EdDSA"],
  "requirements": ["OIDCD-3"]
}
```

### 4.2 The warning, verbatim

```json
{
  "src": "CheckForUnexpectedParametersInServerMetadata",
  "result": "WARNING",
  "schema_link": "/json-schemas/rfc8414/oauth_authorization_server_metadata.json",
  "requirements": ["RFC8414-2", "OIDCD-3"],
  "unknown_properties": [
    { "property": "resource_indicators_supported", "path": "$.resource_indicators_supported" }
  ],
  "msg": "Unknown properties were found in the OAuth Authorization Server metadata. This may
          indicate the sender has misunderstood the spec, or it may be using extensions the test
          suite is unaware of."
}
```

### 4.3 The 38 conditions that passed

Worth recording, because these are now externally verified rather than self-asserted:

`GetDynamicServerConfiguration` · `EnsureDiscoveryEndpointResponseStatusCodeIs200` ·
`CheckDiscoveryEndpointReturnedJsonContentType` · `CheckDiscEndpointDiscoveryUrl` ·
`CheckDiscEndpointIssuer` · `CheckDiscEndpointIssuerIsValidUrl` ·
`ValidateServerMetadataAgainstSchema` · `CheckDiscEndpointAuthorizationEndpoint` ·
`CheckDiscEndpointTokenEndpoint` · `CheckJwksUri` · `OIDCCCheckDiscEndpointResponseTypesSupported` ·
`CheckDiscEndpointSubjectTypesSupported` · `CheckDiscEndpointScopesSupportedContainsOpenId` ·
`CheckDiscEndpointUserinfoEndpoint` · `CheckDiscEndpointRegistrationEndpoint` · `FetchServerKeys` ·
`MapJwksToValidationLocation` · `EnsureJwksHasNoPrivateOrSymmetricKeyMaterial` ·
`ValidateJwksStructure` · `ParseUsableJwksKeys` · `WarnOnUnusableJwksKeys` ·
`CheckDiscEndpointRequestUriParameterSupported` ·
`CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256` ·
`OIDCCCheckDiscEndpointClaimsSupported` · `OIDCCCheckDiscEndpointGrantTypesSupported` ·
`CheckDiscEndpointScopesSupportedSyntax` · `CheckDiscEndpointLocalesSyntax` ·
`CheckDiscEndpointLocalesCanonicalCasing` ·
`EnsureServerConfigurationCodeChallengeMethodsSupportedIsAnArray` ·
`CheckDiscEndpointAllEndpointsAreHttps` × 9 (authorization, token, userinfo, registration,
device_authorization, revocation, introspection, end_session, pushed_authorization_request).

Two of these are non-trivial and are genuine good news:

- **`EnsureJwksHasNoPrivateOrSymmetricKeyMaterial` passed.** An external auditor confirms the
  published JWKS leaks no private or symmetric key material.
- **`ValidateServerMetadataAgainstSchema` passed** against the suite's RFC 8414 JSON schema, and
  every advertised endpoint is HTTPS.

---

## 5. Per-failure verdict

### 5.1 `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported` — **HEARTH DEFECT** (structural)

**Not** a configuration problem, and **not** a test that does not apply.

Evidence, not assertion:

- The suite's assertion is a hard-coded `String[] SET_VALUES = { "RS256" }` with
  `minimumMatchesRequired = 1`
  (`condition/client/OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported.java`). There is no
  variant, profile switch or configuration key that relaxes it.
- It is correct about the spec. **OpenID Connect Discovery 1.0 §3** says of
  `id_token_signing_alg_values_supported`: *"REQUIRED. … **The algorithm RS256 MUST be included.**"*
  **OpenID Connect Core 1.0 §15.1** ("Mandatory to Implement Features for All OpenID Providers")
  independently requires OPs to support signing ID Tokens with RS256.
- Hearth advertises `"id_token_signing_alg_values_supported": ["EdDSA"]` and nothing else, on both
  the global and the realm-scoped document.

This is a deliberate architectural decision, not an oversight: `CLAUDE.md` states *"Signing:
Ed25519 only. No HS256, no `alg:none`"*, and `docs/specs/OIDC.md:44` states ID tokens are signed
with Ed25519. Cryptographically the choice is defensible — arguably better than RS256. But it has a
consequence the project has not written down anywhere:

> **Hearth cannot pass any OpenID Connect Core certification profile — including the
> discovery-only Config OP profile — while it signs ID tokens with EdDSA alone.** Every OP profile
> (Basic, Implicit, Hybrid, Config, Dynamic, Form Post) runs this same condition.

Note the asymmetry the run exposed: Hearth *does* advertise RS256 for **request objects**
(`request_object_signing_alg_values_supported` includes `RS256`, and the corresponding condition
`CheckDiscEndpointRequestObjectSigningAlgValuesSupportedIncludesRS256` **passed**). So the RSA
verification path exists. What is missing is RSA *signing* of ID tokens.

**Not fixed here.** Adding RS256 ID-token signing means per-realm RSA key generation, storage,
rotation, JWKS publication and a client-level `id_token_signed_response_alg` negotiation — a
feature, not a contained fix, and one that reverses a documented security decision. It needs a
decision from whoever owns that decision, not a patch from a conformance run. **Raise as its own
issue.**

### 5.2 `CheckForUnexpectedParametersInServerMetadata` — **HEARTH DEFECT** (minor, spec hygiene)

**Not** a configuration problem.

`resource_indicators_supported` is not a registered OAuth Authorization Server Metadata parameter.
RFC 8707 (Resource Indicators) deliberately defines **no** metadata parameter, and the name is
absent from the IANA registry. The suite is right to flag it.

It is, however, *deliberate*: `docs/specs/AGENT_AUTH.md:185` says the discovery document **MUST**
include `resource_indicators_supported: true`, and `src/identity/oidc.rs:1203` /
`src/identity/engine/mod.rs:4859` implement exactly that.

So this is a Hearth-specific extension published under an unprefixed, unregistered name. It is a
WARNING, not a FAILURE, and would not block certification on its own. Correct resolutions, in
order of preference:

1. Register the parameter with IANA, or adopt a vendor-prefixed name, or
2. Propose it to the OIDF so the suite learns it (the warning text asks for exactly this), or
3. At minimum, note in `docs/specs/AGENT_AUTH.md` that this is a non-standard extension.

**Not fixed here.** `src/identity/engine/mod.rs` is owned by another agent this session, and
removing an advertised capability that Hearth's own normative spec mandates is a cross-spec change,
not a contained one. **Raise as its own issue.**

### 5.3 Environment artefact, for completeness — **NOT a Hearth defect**

The first run's `GetDynamicServerConfiguration` timeout (§2.3) was the host firewall dropping
container→host traffic. Proven by direct test: `nc -z 172.17.0.1 8420` and `nc -z 172.19.0.1 8420`
from a container on the suite network both failed while Hearth was listening on `0.0.0.0:8420` and
answering on the host loopback. Fixed by moving Hearth onto the suite's Docker network; the run
then completed in 0.2 s. Nothing in Hearth changed.

---

## 6. A defect found alongside the run (not by the suite)

**Startup banner advertises `http://` URLs when TLS is enabled.** With
`server.tls_cert_path`/`tls_key_path` set, Hearth's startup panel printed:

```
  API:     http://0.0.0.0:8420
  Admin:   http://0.0.0.0:8420/ui
  Setup:   http://0.0.0.0:8420/ui/setup  (token redacted in prod — set HEARTH_SETUP_TOKEN)
  ...
  Realms: 0   ·   Email: log   ·   TLS: on
```

`src/main.rs` hard-coded `let base = format!("http://{addr}")` while the same panel, two lines
lower, correctly reported `TLS: on`. Port 8420 is the **TLS** listener; the plaintext redirect
listener is on 8419. An operator following the banner's own `Setup:` URL — the one first-run
instruction Hearth gives — sends plaintext at a TLS socket and gets a connection error, on the
first thing they are told to do after a production boot.

(Separately, and left alone here: the panel echoes the bind address verbatim, so a
`bind_address: 0.0.0.0` boot also prints a host that is not itself connectable. That is a distinct,
pre-existing cosmetic issue and was not in scope for this run.)

**Fixed**, with a test written first. See §8.

---

## 7. What was *not* run, and why

Only the **Config OP** profile was executed. The authorization-flow profiles
(`oidcc-basic-certification-test-plan` and siblings) were **not** run.

How far that got and what remains:

- The suite's browser automation is **in-process HtmlUnit** (`frontchannel/BrowserControl.java`,
  `htmlunit3-driver` in `pom.xml`) — no extra container or Playwright service is needed. So this is
  not blocked on infrastructure.
- What it needs is Hearth-side fixtures that a production-mode boot does not hand you: complete the
  first-run `/ui/setup` flow (token-gated, then an emailed link that lands in the `log` transport),
  create an end-user with a password, register an OAuth client with redirect URI
  `https://localhost.emobix.co.uk:8443/test/a/<alias>/callback`, and then author a `browser` block
  of HtmlUnit selectors for Hearth's login and consent pages.
- **It would fail anyway, for the reason in §5.1.** `oidcc-server` — the first module of every flow
  plan — runs the same `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported` condition. Until
  Hearth can sign an ID token with RS256, no OP flow profile can pass, so the flow run would
  measure the same single defect at much greater cost.

That is the honest reason for stopping, and it is a finding, not an excuse: **the RS256 gap gates
every OIDC certification profile there is.**

Also not run: SCIM and SAML — no certifying body's harness exists to run (§1).

---

## 8. Code change made

One fix, small and contained, TDD'd and mutation-proven.

- `src/main.rs` — `build_startup_panel` now derives the URL scheme from `stats.tls`
  (`https` when TLS is on, `http` otherwise) instead of hard-coding `http://`.
- Tests added in the same file: `startup_panel_uses_https_urls_when_tls_is_enabled` and
  `startup_panel_uses_http_urls_when_tls_is_disabled`. Both were written **before** the fix and
  confirmed red against the unmodified function.

No other Hearth code was changed. In particular nothing in `src/identity/`, `src/protocol/` or the
discovery document was touched — the two real conformance findings are reported, not patched.

---

## 9. Certified-adjacent vs still unverified

### Now externally verified (by the OIDF's own harness, locally)

- Hearth's OIDC discovery document — global **and** realm-scoped — parses, returns HTTP 200 with
  `application/json`, and **validates against the suite's RFC 8414 metadata schema**.
- `issuer` is a valid issuer identifier URL and is consistent with the discovery endpoint it was
  fetched from (no issuer-mismatch class of bug).
- Every advertised endpoint uses HTTPS (9 endpoints checked individually).
- The published JWKS is structurally valid, every key parses, every key uses a supported key type
  and curve, and it contains **no private or symmetric key material**.
- `response_types_supported`, `subject_types_supported`, `scopes_supported` (contains `openid`,
  and every entry is a valid RFC 6749 scope-token), `claims_supported`, `grant_types_supported`,
  `code_challenge_methods_supported` and `request_object_signing_alg_values_supported` all match
  what OpenID Connect Discovery requires.
- 38 conditions in total, listed in §4.3.

### Still unverified

- **Every authorization-flow behaviour.** The authorization endpoint, token endpoint, ID token
  contents and signature, userinfo endpoint, nonce/state handling, PKCE enforcement, `prompt`,
  `max_age`, `claims`, refresh, RP-initiated logout and back-channel logout have **not** been
  exercised by any external suite. The in-repo `tests/oidc_conformance.rs` and friends remain
  hand-written self-assessments.
- **FAPI 2.0.** `tests/fapi_conformance.rs` and `tests/fapi2_conformance.rs` are in-repo. The OIDF
  FAPI plans have not been run.
- **SCIM.** No external checker has been run. `tests/scim*.rs` remains self-assessment.
- **SAML.** No external interop suite has been run.

### The line that must not be crossed

**Hearth is not OpenID Certified, and must not be described as certified, conformant, or
"passing the OpenID conformance suite".** This run *failed* the one profile it executed.
Even had it passed: passing locally is not certification. Certification requires an OpenID
Foundation membership and certification agreement, a submitted passing test log, and OIDF
acceptance. None of that happened here, and no claim of it may be made anywhere in this repo,
its README, its marketing copy, or its SDK documentation.

---

## 10. Reproduction

```bash
mkdir -p /scratch/tmp/conformance && cd /scratch/tmp/conformance
git clone --depth 1 -b release-v5.3.1 https://gitlab.com/openid/conformance-suite.git suite

# Hearth: production-mode config per §2.1, self-signed cert, HEARTH_KEK + HEARTH_MASTER_KEY set.
# Run it on the suite's docker network as alias `hearth` (see §2.3 for why).

cd suite && IMAGE_TAG=release-v5.3.1 docker compose -f docker-compose-prebuilt.yml up -d

python3 -m venv venv && ./venv/bin/pip install httpx pyparsing
cd scripts && CONFORMANCE_SERVER=https://localhost.emobix.co.uk:8443/ CONFORMANCE_DEV_MODE=1 \
  ../../venv/bin/python run-test-plan.py --verbose --export-dir ../../results \
    oidcc-config-certification-test-plan ../../hearth-config-op.json

docker compose -f docker-compose-prebuilt.yml down -v    # tear down
```

Result archives from this run were exported to
`/scratch/tmp/conformance/results-config-op{,-realm}/oidcc-config-certification-test-plan--*.zip`.
`/scratch` is volatile, so the material facts are transcribed verbatim in §4 rather than left in
the archives.

## 11. Teardown

The suite stack (`server`, `mongodb`, `nginx`) was stopped and removed with
`docker compose -f docker-compose-prebuilt.yml -f docker-compose-hearth.yml down -v`, which also
removed the `suite_default` network and the mongo volume. The `hearth` container was stopped and
removed. No Hearth process was left running on the host. Pulled images were left in the local
Docker cache; the suite checkout and all run artefacts are under `/scratch/tmp/conformance`, not
the repository.

## 12. Follow-ups to raise

1. **RS256 ID-token signing** (§5.1) — blocks every OIDC certification profile. Needs a decision:
   support RS256 alongside EdDSA, or accept permanently that Hearth cannot be OpenID Certified and
   say so explicitly in `docs/specs/OIDC.md` and in any customer-facing material.
2. **`resource_indicators_supported`** (§5.2) — unregistered metadata parameter; register it,
   vendor-prefix it, propose it to the OIDF, or at minimum document it as non-standard in
   `docs/specs/AGENT_AUTH.md`.
3. **OIDC flow profiles** (§7) — worth doing once (1) is resolved; the fixtures and the HtmlUnit
   `browser` block are the remaining work, and the suite infrastructure now has a known-good recipe.
