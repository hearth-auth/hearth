# SAML 2.0 Flow — Runnable Example

End-to-end demo of Hearth's SAML 2.0 support. Hearth is a **Service
Provider (SP)**: it consumes a signed `<Response>` from an external
Identity Provider and validates XML-DSIG + audience + destination +
InResponseTo + replay. (Hearth does not act as a SAML IdP — that side was
removed in 3.0.0; connect applications to Hearth over OIDC.)

Unlike [`../federation-flow/`](../federation-flow/) (OIDC) and
[`../oauth-consent-flow/`](../oauth-consent-flow/) (OAuth2), this demo
does *not* spin up a full browser round-trip with a separate IdP
process. Standing up a real SAML IdP (Shibboleth / SimpleSAMLphp / Okta)
is a project in itself, so the demo takes a shortcut: **it impersonates
the external IdP directly from a Node script**,
using `xml-crypto` + `node-forge` to sign and verify SAML XML.

---

## What this example demonstrates

- **SP metadata**: Hearth serves `SPSSODescriptor` at
  `/ui/realms/{realm}/federation/saml/metadata?idp=…`. The demo fetches it
  and reads the ACS URL from it.
- **Assertion Consumer Service (ACS)**: the script generates a fresh
  RSA-2048 keypair + self-signed cert for the fake IdP, inlines the
  cert into `hearth.yaml` before boot, then signs an `<Assertion>` with
  that key and POSTs it to Hearth's ACS endpoint. Hearth verifies the
  signature, audience, destination, and `InResponseTo` against the
  `RelayState` it issued at `begin`.
- **Replay protection**: the same signed assertion is POSTed twice. The
  first succeeds; the second is rejected by the `saml:asn:*` sentinel.
- **Algorithm suite locked to RSA-SHA256 + SHA-256 + exclusive C14N**.
  SHA-1 and RSA-SHA1 are rejected server-side (algorithm-downgrade
  defense); the demo uses the accepted suite throughout.

---

## Prerequisites

- Rust toolchain (for `cargo build --release`).
- Node.js 18+.
- `python3` (used by `run.sh` to parse `cargo metadata` output).

The demo binds to `localhost:8420`. If that port is taken, edit
`hearth.yaml` and the port references in `demo.mjs`.

---

## Run it

```bash
cd examples/saml-flow
./run.sh
```

On success you'll see both acts complete:

```
▸ Act 1 — fetch Hearth's SP metadata
✔ SP metadata served (1742 bytes)
  ACS URL: http://localhost:8420/ui/realms/demo/federation/saml/acs

▸ Act 2 — fake IdP issues a signed Response to Hearth's ACS
  RelayState token: …
  Expected InResponseTo: _h…
✔ ACS accepted signed assertion (HTTP 303)
  Redirect target: /ui/account
✔ replay rejected (HTTP 400)

Both acts completed successfully.
```

After the demo exits, Hearth is torn down automatically. Audit events
for both acts are visible if you boot Hearth manually against
`./hearth.yaml.rendered` and browse to `/ui/admin/audit`.

## Interop note

Building this demo turned into a useful interop exercise. The first run
failed on both sides of the round trip because Hearth's narrow
exclusive-C14N implementation differed from `xml-crypto`'s in two
specific ways: (1) which namespace decls got emitted at element
boundaries, and (2) how an extracted subtree should be canonicalized
when the relevant xmlns decl lives on an ancestor OUTSIDE the subtree.
Both issues were fixed as part of shipping this example — tracked in
the "known limitations" section of gap #6 and in
[`memory/saml.md`](../../memory/saml.md). The working round-trip with
`xml-crypto` is a real-world interop signal, not just Hearth
round-tripping its own output.

---

## Files

| File | Role |
|---|---|
| [`hearth.yaml`](./hearth.yaml) | Template config. `__IDP_CERT_PEM__` is a placeholder `run.sh` substitutes at boot with the freshly generated fake-IdP cert. |
| [`gen-idp-cert.mjs`](./gen-idp-cert.mjs) | Emits `.idp-cred.json` (private key + cert for the fake IdP side) and `.idp-cert.pem` (cert only, inlined into `hearth.yaml.rendered`). |
| [`demo.mjs`](./demo.mjs) | Two-act driver. Hand-rolls SAML XML, uses `xml-crypto` for signing + verification. |
| [`run.sh`](./run.sh) | Build + render + boot + drive + teardown. |

---

## Known shortcuts (phase-1 scope)

This demo reflects the known limitations of the phase-1 SAML
implementation (see `docs/gaps/FEATURE_GAPS.md` gap #6):

- **No SLO.** Single Logout is not supported: no SLO endpoint is
  registered, so a logout at the upstream IdP does not end the Hearth
  session.
- **No signed AuthnRequests on the outbound HTTP-Redirect binding.**
  The `sign_authn_requests: false` flag in `hearth.yaml` reflects this;
  IdPs that require signed requests won't interop yet.
- **Certificate parsing is a narrow DER walker, not a full X.509
  validator.** Cert chains, extensions, and revocation are out of scope;
  Hearth trusts the operator-supplied cert PEM verbatim.

For a checklist of what's still to do before enterprise GA, see
[`memory/saml.md`](../../memory/saml.md) (project-internal notes).
