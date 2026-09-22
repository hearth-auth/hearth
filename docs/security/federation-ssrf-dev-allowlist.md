# Decision — no development allowlist for the federation SSRF guard

**Status:** Decided — **Option (a), no allowlist.**
**Date:** 2026-09-15
**Scope:** `src/webhook/ssrf.rs`, `src/identity/federation/http.rs`, `examples/federation-flow/`
**Raised by:** production-readiness audit 2026-08-28, task 25.23 (follow-up to 25.12)

---

## The problem

`UreqFederationTransport::send` puts every federation back-channel fetch —
discovery, `token_endpoint`, `userinfo_endpoint`, `jwks_uri` — through the
crate-wide guard in `src/webhook/ssrf.rs`:

- `check_webhook_url` refuses anything that is not `https://`, resolves the
  host, and refuses if **any** resolved address falls in a private, loopback,
  link-local, CGNAT, documentation, benchmarking, reserved or cloud-metadata
  range;
- the agent is built through `ssrf_agent`, whose `SsrfResolver` re-checks the
  exact addresses `ureq` is about to `connect()` to, closing the DNS-rebinding
  TOCTOU;
- `https_only(true)` and `max_redirects(MAX_WEBHOOK_REDIRECTS /* 0 */)` are
  unconditional.

There is no bypass, no allowlist and no `--dev` exemption anywhere on that
path. The guard behaves identically in `--dev` and in production.

The consequence is that a **self-contained local federation demo is impossible
by construction**. `https://localhost:9090` fails the address check even with a
valid certificate, and `http://localhost:9090` fails the scheme check first.
Task 25.12 therefore rewrote `examples/federation-flow/README.md` to require a
public https tunnel (`cloudflared` / `ngrok`) in front of the local
`node-oidc-provider`, and to say plainly that the guard is deliberate. That is
honest, but it adds a third-party dependency and a network round trip to what
is otherwise a three-process local example, and it is the only example in the
repository that cannot be run offline.

The question this note answers: **should the guard grow a narrow,
explicitly-opted-in development allowlist?**

---

## What is actually at stake

The federation upstream URLs are **configuration-supplied, server-dereferenced
URLs** — a textbook SSRF sink. Two properties make this sink worse than the
webhook sink it shares code with:

1. **The fetch carries Hearth's own network identity.** Hearth runs inside the
   trust boundary that internal services assume. Loopback reaches Hearth's own
   admin plane and `/metrics`, plus every sidecar bound to `127.0.0.1` in the
   same pod. RFC 1918 reaches the whole VPC. `169.254.169.254` reaches AWS/GCP/
   Azure instance metadata, i.e. the node's IAM credentials.
2. **The response is parsed and partially reflected.** Discovery and userinfo
   responses are JSON-decoded; their fields land in JIT-provisioned user
   records and in audit `metadata`, and upstream failures are surfaced in the
   error path. That turns a blind SSRF into a semi-blind one, which is enough
   to exfiltrate an IMDS credential document.

Realm-level federation config is written through `hearth.yaml` and through the
admin **visual config editor** (`POST /ui/admin/config-editor/visual/apply`),
which is a raw JSON→YAML passthrough with no key allowlist that writes
`hearth.yaml` on a running instance. So the principal who chooses the upstream
URL is not necessarily the same operator who would have chosen to arm an
allowlist. An allowlist is a control one principal turns on and a *different*,
less-trusted principal gets to aim.

---

## Options considered

### (a) No allowlist. Keep the tunnel requirement. *(chosen)*

Ship exactly what exists. `examples/federation-flow` keeps its step 1b tunnel
and its explanatory banner.

- **Attack surface added:** none.
- **Cost:** the federation example needs `cloudflared` or `ngrok`; it cannot be
  run on an air-gapped machine. Every other example stays offline-capable.
- **Risk:** developer friction, and the secondary risk that a frustrated
  developer patches the blocklist locally and ships the patch. Mitigated by
  the README already explaining *why* the guard has no bypass.

### (b) A `--dev`-gated hardcoded loopback exemption

`is_ssrf_blocked` (or the federation call site) consults a `dev_mode` boolean
and skips `127.0.0.0/8` + `::1`. No config key; the exemption is compiled in
and armed by the `--dev` flag.

- **Attack surface added if it reaches production:** full loopback SSRF —
  Hearth's own admin plane, `/metrics`, and every co-located sidecar.
  Link-local and RFC 1918 would stay blocked, so IMDS and the VPC stay out of
  reach. That is a materially smaller blast radius than (c).
- **How it could reach production:** `dev_mode` is `#[serde(default)]`, not
  `#[serde(skip)]` — a `dev_mode: true` line in any YAML document populates it.
  What keeps that closed today is a single explicit refusal in
  `Config::from_yaml_str`, the checked loader; the *unchecked* loaders still
  honour the key. A runtime boolean guarding a security bypass is one
  regression in one `if` away from being config-settable. The audit already
  found this exact shape twice (§4.7#3, §4.13#10).
- **Stronger variant:** gate on a **compile-time `cfg`/feature** instead of a
  runtime boolean, so a release binary physically cannot contain the exemption.
  This is the precedent task 20.1 set when it moved the dev and test endpoints
  off a runtime boolean and onto a compile-time `cfg`.

### (c) An explicit config key, gated on dev mode, with a start-up WARN

e.g. `security.federation.dev_ssrf_allowlist: ["127.0.0.0/8"]`, honoured only
when `dev_mode` is true, logging a loud `WARN` at boot.

- **Attack surface added if it reaches production:** whatever the operator
  typed. An allowlist that accepts arbitrary CIDRs accepts
  `169.254.0.0/16` — the IMDS range — and `10.0.0.0/8`. The failure mode is
  not "loopback is reachable"; it is "the blocklist is now operator-editable",
  and copy-paste from a StackOverflow answer is a realistic way it gets set to
  something wide.
- **How a config key leaks into production — five concrete paths:**
  1. **The same file is promoted.** `hearth.yaml` travels from laptop to image
     to ConfigMap. Nothing strips a dev-only key on promotion, and nothing
     warns at build or deploy time.
  2. **`serve --dev` with no `-c` auto-detects `./hearth.yaml`.** Developers
     therefore edit the *production-shaped* file in the working tree rather
     than a separate dev file — so the dev-only key gets added to the file that
     is shipped. (`effective_config_path` / `load_config` in `src/main.rs`;
     this trap was already recorded during task 13.14.)
  3. **The admin visual config editor writes `hearth.yaml` on a live
     instance.** It is a raw JSON→YAML passthrough with no key allowlist, and
     `POST /ui/admin/config-reload` applies the result. The key can be typed
     into a running production server.
  4. **`HEARTH_*` environment variables are read as config, and `env_file`
     injects every key**, so a root `.env` overrides a bind-mounted
     `hearth.yaml` (task 13.11). A dev `.env` baked into an image re-arms the
     key with no YAML change at all.
  5. **The dev gate is itself soft.** See (b): `dev_mode` is a
     `#[serde(default)]` boolean whose only guard is one refusal in one loader.
     A key gated on it inherits that guard's strength, not more.
- **Additional cost:** a `WARN` at start-up is the weakest possible safeguard.
  Production logs are not read at boot, and the audit has already found
  fail-soft gates whose only consequence was a warning nobody saw (§4.11#12,
  §4.13#2).

---

## Recommendation

**Adopt option (a): no allowlist, in any form, for the federation SSRF guard.**

Rationale, in one line: the demo friction is one third-party tunnel binary,
and the thing being traded for it is the only control standing between a
config-supplied URL and the node's IAM credentials.

Option (c) is rejected outright. A config key is the single worst shape here,
because every surface that can write config in this system — the file that
gets promoted, the auto-detected working-directory file, the admin visual
editor, and `HEARTH_*`/`.env` — is a promotion path into production, and
because an operator-editable CIDR list re-opens IMDS, which a hardcoded
loopback exemption never would.

If the demo friction is later judged unacceptable, the **only** acceptable
escape hatch is the compile-time variant of (b), and it requires **all** of:

1. **Compile-time only.** `#[cfg(feature = "dev-federation-loopback")]`, the
   feature absent from the default set, absent from every published build, and
   proven absent by a test that asserts `cfg!(not(feature = …))` plus a CI job
   that builds the release artifact `--no-default-features`-clean. Precedent:
   task 20.1.
2. **No operator-writable surface.** No config key, no CLI flag, no environment
   variable, no admin-API toggle. If it can be written, it can be promoted.
3. **Loopback only, hardcoded.** `127.0.0.0/8` and `::1`, as literals in the
   source. Never RFC 1918, never `169.254.0.0/16`, never `100.64.0.0/10`, and
   never an operator-supplied CIDR — under any build.
4. **The scheme and redirect guards stay unconditional.** `https_only(true)`
   and `MAX_WEBHOOK_REDIRECTS = 0` do not move. The local demo would then need
   a `mkcert`-style local certificate instead of a tunnel, which is a strictly
   cheaper ask than a public hostname and keeps the scheme guard whole.
5. **Visible at runtime.** A start-up `WARN` *and* a persistent banner in the
   admin UI naming the build as non-production — the banner, not the log line,
   is the part that gets noticed.
6. **A red test for the default build.** An assertion that the
   default-features binary still refuses `https://127.0.0.1:9090`, so the
   exemption cannot silently become the default. Prove it by mutation: remove
   the `cfg` and watch exactly that test fail.

Until all six exist, the answer is (a).

---

## Consequences

- `examples/federation-flow/README.md` keeps its tunnel requirement and its
  explanation of why there is no bypass; no change is needed.
- `src/webhook/ssrf.rs` and `src/identity/federation/http.rs` are unchanged by
  this decision.
- Any future PR proposing a `security.*` key that relaxes an SSRF, egress or
  scheme guard should be closed with a reference to this note.
