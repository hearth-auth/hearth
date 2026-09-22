# Can it fail? — the fuzz targets and the load-test harness

Tasks 23.13 and 23.14 (audit 2026-08-28; both subsystems recorded as "never
examined").

**Counts, measured rather than quoted.** Eleven fuzz targets — `fuzz/Cargo.toml`
declares eleven `[[bin]]` entries, `fuzz/fuzz_targets/` holds eleven files, and
`.github/workflows/fuzz.yml:74-85` runs all eleven. Nothing is orphaned in
either direction. The load harness has **two** Goose scenarios (`HearthJourneys`,
`HearthTierMiss`), **one** non-Goose open-loop driver (`saturate`), **five** run
modes, and **nine** distinct measured request names.

The question asked of both was the same one: *what input makes this thing
report a failure?* Counting precisely, because this audit's numbers have been
understated before:

* **One** fuzz target (`credential_verify`) could not fail for any input at all —
  it called nothing.
* **Two more** (`aat_parse`, `oidc_request_parse`) could fail, but not at
  anything their doc comments claimed: one duplicated `jwt_parse`'s Hearth calls
  statement for statement, the other spent half its budget on `serde_json`.
* **Nine of eleven** ran with no seed corpus, which cost them between 16% and
  322% of their reachable edge coverage (measured below).
* **Five** load-harness verdict paths could not report a failure: the process
  exit code, the overall pass for any journey without a latency budget, the
  ceiling attribution under high failure rates, the tier-miss lookup check, and
  the saturate driver's `/introspect` check.
* **One** load-harness CLI parameter (`--revoked-frac`) did nothing at all while
  being stamped into every report.

## How to read this

A test that cannot fail is worse than no test, because it occupies the slot
where a real one would go and it reports green while doing it. Both subsystems
had instances of the same shape:

| Shape | Verdict |
|---|---|
| Harness reaches the parser and propagates its outcome | Real |
| Harness constructs a value and drops it | **Cannot fail** |
| Harness asserts a status code the server returns unconditionally | **Cannot fail** |
| Verdict computed, written to the report, then discarded by the caller | **Cannot fail** |

## Fuzz targets

### F-1 — `credential_verify` called nothing at all

`fuzz/fuzz_targets/credential_verify.rs` at HEAD was, in full:

```rust
let password = hearth::identity::CleartextPassword::new(data.to_vec());
let lossy_hash = String::from_utf8_lossy(data);
drop(password);
drop(lossy_hash);
```

It constructed two values and dropped them. No verifier, no parser, no Hearth
code beyond a `Vec` move. Its own doc comment claimed it exercised
`verify_token_signature` "as a proxy"; it never called that either.

**Failure scenario.** A parser bug in `verify_pbkdf2_sha256` — the hand-rolled
PHC parser written for Keycloak imports, the only password parser in the tree
not delegated to the `password-hash` crate — ships. The `credential_verify` leg
of the fuzz matrix is green on every PR because it is green for every input
that has ever existed or ever will.

**Proof.** The body above is the whole target. It contains no call into any
Hearth verifier, so no input can make it fail — that is a reading of four lines,
not a probabilistic claim, and it is the strongest form the evidence takes.

The measurement agrees. Running the **new** target for 2 000 executions reaches
**780** libFuzzer edges from an empty corpus and **1 722** from the seeds (table
under F-4). The old body's only Hearth call was `CleartextPassword::new`, which
assigns one field.

**The A/B mutation experiment did not finish in this session, and that is worth
stating plainly rather than implying.** It was set up correctly: a
`git archive HEAD` snapshot in `/scratch` (so the shared worktree was never left
carrying a mutation — a temporary edit was made to `src/identity/credentials.rs`
in the worktree first, then reverted within the minute and confirmed reverted
before any sibling could compile against it), `panic!("MUTATION: verify_hash
reached")` planted at `credentials::verify_hash`, and **both** target bodies
built as separate bins (`credential_verify` and a `credential_verify_old`
carrying HEAD's version verbatim) so the two would differ in nothing but the
harness. The instrumented `hearth` rlib — ASAN + sancov, `codegen-units=1`, on a
box already running two other cargo builds — had not finished linking after 70
minutes. To complete it:

```bash
T=$(mktemp -d); git archive HEAD | tar -x -C "$T"
cp fuzz/fuzz_targets/credential_verify.rs "$T/fuzz/fuzz_targets/"
git show HEAD~1:fuzz/fuzz_targets/credential_verify.rs \
  > "$T/fuzz/fuzz_targets/credential_verify_old.rs"
cat >> "$T/fuzz/Cargo.toml" <<'TOML'

[[bin]]
name = "credential_verify_old"
path = "fuzz_targets/credential_verify_old.rs"
doc = false
TOML
# plant `panic!("MUTATION: verify_hash reached");` after the
# HASH_VERIFICATIONS.fetch_add line in "$T/src/identity/credentials.rs"
cargo +nightly fuzz build --fuzz-dir "$T/fuzz" credential_verify credential_verify_old
# expect: credential_verify_old completes 2 000 runs, exit 0
#         credential_verify aborts on run 1 with the planted panic
```

Naming both bins on the `build` line (rather than building all twelve, which is
what made this run so long) cuts it to one link per target.

**Fixed.** The target now builds a real Argon2id credential once
(`hash_password`), overwrites its `hash` field with the fuzz bytes, and runs it
through `verify_password_with_pepper` — reaching the bcrypt / PBKDF2 /
`PasswordHash::new` prefix dispatch, the four pepper-rotation arms,
`apply_pepper`'s HMAC pre-hash, `PepperKey::from_hex`, and the *success* path
(the correct password against the real hash, so a verifier that always answered
"no" would be distinguishable from one that works).

### F-2 — `aat_parse` was a copy of `jwt_parse`, and named a function it cannot call

`fuzz/fuzz_targets/aat_parse.rs` at HEAD declared "Coverage targets:
`validate_aat` — full chain validation including header, claims, sig" and then
ran `decode_claims_unverified` + `verify_token_signature` + a bare
`serde_json::from_str::<Value>` — statement-for-statement `jwt_parse.rs` plus a
`serde_json` self-test.

`validate_aat` is an `IdentityEngine` **trait method** (`src/identity/mod.rs:2678`,
implemented at `src/identity/engine/mod.rs:15910`). It needs storage, a realm
and a signing key. No `libfuzzer` target can call it, so the claim was not
merely unfulfilled — it was unfulfillable.

**Failure scenario.** Two of eleven CI legs, twenty minutes of runner budget
each, fuzzing the identical two functions while the AAT/actor-token surface the
target is named for goes untested. Anyone reading the matrix sees eleven
distinct targets.

**Structural finding behind it.** `verify_token_signature`
(`src/identity/tokens.rs:906`) and `verify_assertion_signature` (`:975`) reject
on the Ed25519 `verify` call **before** decoding `parts[1]`. Every target that
passes an all-zero key — which is all of them — therefore leaves the
`TokenClaims` and `JwtAssertionClaims` deserializers unreachable *for every
input, forever*. Only `decode_claims_unverified` ever reaches claims JSON.

**Fixed.** The false claim is deleted rather than faked. The target now also
re-shapes the fuzz bytes into a syntactically valid `b64url.b64url.b64url`
triple before feeding them back in, so the claims deserializer is actually
reached — random mutation essentially never produces a dot-separated base64url
triple unaided.

### F-3 — `oidc_request_parse` spent half its budget fuzzing `serde_json`

Two of its four statements were `serde_json::from_slice::<serde_json::Value>`
and `from_str::<Value>`; a third duplicated `jwt_parse`. Its doc comment said
"Attempt to parse as `AuthorizationRequest` JSON" — `AuthorizationRequest`
(`src/identity/oidc.rs:820`) derives only `Debug, Clone`, so there is no serde
path to it and none ever ran.

**Fixed.** It now covers the OIDC documents Hearth deserializes **from a remote
party**, none of which any other target touched: `OidcDiscoveryDocument`
(a federated IdP's well-known document), `JwksDocument` / `Jwk` (that IdP's
`jwks_uri` — the keys signatures are checked against, parsed *before* any
signature is verified), `JarClaims` (RFC 9101 request objects, client-supplied),
`IntrospectionResponse`, and `TokenClaims`. It also builds a JWKS wrapper around
the fuzz bytes so the per-key field decoders are reached, which a top-level
parse of random bytes never gets to.

### F-4 — nine of eleven targets ran against an empty corpus

`fuzz/seeds/` held inputs for exactly two targets (`redirect_uri_parse`,
`token_exchange_parse`). The workflow (`fuzz.yml:121-126`) falls back to
`cargo fuzz run <target> -- -runs=1000` when `fuzz/seeds/<target>` is absent,
which starts libFuzzer from the empty input.

**Failure scenario.** A thousand random mutations from empty will not produce a
`<samlp:Response>` envelope, a dot-separated base64url JWT, a CBOR attestation
map, or a 33-byte-minimum WAL record with a valid operation byte. Those legs
proved "the target links and does not panic on garbage" and nothing else, while
reading as coverage of SAML, JWT, WebAuthn and WAL parsing.

**Fixed.** 91 hand-written seeds added across the nine bare targets, shaped to
the real grammar and including the adversarial cases each parser exists to
survive — SAML signature-wrapping and namespace-confusion envelopes, XXE and
billion-laughs DTDs, `alg:none` and `alg:HS256` JWTs, a WAL record with a
lying key length, a WebAuthn credential-ID length that overruns its buffer,
PBKDF2 PHC strings with zero iterations / trailing data / bad base64.

**Measured.** Each target built at `nightly-2026-07-29` equivalent (local
`nightly`, `rustc 1.98.0-nightly f46ec5218`) with ASAN + sancov, then run twice
for 2 000 executions: once from an empty directory (what CI did for nine of
them), once from `fuzz/seeds/<target>/`. `cov` is libFuzzer's edge count, `ft`
its feature count.

| Target | cov, no seeds | cov, seeded | ft, no seeds | ft, seeded | Seeded edge gain |
|---|---:|---:|---:|---:|---:|
| `config_parse` | 2 406 | 2 797 | 3 479 | 5 656 | +16% |
| `jwt_parse` | 218 | 920 | 300 | 1 908 | **+322%** |
| `wal_entry_deserialize` | 25 | 55 | 26 | 56 | **+120%** |
| `credential_verify` | 780 | 1 722 | 912 | 3 294 | **+121%** |
| `oidc_request_parse` | 842 | 1 804 | 1 244 | 4 065 | **+114%** |
| `webauthn_cbor_parse` | 725 | 1 058 | 1 194 | 2 477 | +46% |
| `federation_claims` | 329 | 906 | 412 | 1 662 | **+175%** |
| `saml_xml_parse` | 486 | 1 792 | 586 | 4 419 | **+269%** |
| `token_exchange_parse` | 869 | 1 213 | 1 278 | 3 119 | +40% |
| `redirect_uri_parse` | 130 | 246 | 255 | 476 | +89% |
| `aat_parse` | 512 | 1 198 | 741 | 2 878 | **+134%** |

`wal_entry_deserialize` is the clearest case: 25 edges in 2 000 runs from
empty. `WalEntry::deserialize` rejects anything under 33 bytes before touching
a field (`src/storage/wal.rs:130`), and random mutation from the empty input
rarely clears that, so the target was measuring one length check. With a real
serialised record to mutate, it reaches 55.

No target crashed in any of the 22 runs — 44 000 executions total, exit 0
throughout — so the parsers themselves stand up; the seeds change what "no
crash" is evidence *of*.


### F-5 — `fuzz/Cargo.lock` had drifted from the tree, and OSV was scanning the stale copy

Running `cargo fuzz build` at HEAD rewrites 118 lines of `fuzz/Cargo.lock`:
`bcrypt` 0.16.0 → 0.19.3, `getrandom` 0.2.17 → 0.4.2, `blowfish`, and a `base64`
0.23.1 that was not in the file at all. The main tree had moved; the fuzz
lockfile had not.

`.github/workflows/security.yml:307` passes `--lockfile=fuzz/Cargo.lock` to
osv-scanner as part of its declared **production scope**. So the advisory scan
was auditing a dependency set that has not been built since the bumps landed: a
CVE against `bcrypt` 0.19.x would not have matched, and one against 0.16.0 would
have been reported against a version nothing builds.

**Fixed.** The regenerated lockfile is committed.

### F-6 — `fuzz/target/` was not gitignored

`.gitignore:2` is `/target/`, anchored to the repo root. `fuzz/artifacts/` and
`fuzz/corpus/` are listed (`:22-23`); `fuzz/target/` is not. A local
`cargo fuzz run` leaves several GB of untracked build output in `git status`,
in a tree where `git add -A` is a documented hazard.

**Fixed.** One line in `.gitignore`.

### F-7 — the CI invocation makes libFuzzer write into the tracked seeds directory

`fuzz.yml:123` runs `cargo fuzz run <target> "$SEEDS"`. libFuzzer treats its
**first** corpus argument as the directory it *writes* newly-discovered units
into; only later arguments are read-only inputs. So `fuzz/seeds/<target>/` — the
hand-written, reviewed, version-controlled corpus — is also the fuzzer's output
directory.

Observed directly while doing this audit: two 2 000-run passes over the eleven
targets left between 14 and 364 machine-generated files in each seed directory,
including 131 new untracked files inside the two seed directories that were
already tracked. On a CI runner the checkout is thrown away so nothing is lost,
but it also means CI's discovered inputs are discarded rather than promoted, and
any developer who runs the documented command dirties the repository.

**Exact change** (in `.github/workflows/fuzz.yml`, outside this task's
boundary): `mkdir -p "fuzz/corpus/${{ matrix.target }}"` and then
`cargo fuzz run <target> "fuzz/corpus/<target>" "$SEEDS"` — the writable corpus
first, the read-only seeds second. `fuzz/corpus/` is already gitignored for
exactly this purpose.

### F-8 — `ci.yml` computes a `fuzz-targets` filter that nothing consumes

`ci.yml:75` exports `fuzz-targets` from the paths filter, `:189-192` defines it
(`fuzz/**`, `src/**`, `Cargo.lock`), and `:230` prints it into the job summary
table. No job anywhere reads `needs.filter.outputs.fuzz-targets`. The same is
true of `bench-targets` (`:76`, `:193-196`, `:231`).

Harmless in itself, but it is a filter output that looks like a gate in the
summary table and is not one — the kind of thing that makes a later reader
believe fuzz is wired into `required-summary` when it is deliberately not.
`.github/workflows/` is outside this task's boundary; listed below.

### F-9 — the nightly pin lives only in the workflow (reported, not fixed)

`fuzz.yml:99` pins `nightly-2026-07-29` with a careful comment explaining the
HEA-2019 exit-143 regression. There is no `rust-toolchain.toml` anywhere in the
repo, so a developer running `cargo fuzz` locally gets whatever nightly they
have — and on this machine `cargo fuzz build` on the default stable toolchain
fails outright with "the option `Z` is only accepted on the nightly compiler",
with no hint that a specific nightly is required.

Adding `fuzz/rust-toolchain.toml` would fix the local case but **not** CI:
rustup resolves the file from the working directory, and the workflow invokes
`cargo fuzz` from the repo root. Someone who owns `.github/workflows/` should
decide whether to add the file plus a `--manifest-path`-independent guard, or to
document the required invocation in `fuzz/README.md` (which does not exist).

## Load-test harness

### L-1 — the run's verdict was computed, written to the report, and thrown away

`loadtest/src/load.rs` ended `run_load` with a bare `Ok(())`, and
`loadtest/src/main.rs:64-65` maps `Ok(())` to `ExitCode::SUCCESS`. Every mode
computes a `pass` (`load.rs:689` steady, `:742` ramp, `:773`/`:799` soak, `:904`
tier-miss), prints it — `report: … (pass=false)` — and serialises it to
`report.json`. Nothing ever read it back.

`.github/workflows/loadtest-smoke.yml:80-81` runs `make loadtest-smoke` on every
PR touching `loadtest/**` or `src/**`. Its own header calls it a "PR gate that
proves the load-test harness is alive (HEA-1991)" and says a typecheck-only
`loadtest-check` "cannot catch runtime failures like 'no live tokens'". It could
only ever prove the binary did not crash.

**And it still cannot block a merge.** `loadtest-smoke` is absent from
`required-summary`'s `needs:` list (`ci.yml:1401`), so it runs on its own
`pull_request` trigger — exactly the shape ci.yml's own comment at `:1337-1340`
describes as "could not fail a merge, however red they went" for the five
workflows that were folded in. It was not folded in. Fixing the exit code makes
the job capable of going red; making that red matter is a `.github/workflows/`
change and is listed below.

**Failure scenario, with evidence committed in this repo.** Of the 29
`report.json` files under `loadtest/reports/`, **27 have `"pass": false` and 15
have `"failure_rate" >= 0.99`** — runs in which effectively every request
failed, achieving 13 to 285 RPS. Every one of them exited 0. Had any of them
been a CI run, the check would have been green.

**Fixed.** `run_load` now returns `LoadError::JourneyFailures` when a journey
exceeds the 5% error budget (`load.rs:474-481`), so the process exits non-zero.
A **latency** breach deliberately stays advisory: `loadtest/README.md` documents
that the sub-ms budgets are expected to read `pass:false` on an ordinary dev box,
so gating the exit code on latency would make the command fail everywhere and
mean nothing. The gate also walks every ramp step and soak bucket
(`load.rs:490`), not only the primary rows — a ramp keeps only the knee step in
`journeys`, so a step where the corpus ran dry would otherwise be invisible.

### L-2 — a journey with no latency budget could fail every request and still pass

`budget_for` (`budget.rs:86`) returns `None` for the compound revoke
sub-requests, so their `JourneyRow::pass` is `None`. `overall_pass` read that as
`rows.iter().all(|r| r.pass.unwrap_or(true))` — **`None` counted as a pass**.

**Failure scenario.** `journey_revoke_revalidate` mints a token, revokes it, and
introspects expecting `active:false`. If revocation silently stops taking
effect — the exact class of defect that
`reports/follower-bypass-enumeration-2026-09-21.md` documents four instances of —
every `revoke_revalidate` comes back `active:true`, `expect_active` marks all of
them failed, and the run still reports `"pass": true`. The single most
security-relevant assertion the harness makes had no path to the verdict.

The same function's sibling `budget::passes` carries the doc comment "a journey
that 100%-errors but responds in 1 ms must NOT read as a pass" — the rule was
written down and then bypassed one layer up.

**Fixed.** `report::failing_journeys` (`report.rs:562`) applies the failure-rate
gate to every row, budgeted or not; `overall_pass` (`:575`) now requires it.
Per-row `pass` semantics are unchanged, so `any_breach` — which ramp mode uses
to find the knee — still means "latency breach" and a health failure is not
mistaken for a saturation point.

### L-3 — a run in which everything timed out was blamed on server latency

`summarize` tested `any_breach(rows)` **first** and only then the failure rate.
At a 100% failure rate every response-time sample is a client-side timeout, so a
"breach" is guaranteed and the verdict was `ceiling: "server"`, whose
`ceiling_reason` reads "server latency is the limiter; the observed ceiling is
the server under test".

**Failure scenario, again with committed evidence.**
`loadtest/reports/hea1812/steady-600u.json` has `"failure_rate": 1.0`,
`"achieved_rps": 13.3` and `"ceiling": "server"`. **All 15** of the
effectively-all-failing archived runs carry `"ceiling": "server"` — the
misattribution is unanimous, not incidental. `loadtest/README.md`'s own
"Failure onset" section, describing that exact step, says the opposite: server
CPU fell from 178% to 5.8% and it was the co-resident generator that collapsed.
The human prose and the machine-readable verdict in the same repository
disagreed, and the machine-readable one is what a nightly regression diff reads.

**Fixed.** `report.rs:215` tests the failure rate first. A clean breach (failure
rate within budget) still attributes to `Server`, so the real signal is intact;
the `correct_ceiling_with_resources` post-pass still covers the harder case of a
clean breach against an idle server. Three existing tests asserted
`ceiling == Server` as a *pre-condition* for 100%-failing rows — that
pre-condition was the defect, and they now construct it from a clean breach.

### L-4 — the tier-miss sweep could measure a corpus that was not there

`tier_lookup` (`scenarios.rs:579`) checked only `resp.status().is_success()`.
`GET /dev/probe-user` returns **200 whether or not the user exists** —
`src/protocol/http/admin.rs:3021` says so: "Return 200 regardless of
found/not-found — the measurement is latency, not correctness. A missing user
(e.g. index > corpus_size) contributes a fast cached-miss path, which is fine
noise for the sweep."

**Failure scenario.** Point a tier-miss run at a realm whose bulk corpus was
never seeded, or overstate `--tier-miss-corpus-size`, and every probe misses.
Every request returns 200. The failure rate reads 0%. The report publishes
`hot_p50_ms`, `cold_p50_ms`, `hot_p95_ms`, `cold_p95_ms` and the hot/cold tier
delta — the entire point of the mode — computed over not-found lookups. "Fine
noise" is a claim about the *proportion* of misses, and nothing measured that
proportion.

**Fixed.** The handler already returns the resolved `user_id` (null on a miss);
the sweep simply ignored it. A miss is now a failed request
(`scenarios.rs:656`), so `MAX_FAILURE_RATE` bounds how much of the sample may be
misses and L-1's exit gate fails the run past that.

### L-5 — `--revoked-frac` never revoked anything

`SeedClient::revoke` (`client.rs:395`) had **zero callers anywhere in the
crate**. `seed.rs` wrote `revoked: false` for every minted token, hard-coded.

Meanwhile `--revoked-frac` is a real CLI flag with an env fallback, range
validation (`params.rs:242`), a default of `0.1`, a derived count helper
(`params.rs:280 revoked_per_realm`), and a place in the parameter summary
(`params.rs:336-341`) that is stamped into **every report's `dataset_shape`** as
`revoked/realm=N`. `run-loadtest.sh:45` documents it as "fraction of live tokens
pre-revoked".

**Failure scenario.** Every archived report in `loadtest/reports/` states a
corpus property that did not exist. `LoadContext::from_handle`
(`scenarios.rs:106`) filters `!t.revoked` precisely so the validate journey is
never handed a dead token; with nothing ever marked revoked, that filter was a
no-op and the guarantee it encodes was unimplemented. This is the plainest
instance in either subsystem of a number in a report that nothing produced.

**Fixed.** The seed step now revokes `revoked_per_realm()` of the minted tokens
over `POST /revoke` and marks them (`seed.rs:190-212`), and the seed summary
line prints the counts actually achieved rather than the parameter's claim. One
token is always kept live (`revoke_target_count`, `seed.rs:254`) because
`revoked_per_realm` is a fraction of the *session* count and can exceed the
tokens minted — revoking all of them would fail the run with `NoLiveTokens`.

### L-6 — the saturate driver counted `/introspect` rejections as hot-path hits

`fire_validate` (`saturate.rs:286`) returned `resp.status().is_success()` and
discarded the body. `POST /introspect` answers **200 for an inactive token** —
`tests/tokens.rs:927` pins exactly that, asserting `StatusCode::OK` and
`json["active"] == false` for a forged token. The Goose journey's own doc
comment states the rule the open-loop driver broke:
"Introspection returns 200 even for inactive tokens, so a status check is not
enough — the body's `active` flag is what proves we exercised the live validate
path rather than the reject path."

**Failure scenario.** `saturate` mode maintains its own token pool, independent
of the Goose corpus, and is the mode used to find the server's throughput
ceiling. If that pool goes stale — revoked, expired, or minted against a realm
that was re-bootstrapped between seed and run — every `/introspect` returns 200
with `active:false`. The driver counts each as a success, the failure rate reads
0%, and the *published ceiling* is the rate at which Hearth can reject tokens,
which is cheaper than validating them. The number is wrong in the direction that
flatters the product, and nothing in the report would say so.

This is the same defect as L-4, in a second place, and it is the one place where
the codebase had already written down the correct rule and then not applied it.

**Fixed.** `fire_validate` now also requires the body to report `active: true`
(`saturate.rs:317`). The body was already being read to return the connection to
the pool, and the check is a substring test rather than a `serde_json` parse, so
it costs the generator nothing measurable — which matters in a driver whose
purpose is to not be the bottleneck.

### L-7 — the loadtest crate had never been clippy'd

The crate is excluded from the workspace (root `Cargo.toml` `exclude`), so
`make clippy` never reaches it, and `make loadtest-check` runs only `cargo check`
+ `nextest`. `cargo clippy --manifest-path loadtest/Cargo.toml --all-targets --
-D warnings` was **red at HEAD** with three `dead_code` errors — one of which
(`SeedClient::revoke`) was L-5 announcing itself, in the repo's own lint output,
to anyone who ran the command.

**Fixed** as far as this task's file boundary allows: the crate is now clean
under that command. Wiring it into `make loadtest-check` is a Makefile change
and is proposed below.

## Does the pipeline actually run at HEAD?

Yes. `make loadtest-smoke`'s script was run end to end on this machine with the
fixes in place — `USERS=20 RUN_TIME=15s CORPUS_*=200/150/100/50
USERS_PER_REALM=50`, which is exactly what `.github/workflows/loadtest-smoke.yml`
runs:

```
==> Building release hearth + loadtest binaries   (8m15s + 1m47s)
==> Booting hearth on http://127.0.0.1:44221 (dev, large corpus target=500 users)
==> Large corpus resident; proceeding to token-pool seed + run
    created 50 users
    minted 50 access tokens
    pre-revoked 3 of 50 access tokens
    created 25 sessions
  wrote seed handle: … (50 users, 25 sessions, 50 tokens of which 3 revoked)
==> Running load (mode=steady, users=20, run-time=15s, throttle=0)
  report: loadtest/reports/report.json (pass=false)
SMOKE_EXIT=0
```

That single run proves four things at once:

1. **The pipeline is alive.** 114 156 requests across all seven journey names,
   7 610 RPS, `"failure_rate": 0.0`, all status codes 200/201.
2. **L-5's fix works over real HTTP.** `pre-revoked 3 of 50 access tokens` is
   three genuine `POST /revoke` calls; `dataset_shape`'s `revoked/realm=3` is now
   backed by something, and the seed summary prints what was achieved rather
   than what was requested.
3. **L-1's gate does not false-alarm.** Every journey is at 0% failures, so
   `unhealthy_journeys` is empty and the process exits 0 — while the report
   still says `"pass": false`, for exactly the documented sub-ms-budget reasons.
   The latency verdict and the exit code are now two different statements, which
   is the point.
4. **L-3's precedence change behaves.** `failure_rate: 0.0` with a real latency
   breach still attributes `ceiling: "server"`; the change only fires when the
   samples are not admissible.

## What IS genuinely covered

Neither subsystem is a facade. This is what stands up.

| Area | Evidence |
|---|---|
| WAL, SAML, WebAuthn, federation-claims, redirect-URI, token-exchange, config fuzz targets | Each calls a real parser entry point with the raw bytes and propagates its `Result`. None catches a panic; there is no `catch_unwind` anywhere in `fuzz/`. |
| SAML target breadth | All five SAML parsers (`parse_response`, `parse_authn_request`, `parse_logout_request`, `parse_logout_response`, `parse_idp_metadata`) on the same bytes — the widest single target. |
| Fuzz CI wiring | All eleven targets in the matrix, `fail-fast: false`, pinned nightly, seeds passed when present. No `continue-on-error` anywhere in `fuzz.yml`. |
| Journey response assertions | Every `HearthJourneys` journey asserts something, and the two that need more than a status code get it: `journey_validate` and `journey_revoke_revalidate` parse the body and check the `active` flag in **both** directions (`true` after mint, `false` after revoke), with a doc comment explaining why `/introspect`'s status alone is insufficient. `session_lookup` / `user_lookup` / `issuance` correctly rely on the status, because `/userinfo` and `/admin/users/{id}` do answer 401/404 on failure. |
| `mint_token` error handling | Transport error, non-2xx, invalid JSON, and missing/empty `access_token` are four distinct `set_failure` tags. |
| Empty-corpus refusal | `LoadContext::from_handle` fails closed on no realms, no live tokens, no users, no admin token — four named errors with operator-facing messages. A run cannot start against an empty corpus. |
| Budget provenance | Every engine p99 in `budget.rs` is cited to a `docs/specs/TESTING.md` line, and `engine_constants_match_testing_md` is a test that fails if one drifts. The HTTP budgets are `engine + documented envelope`, and a test pins that formula. |
| The headline throughput number | "≈ 1677 RPS @ 500 users, 0 failures" in `README.md:624` is backed by `loadtest/reports/hea1812/steady-500u.json` (`achieved_rps: 1677.888…`, `failure_rate: 0.0`). It is a measurement, not a prediction typeset as one. |
| Ceiling honesty | The `Ceiling` enum exists at all, including an `Unknown` arm that refuses to attribute a breach without resource evidence, and the README's "Failure onset" section explicitly retracts an earlier, wrong "collapse by 1000u" claim. The instinct is right; L-3 was a precedence bug inside it, not an absent idea. |
| Loopback guards | `guard_run_host` and the seed step's equivalent refuse a non-loopback target unless explicitly overridden. |
| Test count | 142 unit tests in the loadtest crate, all passing (`cargo nextest run --manifest-path loadtest/Cargo.toml`). |

Every load-harness fix in this report was pinned by a test written before the
fix and verified non-vacuous by mutation: reverting `overall_pass`'s new
conjunct and stubbing out `unhealthy_journeys`' primary-row scan turned exactly
`an_all_failing_unbudgeted_journey_sinks_the_overall_verdict` and
`an_all_erroring_run_is_reported_as_unhealthy` red and nothing else, and both
came back on restore. The ceiling-precedence change additionally forced three
pre-existing `correct_ceiling_with_resources` tests to be retargeted, because
their stated *pre-condition* — `ceiling == Server` for rows that were 100%
failing — was the defect itself.

## Per-design — NOT defects

Recording these so a later sweep does not "fix" them.

| Thing | Why it is right |
|---|---|
| `fuzz.yml` is advisory, not in `required-summary` | Documented at `fuzz.yml:9-31` with three reasons, a named owner and a monthly review cadence. Nightly has no stability guarantee; a nightly regression should not block stable-channel PRs. The one stale detail is "Next review due: 2026-09-01" — overdue, and outside this task's file boundary. |
| `let _ = parse(...)` in every fuzz target | This is the libFuzzer idiom, not a swallowed panic. The target asserts absence of *abort*; a returned `Err` is the correct outcome and discarding it is right. There is no `catch_unwind` in `fuzz/`, so a panic still aborts the process and is reported. |
| `fuzz/corpus/` gitignored while `fuzz/seeds/` is tracked | The split is deliberate and documented in `fuzz.yml:117-119`: seeds are hand-written and reviewed, corpus is machine-accumulated. |
| `make loadtest` is not a per-PR gate | `Makefile:72-78` and `README.md` both say nightly/pre-release only. A 1.2M-user corpus seed is not a PR-time cost. The PR-time gate is the separate small-corpus `loadtest-smoke`. |
| Latency breaches do not fail the process | The sub-ms budgets are engine targets plus a loopback envelope and are documented to breach on a dev box; `issuance` breaches by design because it runs a real Argon2id hash. Gating the exit code on them would make the command fail everywhere. The error-budget gate (L-1) is the one that discriminates. |
| `budget_for` returns `None` for the revoke sub-requests | Correct: no atomic engine target maps to mint→revoke→re-validate. The defect was treating "no latency budget" as "no verdict at all" (L-2), not the `None` itself. |
| Goose percentiles are whole milliseconds | A library constraint, compensated for by the harness's own microsecond `min_us`/`max_us`, and the README says plainly that percentile columns only resolve to whole ms. |
| Journey weights, including zero | A weight of `0` dropping a journey is a documented feature (`--weight-* 0`), and `all_zero_weights_are_rejected` stops it degenerating to nothing. |

## Too large to fix here — for whoever owns these files

1. **Unbounded PBKDF2 iteration count** — `src/identity/credentials.rs:562-572`
   parses `i=` from a stored PHC string as a `u32` and rejects only zero. A
   legacy import declaring `i=4294967295` makes every login attempt for that
   user run ~4.3 billion HMAC-SHA256 rounds. Off the hot path and the value is
   importer-supplied rather than attacker-supplied, so the severity is limited,
   but it is unbounded work driven by stored data. **Exact change:** reject
   `iterations > 10_000_000` in `verify_pbkdf2_sha256` alongside the existing
   zero check, with the same `IdentityError::InvalidInput` shape. Until then
   `credential_verify` skips such inputs (`MAX_PBKDF2_ITERATIONS`) so the fuzz
   leg reports crashes instead of hanging.

2. **`make loadtest-check` should run clippy** — it runs `cargo check` +
   `nextest` only, and the crate is outside the workspace, so nothing in the
   repo lints it. **Exact change:** add to the `loadtest-check` target in
   `Makefile`, between the existing two lines:
   `PROTOC=$(PROTOC) cargo clippy --manifest-path loadtest/Cargo.toml --all-targets $(CARGO_FLAGS) -- -D warnings`.
   The crate is clean under that command as of this commit, so it goes in green.

3. **`loadtest-smoke` is not a required check** — see L-1. **Exact change:** add
   a `loadtest-smoke` entry to `ci.yml`'s folded-in workflow block calling
   `./.github/workflows/loadtest-smoke.yml` gated on
   `needs.filter.outputs.rust == 'true'`, add `loadtest-smoke` to
   `required-summary`'s `needs:` array (`ci.yml:1401`), add a
   `LOADTEST_SMOKE: ${{ needs.loadtest-smoke.result }}` env entry, and add
   `"$LOADTEST_SMOKE"` to the allowlist loop. All four edits are required —
   `ci.yml:362-363` records that a job joining `needs:` but not the results loop
   is a fail-open. Worth doing only now that the job can actually fail.

4. **`fuzz.yml`'s overdue review date** — line 31 says "Next review due:
   2026-09-01". Owner of `.github/workflows/`: bump it, or convert the cadence
   comment into a scheduled job that actually fires.

5. **A repo-level nightly pin for `cargo fuzz`** — see F-9. The pin exists only
   inside the workflow, so `cargo fuzz build` from a clean checkout fails with a
   message that does not name the required toolchain.

6. **libFuzzer writes into the tracked seeds directory** — see F-7 for the exact
   two-line change to `fuzz.yml`.

7. **Dead paths-filter outputs in `ci.yml`** — `fuzz-targets` and
   `bench-targets` are computed and printed but consumed by nothing (F-8).
   **Exact change:** either delete the two outputs and their two summary lines,
   or wire them to the jobs they were meant to gate.

8. **`/dev/probe-user` could report the miss explicitly** — the endpoint already
   returns `user_id: null` and the harness now treats that as a miss, so this is
   no longer load-bearing. If the endpoint is revisited, returning 404 for a
   miss would let any future consumer get this right by default rather than by
   reading a comment.
