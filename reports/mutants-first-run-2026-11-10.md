# cargo-mutants first nightly run — 2026-11-10

**OpenSpec change:** `trusted-core-confidence`, task 4.2. **Issue:** #641. Part of #652.

**Run:** [42741969394](https://github.com/hearth-auth/hearth/actions/runs/42741969394), workflow
`mutants-nightly.yml` on `main` at `ec160706`, cargo-mutants 27.1.0, dispatched by hand. All
times are US Eastern (EST).

- Start: 2026-11-09 21:19. End: 2026-11-10 02:25 (5 h 06 min).
- All 13 shards passed. The `budget` job failed, as it must on a first run: no module had a
  recorded budget.
- The runner time was about 50 runner-hours.

## 1. Counts per module

A mutant is in a module when it is in the module's `files` and matches one of its `re`
(`ci/mutants-budget.toml`). "Viable" is caught plus missed: an unviable mutant does not build.

| module | mutants | caught | missed (survivors) | unviable | timeouts | missed / viable |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `token-issuance` | 874 | 551 | **238** | 85 | 0 | 30 % |
| `sessions` | 229 | 126 | **77** | 26 | 0 | 38 % |
| `rbac-resolver` | 384 | 177 | **131** | 76 | 0 | 43 % |
| `permission-check` | 226 | 74 | **96** | 56 | 0 | 56 % |
| **total** | 1,713 | 928 | **542** | 243 | 0 | 37 % |

These counts are the budgets (design Open Question 3: the budget starts at the first-run
count). A later run fails when a module has more survivors.

The run also tested 25 "delete field" mutants that are not in their shard's module.
cargo-mutants 27.1.0 does not apply `--re` to them. 22 match no module and are not counted.
3 are in the other module of `src/identity/engine/mod.rs` (for example, a field of the
session context in `create_derived_session`, tested in a token-issuance shard). The first
version of the check failed on these 3. This PR changes the check: such a mutant is counted
only in the module that holds it, and that module's run tests it too.

## 2. Time per shard

| shard | duration | mutants | mean per mutant | build | test |
| --- | ---: | ---: | ---: | ---: | ---: |
| token-issuance 0/6 | 5 h 06 min | 149 | 121 s | 254 min | 46 min |
| token-issuance 1/6 | 4 h 39 min | 149 | 111 s | 227 min | 49 min |
| token-issuance 2/6 | 4 h 54 min | 149 | 117 s | 238 min | 53 min |
| token-issuance 3/6 | 4 h 14 min | 149 | 101 s | 200 min | 50 min |
| token-issuance 4/6 | 4 h 54 min | 149 | 117 s | 232 min | 59 min |
| token-issuance 5/6 | 3 h 12 min | 147 | 78 s | 155 min | 35 min |
| sessions 0/2 | 3 h 14 min | 122 | 94 s | 155 min | 36 min |
| sessions 1/2 | 3 h 07 min | 122 | 91 s | 150 min | 34 min |
| rbac-resolver 0/3 | 4 h 02 min | 129 | 111 s | 196 min | 43 min |
| rbac-resolver 1/3 | 4 h 05 min | 129 | 113 s | 193 min | 49 min |
| rbac-resolver 2/3 | 2 h 49 min | 129 | 77 s | 136 min | 30 min |
| permission-check 0/2 | 2 h 48 min | 114 | 87 s | 131 min | 35 min |
| permission-check 1/2 | 3 h 02 min | 114 | 94 s | 146 min | 32 min |

The mutant counts include the baseline. About 80 % of the time is the build of each mutant.
The estimate in #799 was about 1 minute per mutant; the real mean is 77 s to 121 s.

The longest token-issuance shard took 5 h 06 min. The job limit is 330 minutes, so that is
too near. This PR gives token-issuance 8 shards (about 111 mutants each, at most about 4 hours).
The run then has 15 shards and leaves 5 of the 20 runners of the GitHub Free plan to PR CI.
From the 00:30 EST start, it ends at about 04:30 EST, before the release PR (about 06:17 EST).

## 3. Where the survivors are

The functions with the most survivors (all mutants in the module's files, also the ones
outside `re`). The full list of each shard is `missed.txt` in the run's artifacts (kept for
30 days), and the `budget` job of the next run lists each survivor.

| module | function | survivors |
| --- | --- | ---: |
| token-issuance | `exchange_authorization_code_inner` (`engine/oauth.rs`) | 15 |
| token-issuance | `introspect_token_inner` (`engine/oauth.rs`) | 14 |
| token-issuance | `rotate_grant_family` (`engine/mod.rs`) | 12 |
| token-issuance | `poll_device_token_inner` (`engine/oauth.rs`) | 10 |
| token-issuance | `issue_tokens_with_context` (`engine/mod.rs`) | 8 |
| token-issuance | `verify_jar_inner`, `initiate_logout_inner` (`engine/oauth.rs`) | 8 each |
| sessions | `revoke_all_user_sessions` (`engine/mod.rs`) | 11 |
| sessions | `sweep_expired_sessions` (`engine/mod.rs`) | 9 |
| sessions | `list_by_realm`, `list_by_user` (`sessions.rs`) | 7, 6 |
| rbac-resolver | `reconcile_roles`, `reconcile_groups` (`rbac/engine.rs`) | 12, 8 |
| rbac-resolver | `orphaned_references` (`rbac/engine.rs`) | 6 |
| permission-check | `CeilingWalk::user`, `admin_holders` (`admin_auth.rs`) | 9, 8 |

Many survivors are arithmetic on times and TTLs (`/` to `%`, `+` to `-`, `<` to `<=`) and
`Debug` or accessor bodies. Some are in checks. Task 4.4 triages the token-issuance and
session survivors: a test that catches each one, or an exclusion with a reason. The design's
Risks entry applies first: a survivor can be one that an integration binary outside the
module's `tests` list catches. Triage then adds that binary to the list.
