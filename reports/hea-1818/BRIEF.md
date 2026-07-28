# HEA-1818 Phase 2 — Coverage Mapping Subagent Brief

You are one of ~11 parallel read-only subagents in the Hearth Test Suite Audit (Phase 2:
coverage mapping). **READ-ONLY. Do NOT modify any code, tests, or specs.**

## Goal
For your assigned domain, cross-reference the code-derived feature inventory against the
actual test suite and classify coverage. This is a *coverage* audit (does a test exist and
at the right layer?), NOT a *test-accuracy* audit (that was Phase 3, separate).

## Inputs (read only the slices assigned to you in your task prompt)
- Feature inventory: `reports/hea-1818/feature-inventory.md` (your line ranges)
- Scenario checklist: `docs/specs/TEST_SCENARIOS.md` (your sections)
- Authoritative live-test list: `reports/hea-1818/nextest-list.txt` — every test binary +
  test name that `cargo nextest list` enumerates. A test present here is compiled and
  live. If the file is missing/empty, fall back to reflex/grep.

## Method
1. For each inventory feature-row (and each assigned TEST_SCENARIOS checkbox), locate the
   test(s) exercising it. Use `mcp__reflex__search_code` / `mcp__reflex__search_regex`
   over `src/**`, `tests/**`, `simulation/**`, `sdks/**`. Confirm the test is LIVE:
   - present in `nextest-list.txt`, OR a real `#[test]`/`#[tokio::test]`/proptest/madsim fn.
   - NOT `#[ignore]`d (grep the fn for `#[ignore]`) — an ignored test = not live.
   - Not a doctest (Hearth bans doctests).
2. **HEA-720 guard:** for every checked `[x]` box in your TEST_SCENARIOS sections, verify a
   real, live, non-ignored test backs it. Flag any checkbox that maps to: no test found,
   an ignored test, a deleted/renamed test, or a vacuously-named-but-absent test. These are
   "checkbox-complete-but-unreachable" findings — HIGH signal.
3. **Unchecked-box triage:** for each `[ ]` box in your sections, decide: still-relevant
   coverage GAP vs. obsolete scenario (feature removed / superseded). State which.
4. Classify each feature:
   - **covered** — behavioral assertions at the right layer (e.g. black-box/integration for
     a route; property/sim for storage invariants).
   - **weakly covered** — only happy-path, only unit-level for something needing integration,
     or only tangential coverage.
   - **uncovered** — no live test exercises it.
5. Note security-relevant gaps explicitly (auth bypass, tenant isolation, crypto, token
   validation, RBAC enforcement, abuse/ratelimit). These rank first in the final gap list.

## Deliverable
Write `reports/hea-1818/domain-<YOURKEY>.md` with:
- A coverage table: `| feature | entry point | test(s) (file:fn or nextest id) | classification |`
- A subsection "Checkbox re-verification" listing each assigned `[x]` box → live test id, or
  a ❌ finding if unreachable.
- A subsection "Unchecked-box triage" (gap vs obsolete, one line each).
- A "Gap list (ranked, security-first)" subsection: each gap = feature, risk, why, suggested
  test layer.

Then RETURN (as your final message) a compact summary:
- domain key + counts: `covered=N weak=N uncovered=N`
- checked boxes verified vs. ❌ unreachable count (list the ❌ box titles)
- unchecked-box triage: gaps vs obsolete counts
- top 5 gaps ranked security-first (one line each)
Keep the returned message under ~400 words; the full detail lives in your file.
