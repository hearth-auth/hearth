# Performance Framing Rule

**Status:** Internal guidance. Enforced by code review and this document.
**Issued:** 2026-08-12 (HEA-2152). **Updated:** 2026-10-10 (network plane; `docs/perf/` is the source of record). References `README.md` §Performance and [`docs/perf/README.md`](../perf/README.md).

---

## The rule

**Every public-facing performance figure must carry two qualifiers inline:**

1. **The measurement plane** — `engine`, `HTTP` or `network`. These are not interchangeable.
2. **A commit SHA** that is a provably ancestor of HEAD (`git merge-base --is-ancestor <sha> HEAD` must return 0).

If either qualifier is absent or the SHA fails the ancestry check, the figure is not cleared for external use.

---

## Why

Hearth measures performance on three planes:

| Plane | Scope | Excludes |
|-------|-------|---------|
| **Engine** | Direct in-process call into `EmbeddedIdentityEngine` / storage | HTTP parsing, TCP, TLS, axum stack |
| **HTTP** | Loopback request to the running server | TLS, network RTT, external proxy |
| **Network** | HTTPS request from a separate load-generator host to the running server | External proxy |

Every competitor publishes end-to-end HTTP figures. An engine figure placed beside a competitor's HTTP figure is a **category error** — it is not a comparison. A network-plane figure is the closest to a competitor's figure, but it is still not a comparison unless the hardware, the configuration (for example the KDF parameters) and the load shape are the same.

The SHA requirement exists because benchmark results are host-, build-, and configuration-sensitive. A figure stamped with a SHA that is not an ancestor of HEAD cannot be reproduced from the public repository and therefore cannot be verified by a reader.

---

## How to apply

Before adding or editing any performance claim in `README.md`, `docs/`, `docs/vision/`, blog posts, or comparison articles:

1. Confirm the figure is in a report in [`docs/perf/`](../perf/README.md) (the source of record).
2. Confirm the SHA cited in that row passes `git merge-base --is-ancestor <sha> HEAD`.
3. Add the plane label inline — e.g. "(engine plane)", "(HTTP plane)" or "(network plane)".
4. If the SHA fails the ancestry check, either re-run the benchmark at a current SHA and add a new report to `docs/perf/`, or remove the claim until re-verification is done.

---

## What triggered this rule

The README headline "Sub-millisecond p99" lacked a plane qualifier. Combined with competitor HTTP-plane figures elsewhere, this created exactly the category error the README itself warns against (README:204).

Additionally, README:210 claimed figures were "HEAD-verified at `1b6b7745`" but that commit is not an ancestor of HEAD — it lives on `feature/perf-updates-7-28-26` and was never merged. The claim was removed in `af4edb59` and replaced with a dated measurement reference pending re-verification.

---

## Checklist for future marketing revisions

- [ ] All engine-plane figures labeled "(engine plane)" inline.
- [ ] All HTTP-plane figures labeled "(HTTP plane)" inline.
- [ ] All network-plane figures labeled "(network plane)" inline.
- [ ] Every SHA in performance claims verified as a HEAD ancestor.
- [ ] No competitor comparison mixes planes.
- [ ] A report in `docs/perf/` is the cited source of record.
