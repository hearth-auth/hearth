# HEA-1946 — K7 disk footprint: CTO decision record

**Status:** decision recorded, implementation delegated
**Date:** 2026-07-29
**Owner:** CTO
**Parent:** HEA-1940 (PERFORMANCE_REPORT v2) → HEA-1867 (perf/load programme)

---

## 1. The miss

| | Value | Source |
|---|---|---|
| Measured bytes-on-disk / user | **2,840 B** (OLS), 2,805 B (endpoint) | `docs/perf/HEA-1904-C0-RERUN-POST-LAYERBA.md`, commit `c82d8eb8` |
| K7 budget (VISION §7.3: <200 GB @ 100M users) | **2,147 B / user** | `docs/vision/VISION.md` §7.3 |
| Projected @ 100M users | **264 GiB** | 2,840 × 1e8 |
| Gap | **1.4×** | |

Per-user storage shape (from HEA-1867 record-size analysis): **5 records** — primary
`User`, email-index entry, and 3 audit events. All postcard-encoded.

SST v3 (HEA-1914) changed the *block framing* but not the *per-record payload*, so
neither v3 nor the HEA-1922 streaming compaction moved this number.

---

## 2. Options considered

### Option A — ZSTD block compression in SST v3

Compress each ~4 KiB data block before AEAD sealing.

- **Reach:** all 5 record classes.
- **Change surface (small, well-contained):** `SstWriter::seal_block` and
  `seal_block_streaming`, one extra field on `BlockIndexEntry`, the footer
  write/parse pair, and the two decrypt sites
  (`SstReader::decode_block_uncached` and the cached block path).
  `src/storage/sst.rs` only.
- **Dependency:** none new — `zstd` is already a workspace dependency
  (`src/backup/mod.rs` uses it for backup archives).
- **Does NOT help K4/K5/K6.** The block cache holds *decompressed* blocks, and
  the memtable is uncompressed. Resident memory is unchanged. See §5.

### Option B — compact (bit-packed) audit event encoding

Replace the postcard `StoredAuditEvent` encoding (HEA-1899) with a packed binary form.

- **Reach:** 3 of 5 records — but byte *share* is what matters, and that was
  unmeasured until this issue. See §3.
- **Helps K4–K6 as well as K7**, because those 3 audit records are also 3 of the
  5 resident SkipMap entries per user. This is a real strategic advantage over
  Option A that the issue description did not credit.

### Option C — audit retention / tiering *(not in the original issue; raised here)*

3 audit events per user retained forever is a **product** decision, not a storage
one. A retention policy, or moving audit to a separate append-only store excluded
from the per-user footprint budget, is potentially the cheapest lever of all — and
the only one that is O(1) in engineering cost. Requires a board/product call, so
it is raised, not decided, here.

---

## 3. Measurement — do not choose without it

The issue description asserts Option A yields "40–60% reduction". **That figure was
an estimate, not a measurement, and it is not safe to plan against.** Hearth's
payload is unusually hostile to compression: every record is dominated by v4 UUIDs
(16 random bytes each), Argon2id hashes, and random session/token identifiers — all
high-entropy and effectively incompressible. What *does* compress is the repeated
structure: field framing, repeated realm IDs, repeated audit event-type strings,
and shared email-domain suffixes.

The real ratio could plausibly land anywhere from 1.1× to 2.5×, and the difference
decides whether Option A alone closes a 1.4× gap or misses it.

Probe (`examples/sst_compression_probe.rs`, HEA-1946) therefore measures, on a real
corpus written through the real code paths and read back as plaintext via the public
`StorageEngine::scan`:

1. **A validation gate first** — the probe's own corpus must reproduce ≈2,840 B/user
   on disk. If it does not, the corpus is unrepresentative and *no ratio it reports
   is trustworthy*. This gate exists because HEA-1901 caught a perf report that
   invented totals from joined tables; a compressibility number from a
   non-representative corpus is the same failure mode.
2. Ratios at zstd levels 1 / 3 / 6, with implied B/user and GiB@100M vs the
   2,147 B budget.
3. **Per-record-class breakdown** (user primary / email index / audit) with each
   class's *share of total bytes* and its own standalone ratio. This is the only
   thing that can tell us whether Option B alone could ever be sufficient — if
   audit records are 30% of bytes, no audit-only encoding change closes 1.4×.
4. Compression throughput, since this lands on the flush and compaction write paths.

### 3.1 Probe results (`examples/sst_compression_probe.rs`, N=12,000)

**Validation gate: PASS.** The probe corpus reproduced 2,812 B/user (N=4,000) and
2,815 B/user (N=12,000) — within 1% of the 2,840 B C0 baseline. Built through the
real `EmbeddedIdentityEngine::create_user` path over a real `EmbeddedStorageEngine`;
nothing synthesized. Ratios below are therefore trustworthy.

| zstd level | ratio | B/user (SST steady state) | GiB @100M | K7 |
|---|---|---|---|---|
| 1 | 0.333 | 385 | 35.8 | PASS |
| 3 | 0.335 | 387 | 36.0 | PASS |
| 6 | 0.334 | 386 | 35.9 | PASS |

Level is irrelevant at 4 KiB — the higher levels' window never pays off. **Level 1**,
at 424 MB/s single-threaded (~80 ms CPU per 32 MiB flush).

Per-class byte share and standalone ratio:

| class | share of bytes | own ratio (L1) |
|---|---|---|
| audit (`audit:*`) | **79.1%** | 0.336 |
| user primary | 13.7% | 0.365 |
| email index | 7.2% | 0.247 |

So the §3 worry was unfounded — the payload compresses ~3× despite the UUID/Argon2
entropy, because postcard framing and repeated realm IDs and event-type strings
dominate. Option A would close K7 with ~3× headroom.

**But two findings displace it entirely. See §3.2 and §3.3.**

### 3.2 The 2,840 B/user baseline is a small-N measurement artifact

`Wal::rotate_locked` (`src/storage/wal.rs`) runs the pre-rotate flush and then
`file.set_len(0)` on a **single** WAL file, with `max_size` defaulting to **64 MiB**
(`src/storage/engine.rs:124`). WAL disk is therefore hard-bounded at 64 MiB — **O(1),
not O(N)**.

At N=12,000 the WAL had accumulated only ~20 MB and **had never rotated**, so it was
still behaving as an O(N) term. It contributed **59%** of the measured
"bytes-on-disk-per-user". That 59% does not scale.

Confirmed empirically by the probe: at **N=60,000 the WAL rotated and disk/user fell
to 1,738 B with zero code changes**, while SST/user held at 1,192 B. Asymptotically
disk/user → SST/user.

**Implication: K7 arguably already passes, uncompressed.** ~1,192 B/user →
**111 GiB @100M**, against a 200 GB budget — roughly 1.8× headroom, versus the
reported 1.4× *miss*. The K7 MISS in PERFORMANCE_REPORT v2 is likely an artifact of
measuring at an N too small to force WAL rotation, not a real product deficiency.

This must be confirmed by re-measurement before the board verdict is amended. The
1,192 B/user SST figure was measured at 60k and extrapolated 1,600×; that
extrapolation assumes compaction keeps SSTs near live size, which is credible
(HEA-1931 set `max_sst_count` to 12) but is an assumption, not a measurement.

### 3.3 Duplicate `UserCreated` audit event on the admin REST path (correctness bug)

The probe found **8.00 keys/user, not the 5 assumed** by the HEA-1867 record-size
analysis: `usr:id`, `usr:email`, and **two** `UserCreated` audit events × 3 keys each.

Verified independently:

- `src/identity/engine/mod.rs:2621` — `create_user_with_status` emits `UserCreated`
  via `record_audit` with `actor: None`.
- `src/protocol/http/admin.rs:704` — the `admin_create_user` handler emits a *second*
  `UserCreated` with `actor: auth.user_id` and `metadata: {"via": "admin_api"}`.

Every admin-API user creation writes **two** audit events for one logical action.
This is a **correctness defect before it is a storage defect**:

- The audit trail double-counts user creations, and one of the two records a **null
  actor** — an auditor or compliance export counting `UserCreated` gets 2× the true
  number with half the entries unattributed.
- The per-realm HMAC hash chain gains two links per logical event.

Storage impact is nonetheless large: audit is 79.1% of stored bytes and half of it is
redundant, so **~39.5% of all stored bytes per user are a duplicate record**. Removing
it takes SST/user from ~1,192 B to ~721 B (≈67 GiB @100M) on its own.

The fix is *not* to delete the identity-layer emitter — it is the only one covering
self-registration, SCIM, and import. The correct shape is to thread the actor down and
emit exactly once at the identity layer.

### 3.4 Probe caveats (carried forward honestly)

- `scan` returns latest-value-only, so live plaintext (961 B/user) is less than
  on-disk by design.
- Users-only corpus (`sessions_frac=0`) — same as C0, so apples-to-apples with the
  target, but it excludes sessions, credentials, and tokens.
- Steady-state SST/user assumes compaction holds SSTs near live size; observed at
  60k, extrapolated to 100M.
- Per-class ratios pack each class into its own blocks; real SSTs interleave by key
  order, so the per-class numbers are indicative, not exact.

---

## 4. Design constraints for Option A (binding on the implementer)

These are the non-obvious ones. They are binding because each maps to a defect class
this codebase has already paid for.

### 4.1 Compress-then-encrypt, and accept the length side channel explicitly

Compression MUST happen before AEAD sealing — ciphertext is incompressible, so the
reverse order is a no-op. This is correct but it introduces a **compression side
channel** (the CRIME/BREACH class): the sealed block's *length* is public and now
depends on plaintext content, so an attacker who can both inject chosen bytes into a
block (e.g. self-registering a user with a chosen email) and observe SST block
lengths can learn something about co-resident plaintext.

Assessment: **low risk, accept and document.** The co-resident secrets that matter
(Argon2id hashes, session/token IDs) are high-entropy and will not compress against
a guess, and the attacker needs filesystem-level read access to the SSTs — at which
point the AEAD key, not the compression ratio, is the relevant control. But this
MUST be written into the security notes of the format, not silently introduced. Flag
to SecurityAuditor as part of the review child.

### 4.2 Size no allocation off an unauthenticated length — including via zstd

This is the **HEA-1917 abort class, and it has now recurred three times**
(HEA-1917 → HEA-1926 → HEA-1933): each time, an allocation was sized from a header
count an attacker could edit, producing a multi-GB `with_capacity` and a SIGABRT.

Decompression is exactly this shape. The mitigating fact is that the per-block
uncompressed length lives in the **AEAD-sealed footer**, so it *is* authenticated
and a forged value cannot survive. That makes it safe in principle — but the
discipline from HEA-1917 is *fix at the trust boundary and clamp anyway*:

- Put `uncompressed_len` in the sealed footer index entry, never in the plaintext
  base header.
- Clamp it at decode against a bound the real writer could have produced
  (`V3_BLOCK_TARGET_BYTES` plus one maximum oversized entry), and reject rather
  than allocate if it exceeds that.
- Use zstd's bounded/streaming decode, not a decode sized from a declared frame
  content size.

Grep **every** allocation sized off a length that crosses the format boundary, not
just the one being added. That is the lesson from HEA-1926, where the identical bug
was reintroduced at a new site.

### 4.3 Store-if-smaller, per block

Some blocks (dense Argon2 hashes, UUID-dominated index entries) will compress to
*larger* than input. Each block records its own codec, and the writer keeps the raw
form whenever compression does not help. Never assume compression is a win per
block just because it is a win in aggregate.

### 4.4 New magic `HSS4` — do not overload `HSS3`

Reusing `HSS3` with a codec byte means an older binary reads a new file and
mis-decodes it. A new magic makes an old reader reject it loudly instead. V3 stays
readable. This is cheap and it is the difference between a clean failure and silent
corruption during a rolling upgrade. (Hearth is greenfield with no migration
tooling — HEA-1837 — so forward-*compat* is not owed, but a clean *rejection* is.)

### 4.5 Preserve lazy block loading and cache semantics

Compression is per-block precisely so HEA-1914's lazy paging and bounded block cache
survive. The cache MUST continue to hold *decompressed* blocks (otherwise every cache
hit pays decompression). Consequence: this buys nothing on resident memory — see §5.

### 4.6 Measure the cold-read regression, do not assume it away

Decompression lands on the cold-path block read. K-targets cover cold lookup latency.
A disk win that regresses cold p99 past its budget is not a win. The implementation
child is not done until cold-read p99 is re-measured, not merely reasoned about.

---

## 5. What this does and does not fix

| Target | Metric | Option A helps? | Option B helps? |
|---|---|---|---|
| K7 (100M disk < 200 GB) | bytes on disk | **Yes** | Partially — bounded by audit's byte share |
| K4 (1M hot < 500 MB) | resident | **No** | Yes |
| K5 (10M hot < 8 GB) | resident | **No** | Yes |
| K6 (100M hot < 50 GB) | resident | **No** | Yes |

K4–K6 remain a **20× / 12× / 20×** miss at 9,960 B/user resident and are **not**
addressed by this issue. Option A is a K7-only lever. Nobody should read a K7 PASS
as progress on the resident-memory misses.

---

## 6. Decision — REVISED after measurement

The §6 decision below was written *before* the probe reported. The measurement
displaced it. **Superseded — recorded verbatim for provenance; §6bis is the
operative decision.**

### 6bis. Operative decision: do not spend on compression yet

Option A is *validated* (3× headroom, zstd level 1, 424 MB/s) — and it is **not the
right next spend**, because the miss it was chartered to close is probably not real.

Priority order:

| # | Action | Rationale | Owner |
|---|---|---|---|
| 1 | Fix the duplicate `UserCreated` audit event (§3.3) | **Correctness first**, disk second. Audit trail double-counts with a null actor. Also ~39.5% of stored bytes. | Engineer |
| 2 | Re-measure C0 disk slope at an N that forces WAL rotation (§3.2) | Likely flips K7 MISS → PASS and corrects the board report. Cheapest possible action. | QA |
| 3 | ZSTD level-1 block compression (Option A, §4) | **Parked.** Validated and available as headroom; do not spend until 1 and 2 land. | — (backlog) |

Rationale for parking a validated win: compression buys a 3× disk reduction at the
cost of a new on-disk format, a compression side channel, an added decompression step
on the cold read path, and a third encounter with the HEA-1917 alloc class. That is a
real risk budget. Spending it to close a gap that measurement suggests does not exist
would be the same error as HEA-1885 (shipped, default-off, never in effect) and
HEA-1888 (targets ticked complete but never measured) — motion mistaken for progress.

If (2) confirms K7 passes, Option A stops being a K7 remedy and becomes a candidate
lever for **cost-per-GB at scale**, to be argued on its own economics rather than
against a target it no longer needs to meet.

**Amend the board report.** PERFORMANCE_REPORT v2's K7 MISS should not stand
unqualified while §3.2 is open; the parent (HEA-1940) needs to know that one of its
two remaining misses is likely a measurement artifact.

### 6ter. Superseded pre-measurement decision

**Primary: Option A, gated on the probe.** It is the only option whose reach covers
all five record classes, its change surface is small and confined to one file, and
it needs no new dependency.

**Option B is not a fallback — it is a complement**, and it is the better *strategic*
buy because it is the only one of the two that also moves K4–K6. Sequence A first
(closes K7 fastest), then B on its own merits against the resident-memory misses.

**If the probe shows an aggregate ratio below ~1.35×**, Option A alone does not close
the gap, and the decision changes to A+B together, with Option C escalated to the
board as a product question. That branch is pre-committed here so the result cannot
be rationalised after the fact.

---

## 7. Delegation

| Child | Scope | Gate |
|---|---|---|
| Probe (this issue) | `examples/sst_compression_probe.rs` — measure, validate corpus, report per-class | Validation gate §3.1 |
| Implementation | `HSS4` block compression per §4 | Blocked on probe result |
| Security review | §4.1 side channel + §4.2 alloc class | Blocked on implementation |
| Re-measure | Rerun C0 disk slope; cold-read p99 per §4.6 | Blocked on implementation |
