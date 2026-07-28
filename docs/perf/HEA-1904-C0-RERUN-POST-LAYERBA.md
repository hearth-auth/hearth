# HEA-1904 — C0 Re-run: Per-User Memory + Write Cost After Layers B+A

**Supersedes the pending HEA-1900 measurement.**
**Parent: HEA-1867, HEA-1904**
Date: 2026-07-28 | Hardware: `dev-ryzen-7840hs` (16 vCPU, 54 GiB RAM, ~29 GiB available during test)
Git SHA: `c82d8eb8` (HEAD of `feature/perf-updates-7-28-26`)

---

## Summary (TL;DR)

| Metric | Pre-remediation (HEA-1868) | Post-remediation (this run) | Change |
|--------|--------------------------|----------------------------|--------|
| bytes-resident-per-user (OLS) | 24,141 B (23.6 KB) | **9,960 B (9.7 KB)** | −59% (2.4× improvement) |
| bytes-resident-per-user (endpoint) | 24,627 B | **10,133 B** | −59% |
| bytes-on-disk-per-user (OLS) | 4,573 B (4.47 KB) | **2,840 B (2.77 KB)** | −38% (1.6× improvement) |
| bytes-on-disk-per-user (endpoint) | 4,508 B | **2,805 B** | −38% |
| Fixed RSS overhead (intercept) | 37.6 MB | **39.7 MB** | ≈ same |
| Seed time (N=12k, ms/user) | 7.76 ms/user | **0.34 ms/user** | −96% (23× improvement) |

**Board claim verdict:** The Layer B + Layer A remediations are real and significant (2.4× memory improvement, 23× write-throughput improvement), but the target of "~1–2 KB resident, ~1.5 KB disk" is **not yet reached**. The remaining gap from the analytical hot-tier floor (~673 B) is structural: 5 SkipMap entries per user (primary + email index + 3 audit records) still reside in-process. Layer C (SST eviction / block-based paging, HEA-1881) is the next lever.

---

## 1. Methodology

### 1.1 Test Configuration

Same as HEA-1868-C0-MEMORY-COST.md — config file:

```yaml
security:
  load_test_unthrottled: true
```

`--dev` mode, `HEARTH_DEV_DATA_DIR` pointed at a fresh `mktemp` per rung. Sessions-fraction = 0 (user-only sweep). Argon2id weakened in dev mode (256 KiB / 1 iter).

### 1.2 User Sweep Protocol

Identical to HEA-1868:
1. Kill stale processes; start fresh hearth on port 18420 with `HEARTH_DEV_DATA_DIR=<tmpdir>`
2. Health-check loop until `/health` returns 200
3. Run seed binary: `--realms 1 --users-per-realm N --sessions-frac 0`
4. After seed exits: read VmRSS from `/proc/{pid}/status`
5. Measure on-disk WAL+SST: `du -sb <tmpdir>`
6. Kill hearth; delete tmpdir

### 1.3 Admissibility Check

- **Host**: `dev-ryzen-7840hs` ✓
- **Swap delta**: all rungs ≤ 40 kB (trivial, likely allocator noise) ✓
- **No void rungs** ✓
- **MemAvailable before each rung**: ~29 GiB (more than C0 baseline ~14 GiB; no memory pressure)

---

## 2. Raw Data

| N users | RSS (KB) | RSS (B) | Disk (B) | Seed time (ms) | ms/user |
|---------|---------|---------|---------|----------------|---------|
| 200 | 32,276 | 33,050,624 | 373,139 | 349 | 1.747 |
| 1,000 | 42,044 | 43,053,056 | 1,694,773 | 537 | 0.537 |
| 4,000 | 98,812 | 101,183,488 | 11,178,603 | 1,456 | 0.364 |
| 12,000 | 149,048 | 152,625,152 | 33,475,080 | 4,048 | 0.337 |

---

## 3. Regression Results

### 3.1 RSS (Memory) Regression

OLS: **RSS(B) = 9,960 × N + 39,652,096**

| N | Actual RSS (B) | Predicted (B) | Error |
|---|---------------|--------------|-------|
| 200 | 33,050,624 | 41,644,002 | −20.6% |
| 1,000 | 43,053,056 | 49,611,627 | −13.2% |
| 4,000 | 101,183,488 | 79,490,221 | +27.3% |
| 12,000 | 152,625,152 | 159,166,471 | −4.1% |

**R² = 0.932** (lower than baseline 0.9974 — see note below)

Endpoint-to-endpoint slope (N=200→12,000): **10,133 B/user**

→ **bytes-resident-per-user: 9,960 B (OLS), 10,133 B (endpoint) — use 10 KB**

Fixed overhead (intercept): **39.7 MB** (Tokio runtime + storage structures; comparable to baseline 37.6 MB)

> **R² note**: The N=4,000 point sits 27% above the OLS prediction, indicating a non-linear
> memory growth step between N=1k and N=4k (likely a SkipMap capacity doubling or jemalloc
> arena expansion). The N=200 and N=12,000 points agree within ±20% and ±4% respectively.
> This does not invalidate the measurement — the endpoint slope (10,133 B/user) is the robust
> estimate; the OLS slope (9,960 B/user) is close. Both indicate ~10 KB/user.
> A future re-run with additional rungs (e.g., N=2k, N=8k) would characterise the growth curve
> more precisely. For the admissibility threshold (R² ≥ 0.85 is conventional), this run passes.

### 3.2 Disk Regression

OLS: **disk(B) = 2,840 × N − 530,353**

| N | Actual disk (B) | Predicted (B) | Error |
|---|----------------|--------------|-------|
| 200 | 373,139 | 37,589 | (intercept artifact at small N; same pattern as C0) |
| 1,000 | 1,694,773 | 2,309,357 | −26.6% |
| 4,000 | 11,178,603 | 10,828,486 | +3.2% |
| 12,000 | 33,475,080 | 33,546,163 | −0.2% |

**R² = 0.9991** (excellent fit; negative intercept is WAL pre-allocation artifact, same as C0)

Endpoint-to-endpoint slope: **2,805 B/user**

→ **bytes-on-disk-per-user: 2,840 B (OLS), 2,805 B (endpoint) — use 2.8 KB**

---

## 4. Session Measurement

**Still NOT MEASURABLE** — same blocker as HEA-1868 (ROPC removed by HEA-1862; no session seeding path).

---

## 5. Write-Cost Ladder (Seed Time)

The Layer B (SkipMap) fix removes the O(N)-per-put CoW clone. The expected signature is a flat or falling ms/user, contrasting the baseline's rising 2.63→7.76 ms/user.

| N | ms/user (pre-remediation) | ms/user (post-remediation) | Change |
|---|--------------------------|---------------------------|--------|
| 200 | 2.63 | 1.75 (cold-start dominated) | −33% |
| 1,000 | 4.40 | 0.54 | −88% |
| 4,000 | 5.61 | 0.36 | −94% |
| 12,000 | 7.76 | 0.34 | **−96%** |

**Ladder verdict**: The rising-cost signature is **eliminated**. Post-fix ms/user decreases from 1.75 to 0.34 as N grows — O(N) clone overhead is confirmed removed. The N=1k→12k slope is **0.319 ms/user** (vs. the baseline's rising cost of ~0.45 ms/user-squared rate). At N=12k the per-user cost converges to ~0.34 ms/user and is flat, consistent with O(log N) SkipMap insertions amortised over N.

---

## 6. Agreement Check: Measured vs Analytical

| | Value |
|--|-------|
| OLS measured slope | 9,960 B/user |
| Analytical hot-tier (§4, HEA-1868) | ~673 B/user |
| Ratio | **14.8×** |

The gap narrowed from 35.9× (pre-remediation) to 14.8× (post-remediation), a significant improvement.
Root cause of remaining gap is unchanged: seeded data resides in the SkipMap memtable (5 keys/user:
primary + email index + 3 audit entries), not in the hot-tier which is populated only after
WAL→SST compaction + read-sweep. The analytical 673 B estimate covers 2 hot-tier entries only.

---

## 7. VISION §7.3 / §7.3.1 Verdict

### Memory

| Target | Budget/user | Pre-fix/user | Post-fix/user | Pre verdict | Post verdict |
|--------|------------|-------------|--------------|-------------|--------------|
| K4: 1M hot users < 500 MB | 524 B | 24,141 B | **9,960 B** | MISS (46×) | **MISS (20×)** |
| K5: 10M hot users < 8 GB | 838 B | 24,141 B | **9,960 B** | MISS (29×) | **MISS (12×)** |
| K6: 100M hot users < 50 GB | 524 B | 24,141 B | **9,960 B** | MISS (46×) | **MISS (20×)** |

K4–K6 extrapolations (using OLS slope 9,960 B/user + 39.7 MB intercept):
- 1M users: **~10.0 GB** (budget 0.5 GB)
- 10M users: **~99.6 GB** (budget 8 GB)
- 100M users: **~996 GB** (budget 50 GB)

### Disk

| Target | Budget/user | Pre-fix/user | Post-fix/user | Pre verdict | Post verdict |
|--------|------------|-------------|--------------|-------------|--------------|
| K7: 100M disk users < 200 GB | 2,147 B | 4,573 B | **2,840 B** | MISS (2.1×) | **MISS (1.4×)** |

K7 extrapolation: 2,840 B × 100M = **284 GB** (budget 200 GB). Still a miss, but narrowed from 2.1× to 1.4×.

### Board Claim Verdict

> **Did 24 KB/user resident and 4.5 KB/user disk drop to ~1–2 KB and ~1.5 KB?**

- **Memory: NO** — dropped to ~10 KB (not 1–2 KB). Layer B + Layer A together achieved a 2.4× reduction. The remaining gap (10 KB vs. 673 B hot-tier floor) requires:
  1. WAL→SST compaction to move records out of the SkipMap
  2. Hot-tier-only operation (Layer C, HEA-1881: SST block eviction)
- **Disk: Partial** — dropped to ~2.8 KB (budget 2.1 KB, VISION target). Layer A binary encoding helped but multi-record structure (primary + email + credential + audit) remains. SST compression post-compaction would reduce this further.

The remediations are real and substantial. K7 is now within striking distance (1.4×) of the VISION disk target.

---

## 8. Findings for HEA-1867 Parent

1. **Layer B (HEA-1897 SkipMap) confirmed: write-throughput defect eliminated.** The O(N) CoW clone signature is gone. Seed write cost at N=12k improved 23× (7.76→0.34 ms/user).

2. **Memory improvement is real but incomplete.** 9,960 B/user vs. 24,141 B — a 2.4× improvement. Still 14.8× above the analytical hot-tier floor (673 B). Root cause: 5 SkipMap entries/user (primary + email + credential + 3 audit), not 2 hot-tier entries.

3. **Disk improvement is meaningful.** 2,840 B/user vs. 4,573 B — a 1.6× improvement. Layer A binary encoding reduced per-record size. K7 MISS ratio improved from 2.1× to 1.4×.

4. **Next lever: Layer C (HEA-1881).** Reaching the 673 B hot-tier floor requires SST compaction + paging (HEA-1881 block-based SST with eviction). Until then, the memtable SkipMap is the capacity ceiling.

5. **Agreement check: still failed** (14.8× gap, narrowed from 35.9×). Two-method validation cannot close until a post-compaction read-sweep measurement exists.
