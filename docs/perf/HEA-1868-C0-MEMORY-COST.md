# HEA-1868 — C0: Real Per-User / Per-Session Memory Cost

**Phase 0.5 of [HEA-1867 Performance Programme](./HEA-1867-PLAN.md)**
Date: 2026-07-28 | Hardware: 16 vCPU, 54 GiB RAM (~14 GiB available during test)

---

## Summary (TL;DR)

| Metric | Value | Method | Status |
|--------|-------|--------|--------|
| bytes-resident-per-user (memtable) | **24,141 B** (23.6 KB) | OLS slope, 4 points, R²=0.9974 | MEASURED |
| bytes-resident-per-hot-user (analytical, hot tier only) | **~673 B** | Struct accounting, 2 entries | ANALYTICAL ONLY |
| bytes-resident-per-session | — | n/a | **NOT MEASURABLE** |
| bytes-on-disk-per-user | **4,573 B** (4.47 KB) | OLS slope, 4 points, R²=0.9975 | MEASURED |
| Fixed RSS overhead (intercept) | **37.6 MB** | OLS intercept | MEASURED |
| VISION §7.3.1 Memory (1M hot users < 500 MB) | **23,022 MB actual** | Extrapolated | **MISS (46×)** |
| VISION §7.3 Disk (100M users < 200 GB) | **~436 GB actual** | Extrapolated | **MISS (2.1×)** |
| Max corpus on this host | **~609,000 users** | 14 GiB available / 23.6 KB/user | — |

**Agreement check**: measured (24 KB) vs analytical hot-tier (673 B) → **35.9× gap — DO NOT AGREE.**
Root cause: all seeded data is memtable-resident (WAL not compacted to SST). Hot-tier is unpopulated.
True bytes-per-hot-user requires: seed → force compaction → read-sweep → measure. See §4.

---

## 1. Methodology

### 1.1 Test Configuration

Config file (`docs/perf/scripts/hearth-c0.yaml`):
```yaml
security:
  load_test_unthrottled: true   # disables rate limits (--dev + loopback only)
realms:
  perf-realm:
    breach_check:
      enabled: false
```

`--dev` mode: Argon2id weakened to 256 KiB / 1 iter for speed. No persistent storage
(HEARTH_DEV_DATA_DIR writes to temp dir per run). Sessions-fraction = 0 (user-only sweep).

### 1.2 User Sweep Protocol

For each N in {200, 1000, 4000, 12000}:
1. Kill stale processes, start fresh hearth on isolated port with measurement config
2. Bootstrap (admin token + realm), create N users via `POST /admin/users` (no password)
3. Wait for seed binary to exit (`--users-per-realm N --sessions-frac 0`)
4. Read RSS from `/proc/{pid}/status` VmRSS field
5. Measure on-disk WAL+SST bytes (`du -sb` of data dir)
6. Kill hearth

### 1.3 Raw Data

| N users | RSS (KB) | Disk (B) | Seed time (ms) |
|---------|---------|----------|----------------|
| 200 | 35,200 | 579,284 | 526 |
| 1,000 | 65,804 | 2,701,718 | 4,400 |
| 4,000 | 139,468 | 15,041,075 | 22,423 |
| 12,000 | 318,988 | 53,772,940 | 93,071 |

---

## 2. Regression Results

### 2.1 RSS (Memory) Regression

OLS: **RSS(B) = 24,141 × N + 39,424,163**

| N | Actual RSS | Predicted | Error |
|---|-----------|-----------|-------|
| 200 | 36,044,800 B | 44,252,363 B | +23% |
| 1,000 | 67,383,296 B | 63,565,163 B | −6% |
| 4,000 | 142,815,232 B | 136,988,163 B | −4% |
| 12,000 | 326,643,712 B | 329,316,163 B | +1% |

**R² = 0.9974** (excellent fit at N ≥ 1,000; N=200 is an outlier, likely allocator cold-start)

Endpoint-to-endpoint slope (N=200→12,000, robust): **24,627 B/user**

→ **bytes-resident-per-user: 24,141 B (OLS), 24,627 B (endpoint) — use 24 KB**

Fixed overhead (intercept): **37.6 MB** (Tokio runtime + base storage structures)

### 2.2 Disk Regression

OLS: **disk(B) = 4,573 × N − 1,641,713**

| N | Actual disk | Predicted | Error |
|---|------------|-----------|-------|
| 200 | 579,284 B | −727,040 B | (intercept artifact at small N) |
| 1,000 | 2,701,718 B | 2,931,651 B | +9% |
| 4,000 | 15,041,075 B | 16,651,745 B | +11% |
| 12,000 | 53,772,940 B | 53,238,661 B | −1% |

**R² = 0.9975** (strong; negative intercept is a WAL pre-allocation artifact, not physical)

Endpoint-to-endpoint slope: **4,508 B/user**

→ **bytes-on-disk-per-user: 4,573 B (OLS), 4,508 B (endpoint) — use 4.5 KB**

---

## 3. Session Measurement: NOT MEASURABLE

**Blocker: HEA-1862** removed `grant_type=password` (ROPC) from both token endpoints.
The seed binary mints sessions via `password_grant` (per-user password flow). With ROPC
removed, the password_grant call returns `unsupported_grant_type` and no sessions are created.

No alternative session creation path exists in the load-test tooling without a browser
flow (authorization_code + PKCE). The `sessions_frac` parameter in the seed binary is
therefore non-functional.

**This is a legitimate NOT-MEASURABLE outcome per HEA-1867 plan grading rules.**

Unblocking options (one of):
- Add a server-side `make-session` admin endpoint for testing (no auth code exchange)
- Restore a test-only session creation path gated on `--dev` + loopback
- Implement session seeding via the authorization_code flow in the seed binary

---

## 4. Agreement Check: Measured vs Analytical

The plan requires both approaches to agree. They do not.

### Analytical Hot-Tier Accounting (per user, 2 entries)

```
CompositeKey stack:            40 B  (RealmId 16B + Vec<u8> header 24B)
HotEntry stack:                24 B  (Arc<[u8]> 16B + AtomicBool 1B + pad 7B)
hashbrown slot amortized:      74 B  (K+V / 0.875 load factor + 1B ctrl)
Key heap (usr:id:{uuid}):      43 B
Arc refcount + align:           8 B
User JSON value (est.):       400 B
─────────────────────────────────────
Primary entry total:          525 B

Email index (usr:email:{email}): 50B key + 16B value + 74B slot + 8B Arc = 148 B

Total per user (2 entries):   673 B/user
```

### Discrepancy Analysis

| | Value |
|--|-------|
| OLS measured slope | 24,141 B/user |
| Analytical hot-tier | ~673 B/user |
| Ratio | **35.9×** |

**Root cause**: during seeding, all writes go to the WAL → memtable (BTreeMap). Hot-tier
promotion only occurs when a key is read from an SST after WAL→SST compaction. In this
sweep, compaction was not triggered and users were never read back, so the hot tier was
essentially empty.

What the measured slope actually captures:
- BTreeMap memtable entries (≥3 records/user: primary + email + possibly credential)
- Value bytes retained in memtable (same bytes as WAL, not compressed)
- Memory allocator fragmentation from 12,000 sequential HTTP create-requests
- RBAC cache invalidation overhead per write

**Required follow-up measurement** (not part of HEA-1868 scope):
```
seed N users → POST /admin/storage/compact (or wait for auto-compaction)
→ read all users back (promotes to hot tier)
→ measure RSS → regression
```
This produces the true bytes-per-hot-tier-user. The analytical estimate (~673 B) is the
floor; the true measured value will be higher due to hashbrown growth overhead.

---

## 5. VISION §7.3 / §7.3.1 Verdict

### Memory

| Target | Budget/user | Measured/user | Ratio | Verdict |
|--------|------------|---------------|-------|---------|
| 1M hot users < 500 MB | 524 B | 24,141 B | 46× | **MISS** |
| 10M hot users < 8 GB | 838 B | 24,141 B | 29× | **MISS** |
| 100M hot users < 50 GB | 524 B | 24,141 B | 46× | **MISS** |

Using the analytical hot-tier floor (673 B):
| 1M hot users < 500 MB | 524 B | 673 B | 1.28× | **MISS (marginal)** |

The hot-tier analytical estimate is marginal — within a factor of 1.3× of the VISION
budget. But the memtable cost (24 KB) represents real working-set memory for recently
written users. Under any write-heavy workload, users that have not yet been compacted
consume 36× the budget. Reaching VISION §7.3.1 requires:
1. Compaction on write, not on a timer
2. Hot-tier-only operation after compaction (no memtable retention of old versions)

### Disk

| Target | Budget/user | Measured/user | Ratio | Verdict |
|--------|------------|---------------|-------|---------|
| 100M disk users < 200 GB | 2,147 B | 4,573 B | 2.1× | **MISS** |

Disk miss is driven by multi-record-per-user storage (primary + email index + credential
record) plus WAL framing overhead. After compaction, SST compression would reduce this.
On-disk measured value is pre-compaction WAL; post-compaction SST bytes will be lower.

### Maximum Corpus on This Host

At 24,141 B/user RSS and 14,055 MB available RAM:
```
(14,055 MB − 38 MB overhead) / 24.141 KB = ~609,000 users
```

**This host holds ~600,000 users in memory (not the 1M VISION target).**

---

## 6. Findings for HEA-1867 Parent

1. **Memtable cost (24 KB/user) dwarfs hot-tier design intent (~673 B).** Any workload
   with frequent writes will see 36× the intended memory footprint until compaction runs.
   Compaction strategy is the primary lever for hitting VISION §7.3.

2. **Disk cost (4.5 KB/user) is 2.1× the VISION target.** Compression in SSTs should
   help, but the multi-index storage model (≥3 records/user) is a structural cost.

3. **Session cost is unknown.** Blocked by HEA-1862. Sessions likely add 2–3 records each
   (ses:id + ses:user index + possibly credential state). Fix the seed binary to enable
   measurement.

4. **Agreement check failed.** Two-method validation cannot close until post-compaction
   read-sweep measurement exists. This is a gap in HEA-1868, not an error in the
   measurement — both results are correct for their respective measurement states.

5. **VISION §7.3 is NOT reachable at current storage structure without compaction tuning.**
   Go/no-go: **NO-GO on current codebase; re-evaluate after compaction + hot-tier-only read.**
