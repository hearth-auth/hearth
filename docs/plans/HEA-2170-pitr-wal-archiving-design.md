# PITR, WAL Archiving, and Incremental Backup — Design Spike

**Issue:** HEA-2170 (HEA-2150 / W2-4, finding H-6) · **Status:** design only, implementation deferred to W5-7 (post-GA) · **Author:** CTO · **Date:** 2026-08-12

---

## 1. Problem statement

Hearth's recovery point objective is **the last full backup**. There is no
point-in-time recovery, no WAL archiving, and no incremental backup. Products in
the identity-store category are generally expected to offer at least continuous
WAL archiving, so this is both a capability gap and — until now — a
documentation gap.

This document is the design that W5-7 will be scoped from. It is deliberately
paired with an **RPO statement shipped immediately** in
[`docs/guides/backup.md`](../guides/backup.md#recovery-point-objective-rpo); the
honest statement is the GA gate, this design is not.

---

## 2. Where we actually are

Facts, with source references, as of `af4edb59`.

| # | Fact | Evidence |
|---|---|---|
| F1 | The WAL is a **single file**, `data_dir/hearth.wal`. Not segmented. | `src/storage/engine.rs:461` |
| F2 | "Rotation" is **truncate-in-place**: `set_len(0)`, rewrite headers, swap DEK. Prior contents are destroyed, not renamed. Size-triggered only (`storage.wal_max_size_bytes`, default 64 MiB). | `src/storage/wal.rs:1584-1622`, `src/config/types.rs:191-192` |
| F3 | **No LSN.** No durable monotonic per-record sequence. `RotationState.record_counter` resets to 0 on every rotation; `GroupState.next_ticket` is in-memory only. | `wal.rs:404-410`, `wal.rs:1618`, `wal.rs:449` |
| F4 | WAL nonce is **positional** (`counter_nonce(record_num)`, ordinal within the current file) under a per-truncation-epoch DEK wrapped by the realm KEK. | `src/storage/encryption.rs:412`, `wal.rs:751-752` |
| F5 | On recovery, a torn tail causes the surviving prefix to be **re-encrypted under a fresh DEK** (HEA-SEC-08, to avoid (DEK, nonce) reuse). The same logical records can therefore exist as two different ciphertexts. | `wal.rs:779-782`, `wal.rs:786-834` |
| F6 | SSTs are immutable once renamed, but there is **no storage manifest** — the live set is recovered by re-scanning `*.sst` and sorting by number. | `engine.rs:948-977`, `engine.rs:752-759` |
| F7 | Compaction **rewrites and unlinks** its inputs, invalidating a large set of previously-backed-up filenames at once. | `engine.rs:1004`, `engine.rs:1183` |
| F8 | **No persisted "WAL durable through N" watermark.** SST headers carry no LSN; recovery replays the entire WAL and relies on idempotent re-application. | `sst.rs:1-45`, `engine.rs:471` |
| F9 | The existing export is **logical** (walks `IdentityEngine` / `RbacEngine` / `AuditEngine` public APIs), not physical. | `src/backup/export.rs:76-80`, `:253-339` |
| F10 | The export is **not point-in-time consistent**: each entity type is a separate paginated live scan with no snapshot handle, version fence, or read transaction. | `export.rs:253`, `:266`, `:291`, `:305`, `:317`, `:330` |
| F11 | `StorageEngine::open` takes an **unconditional exclusive lock** (process-local set + OS `flock` on `{data_dir}/LOCK`). There is no read-only or lock-bypass open mode. | `engine.rs:382-416`, `src/storage/error.rs:128-136` |
| F12 | Consequently `hearth backup create --data-dir <live dir>` **fails** with `AlreadyLocked` while a server is running. The only live-server backup path is `POST /admin/backup`, which reuses the already-open engines. | `src/main.rs:3735-3737`; `src/protocol/http/admin.rs:143`, `:4283-4322` |
| F13 | No config surface for continuous archiving exists — `security.backup` is signature verification + a rate limit; storage has only `wal_max_size_bytes`. | `config/types.rs:922`, `:1273`, `:1280`, `:191` |

Two of these are worse than the H-6 headline and are addressed immediately in
the docs rather than deferred:

- **F10** means the archive is not merely *stale*, it is a **smear**. Users are
  read at T₀ and role assignments at T₈; a principal created at T₄ is absent
  from `users.ndjson` while their assignment is present in
  `assignments.ndjson`. The recovery point is an interval, not an instant.
- **F12** means the backup schedule the guide recommended could never have run.
  Fixed in `backup.md` as part of this issue; the missing read-only open mode is
  tracked as a follow-up (§7).

---

## 3. Design

Three phases. Phase 1 is the load-bearing one — it removes F2/F3/F6/F8
simultaneously, and neither of the later phases is possible without it.

### Phase 1 — Segmented WAL + durable LSN + manifest *(foundation)*

- Replace `hearth.wal` with `wal/{seq:016}.wal`. Segments are **sealed**
  (fsync + parent-dir fsync), never truncated in place.
- Introduce a **global monotonic u64 LSN** per record, in the plaintext payload,
  with first/last LSN mirrored into each segment header. This makes "recover
  through record N" expressible for the first time.
- Add a `CURRENT` manifest naming the live SST set plus a durable
  `last_applied_lsn` watermark, written at memtable flush. Retention rule: a
  sealed segment may be deleted only once the watermark proves every record in
  it is in an SST.
- Keep the existing per-segment DEK model. Because sealed segments are now
  immutable and tail-rebuild (F5) only ever touches the *unsealed* tail,
  archived segments are self-describing, independently decryptable, and can
  never acquire a second ciphertext. F4/F5 stop being archiving hazards.

**Effort: L, ~3–4 weeks.** Storage-engine change with a large crash-recovery and
`hearth-simulation` / `FaultFs` surface. This is where the risk lives.

### Phase 2 — WAL archiving

- New config `storage.wal_archive.{dir|command}` on the PostgreSQL
  `archive_command` model. On seal, hand the segment to the archiver; retain
  locally until the archive acknowledges success.
- The archived artifact is **the sealed segment verbatim** — already encrypted
  and CRC-framed. Archiving is a copy, not a re-encode.
- Archive failure must **not** silently drop segments. Add
  `wal_archive.max_retained_bytes` with an explicit, configured choice between
  fail-stop (reject writes, alarm) and fail-open (drop archiving, keep serving).
  Recommend fail-stop as the default with loud alarming — the classic
  `archive_command` operational failure is a silently filling disk.

**Effort: M, ~1.5 weeks** on top of Phase 1.

### Phase 3 — Base backup + PITR restore

- **Base backup becomes physical**: manifest + SST set + watermark LSN. Cheap,
  consistent (SSTs are immutable), and — unlike today's logical export — an
  actual point-in-time snapshot, which also retires F10.
- **Restore to time T**: lay down the base, then replay archived segments from
  the base watermark up to the first record exceeding the target. Records already
  carry a wall-clock `ts` in the payload, so both `--target-time` and
  `--target-lsn` are expressible; **LSN is the reliable form** (see §7).
- **Incremental backup falls out for free**: base + WAL delta *is* the
  incremental. We do not need a separate mechanism.

**Effort: M–L, ~2–3 weeks.**

**Total W5-7 scope: ~7–9 engineering weeks** including simulation-test hardening.

### Target restore UX

```bash
hearth backup restore-pitr \
  --base /backups/base-2026-08-10 \
  --wal-archive s3://acme-hearth-wal/ \
  --target-time '2026-08-12T14:03:00Z' \
  --data-dir /var/lib/hearth/data
```

### Retention model

Archive retention = `base_backup_interval + pitr_window`: every archived segment
from the oldest base backup you intend to keep must be retained, or that base
becomes non-replayable. Recommended default: **weekly base + 14-day PITR
window**. Segment volume is a function of write throughput, and the guide needs
a measured sizing table before Phase 2 ships — do not publish estimates.

---

## 4. Storage format summary

| Artifact | Format | Immutable? |
|---|---|---|
| Sealed WAL segment | Existing record framing + encryption header, verbatim | Yes (post-Phase 1) |
| `CURRENT` manifest | Live SST set + `last_applied_lsn` | Replaced atomically |
| Base backup | SST set + manifest + watermark | Yes |
| Logical `.hearth-backup` | Unchanged — retained for migration and cross-version transfer | n/a |

The existing logical archive is **not** replaced. It stays as the
portable/cross-version path; PITR is the physical path.

---

## 5. What we will NOT do in 1.x

Stated explicitly so the roadmap conversation is honest:

- **No PITR, no WAL archiving, no incremental backup in 1.x.** All three are
  post-GA (W5-7). 1.x RPO is the last full backup.
- **No SST-level (file-diff) incremental backup — ever.** Compaction rewrites
  and unlinks its inputs (F7), so a file-diff incremental is invalidated
  wholesale by any compaction. Base + WAL is the only sound design.
- **No continuous physical replication or read replicas.** Raft replication is
  consensus over mTLS gRPC, not a backup surface, and will not be repurposed as
  one.
- **No sub-second RPO.** Even with Phase 2, RPO is bounded by segment seal
  cadence. Streaming replication is out of 1.x.
- **No cross-version PITR.** Replaying archived WAL into a different major
  version is out of scope; PITR restore requires the same major version.
- **Sessions and the JTI revocation blocklist stay excluded** from backup, PITR
  or not. A PITR restore still accepts previously-revoked tokens.

---

## 6. What ships now (GA gate)

Not deferred — landed with this issue:

1. An explicit operator-terms RPO statement in
   [`docs/guides/backup.md`](../guides/backup.md#recovery-point-objective-rpo),
   including the consistency-smear caveat from F10.
2. Correction of the recommended backup schedule, which could not have run
   against a live server (F12).
3. A sharpened RPO section in
   [`docs/guides/disaster-recovery.md`](../guides/disaster-recovery.md#recovery-point-objective-rpo--how-much-data-you-can-lose).

---

## 7. Risks and open questions

- **No read-only engine open (F11/F12).** Phase 3's physical base backup needs to
  read a live node's data dir, which the exclusive lock forbids. A read-only /
  shared-lock open mode is a prerequisite. Tracked as a follow-up; it also fixes
  offline base backups independently of PITR.
- **Key custody across KEK rotation.** Segments retained for a 14-day PITR
  window must stay decryptable across a KEK rotation. Needs an explicit
  key-retention rule before Phase 2 ships.
- **Wall-clock targeting is only as good as clock discipline.** `--target-time`
  is a convenience; `--target-lsn` is the correctness-preserving form. Document
  it that way.
- **Phase 1 is a crash-recovery change to the most safety-critical file in the
  system.** It should not be attempted without expanding the `FaultFs`
  simulation suite first.
