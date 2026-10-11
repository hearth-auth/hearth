# Load test on AWS c7i.large, 2026-10-10

| | |
|---|---|
| **Build** | `main` at `11960149`, released as v3.4.0 |
| **Plane** | Network: HTTPS requests from 2 separate load-generator hosts. TLS, TCP and network time are included. |
| **Server** | AWS c7i.large (2 vCPU, 3.8 GB RAM), us-east-1 |
| **Data** | 1,000,000 users in one realm |
| **Tooling** | [`loadtest/live/`](../../loadtest/live/README.md), plan [`plans/2026-10-10-c7i-large.txt`](../../loadtest/live/plans/2026-10-10-c7i-large.txt) |

This report gives two results for one server size:

- The **limit of each feature**: login, refresh, userinfo, admin user lookup, introspect, user creation, and a mix of the first four.
- A **60-minute soak** of the mix at 120 journeys/s, with server memory over time.

Each feature had one ramp. Treat small differences as noise.

## Setup

**Server**

- AWS c7i.large: 2 vCPU (1 physical core with hyper-threading), 3.8 GB RAM, Intel Xeon Platinum 8488C.
- Ubuntu 24.04. Transparent huge pages: `madvise`. No swap was used: the lowest MemAvailable in any run was 2,290 MiB.
- Disk: EBS gp3 root volume, 40 GB, 3,000 IOPS, 125 MB/s. A synced 4 KiB write takes about 3.3 ms (`dd oflag=dsync`: 2,000 writes in 6.57 s).
- Production build, without the `dev-endpoints` feature. `POST /admin/bootstrap` answered `404` before each run.
- Every write is fsynced to the write-ahead log (WAL) before the server acknowledges it.
- HTTPS with TLS 1.3 and HTTP/2.
- glibc malloc arenas are capped at 2 (the default).

**Data**

- 1,000,000 users in one realm. The import took 726 s (1,377 users/s, 0 failures).
- The store is 757 MiB on disk after the import.
- The hot tier (the in-memory cache) sized itself to 1,348,820 entries.

**Password hashing (Argon2id)**

- Parameters: memory 19,456 KiB (19 MiB), 2 iterations, parallelism 1. These are the OWASP-recommended values.
- KDF admission gate: at most 2 hashes run at the same time (1 per vCPU). A login that waits 250 ms for a slot gets `503` with `Retry-After`. Admin operations have 2 more slots of their own.
- Time per hash on this server (`hearth_kdf_compute_seconds` sum ÷ count): 33.4 ms in the soak, 37.7 ms in the login ramp. This is wall time on a hyper-threaded vCPU.
- So the maximum is about 2 slots ÷ 37.7 ms ≈ 53 password checks/s. The measured login limit (50–56 logins/s) agrees with this.

**Load generators**

- 2 × AWS c7i.xlarge (4 vCPU, 7.8 GB RAM each), k6 2.0.0, 1,000 virtual users per generator.
- Open loop: k6 starts journeys at the offered rate, also when the server is slow.
- Before each run, the store was restored from the same post-import copy, the page cache was dropped, and Hearth was restarted.
- Tooling: `loadtest/live/` (k6 2.0.0 script, AWS driver, samplers). Two one-off drivers ran this round with the same steps as the plan file; `round.sh` replaces them. The raw k6 CSVs (about 500 MB) are not committed; the tables below are the output of `loadtest/live/ramps.py` and `memory.py` on them.

## Units

- A **journey** is one simulated user action. Rates are completed (successful) journeys per second, summed over both generators. Only the hold part of each step counts.
- **Login** is 4 HTTP requests: the login page, the login form `POST` (1 Argon2id check), `/authorize`, and `/token` with an authorization code and PKCE. Login latency is for the whole 4-request journey.
- Each other journey is 1 HTTP request:

  | Journey | Request |
  |---|---|
  | Refresh | `POST /realms/{realm}/token` with `grant_type=refresh_token` (with rotation) |
  | Userinfo | `GET /realms/{realm}/userinfo` with a bearer access token |
  | Admin lookup | `GET /admin/users/{id}` as the realm admin |
  | Introspect | `POST /realms/{realm}/introspect` with client Basic authentication |
  | Create user | `POST /admin/users` with an email and a display name, without a password |

- The **mix** picks a journey type at random for each journey: refresh 65%, login 15%, userinfo 15%, admin lookup 5%. On average, a mix journey is 1.45 HTTP requests.
- Server CPU is out of 200% (2 vCPU). Generator k6 CPU is out of 400% (4 vCPU).
- **Dropped** journeys are journeys that k6 could not start on time, because all of its virtual users were still waiting for the server.
- **Clean** means 0 dropped journeys, errors below 0.1%, and p99 below 1 s.

## Limit of each feature

| Feature | Clean | Max served | What limits it |
|---|---|---|---|
| Login | 50 logins/s (p99 207 ms) | ~56 logins/s, with KDF sheds | Argon2id. Server CPU stays at ~150% from 60 offered up. |
| Refresh | ≥1,088 refreshes/s (p99 86 ms) | Not reached | It is the top of the ramp. Server CPU was 104%. |
| Userinfo | 8,000/s (p99 10 ms) | ~9,970/s | Server CPU, at 188% |
| Admin user lookup | 10,000/s (p99 21 ms) | ~11,200/s | Server CPU, at 181%. The generators were up to 64% busy, so the server limit can be slightly higher. |
| Introspect | 4,500/s (p99 18 ms) | ~5,410/s | Server CPU, at 195% |
| Create user | ≥1,377 creates/s (p99 56 ms) | Not reached | It is the top of the ramp. Server CPU was 51%. |
| Mix | 250 journeys/s (358 HTTP req/s) | 632 journeys/s (881 HTTP req/s) | Logins. Above ~45 logins/s, the KDF gate sheds logins. All other journey types had 0 errors up to the top of the ramp. |

## Results per step

### Login (90 s per step)

| Offered/s | Logins/s | Login `503`s | p50 | p99 | Server CPU |
|---|---|---|---|---|---|
| 20 | 19.8 | 0 | 87 ms | 92 ms | 61% |
| 30 | 29.7 | 0 | 88 ms | 99 ms | 87% |
| 40 | 39.6 | 0 | 84 ms | 168 ms | 115% |
| 50 | 49.5 | 0 | 87 ms | 207 ms | 142% |
| 60 | 50.7 | 783 | 319 ms | 441 ms | 150% |
| 70 | 51.1 | 1,653 | 319 ms | 439 ms | 149% |
| 80 | 53.9 | 2,293 | 314 ms | 408 ms | 149% |
| 90 | 55.9 | 3,016 | 313 ms | 433 ms | 148% |
| 100 | 55.8 | 3,926 | 311 ms | 449 ms | 148% |

All failures are `503` from the KDF gate.

### Refresh (90 s per step, 0 errors at every step)

| Offered/s | Refreshes/s | p50 | p99 | Server CPU |
|---|---|---|---|---|
| 200 | 197.8 | 20.1 ms | 84.7 ms | 19% |
| 300 | 296.7 | 19.3 ms | 68.9 ms | 26% |
| 400 | 395.6 | 18.8 ms | 68.4 ms | 33% |
| 500 | 494.5 | 19.9 ms | 117.3 ms | 48% |
| 600 | 593.4 | 19.9 ms | 73.3 ms | 56% |
| 700 | 692.3 | 20.5 ms | 75.3 ms | 66% |
| 800 | 791.2 | 21.3 ms | 81.2 ms | 75% |
| 900 | 890.1 | 22.0 ms | 80.4 ms | 85% |
| 1,000 | 989.0 | 23.1 ms | 90.5 ms | 95% |
| 1,100 | 1,087.9 | 24.2 ms | 85.9 ms | 104% |

### Userinfo (60 s per step, 0 errors at every step)

| Offered/s | Served/s | Dropped | p50 | p99 | Server CPU | k6 CPU, generator 1 / 2 |
|---|---|---|---|---|---|---|
| 2,000 | 1,967 | 0 | 0.3 ms | 0.9 ms | 28% | 40% / 43% |
| 4,000 | 3,934 | 0 | 0.4 ms | 0.9 ms | 59% | 77% / 80% |
| 6,000 | 5,902 | 0 | 0.3 ms | 1.6 ms | 86% | 120% / 127% |
| 8,000 | 7,869 | 0 | 0.4 ms | 10.3 ms | 142% | 156% / 166% |
| 10,000 | 9,804 | 2,236 | 14.9 ms | 396 ms | 185% | 192% / 209% |
| 12,000 | 9,966 | 112,072 | 224 ms | 465 ms | 188% | 187% / 205% |

### Admin user lookup (60 s per step, 0 errors at every step)

| Offered/s | Served/s | Dropped | p50 | p99 | Server CPU | k6 CPU, generator 1 / 2 |
|---|---|---|---|---|---|---|
| 2,000 | 1,967 | 0 | 0.3 ms | 1.0 ms | 24% | 42% / 45% |
| 4,000 | 3,934 | 0 | 0.3 ms | 1.0 ms | 53% | 80% / 84% |
| 6,000 | 5,902 | 0 | 0.3 ms | 1.4 ms | 71% | 126% / 132% |
| 8,000 | 7,869 | 0 | 0.4 ms | 6.4 ms | 112% | 163% / 172% |
| 10,000 | 9,833 | 0 | 0.6 ms | 21.1 ms | 157% | 200% / 214% |
| 12,000 | 11,193 | 37,197 | 188 ms | 450 ms | 181% | 221% / 238% |

### Introspect (60 s per step, 0 errors at every step)

| Offered/s | Served/s | Dropped | p50 | p99 | Server CPU | k6 CPU, generator 1 / 2 |
|---|---|---|---|---|---|---|
| 1,500 | 1,475 | 0 | 0.4 ms | 1.3 ms | 42% | 35% / 37% |
| 3,000 | 2,951 | 0 | 0.5 ms | 4.6 ms | 93% | 63% / 66% |
| 4,500 | 4,426 | 0 | 0.7 ms | 18.1 ms | 153% | 92% / 99% |
| 6,000 | 5,414 | 30,443 | 385 ms | 735 ms | 195% | 117% / 130% |
| 7,500 | 5,409 | 122,031 | 403 ms | 757 ms | 195% | 116% / 126% |
| 9,000 | 5,428 | 208,899 | 403 ms | 747 ms | 194% | 114% / 123% |

### Create user (60 s per step)

| Offered/s | Created/s | `503`s | p50 | p99 | Server CPU |
|---|---|---|---|---|---|
| 200 | 196.7 | 0 | 11.4 ms | 54.1 ms | 11% |
| 400 | 393.4 | 0 | 10.5 ms | 54.5 ms | 18% |
| 600 | 590.2 | 0 | 10.0 ms | 56.0 ms | 24% |
| 800 | 786.9 | 0 | 9.8 ms | 55.4 ms | 31% |
| 1,000 | 981.0 | 156 | 9.9 ms | 58.0 ms | 37% |
| 1,200 | 1,180.3 | 0 | 10.1 ms | 56.2 ms | 43% |
| 1,400 | 1,377.1 | 0 | 10.1 ms | 55.8 ms | 51% |

All 156 `503`s came in one second (17:20:16 UTC). The user-creation admission gate (`operational.user_create`) rejected them after its 250 ms queue wait, during a short server stall. The cause of the stall is not known.

### Mix (90 s per step, 0 dropped at every step)

| Offered journeys/s | Journeys/s | Refresh/s | Login/s | Userinfo/s | Admin lookup/s | HTTP req/s | Login `503`s | Refresh p99 | Login p99 | Server CPU |
|---|---|---|---|---|---|---|---|---|---|---|
| 250 | 247.3 | 160.4 | 36.8 | 37.8 | 12.3 | 358 | 0 | 108 ms | 258 ms | 118% |
| 300 | 296.3 | 193.5 | 43.5 | 44.3 | 15.0 | 428 | 34 | 111 ms | 341 ms | 136% |
| 350 | 341.7 | 225.4 | 46.9 | 52.4 | 17.1 | 491 | 403 | 95 ms | 401 ms | 156% |
| 400 | 385.8 | 256.5 | 50.8 | 58.5 | 19.9 | 558 | 896 | 99 ms | 420 ms | 157% |
| 450 | 428.5 | 289.6 | 50.8 | 65.8 | 22.3 | 614 | 1,505 | 94 ms | 406 ms | 158% |
| 500 | 466.9 | 322.1 | 46.5 | 74.0 | 24.3 | 662 | 2,512 | 91 ms | 409 ms | 163% |
| 550 | 505.3 | 354.6 | 42.5 | 81.4 | 26.9 | 710 | 3,517 | 92 ms | 410 ms | 166% |
| 600 | 545.7 | 387.0 | 41.7 | 88.0 | 29.1 | 766 | 4,337 | 152 ms | 407 ms | 168% |
| 650 | 587.6 | 418.7 | 40.8 | 95.9 | 32.1 | 820 | 5,030 | 91 ms | 406 ms | 170% |
| 700 | 631.5 | 449.7 | 42.5 | 104.3 | 34.9 | 881 | 5,536 | 96 ms | 410 ms | 170% |

All failures are login `503`s from the KDF gate. Userinfo and admin lookup p99 stayed below 11 ms at every step.

## 60-minute soak: mix offered at 120 journeys/s

**Throughput and latency**

The server served 77.9 refreshes/s, 18.0 logins/s, 17.5 userinfo/s and 5.8 admin lookups/s. That is 119.3 journeys/s, or 174 HTTP requests/s. Average server CPU was 54%.

| Journey type | p50 | p99 |
|---|---|---|
| Refresh | 22.0 ms | 83.1 ms |
| Login (4 requests) | 74.4 ms | 165.7 ms |
| Userinfo | 0.8 ms | 3.7 ms |
| Admin lookup | 0.7 ms | 3.6 ms |

- 28 logins failed with `503` from the KDF gate. That is 0.04% of logins.
- The run also had 2,370 `401`s on userinfo and admin lookup. They come from the test tool, not from the server. The tool's pool access tokens expire after 1 hour, and these journeys do not renew them.

**Memory (server RSS)**

The table compares this build with two soaks of 2026-10-09. Those soaks used the same instance types and the same test, on different instances. Minute 0 is the Hearth restart, about 1.5 minutes before the load starts.

| | `main` `48378b06` (2026-10-09) | `48378b06` + Argon2 buffer reuse, #461 (2026-10-09) | `main` `11960149` (this report) |
|---|---|---|---|
| RSS at minute 3 / 30 / 57 | 892 / 919 / 1,162 MiB | 739 / 874 / 1,097 MiB | 889 / 952 / 1,006 MiB |
| RSS trend, minutes 30–58 (least squares) | +605 MiB/h | +620 MiB/h | **+291 MiB/h** |
| RSS peak (a short spike at minute 60) | 2,415 MiB | 2,270 MiB | 2,120 MiB |
| MemAvailable at the end (lowest) | 2,137 (2,005) MiB | 2,240 (2,121) MiB | 2,390 (2,291) MiB |
| Hot-tier entries at minute 4 → 59 | 5,135 → 93,574 | 5,346 → 93,195 | 5,210 → 50,101 |

**What the storage gauges show (this build)**

| Minute | RSS | Hot-tier entries | Active memtable | SST files |
|---|---|---|---|---|
| 4 | 927 MiB | 5,210 | 16 MiB | 22 |
| 16 | 814 MiB | 15,805 | 12 MiB | 24 |
| 28 | 889 MiB | 25,593 | 8 MiB | 26 |
| 40 | 919 MiB | 35,042 | 18 MiB | 27 |
| 48 | 938 MiB | 41,413 | 57 MiB | 27 |
| 59 | 1,006 MiB | 50,101 | 49 MiB | 30 |
| 61 | 1,071 MiB | 51,684 | 9 MiB | 1 |

- **Memtable (the write buffer): bounded.** It fills to about 60 MiB, flushes to an SST file and starts again, about every 12 minutes.
- **SST files: bounded.** Their number grows from 22 to 30. Then a background compaction merges them into 1.
- **Hot tier: grows in a straight line.** Logins and refreshes write new session and token rows, and the hot tier keeps them. There were 0 evictions. The 2026-10-09 builds added hot-tier entries about twice as fast, and their RSS also grew about twice as fast. The likely cause of the difference is PR #462, in which the expiry sweep stops caching the rows that it reads.
- **The minute-60 spike** is the background SST compaction (31 files merged). It adds about 640 MiB of RSS for a few seconds. 22 of the 28 login `503`s of the soak happened in the same seconds. The 2026-10-09 soaks show the same thing.

**Open question: does memory level off?** A 60-minute soak cannot show that. The hot tier has a design limit (1,348,820 entries on this server), so its growth is not a leak. But the limit can be too large for this machine:

- Hearth sizes the hot tier from (MemAvailable − 2 GiB) ÷ an estimated 1 KiB per entry (`src/storage/auto_size.rs`).
- In the three soaks, RSS grew by about 1.8–4.2 KiB per new hot-tier entry (RSS change ÷ entry change, minutes 4–59). This is an upper bound, not a measurement of the entry size, because other memory changed too.
- If an entry costs more than about 2 KiB, a full hot tier does not fit in 3.8 GB.

This is not proven. The next steps, tracked in #445, are a direct measurement of the memory per hot-tier entry, and a soak with a small `storage.hot_tier_capacity`, so that the hot tier fills within the run.

## Admissibility

- **Hardware:** every figure is for the server above.
- **Generator attribution:** for userinfo and admin lookup at the top steps, k6 used up to 238% CPU (of 400%) on a generator, and the lowest generator idle time was 36%. The generators were busy but not saturated. The server CPU was at 181–188%, so the server is the limit. For admin lookup, the generators can have lowered the maximum slightly.
- **Swap:** no run used swap. The lowest server MemAvailable was 2,290 MiB, and the generators' `vmstat` shows 0 swap.
- **Repetition:** each ramp ran once. The 2026-10-09 soaks ran on different instances.
- **MFA:** the test realm does not require MFA, so login has no MFA step.
