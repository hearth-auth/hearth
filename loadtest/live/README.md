# Live stress test

Pushes one production-mode Hearth server on real, small hardware until it
fails, and records how it fails. It complements the in-repo load test
(`loadtest/`), which runs against `--dev` on one machine.

| Part | What it is |
|---|---|
| `gen-config.sh` | Secrets, CA and HTTPS leaf, `hearth.yaml` for one production node |
| `k6/lib.js` | Sign-in through the hosted login form + authorization code + PKCE; admin helpers |
| `k6/prepare.js` | Makes the `api` client a resource server, regenerates its secret, bulk-imports users |
| `k6/stress.js` | One open-loop ramp of one journey (or a mix) |
| `k6/verify.js` | Checks every user a `create_user` ramp saw acknowledged still exists |
| `sampler.sh` | Runs on the server: Hearth CPU, RSS, free memory, disk writes, once a second |
| `analyze.py` | Per-step table and knees from k6's CSV and the sampler (`test_analyze.py` tests it) |
| `cloud.sh` | Orchestration on DigitalOcean or AWS: `up`, `deploy`, `import`, `ramp`, `restart`, `verify`, `down` |
| `provider-aws.sh` | The AWS EC2 versions of `cloud.sh`'s provider commands (`PROVIDER=aws`) |
| `round.sh` | One round from a plan file: setup, then ramps and soaks, each from a restored store; always `down` at the end |
| `plans/` | Plan files for `round.sh`; each published report names its plan |
| `aws-iam.sh`, `aws-policy.json` | Create and delete the scoped IAM user and the local `hearth-stress` profile |
| `remote/` | Scripts that run on the server: observer, `kill -9`, profiler, `malloc-info.sh` (glibc heap snapshot through gdb) |
| `ramps.py` | Per-step table for each journey type, with server CPU and generator CPU |
| `memory.py` | Server memory over a soak: RSS, RssAnon and RssFile at fixed minutes, storage gauges, glibc heap, and the flatness test (`test_memory.py` tests it) |

## What "production mode" means here

No `--dev`, no `dev-endpoints` (`deploy` checks that `POST /admin/bootstrap`
answers `404`), fsync on, TLS on, a real KEK and master key. Users sign in the
way a browser app does; Hearth has no password grant. The realm admin is a
`seed_users` entry with `realm.admin`.

Changed from the defaults, because one generator on one IP address would
otherwise measure the limiters, not the server (all limiters stay on):

| Key | Default | Here |
|---|---|---|
| `security.rate_limiting.token_per_minute` (per realm and client) | 200 | 100,000,000 |
| `security.rate_limiting.admin_per_minute` | 100 | 100,000,000 |
| `security.request_shaper.ip_rps` / `realm_rps` | 100 / 1,000 | 1,000,000 |
| `operational.max_connections` / `max_connections_per_ip` | 1,024 / 64 | 20,000 |
| `token.access_token_ttl` | 15 min | 1 h (the maximum) |

The `api` client is switched to `access_token_authorization: introspection`
(admin API only) and its secret regenerated, so introspection checks a SHA-256
digest instead of an Argon2id hash. That is how an operator runs a busy
resource server.

## Journeys

| Journey | Requests | Notes |
|---|---|---|
| `introspect` | `POST /realms/stress/introspect` | resource server checks a user token |
| `userinfo` | `GET /realms/stress/userinfo` | |
| `refresh` | `POST /realms/stress/token` (`refresh_token`) | rotation: each VU owns one chain |
| `login` | login page, form post, authorize, code exchange | one Argon2id check; latency = sum of the 4 |
| `admin_lookup` | `GET /admin/users/{id}` | |
| `create_user` | `POST /admin/users` | one durable write; logs `ACK <id>` for `verify.js` |
| `mix` | weighted: `refresh:65,login:15,userinfo:15,admin_lookup:5` | override with `MIX` |

## Method

- **Open loop.** k6's `ramping-arrival-rate` starts journeys on schedule, whether
  or not earlier ones finished, so a slow server cannot slow the offered load
  down. When every VU is busy, k6 drops the journey and counts it
  (`dropped`).
- **Steps.** Each step ramps for 5 s, then holds for `hold_s`. Only hold
  seconds are measured.
- **Knees.** Latency knee: p99 over the journey's budget. Error knee: more
  than 1% failed. Collapse: more than 50% failed or the process is gone.
  Sustained: the highest offered rate with ≤ 1% errors, p99 within budget and
  ≤ 1% dropped. A VU that sees more than 50% failures in its last 200
  journeys aborts the ramp.
- **Durability.** `cloud.sh ramp <name> create_user … <kill_at_s>` sends
  `kill -9` to Hearth mid-ramp; `cloud.sh restart` and `cloud.sh verify
  <name>` then check every acknowledged user.

## Running it

```bash
# The shipped image (production build). deploy refuses an image without a revision.
docker build -t hearth-stress:local --build-arg BUILD_REVISION=$(git rev-parse HEAD) .
loadtest/live/cloud.sh up                     # SSH key, firewall, 2 Droplets
loadtest/live/cloud.sh deploy
loadtest/live/cloud.sh ramp intro-1 introspect 250 250 16 30
loadtest/live/cloud.sh down                   # always: deletes every resource of the run
```

### On AWS EC2

`PROVIDER=aws loadtest/live/cloud.sh up` creates the run on EC2 instead
(`provider-aws.sh`: c7i.large server, c7i.xlarge generators, gp3 disks, one
availability zone). Later commands read the provider from the run. It needs
an AWS CLI profile (default `hearth-stress`) for an IAM user with EC2 rights
on resources tagged `hearth-stress` in one region only; it refuses the
account root. Each instance terminates itself after `AWS_MAX_HOURS` (10) in
case `down` never runs. `SERVER_SIZE` and `GENERATOR_SIZE` may also be c7i.2xlarge or
t3.medium (2 vCPU, 4 GiB, about half the price of c7i.large). Use t3.medium for long memory
soaks, not for latency: it starts in unlimited mode, so it never loses CPU when its credits run
out, but its CPUs are older and slower.

Results land in `loadtest/live/results/<run>/<name>/` (`report.md`,
`report.json`, raw k6 CSV, sampler CSV, server log tail). Secrets live in
`loadtest/live/.build/<run>/`. Both directories are git-ignored.

## Round 2 additions

- **Several generators.** `GENERATORS=2` (default) splits every ramp's rate evenly; each
  generator waits after its setup until a shared `START_AT`, so the ramps start together.
  `analyze.py` adds the generators' results up.
- **The run lives on the Droplets.** Each ramp, observer, `kill -9` and profile is a
  `systemd-run` unit (`remote/`). A lost local session loses nothing: run
  `cloud.sh collect <name>` to wait for the end and fetch the results.
- **More observation.** `observe.sh` adds `/metrics` every 5 s (`metrics-scrape.sh`) and
  `iostat` to the sampler. `PROFILE_AT`/`PROFILE_S` schedule `profile.sh` (perf + offcputime);
  it needs a binary with symbols (build with `CARGO_PROFILE_RELEASE_STRIP=none`
  and `CARGO_PROFILE_RELEASE_DEBUG=line-tables-only`, and without the Dockerfile's `strip`).
- **A second server.** `add-server <size>` and `move-store` copy the store to another size of
  Droplet over the private network, so a large store is filled once.
- **`fill`** creates users through `POST /admin/users`; `import` (bulk) was faster in the
  cloud (1,479 users/s against 800/s).
- **`allow-ssh-here`** moves the SSH firewall rule to this machine's current address.

## Running a round (agents: start here)

A round is one setup (servers up, 1M users imported) and then a plan of ramps and
soaks on the same servers. A round on AWS takes 2–3 hours and costs a few dollars.

1. **Build the image** of the commit under test. `deploy` refuses an image without a revision label.
   ```bash
   docker build -t hearth-stress:<tag> --build-arg BUILD_REVISION=$(git rev-parse HEAD) .
   ```
2. **Create the AWS identity.** The owner runs `aws login` (an admin session). Right after it, run
   `loadtest/live/aws-iam.sh up`. The admin session can expire within minutes.
3. **Write a plan.** Start from the newest file in `plans/`.
4. **Start the round detached.** It runs for hours, and the agent's background-task monitor can
   kill a long background command:
   ```bash
   scripts/run-detached.sh run stress-round -- env SETUP=1 IMAGE=hearth-stress:<tag> \
     PLAN_FILE=loadtest/live/plans/<plan>.txt loadtest/live/round.sh
   ```
   `round.sh` runs `cloud.sh down` at the end, also after a failure. Each instance also stops
   itself after `AWS_MAX_HOURS` (default 10).
5. **Analyse** the results in `results/<run>/`:
   ```bash
   python3 loadtest/live/ramps.py results/<run>/<name> ...   # per-step table per journey type
   python3 loadtest/live/memory.py results/<run>/<soak>     # memory over a soak; see below
   ```
6. **Clean up.** Check that `cloud.sh down` printed an empty "left over" list. Then, with an
   admin session, run `loadtest/live/aws-iam.sh down`.
7. **Publish** the results as one file, `docs/perf/<date>-<server>.md` (see "Report format").

## Memory soaks (#445)

A memory soak answers one question: does Hearth's memory stop growing once its caches are full?
Run it with these settings, on top of the round's:

| Setting | Value | Why |
|---------|-------|-----|
| `GENERATORS`, `VUS` | `1`, `500` | k6 holds about 3.4 GB at 1,000 VUs; 500 VUs fit a 4 GiB generator and are far more than 120 journeys/s need |
| `SESSION_TTL`, `REFRESH_TOKEN_TTL` | `1h`, `1h` | expired rows become deletable within the run, so the stored data can level off |
| `K6_ENV` | `"CHAIN_REFRESHES=20 PRESENT=chain"` | each VU signs in again after 20 refreshes (new token families all the time), and userinfo presents the VU's newest token (the token cache fills) |
| `SERVER_RUST_LOG` | `info,hearth::storage::heap=debug` | the log shows each return of free heap to the system |
| `HOT_TIER_CAPACITY`, `BLOCK_CACHE_BYTES` | e.g. `20000`, `33554432` | optional: small caches fill in the first half hour. Leave them unset for a run with the default caches |
| `CLAIMS_CACHE_MAX` | e.g. `4096` | optional: `token.claims_cache_max`. Before #477, a full 65,536-entry token claims cache used all CPU on a server that validated ~40 new tokens a second (the fast soak at 240 journeys/s, from about minute 35); a smaller cap kept such a soak running on builds without #477 |

The sampler records RssAnon (heap and other private memory, the part a leak grows) and RssFile
(the mapped SST files, which the kernel drops when it needs the memory). Total RSS mixes the two,
so do not judge a soak by it.

**The flatness test** (`memory.py`, fixed before the runs of 2026-10-12):

- The *floor* is the lowest RssAnon between two memtable flushes. It comes just after a flush,
  when the memtable is empty and the freed heap was just returned to the system.
- The stored data still grows during a run: no sweep deletes audit events before they are a day
  old. The SST readers hold a block index and a Bloom filter for every file, so their heap grows
  with the data. `hearth_storage_sst_reader_bytes` reports it, and the test subtracts it from the
  floor.
- The test also subtracts the caches' memory: `hearth_storage_hot_tier_bytes` (the hot tier's
  tables, keys and values) and `hearth_storage_block_cache_bytes` (the block cache's charged
  bytes). Each cache stops at its capacity, but the default hot tier does not fill in a day. On
  a 4 GiB server it sizes itself to about 1.36 million entries. In the v4.2.4 run with the
  default caches (2026-10-17) it held about 150,000 entries after 2 hours and still gained about
  4,000 an hour at 24 hours. A cache that fills is not a leak, but without the gauges the test
  counts it as one. This rule was fixed on 2026-10-18, after that run and before the next one. A
  run without the cache gauges subtracts the SST readers only, so earlier verdicts do not change.
- Both 24-hour runs with the default caches had one late step in the floor: about 20 MiB at hour
  18.6 on v4.2.4, and a similar step at hour 19.9 on v4.3.0 (2026-10-19). The cache gauges do
  not hold it. In the v4.3.0 run the hot tier's tables grew in hours 4 to 9, and its gauge did
  not move at the step. The cause of the step is not known (#445).
- After the warm-up (`--warmup-min`, 120), the test fits a line to the bin means
  (`--bin-min`, 60) of floor minus SST reader heap minus caches. The 95 % upper bound of its
  slope uses Student's t over the bin means, because one-second samples are not independent.
- **PASS** when that upper bound is below `--max-slope` (2 MiB/h). Two 12-hour runs must pass:
  one with small caches, one with the default caches.

For a 4-hour soak, use `--warmup-min 60 --bin-min 30`.

### Heap accounting

The flatness test says whether memory grows; heaptrack says what holds it. `HEAPTRACK=1` runs
each plan line's Hearth under heaptrack (setup and the import run without it) and ends each
soak with `kill -9`. The trace's "leaked" memory is then the live heap at that moment, by call
site, and `round.sh` fetches the trace as `heaptrack.zst`. Compare a 2-hour run with a 12-hour
run (`plans/2026-10-12-c7i-large-445-heaptrack-*.txt`): a call site whose live heap grows
between them, and is not a capped cache or the SST readers, is a leak.

heaptrack needs a binary with symbols, and a binary that allocates through glibc's `malloc`:
heaptrack hooks only that, and the release binary allocates through jemalloc (#445).
`--cfg hearth_system_allocator` keeps the system allocator. The live heap by call site does not
depend on the allocator, but RSS does, so judge flatness on a run of the release image. Build
the image from a modified copy of the Dockerfile, outside the repository:

```bash
sed -e '/&& strip target\/release\/hearth/d' \
    -e 's/&& cargo build --release/\&\& CARGO_PROFILE_RELEASE_STRIP=none CARGO_PROFILE_RELEASE_DEBUG=line-tables-only RUSTFLAGS="--cfg hearth_system_allocator" cargo build --release/' \
    Dockerfile > /tmp/Dockerfile.symbols
docker build -f /tmp/Dockerfile.symbols -t hearth-stress:<tag>-symbols \
  --build-arg BUILD_REVISION=$(git rev-parse HEAD) .
```

heaptrack slows every allocation, so run at 60 journeys/s on c7i.large. Read a trace with
`heaptrack_print --print-leaks 1 -s 400 heaptrack.zst` (the default `-s 5` cuts the stacks).

## Method rules

- **Units.** k6 counts journeys. A login journey is 4 HTTP requests; the other journeys are 1.
  Give every rate per journey type (logins/s, refreshes/s, ...), and give HTTP requests/s
  separately. Never call a journey rate "requests/s".
- **Clean step:** 0 dropped journeys, errors below 0.1%, p99 below 1 s. `analyze.py`'s
  "Sustained" line allows 1% errors, so it can read higher than the clean step.
- **Same start for every run.** `round.sh` restores the post-import store copy, drops the page
  cache and restarts Hearth before each plan line.
- **Production build only.** `POST /admin/bootstrap` must answer `404`.
- **Generator attribution.** For fast endpoints (userinfo, admin lookup, introspect), 2 c7i.xlarge
  generators get busy near 8,000–12,000 req/s. Check the k6 CPU (`gen-sampler`) and the generator
  idle time (`vmstat`) before you call a result the server's limit. If the generators are the
  limit, report "at least X/s".
- **A/B claims** need at least 5 alternating runs of each build. One run per build is a hint, not
  a result.
- **Swap.** A run that used swap is void. Check the server's lowest MemAvailable and the
  generators' `vmstat` swap column.

## Pitfalls

- Access tokens live 1 hour at most. k6 renews each one when 10–25 % of its lifetime is left,
  by a sign-in tagged `name=renew` (not a journey; `token_renewals` in the summary). Before
  2026-10-12 it did not, and soaks longer than 1 hour showed `401`s on userinfo and admin lookup.
- k6 uses about 3.4 GB at 1,000 VUs and grows about 60 MB an hour in a soak. On a 4 GiB
  generator, use 500 VUs.
- A round started seconds after `aws-iam.sh up` failed with `InvalidClientTokenId`: IAM refuses a
  new key for some seconds. `aws-iam.sh up` now waits until the key works.
- The background SST compaction of a 1M-user store runs about 60 minutes after the start. It adds
  about 640 MiB of RSS for a few seconds and sheds some logins. Expect it in every soak.
- `hearth --version` prints the Cargo version, not the release tag. Identify a build by the
  image's revision label (`variant.txt`).
- Bash reads a script while it runs. Do not edit a running driver in place: write a new file and
  `mv` it over the old one.
- In a `while read` loop, ssh reads the loop's stdin. Read the loop from another file descriptor,
  or give ssh `< /dev/null` (`round.sh` does both).
- Do not use `pkill -f` in a remote command that contains the pattern: it kills its own shell.
- `ssh ... shutdown -h +N` on an instance replaces its self-stop time.

## Report format

One Markdown file per round, `docs/perf/<date>-<server>.md`, with no separate artifact files:

1. The build commit (on `main`) and the measurement plane (see `docs/dev/perf-framing-rule.md`).
2. The setup: server and generator types, OS, disk, data size, Argon2id parameters, KDF gate.
3. The units and the "clean" definition.
4. A summary table: the clean rate, the maximum served rate and the limit, per feature.
5. A per-step table for each ramp, as `ramps.py` prints it.
6. For a soak: rates and latency per journey type, and memory as `memory.py` prints it.
7. Admissibility: generator attribution, swap, number of runs.
8. The plan file in `plans/` and the tool commit that produced the results.

