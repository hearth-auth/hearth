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
| `memory.py` | Server RSS over a soak: values at fixed minutes, trend, hot-tier and memtable gauges |

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
case `down` never runs.

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
   python3 loadtest/live/memory.py results/<run>/<soak>     # needs metrics-storage.txt: see below
   ```
   `memory.py` reads the storage gauges from `metrics-storage.txt`. Make it from the soak's
   `metrics.txt`: `grep -E " hearth_(storage_|kdf_)" metrics.txt > metrics-storage.txt`.
6. **Clean up.** Check that `cloud.sh down` printed an empty "left over" list. Then, with an
   admin session, run `loadtest/live/aws-iam.sh down`.
7. **Publish** the results as one file, `docs/perf/<date>-<server>.md` (see "Report format").

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

- k6's pool access tokens expire after 1 hour, and the userinfo and admin-lookup journeys do not
  renew them. A soak longer than 1 hour shows `401`s on these journeys. They are test-tool
  failures, not server failures.
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

