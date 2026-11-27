# Hearth, Keycloak, Zitadel and Ory per node on AWS, 2026-11-25 (#913, session 913a)

| | |
|---|---|
| **Builds** | Hearth 4.13.0, revision `cfacb998` (image `hearth-stress:913-cfacb998`, built locally from that revision, production binary: `POST /admin/bootstrap` answered `404`) |
| | Keycloak 26.8.2 (`quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3`) |
| | Zitadel v4.20.5 (`ghcr.io/zitadel/zitadel:v4.20.5@sha256:cb21fe73badfe44972bb24a66cf0ebce6a8dc63ab8ed24567af6b731bd8bbf45`) |
| | Ory Hydra v26.2.0 (`oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9`), Ory Kratos v26.2.0 (`oryd/kratos:v26.2.0@sha256:2a13bb8d362c7a7ae33bd7c0f5168aee46921f15c916a06346db91c06dc76643`), Ory's reference login and consent UI v26.2.0 (`oryd/kratos-selfservice-ui-node:v26.2.0@sha256:46a7bac1ad0c67c692b37d0380613fd4618fd751afac2c5314aa8d3ae77ef1f0`) |
| | PostgreSQL 18.7 for Keycloak, Zitadel and Ory (`postgres:18.7@sha256:eb63372c1e05c755f55fa30cbd07aecc443676fc6c0fa90b9002d01537841e1a`) |
| **Plane** | Network: HTTPS requests from separate load-generator hosts. TLS, TCP and network time are included. |
| **Servers** | Size 1: AWS c7i.large (2 vCPU, 3,812 MiB) for every product. Size 2: AWS c7i.2xlarge (8 vCPU, 15,700 MiB), Hearth only. us-east-1. |
| **Data** | 1M users in 1 realm, plus 1,000 users with a password for the login journey, for every product |
| **Method** | [#913](https://github.com/hearth-auth/hearth/issues/913), fixed before the first run. One rule changed on 2026-11-24 ([Rule change](#rule-change-on-2026-11-24)). |
| **Configs and tooling** | [`loadtest/compare/`](../../loadtest/compare/README.md): every product's setup, the pinned images in [`images.env`](../../loadtest/compare/images.env), the [AWS session driver](../../loadtest/compare/README.md#the-aws-session-aws); on top of [`loadtest/live/`](../../loadtest/live/README.md) |
| **Step data** | [`2026-11-25-aws-913a-comparison-steps.csv`](2026-11-25-aws-913a-comparison-steps.csv): every judged step of every product |

This report compares Hearth with Keycloak, Zitadel and Ory on the same AWS hardware, with the same data, the same security settings and the same load. One server runs the whole product, its database included. The data is from the #913 AWS session 913a (2026-11-24 and 2026-11-25). Every number is a measurement of the pinned version, with the config in this repository, on this hardware. None of them is a general claim about a product. Hearth's own results from that session, with more detail on size 2 and the #647 restore drill, are in the [Hearth report](2026-11-25-aws-913a-hearth-v4.13.0.md). The Hearth values are the same in both reports.

FusionAuth is not in the comparison: its licence forbids publishing benchmark results without its consent ([#913](https://github.com/hearth-auth/hearth/issues/913) says why).

**Found a setup mistake?** Open an issue on [hearth-auth/hearth](https://github.com/hearth-auth/hearth/issues/new) with the product, the setting and the vendor's documentation for it. When a mistake is real, that product runs again and this report is updated. Each setup was checked against its product's published production guide before publication. [Differences from the production guides](#differences-from-the-production-guides) lists every difference found.

## Summary

Size 1 (c7i.large, 2 vCPU), clean rates measured with this setup:

| Journey | p99 budget | Hearth | Keycloak | Zitadel | Ory |
|---|---|---|---|---|---|
| Login | 1,000 ms | 48/s | 32/s (a) | 16/s (b) | 12/s |
| Refresh | 100 ms | 1,600/s | 300/s (a) | 250/s | 100/s |
| Client credentials | 100 ms | ≥ 3,200/s (top step) | 400/s | 350/s | 175/s (c) |
| Userinfo | 50 ms | 11,200/s | 1,600/s | 600/s | 700/s (c) |
| Introspect | 50 ms | 6,400/s | 2,400/s | 350/s | 700/s (c) |
| Admin user lookup | 50 ms | ≥ 12,800/s (top step, generator-bound) | 1,600/s | 150/s | 600/s (c) |
| Create user | 100 ms | 1,000/s | 400/s | 150/s | 200/s |
| Mix | 1,000 ms | 240/s | 160/s (a) | 60/s (b) | 40/s |
| Cold read, 100,000 users | 50 ms | 11,200/s (generator-bound) | 400/s | 150/s | 600/s |
| Cold read, 1M users | 50 ms | 11,200/s (generator-bound) | 400/s | 175/s | 600/s |

- (a) Keycloak commits transactions that change only sessions with `synchronous_commit=off`, by default. These journeys did not wait for a disk flush per write at Keycloak; at Hearth and Ory they did. [Details](#keycloak-commits-session-writes-asynchronously).
- (b) Zitadel's production guide recommends 4 CPU cores for password hashing. Size 1 has 2 vCPU, shared with PostgreSQL.
- (c) Ory ran with its default database pool. A local test found that the pool is not what limits these journeys ([details](#orys-database-pool)). Ory's introspect and admin lookup call its admin ports, which have no caller authentication.

"≥" means that the 8th and last step of the ladder was clean: the ladder, not the product, set the limit, so the value is a lower limit. "Generator-bound" means that the busiest load generator used more than 300 % of its 400 % CPU at the clean step, so the generators may have set the limit. Both marks apply only to Hearth. Keycloak, Zitadel and Ory each failed a step below the top of every ladder, and their busiest generator used at most 83 % of 400 % CPU at any judged step.

There is no size 2 comparison: see [Size 2](#size-2-hearth-only).

**Findings** (all on this hardware and config)

1. Hearth had the highest measured clean rate of the four in every journey. Three of its ten values are lower limits ("≥" or generator-bound).
2. Of the other three, Keycloak had the highest clean rate in 8 of the 10 journeys, and Ory in the two cold reads (600/s, against 400/s for Keycloak).
3. At the first failing login step, Keycloak, Zitadel and Ory used 190–196 % of 200 % CPU. Hearth refused password checks (`login_submit:503`) at 153 %. [Details](#login).
4. At their clean steps, Keycloak's login, refresh and mix wrote 6–8 IOPS; Hearth's wrote 767–888. Keycloak's asynchronous session commits explain the difference. [Details](#keycloak-commits-session-writes-asynchronously).
5. Zitadel's admin user lookup (150/s) was 4 times lower than its userinfo (600/s). A reading of Zitadel's code points to a lock taken before each user read. [Details](#zitadel-admin-user-lookup).

## Method

The method is fixed in #913. This section summarizes it. It is the same for every product.

**Ladder.** Each journey runs in two phases. The coarse phase starts at the journey's start rate and doubles the rate at each 60 s step, at most 8 steps, until the first failing step. The fine phase runs 3 steps evenly spaced between the last clean coarse step and the first failing one.

| Journeys | Start rate | Top coarse step |
|---|---|---|
| Login | 2/s | 256/s |
| Mix | 5/s | 640/s |
| Refresh, client credentials, create user | 25/s | 3,200/s |
| Userinfo, introspect, admin user lookup, cold reads | 100/s | 12,800/s |

**Each phase** is one k6 run. Before it, the seeded store is restored, the page cache is dropped, and the product restarts. The run starts with one warm-up minute at the phase's first rate. The warm-up is never judged. While a phase runs, the driver stops it at the first step that fails for sure (p95 above the budget, or 1 % errors).

**Clean step.** A step is clean when no journey was dropped, errors are below 0.1 % of the finished journeys, p99 is within the journey's budget, and the server stayed alive. Every failed journey is an error, every `503` and `429` included, for every product: Hearth's Argon2 sheds and write-limit `503`s, and Keycloak's queue-full `503`s (`KC_HTTP_MAX_QUEUED_REQUESTS`) alike. k6 request timeouts (`e1050`) are errors too.

**Clean rate.** The judge stops at the first failing step. The clean rate is the highest clean step before it, in either phase. A step after the first failing step does not count, even when it is clean.

**Budgets** (p99, from `cloud.sh collect`): 50 ms for userinfo, introspect, admin user lookup and the cold reads; 100 ms for refresh, client credentials and create user; 1,000 ms for login and the mix.

**Journeys.** Login is the authorization code flow with PKCE through each product's own login page. Refresh, client credentials, userinfo, introspect, admin user lookup by id and create user are one request each. The mix uses the #647 weights. The cold reads are admin user lookups over the first 100,000 or 1M seeded users, after the page-cache drop. Admin user lookup itself uses a working set of 1,000 users. One k6 adapter per product sends the same journeys ([`loadtest/compare/README.md`](../../loadtest/compare/README.md#adapters) lists each product's requests). Every product runs with `PRESENT=chain`: each client presents its own newest access token, as a real client does.

**Measurements.** Server CPU is out of 200 % at size 1. For Hearth, CPU and RSS are those of the Hearth process. For Keycloak, Zitadel and Ory, they are the sum of every container of the product's compose project, PostgreSQL included; RSS there is anon plus mapped file memory, from each container's cgroup (`loadtest/compare/aws/compose-sampler.sh`). Write IOPS are those of the server's data disk. Generator CPU is out of 400 %.

**Once.** Each journey has one judged run per product. [Raw data](#raw-data) lists the phases that started again after a tooling failure.

### Rule change on 2026-11-24

The first rule of #913 did not count Argon2 or password-hash `503`/`429` sheds as errors. Only Hearth has such a shed, so only Hearth got the exclusion. On 2026-11-24, after Hearth's first size 1 login ladder, the owner changed the rule: every `503` and `429` is an error, for every product. Hearth's login and mix at size 1 then ran again. Every result in this report uses the new rule. The [Hearth report](2026-11-25-aws-913a-hearth-v4.13.0.md#rule-change-on-2026-11-24) shows the first data.

## Setup

| | Size 1 (every product) |
|---|---|
| Server | c7i.large, 2 vCPU, 3,812 MiB |
| CPU | Intel Xeon Platinum 8488C |
| Load generators | 2 × c7i.xlarge (4 vCPU, 7,775 MiB) |
| Data volume | EBS gp3, 40 GB, 3,000 IOPS, 125 MB/s |

- Ubuntu 24.04. No swap. One availability zone for the server and the generators.
- The data volume is made from an EBS snapshot of the product's seeded store, and read once in full before the first ramp.
- k6 2.0.0, 1,000 virtual users per generator, open loop: k6 starts journeys at the offered rate, also when the server is slow.
- Hearth runs as one process, with no memory limit. Keycloak, Zitadel and Ory run in Docker Compose (Docker 29.1.3), each with its PostgreSQL on the same server.

| | Hearth | Keycloak | Zitadel | Ory |
|---|---|---|---|---|
| User password hash | Argon2id, m=19,456 KiB, t=2, p=1 (its default) | the same (`KC_SPI_PASSWORD_HASHING__ARGON2__*`; Keycloak's default is Argon2, m=7 MiB, t=5) | the same (`ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_*`; Zitadel's default is bcrypt, cost 14) | the same (Kratos `hashers.argon2`; Kratos's default is bcrypt, cost 12) |
| Client secret, stored as | SHA-256 (fast format), a generated secret | as given, not hashed (Keycloak's default) | bcrypt, cost 4 (Zitadel's default) | PBKDF2-SHA256, 25,000 iterations (Hydra's default; Hydra has no Argon2 option) |
| Access token | JWT, Ed25519 | JWT, RS256 | opaque | opaque (Hydra) |
| Token settings | access token 1 h, reused refresh token refused | the same (`revokeRefreshToken`, `refreshTokenMaxReuse` 0) | the same (Zitadel always rotates) | the same (no grace period, Hydra's default) |
| After a refresh | the old access token stays valid | the same | the old access token is revoked | the old access token is revoked |
| Durable writes | each write fsynced to the WAL before the answer | PostgreSQL `fsync=on`, `synchronous_commit=on`, but Keycloak turns `synchronous_commit` off for session-only transactions ([below](#keycloak-commits-session-writes-asynchronously)) | PostgreSQL `fsync=on`, `synchronous_commit=on` | the same |
| TLS | on Hearth's listener | on Keycloak's listener | on Zitadel's listener | on each listener of Hydra, Kratos and the UI |
| Database | embedded store | PostgreSQL 18.7, one `postgresql.conf` for all three, no TLS to the database | the same | the same, one database each for Hydra and Kratos |
| Database pool | – | 30 (initial = min = max, as Keycloak's deployment example) | 10 open, 5 idle (Zitadel's production guide) | Ory's code default: 4 open, 2 idle per process (2 per CPU) |
| Memory | no limit | container limit 2 GiB (JVM heap 70 %) | container limit 2 GiB | 2 GiB in all: Kratos 1 GiB, Hydra 512 MiB, UI 512 MiB |
| Introspect caller | `api` client, basic auth | `api` client, client secret | `api` application, basic auth | none: Hydra's admin port |
| Admin lookup caller | admin access token | realm admin token (`kc-admin-api` scope) | IAM_OWNER token | none: Kratos's admin port |

- **PostgreSQL.** `shared_buffers` 512 MB (one eighth of the 4 GiB server, which the product shares), `max_connections` 200, `fsync`, `synchronous_commit` and `full_page_writes` on; the rest at PostgreSQL 18's defaults ([`postgres/postgresql.conf`](../../loadtest/compare/postgres/postgresql.conf)). PostgreSQL has no container memory limit.
- **Ory's login app.** Hydra needs a login and consent app. The run uses Ory's reference UI (`kratos-selfservice-ui-node`) at the same release. A deployment with its own app may differ; this is not measured.
- **Zitadel's login.** The run uses Zitadel's login UI v1, served by Zitadel on its own listener. Zitadel v4 defaults new instances to login v2, a separate server behind a proxy; Zitadel's guide says that v1 stays supported.

## Results at size 1 (c7i.large, 2 vCPU)

Every value is measured. CPU, RSS and write IOPS are those of the clean step. "First failing step" is the lowest failing step above the clean rate.

### Login

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 48/s | 278 ms | 152.5 % | 554 MB | 888 | 56/s: 10.12 % `login_submit:503` |
| Keycloak (a) | 32/s | 304 ms | 163.4 % | 872 MB | 6 | 40/s: 99.88 % k6 timeouts (`e1050`), p99 19,996 ms |
| Zitadel (b) | 16/s | 653 ms | 192.3 % | 684 MB | 141 | 20/s: 46.29 % `login_name:e1050`, p99 18,429 ms |
| Ory | 12/s | 268 ms | 160.5 % | 627 MB | 101 | 14/s: p99 1,481 ms |

(a) Keycloak's login writes were committed without waiting for a flush ([details](#keycloak-commits-session-writes-asynchronously)). (b) Zitadel's guide recommends 4 CPU cores for password hashing; this server has 2 vCPU for Zitadel and PostgreSQL together.

**Measured.** At the first failing step, server CPU was 152.6 % for Hearth, 196.1 % for Keycloak, 194.6 % for Zitadel and 190.2 % for Ory. At its failing coarse step (64/s), Keycloak also answered `503` (`login_page:503` × 729, `login_submit:503` × 42, `code_exchange:503` × 34). A login takes 3 requests at Keycloak, 6 at Zitadel and 9 at Ory ([adapters](../../loadtest/compare/README.md#adapters)).

**Inferred.** In this setup, login was bound by the CPU at Keycloak, Zitadel and Ory. Every product checked the password with Argon2id at the same parameters. Hearth limits the number of password checks in flight and refuses the rest with `503`, before its CPU is full.

### Refresh

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 1,600/s | 40.5 ms | 116.0 % | 622 MB | 767 | 2,000/s: 0.38 % `503`, p99 139 ms |
| Keycloak (a) | 300/s | 55.5 ms | 124.3 % | 1,202 MB | 8 | 350/s: p99 141 ms |
| Zitadel | 250/s | 97.8 ms | 150.2 % | 982 MB | 302 | 300/s: p99 4,638 ms |
| Ory | 100/s | 75.2 ms | 140.5 % | 495 MB | 105 | 125/s: p99 363 ms |

(a) Keycloak's refresh writes were committed without waiting for a flush ([details](#keycloak-commits-session-writes-asynchronously)).

### Client credentials

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | ≥ 3,200/s | 0.8 ms | 47.4 % | 436 MB | 1 | none |
| Keycloak | 400/s | 25.9 ms | 107.4 % | 762 MB | 1 | 500/s: p99 1,075 ms |
| Zitadel | 350/s | 88.4 ms | 138.8 % | 927 MB | 428 | 400/s: p99 122 ms |
| Ory (c) | 175/s | 58.8 ms | 127.2 % | 482 MB | 173 | 200/s: p99 114 ms |

Each product checks the client secret in its own stored form, with a different cost: SHA-256 at Hearth, a plain comparison at Keycloak, bcrypt cost 4 at Zitadel, PBKDF2-SHA256 with 25,000 iterations at Ory's Hydra (its default). (c) Ory's database pool: [below](#orys-database-pool). Zitadel's journey ran twice; the reported run is the second ([Raw data](#raw-data)).

### Userinfo

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 11,200/s | 12.6 ms | 98.0 % | 449 MB | 1 | 12,800/s: 754 dropped, p99 125 ms |
| Keycloak | 1,600/s | 5.2 ms | 79.3 % | 949 MB | 1 | 2,000/s: 886 dropped, p99 1,194 ms |
| Zitadel | 600/s | 33.2 ms | 115.2 % | 464 MB | 4 | 700/s: p99 71.5 ms |
| Ory (c) | 700/s | 33.9 ms | 102.0 % | 423 MB | 5 | 800/s: p99 50.7 ms |

Hearth and Keycloak issue JWT access tokens, Zitadel and Ory opaque ones; each product runs its default format. (c) Ory's database pool: [below](#orys-database-pool).

### Introspect

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 6,400/s | 30.6 ms | 139.1 % | 439 MB | 0 | 8,000/s: p99 242 ms |
| Keycloak | 2,400/s | 26.1 ms | 153.1 % | 982 MB | 2 | 2,800/s: p99 55.9 ms |
| Zitadel | 350/s | 18.6 ms | 117.6 % | 463 MB | 4 | 400/s: p99 63.9 ms |
| Ory (c) | 700/s | 32.5 ms | 107.8 % | 416 MB | 6 | 800/s: p99 53.3 ms |

(c) Ory's introspection runs on Hydra's admin port, which takes no client authentication; Ory's guides put that port behind an authenticating gateway. The other products authenticate the calling client on each request. Ory's database pool: [below](#orys-database-pool).

### Admin user lookup

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | ≥ 12,800/s (generator-bound) | 11.6 ms | 97.9 % | 458 MB | 0 | none |
| Keycloak | 1,600/s | 18.6 ms | 128.3 % | 1,016 MB | 0 | 2,000/s: 32,346 dropped, p99 2,534 ms |
| Zitadel | 150/s | 28.5 ms | 100.6 % | 432 MB | 300 | 175/s: p99 59.1 ms |
| Ory (c) | 600/s | 35.4 ms | 182.0 % | 441 MB | 3 | 700/s: p99 74.9 ms |

At Hearth's clean step, the busiest generator used 378 % of 400 % CPU. (c) Kratos's admin port has no authentication of its own: Ory's lookups send no token.

### Create user

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 1,000/s | 59.7 ms | 92.4 % | 961 MB | 924 | 1,200/s: 0.15 % `503` |
| Keycloak | 400/s | 29.1 ms | 111.9 % | 1,031 MB | 342 | 500/s: 14.08 % `503`, p99 3,281 ms |
| Zitadel | 150/s | 61.8 ms | 161.0 % | 940 MB | 346 | 175/s: p99 107 ms |
| Ory | 200/s | 98.9 ms | 126.3 % | 931 MB | 467 | 250/s: p99 197 ms |

Every product creates the user without a password and with a verified email, so no product sends a message. Keycloak commits a user create synchronously.

### Mix

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 240/s | 259 ms | 126.4 % | 580 MB | 850 | 280/s: 0.18 % `login_submit:503` |
| Keycloak (a) | 160/s | 329 ms | 167.6 % | 911 MB | 6 | 200/s: 27.51 % errors (`503` × 2,644, `login_page:503` × 467, others), p99 19,075 ms |
| Zitadel (b) | 60/s | 523 ms | 146.9 % | 718 MB | 126 | 70/s: p99 1,121 ms |
| Ory | 40/s | 549 ms | 130.3 % | 645 MB | 78 | 50/s: 72.72 % errors (mostly k6 timeouts, `e1050`), p99 33,190 ms |

(a) Most of Keycloak's mix writes were committed without waiting for a flush ([details](#keycloak-commits-session-writes-asynchronously)). (b) The mix includes logins: Zitadel's guide recommends 4 CPU cores for password hashing; this server has 2 vCPU.

### Cold read, 100,000 users

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 11,200/s (generator-bound) | 21.6 ms | 87.6 % | 512 MB | 0 | 12,800/s: p99 82 ms |
| Keycloak | 400/s | 12.0 ms | 70.3 % | 1,141 MB | 1 | 500/s: 1,282 dropped, p99 5,447 ms |
| Zitadel | 150/s | 33.7 ms | 101.9 % | 436 MB | 300 | 175/s: p99 65.9 ms |
| Ory | 600/s | 46.0 ms | 182.0 % | 611 MB | 22 | 700/s: p99 71.5 ms |

### Cold read, 1M users

| Product | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Hearth | 11,200/s (generator-bound) | 21.5 ms | 109.1 % | 894 MB | 1 | 12,800/s: 7,089 dropped, p99 123 ms |
| Keycloak | 400/s | 13.5 ms | 76.5 % | 1,131 MB | 2 | 500/s: 2,879 dropped, p99 5,923 ms |
| Zitadel | 175/s | 31.4 ms | 105.8 % | 460 MB | 349 | 200/s: p99 55.8 ms |
| Ory | 600/s | 47.0 ms | 182.0 % | 593 MB | 20 | 700/s: p99 53.3 ms |

Ory's lookups in both cold reads send no token ([Admin user lookup](#admin-user-lookup)).

### Keycloak commits session writes asynchronously

**Measured.** Write IOPS at the clean step of the journeys that write:

| Journey | Hearth | Keycloak | Zitadel | Ory |
|---|---|---|---|---|
| Login | 888 at 48/s | 6 at 32/s | 141 at 16/s | 101 at 12/s |
| Refresh | 767 at 1,600/s | 8 at 300/s | 302 at 250/s | 105 at 100/s |
| Create user | 924 at 1,000/s | 342 at 400/s | 346 at 150/s | 467 at 200/s |
| Mix | 850 at 240/s | 6 at 160/s | 126 at 60/s | 78 at 40/s |

Keycloak's login stayed at about 6 IOPS from 8/s to 40/s, while its create user grew with the rate (23 IOPS at 25/s, 342 at 400/s).

**Documented and in the source.** Keycloak 26.8.2 commits a transaction that changes only sessions or events with PostgreSQL's `synchronous_commit = off`, by default ([database guide](https://www.keycloak.org/server/db), "Asynchronous commits"; [`AsyncCommitIntegrator.java`](https://github.com/keycloak/keycloak/blob/26.8.2/model/jpa/src/main/java/org/keycloak/connections/jpa/AsyncCommitIntegrator.java)). A transaction that also writes a user, a credential or a session removal (a logout) waits for the flush. The login, the code exchange and the refresh rotation write only sessions, so Keycloak's login, refresh and most of its mix did not wait for a disk flush per write. PostgreSQL then flushes the WAL in the background, every 200 ms here (`wal_writer_delay` default); its documentation puts the loss window after a crash at up to three times that. Hearth (each write fsynced before the answer) and Ory (PostgreSQL commits at `synchronous_commit=on`) waited for the flush on every journey that writes.

This is Keycloak's documented default, so the comparison runs it. A run with durable commits (`--spi-connections-jpa--quarkus--async-commit=false`) was planned and then skipped by owner decision: asynchronous commits can only raise Keycloak's results, and Hearth's results were higher on all three journeys even so. The driver keeps that run as the `durable` variant ([`loadtest/compare/README.md`](../../loadtest/compare/README.md#the-aws-session-aws)).

### Ory's database pool

Hydra and Kratos ran with Ory's code default database pool: at most 2 connections per CPU (4 on this server), 2 kept idle. Ory's production pages recommend no pool size; Ory's deployment examples use `max_conns=20&max_idle_conns=4`. Ory's introspect and userinfo failed on p99 at 120–130 % CPU, so the pool was tested before publication.

**Measured locally, not on AWS** (Hydra and PostgreSQL pinned to one physical core with 2 threads, 10,000 Kratos users, introspect and userinfo at 800–2,000/s):

- With the default pool, at most 3 of the 4 connections were busy, also at 1,200/s.
- With Ory's example pool (20/4), p99 was 91–177 ms, against 21–62 ms with the default at the same rates.
- The default's cost is connection churn: it keeps only 2 connections open, so PostgreSQL opened and closed about 36–57 connections per second at 1,000–1,200/s. A pool of 4 with all 4 kept open removed the churn and lowered p99, but it is neither Ory's default nor its documented example, so the method does not use it.

So the pool was not the limit, and Ory's results stand with its default pool. No AWS rerun was made.

### Zitadel admin user lookup

**Measured.** Zitadel's admin user lookup reached 150/s with a working set of 1,000 users, 150/s with 100,000 and 175/s with 1M. Its userinfo reached 600/s. During the lookups, Zitadel's disk saw about 300 writes/s; the other products' lookups wrote 0–22/s.

**Inferred from Zitadel's code, not measured.** At v4.20.5, `GET /v2/users/{id}` runs Zitadel's user projections before each read (`shouldTriggerBulk` is hard-coded to `true`, [user_query.go](https://github.com/zitadel/zitadel/blob/v4.20.5/internal/api/grpc/user/v2/user_query.go#L15)). Each trigger takes a per-instance lock and a PostgreSQL advisory lock ([handler.go](https://github.com/zitadel/zitadel/blob/v4.20.5/internal/eventstore/handler/v2/handler.go#L407-L412)). So the lookups of one instance wait for each other, whatever the data size. The writes during the lookups may come from these triggers. No documented setting removes the lock. The setup matches Zitadel's production, tuning and cache guides.

## Seed

Each product's seed ran on a c7i.large server alone (2 vCPU, the size 1 server), with no generators. Every value is measured.

| | Hearth | Keycloak | Zitadel | Ory |
|---|---|---|---|---|
| Bulk path | `POST /admin/users/import`, from one load-generator host | `partialImport`, 1,000 users per request, 4 in parallel, from the server | `POST /admin/v1/import`, 1,000 per request, 4 in parallel, from the server | Kratos `PATCH /admin/identities`, 1,000 per request, 4 in parallel, from the server |
| Import of 1M users | 80.6 s (12,402 users/s), 0 failed | 1,371.9 s (729 users/s), 0 failed | 2,213.4 s (452 users/s), 0 failed; the user projection had every user after 2,366 s | 1,576.9 s (634 users/s), 0 failed |
| Seed call | 99 s | 1,374 s | 2,367 s | 1,578 s |
| Until usable | 133 s | 1,381 s | 2,378 s | 1,674 s |
| Usable rule | the admin API lists the 1M users | 1,001 admin lookups answer `200` (listing of the ids, 5 s, not counted) | 1,001 admin lookups answer `200` (listing of the ids, 2 s, not counted) | the admin API lists the 1M users |
| Settle after the seed | 20 s | 0 s | 20 s | 10 s |
| Idle RSS | 926 MiB | 1,340 MiB | 769 MiB | 742 MiB |
| Store on disk | 2.0 GB (1,995,467,315 bytes) | 2.1 GB (2,130,540,912 bytes) | 5.7 GB (5,714,330,816 bytes) | 3.2 GB (3,172,143,151 bytes) |

- The 1,000 login users are made before the seed call starts, for every product.
- Keycloak's bulk users have no password. Zitadel's and Ory's each get one unusable Argon2id hash through the import's documented field for hashes from another system, so neither product puts the users into an initial state that sends an email. No seed hashes 1M passwords.
- Idle RSS and store size for Keycloak, Zitadel and Ory include PostgreSQL: all containers of the compose project, and the Docker volumes. Hearth's are its process and `/var/lib/hearth`.
- The usable rule changed during the session: the Hearth and Ory seeds ran with the earlier rule (the admin API lists the 1M users, the listing included). "Until usable" is therefore not measured the same way for all four.
- Hearth's seed ran from a load-generator host. The other products' seeds ran k6 on the seed server, which shares its 2 vCPU with the product. The effect is not measured.
- Seeds ran more than once because of tooling failures (#928, #932). The table gives the attempt whose snapshot the ramps used. Earlier complete imports took 1,432.9 s and 1,405.0 s (Keycloak), 2,273.2 s with every user in the projection after 2,452 s (Zitadel), and 1,610.6 s (Ory).
- PostgreSQL's statistics were current on copies of the seeded stores: autovacuum had analyzed each large table during the seed, and at most 9.4 % of a table's rows had changed since, under PostgreSQL's default 10 % threshold for a new analyze.

## Size 2 (Hearth only)

The method planned size 2 (c7i.2xlarge, 8 vCPU) for Hearth and the fastest other product at size 1. By the geometric mean of its 8 clean rates, that product is Keycloak. Keycloak's size 2 run was not done because of the cost cap (owner decision, 2026-11-25). There is therefore no size 2 comparison. Hearth's size 2 results, for reference:

| Journey | Clean rate | p99 at the clean step | Server CPU | RSS max | Write IOPS | First failing step |
|---|---|---|---|---|---|---|
| Login | 192/s | 156 ms | 484.4 % | 873 MB | 861 | 224/s: 3.56 % `login_submit:503` |
| Refresh | 1,600/s | 55.9 ms | 95.5 % | 694 MB | 855 | 2,000/s: 0.11 % `503`, p99 9.8 ms |
| Client credentials | ≥ 3,200/s | 1.1 ms | 47.7 % | 525 MB | 1 | none |
| Userinfo | ≥ 12,800/s | 2.2 ms | 90.0 % | 551 MB | 1 | none |
| Introspect | ≥ 12,800/s | 2.2 ms | 242.0 % | 532 MB | 1 | none |
| Admin user lookup | ≥ 12,800/s | 7.5 ms | 81.5 % | 565 MB | 0 | none |
| Create user | 1,000/s | 67.3 ms | 90.1 % | 1,079 MB | 841 | 1,200/s: 0.27 % `503` |
| Mix | ≥ 640/s | 137 ms | 246.2 % | 850 MB | 866 | none |

Server CPU is out of 800 % at size 2. The [Hearth report](2026-11-25-aws-913a-hearth-v4.13.0.md#results-at-size-2-c7i2xlarge-8-vcpu) explains these results.

## Differences from the production guides

Before publication, each product's setup was checked against that product's own published production guide. No setting contradicts a guide's stated recommendation. These are the differences, beside the durable-write and pool points above:

**Every product (the method).**

- One node, not a cluster. Keycloak's production guide describes two or more instances.
- No reverse proxy or gateway: clients reach each product's own TLS listener. Keycloak and Hydra recommend a proxy or gateway in front.
- No TLS between a product and its PostgreSQL, which runs on the same server. Keycloak's deployment examples use `verify-server`; Ory's deployment page recommends `verify-full`, and its own examples use `disable`.
- The same 2 vCPU server for every product. Zitadel's production guide recommends 4 CPU cores for password hashing and about one database core per 100 requests/s. Keycloak's sizing guide asks for 150 % CPU head-room; its figures are for its default Argon2 settings.
- The user password hash is Argon2id at m=19,456 KiB, t=2, p=1 for every product (the OWASP setting, Hearth's default). It is not each product's default: Keycloak's is Argon2 at 7 MiB and 5 iterations, Zitadel's is bcrypt cost 14, Kratos's is bcrypt cost 12, and Kratos recommends a hash of 0.5–1 s with as much memory as possible.
- Client secrets and access tokens keep each product's own format ([Setup](#setup)): Hydra hashes client secrets with PBKDF2-SHA256 (25,000 iterations), Zitadel with bcrypt (cost 4), Keycloak stores them as given; Hearth and Keycloak issue JWTs, Zitadel and Hydra opaque tokens.

**Keycloak.** No optimized build (`start`, not `build` then `start --optimized`): this affects startup, and each phase starts with a warm-up minute. The admin API is not on a separate hostname.

**Zitadel.** Configuration through environment variables, not YAML (the guide's reason is secret handling). No rate limiting. Login UI v1 ([Setup](#setup)).

**Ory.** The admin ports of Hydra and Kratos are reached directly, with no authentication; both guides say not to expose them. So Ory's introspect and admin lookup results include no caller authentication.

## Configuration

Every path is under [`loadtest/compare/`](../../loadtest/compare/README.md). The images and digests are in [`images.env`](../../loadtest/compare/images.env). The shared PostgreSQL settings are in `postgres/postgresql.conf`. Each product's requests are in `loadtest/live/k6/products/<product>.js`. The secrets and the TLS leaf are generated per run and are not in the repository. The README has each product's settings in full; in short:

- **Keycloak 26.8.2** (`keycloak/compose.yaml`, `keycloak/realm.py`, `keycloak/keycloak.sh`): production mode (`start`), HTTPS on 8443, HTTP off; database pool 30/30/30; `KC_HTTP_MAX_QUEUED_REQUESTS` 1000 (every step with a `503` already failed on p99); Argon2id through `KC_SPI_PASSWORD_HASHING__ARGON2__*`; container limit 2 GiB, no JVM option set; realm `stress` with `accessTokenLifespan` 3600, `revokeRefreshToken` true, `refreshTokenMaxReuse` 0; public client `app` (PKCE S256, an audience mapper for `api`), confidential client `api` (service account); asynchronous session commits at their default.
- **Zitadel v4.20.5** (`zitadel/compose.yaml`, `zitadel/instance.py`, `zitadel/zitadel.sh`): `init`, `setup` and `start` in separate containers, `--tlsMode enabled`, no proxy; Argon2id through `ZITADEL_SYSTEMDEFAULTS_PASSWORDHASHER_HASHER_*`; client secrets at the default SecretHasher (bcrypt, cost 4); memory cache for the instance and organization objects, 1 h (the cache guide's single-server setup); database pool, eventstore and projections at their defaults; access token 1 h; `LOGINV2_REQUIRED` false; container limit 2 GiB.
- **Ory Hydra and Kratos v26.2.0** (`ory/compose.yaml`, `ory/hydra.yaml`, `ory/kratos.yaml`, `ory/identity.schema.json`, `ory/initdb.sh`, `ory/realm.py`, `ory/ory.sh`): `hydra serve all` and `kratos serve` without `--dev`; migrations as one-shot containers; database pools at Ory's defaults; TLS on each listener; Hydra `ttl.access_token` 1h, opaque access tokens, `oauth2.hashers` pbkdf2 with 25,000 iterations, `rotation_grace_period` 0s; Kratos `hashers.argon2` m=19456KB (KiB), t=2, p=1, password method only, no courier; the reference UI with `NODE_ENV` production; client `app` (public, `skip_consent`) and `api` (`client_secret_basic`).

## How to run it again

The tooling is in `loadtest/compare/aws/`. The session needs an AWS account and costs money: `compare.sh plan` prints the estimate, and the driver stops every part at `STOP_USD` ($20 by default). Session 913a cost $20.05 in all, the Hearth size 2 run and the #647 drill included.

1. Build the Hearth image from the revision under test:

   ```sh
   docker build -t hearth-stress:<tag> --build-arg BUILD_REVISION=$(git rev-parse HEAD) .
   ```

   The other products' images are pulled by digest from `loadtest/compare/images.env`.

2. Create the scoped AWS identity, as in [`loadtest/live/README.md`](../../loadtest/live/README.md): `aws login`, then `loadtest/live/aws-iam.sh up`.

3. Seed each product once, then run its size 1 ladders (each command detached, with the same `SESSION`):

   ```sh
   for p in hearth keycloak zitadel ory; do
     scripts/run-detached.sh run seed-$p -- env SESSION=<id> IMAGE=hearth-stress:<tag> \
       loadtest/compare/aws/compare.sh seed $p
   done
   for p in hearth keycloak zitadel ory; do
     scripts/run-detached.sh run s1-$p -- env SESSION=<id> IMAGE=hearth-stress:<tag> \
       loadtest/compare/aws/compare.sh ramps $p 1
   done
   ```

   `compare.sh ramps keycloak 1 refresh create_user` runs only those journeys. `VARIANT=durable compare.sh ramps keycloak 1` runs Keycloak with durable session commits.

4. Clean up: `compare.sh snapshots`, `compare.sh delete-snapshots <id>...`, then `loadtest/live/aws-iam.sh down`.

The results are in `loadtest/live/results/compare-<id>/` (git-ignored): one JSON per product, journey and size with every step's verdict, the seed records and `summary.md`. To run one product locally (not a result), see [Running locally](../../loadtest/compare/README.md#running-locally).

## Limits of these results

- **Per node only.** One server runs each product. No product's cluster mode is tested.
- **Pinned versions only.** The results are for the versions and image digests in the header, with the config in this repository. Other releases or other settings may perform differently.
- **One run per journey.** Run-to-run variation is not measured. Zitadel's client credentials show its size: in a first, interrupted run, 400/s was clean with p99 88.4 ms; in the judged run, 400/s failed with p99 122 ms.
- **The ladder and the generators.** A "≥" or "generator-bound" result is not the product's limit. Both apply only to Hearth.
- **Step size.** The clean rate is a ladder step. The real limit is somewhere between the clean step and the first failing step.
- **One size.** The comparison is at size 1 only (2 vCPU). How each product gains from a larger server is not compared.
- **One dataset and one disk.** 1M users in 1 realm; EBS gp3 at 3,000 IOPS and 125 MB/s. A different disk changes the write results.
- **Guide settings and defaults.** Each product runs its production guide's settings and its defaults otherwise. Tuning beyond the guides was not tried.

## Raw data

The raw k6 CSVs and the run directories are not committed. The tables are the verdicts of `loadtest/compare/aws/ladder.py` and the reports of `loadtest/live/analyze.py` of each phase. The judged steps are in the [step CSV](2026-11-25-aws-913a-comparison-steps.csv); its Hearth rows are those of the [Hearth report's step CSV](2026-11-25-aws-913a-hearth-v4.13.0-steps.csv).

| Product | Runs (size 1) | Tooling revisions |
|---|---|---|
| Hearth | `913a-hearth-s1-2` (all journeys except login, the mix and the cold reads), `913a-hearth-s1-3` (login, the mix and the cold reads) | `f95d15bc`, `ab10eefe` |
| Keycloak | `913a-keycloak-s1-1` (all journeys) | `ab10eefe` |
| Zitadel | `913a-zitadel-s1-2` (login, refresh), `913a-zitadel-s1-3` (client credentials to the cold read of 100,000), `913a-zitadel-s1-4` (cold read of 1M) | `12ee66a2`, `c0a21ced`, `fcd23859` |
| Ory | `913a-ory-s1-3` (login), `913a-ory-s1-4` (refresh to the mix, and the coarse phase of the cold read of 100,000), `913a-ory-s1-5` (its fine phase, and the cold read of 1M) | `12ee66a2`, `c0a21ced`, `fcd23859` |

Phases that started again after a tooling failure (none because of its result):

- **Zitadel, client credentials.** In `913a-zitadel-s1-2`, the coarse phase was complete (400/s clean, p99 88.4 ms), then the part was stopped during the fine phase. The journey ran again in full in `913a-zitadel-s1-3`, where 400/s failed (p99 122 ms). The reported 350/s is from that second run.
- **Zitadel, cold read of 1M.** The coarse phase in `913a-zitadel-s1-3` ended with no report; the journey ran again in `913a-zitadel-s1-4`.
- **Ory, login.** Two attempts on 2026-11-24 (`913a-ory-s1-1`) ran no step: the k6 job did not end in time. The judged run is in `913a-ory-s1-3`.
- **Ory, refresh.** Attempts in `913a-ory-s1-1`, `-2` and `-3` ended during or right after the first step. The judged run is in `913a-ory-s1-4`.
- **Ory, cold read of 100,000.** The fine phase in `913a-ory-s1-4` ended with no report; it ran again in `913a-ory-s1-5`.
