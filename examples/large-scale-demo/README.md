# Large-scale demo

Stand up a **fully fleshed-out, multi-million-user** Hearth instance on your
laptop to see the storage model perform at scale — several realms with their own
roles, groups, permissions, and OAuth clients, plus a large population of users
distributed across realms.

This is **not a test**; it's a seeder that leaves you with a running, browsable
instance.

## Run it

```bash
make seed-large
```

That runs:

```bash
HEARTH_DEV_DATA_DIR=./data/demo cargo run --release -- serve --dev \
    --config examples/large-scale-demo/hearth.yaml
```

- **First boot** starts serving **immediately** (HTTP listening within ~1 s),
  then seeds every realm's users **in the background**. The instance is reachable
  and usable while it fills — log in as a seeded user the moment its realm starts
  populating. Progress lines (`demo seeding progress … seeded=…` /
  `demo seeding complete … created=…`) stream as it goes; `demo seeding finished
  (all realms)` marks the end. Seeding ~1.2M users takes on the order of seconds
  to a couple of minutes; the `--release` build matters a lot here.
- **Later boots** are instant — a per-realm sentinel records the seeded count,
  so nothing is re-created.
- Browse at <http://127.0.0.1:8420>. Captured emails: <http://127.0.0.1:8420/dev/mail>.

To wipe the data and force a fresh re-seed:

```bash
make seed-large-reset
```

## How it scales (and why it's safe)

- **Gated by `demo.enabled: true`.** A production config omits this block, so the
  mass seeder physically cannot run against real data. The seeder is also
  additive and synthetic-only — it never reads, modifies, or deletes existing
  accounts.
- **One password hash for everyone.** The shared `demo.password` is hashed once
  (Argon2id) and the resulting hash is reused for every account, so seeding a
  million users costs one hash, not a million.
- **Batched writes.** Users are committed in chunks via a single atomic
  `put_batch` each, minimizing WAL fsync amplification.
- **Resumable.** A per-realm sentinel makes re-runs idempotent and lets a raised
  `seeding.users` count seed only the delta.

## Logging in

Every seeded user shares the demo password. Generated accounts are predictable:

| Realm    | Example login              | Password         |
|----------|----------------------------|------------------|
| acme     | `user0000001@acme.demo`    | `DemoPassw0rd!`  |
| globex   | `user0000001@globex.demo`  | `DemoPassw0rd!`  |
| initech  | `user0000001@initech.demo` | `DemoPassw0rd!`  |
| umbrella | `user0000001@umbrella.demo`| `DemoPassw0rd!`  |

A few named accounts carry real roles so you can exercise RBAC, e.g.
`admin@acme.demo` (editor) / `DemoPassw0rd!`.

Admin browsing: bootstrap an admin token with
`curl -X POST http://127.0.0.1:8420/admin/bootstrap`, or sign in at
`/ui/admin/login` with the bootstrap admin.

## Tuning the scale

Edit `seeding.users` per realm in `hearth.yaml`. Cross-realm distribution is just
whichever counts you set. Want a 5M+ stress run? Bump the numbers. Want a quick
smoke? Drop them to a few thousand. After lowering counts, run
`make seed-large-reset` first (the seeder only ever *adds* users).
