# Backup and Restore Guide

Hearth ships a built-in backup CLI that exports realm data to a self-contained `.hearth-backup` archive and restores from it without a running server. The backup engine reads directly from the embedded storage engine, so no HTTP server needs to be running during the operation.

> **The server must in fact be stopped, not merely unnecessary.** The data
> directory carries an exclusive `LOCK`. Run any `--data-dir` subcommand against
> a live instance and it exits `2` with
> `data directory '…' is already locked by another process`.

> **Exporting a KEK-encrypted store.** Production requires a key-encryption key,
> and every CLI subcommand that opens the data directory needs it too — otherwise
> the export hits an `HKEY` envelope it cannot open. Supply it either way:
>
> ```bash
> # Either: the environment variable (takes precedence)
> export HEARTH_KEK=$(cat /etc/hearth/kek.hex)
> hearth backup create --data-dir /var/lib/hearth/data
>
> # Or: point the command at the config file that carries it
> hearth backup create --data-dir /var/lib/hearth/data --config /etc/hearth/hearth.yaml
> ```
>
> `--config` reads only `security.key_encryption_key`; it does **not** run the
> full production validator, so a config that has drifted elsewhere still lets
> you take a backup. `HEARTH_MASTER_KEY` must also be set, as it is for `serve`.
>
> Until task 26.21 this was impossible by any route: the command read neither the
> environment variable nor a config file, and there was no `--config` flag, while
> the error it printed named both.

> **A mistyped `--data-dir` now fails.** `backup create` READS a store, so it no
> longer creates a missing directory: a path that does not exist is refused, and
> so is a directory that holds no realms. `backup verify` refuses an archive with
> zero files for the same reason. Until task 26.26 all three reported success —
> a typo produced an empty archive, `create` exited `0` after printing only
> `warning: no realms found to export`, and `verify` answered
> `OK — all checksums match (0 files verified)` and exited `0` as well.
---

## Archive format

A `.hearth-backup` file is a zstd-compressed archive. Inside, each realm is stored under `realms/<slug>/` with one NDJSON file per entity type:

| File | Contents |
|---|---|
| `manifest.json` | Archive header: version, timestamp, record counts, SHA-256 checksums, optional DEK |
| `realms/<slug>/realm.json` | Realm configuration record |
| `realms/<slug>/users.ndjson` | User records (one JSON object per line) |
| `realms/<slug>/credentials.ndjson` | Hashed credentials |
| `realms/<slug>/mfa_factors.ndjson` | TOTP secrets, recovery codes and WebAuthn passkeys |
| `realms/<slug>/clients.ndjson` | OAuth 2.0 application registrations, including each client's credentials (see [Client credentials](#client-credentials)) |
| `realms/<slug>/roles.ndjson` | RBAC role definitions |
| `realms/<slug>/permissions.ndjson` | Permission definitions |
| `realms/<slug>/groups.ndjson` | Group definitions |
| `realms/<slug>/group_memberships.ndjson` | Group-to-member edges (users and nested groups) |
| `realms/<slug>/assignments.ndjson` | Role/group assignment records |
| `realms/<slug>/scopes.ndjson` | OAuth 2.0 scope definitions |
| `realms/<slug>/organizations.ndjson` | Organization records |
| `realms/<slug>/organization_memberships.ndjson` | Organization membership records, with each member's role |
| `realms/<slug>/consents.ndjson` | OAuth consent records |
| `realms/<slug>/agents.ndjson` | Agent records, each with all of its credentials (API-key hashes, public keys, cert fingerprints) |
| `realms/<slug>/identity_providers.ndjson` | External IdP connector configurations, under their original `IdpId` |
| `realms/<slug>/federation_links.ndjson` | User-to-IdP account links (both index directions rebuilt on import) |
| `realms/<slug>/webhooks.ndjson` | Webhook registrations, HMAC signing secret included |
| `realms/<slug>/saml_service_providers.ndjson` | **Retired in 3.0.0.** Written by earlier releases for the SAML IdP side. A 3.x restore skips it with a warning and lists it in the restore summary; it never fails the restore |
| `realms/<slug>/saml_signing_key.json` | The realm's SAML RSA key and certificate (AES-256-GCM encrypted with the DEK; re-sealed under the destination's KEK on import) |
| `realms/<slug>/scim_mappings.ndjson` | SCIM `externalId` mappings for users and groups |
| `realms/<slug>/invitations.ndjson` | Organization invitations, with the token, dedup and listing indexes rebuilt on import |
| `realms/<slug>/revocations.ndjson` | Token revocations: revoked access-token JTIs (with their expiry), blocked DPoP key thumbprints and revoked AAT JTIs. Re-applied to the restored node's blocklists, so a sessionless (`client_credentials` or agent) token revoked before the backup stays revoked. Expired JTIs are omitted. Also each user's required-action generation, so a required-action link ended by a session revocation before the backup stays ended (a restore only ever raises a generation), and the single-use markers of required-action flows (and forced password updates) that had already ended, so none can end a second time |
| `realms/<slug>/retiring_signing_keys.json` | Signing keys still inside a rotation grace window (AES-256-GCM encrypted with the DEK; re-sealed under the destination's KEK on import) |
| `realms/<slug>/signing_key.json` | Realm signing key (AES-256-GCM encrypted with the DEK) |
| `realms/<slug>/audit.ndjson` | Audit events (**only when `--include-audit` is passed**) |
| `realms/<slug>/audit_chain.json` | The audit chain key and anchor for those events (AES-256-GCM encrypted with the DEK) |

The NDJSON format (one JSON object per line) enables streaming reads during large restores without loading the full file into memory.

### What a backup does not carry

**Read this before you treat a restore as a complete recovery.** The list above
is the *whole* archive. Exactly one entity family is not in it, and it is left
out on purpose. Every family that was missing by accident now round-trips
(OpenSpec 26.40). `hearth backup create` and `hearth backup restore` both print
the remaining row at the end of a run so it cannot be missed.

| Not carried | What a restore loses |
|---|---|
| **Sessions** | Every session — and so every session-bound access and refresh token and every SSO cookie — issued before the backup is dead after the restore, even though the signing key survives. **This one is deliberate and stays that way.** A session is per-node live state carrying a session version and a device binding, and a revocation recorded *after* the backup is not in the archive — so restoring sessions would resurrect exactly the sessions an operator revoked. Treat a restore as a re-authentication event for users. **It is not one for sessionless tokens:** a `client_credentials` or agent access token carries no session, verifies against the restored signing key, and stays valid until its `exp` (at most the configured access-token TTL). Revocations recorded *before* the backup travel in `revocations.ndjson` and are re-applied; a revocation recorded *after* the backup is not in an older archive, so re-revoke those tokens (or rotate the realm signing key) after restoring one. |

Two things about the closed families are worth knowing before you rely on them.

**Secret material is re-sealed, not copied.** Key material at rest is sealed
under the node's KEK. The SAML signing key and any retiring signing keys are
therefore *unsealed* into the archive member (which is itself encrypted with the
archive DEK) and re-sealed under the **destination's** KEK on import. A restore
that copied the sealed bytes verbatim would write ciphertext the destination
cannot open, and the failure would not surface until the first SAML login or the
first validation of a pre-rotation token. Agent credentials need none of this:
API keys are stored as SHA-256 hashes, so the restored hash verifies the same
key the operator issued.

**Retiring signing keys resume their grace window, they do not restart it.**
The deadline carried in the archive is an absolute instant. A key whose grace
window has already closed by the time you restore is skipped, because the origin
would no longer accept it either; the restore report counts it under
`retiring keys … skipped`.

**A key a realm rotated away from never comes back.** Every signing-key
rotation — of any realm, the system realm included, and of both the Ed25519
key and the RS256 ID-token key — records every key it retires and every
retiring key it purges (a revoking rotation, `grace_period_secs=0`, purges them
all), in the same atomic write as the rotation itself. A restore that replaces
a live key records the key it displaces the same way. A restore refuses an
archived retiring key that record names once the target no longer holds it
(reported as an error on that key, in `skip` and `merge` alike), and refuses a
realm restored as new — absent from the target, or deleted since the archive
was made — whose archived active key the record names, before writing
anything. The record carries no key material and outlives the realm, so an
archive made before you rotated a compromised key cannot put that key back into
this data directory, even after the realm is deleted; restore a backup made
after the rotation. A restore into a fresh, empty data directory has nothing to
compare against, so restore the newest archive there.

**Archives taken before these members existed do not contain them.** An older
archive restores exactly as it did before: the members are simply absent, and
absent means "there were none of these".

Empty sections are omitted from the archive, so an absent member means "there
were none of these" — which is also why a *deleted* member used to be
indistinguishable from an empty one. See
[`hearth backup verify`](#hearth-backup-verify).

### The system realm is included

An unfiltered `hearth backup create` exports the **system realm** (the nil-UUID
realm that holds every operator-console account) alongside the realms
`GET /admin/realms` lists. It did not until task 26.39: the unfiltered export
enumerated realms through `list_realms`, which deliberately hides the system
realm, so a "full" backup contained no administrative identity at all. An
instance restored from its own full backup answered `401` at `/ui` while the
origin answered `200` — and neither `create`, `restore` nor `inspect` mentioned
the omission.

That does mean operator credentials (Argon2id hashes) and the system realm's
signing key are in the file. They are protected exactly as every other realm's
already were: `backup create` refuses to write an archive at all without
`HEARTH_MASTER_KEY` or `--encrypt`, and every section is AES-256-GCM encrypted
under a DEK wrapped with Argon2id from that passphrase. Treat the archive and
the passphrase as you would the data directory itself. If you want an archive
without it, name a single realm with `--realm <name>`.

**Which archives contain it:**

| Export | System realm included? |
|---|---|
| `hearth backup create` (no `--realm`) | **Yes** |
| `hearth backup create --realm <tenant>` | No |
| `hearth backup create --realm 00000000-0000-0000-0000-000000000000` | Yes, alone |
| `POST /admin/backup` by a **system-realm** caller (nil `X-Realm-ID`, `hearth.admin` + `hearth.export`) | **Yes** — appended to a full export; `?realm=system` exports it alone |
| `POST /admin/backup` by a tenant-scoped caller | **Never** — its own realm only; `?realm=system` is `403` |
| `POST /admin/backup` from **v1.6.11 or earlier** | **No** — no HTTP export carried it before this release |

`hearth backup inspect` lists the realms an archive carries; the system realm is
the entry whose `realm_id` is `realm_00000000-0000-0000-0000-000000000000` (slug
`system`).

### Restoring the system realm

`hearth backup restore` restores the system realm's contents — operator accounts
with their password hashes and second factors, the system realm's roles, groups
and role assignments (the `realm.admin` grant the console checks), its signing
key and any retiring keys, and its audit log when the archive has one — into the
target's system realm. Before this release it refused the system realm
(`operation not permitted on the system realm: import_realm`) and aborted the
whole restore.

It follows the same rules as every other realm, with one difference that comes
from the system realm always existing (engine construction seeds it, with a
fresh signing key and no users, in every data directory):

| Mode | Operator accounts and other records | System signing key |
|---|---|---|
| `skip` (default) / `merge` | Missing records are added; existing ones are kept (reported as conflicts) | Installed when the target's system realm **holds no user** — a fresh data directory, whose seeded key has signed nothing. Kept (reported as a conflict) when the target already has operators |
| `overwrite` | Existing records are replaced by the archived ones | As `skip` — a live key is **kept** — unless you also pass `--replace-system-signing-key` (CLI only): then the live key is **replaced**, and every token it signed stops verifying at once |
| `--dry-run` | Counted, nothing written | Reports what the real run would do — installed, kept, replaced or refused — and writes nothing |

**A retired system key is never reinstalled.** Every rotation of the system
realm's signing key records the key it retires (and every retiring key it
purges), and so does a `--replace-system-signing-key` restore for the key it
displaces. A restore refuses an archived system key that record names — or
that is still one of the target's retiring keys — in every mode and even with
`--replace-system-signing-key`, and refuses to reinstate an archived retiring
key a revoking rotation purged. An archive made before you rotated a
compromised key therefore cannot bring that key back into a live instance;
restore a backup made after the rotation. The record lives in the data
directory: a restore into a fresh, empty directory has nothing to compare
against, so restore the newest archive there. `POST /admin/backup/restore`
never replaces a live system key — the caller's own token is signed with it.

A system-realm archive never writes, into the system realm, what the live API
cannot create there: organizations (and their memberships and invitations),
agents, external identity providers, federation links, SAML service providers,
OAuth consents (they name a client, and the system realm has none), SCIM
`externalId` mappings, and a SAML or RS256 ID-token signing key. Such a record is refused and reported,
and the rest of the restore carries on.

The system realm's record itself is not re-created; its contents are imported
into the system realm that already exists. In the restore report the `realms`
row of the `system` realm is the signing key's outcome.

The fail-closed signing-key rule applies unchanged: an archive whose system realm
carries no signing key is refused unless you pass `--allow-missing-signing-key`,
in which case the accounts are restored and the target keeps the key it has.

**Who may restore it.** The CLI (an operator with the data directory) and, over
HTTP, a **system-realm caller holding `hearth.admin`** (plus `hearth.export`).
A system-realm caller's backup export or restore reaches every realm — operator
accounts and the system signing key included — so a system-realm operator
delegated only a sub-admin permission (`hearth.users.admin`,
`hearth.realm.admin`, …) is refused (`403`) even with `hearth.export`.

**Every HTTP restore needs `hearth.admin`.** A restore writes users and their
credentials, clients, roles and role assignments, agents and retiring signing
keys at once — every sub-admin domain — so `POST /admin/backup/restore`
requires `hearth.admin` (which the seeded `realm.admin` role carries) plus
`hearth.export`, for a tenant-scoped caller too. A tenant sub-admin
(`hearth.users.admin`, `hearth.realm.admin`, `hearth.clients.admin`,
`hearth.agents.admin`) holding `hearth.export` may still **export** its own
realm, but its restore is refused (`403`) before anything is read, written or
counted against the hourly quota. A tenant-scoped caller's `POST /admin/backup/restore` is authorized against
**every** realm in the archive before its first write: an archive carrying the
system realm, or any other realm but its own, is refused with `403`, in every
mode, and nothing — not even the restore's own audit event — is written.

**After the restore** operators sign in at `/ui/admin/login` with their original
passwords and second factors. Sessions are not restored (see
[What a backup does not carry](#what-a-backup-does-not-carry)), so everyone signs
in again. `hearth backup restore` ends by saying what actually happened: how many
operator accounts it restored, kept (already present) or refused, and what it did
with the system signing key. When it restored no operator from the archive it
says that operator-console access did **not** come back.

### Audit chain verification

Restore re-signs every imported audit event under the **destination** realm's
HMAC key, because the source realm's key is not the destination's. That means
the hashes the archive carries are replaced, so restore checks them first:
`audit_chain.json` holds the source realm's chain key and anchor, and the
restore walks the exported events against them before importing any of them. A
chain that does not match its own hashes aborts the restore with the index of
the first broken link.

The manifest records whether the chain material was written
(`audit_chain_included`). Because the manifest is checksum-covered — and its
signature is verified on every production restore (see
[Signed archives](#signed-archives)) — deleting `audit_chain.json` to reach the
unverified path fails the restore rather than skipping the check.

Archives written before this member existed carry audit events with no chain
material. Those still restore, with a warning: their restored chain attests to
the restore, not to the source. Re-export to get a verifiable audit section.

**Where restored events land.** Imported events are appended at the **end** of
the destination realm's chain, never slotted in among — or re-signed together
with — events the realm already holds, so the realm keeps verifying (`GET
/admin/realms/{id}/audit/verify`) after a restore into a live instance. Every
imported event carries a `backup_restore` entry in its metadata with its
`original_timestamp`, so restored history is never mistaken for events this
instance recorded. Into a realm with no audit event yet (a fresh data directory)
events keep their original timestamps; into a realm that already has events
each is stamped with the restore time, the original kept in the marker. An event
the realm already holds (same id) is skipped, so restoring the same archive
twice adds nothing. The `BackupRestored` event of `POST /admin/backup/restore`
is recorded after the import, in the caller's realm.

**A restore does not stall live audit writes.** Events are imported in atomic
chunks of 512. The realm's audit chain is locked for one chunk's hashing and
write at a time — never across its fsync, nor across the whole import — so
audit writes to the same realm made while a large archive is restoring wait at
most for one chunk, and the chain keeps verifying with them interleaved: once a
live event lands between two chunks, the rest of the import is stamped after it.
A chunk that fails leaves the chunks before it written and verifiable.

### Signed archives

Encryption and checksums do not prove **who** produced an archive: the
checksums live in the very `manifest.json` an attacker would rewrite, and the
encryption passphrase is shared by every operator who can run a restore. The
only proof of origin is a detached **Ed25519 signature** over the manifest
(`detached_signature_b64`). Because the manifest carries the SHA-256 of every
member, signing it signs the whole archive.

**Restore is fail-closed.** Outside dev mode an archive is restored only when
its signature verifies against the configured verify key:

| Verify key (`security.backup.verify_key` / `--verify-key`) | Archive | CLI `backup restore` | HTTP `POST /admin/backup/restore` |
|---|---|---|---|
| configured | signed with the matching key | restores | restores |
| configured | unsigned, or signed with another key, or edited after signing | **refused** — `--allow-unsigned` does not override a configured key | **refused** (also in dev mode) |
| not configured | any | **refused** unless `--allow-unsigned` is passed | **refused** outside dev mode — no override; `--dev` servers restore with a warning |

The private key never needs to be on a server that restores. Keep it on the
host that takes backups; give restoring instances only the public key.

**One-time setup:**

```bash
# 1. Generate a key pair. Writes the private key (PEM, mode 0600) and prints
#    the public verify_key.
hearth backup keygen --output /etc/hearth/backup-signing.pem
# → verify_key: <43-character base64url public key>

# 2. Configure the public key on every instance that restores (hearth.yaml):
#      security:
#        backup:
#          verify_key: "${HEARTH_BACKUP_VERIFY_KEY}"
```

A key from `openssl genpkey -algorithm ed25519 -out backup-signing.pem` works
too; derive its `verify_key` with
`openssl pkey -in backup-signing.pem -pubout -outform DER | tail -c 32 | basenc --base64url | tr -d '='`.

**Signing:** pass `--sign-key` to `hearth backup create`, or sign an existing
archive — including every archive downloaded from `POST /admin/backup`, which
the server cannot sign because it holds no private key — with
[`hearth backup sign`](#hearth-backup-sign).

**Restoring without a key.** Archives created before this release are
unsigned. Verify one (`hearth backup verify`), then either sign it with
`hearth backup sign` or restore it with `hearth backup restore --allow-unsigned`
— either way, only for an archive whose origin you have established out of
band. `verify` passing does not establish it (see
[`hearth backup sign`](#hearth-backup-sign)).

### Signing key encryption

Every backup includes an AES-256-GCM encrypted copy of each realm's Ed25519 signing key, protected by a random 32-byte **DEK** (Data Encryption Key). The DEK itself is stored base64-encoded in `manifest.json`.

A realm in which any client selected RS256 ID tokens (`id_token_signed_response_alg: RS256`) also has an RSA ID-token signing key. It travels the same way — `id_token_signing_key.json`, plus `retiring_id_token_signing_keys.json` for keys still inside a rotation grace window — and is re-sealed under the destination's KEK on restore, so ID tokens issued before the backup keep verifying against the restored JWKS. An archive whose clients receive RS256 ID tokens but which carries no restorable RSA key fails closed exactly like a missing Ed25519 key, with the same `--allow-missing-signing-key` override.

### Client credentials

Each client record carries everything the client authenticates with: the
stored client-secret **hash** (never a plaintext secret), the assertion public
key, the inline `jwks` / `jwks_uri`, and its `dpop_bound_access_tokens` flag,
together with its consent, logout, CORS, MFA and lifecycle settings. A restore writes them back in the same single write that re-creates
the client, so a confidential or `private_key_jwt` client comes back exactly
as strong as it was: it authenticates with the same secret or key, and is
still refused without it. The secret hash is restored verbatim — only the two
formats Hearth writes (`$argon2id$…` and `$hearth-sha256$v=1$…`) are accepted,
and an `$argon2id$` hash whose cost is above the ceilings password
verification enforces (`m` 1 GiB, `t` 64, `p` 16) is refused: the stored hash
chooses the work every authentication attempt costs, so an archive must not
be able to choose a four-terabyte allocation. Client-secret verification
refuses such a hash too (the secret does not match, and the KDF never runs).

A restore never re-creates a client weaker than its source. A client whose
record does not restore — a secret hash in an unknown format or above the
cost ceilings, a JWKS or
assertion key that no longer validates — is **not restored** and is listed, with the reason, in the
restore report (`errors` in the HTTP response, `conflicts` in the CLI output),
and counted as `errored`. So is a record that carries no credential at all
although its grants (`client_credentials`, `jwt-bearer`) are only ever issued
to a client that authenticates: that is what an archive that lost the
credential looks like, and restoring it would create a public client in place
of a confidential one. Every archive written by a 1.x server carries the full
record; this guards hand-built or edited archives. Register such a client
again, or restore from an archive that carries its credential.

The record is validated before anything is written or deleted, with exactly
the rules the restore applies. In `--mode overwrite` a refused record
therefore never costs the live client: the live client is kept unchanged (it
still authenticates as before) and the refusal is reported. A `--dry-run`
runs the same validation and reports the clients the real restore would
refuse, instead of counting them as created.

Before this release a restore dropped these fields and re-created **every**
client as a public client. If you restored an archive with an earlier 1.x
build, restore it again with this build (or re-register the affected
clients).

When `--encrypt` is passed, the DEK is additionally wrapped with a passphrase using **Argon2id** (m=65536, t=3, p=4) so that the archive is self-contained and the passphrase is the only external secret needed to restore signing keys. KDF parameters (algorithm, memory, iterations, parallelism, salt) are stored alongside the wrapped DEK in `manifest.json`.

#### What an unencrypted archive does *not* contain

The `signing_key.json` member is only restorable when the archive is encrypted (the DEK is present and, for `--encrypt` archives, unwrappable with the passphrase). An **unencrypted** archive — one with no wrapped DEK, or opened without the passphrase — carries **no usable signing key**: the realm records, users, credentials, clients, RBAC model, organizations, and (optionally) audit events are all present, but the Ed25519 signing key is not.

Restoring such an archive would generate a **fresh** signing key, which invalidates every JWT and session issued before the backup. Because that is a silent, data-loss-adjacent outcome, **restore fails closed** on a missing signing key (see [`hearth backup restore`](#hearth-backup-restore) below): it aborts with an actionable error rather than degrading. Produce a restorable archive by exporting with encryption enabled (`--encrypt`, or set `HEARTH_MASTER_KEY`), which the `hearth backup create` command now requires.

---

## Commands

### `hearth backup create`

Exports all realms (or a specific realm) to a `.hearth-backup` archive.

```
hearth backup create [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--output`, `-o` | `./hearth-backup-<timestamp>.hearth-backup` | Output archive path |
| `--realm` | all realms | Export only this realm (name or UUID) |
| `--include-audit` | off | Include audit events in the export (can be very large) |
| `--encrypt` | off | Protect the signing-key DEK with an interactively-prompted passphrase |
| `--sign-key` | none | Sign the manifest with this Ed25519 private key (PEM) so a production restore can authenticate it. Without it the archive is unsigned — see [Signed archives](#signed-archives) |
| `--data-dir` | `data` | Path to the Hearth data directory |
| `--config`, `-c` | none | Path to `hearth.yaml`, read for `security.key_encryption_key`. Needed for a KEK-encrypted store unless `HEARTH_KEK` is exported |

**Examples:**

```bash
# Full backup, all realms
hearth backup create --data-dir /var/lib/hearth/data

# Single realm, custom output path
hearth backup create \
  --data-dir /var/lib/hearth/data \
  --realm production \
  --output /backups/prod-$(date +%F).hearth-backup

# Encrypted, signed backup including audit log
hearth backup create \
  --data-dir /var/lib/hearth/data \
  --include-audit \
  --encrypt \
  --sign-key /etc/hearth/backup-signing.pem \
  --output /backups/full-encrypted-$(date +%F).hearth-backup
# → prompts: "Enter backup passphrase:"
```

**Exit codes:** `0` success · `1` partial failure · `2` fatal error.

---

### `hearth backup restore`

Restores realm data from a `.hearth-backup` archive into an existing data directory.

```
hearth backup restore --input <archive> [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--input`, `-i` | required | Path to the archive |
| `--realm` | all realms | Restore only this realm (by archive slug) |
| `--mode` | `skip` | Conflict resolution: `skip` keeps existing records. `overwrite` is **refused** when the target realm is already present — see below |
| `--dry-run` | off | Parse and report without writing anything |
| `--skip-verify` | off | Skip the integrity check restore runs before it writes. Only for a very large archive already verified out of band. **Refused whenever a verify key is configured** — usable only together with `--allow-unsigned` (see below) |
| `--allow-missing-signing-key` | off | Restore anyway when the archive has no restorable signing key, accepting a freshly generated key (see below) |
| `--replace-system-signing-key` | off | With `--mode overwrite` only: also replace a **live** system realm's signing key with the archived one, signing every operator out. Never reinstalls a key the target rotated away from. See [Restoring the system realm](#restoring-the-system-realm) |
| `--verify-key` | from `--config` | Base64url Ed25519 public key the archive's manifest must be signed with. Overrides `security.backup.verify_key` |
| `--allow-unsigned` | off | Restore even though **no** verify key is configured, so the archive's origin is not authenticated. Never overrides a configured key. See [Signed archives](#signed-archives) |
| `--data-dir` | `data` | Path to the target data directory |
| `--config`, `-c` | none | Path to `hearth.yaml`, read for `security.backup.verify_key` and `security.key_encryption_key` |

Restore prints a per-entity-type table of inserted and skipped counts, broken down by entity type (roles, permissions, groups, assignments, scopes, organizations, audit events). Exit `0` means all records imported cleanly; exit `1` means partial success (some records skipped or failed); exit `2` means a fatal error (archive unreadable, target unopenable, or unrecognized archive member).

**Examples:**

```bash
# Dry-run to preview what would be restored
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --config /etc/hearth/hearth.yaml \
  --dry-run

# Full restore into an empty data directory; the verify key comes from the config
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --config /etc/hearth/hearth.yaml \
  --data-dir /var/lib/hearth/data-restored

# Restore a single realm, passing the verify key directly
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --verify-key "$HEARTH_BACKUP_VERIFY_KEY" \
  --realm production \
  --data-dir /var/lib/hearth/data-restored
```

> **Fail-closed on an unauthenticated archive (A-30).** Restore checks the
> manifest signature before it verifies checksums or writes anything. With no
> verify key configured it refuses and names the fix: configure
> `security.backup.verify_key` (or pass `--verify-key`), or pass
> `--allow-unsigned` for an archive whose origin you have verified out of band.
> A configured key is authoritative — an unsigned or badly signed archive is
> refused even with `--allow-unsigned`. Before this, the CLI restore never
> checked the signature at all, and the HTTP restore skipped it whenever no key
> was configured, which was the default.
>
> **A signed restore always verifies every member.** The signature covers
> `manifest.json` only; each member is bound to it by the SHA-256 the manifest
> records, and by nothing else — the importer does not re-hash what it imports.
> `--skip-verify` skips exactly those checksums, so combining it with a verify
> key would have logged "archive signature verified" over members anyone could
> have replaced after signing. Restore therefore **refuses** `--skip-verify`
> whenever a verify key is configured (exit `2`, before anything is written).
> The flag remains only for an `--allow-unsigned` restore, where nothing is
> being authenticated anyway.
>
> **What is imported is what was verified.** Restore reads the archive through
> a private, unlinked copy taken when it starts (the HTTP endpoint streams the
> upload into one), and every later pass — signature, checksums, import — reads
> that copy. It used to reopen `--input` for each pass, so anyone able to write
> that path could replace the archive after it had been verified and have the
> replacement imported. The copy lives in the system temporary directory
> (`$TMPDIR`) and needs as much free space there as the compressed archive.
> `hearth backup sign` works the same way, so it signs exactly the members it
> verified.

> **Signing-key continuity.** Restore preserves each realm's Ed25519 signing key by default (HEA-745). Every JWT issued before backup keeps validating after restore, and the realm's published JWKS `kid` is unchanged. If you need a fresh key after restore — for example because the original key is suspected compromised — rotate it explicitly with `POST /admin/realms/{id}/rotate-signing-key`. There is no `hearth realm rotate-signing-key` CLI command; `hearth realm` has one subcommand, `create`. See the [Disaster Recovery Guide](./disaster-recovery.md#post-incident-signing-key-rotation) for the rotation procedure.
>
> **Fail-closed on a missing signing key (HEA-2168).** If the archive carries no restorable signing key (an unencrypted archive, one produced before signing-key export, or an encrypted archive opened without the passphrase), restore **refuses** with a clear error rather than silently minting a fresh key that would invalidate every pre-backup JWT and session. The remedy is to restore from an encrypted archive whose key round-trips (`hearth backup create --encrypt` / `HEARTH_MASTER_KEY`). If you genuinely intend to start the realm on a new key, pass `--allow-missing-signing-key` to acknowledge that every token issued before the backup will stop validating. The HTTP restore endpoint always fails closed and has no override.
>
> **`--mode overwrite` will not replace a live realm (audit 2026-08-28 §3 B3).** Overwrite used to
> delete the target realm and then re-import it. `delete_realm` runs its cascade on a background
> task for a realm above `cascade_background_threshold` and returns before that cascade finishes, so
> the re-import raced its own deletion and usually lost: the realm was left destroyed, truncated, or
> without its signing key. Of 1,160 recorded runs none completed and 975 destroyed or truncated the
> realm. Restore now **refuses** when the target realm is already present, with nothing deleted.
> Restoring into a data directory where the realm is absent — the disaster-recovery case — is
> unaffected and needs no `--mode` flag at all. To genuinely replace a live realm, delete it
> explicitly, wait for the deletion to complete, then restore.
>
> **Fail-closed on unrecognized archive members (HEA-2160).** If the archive contains a member not recognized by the importer (for example, an archive produced by a newer or forked version of Hearth), restore aborts with exit `2` rather than silently skipping the unknown data. This prevents a partial restore from appearing successful while quietly discarding state. To recover, ensure the Hearth binary version matches or exceeds the version that produced the archive.

**Exit codes:** `0` success · `1` partial (some records skipped/failed) · `2` fatal error.

> **Restore verifies the archive first (task 26.42).** Restore now runs the same
> SHA-256 integrity check as `hearth backup verify` *before* it creates the
> target data directory, and refuses an archive that fails it. Until this
> change it never verified at all: an archive `hearth backup verify` rejected
> with exit `3` — one checksum in the manifest set to 64 zeros — restored with
> exit `0` and `users — created: 3`. Corruption detection was opt-in and out of
> band while this guide presented `verify` as *the* integrity gate.
> `POST /admin/backup/restore` verifies too, and has **no** `--skip-verify`
> equivalent.
>
> **A restore is not transactional.** `import_realm_record` writes the realm and
> its signing key before any user, so a fatal error partway through used to
> leave the target holding a realm with the archive's signing key and no users,
> and the archive's realm config could never be re-applied afterwards because
> the partial realm already occupied the id. Verifying first moves the whole
> demonstrated class of fatal failures — flipped bytes, tampered checksums,
> elided members — in front of the *first* write, so an integrity failure now
> leaves the target untouched. What remains non-atomic is an engine failure
> mid-import. **Always restore into a fresh, empty data directory**, so that if
> a restore aborts you can delete the directory and start again rather than
> reasoning about what was already applied.

---

### `hearth backup verify`

Recomputes SHA-256 checksums of all files in the archive, compares them against `manifest.json`, and reconciles the manifest's file list against the archive's contents **in both directions**. Detects silent corruption, tampering, a member deleted from the archive, and a member added to it.

> **A deleted member used to be invisible (task 26.41).** Verification walked the
> entries *present* in the tar and checked the ones that also appeared in the
> manifest, so a file that was not there was never iterated and its absence was
> not an error. Deleting `users.ndjson` from an archive left `verify` printing
> `OK — all checksums match (15 files verified)` over fourteen files, and
> `restore` then exited `0` with `users — created: 0`: two commands in a row
> reporting success over a realm nobody can log in to. The manifest is now the
> authority on what the archive must contain, and the file count printed is the
> number of files actually read.

```
hearth backup verify --input <archive>
```

```bash
hearth backup verify --input /backups/prod-2026-05-19.hearth-backup
# → OK: all 14 files verified
# → exits 0 (pass) or 3 (integrity failure)
```

**Exit codes:** `0` all checksums match · `3` one or more checksums do not match.

`verify` checks integrity, not origin: it does not check the manifest
signature. Restore does.

---

### `hearth backup sign`

Signs an existing archive's manifest with an Ed25519 private key, so a
production restore can authenticate it (see [Signed archives](#signed-archives)).
Use it for archives taken without `--sign-key`, including every archive from
`POST /admin/backup`.

`sign` verifies the archive's checksums first, but that proves only that the
archive is **internally consistent** — every member matches the checksum the
unsigned manifest records. It says nothing about where the archive came from:
anyone who replaced a member can rewrite its checksum in that same manifest,
and `sign` would then sign the replacement, which every production restore
would accept. The signature is your statement that you produced the archive.
Sign only archives you took yourself and moved over a trusted channel, into a
directory no other user can write — never a file at a shared or predictable
path such as `/tmp/latest.hearth-backup`.

```
hearth backup sign --input <archive> --key-file <key.pem> [--output <archive>]
```

| Flag | Default | Description |
|---|---|---|
| `--input`, `-i` | required | Archive to sign |
| `--key-file` | required | Ed25519 private key (PEM, PKCS#8) — from `backup keygen` or `openssl genpkey -algorithm ed25519` |
| `--output`, `-o` | `--input` | Where to write the signed archive; the input is replaced atomically by default |

**Exit codes:** `0` signed · `2` error (unreadable key, integrity failure, I/O).

---

### `hearth backup keygen`

Generates an Ed25519 key pair for signing archives. Writes the private key
(PEM, PKCS#8, mode `0600`; refuses to overwrite an existing file) and prints
the public `verify_key` to configure as `security.backup.verify_key`.

```
hearth backup keygen --output <key.pem>
```

**Exit codes:** `0` written · `2` error.

---

### `hearth backup inspect`

Prints a human-readable summary of the archive manifest without decompressing entity files. Useful for quick status checks before a restore.

```
hearth backup inspect --input <archive>
```

Output includes: archive version, creation timestamp, Hearth version, per-realm record counts, whether signing keys are present, whether the DEK is passphrase-protected, and whether the manifest is signed.

```bash
hearth backup inspect --input /backups/prod-2026-05-19.hearth-backup
```

---

## Recovery point objective (RPO)

> **Hearth has no point-in-time recovery.** There is no WAL archiving and no
> incremental backup. **Your recovery point is the last successful full
> backup** — everything written after it is lost in a disk-loss or
> datacenter-loss event.

State it to your stakeholders in these terms:

> With hourly backups, the maximum data loss window is **one hour plus the
> duration of one backup run.**

The general form is:

```
worst-case data loss  =  backup interval  +  duration of one backup run
```

The backup's duration counts because the recovery point is the **start** of the
run, not the end — see the consistency caveat below. Substitute your own
cadence: daily backups mean a worst case of just over 24 hours.

**Measure your own run duration** rather than assuming one; it scales with realm
size and is the only term in the formula that is not under your direct control.
Time a real backup on production-shaped data:

```bash
time curl -fsS -X POST -H "Authorization: Bearer $HEARTH_ADMIN_TOKEN" \
  "http://127.0.0.1:8420/admin/backup" -o /tmp/timing-probe.hearth-backup
```

For small realms this is typically well under a minute, making the interval the
dominant term. Confirm it during your [test-restore
drill](./disaster-recovery.md#test-restore-drill-checklist) and re-measure as
the realm grows.

**What this figure does and does not cover:**

| Failure | Data loss |
|---|---|
| Process crash / `kill -9`, disk intact | **Zero** — the WAL replays on startup |
| Single node lost in a 3-node cluster | **Zero** — surviving nodes hold the writes |
| Disk loss on a single-node deployment | **Last backup** (the formula above) |
| Whole-cluster or datacenter loss | **Last backup** (the formula above) |

WAL replay protects you from a crash, **not** from losing the disk: the WAL
lives in the data directory alongside the data, and it is truncated in place
when it rotates rather than being retained as history. It is not a recovery
source beyond the current segment, and it is never shipped off-host.

### Referential consistency — each realm is snapshotted (HEA-2167)

An export reads each entity type at a different moment during the run (users
first, then credentials, clients, roles, and so on). To stop a concurrent write
from tearing the archive — for example a role assignment referring to a user
created *after* `users.ndjson` was written — the exporter holds a per-node
**consistency barrier** across the whole of a single realm's read pass. Every
entity in a realm's archive therefore reflects one point in time, and every
reference (an assignment's subject, a credential's user) resolves within the
same archive.

**Write-availability impact — know this before you schedule backups.** While an
export holds the barrier, **writes to that node block** until the export's read
pass for the current realm completes; they are not lost, only delayed. Reads —
token validation, session and user lookups — are **never** blocked, so
authentication continues normally during a backup. The blocking window scales
with realm size (how long it takes to scan and serialise the realm's entities
into memory), so for very large realms prefer a low-write window. The barrier
covers only that read pass: it is released before the realm's sections are
encrypted, compressed and written to the archive, so a slow or remote backup
destination does not stall writes. The cost is memory — the exporter holds one
realm's serialised sections in RAM between the two steps. The barrier is also
released between realms, so a multi-realm backup does not hold all writes for
the whole run.

This barrier is **single-node**. Multi-node export consistency is not provided
(clustering is EXPERIMENTAL — see the clustering guide). The offline CLI
(`hearth backup create` against a stopped node's data directory) has no
concurrent writer and so is trivially consistent.

### Roadmap

PITR, WAL archiving, and incremental backup are designed but **not in 1.x** —
see the [design spike](../plans/HEA-2170-pitr-wal-archiving-design.md) for the
approach, the phasing, and an explicit list of what will not be built.

---

## Backup strategy recommendations

### Scheduled backups

> **A running server holds an exclusive lock on its data directory.**
> `hearth backup create --data-dir <live dir>` will fail with
> `data directory '...' is already locked by another process` (exit code 2)
> while `hearth serve` is running. The CLI is for **offline** data directories
> only — a stopped node, or a copy of one.

To back up a **live** server, use the admin HTTP endpoint, which runs inside the
server process and needs no lock:

```bash
# /etc/cron.d/hearth-backup
0 * * * * hearth curl -fsS -X POST \
  -H "Authorization: Bearer $HEARTH_ADMIN_TOKEN" \
  "http://127.0.0.1:8420/admin/backup" \
  -o /backups/hearth-$(date +\%FT\%H).hearth-backup \
  >> /var/log/hearth/backup.log 2>&1
```

The endpoint requires the `hearth.export` capability in addition to an admin
permission — `hearth.admin` itself for a system-realm caller, whose export
covers every realm — and is rate-limited to **10 calls per hour per user**, which
caps how tight a cadence you can schedule. Note that `POST /admin/backup` has
no equivalent of the CLI's `--encrypt` flag; encrypt the resulting archive at
rest yourself, or take encrypted archives from a stopped node with the CLI.

The server holds no signing key, so these archives are **unsigned**, and a
production restore refuses them until they are signed. Sign each one on the
backup host as part of the same job (see
[Verifying backups](#verifying-backups)).

Use the CLI form only against a data directory no server is using:

```bash
systemctl stop hearth
hearth backup create --data-dir /var/lib/hearth/data \
  --output /backups/hearth-$(date +%F).hearth-backup --encrypt \
  --sign-key /etc/hearth/backup-signing.pem
systemctl start hearth
```

Rotate old archives with a retention tool (e.g., `find /backups -name "*.hearth-backup" -mtime +30 -delete`).

### Cluster deployments

In a multi-node cluster, **take backups from a follower** to avoid adding I/O
load to the leader (which is processing all writes). Point the `POST
/admin/backup` call at the follower's own admin listener — a running follower
holds the exclusive lock on its data directory, so the CLI form will not work
against it either.

### Verifying backups

Always verify after creation and before storing off-site. `hearth backup verify`
reads only the archive, so it works regardless of which path produced it and
does not touch the data directory:

```bash
# A private (0700) staging directory: `sign` vouches for whatever file sits at
# the path it is given, so no other user may be able to write that path.
STAGE=$(mktemp -d) || exit 1
trap 'rm -rf "$STAGE"' EXIT
ARCHIVE="$STAGE/hearth-$(date +%F-%H%M%S).hearth-backup"

curl -fsS -X POST -H "Authorization: Bearer $HEARTH_ADMIN_TOKEN" \
  "http://127.0.0.1:8420/admin/backup" -o "$ARCHIVE" \
  && hearth backup verify --input "$ARCHIVE" \
  && hearth backup sign --input "$ARCHIVE" \
       --key-file /etc/hearth/backup-signing.pem \
  && mv "$ARCHIVE" /backups/
```

`verify` and `sign` here establish integrity and then origin only because this
job downloaded the archive itself, over the loopback admin listener, into a
directory only it can write. Do not point `sign` at an archive you did not
produce this way.

An unverified backup is not a backup. Fold the `verify` step into the same
scheduled job so a corrupt archive fails the run loudly instead of sitting
undetected until a restore.

### Restoring to a new node

```bash
# 1. Install Hearth on the new node
# 2. Create an empty data directory
mkdir -p /var/lib/hearth/data

# 3. Restore (the config supplies security.backup.verify_key)
hearth backup restore \
  --input /backups/prod-2026-05-19.hearth-backup \
  --config /etc/hearth/hearth.yaml \
  --data-dir /var/lib/hearth/data

# 4. Start the server
hearth serve -c /etc/hearth/hearth.yaml
```

For cluster mode, restore once into one empty data directory and copy that directory to **every** node before the cluster first starts; never restore into a cluster that has already started (its start-up has created every declared realm under a new id), and never run the restore once per node (each run writes its own keys, so the nodes would diverge). The upgrading guide's [rebuild procedure](./upgrading.md#cluster-purged-log-upgrade) gives the steps. To replace one node of a cluster that still has a leader, do not restore at all: start it with an empty data directory and the leader sends it a snapshot.

---

## What is NOT backed up

For the entity families inside a realm that do not round-trip, see
[What a backup does not carry](#what-a-backup-does-not-carry) — that list is the
one that costs you data.

| Excluded | Why |
|---|---|
| Active sessions | Sessions are short-lived; users re-authenticate after restore |
| Revoked JTI blocklist | Intentionally excluded — restored server accepts previously-revoked tokens; rotate signing keys after a restore if this is a concern |
| Raft log (`raft.db`) | Cluster metadata only; not needed for standalone restore |
| Audit events | Excluded by default; use `--include-audit` if compliance requires it |
