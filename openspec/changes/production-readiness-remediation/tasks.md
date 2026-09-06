Source: `reports/production-readiness-audit-2026-08-28.md`. Each task cites every section that
found it, the audit piece, and the report's severity.

## 1. Wave 0 — Make the build green (hard gate on every later wave)

- [x] 1.1 Remove the `unwrap()` at `src/protocol/scim/etag.rs:83`; clippy aborts here as a hard compile error, so `--all-targets` cannot complete (§2.3, §4.12#17 · P00 · Informational)
- [x] 1.2 Run `cargo fmt`; 7 diff hunks across 5 files fail `cargo fmt --check` (§2 · rc 1)
- [x] 1.3 Bump `h2` to `>=0.4.16` for RUSTSEC-2026-0258, an unauthenticated remote DoS reachable pre-auth on the plaintext listener (§2.2, §4.8#7 · MEDIUM)
- [x] 1.4 Resolve the yanked `validit 0.2.5` reached through `openraft 0.9.25` (§2.2 · `cargo audit`)
- [x] 1.5 Fix `hearth::backup_http backup_restore_dry_run_returns_counts` (§2.1 · FAIL)
- [x] 1.6 Fix `hearth::backup_http backup_restore_emits_pre_restore_audit_event`, red since the commit that changed the behaviour it guards (§2.1, §4.12#10 · P00 · MEDIUM)
- [x] 1.7 Fix the `sigterm_does_not_abort_inflight_http_request` harness, which starves its own request task and loses its race in every observed run; its sibling passes vacuously (§2.1, §4.11#10, §4.12#11 · P18/P00 · MEDIUM)
- [x] 1.8 Leave `simulation_c4_partial_compaction_crash_resurrects_deleted_key` red and confirm it is red for the right reason; its defect is blocker B7 in task 2.7 (§2.1, §4.12#2 · P00 · BLOCKER)
- [x] 1.9 Confirm `make check` runs every gate to completion, and that CI executes `cargo fmt --check` and the test suite on the commit (§1, §4.12#17 · P00)

## 2. Wave 1 — The eleven blockers

- [x] 2.1 B1 — Take the realm on `POST /admin/backup` and `/admin/backup/restore` from the caller's identity, not a query parameter; a tenant admin exports and overwrite-restores a peer tenant (§3 B1, §4.1#1 · P13 · BLOCKER)
- [x] 2.2 B2 — Gate the container image, Helm chart, seven SDK releases and two registry packages on the same signal the binary channel uses; today they publish from a red commit and cosign plus SLSA attest to it (§3 B2, §4.8#1 · P27 · BLOCKER)
- [x] 2.3 B3 — Make `mode=overwrite` restore refuse rather than delete the target realm and then fail to restore it; 1,160 CLI runs, none completed, 975 left the realm destroyed or truncated, one reported exit 0 (§3 B3, §4.9#2 · P12 · BLOCKER)
- [x] 2.4 B4 — Stop WAL rotation destroying acknowledged writes under concurrent writers, and flush the memtable on the shutdown path; a clean `SIGTERM` is sufficient (§3 B4, §4.11#1 · P18 · BLOCKER)
- [x] 2.5 B5 — Fix XML Signature Wrapping in the SAML assertion consumer; `verify_signed_element` authenticates one assertion and `parse_response` consumes a different one (§3 B5, §4.10#1 · P23 · BLOCKER shape 4 / HIGH shapes 1–3)
- [x] 2.6 B6 — Stop the publish jobs running ahead of release validation; the v1.6.11 image and chart published 37 minutes before "Release is NOT cleared to publish" (§3 B6, §4.12#1 · P00 · BLOCKER)
- [x] 2.7 B7 — Order partial compaction so the tombstone is not destroyed before the value it shadows is unlinked; a crash in that window resurrects deleted keys on the shipped default config (§3 B7, §4.11#2, §4.12#2, §4.21#1 · P18/P00/P19 · BLOCKER)
- [x] 2.8 B8 — Stop writing the first-run setup token to the production log at WARN at the default level; the full chain to first-admin takeover was reproduced (§3 B8, §4.12#8, §4.13#11, §4.14#1, §4.24#2 · P00/P02/P26/P17 · BLOCKER, escalated)
- [x] 2.9 B9 — Make signing-key rotation revoke the retired key; it mints new admin tokens for the full 24 h grace window and neither documented mitigation stops it (§3 B9, §4.15#1 · P06 · BLOCKER)
- [x] 2.10 B10 — Require proven user verification before a passkey satisfies `mfa_required`; the UV knob is dead code. Interim operator remedy: `passkey_requires_mfa: true` (§3 B10, §4.18#1 · P16 · BLOCKER)
- [x] 2.11 B11 — Make `reload_sst_readers()` fail loudly instead of silently dropping an unopenable SST, so the next partial compaction does not discard tombstones it must keep; no crash or restart is needed (§3 B11, §4.21#2 · P19 · BLOCKER)

## 3. Wave 2 (HIGH) — Build and release integrity

- [x] 3.1 Stop minting cosign signatures and SLSA provenance for a build that fails validation; both documented verification commands currently pass on it (§4.8#2 · P27 · HIGH)
- [x] 3.2 Make a required check actually block a merge: one required context, zero reviews and an always-on bypass let the audited commit merge 41 minutes before that context reported failure (§4.8#3 · P27 · HIGH)
- [x] 3.3 Remove `continue-on-error` from both dependency-advisory gates and make `cargo deny` a required context that runs on every PR, not only lockfile changes; a 70-vulnerability scan produced a `success` job (§4.8#7, §4.12#3 · P27/P00 · HIGH)
- [ ] 3.4 Make the README's Docker and Helm install paths anonymously reachable; two of three documented install paths fail at the first command (§4.8#5, §4.12#4 · P27/P00 · HIGH)
- [x] 3.5 Derive the version from the server release tag and supply it explicitly when `.git` is absent — the container build's exact condition; it is wrong in five of seven operator-visible surfaces including both published SBOMs (§2.4, §4.8#11, §4.12#5 · P27/P00 · HIGH)

## 4. Wave 2 (HIGH) — Storage durability

- [x] 4.1 Stop `open()` returning `Ok` after physically destroying every acknowledged record following a mid-segment CRC mismatch (§4.11#3 · P18 · HIGH)
- [x] 4.2 Handle a torn SST body write that leaves a short file at the live `NNNNNN.sst` name; the next startup refuses to open the data directory (§4.11#4 · P18 · HIGH)

## 5. Wave 2 (HIGH) — Deletion integrity

- [x] 5.1 Replace the three hand-written prefix allowlists in `delete_realm` with the key-space sweep the cluster path already uses; `cred:history:` Argon2id hashes and six `audit:*` families survive both branches and are served to the realm ID's next occupant (§4.9#1 · P12 · HIGH)
- [x] 5.2 Make realm archival a freeze; 11 of 16 mutating engine operations still write an archived realm, including `delete_user`, `set_password` and `register_client` (§4.20#5 · P14 · HIGH)
- [x] 5.3 Delete consent records when a client is retired; a consent record outlives all three retirement routes and the deterministic YAML `ClientId` hands it to the next application (§4.20#1 · P14 · HIGH)
- [x] 5.4 Fix the hot-tier fill/invalidation race; a delete or update overlapping an in-flight read is permanently invisible to `get()` for the life of the process, so a revoked credential stays readable (§4.21#3 · P19 · HIGH)
- [x] 5.5 Stop cold-read promotion cloning the entire hot-tier map under a global mutex — O(capacity·log capacity) on a path any unauthenticated request can drive, and it blocks revocation (§4.21#4 · P19 · HIGH)

## 6. Wave 2 (HIGH) — Backup and restore safety

- [x] 6.1 Carry every TOTP secret, passkey and OTP factor through backup and restore, or make the record type stop claiming it does; an operator restoring loses every second factor in the realm (§4.18#5 · P16 · HIGH)

## 7. Wave 2 (HIGH) — Tenant isolation

- [x] 7.1 Filter `GET /admin/realms` to the caller's visibility; it returns every tenant to any realm admin while its gRPC twin filters, and only the gRPC behaviour is tested (§4.1#2 · P13 · HIGH)
- [x] 7.2 Enforce realm status on the machine-to-machine plane: suspending a realm does not stop the two sessionless grants minting tokens, and neither `introspect` nor `decide` consults realm status (§4.19#6 · P05 · HIGH)

## 8. Wave 2 (HIGH) — Token and session integrity

- [x] 8.1 Require client authentication on `POST /realms/{name}/introspect` and `/revoke`, and apply the RFC 7662 audience restriction their header-form twins enforce; five pieces reached this from five angles (§4.1#3, §4.19#2, §4.22#1, §4.25#1 · P13/P05/P10/P08 · HIGH)
- [x] 8.2 Verify the `id_token_hint` signature before acting on it; unauthenticated `GET /end_session` revokes any user's SSO session and mints a realm-signed logout token with an attacker-chosen `sub` (§4.2#3, §4.19#1 · P04/P05 · HIGH)
- [ ] 8.3 Call `validate_token` in the gRPC `Decide` RPC, so a refresh token — and a DPoP-bound token replayed as a plain bearer — no longer authorizes (§4.2#1 · P04 · HIGH, evidence contested: reproduced variant is a token-species violation, not a privilege gain)
- [ ] 8.4 Validate `token.signing_key_rotation_grace_period` at start-up; a malformed value silently becomes 24 h and a negative value becomes effectively infinite (§4.15#2 · P06 · HIGH)
- [ ] 8.5 Make refresh rotation atomic; it is an unsynchronised read-modify-write, so two concurrent presentations of one token both succeed and the loser is signed out (§4.16#1 · P07 · HIGH, no attacker required)
- [ ] 8.6 Revoke a deleted OAuth client's outstanding refresh tokens; deletion strips the confidential-client authentication and FAPI DPoP gates instead (§4.16#3 · P07 · HIGH)
- [ ] 8.7 Re-resolve claims on refresh instead of copying the presented token's RBAC claims and scope verbatim; a revoked role is re-minted on every refresh, indefinitely (§4.16#4 · P07 · HIGH)
- [ ] 8.8 Replicate the revoked-JTI projection across the cluster; a sessionless token revoked on one node stays valid on every other until that node restarts (§4.16#5 · P07 · HIGH shape 3 only — the README labels this shape not production-supported)
- [ ] 8.9 Mint every device-grant, step-up-MFA, ROPC and password-reset refresh token with an `fid`, so `refresh_tokens` runs the branch holding client authentication and reuse detection (§4.19#3 · P05 · HIGH)
- [ ] 8.10 Consult the JTI revocation blocklist outside the `sid == "none"` branch of `introspect` and `decide`; a revoked delegation stays `active: true` with live permissions (§4.19#5 · P05 · HIGH)

## 9. Wave 2 (HIGH) — Authentication controls

- [ ] 9.1 Stop `/ui/realms/{realm}/saml/slo-idp` acting as an unauthenticated realm-key signing oracle (§4.10#2 · P23 · HIGH)
- [ ] 9.2 Stop recovery credentials reaching the operator log: the onboarding invitation writes a live realm-admin password-reset URL at WARN, and reset links reach the log on the default transport (§4.14#2, §4.24#2 · P26/P17 · HIGH)
- [ ] 9.3 Parse `X-Forwarded-For` across every field line rather than `get()`'s first line only, so a client-supplied line cannot shadow the proxy-appended one (§4.17#1 · P15 · HIGH — degrades to near-nil behind a merge-style proxy such as nginx)
- [ ] 9.4 Rate-shape the login form so a forged per-request client IP cannot drive unbounded pre-auth Argon2id work with no 429, no 503 and green health checks (§4.17#2 · P15 · HIGH — same proxy-shape caveat as 9.3)
- [ ] 9.5 Require a step-up authentication for passkey enrolment; a stolen session otherwise becomes a permanent MFA-free credential (§4.18#2 · P16 · HIGH)
- [ ] 9.6 Make the `mfa_required` gate check factor use, not factor enrolment; federation and ROPC bypass it (§4.18#3 · P16 · HIGH)
- [ ] 9.7 Make one TOTP, recovery, SMS-OTP or email-OTP code single-use under concurrency; it is currently redeemable repeatedly (§4.18#4 · P16 · HIGH)
- [ ] 9.8 Validate the required-action cookie in `enroll_phone_otp_send` and stop reading the billing realm out of the unverified payload (§4.19#7 · P05 · HIGH)
- [ ] 9.9 Invalidate a password-reset token on email change, out-of-band password change and supersession; all three currently leave it working (§4.24#1 · P17 · HIGH)

## 10. Wave 2 (HIGH) — Control liveness

- [ ] 10.1 Stop an absent `security:` block setting `jwks_rps_limit` to 0, which makes every JWKS and discovery request answer 429 from the first request with nothing in the boot log; four pieces found this independently (§4.2#2, §4.13#1, §4.22#2, §4.25#2 · P04/P02/P10/P08 · HIGH)
- [ ] 10.2 Stop a single `dev_mode: true` config-file line arming the whole dev perimeter and bypassing every production fail-closed gate on a release binary; the one hard guard, a loopback bind, does not cover the modal reverse-proxy deployment (§4.7#1 · P03 · HIGH)
- [ ] 10.3 Enforce `want_authn_requests_signed` and `sp_certificate_pem`, or remove them; a documented SAML security flag is a silent no-op (§4.10#4 · P23 · HIGH)
- [ ] 10.4 Refuse misspelled claim release gates instead of discarding them and emitting the claim to third-party clients, and implement the documented Tier-3 `first_party_only: true` default (§4.13#3 · P02 · HIGH)

## 11. Wave 2 (HIGH) — Web UI and browser security

- [ ] 11.1 Add CSRF tokens to the nine authenticated `/ui/admin` mutations that accept the session cookie without one — MFA teardown, session and passkey revocation, audit-log prune — drivable by a top-level form POST from a same-registrable-domain sibling (§4.23#1a · P22 · HIGH)

## 12. Wave 2 (HIGH) — Protocol surface hardening

- [ ] 12.1 Validate `frontchannel_logout_uri` before rendering it into `<iframe src>` on the IdP origin; a `javascript:` scheme executes script on the identity-provider origin (§4.3#1 · P09 · HIGH, threat model assumes an untrusted tenant admin)
- [ ] 12.2 Apply the SSRF guard to `backchannel_logout_uri`, which is stored unvalidated and dereferenced server-side, reaching internal and metadata addresses (§4.3#2 · P09 · HIGH, same threat-model caveat)
- [ ] 12.3 Truncate on character boundaries in the audit-log pill and the SAML `NameID` sink; byte-offset slicing crashes the whole process under `panic=abort`, reproduced at `realms.rs:787:34` with `/health` going to connection-refused (§4.4#1, §4.10#3 · P25/P23 · HIGH)
- [ ] 12.4 Bound SCIM filter recursion; a ~6 KB authenticated request overflows the stack and aborts the multi-tenant process on both `/Users` and `/Groups` (§4.6#1 · P24 · HIGH)
- [ ] 12.5 Reject a reversed scan window (`start > end`) before `range_scan_inner`; one `GET /admin/audit` killed the process with SIGABRT in 6 of 6 runs (§4.9#7 · P12 · HIGH)
- [ ] 12.6 Authenticate the client on both device-grant endpoints per RFC 8628 §3.4; a party without the client secret runs the whole flow under a confidential client's identity (§4.19#4, §4.22#6 · P05/P10 · HIGH)

## 13. Wave 3 — Build and release integrity

- [ ] 13.1 Make the Helm chart's default image tag one the Docker workflow publishes; a default `helm install` cannot pull an image (§4.8#4, §4.12#6 · MEDIUM)
- [ ] 13.2 Fix the release-validation parser so a completed 4-failure suite is not reported as "suite did not complete"; ANSI-coloured nextest output from a pinned third-party action defeats it (§4.8#6, §4.12#9 · MEDIUM)
- [ ] 13.3 Run the generated-SDK freshness check where the paths filter reaches, so TS and Go types cannot drift from `proto/` past the PR gate (§4.8#8 · MEDIUM)
- [ ] 13.4 Encode the crypto-backend and HTTP-client bans in `deny.toml`; a third crypto backend and a policy-banned HTTP client are linked into the published binary (§4.8#9 · MEDIUM)
- [ ] 13.5 Stop the attribution freshness key hashing the whole `Cargo.lock` including the workspace's own version, which trips a legal-attribution gate with nothing to attribute (§4.8#10 · LOW)
- [ ] 13.6 Fix the two failing commands in the release-verification guide, and make the README's headline install step verify something an attacker could not forge (§4.8#12 · MEDIUM)
- [ ] 13.7 Pin the third-party reusable workflow holding `contents: write` + `id-token: write` to a commit SHA and correct its justification (§4.8#13 · MEDIUM)
- [ ] 13.8 Make the systemd crash-loop limiter take effect; it is silently ignored (§4.8#14 · LOW)
- [ ] 13.9 Correct the three false statements the Dockerfile makes about the build it defines (§4.8#15 · Informational)
- [ ] 13.10 Fix scanner configuration that overstates coverage: fifteen dead schedule conditions, advisory-only scanners, an unscanned image, and suppressions for packages absent from the tree they name (§4.8#16, §4.12#15 · Informational/LOW)
- [ ] 13.11 Stop the shipped Docker Compose file sourcing the repository-root `.env` into the container's runtime environment (§4.8#17 · LOW)
- [ ] 13.12 Relabel published container images `Apache-2.0`; every image is labelled `AGPL-3.0-only` and the project relicensed three months ago (§4.12#7 · MEDIUM)
- [ ] 13.13 Make three `ci.yml` SDK jobs and every job in five other workflows able to fail the required check (§4.12#12 · MEDIUM)
- [ ] 13.14 Fix `make sdk-smoke-local`, which fails on any checkout with the documented `hearth.yaml` because it boots `--dev` from the repo root with no `--config` (§4.12#13 · MEDIUM)
- [ ] 13.15 Correct the CHANGELOG claim that a release whose test suite fails "is never published" (§4.12#14 · CLAIM-DEFECT)
- [ ] 13.16 Add `protoc` to the README prerequisites and correct the walkthrough's client secret and four JWT claims the server does not return (§4.12#16 · LOW)
- [ ] 13.17 Make `[profile.ci]` live so a red suite does not under-report by a third and a real flake can be retried; every run is currently fail-fast (§4.12#18 · Informational)
- [ ] 13.18 Fix the UI smoke suite's setup step, which invalidates the URL its next step depends on — the test deletes itself and the run exits 0 (§4.12#19 · Informational)

## 14. Wave 3 — Storage durability

- [ ] 14.1 Stop one failed WAL write on the `SyncMode::None` path burning a record number and making the whole segment permanently unopenable (§4.11#5 · MEDIUM)
- [ ] 14.2 Handle a write fault during WAL rotation that leaves a 1–81-byte header the engine refuses to open, and document the repair (§4.11#6 · MEDIUM)
- [ ] 14.3 Stop a failed open rewriting the segment in place after a one-byte corruption of the WAL magic (§4.11#7 · MEDIUM)
- [ ] 14.4 Log, meter and surface the WAL write fence in `/readyz`; it is permanent, unlogged and invisible today (§4.11#8 · MEDIUM)
- [ ] 14.5 Drain in-flight requests on `SIGTERM` in the TLS-terminating server, which drops the accept loop, returns, and exits 0 (§4.11#9 · MEDIUM)
- [ ] 14.6 Add coverage for the two real SIGTERM defects the red drain test appears to cover but does not (§4.11#10, §4.12#11 · MEDIUM)
- [ ] 14.7 Open production data directories with the production storage config in every CLI subcommand; `hearth backup restore` and both migration importers acknowledge success with `SyncMode::None` and `dev_mode: true` (§4.11#13 · MEDIUM)

## 15. Wave 3 — Deletion integrity

- [ ] 15.1 Enumerate realms from the same source in snapshot build and snapshot install; build uses `known_realms` and install uses `list_realms()`, so a realm the leader has forgotten is deleted from every follower (§4.9#3 · MEDIUM)
- [ ] 15.2 Add a realm dimension to hot-tier eviction and promotion counters and to `TieredConfig` (§4.9#6 · Informational)
- [ ] 15.3 Stop realm deletion choosing between two divergent cascades by realm size; each path skips key families the other deletes (§4.20#2 · MEDIUM)
- [ ] 15.4 Make a realm wedged in `DeletingInProgress` deletable again; the admin API refuses it and startup reconciliation aborts (§4.20#3 · MEDIUM)
- [ ] 15.5 Delete direct permission grants, org extra roles and every group-subject RBAC row on realm deletion; they are silently reactivated when the same `UserId` is re-imported (§4.20#4 · MEDIUM)
- [ ] 15.6 Sweep password history, webhook secrets, org-owned agent credentials, the per-realm MFA DEK and the DPoP nonce key, which neither cascade removes (§4.20#6 · MEDIUM)
- [ ] 15.7 Move delete preconditions out of the protocol adapters; gRPC `DeleteRealm` has no archival gate and REST/gRPC application delete has no YAML-managed gate (§4.20#10 · MEDIUM)
- [ ] 15.8 Stop three rate-limit counters carrying the subject's plaintext email address in the storage key, where it outlives both the user and the realm (§4.20#7 · LOW)
- [ ] 15.9 Make `delete_user` retryable; it deletes the primary record first and then refuses to retry, so a fault mid-cascade orphans the user permanently (§4.20#8 · LOW)
- [ ] 15.10 Correct the four published statements about cascade completeness and crash recovery, and fix the simulation test that is blind to the difference (§4.20#9 · CLAIM-DEFECT)
- [ ] 15.11 Stop every memtable flush re-reading every byte of every live SST to fetch a 60-byte header (§4.21#5 · MEDIUM)
- [ ] 15.12 Reconcile the SST mmap `SAFETY:` comment with `compact_partial`, which violates the invariant it states, and fix the contradicted crash-safety doc on `compact_ssts` (§4.21#6 · CLAIM-DEFECT)
- [ ] 15.13 Remove or wire up the second `unsafe` block in `src/`, which has no production caller and whose build recipe is the truncation its SIGBUS caveat forbids (§4.21#7 · LOW)

## 16. Wave 3 — Backup and restore safety

- [ ] 16.1 Make the backup consistency barrier effective on the storage handle `serve` installs, and give `ClusterStorageAdapter` an atomic `write_batch` (§4.9#4 · MEDIUM)
- [ ] 16.2 Install a `tracing` subscriber for the whole `hearth backup` CLI family; `create`, `restore`, `verify` and `inspect` emit zero bytes, including when `create` fails on the data-directory lock (§4.9#8, §4.14#6 · MEDIUM)
- [ ] 16.3 Wire `security.backup.verify_key` into the restore handler; it is parsed, validated and documented as fail-closed, and the signature check can never fire (§4.13#5 · MEDIUM)
- [ ] 16.4 Make `verify_integrity` report a truncated or fully erased audit log as invalid; it reports valid when the chain-head record is deleted with the rest (§4.14#4 · MEDIUM)
- [ ] 16.5 Verify an imported audit event's integrity hash on restore instead of discarding and re-signing it (§4.14#5 · MEDIUM)
- [ ] 16.6 Rewrite the two "tamper the middle audit record" tests, which write to a key format the engine abandoned (§4.14#10 · LOW)

## 17. Wave 3 — Tenant isolation

- [x] 17.1 Include `active` on the negative `/realms/{name}/introspect` response, per RFC 7662 §2.2 (§4.1#4 · MEDIUM)
- [ ] 17.2 Stop the pre-shared SCIM bearer token reading a suspended or archived realm's user directory (§4.1#5 · MEDIUM)
- [ ] 17.3 Fix the four handlers that bypass the `scoped_realm` BOLA guard — two permissively, two so strictly the system operator is locked out (§4.1#6 · LOW)
- [ ] 17.4 Make the reserved system realm reject role and group writes through public APIs, as the README states (§4.1#7 · CLAIM-DEFECT)
- [ ] 17.5 Give `check_cross_realm_policy` a production caller; cross-realm trust policies are stored and audited but never consulted (§4.1#8 · CLAIM-DEFECT)
- [ ] 17.6 Add per-handler permission gates to the eight authenticated admin handlers that carry none, so any sub-admin reaches them (§4.1#9 · LOW)
- [ ] 17.7 Answer `404` instead of `200` in the five admin handlers that serve an object absent from the caller's realm (§4.1#10 · LOW)
- [ ] 17.8 Bind the WebAuthn challenge store to a realm and check `ceremony_type`; it is process-global, so a challenge minted in realm A is redeemed in realm B (§4.18#8 · MEDIUM)
- [ ] 17.9 Honour `X-Realm-ID` on the eleven `/realms/{name}/*` routes that ignore it, defeating the subdomain-to-header tenant routing the deployment guide prescribes (§4.16#12 · LOW)

## 18. Wave 3 — Token and session integrity

- [ ] 18.1 Publish only algorithms Hearth signs with; JWKS publishes RS256 and ES256 keys it never uses, four SDKs accept them, and the ES256 private key is discarded on every restart under a 1-hour cache directive (§4.2#4, §4.15#5 · MEDIUM)
- [ ] 18.2 Cross-check DPoP `alg` against `kty`; `alg` selects the verifier and `kty` selects the thumbprint, and the two are never compared (§4.2#5 · LOW)
- [ ] 18.3 Enforce `TokenClaims.nbf` in both hot-path validators, or withdraw the documented MUST; also correct the SDK "federation exception" and JWKS key-role claims (§4.2#6, §4.19#10 · CLAIM-DEFECT)
- [ ] 18.4 Emit an audit event for config-driven signing-key rotation; the HTTP path for the same operation does (§4.14#9 · LOW)
- [ ] 18.5 Relate the rotation grace window to token lifetime; a rotation kills every outstanding refresh token 6 days before its own `exp` (§4.15#3 · MEDIUM)
- [ ] 18.6 KEK-wrap the server-wide OIDC RSA-2048 private key, which is written to storage unencrypted while every other key is wrapped, contradicting the CHANGELOG (§4.15#4 · MEDIUM)
- [ ] 18.7 Invalidate signing-key caches across nodes on rotation; they are process-local, so a second node keeps publishing and trusting the pre-rotation key (§4.15#6 · MEDIUM)
- [ ] 18.8 Refuse an unenveloped signing key on a KEK-configured deployment, and re-encrypt what is already stored when the KEK is enabled (§4.15#7 · MEDIUM)
- [ ] 18.9 Correct the rotation operator documentation: a phantom CLI command, a wrong default, a dead source citation and an undocumented config key (§4.15#8 · CLAIM-DEFECT)
- [ ] 18.10 Close the rotation window that lets a holder of a stolen refresh token land a concurrent redemption and obtain a live chain with no theft event (§4.16#2 · MEDIUM)
- [ ] 18.11 Give every grant's refresh token a family; every grant except `authorization_code` mints one that never rotates, replays forever, and cannot trigger theft detection (§4.16#6 · MEDIUM)
- [ ] 18.12 Stop an RFC 7009 revocation racing a rotation being a lost update; `POST /revoke` returns 200 and the grant survives (§4.16#7 · MEDIUM)
- [ ] 18.13 Rate-limit `POST /token` with `grant_type=refresh_token` and no `client_id`, which the token-endpoint limiter never sees (§4.16#8 · MEDIUM)
- [ ] 18.14 Stop `POST /revoke` writing the full bearer token into the persistent audit log as the event's `resource_id` (§4.16#9 · MEDIUM)
- [ ] 18.15 Make `update_user(status = Disabled)` fail when its session write fails; it reports success it never achieved and the user's refresh token keeps working (§4.16#10 · MEDIUM)
- [ ] 18.16 Stop an application refreshing after its consent is revoked (§4.16#11 · MEDIUM)
- [ ] 18.17 Correct the six published documents and four in-tree comments stating properties of refresh rotation the code does not have (§4.16#14 · CLAIM-DEFECT)
- [ ] 18.18 Enforce the DPoP sender-constraint on `/admin/*`, SCIM and the gRPC admin services, where a stolen `cnf`-bound admin token is replayable as a plain Bearer for reads and writes (§4.19#8 · MEDIUM)
- [ ] 18.19 Add the `token_type` check to `decide_token_permission`, which its two siblings enforce; a refresh token the token endpoint refuses returns a live `allowed: true` (§4.19#9 · MEDIUM)
- [ ] 18.20 Remove the two comments describing a "global-key fallback for Phase 0 realms" the signature-verification function does not implement (§4.19#11 · CLAIM-DEFECT)

## 19. Wave 3 — Authentication controls

- [ ] 19.1 Stop `observability.log_level: trace` dumping every outbound request head, including provider API keys, in cleartext (§4.14#3 · MEDIUM)
- [ ] 19.2 Audit failed second-factor verification, and failed logins for unknown users, which are not audited at all (§4.14#7 · MEDIUM)
- [ ] 19.3 Stop the 38 protocol-layer audit writes discarding their failure with no log line, bypassing `AuditFailurePolicy` (§4.14#8 · LOW)
- [ ] 19.4 Parse and enforce the signed `<SubjectConfirmationData>` bindings — `Recipient`, bearer `NotOnOrAfter` and `InResponseTo` (§4.10#5 · MEDIUM)
- [ ] 19.5 Make the SAML SP assertion consumer create a session, or withdraw SP-initiated SSO; it validates the assertion, audits a completed login, and authenticates nobody (§4.10#6, §4.22#4 · MEDIUM/CLAIM-DEFECT)
- [ ] 19.6 Stop anchoring SAML Audience and Destination validation to `X-Forwarded-Host` under the example config (§4.10#7 · MEDIUM)
- [ ] 19.7 Correct `SAML.md`, the `verify_signed_element` doc comment and the `trusted_base_url` doc comment, which claim protections the code does not implement (§4.10#10 · CLAIM-DEFECT)
- [ ] 19.8 Parse `X-Forwarded-For` hops carrying a port suffix or IPv6 brackets, which currently collapse every client into the proxy's rate-limit bucket (§4.17#3 · MEDIUM)
- [ ] 19.9 Build the absent-user dummy hash from the realm's Argon2 config, not the engine base config; a realm that tunes Argon2 leaks account existence by timing, measured at +88 ms (§4.17#4 · MEDIUM)
- [ ] 19.10 Stop per-account lockout short-circuiting before hashing, which makes a locked — therefore existing — account answer ~12 ms faster than a nonexistent one (§4.17#5 · MEDIUM)
- [ ] 19.11 Add an OWASP floor and a start-up warning for Argon2id memory and time cost, settable arbitrarily low from YAML and over the wire (§4.17#6 · MEDIUM)
- [ ] 19.12 Stop production forcing `trust_forwarded_proto: true` on plaintext while `trusted_proxies` defaults to empty, and move the warning after the log subscriber exists (§4.17#7 · MEDIUM)
- [ ] 19.13 Make SMS-OTP and email-OTP factors visible to the `create_session` gate and the direct browser login (§4.18#6 · MEDIUM)
- [ ] 19.14 Give forced-enrolment activation the CSRF check, nonce redemption and rate limit its sibling has (§4.18#7 · MEDIUM)
- [ ] 19.15 Make `mfa_methods` restrict which factors a user may enrol and present (§4.18#10 · CLAIM-DEFECT)
- [ ] 19.16 Stop `POST /ui/forgot-password` leaking account existence through the in-request SMTP send (§4.24#3 · MEDIUM)
- [ ] 19.17 Stop `POST /ui/register`'s duplicate-email arm skipping Argon2id and the verification mail, which makes a registered address measurably faster (§4.24#4 · MEDIUM)
- [ ] 19.18 Validate the new password before consuming the reset token; an 8-to-11-character password destroys the link while the page says "try again" (§4.24#5 · MEDIUM)
- [ ] 19.19 Make magic-link login complete: there is no redemption route, no mail sent, and the grant all seven SDKs post is rejected (§4.24#6 · MEDIUM)
- [ ] 19.20 Make admin password reset recoverable; the emailed link points at a route that does not exist (§4.24#7 · MEDIUM)
- [ ] 19.21 Refuse `email.transport: log` in production validation for a password-only realm, which silently discards every reset email (§4.24#9 · MEDIUM)
- [ ] 19.22 Stop the two admin actions that mint reset tokens, discard them, and report "Reset email sent" (§4.24#10 · MEDIUM)

## 20. Wave 3 — Control liveness and documented claims

- [ ] 20.1 Gate dev and test endpoints and hardcoded dev credentials behind a compile-time `cfg` rather than a runtime boolean, and add a loopback guard to the embedded path, which has none (§4.7#2 · LOW)
- [ ] 20.2 Correct the two source comments asserting `dev_mode` is `#[serde(skip)]`; the attribute is `#[serde(default)]`, and the comments hide the config-file dev-mode defect (§4.7#3, §4.13#10 · LOW/MEDIUM)
- [ ] 20.3 Correct the three normative documents stating "encrypted at rest with per-realm keys"; one KEK covers every realm, so an operator sizes their key-compromise blast radius wrongly (§4.9#5 · CLAIM-DEFECT)
- [ ] 20.4 Make `storage.fsync` a working knob or remove it; it is ignored in both production and dev mode (§4.11#12, §6 · LOW)
- [ ] 20.5 Fail closed when a `${VAR}` reference to an unset environment variable becomes the empty string; the empty string is accepted as a credential, opening `/metrics` and authenticating a confidential client with `Basic <client_id>:` (§4.13#4 · MEDIUM)
- [ ] 20.6 Stop an absent `security:` block setting `reserved_slugs: []` and `slug_cooldown_days: 0`, silently disabling an abuse control (§4.13#2 · MEDIUM)
- [ ] 20.7 Refuse misspelled keys on `PATCH /ui/admin/realms/{realm}/config`, which answers 200 and clears the realm's `default_required_actions` on every request that omits it (§4.13#6 · MEDIUM)
- [ ] 20.8 Give the `0` sentinel one meaning; it means "unlimited" for three rate limiters and "deny everything" for a fourth, in the same file (§4.13#7 · MEDIUM)
- [ ] 20.9 Make `hearth config validate` use the server's validator; it prints "✓ Configuration valid" for configs the server refuses to start with, and the admin UI writes `hearth.yaml` behind that weaker validator (§4.13#8 · MEDIUM)
- [ ] 20.10 Fix the nine config snippets in the reference and the shipped example that fail to parse, and the three in-source comments asserting per-realm YAML support that does not exist (§4.13#9 · MEDIUM)
- [ ] 20.11 Add the mandatory production key material to the canonical config reference, reconcile published defaults with the reference's own tables, and remove the documented CLI flag that does not exist (§4.13#12 · CLAIM-DEFECT)
- [ ] 20.12 Make the documented global `auth.password_memory_cost` / `auth.password_time_cost` keys reach the base config, and correct both documented defaults (§4.17#8 · CLAIM-DEFECT)
- [ ] 20.13 Construct the eight abuse-prevention guards documented as "Shipped" on a production path, and fix the six documented config keys that make the server refuse to boot (§4.17#9 · CLAIM-DEFECT)
- [ ] 20.14 Make the three documented WebAuthn realm policies settable from an operator surface; one is dead code (§4.18#9 · MEDIUM)
- [ ] 20.15 Read `auth.token.magic_link_ttl`, which is documented, parsed, capped and stored (§4.24#12 · CLAIM-DEFECT)
- [ ] 20.16 Correct the rate-limit persistence table in `CONFIGURATION.md`, wrong on four of its five rows (§4.24#13 · CLAIM-DEFECT)
- [ ] 20.17 Add the start-up assertion that every parsed security key reaches a consumer, and fail closed when one does not — the class fix for §1A item 5 (§1A, §9 item 2 · systemic)

## 21. Wave 3 — Web UI and browser security

- [ ] 21.1 Merge the web router under the API router's guard layers so the `Host` allowlist, the per-IP rate cap, the JSON parse-bomb depth guard, the body limit and the request-duration metric all reach `/ui/*`, the SAML ACS and `begin`, and the pre-auth recovery routes; one root cause behind six findings (§4.5#1, §4.5#2, §4.5#3, §4.5#4, §4.10#8, §4.24#8 · MEDIUM/LOW)
- [ ] 21.2 Add CSRF tokens to the eight further `/ui/admin` mutations that are tokenless, including the whole-file `hearth.yaml` rewrite (§4.23#1b · MEDIUM)
- [ ] 21.3 Require a CSRF token and the old password on `POST /required-action/UPDATE_PASSWORD` (§4.23#2 · MEDIUM)
- [ ] 21.4 Stop the double-submit CSRF token being forgeable by cookie-tossing; `cookie_value` returns the first `hearth_ui_csrf` in the header, so the check can compare an attacker-chosen value to itself (§4.23#3 · MEDIUM)
- [ ] 21.5 Stop the config editor's `visual/apply` returning `{"ok":true}` after a partial apply whose live reconcile archives every realm the operator did not re-list (§4.23#4 · MEDIUM)
- [ ] 21.6 Set `Secure` on `hearth_ui_sms_mfa` and `hearth_ui_flash` on every code path, as the session, CSRF and required-action cookies already do (§4.23#5 · MEDIUM)
- [ ] 21.7 Serve `/docs` Swagger UI from the same origin or with Subresource Integrity and a CSP; it is unauthenticated and shares the admin console's origin (§4.23#6 · MEDIUM)
- [ ] 21.8 Fix the `/ui` CSP that blocks Hearth's own SAML HTTP-POST binding — auto-submit by `script-src 'self'`, manual submit by `form-action 'self'` (§4.23#7 · MEDIUM)
- [ ] 21.9 Emit HSTS in the proxy-terminated-TLS deployment, or tell the proxy operator to set it; the hardening guide claims it is automatic "when TLS is enabled" (§4.23#8, §4.5 critic objection · CLAIM-DEFECT)
- [ ] 21.10 Add CSP, `X-Frame-Options` or `frame-ancestors`, and `Cache-Control` to browser-facing HTML on the API router (`GET /docs`, `GET /end_session`) (§4.23#9 · LOW)
- [ ] 21.11 Stop unauthenticated tenant enumeration; a real and a non-existent realm are distinguishable by status and body length across every `/ui/realms/{r}/*` pre-auth shape, with no rate limit on the oracle (§4.23#10 · LOW)
- [ ] 21.12 Stop unauthenticated SAML IdP metadata reflecting `X-Forwarded-Host` into `entityID` and the SSO/SLO endpoint URLs when `onboarding.base_url` is unset (§4.23#11 · LOW)
- [ ] 21.13 Validate content type and size on `/ui/static/theme.css`, which serves an operator-pointed file's raw bytes to unauthenticated clients (§4.23#12 · LOW)
- [ ] 21.14 Verify the `_csrf` field `POST /ui/federation/confirm-link` parses and ignores (§4.22#12 · LOW)

## 22. Wave 3 — Protocol surface hardening

- [ ] 22.1 Re-validate redirect URIs in `update_client`; the register-time scheme, fragment, wildcard and loopback allowlist is bypassable by register-then-PATCH (§4.3#3 · MEDIUM)
- [ ] 22.2 Bound the per-code and per-token advisory-lock maps, which grow without limit (§4.3#4 · LOW)
- [ ] 22.3 Stop the browser JAR authorize path redirecting to the unvalidated outer `redirect_uri` (embedded-only; dead code on every network-facing shape) (§4.3#5 · Informational)
- [ ] 22.4 Stop `mask_phone` byte-slicing an unvalidated phone number, reachable from any required-action session (§4.4#2 · MEDIUM)
- [ ] 22.5 Enforce `operational.request_timeout_secs`, `max_connections` and `queue_depth`, documented but never applied; a 38-second socket transcript ran against a configured 5-second timeout (§4.4#3 · MEDIUM)
- [ ] 22.6 Correct the README, which documents `PUT` for five admin mutation routes the server implements as `PATCH` and answers 405 on (§4.5#5 · CLAIM-DEFECT)
- [ ] 22.7 Apply the SSRF guard, a redirect limit and a timeout to federation JWKS, token and userinfo fetches (§4.6#2 · MEDIUM)
- [ ] 22.8 Apply the SSRF guard, a redirect limit and a timeout to the OIDC back-channel logout POST to a client-registered URL (§4.6#3 · MEDIUM)
- [ ] 22.9 Disclose the `link_existing_accounts: auto` account-takeover risk where the operator sets it (§4.6#4 · MEDIUM)
- [ ] 22.10 Add a timestamp and replay window to the webhook signature, and a global concurrency bound to deliveries (§4.6#5 · LOW)
- [ ] 22.11 Bound the two SAML key spaces that grow without limit, one written by an unauthenticated, unrate-limited GET (§4.10#9 · MEDIUM)
- [ ] 22.12 Read `security.http2.*` and apply the rapid-reset caps to the plaintext listener as well as the TLS one (§4.12#20 · MEDIUM)
- [ ] 22.13 Add a reclamation path to the `oauth:session_fam:` index and the `oauth:revjti:` blocklist (§4.16#13 · LOW)
- [ ] 22.14 Read `client_secret_basic` credentials on the `client_credentials` grant, which reads only the body while discovery and DCR instruct every client to use the header (§4.22#5 · MEDIUM)
- [ ] 22.15 Provide a surface that writes the `assertion_public_key` that `private_key_jwt` and the `jwt-bearer` grant read, or withdraw them and FAPI 2.0 Advanced from discovery (§4.22#7 · MEDIUM)
- [ ] 22.16 Send a realm-scoped federation `redirect_uri` upstream that matches the callback URL the admin UI publishes (§4.22#8 · MEDIUM)
- [ ] 22.17 Make `POST /realms/{realm}/register` issue a `client_id` the token endpoint can parse, and stop it silently dropping the requested grant types (§4.22#9 · MEDIUM)
- [ ] 22.18 Fix every link on the admin Identity Providers list, which emits the prefixed `idp_<uuid>` display form to a handler that parses a bare UUID and 404s (§4.22#10 · MEDIUM)
- [ ] 22.19 Resolve the realm the login started in on the federation confirm-to-link flow, which resolves the default realm (§4.22#11 · MEDIUM)
- [ ] 22.20 Check `azp` on upstream ID tokens with a multi-valued `aud`, per OIDC Core 3.1.3.7 (§4.22#13 · LOW)
- [ ] 22.21 Replicate provider-side `nonce` replay detection and stop sweeping the whole set under a global mutex on every `/authorize` (§4.22#14 · LOW)
- [ ] 22.22 Make the `apple` federation preset reach `AppleConnector` and accept the Apple signing key, or withdraw the preset; it is silently rewritten to a generic OIDC connector (§4.22#3 · CLAIM-DEFECT)
- [ ] 22.23 Make `callback_post` / `callback_scoped_post` succeed from a browser, or unroute them (§4.22#15 · Informational)
- [ ] 22.24 Consult `RegistrationPolicy` in `validate_magic_link`, which creates accounts without it (§4.24#11 · MEDIUM)
- [ ] 22.25 Run equivalent work for unregistered clients in client authentication, which runs Argon2id only for registered confidential clients and leaks client existence and type by timing (§4.25#3 · MEDIUM)
- [ ] 22.26 Draw device user codes without modulo bias (`byte % 28`), and add an attempt limit and request shaping to the approval endpoint (§4.25#4 · MEDIUM)
- [ ] 22.27 Raise PAR `request_uri`, consent tickets, federation confirm tickets, SAML `RelayState` and session IDs from 122 bits to the 128-bit floor RFC 9126 §7.1 makes normative (§4.25#5 · LOW)
- [ ] 22.28 Convert the nine secret-shaped `==` / `!=` comparisons to constant time; measured as not exploitable at realistic sample counts, so this is hygiene, not an open hole (§4.25#6 · LOW)

## 23. Wave 4 — Close the audit's own coverage gaps

- [ ] 23.1 Re-run P21, cluster-mode GA-readiness, to a passing critic: systematic cache enumeration, failover and split-brain test count, operator-documentation walkthrough (§7.2, §8.1 item 1)
- [ ] 23.2 Re-run P30, public claim verification and performance methodology; 413 distinct citation pairs resolved cleanly, and it failed on one non-reproducing repro and two false negative results (§7.2, §8.1 item 2)
- [ ] 23.3 Re-run P29, test-suite quality and the mutation spot-check; we cannot currently say whether this test suite can fail (§7.2, §8.1 item 3)
- [ ] 23.4 Re-run P28, the seven SDKs: produce the per-SDK verify-or-decode-and-trust matrix; an SDK that decodes without verifying would be a critical finding (§7.2, §8.1 item 4)
- [ ] 23.5 Re-run P20, backup round-trip and on-disk format versioning: round-trip diff, restore into a different version, truncated and corrupted backups (§7.2, §8.1 item 5)
- [ ] 23.6 Re-run P31, day-2 upgrade and the cold first-run; whether v1.6.x data can be read by the current build is unknown (§7.2, §8.1 item 6)
- [ ] 23.7 Re-run P11, device grant, DCR, introspection and permission modes; whether DCR is open to the internet by default is unanswered (§7.2, §8.1 item 7)
- [ ] 23.8 Audit LDAP beyond the surface §4.6 covered (§7.3)
- [ ] 23.9 Audit the gRPC management API beyond the `Decide` and admin paths §4.2 and §4.19 reached (§7.3)
- [ ] 23.10 Audit the organisations subsystem, never examined (§7.3)
- [ ] 23.11 Audit the agent-identity surface — DPoP, token exchange, MCP authorisation, approval lifecycle — beyond the token paths in §4.19 (§7.3)
- [ ] 23.12 Audit the email transports beyond the config and recovery paths (§7.3)
- [ ] 23.13 Audit the fuzz targets (§7.3)
- [ ] 23.14 Audit the load-test harness (§7.3)
- [ ] 23.15 Run the mutation spot-check against a green baseline — §8.3's highest-value action (§8.3)
- [ ] 23.16 Stand up a three-node cluster and enumerate every cache the state machine bypasses (§8.3)
- [ ] 23.17 Produce the per-SDK verify/decode matrix (§8.3)
- [ ] 23.18 Run one official conformance suite — OIDC, SCIM or SAML (§8.3)
- [ ] 23.19 Do the cold first-run with a transcript; the brief calls it "the single most informative hour in the whole audit" (§8.3)

## 24. Wave 4 — Systemic guards from the residual risk statement

- [ ] 24.1 Sweep for the class "operations that report success while not having succeeded": a restore that destroys a realm and exits 0, a CLI family emitting zero bytes, a config editor answering `{"ok":true}` after a partial apply, a release pipeline signing a failing build, a SAML consumer auditing a login that never happened, two admin actions reporting "Reset email sent" (§9 item 1)
- [ ] 24.2 Add a test that distinguishes `fsync`-before-ack from no `fsync` at all, and confirm it fails against the old code; the WAL's doc comment names a crash loop that does not exist (§4.11#11, §9 item 3 · CLAIM-DEFECT)
- [ ] 24.3 Add a mutation spot-check to CI: comment out a security-critical check and prove something goes red (§9 item 3)
- [ ] 24.4 Make the merge gate refuse a regression test committed red; two data-integrity regression tests were committed red and stayed red (§9 item 3)
- [ ] 24.5 Run a documentation-truth sweep driven by §6, which has more FALSE rows than TRUE, covering the README, `docs/STATUS.md` and the normative specs (§9 item 4)
- [ ] 24.6 Enumerate every security-relevant control the Raft state machine bypasses on a follower; two accepted pieces found four, including two kill-switches and key rotation, against a known-defects list naming two caches (§4.1 objection, §4.15#6, §4.16#5, §4.19#12, §9 item 5)
