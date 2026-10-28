#!/usr/bin/env python3
"""The restore drill (#651): restore a backup of a large realm and compare the two servers.

Usage:
  restore_drill.py seed     --target ENV --ca CRT --state DIR [--users N] [--batch N]
                            [--workers N] [--sample-every N]
  restore_drill.py snapshot --target ENV --ca CRT --state DIR --phase before|after --out FILE
  restore_drill.py backup   --target ENV --ca CRT --output FILE
  restore_drill.py compare  [--token-file FILE] [--restore-exit N] [--findings FILE]
                            [--require-webhooks] BEFORE AFTER
  restore_drill.py report   --steps FILE --facts FILE [--findings FILE] [--status TEXT]
                            --json FILE --markdown FILE

ENV is the generator.env that gen-config.sh writes, and CRT the run's CA. restore-drill.sh
runs the subcommands in this order:

1. seed: as the realm admin, import --users users through POST /admin/users/import, in
   requests of --batch users, --workers requests at a time. Then create known data through
   the admin API: 5 users (one of them updated), a role, an assignment of the role, an OAuth
   client with a secret, and a webhook subscription. The state dir (private) receives
   seed.json: the ids, the client's secret, and the sample: every --sample-every-th bulk
   user, the last one, the 5 users and the hearth.yaml seed users.
2. snapshot --phase before: what the server answers about that data (below).
3. backup: POST /admin/backup, streamed to a file.
4. hearth backup verify, sign and restore, and a server on the restored data
   (restore-drill.sh).
5. snapshot --phase after, then compare. The exit status is 0 when the servers agree, 1
   when they do not.
6. report: timings.json and a Markdown summary.

A snapshot holds, per section, {"ok": true, "value": ...} or {"ok": false, "error": ...}:
  admin         the realm id (the admin token's tid) and the admin's sub
  user_count    the realm's users: a binary search on the offset cursor of GET /admin/users
  users         GET /admin/users/{id} of each sampled user: every field that the API returns
  email_index   GET /admin/users?email= of each sampled user: the id that it finds
  known_users   a sign-in of the admin and of each seed user: the sub of the token
  jwks          GET /realms/{realm}/.well-known/jwks.json
  client        GET /admin/applications/{id}
  client_token  the status of client_credentials with the secret, and without it
  old_token     introspection of an access token that the client got before the backup
  role          GET /admin/roles/{id}
  assignments   GET /admin/users/{id}/roles of the user with the role
  webhooks      GET /admin/webhooks, with each secret replaced by its SHA-256

The pre-backup token stays in the state dir, not in a snapshot. compare verifies its EdDSA
signature with the JWKS of the restored server (with openssl), as a resource server
checks a token. The restored server must also call the token active, unless the token
expired before the check: a restore can take longer than the 1-hour token lifetime.

The admin API returns no custom attributes per user, so the drill does not compare them.

Only the standard library and the openssl command.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import http.cookiejar
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

API_USERS = 5
ROLE_NAME = "drill.reader"
ROLE_PERMISSIONS = ["drill.read", "user.read"]
CLIENT_NAME = "Restore drill service"
WEBHOOK_URL = "https://example.com/hearth-restore-drill"
# An event that the drill never causes, so the subscription sends nothing.
WEBHOOK_EVENT = "realm_deleted"
HTTP_TIMEOUT = 300
# The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410); the raw key follows it.
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
CSRF = re.compile(r'name="_csrf" value="([^"]*)"')

STEPS = [
    ("original_start_to_ready", "Start of the original server: until `/readyz` answers 200"),
    ("seed", "Seed: import and known data"),
    ("backup_create", "Backup: `POST /admin/backup`"),
    ("backup_verify", "Backup: `hearth backup verify`"),
    ("backup_sign", "Backup: `hearth backup sign`"),
    ("server_stop", "Stop of the original server"),
    ("restore", "Restore: `hearth backup restore`"),
    ("restored_start_to_ready", "Start on the restored data: until `/readyz` answers 200"),
]
INT_FACTS = {"users", "archive_bytes", "data_bytes_before", "data_bytes_after", "cpus",
             "memory_bytes", "restore_exit"}


class DrillError(Exception):
    """A step of the drill that did not work."""


def log(msg):
    print(f"restore_drill: {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------- data and comparison


def bulk_user(i, domain):
    """The import entry for bulk user i. Every 13th user is disabled and every 17th waits
    for verification (moduli prime to the sample stride, so the sample has each status)."""
    entry = {
        "email": f"bulk{i:07d}@{domain}",
        "display_name": f"Bulk {i}",
        "first_name": f"Given{i % 997}",
        "last_name": f"Family{i}",
        "attributes": {"drill_index": str(i)},
    }
    if i % 13 == 3:
        entry["status"] = "disabled"
    elif i % 17 == 5:
        entry["status"] = "pending_verification"
    return entry


def sample_indexes(users, every):
    """The bulk users that the drill compares in full: every every-th one, and the last."""
    if users <= 0:
        return []
    return sorted(set(range(0, users, max(1, every))) | {users - 1})


def count_by_probe(has_at):
    """The exact length n of a list, where has_at(k) is k < n: about 2 log2(n) probes."""
    if not has_at(0):
        return 0
    lo, hi = 0, 1  # an item at lo; none known at hi yet
    while has_at(hi):
        lo, hi = hi, hi * 2
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if has_at(mid):
            lo = mid
        else:
            hi = mid
    return lo + 1


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def jwt_claims(token):
    """The claims of a JWT, unverified."""
    return json.loads(b64url_decode(token.split(".")[1]))


def openssl_verify(public_key, data, signature):
    """Whether signature is an Ed25519 signature of data by the raw 32-byte public_key."""
    pem = ("-----BEGIN PUBLIC KEY-----\n"
           + base64.b64encode(ED25519_SPKI_PREFIX + public_key).decode()
           + "\n-----END PUBLIC KEY-----\n")
    with tempfile.TemporaryDirectory() as d:
        paths = {}
        for name, content in (("key.pem", pem.encode()), ("data", data), ("sig", signature)):
            paths[name] = os.path.join(d, name)
            with open(paths[name], "wb") as f:
                f.write(content)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                            paths["key.pem"], "-rawin", "-in", paths["data"],
                            "-sigfile", paths["sig"]], capture_output=True)
    return r.returncode == 0


def verify_jwt_signature(token, jwks, verify=None):
    """(True, why) when an EdDSA JWT verifies with the JWKS key of its kid, else (False, why)."""
    verify = verify or openssl_verify
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        return False, "not a JWT"
    try:
        header = json.loads(b64url_decode(parts[0]))
        signature = b64url_decode(parts[2])
    except ValueError as e:
        return False, f"not a JWT: {e}"
    if header.get("alg") != "EdDSA":
        return False, f"alg {header.get('alg')!r}, not EdDSA"
    kid = header.get("kid")
    keys = [k for k in (jwks or {}).get("keys", []) if k.get("kid") == kid]
    if not keys:
        return False, f"the JWKS has no key with kid {kid}"
    key = keys[0]
    if key.get("kty") != "OKP" or key.get("crv") != "Ed25519":
        return False, f"key {kid} is not an Ed25519 key"
    try:
        raw = b64url_decode(key.get("x", ""))
    except ValueError:
        raw = b""
    if len(raw) != 32:
        return False, f"key {kid} has no 32-byte x"
    if verify(raw, f"{parts[0]}.{parts[1]}".encode(), signature):
        return True, f"the signature verifies with key {kid}"
    return False, f"the signature does not verify with key {kid}"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def short(value, width=60):
    text = canonical(value)
    return text if len(text) <= width else text[:width - 3] + "..."


_MISSING = object()


def diff_fields(a, b):
    """The keys whose values differ, a key that only one side has included."""
    return sorted(k for k in set(a) | set(b) if a.get(k, _MISSING) != b.get(k, _MISSING))


def describe_diff(a, b):
    return "; ".join(f"{f}: {short(a.get(f))} -> {short(b.get(f))}" for f in diff_fields(a, b))


def iso(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "?"


def section(snap, name):
    """(value, None), or (None, why) when the snapshot has no answer."""
    s = (snap.get("sections") or {}).get(name)
    if s is None:
        return None, "missing"
    if not s.get("ok"):
        return None, s.get("error") or "failed"
    return s.get("value"), None


def pair(before, after, name):
    """(before value, after value, None), or (None, None, why) when a side has no answer."""
    b, why = section(before, name)
    if why:
        return None, None, f"before (the drill's baseline): {why}"
    a, why = section(after, name)
    if why:
        return None, None, f"after: {why}"
    return b, a, None


def finding(check, result, detail):
    return {"check": check, "result": result, "detail": detail}


def check_restore_exit(restore_exit):
    if restore_exit == 0:
        return finding("restore exit status", "PASS", "hearth backup restore exited 0")
    return finding("restore exit status", "FAIL",
                   f"hearth backup restore exited {restore_exit} (see restore.txt)")


def check_realm(before, after):
    name = "realm id"
    b, a, why = pair(before, after, "admin")
    if why:
        return finding(name, "FAIL", why)
    if b.get("realm_id") != a.get("realm_id"):
        return finding(name, "FAIL", f"before {b.get('realm_id')}, after {a.get('realm_id')}")
    return finding(name, "PASS", f"{b.get('realm_id')} before and after")


def check_user_count(before, after):
    name = "user count"
    b, a, why = pair(before, after, "user_count")
    if why:
        return finding(name, "FAIL", why)
    if not isinstance(b, int) or b <= 0:
        return finding(name, "FAIL", f"before (the drill's baseline): {b} users")
    if a != b:
        return finding(name, "FAIL", f"before {b}, after {a}")
    return finding(name, "PASS", f"{b} before and after")


def check_users(before, after):
    name = "sampled users"
    b, a, why = pair(before, after, "users")
    if why:
        return finding(name, "FAIL", why)
    if not b:
        return finding(name, "FAIL", "the drill sampled no user")
    unread = [uid for uid, r in b.items() if r.get("status") != 200]
    if unread:
        return finding(name, "FAIL", f"before (the drill's baseline): {len(unread)} sampled "
                                     f"users unreadable, e.g. {unread[0]}: {b[unread[0]]}")
    missing, unreadable, changed = [], [], {}
    for uid, rb in b.items():
        ra = a.get(uid) or {"status": 404}
        if ra.get("status") == 404:
            missing.append(uid)
        elif ra.get("status") != 200:
            unreadable.append((uid, ra))
        else:
            for field in diff_fields(rb["record"], ra["record"]):
                changed.setdefault(field, []).append(
                    (uid, rb["record"].get(field), ra["record"].get(field)))
    n = len(b)
    if not (missing or unreadable or changed):
        return finding(name, "PASS", f"{n} sampled users: every field equal")
    parts = []
    if missing:
        parts.append(f"{len(missing)} missing (e.g. {missing[0]})")
    if unreadable:
        uid, ra = unreadable[0]
        parts.append(f"{len(unreadable)} unreadable (e.g. {uid}: {ra.get('status')} "
                     f"{ra.get('error', '')})")
    for field in sorted(changed):
        uid, vb, va = changed[field][0]
        parts.append(f"{field} differs in {len(changed[field])} of {n} "
                     f"(e.g. {uid}: {short(vb)} -> {short(va)})")
    return finding(name, "FAIL", f"{n} sampled users: " + "; ".join(parts))


def check_email_index(before, after):
    name = "email index"
    b, a, why = pair(before, after, "email_index")
    if why:
        return finding(name, "FAIL", why)
    if not b:
        return finding(name, "FAIL", "the drill looked up no email")
    lost = [e for e, uid in b.items() if not uid]
    if lost:
        return finding(name, "FAIL", f"before (the drill's baseline): {len(lost)} emails find "
                                     f"no user, e.g. {lost[0]}")
    wrong = [e for e in b if a.get(e) != b[e]]
    if wrong:
        e = wrong[0]
        return finding(name, "FAIL", f"{len(wrong)} of {len(b)} emails find another user or "
                                     f"none, e.g. {e}: {b[e]} -> {a.get(e)}")
    return finding(name, "PASS", f"{len(b)} emails find the same user")


def check_known_users(before, after):
    name = "known users sign in"
    b, a, why = pair(before, after, "known_users")
    if why:
        return finding(name, "FAIL", why)
    if not b:
        return finding(name, "FAIL", "the drill signed in no known user")
    for email, r in b.items():
        if not r.get("ok"):
            return finding(name, "FAIL", f"before (the drill's baseline): {email} cannot sign "
                                         f"in: {r.get('error')}")
    bad = []
    for email, r in b.items():
        ra = a.get(email) or {"ok": False, "error": "not tried"}
        if not ra.get("ok"):
            bad.append(f"{email} cannot sign in ({ra.get('error')})")
        elif ra.get("sub") != r.get("sub"):
            bad.append(f"{email} signs in as another user: sub {r.get('sub')} -> "
                       f"{ra.get('sub')} (re-created from hearth.yaml?)")
    if bad:
        return finding(name, "FAIL", "; ".join(bad))
    return finding(name, "PASS", f"{len(b)} users sign in with their passwords, with the same "
                                 f"sub")


def jwks_keys(jwks):
    return sorted(canonical(k) for k in (jwks or {}).get("keys", []))


def check_jwks(before, after):
    name = "realm JWKS"
    b, a, why = pair(before, after, "jwks")
    if why:
        return finding(name, "FAIL", why)
    if not jwks_keys(b):
        return finding(name, "FAIL", "before (the drill's baseline): the JWKS has no key")
    kids_b = [k.get("kid") for k in b.get("keys", [])]
    if jwks_keys(b) != jwks_keys(a):
        kids_a = [k.get("kid") for k in (a or {}).get("keys", [])]
        return finding(name, "FAIL", f"the keys differ: before kid {kids_b}, after kid {kids_a}")
    return finding(name, "PASS", f"{len(kids_b)} key(s) equal, kid {kids_b}")


def check_token_signature(before, after, token, verify):
    name = "pre-backup token signature"
    if not token:
        return finding(name, "FAIL", "no pre-backup token: the before snapshot got none")
    b, why = section(before, "jwks")
    if why:
        return finding(name, "FAIL", f"before (the drill's baseline): {why}")
    good, why = verify_jwt_signature(token, b, verify)
    if not good:
        return finding(name, "FAIL", f"before (the drill's baseline): {why}")
    a, why = section(after, "jwks")
    if why:
        return finding(name, "FAIL", f"after: {why}")
    good, why = verify_jwt_signature(token, a, verify)
    return finding(name, "PASS" if good else "FAIL", f"with the restored JWKS: {why}")


def check_token_introspection(before, after, token):
    name = "pre-backup token introspection"
    b, a, why = pair(before, after, "old_token")
    if why:
        return finding(name, "FAIL", why)
    if not b.get("active"):
        return finding(name, "FAIL", "before (the drill's baseline): the original server calls "
                                     "the token inactive")
    if a.get("active"):
        return finding(name, "PASS", "the restored server calls the pre-backup token active")
    try:
        exp = jwt_claims(token).get("exp")
    except (AttributeError, IndexError, ValueError):
        exp = None
    checked = a.get("checked_at")
    if exp and checked and checked >= exp:
        return finding(name, "SKIPPED",
                       f"the token expired at {iso(exp)}, before the check at {iso(checked)}: "
                       "the drill took longer than the access-token lifetime. The signature "
                       "check covers the signing key")
    return finding(name, "FAIL", f"the restored server calls the token inactive at "
                                 f"{iso(checked)}, before it expires at {iso(exp)}")


def check_record(before, after, section_name, name):
    b, a, why = pair(before, after, section_name)
    if why:
        return finding(name, "FAIL", why)
    if not b:
        return finding(name, "FAIL", "before (the drill's baseline): no record")
    if canonical(a) != canonical(b):
        return finding(name, "FAIL", f"{', '.join(diff_fields(b, a or {}))} differ: "
                                     f"{describe_diff(b, a or {})}")
    return finding(name, "PASS", f"{b.get('client_id') or b.get('id')}: every field equal")


def check_client_credentials(before, after):
    name = "client credentials"
    b, a, why = pair(before, after, "client_token")
    if why:
        return finding(name, "FAIL", why)
    with_b, without_b = b.get("with_secret"), b.get("without_secret")
    if with_b != 200 or not isinstance(without_b, int) or not 400 <= without_b < 500:
        return finding(name, "FAIL", f"before (the drill's baseline): with the secret "
                                     f"{with_b}, without it {without_b}; want 200 and 4xx")
    if a.get("with_secret") != 200:
        return finding(name, "FAIL", f"the client's secret no longer works: client_credentials "
                                     f"answers {a.get('with_secret')}")
    if a.get("without_secret") != without_b:
        return finding(name, "FAIL", f"without its secret the client gets "
                                     f"{a.get('without_secret')}, before {without_b}: the "
                                     "restore weakened the client")
    return finding(name, "PASS", f"with the secret 200, without it {without_b}, as before")


def check_assignments(before, after):
    name = "role assignments"
    b, a, why = pair(before, after, "assignments")
    if why:
        return finding(name, "FAIL", why)
    if not b:
        return finding(name, "FAIL", "before (the drill's baseline): the user has no assignment")
    if sorted(map(canonical, b)) != sorted(map(canonical, a or [])):
        return finding(name, "FAIL", f"before {len(b)} assignment(s), after {len(a or [])}; "
                                     "they differ")
    return finding(name, "PASS", f"{len(b)} assignment(s) equal")


def check_webhooks(before, after, required):
    name = "webhook subscriptions"
    result = "FAIL" if required else "ADVISORY"
    note = "" if required else " (advisory until backups carry webhook subscriptions, #664)"
    b, a, why = pair(before, after, "webhooks")
    if why:
        return finding(name, result, why + note)
    if not b:
        return finding(name, result, "the drill created no webhook subscription" + note)
    if sorted(map(canonical, b)) != sorted(map(canonical, a or [])):
        return finding(name, result, f"before {len(b)} subscription(s), after {len(a or [])}; "
                                     "they differ" + note)
    return finding(name, "PASS", f"{len(b)} subscription(s) equal")


def compare(before, after, *, token, restore_exit, require_webhooks=False, verify=None):
    """The findings of a before/after comparison: {check, result, detail} each. A result is
    PASS, FAIL, SKIPPED (could not be checked, see detail) or ADVISORY (does not fail)."""
    findings = []
    if restore_exit is not None:
        findings.append(check_restore_exit(restore_exit))
    findings += [
        check_realm(before, after),
        check_user_count(before, after),
        check_users(before, after),
        check_email_index(before, after),
        check_known_users(before, after),
        check_jwks(before, after),
        check_token_signature(before, after, token, verify),
        check_token_introspection(before, after, token),
        check_record(before, after, "client", "client record"),
        check_client_credentials(before, after),
        check_record(before, after, "role", "role"),
        check_assignments(before, after),
        check_webhooks(before, after, require_webhooks),
    ]
    return findings


def verdict(findings):
    """FAIL when a finding failed, else PASS."""
    return "FAIL" if any(f["result"] == "FAIL" for f in findings) else "PASS"


# ---------------------------------------------------------------- report


def read_pairs(path):
    """{key: rest of line} from "key value" lines; {} when the file does not exist."""
    out = {}
    try:
        with open(path) as f:
            for line in f:
                key, _, value = line.strip().partition(" ")
                if key:
                    out[key] = value.strip()
    except FileNotFoundError:
        pass
    return out


def fmt_duration(seconds):
    if seconds is None:
        return "n/a"
    if seconds < 60:
        return f"{seconds:.1f} s"
    r = int(round(seconds))
    if r < 3600:
        return f"{r // 60} min {r % 60:02d} s"
    return f"{r // 3600} h {(r % 3600) // 60:02d} min"


def fmt_bytes(n):
    if n is None:
        return "n/a"
    if n >= 2**30:
        return f"{n / 2**30:.2f} GiB"
    return f"{n / 2**20:.1f} MiB"


def build_timings(steps, facts, findings, status):
    seconds = {k: float(v) for k, v in steps.items()}
    values = {}
    for k, v in facts.items():
        try:
            values[k] = int(v) if k in INT_FACTS else v
        except ValueError:
            values[k] = v
    recovery = None
    if "restore" in seconds and "restored_start_to_ready" in seconds:
        recovery = seconds["restore"] + seconds["restored_start_to_ready"]
    return {
        "status": status,
        "users": values.get("users"),
        "archive_bytes": values.get("archive_bytes"),
        "data_bytes_before": values.get("data_bytes_before"),
        "data_bytes_after": values.get("data_bytes_after"),
        "seconds": seconds,
        "recovery_seconds": recovery,
        "run": {k: values.get(k) for k in ("date", "hearth_version", "commit", "cpus",
                                            "memory_bytes", "restore_exit")},
        "findings": findings,
    }


def render_markdown(t):
    run = t["run"]
    lines = [f"## Restore drill: {t['status']}", ""]
    about = []
    if t["users"] is not None:
        about.append(f"{t['users']:,} users imported into one realm.")
    if run.get("hearth_version"):
        about.append(f"{run['hearth_version']}, commit {run.get('commit') or '?'}.")
    if run.get("cpus"):
        about.append(f"Runner: {run['cpus']} CPUs, {fmt_bytes(run.get('memory_bytes'))} "
                     "memory.")
    if run.get("date"):
        about.append(f"Started {run['date']}.")
    if about:
        lines += [" ".join(about), ""]
    lines += ["| Step | Time |", "|---|---|"]
    for key, label in STEPS:
        if key in t["seconds"]:
            lines.append(f"| {label} | {fmt_duration(t['seconds'][key])} |")
    if t["recovery_seconds"] is not None:
        lines.append(f"| **Recovery: restore and start** | "
                     f"**{fmt_duration(t['recovery_seconds'])}** |")
    lines += ["", "| Size | |", "|---|---|",
              f"| Archive (`POST /admin/backup`) | {fmt_bytes(t['archive_bytes'])} |",
              f"| Data directory before the backup | {fmt_bytes(t['data_bytes_before'])} |",
              f"| Data directory after the restore | {fmt_bytes(t['data_bytes_after'])} |"]
    if t["findings"]:
        lines += ["", "### Checks", "", "| Check | Result | Detail |", "|---|---|---|"]
        for f in t["findings"]:
            detail = f["detail"].replace("|", "\\|")
            lines.append(f"| {f['check']} | {f['result']} | {detail} |")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- the server


class Target:
    """The server under test, from gen-config.sh's generator.env."""

    def __init__(self, env_path, ca):
        env = read_env(env_path)
        self.base = env["STRESS_BASE"]
        self.host = env["STRESS_HOST"]
        self.ip = env["STRESS_SERVER_IP"]
        self.realm = env["STRESS_REALM"]
        self.redirect_uri = env["STRESS_REDIRECT_URI"]
        self.app_client_id = env["STRESS_APP_CLIENT_ID"]
        self.admin = (env["STRESS_ADMIN_EMAIL"], env["STRESS_ADMIN_PASSWORD"])
        self.users = [(f"user{i:06d}@{self.host}", env["STRESS_USER_PASSWORD"])
                      for i in range(1, int(env["STRESS_LOGIN_USERS"]) + 1)]
        self.context = ssl.create_default_context(cafile=ca)
        # Python 3.13 checks X.509 strictly by default, and the run's CA (gen-config.sh) has
        # no key-usage extension. The chain and the host name are still checked.
        self.context.verify_flags &= ~ssl.VERIFY_X509_STRICT

    def known_users(self):
        """The admin and the hearth.yaml seed users, with their passwords."""
        return [self.admin, *self.users]


def read_env(path):
    env = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env[key] = value
    return env


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The sign-in reads each redirect itself."""

    def redirect_request(self, *args, **kwargs):
        return None


def _https_handler(ip, context):
    """HTTPS to ip, with the URL's host name for SNI and the certificate check, like curl
    --resolve: the server's name is not in DNS."""

    class Connection(http.client.HTTPSConnection):
        def connect(self):
            sock = socket.create_connection((ip, self.port), self.timeout)
            self.sock = context.wrap_socket(sock, server_hostname=self.host)

    class Handler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Connection, req, context=context)

    return Handler(context=context)


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    def json(self):
        return json.loads(self.body or b"null")

    def excerpt(self):
        return self.body[:300].decode("utf-8", "replace")


def request(target, method, url, *, form=None, json_body=None, headers=None, jar=None,
            timeout=HTTP_TIMEOUT, out=None):
    """One request, without following redirects. out: a file that receives a 200 body."""
    if url.startswith("/"):
        url = target.base + url
    data = None
    hdrs = {"User-Agent": "hearth-restore-drill"}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        data = json.dumps(json_body).encode()
        hdrs["Content-Type"] = "application/json"
    hdrs.update(headers or {})
    handlers = [_https_handler(target.ip, target.context), _NoRedirect()]
    if jar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    with resp:
        status = resp.getcode()
        if out is not None and status == 200:
            shutil.copyfileobj(resp, out, 1 << 20)
            body = b""
        else:
            body = resp.read()
        return Response(status, resp.headers, body)


def expect(resp, status, what):
    if resp.status != status:
        raise DrillError(f"{what}: {resp.status} {resp.excerpt()}")
    return resp


class SignInError(DrillError):
    def __init__(self, step, status):
        super().__init__(f"{step}: {status}")
        self.status = status


def sign_in(target, email, password):
    """An access token for email: the login form, then the code flow with PKCE (Hearth has
    no password grant). A server that sheds the password check (503, 429) gets retries."""
    deadline = time.monotonic() + 120
    while True:
        try:
            return _sign_in_once(target, email, password)
        except SignInError as e:
            if e.status not in (429, 503) or time.monotonic() > deadline:
                raise
            time.sleep(2)


def _sign_in_once(target, email, password):
    jar = http.cookiejar.CookieJar()
    login = f"/ui/realms/{target.realm}/login"
    page = request(target, "GET", login, jar=jar)
    if page.status != 200:
        raise SignInError("login_page", page.status)
    m = CSRF.search(page.body.decode("utf-8", "replace"))
    posted = request(target, "POST", login, jar=jar, form={
        "_csrf": m.group(1) if m else "", "email": email, "password": password})
    # A sign-in that worked answers a continue page: 200 with "Refresh: 0;url=...".
    if posted.status != 200 or not posted.headers.get("Refresh", "").startswith("0;url="):
        raise SignInError("login_submit", posted.status)
    verifier = b64url(os.urandom(32))
    state = b64url(os.urandom(12))
    query = urllib.parse.urlencode({
        "response_type": "code", "client_id": target.app_client_id,
        "redirect_uri": target.redirect_uri, "state": state, "scope": "openid",
        "code_challenge": b64url(hashlib.sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256"})
    authz = request(target, "GET", f"/ui/realms/{target.realm}/oauth/authorize?{query}",
                    jar=jar)
    params = urllib.parse.parse_qs(urllib.parse.urlsplit(authz.headers.get("Location", "")).query)
    code = (params.get("code") or [None])[0]
    if authz.status != 303 or not code or (params.get("state") or [None])[0] != state:
        raise SignInError("authorize", authz.status)
    token = request(target, "POST", f"/realms/{target.realm}/token", form={
        "grant_type": "authorization_code", "code": code, "redirect_uri": target.redirect_uri,
        "client_id": target.app_client_id, "code_verifier": verifier})
    if token.status != 200:
        raise SignInError("code_exchange", token.status)
    return token.json()["access_token"]


class Admin:
    """The realm admin. A new sign-in replaces a token that has less than 5 minutes left."""

    def __init__(self, target):
        self.target = target
        self._lock = threading.Lock()
        self._sign_in()

    def _sign_in(self):
        self.token = sign_in(self.target, *self.target.admin)
        claims = jwt_claims(self.token)
        self.exp = claims.get("exp", 0)
        self.sub = claims.get("sub")
        self.realm_id = claims["tid"].removeprefix("realm_")

    def headers(self):
        with self._lock:
            if self.exp - time.time() < 300:
                self._sign_in()
            return {"Authorization": f"Bearer {self.token}", "X-Realm-ID": self.realm_id}

    def call(self, method, path, json_body=None, *, timeout=HTTP_TIMEOUT, out=None):
        # 503 (user_create_overloaded) and 429 come before any work (#446): retry them.
        deadline = time.monotonic() + 600
        while True:
            r = request(self.target, method, path, json_body=json_body, headers=self.headers(),
                        timeout=timeout, out=out)
            if r.status not in (429, 503) or time.monotonic() > deadline:
                return r
            try:
                wait = min(30, max(1, int(r.headers.get("Retry-After", "1"))))
            except ValueError:
                wait = 1
            time.sleep(wait)

    def get(self, path, what):
        return expect(self.call("GET", path), 200, what).json()


def write_private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, indent=1)


def load_json(path):
    with open(path) as f:
        return json.load(f)


def user_id_by_email(admin, email):
    found = admin.get(f"/admin/users?email={urllib.parse.quote(email, safe='')}",
                      f"GET /admin/users?email={email}")
    items = found.get("items") or []
    return items[0]["id"] if items else None


def cmd_seed(args):
    target = Target(args.target, args.ca)
    os.makedirs(args.state, mode=0o700, exist_ok=True)
    admin = Admin(target)
    sample_at = set(sample_indexes(args.users, args.sample_every))

    def import_batch(start):
        entries = [bulk_user(i, target.host)
                   for i in range(start, min(start + args.batch, args.users))]
        r = expect(admin.call("POST", "/admin/users/import", {"users": entries}), 200,
                   f"import of users {start}..")
        body = r.json()
        if body.get("imported") != len(entries):
            bad = next((x for x in body.get("results", []) if x.get("error")), {})
            raise DrillError(f"import of users {start}..{start + len(entries) - 1}: "
                             f"{body.get('failed')} failed, e.g. {bad.get('email')}: "
                             f"{bad.get('error')}")
        return [[x["email"], x["id"]] for i, x in enumerate(body["results"], start)
                if i in sample_at]

    started = time.monotonic()
    sample = []
    batches = list(range(0, args.users, args.batch))
    pool = concurrent.futures.ThreadPoolExecutor(args.workers)
    try:
        futures = [pool.submit(import_batch, start) for start in batches]
        for n, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            sample.extend(fut.result())
            if n % max(1, len(batches) // 10) == 0 or n == len(batches):
                log(f"imported {n}/{len(batches)} batches in {time.monotonic() - started:.0f} s")
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    import_s = time.monotonic() - started

    api_users = []
    for k in range(1, API_USERS + 1):
        email = f"api{k}@{target.host}"
        r = expect(admin.call("POST", "/admin/users", {
            "email": email, "display_name": f"API user {k}", "first_name": "Api",
            "last_name": f"User{k}", "attributes": {"drill_kind": "api"}}), 201,
            "POST /admin/users")
        api_users.append([email, r.json()["id"]])
    # One update, so that updated_at differs from created_at.
    expect(admin.call("PATCH", f"/admin/users/{api_users[0][1]}",
                      {"display_name": "API user 1, renamed"}), 200, "PATCH /admin/users")
    seed_users = []
    for email, _ in target.known_users():
        uid = user_id_by_email(admin, email)
        if not uid:
            raise DrillError(f"the seed user {email} does not exist")
        seed_users.append([email, uid])

    role = expect(admin.call("POST", "/admin/roles", {
        "name": ROLE_NAME, "description": "Restore drill role",
        "permissions": ROLE_PERMISSIONS}), 201, "POST /admin/roles").json()
    role_user = api_users[1][1]
    expect(admin.call("POST", f"/admin/users/{role_user}/roles", {"role_id": role["id"]}), 201,
           "POST /admin/users/{id}/roles")
    client = expect(admin.call("POST", "/admin/applications", {
        "client_name": CLIENT_NAME, "redirect_uris": [f"https://drill.{target.host}/cb"],
        "grant_types": ["client_credentials"], "trust_level": "CLIENT_TRUST_LEVEL_FIRST_PARTY",
        "token_endpoint_auth_method": "client_secret_basic"}), 201,
        "POST /admin/applications").json()
    webhook = admin.call("POST", "/admin/webhooks", {
        "url": WEBHOOK_URL, "secret": secrets.token_urlsafe(24), "enabled": True,
        "event_filters": [WEBHOOK_EVENT]})
    webhook_error = None
    if webhook.status != 201:
        webhook_error = f"POST /admin/webhooks: {webhook.status} {webhook.excerpt()}"
        log(f"no webhook subscription: {webhook_error}")

    write_private_json(os.path.join(args.state, "seed.json"), {
        "users": args.users, "import_seconds": round(import_s, 3),
        "realm_id": admin.realm_id,
        "sample": sorted(sample) + api_users + seed_users,
        "client": {"id": client["client_id"], "secret": client["client_secret"]},
        "role_id": role["id"], "role_user_id": role_user, "webhook_error": webhook_error,
    })
    log(f"seeded {args.users} users in {import_s:.1f} s, sample of "
        f"{len(sample) + len(api_users) + len(seed_users)}")
    return 0


def basic_auth(client):
    raw = f"{client['id']}:{client['secret']}".encode()
    return {"Authorization": "Basic " + base64.b64encode(raw).decode()}


def read_users(admin, sample):
    def one(uid):
        r = admin.call("GET", f"/admin/users/{uid}")
        if r.status == 200:
            return uid, {"status": 200, "record": r.json()}
        if r.status == 404:
            return uid, {"status": 404}
        return uid, {"status": r.status, "error": r.excerpt()}

    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        return dict(pool.map(one, [uid for _, uid in sample]))


def read_email_index(admin, sample):
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        ids = pool.map(lambda e: user_id_by_email(admin, e), [e for e, _ in sample])
        return dict(zip([e for e, _ in sample], ids))


def count_users(admin):
    def has_at(offset):
        page = admin.get(f"/admin/users?limit=1&cursor={offset}", "GET /admin/users")
        return bool(page.get("items"))

    return count_by_probe(has_at)


def sign_in_known_users(target):
    out = {}
    for email, password in target.known_users():
        try:
            out[email] = {"ok": True, "sub": jwt_claims(sign_in(target, email, password))["sub"]}
        except (DrillError, OSError, KeyError, ValueError) as e:
            out[email] = {"ok": False, "error": str(e)}
    return out


def client_token_statuses(target, client):
    url = f"/realms/{target.realm}/token"
    with_secret = request(target, "POST", url, form={"grant_type": "client_credentials"},
                          headers=basic_auth(client))
    without = request(target, "POST", url, form={"grant_type": "client_credentials",
                                                 "client_id": client["id"]})
    return {"with_secret": with_secret.status, "without_secret": without.status}


def old_token(target, client, state, phase):
    """Before: a client_credentials token, kept in the state dir. Both phases: whether the
    server's introspection calls it active."""
    path = os.path.join(state, "token.json")
    if phase == "before":
        r = expect(request(target, "POST", f"/realms/{target.realm}/token",
                           form={"grant_type": "client_credentials"},
                           headers=basic_auth(client)), 200, "client_credentials")
        write_private_json(path, {"access_token": r.json()["access_token"]})
    token = load_json(path)["access_token"]
    r = expect(request(target, "POST", f"/realms/{target.realm}/introspect",
                       form={"token": token}, headers=basic_auth(client)), 200, "introspect")
    return {"active": bool(r.json().get("active")), "checked_at": time.time()}


def read_webhooks(admin):
    subs = admin.get("/admin/webhooks", "GET /admin/webhooks").get("webhooks") or []
    out = []
    for s in subs:
        s = dict(s)
        secret = s.pop("secret", None)
        if secret is not None:
            s["secret_sha256"] = hashlib.sha256(str(secret).encode()).hexdigest()
        out.append(s)
    return sorted(out, key=canonical)


def cmd_snapshot(args):
    target = Target(args.target, args.ca)
    seed = load_json(os.path.join(args.state, "seed.json"))
    snap = {"phase": args.phase, "taken_at": time.time(), "sections": {}}
    sections = snap["sections"]

    def take(name, fn):
        started = time.monotonic()
        try:
            sections[name] = {"ok": True, "value": fn()}
        except Exception as e:  # every failure is a finding, not a crash
            sections[name] = {"ok": False, "error": f"{type(e).__name__}: {e}"[:500]}
        log(f"{args.phase}: {name} in {time.monotonic() - started:.1f} s")

    try:
        admin = Admin(target)
    except (DrillError, OSError, KeyError, ValueError) as e:
        sections["admin"] = {"ok": False, "error": f"the admin cannot sign in: {e}"}
        write_private_json(args.out, snap)
        return 0
    sections["admin"] = {"ok": True, "value": {"realm_id": admin.realm_id, "sub": admin.sub}}
    client = seed["client"]
    # Sign-ins before the reads on the original server and after them on the restored one,
    # so that no sign-in changes what the other phase reads.
    if args.phase == "before":
        take("known_users", lambda: sign_in_known_users(target))
    take("users", lambda: read_users(admin, seed["sample"]))
    take("email_index", lambda: read_email_index(admin, seed["sample"]))
    take("user_count", lambda: count_users(admin))
    if args.phase == "after":
        take("known_users", lambda: sign_in_known_users(target))
    take("jwks", lambda: expect(request(target, "GET",
                                        f"/realms/{target.realm}/.well-known/jwks.json"),
                                200, "GET jwks.json").json())
    take("client", lambda: admin.get(f"/admin/applications/{client['id']}", "GET client"))
    take("client_token", lambda: client_token_statuses(target, client))
    take("old_token", lambda: old_token(target, client, args.state, args.phase))
    take("role", lambda: admin.get(f"/admin/roles/{seed['role_id']}", "GET role"))
    take("assignments", lambda: admin.get(f"/admin/users/{seed['role_user_id']}/roles",
                                          "GET assignments").get("items"))
    take("webhooks", lambda: read_webhooks(admin))
    write_private_json(args.out, snap)
    return 0


def cmd_backup(args):
    target = Target(args.target, args.ca)
    admin = Admin(target)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        # The server builds the whole archive before it answers.
        r = admin.call("POST", "/admin/backup", timeout=3 * 3600, out=f)
    if r.status != 200:
        raise DrillError(f"POST /admin/backup: {r.status} {r.excerpt()}")
    log(f"archive: {os.path.getsize(args.output)} bytes")
    return 0


def cmd_compare(args):
    before, after = load_json(args.before), load_json(args.after)
    token = None
    if args.token_file and os.path.exists(args.token_file):
        token = load_json(args.token_file).get("access_token")
    findings = compare(before, after, token=token, restore_exit=args.restore_exit,
                       require_webhooks=args.require_webhooks)
    if args.findings:
        with open(args.findings, "w") as f:
            json.dump(findings, f, indent=1)
    for f in findings:
        print(f"{f['result']:8} {f['check']}: {f['detail']}")
    v = verdict(findings)
    print(f"VERDICT: {v}")
    return 0 if v == "PASS" else 1


def cmd_report(args):
    findings = load_json(args.findings) if args.findings and os.path.exists(args.findings) \
        else []
    status = args.status or (verdict(findings) if findings else "DID NOT FINISH")
    t = build_timings(read_pairs(args.steps), read_pairs(args.facts), findings, status)
    with open(args.json, "w") as f:
        json.dump(t, f, indent=1)
    with open(args.markdown, "w") as f:
        f.write(render_markdown(t))
    return 0


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def server_args(sp):
        sp.add_argument("--target", required=True, help="gen-config.sh's generator.env")
        sp.add_argument("--ca", required=True, help="the run's CA certificate")

    sp = sub.add_parser("seed")
    server_args(sp)
    sp.add_argument("--state", required=True)
    sp.add_argument("--users", type=int, default=1_000_000)
    sp.add_argument("--batch", type=int, default=5000)
    sp.add_argument("--workers", type=int, default=4)
    sp.add_argument("--sample-every", type=int, default=1000)
    sp.set_defaults(fn=cmd_seed)

    sp = sub.add_parser("snapshot")
    server_args(sp)
    sp.add_argument("--state", required=True)
    sp.add_argument("--phase", choices=("before", "after"), required=True)
    sp.add_argument("--out", required=True)
    sp.set_defaults(fn=cmd_snapshot)

    sp = sub.add_parser("backup")
    server_args(sp)
    sp.add_argument("--output", required=True)
    sp.set_defaults(fn=cmd_backup)

    sp = sub.add_parser("compare")
    sp.add_argument("--token-file")
    sp.add_argument("--restore-exit", type=int)
    sp.add_argument("--findings")
    sp.add_argument("--require-webhooks", action="store_true")
    sp.add_argument("before")
    sp.add_argument("after")
    sp.set_defaults(fn=cmd_compare)

    sp = sub.add_parser("report")
    sp.add_argument("--steps", required=True)
    sp.add_argument("--facts", required=True)
    sp.add_argument("--findings")
    sp.add_argument("--status")
    sp.add_argument("--json", required=True)
    sp.add_argument("--markdown", required=True)
    sp.set_defaults(fn=cmd_report)
    return p.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    try:
        return args.fn(args)
    except (DrillError, OSError, KeyError, ValueError) as e:
        log(f"FAILED: {type(e).__name__}: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
