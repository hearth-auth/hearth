import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

/**
 * RFC 6238 TOTP (HMAC-SHA1, 30 s step, 6 digits) for the fixtures that sign
 * the dev admins in. Every realm requires MFA by default (scope-trim-trusted-
 * core, spec `mfa-policy`), so a password alone no longer opens a session.
 */
export function base32Decode(s: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = s.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) throw new Error(`Invalid base32 char: ${ch}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** The TOTP code for `secretBase32` at `unixSec` (default: now). */
export function computeTotp(secretBase32: string, unixSec = Math.floor(Date.now() / 1000)): string {
  const key = base32Decode(secretBase32);
  const counter = Math.floor(unixSec / 30);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (code % 1_000_000).toString().padStart(6, '0');
}

// The last TOTP step spent per secret, shared by every Playwright process.
// Global setup and each worker are separate processes: an in-memory map let
// two of them send the same code in one 30 s window, and the server refused
// the second as a replay (login_flow.spec.ts failed on main and on PRs).
const STEPS_FILE = path.join(__dirname, '..', '.auth', 'totp-steps.json');
const LOCK_DIR = `${STEPS_FILE}.lock`;

const nowStep = () => Math.floor(Date.now() / 1000 / 30);

/** Runs `update` on the shared step table under a cross-process lock. */
function withSteps<T>(update: (steps: Record<string, number>) => T): T {
  fs.mkdirSync(path.dirname(STEPS_FILE), { recursive: true });
  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      fs.mkdirSync(LOCK_DIR); // atomic: exactly one process creates it
      break;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'EEXIST') throw e;
      if (Date.now() > deadline) {
        fs.rmSync(LOCK_DIR, { recursive: true, force: true }); // a crashed holder
        continue;
      }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
    }
  }
  try {
    const steps: Record<string, number> = fs.existsSync(STEPS_FILE)
      ? JSON.parse(fs.readFileSync(STEPS_FILE, 'utf-8'))
      : {};
    const result = update(steps);
    fs.writeFileSync(STEPS_FILE, JSON.stringify(steps));
    return result;
  } finally {
    fs.rmSync(LOCK_DIR, { recursive: true, force: true });
  }
}

/**
 * A TOTP code the server has not seen yet for `secretBase32`. The server
 * refuses a code from a 30 s step it already accepted (replay protection), and
 * bootstrap spends the current step when it activates the factor. So the first
 * code is the NEXT step's (accepted inside the ±1-step window), and each later
 * call, in any process, moves one step on, waiting for the clock when it must.
 */
export async function nextTotp(secretBase32: string): Promise<string> {
  const step = withSteps((steps) => {
    const next = Math.max((steps[secretBase32] ?? nowStep()) + 1, nowStep());
    steps[secretBase32] = next;
    return next;
  });
  while (step > nowStep() + 1) {
    await new Promise((r) => setTimeout(r, 1_000));
  }
  return computeTotp(secretBase32, step * 30);
}

/** Records that the code for the current step was used (a fresh enrolment). */
export function markTotpUsed(secretBase32: string): void {
  withSteps((steps) => {
    steps[secretBase32] = Math.max(steps[secretBase32] ?? 0, nowStep());
  });
}
