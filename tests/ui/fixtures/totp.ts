import * as crypto from 'crypto';

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

const lastStep = new Map<string, number>();

/**
 * A TOTP code the server has not seen yet for `secretBase32`. The server
 * refuses a code from a 30 s step it already accepted (replay protection), and
 * bootstrap spends the current step when it activates the factor. So the first
 * code is the NEXT step's (accepted inside the ±1-step window), and each later
 * call moves one step on, waiting for the clock when it must.
 */
export async function nextTotp(secretBase32: string): Promise<string> {
  const now = () => Math.floor(Date.now() / 1000 / 30);
  const step = Math.max((lastStep.get(secretBase32) ?? now()) + 1, now());
  while (step > now() + 1) {
    await new Promise((r) => setTimeout(r, 1_000));
  }
  lastStep.set(secretBase32, step);
  return computeTotp(secretBase32, step * 30);
}

/** Records that the code for the current step was used (a fresh enrolment). */
export function markTotpUsed(secretBase32: string): void {
  lastStep.set(secretBase32, Math.floor(Date.now() / 1000 / 30));
}
