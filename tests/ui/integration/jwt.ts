/** Minimal JWT decode helpers for assertions (no verification — tests only). */

function decodeSegment(segment: string): Record<string, unknown> {
  const b64 = segment.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  return JSON.parse(Buffer.from(b64 + pad, 'base64').toString('utf8')) as Record<string, unknown>;
}

/** Decodes the JWT payload (claims). */
export function decodeClaims(token: string): Record<string, unknown> {
  return decodeSegment(token.split('.')[1] ?? '');
}

/** Decodes the JWT header — used to read the signing `kid` for rotation tests. */
export function decodeHeader(token: string): Record<string, unknown> {
  return decodeSegment(token.split('.')[0] ?? '');
}
