import { RealmResolutionError } from "./errors.js";

/** Regex for RFC 4122 UUID (any version). */
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Returns true when `value` is a well-formed UUID string. */
export function looksLikeUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/** Resolved realm identity — both UUID and slug are known. */
export interface ResolvedRealm {
  /** Canonical UUID used for `X-Realm-ID` headers and admin API paths. */
  id: string;
  /** Human-readable slug used in OIDC URL paths. */
  slug: string;
}

/**
 * Wire shape returned by `GET /v1/realms/{slugOrId}`.
 * The server must supply at minimum `id` and `slug`.
 */
interface RealmDocument {
  id: string;
  slug: string;
  [key: string]: unknown;
}

/**
 * Module-level in-memory cache.
 *
 * Key: `${baseUrl}\0${slugOrId}` — separated by NUL so a malicious realm
 * name cannot collide with a different baseUrl.
 *
 * Realm UUID↔slug mappings are immutable after creation, so no TTL is needed.
 * Entries are stored under both the input key and both canonical keys so the
 * resolver short-circuits on any subsequent lookup regardless of input form.
 */
const _cache = new Map<string, ResolvedRealm>();

/** Visible for tests — clears the resolution cache. */
export function _clearRealmCache(): void {
  _cache.clear();
}

async function fetchRealmDocument(
  baseUrl: string,
  slugOrId: string,
  httpTimeout: number,
): Promise<ResolvedRealm> {
  const url = `${baseUrl}/v1/realms/${encodeURIComponent(slugOrId)}`;
  let resp: Response;
  try {
    resp = await fetch(url, { signal: AbortSignal.timeout(httpTimeout) });
  } catch (err) {
    throw new RealmResolutionError(
      `Realm resolution endpoint unreachable: ${url}`,
      { cause: err },
    );
  }

  if (!resp.ok) {
    throw new RealmResolutionError(
      `Realm resolution returned HTTP ${resp.status} for realm "${slugOrId}"`,
    );
  }

  let doc: RealmDocument;
  try {
    doc = (await resp.json()) as RealmDocument;
  } catch (err) {
    throw new RealmResolutionError(`Realm resolution returned invalid JSON`, {
      cause: err,
    });
  }

  if (!doc.id || !doc.slug) {
    throw new RealmResolutionError(
      `Realm resolution response is missing required fields (id, slug) for realm "${slugOrId}"`,
    );
  }

  return { id: doc.id, slug: doc.slug };
}

/**
 * Resolves a realm slug or UUID to a {@link ResolvedRealm} containing both
 * forms.
 *
 * **Fast path:** when `slugOrId` is already a UUID _and_ `requireSlug` is
 * false, the function returns without a network call.
 *
 * **Resolution:** calls `GET {baseUrl}/v1/realms/{slugOrId}` which is a
 * public (unauthenticated) endpoint that returns the canonical realm document.
 *
 * Results are cached in a module-level map for the process lifetime. Realm
 * identity is immutable once created, so no TTL is required.
 *
 * @param baseUrl     Root URL of the Hearth instance (no trailing slash).
 * @param slugOrId    Either a realm UUID or a human-readable slug.
 * @param httpTimeout Timeout for the resolution request in milliseconds.
 * @param requireSlug When true, always resolve to obtain the slug even if the
 *                    input is already a UUID.
 */
export async function resolveRealm(
  baseUrl: string,
  slugOrId: string,
  httpTimeout: number,
  requireSlug = false,
): Promise<ResolvedRealm> {
  // Fast path: UUID input and slug not required — skip network call.
  if (looksLikeUuid(slugOrId) && !requireSlug) {
    // We have a UUID but no slug. Return a synthetic entry; slug will be
    // fetched on demand if/when it is ever needed.
    return { id: slugOrId, slug: slugOrId };
  }

  const cacheKey = `${baseUrl}\0${slugOrId}`;
  const cached = _cache.get(cacheKey);
  if (cached) return cached;

  const resolved = await fetchRealmDocument(baseUrl, slugOrId, httpTimeout);

  // Populate cache for all three keys to avoid duplicate fetches.
  _cache.set(cacheKey, resolved);
  _cache.set(`${baseUrl}\0${resolved.id}`, resolved);
  _cache.set(`${baseUrl}\0${resolved.slug}`, resolved);

  return resolved;
}

/**
 * Resolves the UUID for a realm from an opaque `realm` config value (slug or
 * UUID string).
 *
 * When the input is already a UUID the function returns it immediately without
 * a network round-trip. When the input is a slug, it calls
 * {@link resolveRealm} to fetch and cache the mapping.
 */
export async function resolveRealmId(
  baseUrl: string,
  slugOrId: string,
  httpTimeout: number,
): Promise<string> {
  if (looksLikeUuid(slugOrId)) return slugOrId;
  const resolved = await resolveRealm(baseUrl, slugOrId, httpTimeout);
  return resolved.id;
}
