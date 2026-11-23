// Helpers the product adapters share. Pure functions without k6 modules, so
// node tests them (test_products.mjs).

/** The value of the hidden form field `name` in an HTML page, or null. */
export function hidden(body, name) {
  const m = new RegExp(`name="${name}" value="([^"]*)"`).exec(body || '');
  return m ? m[1] : null;
}

/** A form-encoded query string from an object. */
export function query(params) {
  return Object.keys(params)
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
    .join('&');
}

/** The query parameters of a redirect `location`, decoded. */
export function redirectParams(location) {
  const q = (location || '').split('?')[1] || '';
  const out = {};
  for (const pair of q.split('&')) {
    if (!pair) continue;
    const [k, v] = pair.split('=');
    out[decodeURIComponent(k)] = decodeURIComponent((v || '').replace(/\+/g, ' '));
  }
  return out;
}

/** A response header, whatever its case (k6 canonicalises names; tests may not). */
export function header(res, name) {
  const h = (res && res.headers) || {};
  if (h[name] !== undefined) return h[name];
  const lower = name.toLowerCase();
  for (const k of Object.keys(h)) {
    if (k.toLowerCase() === lower) return h[k];
  }
  return undefined;
}

/** The JSON body of a response, or null when it is not JSON. */
export function json(res) {
  try {
    return JSON.parse(res.body);
  } catch (e) {
    return null;
  }
}

/**
 * The query of an authorization request with PKCE, from a sign-in flow `f`
 * (scope `f.scope`, else openid).
 */
export function authorizeQuery(f, clientId, redirectUri) {
  return query({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    state: f.state,
    scope: f.scope || 'openid',
    code_challenge: f.challenge,
    code_challenge_method: 'S256',
  });
}

/**
 * True when `res` redirects to the redirect URI with a code for flow `f`
 * (status `status`, the state `f` sent). Sets `f.code`.
 */
export function takeCode(res, f, status) {
  if (res.status !== status) return false;
  const p = redirectParams(header(res, 'Location'));
  if (!p.code || p.state !== f.state) return false;
  f.code = p.code;
  return true;
}

/** The token request that exchanges flow `f`'s code (RFC 6749 §4.1.3, RFC 7636). */
export function codeExchange(url, f, clientId, redirectUri) {
  return {
    method: 'POST',
    url,
    body: {
      grant_type: 'authorization_code',
      code: f.code,
      redirect_uri: redirectUri,
      client_id: clientId,
      code_verifier: f.verifier,
    },
  };
}

/**
 * True when a token response succeeded. Sets `f.access`, `f.refresh` and
 * `f.expiresIn` (the response's `expires_in`, read by tokenLife).
 */
export function takeTokens(res, f) {
  if (res.status !== 200) return false;
  const b = json(res);
  if (!b || !b.access_token) return false;
  f.access = b.access_token;
  f.refresh = b.refresh_token;
  f.expiresIn = b.expires_in;
  return true;
}

/**
 * The issue and expiry times (epoch seconds) of an access token received at
 * `nowS` with the token response's `expires_in` (RFC 6749 section 5.1: the
 * lifetime in seconds). The same for every product, whatever its token format
 * (a JWT's claims or an opaque string): the harness never reads the token.
 * Throws when `expires_in` is missing or not a positive number of seconds; the
 * harness does not guess a lifetime.
 */
export function tokenLife(expiresIn, nowS) {
  if (typeof expiresIn !== 'number' || !Number.isFinite(expiresIn) || expiresIn <= 0) {
    throw new Error(`the token response has no valid expires_in (${JSON.stringify(expiresIn)})`);
  }
  return { iat: nowS, exp: nowS + expiresIn };
}
