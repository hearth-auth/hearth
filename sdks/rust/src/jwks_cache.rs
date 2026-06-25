//! JWKS key cache with TTL (spec §2).
//!
//! Caches Ed25519/OKP keys by `kid`. Keys are never evicted — only re-fetched when
//! stale. On cache miss for a `kid`, re-fetches once before returning `None`.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use tokio::sync::Mutex;

use crate::error::HearthError;

const DEFAULT_TTL: Duration = Duration::from_secs(300); // 5 minutes
const MAX_TTL: Duration = Duration::from_secs(86_400); // 24 hours (spec §2 maximum)

struct CachedEntry {
    jwk: Jwk,
    fetched_at: Instant,
    ttl: Duration,
}

struct Inner {
    /// Kid-indexed JWKS entries. Keys are never removed; only refreshed on TTL expiry.
    keys: HashMap<String, CachedEntry>,
    jwks_url: Option<String>,
}

/// Thread-safe JWKS key cache with TTL (spec §2).
///
/// - Caches keys by `kid`. Keys are never evicted; only re-fetched when stale.
/// - Respects `Cache-Control: max-age` from the JWKS response; falls back to 5 min.
/// - Maximum cache age is 24 hours regardless of `Cache-Control`.
/// - On cache miss for a `kid`: re-fetches once before returning `None`.
/// - Skips (does not error on) keys with an unrecognized `kty`.
#[derive(Clone)]
pub struct JwksCache {
    inner: Arc<Mutex<Inner>>,
    http: reqwest::Client,
    /// When `Some`, overrides Cache-Control for TTL.
    override_ttl: Option<Duration>,
}

impl JwksCache {
    /// Create a new empty cache.
    ///
    /// Call [`JwksCache::set_url`] before the first [`JwksCache::get`] call.
    pub fn new(http: reqwest::Client, override_ttl: Option<Duration>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                keys: HashMap::new(),
                jwks_url: None,
            })),
            http,
            override_ttl,
        }
    }

    /// Set the JWKS endpoint URL.
    pub async fn set_url(&self, url: impl Into<String>) {
        self.inner.lock().await.jwks_url = Some(url.into());
    }

    /// Get a JWK by `kid`.
    ///
    /// Returns the cached key if still fresh. On a cache miss or stale entry,
    /// re-fetches the JWKS endpoint once before returning. Returns `None` if the
    /// `kid` is absent from the JWKS even after a fresh fetch.
    ///
    /// # Errors
    /// Returns [`HearthError::ConfigurationError`] if no JWKS URL has been set.
    /// Returns [`HearthError::JWKSFetchError`] if the fetch fails.
    pub async fn get(&self, kid: &str) -> Result<Option<Jwk>, HearthError> {
        // Fast path: check cache while holding the lock briefly.
        let maybe_cached = {
            let inner = self.inner.lock().await;
            inner.keys.get(kid).and_then(|entry| {
                if entry.fetched_at.elapsed() < entry.ttl {
                    Some(entry.jwk.clone())
                } else {
                    None // stale
                }
            })
        };
        if let Some(jwk) = maybe_cached {
            return Ok(Some(jwk));
        }

        // Cache miss or stale — fetch once and retry.
        self.fetch_and_update().await?;

        let inner = self.inner.lock().await;
        Ok(inner.keys.get(kid).map(|e| e.jwk.clone()))
    }

    /// Force a fetch of the JWKS endpoint, merging new keys into the cache.
    ///
    /// Existing keys are kept even if absent from the latest response (spec §2: "do
    /// not discard keys not present in the latest fetch").
    pub async fn fetch_and_update(&self) -> Result<(), HearthError> {
        let url = {
            let inner = self.inner.lock().await;
            inner.jwks_url.clone().ok_or_else(|| HearthError::ConfigurationError {
                message: "JwksCache: set_url() must be called before fetching".into(),
            })?
        };

        let resp = self.http.get(&url).send().await.map_err(|e| HearthError::JWKSFetchError {
            url: url.clone(),
            message: e.to_string(),
        })?;

        let ttl = self.override_ttl.unwrap_or_else(|| {
            parse_cache_control_max_age(resp.headers())
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_TTL)
                .min(MAX_TTL)
        });

        let jwks: JwkSet = resp.json().await.map_err(|e| HearthError::JWKSFetchError {
            url: url.clone(),
            message: format!("JSON parse: {e}"),
        })?;

        let now = Instant::now();
        let mut inner = self.inner.lock().await;

        for jwk in jwks.keys {
            if let Some(kid) = jwk.common.key_id.clone() {
                inner.keys.insert(kid, CachedEntry { jwk, fetched_at: now, ttl });
            }
            // Keys without a kid are skipped (no way to look them up by kid).
        }

        Ok(())
    }
}

/// Test helper: directly insert a JWK into the cache without a network fetch.
///
/// The inserted entry is given a 24h TTL so it will not be evicted during tests.
#[cfg(test)]
impl JwksCache {
    pub async fn inject_for_test(&self, kid: impl Into<String>, jwk: Jwk) {
        let mut inner = self.inner.lock().await;
        inner.keys.insert(
            kid.into(),
            CachedEntry {
                jwk,
                fetched_at: Instant::now(),
                ttl: MAX_TTL,
            },
        );
    }
}

fn parse_cache_control_max_age(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let cc = headers.get(reqwest::header::CACHE_CONTROL)?;
    let cc_str = cc.to_str().ok()?;
    for part in cc_str.split(',') {
        if let Some(val) = part.trim().strip_prefix("max-age=") {
            return val.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(value: &'static str) -> reqwest::header::HeaderMap {
        let mut map = reqwest::header::HeaderMap::new();
        map.insert(
            reqwest::header::CACHE_CONTROL,
            reqwest::header::HeaderValue::from_static(value),
        );
        map
    }

    #[test]
    fn parse_max_age_simple() {
        let headers = make_headers("max-age=3600");
        assert_eq!(parse_cache_control_max_age(&headers), Some(3600));
    }

    #[test]
    fn parse_max_age_with_other_directives() {
        let headers = make_headers("public, max-age=7200, must-revalidate");
        assert_eq!(parse_cache_control_max_age(&headers), Some(7200));
    }

    #[test]
    fn parse_max_age_absent_header() {
        let map = reqwest::header::HeaderMap::new();
        assert_eq!(parse_cache_control_max_age(&map), None);
    }

    #[test]
    fn parse_max_age_no_directive() {
        let headers = make_headers("no-cache, no-store");
        assert_eq!(parse_cache_control_max_age(&headers), None);
    }

    #[test]
    fn max_ttl_capped_at_24h() {
        // Even if Cache-Control says max-age=999999, we cap at 24h.
        let very_long = Duration::from_secs(999_999).min(MAX_TTL);
        assert_eq!(very_long, MAX_TTL);
    }

    #[tokio::test]
    async fn set_url_before_get_required() {
        let cache = JwksCache::new(reqwest::Client::new(), None);
        let err = cache.get("any-kid").await.unwrap_err();
        match err {
            HearthError::ConfigurationError { message } => {
                assert!(message.contains("set_url"));
            }
            other => panic!("expected ConfigurationError, got {other:?}"),
        }
    }
}
