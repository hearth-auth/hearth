//! Duplicate-tolerant query-string extractor for admin list endpoints.

use std::collections::BTreeMap;

use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use axum::http::{StatusCode, Uri};
use serde::de::DeserializeOwned;

/// Like axum's [`Query`], but tolerant of repeated query-string keys.
///
/// HTMX 1.9's `hx-include` can emit the same parameter several times for a
/// single GET request — e.g. clicking a sortable column header while a search
/// box is populated produces `?sort=name&dir=asc&q=foo&q=foo`. The parser
/// behind axum's [`Query`] (`serde_urlencoded`) treats a repeated scalar key
/// as a duplicate-field error and rejects the whole request with `400`.
///
/// That silently broke **sort-while-searching** on every admin table
/// (HEA-1615): the sort request 400'd, `hx-select` found nothing, and the
/// table never updated — so sorting "didn't work" whenever a search term was
/// active. The same collision hit the sessions `status` filter and the search
/// form's preserved `sort`/`dir`.
///
/// `DedupQuery` collapses repeated keys to their **last** value (matching
/// browser form semantics) before deserializing, so list endpoints stay
/// correct no matter how many times the client repeats a parameter. Dedup
/// happens on the raw, still-encoded pairs, so no value is decoded twice.
pub struct DedupQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for DedupQuery<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let query = parts.uri.query().unwrap_or("");
        let rebuilt = dedup_query(query);
        // Reuse axum's own Query parsing on the collapsed query string so the
        // deserialize semantics stay identical to every non-deduped endpoint.
        let uri: Uri = format!("http://_/?{rebuilt}")
            .parse()
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid query string"))?;
        let Query(value) = Query::<T>::try_from_uri(&uri)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid query string"))?;
        Ok(Self(value))
    }
}

/// Collapses duplicate keys in a raw (percent-encoded) query string, keeping
/// each key's last occurrence while preserving first-seen ordering.
fn dedup_query(query: &str) -> String {
    let mut collapsed: Vec<&str> = Vec::new();
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let key = pair.split('=').next().unwrap_or(pair);
        if let Some(&idx) = seen.get(key) {
            collapsed[idx] = pair; // last value wins
        } else {
            seen.insert(key, collapsed.len());
            collapsed.push(pair);
        }
    }
    collapsed.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_scalar_key_keeps_last_value() {
        // The exact shape HTMX hx-include produces on a sort-while-searching
        // click: q repeated. Must collapse, not error.
        assert_eq!(
            dedup_query("sort=name&dir=asc&q=foo&q=foo"),
            "sort=name&dir=asc&q=foo"
        );
    }

    #[test]
    fn distinct_last_value_wins() {
        // First-seen POSITION of `q` is kept, but its VALUE is the last one.
        assert_eq!(dedup_query("q=old&sort=email&q=new"), "q=new&sort=email");
        assert_eq!(dedup_query("q=old&q=new"), "q=new");
    }

    #[test]
    fn preserves_order_and_singletons() {
        assert_eq!(
            dedup_query("page=2&per_page=25&sort=name&dir=desc"),
            "page=2&per_page=25&sort=name&dir=desc"
        );
    }

    #[test]
    fn empty_query_is_empty() {
        assert_eq!(dedup_query(""), "");
    }

    #[test]
    fn keyless_and_valueless_pairs_do_not_panic() {
        // `&&`, a bare key, and a trailing `&` must not break dedup.
        assert_eq!(dedup_query("a=1&&b&c=2&"), "a=1&b&c=2");
    }
}
