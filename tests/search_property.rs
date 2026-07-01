#![allow(clippy::unwrap_used)]
//! Property tests for `src/identity/search.rs`.
//!
//! Invariants verified:
//! 1. `SearchQuery::compile` never panics on arbitrary Unicode input.
//! 2. The exact-match set is a subset of the substring-match set.

use hearth::identity::search::SearchQuery;
use proptest::prelude::*;

proptest! {
    /// Compiling any arbitrary Unicode string must never panic.
    #[test]
    fn compile_never_panics(q in ".*") {
        let _ = SearchQuery::compile(&q);
    }

    /// Compiling a string containing glob-special chars and Unicode never panics.
    #[test]
    fn compile_glob_unicode_never_panics(
        q in r#"[*?"a-z0-9\u{0080}-\u{FFFF}]{0,64}"#,
    ) {
        let _ = SearchQuery::compile(&q);
    }

    /// Exact-match set ⊆ substring-match set.
    ///
    /// For any pattern `p` and field `f`, if `"p"` (exact query) matches `f`
    /// then the bare `p` (substring query) also matches `f`.
    ///
    /// Proof sketch: exact match ⟺ `f.to_lowercase() == p.to_lowercase()`,
    /// which implies `f.to_lowercase().contains(p.to_lowercase())`.
    #[test]
    fn exact_implies_substring(
        p in "[a-z0-9@._]{2,32}",
        f in "[a-z0-9@._]{0,64}",
    ) {
        let exact_query = format!("\"{}\"", p);
        let exact_matches = SearchQuery::compile(&exact_query).matches(&f);
        let substr_matches = SearchQuery::compile(&p).matches(&f);

        if exact_matches {
            prop_assert!(
                substr_matches,
                "exact matched but substring did not: pattern={p:?} field={f:?}"
            );
        }
    }
}
