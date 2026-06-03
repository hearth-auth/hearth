//! Adversarial tests for the trait-level pagination hard cap (A-23).
//!
//! Verifies that `cap_page_size` enforces `MAX_PAGE_SIZE` at the
//! trait boundary before any storage scan is attempted.
//!
//! D-4 taxonomy: negative-scenario (adversarial) per §3.41.

use hearth::identity::{cap_page_size, IdentityError, MAX_PAGE_SIZE};

// ─────────────────────────────────────────────────────────────────────────────
// A-23 — Pagination hard cap
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: request for more rows than MAX_PAGE_SIZE is rejected.
#[test]
fn a23_over_cap_returns_error() {
    let result = cap_page_size(MAX_PAGE_SIZE + 1);
    assert!(
        matches!(result, Err(IdentityError::InvalidInput { .. })),
        "limit > MAX_PAGE_SIZE must return InvalidInput, got {result:?}"
    );
}

/// Adversarial: extreme limit (usize::MAX) is rejected.
#[test]
fn a23_extreme_limit_rejected() {
    let result = cap_page_size(usize::MAX);
    assert!(
        matches!(result, Err(IdentityError::InvalidInput { .. })),
        "usize::MAX page size must return InvalidInput"
    );
}

/// Negative: exactly MAX_PAGE_SIZE is accepted.
#[test]
fn a23_exact_cap_accepted() {
    assert_eq!(
        cap_page_size(MAX_PAGE_SIZE).expect("exact cap must be accepted"),
        MAX_PAGE_SIZE
    );
}

/// Negative: zero is accepted (returns empty page).
#[test]
fn a23_zero_accepted() {
    assert_eq!(cap_page_size(0).expect("zero must be accepted"), 0);
}

/// Negative: values below cap are passed through unchanged.
#[test]
fn a23_below_cap_accepted() {
    for limit in [1, 10, 50, 100, 500, MAX_PAGE_SIZE - 1] {
        assert_eq!(
            cap_page_size(limit).expect("below-cap limit must be accepted"),
            limit,
            "cap_page_size({limit}) must return {limit}"
        );
    }
}
