//! Layer-neutral pagination vocabulary.
//!
//! Two complementary pagination models:
//!
//! - **Cursor-based** ([`Page<T>`]): opaque `next_cursor` token. Stable under
//!   concurrent writes; use for streaming/append workloads.
//! - **Offset-based** ([`PageRequest`] + [`PagedResult<T>`]): numeric
//!   offset + capped total count. Supports "page N of M" display in admin UIs.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default items per page when the caller does not specify.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;

/// Hard cap on items per page for offset-based pagination.
pub const MAX_PAGE_LIMIT: u32 = 200;

/// Default cap passed to [`StorageEngine::count_prefix`].
///
/// When the real count exceeds this, `count_prefix` returns the cap value and
/// callers display "10,000+" rather than spending O(N) time counting.
pub const DEFAULT_COUNT_CAP: u64 = 10_000;

// ---------------------------------------------------------------------------
// Offset-based request
// ---------------------------------------------------------------------------

/// Offset-based page request.
///
/// Build via [`PageRequest::from_page_number`] (1-based UI page numbers) or
/// [`PageRequest::new`] (raw offset + limit). Both clamp `limit` to
/// `[1, `[`MAX_PAGE_LIMIT`]`]`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    /// Zero-based offset into the full result set.
    pub offset: u64,
    /// Maximum items to return. Always in `[1, `[`MAX_PAGE_LIMIT`]`]`.
    pub limit: u32,
}

impl PageRequest {
    /// Constructs a `PageRequest` from a **1-based** page number and
    /// items-per-page.
    ///
    /// `page` is floor-clamped to 1. `per_page` is clamped to
    /// `[1, `[`MAX_PAGE_LIMIT`]`]`. Overflow-safe: offset is computed with
    /// saturating arithmetic.
    pub fn from_page_number(page: u32, per_page: u32) -> Self {
        let page = page.max(1);
        let limit = per_page.clamp(1, MAX_PAGE_LIMIT);
        let offset = u64::from(page.saturating_sub(1)).saturating_mul(u64::from(limit));
        Self { offset, limit }
    }

    /// Constructs a `PageRequest` from a raw offset and limit.
    ///
    /// `limit` is clamped to `[1, `[`MAX_PAGE_LIMIT`]`]`.
    pub fn new(offset: u64, limit: u32) -> Self {
        Self {
            offset,
            limit: limit.clamp(1, MAX_PAGE_LIMIT),
        }
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: DEFAULT_PAGE_LIMIT,
        }
    }
}

// ---------------------------------------------------------------------------
// Offset-based result
// ---------------------------------------------------------------------------

/// Result of an offset-based paged query.
///
/// Carries the items for the requested window plus the (possibly capped) total
/// count. Callers should display "10,000+" when `total` equals
/// [`DEFAULT_COUNT_CAP`] and the current page is not the last page, to avoid
/// implying exactness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagedResult<T> {
    /// Items in the requested window.
    pub items: Vec<T>,
    /// Total items in the full result set (possibly capped).
    pub total: u64,
    /// Echo of the request offset.
    pub offset: u64,
    /// Echo of the request limit (after clamping).
    pub limit: u32,
}

impl<T> Default for PagedResult<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            total: 0,
            offset: 0,
            limit: DEFAULT_PAGE_LIMIT,
        }
    }
}

impl<T> PagedResult<T> {
    /// Constructs a result from components.
    pub fn new(items: Vec<T>, total: u64, offset: u64, limit: u32) -> Self {
        Self {
            items,
            total,
            offset,
            limit,
        }
    }

    /// Total number of pages, rounding up.
    ///
    /// Returns `0` when `total` is `0`.
    pub fn total_pages(&self) -> u64 {
        if self.limit == 0 || self.total == 0 {
            return 0;
        }
        self.total.div_ceil(u64::from(self.limit))
    }

    /// Current 1-based page number derived from offset and limit.
    pub fn current_page(&self) -> u64 {
        if self.limit == 0 {
            return 1;
        }
        self.offset / u64::from(self.limit) + 1
    }
}

// ---------------------------------------------------------------------------
// Cursor-based page (unified — replaces duplicates in identity + rbac)
// ---------------------------------------------------------------------------

/// A cursor-based page of results.
///
/// `next_cursor` is an opaque token the client echoes back to fetch the
/// following page. `None` means there are no further pages.
///
/// This is the cursor-based counterpart to [`PagedResult`]. Prefer cursor
/// pagination for streaming/append workloads where offset semantics would
/// drift under concurrent writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    /// Items on this page.
    pub items: Vec<T>,
    /// Cursor for the next page, or `None` if this is the last page.
    pub next_cursor: Option<String>,
}

impl<T> Default for Page<T> {
    fn default() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    use proptest::prelude::*;

    // ===== PageRequest::from_page_number =====

    #[test]
    fn page_request_page_1_offset_zero() {
        let req = PageRequest::from_page_number(1, 20);
        assert_eq!(req.offset, 0);
        assert_eq!(req.limit, 20);
    }

    #[test]
    fn page_request_page_2_offset_correct() {
        let req = PageRequest::from_page_number(2, 20);
        assert_eq!(req.offset, 20);
        assert_eq!(req.limit, 20);
    }

    #[test]
    fn page_request_page_number_clamped_to_1() {
        let req = PageRequest::from_page_number(0, 10);
        assert_eq!(req.offset, 0, "page 0 treated as page 1");
    }

    #[test]
    fn page_request_limit_clamped_to_max() {
        let req = PageRequest::from_page_number(1, 9999);
        assert_eq!(req.limit, MAX_PAGE_LIMIT);
    }

    #[test]
    fn page_request_limit_clamped_to_1() {
        let req = PageRequest::from_page_number(1, 0);
        assert_eq!(req.limit, 1);
    }

    #[test]
    fn page_request_new_clamps_limit() {
        let req = PageRequest::new(100, 0);
        assert_eq!(req.limit, 1);
        let req = PageRequest::new(100, u32::MAX);
        assert_eq!(req.limit, MAX_PAGE_LIMIT);
    }

    #[test]
    fn page_request_default_is_first_page() {
        let req = PageRequest::default();
        assert_eq!(req.offset, 0);
        assert_eq!(req.limit, DEFAULT_PAGE_LIMIT);
    }

    // ===== PagedResult helpers =====

    #[test]
    fn paged_result_total_pages_rounds_up() {
        let r = PagedResult::new(vec![1u32; 10], 25, 0, 10);
        assert_eq!(r.total_pages(), 3); // ceil(25/10) = 3
    }

    #[test]
    fn paged_result_total_pages_exact() {
        let r = PagedResult::new(vec![1u32; 10], 20, 0, 10);
        assert_eq!(r.total_pages(), 2);
    }

    #[test]
    fn paged_result_total_pages_zero_when_empty() {
        let r: PagedResult<u32> = PagedResult::new(vec![], 0, 0, 10);
        assert_eq!(r.total_pages(), 0);
    }

    #[test]
    fn paged_result_current_page() {
        let r = PagedResult::new(vec![0u32; 5], 100, 40, 20);
        assert_eq!(r.current_page(), 3); // offset=40, limit=20 → page 3
    }

    #[test]
    fn paged_result_current_page_first() {
        let r = PagedResult::new(vec![0u32; 5], 100, 0, 20);
        assert_eq!(r.current_page(), 1);
    }

    // ===== Page (cursor-based) =====

    #[test]
    fn page_default_is_empty_no_cursor() {
        let p: Page<u32> = Page::default();
        assert!(p.items.is_empty());
        assert!(p.next_cursor.is_none());
    }

    // ===== Property tests =====

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 256,
            ..Default::default()
        })]

        /// For any (count, per_page, page), the offset window and computed
        /// total_pages are internally consistent:
        /// - items in window ≤ limit
        /// - items in window = min(limit, count.saturating_sub(offset))
        /// - total_pages = ceil(count / limit) when count > 0
        /// - current_page is derived correctly from offset and limit
        #[test]
        fn page_request_window_consistency(
            count in 0u64..=10_000,
            per_page in 1u32..=MAX_PAGE_LIMIT,
            page in 1u32..=200,
        ) {
            let req = PageRequest::from_page_number(page, per_page);
            prop_assert!(req.limit >= 1);
            prop_assert!(req.limit <= MAX_PAGE_LIMIT);

            // Simulate the item window for these params.
            let window_size = if req.offset >= count {
                0u64
            } else {
                (count - req.offset).min(u64::from(req.limit))
            };
            let items: Vec<u32> = vec![0; window_size as usize];
            let result = PagedResult::new(items, count, req.offset, req.limit);

            // Window must not exceed limit.
            prop_assert!(result.items.len() as u64 <= u64::from(result.limit));

            // total_pages consistency.
            if count == 0 {
                prop_assert_eq!(result.total_pages(), 0);
            } else {
                let expected_pages = count.div_ceil(u64::from(req.limit));
                prop_assert_eq!(result.total_pages(), expected_pages);
            }

            // current_page derived from offset.
            let expected_page = req.offset / u64::from(req.limit) + 1;
            prop_assert_eq!(result.current_page(), expected_page);
        }
    }
}
