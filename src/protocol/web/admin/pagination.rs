//! Shared pagination view-model for admin list pages.
//!
//! [`AdminPageParams`] replaces the old cursor-based `PaginationParams`.
//! [`PaginationView`] is the template-ready view-model built from a
//! [`PagedResult`]. Both are re-exported from `admin::mod`.

use serde::Deserialize;

use crate::core::{PageRequest, PagedResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Allowed `per_page` values in the UI dropdown.  Any value not in this
/// set is rejected and replaced with [`DEFAULT_PER_PAGE`].
pub const PAGE_SIZES: [u32; 5] = [5, 10, 25, 50, 100];

/// Default items per page for admin list pages.
pub const DEFAULT_PER_PAGE: u32 = 25;

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

/// Offset-based page query params for admin list endpoints.
///
/// Replaces the old `PaginationParams { cursor }`.  Per-entity modules that
/// also carry `q` / `status` / filter fields add those alongside these.
#[derive(Debug, Default, Deserialize)]
pub struct AdminPageParams {
    /// 1-based page number. Defaults to 1.
    pub page: Option<u32>,
    /// Items per page.  Must be in [`PAGE_SIZES`]; clamped to
    /// [`DEFAULT_PER_PAGE`] otherwise.
    pub per_page: Option<u32>,
}

impl AdminPageParams {
    /// Returns the validated `per_page`, clamped to [`DEFAULT_PER_PAGE`] when
    /// the raw value is not in [`PAGE_SIZES`].
    pub fn per_page_validated(&self) -> u32 {
        validate_per_page(self.per_page.unwrap_or(DEFAULT_PER_PAGE))
    }

    /// Constructs a [`PageRequest`] from the validated page + per_page.
    pub fn as_page_request(&self) -> PageRequest {
        PageRequest::from_page_number(self.page.unwrap_or(1), self.per_page_validated())
    }
}

/// Clamps `per_page` to the allowlist — anything not in [`PAGE_SIZES`] becomes
/// [`DEFAULT_PER_PAGE`].  Never trusts the raw query-string value.
pub fn validate_per_page(per_page: u32) -> u32 {
    if PAGE_SIZES.contains(&per_page) {
        per_page
    } else {
        DEFAULT_PER_PAGE
    }
}

// ---------------------------------------------------------------------------
// View-model
// ---------------------------------------------------------------------------

/// One item in the page-number window rendered in the pagination bar.
///
/// Represents either a clickable page link or a `…` separator.
pub struct PageWindowItem {
    /// `None` = ellipsis (`…`); `Some(n)` = page number link.
    pub page: Option<u64>,
    /// Pre-computed: `true` when this item is the current page.
    ///
    /// Avoids an `&u64 == u64` comparison in the Askama template (Askama
    /// borrows iterated items and Some-bound values, so a direct `==`
    /// comparison against a `u64` field would fail at the trait-bound level).
    pub is_current: bool,
}

impl PageWindowItem {
    /// `true` when this item is an ellipsis, not a page link.
    pub fn is_ellipsis(&self) -> bool {
        self.page.is_none()
    }
}

/// One option in the page-size `<select>` dropdown.
///
/// Carries the `selected` flag so the Askama template avoids a
/// `&u32 == u32` comparison (Askama borrows iterated Vec items).
pub struct PageSizeOption {
    /// The page-size value (5 / 10 / 25 / 50 / 100).
    pub size: u32,
    /// `true` when this size is the currently active page size.
    pub selected: bool,
}

/// Template-ready view-model for an offset-based pagination bar.
///
/// Constructed via [`PaginationView::new`] from a [`PagedResult`].
pub struct PaginationView {
    /// Current 1-based page number.
    pub current_page: u64,
    /// Total number of pages (may be 0 when the result set is empty).
    pub total_pages: u64,
    /// Total items in the full result set.
    pub total: u64,
    /// Effective `per_page` value (validated against the allowlist).
    pub per_page: u32,
    /// Page-size dropdown options (5/10/25/50/100 with `selected` flag).
    ///
    /// Pre-computed so the Askama template can render the `<select>` without
    /// a `&u32 == u32` comparison (Askama borrows iterated Vec items).
    pub page_size_options: Vec<PageSizeOption>,
    /// Previous page number, or `None` when on the first page.
    pub prev_page: Option<u64>,
    /// Next page number, or `None` when on the last page.
    pub next_page: Option<u64>,
    /// Ellipsis-truncated window of page links (up to 7 visible page numbers).
    pub page_window: Vec<PageWindowItem>,
    /// Base URL path (no query-string) for page / page-size links.
    ///
    /// Example: `/ui/admin/realms`.
    pub base_url: String,
    /// URL-encoded query params to preserve across page navigation and
    /// page-size changes (e.g. `q=foo&status=active`).
    ///
    /// Must NOT include `page` or `per_page` — those are added by the template.
    /// May be empty.  Used in href `?page=N&per_page=M&{preserved_params}`.
    pub preserved_params: String,
    /// Pre-split `(name, value)` pairs from `preserved_params` for the
    /// page-size `<form>`'s hidden inputs.  The template iterates these
    /// directly — avoids Askama's restricted template language having to
    /// split strings.
    pub filter_params: Vec<(String, String)>,
}

impl PaginationView {
    /// Builds a [`PaginationView`] from a paged result and URL context.
    ///
    /// `base_url` is the path-only URL of the list page (no `?` or query).
    /// `preserved_params` is an already-encoded query fragment (no leading `?`)
    /// in `key=value&key2=value2` form.  Each pair is also split into
    /// [`Self::filter_params`] for the template's hidden inputs.
    pub fn new<T>(
        result: &PagedResult<T>,
        base_url: impl Into<String>,
        preserved_params: impl Into<String>,
    ) -> Self {
        let current_page = result.current_page();
        let total_pages = result.total_pages();
        let prev_page = if current_page > 1 {
            Some(current_page - 1)
        } else {
            None
        };
        let next_page = if current_page < total_pages {
            Some(current_page + 1)
        } else {
            None
        };

        let preserved_params: String = preserved_params.into();
        let filter_params = parse_query_pairs(&preserved_params);
        let per_page = result.limit;
        let page_size_options = PAGE_SIZES
            .iter()
            .map(|&s| PageSizeOption {
                size: s,
                selected: s == per_page,
            })
            .collect();

        Self {
            current_page,
            total_pages,
            total: result.total,
            per_page,
            page_size_options,
            prev_page,
            next_page,
            page_window: build_page_window(current_page, total_pages),
            base_url: base_url.into(),
            preserved_params,
            filter_params,
        }
    }

    /// Returns the 1-based index of the first item on this page.
    pub fn range_start(&self) -> u64 {
        if self.total == 0 {
            return 0;
        }
        (self.current_page - 1) * u64::from(self.per_page) + 1
    }

    /// Returns the 1-based index of the last item on this page (≤ total).
    pub fn range_end(&self) -> u64 {
        let end = self.current_page * u64::from(self.per_page);
        end.min(self.total)
    }
}

// ---------------------------------------------------------------------------
// Page window builder (up to 7 visible items + ellipsis)
// ---------------------------------------------------------------------------

/// Builds the page-number window displayed in the pagination bar.
///
/// Strategy: always show page 1 and the last page.  Show a window of 3
/// pages centred on `current_page`.  Insert `…` when the gaps are wider
/// than 1.  Total visible items ≤ 7 (including ellipses).
fn build_page_window(current: u64, total: u64) -> Vec<PageWindowItem> {
    if total == 0 {
        return Vec::new();
    }
    let mk = |p: u64| PageWindowItem {
        page: Some(p),
        is_current: p == current,
    };
    let ellipsis = || PageWindowItem {
        page: None,
        is_current: false,
    };

    if total <= 7 {
        return (1..=total).map(mk).collect();
    }

    let mut pages: Vec<u64> = Vec::new();
    // Always include first and last.
    pages.push(1);

    // Window around current (±2).
    let window_start = current.saturating_sub(2).max(2);
    let window_end = (current + 2).min(total - 1);
    for p in window_start..=window_end {
        pages.push(p);
    }
    pages.push(total);
    pages.dedup();

    // Build output, inserting ellipses for gaps > 1.
    let mut out = Vec::with_capacity(pages.len() + 2);
    for (i, &p) in pages.iter().enumerate() {
        if i > 0 {
            let prev = pages[i - 1];
            if p > prev + 1 {
                out.push(ellipsis());
            }
        }
        out.push(mk(p));
    }
    out
}

// ---------------------------------------------------------------------------
// Helpers for URL building used in handlers
// ---------------------------------------------------------------------------

/// Encodes a single `key=value` pair for use in `preserved_params`.
///
/// Returns an empty string when `value` is empty.
pub fn encode_param(key: &str, value: &str) -> String {
    if value.is_empty() {
        String::new()
    } else {
        // Simple percent-encoding of space → `+` (form-style).
        let encoded = value.replace(' ', "+");
        format!("{key}={encoded}")
    }
}

/// Joins non-empty `key=value` strings with `&`.
pub fn join_params(parts: &[String]) -> String {
    parts
        .iter()
        .filter(|s| !s.is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("&")
}

/// Splits a `key=value&key2=value2` fragment into `(name, value)` pairs.
///
/// Used internally to populate [`PaginationView::filter_params`] so the
/// Askama template can render hidden inputs without string-splitting in the
/// template language.
fn parse_query_pairs(query: &str) -> Vec<(String, String)> {
    if query.is_empty() {
        return Vec::new();
    }
    query
        .split('&')
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?.to_string();
            let v = it.next().unwrap_or("").to_string();
            if k.is_empty() {
                None
            } else {
                Some((k, v))
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ===== validate_per_page =====

    #[test]
    fn per_page_allowlist_valid_values_pass_through() {
        for &size in &PAGE_SIZES {
            assert_eq!(
                validate_per_page(size),
                size,
                "allowlist value {size} must pass through"
            );
        }
    }

    #[test]
    fn per_page_out_of_allowlist_clamps_to_default() {
        for &bad in &[0u32, 3, 15, 30, 99, 101, 1000, u32::MAX] {
            assert_eq!(
                validate_per_page(bad),
                DEFAULT_PER_PAGE,
                "out-of-allowlist {bad} must clamp to DEFAULT_PER_PAGE"
            );
        }
    }

    #[test]
    fn admin_page_params_default_gives_page1_default_per_page() {
        let params = AdminPageParams::default();
        let req = params.as_page_request();
        assert_eq!(req.offset, 0, "default page 1 → offset 0");
        assert_eq!(req.limit, DEFAULT_PER_PAGE);
    }

    #[test]
    fn admin_page_params_out_of_allowlist_per_page_clamped() {
        let params = AdminPageParams {
            page: Some(1),
            per_page: Some(100_000),
        };
        assert_eq!(params.per_page_validated(), DEFAULT_PER_PAGE);
        let req = params.as_page_request();
        assert_eq!(req.limit, DEFAULT_PER_PAGE);
    }

    #[test]
    fn admin_page_params_page2_offset_correct() {
        let params = AdminPageParams {
            page: Some(2),
            per_page: Some(25),
        };
        let req = params.as_page_request();
        assert_eq!(req.offset, 25);
        assert_eq!(req.limit, 25);
    }

    // ===== PaginationView =====

    fn make_result(total: u64, offset: u64, limit: u32) -> PagedResult<u32> {
        let end = (offset + u64::from(limit)).min(total);
        let count = if offset < total {
            (end - offset) as usize
        } else {
            0
        };
        PagedResult::new(vec![0u32; count], total, offset, limit)
    }

    #[test]
    fn pagination_view_first_page() {
        let r = make_result(100, 0, 25);
        let v = PaginationView::new(&r, "/items", "");
        assert_eq!(v.current_page, 1);
        assert_eq!(v.total_pages, 4);
        assert_eq!(v.prev_page, None);
        assert_eq!(v.next_page, Some(2));
        assert_eq!(v.range_start(), 1);
        assert_eq!(v.range_end(), 25);
    }

    #[test]
    fn pagination_view_last_page() {
        let r = make_result(100, 75, 25);
        let v = PaginationView::new(&r, "/items", "");
        assert_eq!(v.current_page, 4);
        assert_eq!(v.total_pages, 4);
        assert_eq!(v.prev_page, Some(3));
        assert_eq!(v.next_page, None);
        assert_eq!(v.range_start(), 76);
        assert_eq!(v.range_end(), 100);
    }

    #[test]
    fn preserved_params_carry_search_sort_and_dir_together() {
        // Regression (HEA-1615): paginating after a combined search + sort must
        // keep EVERY dimension. The reported bug was that navigating pages (or
        // changing page size) silently dropped `q`/`sort`/`dir`, resetting the
        // list. `preserved_params` feeds prev/next hrefs verbatim and
        // `filter_params` feeds the page-size form's hidden inputs — both must
        // round-trip all three keys.
        let preserved = join_params(&[
            encode_param("q", "alice"),
            encode_param("sort", "email"),
            encode_param("dir", "desc"),
        ]);
        assert_eq!(preserved, "q=alice&sort=email&dir=desc");

        let r = make_result(100, 25, 25); // page 2 of 4
        let v = PaginationView::new(&r, "/ui/admin/admin-users", preserved);

        assert_eq!(
            v.preserved_params, "q=alice&sort=email&dir=desc",
            "prev/next hrefs embed the full preserved query"
        );
        let keys: Vec<&str> = v.filter_params.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"q"), "page-size form must resend q");
        assert!(keys.contains(&"sort"), "page-size form must resend sort");
        assert!(keys.contains(&"dir"), "page-size form must resend dir");
        assert_eq!(v.current_page, 2);
        assert_eq!(v.prev_page, Some(1));
        assert_eq!(v.next_page, Some(3));
    }

    #[test]
    fn cleared_search_drops_query_from_preserved_params() {
        // Regression (HEA-1615): after clearing the search box, pagination must
        // NOT re-introduce the old query. An empty value encodes to nothing, so
        // preserved_params carries only the still-active sort.
        let preserved = join_params(&[
            encode_param("q", ""),
            encode_param("sort", "email"),
            encode_param("dir", "asc"),
        ]);
        assert_eq!(preserved, "sort=email&dir=asc", "no dangling q= remains");
        let r = make_result(100, 0, 25);
        let v = PaginationView::new(&r, "/ui/admin/admin-users", preserved);
        let keys: Vec<&str> = v.filter_params.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"q"), "cleared search must not resurface");
    }

    #[test]
    fn pagination_view_empty_result() {
        let r = make_result(0, 0, 25);
        let v = PaginationView::new(&r, "/items", "");
        assert_eq!(v.total_pages, 0);
        assert_eq!(v.prev_page, None);
        assert_eq!(v.next_page, None);
        assert_eq!(v.range_start(), 0);
        assert_eq!(v.range_end(), 0);
    }

    #[test]
    fn page_window_small_total_no_ellipsis() {
        let w = build_page_window(1, 5);
        let pages: Vec<u64> = w.iter().filter_map(|i| i.page).collect();
        assert_eq!(pages, [1, 2, 3, 4, 5]);
        assert!(!w.iter().any(|i| i.is_ellipsis()));
    }

    #[test]
    fn page_window_large_total_has_ellipsis() {
        let w = build_page_window(1, 20);
        assert!(w.iter().any(|i| i.is_ellipsis()), "expected at least one …");
        let first = w.first().expect("window non-empty").page;
        let last = w.last().expect("window non-empty").page;
        assert_eq!(first, Some(1));
        assert_eq!(last, Some(20));
    }

    #[test]
    fn page_window_middle_page_has_ellipsis_both_sides() {
        let w = build_page_window(10, 20);
        let ellipsis_count = w.iter().filter(|i| i.is_ellipsis()).count();
        assert!(
            ellipsis_count >= 2,
            "middle page on large set must have 2 ellipsis items"
        );
    }

    #[test]
    fn page_window_empty_total() {
        let w = build_page_window(1, 0);
        assert!(w.is_empty());
    }

    // ===== URL helpers =====

    #[test]
    fn encode_param_empty_value_returns_empty() {
        assert_eq!(encode_param("q", ""), "");
    }

    #[test]
    fn encode_param_non_empty_value() {
        assert_eq!(encode_param("q", "foo bar"), "q=foo+bar");
    }

    #[test]
    fn join_params_filters_empty() {
        let parts = vec![encode_param("q", ""), encode_param("status", "active")];
        assert_eq!(join_params(&parts), "status=active");
    }
}
