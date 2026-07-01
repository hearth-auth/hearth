//! Pure query→matcher compiler for admin-table search.
//!
//! No I/O, no storage — compiles a raw query string into a typed matcher and
//! tests field values against it.  Used by admin list handlers to filter rows
//! in-process after loading them from the KV store.
//!
//! # Grammar (case-insensitive)
//!
//! | Form | Example | Behaviour |
//! |------|---------|-----------|
//! | Empty / < 2 chars | `""`, `"j"` | Match all (backward-compatible guard) |
//! | Substring (default) | `john` | Field contains the literal |
//! | Glob | `john*`, `*@acme.com`, `a?z` | Anchored whole-field glob |
//! | Exact | `"john@acme.com"` | Whole-field case-insensitive equality |

/// A compiled search query ready to match against field values.
///
/// Construct with [`SearchQuery::compile`]; test a single field with
/// [`SearchQuery::matches`] or test a row of fields with
/// [`SearchQuery::matches_any`].
#[derive(Debug, Clone)]
pub enum SearchQuery {
    /// Empty or fewer-than-2-character query — always matches every row.
    MatchAll,
    /// Case-insensitive substring match (the default when no special syntax is
    /// detected).  The inner [`String`] is already lowercased.
    Substring(String),
    /// Anchored glob: `*` = any sequence of characters (including empty),
    /// `?` = exactly one character.  All comparisons are case-insensitive.
    Glob(Vec<GlobSegment>),
    /// Case-insensitive whole-field equality.  The inner [`String`] is already
    /// lowercased; it must equal the lowercased field for a match.
    Exact(String),
}

/// One segment in a compiled glob pattern.
#[derive(Debug, Clone, PartialEq)]
pub enum GlobSegment {
    /// Literal characters (already lowercased at compile time).
    Literal(String),
    /// `*` wildcard — matches any sequence of characters, including the empty
    /// sequence.
    Star,
    /// `?` wildcard — matches exactly one character.
    Question,
}

impl SearchQuery {
    /// Compiles a raw query string into a [`SearchQuery`].
    ///
    /// Classification rules (applied in order):
    ///
    /// 1. Fewer than 2 chars after trimming → [`SearchQuery::MatchAll`]
    /// 2. Starts **and** ends with `"` → [`SearchQuery::Exact`] (inner text,
    ///    lowercased)
    /// 3. Contains `*` or `?` → [`SearchQuery::Glob`] (anchored, case-insensitive)
    /// 4. Otherwise → [`SearchQuery::Substring`] (lowercased)
    ///
    /// This function never panics regardless of input.
    #[must_use]
    pub fn compile(query: &str) -> Self {
        let q = query.trim();

        if q.len() < 2 {
            return Self::MatchAll;
        }

        // Exact: wrapped in double quotes.
        if q.starts_with('"') && q.ends_with('"') {
            let inner = q[1..q.len() - 1].to_lowercase();
            return Self::Exact(inner);
        }

        // Glob: contains wildcard characters.
        if q.contains('*') || q.contains('?') {
            return Self::Glob(compile_glob(q));
        }

        Self::Substring(q.to_lowercase())
    }

    /// Returns `true` if `field` satisfies this query.
    #[must_use]
    pub fn matches(&self, field: &str) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Substring(pat) => field.to_lowercase().contains(pat.as_str()),
            Self::Exact(pat) => field.to_lowercase() == *pat,
            Self::Glob(segments) => {
                let lower = field.to_lowercase();
                let chars: Vec<char> = lower.chars().collect();
                glob_match(segments, &chars)
            }
        }
    }

    /// Returns `true` if at least one entry in `fields` satisfies this query.
    ///
    /// Returns `false` when `fields` is empty, even for [`SearchQuery::MatchAll`].
    #[must_use]
    pub fn matches_any(&self, fields: &[&str]) -> bool {
        fields.iter().any(|f| self.matches(f))
    }
}

/// Compiles a glob pattern string into an ordered list of [`GlobSegment`]s.
///
/// Consecutive `*` wildcards are collapsed into a single [`GlobSegment::Star`]
/// to prevent backtracking blowup during matching.
fn compile_glob(pattern: &str) -> Vec<GlobSegment> {
    let mut segments: Vec<GlobSegment> = Vec::new();
    let mut lit = String::new();

    for ch in pattern.to_lowercase().chars() {
        match ch {
            '*' => {
                if !lit.is_empty() {
                    segments.push(GlobSegment::Literal(std::mem::take(&mut lit)));
                }
                // Collapse consecutive stars — key ReDoS mitigation.
                if segments.last() != Some(&GlobSegment::Star) {
                    segments.push(GlobSegment::Star);
                }
            }
            '?' => {
                if !lit.is_empty() {
                    segments.push(GlobSegment::Literal(std::mem::take(&mut lit)));
                }
                segments.push(GlobSegment::Question);
            }
            c => lit.push(c),
        }
    }

    if !lit.is_empty() {
        segments.push(GlobSegment::Literal(lit));
    }

    segments
}

/// A char-level glob token, produced by flattening [`GlobSegment`]s.
#[derive(PartialEq)]
enum GlobToken {
    /// A single literal character (already lowercased).
    Lit(char),
    /// `?` — matches exactly one arbitrary character.
    Any,
    /// `*` — matches any (possibly empty) run of characters.
    Star,
}

/// Linear-time anchored glob matcher (two-pointer with a single star backtrack).
///
/// The pattern is fully anchored: it must consume *all* of `text`.  Runs in
/// `O(text.len() × pattern.len())` worst case — there is exactly one backtrack
/// anchor (the most recent `*`), so adversarial patterns such as `a*a*a*b`
/// against a long `aaaa…` field cannot trigger exponential backtracking
/// (ReDoS). This is the standard iterative wildcard-matching algorithm.
fn glob_match(segments: &[GlobSegment], text: &[char]) -> bool {
    // Flatten segments into a flat char/wildcard token stream so the two-pointer
    // walk operates one input character at a time.
    let mut toks: Vec<GlobToken> = Vec::new();
    for seg in segments {
        match seg {
            GlobSegment::Literal(s) => toks.extend(s.chars().map(GlobToken::Lit)),
            GlobSegment::Question => toks.push(GlobToken::Any),
            GlobSegment::Star => toks.push(GlobToken::Star),
        }
    }

    let (mut t, mut p) = (0usize, 0usize);
    // `star` is the pattern index of the most recent `*`; `star_t` is the text
    // index it is currently assumed to have consumed up to.
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;

    while t < text.len() {
        match toks.get(p) {
            Some(GlobToken::Any) => {
                t += 1;
                p += 1;
            }
            Some(GlobToken::Lit(c)) if *c == text[t] => {
                t += 1;
                p += 1;
            }
            Some(GlobToken::Star) => {
                star = Some(p);
                star_t = t;
                p += 1;
            }
            // Literal mismatch or pattern exhausted: extend the last `*` by one
            // character if one exists, otherwise the match fails.
            _ => {
                let Some(sp) = star else { return false };
                p = sp + 1;
                star_t += 1;
                t = star_t;
            }
        }
    }

    // Any pattern remainder must be all `*` for a full (anchored) match.
    while matches!(toks.get(p), Some(GlobToken::Star)) {
        p += 1;
    }

    p == toks.len()
}

// ---------------------------------------------------------------------------
// Sort types — per-entity enums
// ---------------------------------------------------------------------------

/// Column by which the realm list may be sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RealmSortField {
    /// Sort by realm name.
    #[default]
    Name,
    /// Sort by realm status (Active → Suspended → Archived).
    Status,
    /// Sort by creation timestamp (oldest first when ascending).
    Created,
}

impl RealmSortField {
    /// Parses a raw query-parameter string; unknown values fall back to `Name`.
    #[must_use]
    pub fn from_param(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "status" => Self::Status,
            "created" => Self::Created,
            _ => Self::Name,
        }
    }

    /// Canonical query-parameter name.
    #[must_use]
    pub fn as_param(&self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Status => "status",
            Self::Created => "created",
        }
    }
}

/// Column by which the organization list may be sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrgSortField {
    /// Sort by organization name.
    #[default]
    Name,
    /// Sort by slug.
    Slug,
}

impl OrgSortField {
    /// Parses a raw query-parameter string; unknown values fall back to `Name`.
    #[must_use]
    pub fn from_param(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "slug" => Self::Slug,
            _ => Self::Name,
        }
    }

    /// Canonical query-parameter name.
    #[must_use]
    pub fn as_param(&self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Slug => "slug",
        }
    }
}

/// Column by which the group list may be sorted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupSortField {
    /// Sort by group name.
    #[default]
    Name,
    /// Sort by slug.
    Slug,
}

impl GroupSortField {
    /// Parses a raw query-parameter string; unknown values fall back to `Name`.
    #[must_use]
    pub fn from_param(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "slug" => Self::Slug,
            _ => Self::Name,
        }
    }

    /// Canonical query-parameter name.
    #[must_use]
    pub fn as_param(&self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Slug => "slug",
        }
    }
}

// ---------------------------------------------------------------------------
// Sort types for user list queries
// ---------------------------------------------------------------------------

/// Column by which the user list may be sorted.
///
/// All variants map directly to a field on [`crate::identity::types::User`].
/// The set is intentionally closed so the protocol layer cannot request an
/// unsortable column — unknown strings silently map to the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserSortField {
    /// Sort by normalized email address.
    #[default]
    Email,
    /// Sort by display name.
    Name,
    /// Sort by account status (Active → PendingVerification → Disabled).
    Status,
    /// Sort by creation timestamp (oldest first when ascending).
    Created,
}

impl UserSortField {
    /// Parses a raw query-parameter string.  Unknown values fall back to
    /// [`UserSortField::Email`] so the URL cannot cause a server error.
    #[must_use]
    pub fn from_param(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "name" => Self::Name,
            "status" => Self::Status,
            "created" => Self::Created,
            _ => Self::Email,
        }
    }

    /// Canonical query-parameter name for round-tripping through URLs.
    #[must_use]
    pub fn as_param(&self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Name => "name",
            Self::Status => "status",
            Self::Created => "created",
        }
    }
}

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDir {
    /// Ascending order (A → Z, oldest → newest).
    #[default]
    Asc,
    /// Descending order (Z → A, newest → oldest).
    Desc,
}

impl SortDir {
    /// Parses a raw query-parameter string.  Unknown values fall back to
    /// [`SortDir::Asc`].
    #[must_use]
    pub fn from_param(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "desc" => Self::Desc,
            _ => Self::Asc,
        }
    }

    /// Canonical query-parameter name for round-tripping through URLs.
    #[must_use]
    pub fn as_param(&self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn m(query: &str, field: &str) -> bool {
        SearchQuery::compile(query).matches(field)
    }

    // ── MatchAll guard ───────────────────────────────────────────────────────

    #[test]
    fn empty_query_matches_all() {
        assert!(m("", "anything@example.com"));
        assert!(m("", ""));
    }

    #[test]
    fn single_char_query_matches_all() {
        assert!(m("j", "john@example.com"));
        assert!(m("j", "alice@example.com"));
    }

    #[test]
    fn whitespace_padded_single_char_matches_all() {
        assert!(m(" a ", "xyz"));
    }

    #[test]
    fn compile_empty_is_match_all() {
        assert!(matches!(SearchQuery::compile(""), SearchQuery::MatchAll));
    }

    // ── Substring ────────────────────────────────────────────────────────────

    #[test]
    fn substring_matches_middle_of_field() {
        assert!(m("ohn", "john@example.com"));
    }

    #[test]
    fn substring_no_match() {
        assert!(!m("xyz", "john@example.com"));
    }

    #[test]
    fn substring_case_insensitive_upper_query() {
        assert!(m("JOHN", "john@example.com"));
    }

    #[test]
    fn substring_case_insensitive_upper_field() {
        assert!(m("john", "JOHN@EXAMPLE.COM"));
    }

    #[test]
    fn two_char_query_is_substring_not_match_all() {
        assert!(m("jo", "john"));
        assert!(!m("jo", "alice"));
    }

    // ── Exact ────────────────────────────────────────────────────────────────

    #[test]
    fn exact_whole_field_equality() {
        assert!(m(r#""john@acme.com""#, "john@acme.com"));
    }

    #[test]
    fn exact_no_partial_match_prefix() {
        assert!(!m(r#""john""#, "johnny"));
    }

    #[test]
    fn exact_no_partial_match_suffix() {
        assert!(!m(r#""john""#, "mr.john"));
    }

    #[test]
    fn exact_case_insensitive_query() {
        assert!(m(r#""John@Acme.com""#, "john@acme.com"));
    }

    #[test]
    fn exact_case_insensitive_field() {
        assert!(m(r#""john@acme.com""#, "JOHN@ACME.COM"));
    }

    #[test]
    fn exact_empty_inner_matches_empty_field_only() {
        assert!(m(r#""""#, ""));
        assert!(!m(r#""""#, "nonempty"));
    }

    // ── Glob — star ──────────────────────────────────────────────────────────

    #[test]
    fn glob_prefix_star_matches_start() {
        assert!(m("john*", "john@example.com"));
        assert!(m("john*", "john"));
    }

    #[test]
    fn glob_prefix_star_no_match_middle() {
        assert!(!m("john*", "mr.john@example.com"));
    }

    #[test]
    fn glob_suffix_star_matches_end() {
        assert!(m("*@acme.com", "john@acme.com"));
        assert!(m("*@acme.com", "alice@acme.com"));
    }

    #[test]
    fn glob_suffix_star_no_match_different_domain() {
        assert!(!m("*@acme.com", "john@other.com"));
    }

    #[test]
    fn glob_anchored_both_ends() {
        assert!(m("a*z", "az"));
        assert!(m("a*z", "abcz"));
        assert!(!m("a*z", "abc"));
        assert!(!m("a*z", "zabc"));
    }

    #[test]
    fn glob_bare_star_matches_anything() {
        assert!(m("*", ""));
        assert!(m("*", "anything"));
    }

    #[test]
    fn glob_consecutive_stars_collapsed() {
        assert!(m("a**z", "az"));
        assert!(m("a**z", "abcz"));
        assert!(!m("a**z", "abc"));
    }

    #[test]
    fn glob_adversarial_pattern_no_catastrophic_backtracking() {
        // Many stars separated by literals against a long non-matching field.
        // The linear two-pointer matcher returns instantly; a naive recursive
        // matcher would exhibit exponential backtracking (ReDoS) here.
        let field = "a".repeat(64);
        assert!(!m("a*a*a*a*a*a*a*a*b", &field));
        // The matching variant still resolves correctly and quickly.
        let matching = format!("{}b", "a".repeat(64));
        assert!(m("a*a*a*a*a*a*a*a*b", &matching));
    }

    // ── Glob — question mark ─────────────────────────────────────────────────

    #[test]
    fn glob_question_matches_exactly_one_char() {
        assert!(m("j?hn", "john"));
        assert!(m("j?hn", "jahn"));
    }

    #[test]
    fn glob_question_no_match_too_short() {
        assert!(!m("j?hn", "jhn"));
    }

    #[test]
    fn glob_question_no_match_too_long() {
        assert!(!m("j?hn", "jooohn"));
    }

    #[test]
    fn glob_question_and_star_combined() {
        assert!(m("?ohn*", "john@example.com"));
        assert!(!m("?ohn*", "ohn@example.com"));
    }

    // ── Glob — case insensitivity ────────────────────────────────────────────

    #[test]
    fn glob_case_insensitive_query() {
        assert!(m("JOHN*", "john@example.com"));
    }

    #[test]
    fn glob_case_insensitive_field() {
        assert!(m("*@acme.com", "ALICE@ACME.COM"));
    }

    // ── matches_any ──────────────────────────────────────────────────────────

    #[test]
    fn matches_any_hits_first_field() {
        let q = SearchQuery::compile("john");
        assert!(q.matches_any(&["john@example.com", "Alice"]));
    }

    #[test]
    fn matches_any_hits_second_field() {
        let q = SearchQuery::compile("alice");
        assert!(q.matches_any(&["john@example.com", "Alice Smith"]));
    }

    #[test]
    fn matches_any_no_match() {
        let q = SearchQuery::compile("xyz");
        assert!(!q.matches_any(&["john@example.com", "Alice Smith"]));
    }

    #[test]
    fn matches_any_empty_slice_is_false() {
        let q = SearchQuery::compile("john");
        assert!(!q.matches_any(&[]));
    }

    #[test]
    fn match_all_on_empty_slice_is_false() {
        let q = SearchQuery::compile("");
        assert!(!q.matches_any(&[]));
    }
}
