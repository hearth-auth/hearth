# Admin Table Search and Sort

**Audience:** operators and administrators finding, filtering, and navigating records in the Hearth admin UI or via the Admin REST API.

The users table in the admin UI and the `GET /admin/users` REST endpoint share the same search grammar. Every query tests a user's **email address** and **display name** — a user is returned when either field satisfies the query.

All comparisons are **case-insensitive**: `ALICE`, `Alice`, and `alice` match identically.

---

## Search Grammar

Queries are classified at compile time based on syntax, not field type.

| Query form | Example | Behaviour |
|---|---|---|
| Empty or fewer than 2 characters | `""`, `"j"` | **Match-all guard** — skips filtering; returns all users |
| Plain text | `john` | **Substring** — field contains the literal anywhere |
| Quoted string | `"john@acme.com"` | **Exact** — whole-field equality (not a substring) |
| Contains `*` or `?` | `john*`, `*@acme.com`, `a?z` | **Glob** — anchored whole-field pattern match |

### Match-all guard

Queries shorter than 2 characters (after trimming leading/trailing whitespace) bypass filtering and return all users. This prevents full-table scans caused by a single-keystroke in a live-search input.

### Substring (default)

Plain text with no wildcards and no surrounding quotes performs a **case-insensitive substring search** across email and display name. The query string may appear anywhere within the field.

```
john      → "john@acme.com", "johnny@test.com", "John Smith"
@acme     → everyone whose email contains "@acme"
Smith     → all users whose display name contains "Smith"
```

### Exact match

Wrap the query in **double quotes** to require whole-field equality. The comparison is case-insensitive, but partial matches are rejected — the query must equal the entire field value.

```
"john@acme.com"   → "john@acme.com" ✓   "john@acme.com.br" ✗   "mr.john@acme.com" ✗
"Alice Smith"     → "alice smith"   ✓   "Alice Smithson"   ✗
```

Quoting an empty string (`""`) matches only users whose email or display name is itself empty — typically zero results.

### Glob (wildcard)

Use `*` and `?` to build patterns. Globs are **fully anchored**: the pattern must match the entire field value, not just a substring of it.

| Wildcard | Meaning |
|---|---|
| `*` | Any sequence of characters, including the empty string |
| `?` | Exactly one character |

```
john*           → email starts with "john": "john@acme.com", "johndoe@test.com"
*@acme.com      → email ends with "@acme.com": "alice@acme.com", "bob@acme.com"
j?hn@test.com   → "john@test.com" or "jahn@test.com" (exactly one char between j and hn)
*smith*         → display name contains "Smith" (leading + trailing * make it a substring)
*               → matches every user (bare star; equivalent to the match-all guard)
```

Consecutive wildcards (`**`) are collapsed to a single `*` before matching; `a**z` behaves identically to `a*z`.

---

## Searchable and Sortable Fields — Users Table

| Column | Searched by query | Sortable |
|---|---|---|
| Email | Yes | Yes — `sort=email` |
| Display name | Yes | Yes — `sort=name` |
| Status | No | Yes — `sort=status` |
| Created | No | Yes — `sort=created` |

Search always evaluates both email **and** display name. A user matches if either satisfies the query.

---

## Column Sort (Admin UI)

Click any column header to sort by that column. Clicking the same header a second time reverses direction (ascending → descending → ascending). The sort state is stored in the page URL so links, bookmarks, and browser history preserve the current view.

### URL parameters

| Parameter | Values | Default | Description |
|---|---|---|---|
| `q` | Any string | `""` (match all) | Search query, using the grammar above |
| `sort` | `email`, `name`, `status`, `created` | (unsorted) | Column to sort by; omit to use insertion order |
| `dir` | `asc`, `desc` | `asc` | Sort direction |
| `page` | Positive integer | `1` | 1-based page number |
| `per_page` | `5`, `10`, `25`, `50`, `100` | `25` | Rows per page |

Unknown values for `sort` and `dir` are silently ignored — the server never returns an error for an unrecognised sort column.

**Status sort order:** `Active` → `PendingVerification` → `Disabled`.

**Example URL** — all `@acme.com` users sorted by display name, descending:

```
/ui/admin/realms/my-realm/users?q=*@acme.com&sort=name&dir=desc
```

---

## REST API

The `GET /admin/users` endpoint accepts a `search` parameter that uses the same grammar described above. Pass any of the four forms (match-all guard, substring, exact, glob) and they are interpreted identically to the admin UI search box.

```bash
# Substring — all users whose email or name contains "acme"
GET /admin/users?search=acme

# Exact — one specific user
GET /admin/users?search="alice@acme.com"

# Glob — all users at acme.com
GET /admin/users?search=*@acme.com
```

Queries shorter than 2 characters return an empty result immediately rather than scanning all users.

Column sorting (`sort`, `dir`) is not currently available on the REST endpoint. Apply sort client-side, or use the admin UI for sorted exports.

---

## Search + Sort + Pagination

Sort applies to the **entire filtered result set** before the page slice is taken. Consequences:

- `total` in the response counts all matching users, not the page size.
- Pages are stable — page 2 always contains the second batch in sorted order with no gaps or duplicates.
- Changing sort column or direction on a non-first page returns to page 1 automatically.

**Example — newest `@acme.com` accounts, second page of 25:**

```
/ui/admin/realms/my-realm/users?q=*@acme.com&sort=created&dir=desc&page=2&per_page=25
```

---

## Unicode

Queries and stored fields are both lowercased before comparison using Rust's Unicode case-folding. Searching for `müller` matches a display name of `Müller`.

---

## Keycloak migration reference

| Keycloak admin UI | Hearth equivalent |
|---|---|
| User search box (substring, default) | Plain text query — same default substring behaviour |
| Exact match toggle / `exact` API param | Wrap query in double quotes: `"alice@acme.com"` |
| No wildcard support | Use `*` (any chars) and `?` (one char) in Hearth |
| Sort by Last Name, First Name | `sort=name` sorts by `display_name` — Hearth has no separate first/last sort |
| Sort by Email | `sort=email` |
| Sort by Username | Not applicable — Hearth uses email as the primary identifier |
| Sort by Created Date | `sort=created` |
