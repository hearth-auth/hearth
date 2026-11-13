# Admin Table Search and Sort

**Audience:** operators and administrators finding, filtering, and navigating records in the Hearth admin UI or via the Admin REST API.

The users table in the admin UI and the `GET /admin/users` REST endpoint share the same search grammar. Every query tests a user's **email address** and **display name** — a user is returned when either field satisfies the query.

All comparisons are **case-insensitive**: `ALICE`, `Alice`, and `alice` match identically.

---

## Search Grammar

Queries are classified at compile time based on syntax, not field type.

| Query form | Example | Behaviour |
|---|---|---|
| Empty | `""` | **Match-all guard** — skips filtering; returns all users |
| 1 or 2 characters | `j`, `jo` | **Email prefix** — the email starts with the text (users table only, see below) |
| Plain text | `john` | **Substring** — field contains the literal anywhere |
| Quoted string | `"john@acme.com"` | **Exact** — whole-field equality (not a substring) |
| Contains `*` or `?` | `john*`, `*@acme.com`, `a?z` | **Glob** — anchored whole-field pattern match |

### Match-all guard

An empty query (after trimming leading/trailing whitespace) skips filtering and returns all users. On the other admin tables (realms, organizations, groups, webhooks), a query shorter than 2 characters also returns all rows.

### Email prefix (users table)

On the users table, a query of 1 or 2 characters with no wildcard and no quotes matches the users whose **email starts with** the text. It does not search the display name. The search reads the email index, so it does not read every user record of the realm.

```
j    → "john@acme.com", "jane@test.com"   (not "Bob Jones")
jo   → "john@acme.com", "joe@test.com"
```

### How the users table searches (search index)

The users table and `GET /admin/users` search with a **search index** of each user's email and display name: the index holds every 3-character run (a *trigram*) of the lowercased text. A search reads only the users whose index entry holds every trigram of the query, and then checks each of these users against the query. So the results and the `total` are exact, and a search reads about as many user records as it has candidates, not the whole realm.

- A user write puts its change in a queue; a background task adds it to the index, normally within 1 second. A search also reads the users in this queue, so a search finds a user directly after the write.
- A glob needs at least **3 characters in a row** (`*smith*`, `j?hn@acme*`), or must **start with a character** that is not a wildcard (`jo*`). Any other glob (for example `*a*` or `?b*`) is **too broad** for the index: the admin UI shows a message and no users, and the REST endpoint returns `400`. A glob of stars only (`*`, `**`) matches every user.

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
*a*             → users table: refused as too broad (no 3 characters in a row, no start)
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
| `sort` | `email`, `name`, `status`, `created` | `email` | Column to sort by; with no sort, the users table is in email order |
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

The `GET /admin/users` endpoint accepts a `search` parameter that uses the same grammar described above, with the same email-prefix rule for 1 or 2 characters. Results are in email order.

```bash
# Substring — all users whose email or name contains "acme"
GET /admin/users?search=acme

# Exact — one specific user
GET /admin/users?search="alice@acme.com"

# Glob — all users at acme.com
GET /admin/users?search=*@acme.com
```

An empty `search` returns an empty result. A glob that is too broad for the search index returns `400`.

Column sorting (`sort`, `dir`) is not currently available on the REST endpoint. Apply sort client-side, or use the admin UI for sorted exports.

---

## Search + Sort + Pagination

Sort applies to the **entire filtered result set** before the page slice is taken. On the users table, up to 10,000 matches are sorted in memory; with more matches, the search reads the sort index of the column in order and keeps the matches until the page is full. Consequences:

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
