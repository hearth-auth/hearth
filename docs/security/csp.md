# Content Security Policy — Design Rationale

> **Status:** Risk accepted / migration in progress.  
> **Last reviewed:** 2026-05-26 (HEA-824)  
> **Implemented in:** `src/protocol/web/security.rs`

## Current policy

```
default-src 'self';
script-src  'self' 'unsafe-eval';
style-src   'self' 'unsafe-inline';
font-src    'self';
img-src     'self' data:;
connect-src 'self';
frame-ancestors 'none';
base-uri    'self'
```

## Gap: `unsafe-eval` (GAP-4)

Alpine.js v3 evaluates directive expressions (`x-show="open"`, `:class="…"`,
`@click="handler()"`) via `new Function()` at runtime, which requires
`unsafe-eval` in `script-src`.

`unsafe-eval` means a successful XSS attacker who can inject a script can also
call `eval()` / `new Function()` without the CSP blocking them. The practical
risk is very low because:

1. **eval() is not the entry point.** An attacker first needs a reflected or
   stored XSS vector. Hearth's output is rendered by Askama (compiled templates)
   and all user-supplied content is HTML-escaped by default; server-side template
   injection is not possible.
2. **All scripts are first-party.** `script-src 'self'` blocks all external JS
   origins. No CDN, no third-party analytics, no injected `<script src="…">`.
3. **Admin surface only.** The majority of Alpine usage is on authenticated admin
   pages, which require a valid session. An XSS on an admin page presupposes the
   attacker already has admin access or can forge a session — which is a much
   larger breach than eval bypass.
4. **No sensitive data in eval scope.** The Alpine directives operate on UI state
   (`open: false`, `confirm: false`). No passwords, tokens, or PII are passed
   into directive expressions.

Severity from audit: **Low**. Exploitability: **Very Low** (requires a separate
XSS entry point first).

### Accepted risk

The Alpine.js `unsafe-eval` dependency is a known, documented limitation.
It is not a critical or high severity finding and is acceptable while the
migration to HTMX + Hyperscript is in progress. See [HEA-824](/HEA/issues/HEA-824)
for tracking.

## Gap: `unsafe-inline` on `style-src`

Alpine adds inline `style="display: none;"` attributes for `x-show`/`x-cloak`
toggling. This requires `'unsafe-inline'` on `style-src`.

Inline styles carry much lower risk than inline scripts — they cannot exfiltrate
data or execute code. The main risk is CSS injection for visual defacement, which
is an extremely limited attack surface in an admin-authenticated UI.

This gap is also resolved as part of the Alpine → Hyperscript migration, since
Hyperscript uses CSS class toggling instead of inline styles.

## Migration path (option b)

The goal is to remove both `unsafe-eval` and `unsafe-inline` from `script-src`
and `style-src` respectively, by replacing Alpine.js with HTMX + Hyperscript.

Alpine is used in approximately 40 templates and 10 registered components.
The migration is tracked in child issues of [HEA-824](/HEA/issues/HEA-824):

| Category | Status |
|---|---|
| CSS-only patterns (tooltips) | Done ([HEA-824](/HEA/issues/HEA-824)) |
| Simple toggle / modal dialogs | In progress |
| Confirm-then-submit patterns | In progress |
| Settings config editor | Pending |
| WebAuthn components (security-sensitive) | Pending — requires SecurityAuditor sign-off |
| User import wizard, bulk actions | Pending |
| Password strength meter | Pending |

Once all Alpine usage is removed, `src/protocol/web/security.rs` will be updated
to:

```
script-src 'self';
style-src  'self';
```

## Alternatives considered

| Option | Trade-off |
|---|---|
| Alpine CSP build | Requires registering every directive expression as a named JS function; effectively the same effort as rewriting in plain JS |
| Nonces | Requires per-request nonce injection into every template and into `admin.js`; adds complexity without eliminating Alpine's need for eval |
| Hash-based CSP | Only applies to static inline scripts/styles, not to Alpine expressions |
| Accept + document (this file) | Zero code change, closes audit finding for Low/Very-Low severity gap; appropriate while migration is in progress |

## References

- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Alpine.js CSP limitations](https://alpinejs.dev/advanced/csp) — Alpine has a CSP-compatible build but it requires all expressions to be pre-registered as functions, which requires the same refactoring effort as a full migration.
- [Hyperscript](https://hyperscript.org) — does not use `eval()` or `new Function()`; directive strings are interpreted by the library's own parser/evaluator.
- `src/protocol/web/security.rs` — policy implementation
- `src/protocol/web/assets/admin.js` — Alpine component registrations
