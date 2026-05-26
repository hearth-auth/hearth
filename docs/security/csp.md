# Content Security Policy — Design Rationale

> **Status:** Migration complete (HEA-850).  
> **Last reviewed:** 2026-05-26 (HEA-850)  
> **Implemented in:** `src/protocol/web/security.rs`

## Current policy

```
default-src 'self';
script-src  'self';
style-src   'self';
font-src    'self';
img-src     'self' data:;
connect-src 'self';
frame-ancestors 'none';
base-uri    'self'
```

Both `'unsafe-eval'` and `'unsafe-inline'` have been removed. Alpine.js was the
sole reason they existed; it has been fully replaced by HTMX + Hyperscript (HEA-850).

## Prior gaps (now resolved)

### GAP-4: `unsafe-eval`

**Previously required by:** Alpine.js v3 evaluated directive expressions
(`x-show="open"`, `:class="…"`) via `new Function()`.

**Resolution (HEA-850):** Alpine removed. Layout reactivity (sidebar, realm nav,
toasts, realm pill) is handled by vanilla JS classes in `admin.js`. Template
interactions use Hyperscript `_="..."` attributes, which are interpreted by the
library's own parser — no `eval()` or `new Function()` involved.

### GAP-5: `unsafe-inline` on `style-src`

**Previously required by:** Alpine injected inline `style="display: none;"`
attributes for `x-show`/`x-cloak` toggling.

**Resolution (HEA-850):** Hyperscript uses CSS class toggling (`.hidden`) instead
of inline styles. No inline style injection occurs.

## Migration summary

All Alpine.js usage across ~40 templates was replaced across HEA-824 child issues:

| Category | Issue | Status |
|---|---|---|
| CSS-only patterns (tooltips) | HEA-824 | Done |
| Simple toggle / modal dialogs | HEA-847 | Done |
| Complex components (config editor, WebAuthn) | HEA-848, HEA-849 | Done |
| WebAuthn passkey flows | HEA-849 | Done (SecurityAuditor reviewed) |
| Layout, remaining tabs, password strength | HEA-850 | Done |

## Alternatives considered

| Option | Trade-off |
|---|---|
| Alpine CSP build | Requires registering every directive expression as a named JS function; same effort as plain JS rewrite |
| Nonces | Per-request nonce injection into every template and `admin.js`; adds complexity |
| Hash-based CSP | Only applies to static inline scripts/styles, not Alpine expressions |

## References

- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [Hyperscript](https://hyperscript.org) — eval-free; directive strings parsed by its own interpreter.
- `src/protocol/web/security.rs` — policy implementation
- `src/protocol/web/assets/admin.js` — vanilla JS layout managers (SidebarManager, RealmNav, ToastManager)
