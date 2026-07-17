# Content Security Policy — Design Rationale

> **Status:** Migration complete (HEA-850, HEA-1049, HEA-1757).  
> **Last reviewed:** 2026-07-17 (HEA-1757 — `object-src` and `form-action` pinned)  
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
base-uri    'self';
object-src  'none';
form-action 'self'
```

Both `'unsafe-eval'` and `'unsafe-inline'` have been removed. Alpine.js was the
original reason they existed; it was replaced first by Hyperscript (HEA-850), then
Hyperscript itself was replaced by vanilla JS components (HEA-1049). The policy has
been strict throughout all three generations.

`object-src 'none'` prevents plugin-based execution vectors (Flash, Java applets).
`form-action 'self'` prevents a cross-site request forgery variant where a crafted
page submits an HTML form to Hearth's authenticated endpoints — combined with CSRF
tokens on state-changing forms, this provides defense-in-depth.

## Prior gaps (now resolved)

### GAP-4: `unsafe-eval`

**Previously required by:** Alpine.js v3 evaluated directive expressions
(`x-show="open"`, `:class="…"`) via `new Function()`.

**Resolution (HEA-850 → HEA-1049):** Alpine removed; Hyperscript subsequently also
removed. All interactivity is now vanilla JS via `data-component` attributes backed
by `components.js`. Layout managers (SidebarManager, RealmNav, ToastManager) live
in `admin.js`. No `eval()` or `new Function()` anywhere in the stack.

### GAP-5: `unsafe-inline` on `style-src`

**Previously required by:** Alpine injected inline `style="display: none;"`
attributes for `x-show`/`x-cloak` toggling.

**Resolution (HEA-850 → HEA-1049):** Visibility is controlled via CSS class toggling
(`.hidden`) in both the Hyperscript era and the current `components.js` era.
No inline style injection occurs.

## Migration summary

All Alpine.js usage across ~40 templates was replaced across HEA-824 child issues:

| Category | Issue | Status |
|---|---|---|
| CSS-only patterns (tooltips) | HEA-824 | Done |
| Simple toggle / modal dialogs | HEA-847 | Done |
| Complex components (config editor, WebAuthn) | HEA-848, HEA-849 | Done |
| WebAuthn passkey flows | HEA-849 | Done (SecurityAuditor reviewed) |
| Layout, remaining tabs, password strength | HEA-850 | Done |
| Hyperscript removed → vanilla JS `components.js` | HEA-1049 | Done |
| `object-src 'none'` and `form-action 'self'` pinned | HEA-1757 | Done |

## Alternatives considered

| Option | Trade-off |
|---|---|
| Alpine CSP build | Requires registering every directive expression as a named JS function; same effort as plain JS rewrite |
| Nonces | Per-request nonce injection into every template and `admin.js`; adds complexity |
| Hash-based CSP | Only applies to static inline scripts/styles, not Alpine expressions |

## References

- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- `src/protocol/web/security.rs` — policy implementation
- `src/protocol/web/assets/admin.js` — layout managers (SidebarManager, RealmNav, ToastManager)
- `src/protocol/web/assets/components.js` — vanilla JS `data-component` UI components
