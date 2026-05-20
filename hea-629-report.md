# Full UX Sweep — Hearth Admin UI

**Scope:** http://localhost:8420/ui, logged in as `seed@example.com` (Admin).
**Method:** Manual exploration via headless browser (Playwright). Captured page snapshots, console errors, network responses, and screenshots across the dashboard, account, admin (users/realms/audit/yaml editor), per-realm (overview/users/permissions/roles/permission-check), and login surfaces.

## P0 — Site-wide blockers

### 1. CSP blocks Google Fonts, breaking mandatory typography
- **Pages:** every page in `/ui` and `/ui/admin`.
- **Symptom:** console repeats `Refused to load the stylesheet 'https://fonts.googleapis.com/css2?family=Fraunces…&family=Manrope…&family=JetBrains+Mono…' because it violates the following Content Security Policy directive: "style-src 'self' 'unsafe-inline'"`. The page therefore falls back to the system sans/serif/mono stack.
- **Impact:** the entire theme contract in `docs/specs/THEME.md` (Fraunces display, Manrope body, JetBrains Mono code) is silently broken in production-style configs. Branding looks generic and inconsistent with the marketing surfaces.
- **Remediation:** either (a) self-host the three fonts under `src/protocol/web/assets/fonts/` and ship `@font-face` rules in `app.css` (preferred — removes a third-party dependency from the auth hot path); or (b) extend CSP `style-src`/`font-src` to include `https://fonts.googleapis.com` and `https://fonts.gstatic.com`. Self-hosting also fixes air-gapped deployments.

### 2. CSP blocks every inline `<script>` — Alpine.js components silently dead
- **Pages observed broken:** `/ui/login`, `/ui/account`, `/ui/admin/audit`, every per-realm "Permission check" form, the Config Editor.
- **Symptom:** console fires `Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net"` despite `'unsafe-inline'` being declared — because a `'nonce-…'` or `'strict-dynamic'` is also present, browsers drop `'unsafe-inline'`. So every page that ships an inline `x-data="…"` initialiser or `Alpine.data(...)` registration loses Alpine entirely.
- **Impact:** the audit filter panel, permission-check tester, password show/hide toggle, yaml-editor visual/raw tabs, and several form validators all become no-ops. The user sees the markup but interaction silently fails.
- **Remediation:** stop relying on inline scripts. Move every `Alpine.data` registration into a hashed/served file (e.g. `assets/admin.js`) and add it to `script-src` via SRI hash, **or** emit per-request nonces and stamp them onto every inline `<script>` tag the server renders. Do not just add `'unsafe-inline'` — that defeats CSP.

### 3. Alpine.js loaded from third-party CDN
- **Page:** every admin page (`<script src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.9/dist/cdn.min.js" defer>`).
- **Impact:** breaks air-gapped installs, leaks the admin's IP to jsDelivr on every page view, and creates a supply-chain pivot for an identity server. Inappropriate for a security product.
- **Remediation:** vendor Alpine into `src/protocol/web/assets/vendor/alpine.min.js`, serve from `'self'`, and add an SRI hash. Drop `cdn.jsdelivr.net` from CSP entirely.

## P1 — Information architecture & navigation

### 4. Dashboard cards all link to the same place
- **Page:** `/ui/admin` ("Welcome back, Seed Admin").
- **Symptom:** "Realms", "Users", "Permissions", "Roles", "Sessions" cards all navigate to `/ui/admin/realms`. Permissions/Roles are realm-scoped under the new RBAC model, so the dashboard cannot actually deep-link to a global list — but the cards pretend it can.
- **Remediation:** either (a) make the cards aggregate links that show "X realms / Y users across all realms" and click through to the realm list (current default behaviour) with hover copy that explains the scope, or (b) replace Permissions/Roles/Sessions tiles with realm-pick affordances ("Pick a realm to manage permissions…"). Today the cards just look broken.

### 5. Empty-state copy is inconsistent
- **Page:** `/ui/admin/realms/customer-portal/users` shows a Manrope-styled "No users yet" panel with a Create button. `/ui/admin/realms/new-portal/applications` shows a bare `<p>No applications.</p>` with no CTA. `/ui/admin/realms/new-portal/identity-providers` shows "No identity providers configured." again with no CTA, even though "Add provider" is the obvious next step.
- **Remediation:** adopt the dashed-border empty-state card pattern from Users on every list (Applications, Identity Providers, Scopes, Roles), with a primary CTA button and one-sentence guidance.

### 6. Realm overview "Quick links" is just three plain blue links
- **Page:** `/ui/admin/realms/{realm}`.
- **Symptom:** "Quick links" section is a `<ul>` of `<a>`s in browser-default blue, no icons, no spacing, no card treatment.
- **Remediation:** convert into the same icon-tile pattern used on the global dashboard so navigation is visually consistent.

### 7. Side nav doesn't indicate active page or current realm
- **Pages:** all `/ui/admin/realms/{realm}/*` pages.
- **Symptom:** secondary nav (Overview / Users / Applications / Identity providers / Roles / Permissions / Scopes / Permission check) does not mark the current item; nothing in the chrome reminds the operator which realm they're inside until they read the breadcrumb.
- **Remediation:** add `aria-current="page"` styling (border-left or ember underline) on the active item; add a persistent "Realm: customer-portal" pill in the top bar.

### 8. Breadcrumbs missing entirely on several admin pages
- **Pages:** `/ui/admin/audit`, `/ui/admin/realms`, `/ui/admin/users`, `/ui/admin/config-editor`.
- **Symptom:** there is no Home → Admin → … trail; only the page H1.
- **Remediation:** ship the same breadcrumb component used elsewhere on every `/ui/admin/*` route.

## P1 — Forms & data display

### 9. No password strength meter and no client-side validation on "New user"
- **Page:** `/ui/admin/realms/{realm}/users/new`.
- **Symptom:** form has Email, First/Last/Display name, Initial password textboxes. No required-field markers, no `aria-required`, no client-side email format check, no password rules surfaced, no strength meter.
- **Impact:** the user can submit blanks and only learn the server's rules from a 400 response. For an identity product where password complexity is part of the value prop, this is a glaring miss.
- **Remediation:** add explicit `*` markers and `aria-required="true"`, an inline email regex check, surface the configured password policy text below the password input, and add a strength meter (zxcvbn or built-in scoring) — Alpine.js components already exist for this pattern in the account-password change form.

### 10. Audit log table renders raw JSON metadata
- **Page:** `/ui/admin/audit`.
- **Symptom:** "metadata" column shows `{"realm_id":"…","actor_role":"admin"}` literally. No formatting, no truncation, no popover. On narrow viewports the column overflows and pushes other columns out.
- **Remediation:** render metadata as compact pill list (`realm_id: …` `actor_role: admin`) with a "details" disclosure that opens a JSON pretty-print drawer. Truncate to 2 keys + count.

### 11. Date/time formatting is inconsistent
- **Pages:** Audit log shows `2026-05-19T22:48:13.512Z`. Realms list shows `May 19, 2026`. Account page shows `2026-05-19 22:48`. Session list (when present) shows epoch seconds.
- **Remediation:** standardise on `2026-05-19 22:48 UTC` (or relative "3 minutes ago" with absolute tooltip) everywhere. A single `format_timestamp()` helper in the templates module should be the only path.

### 12. Audit filters submit synchronously and lose scroll position
- **Page:** `/ui/admin/audit`.
- **Symptom:** changing the "Actor" filter triggers a full page reload (because Alpine is broken — see #2). Scroll jumps to top. There is no loading indicator.
- **Remediation:** restore the Alpine-driven filter (after #2 is fixed) so the table refreshes in place with an HTMX-style swap; surface a 200 ms-debounced spinner in the table header.

### 13. Config Editor first paint is blank
- **Page:** `/ui/admin/config-editor`.
- **Symptom:** the heading "YAML Configuration Editor" is the only visible element on initial paint; the visual/raw tab body is empty until JS finishes. With CSP killing inline scripts (see #2) it stays empty indefinitely.
- **Remediation:** server-side render the initial YAML body (raw view as the SSR default), then hydrate to the tabbed Alpine component when JS attaches. This is also good for users with JS disabled.

## P2 — Visual polish

### 14. Primary text colour drift
- **Symptom:** several pages render headers in pure `#ffffff` (browser default for `<h1>` with no rule) instead of the mandated `graphite-50 (#f5f1e8)`. Most obvious on the Audit log and login pages, where the H1 looks colder than the body copy and breaks the warm-paper feel of the theme.
- **Remediation:** add `text-graphite-50` to the base typography layer in `ui/input.css` so it cascades to every h1/h2/h3.

### 15. Ember gradient appears multiple times on the dashboard
- **Page:** `/ui/admin`.
- **Symptom:** every metric card has a thin ember-coloured border accent, and the "Open audit log" button also uses the ember gradient. THEME.md mandates ember-gradient at most once per visible region.
- **Remediation:** keep the ember gradient on the single primary CTA per region (e.g. "View audit" or the H1 underline), demote all other accents to `border-white/6` + `text-graphite-300`.

### 16. Inputs default to browser-grey instead of theme tokens
- **Pages:** login form, "New user" form, permission-check form.
- **Symptom:** `<input>` borders, focus rings, and placeholder colour are browser default. Buttons get the theme but inputs do not.
- **Remediation:** add a `.input` utility in `ui/input.css` styling border (`border-white/6`), background (`bg-graphite-900/60`), focus ring (ember at 30 % alpha), placeholder (`text-graphite-400`), and apply it to every text/email/password input through a small template helper.

### 17. Buttons use mixed verbs and casing
- **Examples:** "Create user", "New Realm", "Add provider", "Save Configuration", "Delete realm". Casing flips between Sentence case and Title Case; verb choice flips between Create/New/Add.
- **Remediation:** pick one (recommend Sentence case with the verb "Create" for primary creation, "Add" only for many-to-many assignments) and sweep the templates.

## P2 — Accessibility

### 18. Form fields lack visible labels or rely on placeholder alone
- **Pages:** login form (`Email`, `Password` are labels-by-placeholder), permission-check form (subject/object/relation use only placeholders).
- **Remediation:** add explicit `<label for>` elements above each field with `text-graphite-300 text-sm`. Placeholders should be example values, not field names.

### 19. No skip-to-content link, no landmark roles on the side nav
- **Symptom:** screen-reader users have to tab through the entire top bar + side nav on every navigation.
- **Remediation:** add a visually-hidden "Skip to content" anchor at the top of `templates/ui/_layout.html`, and wrap the side nav in `<nav aria-label="Admin">`.

### 20. Focus ring invisible on dark backgrounds
- **Symptom:** default browser focus outline is barely visible against `graphite-900`. Keyboard navigation is effectively blind.
- **Remediation:** add `focus-visible:ring-2 focus-visible:ring-ember-400 focus-visible:ring-offset-2 focus-visible:ring-offset-graphite-900` to all interactive elements.

## Evidence

Screenshots attached (saved in repo root, ready for upload):
- `hea-629-01-dashboard.png` — main dashboard
- `hea-629-02-account.png` — `/ui/account`
- `hea-629-03-admin-users.png` — global Users list
- `hea-629-04-realms.png` — realms list
- `hea-629-05-realm-overview.png` — per-realm overview
- `hea-629-06-realm-users-empty.png` — empty Users state in `customer-portal`
- `hea-629-07-audit.png` — audit log (showing raw JSON column + ISO timestamps)
- `hea-629-08-config-editor.png` — blank Config Editor first paint

Console errors captured across pages (representative sample):
- `Refused to load the stylesheet 'https://fonts.googleapis.com/css2?…'` (every page)
- `Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net"` (login, account, audit, permission-check, config-editor)
- `Alpine Expression Error: Cannot read properties of undefined (reading 'open')` (audit filter panel, downstream of #2)

## Known gaps in this sweep (not yet audited)

Recommend a follow-up child issue:
- Per-realm **Scopes** create/edit forms.
- **User detail / edit** (`/ui/admin/realms/{realm}/users/{id}`) including credential reset, MFA reset, lock/unlock actions.
- **Application detail / edit** including secret-rotation UX.
- **Identity provider** "new" and "edit" forms (OIDC vs SAML).
- **TOTP enrollment** (`/ui/account/totp`) and **active sessions** (`/ui/account/sessions`).
- **Forgot password / password reset** flow end-to-end.
- **Dev mailcatcher** at `/dev/mail` (look-and-feel only; this is a dev surface, low priority).
- **Mobile/narrow-viewport** behaviour — entire sweep so far was at 1280×900.

## Verdict

**FAIL.** Three site-wide P0 issues (CSP killing fonts, CSP killing inline scripts, and Alpine loaded from a third-party CDN on a security product) gate everything else. The dashboard cards, inconsistent empty states, raw-JSON audit metadata, and missing form validation are individually small but compound into an admin UX that feels unfinished. The good news: most fixes are narrow (CSP header + a self-hosted fonts/Alpine bundle + a styled-input utility class will resolve roughly half the list). Recommend handing this report to a frontend coder with the P0 items first.
