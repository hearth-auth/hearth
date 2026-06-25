# Authoring Conventions

Internal reference for contributors writing documentation for the Hearth docs site. This file (prefixed `_`) is excluded from rendered output — it does not appear in the sidebar or search index.

---

## Admonitions

Use admonition blocks for asides that are **important enough to interrupt reading flow** but not long enough to warrant a dedicated section. Admonitions work in both `.md` and `.mdx` files — no import needed.

### Types and when to use them

| Type | When to use |
|------|-------------|
| `:::note` | Scope clarifications, prerequisites, cross-references. Neutral in tone. |
| `:::tip` | Shortcuts, performance hints, runnable examples, "you can also…" patterns. |
| `:::warning` | Production gotchas, security caveats, data-loss risks. Reader should pause before proceeding. |
| `:::danger` | Irreversible or destructive operations. Use sparingly — one per doc maximum. |
| `:::info` | Background context. Prefer `:::note` unless the content is long-form explanation. |

### Syntax

```
:::warning[Production note]
This endpoint returns `404 Not Found` outside `--dev` mode.
:::
```

Titles are optional. Use them when the default type name ("Note", "Warning") is too generic. Good examples: `:::warning[Production note]`, `:::tip[JWKS caching]`, `:::note[Scope of this guide]`.

### What NOT to use admonitions for

- Long reference tables — keep those in the surrounding prose.
- More than two admonitions per major section — if content needs that many interruptions, restructure the prose.
- `:::info` for things that are actually warnings. Choose the severity that matches the consequence.
- Decorative asides with no actionable content.

---

## Tabs

Use `<Tabs>` when the **same procedure has parallel but non-identical steps** across multiple languages, runtimes, or platforms — and the reader only needs one path.

**Do not use Tabs for:**
- Content that is language-agnostic (use a single code block).
- More than 6 tab options (too wide; reorganise into subsections instead).
- Sequential steps within one language (use numbered headings).

### File type requirement

Tabs require MDX. If the file ends in `.md`, rename it to `.mdx`. Admonitions work in both `.md` and `.mdx` without renaming.

### Canonical tab order

When offering SDK or language tabs, always use this order (omit languages the guide does not cover):

1. **TypeScript** — label: `TypeScript`
2. **Go** — label: `Go`
3. **Python** — label: `Python`
4. **PHP** — label: `PHP`
5. **Rust** — label: `Rust`
6. **curl** — label: `curl` (lowercase; for raw HTTP examples)

### Import

Place imports immediately after front matter (if any), at the top of the file:

```mdx
import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';
```

### Markup

```mdx
<Tabs groupId="lang">
  <TabItem value="ts" label="TypeScript" default>

  ```ts
  // TypeScript example
  ```

  </TabItem>
  <TabItem value="go" label="Go">

  ```go
  // Go example
  ```

  </TabItem>
  <TabItem value="curl" label="curl">

  ```bash
  # curl example
  ```

  </TabItem>
</Tabs>
```

Use `groupId="lang"` so Docusaurus syncs the selected tab across all tab groups on the page that share the same `groupId`. The `default` prop marks the tab selected on first render — put it on the first `<TabItem>`.

### Option-A constraint: raw-readable prose

Docs source files live in `docs/guides/` and are read directly on GitHub. Every tabbed block **must be preceded and followed by language-agnostic prose** that summarises the intent. A reader viewing raw `.mdx` on GitHub sees JSX markup; the surrounding prose keeps the document useful without a rendered output.

Required pattern:

```text
Describe what the following examples do in one sentence.

<Tabs groupId="lang">…</Tabs>

Note what all paths have in common — shared return type, shared
precondition, or next step.
```

Do **not** open a section with a bare `<Tabs>` block. The intro sentence and closing summary are mandatory.

---

## Code blocks

- Always specify a language tag: ` ```ts`, ` ```go`, ` ```bash`, ` ```yaml`, ` ```json`, ` ```rust`.
- Use ` ```bash` for shell commands (not ` ```sh` or ` ```shell`).
- Use ` ```text` for output that is not valid code.
- Languages registered in `docusaurus.config.js`: `rust`, `bash`, `toml`, `yaml`, `json`, `protobuf`.
- Placeholder values use angle brackets: `<realm-id>`, `<access-token>`, `<your-client-id>`. Never embed real credentials.
