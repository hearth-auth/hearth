//! Named UI themes for the Hearth admin UI.
//!
//! Each theme is a small CSS block that overrides `--ht-*` CSS custom
//! properties declared in `ui/input.css`. The semantic Tailwind tokens
//! (`ht-surface-*`, `ht-content-*`, etc.) read these variables at runtime,
//! so swapping the CSS block is sufficient to change the entire UI palette.
//!
//! Every call returns a non-empty `:root { … }` block — even ember. That way
//! `GET /ui/static/theme.css` always serves a complete palette independent of
//! whatever order the base `app.css` loads in, and operators are never staring
//! at an empty response body when debugging theming.

/// All valid theme names accepted by `branding.theme` in `hearth.yaml`.
pub const VALID_THEMES: &[&str] = &["ember", "ocean", "midnight", "forest", "cloud", "slate"];

/// Returns the CSS override block for the given theme name.
///
/// Always returns a non-empty `:root { … }` block. Unknown names fall back
/// to the ember palette.
#[must_use]
pub fn theme_css(name: &str) -> &'static str {
    match name {
        "ocean" => OCEAN,
        "midnight" => MIDNIGHT,
        "forest" => FOREST,
        "cloud" => CLOUD,
        "slate" => SLATE,
        _ => EMBER,
    }
}

// ---------------------------------------------------------------------------
// Operator-supplied custom CSS (`branding.custom_css`, `realms.*.web.custom_css`)
// ---------------------------------------------------------------------------

/// Largest operator-supplied custom CSS file Hearth will load and serve.
///
/// The bytes are held resident in [`super::WebState::theme_css`] for the life
/// of the process and returned verbatim to every unauthenticated client that
/// asks for `GET /ui/static/theme.css`, so an unbounded file is both a memory
/// and a bandwidth amplifier. 256 KiB is roughly four times the size of
/// Hearth's own minified `app.css`.
pub const MAX_CUSTOM_CSS_BYTES: u64 = 256 * 1024;

/// Why an operator-supplied custom CSS file was refused.
///
/// `branding.custom_css` names a path that Hearth reads at startup and then
/// serves, raw, to unauthenticated clients. A typo, a shell glob that resolved
/// to the wrong file, or a copied deployment template can point it at a
/// private key, an `.env` file or `/etc/passwd`, and nothing downstream
/// inspects the bytes (audit 2026-08-28 §4.23#12). These variants are the
/// reasons a candidate file is not treated as a stylesheet.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CustomCssError {
    /// The path does not resolve to a readable regular file.
    NotAFile,
    /// The filename does not end in `.css`.
    WrongExtension,
    /// The file is larger than [`MAX_CUSTOM_CSS_BYTES`].
    TooLarge {
        /// Actual size on disk, in bytes.
        bytes: u64,
    },
    /// The bytes are not valid UTF-8, so they are not a stylesheet.
    NotUtf8,
    /// The bytes decoded but do not look like CSS.
    NotCss {
        /// Short, non-sensitive explanation of which check failed.
        reason: &'static str,
    },
    /// The file could not be read.
    Io(String),
}

impl std::fmt::Display for CustomCssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAFile => write!(f, "not found or not a regular file"),
            Self::WrongExtension => write!(f, "filename must end in `.css`"),
            Self::TooLarge { bytes } => write!(
                f,
                "file is {bytes} bytes; the limit is {MAX_CUSTOM_CSS_BYTES} bytes"
            ),
            Self::NotUtf8 => write!(f, "file is not valid UTF-8, so it is not a stylesheet"),
            Self::NotCss { reason } => write!(f, "file does not look like CSS: {reason}"),
            Self::Io(e) => write!(f, "could not be read: {e}"),
        }
    }
}

impl std::error::Error for CustomCssError {}

/// Reads and validates an operator-supplied custom CSS file.
///
/// Applied to `branding.custom_css` and every `realms.<name>.web.custom_css`
/// before the bytes are composed into the response served at
/// `GET /ui/static/theme.css` and `GET /ui/static/realm-theme/{id}`.
///
/// Four gates, in order: the path must be a regular file, the filename must
/// end in `.css`, the file must be at most [`MAX_CUSTOM_CSS_BYTES`], and the
/// decoded text must pass [`validate_custom_css_text`].
///
/// # Errors
///
/// Returns the [`CustomCssError`] naming the first gate that refused.
pub fn load_custom_css(path: &str) -> Result<String, CustomCssError> {
    let meta = std::fs::metadata(path).map_err(|_| CustomCssError::NotAFile)?;
    if !meta.is_file() {
        return Err(CustomCssError::NotAFile);
    }
    if !has_css_extension(path) {
        return Err(CustomCssError::WrongExtension);
    }
    if meta.len() > MAX_CUSTOM_CSS_BYTES {
        return Err(CustomCssError::TooLarge { bytes: meta.len() });
    }
    let bytes = std::fs::read(path).map_err(|e| CustomCssError::Io(e.to_string()))?;
    // Re-check after the read: the file can grow between `metadata` and `read`.
    let len = bytes.len() as u64;
    if len > MAX_CUSTOM_CSS_BYTES {
        return Err(CustomCssError::TooLarge { bytes: len });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| CustomCssError::NotUtf8)?;
    validate_custom_css_text(text)?;
    Ok(text.to_string())
}

/// Returns `true` when `path`'s filename ends in `.css`, case-insensitively.
fn has_css_extension(path: &str) -> bool {
    std::path::Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("css"))
}

/// Content-shape check for decoded custom CSS.
///
/// A stylesheet that is not empty once comments and whitespace are stripped
/// must contain a declaration block, and must not contain control characters
/// or markup. `/etc/passwd`, a PEM private key and an `.env` file all fail the
/// brace test; a binary fails the control-character test; an HTML page fails
/// the markup test.
///
/// # Errors
///
/// Returns [`CustomCssError::NotCss`] naming the check that refused.
pub fn validate_custom_css_text(text: &str) -> Result<(), CustomCssError> {
    if text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\u{c}'))
    {
        return Err(CustomCssError::NotCss {
            reason: "contains control characters",
        });
    }
    // `<!`, `</` and `<?` never appear in CSS and are the opening bytes of
    // HTML, XML and SVG documents.
    for marker in ["<!", "</", "<?"] {
        if text.contains(marker) {
            return Err(CustomCssError::NotCss {
                reason: "contains markup",
            });
        }
    }
    let stripped = strip_css_comments(text);
    if stripped.trim().is_empty() {
        // Comments and whitespace only — nothing to serve, nothing to leak.
        return Ok(());
    }
    if !(stripped.contains('{') && stripped.contains('}')) {
        return Err(CustomCssError::NotCss {
            reason: "no declaration block",
        });
    }
    Ok(())
}

/// Removes `/* … */` comments so the declaration-block test measures real CSS.
///
/// An unterminated comment swallows the rest of the file, which is the same
/// thing a CSS parser does.
fn strip_css_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Theme constants
// ---------------------------------------------------------------------------

/// Ember (default dark theme). Must mirror the `:root` block in
/// `ui/input.css` so that `theme.css` alone is sufficient to establish the
/// full palette even if `app.css` hasn't loaded yet.
const EMBER: &str = r":root {
  --ht-surface-base:     #141418;
  --ht-surface-raised:   #0e0e12;
  --ht-surface-elevated: #1f1f27;
  --ht-surface-input:    #1f1f27;
  --ht-content-primary:   #f5f1e8;
  --ht-content-secondary: #a8a39a;
  --ht-content-muted:     #8a8a94;  /* WCAG AA 4.79:1 on #1f1f27 */
  --ht-content-brand:     #f5b544;
  --ht-content-on-brand:  #0e0e12;
  --ht-divider: #ffffff;
  --ht-brand-from: #f5b544;
  --ht-brand-via:  #e8743b;
  --ht-brand-deep: #a8321f;
  --ht-teal-bg:    #0f2825;
  --ht-teal-fg:    #7ac4b8;
  --ht-violet-bg:  #1d1a2e;
  --ht-violet-fg:  #b0a5d4;
  --ht-rose-bg:    #2a1920;
  --ht-rose-fg:    #e5a3aa;
  --ht-steel-bg:   #1a2332;
  --ht-steel-fg:   #8fa8c9;
}";

/// Ocean — dark teal/cyan accent.
const OCEAN: &str = r":root {
  --ht-content-brand:  #0d9488;
  --ht-brand-from:     #0d9488;
  --ht-brand-via:      #0891b2;
  --ht-brand-deep:     #0e7490;
}";

/// Midnight — dark violet/purple accent.
const MIDNIGHT: &str = r":root {
  --ht-content-brand:  #7c3aed;
  --ht-brand-from:     #7c3aed;
  --ht-brand-via:      #6d28d9;
  --ht-brand-deep:     #4c1d95;
}";

/// Forest — dark emerald/green accent.
const FOREST: &str = r":root {
  --ht-content-brand:  #059669;
  --ht-brand-from:     #059669;
  --ht-brand-via:      #047857;
  --ht-brand-deep:     #065f46;
}";

/// Cloud — light theme with blue accent.
const CLOUD: &str = r":root {
  --ht-surface-base:     #e8ebf4;
  --ht-surface-raised:   #f8faff;
  --ht-surface-elevated: #dae0ee;
  --ht-surface-input:    #f8faff;
  --ht-content-primary:  #0e0e12;
  --ht-content-secondary:#444450;
  --ht-content-muted:    #888894;
  --ht-content-brand:    #2563eb;
  --ht-content-on-brand: #ffffff;
  --ht-divider:          #000000;
  --ht-brand-from:       #3b82f6;
  --ht-brand-via:        #2563eb;
  --ht-brand-deep:       #1d4ed8;
  /* Accent ramp overrides for light background */
  --ht-teal-bg:   #ccfbf1;
  --ht-teal-fg:   #0d9488;
  --ht-violet-bg: #ede9fe;
  --ht-violet-fg: #6d28d9;
  --ht-rose-bg:   #ffe4e6;
  --ht-rose-fg:   #be123c;
  --ht-steel-bg:  #dbeafe;
  --ht-steel-fg:  #1d4ed8;
}";

/// Slate — light theme with cool blue-gray surfaces and steel-blue brand accent.
const SLATE: &str = r":root {
  --ht-surface-base:     #e4e8ee;
  --ht-surface-raised:   #f4f6f9;
  --ht-surface-elevated: #d8dde6;
  --ht-surface-input:    #f4f6f9;
  --ht-content-primary:  #0f1923;
  --ht-content-secondary:#3a4a5c;
  --ht-content-muted:    #6b7d90;
  --ht-content-brand:    #1e4d8c;
  --ht-content-on-brand: #ffffff;
  --ht-divider:          #000000;
  --ht-brand-from:       #2563eb;
  --ht-brand-via:        #1d4ed8;
  --ht-brand-deep:       #1e40af;
  /* Accent ramp overrides for light background */
  --ht-teal-bg:   #ccfbf1;
  --ht-teal-fg:   #0d9488;
  --ht-violet-bg: #ede9fe;
  --ht-violet-fg: #6d28d9;
  --ht-rose-bg:   #ffe4e6;
  --ht-rose-fg:   #be123c;
  --ht-steel-bg:  #dbeafe;
  --ht-steel-fg:  #1d4ed8;
}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ember_returns_root_block() {
        let css = theme_css("ember");
        assert!(css.starts_with(":root {"));
        assert!(css.contains("--ht-surface-base"));
    }

    #[test]
    fn empty_string_falls_back_to_ember() {
        assert_eq!(theme_css(""), theme_css("ember"));
    }

    #[test]
    fn unknown_name_falls_back_to_ember() {
        assert_eq!(theme_css("neon-banana"), theme_css("ember"));
    }

    #[test]
    fn every_valid_theme_emits_root_block() {
        for &name in VALID_THEMES {
            let css = theme_css(name);
            assert!(
                css.contains(":root {") && css.contains("--ht-"),
                "theme {name:?} did not emit a :root block with --ht- vars"
            );
        }
    }

    // -------------------------------------------------------------------
    // 21.13 (audit 2026-08-28 §4.23#12): `branding.custom_css` names a file
    // whose raw bytes are served to unauthenticated clients at
    // `GET /ui/static/theme.css`. Before this, `std::fs::read_to_string`
    // was the only gate: any size, any content type.
    // -------------------------------------------------------------------

    fn write_temp(name: &str, contents: &[u8]) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        std::fs::write(&path, contents).expect("write temp file");
        let as_str = path.to_str().expect("utf-8 temp path").to_string();
        (dir, as_str)
    }

    #[test]
    fn custom_css_accepts_a_real_stylesheet() {
        let (_dir, path) = write_temp("brand.css", b":root { --ht-content-brand: #abcdef; }\n");
        let css = load_custom_css(&path).expect("valid stylesheet must load");
        assert!(css.contains("--ht-content-brand"));
    }

    #[test]
    fn custom_css_rejects_a_file_over_the_size_cap() {
        let oversize = usize::try_from(MAX_CUSTOM_CSS_BYTES).expect("cap fits usize") + 1;
        let mut body = Vec::with_capacity(oversize);
        body.extend_from_slice(b"a { b: c; }");
        body.resize(oversize, b' ');
        let (_dir, path) = write_temp("huge.css", &body);
        assert!(
            matches!(load_custom_css(&path), Err(CustomCssError::TooLarge { .. })),
            "a file over {MAX_CUSTOM_CSS_BYTES} bytes must not be served to anonymous clients"
        );
    }

    #[test]
    fn custom_css_rejects_a_non_css_extension() {
        let (_dir, path) = write_temp("secrets.env", b"API_KEY=hunter2\n");
        assert_eq!(load_custom_css(&path), Err(CustomCssError::WrongExtension));
    }

    #[test]
    fn custom_css_rejects_a_secret_file_renamed_to_css() {
        // The extension gate alone is bypassed by a symlink or a rename, so
        // the content must be checked too. A passwd file, a PEM key and a
        // dotenv all lack a declaration block.
        for body in [
            &b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                [..],
            &b"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----\n"[..],
            &b"HEARTH_AUTH__TOKEN__SIGNING_KEY=abc123\n"[..],
        ] {
            let (_dir, path) = write_temp("theme.css", body);
            assert!(
                matches!(load_custom_css(&path), Err(CustomCssError::NotCss { .. })),
                "a non-stylesheet must not be served at /ui/static/theme.css"
            );
        }
    }

    #[test]
    fn custom_css_rejects_binary_and_markup() {
        let (_dir, bin) = write_temp("blob.css", &[0x7f, 0x45, 0x4c, 0x46, 0x02, 0x00, 0x00]);
        assert!(matches!(
            load_custom_css(&bin),
            Err(CustomCssError::NotCss { .. } | CustomCssError::NotUtf8)
        ));

        let (_dir2, html) = write_temp("page.css", b"<!DOCTYPE html><html><body>{}</body></html>");
        assert!(matches!(
            load_custom_css(&html),
            Err(CustomCssError::NotCss { .. })
        ));
    }

    #[test]
    fn custom_css_rejects_a_missing_path() {
        assert_eq!(
            load_custom_css("/nonexistent/hearth/brand.css"),
            Err(CustomCssError::NotAFile)
        );
    }

    #[test]
    fn custom_css_allows_media_query_range_syntax() {
        // Media Queries Level 4 range syntax puts `<` in legitimate CSS. The
        // markup check must not turn that into a rejection.
        let (_dir, path) = write_temp(
            "range.css",
            b"@media (400px <= width <= 700px) { :root { --ht-divider: #fff; } }",
        );
        assert!(load_custom_css(&path).is_ok());
    }

    #[test]
    fn custom_css_allows_a_comment_only_file() {
        let (_dir, path) = write_temp("notes.css", b"/* intentionally blank for now */\n");
        assert_eq!(
            load_custom_css(&path).expect("comment-only file is not a leak"),
            "/* intentionally blank for now */\n"
        );
    }

    #[test]
    fn valid_themes_contains_expected_names() {
        assert!(VALID_THEMES.contains(&"ember"));
        assert!(VALID_THEMES.contains(&"ocean"));
        assert!(VALID_THEMES.contains(&"midnight"));
        assert!(VALID_THEMES.contains(&"forest"));
        assert!(VALID_THEMES.contains(&"cloud"));
        assert!(VALID_THEMES.contains(&"slate"));
        assert_eq!(VALID_THEMES.len(), 6);
    }
}
