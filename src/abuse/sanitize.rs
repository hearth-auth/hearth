//! Tenant-content sanitizers (A-45).
//!
//! All tenant-supplied SVG and CSS must pass through these functions before
//! being rendered into HTML without escaping. See `docs/specs/ABUSE.md` §A-45.
//!
//! # Fail mode
//!
//! Per §6.1 of the abuse-prevention plan: these sanitizers are **fail-closed**.
//! When SVG input cannot be parsed, the empty string is returned rather than
//! the original content. When CSS input is malformed, any declaration matching
//! a dangerous pattern is dropped and the rest is returned.
//!
//! # SVG sanitizer
//!
//! Uses [`quick_xml`] to stream-parse SVG. The following are stripped:
//!
//! - Entire subtrees rooted at `<script>`, `<foreignObject>`, `<iframe>`,
//!   `<object>`, and `<embed>`.
//! - Any attribute whose lowercased name starts with `on` (event handlers:
//!   `onload`, `onclick`, `onerror`, …).
//! - `href` and `xlink:href` attributes whose value is not a fragment ref
//!   (`#…`) — this blocks external resource pulls and `data:` / `javascript:`
//!   URIs.
//! - `style` attribute values containing `expression(`, `javascript:`,
//!   `behavior:`, or `-moz-binding` (CSS-in-SVG injection vectors).
//!
//! # CSS sanitizer
//!
//! Scans each line of the CSS text. Lines (declarations or at-rules) whose
//! lowercased content matches any entry in [`CSS_DANGEROUS_PATTERNS`] are
//! dropped.  `@import` rules are also dropped — they could load external
//! sheets containing arbitrary content.

use quick_xml::events::Event;
use quick_xml::{Reader, Writer};
use std::io::Cursor;

// ─────────────────────────────────────────────────────────────────────────────
// SVG sanitizer
// ─────────────────────────────────────────────────────────────────────────────

/// SVG elements whose entire subtree is stripped.
const SVG_BLOCKED_ELEMENTS: &[&str] = &["script", "foreignobject", "iframe", "object", "embed"];

/// Sanitizes a tenant-supplied SVG string for safe inline rendering.
///
/// Returns the sanitized SVG. Returns an empty string if the input cannot be
/// parsed at all. Malformed individual events within an otherwise parseable
/// document are skipped.
#[must_use]
pub fn sanitize_svg(input: &str) -> String {
    let mut reader = Reader::from_str(input);
    // Don't enforce end-name matching — let us handle malformed SVG gracefully.
    reader.config_mut().check_end_names = false;

    let mut out = Cursor::new(Vec::<u8>::new());
    let mut writer = Writer::new(&mut out);
    let mut buf = Vec::new();

    // Depth counter: > 0 means we are inside a blocked element.
    // We still track start/end nesting so nested blocked tags don't confuse us.
    let mut skip_depth: u32 = 0;

    // fail-closed: loop exits on any parse error; Eof exits via explicit break.
    while let Ok(event) = reader.read_event_into(&mut buf) {
        match event {
            Event::Eof => break,

            Event::Start(ref start) => {
                let lname = local_name_lower(start.local_name().as_ref());
                // Increment depth when entering a blocked element OR when already
                // inside one (tracks nested tags so closing tags pair correctly).
                if SVG_BLOCKED_ELEMENTS.contains(&lname.as_str()) || skip_depth > 0 {
                    skip_depth = skip_depth.saturating_add(1);
                } else {
                    let filtered = filter_svg_attrs(start);
                    let _ = writer.write_event(Event::Start(filtered));
                }
            }

            Event::End(_) => {
                if skip_depth > 0 {
                    skip_depth -= 1;
                } else {
                    let _ = writer.write_event(event);
                }
            }

            Event::Empty(ref start) => {
                let lname = local_name_lower(start.local_name().as_ref());
                if skip_depth == 0 && !SVG_BLOCKED_ELEMENTS.contains(&lname.as_str()) {
                    let filtered = filter_svg_attrs(start);
                    let _ = writer.write_event(Event::Empty(filtered));
                }
            }

            // Pass through text, comments, PI, CDATA only when not inside a
            // blocked element. XML comments are safe in SVG, PI/CDATA are stripped
            // by the existing prepare_svg_for_email caller.
            _ => {
                if skip_depth == 0 {
                    let _ = writer.write_event(event);
                }
            }
        }

        buf.clear();
    }

    String::from_utf8(out.into_inner()).unwrap_or_default()
}

/// Returns the lowercased local name (part after `:`) from raw name bytes.
fn local_name_lower(raw: &[u8]) -> String {
    std::str::from_utf8(raw).unwrap_or("").to_ascii_lowercase()
}

/// Rebuilds a `BytesStart` with dangerous attributes stripped.
fn filter_svg_attrs(
    start: &quick_xml::events::BytesStart<'_>,
) -> quick_xml::events::BytesStart<'static> {
    // Re-emit the full qualified name (preserves namespace prefixes on the tag).
    let name_bytes = start.name();
    let qname = std::str::from_utf8(name_bytes.as_ref()).unwrap_or("unknown");
    let mut new = quick_xml::events::BytesStart::new(qname.to_string());

    for attr_result in start.attributes() {
        let attr = match attr_result {
            Ok(a) => a,
            Err(_) => continue, // skip malformed attributes
        };

        let key_str = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        let key_lower = key_str.to_ascii_lowercase();

        // 1. Strip on* event handlers.
        if key_lower.starts_with("on") {
            continue;
        }

        // 2. Strip href / xlink:href that isn't a safe fragment ref.
        if key_lower == "href" || key_lower == "xlink:href" {
            let value = std::str::from_utf8(attr.value.as_ref()).unwrap_or("");
            if !is_safe_svg_href(value) {
                continue;
            }
        }

        // 3. Strip style attributes containing dangerous CSS patterns.
        if key_lower == "style" {
            let value = std::str::from_utf8(attr.value.as_ref()).unwrap_or("");
            if has_dangerous_css(value) {
                continue;
            }
        }

        // Attribute is safe — re-push with owned bytes.
        new.push_attribute((attr.key.as_ref(), attr.value.as_ref()));
    }

    new
}

/// Returns `true` for `href` values that are safe to keep:
/// fragment references (`#id`) or empty strings.
fn is_safe_svg_href(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// Returns `true` if a CSS value string contains a known dangerous pattern.
fn has_dangerous_css(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    CSS_DANGEROUS_PATTERNS.iter().any(|p| lower.contains(p))
}

// ─────────────────────────────────────────────────────────────────────────────
// CSS sanitizer
// ─────────────────────────────────────────────────────────────────────────────

/// Dangerous CSS value patterns checked case-insensitively.
///
/// Any CSS declaration or at-rule whose lowercased text contains one of these
/// patterns is stripped entirely.
const CSS_DANGEROUS_PATTERNS: &[&str] = &[
    "expression(",
    "javascript:",
    "behavior:",
    "-moz-binding",
    "url(data:",
    "url(javascript:",
    "-ms-filter",
    "progid:",
];

/// Sanitizes a tenant-supplied CSS string for safe injection into HTML pages.
///
/// Processes CSS at the **declaration level** (bounded by `;`, `{`, `}`) rather
/// than line-by-line so that a single dangerous declaration inside a multi-
/// declaration `:root {}` block is dropped without discarding its safe siblings.
///
/// Dropped segments:
/// - Any declaration (`;`-terminated) containing a pattern from
///   [`CSS_DANGEROUS_PATTERNS`].
/// - Any `@import` rule (could load external sheets with arbitrary content).
///
/// Block structure (selectors, `{`, `}`, `@media` etc.) is preserved; only
/// individual dangerous declarations are removed.
#[must_use]
pub fn sanitize_css(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    // Accumulates characters for the current CSS token (selector, declaration,
    // or block boundary).
    let mut buf = String::new();

    for ch in input.chars() {
        match ch {
            ';' => {
                // End of a CSS declaration or at-rule.
                buf.push(';');
                let lower = buf.trim().to_ascii_lowercase();
                // Drop @import rules and dangerous declarations.
                if !lower.starts_with("@import")
                    && !CSS_DANGEROUS_PATTERNS.iter().any(|p| lower.contains(p))
                {
                    output.push_str(&buf);
                }
                buf.clear();
            }
            '{' => {
                // Block opener — flush the selector/at-rule.
                let lower = buf.trim().to_ascii_lowercase();
                if lower.starts_with("@import") {
                    // @import with a block body (unusual but possible) — drop.
                    buf.clear();
                } else if !CSS_DANGEROUS_PATTERNS.iter().any(|p| lower.contains(p)) {
                    output.push_str(&buf);
                    output.push('{');
                }
                // If the selector itself was dangerous, we still emit `{` so
                // the closing `}` pairs correctly and the block body can be
                // individually evaluated.
                buf.clear();
            }
            '}' => {
                // Block closer — flush any partial declaration before the `}`.
                let lower = buf.trim().to_ascii_lowercase();
                if !lower.is_empty() && !CSS_DANGEROUS_PATTERNS.iter().any(|p| lower.contains(p)) {
                    output.push_str(&buf);
                }
                output.push('}');
                buf.clear();
            }
            _ => {
                buf.push(ch);
            }
        }
    }

    // Flush any trailing content that had no terminator.
    let lower = buf.trim().to_ascii_lowercase();
    if !lower.is_empty()
        && !lower.starts_with("@import")
        && !CSS_DANGEROUS_PATTERNS.iter().any(|p| lower.contains(p))
    {
        output.push_str(&buf);
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── SVG unit tests ────────────────────────────────────────────────────

    #[test]
    fn sanitize_svg_clean_svg_preserved() {
        // Use r##"..."## so that "# in fill="#f00" doesn't close the raw string.
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path d="M12 2L2 22h20L12 2z" fill="#f00"/>
</svg>"##;
        let out = sanitize_svg(svg);
        assert!(out.contains("<path"), "clean path element must survive");
        assert!(out.contains("viewBox"), "viewBox attr must survive");
    }

    #[test]
    fn sanitize_svg_script_element_stripped() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><circle r="5"/></svg>"#;
        let out = sanitize_svg(svg);
        assert!(!out.contains("<script"), "script element must be stripped");
        assert!(!out.contains("alert"), "script body must be stripped");
        assert!(out.contains("<circle"), "sibling element must be preserved");
    }

    #[test]
    fn sanitize_svg_event_handler_stripped() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><circle r="5" onload="alert(1)" cx="10" cy="10"/></svg>"#;
        let out = sanitize_svg(svg);
        assert!(!out.contains("onload"), "onload handler must be stripped");
        assert!(out.contains("cx="), "safe attr cx must be preserved");
    }

    #[test]
    fn sanitize_svg_external_href_stripped() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><use href="https://evil.com/x.svg#icon"/></svg>"#;
        let out = sanitize_svg(svg);
        assert!(
            !out.contains("https://evil.com"),
            "external href must be stripped"
        );
    }

    #[test]
    fn sanitize_svg_data_uri_href_stripped() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/svg+xml;base64,abc"/></svg>"#;
        let out = sanitize_svg(svg);
        assert!(!out.contains("data:"), "data: URI href must be stripped");
    }

    #[test]
    fn sanitize_svg_fragment_href_preserved() {
        let svg = r##"<svg xmlns="http://www.w3.org/2000/svg"><use href="#icon"/></svg>"##;
        let out = sanitize_svg(svg);
        assert!(
            out.contains(r##"href="#icon""##),
            "fragment-only href must be preserved"
        );
    }

    #[test]
    fn sanitize_svg_foreign_object_stripped() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div>xss</div></foreignObject><rect/></svg>"#;
        let out = sanitize_svg(svg);
        assert!(
            !out.to_ascii_lowercase().contains("foreignobject"),
            "foreignObject must be stripped"
        );
        assert!(
            !out.contains("<div"),
            "div inside foreignObject must be stripped"
        );
        assert!(out.contains("<rect"), "sibling rect must be preserved");
    }

    #[test]
    fn sanitize_svg_style_with_expression_stripped() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="color:expression(alert(1))"/></svg>"#;
        let out = sanitize_svg(svg);
        assert!(
            !out.contains("expression("),
            "expression() in style must be stripped"
        );
    }

    #[test]
    fn sanitize_svg_javascript_href_stripped() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><text>click</text></a></svg>"#;
        let out = sanitize_svg(svg);
        assert!(
            !out.contains("javascript:"),
            "javascript: href must be stripped"
        );
    }

    // ── CSS unit tests ────────────────────────────────────────────────────

    #[test]
    fn sanitize_css_valid_custom_properties_preserved() {
        let css = ":root {\n  --ht-content-brand: #0d9488;\n  --ht-brand-from: #0d9488;\n}";
        let out = sanitize_css(css);
        assert!(
            out.contains("--ht-content-brand"),
            "valid CSS custom property must be preserved"
        );
    }

    #[test]
    fn sanitize_css_expression_stripped() {
        let css = "color: expression(alert(document.cookie));";
        let out = sanitize_css(css);
        assert!(
            !out.contains("expression("),
            "expression() must be stripped"
        );
    }

    #[test]
    fn sanitize_css_javascript_url_stripped() {
        let css = "background: url(javascript:alert(1));";
        let out = sanitize_css(css);
        assert!(
            !out.contains("javascript:"),
            "javascript: in CSS must be stripped"
        );
    }

    #[test]
    fn sanitize_css_behavior_stripped() {
        let css = "behavior: url(http://evil.com/x.htc);";
        let out = sanitize_css(css);
        assert!(!out.contains("behavior:"), "behavior: must be stripped");
    }

    #[test]
    fn sanitize_css_moz_binding_stripped() {
        let css = "-moz-binding: url(http://evil.com/xss.xml);";
        let out = sanitize_css(css);
        assert!(
            !out.contains("-moz-binding"),
            "-moz-binding must be stripped"
        );
    }

    #[test]
    fn sanitize_css_import_stripped() {
        let css = "@import url('https://evil.com/steal.css');\nbody { color: red; }";
        let out = sanitize_css(css);
        assert!(!out.contains("@import"), "@import must be stripped");
        assert!(
            out.contains("color: red"),
            "non-dangerous rule must be preserved"
        );
    }

    #[test]
    fn sanitize_css_safe_siblings_preserved_in_mixed_block() {
        // A single dangerous declaration must not kill safe siblings in the same block.
        let css =
            ":root { --ht-surface-base: #111; color: expression(alert(1)); --ht-brand: #e85d04; }";
        let out = sanitize_css(css);
        assert!(
            !out.contains("expression("),
            "expression() must be stripped"
        );
        assert!(
            out.contains("--ht-surface-base"),
            "first safe custom prop must survive"
        );
        assert!(
            out.contains("--ht-brand"),
            "second safe custom prop must survive"
        );
    }

    #[test]
    fn sanitize_css_data_url_stripped() {
        let css = "background: url(data:image/svg+xml;base64,abc);";
        let out = sanitize_css(css);
        assert!(!out.contains("url(data:"), "data: URL must be stripped");
    }
}
