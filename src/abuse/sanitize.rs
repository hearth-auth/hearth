//! Tenant-content sanitizers (A-45).
//!
//! All tenant-supplied SVG and CSS must pass through these functions before
//! being rendered into HTML without escaping. See `openspec/specs/abuse-prevention/spec.md` §A-45.
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
//! Splits the CSS into statements and blocks. Declarations whose lowercased
//! content matches any entry in [`CSS_DANGEROUS_PATTERNS`] are dropped, a rule
//! whose selector or prelude matches is dropped whole, and `@import` rules are
//! dropped — they could load external sheets containing arbitrary content.
//! The output always has balanced braces.

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

    // fail-closed: a parse error anywhere discards everything written so far.
    loop {
        let Ok(event) = reader.read_event_into(&mut buf) else {
            return String::new();
        };
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
/// Works at the **statement level** rather than line by line, so a single
/// dangerous declaration inside a multi-declaration `:root {}` block is dropped
/// without discarding its safe siblings. `;`, `{` and `}` inside comments,
/// quoted strings and parentheses (`url(data:…;base64,…)`) do not split
/// statements.
///
/// Dropped:
/// - Any declaration or statement containing a pattern from
///   [`CSS_DANGEROUS_PATTERNS`], and every `@import` rule.
/// - Any rule or at-rule whose selector or prelude contains such a pattern,
///   **whole**: its block, nested blocks and closing `}` go with it.
///
/// The output always has balanced braces: a stray `}` is dropped, a block left
/// open at end of input is closed, and trailing text that would carry a brace
/// is dropped. Everything else, including `@media`, `@keyframes`, `:root {}`
/// blocks and `--ht-*` custom properties, is kept as written.
#[must_use]
pub fn sanitize_css(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    // Text of the current statement, selector or prelude.
    let mut buf = String::new();
    // One entry per open block: `true` when its contents are emitted.
    let mut blocks: Vec<bool> = Vec::new();
    // Open blocks being dropped (a dropped block drops everything inside it).
    let mut dropped_depth: usize = 0;
    let mut scan = CssScan::default();

    for ch in input.chars() {
        if !scan.is_structural(ch) {
            buf.push(ch);
            continue;
        }
        match ch {
            ';' => {
                buf.push(';');
                if dropped_depth == 0 && css_statement_is_safe(&buf) {
                    output.push_str(&buf);
                }
                buf.clear();
            }
            '{' => {
                if dropped_depth == 0 && css_statement_is_safe(&buf) {
                    output.push_str(&buf);
                    output.push('{');
                    blocks.push(true);
                } else {
                    dropped_depth += 1;
                    blocks.push(false);
                }
                buf.clear();
            }
            // '}'
            _ => {
                match blocks.pop() {
                    Some(true) => {
                        if css_statement_is_safe(&buf) {
                            output.push_str(&buf);
                        }
                        output.push('}');
                    }
                    Some(false) => dropped_depth -= 1,
                    // A stray `}` closes nothing; keep the text before it.
                    None => {
                        if css_statement_is_safe(&buf) {
                            output.push_str(&buf);
                        }
                    }
                }
                buf.clear();
            }
        }
    }

    // Trailing text with no terminator. Text the scanner never released (an
    // unclosed string, comment or parenthesis) may hide a brace, so it is
    // kept only when it carries none.
    if dropped_depth == 0 && !buf.contains(['{', '}']) && css_statement_is_safe(&buf) {
        output.push_str(&buf);
    }
    // Close every emitted block still open.
    let still_open = blocks.iter().filter(|kept| **kept).count();
    output.extend(std::iter::repeat_n('}', still_open));

    output
}

/// Lexical state that decides whether `;`, `{` and `}` are structural.
#[derive(Default)]
struct CssScan {
    /// Inside `/* … */`.
    in_comment: bool,
    /// Inside a quoted string: the quote character.
    quote: Option<char>,
    /// The previous character was a backslash inside a string.
    escaped: bool,
    /// Nesting depth of `(`.
    parens: u32,
    /// The previous character (for `/*` and `*/`).
    prev: char,
}

impl CssScan {
    /// Advances over `ch` and returns `true` when it is a structural `;`,
    /// `{` or `}` (outside comments, strings and parentheses).
    fn is_structural(&mut self, ch: char) -> bool {
        let prev = std::mem::replace(&mut self.prev, ch);
        if self.in_comment {
            if prev == '*' && ch == '/' {
                self.in_comment = false;
                // `*/` must not also open a comment with a following `*`.
                self.prev = '\0';
            }
            return false;
        }
        if let Some(q) = self.quote {
            if self.escaped {
                self.escaped = false;
            } else if ch == '\\' {
                self.escaped = true;
            } else if ch == q || ch == '\n' {
                self.quote = None;
            }
            return false;
        }
        match ch {
            '*' if prev == '/' => {
                self.in_comment = true;
                false
            }
            '"' | '\'' => {
                self.quote = Some(ch);
                false
            }
            '(' => {
                self.parens = self.parens.saturating_add(1);
                false
            }
            ')' => {
                self.parens = self.parens.saturating_sub(1);
                false
            }
            ';' | '{' | '}' => self.parens == 0,
            _ => false,
        }
    }
}

/// `true` when a CSS statement, selector or prelude may be emitted: it is not
/// an `@import` rule and contains no [`CSS_DANGEROUS_PATTERNS`] entry, with
/// comments removed so `expr/**/ession(` is caught too.
fn css_statement_is_safe(text: &str) -> bool {
    let lower = strip_css_comments(text).to_ascii_lowercase();
    !lower.trim_start().starts_with("@import")
        && !CSS_DANGEROUS_PATTERNS.iter().any(|p| lower.contains(p))
}

/// Removes `/* … */` comments; an unterminated comment runs to the end.
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
