//! Environment variable substitution for configuration strings.
//!
//! Replaces `${VAR_NAME}` patterns with the corresponding environment
//! variable values. Supports `${VAR:-default}` syntax for fallback
//! values (matching POSIX shell `:-` semantics).
//!
//! Also provides `.env` file loading via [`load_dotenv`].

use crate::config::error::ConfigError;
use std::path::Path;

/// A warning emitted when an environment variable referenced in the
/// config is missing or empty. Unlike previous behaviour (hard error),
/// warnings allow the server to start and report the issue through
/// tracing + the admin UI.
#[derive(Debug, Clone)]
pub struct EnvVarWarning {
    /// Name of the environment variable.
    pub var_name: String,
    /// What went wrong.
    pub kind: EnvVarWarningKind,
}

/// The flavour of an [`EnvVarWarning`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvVarWarningKind {
    /// The variable is not set in the environment and no default was provided.
    Missing,
    /// The variable is set to an empty string and no default was provided.
    Empty,
    /// The value cannot be spliced into the YAML at that position without
    /// changing the document's structure — a line break inside a
    /// single-quoted string, or a YAML-significant sequence (` #`, `: `, a
    /// line break) in the middle of a longer unquoted value. Nothing is
    /// substituted (GA audit 2026-09-28 OPS-12).
    Unrepresentable,
}

impl EnvVarWarning {
    /// Human-readable label suitable for the admin dashboard.
    #[must_use]
    pub fn kind_label(&self) -> &'static str {
        match self.kind {
            EnvVarWarningKind::Missing => "not set (substituted empty string)",
            EnvVarWarningKind::Empty => "set but empty (possible misconfiguration)",
            EnvVarWarningKind::Unrepresentable => {
                "not substituted: its value cannot be placed there safely — quote the whole \
                 YAML value in double quotes"
            }
        }
    }
}

/// Substitutes `${VAR_NAME}` and `${VAR_NAME:-default}` patterns in the
/// input string with environment variable values.
///
/// # Default syntax
///
/// `${VAR:-fallback}` uses `fallback` when `VAR` is unset **or** empty
/// (matching POSIX shell `:-` semantics). The default value extends to
/// the closing `}` and may contain colons (e.g. `${HOST:-0.0.0.0:8080}`).
/// `${VAR:-}` explicitly defaults to the empty string (no warning).
///
/// # Graceful degradation
///
/// If a variable is missing or empty **and** no default was specified,
/// the function substitutes an empty string and records a warning. This
/// prevents the server from crashing before tracing initialises.
///
/// Literal `${}` sequences (empty variable name) are left unchanged.
///
/// # YAML comments are not substituted (task 26.22)
///
/// The scan used to be a plain character walk with no idea what a comment was,
/// so a `${VAR}` inside a `#` comment was substituted and, when the variable
/// was unset, warned about. `hearth config validate` reported those warnings as
/// errors: `hearth.example.yaml` — which is also what `hearth config example`
/// emits — failed with 22 errors, **20 of them raised by commented-out lines**
/// that document what an operator *could* set.
///
/// A comment runs from an unquoted `#` (at the start of a line, or preceded by
/// whitespace, as YAML requires) to the end of that line. Quote state is
/// tracked across newlines so a `#` inside a multi-line quoted scalar is not
/// mistaken for one.
///
/// # Values are escaped for where they land (GA audit 2026-09-28 OPS-12)
///
/// Values used to be pasted in raw: ` #` in an unquoted secret silently
/// truncated it, a line break could inject keys, and a `"` broke a
/// double-quoted scalar. And the quote tracker toggled on *any* apostrophe, so
/// after `product_name: Brad's` every later comment was scanned as YAML and its
/// `${VAR}` substituted — a hard error in production.
///
/// A quote now opens a quoted scalar only where a scalar begins, and each
/// value is spelled for its context (see [`splice`]):
///
/// * inside `"…"` — escaped (`\"`, `\\`, `\n`, …);
/// * inside `'…'` — `'` doubled; a line break cannot be represented there;
/// * unquoted — spliced raw when that is safe (so `port: ${PORT}` stays a
///   number); otherwise, when the reference is the whole value, emitted as a
///   double-quoted string.
///
/// A value with no safe spelling is not substituted and is reported as
/// [`EnvVarWarningKind::Unrepresentable`].
pub(crate) fn substitute_env_vars(input: &str) -> (String, Vec<EnvVarWarning>) {
    let mut result = String::with_capacity(input.len());
    let mut warnings = Vec::new();
    let mut chars = input.chars().peekable();
    let mut lex = YamlLex::new();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') && lex.substitutes_here() {
            // A reference can be the first thing on a line (block-scalar
            // content included): settle the line's indentation first.
            lex.note_non_space();
            // Where the value lands, fixed before anything is consumed.
            let context = lex.context();
            let at_scalar_start = lex.at_scalar_start();
            let whole_scalar = at_scalar_start && reference_ends_scalar(&chars, lex.flow_depth);
            chars.next(); // the '{'

            let mut raw = String::new();
            let mut found_close = false;
            for c in chars.by_ref() {
                if c == '}' {
                    found_close = true;
                    break;
                }
                raw.push(c);
            }

            if !found_close || raw.is_empty() {
                // Malformed or empty — write through literally.
                let mut literal = String::from("${");
                literal.push_str(&raw);
                if found_close {
                    literal.push('}');
                }
                let mut rest = literal.chars().peekable();
                while let Some(c) = rest.next() {
                    lex.step(c, rest.peek().copied());
                    result.push(c);
                }
                continue;
            }

            let (var_name, default_value) = match raw.find(":-") {
                Some(pos) => (&raw[..pos], Some(&raw[pos + 2..])),
                None => (raw.as_str(), None),
            };
            let value = match std::env::var(var_name) {
                Ok(value) if !value.is_empty() => Some(value),
                Ok(_empty) => default_value.map(str::to_string).or_else(|| {
                    warnings.push(EnvVarWarning {
                        var_name: var_name.to_string(),
                        kind: EnvVarWarningKind::Empty,
                    });
                    None
                }),
                Err(_) => default_value.map(str::to_string).or_else(|| {
                    warnings.push(EnvVarWarning {
                        var_name: var_name.to_string(),
                        kind: EnvVarWarningKind::Missing,
                    });
                    None
                }),
            };
            if let Some(value) = value {
                match splice(
                    &value,
                    context,
                    at_scalar_start,
                    whole_scalar,
                    lex.flow_depth > 0,
                ) {
                    Some(spelled) => result.push_str(&spelled),
                    None => warnings.push(EnvVarWarning {
                        var_name: var_name.to_string(),
                        kind: EnvVarWarningKind::Unrepresentable,
                    }),
                }
            }
            lex.after_substitution(context);
            continue;
        }

        lex.step(ch, chars.peek().copied());
        result.push(ch);
    }

    (result, warnings)
}

/// Where a `${VAR}` reference sits in the YAML.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpliceContext {
    /// An unquoted (plain) scalar, or where one may begin.
    Plain,
    /// Inside `'…'`.
    SingleQuoted,
    /// Inside `"…"`.
    DoubleQuoted,
    /// Inside a `|` / `>` block scalar.
    Block,
}

/// Just enough YAML lexing to know whether a character is in a comment, a
/// quoted scalar, a block scalar, or plain text — and whether a plain scalar
/// begins here (only there does a quote character open a quoted scalar).
#[allow(clippy::struct_excessive_bools)] // independent lexer flags
struct YamlLex {
    quote: Option<SpliceContext>,
    in_comment: bool,
    /// A `#` opens a comment only at the start of a line or after whitespace.
    prev_was_space: bool,
    /// The next non-space character begins a scalar (or a collection).
    scalar_start: bool,
    /// Inside, or just after, a plain or quoted scalar.
    in_plain: bool,
    flow_depth: usize,
    /// Inside `"…"`, the previous character was an unconsumed `\`.
    escape_next: bool,
    /// Inside `'…'`, the previous `'` was the first half of `''`.
    single_escape: bool,
    /// Spaces seen so far at the start of the current line; `None` once a
    /// non-space character has been seen on it.
    leading_spaces: Option<usize>,
    /// Indentation of the current line (fixed at its first non-space).
    line_indent: usize,
    /// A `|` / `>` header on this line: content lines follow.
    block_pending: bool,
    /// While in a block scalar: the indentation of its header line.
    block_parent: Option<usize>,
    /// The current line is block-scalar content.
    in_block_line: bool,
}

impl YamlLex {
    fn new() -> Self {
        Self {
            quote: None,
            in_comment: false,
            prev_was_space: true,
            scalar_start: true,
            in_plain: false,
            flow_depth: 0,
            escape_next: false,
            single_escape: false,
            leading_spaces: Some(0),
            line_indent: 0,
            block_pending: false,
            block_parent: None,
            in_block_line: false,
        }
    }

    /// `${…}` is substituted everywhere except in comments.
    fn substitutes_here(&self) -> bool {
        !self.in_comment
    }

    fn context(&self) -> SpliceContext {
        if self.in_block_line {
            SpliceContext::Block
        } else {
            self.quote.unwrap_or(SpliceContext::Plain)
        }
    }

    fn at_scalar_start(&self) -> bool {
        self.quote.is_none() && !self.in_block_line && self.scalar_start && !self.in_plain
    }

    fn after_substitution(&mut self, context: SpliceContext) {
        if context == SpliceContext::Plain {
            self.scalar_start = false;
            self.in_plain = true;
            self.prev_was_space = false;
        }
        self.note_non_space();
    }

    /// Records that the current line has content, fixing its indentation and
    /// deciding whether it belongs to a block scalar.
    fn note_non_space(&mut self) {
        if let Some(spaces) = self.leading_spaces.take() {
            self.line_indent = spaces;
            if let Some(parent) = self.block_parent {
                if spaces > parent {
                    self.in_block_line = true;
                } else {
                    self.block_parent = None;
                }
            }
        }
    }

    fn newline(&mut self) {
        self.in_comment = false;
        self.prev_was_space = true;
        if self.quote.is_none() {
            self.scalar_start = true;
            self.in_plain = false;
        }
        if self.block_pending {
            self.block_pending = false;
            self.block_parent = Some(self.line_indent);
        }
        self.in_block_line = false;
        self.leading_spaces = Some(0);
    }

    /// Advances over one character that is copied through unchanged.
    fn step(&mut self, ch: char, next: Option<char>) {
        if ch == '\n' {
            self.newline();
            return;
        }
        if let Some(spaces) = self.leading_spaces.as_mut() {
            if ch == ' ' {
                *spaces += 1;
                return;
            }
            self.note_non_space();
        }
        if self.in_comment || self.in_block_line {
            return;
        }
        match self.quote {
            Some(SpliceContext::DoubleQuoted) => {
                if self.escape_next {
                    self.escape_next = false;
                } else if ch == '\\' {
                    self.escape_next = true;
                } else if ch == '"' {
                    self.close_quote();
                }
                return;
            }
            Some(_) => {
                if ch == '\'' {
                    if self.single_escape {
                        self.single_escape = false;
                    } else if next == Some('\'') {
                        self.single_escape = true;
                    } else {
                        self.close_quote();
                    }
                }
                return;
            }
            None => {}
        }
        if ch == '#' && self.prev_was_space {
            self.in_comment = true;
            return;
        }
        if ch.is_whitespace() {
            self.prev_was_space = true;
            return;
        }
        self.prev_was_space = false;
        let next_is_space = next.is_none_or(char::is_whitespace);

        if self.scalar_start && !self.in_plain {
            match ch {
                '\'' => {
                    self.quote = Some(SpliceContext::SingleQuoted);
                    self.scalar_start = false;
                    return;
                }
                '"' => {
                    self.quote = Some(SpliceContext::DoubleQuoted);
                    self.scalar_start = false;
                    return;
                }
                '[' | '{' => {
                    self.flow_depth += 1;
                    return;
                }
                '-' | '?' if next_is_space => return,
                '|' | '>' if self.flow_depth == 0 => {
                    self.block_pending = true;
                    self.scalar_start = false;
                    self.in_plain = true;
                    return;
                }
                _ => {
                    self.scalar_start = false;
                    self.in_plain = true;
                }
            }
        }
        match ch {
            ':' if next_is_space => {
                self.scalar_start = true;
                self.in_plain = false;
            }
            ',' if self.flow_depth > 0 => {
                self.scalar_start = true;
                self.in_plain = false;
            }
            ']' | '}' if self.flow_depth > 0 => {
                self.flow_depth -= 1;
                self.scalar_start = false;
                self.in_plain = true;
            }
            _ => {}
        }
    }

    fn close_quote(&mut self) {
        self.quote = None;
        self.scalar_start = false;
        self.in_plain = true;
    }
}

/// Whether the text after a `${…}` reference ends the scalar — so the
/// reference is the whole value and may be emitted as a quoted string.
fn reference_ends_scalar(
    chars: &std::iter::Peekable<std::str::Chars<'_>>,
    flow_depth: usize,
) -> bool {
    let mut rest = chars.clone();
    rest.next(); // the '{'
    if !rest.by_ref().any(|c| c == '}') {
        return false;
    }
    let mut saw_space = false;
    for c in rest {
        match c {
            ' ' | '\t' => saw_space = true,
            '\n' | '\r' => return true,
            '#' => return saw_space,
            ',' | ']' | '}' => return flow_depth > 0,
            _ => return false,
        }
    }
    true
}

/// Spells `value` for `context`, or returns `None` when no spelling keeps the
/// document's structure.
fn splice(
    value: &str,
    context: SpliceContext,
    at_scalar_start: bool,
    whole_scalar: bool,
    in_flow: bool,
) -> Option<String> {
    match context {
        SpliceContext::DoubleQuoted => Some(escape_double_quoted(value)),
        SpliceContext::SingleQuoted => {
            (!value.chars().any(char::is_control)).then(|| value.replace('\'', "''"))
        }
        SpliceContext::Block => (!value.contains(['\n', '\r'])).then(|| value.to_string()),
        SpliceContext::Plain => {
            if plain_safe(value, at_scalar_start, in_flow) {
                Some(value.to_string())
            } else if whole_scalar {
                Some(format!("\"{}\"", escape_double_quoted(value)))
            } else {
                None
            }
        }
    }
}

/// Whether `value` can be spliced into an unquoted scalar verbatim.
fn plain_safe(value: &str, at_scalar_start: bool, in_flow: bool) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.chars().any(char::is_control)
        || value.contains(": ")
        || value.contains(" #")
        || value.ends_with(':')
        || value.starts_with(char::is_whitespace)
        || value.ends_with(char::is_whitespace)
    {
        return false;
    }
    if in_flow && value.contains([',', '[', ']', '{', '}']) {
        return false;
    }
    if at_scalar_start {
        let indicator = value.starts_with([
            '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@',
            '`',
        ]);
        if indicator || value == "-" || value.starts_with("- ") {
            return false;
        }
    }
    true
}

/// Escapes `value` for the inside of a YAML double-quoted scalar.
fn escape_double_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Loads a `.env` file and injects each `KEY=VALUE` pair into the process
/// environment, **skipping variables that are already set**.
///
/// Silently succeeds if `path` does not exist — a missing `.env` is not an
/// error. Returns an error only for genuine parse failures in an existing file.
///
/// # Format supported
///
/// - `KEY=VALUE` — unquoted; inline comments stripped after ` #`
/// - `KEY="VALUE"` — double-quoted; supports `\n`, `\r`, `\t`, `\\`, `\"`
/// - `KEY='VALUE'` — single-quoted; no escape processing
/// - `export KEY=VALUE` — optional `export` prefix
/// - Lines starting with `#` and blank lines are ignored
///
/// Real environment variables always take precedence: if `KEY` is already set
/// in the process environment it will not be overwritten.
///
/// # Threading
///
/// This function mutates the process environment via [`std::env::set_var`].
/// It must be called before the async runtime starts (i.e., during startup
/// initialization) to avoid concurrent access to the environment.
pub(crate) fn load_dotenv(path: &Path) -> Result<(), ConfigError> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ConfigError::FileRead(e)),
    };

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();

        // Skip blank lines and full-line comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip optional `export` prefix (e.g. `export KEY=VALUE`)
        let line = line
            .strip_prefix("export")
            .and_then(|rest| {
                // Require at least one whitespace after `export`
                let trimmed = rest.trim_start();
                if trimmed.len() < rest.len() {
                    Some(trimmed)
                } else {
                    None
                }
            })
            .unwrap_or(line);

        let eq = line.find('=').ok_or_else(|| ConfigError::DotenvParse {
            line: line_no,
            message: format!("expected KEY=VALUE, got: {line:?}"),
        })?;

        let key = line[..eq].trim_end();
        if key.is_empty() {
            return Err(ConfigError::DotenvParse {
                line: line_no,
                message: "key must not be empty".to_string(),
            });
        }

        let value = parse_dotenv_value(&line[eq + 1..]);

        // Real env vars take precedence; .env only fills gaps
        if std::env::var(key).is_err() {
            std::env::set_var(key, &value);
        }
    }

    Ok(())
}

/// Parses the value portion of a `KEY=VALUE` `.env` line.
fn parse_dotenv_value(raw: &str) -> String {
    // Trim any leading whitespace before the value (e.g. `KEY= "foo"`)
    let s = raw.trim_start();

    if let Some(inner) = s.strip_prefix('"') {
        parse_double_quoted(inner)
    } else if let Some(inner) = s.strip_prefix('\'') {
        // Single-quoted: no escape sequences; content up to the next `'`
        inner
            .split_once('\'')
            .map_or_else(|| inner.to_string(), |(v, _)| v.to_string())
    } else {
        // Unquoted: strip inline comment and trailing whitespace
        strip_inline_comment(s).trim_end().to_string()
    }
}

/// Parses a double-quoted `.env` value, handling common escape sequences.
///
/// Reads characters until the closing `"` is found. Supports `\\`, `\"`,
/// `\n`, `\r`, and `\t`.
fn parse_double_quoted(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('n') => result.push('\n'),
                Some('r') => result.push('\r'),
                Some('t') => result.push('\t'),
                Some(other) => result.push(other),
                None => break,
            },
            other => result.push(other),
        }
    }
    result
}

/// Strips an inline comment from an unquoted `.env` value.
///
/// An inline comment begins at the first ` #` (space followed by `#`).
/// A bare `#` at the very start of the value is also treated as a comment.
fn strip_inline_comment(s: &str) -> &str {
    if s.starts_with('#') {
        return "";
    }
    match s.find(" #") {
        Some(pos) => &s[..pos],
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_var_substitution_in_yaml() {
        std::env::set_var("HEARTH_TEST_DIR", "/tmp/hearth-test");
        let input = "data_dir: ${HEARTH_TEST_DIR}/storage";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "data_dir: /tmp/hearth-test/storage");
        assert!(warnings.is_empty());
        std::env::remove_var("HEARTH_TEST_DIR");
    }

    #[test]
    fn missing_env_var_warns_not_errors() {
        std::env::remove_var("HEARTH_NONEXISTENT_VAR_FOR_TEST");
        let input = "path: ${HEARTH_NONEXISTENT_VAR_FOR_TEST}";
        let (result, warnings) = substitute_env_vars(input);
        // Should substitute empty string, not error
        assert_eq!(result, "path: ");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].var_name, "HEARTH_NONEXISTENT_VAR_FOR_TEST");
        assert_eq!(warnings[0].kind, EnvVarWarningKind::Missing);
    }

    #[test]
    fn empty_env_var_warns() {
        std::env::set_var("HEARTH_EMPTY_VAR_TEST", "");
        let input = "val: ${HEARTH_EMPTY_VAR_TEST}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "val: ");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].var_name, "HEARTH_EMPTY_VAR_TEST");
        assert_eq!(warnings[0].kind, EnvVarWarningKind::Empty);
        std::env::remove_var("HEARTH_EMPTY_VAR_TEST");
    }

    #[test]
    fn no_substitution_when_no_vars() {
        let input = "server:\n  port: 8420\n  bind: 127.0.0.1";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, input);
        assert!(warnings.is_empty());
    }

    #[test]
    fn multiple_vars_substituted() {
        std::env::set_var("HEARTH_TEST_HOST", "0.0.0.0");
        std::env::set_var("HEARTH_TEST_PORT", "9090");
        let input = "host: ${HEARTH_TEST_HOST}\nport: ${HEARTH_TEST_PORT}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "host: 0.0.0.0\nport: 9090");
        assert!(warnings.is_empty());
        std::env::remove_var("HEARTH_TEST_HOST");
        std::env::remove_var("HEARTH_TEST_PORT");
    }

    #[test]
    fn empty_braces_pass_through() {
        let input = "value: ${}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "value: ${}");
        assert!(warnings.is_empty());
    }

    #[test]
    fn unclosed_brace_passes_through() {
        let input = "value: ${UNCLOSED";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "value: ${UNCLOSED");
        assert!(warnings.is_empty());
    }

    #[test]
    fn dollar_without_brace_passes_through() {
        let input = "price: $100";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "price: $100");
        assert!(warnings.is_empty());
    }

    // === ${VAR:-default} tests ===

    #[test]
    fn env_var_with_default_when_unset() {
        std::env::remove_var("HEARTH_DEFAULT_UNSET_TEST");
        let input = "bind: ${HEARTH_DEFAULT_UNSET_TEST:-127.0.0.1}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "bind: 127.0.0.1");
        assert!(warnings.is_empty(), "default should suppress warning");
    }

    #[test]
    fn env_var_with_default_when_set() {
        std::env::set_var("HEARTH_DEFAULT_SET_TEST", "0.0.0.0");
        let input = "bind: ${HEARTH_DEFAULT_SET_TEST:-127.0.0.1}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "bind: 0.0.0.0");
        assert!(warnings.is_empty());
        std::env::remove_var("HEARTH_DEFAULT_SET_TEST");
    }

    #[test]
    fn env_var_with_default_when_empty() {
        std::env::set_var("HEARTH_DEFAULT_EMPTY_TEST", "");
        let input = "bind: ${HEARTH_DEFAULT_EMPTY_TEST:-127.0.0.1}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "bind: 127.0.0.1");
        assert!(
            warnings.is_empty(),
            "empty var with default should not warn"
        );
        std::env::remove_var("HEARTH_DEFAULT_EMPTY_TEST");
    }

    #[test]
    fn env_var_default_containing_colons() {
        std::env::remove_var("HEARTH_COLON_DEFAULT_TEST");
        let input = "addr: ${HEARTH_COLON_DEFAULT_TEST:-host:8080}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "addr: host:8080");
        assert!(warnings.is_empty());
    }

    #[test]
    fn env_var_with_empty_default() {
        std::env::remove_var("HEARTH_EMPTY_DEFAULT_TEST");
        let input = "val: ${HEARTH_EMPTY_DEFAULT_TEST:-}";
        let (result, warnings) = substitute_env_vars(input);
        assert_eq!(result, "val: ");
        assert!(
            warnings.is_empty(),
            "explicit empty default should not warn"
        );
    }

    // === load_dotenv tests ===

    #[test]
    fn dotenv_loads_key_value_pairs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(
            &dotenv,
            "HEARTH_DENV_LOAD_A=hello\nHEARTH_DENV_LOAD_B=world\n",
        )
        .expect("write .env");
        std::env::remove_var("HEARTH_DENV_LOAD_A");
        std::env::remove_var("HEARTH_DENV_LOAD_B");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(std::env::var("HEARTH_DENV_LOAD_A").expect("var A"), "hello");
        assert_eq!(std::env::var("HEARTH_DENV_LOAD_B").expect("var B"), "world");
        std::env::remove_var("HEARTH_DENV_LOAD_A");
        std::env::remove_var("HEARTH_DENV_LOAD_B");
    }

    #[test]
    fn dotenv_does_not_override_existing_env() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "HEARTH_DENV_NO_OVERRIDE=from_file\n").expect("write .env");
        std::env::set_var("HEARTH_DENV_NO_OVERRIDE", "from_env");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_NO_OVERRIDE").expect("env var"),
            "from_env",
            "real env var must not be overwritten by .env"
        );
        std::env::remove_var("HEARTH_DENV_NO_OVERRIDE");
    }

    #[test]
    fn dotenv_skips_comments_and_blank_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(
            &dotenv,
            "# This is a comment\n\nHEARTH_DENV_COMMENT_KEY=value\n# another comment\n",
        )
        .expect("write .env");
        std::env::remove_var("HEARTH_DENV_COMMENT_KEY");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_COMMENT_KEY").expect("env var"),
            "value"
        );
        std::env::remove_var("HEARTH_DENV_COMMENT_KEY");
    }

    #[test]
    fn dotenv_handles_double_quoted_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "HEARTH_DENV_DQ=\" hello world \"\n").expect("write .env");
        std::env::remove_var("HEARTH_DENV_DQ");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_DQ").expect("env var"),
            " hello world "
        );
        std::env::remove_var("HEARTH_DENV_DQ");
    }

    #[test]
    fn dotenv_handles_double_quoted_escapes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, r#"HEARTH_DENV_ESC="line1\nline2\ttab""#).expect("write .env");
        std::env::remove_var("HEARTH_DENV_ESC");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_ESC").expect("var ESC"),
            "line1\nline2\ttab"
        );
        std::env::remove_var("HEARTH_DENV_ESC");
    }

    #[test]
    fn dotenv_handles_single_quoted_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        // Single-quoted: backslashes are literal, no escaping
        std::fs::write(&dotenv, "HEARTH_DENV_SQ='no\\escape'\n").expect("write .env");
        std::env::remove_var("HEARTH_DENV_SQ");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_SQ").expect("env var"),
            r"no\escape"
        );
        std::env::remove_var("HEARTH_DENV_SQ");
    }

    #[test]
    fn dotenv_handles_export_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "export HEARTH_DENV_EXPORT=exported\n").expect("write .env");
        std::env::remove_var("HEARTH_DENV_EXPORT");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_EXPORT").expect("env var"),
            "exported"
        );
        std::env::remove_var("HEARTH_DENV_EXPORT");
    }

    #[test]
    fn dotenv_strips_inline_comments_from_unquoted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "HEARTH_DENV_INLINE=myvalue # this is a comment\n")
            .expect("write .env");
        std::env::remove_var("HEARTH_DENV_INLINE");

        load_dotenv(&dotenv).expect("load_dotenv");

        assert_eq!(
            std::env::var("HEARTH_DENV_INLINE").expect("env var"),
            "myvalue"
        );
        std::env::remove_var("HEARTH_DENV_INLINE");
    }

    #[test]
    fn dotenv_missing_file_is_silently_ignored() {
        let result = load_dotenv(std::path::Path::new("/nonexistent/.env"));
        assert!(result.is_ok(), "missing .env must not be an error");
    }

    #[test]
    fn dotenv_malformed_line_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "GOOD=value\nBAD_LINE_NO_EQUALS\n").expect("write .env");

        let err = load_dotenv(&dotenv).expect_err("malformed line should error");
        let display = format!("{err}");
        assert!(
            display.contains("line 2"),
            "should report line number, got: {display}"
        );
    }

    #[test]
    fn dotenv_empty_key_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dotenv = dir.path().join(".env");
        std::fs::write(&dotenv, "=value\n").expect("write .env");

        let err = load_dotenv(&dotenv).expect_err("empty key should error");
        let display = format!("{err}");
        assert!(display.contains("key must not be empty"), "got: {display}");
    }
}

#[cfg(test)]
mod comment_substitution_tests {
    use super::*;

    /// Task 26.22 — a `${VAR}` inside a YAML comment must be left alone.
    ///
    /// The scan had no idea what a comment was, so commented-out lines that
    /// document what an operator *could* set were substituted and warned about.
    /// `hearth config validate` reports those warnings as errors, so
    /// `hearth.example.yaml` — the file `hearth config example` itself emits —
    /// failed with 22 errors, 20 of them raised by comments.
    #[test]
    fn a_variable_in_a_comment_is_neither_substituted_nor_warned_about() {
        std::env::remove_var("HEARTH_TEST_26_22_UNSET");
        let input =
            "server:\n  # port: ${HEARTH_TEST_26_22_UNSET}\n  bind_address: \"127.0.0.1\"\n";

        let (out, warnings) = substitute_env_vars(input);

        assert_eq!(out, input, "a comment must pass through byte for byte");
        assert!(
            warnings.is_empty(),
            "a commented-out variable is documentation, not configuration: {warnings:?}"
        );
    }

    /// Control — a real value on the same line still substitutes.
    ///
    /// Without this, a change that skipped everything after the first `#`
    /// anywhere would pass the test above while breaking every config that
    /// uses a trailing comment.
    #[test]
    fn a_variable_before_a_trailing_comment_still_substitutes() {
        std::env::set_var("HEARTH_TEST_26_22_SET", "8443");
        let (out, warnings) =
            substitute_env_vars("server:\n  port: ${HEARTH_TEST_26_22_SET}  # the TLS port\n");
        std::env::remove_var("HEARTH_TEST_26_22_SET");

        assert!(
            out.contains("port: 8443"),
            "the value before the comment must still be substituted; got: {out}"
        );
        assert!(out.contains("# the TLS port"), "the comment must survive");
        assert!(warnings.is_empty(), "no warnings expected: {warnings:?}");
    }

    /// Control — a `#` inside a quoted scalar is not a comment.
    ///
    /// Quote state is tracked across newlines for exactly this case; treating
    /// it as a comment would silently stop substituting the rest of the file.
    #[test]
    fn a_hash_inside_a_quoted_value_does_not_open_a_comment() {
        std::env::set_var("HEARTH_TEST_26_22_QUOTED", "indigo");
        let (out, _) = substitute_env_vars(
            "theme:\n  accent: \"#ff0000 is not a comment\"\n  name: ${HEARTH_TEST_26_22_QUOTED}\n",
        );
        std::env::remove_var("HEARTH_TEST_26_22_QUOTED");

        assert!(
            out.contains("name: indigo"),
            "a '#' inside quotes must not stop substitution for the rest of the file; got: {out}"
        );
    }
}

/// GA audit 2026-09-28 OPS-12 — `${VAR}` values were spliced into the YAML
/// raw, and an apostrophe anywhere toggled the quote tracker.
#[cfg(test)]
mod safe_splice_tests {
    use super::*;

    /// Substitutes `input` with `var` = `value`, then parses the result.
    fn parsed(var: &str, value: &str, input: &str) -> (serde_norway::Value, Vec<EnvVarWarning>) {
        std::env::set_var(var, value);
        let (out, warnings) = substitute_env_vars(input);
        std::env::remove_var(var);
        let parsed = serde_norway::from_str(&out)
            .unwrap_or_else(|e| panic!("substituted YAML must parse: {e}\n---\n{out}"));
        (parsed, warnings)
    }

    fn get<'a>(v: &'a serde_norway::Value, key: &str) -> &'a serde_norway::Value {
        v.get(key)
            .unwrap_or_else(|| panic!("missing key {key} in {v:?}"))
    }

    /// `product_name: Brad's` opened a "single-quoted string" that never
    /// closed, so every later comment was scanned as live YAML and its
    /// `${VAR}` substituted — a hard error in production.
    #[test]
    fn an_apostrophe_in_a_plain_scalar_does_not_hide_later_comments() {
        std::env::remove_var("HEARTH_OPS12_UNSET");
        let input = "branding:\n  product_name: Brad's\n  # secret: ${HEARTH_OPS12_UNSET}\n";
        let (out, warnings) = substitute_env_vars(input);
        assert_eq!(out, input);
        assert!(
            warnings.is_empty(),
            "the comment was substituted: {warnings:?}"
        );
    }

    /// ` #` in an unquoted value used to start a comment and truncate the
    /// secret silently.
    #[test]
    fn a_hash_in_an_unquoted_value_is_kept() {
        let (v, warnings) = parsed(
            "HEARTH_OPS12_HASH",
            "abc #def",
            "password: ${HEARTH_OPS12_HASH}\n",
        );
        assert!(warnings.is_empty());
        assert_eq!(get(&v, "password").as_str(), Some("abc #def"));
    }

    /// A newline in a value used to inject new keys.
    #[test]
    fn a_newline_in_a_value_cannot_inject_a_key() {
        let (v, _) = parsed(
            "HEARTH_OPS12_NL",
            "x\nadmin: true",
            "password: ${HEARTH_OPS12_NL}\nother: 1\n",
        );
        assert_eq!(get(&v, "password").as_str(), Some("x\nadmin: true"));
        assert!(v.get("admin").is_none(), "a key was injected: {v:?}");
    }

    /// A `"` or `\` inside a double-quoted scalar used to break it.
    #[test]
    fn double_quoted_values_are_escaped() {
        let (v, warnings) = parsed(
            "HEARTH_OPS12_DQ",
            "a\"b\\c",
            "password: \"${HEARTH_OPS12_DQ}\"\n",
        );
        assert!(warnings.is_empty());
        assert_eq!(get(&v, "password").as_str(), Some("a\"b\\c"));
    }

    #[test]
    fn single_quoted_values_are_escaped() {
        let (v, warnings) = parsed(
            "HEARTH_OPS12_SQ",
            "it's",
            "password: '${HEARTH_OPS12_SQ}'\n",
        );
        assert!(warnings.is_empty());
        assert_eq!(get(&v, "password").as_str(), Some("it's"));
    }

    /// A single-quoted YAML string cannot hold a line break verbatim, and a
    /// value embedded in a longer plain scalar cannot be quoted: both are
    /// refused rather than spliced unsafely.
    #[test]
    fn values_with_no_safe_spelling_are_refused() {
        std::env::set_var("HEARTH_OPS12_BAD", "a\nb");
        let (_, sq) = substitute_env_vars("password: '${HEARTH_OPS12_BAD}'\n");
        std::env::set_var("HEARTH_OPS12_BAD", "a #b");
        let (_, mid) = substitute_env_vars("url: https://${HEARTH_OPS12_BAD}/x\n");
        std::env::remove_var("HEARTH_OPS12_BAD");
        for warnings in [sq, mid] {
            assert!(
                warnings
                    .iter()
                    .any(|w| w.kind == EnvVarWarningKind::Unrepresentable),
                "expected an Unrepresentable warning, got {warnings:?}"
            );
        }
    }

    /// Safe values are still spliced raw, so numbers stay numbers.
    #[test]
    fn plain_safe_values_keep_their_yaml_type() {
        let (v, _) = parsed("HEARTH_OPS12_PORT", "8443", "port: ${HEARTH_OPS12_PORT}\n");
        assert_eq!(get(&v, "port").as_u64(), Some(8443));
    }

    /// Block-scalar content is text: a leading `'` there opens no quote, and a
    /// reference on its own line is substituted verbatim.
    #[test]
    fn block_scalar_content_is_text() {
        std::env::remove_var("HEARTH_OPS12_UNSET_BLOCK");
        let (v, warnings) = parsed(
            "HEARTH_OPS12_BLOCK",
            "it's #fine",
            "cert: |\n  'quoted-looking line\n  ${HEARTH_OPS12_BLOCK}\n# note: ${HEARTH_OPS12_UNSET_BLOCK}\nother: x\n",
        );
        assert!(
            warnings.is_empty(),
            "the comment after the block was substituted: {warnings:?}"
        );
        assert_eq!(
            get(&v, "cert").as_str(),
            Some("'quoted-looking line\nit's #fine\n")
        );
        assert_eq!(get(&v, "other").as_str(), Some("x"));
    }

    #[test]
    fn a_comma_in_a_flow_sequence_value_stays_one_element() {
        let (v, _) = parsed(
            "HEARTH_OPS12_FLOW",
            "x,y",
            "list: [${HEARTH_OPS12_FLOW}, b]\n",
        );
        let list = get(&v, "list").as_sequence().expect("sequence");
        assert_eq!(list.len(), 2, "got {list:?}");
        assert_eq!(list[0].as_str(), Some("x,y"));
    }
}
