//! Guard: every YAML snippet an operator can copy out of the canonical config
//! reference — and every shipped example config — must actually deserialize into
//! [`hearth::config::Config`] (audit §4.13 finding 9).
//!
//! ## Why this exists
//!
//! Every struct in `src/config/types.rs` carries `#[serde(deny_unknown_fields)]`
//! (HEA-2113). That makes a misspelled or phantom key in the documentation a hard
//! startup failure for anyone who copies it: the server refuses to boot and names
//! a key the operator read in our own reference. The 2026-08-28 audit found nine
//! such snippets. Fixing nine snippets by hand fixes nine snippets; this test
//! fixes the class, because the tenth goes red the moment it is written.
//!
//! ## What is checked
//!
//! For every fenced ```` ```yaml ```` block in [`DOC_SOURCES`], and for every file
//! in [`FILE_SOURCES`], the block is passed through
//! [`Config::from_yaml_str_unchecked`] — the real parser, including `${VAR}`
//! substitution and `deny_unknown_fields`. Deserialization must succeed.
//!
//! Validation (`Config::validate`) is deliberately *not* run: a doc snippet is a
//! fragment showing one section, so it legitimately omits the production-mode
//! requirements (TLS, KEK) that a whole config must satisfy. What this test
//! asserts is the property an operator actually depends on — *the keys are real
//! and the shapes are right*.
//!
//! ## Fragments
//!
//! Every snippet in the reference is rooted at a top-level key (`server:`,
//! `realms:`, …), so each one is a valid standalone config document. A snippet
//! that is only an inner fragment must be wrapped in its parent keys in the doc
//! itself — that is a documentation improvement, not an exemption, because an
//! unrooted fragment is not copy-pasteable either.
//!
//! ## Known-broken quarantine
//!
//! [`KNOWN_BROKEN_SNIPPETS`] lists snippets that are deliberately invalid — a
//! "do not do this" counter-example. The test asserts each one *still* fails, so
//! the entry cannot outlive the snippet: making it parse makes this test fail
//! until the entry is deleted.

use std::path::{Path, PathBuf};

use hearth::config::Config;

/// Markdown documents whose fenced `yaml` blocks are checked.
const DOC_SOURCES: &[&str] = &["docs/specs/CONFIGURATION.md"];

/// Whole YAML files shipped to operators, checked end to end.
const FILE_SOURCES: &[&str] = &["hearth.example.yaml", "hearth.maximal.yaml"];

/// Snippets that are *intended* to fail to parse, keyed by the substring that
/// identifies them. Each entry is `(source, identifying substring, why)`.
///
/// The test asserts each listed snippet still fails. Empty is the goal state.
const KNOWN_BROKEN_SNIPPETS: &[(&str, &str, &str)] = &[
    // These three realm features are real and enforced at runtime, but have no
    // `hearth.yaml` surface and no admin-API surface — `RealmConfigYaml` maps them
    // straight to `::default()`. The reference now carries a "Not settable in
    // hearth.yaml" admonition above each block; the snippet is retained as a shape
    // illustration. Delete the entry in the same change that adds the YAML key.
    (
        "docs/specs/CONFIGURATION.md",
        "adaptive_mfa:",
        "adaptive_mfa has no realm YAML key (src/config/types.rs maps it to ::default())",
    ),
    (
        "docs/specs/CONFIGURATION.md",
        "breach_check:",
        "breach_check has no realm YAML key (src/config/types.rs maps it to ::default())",
    ),
    (
        "docs/specs/CONFIGURATION.md",
        "pre_token_webhook:",
        "pre_token_webhook has no realm YAML key (src/config/types.rs maps it to None)",
    ),
];

/// One fenced YAML block, with enough provenance to name it in a failure.
struct Snippet {
    source: String,
    /// 1-based line number of the first content line of the block.
    line: usize,
    body: String,
}

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the `hearth` crate root, which is the repo root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Extracts every fenced ```` ```yaml ```` block from a markdown document.
///
/// Handles indented fences (a snippet nested inside a list item) by stripping
/// the fence's own indentation from each body line.
fn extract_yaml_blocks(source: &str, text: &str) -> Vec<Snippet> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let indent_len = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        let is_yaml_fence = trimmed
            .strip_prefix("```")
            .is_some_and(|rest| matches!(rest.trim_end(), "yaml" | "yml"));
        if !is_yaml_fence {
            i += 1;
            continue;
        }
        let body_start = i + 1;
        let mut j = body_start;
        while j < lines.len() && lines[j].trim_start() != "```" {
            j += 1;
        }
        let body = lines[body_start..j.min(lines.len())]
            .iter()
            .map(|l| {
                if l.len() >= indent_len && l[..indent_len].chars().all(char::is_whitespace) {
                    &l[indent_len..]
                } else {
                    l.trim_start()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(Snippet {
            source: source.to_string(),
            line: body_start + 1,
            body,
        });
        i = j + 1;
    }
    out
}

/// Collects every snippet this test is responsible for.
fn all_snippets() -> Vec<Snippet> {
    let root = repo_root();
    let mut snippets = Vec::new();
    for doc in DOC_SOURCES {
        let path = root.join(doc);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("doc source {} must be readable: {e}", path.display()));
        snippets.extend(extract_yaml_blocks(doc, &text));
    }
    for file in FILE_SOURCES {
        let path = root.join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("example config {} must be readable: {e}", path.display()));
        snippets.push(Snippet {
            source: (*file).to_string(),
            line: 1,
            body: text,
        });
    }
    snippets
}

/// True when a snippet is quarantined as a deliberate counter-example.
fn quarantine_reason(snippet: &Snippet) -> Option<&'static str> {
    KNOWN_BROKEN_SNIPPETS
        .iter()
        .find(|(source, needle, _)| *source == snippet.source && snippet.body.contains(needle))
        .map(|(_, _, why)| *why)
}

/// Blank or comment-only snippets carry no keys and are skipped, not failed.
fn is_effectively_empty(body: &str) -> bool {
    body.lines()
        .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
}

#[test]
fn every_documented_yaml_snippet_parses() {
    let snippets = all_snippets();
    assert!(
        snippets.len() >= 40,
        "extractor found only {} snippets — the fence walker is probably broken",
        snippets.len()
    );

    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for snippet in &snippets {
        if is_effectively_empty(&snippet.body) {
            continue;
        }
        let outcome = Config::from_yaml_str_unchecked(&snippet.body);
        match (quarantine_reason(snippet), outcome) {
            (None, Err(e)) => failures.push(format!(
                "{}:{} — {e}\n    first line: {}",
                snippet.source,
                snippet.line,
                snippet.body.lines().next().unwrap_or("<empty>")
            )),
            (Some(why), Ok(_)) => failures.push(format!(
                "{}:{} — quarantined as \"{why}\" but it now PARSES; delete the \
                 KNOWN_BROKEN_SNIPPETS entry",
                snippet.source, snippet.line
            )),
            _ => {}
        }
        checked += 1;
    }

    assert!(
        failures.is_empty(),
        "{} of {checked} documented YAML snippets do not deserialize into `Config`.\n\
         An operator who copies one of these gets a server that refuses to boot.\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}

/// The extractor itself must be able to see a fence; a silent zero-block walk
/// would make the guard above vacuously green.
#[test]
fn fence_extractor_finds_indented_and_plain_blocks() {
    let text = "prose\n```yaml\nserver:\n  port: 1\n```\n- item\n  ```yaml\n  storage:\n    data_dir: \"/x\"\n  ```\n";
    let blocks = extract_yaml_blocks("synthetic.md", text);
    assert_eq!(blocks.len(), 2, "both fences must be found");
    assert_eq!(blocks[0].body, "server:\n  port: 1");
    assert_eq!(
        blocks[1].body, "storage:\n  data_dir: \"/x\"",
        "an indented fence must have its indentation stripped"
    );
}

/// Sanity: the sources this test names must exist, or it silently checks nothing.
#[test]
fn declared_sources_exist() {
    let root = repo_root();
    for source in DOC_SOURCES.iter().chain(FILE_SOURCES.iter()) {
        let path: &Path = &root.join(source);
        assert!(path.is_file(), "declared source {source} does not exist");
    }
}
