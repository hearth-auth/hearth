//! Guard: every `hearth ...` invocation printed in the upgrade and disaster-recovery
//! guides must be accepted by the real CLI parser (HEA-2155).
//!
//! Motivation: `docs/specs/CONFIGURATION.md` once documented `branding.*` YAML keys
//! that did not exist, which — with `deny_unknown_fields` (HEA-2113) — meant an
//! operator who copied our documentation could not start the server. The same class
//! of defect exists for CLI invocations, and it is worse there: the disaster-recovery
//! runbook is read *during an outage*, when a phantom command costs recovery minutes.
//!
//! `docs/guides/upgrading.md` was already corrected once for this class of error at
//! `af4edb59`. This test is what stops the third occurrence.
//!
//! ## What is checked
//!
//! For every `hearth` invocation found in a fenced code block or an inline code span
//! of the guides:
//!
//! 1. The **subcommand path** (leading non-flag tokens) resolves — verified by running
//!    `hearth <path...> --help` and requiring a success exit. `--help` short-circuits
//!    before any command executes, so this test has no side effects.
//! 2. Every **long flag** (`--foo`) used in the invocation appears in that subcommand's
//!    `--help` output.
//!
//! Short flags are not checked: `-c` cannot be distinguished from prose in help text
//! without parsing clap's layout, and every short flag in these guides has a long form
//! checked elsewhere.
//!
//! ## Known-broken quarantine
//!
//! [`KNOWN_BROKEN`] lists invocations that are documented but do **not** exist. The
//! test asserts each one is *still* broken, so the entry cannot outlive the defect:
//! fixing the guide makes this test fail until the entry is deleted. That keeps the
//! debt visible in code rather than in a comment nobody reads.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Guides whose CLI invocations are covered by this test.
const GUIDES: &[&str] = &["docs/guides/upgrading.md", "docs/guides/disaster-recovery.md"];

/// Invocations that are documented but rejected by the real CLI.
///
/// Each entry is `(invocation, why it is broken, owning issue)`. The test asserts the
/// invocation is still broken — delete the entry in the same change that fixes the doc.
///
/// This list started at six, all in `docs/guides/disaster-recovery.md`: `cluster status`,
/// `session revoke-all`, `storage scan`, `backup inspect --data-dir`,
/// `realm rotate-signing-key`, and `serve --data-dir/--listen`. All six were fixed under
/// HEA-2196 and their entries deleted — the quarantine test is what reported each fix and
/// refused to let the entry outlive it. No deferrals remain.
///
/// The sole entry below is **not** a deferral; it asserts a documented *absence*.
const KNOWN_BROKEN: &[(&str, &str, &str)] = &[
    // Not a defect: upgrading.md states *that this command does not exist*. The entry keeps
    // the claim honest — if a `cluster` subcommand is ever added, the quarantine test fails
    // and forces the prose to be corrected.
    (
        "hearth cluster",
        "documented in upgrading.md as intentionally absent (\"There is no `hearth cluster` \
         CLI subcommand\"); the prose is correct and needs no fix",
        "intentional — no CLI planned",
    ),
];

/// Path to the compiled `hearth` binary, alongside the integration test binary.
fn hearth_bin() -> PathBuf {
    let mut path = std::env::current_exe()
        .expect("current exe")
        .parent()
        .expect("parent dir")
        .parent()
        .expect("grandparent dir")
        .to_path_buf();
    path.push("hearth");
    path
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// A single `hearth` invocation recovered from a guide.
#[derive(Debug)]
struct Invocation {
    /// Source guide, for failure messages.
    guide: String,
    /// 1-based line number, for failure messages.
    line: usize,
    /// Normalized command text (`hearth ...`, comments and continuations removed).
    text: String,
    /// Leading non-flag tokens after `hearth` — the subcommand path.
    path: Vec<String>,
    /// Long flags (`--foo`) used in the invocation.
    long_flags: Vec<String>,
}

/// Strips shell prompt markers and `sudo`, and drops a trailing `# ...` comment.
fn normalize(raw: &str) -> String {
    let mut s = raw.trim();
    for prefix in ["$ ", "sudo "] {
        s = s.strip_prefix(prefix).unwrap_or(s);
    }
    // A `#` preceded by whitespace starts a comment. Paths in these guides contain no `#`.
    let s = match s.find(" #") {
        Some(idx) => &s[..idx],
        None => s,
    };
    s.trim().to_string()
}

/// Returns the invocation if `line` invokes the `hearth` binary.
fn parse_invocation(guide: &str, line_no: usize, raw: &str) -> Option<Invocation> {
    // A `#`-led line inside a bash block is a comment or sample output, not a command.
    // The upgrade guide prints `#   hearth version : 1.6.9` as example `backup inspect`
    // output; stripping the `#` would turn that output into a phantom invocation.
    if raw.trim_start().starts_with('#') {
        return None;
    }
    let text = normalize(raw);
    let mut tokens = text.split_whitespace();
    let first = tokens.next()?;
    // Accept bare `hearth`, `./hearth`, and `target/release/hearth`.
    if first != "hearth" && !first.ends_with("/hearth") {
        return None;
    }

    let rest: Vec<&str> = tokens.collect();
    let path: Vec<String> = rest
        .iter()
        .take_while(|t| !t.starts_with('-'))
        .map(|t| (*t).to_string())
        .collect();
    let long_flags: Vec<String> = rest
        .iter()
        .filter(|t| t.starts_with("--") && t.len() > 2)
        // `--flag=value` → `--flag`
        .map(|t| t.split('=').next().unwrap_or(t).to_string())
        .collect();

    Some(Invocation {
        guide: guide.to_string(),
        line: line_no,
        text,
        path,
        long_flags,
    })
}

/// Extracts every `hearth` invocation from fenced code blocks and inline code spans.
///
/// Backslash line continuations inside fenced blocks are joined so that multi-line
/// invocations are checked as a single command.
fn extract_invocations(guide: &str) -> Vec<Invocation> {
    let full = repo_root().join(guide);
    let body = std::fs::read_to_string(&full)
        .unwrap_or_else(|e| panic!("guide {} must be readable: {e}", full.display()));

    let mut found = Vec::new();
    let mut in_fence = false;
    // Accumulated `\`-continued command and the line it started on.
    let mut pending: Option<(usize, String)> = None;

    for (idx, line) in body.lines().enumerate() {
        let line_no = idx + 1;

        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            pending = None;
            continue;
        }

        if in_fence {
            let trimmed = line.trim_end();
            let (fragment, continues) = match trimmed.strip_suffix('\\') {
                Some(head) => (head.trim_end(), true),
                None => (trimmed, false),
            };

            let (start_line, mut acc) = pending.take().unwrap_or((line_no, String::new()));
            if acc.is_empty() {
                acc.push_str(fragment.trim());
            } else {
                acc.push(' ');
                acc.push_str(fragment.trim());
            }

            if continues {
                pending = Some((start_line, acc));
            } else if let Some(inv) = parse_invocation(guide, start_line, &acc) {
                found.push(inv);
            }
            continue;
        }

        // Prose: check inline code spans, e.g. run `hearth storage scan`.
        let mut rest = line;
        while let Some(open) = rest.find('`') {
            let after = &rest[open + 1..];
            let Some(close) = after.find('`') else { break };
            if let Some(inv) = parse_invocation(guide, line_no, &after[..close]) {
                found.push(inv);
            }
            rest = &after[close + 1..];
        }
    }

    found
}

/// Runs `hearth <path...> --help`, returning `(success, help_text)`.
///
/// `--help` short-circuits inside clap before any command body runs, so this never
/// touches a data directory or opens a listener.
fn help_for(path: &[String]) -> (bool, String) {
    let output = Command::new(hearth_bin())
        .args(path)
        .arg("--help")
        .output()
        .expect("hearth binary must be executable — run via `cargo nextest run`");
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    (output.status.success(), text)
}

/// Reports whether an invocation is accepted by the real CLI, with a reason if not.
fn check(inv: &Invocation) -> Result<(), String> {
    // `hearth --version` and friends carry no subcommand path.
    let (ok, help) = help_for(&inv.path);
    if !ok {
        return Err(format!(
            "subcommand path `{}` is not accepted by the CLI",
            inv.path.join(" ")
        ));
    }
    for flag in &inv.long_flags {
        if !help.contains(flag.as_str()) {
            return Err(format!(
                "flag `{flag}` is not accepted by `hearth {}`",
                inv.path.join(" ")
            ));
        }
    }
    Ok(())
}

/// The guides must contain invocations — an extractor that silently matches nothing
/// would make every other assertion in this file vacuous (TESTING.md anti-pattern B).
#[test]
fn extractor_finds_invocations_in_every_guide() {
    for guide in GUIDES {
        let found = extract_invocations(guide);
        assert!(
            found.len() >= 3,
            "expected at least 3 `hearth` invocations in {guide}, found {} — the \
             extractor is probably broken, which would make the guard vacuous",
            found.len()
        );
    }
}

/// Every documented `hearth` invocation outside the quarantine must parse (HEA-2155).
#[test]
fn documented_cli_invocations_are_accepted_by_the_real_cli() {
    let mut failures = Vec::new();

    for guide in GUIDES {
        for inv in extract_invocations(guide) {
            if KNOWN_BROKEN.iter().any(|(text, _, _)| *text == inv.text) {
                continue;
            }
            if let Err(reason) = check(&inv) {
                failures.push(format!(
                    "{}:{}: `{}` — {reason}",
                    inv.guide, inv.line, inv.text
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "documented CLI invocations rejected by the real parser \
         (fix the guide, or quarantine in KNOWN_BROKEN with an owning issue):\n  {}",
        failures.join("\n  ")
    );
}

/// Each quarantined invocation must still be present in a guide and still be broken.
///
/// This is what retires the quarantine: fix the guide and this test fails until the
/// corresponding [`KNOWN_BROKEN`] entry is deleted.
#[test]
fn known_broken_invocations_are_still_broken_and_still_documented() {
    let documented: Vec<Invocation> =
        GUIDES.iter().flat_map(|g| extract_invocations(g)).collect();

    for (text, why, issue) in KNOWN_BROKEN {
        let inv = documented.iter().find(|i| i.text == *text).unwrap_or_else(|| {
            panic!(
                "KNOWN_BROKEN entry `{text}` ({issue}) no longer appears in any guide — \
                 the doc was fixed; delete this entry from KNOWN_BROKEN"
            )
        });

        assert!(
            check(inv).is_err(),
            "KNOWN_BROKEN entry `{text}` ({issue}) is now accepted by the CLI — \
             the command was implemented; delete this entry from KNOWN_BROKEN. \
             Recorded reason was: {why}"
        );
    }
}
