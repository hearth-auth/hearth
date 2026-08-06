//! Theme-token lint fence (HEA-2074).
//!
//! `THEME.md` bans pure `#ffffff`; primary text is `graphite-50`. Tailwind's
//! `text-white` compiles to pure white and is therefore forbidden in the UI
//! templates. axe has no theme-token rule, so this cheap repo-level walk is the
//! regression fence for finding #1 — it needs no browser and no running server.
//!
//! If this ever needs to allow a genuine exception, prefer a scoped
//! `graphite-*` token from `ui/tailwind.config.js` over re-introducing
//! `text-white`.

use std::fs;
use std::path::{Path, PathBuf};

/// Recursively collects every `.html` file under `dir`.
fn collect_html(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_html(&path, out);
        } else if path.extension().is_some_and(|e| e == "html") {
            out.push(path);
        }
    }
}

#[test]
fn no_text_white_in_templates() {
    let templates = Path::new(env!("CARGO_MANIFEST_DIR")).join("templates");
    let mut files = Vec::new();
    collect_html(&templates, &mut files);
    assert!(
        !files.is_empty(),
        "no templates found under {} — did the path change?",
        templates.display()
    );

    let mut offenders = Vec::new();
    for file in &files {
        let contents = fs::read_to_string(file).expect("template should be readable");
        for (idx, line) in contents.lines().enumerate() {
            if line.contains("text-white") {
                let rel = file.strip_prefix(&templates).unwrap_or(file);
                offenders.push(format!("templates/{}:{}", rel.display(), idx + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "`text-white` is banned by THEME.md (use a `graphite-*` token instead); found at:\n{}",
        offenders.join("\n")
    );
}
