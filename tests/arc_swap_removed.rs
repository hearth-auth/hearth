//! Task 26.5 — `arc-swap` must not come back.
//!
//! `arc-swap` 1.9.2 corrupts the heap under the `load` + `rcu` pattern:
//! measured at 3 failures in 150 loaded runs under `MALLOC_CHECK_=3` (two
//! `SIGSEGV`, one `free(): invalid size`), 0 once the primitive was replaced,
//! and there is no release that fixes it
//! (`reports/arc-swap-use-after-free-2026-09-21.md`). Every call site moved to
//! `hearth::core::SwapCell` (off the hot path) or `hearth::core::EpochCell`
//! (on it), and the dependency was removed.
//!
//! This guard keeps it removed. Adding it back as a direct dependency fails
//! the first test; a new dependency that drags it in transitively fails the
//! second, because the crate's `unsafe` would be in the binary either way.
//! `deny.toml` bans it too, so `cargo deny check` catches the same thing in
//! the root graph; this test also covers `fuzz/Cargo.lock`, which that check
//! does not read.

use std::path::Path;

/// The crate as cargo spells it in manifests and lockfiles.
const CRATE: &str = "arc-swap";

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
}

#[test]
fn arc_swap_is_not_a_declared_dependency() {
    let manifest = read("Cargo.toml");
    // Any mention outside a comment: `arc-swap = "1"`, `[dependencies.arc-swap]`,
    // a `package = "arc-swap"` rename, or a `[target.'cfg(..)'.dependencies]`
    // entry all name it in code.
    let declared: Vec<&str> = manifest
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .filter(|code| code.contains(CRATE) || code.contains("arc_swap"))
        .collect();
    assert!(
        declared.is_empty(),
        "Cargo.toml declares {CRATE} again: {declared:?}. It corrupts the heap under \
         load + rcu (task 26.1); use hearth::core::EpochCell on the hot path or \
         hearth::core::SwapCell elsewhere."
    );
}

#[test]
fn arc_swap_is_not_in_the_dependency_graph() {
    let needle = format!("name = \"{CRATE}\"");
    for lockfile in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let lock = read(lockfile);
        assert!(
            lock.contains("[[package]]"),
            "{lockfile} does not look like a lockfile — the guard would pass vacuously"
        );
        assert!(
            !lock.lines().any(|line| line.trim() == needle),
            "{lockfile} resolves {CRATE}: some dependency pulls it back into the build. \
             Run `cargo tree -i {CRATE}` to find which, and see task 26.5 for why it \
             must stay out."
        );
    }
}
