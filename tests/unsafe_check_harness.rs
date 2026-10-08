//! `unsafe-check/` must keep covering hearth's `unsafe` code
//! (`docs/dev/ARCHITECTURE.md` §9.2).
//!
//! §9.2: "All unsafe code MUST be covered by Miri tests where feasible, and by
//! address sanitizer runs in CI." Hearth cannot be built for Miri — `ring`,
//! `aws-lc-sys` and `zstd-sys` are C — so `unsafe-check/` compiles each source
//! file that holds `unsafe` on its own, with that file's own unit tests, and
//! `make miri` / `make asan` run them (CI: the `unsafe-code` job). Before the
//! harness was committed, Miri had only ever been run by hand, from a scratch
//! crate, and nothing in CI ran either tool.
//!
//! The harness can only vouch for what it compiles, against the dependency
//! versions hearth ships. These tests hold both, on the stable toolchain that
//! `make check` already runs:
//!
//! 1. A file in `src/` that gains an `unsafe` block, fn, impl or extern must be
//!    added to `unsafe-check/src/lib.rs` or to [`NOT_UNDER_MIRI`] with the
//!    reason Miri cannot run it.
//! 2. The harness must resolve the same `crossbeam-epoch` and
//!    `crossbeam-utils` as `Cargo.lock`: `EpochCell`'s grace period is
//!    `crossbeam-epoch`'s, so checking it against another release checks
//!    nothing about the one in the binary.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Files in `src/` that hold `unsafe` the harness does not compile, each with
/// the reason Miri cannot run it.
const NOT_UNDER_MIRI: &[(&str, &str)] = &[
    (
        "src/storage/fs.rs",
        "`memmap2::Mmap::map` — Miri cannot model mmap, and the call's soundness \
         rests on the file not being truncated under the mapping, a property of \
         the data directory rather than of code",
    ),
    (
        "src/main.rs",
        "glibc FFI only — `mallopt(M_ARENA_MAX)` at startup, and `open_memstream` / \
         `malloc_info` / `free` in its test. Miri cannot call foreign C functions, \
         and the binary's entry point does not build as a standalone harness file",
    ),
];

/// Dependencies whose code the harness exercises in place of hearth's.
const PINNED_WITH_HEARTH: &[&str] = &["crossbeam-epoch", "crossbeam-utils"];

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(relative: &str) -> String {
    let path = root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("could not list {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Whether a line of Rust source opens `unsafe` code, ignoring comments.
fn opens_unsafe(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or_default();
    ["unsafe {", "unsafe fn ", "unsafe impl", "unsafe extern"]
        .iter()
        .any(|marker| code.contains(marker))
}

/// `src/`-relative paths (as `src/...`) of every file holding `unsafe` code.
fn files_with_unsafe() -> BTreeSet<String> {
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    files
        .into_iter()
        .filter(|path| {
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
                .lines()
                .any(opens_unsafe)
        })
        .map(|path| {
            path.strip_prefix(root())
                .expect("under the crate root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

/// The `src/...` files `unsafe-check/src/lib.rs` compiles through
/// `#[path = "../../src/..."]`.
fn files_the_harness_compiles() -> BTreeSet<String> {
    read("unsafe-check/src/lib.rs")
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("#[path = \"../../")?;
            Some(rest.split('"').next()?.to_string())
        })
        .collect()
}

/// The version `lockfile` resolves for `krate`, which must be exactly one.
fn locked_version(lockfile: &str, krate: &str) -> String {
    let lock = read(lockfile);
    let name = format!("name = \"{krate}\"");
    let versions: Vec<&str> = lock
        .split("[[package]]")
        .filter(|package| package.lines().any(|line| line.trim() == name))
        .filter_map(|package| {
            package
                .lines()
                .find_map(|line| line.trim().strip_prefix("version = \""))
                .and_then(|rest| rest.strip_suffix('"'))
        })
        .collect();
    assert_eq!(
        versions.len(),
        1,
        "{lockfile} should resolve exactly one {krate}, found {versions:?}"
    );
    versions[0].to_string()
}

#[test]
fn every_file_with_unsafe_code_is_under_miri_or_says_why_not() {
    let with_unsafe = files_with_unsafe();
    assert!(
        with_unsafe.contains("src/core/epoch_cell.rs"),
        "the scan did not find EpochCell's unsafe blocks, so it would pass vacuously: \
         {with_unsafe:?}"
    );
    let compiled = files_the_harness_compiles();
    let exempt: BTreeSet<String> = NOT_UNDER_MIRI
        .iter()
        .map(|(f, _)| (*f).to_string())
        .collect();

    let uncovered: Vec<&String> = with_unsafe
        .iter()
        .filter(|file| !compiled.contains(*file) && !exempt.contains(*file))
        .collect();
    assert!(
        uncovered.is_empty(),
        "{uncovered:?} hold unsafe code that no Miri or AddressSanitizer run covers \
         (docs/dev/ARCHITECTURE.md §9.2). Compile the file in unsafe-check/src/lib.rs with \
         `#[path = \"../../<file>\"]` so `make miri` and `make asan` run its tests, or add it \
         to NOT_UNDER_MIRI with the reason Miri cannot run it."
    );

    let stale: Vec<&String> = compiled
        .iter()
        .chain(exempt.iter())
        .filter(|file| !with_unsafe.contains(*file))
        .collect();
    assert!(
        stale.is_empty(),
        "{stale:?} no longer hold unsafe code (or no longer exist); drop them from \
         unsafe-check/src/lib.rs or NOT_UNDER_MIRI so the list stays a true inventory"
    );
}

#[test]
fn the_harness_resolves_the_crossbeam_hearth_ships() {
    for krate in PINNED_WITH_HEARTH {
        let hearth = locked_version("Cargo.lock", krate);
        let harness = locked_version("unsafe-check/Cargo.lock", krate);
        assert_eq!(
            harness, hearth,
            "unsafe-check/Cargo.lock resolves {krate} {harness}, hearth ships {hearth}: \
             Miri and AddressSanitizer would be checking a release that is not in the \
             binary. Run `cargo update --manifest-path unsafe-check/Cargo.toml -p {krate} \
             --precise {hearth}`."
        );
    }
}
