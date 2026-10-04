//! hearth's `unsafe` code, compiled on its own for Miri and AddressSanitizer.
//!
//! `docs/dev/ARCHITECTURE.md` §9.2: all `unsafe` code MUST be covered by
//! Miri tests where feasible, and by address-sanitizer runs in CI. hearth
//! itself cannot be built for Miri — `ring`, `aws-lc-sys` and `zstd-sys` are
//! C — so each source file that holds `unsafe` is compiled here from the same
//! file, with its own `#[cfg(test)]` unit tests, against the releases of its
//! dependencies that hearth ships. `make miri` runs those tests under Miri and
//! `make asan` under AddressSanitizer; CI runs both in the `unsafe-code` job.
//!
//! `tests/unsafe_check_harness.rs` in hearth fails if a file in `src/` gains
//! `unsafe` without being listed here (or exempted there, with the reason
//! Miri cannot run it), and if `Cargo.lock` here drifts from hearth's.

// The modules' non-test items are hearth's API, which nothing here calls.
#![allow(dead_code)]

/// `EpochCell`: the hot path's epoch-reclaimed atomic `Arc` (task 26.5).
#[path = "../../src/core/epoch_cell.rs"]
pub mod epoch_cell;
