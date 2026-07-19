//! Hearth load-testing harness.
//!
//! Foundation skeleton for the load harness tracked in HEA-1787. Scenarios
//! (auth flows, token validation, session lookup, RBAC checks) are added in
//! follow-up issues. For now this binary is an empty entrypoint that compiles
//! against `goose` and exits cleanly so `make loadtest` is wired end-to-end.
//!
//! Run via `make loadtest` (see the repo Makefile) or directly:
//! `cargo run --release -p hearth-loadtest -- --help`.

fn main() {
    // Scenario registration and GooseAttack setup land in follow-up issues
    // under HEA-1787. This placeholder keeps the excluded crate building and
    // the `make loadtest` target invocable.
    println!("hearth-loadtest: no scenarios wired yet (see HEA-1787).");
}
