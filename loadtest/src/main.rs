//! Hearth load-testing harness (HEA-1787).
//!
//! Subcommands:
//! * `seed` — build a deterministic, parameterized corpus on a running dev
//!   Hearth and persist a JSON seed-handle (HEA-1789). See [`seed`].
//!
//! Goose load scenarios (auth flows, token validation, session lookup, RBAC
//! checks) are added in follow-up issues under HEA-1787.
//!
//! Run via `make loadtest` / `make seed` (see the repo Makefile) or directly:
//! `cargo run --release -p hearth-loadtest -- seed --help`.

mod client;
mod handle;
mod params;
mod seed;

use clap::{Parser, Subcommand};

use params::SeedParams;

#[derive(Parser)]
#[command(name = "hearth-loadtest", about = "Load-testing harness for Hearth")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Seed a deterministic, parameterized dataset on a running dev instance.
    Seed(SeedParams),
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Seed(params) => run_seed(params),
    }
}

/// Validates params and runs the async seed flow on a multi-thread runtime.
fn run_seed(params: SeedParams) -> std::process::ExitCode {
    if let Err(e) = params.validate() {
        eprintln!("invalid parameters: {e}");
        return std::process::ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start tokio runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(seed::run_seed(&params)) {
        Ok(_) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("seed failed: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
