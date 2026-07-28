//! Hearth load-testing harness (HEA-1787).
//!
//! Subcommands:
//! * `seed` — build a deterministic, parameterized corpus on a running dev
//!   Hearth and persist a JSON seed-handle (HEA-1789). See [`seed`].
//! * `run` — drive the five closed-loop Goose journeys against a seeded
//!   instance with configurable per-journey weighting (HEA-1790). See
//!   [`load`] and [`scenarios`].
//!
//! Run via `make loadtest` / `make seed` (see the repo Makefile) or directly:
//! `cargo run --release -p hearth-loadtest -- seed --help`.

mod budget;
mod client;
mod handle;
mod html;
mod latency;
mod load;
mod params;
mod report;
mod resources;
mod scenarios;
mod seed;

use clap::{Parser, Subcommand};

use load::LoadParams;
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
    /// Run the closed-loop Goose journeys against a seeded instance.
    Run(Box<LoadParams>),
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Seed(params) => run_seed(params),
        Command::Run(params) => run_load(&params),
    }
}

/// Runs the Goose load journeys on a multi-thread runtime.
fn run_load(params: &LoadParams) -> std::process::ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to start tokio runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(load::run_load(params)) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("load run failed: {e}");
            std::process::ExitCode::FAILURE
        }
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
