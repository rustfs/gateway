//! Repository automation entry point.
//!
//! Responsible for: the `cargo xtask` command surface. Subcommands are added by the task that
//! needs them; this file only owns dispatch.
//! NOT responsible for: any protocol logic.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("verify") => verify(args.collect()),
        Some("bootstrap") => {
            println!("nothing to bootstrap yet");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}\n\n{USAGE}");
            ExitCode::FAILURE
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage: cargo xtask <command>

commands:
  verify [--crate <name>]   run the test suite (whole workspace, or one crate)
  bootstrap                 prepare a fresh checkout for work
";

/// Forwards to `cargo test`. Widened by later tasks into the <=30s per-crate feedback loop.
fn verify(args: Vec<String>) -> ExitCode {
    let mut cmd = std::process::Command::new(env!("CARGO"));
    cmd.arg("test");
    match args.as_slice() {
        [] => {
            cmd.arg("--workspace");
        }
        [flag, name] if flag == "--crate" => {
            cmd.args(["-p", name]);
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    }
    match cmd.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(err) => {
            eprintln!("failed to run cargo: {err}");
            ExitCode::FAILURE
        }
    }
}
