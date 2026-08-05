// Copyright 2026 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
