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
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.

#[cfg(feature = "full")]
mod bootstrap;
mod catalog;
mod codegen;
#[cfg(feature = "full")]
mod ir;
#[cfg(feature = "full")]
mod model;
#[cfg(feature = "full")]
mod new_op;
#[cfg(feature = "full")]
mod route;
mod verify;
#[cfg(feature = "full")]
mod why;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    let rest: Vec<String> = args.collect();
    dispatch(first, rest)
}

#[cfg(feature = "full")]
fn dispatch(first: Option<String>, rest: Vec<String>) -> ExitCode {
    match first.as_deref() {
        Some("verify") => verify::verify(&rest),
        Some("codegen") => codegen::codegen(&rest),
        Some("ir") => ir::command(&rest),
        Some("model") => model::model(&rest),
        Some("spec") => match rest.first().map(String::as_str) {
            Some("verify") => codegen::verify(&rest[1..]),
            other => {
                eprintln!("unknown `spec` subcommand: {}\n\n{USAGE}", other.unwrap_or("(none)"));
                ExitCode::from(2)
            }
        },
        Some("why") => why::run(&rest),
        Some("conformance") => conformance(rest),
        Some("route") => route::route(&rest),
        Some("new-op") => new_op::new_op(&rest),
        Some("bootstrap") => bootstrap::bootstrap(&rest),
        Some("-h" | "--help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}\n\n{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(not(feature = "full"))]
fn dispatch(first: Option<String>, rest: Vec<String>) -> ExitCode {
    match first.as_deref() {
        Some("codegen") => codegen::codegen(&rest),
        Some("spec") if rest.first().map(String::as_str) == Some("verify") => codegen::verify(&rest[1..]),
        Some("verify") if verify::is_crate_request(&rest) => verify::verify(&rest),
        _ => run_full(first, &rest),
    }
}

#[cfg(not(feature = "full"))]
fn run_full(first: Option<String>, rest: &[String]) -> ExitCode {
    let mut command = std::process::Command::new(env!("CARGO"));
    command.args(["run", "--quiet", "--package", "xtask", "--features", "full", "--"]);
    if let Some(first) = first {
        command.arg(first);
    }
    command.args(rest);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        let error = command.exec();
        eprintln!("failed to run full xtask: {error}");
        ExitCode::FAILURE
    }
    #[cfg(not(unix))]
    match command.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(error) => {
            eprintln!("failed to run full xtask: {error}");
            std::process::exit(1)
        }
    }
}

#[cfg(feature = "full")]
const USAGE: &str = "\
usage: cargo xtask <command>

use --json to request a machine-readable result

commands:
  verify --op <operation>   run the affected operation crates (<=30 seconds)
  verify --crate <name>     run one crate's tests (<=30 seconds)
  verify --all              run the workspace tests (<=10 minutes)
  codegen                   regenerate spec/operations, OPERATIONS.md and generated/
  codegen diff --semantic   print a semantic diff capped at 50 lines
  codegen --check           fail when generated output or the verify map drifted
  ir validate [--expect-fail <dir>]
                            validate the frozen IR schema and its samples
  spec verify               fail when any generated artefact differs from a fresh run
  model verify              verify the vendored model against its provenance record
  model drift --against <path>
                            report wire-affecting differences in a candidate model
  why <target> [--json]     trace a quirk, operation, error code, header, ADR or assembly rule
  route explain [--json] 'METHOD /path?query'
                            explain route selection and every predicate
  new-op <Operation>        create an intentionally-red operation scaffold
  bootstrap                 prepare a fresh checkout for work (<=5 minutes)
  conformance <run|validate|baseline> [--filter <glob>] [--transport hyper|conn]
              [--profile aws|minio|strict] [--baseline <f>] [--json <f>] [--junit <f>]
";

/// Shells out to the conformance binary.
///
/// The suite remains a separate process so its exit classes and public-facade boundary are the
/// same here as they are for an outside implementation.
#[cfg(feature = "full")]
fn conformance(args: Vec<String>) -> ExitCode {
    let mut cmd = std::process::Command::new(env!("CARGO"));
    cmd.args([
        "run",
        "--quiet",
        "--package",
        "rustfs-gateway-conformance",
        "--bin",
        "rustfs-gateway-conformance",
        "--",
    ]);
    cmd.args(&args);
    match cmd.status() {
        // Exit code 3 means "no case executed", which is not success. Passing the child's
        // code through unchanged is what keeps that distinction visible to CI.
        Ok(status) => ExitCode::from(u8::try_from(status.code().unwrap_or(3)).unwrap_or(3)),
        Err(err) => {
            eprintln!("failed to run cargo: {err}");
            ExitCode::FAILURE
        }
    }
}
