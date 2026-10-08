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

//! The build that runs ahead of a crate's feedback deadline.
//!
//! Responsible for: deriving the Cargo commands that produce every artifact a crate's measured
//! steps need, running them with no deadline over them, and reporting what they cost.
//! NOT responsible for: choosing the steps, enforcing the deadline, or wording a budget failure.
//! Upstream: crate verification. Downstream: Cargo.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::{diagnostic, print_cargo_failure, process, rerun_command};

/// What the build that ran ahead of the deadline cost, so the deadline can start after it.
pub(super) struct Prebuild {
    pub(super) elapsed: Duration,
    pub(super) compiled_crates: usize,
}

/// The Cargo commands that produce every artifact the measured steps will need, and nothing else.
///
/// The loop's own commands, minus the run: a `test` step becomes the same selection with
/// `--no-run` and without its filter tail, and a `clippy` step runs as itself, lint arguments
/// included. The crate's conformance case builds the conformance library once, without the case
/// filter.
///
/// Clippy is prepared by Clippy because nothing else prepares it. Cargo fingerprints a workspace
/// member's lint pass against the Clippy driver and against the lint arguments, so the `check` of
/// the same targets this used to run warmed only the dependencies and left every workspace crate
/// with a stale lint pass to be relinted inside the budget (the "compiled N crates inside the
/// budget" receipts on rustfs/gateway#1264, #1336 and #1367), and a `clippy` without the
/// `-- -D warnings` tail would relint the whole closure there again.
///
/// This is the fix for the build the four-command gate does not produce (rustfs/gateway#642): a
/// `-p <crate>` selection resolves a different artifact universe from `--workspace`, so the first
/// `verify --crate` after the gate compiled up to 93 crates inside a 30-second window and was
/// killed at the deadline having measured nothing. The build is real work and still runs — it is
/// simply not what the 30 seconds are for.
pub(super) fn prebuild_commands(step_batches: &[Vec<Vec<String>>], conformance_case: Option<&str>) -> Vec<Vec<String>> {
    let mut commands: Vec<Vec<String>> = Vec::new();
    if conformance_case.is_some() {
        commands.push(
            ["test", "-p", "rustfs-gateway-conformance", "--lib", "--no-run"]
                .map(str::to_owned)
                .to_vec(),
        );
    }
    for step in step_batches.iter().flatten() {
        let selection = step.iter().skip(1).take_while(|argument| *argument != "--").cloned();
        let command: Vec<String> = match step.first().map(String::as_str) {
            Some("test") => std::iter::once("test".to_owned())
                .chain(selection.filter(|argument| argument != "--no-run"))
                .chain(std::iter::once("--no-run".to_owned()))
                .collect(),
            Some("clippy") => step.clone(),
            _ => continue,
        };
        if !commands.contains(&command) {
            commands.push(command);
        }
    }
    commands
}

/// Runs the prebuild commands one at a time with no deadline over them, timing the whole.
pub(super) fn run_prebuild(commands: &[Vec<String>], subject: &str) -> Result<Prebuild, ExitCode> {
    let started = Instant::now();
    let mut compiled_crates = 0;
    for (number, args) in commands.iter().enumerate() {
        let step = format!("{subject} build {}", number + 1);
        let batch = process::run(&[(env!("CARGO").to_owned(), args.clone(), step.clone())], Path::new("."), None);
        if batch.interrupted {
            return Err(diagnostic(
                "verification interrupted",
                subject,
                "the build ahead of the budget was interrupted",
            ));
        }
        for (_, output) in batch.results {
            match output {
                Ok(output) if output.status.success() => {
                    compiled_crates += process::build_line_count(&output.stderr);
                }
                Ok(output) => {
                    print_cargo_failure(&output);
                    return Err(diagnostic(
                        "verification build failed",
                        subject,
                        &format!(
                            "the crate must build and lint clean before its loop is measured; `{}` exited with {}",
                            rerun_command(env!("CARGO"), args),
                            output.status
                        ),
                    ));
                }
                Err(error) => {
                    return Err(diagnostic(
                        "cargo could not be started",
                        subject,
                        &format!("the crate must build before its loop is measured; {error}"),
                    ));
                }
            }
        }
    }
    Ok(Prebuild {
        elapsed: started.elapsed(),
        compiled_crates,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{crate_case, crate_step_batches};
    use super::*;
    fn owned(arguments: &[&str]) -> Vec<String> {
        arguments.iter().map(|argument| (*argument).to_owned()).collect()
    }

    #[test]
    fn a_test_step_is_prebuilt_as_the_same_selection_without_its_filter_tail() {
        let steps = vec![vec![owned(&[
            "test",
            "-p",
            "rustfs-gateway-core",
            "--lib",
            "--test",
            "integration",
            "--",
            "--skip",
            "compile_fail::compile_time_contracts_are_not_openable",
        ])]];

        assert_eq!(
            prebuild_commands(&steps, None),
            vec![owned(&[
                "test",
                "-p",
                "rustfs-gateway-core",
                "--lib",
                "--test",
                "integration",
                "--no-run"
            ])]
        );
    }

    /// Neither a `check` of the same targets nor a `clippy` without its lint arguments prepares
    /// what the loop's Clippy step runs (rustfs/gateway#1264), so the step is prebuilt as itself.
    #[test]
    fn a_clippy_step_is_prebuilt_as_itself() {
        let step = owned(&["clippy", "-p", "rustfs-gateway-http", "--all-targets", "--", "-D", "warnings"]);

        assert_eq!(prebuild_commands(&[vec![step.clone()]], None), vec![step]);
    }

    #[test]
    fn the_crate_conformance_case_is_prebuilt_as_the_library_without_its_filter() {
        assert_eq!(
            prebuild_commands(&[], Some("c-sig-0001")),
            vec![owned(&["test", "-p", "rustfs-gateway-conformance", "--lib", "--no-run"])]
        );
        assert!(prebuild_commands(&[], None).is_empty());
    }

    #[test]
    fn a_step_that_is_neither_test_nor_clippy_is_not_prebuilt() {
        let steps = vec![vec![
            owned(&["bench", "-p", "rustfs-gateway-http"]),
            owned(&["doc", "-p", "rustfs-gateway-http"]),
        ]];

        assert!(prebuild_commands(&steps, None).is_empty());
    }

    #[test]
    fn nothing_after_the_filter_separator_reaches_the_prebuild_and_no_run_is_not_repeated() {
        let steps = vec![vec![
            owned(&[
                "test",
                "-p",
                "rustfs-gateway-sig",
                "--no-run",
                "--",
                "--skip",
                "timing::slow",
                "--exact",
            ]),
            owned(&["test", "-p", "rustfs-gateway-sig", "--", "--skip", "timing::other"]),
        ]];

        let commands = prebuild_commands(&steps, None);

        assert_eq!(commands, vec![owned(&["test", "-p", "rustfs-gateway-sig", "--no-run"])]);
        assert!(
            commands
                .iter()
                .flatten()
                .all(|argument| !argument.starts_with("--skip") && argument != "--exact")
        );
    }

    #[test]
    fn the_real_crate_scopes_prebuild_no_run_tests_and_their_clippy_steps_as_themselves() {
        for package in [
            "rustfs-gateway-core",
            "rustfs-gateway",
            "rustfs-gateway-server",
            "rustfs-gateway-fs",
            "rustfs-gateway-goldens",
            "xtask",
            "rustfs-gateway-sig",
        ] {
            let step_batches = crate_step_batches(package);
            let commands = prebuild_commands(&step_batches, crate_case(package));
            let kinds: Vec<&str> = commands.iter().map(|command| command[0].as_str()).collect();
            assert!(kinds.iter().all(|kind| *kind == "test" || *kind == "clippy"), "{package}: {kinds:?}");
            for command in commands.iter().filter(|command| command[0] == "test") {
                assert_eq!(command.last().map(String::as_str), Some("--no-run"), "{package}: {command:?}");
                assert!(command.iter().all(|argument| argument != "--"), "{package}: {command:?}");
            }
            let clippy_steps: Vec<&Vec<String>> = step_batches.iter().flatten().filter(|step| step[0] == "clippy").collect();
            assert!(!clippy_steps.is_empty(), "{package} has no clippy step to prebuild");
            for step in clippy_steps {
                assert!(commands.contains(step), "{package}: {step:?} is not prebuilt as itself in {commands:?}");
            }
        }
    }

    #[test]
    fn conformance_prebuild_keeps_the_library_and_allocation_harness_in_both_steps() {
        assert_eq!(
            prebuild_commands(&crate_step_batches("rustfs-gateway-conformance"), None),
            vec![
                owned(&[
                    "test",
                    "-p",
                    "rustfs-gateway-conformance",
                    "--lib",
                    "--test",
                    "list_allocations",
                    "--no-run"
                ]),
                owned(&[
                    "clippy",
                    "-p",
                    "rustfs-gateway-conformance",
                    "--lib",
                    "--test",
                    "list_allocations",
                    "--",
                    "-D",
                    "warnings"
                ]),
            ]
        );
    }

    #[test]
    fn compiled_crates_are_counted_from_cargo_lines_alone() {
        let stderr = b"   Compiling proc-macro2 v1.0.0\n     Running unittests\n   Compiling syn v2.0.0\nnote: Compiling is not a cargo line here\n";

        assert_eq!(process::build_line_count(stderr), 2);
        assert_eq!(process::build_line_count(b""), 0);
        assert_eq!(process::build_line_count(b"    Finished `test` profile\n"), 0);
    }

    /// `CARGO_TERM_COLOR=always`, as every CI job sets it, wraps the verb in SGR escapes.
    #[test]
    fn coloured_cargo_lines_are_counted() {
        let stderr = b"\x1b[1m\x1b[92m   Compiling\x1b[0m ring v0.17.14\n\x1b[1m\x1b[92m    Checking\x1b[0m xtask v0.1.4\n\x1b[1m\x1b[92m    Finished\x1b[0m `dev` profile\n";

        assert_eq!(process::build_line_count(stderr), 2);
    }

    /// A Clippy step builds the crates it lints and reports them as `Checking`.
    #[test]
    fn checking_lines_are_builds_too() {
        assert_eq!(process::build_line_count(b"    Checking rustfs-gateway-core v0.44.0\n"), 1);
    }

    #[test]
    fn n_lines_that_only_mention_a_verb_are_not_builds() {
        for stderr in [
            &b"note: Compiling is not a cargo line here\n"[..],
            b"warning: Checking this later\n",
            b"   Compilingx proc-macro2\n",
            b"   Checking\n",
            b"\x1b[1m   Finished\x1b[0m Compiling-free\n",
            b"test compiling_is_lowercase ... ok\n",
        ] {
            assert_eq!(process::build_line_count(stderr), 0, "{}", String::from_utf8_lossy(stderr));
        }
    }
}
