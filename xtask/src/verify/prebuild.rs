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

use super::{diagnostic, print_cargo_failure, process};

/// What the build that ran ahead of the deadline cost, so the deadline can start after it.
pub(super) struct Prebuild {
    pub(super) elapsed: Duration,
    pub(super) compiled_crates: usize,
}

/// The Cargo commands that produce every artifact the measured steps will need, and nothing else.
///
/// A `test` step becomes the same selection with `--no-run` and without its filter tail; a
/// `clippy` step becomes a `check` of the same targets, which shares the dependency artifacts
/// Clippy then reuses while leaving the workspace crate's own lint pass inside the budget. The
/// crate's conformance case builds the conformance library once, without the case filter.
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
            Some("clippy") => std::iter::once("check".to_owned()).chain(selection).collect(),
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
                    compiled_crates += compiled_crate_count(&output.stderr);
                }
                Ok(output) => {
                    print_cargo_failure(&output);
                    return Err(diagnostic(
                        "verification build failed",
                        subject,
                        &format!("the crate must build before its loop is measured; cargo exited with {}", output.status),
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

/// Counts the `Compiling <crate>` lines cargo wrote, an observation of what the build did.
fn compiled_crate_count(stderr: &[u8]) -> usize {
    String::from_utf8_lossy(stderr)
        .lines()
        .filter(|line| line.trim_start().starts_with("Compiling "))
        .count()
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

    #[test]
    fn a_clippy_step_is_prebuilt_as_a_check_of_the_same_targets() {
        let steps = vec![vec![owned(&[
            "clippy",
            "-p",
            "rustfs-gateway-http",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ])]];

        assert_eq!(
            prebuild_commands(&steps, None),
            vec![owned(&["check", "-p", "rustfs-gateway-http", "--all-targets"])]
        );
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
    fn the_real_crate_scopes_all_prebuild_to_a_no_run_test_and_a_check() {
        for package in [
            "rustfs-gateway-core",
            "rustfs-gateway",
            "rustfs-gateway-server",
            "xtask",
            "rustfs-gateway-sig",
        ] {
            let commands = prebuild_commands(&crate_step_batches(package), crate_case(package));
            let kinds: Vec<&str> = commands.iter().map(|command| command[0].as_str()).collect();
            assert!(kinds.iter().all(|kind| *kind == "test" || *kind == "check"), "{package}: {kinds:?}");
            assert!(
                commands
                    .iter()
                    .filter(|command| command[0] == "test")
                    .all(|command| command.last().map(String::as_str) == Some("--no-run")),
                "{package}: {commands:?}"
            );
            assert!(commands.iter().flatten().all(|argument| argument != "--"), "{package}: {commands:?}");
        }
    }

    #[test]
    fn compiled_crates_are_counted_from_cargo_lines_alone() {
        let stderr = b"   Compiling proc-macro2 v1.0.0\n    Checking xtask v0.1.3\n   Compiling syn v2.0.0\n     Running unittests\nnote: Compiling is not a cargo line here\n";

        assert_eq!(compiled_crate_count(stderr), 2);
        assert_eq!(compiled_crate_count(b""), 0);
        assert_eq!(compiled_crate_count(b"    Finished `test` profile\n"), 0);
    }
}
