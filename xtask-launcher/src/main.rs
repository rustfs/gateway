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

//! Budget-aware launcher for repository automation.
//!
//! Responsible for: selecting the runner for repository automation and recording the time before
//! the selected Cargo process starts. NOT responsible for: verification selection or
//! budget enforcement. Upstream: the Cargo alias. Downstream: the light or operation xtask runner.

use std::ffi::{OsStr, OsString};
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

const STARTED_ENV: &str = "RUSTFS_GATEWAY_XTASK_STARTED_UNIX_NANOS";
const LIGHT_RUNNER: &[&str] = &["--no-default-features"];
const OPERATION_RUNNER: &[&str] = &["--no-default-features", "--features", "operation"];

/// Picks the xtask feature graph a request is built on, before the feedback clock starts.
///
/// Crate verification only shells out to Cargo, so it runs on the light graph, whose only
/// workspace dependencies are the codegen and model crates. The full graph links the facade,
/// core, conformance and everything under them: after an edit to any of those crates the full
/// runner had to rebuild that chain up to xtask before verification could start, and the rebuild
/// ran inside the 30-second budget — 15.5s after a comment in `core`, 20.6s after one in `sig`,
/// against about a second on the light graph (rustfs/backlog#2000). Every other request enters
/// the light runner too, which re-executes the full one only for commands that need it.
fn runner_for_request(arguments: &[String]) -> &'static [&'static str] {
    if matches!(arguments, [command, flag, _] if command == "verify" && flag == "--op")
        || matches!(arguments, [command, json, flag, _] if command == "verify" && json == "--json" && flag == "--op")
    {
        return OPERATION_RUNNER;
    }
    LIGHT_RUNNER
}

/// Whether `name` is one of the variables `cargo run` sets for the package it runs.
///
/// `cargo xtask` is `cargo run --package xtask-launcher`, so this process holds the launcher's
/// `CARGO_MANIFEST_DIR`, `CARGO_MANIFEST_PATH` and `CARGO_PKG_*`. `ring`'s build script declares
/// `rerun-if-env-changed` on those names, so a nested Cargo that inherits them sees values the
/// shell never had and rebuilds `ring` and everything above it up to xtask, inside the budget this
/// launcher starts. `xtask/src/nested_cargo.rs` applies the same rule to xtask's own children.
fn is_package_variable(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(name, "CARGO_MANIFEST_DIR" | "CARGO_MANIFEST_PATH") || name.starts_with("CARGO_PKG_")
}

/// Removes every package variable this process inherited from `cargo run`, and nothing else.
fn without_package_environment(command: &mut Command) -> &mut Command {
    for (name, _) in std::env::vars_os() {
        if is_package_variable(&name) {
            command.env_remove(name);
        }
    }
    command
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let runner = runner_for_request(&arguments);
    let started = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(started) => started.as_nanos().to_string(),
        Err(error) => {
            eprintln!("failed to read the xtask launcher clock: {error}");
            return ExitCode::FAILURE;
        }
    };
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(&cargo);
    without_package_environment(&mut command);
    let status = command
        .args(["run", "--quiet", "--package", "xtask"])
        .args(runner)
        .arg("--")
        .args(arguments)
        .env(STARTED_ENV, started)
        .status();
    match status {
        Ok(status) => ExitCode::from(u8::try_from(status.code().unwrap_or(1)).unwrap_or(1)),
        Err(error) => {
            eprintln!("failed to start xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::process::Command;

    use super::{LIGHT_RUNNER, OPERATION_RUNNER, is_package_variable, runner_for_request, without_package_environment};

    fn removed(command: &Command) -> Vec<OsString> {
        command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_owned())
            .collect()
    }

    /// `cargo test` sets the same package variables for this binary that `cargo run` sets for the
    /// launcher, so the live environment is the input rather than a copied list.
    #[test]
    fn the_xtask_child_inherits_no_package_variable_of_the_launcher() {
        let inherited: Vec<OsString> = std::env::vars_os()
            .map(|(name, _)| name)
            .filter(|name| name == "CARGO_MANIFEST_DIR" || name.to_string_lossy().starts_with("CARGO_PKG_"))
            .collect();
        assert!(inherited.iter().any(|name| name == "CARGO_MANIFEST_DIR"));

        let mut command = Command::new("cargo");
        without_package_environment(&mut command);
        let removed = removed(&command);

        for name in &inherited {
            assert!(removed.contains(name), "{name:?} reaches the xtask cargo");
        }
    }

    #[test]
    fn n_cargo_configuration_and_look_alike_names_reach_the_xtask_child() {
        for name in [
            "CARGO",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_JOBS",
            "CARGO_INCREMENTAL",
            "RUSTFLAGS",
            "CARGO_PKG",
            "XCARGO_PKG_NAME",
            "CARGO_MANIFEST_DIRS",
        ] {
            assert!(!is_package_variable(OsStr::new(name)), "{name}");
        }
        let mut command = Command::new("cargo");
        without_package_environment(&mut command);
        assert!(removed(&command).iter().all(|name| is_package_variable(name)));
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn every_exact_crate_request_uses_the_light_runner() {
        for name in [
            "rustfs-gateway",
            "s3gate",
            "conformance",
            "rustfs-gateway-conformance",
            "core",
            "rustfs-gateway-core",
            "rustfs-gateway-sig",
            "rustfs-gateway-http",
            "rustfs-gateway-types",
            "rustfs-gateway-server",
            "rustfs-gateway-goldens",
            "xtask",
        ] {
            assert_eq!(runner_for_request(&strings(&["verify", "--crate", name])), LIGHT_RUNNER, "{name}");
            assert_eq!(
                runner_for_request(&strings(&["verify", "--json", "--crate", name])),
                LIGHT_RUNNER,
                "{name}"
            );
        }
    }

    #[test]
    fn n_no_other_request_selects_a_graph_that_links_the_facade() {
        let requests: [&[&str]; 6] = [
            &["codegen"],
            &["verify", "--all"],
            &["verify"],
            &["verify", "--crate", "core", "extra"],
            &["conformance", "run"],
            &[],
        ];
        for arguments in requests {
            assert_eq!(runner_for_request(&strings(arguments)), LIGHT_RUNNER, "{arguments:?}");
        }
        assert!(!LIGHT_RUNNER.contains(&"--features"), "the light runner must enable no feature");
    }

    #[test]
    fn n_operation_verification_keeps_its_bounded_in_process_graph() {
        assert_eq!(runner_for_request(&strings(&["verify", "--op", "GetObject"])), OPERATION_RUNNER);
        assert_eq!(runner_for_request(&strings(&["verify", "--json", "--op", "GetObject"])), OPERATION_RUNNER);
        assert_eq!(runner_for_request(&strings(&["verify", "--op"])), LIGHT_RUNNER);
    }
}
