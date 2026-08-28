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
//! budget enforcement. Upstream: the Cargo alias. Downstream: the full or light xtask runner.

use std::ffi::OsString;
use std::process::{Command, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

const STARTED_ENV: &str = "RUSTFS_GATEWAY_XTASK_STARTED_UNIX_NANOS";
const FULL_RUNNER: &[&str] = &["--features", "full"];
const LIGHT_RUNNER: &[&str] = &["--no-default-features"];

fn crate_request_name(arguments: &[String]) -> Option<&str> {
    if arguments.first().map(String::as_str) != Some("verify") {
        return None;
    }
    let mut verify_arguments = arguments[1..]
        .iter()
        .map(String::as_str)
        .filter(|argument| *argument != "--json");
    match (verify_arguments.next(), verify_arguments.next(), verify_arguments.next()) {
        (Some("--crate"), Some(name), None) => Some(name),
        _ => None,
    }
}

fn runner_for_request(arguments: &[String]) -> &'static [&'static str] {
    match crate_request_name(arguments) {
        Some("rustfs-gateway" | "s3gate") | None => LIGHT_RUNNER,
        Some(_) => FULL_RUNNER,
    }
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
    let status = Command::new(&cargo)
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
    use super::{FULL_RUNNER, LIGHT_RUNNER, runner_for_request};

    #[test]
    fn the_facade_uses_the_light_runner_without_changing_other_selection() {
        let strings = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>();

        for name in ["rustfs-gateway", "s3gate"] {
            assert_eq!(runner_for_request(&strings(&["verify", "--crate", name])), LIGHT_RUNNER);
            assert_eq!(runner_for_request(&strings(&["verify", "--json", "--crate", name])), LIGHT_RUNNER);
        }
        assert_eq!(runner_for_request(&strings(&["verify", "--crate", "core"])), FULL_RUNNER);
        assert_eq!(runner_for_request(&strings(&["codegen"])), LIGHT_RUNNER);
        assert_eq!(runner_for_request(&strings(&["verify", "--op", "GetObject"])), LIGHT_RUNNER);
        assert_eq!(runner_for_request(&strings(&["verify", "--json", "--op", "GetObject"])), LIGHT_RUNNER);
        assert_eq!(runner_for_request(&strings(&["verify", "--crate", "core", "extra"])), LIGHT_RUNNER);
    }
}
