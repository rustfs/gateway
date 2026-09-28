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

//! Pinned external signing-suite process boundary.
//!
//! Responsible for: fetching the protected smithy-rs revision and invoking the sig crate's real
//! suite test against that clean checkout. NOT responsible for: signing assertions or case
//! disposition, which remain in the sig test and protected lock. Upstream: the protected suite
//! lock. Downstream: CI and maintainers running `cargo xtask sigsuite`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::nested_cargo::without_package_environment;

const LOCK: &str = include_str!("../../spec/third-party/aws-signing-test-suite.lock");

struct SuiteLock<'a> {
    repository: &'a str,
    commit: &'a str,
    suite_path: &'a str,
}

pub(crate) fn command(args: &[String]) -> ExitCode {
    let result = match args {
        [action] if action == "fetch" => fetch().map(|path| {
            println!("fetched aws-signing-test-suite @ {} -> {}", lock().commit, path.display());
        }),
        [action] if action == "run" => run(),
        _ => Err("usage: cargo xtask sigsuite <fetch|run>".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("sigsuite: {error}");
            ExitCode::FAILURE
        }
    }
}

fn lock() -> SuiteLock<'static> {
    SuiteLock {
        repository: lock_string("repository"),
        commit: lock_string("commit"),
        suite_path: lock_string("suite_path"),
    }
}

fn lock_string(name: &str) -> &'static str {
    let prefix = format!("{name} = \"");
    LOCK.lines()
        .find_map(|line| line.strip_prefix(&prefix).and_then(|value| value.strip_suffix('"')))
        .unwrap_or_else(|| panic!("protected signing-suite lock has no valid {name}"))
}

fn root() -> PathBuf {
    crate::repo_root::repo_root()
}

fn checkout() -> PathBuf {
    root().join("target/third-party/smithy-rs-signing-suite")
}

fn fetch() -> Result<PathBuf, String> {
    let lock = lock();
    let checkout = checkout();
    if checkout.exists() {
        validate_checkout(&checkout)?;
        return Ok(checkout);
    }

    let parent = checkout.parent().expect("checkout has a parent");
    std::fs::create_dir_all(parent).map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    let temporary = parent.join(format!("smithy-rs-signing-suite.fetch-{}", std::process::id()));
    if temporary.exists() {
        return Err(format!("temporary fetch path already exists: {}", temporary.display()));
    }

    let fetched = (|| {
        std::fs::create_dir(&temporary).map_err(|error| format!("cannot create {}: {error}", temporary.display()))?;
        git(&["init", "--quiet"], &temporary)?;
        git(&["remote", "add", "origin", lock.repository], &temporary)?;
        git(&["sparse-checkout", "init", "--cone"], &temporary)?;
        git(&["sparse-checkout", "set", lock.suite_path], &temporary)?;
        git(&["fetch", "--depth=1", "--filter=blob:none", "origin", lock.commit], &temporary)?;
        git(&["checkout", "--quiet", "--detach", "FETCH_HEAD"], &temporary)?;
        validate_checkout(&temporary)?;
        std::fs::rename(&temporary, &checkout)
            .map_err(|error| format!("cannot install checkout at {}: {error}", checkout.display()))?;
        Ok(checkout.clone())
    })();
    if fetched.is_err() {
        let _ = std::fs::remove_dir_all(&temporary);
    }
    fetched.map_err(|error: String| {
        format!("external suite is unavailable: {error}; check the network or reuse the validated target cache")
    })
}

fn git(args: &[&str], directory: &Path) -> Result<(), String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(directory);
    command.args(args);
    let status = command.status().map_err(|error| format!("git could not start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("git exited with {status}"))
    }
}

fn validate_checkout(checkout: &Path) -> Result<(), String> {
    let status = Command::new(root().join("scripts/check_signing_suite_lock.sh"))
        .args(["--checkout", checkout.to_str().ok_or("checkout path is not UTF-8")?])
        .status()
        .map_err(|error| format!("checkout guard could not start: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| "checkout does not match the protected lock".to_owned())
}

fn suite_cargo_command() -> Command {
    let mut command = Command::new("cargo");
    without_package_environment(&mut command);
    command
}

fn run() -> Result<(), String> {
    let lock = lock();
    let checkout = checkout();
    validate_checkout(&checkout).map_err(|error| format!("run `cargo xtask sigsuite fetch` first: {error}"))?;
    let suite = checkout.join(lock.suite_path);
    let status = suite_cargo_command()
        .current_dir(root())
        .args([
            "test",
            "-p",
            "rustfs-gateway-sig",
            "--lib",
            "full_chain_tests::c_sig_official_suite",
            "--",
            "--exact",
        ])
        .env("S3GATE_AWS_SIGV4_SUITE_DIR", suite.join("v4"))
        .env("S3GATE_AWS_SIGV4A_SUITE_DIR", suite.join("v4a"))
        .status()
        .map_err(|error| format!("suite test could not start: {error}"))?;
    status
        .success()
        .then_some(())
        .ok_or_else(|| format!("suite test exited with {status}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_requires_an_exact_action() {
        assert_eq!(command(&[]), ExitCode::FAILURE);
        assert_eq!(command(&["unknown".to_owned()]), ExitCode::FAILURE);
    }

    #[test]
    fn suite_uses_the_repository_selected_cargo() {
        assert_eq!(suite_cargo_command().get_program(), "cargo");
    }
}
