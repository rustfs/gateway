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

//! The environment a child process started by xtask inherits.
//!
//! Responsible for: removing the per-package variables `cargo run` put into this process's own
//! environment before a child — above all a nested Cargo — inherits them.
//! NOT responsible for: choosing commands, arguments, or any user-set Cargo configuration.
//! Upstream: every place xtask starts Cargo. Downstream: `std::process::Command`.
//!
//! `cargo run --package xtask` gives xtask `CARGO_MANIFEST_DIR`, `CARGO_MANIFEST_PATH` and the
//! `CARGO_PKG_*` family of the xtask package. A build script that declares
//! `rerun-if-env-changed` on one of them — `ring` does, for `CARGO_MANIFEST_DIR` and
//! `CARGO_PKG_*` — is judged against the environment of the Cargo that builds it. A nested Cargo
//! inheriting xtask's values therefore sees them differ from the shell's, reruns the script and
//! rebuilds everything above it: `ring`, `rustls`, the server, the facade, conformance and xtask
//! itself, once inside the verification, and again at the next command from a shell.

use std::ffi::OsStr;
use std::process::Command;

/// Whether `name` is one of the variables `cargo run` sets for the package it runs.
///
/// Only those are removed. `CARGO` (the Cargo binary a nested command must reuse) and every
/// variable a user sets to configure Cargo — `CARGO_HOME`, `CARGO_TARGET_DIR`,
/// `CARGO_BUILD_JOBS`, `CARGO_INCREMENTAL`, `RUSTFLAGS` — pass through untouched.
fn is_package_variable(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    matches!(name, "CARGO_MANIFEST_DIR" | "CARGO_MANIFEST_PATH") || name.starts_with("CARGO_PKG_")
}

/// Removes from `command` every package variable this process inherited from `cargo run`, so the
/// child sees the environment the shell that started `cargo xtask` had.
pub(crate) fn without_package_environment(command: &mut Command) -> &mut Command {
    for (name, _) in std::env::vars_os() {
        if is_package_variable(&name) {
            command.env_remove(name);
        }
    }
    command
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::process::Command;

    use super::{is_package_variable, without_package_environment};

    fn removed(command: &Command) -> Vec<OsString> {
        command
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(name, _)| name.to_owned())
            .collect()
    }

    /// `cargo test` gives this test binary the same package variables `cargo run` gives xtask,
    /// so the process environment here is the real input, not a list copied from Cargo's docs.
    #[test]
    fn every_package_variable_cargo_set_for_this_process_is_removed() {
        let inherited: Vec<OsString> = std::env::vars_os()
            .map(|(name, _)| name)
            .filter(|name| name == "CARGO_MANIFEST_DIR" || name.to_string_lossy().starts_with("CARGO_PKG_"))
            .collect();
        assert!(
            inherited.iter().any(|name| name == "CARGO_MANIFEST_DIR"),
            "cargo test must provide the variables this contract is about"
        );
        assert!(inherited.iter().any(|name| name == "CARGO_PKG_NAME"));

        let mut command = Command::new("cargo");
        without_package_environment(&mut command);
        let removed = removed(&command);

        for name in &inherited {
            assert!(removed.contains(name), "{name:?} reaches a nested cargo");
        }
    }

    #[test]
    fn n_the_cargo_binary_and_user_cargo_configuration_are_not_package_variables() {
        for name in [
            "CARGO",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_JOBS",
            "CARGO_INCREMENTAL",
            "CARGO_TERM_COLOR",
            "RUSTFLAGS",
            "RUSTUP_TOOLCHAIN",
            "PATH",
        ] {
            assert!(!is_package_variable(OsStr::new(name)), "{name} must reach a nested cargo");
        }
    }

    #[test]
    fn n_a_name_that_only_resembles_a_package_variable_is_kept() {
        for name in [
            "CARGO_PKG",
            "XCARGO_PKG_NAME",
            "cargo_pkg_name",
            "CARGO_MANIFEST",
            "CARGO_MANIFEST_DIRS",
        ] {
            assert!(!is_package_variable(OsStr::new(name)), "{name}");
        }
    }

    #[test]
    fn n_nothing_but_package_variables_is_removed() {
        let mut command = Command::new("cargo");
        without_package_environment(&mut command);

        for name in removed(&command) {
            assert!(is_package_variable(&name), "{name:?} was removed");
        }
        assert!(!removed(&command).iter().any(|name| name == "CARGO" || name == "PATH"));
    }

    #[test]
    fn n_values_the_caller_set_explicitly_are_left_for_the_caller() {
        let mut command = Command::new("cargo");
        command.env("GATEWAY_EXPLICIT", "1");
        without_package_environment(&mut command);

        assert!(
            command
                .get_envs()
                .any(|(name, value)| name == "GATEWAY_EXPLICIT" && value == Some(OsStr::new("1")))
        );
    }
}
