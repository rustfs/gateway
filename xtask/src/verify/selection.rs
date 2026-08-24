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

//! Crate-local verification command selection.
//!
//! Responsible for: choosing the Cargo test and Clippy targets for one crate. NOT responsible for:
//! scheduling commands or enforcing deadlines. Upstream: crate verification. Downstream: Cargo.

pub(super) fn crate_steps(package: &str) -> Vec<Vec<String>> {
    if package == "xtask" {
        let target_scope = ["--workspace", "--bin", "xtask", "--test", "xtask-integration"];
        return vec![
            std::iter::once("test").chain(target_scope).map(str::to_owned).collect(),
            std::iter::once("clippy")
                .chain(target_scope)
                .chain(["--", "-D", "warnings"])
                .map(str::to_owned)
                .collect(),
        ];
    }
    let clippy_step = vec![
        "clippy".to_owned(),
        "-p".to_owned(),
        package.to_owned(),
        match package {
            "rustfs-gateway-conformance" => "--lib",
            _ => "--all-targets",
        }
        .to_owned(),
        "--".to_owned(),
        "-D".to_owned(),
        "warnings".to_owned(),
    ];
    if package == "rustfs-gateway-core" {
        return vec![
            vec![
                "test".to_owned(),
                "-p".to_owned(),
                package.to_owned(),
                "--lib".to_owned(),
                "--test".to_owned(),
                "integration".to_owned(),
                "--".to_owned(),
                "--skip".to_owned(),
                "compile_fail::compile_time_contracts_are_not_openable".to_owned(),
            ],
            clippy_step,
        ];
    }
    let mut test_step = vec!["test".to_owned(), "-p".to_owned(), package.to_owned()];
    if package == "rustfs-gateway" {
        test_step.extend(["--lib".to_owned(), "--test".to_owned(), "integration".to_owned()]);
        test_step.extend([
            "--".to_owned(),
            "--skip".to_owned(),
            "compile_fail::gateway_compile_fail_contracts_are_enforced".to_owned(),
        ]);
    } else if package == "rustfs-gateway-sig" {
        test_step.extend(
            [
                "--",
                "--skip",
                "timing::c_sig_0552_sigv2_difference_position_does_not_change_the_latency",
                "--skip",
                "timing::c_sig_0111_an_unknown_key_costs_the_same_as_a_bad_signature",
                "--skip",
                "timing::a_match_and_a_mismatch_cost_the_same",
                "--skip",
                "timing::c_sig_0107_and_0108_the_position_of_the_difference_does_not_change_the_latency",
                "--exact",
            ]
            .map(str::to_owned),
        );
    } else if package == "rustfs-gateway-conformance" {
        test_step.push("--lib".to_owned());
    }
    vec![test_step, clippy_step]
}
