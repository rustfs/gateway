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

//! The `--profile rustfs` contract on the command line.
//!
//! Responsible for: the spelling, and the refusal of the claim without an external endpoint — the
//! bundled reference assembly does not run the RustFS preset, so a `rustfs` run over it would
//! report a profile the target never had.
//! NOT responsible for: the gate on `case.applies_to.profiles`, which `runner::profile_tests` owns.
//! Upstream: `super`. Downstream: Cargo's test harness.

use super::tests::args;
use super::*;

#[test]
fn the_rustfs_profile_parses_with_an_endpoint() {
    let options = Options::parse(&args(&["run", "--profile", "rustfs", "--endpoint", "http://127.0.0.1:9100"]))
        .expect("parses")
        .expect("not help");
    assert_eq!(options.profile, Profile::Rustfs);
    assert_eq!(options.transport, Transport::Conn);
}

/// Negative — the claim names a RustFS candidate, and the in-process target is not one.
#[test]
fn the_rustfs_profile_without_an_endpoint_is_a_usage_error() {
    for command in ["run", "baseline", "diff-transports", "audit-keys"] {
        let error = Options::parse(&args(&[command, "--profile", "rustfs"])).expect_err(command);
        assert!(error.contains("--endpoint") && error.contains("rustfs"), "{command}: {error}");
    }
}

/// Negative — `validate` contacts no target, so the profile it would claim is irrelevant, and the
/// refusal still holds: an option that is accepted on one command and refused on another is the
/// kind of thing a reader has to look up.
#[test]
fn validate_under_the_rustfs_profile_is_refused_like_every_other_local_command() {
    let error = Options::parse(&args(&["validate", "--profile", "rustfs"])).expect_err("validate");
    assert!(error.contains("--endpoint"), "{error}");
}

#[test]
fn the_other_profiles_still_parse_without_an_endpoint() {
    for profile in ["aws", "minio", "strict"] {
        let options = Options::parse(&args(&["run", "--profile", profile]))
            .expect("parses")
            .expect("not help");
        assert_eq!(options.profile.as_str(), profile);
    }
}
