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

//! P7-02 ownership and dependency guard positive controls.
//!
//! Responsible for: making the three source-guard case IDs part of the crate-local test suite.
//! NOT responsible for: mutations; `scripts/test_guard_scripts.sh` proves each guard can fail.
//! Upstream: repository scripts. Downstream: `cargo xtask verify --crate server`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("server crate is two levels below the repository root")
        .to_owned()
}

fn assert_guard(script: &str) {
    let root = repository_root();
    let status = Command::new(root.join("scripts").join(script))
        .current_dir(&root)
        .status()
        .expect("guard starts");
    assert!(status.success(), "{script} failed its positive control");
}

#[test]
fn a_srv_0021_ring_one_dependencies_stay_in_the_reviewed_allowlist() {
    assert_guard("check_ring_boundaries.sh");
}

#[test]
fn a_srv_0022_host_normalization_remains_outside_the_server_runtime() {
    assert_guard("check_no_host_normalize.sh");
}

#[test]
fn a_srv_0023_body_and_handler_timeouts_remain_outside_the_server_runtime() {
    assert_guard("check_timeout_layer_ownership.sh");
}
