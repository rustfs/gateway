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

//! Route-only generation boundaries.
//!
//! Responsible for: proving a protocol-known selector can reach the route table without minting
//! a DTO, codec, operation spec or handler-macro registration.
//! NOT responsible for: runtime route resolution and dispatch, which core integration tests own.
//! Upstream: the pinned model and reviewed overlays. Downstream: generated runtime data.

use super::codegen_tests::{artifacts, body};

#[test]
fn create_session_emits_only_route_level_artifacts() {
    let artifacts = artifacts();
    let routes = body(&artifacts, "generated/routes.rs");
    let operations = body(&artifacts, "generated/OPERATIONS.json");
    let macro_names = body(&artifacts, "crates/macros/src/op_names.rs");
    let operations_md = body(&artifacts, "OPERATIONS.md");

    assert!(routes.contains("operation: \"CreateSession\",\n        handler_registration: false,"));
    assert!(operations_md.contains("| CreateSession | `GET /{Bucket}` |"));
    assert!(!operations.contains("CreateSession"));
    assert!(!macro_names.contains("CreateSession"));

    let forbidden_paths = [
        "spec/operations/CreateSession.toml",
        "generated/ir/CreateSession.json",
        "generated/dto/ops/create_session.rs",
        "generated/codec/ops/create_session.rs",
    ];
    for suffix in forbidden_paths {
        assert!(
            artifacts
                .files
                .iter()
                .all(|(path, _)| !path.to_string_lossy().ends_with(suffix)),
            "route-only generation must not emit {suffix}"
        );
    }
}
