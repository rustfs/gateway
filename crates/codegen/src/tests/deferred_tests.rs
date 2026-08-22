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

//! Generated capability boundaries for responses that may fail after their status is sent.
//!
//! Responsible for: pinning the exact IR-selected operation set that receives the sealed deferred
//! capability. NOT responsible for: runtime task or response-head behavior.
//! Upstream: the lowered operation IR. Downstream: generated core codec modules.

#[test]
fn only_the_three_ir_marked_operations_receive_the_deferred_capability() {
    let artifacts = super::codegen_tests::artifacts();
    let mut marked = artifacts
        .files
        .iter()
        .filter(|(_, body)| body.contains("impl crate::handler::DeferredOperation for dto::"))
        .filter_map(|(path, _)| path.file_stem().and_then(|name| name.to_str()))
        .collect::<Vec<_>>();
    marked.sort_unstable();

    assert_eq!(
        marked,
        ["complete_multipart_upload", "copy_object", "upload_part_copy"],
        "the sealed capability must follow the exact IR set"
    );
}
