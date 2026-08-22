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

//! Generated request-body handoff contracts.
//!
//! Responsible for: proving codecs publish the lowered buffering mode. NOT responsible for:
//! choosing that mode in the model. Upstream: code generation. Downstream: runtime dispatch.

use super::codegen_tests::{artifacts, body};

#[test]
fn generated_codecs_publish_the_request_body_mode() {
    let artifacts = artifacts();
    for (operation, mode) in [
        ("put_object", "Streaming"),
        ("delete_objects", "Full"),
        ("get_object", "None"),
    ] {
        let generated = body(&artifacts, &format!("generated/codec/ops/{operation}.rs"));
        assert!(
            generated.contains(&format!("const REQUEST_BODY: RequestBodyMode = RequestBodyMode::{mode};")),
            "{operation} lost its {mode} request-body handoff"
        );
    }
}
