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

#[test]
fn required_streaming_payload_is_injected_once_before_other_bindings() {
    let generated = body(&artifacts(), "generated/codec/ops/put_object_annotation.rs");
    let constructor = "let mut input = Input::from_required_body(body.into_required_stream()?);";
    assert!(generated.contains(constructor), "the decoder did not inject the live request body");
    assert_eq!(
        generated.matches("body.into_required_stream()").count(),
        1,
        "the live body was consumed more than once"
    );
    assert!(
        !generated.contains("input.annotation_payload ="),
        "the decoder reassigned the required body after controlled construction"
    );
    assert!(
        generated.find(constructor) < generated.find("input.bucket ="),
        "the required body must exist before ordinary bindings are decoded"
    );
}
