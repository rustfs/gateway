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

//! What the CopyObject codec emits when the backend has no entity tag.
//!
//! Responsible for: the optional CopyObject response member's wire omission.
//! NOT responsible for: response generation or any other operation.
//! Upstream: the shared codec test fixtures. Downstream: nothing; this is a leaf.

use super::*;

#[test]
fn n_omits_a_missing_copy_object_entity_tag() {
    let request = accepted("PUT", "/photos/key", &[("x-amz-copy-source", "source/key")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::CopyObjectOutput {
        e_tag: None,
        last_modified: Some(Timestamp::from_secs(1_700_000_000)),
        ..Default::default()
    };
    let response = dto::CopyObject::encode(output, &view, 200).expect("encodes");
    let body = body_text(&response.body);

    assert!(body.contains("<CopyObjectResult"), "{body}");
    assert!(!body.contains("<ETag>"), "a missing ETag must not produce an empty element: {body}");
    assert!(body.contains("<LastModified>2023-11-14T22:13:20.000Z</LastModified>"), "{body}");
}
