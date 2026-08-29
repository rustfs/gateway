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

//! Regression coverage for structure members whose non-empty XML loses every unknown child.
//!
//! Responsible for: proving the generated guard and its recognized names come from the typed
//! Filter rule. NOT responsible for: runtime XML parsing, covered by the core integration test.
//! Upstream: replication overlays and codec emission. Downstream: generated request codecs.

use super::codegen_tests::{artifacts, body};

#[test]
fn the_replication_filter_guard_uses_its_shape_child_names() {
    let generated = body(&artifacts(), "generated/codec/ops/put_bucket_replication.rs");

    assert!(generated.contains("if !child.children.is_empty()"), "{generated}");
    assert!(generated.contains("let recognized = [\"And\", \"Prefix\", \"Tag\"];"), "{generated}");
    assert!(generated.contains("recognized.contains(&nested.name.as_str())"), "{generated}");
    assert!(
        generated.contains("a non-empty structure contains no recognized child element"),
        "{generated}"
    );
}
