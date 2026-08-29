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

//! Tagging-family code-generation regression tests.
//!
//! Responsible for: proving tagging codec rules read each declared typed source.
//! NOT responsible for: exercising the generated codec on an HTTP exchange.
//! Upstream: the lowered tagging overlays. Downstream: generated quirk tables and codecs.

use super::codegen_tests::artifacts;

#[test]
fn tagging_count_omission_reads_both_mirrored_output_fields() {
    let artifacts = artifacts();
    let (_, emitted) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-tag-count-omit-0095.toml"))
        .expect("the tag-count omission rule is a typed mutation source");

    assert!(emitted.contains("mutation_dimension = \"omit_strategy\""));
    assert!(
        emitted.contains("path = \"GetObject.output.TagCount.omit_when\"\ncurrent = \"ValueEquals(0)\""),
        "GetObject must expose its own typed omission source"
    );
    assert!(
        emitted.contains("path = \"HeadObject.output.TagCount.omit_when\"\ncurrent = \"ValueEquals(0)\""),
        "HeadObject must expose its own typed omission source"
    );
}
