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

//! Fail-closed census for RustFS ecstore Replication source-(a) fixtures.
//!
//! Responsible for: independently pinning fixture SHA, source aliases, revision, and D1-D5 reach.
//! NOT responsible for: defining fixture bytes or codec behavior. Upstream: the Replication sample
//! registry. Downstream: the source-(a) completeness gate.

use super::{accepted_cases, assert_replication_four_way};

#[test]
fn ecstore_replication_fixtures_are_registered_once_by_exact_sha() {
    for (sha256, source) in [
        (
            "0e4d3bc8b51d7c8b9ada416d2163c617cdf9d47e9884a68ced18e0628a87ebf5",
            "crates/ecstore/src/bucket/metadata.rs::tests::delete_admission_configs_update_parsed_state_atomically::replication_xml",
        ),
        (
            "edde78c0ac00775fd038a4841bc9ebeb5929b118eaa5e1ea127ee8c062aae126",
            "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::replication_xml (aliases: crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::replication_xml)",
        ),
    ] {
        let matches = accepted_cases()
            .into_iter()
            .filter(|(sample, _)| sample.origin.sha256 == sha256)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "the ecstore Replication SHA must be registered exactly once");
        let sample = &matches[0].0;
        assert_eq!(sample.origin.source, source);
        assert_eq!(sample.origin.version, "c876df53f5097618b1817568a471cbb8b4f26ee8");
        assert_replication_four_way(sample).expect("the RustFS ecstore Replication fixture passes D1-D5");
    }
}
