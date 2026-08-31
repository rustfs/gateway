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

//! RustFS ecstore source-(a) persistence fixtures shared by family matrices.
//!
//! Responsible for: binding exact repository bytes to every physical source reference that owns
//! them. NOT responsible for: parsing the bytes or deciding D1-D5 compatibility. Upstream: RustFS
//! ecstore metadata tests at the pinned revision. Downstream: Tagging and Replication goldens.

use crate::ConfigKind;

/// The RustFS revision that owns these physical fixtures.
pub(crate) const SOURCE_REVISION: &str = "c876df53f5097618b1817568a471cbb8b4f26ee8";

/// Exact bytes, SHA-256, and all repository locations sharing those bytes.
pub(crate) type FixtureBinding = (&'static [u8], &'static str, &'static [&'static str]);

const TAGGING_ENV_PROD: &[u8] = b"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>";
const TAGGING_COMPLETE: &[u8] = b"<Tagging><TagSet><Tag><Key>Environment</Key><Value>Test</Value></Tag><Tag><Key>Owner</Key><Value>RustFS</Value></Tag></TagSet></Tagging>";
const REPLICATION_DELETE_ADMISSION: &[u8] = b"<ReplicationConfiguration><Role>arn:aws:s3:::target-bucket</Role><Rule><ID>rule1</ID><Status>Enabled</Status><Prefix></Prefix><Destination><Bucket>arn:aws:s3:::target-bucket</Bucket></Destination></Rule></ReplicationConfiguration>";
const REPLICATION_COMPLETE: &[u8] = b"<ReplicationConfiguration><Role>arn:aws:iam::123456789012:role/replication-role</Role><Rule><ID>rule1</ID><Status>Enabled</Status><Prefix>documents/</Prefix><Destination><Bucket>arn:aws:s3:::destination-bucket</Bucket></Destination></Rule></ReplicationConfiguration>";

const TAGGING_ENV_PROD_REFS: &[&str] =
    &["crates/ecstore/src/bucket/metadata.rs::tests::tagging_update_config_clears_parsed_config_on_delete::tagging_xml"];
const TAGGING_COMPLETE_REFS: &[&str] = &[
    "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::tagging_xml",
    "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::tagging_xml",
];
const REPLICATION_DELETE_ADMISSION_REFS: &[&str] =
    &["crates/ecstore/src/bucket/metadata.rs::tests::delete_admission_configs_update_parsed_state_atomically::replication_xml"];
const REPLICATION_COMPLETE_REFS: &[&str] = &[
    "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::replication_xml",
    "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::replication_xml",
];

const FIXTURES: [(ConfigKind, FixtureBinding); 4] = [
    (
        ConfigKind::Tagging,
        (
            TAGGING_ENV_PROD,
            "6a6c84a2c75d7125d9792de21a0fef4d7f65c8ce107709c1b68d2f8264ab90ba",
            TAGGING_ENV_PROD_REFS,
        ),
    ),
    (
        ConfigKind::Tagging,
        (
            TAGGING_COMPLETE,
            "7f46d946932dcb5747aefef2fe35536332a37d0df71354675804b484689dc826",
            TAGGING_COMPLETE_REFS,
        ),
    ),
    (
        ConfigKind::Replication,
        (
            REPLICATION_DELETE_ADMISSION,
            "0e4d3bc8b51d7c8b9ada416d2163c617cdf9d47e9884a68ced18e0628a87ebf5",
            REPLICATION_DELETE_ADMISSION_REFS,
        ),
    ),
    (
        ConfigKind::Replication,
        (
            REPLICATION_COMPLETE,
            "edde78c0ac00775fd038a4841bc9ebeb5929b118eaa5e1ea127ee8c062aae126",
            REPLICATION_COMPLETE_REFS,
        ),
    ),
];

/// Returns each SHA-deduplicated fixture for one persistence family.
pub(crate) fn fixture_bindings(kind: ConfigKind) -> impl Iterator<Item = FixtureBinding> {
    FIXTURES
        .into_iter()
        .filter(move |(fixture_kind, _)| *fixture_kind == kind)
        .map(|(_, binding)| binding)
}

/// Renders one primary repository location plus any exact-byte aliases.
pub(crate) fn provenance_source(source_refs: &[&str]) -> String {
    let Some((primary, aliases)) = source_refs.split_first() else {
        return String::new();
    };
    if aliases.is_empty() {
        (*primary).to_owned()
    } else {
        format!("{primary} (aliases: {})", aliases.join(", "))
    }
}
