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

//! Replication source-(a) union-census rows.
//!
//! Responsible for: exposing Replication source references and byte identities to the union census.
//! NOT responsible for: codec behavior, sample construction, or aggregate census policy.
//! Upstream: Replication-owned fixture constants. Downstream: the source-(a) union census.

use crate::ConfigKind;
use crate::source_a_census::SourceARow;

use super::{NEW_WRITER_REPLICATION_SHA256, NEW_WRITER_REPLICATION_SOURCE};

pub(crate) fn source_a_rows() -> Vec<SourceARow> {
    vec![
        SourceARow::accepted_sample(
            ConfigKind::Replication,
            "crates/replication/src/config.rs::explicit_standard_storage_class_is_accepted_from_wire_xml",
            "2560f5c5c7d9d9c7cec7b2243e7bc8a0893c0365f6246cdec4da334c4902bfa1",
        ),
        SourceARow::accepted_sample(
            ConfigKind::Replication,
            "crates/replication/src/config.rs::historical_destination_fields_survive_the_s3_xml_round_trip",
            "e43422968e98588f09f159bed479bf8388293910fd13569f2c72c62699babe82",
        ),
        SourceARow::accepted_sample(
            ConfigKind::Replication,
            "crates/replication/src/config.rs::s3_xml_parser_discards_unknown_replication_elements_before_validation",
            "6255f7f096dc3ec330244406b5340f20aba3349491025e8d4f189ea158936d2d",
        ),
        SourceARow::accepted_sample(ConfigKind::Replication, NEW_WRITER_REPLICATION_SOURCE, NEW_WRITER_REPLICATION_SHA256),
    ]
}
