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

//! Fail-closed union census for RustFS source-(a) persistence fixtures.
//!
//! Responsible for: binding every audited physical source reference to one kind, digest,
//! disposition, and sample/alias role. NOT responsible for: discovering RustFS source or parsing
//! XML. Upstream: family-owned source-(a) binding tables. Downstream: the golden corpus gate.

use crate::{ConfigKind, FamilyCorpusEvidence};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceADisposition {
    Accepted,
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceASampleMode {
    Sample,
    Alias,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SourceARow {
    pub(crate) kind: ConfigKind,
    pub(crate) source_ref: &'static str,
    pub(crate) sha256: &'static str,
    pub(crate) disposition: SourceADisposition,
    pub(crate) sample_mode: SourceASampleMode,
}

impl SourceARow {
    pub(crate) const fn accepted_sample(kind: ConfigKind, source_ref: &'static str, sha256: &'static str) -> Self {
        Self {
            kind,
            source_ref,
            sha256,
            disposition: SourceADisposition::Accepted,
            sample_mode: SourceASampleMode::Sample,
        }
    }

    pub(crate) const fn accepted_alias(kind: ConfigKind, source_ref: &'static str, sha256: &'static str) -> Self {
        Self {
            kind,
            source_ref,
            sha256,
            disposition: SourceADisposition::Accepted,
            sample_mode: SourceASampleMode::Alias,
        }
    }

    pub(crate) const fn refused_sample(kind: ConfigKind, source_ref: &'static str, sha256: &'static str) -> Self {
        Self {
            kind,
            source_ref,
            sha256,
            disposition: SourceADisposition::Refused,
            sample_mode: SourceASampleMode::Sample,
        }
    }
}

macro_rules! accepted_sample {
    ($kind:ident, $source:literal, $sha:literal) => {
        SourceARow::accepted_sample(ConfigKind::$kind, $source, $sha)
    };
}
macro_rules! accepted_alias {
    ($kind:ident, $source:literal, $sha:literal) => {
        SourceARow::accepted_alias(ConfigKind::$kind, $source, $sha)
    };
}
macro_rules! refused_sample {
    ($kind:ident, $source:literal, $sha:literal) => {
        SourceARow::refused_sample(ConfigKind::$kind, $source, $sha)
    };
}

const EXPECTED_ROWS: [SourceARow; 38] = [
    accepted_sample!(
        Cors,
        "conformance/fixtures/cors/one-hundred-rules.xml",
        "c248351230630ceec7b691fc3b627358c048ffd81d38fa1c46372a732d4fc62e"
    ),
    accepted_sample!(
        Cors,
        "conformance/fixtures/cors/hundred-and-one-rules.xml",
        "fac97360ccd3634249fa3480b26285dfcbc459a7f88abae55e19f30558598f6f"
    ),
    accepted_sample!(
        Cors,
        "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[BUCKET_CORS_CONFIG]",
        "64dbcc0152a855b9df46deda0d683c1fed82f265cf2b190cde87622e75a9d6d0"
    ),
    accepted_sample!(
        Lifecycle,
        "conformance/fixtures/lifecycle/one-thousand-rules.xml",
        "8474db2e2aa4e1e1bfee638c2447e5d5bc069e412693e214969f0d2f896dc606"
    ),
    accepted_sample!(
        Lifecycle,
        "conformance/fixtures/lifecycle/thousand-and-one-rules.xml",
        "44d626c690670ab97f5182b855e9832e923832833a1b9f0b168a105bf1d1849c"
    ),
    accepted_sample!(
        Lifecycle,
        "crates/ecstore/src/bucket/metadata.rs::lifecycle_update_config_clears_parsed_config_on_delete::lifecycle_xml",
        "d02252be7653043d28995e397c4953a0a405f287426d914ade100a3c7d1ea1b5"
    ),
    accepted_alias!(
        Lifecycle,
        "crates/ecstore/src/bucket/metadata.rs::marshal_msg_complete_example::lifecycle_xml",
        "d02252be7653043d28995e397c4953a0a405f287426d914ade100a3c7d1ea1b5"
    ),
    accepted_alias!(
        Lifecycle,
        "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::lifecycle_xml",
        "d02252be7653043d28995e397c4953a0a405f287426d914ade100a3c7d1ea1b5"
    ),
    accepted_sample!(
        Lifecycle,
        "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[BUCKET_LIFECYCLE_CONFIG]",
        "1a7189c8038cf900f74855cdc4131c644664bfb0ce04486e8c48fce41b5b4a0c"
    ),
    accepted_sample!(
        Replication,
        "crates/replication/src/config.rs::explicit_standard_storage_class_is_accepted_from_wire_xml",
        "2560f5c5c7d9d9c7cec7b2243e7bc8a0893c0365f6246cdec4da334c4902bfa1"
    ),
    accepted_sample!(
        Replication,
        "crates/replication/src/config.rs::historical_destination_fields_survive_the_s3_xml_round_trip",
        "e43422968e98588f09f159bed479bf8388293910fd13569f2c72c62699babe82"
    ),
    accepted_sample!(
        Replication,
        "crates/replication/src/config.rs::s3_xml_parser_discards_unknown_replication_elements_before_validation",
        "6255f7f096dc3ec330244406b5340f20aba3349491025e8d4f189ea158936d2d"
    ),
    accepted_sample!(
        Replication,
        "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[7] (BUCKET_REPLICATION_CONFIG -> NEW_WRITER_REPLICATION_XML)",
        "c4ee7b2dbff03b885bfc04e2c3141aef7a0ccd3a6b3a2d3129b9a91512271066"
    ),
    accepted_sample!(
        Replication,
        "crates/ecstore/src/bucket/metadata.rs::tests::delete_admission_configs_update_parsed_state_atomically::replication_xml",
        "0e4d3bc8b51d7c8b9ada416d2163c617cdf9d47e9884a68ced18e0628a87ebf5"
    ),
    accepted_sample!(
        Replication,
        "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::replication_xml",
        "edde78c0ac00775fd038a4841bc9ebeb5929b118eaa5e1ea127ee8c062aae126"
    ),
    accepted_alias!(
        Replication,
        "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::replication_xml",
        "edde78c0ac00775fd038a4841bc9ebeb5929b118eaa5e1ea127ee8c062aae126"
    ),
    accepted_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_bug_report_exact_scenario_xml",
        "6d8ad7df7053178be819bdf07ece233fb8b9d8d7a938ccdd2538261aeb3a7462"
    ),
    accepted_alias!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_url_encoded_keys",
        "6d8ad7df7053178be819bdf07ece233fb8b9d8d7a938ccdd2538261aeb3a7462"
    ),
    refused_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_prefix_only_filter_xml",
        "3d158a352ffad11be2a693a96f30323300a49c01abb5c87aa27ce214b6935c57"
    ),
    accepted_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_capitalized_filter_names_xml",
        "bda4c44ce912e6995e3b494705a46600deaa4a9b2943040cb8ecab4dc1549dbe"
    ),
    refused_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_suffix_only_filter_xml",
        "f1cbe0eb758ff2a6416d1e6acbafdc3b8a885c99139489d564d2291b0041f827"
    ),
    accepted_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_no_filter_xml",
        "d984eebb4c4cecdcd81785592e31d576c2ae88b32c4fe4e5dae5e1b8bb7a814b"
    ),
    accepted_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_specific_event_type_xml",
        "03be4d49be4600c44938b011807aa6fcc86fe7239d9146616110db9a2781d581"
    ),
    refused_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_multiple_queue_configs_xml",
        "813cdc05e81e0fbadb8a3f96d1189005ca2e44aac94083bfe98a8d9118206320"
    ),
    refused_sample!(
        Notification,
        "crates/notify/src/rules/config_test.rs::test_compound_event_expansion_integration",
        "c579c698faa21543dfcf82cf48264e36adb063ec01962195de23527e8857b3a9"
    ),
    accepted_sample!(
        Notification,
        "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[BUCKET_NOTIFICATION_CONFIG]",
        "c1f563b9bdb5fcdc9ef642ba79826762a94492d592ac89676fbc7e570b004c96"
    ),
    accepted_sample!(
        Notification,
        "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::notification_xml",
        "60f422ed2bc9a9d19766165bd86398ca147c32912a4579f344891624a26e9832"
    ),
    accepted_alias!(
        Notification,
        "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::notification_xml",
        "60f422ed2bc9a9d19766165bd86398ca147c32912a4579f344891624a26e9832"
    ),
    accepted_sample!(
        Logging,
        "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[9] (BUCKET_LOGGING_CONFIG)",
        "8765391c6f36056db1a73da9ddedce92f07391cfffd70687bafba7c53c8e981b"
    ),
    accepted_sample!(
        PublicAccessBlock,
        "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[13] (BUCKET_PUBLIC_ACCESS_BLOCK_CONFIG)",
        "a19ebff082ac54c44e8d434b02d1d14fdd7adfeb342d565738001869961f76e9"
    ),
    accepted_sample!(
        Tagging,
        "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[6] (BUCKET_TAGGING_CONFIG)",
        "e1c0bf5c6e7c7ae427dcdf6e0df463397fb3844504b25dbf5262f18a56505779"
    ),
    accepted_sample!(
        Tagging,
        "crates/ecstore/src/bucket/metadata.rs::tests::tagging_update_config_clears_parsed_config_on_delete::tagging_xml",
        "6a6c84a2c75d7125d9792de21a0fef4d7f65c8ce107709c1b68d2f8264ab90ba"
    ),
    accepted_sample!(
        Tagging,
        "crates/ecstore/src/bucket/metadata.rs::tests::marshal_msg_complete_example::tagging_xml",
        "7f46d946932dcb5747aefef2fe35536332a37d0df71354675804b484689dc826"
    ),
    accepted_alias!(
        Tagging,
        "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::tagging_xml",
        "7f46d946932dcb5747aefef2fe35536332a37d0df71354675804b484689dc826"
    ),
    accepted_alias!(
        Versioning,
        "crates/ecstore/src/store/mod.rs::ENABLED_VERSIONING_CONFIG",
        "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a"
    ),
    accepted_alias!(
        Versioning,
        "crates/ecstore/src/store/bucket.rs::handle_make_bucket::versioning_config_xml",
        "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a"
    ),
    accepted_alias!(
        ObjectLock,
        "crates/ecstore/src/store/mod.rs::ENABLED_OBJECT_LOCK_CONFIG",
        "9cf16b957c9f7a738af95d6962500ebaae0e23d0138c811a8b6f39bcc941bbb2"
    ),
    accepted_alias!(
        ObjectLock,
        "crates/ecstore/src/store/bucket.rs::handle_make_bucket::object_lock_config_xml",
        "9cf16b957c9f7a738af95d6962500ebaae0e23d0138c811a8b6f39bcc941bbb2"
    ),
];

fn actual_rows() -> Vec<SourceARow> {
    [
        crate::source_a_boundary::source_a_rows(),
        crate::source_a_lifecycle::source_a_rows(),
        crate::source_a_new_writer::source_a_rows(),
        crate::source_a_create_defaults::source_a_rows(),
        crate::ecstore_source_a::source_a_rows(),
        crate::replication::source_a_census::source_a_rows(),
        crate::notification::source_a_rows(),
        crate::tagging::source_a_rows(),
        crate::logging::source_a_rows(),
        crate::public_access_block::source_a_rows(),
    ]
    .concat()
}

fn validate_rows(expected: &[SourceARow], actual: &[SourceARow]) -> Result<(), String> {
    for (index, row) in actual.iter().enumerate() {
        if actual[..index].iter().any(|candidate| candidate.source_ref == row.source_ref) {
            return Err(format!("duplicate source-(a) reference: {}", row.source_ref));
        }
    }
    for expected_row in expected {
        let Some(actual_row) = actual.iter().find(|row| row.source_ref == expected_row.source_ref) else {
            return Err(format!("missing source-(a) reference: {}", expected_row.source_ref));
        };
        if actual_row != expected_row {
            return Err(format!(
                "wrong source-(a) binding for {}: expected {expected_row:?}, found {actual_row:?}",
                expected_row.source_ref
            ));
        }
    }
    if let Some(extra) = actual
        .iter()
        .find(|row| !expected.iter().any(|candidate| candidate.source_ref == row.source_ref))
    {
        return Err(format!("extra source-(a) reference: {}", extra.source_ref));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CorpusRegistration {
    kind: ConfigKind,
    sha256: String,
    disposition: SourceADisposition,
}

fn corpus_registrations(families: &[FamilyCorpusEvidence]) -> Vec<CorpusRegistration> {
    families
        .iter()
        .flat_map(FamilyCorpusEvidence::source_a_registrations)
        .map(|(kind, sha256, accepted)| CorpusRegistration {
            kind,
            sha256,
            disposition: if accepted {
                SourceADisposition::Accepted
            } else {
                SourceADisposition::Refused
            },
        })
        .collect()
}

fn distinct_expected_rows(expected: &[SourceARow]) -> Vec<SourceARow> {
    let mut distinct = Vec::new();
    for row in expected {
        if !distinct.iter().any(|candidate: &SourceARow| {
            (candidate.kind, candidate.sha256, candidate.disposition) == (row.kind, row.sha256, row.disposition)
        }) {
            distinct.push(*row);
        }
    }
    distinct
}

fn validate_membership(expected: &[SourceARow], registrations: &[CorpusRegistration]) -> Result<(), String> {
    let distinct = distinct_expected_rows(expected);
    if distinct.len() != 30 {
        return Err(format!("expected 30 distinct source-(a) digests, found {}", distinct.len()));
    }
    for row in distinct {
        let matches = registrations
            .iter()
            .filter(|registration| {
                registration.kind == row.kind && registration.sha256 == row.sha256 && registration.disposition == row.disposition
            })
            .count();
        if matches != 1 {
            return Err(format!(
                "source-(a) digest {} for {:?}/{:?} has {matches} corpus registrations; expected exactly one",
                row.sha256, row.kind, row.disposition
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate(families: &[FamilyCorpusEvidence]) -> Result<(), String> {
    let actual = actual_rows();
    validate_rows(&EXPECTED_ROWS, &actual)?;
    if actual.len() != 38 {
        return Err(format!("expected 38 physical source-(a) references, found {}", actual.len()));
    }
    validate_membership(&EXPECTED_ROWS, &corpus_registrations(families))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_a_union_is_exactly_thirty_eight_refs_and_thirty_distinct_digests() {
        let actual = actual_rows();
        validate_rows(&EXPECTED_ROWS, &actual).expect("the source-(a) union must match the audited closed set");
        assert_eq!(actual.len(), 38);
        let mut distinct = Vec::new();
        for row in actual {
            if !distinct.contains(&(row.kind, row.sha256, row.disposition)) {
                distinct.push((row.kind, row.sha256, row.disposition));
            }
        }
        assert_eq!(distinct.len(), 30);
    }

    #[test]
    fn census_rejects_a_missing_reference() {
        let mut actual = actual_rows();
        actual.remove(0);
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("missing"));
    }

    #[test]
    fn census_rejects_an_extra_reference() {
        let mut actual = actual_rows();
        actual.push(SourceARow::accepted_sample(ConfigKind::Cors, "extra.rs::xml", "00"));
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("extra"));
    }

    #[test]
    fn census_rejects_a_duplicate_reference() {
        let mut actual = actual_rows();
        actual.push(actual[0]);
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("duplicate"));
    }

    #[test]
    fn census_rejects_a_wrong_kind() {
        let mut actual = actual_rows();
        actual[0].kind = ConfigKind::Lifecycle;
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("wrong"));
    }

    #[test]
    fn census_rejects_a_wrong_digest() {
        let mut actual = actual_rows();
        actual[0].sha256 = "00";
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("wrong"));
    }

    #[test]
    fn census_rejects_a_wrong_disposition() {
        let mut actual = actual_rows();
        actual[0].disposition = SourceADisposition::Refused;
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("wrong"));
    }

    #[test]
    fn census_rejects_promoting_an_alias_to_a_sample() {
        let mut actual = actual_rows();
        let alias = actual
            .iter_mut()
            .find(|row| row.sample_mode == SourceASampleMode::Alias)
            .expect("the audited union contains aliases");
        alias.sample_mode = SourceASampleMode::Sample;
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("wrong"));
    }

    #[test]
    fn census_rejects_demoting_a_sample_to_an_alias() {
        let mut actual = actual_rows();
        let sample = actual
            .iter_mut()
            .find(|row| row.sample_mode == SourceASampleMode::Sample)
            .expect("the audited union contains samples");
        sample.sample_mode = SourceASampleMode::Alias;
        assert!(validate_rows(&EXPECTED_ROWS, &actual).unwrap_err().contains("wrong"));
    }

    #[test]
    fn census_rejects_a_missing_distinct_corpus_registration() {
        let families = crate::all_family_corpus_evidence().expect("the baseline corpus is valid");
        let mut registrations = corpus_registrations(&families);
        let first = &EXPECTED_ROWS[0];
        registrations.retain(|registration| {
            !(registration.kind == first.kind
                && registration.sha256 == first.sha256
                && registration.disposition == first.disposition)
        });
        assert!(
            validate_membership(&EXPECTED_ROWS, &registrations)
                .unwrap_err()
                .contains("0 corpus registrations")
        );
    }

    #[test]
    fn census_rejects_a_duplicate_distinct_corpus_registration() {
        let families = crate::all_family_corpus_evidence().expect("the baseline corpus is valid");
        let mut registrations = corpus_registrations(&families);
        let duplicate = registrations
            .iter()
            .find(|registration| registration.kind == EXPECTED_ROWS[0].kind && registration.sha256 == EXPECTED_ROWS[0].sha256)
            .expect("the baseline contains the first audited digest")
            .clone();
        registrations.push(duplicate);
        assert!(
            validate_membership(&EXPECTED_ROWS, &registrations)
                .unwrap_err()
                .contains("2 corpus registrations")
        );
    }
}
