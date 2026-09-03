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

//! Source-(a) RustFS Lifecycle fixture and aliases.
//!
//! Responsible for: binding one unique Lifecycle literal and its duplicate source aliases.
//! NOT responsible for: RustFS metadata behavior or Lifecycle codec behavior.
//! Upstream: RustFS bucket metadata tests. Downstream: Lifecycle D1-D5 corpus and source census.

use rustfs_gateway_types::persistence::{PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleRule};
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::source_a_census::SourceARow;
use crate::{AcceptedCorpusCase, ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

const LIFECYCLE_XML: &[u8] = b"<LifecycleConfiguration><Rule><ID>rule1</ID><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
pub(crate) const LIFECYCLE_SHA256: &str = "d02252be7653043d28995e397c4953a0a405f287426d914ade100a3c7d1ea1b5";
const RUSTFS_VERSION: &str = "rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8";
const UPDATE_CONFIG_REF: &str =
    "crates/ecstore/src/bucket/metadata.rs::lifecycle_update_config_clears_parsed_config_on_delete::lifecycle_xml";
const INLINE_MARSHAL_REF: &str = "crates/ecstore/src/bucket/metadata.rs::marshal_msg_complete_example::lifecycle_xml";
const MODULE_MARSHAL_REF: &str = "crates/ecstore/src/bucket/metadata_test.rs::marshal_msg_complete_example::lifecycle_xml";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingMode {
    Concrete,
    Alias,
}

#[derive(Clone, Copy, Debug)]
struct SourceBinding {
    source_ref: &'static str,
    sha256: &'static str,
    bytes: &'static [u8],
    mode: BindingMode,
}

fn bindings() -> [SourceBinding; 3] {
    [
        SourceBinding {
            source_ref: UPDATE_CONFIG_REF,
            sha256: LIFECYCLE_SHA256,
            bytes: LIFECYCLE_XML,
            mode: BindingMode::Concrete,
        },
        SourceBinding {
            source_ref: INLINE_MARSHAL_REF,
            sha256: LIFECYCLE_SHA256,
            bytes: LIFECYCLE_XML,
            mode: BindingMode::Alias,
        },
        SourceBinding {
            source_ref: MODULE_MARSHAL_REF,
            sha256: LIFECYCLE_SHA256,
            bytes: LIFECYCLE_XML,
            mode: BindingMode::Alias,
        },
    ]
}

pub(crate) fn source_a_rows() -> Vec<SourceARow> {
    bindings()
        .into_iter()
        .map(|binding| match binding.mode {
            BindingMode::Concrete => SourceARow::accepted_sample(ConfigKind::Lifecycle, binding.source_ref, binding.sha256),
            BindingMode::Alias => SourceARow::accepted_alias(ConfigKind::Lifecycle, binding.source_ref, binding.sha256),
        })
        .collect()
}

pub(crate) fn lifecycle_case() -> AcceptedCorpusCase<PersistedLifecycleConfiguration> {
    let concrete = bindings()
        .into_iter()
        .find(|binding| binding.mode == BindingMode::Concrete)
        .expect("the closed binding table declares one concrete source"); // The table above is static and contains that entry.
    AcceptedCorpusCase {
        sample: GoldenSample {
            kind: ConfigKind::Lifecycle,
            bytes: concrete.bytes.to_vec(),
            value: PersistedLifecycleConfiguration {
                expiry_updated_at: None,
                rules: vec![PersistedLifecycleRule {
                    abort_incomplete_multipart_upload: None,
                    del_marker_expiration: None,
                    expiration: Some(PersistedLifecycleExpiration {
                        days: Some(30),
                        ..PersistedLifecycleExpiration::default()
                    }),
                    filter: None,
                    id: Some("rule1".to_owned()),
                    noncurrent_version_expiration: None,
                    noncurrent_version_transitions: None,
                    prefix: None,
                    status: "Enabled".to_owned(),
                    transitions: None,
                }],
            },
            origin: SampleOrigin {
                source: "Source-(a) RustFS Lifecycle metadata fixture".to_owned(),
                producer: concrete.source_ref.to_owned(),
                version: RUSTFS_VERSION.to_owned(),
                sha256: concrete.sha256.to_owned(),
            },
            notes: format!(
                "byte-exact update_config fixture; identical marshal aliases: {INLINE_MARSHAL_REF}; {MODULE_MARSHAL_REF}"
            ),
        },
        variants: vec![CorpusVariant::Canonical],
    }
}

#[cfg(test)]
fn validate_census(candidates: &[SourceBinding]) -> Result<(), String> {
    if candidates.len() != 3 {
        return Err(format!("expected 3 Lifecycle source bindings, found {}", candidates.len()));
    }
    let expected_refs = [UPDATE_CONFIG_REF, INLINE_MARSHAL_REF, MODULE_MARSHAL_REF];
    for (binding, expected_ref) in candidates.iter().zip(expected_refs) {
        if binding.source_ref != expected_ref {
            return Err(format!("unexpected or duplicate Lifecycle source reference: {}", binding.source_ref));
        }
        let observed = hex::encode(Sha256::digest(binding.bytes));
        if observed != binding.sha256 {
            return Err(format!(
                "SHA-256 mismatch for {}: expected {}, observed {observed}",
                binding.source_ref, binding.sha256
            ));
        }
    }
    let concrete_count = candidates
        .iter()
        .filter(|binding| binding.mode == BindingMode::Concrete)
        .count();
    let alias_count = candidates.iter().filter(|binding| binding.mode == BindingMode::Alias).count();
    if concrete_count != 1 || alias_count != 2 {
        return Err(format!(
            "expected one concrete Lifecycle sample and two aliases, found {concrete_count} concrete and {alias_count} aliases"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_lifecycle_source_bindings_are_registered() {
        let registered = bindings();
        validate_census(&registered).expect("the unique fixture and two aliases must be registered");
        assert_eq!(registered.map(|binding| binding.bytes.len()), [140, 140, 140]);
        assert_eq!(lifecycle_case().sample.origin.sha256, LIFECYCLE_SHA256);
        assert!(lifecycle_case().sample.notes.contains(INLINE_MARSHAL_REF));
        assert!(lifecycle_case().sample.notes.contains(MODULE_MARSHAL_REF));
    }

    #[test]
    fn census_rejects_a_stale_digest() {
        let mut stale = bindings();
        stale[0].sha256 = "e02252be7653043d28995e397c4953a0a405f287426d914ade100a3c7d1ea1b5";
        let error = validate_census(&stale).expect_err("a stale source digest must fail closed");
        assert!(error.contains(UPDATE_CONFIG_REF));
        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn census_rejects_a_duplicate_source_reference() {
        let mut duplicated = bindings();
        duplicated[2].source_ref = INLINE_MARSHAL_REF;
        let error = validate_census(&duplicated).expect_err("a duplicate alias must fail closed");
        assert!(error.contains(INLINE_MARSHAL_REF));
        assert!(error.contains("unexpected or duplicate"));
    }

    #[test]
    fn census_rejects_counting_a_marshal_alias_as_concrete() {
        let mut inflated = bindings();
        inflated[1].mode = BindingMode::Concrete;
        let error = validate_census(&inflated).expect_err("a duplicate byte sequence must not inflate the corpus");
        assert!(error.contains("one concrete Lifecycle sample and two aliases"));
    }
}
