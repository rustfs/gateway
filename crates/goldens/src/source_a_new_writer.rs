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

//! Source-(a) RustFS new-writer configuration fixtures.
//!
//! Responsible for: binding selected `NEW_WRITER_CONFIGS` bytes to their exact RustFS source references.
//! NOT responsible for: writing bucket metadata or adding configuration families outside CORS and Lifecycle.
//! Upstream: RustFS `metadata_sys.rs` test constants. Downstream: CORS and Lifecycle persistence corpora.

use rustfs_gateway_types::cors_tagging::{PersistedCorsConfiguration, PersistedCorsRule};
use rustfs_gateway_types::persistence::{
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule,
};
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::source_a_census::SourceARow;
use crate::{AcceptedCorpusCase, ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

const CORS: &[u8] = b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>https://example.test</AllowedOrigin></CORSRule></CORSConfiguration>";
const LIFECYCLE: &[u8] = b"<LifecycleConfiguration><Rule><ID>expire</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
const RUSTFS_COMMIT: &str = "rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8";
const CANONICAL_VARIANT: &[CorpusVariant] = &[CorpusVariant::Canonical];
const CORS_SOURCE_REF: &str = "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[BUCKET_CORS_CONFIG]";
const LIFECYCLE_SOURCE_REF: &str = "crates/ecstore/src/bucket/metadata_sys.rs::NEW_WRITER_CONFIGS[BUCKET_LIFECYCLE_CONFIG]";

#[derive(Clone, Copy, Debug)]
struct NewWriterBinding {
    kind: ConfigKind,
    source_ref: &'static str,
    sha256: &'static str,
    bytes: &'static [u8],
}

fn bindings() -> [NewWriterBinding; 2] {
    [
        NewWriterBinding {
            kind: ConfigKind::Cors,
            source_ref: CORS_SOURCE_REF,
            sha256: "64dbcc0152a855b9df46deda0d683c1fed82f265cf2b190cde87622e75a9d6d0",
            bytes: CORS,
        },
        NewWriterBinding {
            kind: ConfigKind::Lifecycle,
            source_ref: LIFECYCLE_SOURCE_REF,
            sha256: "1a7189c8038cf900f74855cdc4131c644664bfb0ce04486e8c48fce41b5b4a0c",
            bytes: LIFECYCLE,
        },
    ]
}

pub(crate) fn source_a_rows() -> Vec<SourceARow> {
    bindings()
        .into_iter()
        .map(|binding| SourceARow::accepted_sample(binding.kind, binding.source_ref, binding.sha256))
        .collect()
}

#[cfg(test)]
fn validate_census(candidates: &[NewWriterBinding]) -> Result<(), String> {
    if candidates.len() != 2 {
        return Err(format!("expected 2 selected NEW_WRITER_CONFIGS bindings, found {}", candidates.len()));
    }
    let expected_refs = [CORS_SOURCE_REF, LIFECYCLE_SOURCE_REF];
    for (binding, expected_ref) in candidates.iter().zip(expected_refs) {
        if binding.source_ref != expected_ref {
            return Err(format!(
                "unexpected or duplicate NEW_WRITER_CONFIGS source reference: {}",
                binding.source_ref
            ));
        }
        let observed = hex::encode(Sha256::digest(binding.bytes));
        if observed != binding.sha256 {
            return Err(format!(
                "SHA-256 mismatch for {}: expected {}, observed {observed}",
                binding.source_ref, binding.sha256
            ));
        }
    }
    Ok(())
}

fn origin(binding: NewWriterBinding) -> SampleOrigin {
    SampleOrigin {
        source: "Source-(a) RustFS new-writer configuration fixture".to_owned(),
        producer: binding.source_ref.to_owned(),
        version: RUSTFS_COMMIT.to_owned(),
        sha256: binding.sha256.to_owned(),
    }
}

pub(crate) fn cors_cases() -> Vec<(GoldenSample<PersistedCorsConfiguration>, &'static [CorpusVariant])> {
    bindings()
        .into_iter()
        .filter(|binding| binding.kind == ConfigKind::Cors)
        .map(|binding| {
            (
                GoldenSample {
                    kind: ConfigKind::Cors,
                    bytes: binding.bytes.to_vec(),
                    value: PersistedCorsConfiguration {
                        cors_rules: vec![PersistedCorsRule {
                            allowed_methods: vec!["GET".to_owned()],
                            allowed_origins: vec!["https://example.test".to_owned()],
                            ..PersistedCorsRule::default()
                        }],
                    },
                    origin: origin(binding),
                    notes: "RustFS new-writer rollback fixture from the named NEW_WRITER_CONFIGS entry".to_owned(),
                },
                CANONICAL_VARIANT,
            )
        })
        .collect()
}

pub(crate) fn lifecycle_cases() -> Vec<AcceptedCorpusCase<PersistedLifecycleConfiguration>> {
    bindings()
        .into_iter()
        .filter(|binding| binding.kind == ConfigKind::Lifecycle)
        .map(|binding| AcceptedCorpusCase {
            sample: GoldenSample {
                kind: ConfigKind::Lifecycle,
                bytes: binding.bytes.to_vec(),
                value: PersistedLifecycleConfiguration {
                    expiry_updated_at: None,
                    rules: vec![PersistedLifecycleRule {
                        abort_incomplete_multipart_upload: None,
                        del_marker_expiration: None,
                        expiration: Some(PersistedLifecycleExpiration {
                            days: Some(30),
                            ..PersistedLifecycleExpiration::default()
                        }),
                        filter: Some(PersistedLifecycleFilter {
                            prefix: Some("logs/".to_owned()),
                            ..PersistedLifecycleFilter::default()
                        }),
                        id: Some("expire".to_owned()),
                        noncurrent_version_expiration: None,
                        noncurrent_version_transitions: None,
                        prefix: None,
                        status: "Enabled".to_owned(),
                        transitions: None,
                    }],
                },
                origin: origin(binding),
                notes: "RustFS new-writer rollback fixture from the named NEW_WRITER_CONFIGS entry".to_owned(),
            },
            variants: vec![CorpusVariant::Canonical],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_selected_new_writer_configs_are_registered() {
        let registered = bindings();
        validate_census(&registered).expect("the two selected RustFS new-writer fixtures must stay byte-exact");
        assert_eq!(registered.map(|binding| binding.source_ref), [CORS_SOURCE_REF, LIFECYCLE_SOURCE_REF]);
        assert_eq!(registered.map(|binding| binding.bytes.len()), [145, 180]);
        assert_eq!(cors_cases().len(), 1);
        assert_eq!(lifecycle_cases().len(), 1);
    }

    #[test]
    fn census_rejects_a_stale_digest() {
        let mut stale = bindings();
        stale[0].sha256 = "d4dbcc0152a855b9df46deda0d683c1fed82f265cf2b190cde87622e75a9d6d0";
        let error = validate_census(&stale).expect_err("a stale source digest must fail closed");
        assert!(error.contains(CORS_SOURCE_REF));
        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn census_rejects_a_duplicate_source_reference() {
        let mut duplicated = bindings();
        duplicated[1].source_ref = CORS_SOURCE_REF;
        let error = validate_census(&duplicated).expect_err("a duplicate source reference must fail closed");
        assert!(error.contains(CORS_SOURCE_REF));
        assert!(error.contains("unexpected or duplicate"));
    }
}
