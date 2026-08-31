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

//! Live official-mc source-(b) persistence captures.
//!
//! Responsible for: registering byte-exact offline exports and a deduplicated Versioning provenance alias.
//! NOT responsible for: request-file generation, client execution, or persistence codec behavior.
//! Upstream: official `mc` against disposable RustFS. Downstream: family corpora and capture census.

use rustfs_gateway_types::cors_tagging::{PersistedCorsConfiguration, PersistedCorsRule};
use rustfs_gateway_types::persistence::{
    PersistedLifecycleConfiguration, PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule,
    PersistedNoncurrentVersionExpiration,
};
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::{AcceptedCorpusCase, ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

const CORS_XML: &[u8] = b"<CORSConfiguration><CORSRule><AllowedHeader>x-amz-checksum-*</AllowedHeader><AllowedMethod>DELETE</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>https://mc-primary.example.test</AllowedOrigin><AllowedOrigin>https://mc-secondary.example.test</AllowedOrigin><ExposeHeader>x-amz-checksum-sha256</ExposeHeader><ID>mc-cors-rule</ID><MaxAgeSeconds>777</MaxAgeSeconds></CORSRule></CORSConfiguration>";
const LIFECYCLE_XML: &[u8] = b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-31T05:01:50.823Z</ExpiryUpdatedAt><Rule><Expiration><Days>61</Days></Expiration><Filter><Prefix>mc-generated/</Prefix></Filter><ID>daaglfmir7fvdkrslbmg</ID><NoncurrentVersionExpiration><NoncurrentDays>23</NoncurrentDays></NoncurrentVersionExpiration><Status>Enabled</Status></Rule></LifecycleConfiguration>";
#[cfg(test)]
const VERSIONING_XML: &[u8] = b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
const CORS_SHA256: &str = "5ced5e2fb39bc38f489e8fe7771c2b044eb4f882c47969678443359292e42418";
const LIFECYCLE_SHA256: &str = "52b71f5cdd541aab280f1ceaf1c6452e7c9f27c1f0dff5ebb94ed07e63a2e3e4";
const VERSIONING_SHA256: &str = "dd6f6f21cc8680cc5c32bba98d4297e37552279d7e326a35df847ed2713f2d6a";
const CORS_METADATA_SHA256: &str = "94eb87880232b5bd5d7c38ec7b176e80c128d71593f453d53528e0c6ddc289b7";
const LIFECYCLE_METADATA_SHA256: &str = "64b6b2cba58938f5d694ba442318b5f3d8a8b91d42ef8c97ca4edd3d82b816e9";
const VERSIONING_METADATA_SHA256: &str = "d3d9c23934f16f653e02886fe07696405334c74c5ffe0208d85884b1c60f57f3";
const CAPTURE_VERSION: &str = "mc@RELEASE.2025-08-13T08-35-41Z; mc-commit@7394ce0dd2a80935aded936b09fa12cbb3cb8096; mc-sha256:a877fd0c183409da9f20f9d6e1811987298bbbca1aa03428eebdffba79fb9445; rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8; rustfs-server-sha256:48e39ce70afeb390c729345c65ff10481db047e22f7f1d6b3c0863db6fea467c; rustfs-cli-sha256:264bc47c0fc9ca07ff1494c9aca8f95982d6406b716d6535a81c7e030f5463f9";
const CANONICAL_VARIANT: &[CorpusVariant] = &[CorpusVariant::Canonical];

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "Source-(b) live official-mc client matrix capture".to_owned(),
        producer: "official mc against disposable RustFS; rustfs-cli offline raw export".to_owned(),
        version: CAPTURE_VERSION.to_owned(),
        sha256: sha256.to_owned(),
    }
}

pub(crate) fn cors_cases() -> [(GoldenSample<PersistedCorsConfiguration>, &'static [CorpusVariant]); 1] {
    [(
        GoldenSample {
            kind: ConfigKind::Cors,
            bytes: CORS_XML.to_vec(),
            value: PersistedCorsConfiguration {
                cors_rules: vec![PersistedCorsRule {
                    allowed_headers: Some(vec!["x-amz-checksum-*".to_owned()]),
                    allowed_methods: vec!["DELETE".to_owned(), "PUT".to_owned()],
                    allowed_origins: vec![
                        "https://mc-primary.example.test".to_owned(),
                        "https://mc-secondary.example.test".to_owned(),
                    ],
                    expose_headers: Some(vec!["x-amz-checksum-sha256".to_owned()]),
                    id: Some("mc-cors-rule".to_owned()),
                    max_age_seconds: Some(777),
                }],
            },
            origin: origin(CORS_SHA256),
            notes: format!(
                "byte-exact CORS XML persisted after official mc cors set; raw metadata SHA-256 {CORS_METADATA_SHA256}"
            ),
        },
        CANONICAL_VARIANT,
    )]
}

pub(crate) fn lifecycle_case() -> AcceptedCorpusCase<PersistedLifecycleConfiguration> {
    AcceptedCorpusCase {
        sample: GoldenSample {
            kind: ConfigKind::Lifecycle,
            bytes: LIFECYCLE_XML.to_vec(),
            value: PersistedLifecycleConfiguration {
                expiry_updated_at: Some("2026-08-31T05:01:50.823Z".to_owned()),
                rules: vec![PersistedLifecycleRule {
                    abort_incomplete_multipart_upload: None,
                    del_marker_expiration: None,
                    expiration: Some(PersistedLifecycleExpiration {
                        days: Some(61),
                        ..PersistedLifecycleExpiration::default()
                    }),
                    filter: Some(PersistedLifecycleFilter {
                        prefix: Some("mc-generated/".to_owned()),
                        ..PersistedLifecycleFilter::default()
                    }),
                    id: Some("daaglfmir7fvdkrslbmg".to_owned()),
                    noncurrent_version_expiration: Some(PersistedNoncurrentVersionExpiration {
                        newer_noncurrent_versions: None,
                        noncurrent_days: Some(23),
                    }),
                    noncurrent_version_transitions: None,
                    prefix: None,
                    status: "Enabled".to_owned(),
                    transitions: None,
                }],
            },
            origin: origin(LIFECYCLE_SHA256),
            notes: format!(
                "byte-exact Lifecycle XML persisted after official mc ilm rule add; raw metadata SHA-256 {LIFECYCLE_METADATA_SHA256}"
            ),
        },
        variants: vec![CorpusVariant::Canonical, CorpusVariant::TimestampPrecision],
    }
}

pub(crate) fn versioning_alias_note() -> String {
    format!(
        "pinned MinIO-compatible HTTP decoding of the bare Enabled body persists this canonical old-readable XML; official mc version enable independently produced the same 75 bytes ({VERSIONING_SHA256}) through rustfs-cli offline raw export, metadata SHA-256 {VERSIONING_METADATA_SHA256}, {CAPTURE_VERSION}"
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureMode {
    Concrete,
    Alias,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct CaptureBinding {
    label: &'static str,
    bytes: &'static [u8],
    sha256: &'static str,
    metadata_sha256: &'static str,
    mode: CaptureMode,
}

#[cfg(test)]
fn capture_bindings() -> [CaptureBinding; 3] {
    [
        CaptureBinding {
            label: "cors-concrete",
            bytes: CORS_XML,
            sha256: CORS_SHA256,
            metadata_sha256: CORS_METADATA_SHA256,
            mode: CaptureMode::Concrete,
        },
        CaptureBinding {
            label: "lifecycle-concrete",
            bytes: LIFECYCLE_XML,
            sha256: LIFECYCLE_SHA256,
            metadata_sha256: LIFECYCLE_METADATA_SHA256,
            mode: CaptureMode::Concrete,
        },
        CaptureBinding {
            label: "versioning-alias",
            bytes: VERSIONING_XML,
            sha256: VERSIONING_SHA256,
            metadata_sha256: VERSIONING_METADATA_SHA256,
            mode: CaptureMode::Alias,
        },
    ]
}

#[cfg(test)]
fn validate_census(captures: &[CaptureBinding]) -> Result<(), String> {
    if captures.len() != 3 {
        return Err(format!("expected 3 official-mc captures, found {}", captures.len()));
    }
    for capture in captures {
        let observed = hex::encode(Sha256::digest(capture.bytes));
        if observed != capture.sha256 {
            return Err(format!("raw export SHA-256 mismatch for {}", capture.label));
        }
        if capture.metadata_sha256.len() != 64 {
            return Err(format!("invalid metadata SHA-256 for {}", capture.label));
        }
    }
    if captures[2].mode != CaptureMode::Alias {
        return Err("versioning duplicate must remain a provenance alias".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_official_mc_captures_are_registered() {
        let registered = capture_bindings();
        validate_census(&registered).expect("the official-mc capture census must be byte-exact");
        assert_eq!(
            registered.map(|capture| capture.label),
            ["cors-concrete", "lifecycle-concrete", "versioning-alias"]
        );
        assert_eq!(registered.map(|capture| capture.bytes.len()), [409, 355, 75]);
        assert_eq!(cors_cases().len(), 1);
        let versioning_matches = crate::versioning::corpus_evidence()
            .accepted
            .into_iter()
            .filter(|case| case.sample.origin.sha256 == VERSIONING_SHA256)
            .count();
        assert_eq!(versioning_matches, 1);
        assert!(versioning_alias_note().contains(VERSIONING_SHA256));
    }

    #[test]
    fn census_rejects_a_stale_raw_export_digest() {
        let mut stale = capture_bindings();
        stale[0].sha256 = "6ced5e2fb39bc38f489e8fe7771c2b044eb4f882c47969678443359292e42418";
        let error = validate_census(&stale).expect_err("a stale official-mc digest must fail closed");
        assert!(error.contains("cors-concrete"));
        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn census_rejects_counting_the_versioning_alias_as_a_sample() {
        let mut duplicated = capture_bindings();
        duplicated[2].mode = CaptureMode::Concrete;
        let error = validate_census(&duplicated).expect_err("duplicate Versioning bytes must not increment the corpus");
        assert!(error.contains("must remain a provenance alias"));
    }
}
