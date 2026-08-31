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

//! Live AWS SDK for JavaScript v3 source-(b) persistence captures.
//!
//! Responsible for: binding real SDK CORS, Lifecycle, and Versioning captures to a byte-exact census.
//! NOT responsible for: SDK request construction, client execution, or persistence codec behavior.
//! Upstream: official SDK against disposable RustFS. Downstream: family corpora and capture census.

use rustfs_gateway_types::cors_tagging::{PersistedCorsConfiguration, PersistedCorsRule};
use rustfs_gateway_types::persistence::{
    PersistedAbortIncompleteMultipartUpload, PersistedLifecycleAnd, PersistedLifecycleConfiguration,
    PersistedLifecycleExpiration, PersistedLifecycleFilter, PersistedLifecycleRule, PersistedLifecycleTag,
    PersistedVersioningConfiguration,
};
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::{AcceptedCorpusCase, ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

const CORS_XML: &[u8] = b"<CORSConfiguration><CORSRule><AllowedHeader>x-js-sdk-v3-*</AllowedHeader><AllowedHeader>content-md5</AllowedHeader><AllowedMethod>HEAD</AllowedMethod><AllowedMethod>POST</AllowedMethod><AllowedOrigin>https://js-v3-a.example.test</AllowedOrigin><AllowedOrigin>https://js-v3-b.example.test</AllowedOrigin><ExposeHeader>x-amz-request-id</ExposeHeader><ExposeHeader>x-amz-id-2</ExposeHeader><ID>js-v3-cors</ID><MaxAgeSeconds>913</MaxAgeSeconds></CORSRule></CORSConfiguration>";
const LIFECYCLE_XML: &[u8] = b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-31T05:44:42.209Z</ExpiryUpdatedAt><Rule><AbortIncompleteMultipartUpload><DaysAfterInitiation>23</DaysAfterInitiation></AbortIncompleteMultipartUpload><Expiration><Days>47</Days></Expiration><Filter><And><Prefix>js-v3/</Prefix><Tag><Key>client</Key><Value>javascript-v3</Value></Tag></And></Filter><ID>js-v3-lifecycle</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const VERSIONING_XML: &[u8] =
    b"<VersioningConfiguration><MfaDelete>Disabled</MfaDelete><Status>Suspended</Status></VersioningConfiguration>";
const CORS_SHA256: &str = "ed34100072dec533c8f5b767599780cf831dab5fd8fbb546418cbb6b0014787e";
const LIFECYCLE_SHA256: &str = "8e3d31452cf0829aea5eac72be1d21b0cc534af165eaee35c743e214a3cb59d3";
const VERSIONING_SHA256: &str = "9ab3f03babdbcc8a7b4c74f25c7519ea38231c1f0b54c88bb76dfacb5f3d91d4";
const CORS_METADATA_SHA256: &str = "ecf2a7031cc2f8278b9f3aa7d7df4b398dc9f8d1d227b357787233e02b3c7b1e";
const LIFECYCLE_METADATA_SHA256: &str = "29f448cea830579b7a0f3500673d2a410c14aacdd1e0067fd867c6029f1247d5";
const VERSIONING_METADATA_SHA256: &str = "753d65b377a884342ffa1c5503952c7df82c74b57f98ca52bca58988fd00cab4";
const CAPTURE_VERSION: &str = "@aws-sdk/client-s3@3.1121.0; npm-tarball-sha256:24fc6c5d5d422e1772177fd10298c19572f13e01e720e6db0034b53b1aa8214b; npm-shasum:6fc78ca0169448f3eb07dd5e9f519e870eb1b21e; npm-integrity:sha512-hBnoqaVBeWdkgXcJElMXA2yUZWkBCBntu2qmN+tfqmzC+j4LzJC3ox8qIgS2WdMS1cb8UwyBogUVrkRXybNm0A==; node@v22.22.2; rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8; rustfs-server-sha256:48e39ce70afeb390c729345c65ff10481db047e22f7f1d6b3c0863db6fea467c; rustfs-cli-sha256:264bc47c0fc9ca07ff1494c9aca8f95982d6406b716d6535a81c7e030f5463f9";
const CANONICAL_VARIANT: &[CorpusVariant] = &[CorpusVariant::Canonical];

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "Source-(b) live AWS SDK for JavaScript v3 client matrix capture".to_owned(),
        producer: "official AWS SDK for JavaScript v3 against disposable RustFS; rustfs-cli offline raw export".to_owned(),
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
                    allowed_headers: Some(vec!["x-js-sdk-v3-*".to_owned(), "content-md5".to_owned()]),
                    allowed_methods: vec!["HEAD".to_owned(), "POST".to_owned()],
                    allowed_origins: vec![
                        "https://js-v3-a.example.test".to_owned(),
                        "https://js-v3-b.example.test".to_owned(),
                    ],
                    expose_headers: Some(vec!["x-amz-request-id".to_owned(), "x-amz-id-2".to_owned()]),
                    id: Some("js-v3-cors".to_owned()),
                    max_age_seconds: Some(913),
                }],
            },
            origin: origin(CORS_SHA256),
            notes: format!(
                "byte-exact CORS XML persisted after SDK Put and confirmed by SDK Get; raw metadata SHA-256 {CORS_METADATA_SHA256}"
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
                expiry_updated_at: Some("2026-08-31T05:44:42.209Z".to_owned()),
                rules: vec![PersistedLifecycleRule {
                    abort_incomplete_multipart_upload: Some(PersistedAbortIncompleteMultipartUpload {
                        days_after_initiation: Some(23),
                    }),
                    del_marker_expiration: None,
                    expiration: Some(PersistedLifecycleExpiration {
                        days: Some(47),
                        ..PersistedLifecycleExpiration::default()
                    }),
                    filter: Some(PersistedLifecycleFilter {
                        and: Some(PersistedLifecycleAnd {
                            prefix: Some("js-v3/".to_owned()),
                            tags: Some(vec![PersistedLifecycleTag {
                                key: Some("client".to_owned()),
                                value: Some("javascript-v3".to_owned()),
                            }]),
                            ..PersistedLifecycleAnd::default()
                        }),
                        ..PersistedLifecycleFilter::default()
                    }),
                    id: Some("js-v3-lifecycle".to_owned()),
                    noncurrent_version_expiration: None,
                    noncurrent_version_transitions: None,
                    prefix: None,
                    status: "Enabled".to_owned(),
                    transitions: None,
                }],
            },
            origin: origin(LIFECYCLE_SHA256),
            notes: format!(
                "byte-exact Lifecycle XML persisted after SDK Put and confirmed by SDK Get; raw metadata SHA-256 {LIFECYCLE_METADATA_SHA256}"
            ),
        },
        variants: vec![CorpusVariant::Canonical, CorpusVariant::TimestampPrecision],
    }
}

pub(crate) fn versioning_case() -> AcceptedCorpusCase<PersistedVersioningConfiguration> {
    AcceptedCorpusCase {
        sample: GoldenSample {
            kind: ConfigKind::Versioning,
            bytes: VERSIONING_XML.to_vec(),
            value: PersistedVersioningConfiguration {
                status: Some("Suspended".to_owned()),
                mfa_delete: Some("Disabled".to_owned()),
                ..PersistedVersioningConfiguration::default()
            },
            origin: origin(VERSIONING_SHA256),
            notes: format!(
                "byte-exact Versioning XML persisted after SDK Put and confirmed as Suspended by SDK Get; raw metadata SHA-256 {VERSIONING_METADATA_SHA256}"
            ),
        },
        variants: vec![CorpusVariant::Canonical],
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct CaptureBinding {
    label: &'static str,
    bytes: &'static [u8],
    sha256: &'static str,
    metadata_sha256: &'static str,
}

#[cfg(test)]
fn capture_bindings() -> [CaptureBinding; 3] {
    [
        CaptureBinding {
            label: "cors-concrete",
            bytes: CORS_XML,
            sha256: CORS_SHA256,
            metadata_sha256: CORS_METADATA_SHA256,
        },
        CaptureBinding {
            label: "lifecycle-concrete",
            bytes: LIFECYCLE_XML,
            sha256: LIFECYCLE_SHA256,
            metadata_sha256: LIFECYCLE_METADATA_SHA256,
        },
        CaptureBinding {
            label: "versioning-concrete",
            bytes: VERSIONING_XML,
            sha256: VERSIONING_SHA256,
            metadata_sha256: VERSIONING_METADATA_SHA256,
        },
    ]
}

#[cfg(test)]
fn validate_census(captures: &[CaptureBinding]) -> Result<(), String> {
    if captures.len() != 3 {
        return Err(format!("expected 3 JavaScript v3 captures, found {}", captures.len()));
    }
    for capture in captures {
        let observed = hex::encode(Sha256::digest(capture.bytes));
        if observed != capture.sha256 {
            return Err(format!("raw export SHA-256 mismatch for {}", capture.label));
        }
        if capture.metadata_sha256.len() != 64 || !capture.metadata_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!("invalid metadata SHA-256 for {}", capture.label));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_javascript_v3_captures_are_registered() {
        let registered = capture_bindings();
        validate_census(&registered).expect("the JavaScript v3 capture census must be byte-exact");
        assert_eq!(
            registered.map(|capture| capture.label),
            ["cors-concrete", "lifecycle-concrete", "versioning-concrete"]
        );
        assert_eq!(registered.map(|capture| capture.bytes.len()), [471, 426, 108]);
        assert_eq!(cors_cases().len(), 1);
        assert_eq!(lifecycle_case().sample.origin.sha256, LIFECYCLE_SHA256);
        assert_eq!(versioning_case().sample.origin.sha256, VERSIONING_SHA256);
    }

    #[test]
    fn census_rejects_a_stale_raw_export_digest() {
        let mut stale = capture_bindings();
        stale[0].sha256 = "fd34100072dec533c8f5b767599780cf831dab5fd8fbb546418cbb6b0014787e";
        let error = validate_census(&stale).expect_err("a stale SDK raw digest must fail closed");
        assert!(error.contains("cors-concrete"));
        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn census_rejects_a_non_hex_metadata_digest() {
        let mut stale = capture_bindings();
        stale[2].metadata_sha256 = "z53d65b377a884342ffa1c5503952c7df82c74b57f98ca52bca58988fd00cab4";
        let error = validate_census(&stale).expect_err("a malformed metadata digest must fail closed");
        assert!(error.contains("versioning-concrete"));
        assert!(error.contains("metadata SHA-256"));
    }
}
