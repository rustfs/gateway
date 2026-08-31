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

//! Live source-(b) Lifecycle persistence sample.
//!
//! Responsible for: registering byte-exact boto3, aws-cli, and official-mc raw exports and provenance.
//! NOT responsible for: HTTP request construction, offline export, or Lifecycle codec behavior.
//! Upstream: disposable RustFS capture and `rustfs-cli` raw export. Downstream: Lifecycle D1-D5 corpus.

use super::*;

const BOTO3_XML: &[u8] = b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-31T03:18:31.259Z</ExpiryUpdatedAt><Rule><AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload><Expiration><Days>30</Days></Expiration><Filter><Prefix>archive/</Prefix></Filter><ID>boto3-lifecycle</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>";
const AWS_CLI_XML: &[u8] = b"<LifecycleConfiguration><ExpiryUpdatedAt>2026-08-31T03:57:41.836Z</ExpiryUpdatedAt><Rule><AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation></AbortIncompleteMultipartUpload><Expiration><Days>45</Days></Expiration><Filter><Prefix>cli/</Prefix></Filter><ID>aws-cli-lifecycle</ID><Status>Enabled</Status></Rule></LifecycleConfiguration>";

fn boto3_case() -> AcceptedCorpusCase<PersistedLifecycleConfiguration> {
    AcceptedCorpusCase {
        sample: GoldenSample {
            kind: ConfigKind::Lifecycle,
            bytes: BOTO3_XML.to_vec(),
            value: PersistedLifecycleConfiguration {
                expiry_updated_at: Some("2026-08-31T03:18:31.259Z".to_owned()),
                rules: vec![PersistedLifecycleRule {
                    abort_incomplete_multipart_upload: Some(PersistedAbortIncompleteMultipartUpload {
                        days_after_initiation: Some(7),
                    }),
                    expiration: Some(PersistedLifecycleExpiration {
                        days: Some(30),
                        ..PersistedLifecycleExpiration::default()
                    }),
                    filter: Some(PersistedLifecycleFilter {
                        prefix: Some("archive/".to_owned()),
                        ..PersistedLifecycleFilter::default()
                    }),
                    id: Some("boto3-lifecycle".to_owned()),
                    del_marker_expiration: None,
                    noncurrent_version_expiration: None,
                    noncurrent_version_transitions: None,
                    prefix: None,
                    status: "Enabled".to_owned(),
                    transitions: None,
                }],
            },
            origin: SampleOrigin {
                source: "Source-(b) live boto3 client matrix capture".to_owned(),
                producer: "boto3 1.40.21 against disposable RustFS; rustfs-cli raw export".to_owned(),
                version: "botocore@1.40.76; rustfs-server@sha256:e294d7887fbea1992496146f98c32e3b517efc6dec9e53bb592fff9a04bb2ae9; rustfs-cli@c876df53f5097618b1817568a471cbb8b4f26ee8".to_owned(),
                sha256: "2c2ef93c0173c836faef692592ccb400771cd65b9ff64afee941fd7253b4ed00".to_owned(),
            },
            notes: "byte-exact Lifecycle XML persisted after a structured boto3 PutBucketLifecycleConfiguration request"
                .to_owned(),
        },
        variants: vec![CorpusVariant::Canonical, CorpusVariant::TimestampPrecision],
    }
}

fn aws_cli_case() -> AcceptedCorpusCase<PersistedLifecycleConfiguration> {
    AcceptedCorpusCase {
        sample: GoldenSample {
            kind: ConfigKind::Lifecycle,
            bytes: AWS_CLI_XML.to_vec(),
            value: PersistedLifecycleConfiguration {
                expiry_updated_at: Some("2026-08-31T03:57:41.836Z".to_owned()),
                rules: vec![PersistedLifecycleRule {
                    abort_incomplete_multipart_upload: Some(PersistedAbortIncompleteMultipartUpload {
                        days_after_initiation: Some(3),
                    }),
                    expiration: Some(PersistedLifecycleExpiration {
                        days: Some(45),
                        ..PersistedLifecycleExpiration::default()
                    }),
                    filter: Some(PersistedLifecycleFilter {
                        prefix: Some("cli/".to_owned()),
                        ..PersistedLifecycleFilter::default()
                    }),
                    id: Some("aws-cli-lifecycle".to_owned()),
                    del_marker_expiration: None,
                    noncurrent_version_expiration: None,
                    noncurrent_version_transitions: None,
                    prefix: None,
                    status: "Enabled".to_owned(),
                    transitions: None,
                }],
            },
            origin: SampleOrigin {
                source: "Source-(b) live aws-cli client matrix capture".to_owned(),
                producer: "aws-cli 1.44.87 against disposable RustFS; rustfs-cli raw export".to_owned(),
                version: "botocore@1.42.97; rustfs-server@sha256:1174803fcd0051a4a008fdaaed29fc7e8e7e16b07abdf8108553a439523e998a; rustfs-cli@c876df53f5097618b1817568a471cbb8b4f26ee8".to_owned(),
                sha256: "240a19991600e5ebeabdf4147638dc5f29a07fe5ed4d7347645be8c212889b5d".to_owned(),
            },
            notes: "byte-exact Lifecycle XML persisted after an aws-cli put-bucket-lifecycle-configuration request"
                .to_owned(),
        },
        variants: vec![CorpusVariant::Canonical, CorpusVariant::TimestampPrecision],
    }
}

pub(super) fn cases() -> Vec<AcceptedCorpusCase<PersistedLifecycleConfiguration>> {
    vec![boto3_case(), aws_cli_case(), crate::source_b_mc::lifecycle_case()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_b_boto3_lifecycle_capture_is_registered() {
        let sample = boto3_case().sample;
        assert_eq!(sample.origin.sha256, "2c2ef93c0173c836faef692592ccb400771cd65b9ff64afee941fd7253b4ed00");
        assert_eq!(sample.bytes.len(), 360);
    }

    #[test]
    fn source_b_aws_cli_lifecycle_capture_is_registered() {
        let sample = super::super::corpus_evidence()
            .accepted
            .into_iter()
            .find(|case| case.sample.origin.producer.starts_with("aws-cli"))
            .expect("the live aws-cli Lifecycle capture is registered")
            .sample;
        assert_eq!(sample.origin.sha256, "240a19991600e5ebeabdf4147638dc5f29a07fe5ed4d7347645be8c212889b5d");
        assert_eq!(sample.bytes.len(), 358);
    }
}
