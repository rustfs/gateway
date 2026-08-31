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

//! Live AWS SDK for Rust Tagging persistence capture.
//!
//! Responsible for: pinning the byte-exact SDK-to-RustFS raw export and its provenance.
//! NOT responsible for: issuing live requests or defining generic Tagging boundaries.
//! Upstream: AWS SDK for Rust 1.144.0 and RustFS `inspect bucket-meta --raw`.
//! Downstream: the parent Tagging D1-D5 and backup ZIP corpus.

use rustfs_gateway_types::cors_tagging::{PersistedTag, PersistedTagging};

use crate::{ConfigKind, CorpusVariant, GoldenSample, RejectedGoldenSample, SampleOrigin};

use super::{AcceptedTaggingCase, RejectedTaggingCase};

const AWS_SDK_RUST_XML: &[u8] = b"<Tagging><TagSet><Tag><Key>client</Key><Value>aws-sdk-rust</Value></Tag><Tag><Key>purpose</Key><Value>source-b-capture</Value></Tag></TagSet></Tagging>";
const AWS_SDK_RUST_SHA256: &str = "f90c97e975427a0a62982ebf116bb671f607bf5cce52e815b7ace1ba9898e924";
const DUPLICATE_TAG_SET: &[u8] = b"<Tagging><TagSet><Tag><Key>client</Key><Value>aws-sdk-rust</Value></Tag></TagSet><TagSet><Tag><Key>purpose</Key><Value>source-b-capture</Value></Tag></TagSet></Tagging>";
const DUPLICATE_TAG_SET_SHA256: &str = "ceb30ecbb85ab6ff65dec3a02969181b8bc14dddbc43fbf485a0832cd80b9675";

pub(super) fn cases() -> [AcceptedTaggingCase; 1] {
    [(
        GoldenSample {
            kind: ConfigKind::Tagging,
            bytes: AWS_SDK_RUST_XML.to_vec(),
            value: PersistedTagging {
                tag_set: vec![
                    PersistedTag {
                        key: Some("client".to_owned()),
                        value: Some("aws-sdk-rust".to_owned()),
                    },
                    PersistedTag {
                        key: Some("purpose".to_owned()),
                        value: Some("source-b-capture".to_owned()),
                    },
                ],
            },
            origin: SampleOrigin {
                source: "Source-(b) live AWS SDK for Rust client matrix capture".to_owned(),
                producer: "aws-sdk-s3 1.144.0 against disposable RustFS; rustfs inspect bucket-meta --raw".to_owned(),
                version: "rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8".to_owned(),
                sha256: AWS_SDK_RUST_SHA256.to_owned(),
            },
            notes: "byte-exact Tagging XML persisted after an AWS SDK for Rust PutBucketTagging request".to_owned(),
        },
        &[CorpusVariant::Canonical],
    )]
}

pub(super) fn rejected_cases() -> [RejectedTaggingCase; 1] {
    [(
        RejectedGoldenSample {
            kind: ConfigKind::Tagging,
            bytes: DUPLICATE_TAG_SET.to_vec(),
            origin: SampleOrigin {
                source: "Source-(b) AWS SDK for Rust capture duplicate-TagSet mutation".to_owned(),
                producer: "one-field mutation of the live aws-sdk-s3 1.144.0 capture".to_owned(),
                version: "rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8".to_owned(),
                sha256: DUPLICATE_TAG_SET_SHA256.to_owned(),
            },
            notes: "a duplicate TagSet derived from the live capture must fail closed".to_owned(),
        },
        &[CorpusVariant::DuplicateField],
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_b_aws_sdk_rust_tagging_capture_is_registered() {
        let matches = super::super::accepted_cases()
            .into_iter()
            .filter(|(sample, _)| sample.origin.sha256 == "f90c97e975427a0a62982ebf116bb671f607bf5cce52e815b7ace1ba9898e924")
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "the live AWS SDK for Rust Tagging SHA must be registered once");
        let sample = &matches[0].0;
        assert_eq!(sample.bytes, AWS_SDK_RUST_XML);
        assert_eq!(sample.origin.sha256, AWS_SDK_RUST_SHA256);
        assert_eq!(sample.origin.source, "Source-(b) live AWS SDK for Rust client matrix capture");
        assert_eq!(sample.origin.version, "rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8");
        super::super::assert_tagging_four_way(sample).expect("the live AWS SDK for Rust Tagging capture passes D1-D5");
    }

    #[test]
    fn source_b_duplicate_tag_set_mutation_is_registered_as_rejected() {
        let matches = super::super::rejected_cases()
            .into_iter()
            .filter(|(sample, _)| sample.origin.sha256 == "ceb30ecbb85ab6ff65dec3a02969181b8bc14dddbc43fbf485a0832cd80b9675")
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "the source-(b) duplicate TagSet mutation must be registered once");
        assert_eq!(matches[0].0.bytes, DUPLICATE_TAG_SET);
        assert_eq!(matches[0].0.origin.sha256, DUPLICATE_TAG_SET_SHA256);
    }
}
