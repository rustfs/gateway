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

//! Live AWS SDK for Rust Object Lock persistence captures.
//!
//! Responsible for: pinning byte-exact SDK-to-RustFS Object Lock exports and duplicate provenance.
//! NOT responsible for: issuing live requests or defining generic Object Lock boundaries.
//! Upstream: AWS SDK for Rust 1.144.0 and RustFS `inspect bucket-meta --raw`.
//! Downstream: the parent Object Lock D1-D5 and backup ZIP corpus.

use rustfs_gateway_types::persistence::PersistedObjectLockConfiguration;

use crate::{AcceptedCorpusCase, ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

use super::{enabled, retention};

const GOVERNANCE_DAYS_7_XML: &[u8] = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Days>7</Days><Mode>GOVERNANCE</Mode></DefaultRetention></Rule></ObjectLockConfiguration>";
const GOVERNANCE_DAYS_7_SHA256: &str = "dcfcc170c7bfd336318086d434f5599c1fe0960266b99f66bac26463e286a1b1";
const COMPLIANCE_YEARS_2_XML: &[u8] = b"<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>";
const COMPLIANCE_YEARS_2_SHA256: &str = "323e4f84d687776e51c8706afc1a2f32328956a55643e3a096d425196453cb52";
const ENABLED_ONLY_SHA256: &str = "9cf16b957c9f7a738af95d6962500ebaae0e23d0138c811a8b6f39bcc941bbb2";

fn captured(
    bytes: &[u8],
    sha256: &str,
    value: PersistedObjectLockConfiguration,
    notes: &str,
) -> AcceptedCorpusCase<PersistedObjectLockConfiguration> {
    AcceptedCorpusCase {
        sample: GoldenSample {
            kind: ConfigKind::ObjectLock,
            bytes: bytes.to_vec(),
            value,
            origin: SampleOrigin {
                source: "Source-(b) live AWS SDK for Rust Object Lock client matrix capture".to_owned(),
                producer: "aws-sdk-s3 1.144.0 Put/GetObjectLockConfiguration; rustfs inspect bucket-meta --raw".to_owned(),
                version: "rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8".to_owned(),
                sha256: sha256.to_owned(),
            },
            notes: notes.to_owned(),
        },
        variants: vec![CorpusVariant::Canonical],
    }
}

pub(super) fn cases() -> [AcceptedCorpusCase<PersistedObjectLockConfiguration>; 2] {
    [
        captured(
            GOVERNANCE_DAYS_7_XML,
            GOVERNANCE_DAYS_7_SHA256,
            enabled(Some(retention("GOVERNANCE", Some(7), None))),
            "seven-day Governance retention persisted after a real SDK Put/Get round trip",
        ),
        captured(
            COMPLIANCE_YEARS_2_XML,
            COMPLIANCE_YEARS_2_SHA256,
            enabled(Some(retention("COMPLIANCE", None, Some(2)))),
            "two-year Compliance retention persisted after a real SDK Put/Get round trip",
        ),
    ]
}

pub(super) fn decorate_enabled_only_alias(sample: &mut GoldenSample<PersistedObjectLockConfiguration>) {
    debug_assert_eq!(sample.origin.sha256, ENABLED_ONLY_SHA256);
    sample
        .origin
        .source
        .push_str(" (alias: Source-(b) live AWS SDK for Rust Object Lock enabled-only capture)");
    sample.notes.push_str(
        "; exact-byte alias from aws-sdk-s3 1.144.0 Put/GetObjectLockConfiguration and RustFS inspect --raw at rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_b_aws_sdk_rust_object_lock_captures_are_registered() {
        let corpus = super::super::corpus_evidence();
        for (sha256, bytes, expected) in [
            (
                GOVERNANCE_DAYS_7_SHA256,
                GOVERNANCE_DAYS_7_XML,
                enabled(Some(retention("GOVERNANCE", Some(7), None))),
            ),
            (
                COMPLIANCE_YEARS_2_SHA256,
                COMPLIANCE_YEARS_2_XML,
                enabled(Some(retention("COMPLIANCE", None, Some(2)))),
            ),
        ] {
            let matches = corpus
                .accepted
                .iter()
                .filter(|case| case.sample.origin.sha256 == sha256)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "each new live Object Lock SHA must be registered once");
            let sample = &matches[0].sample;
            assert_eq!(sample.bytes, bytes);
            assert_eq!(sample.value, expected);
            assert_eq!(sample.origin.source, "Source-(b) live AWS SDK for Rust Object Lock client matrix capture");
            assert_eq!(
                sample.origin.producer,
                "aws-sdk-s3 1.144.0 Put/GetObjectLockConfiguration; rustfs inspect bucket-meta --raw"
            );
            assert_eq!(sample.origin.version, "rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8");
            super::super::assert_object_lock_four_way(sample)
                .expect("each live AWS SDK for Rust Object Lock capture passes D1-D5");
        }
    }

    #[test]
    fn source_b_enabled_only_capture_is_a_single_provenance_alias() {
        let matches = super::super::corpus_evidence()
            .accepted
            .into_iter()
            .filter(|case| case.sample.origin.sha256 == ENABLED_ONLY_SHA256)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "the exact-byte alias must not duplicate the sample");
        assert_eq!(
            matches[0].sample.origin.source,
            "P9 Object Lock persistence matrix (alias: Source-(b) live AWS SDK for Rust Object Lock enabled-only capture)"
        );
        assert!(matches[0].sample.notes.contains("aws-sdk-s3 1.144.0"));
        assert!(
            matches[0]
                .sample
                .notes
                .contains("rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8")
        );
    }
}
