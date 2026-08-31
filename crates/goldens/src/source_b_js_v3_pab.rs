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

//! Live AWS SDK for JavaScript v3 Public Access Block source-(b) captures.
//!
//! Responsible for: binding three semantic SDK captures to concrete or deduplicated provenance.
//! NOT responsible for: SDK execution, persistence export, or Public Access Block policy behavior.
//! Upstream: official SDK against disposable RustFS. Downstream: PAB corpus and capture census.

use rustfs_gateway_types::persistence::PersistedPublicAccessBlockConfiguration;
#[cfg(test)]
use sha2::{Digest, Sha256};

use crate::{ConfigKind, CorpusVariant, GoldenSample, SampleOrigin};

const ALL_FALSE_XML: &[u8] = b"<PublicAccessBlockConfiguration><BlockPublicAcls>false</BlockPublicAcls><BlockPublicPolicy>false</BlockPublicPolicy><IgnorePublicAcls>false</IgnorePublicAcls><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>";
const MIXED_XML: &[u8] = b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><IgnorePublicAcls>false</IgnorePublicAcls><RestrictPublicBuckets>false</RestrictPublicBuckets></PublicAccessBlockConfiguration>";
#[cfg(test)]
const ALL_TRUE_XML: &[u8] = b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><IgnorePublicAcls>true</IgnorePublicAcls><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>";
const ALL_FALSE_SHA256: &str = "944fb8e6edcf2fe42123f2c1cc81a7319b3dcc954444fb99138526d6b3a18d9e";
const MIXED_SHA256: &str = "ad7548b40a234cff37c87235f803eb6b5f9a8344583c5c2f3b6c1059724aba8f";
const ALL_TRUE_SHA256: &str = "ea08b0fff9a3578a8e60f3da84d74dfdb9ddb7d970baa2d01641c68d6f363b2f";
const ALL_FALSE_METADATA_SHA256: &str = "187a9452d899dceec48cfdbf4f7827f812af15c3e54fe04f34905d530482b0eb";
const MIXED_METADATA_SHA256: &str = "6321667681f7002b4324a61190ed71547cb593342ef59d77d9112726c7c8cee3";
const ALL_TRUE_METADATA_SHA256: &str = "ab5bcc8395de35f507935b2ccca8a103b61ad391928eccfe21d2abf9852699b0";

fn origin(sha256: &str) -> SampleOrigin {
    SampleOrigin {
        source: "Source-(b) live AWS SDK for JavaScript v3 Public Access Block capture".to_owned(),
        producer: "official AWS SDK for JavaScript v3 against disposable RustFS; rustfs-cli offline raw export".to_owned(),
        version: crate::source_b_js_v3::CAPTURE_VERSION.to_owned(),
        sha256: sha256.to_owned(),
    }
}

fn configuration(
    block_public_acls: bool,
    ignore_public_acls: bool,
    block_public_policy: bool,
    restrict_public_buckets: bool,
) -> PersistedPublicAccessBlockConfiguration {
    PersistedPublicAccessBlockConfiguration {
        block_public_acls: Some(block_public_acls),
        ignore_public_acls: Some(ignore_public_acls),
        block_public_policy: Some(block_public_policy),
        restrict_public_buckets: Some(restrict_public_buckets),
    }
}

pub(crate) fn cases() -> Vec<(GoldenSample<PersistedPublicAccessBlockConfiguration>, Vec<CorpusVariant>)> {
    vec![
        (
            GoldenSample {
                kind: ConfigKind::PublicAccessBlock,
                bytes: ALL_FALSE_XML.to_vec(),
                value: configuration(false, false, false, false),
                origin: origin(ALL_FALSE_SHA256),
                notes: format!(
                    "byte-exact all-false PAB XML persisted after SDK Put and confirmed by SDK Get; raw metadata SHA-256 {ALL_FALSE_METADATA_SHA256}"
                ),
            },
            vec![CorpusVariant::Canonical],
        ),
        (
            GoldenSample {
                kind: ConfigKind::PublicAccessBlock,
                bytes: MIXED_XML.to_vec(),
                value: configuration(true, false, true, false),
                origin: origin(MIXED_SHA256),
                notes: format!(
                    "byte-exact mixed-switch PAB XML persisted after SDK Put and confirmed by SDK Get; raw metadata SHA-256 {MIXED_METADATA_SHA256}"
                ),
            },
            vec![CorpusVariant::Canonical],
        ),
    ]
}

pub(crate) fn all_true_alias_note() -> String {
    format!(
        "official AWS SDK for JavaScript v3 independently persisted the same all-true XML ({ALL_TRUE_SHA256}) after successful Put/Get; offline metadata SHA-256 {ALL_TRUE_METADATA_SHA256}; {}",
        crate::source_b_js_v3::CAPTURE_VERSION
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
            label: "all-false-concrete",
            bytes: ALL_FALSE_XML,
            sha256: ALL_FALSE_SHA256,
            metadata_sha256: ALL_FALSE_METADATA_SHA256,
            mode: CaptureMode::Concrete,
        },
        CaptureBinding {
            label: "mixed-concrete",
            bytes: MIXED_XML,
            sha256: MIXED_SHA256,
            metadata_sha256: MIXED_METADATA_SHA256,
            mode: CaptureMode::Concrete,
        },
        CaptureBinding {
            label: "all-true-alias",
            bytes: ALL_TRUE_XML,
            sha256: ALL_TRUE_SHA256,
            metadata_sha256: ALL_TRUE_METADATA_SHA256,
            mode: CaptureMode::Alias,
        },
    ]
}

#[cfg(test)]
fn validate_census(captures: &[CaptureBinding]) -> Result<(), String> {
    if captures.len() != 3 {
        return Err(format!("expected 3 JavaScript v3 PAB captures, found {}", captures.len()));
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
    if captures
        .iter()
        .filter(|capture| capture.mode == CaptureMode::Concrete)
        .count()
        != 2
        || captures.iter().filter(|capture| capture.mode == CaptureMode::Alias).count() != 1
    {
        return Err("PAB capture census must remain two concrete samples and one alias".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_three_javascript_v3_pab_captures_are_registered() {
        let registered = capture_bindings();
        validate_census(&registered).expect("the JavaScript v3 PAB census must be byte-exact");
        assert_eq!(
            registered.map(|capture| capture.label),
            ["all-false-concrete", "mixed-concrete", "all-true-alias"]
        );
        assert_eq!(registered.map(|capture| capture.bytes.len()), [243, 241, 239]);
        assert_eq!(cases().len(), 2);
        assert!(all_true_alias_note().contains(ALL_TRUE_SHA256));
    }

    #[test]
    fn census_rejects_a_stale_raw_export_digest() {
        let mut stale = capture_bindings();
        stale[0].sha256 = "a44fb8e6edcf2fe42123f2c1cc81a7319b3dcc954444fb99138526d6b3a18d9e";
        let error = validate_census(&stale).expect_err("a stale PAB digest must fail closed");
        assert!(error.contains("all-false-concrete"));
        assert!(error.contains("SHA-256 mismatch"));
    }

    #[test]
    fn census_rejects_counting_the_all_true_alias_as_concrete() {
        let mut inflated = capture_bindings();
        inflated[2].mode = CaptureMode::Concrete;
        let error = validate_census(&inflated).expect_err("the duplicate all-true PAB bytes must remain an alias");
        assert!(error.contains("two concrete samples and one alias"));
    }
}
