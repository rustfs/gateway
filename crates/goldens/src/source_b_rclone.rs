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

//! Live rclone source-(b) persistence capture.
//!
//! Responsible for: binding rclone's supported Versioning capture as a deduplicated provenance alias.
//! NOT responsible for: unsupported rclone bucket-config APIs or adding a duplicate corpus sample.
//! Upstream: official rclone against disposable RustFS. Downstream: Versioning provenance and capture census.

#[cfg(test)]
use sha2::{Digest, Sha256};

#[cfg(test)]
const VERSIONING_XML: &[u8] = b"<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>";
const VERSIONING_SHA256: &str = "7ecd6025d6e250b27b84aed6bc0df05b96726bce8df5b0a1ab57e9889ce8fe29";
const METADATA_SHA256: &str = "e12aa902801d7ada971881fc6127e004e83f37328f5ae3caae6150ac4c5ff991";
const CAPTURE_VERSION: &str = "rclone@v1.75.0; release-zip-sha256:35e8f2a666ce789b29111db0dd843ddabc0d59c6b609d07bcaae5d1a07cba6f8; rclone-binary-sha256:f52ccc22e6fe61ea5791f0e186db323155ad1cc1b6dfe547f4bc665bea57a2dd; rustfs@c876df53f5097618b1817568a471cbb8b4f26ee8; rustfs-server-sha256:48e39ce70afeb390c729345c65ff10481db047e22f7f1d6b3c0863db6fea467c; rustfs-cli-sha256:264bc47c0fc9ca07ff1494c9aca8f95982d6406b716d6535a81c7e030f5463f9";

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CaptureMode {
    Alias,
    Concrete,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct CaptureBinding {
    bytes: &'static [u8],
    sha256: &'static str,
    metadata_sha256: &'static str,
    mode: CaptureMode,
}

#[cfg(test)]
fn capture_bindings() -> [CaptureBinding; 1] {
    [CaptureBinding {
        bytes: VERSIONING_XML,
        sha256: VERSIONING_SHA256,
        metadata_sha256: METADATA_SHA256,
        mode: CaptureMode::Alias,
    }]
}

pub(crate) fn versioning_alias_note() -> String {
    format!(
        "official rclone backend versioning set Enabled, got Enabled, set Suspended, and got Suspended against disposable RustFS; offline raw export independently produced the existing 77-byte Suspended XML ({VERSIONING_SHA256}), metadata SHA-256 {METADATA_SHA256}, {CAPTURE_VERSION}; rclone v1.75.0 S3 backend help exposes Versioning as its only bucket-configuration command"
    )
}

#[cfg(test)]
fn validate_census(candidates: &[CaptureBinding]) -> Result<(), String> {
    if candidates.len() != 1 {
        return Err(format!("expected 1 rclone capture binding, found {}", candidates.len()));
    }
    let capture = candidates[0];
    let observed = hex::encode(Sha256::digest(capture.bytes));
    if observed != capture.sha256 {
        return Err(format!(
            "rclone raw export SHA-256 mismatch: expected {}, observed {observed}",
            capture.sha256
        ));
    }
    if capture.metadata_sha256.len() != 64 {
        return Err("rclone metadata SHA-256 is not 64 hexadecimal characters".to_owned());
    }
    if capture.mode != CaptureMode::Alias {
        return Err("rclone Versioning duplicate must remain a provenance alias".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rclone_versioning_alias_is_registered() {
        let registered = capture_bindings();
        validate_census(&registered).expect("the rclone Versioning alias must be registered");
        assert_eq!(registered[0].bytes.len(), 77);
        assert!(versioning_alias_note().contains(VERSIONING_SHA256));
        assert!(versioning_alias_note().contains(METADATA_SHA256));
    }

    #[test]
    fn census_rejects_a_stale_rclone_raw_digest() {
        let mut stale = capture_bindings();
        stale[0].sha256 = "8ecd6025d6e250b27b84aed6bc0df05b96726bce8df5b0a1ab57e9889ce8fe29";
        let error = validate_census(&stale).expect_err("a stale rclone digest must fail closed");
        assert!(error.contains("raw export SHA-256 mismatch"));
        assert!(error.contains(VERSIONING_SHA256));
    }

    #[test]
    fn census_rejects_counting_the_rclone_alias_as_concrete() {
        let mut inflated = capture_bindings();
        inflated[0].mode = CaptureMode::Concrete;
        let error = validate_census(&inflated).expect_err("duplicate Versioning bytes must not increment the corpus");
        assert!(error.contains("must remain a provenance alias"));
    }
}
