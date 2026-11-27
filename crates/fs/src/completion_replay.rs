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

//! A repeated `CompleteMultipartUpload`, answered as RustFS answers it (rustfs/gateway#1002).
//!
//! Responsible for: the completion receipt written into the version a completion published, and
//! the replay of a retry against it: the same upload and parts replay the committed object, other
//! parts are `InvalidPart`, and anything else keeps the original `NoSuchUpload`. RustFS's
//! `complete_multipart_upload` does the same (`retried_complete_multipart_upload_returns_the_committed_object`
//! in `crates/ecstore/src/set_disk/ops/multipart.rs`).
//! NOT responsible for: the first completion (`super::completion`), or upload-id validation
//! (`rustfs_gateway::resolve_upload`, which the replay reuses so a forged id is refused alike).
//! Upstream: `super::completion`'s handler. Downstream: nothing.

use std::path::Path;

use rustfs_gateway::dto::{CompleteMultipartUpload, CompleteMultipartUploadInput, CompleteMultipartUploadOutput};
use rustfs_gateway::{ErrorCode, HandlerError, HandlerResult, RecordedUpload, Resp, resolve_upload};

use super::FsBackend;

/// The receipt file a completion leaves in the version directory it published.
const COMPLETION_FILE: &str = "completion";
const COMPLETION_SECTION: &str = "completion/1";

struct Completion {
    bucket: String,
    key: String,
    upload_id: String,
    version_id: Option<String>,
    parts: Vec<(i32, String)>,
}

impl RecordedUpload for Completion {
    fn bucket(&self) -> &str {
        &self.bucket
    }

    fn key(&self) -> &str {
        &self.key
    }
}

impl Completion {
    fn encode(&self) -> String {
        let mut text = format!(
            "{COMPLETION_SECTION}\n{}\n{}\n",
            hex::encode(&self.upload_id),
            self.version_id.as_deref().unwrap_or("-")
        );
        for (number, e_tag) in &self.parts {
            text.push_str(&format!("{number} {e_tag}\n"));
        }
        text
    }

    fn decode(bucket: &str, key: &str, text: &str) -> Option<Self> {
        let mut lines = text.lines();
        if lines.next()? != COMPLETION_SECTION {
            return None;
        }
        let upload_id = String::from_utf8(hex::decode(lines.next()?).ok()?).ok()?;
        let version_id = match lines.next()? {
            "-" => None,
            id => Some(id.to_owned()),
        };
        let parts = lines
            .map(|line| {
                let (number, e_tag) = line.split_once(' ')?;
                Some((number.parse().ok()?, e_tag.to_owned()))
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            upload_id,
            version_id,
            parts,
        })
    }
}

/// Information needed to write a completion replay receipt inside the staged version directory
/// before atomic publication rename.
pub(super) struct CompletionReceiptSpec {
    pub(super) upload_id: String,
    pub(super) parts: Vec<(i32, String)>,
}

/// Writes the completion replay receipt into `staging_dir` before the version directory is renamed
/// into place. Best effort: an obstruction or write failure does not fail the completion, and only
/// means a later retry answers `NoSuchUpload`.
pub(super) fn write_staged_completion_receipt(staging_dir: &Path, spec: &CompletionReceiptSpec, version_id: Option<&str>) {
    let receipt = Completion {
        bucket: String::new(),
        key: String::new(),
        upload_id: spec.upload_id.clone(),
        version_id: version_id.map(ToOwned::to_owned),
        parts: spec.parts.clone(),
    };
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging_dir.join(COMPLETION_FILE))
        .and_then(|mut file| std::io::Write::write_all(&mut file, receipt.encode().as_bytes()));
}

impl FsBackend {
    /// Answers a completion whose upload is gone while acquiring the shared-root version lock.
    pub(super) async fn replay_completion(
        &self,
        input: &CompleteMultipartUploadInput,
        missing: HandlerError,
    ) -> HandlerResult<CompleteMultipartUpload> {
        let _guard = self.version_lock.lock().await?;
        self.replay_completion_locked(input, missing).await
    }

    /// Answers a completion whose upload is gone while the caller already holds the shared-root
    /// version lock: a replay of the committed object when the key's current version was published
    /// by this upload with these parts, `InvalidPart` when the parts differ, and `missing`
    /// otherwise.
    pub(super) async fn replay_completion_locked(
        &self,
        input: &CompleteMultipartUploadInput,
        missing: HandlerError,
    ) -> HandlerResult<CompleteMultipartUpload> {
        let bucket = input.bucket.as_str();
        let key = input.key.as_str();
        let Ok(super::reads::Selected::Found(current)) = self.select_locked(bucket, key, None).await else {
            return Err(missing);
        };
        let current = *current;
        let Some(directory) = current.directory.as_deref() else {
            return Err(missing);
        };
        let Ok(text) = tokio::fs::read_to_string(directory.join(COMPLETION_FILE)).await else {
            return Err(missing);
        };
        let Some(completion) = Completion::decode(bucket, key, &text) else {
            return Err(missing);
        };
        let upload_id = completion.upload_id.clone();
        let Ok((_, completion)) =
            resolve_upload(&input.upload_id, &input.bucket, &input.key, |id| (id == upload_id).then_some(completion))
        else {
            return Err(missing);
        };
        let requested = input
            .multipart_upload
            .parts
            .iter()
            .map(|part| Some((part.part_number, part.e_tag.as_ref()?.opaque_tag().to_owned())))
            .collect::<Option<Vec<_>>>();
        if requested.as_ref() != Some(&completion.parts) {
            return Err(HandlerError::new(
                ErrorCode::INVALID_PART,
                "the completion names parts other than the ones this upload was completed with",
            ));
        }
        let encryption = current.headers.encryption();
        let mut output = CompleteMultipartUploadOutput {
            location: Some(format!("/{bucket}/{key}")),
            bucket: Some(input.bucket.clone()),
            key: Some(input.key.clone()),
            e_tag: Some(current.e_tag),
            version_id: completion.version_id,
            checksum_type: current.checksum.and_then(super::checksums::StoredChecksum::dto_type),
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            ..CompleteMultipartUploadOutput::default()
        };
        if let Some(checksum) = current.checksum {
            super::uploads::render_completed_checksum(&mut output, checksum.value)?;
        }
        Ok(Resp::new(output))
    }
}
