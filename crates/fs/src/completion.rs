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

//! `CompleteMultipartUpload`: an upload's parts judged against the completion's list, assembled,
//! and published as one object.
//!
//! Responsible for: the first completion of an upload — its checksum negotiation, the part list
//! (order, entity tags, sizes, checksums), the composite entity tag, the write conditions, and the
//! publication that retires the upload — and handing a completion whose upload is gone to the
//! replay.
//! NOT responsible for: replaying a retried completion (`super::completion_replay`), upload records
//! and checksum rules (`super::uploads`), or version publication (`super::versioning`).
//! Upstream: the registry's `CompleteMultipartUpload` route. Downstream: `super::uploads`,
//! `super::completion_replay`, and the publication in `super::versioning`.

use std::io;
use std::sync::atomic::Ordering;

use md5::{Digest as _, Md5};
use rustfs_gateway::dto::{CompleteMultipartUpload, CompleteMultipartUploadOutput};
use rustfs_gateway::{ETag, ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, Timestamp};

use super::{
    FsBackend, MIN_MULTIPART_PART_BYTES, completion_replay, conditions, etag, no_such_upload, storage_error, tagging, uploads,
};

impl Handler<CompleteMultipartUpload> for FsBackend {
    async fn call(&self, request: Req<CompleteMultipartUpload>) -> HandlerResult<CompleteMultipartUpload> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let input = self.normalized_completion(input)?;
        let (upload_id, record) = match self.resolve_upload(&input.upload_id, &input.bucket, &input.key) {
            Ok(found) => found,
            Err(missing) => return self.replay_completion(&input, missing).await,
        };
        let completion_claim = input.checksum_spec;
        if let Some(checksum) = record.checksum {
            checksum.validate_completion_type(input.checksum_type.as_ref())?;
        } else if input.checksum_type.is_some() || completion_claim.is_some() {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the completion names a checksum type for an upload without checksum negotiation",
            ));
        }
        let completed = input.multipart_upload.parts;
        if completed.is_empty() {
            return Err(HandlerError::new(ErrorCode::INVALID_PART, "the completion names no uploaded part"));
        }
        let mut requested = Vec::with_capacity(completed.len());
        let mut previous = 0;
        for part in completed {
            let number = part.part_number;
            uploads::validate_completion_part_number(record.checksum, previous, number)?;
            previous = number;
            let checksum = record
                .checksum
                .map(|selection| selection.completed_part(&part))
                .transpose()?
                .flatten();
            let entity_tag = part
                .e_tag
                .ok_or_else(|| HandlerError::new(ErrorCode::INVALID_PART, "a completed part has no entity tag"))?;
            requested.push((number, entity_tag, checksum));
        }

        let upload = self.upload_path(input.bucket.as_str(), &upload_id);
        let mut completed_bytes = Vec::new();
        let mut part_digests = Vec::with_capacity(requested.len());
        let mut part_checksums = Vec::with_capacity(requested.len());
        let final_part = requested.len().saturating_sub(1);
        for (index, (number, expected, expected_checksum)) in requested.iter().enumerate() {
            let path = Self::part_path(&upload, *number);
            let metadata = tokio::fs::symlink_metadata(&path).await.map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => HandlerError::new(ErrorCode::INVALID_PART, "a completed part was not uploaded"),
                _ => storage_error(),
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the multipart part path is not a safe regular file",
                ));
            }
            let bytes = tokio::fs::read(path).await.map_err(|_| storage_error())?;
            if index != final_part && bytes.len() < MIN_MULTIPART_PART_BYTES {
                return Err(HandlerError::new(
                    ErrorCode::ENTITY_TOO_SMALL,
                    "the proposed multipart upload contains an undersized non-final part",
                ));
            }
            let actual = etag(&bytes)?;
            if actual != *expected {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_PART,
                    "a completed part entity tag does not match the uploaded part",
                ));
            }
            if let Some(selection) = record.checksum {
                let actual_checksum = selection.validate_part(*expected_checksum, &bytes)?;
                part_checksums.push(actual_checksum);
            }
            part_digests.push(Md5::digest(&bytes).into());
            completed_bytes.extend_from_slice(&bytes);
        }
        let composite = ETag::from_part_digests(&part_digests).map_err(|_| storage_error())?;
        let completed_checksum = record
            .checksum
            .map(|selection| selection.complete(&part_checksums, &completed_bytes))
            .transpose()?;
        if let (Some(selection), Some(actual)) = (record.checksum, completed_checksum.as_ref()) {
            selection.validate_completed_object(completion_claim, actual)?;
        }

        let mut attributes = (*record.attributes).clone();
        attributes.tags = tagging::read_persisted_tags(&upload).await?;
        let tombstone = self.uploads_path(input.bucket.as_str()).join(format!(
            ".complete-{}-{}",
            std::process::id(),
            self.temporary_id.fetch_add(1, Ordering::Relaxed)
        ));
        tokio::fs::rename(&upload, &tombstone).await.map_err(|_| no_such_upload())?;
        // The completion's write conditions are the same verdict `PutObject` gives, evaluated
        // inside the publication's version lock (rustfs/gateway#1002, #808).
        let write_conditions = conditions::conditions(
            input.if_match.as_deref(),
            None,
            input.if_none_match.as_deref(),
            None,
            Timestamp::from_secs(self.clock.now().unix_seconds()),
        )?;
        let published = match self
            .publish_object_if(
                input.bucket.as_str(),
                input.key.as_str(),
                &completed_bytes,
                &composite,
                &attributes,
                conditions::any(&write_conditions).then_some(&write_conditions),
            )
            .await
        {
            Ok(published) => published,
            Err(error) => {
                let _ = tokio::fs::rename(&tombstone, &upload).await;
                return Err(error);
            }
        };
        let _ = tokio::fs::remove_dir_all(tombstone).await;
        let parts = requested.iter().map(|(number, e_tag, _)| (*number, e_tag));
        completion_replay::record_completion(&published.directory, &upload_id, published.version_id.as_deref(), parts).await;
        let mut output = CompleteMultipartUploadOutput {
            location: Some(format!("/{}/{}", input.bucket.as_str(), input.key.as_str())),
            bucket: Some(input.bucket),
            key: Some(input.key),
            e_tag: Some(composite),
            version_id: published.version_id,
            checksum_type: record.checksum.map(uploads::UploadChecksum::dto_type),
            server_side_encryption: record.attributes.headers.encryption().reported_algorithm(),
            ssekms_key_id: record.attributes.headers.encryption().kms_key_id,
            ..CompleteMultipartUploadOutput::default()
        };
        if let Some(checksum) = completed_checksum {
            uploads::render_completed_checksum(&mut output, checksum)?;
        }
        Ok(Resp::new(output))
    }
}
