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

//! Filesystem-backed `UploadPartCopy`: one part of an upload taken from a span of another object
//! (rustfs/gateway#979).
//!
//! Responsible for: selecting the authorized source representation, its copy-source conditions,
//! resolving `x-amz-copy-source-range` against it, and storing the span as the part.
//! NOT responsible for: parsing or authorizing `x-amz-copy-source` (the framework's proof), the
//! range grammar (`resolve_copy_range`), or completing the upload.
//! Upstream: `rustfs-gateway` copy-source contract, `super::copy`'s condition guard and
//! `super::reads`. Downstream: the multipart registry.

use rustfs_gateway::dto::{UploadPartCopy, UploadPartCopyOutput};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp, Timestamp, resolve_copy_range};

use super::copy::{SourceConditions, guard_copy_source, guard_copy_source_form};
use super::{FsBackend, etag};

impl Handler<UploadPartCopy> for FsBackend {
    async fn call(&self, request: Req<UploadPartCopy>) -> HandlerResult<UploadPartCopy> {
        let source = request
            .resources()
            .source()
            .resolve(request.read_proof())
            .ok_or_else(|| HandlerError::internal_error("the copy-source authorization proof did not match"))?;
        guard_copy_source_form(source.form())?;
        let source_bucket = source
            .bucket()
            .ok_or_else(|| HandlerError::internal_error("a path copy source has no bucket"))?;
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let (upload_id, record) = self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?;
        let representation = self
            .representation(source_bucket.as_str(), source.key().as_str(), source.version_id())
            .await?;
        guard_copy_source(
            &SourceConditions {
                if_match: input.copy_source_if_match.as_deref(),
                if_none_match: input.copy_source_if_none_match.as_deref(),
                if_modified_since: input.copy_source_if_modified_since,
                if_unmodified_since: input.copy_source_if_unmodified_since,
            },
            &representation,
            Timestamp::from_secs(self.clock.now().unix_seconds()),
        )?;
        let length = u64::try_from(representation.bytes.len()).map_err(|_| super::storage_error())?;
        let span = resolve_copy_range(input.copy_source_range.as_deref(), length)
            .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
        let bytes = match span {
            Some(span) => {
                let start = usize::try_from(span.start).map_err(|_| super::storage_error())?;
                let end = usize::try_from(span.end_inclusive).map_err(|_| super::storage_error())?;
                representation.bytes.get(start..=end).ok_or_else(super::storage_error)?
            }
            None => representation.bytes.as_slice(),
        };
        if let Some(checksum) = record.checksum {
            // A copied part carries no client checksum, so a composite upload refuses it here
            // exactly as it refuses an `UploadPart` without one.
            checksum.validate_part(None, bytes)?;
        }
        self.store_part(input.bucket.as_str(), &upload_id, input.part_number, bytes)
            .await?;
        let encryption = record.attributes.headers.encryption();
        Ok(Resp::new(UploadPartCopyOutput {
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            e_tag: etag(bytes)?,
            last_modified: Some(Timestamp::from_secs(self.clock.now().unix_seconds())),
            copy_source_version_id: source.version_id().map(ToOwned::to_owned).or(representation.version_id),
            ..UploadPartCopyOutput::default()
        }))
    }
}
