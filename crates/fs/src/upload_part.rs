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

//! Shared ordinary and external-input UploadPart publication.
//!
//! Responsible for: multipart admission, checked input and verification before storing a part.
//! NOT responsible for: transport, wire authentication or whole multipart completion.
//! Upstream: ordinary and explicitly capable handlers. Downstream: atomic part storage.

use super::external_input::PublicationGate;
use super::{FsBackend, drain_with_trailers, etag};
use rustfs_gateway::dto::{UploadPart, UploadPartOutput};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, request_checksum};

impl Handler<UploadPart> for FsBackend {
    async fn call(&self, request: Req<UploadPart>) -> HandlerResult<UploadPart> {
        self.upload_part_with_gate(request, PublicationGate::default()).await
    }
}
impl FsBackend {
    pub(super) async fn upload_part_with_gate(
        &self,
        request: Req<UploadPart>,
        gate: PublicationGate,
    ) -> HandlerResult<UploadPart> {
        let input = request.into_input();
        self.require_bucket(input.bucket.as_str()).await?;
        let admitted = if gate.is_external() {
            Some(self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?)
        } else {
            None
        };
        gate.accept().await?;
        let (bytes, trailers) = drain_with_trailers(input.body).await?;
        if i64::try_from(bytes.len()).ok() != Some(input.content_length) {
            return Err(HandlerError::new(
                ErrorCode::INCOMPLETE_BODY,
                "the request body did not match its declared content length",
            ));
        }
        let (upload_id, record) = match admitted {
            Some(admitted) => admitted,
            None => self.resolve_upload(&input.upload_id, &input.bucket, &input.key)?,
        };
        let claimed = request_checksum(input.checksum_spec, &trailers)?;
        let checksum_spec = match record.checksum {
            Some(checksum) => Some(checksum.validate_part(claimed, &bytes)?),
            None => claimed,
        };
        gate.verify().await?;
        self.store_part(input.bucket.as_str(), &upload_id, input.part_number, &bytes)
            .await?;
        // A part reports the encryption its upload was initiated under.
        let encryption = record.attributes.headers.encryption();
        Ok(Resp::new(UploadPartOutput {
            e_tag: etag(&bytes)?,
            checksum_spec,
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            ..UploadPartOutput::default()
        }))
    }
}
