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

//! Shared ordinary and external-input PutObject publication.
//!
//! Responsible for: object attributes, conditions and verification before version publication.
//! NOT responsible for: wire authentication, data transport or physical storage tiers.
//! Upstream: ordinary and explicitly capable handlers. Downstream: shared version publication.

use super::conditions::{self, conditions};
use super::external_input::PublicationGate;
use super::lifecycle::ExpiringObject;
use super::records::ObjectAttributes;
use super::tagging::tags_from_header;
use super::transitions::requested_storage_class;
use super::{FsBackend, drain_with_trailers, etag};
use rustfs_gateway::dto::{PutObject, PutObjectOutput, ServerSideEncryption};
use rustfs_gateway::{Handler, HandlerResult, Req, Resp, Timestamp, request_checksum};

impl Handler<PutObject> for FsBackend {
    async fn call(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        self.put_object_with_gate(request, PublicationGate::default()).await
    }
}
impl FsBackend {
    pub(super) async fn put_object_with_gate(&self, request: Req<PutObject>, gate: PublicationGate) -> HandlerResult<PutObject> {
        let input = request.into_input();
        if gate.is_external() {
            self.require_bucket(input.bucket.as_str()).await?;
        }
        gate.accept().await?;
        // The body is drained before any attribute is judged, so a refusal is reported as itself
        // rather than as a body the handler abandoned. Every refusal still precedes publication:
        // a malformed tag header or an unknown class fails the request with no version written.
        let (bytes, trailers) = drain_with_trailers(input.body).await?;
        let checksum = request_checksum(input.checksum_spec, &trailers)?;
        let encryption = self
            .write_encryption(
                input.bucket.as_str(),
                input.server_side_encryption.as_ref().map(ServerSideEncryption::as_str),
                input.ssekms_key_id.as_deref(),
            )
            .await?;
        let attributes = ObjectAttributes {
            part_lengths: None,
            part_metadata: None,
            checksum: checksum.map(super::checksums::StoredChecksum::plain),
            headers: request_content_headers!(self, input).with_encryption(encryption.clone()),
            storage_class: requested_storage_class(input.storage_class.as_ref())?,
            tags: tags_from_header(input.tagging.as_deref())?,
            metadata: input.metadata,
        };
        let e_tag = etag(&bytes)?;
        // A write reads only `If-Match` and `If-None-Match`; the two date conditions are a read's.
        let write_conditions = conditions(
            input.if_match.as_deref(),
            None,
            input.if_none_match.as_deref(),
            None,
            Timestamp::from_secs(self.clock.now().unix_seconds()),
        )?;
        gate.verify().await?;
        let published = self
            .publish_object_if(
                input.bucket.as_str(),
                input.key.as_str(),
                &bytes,
                &e_tag,
                &attributes,
                conditions::any(&write_conditions).then_some(&write_conditions),
            )
            .await?;
        let written = ExpiringObject {
            key: input.key.as_str(),
            size: published.size,
            tags: &attributes.tags,
            modified: published.last_modified.secs(),
        };
        Ok(Resp::new(PutObjectOutput {
            checksum_spec: checksum,
            expiration: self.expiration_header(input.bucket.as_str(), &written).await.map(Into::into),
            size: Some(published.size),
            e_tag,
            version_id: published.version_id,
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            ..PutObjectOutput::default()
        }))
    }
}
