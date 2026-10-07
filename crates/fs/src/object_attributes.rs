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

//! Selected metadata for GetObjectAttributes from the persisted object representation.
//!
//! Responsible for: requested attribute groups, stored checksums and version-aware metadata.
//! NOT responsible for: multipart part-list persistence or pagination; unavailable detail is refused.
//! Upstream: the CRUD registry and representation reader. Downstream: generated attributes encoding.

use rustfs_gateway::dto::{Checksum, GetObjectAttributes, GetObjectAttributesOutput, StorageClass};
use rustfs_gateway::{Handler, HandlerError, HandlerResult, Req, Resp};

use super::encryption::refuse_read_encryption;

impl Handler<GetObjectAttributes> for super::FsBackend {
    async fn call(&self, request: Req<GetObjectAttributes>) -> HandlerResult<GetObjectAttributes> {
        refuse_read_encryption(request.sse())?;
        let input = request.input();
        let selected = |name: &str| input.object_attributes.iter().any(|attribute| attribute.as_str() == name);
        let representation = self
            .representation(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        if selected("ObjectParts") && representation.e_tag.part_count().is_some() {
            // The existing table contains ordinal lengths, not the original (possibly sparse)
            // upload numbers. Returning those ordinals as PartNumber would invent stored facts.
            return Err(HandlerError::not_implemented(
                "original multipart part numbers are not stored by this reference backend",
            ));
        }
        let checksum = if selected("Checksum") {
            let mut output = Checksum::default();
            set_object_checksum!(output, representation.checksum);
            output.checksum_type = representation.checksum.and_then(super::checksums::StoredChecksum::dto_type);
            Some(output)
        } else {
            None
        };
        Ok(Resp::new(GetObjectAttributesOutput {
            last_modified: Some(representation.last_modified),
            version_id: representation.version_id,
            e_tag: selected("ETag").then_some(representation.e_tag),
            object_size: if selected("ObjectSize") {
                Some(i64::try_from(representation.bytes.len()).map_err(|_| super::storage_error())?)
            } else {
                None
            },
            storage_class: selected("StorageClass").then(|| representation.storage_class.unwrap_or(StorageClass::STANDARD)),
            checksum,
            ..GetObjectAttributesOutput::default()
        }))
    }
}
