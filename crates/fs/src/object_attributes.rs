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
//! NOT responsible for: multipart persistence or GET byte windows; unavailable old detail is refused.
//! Upstream: the CRUD registry and representation reader. Downstream: generated attributes encoding.

use rustfs_gateway::dto::{
    Checksum, GetObjectAttributes, GetObjectAttributesOutput, GetObjectAttributesParts, ObjectPart, StorageClass,
};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp};

use super::encryption::refuse_read_encryption;

impl Handler<GetObjectAttributes> for super::FsBackend {
    async fn call(&self, request: Req<GetObjectAttributes>) -> HandlerResult<GetObjectAttributes> {
        refuse_read_encryption(request.sse())?;
        let input = request.input();
        let selected = |name: &str| input.object_attributes.iter().any(|attribute| attribute.as_str() == name);
        let representation = self
            .representation(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        let marker = input
            .part_number_marker
            .as_deref()
            .map(str::parse::<i32>)
            .transpose()
            .map_err(|_| invalid_page("part-number-marker must be a non-negative integer"))?
            .unwrap_or_default();
        if marker < 0 {
            return Err(invalid_page("part-number-marker must be a non-negative integer"));
        }
        let object_parts = if selected("ObjectParts") {
            part_attributes(&representation, marker, input.max_parts)?
        } else {
            None
        };
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
            object_parts,
            ..GetObjectAttributesOutput::default()
        }))
    }
}

fn invalid_page(message: &'static str) -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_ARGUMENT, message)
}

fn part_attributes(
    representation: &super::reads::Representation,
    marker: i32,
    max_parts: Option<i32>,
) -> Result<Option<GetObjectAttributesParts>, HandlerError> {
    let max_parts = max_parts.unwrap_or(1000);
    if !(1..=1000).contains(&max_parts) {
        return Err(invalid_page("max-parts must be between 1 and 1000"));
    }
    if representation.e_tag.part_count().is_none() {
        return Ok(None);
    }
    let unavailable = || HandlerError::not_implemented("original multipart part numbers are unavailable in this older record");
    let metadata = representation.part_metadata.as_deref().ok_or_else(unavailable)?;
    let lengths = representation.part_lengths.as_deref().ok_or_else(unavailable)?;
    // AWS lists original numbers greater than the marker, even if no part has that number.
    // https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html
    let mut selected = metadata.iter().zip(lengths).filter(|(part, _)| part.number > marker as u32);
    let parts = selected
        .by_ref()
        .take(max_parts as usize)
        .map(|(part, length)| {
            let mut output = ObjectPart {
                part_number: part.number as i32,
                size: i64::try_from(*length).map_err(|_| super::storage_error())?,
                ..ObjectPart::default()
            };
            set_object_checksum!(output, part.checksum.map(super::checksums::StoredChecksum::plain));
            Ok(output)
        })
        .collect::<Result<Vec<_>, HandlerError>>()?;
    Ok(Some(GetObjectAttributesParts {
        total_parts_count: metadata.len() as i32,
        part_number_marker: (marker > 0).then(|| marker.to_string()),
        next_part_number_marker: parts.last().map(|part| part.part_number).map(|number| number.to_string()),
        max_parts,
        is_truncated: selected.next().is_some(),
        parts,
    }))
}
