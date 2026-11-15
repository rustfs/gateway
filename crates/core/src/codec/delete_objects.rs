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

//! XML leaf conversions for DeleteObjects entry carriers.
//!
//! Responsible for: decoding entry keys and conditions, and rendering error key echoes.
//! NOT responsible for: document structure or resource proof.
//! Upstream: generated DeleteObjects codec. Downstream: typed request and response DTOs.

use rustfs_gateway_types::NamePolicy;
use rustfs_gateway_types::dto::{DeleteKeyEcho, DeleteObjectETag, DeleteObjectKey};

use super::document::DocumentReading;
use super::error::CodecError;
use super::value::{etag_xml, object_key, unusable};

pub(crate) fn delete_object_key(
    value: &str,
    member: &'static str,
    names: &NamePolicy,
    reading: DocumentReading,
) -> Result<DeleteObjectKey, CodecError> {
    match reading {
        DocumentReading::Tree => object_key(value, member, names).map(Into::into),
        DocumentReading::RustFs => DeleteObjectKey::materialize_rustfs_decoded(value, names).map_err(|_| unusable(member)),
    }
}

pub(super) const STRONG_EMPTY: &str = "\"\"";

pub(crate) fn delete_object_etag(
    value: &str,
    member: &'static str,
    reading: DocumentReading,
) -> Result<DeleteObjectETag, CodecError> {
    if reading == DocumentReading::RustFs && value == STRONG_EMPTY {
        return Ok(DeleteObjectETag::STRONG_EMPTY);
    }
    etag_xml(value, member).map(Into::into)
}

pub(crate) fn render_delete_key_echo(value: &DeleteKeyEcho) -> &str {
    value.as_str()
}
