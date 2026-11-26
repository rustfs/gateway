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

use std::borrow::Cow;

use rustfs_gateway_types::dto::{DeleteKeyEcho, DeleteObjectETag, DeleteObjectKey};
use rustfs_gateway_types::{NamePolicy, SlashPolicy};

use super::document::DocumentReading;
use super::error::CodecError;
use super::value::{etag_xml, object_key, unusable};

pub(crate) fn delete_object_key(
    value: &str,
    member: &'static str,
    names: &NamePolicy,
    reading: DocumentReading,
) -> Result<DeleteObjectKey, CodecError> {
    // `SlashPolicy::RustfsLegacy` models legacy RustFS's HTTP request-path parser and never
    // rewrites XML `<Delete><Object><Key>` entries; `SlashPolicy::Collapse` still applies.
    let effective = if names.slash_policy() == SlashPolicy::RustfsLegacy {
        Cow::Owned(names.clone().with_slash_policy(SlashPolicy::AwsPreserve))
    } else {
        Cow::Borrowed(names)
    };
    match reading {
        DocumentReading::Tree => object_key(value, member, &effective).map(Into::into),
        DocumentReading::RustFs => DeleteObjectKey::materialize_rustfs_decoded(value, &effective).map_err(|_| unusable(member)),
    }
}

const STRONG_EMPTY: &str = "\"\"";

/// Whether RustFS reads this `<ETag>` text as the strong-empty condition: the quoted pair, or the
/// empty element an SDK writes for `Some("")`.
pub(super) fn is_strong_empty_text(value: &str) -> bool {
    value.is_empty() || value == STRONG_EMPTY
}

pub(crate) fn delete_object_etag(
    value: &str,
    member: &'static str,
    reading: DocumentReading,
) -> Result<DeleteObjectETag, CodecError> {
    if reading == DocumentReading::RustFs && is_strong_empty_text(value) {
        return Ok(DeleteObjectETag::STRONG_EMPTY);
    }
    etag_xml(value, member).map(Into::into)
}

pub(crate) fn render_delete_key_echo(value: &DeleteKeyEcho) -> &str {
    value.as_str()
}
