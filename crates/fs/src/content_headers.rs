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

//! The standard representation headers an object version stores, and their persisted section.
//!
//! Responsible for: the six headers a write may carry and every later read answers
//! (`Content-Type`, `Content-Encoding`, `Content-Disposition`, `Content-Language`,
//! `Cache-Control`, `Expires`), reading them out of a write request, the model's default media
//! type, their storability rule, and the byte form of the `headers/1` trailing section — which
//! also carries the server-managed encryption a version was written under
//! (`x-amz-server-side-encryption` and its KMS key id), resolved by `super::encryption`.
//! NOT responsible for: where that section sits in a record or an upload, or the sections around
//! it, which are `super::records`'; `response-*` overrides, which the codec applies.
//! Upstream: the write handlers, through `request_content_headers!`. Downstream: `super::records`,
//! which embeds the section, and `super::reads`, which answers the stored values.

use rustfs_gateway::{ErrorCode, HandlerError};

use super::records::decode_hex_text;

/// Reads the six stored representation headers out of any write input that declares them.
///
/// `PutObject`, `CopyObject` and `CreateMultipartUpload` spell the six members identically, so one
/// reader serves all three and none of them can forget a header the others store.
macro_rules! request_content_headers {
    ($input:expr) => {
        $crate::content_headers::ContentHeaders::from_request(
            $input.cache_control.clone(),
            $input.content_disposition.clone(),
            $input.content_encoding.clone(),
            $input.content_language.clone(),
            $input.content_type.clone(),
            $input.expires.as_ref().map(|value| value.as_str().to_owned()),
        )
    };
}

/// The name and version of the trailing section that carries the stored representation headers.
pub(super) const CONTENT_HEADERS_SECTION: &str = "headers/1";

/// The media type S3 answers for an object stored without one.
///
/// `GetObject.ContentType` and `HeadObject.ContentType` declare this default (`q-content-0008`), so
/// a read of an object whose write named no type answers it rather than omitting the header — an
/// omitted `Content-Type` is what crashed the `aws-sdk-go-v2` mint suite (rustfs/gateway#718). The
/// write no longer fills it in (rustfs/gateway#749): an untyped `PutObject` arrives here as `None`,
/// which this backend stores as no type and serves as this value.
pub(super) const DEFAULT_CONTENT_TYPE: &str = "binary/octet-stream";

/// The representation headers a write may carry and every later read must answer.
///
/// These are the standard headers S3 stores with an object version — as opposed to `x-amz-meta-*`,
/// which is the record's user-metadata map. A write's `Content-Type`, `Content-Encoding`, and the rest
/// describe the stored bytes, so they belong to the version and are copied, transitioned, and
/// deleted with it.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ContentHeaders {
    pub(super) cache_control: Option<String>,
    pub(super) content_disposition: Option<String>,
    pub(super) content_encoding: Option<String>,
    pub(super) content_language: Option<String>,
    pub(super) content_type: Option<String>,
    pub(super) expires: Option<String>,
    /// The server-managed algorithm the version was written under, reported and never applied
    /// (see `super::encryption`); set after the request is read, never by `from_request`.
    pub(super) server_side_encryption: Option<String>,
    /// The KMS key id beside an `aws:kms` algorithm.
    pub(super) ssekms_key_id: Option<String>,
}

impl ContentHeaders {
    /// The header names this section may carry, in the order they are written.
    const NAMES: [&'static str; 8] = [
        "cache-control",
        "content-disposition",
        "content-encoding",
        "content-language",
        "content-type",
        "expires",
        "x-amz-server-side-encryption",
        "x-amz-server-side-encryption-aws-kms-key-id",
    ];

    fn slot(&mut self, name: &str) -> Option<&mut Option<String>> {
        match name {
            "cache-control" => Some(&mut self.cache_control),
            "content-disposition" => Some(&mut self.content_disposition),
            "content-encoding" => Some(&mut self.content_encoding),
            "content-language" => Some(&mut self.content_language),
            "content-type" => Some(&mut self.content_type),
            "expires" => Some(&mut self.expires),
            "x-amz-server-side-encryption" => Some(&mut self.server_side_encryption),
            "x-amz-server-side-encryption-aws-kms-key-id" => Some(&mut self.ssekms_key_id),
            _ => None,
        }
    }

    fn entries(&self) -> [(&'static str, Option<&str>); 8] {
        [
            (Self::NAMES[0], self.cache_control.as_deref()),
            (Self::NAMES[1], self.content_disposition.as_deref()),
            (Self::NAMES[2], self.content_encoding.as_deref()),
            (Self::NAMES[3], self.content_language.as_deref()),
            (Self::NAMES[4], self.content_type.as_deref()),
            (Self::NAMES[5], self.expires.as_deref()),
            (Self::NAMES[6], self.server_side_encryption.as_deref()),
            (Self::NAMES[7], self.ssekms_key_id.as_deref()),
        ]
    }

    /// The headers a write carried, with the model's default media type folded into "none".
    ///
    /// A `Content-Type` equal to [`DEFAULT_CONTENT_TYPE`] is not stored: a read answers that value
    /// for an untyped object anyway, and storing it would give every untyped object a trailing
    /// section — which a build predating the section refuses — for no observable difference.
    pub(super) fn from_request(
        cache_control: Option<String>,
        content_disposition: Option<String>,
        content_encoding: Option<String>,
        content_language: Option<String>,
        content_type: Option<String>,
        expires: Option<String>,
    ) -> Self {
        Self {
            cache_control,
            content_disposition,
            content_encoding,
            content_language,
            content_type: content_type.filter(|value| value != DEFAULT_CONTENT_TYPE),
            expires,
            server_side_encryption: None,
            ssekms_key_id: None,
        }
    }

    /// These headers with the encryption a write resolved in place of whatever they carried.
    pub(super) fn with_encryption(mut self, encryption: super::encryption::ObjectEncryption) -> Self {
        self.server_side_encryption = encryption.algorithm;
        self.ssekms_key_id = encryption.kms_key_id;
        self
    }

    /// The encryption this version was written under.
    pub(super) fn encryption(&self) -> super::encryption::ObjectEncryption {
        super::encryption::ObjectEncryption {
            algorithm: self.server_side_encryption.clone(),
            kms_key_id: self.ssekms_key_id.clone(),
        }
    }

    /// The `Content-Type` a read answers: the stored one, or the model default.
    pub(super) fn served_content_type(&self) -> String {
        self.content_type.clone().unwrap_or_else(|| DEFAULT_CONTENT_TYPE.to_owned())
    }

    fn is_empty(&self) -> bool {
        self.entries().iter().all(|(_, value)| value.is_none())
    }
}

/// Refuses a representation header this backend could store but could never hand back.
///
/// # Errors
///
/// [`ErrorCode::INVALID_REQUEST`] when a value is not a legal header value.
pub(super) fn validate_content_headers(headers: &ContentHeaders) -> Result<(), HandlerError> {
    for (_, value) in headers.entries() {
        if value.is_some_and(|value| http::HeaderValue::from_str(value).is_err()) {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "a stored representation header value must be free of control characters",
            ));
        }
    }
    Ok(())
}

/// Renders the trailing representation-header section, or nothing for an object without one.
pub(super) fn encode_content_headers_section(headers: &ContentHeaders) -> String {
    if headers.is_empty() {
        return String::new();
    }
    let present = headers
        .entries()
        .into_iter()
        .filter_map(|(name, value)| value.map(|value| (name, value)));
    let mut section = format!("{CONTENT_HEADERS_SECTION} {}\n", present.clone().count());
    for (name, value) in present {
        section.push_str(name);
        section.push(' ');
        section.push_str(&hex::encode(value));
        section.push('\n');
    }
    section
}

pub(super) fn decode_content_header_entries(
    lines: &mut std::str::Lines<'_>,
    count: &str,
) -> Result<ContentHeaders, HandlerError> {
    let count = count.parse::<usize>().map_err(|_| {
        HandlerError::internal_error("the persisted representation-header section does not declare a decimal entry count")
    })?;
    let mut headers = ContentHeaders::default();
    let mut previous: Option<usize> = None;
    for _ in 0..count {
        let entry = lines.next().ok_or_else(|| {
            HandlerError::internal_error("the persisted representation-header section declares more entries than it holds")
        })?;
        let malformed = || HandlerError::internal_error("a persisted representation header is not a known name and a hex value");
        let (name, value) = entry.split_once(' ').ok_or_else(malformed)?;
        let position = ContentHeaders::NAMES
            .iter()
            .position(|known| *known == name)
            .ok_or_else(malformed)?;
        if previous.is_some_and(|previous| previous >= position) {
            return Err(HandlerError::internal_error(
                "the persisted representation-header section repeats or reorders an entry",
            ));
        }
        previous = Some(position);
        let value = decode_hex_text(value).ok_or_else(malformed)?;
        *headers.slot(name).ok_or_else(malformed)? = Some(value);
    }
    validate_content_headers(&headers)
        .map_err(|_| HandlerError::internal_error("a persisted representation header cannot be returned as a header"))?;
    Ok(headers)
}
