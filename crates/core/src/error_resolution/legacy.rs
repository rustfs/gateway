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

//! The RustFS profile's refusal: an error answered exactly as legacy RustFS writes it
//! (rustfs/gateway#1148).
//!
//! Responsible for: [`LegacyRustfsRefusal`] — the code (with its status), the message and the
//! fact headers of one legacy RustFS error, validated at construction — and its resolution, which
//! states exactly those and nothing the typed contexts would add: no document element beyond `Code`
//! and `Message`, no header beyond the facts the error carried, and no `Message` element when the
//! legacy document has none.
//! NOT responsible for: reading a legacy error (the migration seam's `refusal_from_legacy` does,
//! refusing by name what this type cannot state), the AWS answers the typed contexts give every
//! other deployment (the parent), or hiding a missing object from a caller who may not list the
//! bucket (the parent's `hide_missing_object`, which applies to these refusals as to the typed
//! ones).
//! Upstream: the RustFS ring-2 adapter, through `HandlerErrorContext::legacy_rustfs`. Downstream:
//! the parent's `resolve`.
//!
//! # Why this exists beside the typed contexts
//!
//! The typed contexts state what AWS states: a `304` always carries its entity tag, a `416` its
//! `Content-Range` and two document elements, a delete-marker read its instant, a message at most
//! 1024 bytes, and each missing-object code the gateway's own sentence. Legacy RustFS writes what
//! its app body put in the error and nothing more (`rustfs/src/storage/ecfs_extend.rs:557-604`,
//! `rustfs/src/app/object/head.rs:423,431`, `rustfs/src/app/object/shared.rs:60-100,159-174` on
//! rustfs/rustfs `e870a6d25b`), and its clients see exactly that today. RustFS will answer every
//! request through the gateway, so the RustFS profile answers these errors as legacy RustFS does,
//! and the typed contexts stay the default for every other deployment.
//!
//! Legacy-compat (rustfs/backlog#2684): legacy RustFS answers a `304` to a conditional `HEAD` with
//! no `ETag` (RFC 9110 §15.4.5 requires the validator a `200` would carry), a `416` with no
//! `Content-Range` (§15.5.17 asks for the current length), a read of a current delete marker with
//! no `Last-Modified`, and messages of any length. Kept so RustFS clients see no change; the
//! intended future behaviour is the typed contexts' AWS answers.
//!
//! # What a `304` repeats (rustfs/gateway#1612)
//!
//! RFC 9110 §15.4.5 (<https://www.rfc-editor.org/rfc/rfc9110#section-15.4.5>) has a `304` carry
//! each of `Cache-Control`, `Content-Location`, `Date`, `ETag`, `Expires` and `Vary` the `200`
//! would have carried. Legacy RustFS writes the stored four and the evaluated version's
//! `x-amz-version-id` beside its validators (`not_modified_error` in
//! `rustfs/src/storage/ecfs_extend.rs` on rustfs/rustfs `59bc6d7c9`), so a refusal states them when
//! given; `Date` is the framework's stamp on every response.

use std::borrow::Cow;

use http::StatusCode;
use rustfs_gateway_types::{ETag, ErrorCode, is_xml_representable};

use super::validate::validate_code;
use super::{BodyPolicy, ErrorResolution, InvalidErrorContext, MissingObject};
use crate::{ErrorHeader, HttpDate, StoredHeaderValue, VersionIdLabel};

/// The fact headers a legacy RustFS error carried, each already read from the error's own
/// header map.
///
/// Every member is optional because legacy RustFS writes each only when its app body attached it.
/// Which code may carry which fact is checked by [`LegacyRustfsRefusal::new`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LegacyRustfsFacts {
    /// The `ETag` of a `304`.
    pub etag: Option<ETag>,
    /// The `Last-Modified` of a `304` or a delete-marker read, in Unix seconds.
    pub last_modified: Option<i64>,
    /// The version id of the delete marker a `NoSuchKey` or `MethodNotAllowed` read found, stated
    /// with `x-amz-delete-marker: true`.
    pub delete_marker: Option<String>,
    /// The complete length a `416` states as `Content-Range: bytes */<length>`.
    pub complete_length: Option<u64>,
    /// The stored `Cache-Control` a `304` repeats.
    pub cache_control: Option<String>,
    /// The stored `Content-Location` a `304` repeats.
    pub content_location: Option<String>,
    /// The stored `Expires` a `304` repeats, as stored: its date grammar is not checked.
    pub expires: Option<String>,
    /// The stored `Vary` a `304` repeats.
    pub vary: Option<String>,
    /// The version id of the version a `304` evaluated, stated as `x-amz-version-id`.
    ///
    /// Not [`Self::delete_marker`]: that is the id of a delete marker a `NoSuchKey` or
    /// `MethodNotAllowed` read found and is stated with `x-amz-delete-marker: true`; this is the id of
    /// the version whose validators a `NotModified` matched, stated alone. The codes they belong to
    /// are disjoint, so a refusal states at most one `x-amz-version-id`. Both are withheld when the
    /// refusal is answered for a copy source, for the same reason (see
    /// `LegacyRustfsRefusal::without_version_id`).
    pub version_id: Option<String>,
}

/// One refusal exactly as legacy RustFS writes it; see the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyRustfsRefusal {
    code: ErrorCode,
    message: Option<Cow<'static, str>>,
    etag: Option<ETag>,
    last_modified: Option<HttpDate>,
    delete_marker: bool,
    /// The marker's version id on a marker read, the evaluated version's on a `304`.
    version_id: Option<VersionIdLabel>,
    complete_length: Option<u64>,
    /// The stored headers a `304` repeats, in emission order.
    stored: Vec<ErrorHeader>,
}

impl LegacyRustfsRefusal {
    /// Validates one legacy refusal: `code` answered at its own status (a declared code at its
    /// declared status, or `ErrorCode::custom` naming the status legacy RustFS wrote), with
    /// `message` as the `<Message>` text (`None` for a document without one) and `facts` as the
    /// only headers beside it.
    ///
    /// # Errors
    ///
    /// [`InvalidErrorContext::InvalidCode`] for a code that is not a bounded identifier, or whose
    /// status is neither a refusal (4xx, 5xx) nor the `304` of `NotModified`;
    /// [`InvalidErrorContext::InvalidMessage`] for text XML 1.0 cannot carry (there is no length
    /// bound: legacy RustFS writes a message whole); [`InvalidErrorContext::InvalidDetail`] for a
    /// fact its code does not state — an entity tag on anything but `NotModified`, a complete length
    /// on anything but `InvalidRange`, a delete marker on anything but `NoSuchKey` or
    /// `MethodNotAllowed`, an instant on anything but `NotModified` or a delete-marker read, a stored
    /// header or an evaluated version on anything but `NotModified` — or a stored header value a
    /// header cannot carry ([`StoredHeaderValue::new`]);
    /// [`InvalidErrorContext::InvalidVersionId`] and [`InvalidErrorContext::InvalidLastModified`]
    /// for a marker or evaluated version id or an instant the headers cannot carry.
    pub fn new(code: ErrorCode, message: Option<String>, facts: LegacyRustfsFacts) -> Result<Self, InvalidErrorContext> {
        validate_code(&code)?;
        let status = code.default_status();
        let not_modified = code.as_str() == ErrorCode::NOT_MODIFIED.as_str();
        let refusal = status.is_client_error() || status.is_server_error();
        if !((refusal && !not_modified) || (not_modified && status == StatusCode::NOT_MODIFIED)) {
            return Err(InvalidErrorContext::InvalidCode);
        }
        if message.as_deref().is_some_and(|text| !is_xml_representable(text)) {
            return Err(InvalidErrorContext::InvalidMessage);
        }
        let LegacyRustfsFacts {
            etag,
            last_modified,
            delete_marker,
            complete_length,
            cache_control,
            content_location,
            expires,
            vary,
            version_id: evaluated,
        } = facts;
        let repeated =
            cache_control.is_some() || content_location.is_some() || expires.is_some() || vary.is_some() || evaluated.is_some();
        let marker_code = matches!(
            (code.as_str(), status),
            ("NoSuchKey", StatusCode::NOT_FOUND) | ("MethodNotAllowed", StatusCode::METHOD_NOT_ALLOWED)
        );
        let range_code = code.as_str() == ErrorCode::INVALID_RANGE.as_str();
        if (etag.is_some() && !not_modified)
            || (complete_length.is_some() && !range_code)
            || (delete_marker.is_some() && !marker_code)
            || (last_modified.is_some() && !(not_modified || delete_marker.is_some()))
            || (repeated && !not_modified)
        {
            return Err(InvalidErrorContext::InvalidDetail);
        }
        let marked = delete_marker.is_some();
        let version_id = delete_marker
            .or(evaluated)
            .map(|version_id| VersionIdLabel::new(&version_id).map_err(|_| InvalidErrorContext::InvalidVersionId))
            .transpose()?;
        let stored_header = |value: Option<String>, header: fn(StoredHeaderValue) -> ErrorHeader| {
            value
                .map(|text| {
                    StoredHeaderValue::new(&text)
                        .map(header)
                        .map_err(|_| InvalidErrorContext::InvalidDetail)
                })
                .transpose()
        };
        let stored = [
            stored_header(cache_control, |value| ErrorHeader::CacheControl { value })?,
            stored_header(content_location, |value| ErrorHeader::ContentLocation { value })?,
            stored_header(expires, |value| ErrorHeader::Expires { value })?,
            stored_header(vary, |value| ErrorHeader::Vary { value })?,
        ]
        .into_iter()
        .flatten()
        .collect();
        let last_modified = last_modified
            .map(|seconds| HttpDate::from_unix_seconds(seconds).map_err(|_| InvalidErrorContext::InvalidLastModified))
            .transpose()?;
        Ok(Self {
            code,
            message: message.map(Cow::Owned),
            etag,
            last_modified,
            delete_marker: marked,
            version_id,
            complete_length,
            stored,
        })
    }

    /// The code, whose status is the one answered.
    #[must_use]
    pub const fn code(&self) -> &ErrorCode {
        &self.code
    }

    /// The missing object this refusal reports, when it reports one: `NoSuchKey` (a current delete
    /// marker included) or `NoSuchVersion`. What a caller who may not list the bucket must not
    /// learn, exactly as for the typed missing-object contexts.
    pub(super) fn missing_object(&self) -> Option<MissingObject> {
        match self.code.as_str() {
            "NoSuchKey" if self.code.default_status() == StatusCode::NOT_FOUND => Some(MissingObject::Key),
            "NoSuchVersion" if self.code.default_status() == StatusCode::NOT_FOUND => Some(MissingObject::Version),
            _ => None,
        }
    }

    /// The refusal a copy answers for its source: every version id withheld, as the typed marker
    /// contexts withhold the marker's (`x-amz-version-id` on a copy names the version it wrote). The
    /// evaluated version of a `304` is the source's too, so the same rule withholds it; the marker
    /// flag, the instant, the validators and the stored headers stay.
    pub(super) fn without_version_id(mut self) -> Self {
        self.version_id = None;
        self
    }

    /// The response facts, with nothing added.
    pub(super) fn resolution(self) -> ErrorResolution {
        let status = self.code.default_status();
        let bodyless = status == StatusCode::NOT_MODIFIED;
        let mut headers = Vec::new();
        if self.delete_marker {
            headers.push(ErrorHeader::DeleteMarker);
        }
        if let Some(version_id) = self.version_id {
            headers.push(ErrorHeader::VersionId { version_id });
        }
        if let Some(at) = self.last_modified {
            headers.push(ErrorHeader::LastModified { at });
        }
        if let Some(complete_length) = self.complete_length {
            headers.push(ErrorHeader::UnsatisfiedRange { complete_length });
        }
        headers.extend(self.stored);
        ErrorResolution {
            status,
            code: Some(self.code),
            body_policy: if bodyless {
                BodyPolicy::None
            } else {
                BodyPolicy::ErrorDocument
            },
            // A `304` has no document, so no message a `HEAD` could be measured by either.
            message: if bodyless { None } else { self.message },
            headers,
            details: Vec::new(),
            etag: self.etag,
            resource: None,
        }
    }
}
