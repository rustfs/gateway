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

//! The RustFS-profile switch that answers a `304` with the object headers legacy RustFS sends
//! (rustfs/gateway#1120).
//!
//! Responsible for: [`ServiceBuilder::answer_not_modified_with_legacy_rustfs_headers`] and
//! [`NotModifiedHeaders::apply`], which the pipeline applies to the answer an object read produced.
//! NOT responsible for: whether a read is not modified (the handler, with `crate::evaluate`), a
//! `304`'s framing (`crate::invariants`), or the headers written on every answer after this — the
//! CORS decoration and the request identifiers, `Date` and `Server` (`crate::stamp`).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! Observed on rustfs/rustfs `ebe31dfdb`: `GetObject` and `HeadObject` repeat the stored
//! `ETag`, `Last-Modified`, `Cache-Control`, `Content-Location`, `Expires`, `Vary` and evaluated
//! `x-amz-version-id` on a bodyless `304`, for both latest and explicit-version reads. Other
//! representation headers, user metadata and restore state are absent. The profile preserves
//! those fields as written; it does not add missing facts.
//! Evidence: <https://github.com/rustfs/rustfs/blob/ebe31dfdb/rustfs/src/storage/ecfs_extend.rs>.

use http::HeaderMap;
use http::header::{
    ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_RANGE, CONTENT_TYPE, HeaderName,
};

use super::ServiceBuilder;
use crate::trace::{HOST_ID_HEADER, REQUEST_ID_HEADER};

/// The standard representation headers absent from current RustFS object-read `304` answers.
const REPRESENTATION_HEADERS: [HeaderName; 6] = [
    ACCEPT_RANGES,
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_LANGUAGE,
    CONTENT_RANGE,
    CONTENT_TYPE,
];

/// Which object headers a `304` answer to an object read keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NotModifiedHeaders {
    /// Whatever the operation wrote.
    #[default]
    AsWritten,
    /// Current RustFS's stored validators, caching fields and evaluated version on both reads.
    LegacyRustfs,
}

impl NotModifiedHeaders {
    /// Removes from `headers`, the headers of a `304` that `operation` answered, the object headers
    /// legacy RustFS does not send.
    ///
    /// Only an answer that is a `304` to `GetObject` or `HeadObject` is touched. The CORS
    /// decoration (`Access-Control-*`, `Vary`), the request and host identifiers, and any header
    /// that is neither standard nor `x-amz-*` are kept.
    pub(crate) fn apply(self, operation: Option<&str>, status: http::StatusCode, headers: &mut HeaderMap) {
        if self == Self::AsWritten || status != http::StatusCode::NOT_MODIFIED {
            return;
        }
        if !matches!(operation, Some("GetObject" | "HeadObject")) {
            return;
        }
        for name in REPRESENTATION_HEADERS {
            headers.remove(name);
        }
        let amz: Vec<HeaderName> = headers
            .keys()
            .filter(|name| {
                name.as_str().starts_with("x-amz-")
                    && **name != REQUEST_ID_HEADER
                    && **name != HOST_ID_HEADER
                    && name.as_str() != "x-amz-version-id"
            })
            .cloned()
            .collect();
        for name in amz {
            headers.remove(name);
        }
    }
}

impl ServiceBuilder {
    /// Answers a `304` to `GetObject` or `HeadObject` with current RustFS's object fields:
    /// validators, stored caching fields and the evaluated version id (rustfs/gateway#1120).
    ///
    /// Off by default: a `304` carries what the operation wrote. This switch removes the other
    /// standard representation headers and every `x-amz-*` header except the version, request and
    /// host identifiers. It never adds missing facts or touches another status, another operation,
    /// or the CORS headers.
    #[must_use]
    pub fn answer_not_modified_with_legacy_rustfs_headers(mut self) -> Self {
        self.view_policy.not_modified_headers = NotModifiedHeaders::LegacyRustfs;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use http::{HeaderValue, StatusCode};

    use super::*;

    /// What the reference backend and the CORS stage put on a `304`, with the identifiers.
    fn written() -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("etag", "\"5eb63bbbe01eeed093cb22bb8f5acdc3\""),
            ("last-modified", "Tue, 29 Sep 2026 23:13:46 GMT"),
            ("cache-control", "max-age=60"),
            ("expires", "opaque stored expiry"),
            ("content-location", "/snapshot"),
            ("content-type", "text/html"),
            ("content-disposition", "attachment"),
            ("content-language", "en"),
            ("content-encoding", "gzip"),
            ("accept-ranges", "bytes"),
            ("content-range", "bytes 0-3/11"),
            ("x-amz-meta-foo", "bar"),
            ("x-amz-version-id", "v1"),
            ("x-amz-tagging-count", "1"),
            ("x-amz-restore", "ongoing-request=\"true\""),
            ("x-amz-request-id", "0123456789ABCDEF"),
            ("x-amz-id-2", "host"),
            ("access-control-allow-origin", "https://app.example.com"),
            ("vary", "Origin"),
            ("x-deployment-note", "kept"),
        ] {
            headers.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
        }
        headers.insert("etag", HeaderValue::from_bytes(b"\"a\"\xc3\xa9\"").expect("opaque HTTP ETag bytes"));
        headers.append("vary", HeaderValue::from_static("Accept-Language"));
        headers
    }

    fn names(headers: &HeaderMap) -> Vec<&str> {
        let mut names: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Both reads retain exactly the current RustFS object fields, byte for byte.
    #[test]
    fn a_not_modified_keeps_current_rustfs_fields() {
        for operation in ["GetObject", "HeadObject"] {
            let original = written();
            let mut headers = original.clone();
            NotModifiedHeaders::LegacyRustfs.apply(Some(operation), StatusCode::NOT_MODIFIED, &mut headers);
            assert_eq!(
                names(&headers),
                [
                    "access-control-allow-origin",
                    "cache-control",
                    "content-location",
                    "etag",
                    "expires",
                    "last-modified",
                    "vary",
                    "x-amz-id-2",
                    "x-amz-request-id",
                    "x-amz-version-id",
                    "x-deployment-note"
                ],
                "{operation}"
            );
            for name in headers.keys() {
                assert_eq!(headers.get_all(name), original.get_all(name), "{operation} {name}");
            }
        }
    }

    /// Missing object fields stay absent; the policy does not manufacture facts.
    #[test]
    fn n_missing_fields_are_not_added() {
        for operation in ["GetObject", "HeadObject"] {
            let mut headers = HeaderMap::new();
            NotModifiedHeaders::LegacyRustfs.apply(Some(operation), StatusCode::NOT_MODIFIED, &mut headers);
            assert!(headers.is_empty());
        }
    }

    /// Negative — another status, another operation, an unrouted answer, and the default leave the
    /// headers as written.
    #[test]
    fn n_nothing_else_is_touched() {
        for (policy, operation, status) in [
            (NotModifiedHeaders::LegacyRustfs, Some("GetObject"), StatusCode::OK),
            (NotModifiedHeaders::LegacyRustfs, Some("HeadObject"), StatusCode::PARTIAL_CONTENT),
            (NotModifiedHeaders::LegacyRustfs, Some("HeadObject"), StatusCode::PRECONDITION_FAILED),
            (NotModifiedHeaders::LegacyRustfs, Some("GetObjectAttributes"), StatusCode::NOT_MODIFIED),
            (NotModifiedHeaders::LegacyRustfs, None, StatusCode::NOT_MODIFIED),
            (NotModifiedHeaders::AsWritten, Some("GetObject"), StatusCode::NOT_MODIFIED),
            (NotModifiedHeaders::AsWritten, Some("HeadObject"), StatusCode::NOT_MODIFIED),
        ] {
            let mut headers = written();
            policy.apply(operation, status, &mut headers);
            assert_eq!(headers, written(), "{policy:?} {operation:?} {status}");
        }
        assert_eq!(NotModifiedHeaders::default(), NotModifiedHeaders::AsWritten);
    }
}
