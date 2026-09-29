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
//! Legacy RustFS answers a read whose precondition says the client's copy is current with an error
//! the legacy stack writes as a bodyless `304`. `GetObject`'s carries the object's `ETag` and
//! `Last-Modified` and nothing else of the object (`check_preconditions`,
//! `rustfs/src/storage/ecfs_extend.rs:527-609`); `HeadObject`'s carries nothing of the object at
//! all (`rustfs/src/app/object/head.rs:417-432`). Observed against a legacy RustFS build on
//! rustfs/rustfs `e870a6d25b`: an object stored with `Cache-Control`, `Expires`, `Content-Type`,
//! `Content-Disposition`, `Content-Language`, user metadata and a tag answers a matching
//! `If-None-Match`, `If-None-Match: *` or an `If-Modified-Since` at its modification time with
//! exactly those two headers on `GET` — under `response-cache-control` and `response-content-type`,
//! `partNumber` and `x-amz-checksum-mode` too — and with neither on `HEAD`; a versioned read's `304`
//! names no version. The gateway's reference backend also writes `Cache-Control` and `Expires`,
//! applies the response overrides, and keeps both validators on `HEAD`, as RFC 9110 §15.4.5 asks.

use http::HeaderMap;
use http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    EXPIRES, HeaderName, LAST_MODIFIED,
};

use super::ServiceBuilder;
use crate::trace::{HOST_ID_HEADER, REQUEST_ID_HEADER};

/// The standard headers an object read writes about the object, besides its two validators.
const REPRESENTATION_HEADERS: [HeaderName; 8] = [
    ACCEPT_RANGES,
    CACHE_CONTROL,
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_LANGUAGE,
    CONTENT_RANGE,
    CONTENT_TYPE,
    EXPIRES,
];

/// Which object headers a `304` answer to an object read keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NotModifiedHeaders {
    /// Whatever the operation wrote.
    #[default]
    AsWritten,
    /// Legacy RustFS's: `GetObject`'s validators, and nothing of the object on `HeadObject`.
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
        let keeps_validators = match operation {
            Some("GetObject") => true,
            Some("HeadObject") => false,
            _ => return,
        };
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS answers a `HeadObject` `304` with no
        // `ETag` or `Last-Modified`, and a `GetObject` `304` with those two and no `Cache-Control`
        // or `Expires`, where RFC 9110 §15.4.5 asks a `304` to carry the validators and caching
        // headers its `200` would, and AWS S3 sends them. A cache revalidating with `HEAD` cannot
        // refresh its stored validators from the answer. Kept so the clients RustFS serves today see
        // the answer they see now; the intended future behaviour is the reference backend's — both
        // validators on both methods, with `Cache-Control` and `Expires`.
        for name in REPRESENTATION_HEADERS {
            headers.remove(name);
        }
        if !keeps_validators {
            headers.remove(ETAG);
            headers.remove(LAST_MODIFIED);
        }
        let amz: Vec<HeaderName> = headers
            .keys()
            .filter(|name| name.as_str().starts_with("x-amz-") && **name != REQUEST_ID_HEADER && **name != HOST_ID_HEADER)
            .cloned()
            .collect();
        for name in amz {
            headers.remove(name);
        }
    }
}

impl ServiceBuilder {
    /// Answers a `304` to an object read with the object headers legacy RustFS sends: `GetObject`'s
    /// keeps its `ETag` and `Last-Modified` and nothing else of the object, `HeadObject`'s keeps
    /// nothing of the object (rustfs/gateway#1120).
    ///
    /// Off by default: a `304` carries what the operation wrote — with the reference backend, both
    /// validators and the caching headers on both methods, as RFC 9110 §15.4.5 asks. The switch
    /// removes the standard representation headers and every `x-amz-*` header but the request and
    /// host identifiers; it never touches another status, another operation, or the CORS headers.
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
            ("expires", "Wed, 01 Jan 2031 00:00:00 GMT"),
            ("content-type", "text/html"),
            ("content-disposition", "attachment"),
            ("content-language", "en"),
            ("content-encoding", "gzip"),
            ("accept-ranges", "bytes"),
            ("content-range", "bytes 0-3/11"),
            ("x-amz-meta-foo", "bar"),
            ("x-amz-version-id", "v1"),
            ("x-amz-tagging-count", "1"),
            ("x-amz-request-id", "0123456789ABCDEF"),
            ("x-amz-id-2", "host"),
            ("access-control-allow-origin", "https://app.example.com"),
            ("vary", "Origin"),
            ("x-deployment-note", "kept"),
        ] {
            headers.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
        }
        headers
    }

    fn names(headers: &HeaderMap) -> Vec<&str> {
        let mut names: Vec<&str> = headers.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Positive — a `GetObject` `304` keeps its two validators and loses every other object header.
    #[test]
    fn a_get_not_modified_keeps_only_its_validators() {
        let mut headers = written();
        NotModifiedHeaders::LegacyRustfs.apply(Some("GetObject"), StatusCode::NOT_MODIFIED, &mut headers);
        assert_eq!(
            names(&headers),
            [
                "access-control-allow-origin",
                "etag",
                "last-modified",
                "vary",
                "x-amz-id-2",
                "x-amz-request-id",
                "x-deployment-note"
            ]
        );
        assert_eq!(
            headers.get(ETAG).map(HeaderValue::as_bytes),
            Some(&b"\"5eb63bbbe01eeed093cb22bb8f5acdc3\""[..])
        );
    }

    /// Positive — a `HeadObject` `304` keeps nothing of the object, not even its validators.
    #[test]
    fn a_head_not_modified_keeps_nothing_of_the_object() {
        let mut headers = written();
        NotModifiedHeaders::LegacyRustfs.apply(Some("HeadObject"), StatusCode::NOT_MODIFIED, &mut headers);
        assert_eq!(
            names(&headers),
            [
                "access-control-allow-origin",
                "vary",
                "x-amz-id-2",
                "x-amz-request-id",
                "x-deployment-note"
            ]
        );
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
