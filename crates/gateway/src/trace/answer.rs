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

//! Which identifiers an answer carries: AWS's shape by default, legacy RustFS's under the RustFS
//! profile (rustfs/backlog#1677, ruling R10).
//!
//! Responsible for: [`Answer`], the per-request choice [`super::RequestTrace`] writes out, and
//! [`Identification`], the assembly's choice and the one place a request's trace is settled — the
//! host's identifier taken over, the answer chosen by the request's path.
//! NOT responsible for: writing a header or an element (`super::RequestTrace`), minting
//! (`super::TraceSource`), or the builder switch (`crate::builder`'s `identifiers`).
//! Upstream: `super`, `rustfs-gateway-core`'s router. Downstream: `crate::service`, once per request.
//!
//! # What legacy RustFS answers with
//!
//! Observed in source, rustfs/rustfs `e870a6d25b`, and pinned side by side against the legacy stack
//! in `crates/goldens` (`error_parity`):
//!
//! - **An S3 request** is given a server-owned `uuid::Uuid::new_v4()` at ingress
//!   (`rustfs/src/storage/request_context.rs:121-123`), and its answer carries that value in both
//!   `x-request-id` and `x-amz-request-id`, whatever the handler or the S3 library wrote there
//!   (`rustfs/src/server/layer.rs:253-276`, `:364-367`).
//! - **A request under an admin, table-catalog or profiling path** (`layer.rs:172-207`,
//!   `rustfs/src/server/prefix.rs:67-77`) keeps the caller's own `x-request-id`, or a fresh UUID
//!   when it sent none, and its answer carries that one header only, and only when the handler did
//!   not write it (`layer.rs:262-270`, `:368-370`).
//! - **No answer carries `x-amz-id-2`.** RustFS defines the name (`crates/utils/src/http/headers.rs:159`)
//!   and never writes it; its notifications fill the element with an empty string
//!   (`crates/notify/src/event.rs:249`).
//! - **No error document names the request.** The legacy S3 library writes `<RequestId>` only when
//!   the error carries one, and RustFS never sets one outside a test (`rustfs/src/app/object/shared.rs:1188`
//!   is under `#[cfg(test)]`); `<HostId>` it never writes. The only RustFS documents that name the
//!   request are ones RustFS renders itself, in front of the S3 stack: the rate-limit `429`
//!   (`rustfs/src/server/rate_limit.rs:434-438`), the SSE-C transport refusal
//!   (`ssec_transport.rs:116-120`) and the STS envelopes (`layer.rs:1780-1910`).
//!
//! # Why a claimed path is the host's
//!
//! A path under a dialect's claim is a path RustFS's admin router owns (ADR-0024), and on such a
//! path legacy RustFS writes the caller's own identifier back, which this service never writes: no
//! identifier it writes is read from a request. So under the RustFS profile an answer on a
//! claimed path carries no identifier from this service at all, and the host's own layer writes the
//! one legacy RustFS writes.
//!
//! The test approximates RustFS's own classification rather than repeating it. Like RustFS's, it
//! reads the path alone, so a virtual-hosted request under an admin prefix counts too. RustFS also
//! owns health, console, STS and gRPC paths, which never reach this service, and it counts a
//! profiling path only for an exact-path `GET`; a request this test counts and RustFS does not is
//! still answered alike, because RustFS's layer writes both of its S3 headers over every answer it
//! counts as S3 (`layer.rs:364-367`), whatever this service wrote.
//!
//! # Where the RustFS profile answers otherwise than legacy RustFS
//!
//! In one place, by ruling: an S3 error document names its request in `<RequestId>`, the value the
//! head carries (rustfs/backlog#1677, ruling R10: "RustFS's id is canonical; the gateway must accept
//! a host-provided id so header and error body agree"). Legacy RustFS's documents name none, so a
//! client reading the element finds the request the header already named; the Ceph s3-tests case
//! `test_object_requestid_matches_header_on_error` holds exactly that, and legacy RustFS fails it
//! (rustfs/rustfs `e870a6d25b`, `scripts/s3-tests/excluded_tests.txt:220`). The divergence is
//! registered as `rd-err-0001`'s RustFS-profile half. Nothing else the ruling does not cover moves
//! from legacy RustFS's answer.
//!
//! Legacy-compat (rustfs/backlog#2684): legacy RustFS answers without `x-amz-id-2` and without a
//! `<HostId>`, where AWS answers with both on every response, so SDK diagnostics show an empty
//! extended request id. Kept so RustFS clients read what they read today; the intended future
//! behaviour is the AWS answer ([`Answer::Aws`]) with the host's request identifier.

use rustfs_gateway_core::Router;

use super::{HostRequestId, RequestTrace};

/// Which identifiers one answer carries, and where. Settled once per request.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) enum Answer {
    /// `x-amz-request-id` and `x-amz-id-2` in the head, `<RequestId>` and `<HostId>` last in an
    /// error document: AWS's answer, and every assembly's default.
    #[default]
    Aws,
    /// Legacy RustFS's S3 answer: the request identifier in `x-amz-request-id` and in
    /// `x-request-id`, and in an error document's `<RequestId>` (ruling R10); no host identifier
    /// anywhere.
    LegacyRustfs,
    /// Legacy RustFS's answer on a path its admin router owns: no identifier from this service in
    /// the head or the document. The host writes its own.
    HostWritten,
}

/// Which identifiers an assembly's answers carry: the builder's choice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Identification {
    /// AWS's answer on every request.
    #[default]
    Aws,
    /// Legacy RustFS's answer (`ServiceBuilder::identify_requests_as_legacy_rustfs`).
    LegacyRustfs,
}

impl Identification {
    /// The trace one request is answered and reported with: `minted`, identified by the host's own
    /// identifier when the request carries a [`HostRequestId`], and answered as this assembly and the
    /// request's path select.
    pub(crate) fn settle<B>(self, minted: RequestTrace, request: &http::Request<B>, router: &Router) -> RequestTrace {
        let host = request.extensions().get::<HostRequestId>();
        let answer = match self {
            Self::Aws => Answer::Aws,
            Self::LegacyRustfs if claimed(request.uri().path(), router) => Answer::HostWritten,
            Self::LegacyRustfs => Answer::LegacyRustfs,
        };
        minted.identified(host, answer)
    }
}

/// Whether `path` is one of the router's claimed prefixes or continues one with `/`: the claim's own
/// test, which is RustFS's (`has_path_prefix`, rustfs/rustfs `e870a6d25b`,
/// `rustfs/src/server/prefix.rs:75-77`), asked of the path alone.
fn claimed(path: &str, router: &Router) -> bool {
    router.claims().claims().iter().any(|installed| installed.claim.covers(path))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use http::HeaderMap;
    use http::header::HeaderValue;
    use rustfs_gateway_xml::XmlWriter;

    use super::super::{HOST_ID_HEADER, REQUEST_ID_HEADER, RequestId, X_REQUEST_ID_HEADER};
    use super::*;

    fn trace(answer: Answer) -> RequestTrace {
        let host = HostRequestId::new("7c9e6679-7425-40de-944b-e07fc1f90ae7").expect("RustFS's shape");
        RequestTrace::from_bits(0xAAAA, 0xBBBB).identified(Some(&host), answer)
    }

    fn headers_with_everything() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("ENCODERCHOSEN000"));
        headers.insert(HOST_ID_HEADER, HeaderValue::from_static("ENCODERCHOSEN000"));
        headers.insert(X_REQUEST_ID_HEADER, HeaderValue::from_static("host-written"));
        headers
    }

    fn document(trace: &RequestTrace) -> String {
        let mut xml = XmlWriter::fragment();
        xml.open("Error", None);
        xml.element("Code", "NoSuchKey");
        trace.write_document_elements(&mut xml);
        xml.close();
        xml.finish()
    }

    /// Negative — a legacy RustFS answer carries the request identifier under both of RustFS's
    /// names, once each, and in its document, and no host identifier anywhere, whatever an encoder
    /// wrote before it.
    #[test]
    fn a_legacy_rustfs_answer_names_the_request_and_never_the_host() {
        let mut headers = headers_with_everything();
        trace(Answer::LegacyRustfs).apply(&mut headers);
        let id = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
        assert_eq!(headers.get_all(REQUEST_ID_HEADER).iter().collect::<Vec<_>>(), [id]);
        assert_eq!(headers.get_all(X_REQUEST_ID_HEADER).iter().collect::<Vec<_>>(), [id]);
        assert!(!headers.contains_key(HOST_ID_HEADER), "{headers:?}");
        assert_eq!(
            document(&trace(Answer::LegacyRustfs)),
            "<Error><Code>NoSuchKey</Code><RequestId>7c9e6679-7425-40de-944b-e07fc1f90ae7</RequestId></Error>"
        );
    }

    /// Negative — an answer on the host's path carries no identifier of this service: both of its
    /// names are removed, and the host's own `x-request-id` is left exactly as the host wrote it.
    #[test]
    fn a_host_written_answer_carries_no_identifier_of_this_service() {
        let mut headers = headers_with_everything();
        trace(Answer::HostWritten).apply(&mut headers);
        assert!(!headers.contains_key(REQUEST_ID_HEADER), "{headers:?}");
        assert!(!headers.contains_key(HOST_ID_HEADER), "{headers:?}");
        assert_eq!(headers.get(X_REQUEST_ID_HEADER).map(HeaderValue::as_bytes), Some(&b"host-written"[..]));
        assert_eq!(document(&trace(Answer::HostWritten)), "<Error><Code>NoSuchKey</Code></Error>");
    }

    /// Positive — the AWS answer is unchanged by a host's identifier: both headers and both
    /// document elements, the host's value where the request's goes, and `x-request-id` untouched.
    #[test]
    fn the_aws_answer_carries_the_host_identifier_in_both_places() {
        let mut headers = headers_with_everything();
        let aws = trace(Answer::Aws);
        aws.apply(&mut headers);
        assert_eq!(
            headers.get(REQUEST_ID_HEADER).map(HeaderValue::as_bytes),
            Some(&b"7c9e6679-7425-40de-944b-e07fc1f90ae7"[..])
        );
        assert_eq!(
            headers.get(HOST_ID_HEADER).map(HeaderValue::as_bytes),
            Some(&b"0000000000000000000000000000BBBB"[..])
        );
        assert_eq!(headers.get(X_REQUEST_ID_HEADER).map(HeaderValue::as_bytes), Some(&b"host-written"[..]));
        assert_eq!(
            document(&aws),
            "<Error><Code>NoSuchKey</Code><RequestId>7c9e6679-7425-40de-944b-e07fc1f90ae7</RequestId>\
             <HostId>0000000000000000000000000000BBBB</HostId></Error>"
        );
    }

    /// Negative — without a host identifier the minted one stands, in every answer shape.
    #[test]
    fn without_a_host_identifier_the_minted_one_stands() {
        for answer in [Answer::Aws, Answer::LegacyRustfs, Answer::HostWritten] {
            let settled = RequestTrace::from_bits(0xAAAA, 0xBBBB).identified(None, answer);
            assert_eq!(settled.request_id(), &RequestId::from_bits(0xAAAA), "{answer:?}");
        }
    }
}
