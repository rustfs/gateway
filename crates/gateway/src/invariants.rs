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

//! The response invariants, applied once to every response the service produces.
//!
//! Responsible for: [`enforce`] — dropping the content a response is forbidden to carry, and the
//! two headers it is forbidden to carry, on the answered path and the refused path alike, after
//! the body has been chosen and before it is written out.
//! NOT responsible for: deciding the rule. That is
//! [`rustfs_gateway_core::body_allowance`], a function of the method and the status, so that this
//! file and `EncodedResponse::enforce_http_invariants` cannot come to different conclusions.
//! Nor for any header the framework stamps: `crate::stamp` writes those, afterwards.
//! Upstream: `rustfs-gateway-core`, `rustfs-gateway-stream`. Downstream: `crate::service`.
//!
//! # Why the rule is enforced here rather than passed into `render`
//!
//! Six stages can refuse a request and one can answer it, and only the answering path ever reaches
//! an encoder. Threading the request method into [`crate::render::render`] would put the `HEAD`
//! rule in two places — the encoder's and the renderer's — and two enforcement points for one rule
//! is the shape that drifts: the next status added to the bodyless set gets added to one of them.
//! [`crate::service::S3Service::call`] is the single position both paths pass through with the body
//! already chosen and nothing yet written, so the rule runs there, once, and is the last word.
//!
//! # Why this is not a "set `Content-Length` to zero" function
//!
//! RFC 9110 §9.3.2 says a `HEAD` response carries the header fields a `GET` would have carried and
//! no content. The length is one of those fields, and it is the answer the request was asking for:
//! rewriting it to `0` turns "this object is 5 bytes and I am not sending them" into "this object is
//! empty", which is a wrong answer rather than a missing one. So the bytes go and the number stays.
//! Only the statuses that carry no content *and* no framing — `1xx`, `204`, `205`, `304` — lose the
//! header too, which is what `c-cond-0005`, `c-cond-0007`, `c-cond-0010`, `c-cond-0017` and
//! `c-cond-0022` pin for the `304`.
//!
//! # The third rule: a declared length that the body cannot honour
//!
//! On the one status class that *may* carry content, a `Content-Length` that disagrees with a body
//! whose length is known is corrected to the body's. A response announcing more bytes than it sends
//! desynchronises the connection and hangs the client until its own read timeout — the shape behind
//! s3s#54 and s3s#350 — and one announcing fewer turns the tail into the next message on a reused
//! connection.
//!
//! The rule exists here rather than in the encoders because [`crate::StageFilter::on_response`] is
//! the one place a response is rewritten by code the framework did not write. It is a no-op for
//! every response an encoder produced, and it is deliberately silent about a body whose length is
//! not known: a stream declares what it declares, and inventing a number for one would be worse
//! than the disagreement.
//! # Why the customer-key headers are stripped here and not asked of backends
//!
//! `x-amz-server-side-encryption-customer-key` and its `copy-source` twin carry a raw AES key. A
//! response carrying one hands that key to every proxy, cache and access log between here and the
//! caller — and to the caller's own logs, which is where it will actually be found. AWS echoes
//! the *algorithm* and the *key digest* and never the key; the model agrees, binding only those
//! two on every SSE-C operation's output.
//!
//! So the framework does not ask. Every response passes through this function with its headers
//! already chosen, on both paths, and the two names are removed unconditionally. A backend that
//! sets one has a defect, and the defect does not reach the wire. Putting the rule in a code
//! review, or in each encoder, is the arrangement where the one encoder nobody reviewed is the
//! one that leaks; putting it in `crate::stamp::is_reserved` would cover a refusal's extra
//! headers and not an encoder's, which is the half of the surface that matters here.

use http::{HeaderName, Method, Response};
use rustfs_gateway_core::{BodyAllowance, body_allowance};
use rustfs_gateway_stream::Body;

/// Drops whatever content and whichever headers this response is forbidden to carry, and corrects
/// a length it cannot honour.
///
/// Idempotent, and deliberately so: the generated encoders already applied the body decision to
/// their own output, and this call is what extends it to the refusal path without the two paths
/// holding two copies of the rule.
pub(crate) fn enforce(response: &mut Response<Body>, method: &Method) {
    strip_customer_keys(response.headers_mut());
    match body_allowance(method, response.status()) {
        BodyAllowance::Content => reconcile_length(response),
        BodyAllowance::HeadOfContent => *response.body_mut() = Body::empty(),
        BodyAllowance::Bodyless => {
            *response.body_mut() = Body::empty();
            let headers = response.headers_mut();
            headers.remove(http::header::CONTENT_LENGTH);
            headers.remove(http::header::TRANSFER_ENCODING);
        }
    }
}

/// Makes `Content-Length` agree with a body whose length is known.
///
/// Does nothing when there is no declared length, when the body's length is not known, or when the
/// two already agree — which is every response this workspace's encoders produce.
fn reconcile_length(response: &mut Response<Body>) {
    let Some(actual) = response.body().len_hint() else {
        return;
    };
    let declared = response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok());
    if declared.is_none_or(|declared| declared == actual) {
        return;
    }
    let Ok(corrected) = http::HeaderValue::from_str(&actual.to_string()) else {
        // An ASCII decimal is always a legal header value; the fallible constructor is the only
        // one there is. Removing the header rather than leaving a lie is the safe half.
        response.headers_mut().remove(http::header::CONTENT_LENGTH);
        return;
    };
    response.headers_mut().insert(http::header::CONTENT_LENGTH, corrected);
}

/// Removes every header naming a customer-provided encryption key.
///
/// One `remove` per name, and that is enough: `HeaderMap::remove` drops **every** value stored
/// under the name and returns only the first of them. This was written as a `while` loop on the
/// strength of the return value alone; the mutation that replaced the loop with a single call left
/// every assertion green, which is how the second iteration turned out to be unreachable. The
/// repeated-header test below stays, because "both lines are gone" is the property — it is now
/// pinned against a rewrite to `get_mut` or `entry`, which would keep the second line.
fn strip_customer_keys(headers: &mut http::HeaderMap) {
    for name in rustfs_gateway_core::sse::NEVER_IN_A_RESPONSE {
        let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
            // Unreachable: the names are ASCII constants in this workspace. Skipped rather than
            // unwrapped, because a panic in the last writer of every response is worse than a
            // header that a source guard also refuses to let exist.
            continue;
        };
        headers.remove(&name);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use http::StatusCode;
    use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};

    /// A response carrying five bytes and a truthful `Content-Length`.
    fn five_bytes(status: StatusCode) -> Response<Body> {
        let mut response = Response::new(Body::from(b"hello".to_vec()));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, http::HeaderValue::from_static("5"));
        response
    }

    fn length_of(response: &Response<Body>) -> Option<&str> {
        response.headers().get(CONTENT_LENGTH).and_then(|value| value.to_str().ok())
    }

    /// Negative — a `HEAD` loses the bytes and keeps the number. The number is the answer, so a
    /// version of this function that wrote `0` would be a different defect wearing this one's fix.
    #[test]
    fn a_head_loses_its_bytes_and_keeps_its_length() {
        let mut response = five_bytes(StatusCode::OK);
        enforce(&mut response, &Method::HEAD);
        assert!(response.body().is_empty());
        assert_eq!(length_of(&response), Some("5"));
    }

    /// Negative — the rule has no status exception: a `HEAD` answered `404` loses its content just
    /// as a `HEAD` answered `200` does. This is the whole of the refusal-path defect.
    #[test]
    fn a_head_loses_its_bytes_on_every_status_not_only_on_success() {
        for status in [
            StatusCode::NOT_FOUND,
            StatusCode::PRECONDITION_FAILED,
            StatusCode::FORBIDDEN,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::RANGE_NOT_SATISFIABLE,
        ] {
            let mut response = five_bytes(status);
            enforce(&mut response, &Method::HEAD);
            assert!(response.body().is_empty(), "{status} kept its content");
            assert_eq!(length_of(&response), Some("5"), "{status} lost its length");
        }
    }

    /// Negative — a bodyless status loses the framing header as well as the bytes, whatever method
    /// asked for it. A `304` that announced five bytes it will never send desynchronises the
    /// connection exactly as the `HEAD` case does.
    #[test]
    fn a_bodyless_status_loses_its_framing_headers_too() {
        for status in [
            StatusCode::NOT_MODIFIED,
            StatusCode::NO_CONTENT,
            StatusCode::RESET_CONTENT,
            StatusCode::CONTINUE,
        ] {
            for method in [Method::GET, Method::HEAD, Method::PUT] {
                let mut response = five_bytes(status);
                response
                    .headers_mut()
                    .insert(TRANSFER_ENCODING, http::HeaderValue::from_static("chunked"));
                enforce(&mut response, &method);
                assert!(response.body().is_empty(), "{status} under {method} kept its content");
                assert_eq!(length_of(&response), None, "{status} under {method} kept its length");
                assert!(response.headers().get(TRANSFER_ENCODING).is_none());
            }
        }
    }

    /// Negative — a `GET` that is allowed content keeps every byte of it. A rule that dropped
    /// bodies too eagerly would be invisible to the two cases above and fatal to every read.
    #[test]
    fn a_get_that_may_carry_content_is_left_alone() {
        let mut response = five_bytes(StatusCode::OK);
        enforce(&mut response, &Method::GET);
        assert!(!response.body().is_empty());
        assert_eq!(length_of(&response), Some("5"));
    }

    /// Negative — applying the rule twice answers what applying it once did. The generated encoders
    /// already ran it, so this function is always the second application on the answered path.
    #[test]
    fn a_second_application_changes_nothing() {
        for (status, method) in [
            (StatusCode::OK, Method::HEAD),
            (StatusCode::NOT_MODIFIED, Method::GET),
            (StatusCode::OK, Method::GET),
        ] {
            let mut once = five_bytes(status);
            enforce(&mut once, &method);
            let mut twice = five_bytes(status);
            enforce(&mut twice, &method);
            enforce(&mut twice, &method);
            assert_eq!(once.body().is_empty(), twice.body().is_empty());
            assert_eq!(length_of(&once), length_of(&twice));
        }
    }

    /// Negative — a backend that wrote a customer key onto a response does not get it out.
    ///
    /// Both names, both directions of the response's fate, and the neighbouring headers left
    /// alone: a strip that removed the whole SSE family would take the algorithm and the digest
    /// with it, which AWS returns and which clients read.
    #[test]
    fn n_a_customer_key_header_never_reaches_the_wire() {
        const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        const DIGEST: &str = "tP/LI3N87DFaSk0aoqYgzg==";
        for status in [StatusCode::OK, StatusCode::FORBIDDEN, StatusCode::NOT_MODIFIED] {
            for method in [Method::GET, Method::HEAD, Method::PUT] {
                let mut response = five_bytes(status);
                let headers = response.headers_mut();
                headers.insert("x-amz-server-side-encryption-customer-key", http::HeaderValue::from_static(KEY));
                headers.insert(
                    "x-amz-copy-source-server-side-encryption-customer-key",
                    http::HeaderValue::from_static(KEY),
                );
                headers.insert(
                    "x-amz-server-side-encryption-customer-algorithm",
                    http::HeaderValue::from_static("AES256"),
                );
                headers.insert("x-amz-server-side-encryption-customer-key-md5", http::HeaderValue::from_static(DIGEST));
                enforce(&mut response, &method);
                let headers = response.headers();
                assert!(
                    headers.get("x-amz-server-side-encryption-customer-key").is_none(),
                    "{status} under {method} echoed the customer key"
                );
                assert!(
                    headers.get("x-amz-copy-source-server-side-encryption-customer-key").is_none(),
                    "{status} under {method} echoed the copy-source customer key"
                );
                assert_eq!(
                    headers
                        .get("x-amz-server-side-encryption-customer-algorithm")
                        .and_then(|value| value.to_str().ok()),
                    Some("AES256"),
                    "the algorithm must survive: AWS returns it"
                );
                assert_eq!(
                    headers
                        .get("x-amz-server-side-encryption-customer-key-md5")
                        .and_then(|value| value.to_str().ok()),
                    Some(DIGEST),
                    "the key digest must survive: AWS returns it"
                );
                assert!(!format!("{headers:?}").contains(KEY), "the key is still reachable through the header map");
            }
        }
    }

    /// Negative — a repeated key header loses every line, not only the first.
    ///
    /// `HeaderMap::remove` returns one value and discards the rest of that name's list, so a
    /// single call reads like a fix and leaves nothing behind only when there was one line.
    #[test]
    fn n_a_repeated_customer_key_header_is_removed_line_by_line() {
        let mut response = five_bytes(StatusCode::OK);
        let headers = response.headers_mut();
        headers.append("x-amz-server-side-encryption-customer-key", http::HeaderValue::from_static("QUJD"));
        headers.append("x-amz-server-side-encryption-customer-key", http::HeaderValue::from_static("REVG"));
        assert_eq!(
            response
                .headers()
                .get_all("x-amz-server-side-encryption-customer-key")
                .iter()
                .count(),
            2
        );
        enforce(&mut response, &Method::GET);
        assert_eq!(
            response
                .headers()
                .get_all("x-amz-server-side-encryption-customer-key")
                .iter()
                .count(),
            0
        );
    }

    /// Positive — a `304` answered to a `HEAD` takes the stricter of the two rules. The statuses
    /// are checked before the method for exactly this overlap.
    #[test]
    fn a_not_modified_head_is_bodyless_rather_than_head_of_content() {
        let mut response = five_bytes(StatusCode::NOT_MODIFIED);
        enforce(&mut response, &Method::HEAD);
        assert!(response.body().is_empty());
        assert_eq!(length_of(&response), None);
    }
}
