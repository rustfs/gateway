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

//! The RFC 9110 body invariants, applied once to every response the service produces.
//!
//! Responsible for: [`enforce`] — dropping the content a response is forbidden to carry, on the
//! answered path and the refused path alike, after the body has been chosen and before it is
//! written out.
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

use http::{Method, Response};
use rustfs_gateway_core::{BodyAllowance, body_allowance};
use rustfs_gateway_stream::Body;

/// Drops whatever content this response is forbidden to carry.
///
/// Idempotent, and deliberately so: the generated encoders already applied the same decision to
/// their own output, and this call is what extends it to the refusal path without the two paths
/// holding two copies of the rule.
pub(crate) fn enforce(response: &mut Response<Body>, method: &Method) {
    match body_allowance(method, response.status()) {
        BodyAllowance::Content => {}
        BodyAllowance::HeadOfContent => *response.body_mut() = Body::empty(),
        BodyAllowance::Bodyless => {
            *response.body_mut() = Body::empty();
            let headers = response.headers_mut();
            headers.remove(http::header::CONTENT_LENGTH);
            headers.remove(http::header::TRANSFER_ENCODING);
        }
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
