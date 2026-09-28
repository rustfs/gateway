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

//! The checksum a streaming request body claimed, whether it arrived as a header or a trailer.
//!
//! No `Members:` line, and that is the honest state rather than an omission, for the reason
//! `part_table` gives: an `impl Operation` decodes its input before a body byte is read, and a
//! trailer exists only once the body has ended, so no operation module can call this. The caller
//! is the backend that drained the body, reaching it through the facade re-export.
//!
//! Responsible for: turning the header-decoded `x-amz-checksum-*` value and the trailer section a
//! streaming body ended with into the one checksum the request claimed, with the header decoder's
//! own rules (one algorithm, a well-formed value) applied to the trailer fields, and refusing a
//! request that claimed one in both places (rustfs/gateway#929: aws-sdk-java-v2 sends every
//! `UploadPart` checksum as a trailer, so a backend reading headers only saw no checksum at all).
//! NOT responsible for: comparing the claim against the body. The wire layer
//! (`rustfs_gateway_http::BodyDigests::verify_with_trailers`) has already done that before the
//! body reports its end, so the trailers a handler receives are verified ones; what a backend does
//! with the claim — a negotiated multipart algorithm, a stored part checksum — is its own.
//! Upstream: [`crate::codec::value::checksum_spec`]'s field rule and
//! `rustfs_gateway_http::ChecksumReject` for the header-and-trailer refusal. Downstream: the
//! facade re-export, and through it every backend that stores a part or object checksum.

use rustfs_gateway_http::ChecksumReject;
use rustfs_gateway_stream::TrailingHeaders;
use rustfs_gateway_types::ChecksumSpec;

use crate::HandlerError;
use crate::codec::value::{CHECKSUM_PREFIX, checksum_spec_of_fields};

/// The model member a refusal names, matching the header decoder's.
const MEMBER: &str = "ChecksumSpec";

/// The checksum a request body claimed: its `x-amz-checksum-*` header, or its trailer.
///
/// `header` is the decoded input's `checksum_spec`; `trailers` is the section the body ended
/// with. Call it only after the body has been read to its end — before that the section is empty
/// and a trailer-carried claim is indistinguishable from none, which is the defect this exists to
/// close.
///
/// # Errors
///
/// `InvalidRequest` when a checksum arrived in both places (the wire layer's own
/// [`ChecksumReject::HeaderAndTrailerBothPresent`] refusal, repeated for a body that did not come
/// through it), and the header decoder's refusals for a trailer checksum value that is not valid
/// for its algorithm, is not text, or names a second algorithm.
pub fn request_checksum(header: Option<ChecksumSpec>, trailers: &TrailingHeaders) -> Result<Option<ChecksumSpec>, HandlerError> {
    let refuse = |error: crate::CodecError| HandlerError::new(error.code().clone(), error.message());
    let fields = || {
        trailers
            .iter()
            .filter_map(|(name, value)| name.as_str().strip_prefix(CHECKSUM_PREFIX).map(|suffix| (suffix, value)))
    };
    // A checksum field whose value is not text is refused, never skipped: skipping it would read
    // a claim the caller made as no claim at all. The header decoder gets the same answer from
    // the wire layer, which admits only text header values.
    if fields().any(|(_, value)| value.to_str().is_err()) {
        return Err(HandlerError::new(
            rustfs_gateway_types::ErrorCode::INVALID_REQUEST,
            "the request carries a checksum value that is not valid for the algorithm its header names",
        ));
    }
    let trailer = checksum_spec_of_fields(
        fields().filter_map(|(suffix, value)| value.to_str().ok().map(|value| (suffix, value))),
        CHECKSUM_PREFIX,
        MEMBER,
    )
    .map_err(refuse)?;
    match (header, trailer) {
        (Some(_), Some(_)) => {
            let rejection = ChecksumReject::HeaderAndTrailerBothPresent;
            Err(HandlerError::new(rejection.error_code(), rejection.message()))
        }
        (claim, None) | (None, claim) => Ok(claim),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // Test fixtures: a failed expectation is the assertion.
mod tests {
    use http::{HeaderMap, HeaderName, HeaderValue};
    use rustfs_gateway_types::{ChecksumAlgorithm, ErrorCode};

    use super::*;

    fn crc32_of(bytes: &[u8]) -> ChecksumSpec {
        let mut checksummer = ChecksumAlgorithm::Crc32.checksummer();
        checksummer.update(bytes);
        ChecksumSpec::from_digest(ChecksumAlgorithm::Crc32, &checksummer.finalize()).expect("a CRC32 width")
    }

    fn trailers(fields: &[(&'static str, &[u8])]) -> TrailingHeaders {
        let mut map = HeaderMap::new();
        for (name, value) in fields {
            map.append(
                HeaderName::from_static(name),
                HeaderValue::from_bytes(value).expect("a fixture trailer value"),
            );
        }
        TrailingHeaders::from_header_map(map)
    }

    fn refusal(result: Result<Option<ChecksumSpec>, HandlerError>) -> (ErrorCode, String) {
        let error = result.expect_err("a refused claim");
        (error.code().clone(), error.message().to_owned())
    }

    /// Positive — a trailer checksum is the request's checksum when no header carried one.
    #[test]
    fn a_trailer_checksum_is_the_claim_when_no_header_carried_one() {
        let spec = crc32_of(b"part");
        let claimed = request_checksum(None, &trailers(&[("x-amz-checksum-crc32", spec.render_base64().as_bytes())]))
            .expect("one trailer checksum");
        assert_eq!(claimed, Some(spec));
    }

    /// Positive — a header checksum passes through when the body ended with no checksum trailer.
    #[test]
    fn a_header_checksum_is_the_claim_when_no_trailer_carried_one() {
        let spec = crc32_of(b"part");
        assert_eq!(request_checksum(Some(spec), &TrailingHeaders::empty()), Ok(Some(spec)));
    }

    /// Negative — no header and no checksum trailer is no claim, not an invented one.
    #[test]
    fn neither_place_is_no_claim_and_other_trailer_fields_are_not_a_claim() {
        assert_eq!(request_checksum(None, &TrailingHeaders::empty()), Ok(None));
        assert_eq!(request_checksum(None, &trailers(&[("x-amz-meta-note", b"value")])), Ok(None));
    }

    /// Negative — a claim in both places is refused, even when both agree.
    #[test]
    fn a_header_and_a_trailer_checksum_together_are_refused() {
        let spec = crc32_of(b"part");
        let (code, message) = refusal(request_checksum(
            Some(spec),
            &trailers(&[("x-amz-checksum-crc32", spec.render_base64().as_bytes())]),
        ));
        assert_eq!(code, ErrorCode::INVALID_REQUEST);
        assert_eq!(message, ChecksumReject::HeaderAndTrailerBothPresent.message());
    }

    /// Negative — a trailer value that is not valid for its algorithm is refused, not skipped.
    #[test]
    fn a_malformed_trailer_checksum_is_refused_rather_than_skipped() {
        let (code, message) = refusal(request_checksum(None, &trailers(&[("x-amz-checksum-crc32", b"AAAA")])));
        assert_eq!(code, ErrorCode::INVALID_REQUEST);
        assert!(message.contains("not valid for the algorithm"), "{message}");
    }

    /// Negative — a trailer value that is not text is refused, not skipped.
    #[test]
    fn a_non_text_trailer_checksum_is_refused_rather_than_skipped() {
        let (code, _) = refusal(request_checksum(None, &trailers(&[("x-amz-checksum-crc32", b"\xffAAAAA==")])));
        assert_eq!(code, ErrorCode::INVALID_REQUEST);
    }

    /// Negative — two trailer checksums under two algorithms are a contradiction, not a choice.
    #[test]
    fn two_trailer_algorithms_are_refused() {
        let crc32 = crc32_of(b"part");
        let (code, message) = refusal(request_checksum(
            None,
            &trailers(&[
                ("x-amz-checksum-crc32", crc32.render_base64().as_bytes()),
                ("x-amz-checksum-sha1", b"2jmj7l5rSw0yVb/vlWAYkK/YBwk="),
            ]),
        ));
        assert_eq!(code, ErrorCode::INVALID_REQUEST);
        assert!(message.contains("more than one checksum algorithm"), "{message}");
    }
}
