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

//! Signature-owned payload declarations read from the request head.
//!
//! Responsible for: deriving one complete [`PayloadMode`] from the signed payload and trailer
//! headers, and turning a signed exact digest into body-reader work. NOT responsible for:
//! authenticating the declaration or decoding `aws-chunked` framing. Upstream: `crate::service`.
//! Downstream: `rustfs-gateway-sig` payload parsing and `crate::gate` body validation.

use http::HeaderMap;
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_sig::{PayloadMode, SigLocation, TrailerSet};
use rustfs_gateway_types::ErrorCode;

use crate::close::ConnectionIntent;
use crate::gate::BodyDigestObligation;
use crate::render::{S3Error, from_handler};

/// A recognised presigned payload shape this assembly deliberately does not implement.
pub(crate) struct StreamingPresignedUnsupported;

/// What `x-amz-content-sha256` said about the body.
///
/// An absent header is [`PayloadMode::Unsigned`] for a presigned query and
/// [`PayloadMode::Empty`] for a header signature. The trailer set is read atomically with the
/// digest because the two are valid only in specific combinations.
pub(crate) fn payload_mode(headers: &HeaderMap, location: SigLocation) -> Result<PayloadMode, S3Error> {
    let Some(value) = headers.get("x-amz-content-sha256") else {
        return Ok(if location.is_presigned() {
            PayloadMode::Unsigned
        } else {
            PayloadMode::Empty
        });
    };
    let Ok(text) = value.to_str() else {
        return Err(ordinary_refusal(
            ErrorCode::INVALID_REQUEST,
            "the x-amz-content-sha256 header is not a readable value",
        ));
    };
    PayloadMode::parse(text, declared_trailers(headers)?).map_err(|_| {
        ordinary_refusal(
            ErrorCode::INVALID_REQUEST,
            "the x-amz-content-sha256 header is not a value this service accepts",
        )
    })
}

/// The framing an anonymous request's own head declares (rustfs/gateway#1060).
///
/// `STREAMING-UNSIGNED-PAYLOAD-TRAILER` needs no signature to decode, so an anonymous request that
/// declares it is decoded exactly as a signed one is; handing it through would store the framing
/// as object data. A chunk-signed streaming mode cannot be verified without a signature and is
/// refused. Any other declaration leaves the body plain, as before: an anonymous request's digest
/// is not an obligation this assembly takes on.
pub(crate) fn anonymous_framing(headers: &HeaderMap) -> Result<Option<PayloadMode>, S3Error> {
    let declares_streaming = headers
        .get("x-amz-content-sha256")
        .is_some_and(|value| value.as_bytes().starts_with(b"STREAMING-"));
    if !declares_streaming {
        return Ok(None);
    }
    match payload_mode(headers, SigLocation::Header)? {
        mode @ PayloadMode::StreamingUnsigned { .. } => Ok(Some(mode)),
        PayloadMode::StreamingSigned { .. } => Err(ordinary_refusal(
            ErrorCode::INVALID_REQUEST,
            "a chunk-signed streaming payload needs a signed request",
        )),
        _ => Ok(None),
    }
}

/// The body-integrity work a signed payload declaration leaves for the body reader.
///
/// An exact digest is an obligation wherever the signature travels: the signature covers
/// `x-amz-content-sha256`, and only comparing that declaration with the body makes it cover the
/// body. A header-signed digest that went uncompared authenticated the head and not the payload, so
/// a replayed head carried any body (c-sig-0596, beside the presigned c-sig-0430). A framed payload
/// declares no digest — its chain of chunk signatures covers it — and a presigned query cannot seed
/// that chain, so the presigned streaming form is refused.
pub(crate) fn body_digest_obligation(
    payload: &PayloadMode,
    location: SigLocation,
) -> Result<BodyDigestObligation, StreamingPresignedUnsupported> {
    if let Some(digest) = payload.digest() {
        return Ok(BodyDigestObligation::Sha256(*digest));
    }
    if location.is_presigned() && payload.is_framed() {
        return Err(StreamingPresignedUnsupported);
    }
    Ok(BodyDigestObligation::None)
}

fn declared_trailers(headers: &HeaderMap) -> Result<TrailerSet, S3Error> {
    let Some(value) = headers.get("x-amz-trailer") else {
        return Ok(TrailerSet::None);
    };
    let malformed = || ordinary_refusal(ErrorCode::INVALID_REQUEST, "the x-amz-trailer header is not one this service can read");
    let text = value.to_str().map_err(|_| malformed())?;
    let mut names = Vec::new();
    for name in text.split(',').map(str::trim).filter(|name| !name.is_empty()) {
        names.push(rustfs_gateway_sig::TrailerName::new(name).map_err(|_| malformed())?);
    }
    rustfs_gateway_sig::DeclaredTrailers::new(names, false)
        .map(TrailerSet::Declared)
        .map_err(|_| malformed())
}

fn ordinary_refusal(code: ErrorCode, message: &'static str) -> S3Error {
    from_handler(HandlerError::new(code, message), ResponseKind::Other, ConnectionIntent::MayKeepAlive)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_content_sha256_uses_the_signature_location() {
        assert!(matches!(payload_mode(&HeaderMap::new(), SigLocation::Header), Ok(PayloadMode::Empty)));
        assert!(matches!(payload_mode(&HeaderMap::new(), SigLocation::Query), Ok(PayloadMode::Unsigned)));
    }

    #[test]
    fn an_unframeable_payload_declaration_is_refused() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::HeaderName::from_static("x-amz-content-sha256"),
            http::HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"),
        );
        assert!(payload_mode(&headers, SigLocation::Header).is_err());
    }
}
