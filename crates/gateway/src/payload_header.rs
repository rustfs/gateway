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
//! headers. NOT responsible for: authenticating the declaration or decoding `aws-chunked` framing.
//! Upstream: `crate::service`. Downstream: `rustfs-gateway-sig` payload parsing.

use http::HeaderMap;
use rustfs_gateway_core::{HandlerError, ResponseKind};
use rustfs_gateway_sig::{PayloadMode, SigLocation, TrailerSet};
use rustfs_gateway_types::ErrorCode;

use crate::close::ConnectionIntent;
use crate::render::{S3Error, from_handler};

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
