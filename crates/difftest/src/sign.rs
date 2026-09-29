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

//! A recorded request, signed again for the replay, with the one credential both stacks hold.
//!
//! Responsible for: re-signing a request whose recorded signature was redacted, with SigV4 in the
//! `Authorization` header, at the moment of the replay, under the payload mode its own
//! `x-amz-content-sha256` names. A signed request takes the same admission path on both stacks as
//! the client's request did on the recorded server; sent unsigned it takes the anonymous path,
//! where the legacy stack decodes no aws-chunked framing, so a recording of a signed
//! `STREAMING-UNSIGNED-PAYLOAD-TRAILER` upload reached the legacy handler still framed.
//! NOT responsible for: chunk signatures (`STREAMING-AWS4-HMAC-SHA256-*`), which would need the
//! body re-framed; those recordings stay skipped. Nor for deciding which requests to re-sign
//! (`corpus.rs`).
//! Upstream: `corpus.rs`. Downstream: `gateway.rs` and `oracle.rs` hold [`ACCESS_KEY`] and
//! [`SECRET_KEY`].

use http::{HeaderMap, HeaderName, HeaderValue};
use rustfs_gateway::RequestNow;
use rustfs_gateway_http::RawHost;
use rustfs_gateway_sig::{
    AmzDate, DeclaredTrailers, EMPTY_PAYLOAD_SHA256_HEX, PayloadMode, SigService, SigV4Signer, SigningCredentials,
    SigningRequest, SigningScope, TrailerName, TrailerSet,
};

use crate::request::{DEFAULT_HOST, RawRequest};

/// The access key both stacks' credential stores hold.
pub(crate) const ACCESS_KEY: &str = "AKIDDIFFTEST";
/// Its secret.
pub(crate) const SECRET_KEY: &str = "difftest-secret-key";
/// The one region both stacks serve.
pub(crate) const REGION: &str = "us-east-1";

/// `YYYYMMDDTHHMMSSZ` for a Unix time.
fn amz_date(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let second_of_day = unix.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 { month_index + 3 } else { month_index - 9 };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60
    )
}

fn header<'a>(request: &'a RawRequest, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(present, _)| present.eq_ignore_ascii_case(name))
        .and_then(|(_, value)| std::str::from_utf8(value).ok())
}

/// `request`, signed now with [`ACCESS_KEY`] under the payload mode its `x-amz-content-sha256`
/// names (unsigned when it names none and the request has a body, the empty payload's digest when
/// it has neither).
///
/// # Errors
///
/// A payload mode the replay cannot sign (chunk signatures, SigV4a), or a request head the signer
/// cannot canonicalise.
pub(crate) fn signed(request: &RawRequest) -> Result<RawRequest, String> {
    let trailer = match header(request, "x-amz-trailer") {
        Some(names) => {
            let names = names
                .split(',')
                .map(|name| TrailerName::new(name.trim()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("x-amz-trailer: {error:?}"))?;
            TrailerSet::Declared(DeclaredTrailers::new(names, false).map_err(|error| format!("x-amz-trailer: {error:?}"))?)
        }
        None => TrailerSet::None,
    };
    let has_body = request.body.iter().any(|piece| !piece.is_empty());
    let payload = match header(request, "x-amz-content-sha256") {
        Some(value) => PayloadMode::parse(value, trailer).map_err(|error| format!("x-amz-content-sha256: {error:?}"))?,
        None if has_body => PayloadMode::Unsigned,
        // SDKs sign a bodiless request with the empty payload's digest, and s3s requires the header.
        None => {
            PayloadMode::parse(EMPTY_PAYLOAD_SHA256_HEX, TrailerSet::None).map_err(|error| format!("empty payload: {error:?}"))?
        }
    };
    if matches!(payload, PayloadMode::StreamingSigned { .. }) {
        return Err("chunk signatures cannot be signed again without re-framing the body".to_owned());
    }

    // The signer sets the headers it mints (`authorization`, `x-amz-date`, `x-amz-content-sha256`),
    // replacing a recorded copy, so each is sent once with the replay's value.
    let mut headers = HeaderMap::new();
    for (name, value) in &request.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| format!("header {name:?}: {error}"))?;
        let value = HeaderValue::from_bytes(value).map_err(|error| format!("header {name} value: {error}"))?;
        headers.append(name, value);
    }
    if !headers.contains_key(http::header::HOST) {
        headers.insert(http::header::HOST, HeaderValue::from_static(DEFAULT_HOST));
    }
    let host_bytes = headers.get(http::header::HOST).map(HeaderValue::as_bytes).unwrap_or_default();
    let raw_host = RawHost::from_host_header(host_bytes).map_err(|error| format!("host: {error:?}"))?;

    let stamp = AmzDate::parse(&amz_date(RequestNow::capture().unix_seconds())).map_err(|error| format!("stamp: {error:?}"))?;
    let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).map_err(|error| format!("scope: {error:?}"))?;
    let credentials =
        SigningCredentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credentials: {error:?}"))?;
    let mut signer = SigV4Signer::new(credentials, scope);

    let (path, query) = request.target.split_once('?').unwrap_or((request.target.as_str(), ""));
    let mut signing = SigningRequest::new(&request.method, path, query, &headers, &raw_host, payload.clone(), stamp);
    if let Some(length) = header(request, "content-length").and_then(|length| length.trim().parse::<u64>().ok()) {
        signing = signing.with_wire_content_length(length);
    }
    if payload.requires_decoded_length() {
        let decoded = header(request, "x-amz-decoded-content-length")
            .and_then(|length| length.trim().parse::<u64>().ok())
            .ok_or("a streaming payload without x-amz-decoded-content-length")?;
        signing = signing.with_decoded_content_length(decoded);
    }
    let signed = signer.sign_headers(&signing).map_err(|error| format!("signing: {error:?}"))?;

    let mut out = RawRequest {
        headers: Vec::new(),
        ..request.clone()
    };
    for (name, value) in signed.headers() {
        out.headers.push((name.as_str().to_owned(), value.as_bytes().to_vec()));
    }
    Ok(out)
}
