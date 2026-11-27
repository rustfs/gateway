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

//! Fuzzes `rustfs-gateway-sig` query bearer claims, host header-token claims, and STS form-body signing.
//!
//! Responsible for: exercising `QueryBearerClaim` path binding and query stripping, `HeaderTokenClaim`
//! alias rejection and `SecurityFloor::admit`, and `SigService::Sts` form-body signing invariants
//! without duplicating `SigV4Authorization::parse` (`credential_header_parse.rs`).
//! NOT responsible for: SigV4 authorization-header grammar (`credential_header_parse.rs`) or SigV2
//! (`sigv2_parse.rs`).
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-sig`.

#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use libfuzzer_sys::fuzz_target;
use rustfs_gateway_sig::{
    Admission, AmzDate, HeaderTokenClaim, OperationFloor, PayloadMode, QueryBearerClaim, RawHost, RawQuery, RequestNow,
    ScopeDate, SecurityFloor, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope, WireView,
};

const NOW: i64 = 1_767_225_600;
const BEARER_CLAIM: QueryBearerClaim = QueryBearerClaim::new("token", ".zip");
const TOKEN_ALIASES: &[&str] = &["x-subject-token", "x-storage-token"];

fn take_str(input: &mut &[u8], max_len: usize) -> String {
    let Some((&len, rest)) = input.split_first() else {
        return String::new();
    };
    let n = usize::from(len).min(max_len).min(rest.len());
    let (head, tail) = rest.split_at(n);
    *input = tail;
    String::from_utf8_lossy(head).into_owned()
}

fuzz_target!(|input: &[u8]| {
    let mut rest = input;
    let flags = rest.first().copied().unwrap_or_default();
    rest = rest.get(1..).unwrap_or_default();

    let raw_path = take_str(&mut rest, 128);
    let raw_query = take_str(&mut rest, 256);
    let token_val = take_str(&mut rest, 128);
    let alias_val = take_str(&mut rest, 128);
    let auth_val = take_str(&mut rest, 256);

    // 1. QueryBearerClaim path binding, query stripping, and floor admission.
    let _ = BEARER_CLAIM.bound_resource(&raw_path);
    let stripped = BEARER_CLAIM.strip_from(&raw_query);
    assert!(
        !stripped.split('&').any(|pair| pair.split('=').next() == Some("token")),
        "strip_from must not leave bare token parameter behind"
    );

    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("host"), HeaderValue::from_static("s3.example.com"));
    if flags & 1 != 0
        && let Ok(val) = HeaderValue::from_str(&token_val)
    {
        headers.insert(HeaderName::from_static("x-auth-token"), val);
    }
    if flags & 2 != 0
        && let Ok(val) = HeaderValue::from_str(&alias_val)
    {
        headers.insert(HeaderName::from_static("x-subject-token"), val);
    }
    if flags & 4 != 0
        && let Ok(val) = HeaderValue::from_str(&auth_val)
    {
        headers.insert(HeaderName::from_static("authorization"), val);
    }

    let now = RequestNow::from_unix_seconds(NOW);
    let view = WireView::new(&headers, RawQuery::new(&raw_query));
    let _ = BEARER_CLAIM.presented(&view);

    // 2. HeaderTokenClaim with alias refusal and SecurityFloor::admit invariants
    //    (ADR-0056 keeps token verification sealed inside rustfs-gateway).
    let claim = HeaderTokenClaim::new("x-auth-token")
        .expect("valid header name")
        .refusing_aliases(TOKEN_ALIASES)
        .expect("valid aliases");
    let _ = claim.presented(&headers);
    let token_floor = OperationFloor::builtin("GetObject", SigService::S3);
    let security_floor = SecurityFloor::new().with_header_token_claim(claim);
    let admitted = security_floor.admit(view, &token_floor, now);
    if headers.contains_key("x-subject-token") {
        assert!(
            !matches!(admitted, Ok(Admission::HeaderToken(_))),
            "refused alias must never be admitted as a header token"
        );
    }
    if matches!(admitted, Ok(Admission::HeaderToken(_))) {
        assert!(headers.contains_key("x-auth-token"), "header token admission requires the claimed header");
        assert!(
            !headers.contains_key("authorization"),
            "header token admission must not succeed alongside Authorization"
        );
    }

    // 3. STS form-body signing with SigService::Sts (both empty and hashed form-body modes).
    let form_body = take_str(&mut rest, 256);
    let mut digest = [0u8; 32];
    for (idx, byte) in form_body.bytes().enumerate() {
        digest[idx % 32] ^= byte.wrapping_add(idx as u8);
    }
    let creds = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("synthetic credentials");
    let scope = SigningScope::new(ScopeDate::parse("20260101").expect("valid date"), "us-east-1", SigService::Sts)
        .expect("valid STS scope");
    let mut signer = SigV4Signer::new(creds, scope);
    let host = RawHost::from_host_header(b"sts.example.com").expect("valid host");
    let mut sts_headers = HeaderMap::new();
    sts_headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    let stamp = AmzDate::parse("20260101T000000Z").expect("valid timestamp");
    let empty_req = SigningRequest::new(&Method::POST, "/", &raw_query, &sts_headers, &host, PayloadMode::Empty, stamp);
    let _ = signer.sign_headers(&empty_req);

    if let Ok(len_val) = HeaderValue::from_str(&form_body.len().to_string()) {
        sts_headers.insert(HeaderName::from_static("content-length"), len_val);
    }
    let hashed_req = SigningRequest::new(
        &Method::POST,
        "/",
        &raw_query,
        &sts_headers,
        &host,
        PayloadMode::ExactSha256(digest),
        stamp,
    );
    let _ = signer.sign_headers(&hashed_req);
});
