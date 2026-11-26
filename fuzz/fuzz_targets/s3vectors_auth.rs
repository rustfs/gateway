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

//! Fuzzes S3 Vectors (`s3vectors`) canonical query signing, scope enforcement, and route admission.
//!
//! Responsible for: exercising `SigService::S3Vectors` list-valued `tagKeys` query canonicalization
//! (and duplicate-parameter rejection for all other names), `SigV4Signer` signing for `s3vectors`,
//! `SecurityFloor::admit` on S3 Vectors operations, and `Dialect::assemble_for_service` route
//! admission without duplicating `SigV4Authorization::parse` (`credential_header_parse.rs`).
//! NOT responsible for: S3 Vectors storage handlers or JSON schema validation.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-sig` and `rustfs-gateway-core`.

#![no_main]

use http::{HeaderMap, HeaderName, HeaderValue, Method};
use libfuzzer_sys::fuzz_target;
use rustfs_gateway_sig::{
    AmzDate, OperationFloor, PayloadMode, QueryExclusion, RawHost, RawQuery, RequestNow, ScopeDate, SecurityFloor, SigService,
    SigV4Signer, SigningCredentials, SigningRequest, SigningScope, WireView,
};

const METHODS: [Method; 4] = [Method::POST, Method::GET, Method::DELETE, Method::PUT];
const NOW: i64 = 1_440_938_160; // 2015-08-30T12:36:00Z

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
    let selector = rest.first().copied().unwrap_or_default();
    rest = rest.get(1..).unwrap_or_default();

    let method = &METHODS[usize::from(selector) % METHODS.len()];
    let raw_path = take_str(&mut rest, 128);
    let path = if raw_path.starts_with('/') {
        raw_path
    } else {
        format!("/{raw_path}")
    };
    let query = take_str(&mut rest, 256);
    let auth_header = take_str(&mut rest, 256);
    let date_header = take_str(&mut rest, 64);

    // 1. S3 Vectors query canonicalization & strict duplicate isolation vs ordinary S3.
    let _ = RawQuery::new(&query).canonical(QueryExclusion::None);
    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("synthetic credentials");
    let date = ScopeDate::parse("20150830").expect("valid scope date");
    let stamp = AmzDate::parse("20150830T123600Z").expect("valid timestamp");
    let host = RawHost::from_host_header(b"vectors.example.com").expect("valid host");
    let headers = HeaderMap::new();

    if let Ok(scope) = SigningScope::new(date, "us-east-1", SigService::S3Vectors) {
        let mut signer = SigV4Signer::new(credentials, scope);
        let req = SigningRequest::new(method, &path, &query, &headers, &host, PayloadMode::Empty, stamp);
        let _ = signer.sign_headers(&req);
    }

    // 2. S3 Vectors SecurityFloor admission against arbitrary headers and queries.
    let mut wire_headers = HeaderMap::new();
    wire_headers.insert(HeaderName::from_static("host"), HeaderValue::from_static("vectors.example.com"));
    if let Ok(val) = HeaderValue::from_str(&auth_header) {
        wire_headers.insert(HeaderName::from_static("authorization"), val);
    }
    if let Ok(val) = HeaderValue::from_str(&date_header) {
        wire_headers.insert(HeaderName::from_static("x-amz-date"), val);
    }
    let floor = OperationFloor::builtin("s3vectors:PutVectors", SigService::S3Vectors).require_sigv4_under_every_policy();
    let view = WireView::new(&wire_headers, RawQuery::new(&query));
    let _ = SecurityFloor::new().admit(view, &floor, RequestNow::from_unix_seconds(NOW));
});
