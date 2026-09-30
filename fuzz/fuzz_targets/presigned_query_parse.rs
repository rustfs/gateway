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

//! Exercises presigned query parsing with arbitrary UTF-8 query strings: the five SigV4
//! `X-Amz-*` parameters under both empty-region rules, each parameter's percent-decoded value,
//! and percent decoding itself.
//! It does not verify a signature, check expiry, or read credentials.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-sig`'s `PresignedParams` and
//! `RawQuery` (rustfs/gateway#1223).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_sig::{
    EmptyRegion, PresignedParams, RawQuery, X_AMZ_ALGORITHM, X_AMZ_CREDENTIAL, X_AMZ_DATE, X_AMZ_SIGNATURE,
    X_AMZ_SIGNED_HEADERS, percent_decode,
};

fuzz_target!(|input: &[u8]| {
    let Ok(raw) = std::str::from_utf8(input) else {
        return;
    };
    let query = RawQuery::new(raw);
    let _ = PresignedParams::parse(&query);
    let _ = PresignedParams::parse_with(&query, EmptyRegion::Admitted);
    for name in [
        X_AMZ_ALGORITHM,
        X_AMZ_CREDENTIAL,
        X_AMZ_DATE,
        X_AMZ_SIGNED_HEADERS,
        X_AMZ_SIGNATURE,
        "X-Amz-Expires",
        "AWSAccessKeyId",
        "Signature",
        "Expires",
    ] {
        let _ = query.decoded_value(name);
    }
    let _ = percent_decode(raw);
});
