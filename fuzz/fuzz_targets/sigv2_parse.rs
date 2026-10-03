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

//! Exercises the SigV2 parsers with arbitrary UTF-8: the `Authorization: AWS` header, the
//! presigned `AWSAccessKeyId`/`Signature` pair and `Expires`, and the signed date spellings.
//! It does not verify a signature or read credentials.
//! Upstream: libFuzzer bytes, the first choosing the parser. Downstream: `rustfs-gateway-sig`'s
//! `sig_v2` parsers (rustfs/gateway#1223).

#![no_main]

use libfuzzer_sys::fuzz_target;
use rustfs_gateway_sig::RequestNow;
use rustfs_gateway_sig::sig_v2::{parse_authorization, parse_presigned_credential, parse_presigned_expires, parse_sigv2_date};

/// A fixed request time, so a verdict on `Expires` never depends on when the fuzzer ran.
const NOW: RequestNow = RequestNow::from_unix_seconds(1_767_323_045);

fuzz_target!(|input: &[u8]| {
    let Some((&selector, rest)) = input.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    match selector % 4 {
        0 => {
            let _ = parse_authorization(text);
        }
        1 => {
            let (access_key_id, signature) = text.split_once('\n').unwrap_or((text, ""));
            let _ = parse_presigned_credential(access_key_id, signature);
        }
        2 => {
            let _ = parse_presigned_expires(text, NOW);
        }
        _ => {
            let _ = parse_sigv2_date(text);
        }
    }
});
