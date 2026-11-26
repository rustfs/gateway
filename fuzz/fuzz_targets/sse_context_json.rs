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

//! Fuzzes `rustfs-gateway-core::sse` managed-channel encryption context JSON parsing and SSE-C
//! transport/key enforcement invariants.
//!
//! Responsible for: driving `crates/core/src/sse/context.rs` (`x-amz-server-side-encryption-context`
//! base64-encoded JSON string-pair validation) and SSE-C header parsing under plaintext and
//! encrypted transports, asserting plaintext customer-key refusal and non-echo of customer keys.
//! NOT responsible for: cryptographic key storage or S3 response filtering.
//! Upstream: libFuzzer bytes. Downstream: `rustfs-gateway-core::sse`.

#![no_main]

use http::{HeaderName, HeaderValue, Method, Request};
use libfuzzer_sys::fuzz_target;
use rustfs_gateway_core::codec::MetaView;
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_core::sse::{
    COPY_SSEC_ALGORITHM, COPY_SSEC_KEY, COPY_SSEC_KEY_MD5, SSE_ALGORITHM, SSE_BUCKET_KEY_ENABLED, SSE_CONTEXT, SSE_KMS_KEY_ID,
    SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5, SseConfig, TransportSecurity, enforce,
};
use rustfs_gateway_http::{Limits, WireRequest};

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(char::from(TABLE[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[((triple >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

fn take_slice<'a>(input: &mut &'a [u8], max_len: usize) -> &'a [u8] {
    let Some((&len, rest)) = input.split_first() else {
        return &[];
    };
    let n = usize::from(len).min(max_len).min(rest.len());
    let (head, tail) = rest.split_at(n);
    *input = tail;
    head
}

fuzz_target!(|input: &[u8]| {
    let mut rest = input;
    let mode = rest.first().copied().unwrap_or_default();
    rest = rest.get(1..).unwrap_or_default();

    let mut req = Request::builder()
        .method(Method::PUT)
        .uri("/bucket/key")
        .header("host", "s3.example.com")
        .body(())
        .expect("request builds");

    if mode & 1 == 0 {
        // Managed KMS channel: exercise base64 + JSON StringPairs parsing in sse/context.rs.
        req.headers_mut()
            .insert(HeaderName::from_static(SSE_ALGORITHM), HeaderValue::from_static("aws:kms"));
        let context_header = if mode & 2 == 0 {
            // Base64-wrap arbitrary JSON bytes so the fuzzer reaches context.rs directly.
            base64_encode(&rest[..rest.len().min(3072)])
        } else {
            // Also pass raw arbitrary bytes to fuzz base64 rejection and ceiling checks.
            String::from_utf8_lossy(&rest[..rest.len().min(3072)]).into_owned()
        };
        if let Ok(val) = HeaderValue::from_str(&context_header) {
            req.headers_mut().insert(HeaderName::from_static(SSE_CONTEXT), val);
        }
        if mode & 4 != 0 {
            req.headers_mut()
                .insert(HeaderName::from_static(SSE_KMS_KEY_ID), HeaderValue::from_static("alias/test"));
        }
        if mode & 8 != 0 {
            req.headers_mut().insert(
                HeaderName::from_static(SSE_BUCKET_KEY_ENABLED),
                HeaderValue::from_static(if mode & 16 == 0 { "true" } else { "bogus" }),
            );
        }
    } else {
        // Customer-key (SSE-C) channel: exercise plaintext refusal and non-echo invariants.
        let key_bytes = take_slice(&mut rest, 128);
        let md5_bytes = take_slice(&mut rest, 64);
        let alg_bytes = take_slice(&mut rest, 32);
        let (alg_hdr, key_hdr, md5_hdr) = if mode & 2 == 0 {
            (SSEC_ALGORITHM, SSEC_KEY, SSEC_KEY_MD5)
        } else {
            (COPY_SSEC_ALGORITHM, COPY_SSEC_KEY, COPY_SSEC_KEY_MD5)
        };
        if let Ok(v) = HeaderValue::from_bytes(alg_bytes) {
            req.headers_mut().insert(HeaderName::from_static(alg_hdr), v);
        }
        let sentinel_key = if mode & 4 == 0 {
            base64_encode(key_bytes)
        } else {
            "SENSITIVE_CUSTOMER_KEY_SENTINEL_1234567890==".to_owned()
        };
        if let Ok(v) = HeaderValue::from_str(&sentinel_key) {
            req.headers_mut().insert(HeaderName::from_static(key_hdr), v);
        }
        if let Ok(v) = HeaderValue::from_bytes(md5_bytes) {
            req.headers_mut().insert(HeaderName::from_static(md5_hdr), v);
        }
        if let Ok(wire) = WireRequest::accept(req, &Limits::default())
            && let Ok(meta) = MetaView::of(&wire, TargetKind::Object)
        {
            let plain = enforce(&meta, TransportSecurity::Plaintext, &SseConfig::strict());
            let err = match plain {
                Ok(_) => panic!("strict SSE config must always refuse customer keys over plaintext"),
                Err(err) => err,
            };
            let err_text = format!("{err:?}");
            assert!(
                !err_text.contains("SENSITIVE_CUSTOMER_KEY_SENTINEL_1234567890=="),
                "customer key leaked into SSE refusal diagnostics"
            );
            if let Err(err) = enforce(&meta, TransportSecurity::Encrypted, &SseConfig::strict()) {
                assert!(
                    !format!("{err:?}").contains("SENSITIVE_CUSTOMER_KEY_SENTINEL_1234567890=="),
                    "customer key leaked into encrypted SSE refusal diagnostics"
                );
            }
        }
        return;
    }

    if let Ok(wire) = WireRequest::accept(req, &Limits::default())
        && let Ok(meta) = MetaView::of(&wire, TargetKind::Object)
    {
        let _ = enforce(&meta, TransportSecurity::Encrypted, &SseConfig::strict());
    }
});
