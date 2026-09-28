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

//! Timing records for SigV4 header verification and per-chunk signing.
//!
//! Responsible for: rustfs/backlog#1766 `sig/v4_header_verify` — one full header-signature
//! verification (parse, skew, scope, signed-header set, canonical request, derived key, HMAC,
//! constant-time compare) through the crate's public verification primitives — and
//! `sig/chunk_signature`, one link of the `aws-chunked` chain over a 64 KiB chunk. Nothing here is
//! a time threshold, and allocation is not measured: this crate takes no allocator instrument, and
//! the verified request's allocations are gated end to end by the gateway's steady-state probe.
//! NOT responsible for: verification correctness, which `signer_tests` and the signing suite own.
//! Upstream: the public `rustfs-gateway-sig` API. Downstream: `perf-evidence.yml`.

use std::hint::black_box;
use std::time::Instant;

use http::{HeaderMap, Method};
use rustfs_gateway_sig::{
    AmzDate, CanonicalRequestSpec, ExpectedScope, PayloadMode, RawHost, RawQuery, RegionSet, RequestNow, ScopeDate, SecretBytes,
    SigService, SigV4Authorization, SigV4Signer, SignedHeaderSet, SignedRequest, SigningCredentials, SigningRequest,
    SigningScope, SkewWindow, TrailerSet, UriPathCandidates, calculate_signature, enforce_clock_skew, enforce_scope, signing_key,
};

const KEY: &[u8] = b"wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
const STAMP: &str = "20150830T123600Z";

fn host() -> RawHost {
    RawHost::from_host_header(b"example.amazonaws.com").expect("a valid host")
}

fn signer() -> SigV4Signer {
    let credentials = SigningCredentials::new("AKIDEXAMPLE", KEY).expect("valid credentials");
    let scope = SigningScope::new(ScopeDate::parse("20150830").expect("a day"), "us-east-1", SigService::S3).expect("a scope");
    SigV4Signer::new(credentials, scope)
}

/// One header-signature verification, the way the authenticator performs it.
fn verify(signed: &SignedRequest, secret: &SecretBytes, regions: &RegionSet, host: &RawHost) -> bool {
    let expected = ExpectedScope::new(SigService::S3, regions);
    let Some(header) = signed.authorization() else { return false };
    let Ok(auth) = SigV4Authorization::parse(header) else { return false };
    let Some(date) = signed
        .headers()
        .get("x-amz-date")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| AmzDate::parse(text).ok())
    else {
        return false;
    };
    let Ok(clock) = enforce_clock_skew(&date, RequestNow::from_unix_seconds(1_440_938_160), SkewWindow::DEFAULT) else {
        return false;
    };
    let Ok(verified) = enforce_scope(auth.scope(), clock, &expected) else { return false };
    let Ok(set) = SignedHeaderSet::parse_and_enforce(auth.signed_headers(), signed.headers(), None) else {
        return false;
    };
    let Ok(paths) = UriPathCandidates::new(signed.path()) else { return false };
    let raw_query = RawQuery::new(signed.query());
    let spec = CanonicalRequestSpec::new(
        signed.method(),
        &paths,
        &raw_query,
        signed.headers(),
        &set,
        host,
        PayloadMode::Unsigned.canonical_payload_token(),
    );
    let material = signing_key(secret, &verified);
    let Ok(candidates) = spec.candidates() else { return false };
    candidates.into_iter().any(|candidate| {
        let computed = calculate_signature(&material, &candidate.string_to_sign(&date, auth.scope()));
        auth.signature().ct_verify(&computed).is_ok()
    })
}

fn main() {
    let map = HeaderMap::new();
    let host = host();
    let stamp = AmzDate::parse(STAMP).expect("a stamp");
    let request = SigningRequest::new(&Method::GET, "/bucket/key", "", &map, &host, PayloadMode::Unsigned, stamp);
    let mut signer = signer();
    let signed = signer.sign_headers(&request).expect("signable");
    let secret = SecretBytes::new(KEY);
    let regions = RegionSet::new(["us-east-1"]).expect("a region set");
    assert!(verify(&signed, &secret, &regions, &host), "the fixture signature verifies");
    assert!(
        !verify(&signed, &SecretBytes::new(b"not-the-secret"), &regions, &host),
        "a wrong secret must not verify, or the timing below measures a verifier that accepts anything"
    );

    const VERIFIES: u32 = 20_000;
    let started = Instant::now();
    for _ in 0..VERIFIES {
        black_box(verify(black_box(&signed), &secret, &regions, &host));
    }
    let micros = started.elapsed().as_secs_f64() * 1_000_000.0 / f64::from(VERIFIES);
    println!("sig/v4_header_verify: {micros:.3} us/verification ({VERIFIES} iterations; record-only, non-blocking)");

    let streaming = PayloadMode::parse("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", TrailerSet::None).expect("a mode");
    let seed_request = SigningRequest::new(&Method::PUT, "/bucket/key", "", &map, &host, streaming, stamp)
        .with_decoded_content_length(64 * 1024 * 256);
    let seed = signer.sign_headers(&seed_request).expect("signable");
    let mut chain = signer.chunk_signer(&seed).expect("seedable");
    let chunk = vec![0x5a_u8; 64 * 1024];
    black_box(chain.sign_chunk(&chunk));
    const CHUNKS: u32 = 2_000;
    let started = Instant::now();
    for _ in 0..CHUNKS {
        black_box(chain.sign_chunk(black_box(&chunk)));
    }
    let seconds = started.elapsed().as_secs_f64();
    println!(
        "sig/chunk_signature: {:.3} us/64 KiB link, {:.2} GiB/s ({CHUNKS} links; record-only, non-blocking)",
        seconds * 1_000_000.0 / f64::from(CHUNKS),
        f64::from(CHUNKS) * 64.0 * 1024.0 / seconds / f64::from(1_u32 << 30)
    );
}
