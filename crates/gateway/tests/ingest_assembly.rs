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

//! What the assembly does with a derived chunk-signing key, as opposed to what a cache would.
//!
//! Responsible for: the one property `c-ing-0003` is actually about — that the number of signing
//! keys a request derives does not grow with the number of chunks it sends — asserted on the
//! types the running service uses.
//! NOT responsible for: the HMAC arithmetic (`crates/http/tests/ingest_perf_gates.rs` counts it),
//! the derivation chain itself (`rustfs-gateway-sig` owns it), or the chunk chain
//! (`crates/http/tests/ingest_verify.rs`).
//! Upstream: `rustfs-gateway`'s public authenticator surface. Downstream: nothing.
//!
//! # Why this file exists at all
//!
//! `rustfs_gateway_http::SigningKeyCache` is the type the task specified, and it has a full gate
//! of its own — but the assembly does not use it. `SigV4Authenticator` derives `k_signing` once,
//! on the path that has already produced a signature match, and publishes it into a write-once
//! [`ChunkSink`]; the body reader collects it from there. So "one derivation per request" is a
//! property of the sink and of where the derivation sits, not of a cache, and a green cache test
//! is not evidence about the running service. This asserts it where it holds.
//!
//! 1 positive / 1 negative.

use rustfs_gateway::sig::SigningKey;
use rustfs_gateway::{ChunkSink, ChunkVerification};

/// The published AWS example scope. Nothing here authenticates anything: the key is a fixed
/// pattern and is never presented to a verifier.
const SCOPE: &str = "20130524/us-east-1/s3/aws4_request";
const AMZ_DATE: &str = "20130524T000000Z";

/// Material standing in for one identity's derived key.
fn material(byte: u8, scope: &str) -> ChunkVerification {
    ChunkVerification::new(SigningKey::from_array([byte; 32]), scope.to_owned(), AMZ_DATE.to_owned())
}

/// Positive — a request derives one key, and reading it once per chunk does not derive another.
///
/// The count that matters is not how many times the sink is read; it is how many keys exist to
/// be read. A `OnceLock` that has been set holds exactly one, so 81,920 chunk verifications
/// consume the same 32 bytes the four-step derivation produced once — which is the whole of the
/// 409,600-to-81,924 difference, expressed where the service actually lives.
#[test]
fn c_ing_0003_the_assembly_holds_one_derived_key_per_request_however_many_chunks_it_has() {
    let sink = ChunkSink::new();
    sink.publish(material(0x11, SCOPE));

    // One read per chunk of a 5 GiB upload in 64 KiB chunks would be 81,920; a thousand is enough
    // to show the answer does not depend on the count, and keeps the gate inside its budget.
    for _ in 0..1000 {
        let held = sink.get().expect("the authenticator published before the body was read");
        assert_eq!(held.scope_line(), SCOPE);
        assert_eq!(held.amz_date(), AMZ_DATE);
        assert!(held.chunk_signing_key().is_some(), "the published key is the 32 bytes SigV4 produces");
    }
}

/// Negative — a second publication never replaces the key the body is verified against.
///
/// This is the half that makes the sink a security boundary rather than a convenience. An
/// authenticator that published twice — a retry, a second scheme, an extension that ran after the
/// first — would otherwise be able to repoint a body already being read at another identity's
/// derived key, and the reader has no provenance to notice with. The second publication here
/// carries both a different key and a different date scope, so a sink that took it would be
/// visible in either field.
#[test]
fn c_ing_0003_a_second_publication_never_replaces_the_key_the_body_is_verified_against() {
    let sink = ChunkSink::new();
    sink.publish(material(0x11, SCOPE));
    sink.publish(material(0x22, "20240101/eu-west-1/s3/aws4_request"));

    let held = sink.get().expect("the first publication stands");
    assert_eq!(
        held.scope_line(),
        SCOPE,
        "the second publication must not repoint a body at another scope"
    );
    assert_eq!(held.amz_date(), AMZ_DATE);
}
