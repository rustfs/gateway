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

//! Chunk-seed extraction and ownership controls.
//!
//! Responsible for: preserving header/query extraction while requiring the seed to borrow the
//! exact wire run. NOT responsible for: accepting signatures or verifying chunk chains.
//! Upstream: the authenticated request head. Downstream: `ChunkIngest::prepare` and its signer.

use super::*;

fn assert_signature_is_borrowed(signature: impl AsRef<str>, wire_run: &str) {
    assert!(
        std::ptr::eq(signature.as_ref().as_ptr(), wire_run.as_ptr()),
        "a chunk seed must borrow its exact wire run"
    );
}

/// Positive — the header form is read, and only the hex run is taken. The signature is the
/// last element of the header, but a parser that took the rest of the string would break the
/// moment a client appended anything.
#[test]
fn the_header_signature_is_read_as_hex_and_stops_at_the_hex() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static(
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host, Signature=abcdef0123456789, Extra=1",
        ),
    );
    let signature = presented_signature_hex(&headers, "");
    assert_eq!(signature, Some("abcdef0123456789"));
    let wire = headers
        .get(http::header::AUTHORIZATION)
        .expect("the fixture has an Authorization header")
        .to_str()
        .expect("an ASCII header");
    let run = wire.split_once("Signature=").expect("the fixture has a signature").1;
    assert_signature_is_borrowed(signature.expect("the signature exists"), run);
}

/// Negative — a header with no signature element yields nothing rather than a guess. The
/// caller refuses on `None`; a parser that returned an empty string here would build a signer
/// seeded with nothing.
#[test]
fn a_header_without_a_signature_element_yields_nothing() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("AWS4-HMAC-SHA256 Credential=AKID/x, SignedHeaders=host"),
    );
    assert_eq!(presented_signature_hex(&headers, ""), None);
    assert_eq!(presented_signature_hex(&HeaderMap::new(), ""), None);
}

/// Negative — `Signature=` with nothing usable after it is nothing, not the empty seed.
#[test]
fn an_empty_signature_element_is_not_a_seed() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("AWS4-HMAC-SHA256 Signature=, SignedHeaders=host"),
    );
    assert_eq!(presented_signature_hex(&headers, ""), None);
}

/// Positive — the presigned form is read from the query when the header carries nothing.
#[test]
fn the_presigned_signature_is_read_from_the_query() {
    let query = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=deadbeef&X-Amz-Expires=60";
    let headers = HeaderMap::new();
    let signature = presented_signature_hex(&headers, query);
    assert_eq!(signature, Some("deadbeef"));
    let run = query.split_once("X-Amz-Signature=").expect("the fixture has a signature").1;
    assert_signature_is_borrowed(signature.expect("the signature exists"), run);
}

/// Negative — a non-ASCII header is not a usable textual seed.
#[test]
fn a_non_ascii_header_is_not_a_seed() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_bytes(b"AWS4-HMAC-SHA256 Signature=\xff").expect("opaque header bytes"),
    );
    assert_eq!(presented_signature_hex(&headers, ""), None);
}

/// Negative — an ASCII non-hex prefix cannot become a seed.
#[test]
fn a_non_hex_signature_prefix_is_not_a_seed() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_static("AWS4-HMAC-SHA256 Signature=gabc"),
    );
    assert_eq!(presented_signature_hex(&headers, ""), None);
}

/// Negative — a malformed query pair is not silently skipped to invent a later seed.
#[test]
fn a_malformed_query_before_the_signature_yields_nothing() {
    let query = "malformed&X-Amz-Signature=deadbeef";
    assert_eq!(presented_signature_hex(&HeaderMap::new(), query), None);
}

/// Negative — a signature query name without its value separator remains unusable.
#[test]
fn a_signature_query_without_a_value_separator_yields_nothing() {
    assert_eq!(presented_signature_hex(&HeaderMap::new(), "X-Amz-Signature"), None);
}
