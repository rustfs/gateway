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

//! Every argument of the tagging contract, built out of a decoded request and nothing else.
//!
//! Responsible for: proving that a backend outside this workspace can *call*
//! [`parse_tagging_header`] and [`validate_tag_set`] — not that they are exported, which
//! `facade_probe.rs` already covers, but that their inputs are constructible from what a
//! request actually hands a handler on both channels the tag-set contract serves: the packed
//! `x-amz-tagging` header (`CreateMultipartUpload` here, standing in for the header channel it
//! shares with `PutObject` and `CopyObject`) and the `<Tagging>` document of the `?tagging`
//! subresource (`PutObjectTagging`, `PutBucketTagging`), under both scopes the shared validator
//! serves.
//! NOT responsible for: what the rules decide, which is `rustfs-gateway-core`'s
//! `ops/shared/tagging.rs` inline tests, or the wire shape of the XML document, which
//! `conformance/cases/tagging/` pins.
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Issue #15 found `evaluate_range` exported and uncallable, and left the rest of the exported
//! surface open with the acceptance bar: **every argument of every exported constructor must be
//! constructible from `Req<O>` alone.** The tagging contract was never checked against that bar.
//! `validate_tag_set` is called today only by the conformance fixture's own reference
//! implementation (`crates/conformance/src/fixture.rs`) — nothing in this workspace proves a
//! backend outside it can reach the same two functions from a decoded request, on both channels
//! and both scopes, rather than re-deriving the count ceilings and the duplicate-key rule by
//! hand the way the range mirror once did.

use md5::{Digest, Md5};
use rustfs_gateway::{
    Limits, MetaView, OperationCodec, RequestBody, TagScope, TargetKind, WireRequest, dto, parse_tagging_header, validate_tag_set,
};

/// `Content-MD5` of `body`, base64-encoded — the two XML-channel operations below declare
/// `httpChecksumRequired`, and unlike the `require_integrity` presence check, the decoder also
/// verifies a declared `Content-MD5` actually matches the buffered body (`BadDigest` otherwise).
/// This is test-data generation, not a cryptographic use, so a hand-rolled standard base64
/// encoder is used rather than adding a dependency for six lines.
pub(super) fn content_md5(body: &[u8]) -> String {
    let digest = Md5::digest(body);
    base64_standard(&digest)
}

/// A standard (RFC 4648, padded) base64 encoding of `bytes`.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let indices = [
            b0 >> 2,
            ((b0 & 0b0000_0011) << 4) | (b1 >> 4),
            ((b1 & 0b0000_1111) << 2) | (b2 >> 6),
            b2 & 0b0011_1111,
        ];
        for (position, index) in indices.iter().enumerate() {
            if position <= chunk.len() {
                out.push(ALPHABET[*index as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A request as it reaches a decoder, with whatever header lines the case needs.
pub(super) fn accepted(method: &'static str, uri: &'static str, headers: &[(&'static str, &'static str)]) -> WireRequest<()> {
    let mut request = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    for (name, value) in headers {
        request
            .headers_mut()
            .append(http::HeaderName::from_static(name), http::HeaderValue::from_static(value));
    }
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// What a backend has after decoding a `CreateMultipartUpload` carrying (or not) the packed
/// `x-amz-tagging` header — the header channel, with no body to buffer.
fn decoded_header_write(tagging: Option<&'static str>) -> dto::CreateMultipartUploadInput {
    let mut headers: Vec<(&'static str, &'static str)> = Vec::new();
    if let Some(value) = tagging {
        headers.push(("x-amz-tagging", value));
    }
    let request = accepted("POST", "http://host.invalid/conf-tagging/hello", &headers);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::CreateMultipartUpload::decode(&view, RequestBody::None).expect("a tagged multipart start is not a refusal")
}

/// What a backend has after decoding a `PutObjectTagging` write — the XML channel at object
/// scope.
fn decoded_object_document(pairs: &[(&str, &str)]) -> dto::PutObjectTaggingInput {
    let bytes = document(pairs).into_bytes();
    let digest = content_md5(&bytes);
    let request = accepted(
        "PUT",
        "http://host.invalid/conf-tagging/hello?tagging",
        &[
            ("content-type", "application/xml"),
            ("content-md5", Box::leak(digest.into_boxed_str())),
        ],
    );
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    let body = RequestBody::Buffered(bytes.into());
    dto::PutObjectTagging::decode(&view, body).expect("a well-formed object tagging write is not a refusal")
}

/// What a backend has after decoding a `PutBucketTagging` write — the XML channel at bucket
/// scope, where the count ceiling differs from the object scope above.
fn decoded_bucket_document(pairs: &[(&str, &str)]) -> dto::PutBucketTaggingInput {
    let bytes = document(pairs).into_bytes();
    let digest = content_md5(&bytes);
    let request = accepted(
        "PUT",
        "http://host.invalid/conf-tagging?tagging",
        &[
            ("content-type", "application/xml"),
            ("content-md5", Box::leak(digest.into_boxed_str())),
        ],
    );
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path has one label");
    let body = RequestBody::Buffered(bytes.into());
    dto::PutBucketTagging::decode(&view, body).expect("a well-formed bucket tagging write is not a refusal")
}

/// A `<Tagging>` document carrying exactly the pairs given, in order.
fn document(pairs: &[(&str, &str)]) -> String {
    let mut out = String::from("<Tagging><TagSet>");
    for (key, value) in pairs {
        out.push_str("<Tag><Key>");
        out.push_str(key);
        out.push_str("</Key><Value>");
        out.push_str(value);
        out.push_str("</Value></Tag>");
    }
    out.push_str("</TagSet></Tagging>");
    out
}

/// `n` numbered pairs, `("k0", "v0")` through `("k{n-1}", "v{n-1}")`.
fn numbered_pairs(n: usize) -> Vec<(String, String)> {
    (0..n).map(|i| (format!("k{i}"), format!("v{i}"))).collect()
}

fn as_str_pairs(owned: &[(String, String)]) -> Vec<(&str, &str)> {
    owned.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

/// The bridge a backend has to write itself for the XML channel: `dto::Tag`'s two `String`
/// fields, collected into the pairs [`validate_tag_set`] wants.
fn tag_pairs(document: &dto::Tagging) -> Vec<(String, String)> {
    document
        .tag_set
        .iter()
        .map(|tag| (tag.key.clone(), tag.value.clone()))
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Header channel: CreateMultipartUpload's packed `x-amz-tagging`
// ---------------------------------------------------------------------------------------------

/// Positive — a well-formed header reaches the handler and both pairs survive the bridge.
#[test]
fn a_well_formed_header_tag_set_on_a_write_reaches_the_handler() {
    let input = decoded_header_write(Some("project=alpha&owner=ops"));
    let pairs = parse_tagging_header(input.tagging.as_deref()).expect("two pairs, no escapes");
    validate_tag_set(&pairs, TagScope::Object).expect("two ordinary tags are under every ceiling");
    assert_eq!(
        pairs,
        vec![
            ("project".to_owned(), "alpha".to_owned()),
            ("owner".to_owned(), "ops".to_owned())
        ]
    );
}

/// Positive — a write that never mentioned the header decodes to `None`, and the header contract
/// answers an empty set rather than inventing one or refusing.
#[test]
fn an_absent_tagging_header_on_a_write_reaches_the_handler_as_no_tags() {
    let input = decoded_header_write(None);
    assert_eq!(input.tagging, None, "a header nobody sent must not arrive as a default");
    let pairs = parse_tagging_header(input.tagging.as_deref()).expect("absence is not malformed");
    assert!(pairs.is_empty());
    validate_tag_set(&pairs, TagScope::Object).expect("zero tags is under every ceiling");
}

/// Negative — a header segment with no `=` is refused, not silently dropped: the syntax rule is
/// reachable from the same wire string the passing case above used.
#[test]
fn n_a_malformed_header_pair_with_no_equals_is_refused() {
    let input = decoded_header_write(Some("not-a-pair"));
    let result = parse_tagging_header(input.tagging.as_deref());
    assert!(result.is_err(), "a segment without '=' is not a tag pair");
}

/// Negative — a repeated key in the header channel is refused before it ever reaches the shared
/// count ceiling: the header's own duplicate rule is reachable independently of
/// [`validate_tag_set`]'s.
#[test]
fn n_a_duplicate_key_in_the_header_channel_is_refused() {
    let input = decoded_header_write(Some("a=1&a=2"));
    let result = parse_tagging_header(input.tagging.as_deref());
    assert!(
        result.is_err(),
        "the same key appearing twice is a malformed header, not a last-write-wins pair"
    );
}

/// Negative — an empty key in the header channel is refused with `InvalidTag`, reached from the
/// same decoded string as every other header case.
#[test]
fn n_an_empty_key_in_the_header_channel_is_refused() {
    let input = decoded_header_write(Some("=value"));
    let result = parse_tagging_header(input.tagging.as_deref());
    assert!(
        result.is_err(),
        "a key with zero characters has no legal representation in either channel"
    );
}

/// Negative — the header channel's syntax is fine with eleven tags; it is
/// [`validate_tag_set`]'s object-scope ceiling that refuses the write one past the boundary the
/// positive case below sits on.
#[test]
fn n_an_object_tag_set_one_past_the_header_ceiling_is_refused() {
    let owned = numbered_pairs(11);
    let header = as_str_pairs(&owned)
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    let leaked: &'static str = Box::leak(header.into_boxed_str());
    let input = decoded_header_write(Some(leaked));
    let pairs = parse_tagging_header(input.tagging.as_deref()).expect("eleven well-formed pairs parse");
    let result = validate_tag_set(&pairs, TagScope::Object);
    assert!(result.is_err(), "eleven tags on an object is one past the documented ceiling of ten");
}

// ---------------------------------------------------------------------------------------------
// XML channel: PutObjectTagging (object scope) and PutBucketTagging (bucket scope)
// ---------------------------------------------------------------------------------------------

/// Positive — the object scope's own ceiling, ten tags, is accepted exactly at the boundary.
#[test]
fn an_object_tag_set_at_the_ten_tag_ceiling_is_accepted() {
    let owned = numbered_pairs(10);
    let input = decoded_object_document(&as_str_pairs(&owned));
    let pairs = tag_pairs(&input.tagging);
    assert_eq!(pairs.len(), 10);
    validate_tag_set(&pairs, TagScope::Object).expect("exactly ten tags on an object is the documented ceiling, not past it");
}

/// Positive — the bucket scope's ceiling, fifty tags, is accepted exactly at the boundary —
/// distinct from the object scope's ten, proving [`TagScope::Bucket`] is reachable and not just
/// declared.
#[test]
fn a_bucket_tag_set_at_the_fifty_tag_ceiling_is_accepted() {
    let owned = numbered_pairs(50);
    let input = decoded_bucket_document(&as_str_pairs(&owned));
    let pairs = tag_pairs(&input.tagging);
    assert_eq!(pairs.len(), 50);
    validate_tag_set(&pairs, TagScope::Bucket).expect("exactly fifty tags on a bucket is the documented ceiling, not past it");
}

/// Negative — one tag past the object ceiling is refused, reached from the XML channel rather
/// than the header channel `n_an_object_tag_set_one_past_the_header_ceiling_is_refused` already
/// covers — the two channels share the validator, not just the number.
#[test]
fn n_an_object_tag_set_one_past_the_ceiling_in_the_xml_channel_is_refused() {
    let owned = numbered_pairs(11);
    let input = decoded_object_document(&as_str_pairs(&owned));
    let pairs = tag_pairs(&input.tagging);
    let result = validate_tag_set(&pairs, TagScope::Object);
    assert!(result.is_err(), "eleven tags on an object is one past the documented ceiling of ten");
}

/// Negative — one tag past the bucket ceiling is refused, at the scope whose ceiling is fifty
/// rather than ten.
#[test]
fn n_a_bucket_tag_set_one_past_the_fifty_tag_ceiling_is_refused() {
    let owned = numbered_pairs(51);
    let input = decoded_bucket_document(&as_str_pairs(&owned));
    let pairs = tag_pairs(&input.tagging);
    let result = validate_tag_set(&pairs, TagScope::Bucket);
    assert!(result.is_err(), "fifty-one tags on a bucket is one past the documented ceiling of fifty");
}

/// Negative — a repeated key inside the `<Tagging>` document decodes without complaint (the
/// generated codec has no duplicate-key rule of its own) and is refused only once the shared
/// validator runs — proving the XML channel actually reaches the same duplicate-key rule the
/// header channel enforces at parse time.
#[test]
fn n_a_duplicate_key_in_the_xml_document_channel_is_refused() {
    let input = decoded_object_document(&[("project", "alpha"), ("project", "beta")]);
    let pairs = tag_pairs(&input.tagging);
    assert_eq!(pairs.len(), 2, "the codec decoded both tags; nothing collapsed them on the way in");
    let result = validate_tag_set(&pairs, TagScope::Object);
    assert!(result.is_err(), "the same key twice must be refused, not last-write-wins");
}

/// Negative — a key past the 128-UTF-16-unit ceiling is refused, reached only through the shared
/// validator: the generated codec places no length limit of its own on `<Key>`.
#[test]
fn n_a_tag_key_over_the_length_ceiling_in_the_xml_channel_is_refused() {
    let long_key = "a".repeat(129);
    let input = decoded_object_document(&[(long_key.as_str(), "value")]);
    let pairs = tag_pairs(&input.tagging);
    assert_eq!(pairs[0].0.chars().count(), 129);
    let result = validate_tag_set(&pairs, TagScope::Object);
    assert!(result.is_err(), "a 129-unit key is one past the documented 128-unit ceiling");
}
