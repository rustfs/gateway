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

//! The `?tagging` band, end to end: route, codec, fixture, response bytes.
//!
//! Responsible for: proving that the three tagging operations claim their own selector rather than
//! the plain object band's, and that the fixture answers them out of what the request that wrote the
//! tags actually sent. The positive case is the pair of exchanges `c-copy-0008` asserts, replayed
//! here through the same facade.
//! NOT responsible for: the corpus verdict. `crate::inprocess` now registers the whole tagging
//! family, so `c-copy-0008` and the `tagging/` domain run against the real assembly; what this
//! file keeps is the finer-grained view — fixture state inspected directly between exchanges,
//! which no corpus case can do. See `crates/conformance/MAP.md`.
//! Upstream: the published API of `rustfs_gateway` and `rustfs_gateway_conformance::fixture`.
//! Downstream: nothing.
//!
//! # Why this service is assembled by hand, and why it still signs
//!
//! The service is assembled here over the same [`Stub`] and the same credentials the corpus
//! transport uses — and every request is really signed, because every AWS operation ships with
//! `AllowedSchemes::HEADER_ONLY` and an unsigned one is refused by the floor before routing.
//! Nothing about the tagging band would be observable through a `403`.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};
use rustfs_gateway::{
    Credentials, FixedClock, Limits, RegionSet, S3Service, ServiceBuilder, SigV4Authenticator, StaticCredentials, WireRequest,
    allow_when, collect, dto,
};
use rustfs_gateway_conformance::exec::block_on;
use rustfs_gateway_conformance::fixture::{Fixture, StoredObject, Stub};
use rustfs_gateway_conformance::inprocess::{HOST, REGION, VALID_ACCESS_KEY, VALID_SECRET};

/// The instant every fixture below is pinned to, and the stamp its signatures carry.
///
/// `c-copy-0008` pins `2026-01-02T03:04:05Z`; the two spellings are the same instant, and the clock
/// the service is built with has to agree with the stamp or every exchange fails on skew.
const NOW: i64 = 1_767_322_845;
const NOW_STAMP: &str = "20260102T030405Z";

/// The bucket and the source key `c-copy-0008` declares in `[setup]`.
const BUCKET: &str = "conf-copy";
const SOURCE_KEY: &str = "src/plain.txt";
const DEST_KEY: &str = "dst/0008";

/// `Content-MD5` for a tagging document.
///
/// `PutObjectTagging` declares `http_checksum_required`, so a write with no integrity header is
/// refused before the decoder reads the body — which is a real property of the overlay and not a
/// hurdle these tests get to skip. The digest is computed rather than pinned so a test that changes
/// its document cannot leave a stale one behind.
fn content_md5(body: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digest = rustfs_gateway_conformance::md5::digest(body);
    let mut out = String::new();
    for chunk in digest.chunks(3) {
        let (a, b, c) = (chunk[0], chunk.get(1).copied(), chunk.get(2).copied());
        let packed = (u32::from(a) << 16) | (u32::from(b.unwrap_or(0)) << 8) | u32::from(c.unwrap_or(0));
        out.push(char::from(ALPHABET[(packed >> 18) as usize & 63]));
        out.push(char::from(ALPHABET[(packed >> 12) as usize & 63]));
        out.push(if b.is_some() {
            char::from(ALPHABET[(packed >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if c.is_some() {
            char::from(ALPHABET[packed as usize & 63])
        } else {
            '='
        });
    }
    out
}

/// One assembled service over one fixture, and the state behind it.
struct Harness {
    service: S3Service,
    state: Arc<Mutex<Fixture>>,
}

/// What one exchange observed: the status line and the whole body.
struct Answer {
    status: u16,
    body: String,
}

impl Answer {
    fn assert_contains(&self, needle: &str) {
        assert!(self.body.contains(needle), "the body does not contain {needle}: {}", self.body);
    }

    fn assert_lacks(&self, needle: &str) {
        assert!(!self.body.contains(needle), "the body contains {needle}: {}", self.body);
    }
}

impl Harness {
    /// The fixture `c-copy-0008` declares: one bucket, one source object with metadata and no tags.
    fn new() -> Harness {
        let mut fixture = Fixture::at(NOW);
        fixture.declare_bucket(BUCKET, false);
        let mut source = StoredObject::new(b"hello world".to_vec(), Some("text/plain".to_owned()), NOW);
        source.metadata.insert("origin".to_owned(), "source".to_owned());
        fixture.put_object(BUCKET, SOURCE_KEY, source);

        let state = Arc::new(Mutex::new(fixture));
        let backend = Arc::new(Stub::new(Arc::clone(&state)));
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new(VALID_ACCESS_KEY, VALID_SECRET).expect("a valid key id")));
        let service = ServiceBuilder::new()
            .register::<dto::CopyObject, _>(Arc::clone(&backend))
            .register::<dto::DeleteObject, _>(Arc::clone(&backend))
            .register::<dto::DeleteObjectTagging, _>(Arc::clone(&backend))
            .register::<dto::GetObject, _>(Arc::clone(&backend))
            .register::<dto::GetObjectTagging, _>(Arc::clone(&backend))
            .register::<dto::PutObject, _>(Arc::clone(&backend))
            .register::<dto::PutObjectTagging, _>(Arc::clone(&backend))
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new([REGION]).expect("non-empty")))
            .authorizer(allow_when(|request| !request.is_anonymous()))
            .clock(FixedClock::at_unix_seconds(NOW))
            .build()
            .expect("the service assembles");
        Harness { service, state }
    }

    /// Signs one request and drains what came back.
    ///
    /// The signature is over the head this call is about to send, so a test that changes a header
    /// changes what was signed — there is no pre-signed template here that a new header could slip
    /// past.
    fn send(&self, method: &str, target: &str, headers: &[(&str, &str)], body: &'static [u8]) -> Answer {
        let (path, query) = target.split_once('?').map_or((target, ""), |(path, query)| (path, query));

        let mut map = http::HeaderMap::new();
        map.append(http::header::HOST, http::HeaderValue::from_static(HOST));
        for (name, value) in headers {
            let name: http::HeaderName = name.parse().expect("a header name");
            map.append(name, http::HeaderValue::from_str(value).expect("a header value"));
        }
        map.append("content-length", http::HeaderValue::from(body.len()));

        // The canonical request is defined over the host the acceptance layer settled on, and
        // `WireRequest` is the only way to obtain that spelling through the facade.
        let probe = http::Request::builder()
            .method("GET")
            .uri("/")
            .header("host", HOST)
            .body(Bytes::new())
            .expect("a well-formed probe");
        let accepted = WireRequest::accept(probe, &Limits::default()).expect("the probe host is acceptable");

        let credentials = SigningCredentials::new(VALID_ACCESS_KEY, VALID_SECRET).expect("valid signing credentials");
        let stamp = AmzDate::parse(NOW_STAMP).expect("a SigV4 stamp");
        let scope = SigningScope::new(stamp.day(), REGION, SigService::S3).expect("a well-formed scope");
        let payload = if body.is_empty() {
            PayloadMode::Empty
        } else {
            PayloadMode::ExactSha256(rustfs_gateway_conformance::sha256::digest(body))
        };
        let method_value = http::Method::from_bytes(method.as_bytes()).expect("a method");
        let signing = SigningRequest::new(&method_value, path, query, &map, accepted.host().raw_for_signing(), payload, stamp)
            .with_wire_content_length(body.len() as u64);
        let signed = SigV4Signer::new(credentials, scope)
            .sign_headers(&signing)
            .expect("the request signs");

        let mut builder = http::Request::builder().method(method).uri(target);
        for (name, value) in signed.headers() {
            builder = builder.header(name, value);
        }
        let request = builder.body(Bytes::from_static(body)).expect("a well-formed request");
        let response = block_on(self.service.call_bytes(request));
        let (parts, payload) = response.into_parts();
        let status = parts.status.as_u16();
        let drained = block_on(collect(http::Response::from_parts(parts, payload))).expect("the body drains");
        Answer {
            status,
            body: String::from_utf8_lossy(drained.body()).into_owned(),
        }
    }

    /// A tagging write, with the integrity header the operation requires.
    fn put_tags(&self, target: &str, body: &'static [u8]) -> Answer {
        let digest = content_md5(body);
        self.send("PUT", target, &[("content-md5", digest.as_str())], body)
    }

    /// The tag set the fixture is holding for a key, as pairs. Reads state, not the wire.
    fn stored_tags(&self, key: &str) -> Vec<(String, String)> {
        let fixture = self.state.lock().expect("the fixture is not poisoned");
        fixture
            .object(BUCKET, key)
            .map(|object| object.tags.clone())
            .unwrap_or_default()
    }
}

/// The two exchanges of `c-copy-0008`, replayed: a copy with `REPLACE` writes the tag set the
/// request sent, and the `?tagging` read-back answers with it rather than with the object.
#[test]
fn a_copy_replacing_the_tag_set_is_read_back_through_the_tagging_subresource() {
    let harness = Harness::new();
    let copied = harness.send(
        "PUT",
        "/conf-copy/dst/0008",
        &[
            ("x-amz-copy-source", "/conf-copy/src/plain.txt"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "a=1&b=2"),
        ],
        b"",
    );
    assert_eq!(copied.status, 200, "{}", copied.body);
    copied.assert_contains("<CopyObjectResult");

    let read_back = harness.send("GET", "/conf-copy/dst/0008?tagging", &[], b"");
    assert_eq!(read_back.status, 200, "{}", read_back.body);
    read_back.assert_contains("<Key>a</Key>");
    read_back.assert_contains("<Value>1</Value>");
    read_back.assert_contains("<Key>b</Key>");
    read_back.assert_contains("<Value>2</Value>");
    // The read must be the tag set and nothing else. Before the row existed this exact request was
    // answered by `GetObject`, so the object's bytes are the specific wrong answer to exclude.
    read_back.assert_lacks("hello world");
}

/// Negative — the read is not the object. Without a `?tagging` row `GetObject` claimed this request
/// and answered `200` with the body, which is the disclosure issue #16 records.
#[test]
fn n_a_tagging_read_does_not_answer_with_the_object() {
    let harness = Harness::new();
    let answer = harness.send("GET", "/conf-copy/src/plain.txt?tagging", &[], b"");
    assert_eq!(answer.status, 200, "{}", answer.body);
    answer.assert_lacks("hello world");
    answer.assert_contains("<Tagging");
    // No writer gave this object tags, so the set is empty rather than absent: an object with no
    // labels is a 200 with an empty TagSet, never a 404.
    answer.assert_lacks("<Tag>");
}

/// Negative — the write is not a write of the object. `PutObject`'s selector accepts this request,
/// and if it claimed it the `<Tagging>` document would replace the object's eleven bytes.
#[test]
fn n_a_tagging_write_does_not_replace_the_object() {
    let harness = Harness::new();
    let written = harness.put_tags(
        "/conf-copy/src/plain.txt?tagging",
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(written.status, 200, "{}", written.body);
    assert_eq!(harness.stored_tags(SOURCE_KEY), [("colour".to_owned(), "green".to_owned())]);

    let object = harness.send("GET", "/conf-copy/src/plain.txt", &[], b"");
    assert_eq!(object.status, 200, "{}", object.body);
    assert_eq!(object.body, "hello world", "the tagging document was stored as the object");
}

/// Negative — the delete is not a delete of the object. `DeleteObject` answers the same `204`, so
/// the status alone cannot tell the two apart; the object has to still be readable afterwards.
#[test]
fn n_a_tagging_delete_does_not_delete_the_object() {
    let harness = Harness::new();
    harness.put_tags(
        "/conf-copy/src/plain.txt?tagging",
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    let cleared = harness.send("DELETE", "/conf-copy/src/plain.txt?tagging", &[], b"");
    assert_eq!(cleared.status, 204, "{}", cleared.body);
    assert!(harness.stored_tags(SOURCE_KEY).is_empty());

    let object = harness.send("GET", "/conf-copy/src/plain.txt", &[], b"");
    assert_eq!(object.status, 200, "the object was deleted along with its tags: {}", object.body);
    assert_eq!(object.body, "hello world");
}

/// Negative — a copy carrying `?tagging` is a tagging write, not a copy. The row at 490 sits ahead
/// of `CopyObject` at 790 for this request: the other order would overwrite the destination from the
/// source and discard the document the request carried.
#[test]
fn n_a_copy_source_header_does_not_turn_a_tagging_write_into_a_copy() {
    let harness = Harness::new();
    const DOCUMENT: &[u8] = b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>";
    let digest = content_md5(DOCUMENT);
    let answer = harness.send(
        "PUT",
        "/conf-copy/dst/0008?tagging",
        &[
            ("x-amz-copy-source", "/conf-copy/src/plain.txt"),
            ("content-md5", digest.as_str()),
        ],
        DOCUMENT,
    );
    // The destination does not exist, so a tagging write is a `NoSuchKey` — and a copy would have
    // been a `200` that created it. The refusal is what proves which row claimed the request.
    assert_eq!(answer.status, 404, "{}", answer.body);
    answer.assert_contains("NoSuchKey");
    answer.assert_lacks("<CopyObjectResult");
}

/// Negative — the copy directive defaults to `COPY`, so a copy that names no directive inherits the
/// source's tags rather than reading `x-amz-tagging` off the request.
#[test]
fn n_a_copy_without_the_directive_does_not_read_the_requests_tag_set() {
    let harness = Harness::new();
    harness.put_tags(
        "/conf-copy/src/plain.txt?tagging",
        b"<Tagging><TagSet><Tag><Key>origin</Key><Value>source</Value></Tag></TagSet></Tagging>",
    );
    let copied = harness.send(
        "PUT",
        "/conf-copy/dst/0008",
        &[
            ("x-amz-copy-source", "/conf-copy/src/plain.txt"),
            ("x-amz-tagging", "a=1&b=2"),
        ],
        b"",
    );
    assert_eq!(copied.status, 200, "{}", copied.body);
    assert_eq!(
        harness.stored_tags(DEST_KEY),
        [("origin".to_owned(), "source".to_owned())],
        "the request's inline tag set was applied without a REPLACE directive"
    );
}

/// Negative — an `x-amz-tagging` header that repeats a key is refused, and nothing is written.
#[test]
fn n_a_duplicate_key_in_the_inline_tag_set_is_refused() {
    let harness = Harness::new();
    let answer = harness.send(
        "PUT",
        "/conf-copy/dst/0008",
        &[
            ("x-amz-copy-source", "/conf-copy/src/plain.txt"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "a=1&a=2"),
        ],
        b"",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidArgument");
    assert!(harness.stored_tags(DEST_KEY).is_empty(), "the destination was written anyway");
}

/// Negative — a truncated percent escape is refused rather than stored as the literal bytes, which
/// would leave a tag under a name no later request can spell.
#[test]
fn n_a_broken_escape_in_the_inline_tag_set_is_refused() {
    let harness = Harness::new();
    let answer = harness.send(
        "PUT",
        "/conf-copy/dst/0008",
        &[
            ("x-amz-copy-source", "/conf-copy/src/plain.txt"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "a=%2"),
        ],
        b"",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidArgument");
    assert!(harness.stored_tags(DEST_KEY).is_empty());
}

/// Negative — a `<Tagging>` document that repeats a key is refused, the XML twin of the header rule.
#[test]
fn n_a_duplicate_key_in_the_tagging_document_is_refused() {
    let harness = Harness::new();
    let answer = harness.put_tags(
        "/conf-copy/src/plain.txt?tagging",
        b"<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>a</Key><Value>2</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidTag");
    assert!(harness.stored_tags(SOURCE_KEY).is_empty());
}

/// Negative — a body rooted at the wrong element is refused by the generated decoder before the
/// handler runs, so the object keeps whatever tags it had.
#[test]
fn n_a_tagging_document_with_the_wrong_root_is_refused() {
    let harness = Harness::new();
    let answer = harness.put_tags(
        "/conf-copy/src/plain.txt?tagging",
        b"<TagSet><Tag><Key>a</Key><Value>1</Value></Tag></TagSet>",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("MalformedXML");
    assert!(harness.stored_tags(SOURCE_KEY).is_empty());
}

/// Negative — a tagging read that names a version is refused rather than answered with the current
/// version's tag set, which would be a wrong answer wearing a `200`.
#[test]
fn n_a_versioned_tagging_read_is_refused_rather_than_answered_from_the_newest_version() {
    let harness = Harness::new();
    let answer = harness.send("GET", "/conf-copy/src/plain.txt?tagging&versionId=null", &[], b"");
    assert_eq!(answer.status, 501, "{}", answer.body);
    answer.assert_contains("NotImplemented");
}

/// Negative — a tagging read of a key that is not there is a `NoSuchKey`, not an empty tag set.
#[test]
fn n_a_tagging_read_of_a_missing_key_is_not_an_empty_tag_set() {
    let harness = Harness::new();
    let answer = harness.send("GET", "/conf-copy/absent?tagging", &[], b"");
    assert_eq!(answer.status, 404, "{}", answer.body);
    answer.assert_contains("NoSuchKey");
}

/// Negative — a tagging write with no integrity header is refused before the document is read.
///
/// `http_checksum_required` is stated in `model/overlays/ops/object-acl.toml` because the pinned
/// model carries it under a trait lowering does not read. This is the assertion that says the
/// statement took effect: without it the requirement would be lost silently, which is the one
/// failure mode a declaration in an overlay has.
#[test]
fn n_a_tagging_write_without_an_integrity_header_is_refused() {
    let harness = Harness::new();
    let answer = harness.send(
        "PUT",
        "/conf-copy/src/plain.txt?tagging",
        &[],
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidRequest");
    assert!(harness.stored_tags(SOURCE_KEY).is_empty());
}

/// Negative — an empty tag key has no representation in the model's own type for it, so a header
/// spelling one is refused rather than stored under a name no later request can name.
#[test]
fn n_an_empty_tag_key_in_the_inline_tag_set_is_refused() {
    let harness = Harness::new();
    let answer = harness.send(
        "PUT",
        "/conf-copy/dst/0008",
        &[
            ("x-amz-copy-source", "/conf-copy/src/plain.txt"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "=1"),
        ],
        b"",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidTag");
    assert!(harness.stored_tags(DEST_KEY).is_empty());
}

/// Negative — a segment with no `=` is not half a tag. AWS answers one sentence for every malformed
/// spelling of this header, and the refusal has to be the same one.
#[test]
fn n_an_inline_tag_set_segment_without_a_separator_is_refused() {
    let harness = Harness::new();
    let answer = harness.send(
        "PUT",
        "/conf-copy/dst/0008",
        &[
            ("x-amz-copy-source", "/conf-copy/src/plain.txt"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "a"),
        ],
        b"",
    );
    assert_eq!(answer.status, 400, "{}", answer.body);
    answer.assert_contains("InvalidArgument");
    assert!(harness.stored_tags(DEST_KEY).is_empty());
}
