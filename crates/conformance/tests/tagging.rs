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

/// The versioned bucket the `?tagging&versionId` tests work in, and the key that holds two versions.
///
/// A second bucket rather than a flag on the first: `Fixture::declare_bucket` decides whether a
/// write appends a version or replaces the single `null` one, and every test above this line asserts
/// on the replacing shape. Flipping the shared bucket would have rewritten what those tests measure.
const VERSIONED_BUCKET: &str = "conf-tagging-versions";
const VERSIONED_KEY: &str = "doc.txt";

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

/// What one exchange observed: the status line, the answered headers, and the whole body.
struct Answer {
    status: u16,
    headers: http::HeaderMap,
    body: String,
}

impl Answer {
    fn assert_contains(&self, needle: &str) {
        assert!(self.body.contains(needle), "the body does not contain {needle}: {}", self.body);
    }

    fn assert_lacks(&self, needle: &str) {
        assert!(!self.body.contains(needle), "the body contains {needle}: {}", self.body);
    }

    /// One answered header, as text. `None` for a header the answer did not carry.
    ///
    /// Absence is a value here rather than a panic: `x-amz-version-id` is *omitted* on an
    /// unversioned bucket, and a test that could not tell "absent" from "present and wrong" could
    /// not assert that omission at all.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
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
        Harness::over(fixture)
    }

    /// The same service over a versioned bucket holding two versions of one key.
    ///
    /// The two versions are written through [`Fixture::put_object`] rather than declared, because
    /// that is the only path that mints ids — and the ids are what the `?tagging&versionId` tests
    /// name. Neither version carries tags: every tag set below is written by the exchange under
    /// test, so a set a test observes is one a request in that test put there.
    fn versioned() -> Harness {
        let mut fixture = Fixture::at(NOW);
        fixture.declare_bucket(VERSIONED_BUCKET, true);
        fixture.put_object(
            VERSIONED_BUCKET,
            VERSIONED_KEY,
            StoredObject::new(b"first".to_vec(), Some("text/plain".to_owned()), NOW),
        );
        fixture.put_object(
            VERSIONED_BUCKET,
            VERSIONED_KEY,
            StoredObject::new(b"second".to_vec(), Some("text/plain".to_owned()), NOW),
        );
        Harness::over(fixture)
    }

    /// The assembled service, over whatever state the caller built.
    fn over(fixture: Fixture) -> Harness {
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
            .clock_with_skew_ack(
                FixedClock::at_unix_seconds(NOW),
                rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
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
        let headers = parts.headers.clone();
        let drained = block_on(collect(http::Response::from_parts(parts, payload))).expect("the body drains");
        Answer {
            status,
            headers,
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

    /// The tag set held on one *named version* of the versioned key. Reads state, not the wire.
    ///
    /// This is the observation no corpus case can make: a wire read of one version cannot tell a
    /// store that isolated the write from one that applied it everywhere and happened to be asked
    /// about the version it was meant for.
    fn stored_tags_of(&self, version_id: &str) -> Vec<(String, String)> {
        let fixture = self.state.lock().expect("the fixture is not poisoned");
        fixture
            .version(VERSIONED_BUCKET, VERSIONED_KEY, version_id)
            .and_then(|version| version.object.as_ref())
            .map(|object| object.tags.clone())
            .unwrap_or_default()
    }

    /// The ids of the two versions [`Harness::versioned`] wrote, oldest first.
    fn version_ids(&self) -> (String, String) {
        let fixture = self.state.lock().expect("the fixture is not poisoned");
        let mut ids: Vec<String> = fixture
            .versions_in(VERSIONED_BUCKET)
            .into_iter()
            .map(|entry| entry.version.version_id.clone())
            .collect();
        assert_eq!(ids.len(), 2, "the versioned fixture holds two versions");
        // `versions_in` answers newest first, and every test below names the older one first.
        ids.reverse();
        let newest = ids.pop().expect("two versions");
        let oldest = ids.pop().expect("two versions");
        (oldest, newest)
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

/// A tag set belongs to a version, not to a key: the write lands on the version the request named
/// and the version beside it keeps whatever it had.
///
/// Both directions are asserted on purpose. A store that ignored `versionId` and one that applied
/// the write to every version would each satisfy "the named version carries the new set" alone,
/// and the second assertion is the only one that separates them.
#[test]
fn a_tag_set_written_to_one_version_is_read_back_from_that_version_and_from_no_other() {
    let harness = Harness::versioned();
    let (oldest, newest) = harness.version_ids();

    let written = harness.put_tags(
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={oldest}"),
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(written.status, 200, "{}", written.body);
    assert_eq!(harness.stored_tags_of(&oldest), [("colour".to_owned(), "green".to_owned())]);
    assert!(
        harness.stored_tags_of(&newest).is_empty(),
        "the write landed on a version the request did not name"
    );

    let named = harness.send(
        "GET",
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={oldest}"),
        &[],
        b"",
    );
    assert_eq!(named.status, 200, "{}", named.body);
    named.assert_contains("<Key>colour</Key>");

    let other = harness.send(
        "GET",
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={newest}"),
        &[],
        b"",
    );
    assert_eq!(other.status, 200, "{}", other.body);
    other.assert_lacks("<Tag>");

    // No `versionId` selects the newest version, which is the one that was never tagged. A read
    // that answered the older version's set here would make the parameter's absence mean
    // "whichever version happens to have labels".
    let current = harness.send("GET", &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging"), &[], b"");
    assert_eq!(current.status, 200, "{}", current.body);
    current.assert_lacks("<Tag>");
}

/// Negative — a tagging delete that names a version clears that version's set and no other's.
#[test]
fn n_a_versioned_tagging_delete_does_not_clear_another_versions_tag_set() {
    let harness = Harness::versioned();
    let (oldest, newest) = harness.version_ids();
    for version in [&oldest, &newest] {
        let written = harness.put_tags(
            &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={version}"),
            b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
        );
        assert_eq!(written.status, 200, "{}", written.body);
    }

    let cleared = harness.send(
        "DELETE",
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={oldest}"),
        &[],
        b"",
    );
    assert_eq!(cleared.status, 204, "{}", cleared.body);
    assert!(harness.stored_tags_of(&oldest).is_empty());
    assert_eq!(
        harness.stored_tags_of(&newest),
        [("colour".to_owned(), "green".to_owned())],
        "the delete cleared a version the request did not name"
    );
}

/// Negative — a `versionId` this fixture never minted is `NoSuchVersion`, not the newest version's
/// tag set under a `200`. The wrong answer here is the dangerous one: a caller auditing the labels
/// of an archived version would be shown the current ones and told they were that version's.
#[test]
fn n_a_tagging_request_naming_an_unminted_version_is_not_answered_from_the_newest() {
    let harness = Harness::versioned();
    let (oldest, _) = harness.version_ids();
    let written = harness.put_tags(
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={oldest}"),
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(written.status, 200, "{}", written.body);

    let read = harness.send(
        "GET",
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId=conformance-version-9999"),
        &[],
        b"",
    );
    assert_eq!(read.status, 404, "{}", read.body);
    read.assert_contains("NoSuchVersion");
    read.assert_lacks("<Key>colour</Key>");

    let write = harness.put_tags(
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId=conformance-version-9999"),
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>red</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(write.status, 404, "{}", write.body);
    write.assert_contains("NoSuchVersion");
    assert_eq!(
        harness.stored_tags_of(&oldest),
        [("colour".to_owned(), "green".to_owned())],
        "a write against an unknown version was applied to a real one"
    );

    let delete = harness.send(
        "DELETE",
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId=conformance-version-9999"),
        &[],
        b"",
    );
    assert_eq!(delete.status, 404, "{}", delete.body);
    delete.assert_contains("NoSuchVersion");
    assert_eq!(
        harness.stored_tags_of(&oldest),
        [("colour".to_owned(), "green".to_owned())],
        "a delete against an unknown version cleared a real one"
    );
}

/// The unversioned bucket's own version has a spelling, and `versionId=null` names it.
///
/// S3 calls the version of an object in a bucket that was never versioned `null`, and a request
/// that spells it must be answered rather than refused — a client that read `x-amz-version-id` off
/// a listing and put it back on a tagging read gets exactly this request. The boundary companion is
/// the versioned bucket, where no null version was ever minted and the same spelling names nothing.
#[test]
fn n_the_null_version_names_the_only_version_of_an_unversioned_object_and_nothing_else() {
    let unversioned = Harness::new();
    let written = unversioned.put_tags(
        "/conf-copy/src/plain.txt?tagging&versionId=null",
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(written.status, 200, "{}", written.body);
    assert_eq!(unversioned.stored_tags(SOURCE_KEY), [("colour".to_owned(), "green".to_owned())]);
    let read = unversioned.send("GET", "/conf-copy/src/plain.txt?tagging&versionId=null", &[], b"");
    assert_eq!(read.status, 200, "{}", read.body);
    read.assert_contains("<Key>colour</Key>");
    // Naming the null version does not conjure a version id into the answer: the bucket has no
    // history, so there is still nothing for a client to come back for.
    assert_eq!(read.header("x-amz-version-id"), None);

    let versioned = Harness::versioned();
    let refused = versioned.send("GET", &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId=null"), &[], b"");
    assert_eq!(refused.status, 404, "{}", refused.body);
    refused.assert_contains("NoSuchVersion");
}

/// Negative — a version id is not a global handle. An id minted for one key names nothing under
/// another, and a lookup keyed on the id alone would answer one object's labels for a request that
/// named a different one.
#[test]
fn n_a_version_id_minted_for_one_key_is_not_a_version_of_another() {
    let harness = Harness::versioned();
    let (oldest, _) = harness.version_ids();
    let answer = harness.send("GET", &format!("/{VERSIONED_BUCKET}/other.txt?tagging&versionId={oldest}"), &[], b"");
    assert_eq!(answer.status, 404, "{}", answer.body);
    answer.assert_contains("NoSuchVersion");
}

/// Negative — a delete marker is a version with no representation, so it has no tag set to read or
/// to write. `NoSuchKey` would be the wrong refusal: the version is right there in the history.
#[test]
fn n_a_tagging_request_naming_a_delete_marker_is_refused_as_method_not_allowed() {
    let harness = Harness::versioned();
    let removed = harness.send("DELETE", &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}"), &[], b"");
    assert_eq!(removed.status, 204, "{}", removed.body);
    let marker = removed
        .header("x-amz-version-id")
        .expect("the delete named its marker")
        .to_owned();

    let read = harness.send(
        "GET",
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={marker}"),
        &[],
        b"",
    );
    assert_eq!(read.status, 405, "{}", read.body);
    read.assert_contains("MethodNotAllowed");

    let write = harness.put_tags(
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={marker}"),
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(write.status, 405, "{}", write.body);
    write.assert_contains("MethodNotAllowed");
}

/// The three tagging answers name the version they acted on, and only on a versioned bucket.
///
/// Without the header a client that wrote tags without naming a version cannot say which version
/// now carries them; with it on an *unversioned* bucket the client is told its object has a version
/// to come back for, and `null` is not a handle any later request may use.
#[test]
fn n_the_tagging_answers_do_not_report_a_version_on_an_unversioned_bucket() {
    let unversioned = Harness::new();
    let written = unversioned.put_tags(
        "/conf-copy/src/plain.txt?tagging",
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(written.status, 200, "{}", written.body);
    assert_eq!(written.header("x-amz-version-id"), None);
    let read = unversioned.send("GET", "/conf-copy/src/plain.txt?tagging", &[], b"");
    assert_eq!(read.header("x-amz-version-id"), None);
    let cleared = unversioned.send("DELETE", "/conf-copy/src/plain.txt?tagging", &[], b"");
    assert_eq!(cleared.header("x-amz-version-id"), None);

    let versioned = Harness::versioned();
    let (oldest, newest) = versioned.version_ids();
    let named = versioned.put_tags(
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={oldest}"),
        b"<Tagging><TagSet><Tag><Key>colour</Key><Value>green</Value></Tag></TagSet></Tagging>",
    );
    assert_eq!(named.header("x-amz-version-id"), Some(oldest.as_str()));
    let current = versioned.send("GET", &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging"), &[], b"");
    assert_eq!(current.header("x-amz-version-id"), Some(newest.as_str()));
    let cleared = versioned.send(
        "DELETE",
        &format!("/{VERSIONED_BUCKET}/{VERSIONED_KEY}?tagging&versionId={oldest}"),
        &[],
        b"",
    );
    assert_eq!(cleared.header("x-amz-version-id"), Some(oldest.as_str()));
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
