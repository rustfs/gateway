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

//! Whether an arbitrary tag set survives the trip out and back, on both scopes and one wire.
//!
//! Responsible for: the `decode ∘ encode` identity over the `Tagging` document — `GetObjectTagging`
//! and `GetBucketTagging` write one, `PutObjectTagging` and `PutBucketTagging` read one, and a
//! stored set has to come back the same tags in the same order — together with the wire shape that
//! identity is only worth anything against, and with the cross-scope claim that the four codecs
//! agree on a single document rather than on two that happen to round-trip separately.
//! NOT responsible for: the semantic rules (count ceilings, character set, duplicate keys), which
//! `tagging_contract.rs` owns over `ops::shared::tagging` and the `tagging/` corpus owns end to
//! end; the packed `x-amz-tagging` header, which is the other channel and has its own property;
//! and the bytes of any one fixed document, which the `tagging/` case goldens pin.
//! Upstream: the generated codecs for the four operations named above. Downstream: nothing.
//!
//! # Why the wrapper assertions point both ways here
//!
//! An identity is blind to anything both directions agree on: rustfs/gateway#206 found that an
//! encoder and a decoder which *both* invent a wrapper element round-trip perfectly while being
//! unreadable by every SDK. The sibling families answer that by naming the wrappers that must
//! never appear, because their lists are flattened. This family is the opposite case — `<TagSet>`
//! is the one wrapper on this wire and it is mandatory — so the shape claim has to say both
//! things: `<TagSet>` present, and no *second* wrapper invented around, inside or instead of it.
//!
//! # The empty document, and what it took to see it
//!
//! Until rustfs/backlog#1717 the encoder wrote `<Tagging><TagSet></TagSet></Tagging>` for an
//! untagged object — that is `q-tag-object-unconfigured-0090`, the answer `GetObjectTagging` owes —
//! and the decoder answered `MalformedXML` for exactly those bytes, because the generated reader
//! turned `smithy.api#required` on the list into "at least one entry". So the gateway emitted a
//! document it would not read, and no fixed case could see it: every case wrote a document it also
//! read, or read one it also wrote. The property is what crosses the two, and the empty tag set is
//! the value at the boundary, which is why it is a named test as well as a generated one.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::tagging::{TagScope, validate_tag_set};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// Both tagging writes are `httpChecksumRequired`, so every read fixture has to make an integrity
/// claim before the body is looked at. The claim's *value* is settled below this layer — the wire
/// layer verifies an `x-amz-checksum-*` against the octets it read, and `value::verify_body_digest`
/// settles a `Content-MD5` inside the decoder (`c-tagging-0026`) — and this fixture hands the
/// decoder an already-buffered body with no `Content-MD5`, so neither runs. That is deliberate:
/// what is under test here is the document, and a fixture that also had to carry a live digest
/// would have to recompute one per generated case for no assertion it makes.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The root element of this wire, which the model happens to name the same way.
const WIRE_ROOT: &str = "<Tagging";

/// The one wrapper this wire carries, and the reason the family has a `wire_form` quirk at all
/// (`q-tag-wrapped-0088`). The listing families flatten their collections; this one does not, and
/// an encoder that reused the flattened shape would drop the enclosing element and be read as a
/// document with no `TagSet` member at all.
const REQUIRED_WRAPPER: &str = "<TagSet>";

/// Every wrapper element name that must never appear on this wire.
///
/// `<Tag>` repeats directly inside `<TagSet>` and its two members repeat inside `<Tag>`; anything
/// enclosing either is invented. The list exists because an encoder and a decoder that both
/// invented the same wrapper would satisfy the identity below while shipping a document no SDK
/// reads — `member` is on it because that is the element name Smithy's default list serialisation
/// would have produced had the `xmlName` trait been dropped.
const FORBIDDEN_WRAPPERS: &[&str] = &["<Tags>", "<TagSets>", "<Keys>", "<Values>", "<member>", "<Entries>"];

fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

fn document_of(body: ResponseBody) -> String {
    match body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a tagging read is a document, never a stream"),
    }
}

/// Serialises the set the way `GetObjectTagging` answers a read.
fn encode_object_read(tags: Vec<dto::Tag>) -> String {
    let request = accepted("GET", "/photos/kitten.jpg?tagging", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::GetObjectTaggingOutput {
        tag_set: tags,
        version_id: None,
    };
    let response = dto::GetObjectTagging::encode(output, &view, 200).expect("a tag set always encodes");
    document_of(response.body)
}

/// Serialises the set the way `GetBucketTagging` answers a read.
fn encode_bucket_read(tags: Vec<dto::Tag>) -> String {
    let request = accepted("GET", "/photos?tagging", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketTaggingOutput { tag_set: tags };
    let response = dto::GetBucketTagging::encode(output, &view, 200).expect("a tag set always encodes");
    document_of(response.body)
}

/// Reads a document back the way `PutObjectTagging` reads a write.
fn decode_object_write(document: &str) -> Result<dto::Tagging, CodecError> {
    let request = accepted("PUT", "/photos/kitten.jpg?tagging", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutObjectTagging::decode(&view, body).map(|input| input.tagging)
}

/// Reads a document back the way `PutBucketTagging` reads a write.
fn decode_bucket_write(document: &str) -> Result<dto::Tagging, CodecError> {
    let request = accepted("PUT", "/photos?tagging", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketTagging::decode(&view, body).map(|input| input.tagging)
}

/// The comparable projection of a tag set. `Tag` carries no `PartialEq` — ADR-0004 keeps derived
/// equality off the DTOs — so equality is spelled here, over every member, in order. A member left
/// out of this tuple is a member the identity would stop covering.
type Projection = Vec<(String, String)>;

fn projection(tags: &[dto::Tag]) -> Projection {
    tags.iter()
        .map(|tag| (tag.key.as_str().to_owned(), tag.value.clone()))
        .collect()
}

fn tag(key: &str, value: &str) -> dto::Tag {
    dto::Tag {
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

/// Text drawn from the documented tag alphabet, plus the characters an XML writer has to escape.
///
/// `&` and `<` are outside what `validate_tag_set` accepts, so they never reach a stored set — but
/// they do reach this writer through `RestoreObject`'s copy of the same shape, and a writer that
/// dropped the escaping would produce a document its own reader could not parse. Generating them
/// here is how the identity covers the escaping rather than assuming it.
fn tag_text(min: usize, max: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(
        proptest::sample::select("abXY09 +-=._:/@\u{e9}&<>\"'".chars().collect::<Vec<char>>()),
        min..max,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// Sets of up to ten tags with distinct keys, values free to be empty.
///
/// Nothing is filtered out of the key alphabet, and that matters: until the `Tag.Key` member was
/// typed as a plain string this generator had to drop every key the *object-key* floor refuses —
/// `//x`, `../x` — because the decoder ran a path floor over what is a label. A generator that
/// skips the values its own decoder cannot read is a property that cannot see the asymmetry it
/// exists to find, so the narrowing came out with the defect.
fn tag_sets() -> impl Strategy<Value = Vec<dto::Tag>> {
    (
        proptest::collection::btree_set(tag_text(1, 12), 0..10),
        proptest::collection::vec(tag_text(0, 12), 10),
    )
        .prop_map(|(keys, values)| keys.into_iter().zip(values).map(|(k, v)| tag(&k, &v)).collect())
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the tags are, writing them and reading them back yields the same tags in the same
    /// order — on both scopes, out of one document that names this wire's root and carries exactly
    /// one wrapper.
    ///
    /// The halves are one test on purpose. Identity alone is satisfied by any encoder and decoder
    /// that agree with each other, including a pair that agrees on a shape no SDK reads; the root
    /// and wrapper assertions are what stop the property from being self-fulfilling. The
    /// cross-scope half is the third direction: the two reads and the two writes are four
    /// separately generated codecs over one shape, and a family that only checked object against
    /// object would let the bucket pair drift into its own private dialect.
    #[test]
    fn a_tag_set_survives_encode_then_decode_on_both_scopes(tags in tag_sets()) {
        let document = encode_object_read(tags.clone());

        prop_assert!(
            document.contains(WIRE_ROOT),
            "the written document does not open on the wire's root element: {}",
            document
        );
        prop_assert!(
            document.contains(REQUIRED_WRAPPER),
            "the written document drops the one wrapper this wire has, so every SDK reads no member at all: {}",
            document
        );
        for wrapper in FORBIDDEN_WRAPPERS {
            prop_assert!(
                !document.contains(wrapper),
                "the written document carries the invented wrapper {wrapper}: {document}"
            );
        }

        // The bucket read is a separately generated codec over the same shape. Byte equality is
        // the claim: two scopes, one document.
        let bucket_document = encode_bucket_read(tags.clone());
        prop_assert_eq!(
            bucket_document.as_str(),
            document.as_str(),
            "the two scopes write two different documents for one tag set"
        );

        let expected = projection(&tags);
        for (scope, decoded) in [
            ("object", decode_object_write(&document)),
            ("bucket", decode_bucket_write(&document)),
        ] {
            let decoded = decoded.map_err(|error| {
                TestCaseError::fail(format!("{scope}: a document this codec wrote is one it must read: {error:?}: {document}"))
            })?;
            prop_assert_eq!(projection(&decoded.tag_set), expected.clone(), "{}: {}", scope, document);
        }
    }
}

// ── the boundary the property brackets, named ────────────────────────────────────────────────

/// The empty tag set: the document `GetObjectTagging` owes an untagged object, read back.
///
/// This is the regression rustfs/backlog#1717 landed, kept as a named test because the generator
/// reaches an empty set only one draw in ten and a silent narrowing of `tag_sets` would take the
/// boundary away without failing anything.
#[test]
fn an_empty_tag_set_survives_the_round_trip() {
    let document = encode_object_read(Vec::new());
    assert!(document.contains(REQUIRED_WRAPPER), "{document}");
    let decoded = decode_object_write(&document).expect("the encoder's own empty document reads back");
    assert!(decoded.tag_set.is_empty(), "{document}");
    let decoded = decode_bucket_write(&document).expect("and reads back at the bucket scope too");
    assert!(decoded.tag_set.is_empty(), "{document}");
}

/// A tag with an empty value survives a read-modify-write.
///
/// rustfs/gateway#218 found the sibling shape in the lifecycle family: an empty legacy `<Prefix>`
/// was accepted on ingress and dropped on re-encode, so one read-modify-write cycle broke an
/// installed rule. `Value` is required in the model, so the writer emits `<Value></Value>` rather
/// than omitting it and the reader reads the empty text back as an empty string — but "required"
/// is what makes that true, and a member moved to the omit-when-empty writer would break it
/// silently. This pins it.
#[test]
fn a_tag_with_an_empty_value_survives_a_read_modify_write() {
    let original = vec![tag("flag", ""), tag("owner", "ops")];
    let document = encode_object_read(original.clone());
    assert!(document.contains("<Value></Value>"), "an empty value is written, not omitted: {document}");
    let decoded = decode_object_write(&document).expect("the empty value reads back");
    assert_eq!(projection(&decoded.tag_set), projection(&original));

    // The second cycle is the one that breaks in the shape #218 found: a document re-encoded from
    // what was decoded, rather than from what was written first.
    let again = encode_object_read(decoded.tag_set);
    assert_eq!(again, document, "a re-encode of what was read is not the document that was read");
}

/// Negative — a `<Tagging>` document with no `<TagSet>` member at all is still refused.
///
/// The ruling that made the *empty* wrapper legal must not have made the *absent* one legal: the
/// member is required, and `required` is exactly the claim that the element has to be there. A fix
/// that dropped the check instead of re-reading it would pass every other test in this file.
#[test]
fn n_a_document_without_the_wrapper_is_refused() {
    let error = decode_object_write("<Tagging></Tagging>").expect_err("an absent TagSet is a missing member");
    assert_eq!(error.code().as_str(), "MalformedXML", "{error:?}");
    let error = decode_bucket_write("<Tagging></Tagging>").expect_err("an absent TagSet is a missing member");
    assert_eq!(error.code().as_str(), "MalformedXML", "{error:?}");
}

/// Negative — a tag whose `<Value>` element is absent is not a tag with an empty value.
///
/// The distinction the previous test draws at the list level, drawn again one level down: an empty
/// element and a missing element are two documents, and only the second is a missing member.
#[test]
fn n_a_tag_without_a_value_element_is_refused() {
    let error = decode_object_write("<Tagging><TagSet><Tag><Key>k</Key></Tag></TagSet></Tagging>")
        .expect_err("an absent Value is a missing member");
    assert_eq!(error.code().as_str(), "MalformedXML", "{error:?}");
}

/// Negative — a wrapped `<Tag>` list hides every tag from the decoder.
///
/// The direction the identity cannot see on its own: if the encoder and the decoder both invented
/// `<Tags>` they would agree, so this asserts that the *decoder* reads a wrapped list as no tags
/// rather than as the tags it encloses. It is the reason [`FORBIDDEN_WRAPPERS`] is asserted against
/// the written bytes rather than trusted.
#[test]
fn n_a_second_wrapper_around_the_tags_hides_them() {
    let decoded = decode_object_write("<Tagging><TagSet><Tags><Tag><Key>k</Key><Value>v</Value></Tag></Tags></TagSet></Tagging>")
        .expect("the wrapper is present, so the member is present");
    assert!(decoded.tag_set.is_empty(), "an invented wrapper must hide the tags, not be seen through");
}

/// Negative — a set the writer produced is still a set the validator judges.
///
/// The codec answers syntax and `ops::shared::tagging::validate_tag_set` answers semantics, and the
/// property deliberately generates keys the validator refuses (`&`, `<`) so that the escaping is
/// covered. This is the seam that says the two layers are still separate: a document that
/// round-trips is not thereby a document that may be stored.
#[test]
fn n_a_document_that_round_trips_is_not_thereby_a_set_that_may_be_stored() {
    let document = encode_object_read(vec![tag("a<b", "v")]);
    let decoded = decode_object_write(&document).expect("the escaping survives the round trip");
    let pairs = projection(&decoded.tag_set);
    assert_eq!(pairs, vec![("a<b".to_owned(), "v".to_owned())]);
    validate_tag_set(&pairs, TagScope::Object).expect_err("the character set is the validator's rule, not the codec's");
}

/// A tag key that reads as a path traversal is a tag key, and survives the round trip.
///
/// The named half of the property, and the regression this file's generator was narrowed around.
/// `Tag.Key` targets `com.amazonaws.s3#ObjectKey` in the pinned model — AWS's own modelling
/// shortcut, since a tag key is not an object key — and `scalars.toml` turned that shape name into
/// the `ObjectKey` type, so the generated decoder ran `value::object_key` and with it
/// `floor_check_key`: the *path* floor that refuses a leading `//` as a UNC spelling and any `..`
/// segment as traversal. AWS's tag alphabet admits both `/` and `.`, so `..` and `//label` are tag
/// keys a client may legitimately send, and the encoder wrote them happily while the decoder
/// answered `400 InvalidArgument` to the document the encoder had just produced. The member is a
/// plain string now, and these three keys are the values that go red if it is ever typed back.
///
/// `..` is here by name because it is the exact value the lifecycle property shrank to; the sibling
/// test in `lifecycle_roundtrip.rs` pins it on the other family reached through the same shape.
#[test]
fn a_tag_key_that_looks_like_a_path_survives_the_round_trip() {
    for key in ["..", "//label", "../label"] {
        let original = vec![tag(key, "v")];
        let document = encode_object_read(original.clone());
        let decoded = decode_object_write(&document)
            .unwrap_or_else(|error| panic!("{key}: a document this codec wrote is one it must read: {error:?}: {document}"));
        assert_eq!(projection(&decoded.tag_set), projection(&original), "{key}: {document}");
    }
}

/// Negative — repairing the key type did not loosen a member that really is an object key.
///
/// The fix moved one member off the `ObjectKey` type; the danger of that shape of change is that
/// it is applied one member too widely. `ObjectIdentifier.Key` in a `DeleteObjects` body *is* a
/// path, the traversal floor is what keeps `../victim/x` out of the storage layer, and this asserts
/// the floor still answers there. Without it, the whole repair could be re-done as "stop running
/// `floor_check_key` in the codec" and every other test in this file would stay green.
#[test]
fn n_a_traversal_key_in_a_delete_body_is_still_refused() {
    let request = accepted("POST", "/photos?delete", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::from_static(b"<Delete><Object><Key>../victim/x</Key></Object></Delete>"));
    let error = dto::DeleteObjects::decode(&view, body).expect_err("an object key is still a path");
    assert_eq!(error.code().as_str(), "InvalidArgument", "{error:?}");
}

/// Negative — a tag key the codec now carries is still a tag key the validator may refuse.
///
/// The seam [`n_a_document_that_round_trips_is_not_thereby_a_set_that_may_be_stored`] draws over
/// the character set, drawn again over the two rules the object-key type used to enforce by
/// accident: an empty key, and a key past the documented ceiling. Neither is the codec's business
/// any more, and neither may reach a stored set — so the ceiling has to be somewhere, and this
/// says where.
#[test]
fn n_an_empty_or_oversized_tag_key_is_refused_by_the_validator() {
    let document = encode_object_read(vec![tag("", "v")]);
    let decoded = decode_object_write(&document).expect("an empty key is text, and text round-trips");
    let pairs = projection(&decoded.tag_set);
    assert_eq!(pairs, vec![(String::new(), "v".to_owned())]);
    validate_tag_set(&pairs, TagScope::Object).expect_err("an empty tag key has no legal representation");

    let long = "k".repeat(129);
    let document = encode_object_read(vec![tag(&long, "v")]);
    let decoded = decode_object_write(&document).expect("an oversized key is text, and text round-trips");
    let pairs = projection(&decoded.tag_set);
    validate_tag_set(&pairs, TagScope::Object).expect_err("128 UTF-16 units is the validator's ceiling");
}
