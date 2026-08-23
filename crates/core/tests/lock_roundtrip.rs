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

//! Whether the object-lock family's three documents survive the trip out and back, and under
//! which root element each of them travels.
//!
//! Responsible for: the `decode ∘ encode` identity over `ObjectLockConfiguration`,
//! `ObjectLockRetention` and `ObjectLockLegalHold` — each is written by a `Get` and read by the
//! matching `Put`, and a stored WORM document has to come back saying the same thing — together
//! with the wire shape that identity is only worth anything against.
//! NOT responsible for: the semantic rules of `ops::shared::object_lock` — the closed `Mode`,
//! `Status` and `ObjectLockEnabled` sets, the `Days`/`Years` mutex and its floor, and the
//! future-only `RetainUntilDate` — all of which that module owns and its own tests pin. Nor
//! **enforcing** a lock, which the module docs there place on the storage side. Nor the bytes of
//! any one fixed document, which `c-lock-0005` and `c-lock-0006` pin.
//! Upstream: the generated codecs for the family's six operations, and `ops::shared::object_lock`.
//! Downstream: nothing.
//!
//! # Why the shape half of this property is about the ROOT and not about a wrapper
//!
//! Every sibling property in this workspace argues about list wrappers. This family has no list
//! at all — not one member of the three documents is a collection — so there is no wrapper to
//! get wrong. What it has instead is the workspace's only pair of **renamed roots**: the shape
//! `ObjectLockRetention` travels as `<Retention>` and `ObjectLockLegalHold` travels as
//! `<LegalHold>` (`q-lock-0004`, `q-lock-0005`). That is the same defect on a different element.
//! A codec pair keyed to the shape name round-trips perfectly and is refused by every real
//! client, and — because the shape name is what the Rust type is called — it is the mistake a
//! generator is most likely to make and a reader least likely to notice.
//!
//! So each property here asserts the root element by **name**, extracted from the document
//! rather than searched for, and asserts that the shape name does not appear as a root. Those
//! two are not the same claim: a writer emitting `<Retention>` inside an `<ObjectLockRetention>`
//! envelope would satisfy a `contains` and fail the extraction.
//!
//! # What these properties cannot see
//!
//! An identity is blind to anything both directions agree on: element order within a document,
//! and the `xmlns` on the root. Both are pinned by `c-lock-0005` and `c-lock-0006`, which is the
//! complementary guard — a case pins one document exactly, a property pins every document
//! approximately.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::object_lock::{
    ObjectLockRejection, validate_legal_hold, validate_lock_configuration, validate_retention,
};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::Timestamp;
use rustfs_gateway_types::dto;

/// All three writes are `httpChecksumRequired` (`q-lock-0006`), so every read fixture has to make
/// an integrity claim before the body is looked at. The claim's *value* is settled below this
/// layer, and these fixtures hand the decoder an already-buffered body, so neither the wire-layer
/// check nor `value::verify_body_digest` runs. That is deliberate: what is under test here is the
/// document.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The three root elements the wire actually uses. Two of them are not the shape's name.
const ROOT_CONFIGURATION: &str = "ObjectLockConfiguration";
const ROOT_RETENTION: &str = "Retention";
const ROOT_LEGAL_HOLD: &str = "LegalHold";

/// The shape names that must never reach the wire as a root. `q-lock-0004` and `q-lock-0005`
/// record that a decoder keyed to these would refuse every real client's document; the same is
/// true in reverse of an encoder that wrote them.
const SHAPE_NAMES_THAT_ARE_NOT_ROOTS: &[&str] = &["ObjectLockRetention", "ObjectLockLegalHold"];

/// Names no element of this family carries. `Rule` is singular in the model *and* on the wire, so
/// a pluralised wrapper is a name the writer invented; `Retentions` and `LegalHolds` are the same
/// mistake on the other two documents.
const FORBIDDEN_WRAPPERS: &[&str] = &["<Rules>", "<Retentions>", "<LegalHolds>", "<DefaultRetentions>"];

/// A fixed instant to validate against, so that no assertion in this file reads a wall clock.
/// 2026-01-01T00:00:00Z.
const NOW: i64 = 1_767_225_600;

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

fn body_of(response: rustfs_gateway_core::codec::response::EncodedResponse) -> String {
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// The root element's name, read out of the document rather than searched for.
///
/// A `contains("<Retention")` is satisfied by a `<Retention>` nested anywhere, including inside an
/// envelope no client expects. Naming the root is what makes the wire-shape half of these
/// properties an assertion about the document rather than about one of its substrings.
fn root_element(document: &str) -> String {
    let after_declaration = document.find("?>").map_or(0, |index| index + 2);
    let rest = &document[after_declaration..];
    let open = rest.find('<').expect("a document opens an element");
    rest[open + 1..]
        .split([' ', '>', '/', '\n', '\t'])
        .next()
        .expect("the root element has a name")
        .to_owned()
}

// ── the three codecs, each in both directions ────────────────────────────────────────────────

fn encode_configuration(configuration: dto::ObjectLockConfiguration) -> String {
    let request = accepted("GET", "/photos?object-lock", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetObjectLockConfigurationOutput {
        object_lock_configuration: Some(configuration),
    };
    body_of(dto::GetObjectLockConfiguration::encode(output, &view, 200).expect("a configuration always encodes"))
}

fn decode_configuration(document: &str) -> Result<dto::ObjectLockConfiguration, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?object-lock", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutObjectLockConfiguration::decode(&view, body).map(|input| input.object_lock_configuration)
}

fn encode_retention(retention: dto::ObjectLockRetention) -> String {
    let request = accepted("GET", "/photos/key?retention", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::GetObjectRetentionOutput {
        retention: Some(retention),
    };
    body_of(dto::GetObjectRetention::encode(output, &view, 200).expect("a retention always encodes"))
}

fn decode_retention(document: &str) -> Result<dto::ObjectLockRetention, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos/key?retention", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutObjectRetention::decode(&view, body).map(|input| input.retention)
}

fn encode_legal_hold(legal_hold: dto::ObjectLockLegalHold) -> String {
    let request = accepted("GET", "/photos/key?legal-hold", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let output = dto::GetObjectLegalHoldOutput {
        legal_hold: Some(legal_hold),
    };
    body_of(dto::GetObjectLegalHold::encode(output, &view, 200).expect("a legal hold always encodes"))
}

fn decode_legal_hold(document: &str) -> Result<dto::ObjectLockLegalHold, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos/key?legal-hold", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutObjectLegalHold::decode(&view, body).map(|input| input.legal_hold)
}

// ── the comparable projections ───────────────────────────────────────────────────────────────

/// The ACL and lifecycle DTOs carry no `PartialEq` — ADR-0004 keeps derived equality off the DTOs
/// — so equality is spelled here, over every member of each document, including the nanosecond
/// remainder of the timestamp. A member left out of a projection is a member the identity would
/// stop covering.
type ConfigurationProjection = (Option<String>, Option<(Option<String>, Option<i32>, Option<i32>)>);

fn configuration_projection(configuration: &dto::ObjectLockConfiguration) -> ConfigurationProjection {
    (
        configuration
            .object_lock_enabled
            .as_ref()
            .map(|enabled| enabled.as_str().to_owned()),
        configuration
            .rule
            .as_ref()
            .and_then(|rule| rule.default_retention.as_ref())
            .map(|default| (default.mode.as_ref().map(|mode| mode.as_str().to_owned()), default.days, default.years)),
    )
}

type RetentionProjection = (Option<String>, Option<(i64, u32)>);

fn retention_projection(retention: &dto::ObjectLockRetention) -> RetentionProjection {
    (
        retention.mode.as_ref().map(|mode| mode.as_str().to_owned()),
        retention
            .retain_until_date
            .as_ref()
            .map(|instant| (instant.secs(), instant.subsec_nanos())),
    )
}

fn legal_hold_projection(legal_hold: &dto::ObjectLockLegalHold) -> Option<String> {
    legal_hold.status.as_ref().map(|status| status.as_str().to_owned())
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// The two documented retention modes. Values outside the set are `object_lock.rs`'s to refuse,
/// and this file does not duplicate that; what it samples is what a stored document may say.
fn mode() -> impl Strategy<Value = dto::Mode> {
    prop_oneof![Just(dto::Mode::GOVERNANCE), Just(dto::Mode::COMPLIANCE)]
}

/// A retain-until instant.
///
/// **Nothing about the range is narrowed.** The seconds span both sides of the epoch and reach
/// past the year 9000, because a stored WORM document is re-read by every future release and a
/// renderer that overflowed at some year boundary would corrupt exactly the documents that are
/// meant to outlive everything else.
///
/// The sub-second remainder is deliberately confined to **whole milliseconds**, and that is the
/// one exclusion in this file. It is not narrowing around a defect: the ISO 8601 rendering S3
/// uses carries three fractional digits and nothing finer has a wire spelling, so a `Timestamp`
/// holding 1_500_000 nanoseconds is a value the format cannot represent rather than one it
/// represents wrongly. The exclusion is pinned by name, not assumed, in
/// [`n_a_retain_until_instant_finer_than_a_millisecond_is_truncated_on_the_way_out`], so the day
/// the format grows digits the pin goes red and this comment expires with it.
fn retain_until() -> impl Strategy<Value = Timestamp> {
    (-2_000_000_000i64..222_000_000_000i64, 0u32..1000)
        .prop_map(|(secs, millis)| Timestamp::from_secs_nanos(secs, millis * 1_000_000).expect("below one second"))
}

/// A retention document. Both members are optional in the model and `object_lock.rs` documents
/// that a document naming only one of them, or neither, passes on purpose — so all four
/// combinations are sampled, including the empty one.
fn retention() -> impl Strategy<Value = dto::ObjectLockRetention> {
    (prop::option::of(mode()), prop::option::of(retain_until()))
        .prop_map(|(mode, retain_until_date)| dto::ObjectLockRetention { mode, retain_until_date })
}

/// A legal hold. The set is closed at `ON`/`OFF` by `q-lock-0011`, and absent is legal.
fn legal_hold() -> impl Strategy<Value = dto::ObjectLockLegalHold> {
    prop::option::of(prop_oneof![Just(dto::Status::ON), Just(dto::Status::OFF)])
        .prop_map(|status| dto::ObjectLockLegalHold { status })
}

/// A bucket lock configuration.
///
/// `Days` and `Years` sample the **whole** of `i32`, negatives and both extremes included. That
/// is on purpose and it is the opposite of what the validator accepts: `object_lock.rs` refuses a
/// period below one, but the decoder is lenient by design (`q-lock-0014` and the module docs on
/// why a stored WORM document must not meet a stricter reader than the one that wrote it), so a
/// value it will not refuse is a value that has to survive. `i32::MIN` has no positive counterpart
/// and is exactly the sort of value a hand-rolled renderer loses.
fn lock_configuration() -> impl Strategy<Value = dto::ObjectLockConfiguration> {
    (
        prop::option::of(Just(dto::ObjectLockEnabled::ENABLED)),
        prop::option::of((prop::option::of(mode()), prop::option::of(any::<i32>()), prop::option::of(any::<i32>()))),
    )
        .prop_map(|(object_lock_enabled, default)| dto::ObjectLockConfiguration {
            object_lock_enabled,
            rule: default.map(|(mode, days, years)| dto::ObjectLockRule {
                default_retention: Some(dto::DefaultRetention { mode, days, years }),
            }),
        })
}

// ── the three properties ─────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the configuration says, writing it and reading it back yields the same document —
    /// and the document that carried it named `<ObjectLockConfiguration>` as its root and no
    /// wrapper the model invented.
    #[test]
    fn an_object_lock_configuration_survives_encode_then_decode(configuration in lock_configuration()) {
        let document = encode_configuration(configuration.clone());

        prop_assert_eq!(root_element(&document), ROOT_CONFIGURATION, "document: {}", document);
        for wrapper in FORBIDDEN_WRAPPERS {
            prop_assert!(!document.contains(wrapper), "the document carries {wrapper}: {document}");
        }

        let read_back = decode_configuration(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(
            configuration_projection(&read_back),
            configuration_projection(&configuration),
            "document: {}",
            document
        );
    }

    /// The same for a retention — and this is the family's sharp case, because the root the wire
    /// uses is **not** the shape's name. A codec pair keyed to `ObjectLockRetention` would satisfy
    /// the identity and be refused by every client that has ever read an S3 retention.
    #[test]
    fn a_retention_survives_encode_then_decode(retention in retention()) {
        let document = encode_retention(retention.clone());

        prop_assert_eq!(root_element(&document), ROOT_RETENTION, "document: {}", document);
        for shape_name in SHAPE_NAMES_THAT_ARE_NOT_ROOTS {
            prop_assert!(
                root_element(&document) != *shape_name,
                "the writer used the shape's name as the root, which q-lock-0004 records no client reading: {document}"
            );
        }
        for wrapper in FORBIDDEN_WRAPPERS {
            prop_assert!(!document.contains(wrapper), "the document carries {wrapper}: {document}");
        }

        let read_back = decode_retention(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(
            retention_projection(&read_back),
            retention_projection(&retention),
            "document: {}",
            document
        );
    }

    /// And the legal hold, whose root is renamed the same way (`q-lock-0005`).
    #[test]
    fn a_legal_hold_survives_encode_then_decode(legal_hold in legal_hold()) {
        let document = encode_legal_hold(legal_hold.clone());

        prop_assert_eq!(root_element(&document), ROOT_LEGAL_HOLD, "document: {}", document);
        for shape_name in SHAPE_NAMES_THAT_ARE_NOT_ROOTS {
            prop_assert!(
                root_element(&document) != *shape_name,
                "the writer used the shape's name as the root, which q-lock-0005 records no client reading: {document}"
            );
        }

        let read_back = decode_legal_hold(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(
            legal_hold_projection(&read_back),
            legal_hold_projection(&legal_hold),
            "document: {}",
            document
        );
    }
}

// ── the boundaries the properties reach only by luck ─────────────────────────────────────────

/// The two renamed roots, named one document at a time. The properties cover this, but a shrunk
/// counterexample would name a whole document; this names the rename, and it is the assertion
/// `q-lock-0004` and `q-lock-0005` exist for.
#[test]
fn the_two_renamed_roots_are_written_and_read_under_their_wire_names() {
    let retention = dto::ObjectLockRetention {
        mode: Some(dto::Mode::GOVERNANCE),
        retain_until_date: Some(Timestamp::from_secs(NOW + 86_400)),
    };
    let document = encode_retention(retention);
    assert_eq!(root_element(&document), "Retention", "{document}");
    assert!(!document.contains("ObjectLockRetention"), "{document}");

    let legal_hold = dto::ObjectLockLegalHold {
        status: Some(dto::Status::ON),
    };
    let document = encode_legal_hold(legal_hold);
    assert_eq!(root_element(&document), "LegalHold", "{document}");
    assert!(!document.contains("ObjectLockLegalHold"), "{document}");
}

/// A document a backend would actually store, taken through the pair a write performs: decode,
/// then the family's validator. A round trip that never validated would be comparing against a
/// document no write would ever have accepted.
#[test]
fn a_document_this_codec_wrote_is_one_the_family_accepts() {
    let configuration = dto::ObjectLockConfiguration {
        object_lock_enabled: Some(dto::ObjectLockEnabled::ENABLED),
        rule: Some(dto::ObjectLockRule {
            default_retention: Some(dto::DefaultRetention {
                mode: Some(dto::Mode::COMPLIANCE),
                days: Some(30),
                years: None,
            }),
        }),
    };
    let read_back = decode_configuration(&encode_configuration(configuration.clone())).expect("reads");
    assert_eq!(validate_lock_configuration(&read_back), Ok(()));
    assert_eq!(configuration_projection(&read_back), configuration_projection(&configuration));

    let retention = dto::ObjectLockRetention {
        mode: Some(dto::Mode::GOVERNANCE),
        retain_until_date: Some(Timestamp::from_secs(NOW + 86_400)),
    };
    let read_back = decode_retention(&encode_retention(retention.clone())).expect("reads");
    assert_eq!(validate_retention(&read_back, NOW), Ok(()));
    assert_eq!(retention_projection(&read_back), retention_projection(&retention));

    let hold = dto::ObjectLockLegalHold {
        status: Some(dto::Status::OFF),
    };
    let read_back = decode_legal_hold(&encode_legal_hold(hold.clone())).expect("reads");
    assert_eq!(validate_legal_hold(&read_back), Ok(()));
    assert_eq!(legal_hold_projection(&read_back), legal_hold_projection(&hold));
}

/// Reading is order-insensitive while writing is not. Element order inside a document is pinned
/// by `c-lock-0005`; a *sender* is under no such obligation.
#[test]
fn a_document_whose_members_arrive_in_another_order_is_the_same_document() {
    let canonical = "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00.000Z</RetainUntilDate></Retention>";
    let shuffled = "<Retention><RetainUntilDate>2030-01-01T00:00:00.000Z</RetainUntilDate><Mode>GOVERNANCE</Mode></Retention>";

    let first = decode_retention(canonical).expect("reads");
    let second = decode_retention(shuffled).expect("reads");

    assert_eq!(retention_projection(&second), retention_projection(&first));
}

/// The empty document of each kind. Every member of all three shapes is optional, so `<Retention/>`
/// is a legal thing to store, and it has to come back as itself rather than as a parse failure or
/// as a document that grew a default.
#[test]
fn an_empty_document_of_each_kind_comes_back_empty() {
    let retention = dto::ObjectLockRetention {
        mode: None,
        retain_until_date: None,
    };
    let read_back = decode_retention(&encode_retention(retention)).expect("an empty retention is still a retention");
    assert_eq!(retention_projection(&read_back), (None, None));

    let hold = dto::ObjectLockLegalHold { status: None };
    let read_back = decode_legal_hold(&encode_legal_hold(hold)).expect("an empty hold is still a hold");
    assert_eq!(legal_hold_projection(&read_back), None);

    let configuration = dto::ObjectLockConfiguration {
        object_lock_enabled: None,
        rule: None,
    };
    let read_back = decode_configuration(&encode_configuration(configuration)).expect("reads");
    assert_eq!(configuration_projection(&read_back), (None, None));
}

// ── negative: the shapes and values that must not be stored ──────────────────────────────────

/// The one exclusion the timestamp generator makes, pinned rather than assumed.
///
/// `Timestamp` carries nanoseconds; the ISO 8601 form S3 writes carries three fractional digits.
/// So an instant with a sub-millisecond remainder comes back **truncated toward the past** — for
/// a `RetainUntilDate` that is the safe direction only by accident, and it is a lossy round trip
/// either way. This is the reason `retain_until()` samples whole milliseconds, and this test is
/// what makes that exclusion visible instead of silent.
#[test]
fn n_a_retain_until_instant_finer_than_a_millisecond_is_truncated_on_the_way_out() {
    let precise = Timestamp::from_secs_nanos(1_893_456_000, 123_456_789).expect("below one second");
    let retention = dto::ObjectLockRetention {
        mode: None,
        retain_until_date: Some(precise),
    };

    let document = encode_retention(retention);
    assert!(document.contains(".123Z"), "the renderer carries three digits: {document}");

    let read_back = decode_retention(&document).expect("reads");

    assert_eq!(
        read_back.retain_until_date.map(|instant| instant.subsec_nanos()),
        Some(123_000_000),
        "the remainder below a millisecond is gone, and the identity does not hold for it"
    );
}

/// A document whose root is the *shape's* name rather than the wire's. This is the read side of
/// `q-lock-0004`: a decoder that accepted it would be one half of a pair that round-trips
/// perfectly and speaks to nobody, so the refusal is what keeps the writer honest.
#[test]
fn n_a_retention_under_its_shape_name_is_refused() {
    let document = "<ObjectLockRetention><Mode>GOVERNANCE</Mode></ObjectLockRetention>";

    let error = decode_retention(document).expect_err("the shape name is not the wire root");

    assert_eq!(error.member(), Some("Retention"), "{error:?}");
}

/// The same for the legal hold (`q-lock-0005`).
#[test]
fn n_a_legal_hold_under_its_shape_name_is_refused() {
    let document = "<ObjectLockLegalHold><Status>ON</Status></ObjectLockLegalHold>";

    let error = decode_legal_hold(document).expect_err("the shape name is not the wire root");

    assert_eq!(error.member(), Some("LegalHold"), "{error:?}");
}

/// The three roots are not interchangeable. A `<Retention>` sent to the legal-hold write and a
/// `<LegalHold>` sent to the retention write are each refused, which is what stops one document
/// being stored as another — the failure mode that matters here, because a retention read back as
/// a hold is a protection promise nothing enforces.
#[test]
fn n_one_documents_root_is_not_another_documents() {
    let retention_document = "<Retention><Mode>GOVERNANCE</Mode></Retention>";
    let hold_document = "<LegalHold><Status>ON</Status></LegalHold>";

    assert!(decode_legal_hold(retention_document).is_err(), "a retention is not a hold");
    assert!(decode_retention(hold_document).is_err(), "a hold is not a retention");
    assert!(decode_configuration(retention_document).is_err(), "and neither is a configuration");
}

/// A `Mode` outside the closed set survives the decoder and is refused by the validator. What
/// this adds to `object_lock.rs`'s own test is *which layer* produces the refusal: the decoder is
/// lenient on purpose, so a refactor moving the check into it would change what a stored document
/// means on the next release, and would have to move this assertion too.
#[test]
fn n_a_mode_outside_the_closed_set_survives_the_decoder_and_is_refused_after() {
    let document = "<Retention><Mode>governance</Mode></Retention>";

    let retention = decode_retention(document).expect("Mode is an open string enum on the wire");

    assert_eq!(
        retention.mode.as_ref().map(dto::Mode::as_str),
        Some("governance"),
        "the decoder is not the layer that closes the set"
    );
    assert_eq!(validate_retention(&retention, NOW), Err(ObjectLockRejection::ModeUnknown));
}

/// A legal-hold `Status` of `Enabled`. The generated `Status` enum is shared with the lifecycle
/// family, so `is_known()` accepts it; `object_lock.rs` closes the set at `ON`/`OFF` for exactly
/// that reason. The round trip is what proves the value reached the validator unchanged rather
/// than being normalised into something the check would have passed.
#[test]
fn n_a_legal_hold_status_from_the_shared_enum_is_carried_intact_and_refused() {
    let document = "<LegalHold><Status>Enabled</Status></LegalHold>";

    let hold = decode_legal_hold(document).expect("Status is an open string enum on the wire");

    assert_eq!(legal_hold_projection(&hold), Some("Enabled".to_owned()));
    assert_eq!(validate_legal_hold(&hold), Err(ObjectLockRejection::StatusUnknown));
}

/// An unreadable `RetainUntilDate` is refused by the **decoder**, not carried through as absent.
/// A timestamp that failed to parse and was dropped would store a retention with no expiry — a
/// document that says less than the client wrote and that no later read could tell from one that
/// never named a date.
#[test]
fn n_an_unreadable_retain_until_date_is_refused_rather_than_dropped() {
    let document = "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>tomorrow</RetainUntilDate></Retention>";

    let error = decode_retention(document).expect_err("an unparseable instant is not an absent one");

    assert_eq!(error.member(), Some("RetainUntilDate"), "{error:?}");
}

/// An empty body is refused rather than read as an empty document (`q-lock-0007`). The payload
/// member is promoted to required on all three writes, so "the client sent nothing" and "the
/// client sent an empty document" are different requests and must not collapse into one.
#[test]
fn n_an_empty_body_is_not_an_empty_document() {
    assert!(decode_retention("").is_err(), "an empty body is not a retention");
    assert!(decode_legal_hold("").is_err(), "nor a legal hold");
    assert!(decode_configuration("").is_err(), "nor a configuration");
}

/// A document nested inside an envelope. The root is the envelope, so the write is refused —
/// and this is the case that separates "the root element is `Retention`" from "a `<Retention>`
/// appears somewhere in the body". A decoder that searched instead of reading the root would
/// accept a document whose outermost element it never agreed to, and an encoder mirroring it
/// would produce one no client unwraps.
#[test]
fn n_a_retention_wrapped_in_an_envelope_is_not_a_retention() {
    let document = "<Envelope><Retention><Mode>GOVERNANCE</Mode></Retention></Envelope>";

    let error = decode_retention(document).expect_err("the envelope is the root, and it is not Retention");

    assert_eq!(error.member(), Some("Retention"), "{error:?}");
    assert_eq!(root_element(document), "Envelope", "and the helper agrees which element is the root");
}

/// A `Days` that is not a number is refused by the decoder rather than stored as absent or as a
/// zero. A default here would be a retention period the client never asked for, on the one family
/// where the stored number is the length of a legal obligation.
#[test]
fn n_a_days_value_that_is_not_a_number_is_refused() {
    let document = "<ObjectLockConfiguration><Rule><DefaultRetention><Mode>GOVERNANCE</Mode>\
                    <Days>thirty</Days></DefaultRetention></Rule></ObjectLockConfiguration>";

    let error = decode_configuration(document).expect_err("a period is a number or it is nothing");

    assert_eq!(error.member(), Some("Days"), "{error:?}");
}

/// An unknown element is skipped rather than refused (`q-lock-0014`), and — this is the half that
/// matters — it does not survive the round trip. A decoder that kept it could not, because the
/// DTO has nowhere to put it; the assertion is that the document that comes back is a truthful
/// report of what was stored rather than an echo of what was sent.
#[test]
fn n_an_unknown_element_is_skipped_and_does_not_come_back() {
    let document = "<Retention><Mode>GOVERNANCE</Mode><Governance>yes</Governance></Retention>";

    let retention = decode_retention(document).expect("an unknown element is skipped, not refused");
    let reserialised = encode_retention(retention);

    assert!(
        !reserialised.contains("<Governance>"),
        "the unknown element was echoed rather than dropped: {reserialised}"
    );
    assert_eq!(root_element(&reserialised), ROOT_RETENTION);
}
