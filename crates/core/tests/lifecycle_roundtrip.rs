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

//! Whether an arbitrary lifecycle document survives the trip out and back, and on which wire.
//!
//! Responsible for: the `decode ∘ encode` identity over `BucketLifecycleConfiguration` —
//! `GetBucketLifecycleConfiguration` writes a document, `PutBucketLifecycleConfiguration` reads
//! one, and RustFS's write path is parse-then-reserialise, so a member this pair disagrees about
//! is not a rendering defect but a member that disappears from disk the first time an operator
//! touches the configuration — together with the wire shape that identity is only worth anything
//! against. An encoder and a decoder that both wrote `<Rules>` around the rule list, or both
//! named the root after the model's shape (`BucketLifecycleConfiguration`) instead of the wire's
//! (`LifecycleConfiguration`), would satisfy the identity perfectly and be unreadable by every
//! SDK; `q-lc-0002` and `q-lc-0003` are the two quirks that says so, and the assertions here are
//! what stop the property from being self-fulfilling.
//! NOT responsible for: the enumeration of every semantic rule — the filter's one-child grammar,
//! the expiration mutex, the midnight rule, the id caps — which
//! `ops::shared::lifecycle::validate_lifecycle` owns and the `lifecycle/` conformance cases pin
//! end to end; the bytes of any one fixed document, which the `lifecycle/` goldens pin; and the
//! dialect members this codec does not carry, which `c-lifecycle-0018` pins as this release's
//! honest lossy behaviour until ADR-0007's vtables reach production.
//! Upstream: the generated codecs for `GetBucketLifecycleConfiguration` and
//! `PutBucketLifecycleConfiguration`, and `ops::shared::lifecycle`. Downstream: nothing.
//!
//! # What this property cannot see
//!
//! An identity is blind to anything both directions agree on. Element *order* inside a rule is
//! the clearest instance: the reader is order-insensitive by design, so an encoder that emitted
//! `<Status>` first would round-trip perfectly here. That is caught in the corpus, by the goldens
//! of `c-lifecycle-0002` and its neighbours, and the two guards are complementary rather than
//! redundant — a golden pins one document exactly, a property pins every document approximately.
//!
//! # Why a property and not another table row
//!
//! The `lifecycle/` corpus pins particular documents. A table cannot say what happens to the
//! *combinations* it does not list — a `Transition` next to a `NoncurrentVersionTransition`, an
//! `<And>` whose tags carry characters XML has to escape, a rule scoped by the legacy top-level
//! `<Prefix>` sitting beside one scoped by a `<Filter>`, which `omit`-on-empty member disappears
//! when its neighbour is present. Each generated case here is a document nobody wrote by hand,
//! and the identity has to hold for all of them.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::lifecycle::{LifecycleRejection, MAX_LIFECYCLE_RULES, validate_lifecycle};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// `PutBucketLifecycleConfiguration` is `httpChecksumRequired`, so every read fixture has to make
/// an integrity claim before the body is looked at. The claim's *value* is settled below this
/// layer — `value::verify_body_digest` compares a `Content-MD5` against the octets the decoder
/// buffered (`c-lifecycle-0030`) — and this fixture hands the decoder an already-buffered body,
/// so that comparison never runs. That is deliberate: what is under test here is the document,
/// and a fixture that also had to carry a live digest would have to recompute one per generated
/// case for no assertion it makes.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The root element the wire uses, which is *not* the model's shape name.
///
/// A decoder keyed on the shape name refuses every document a real SDK produces, and an encoder
/// keyed on it produces documents no SDK reads. The pair would still round-trip.
const WIRE_ROOT: &str = "<LifecycleConfiguration";

/// The root element the model names and the wire must never carry (`q-lc-0002`).
const SHAPE_ROOT: &str = "<BucketLifecycleConfiguration";

/// Every wrapper element name that must never appear on this wire.
///
/// `Rule` is flattened — the rules repeat as siblings directly under the root (`q-lc-0003`) — and
/// so are the two transition lists inside a rule and the tag list inside an `<And>`. A wrapper
/// makes every SDK read zero rules, and — the reason this constant exists at all — an encoder and
/// a decoder that both used one would satisfy the round-trip identity while shipping a document
/// no client can read.
const FORBIDDEN_WRAPPERS: &[&str] = &[
    "<Rules>",
    "<Transitions>",
    "<NoncurrentVersionTransitions>",
    "<Tags>",
    "<TagSet>",
];

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

/// Serialises the rules the way `GetBucketLifecycleConfiguration` answers a read.
fn encode_read(rules: Vec<dto::LifecycleRule>) -> String {
    let request = accepted("GET", "/photos?lifecycle", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketLifecycleConfigurationOutput {
        rules,
        ..dto::GetBucketLifecycleConfigurationOutput::default()
    };
    let response = dto::GetBucketLifecycleConfiguration::encode(output, &view, 200).expect("a configuration always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// Reads a document back the way `PutBucketLifecycleConfiguration` reads a write.
fn decode_write(document: &str) -> Result<Option<dto::BucketLifecycleConfiguration>, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?lifecycle", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketLifecycleConfiguration::decode(&view, body).map(|input| input.lifecycle_configuration)
}

/// The comparable projection of one rule. `LifecycleRule` carries no `PartialEq` — ADR-0004 keeps
/// derived equality off the DTOs — so equality is spelled here, over every member, in order. A
/// member left out of this projection is a member the identity would stop covering, which for
/// this family means a member that can vanish between two releases with no test going red.
type RuleProjection = (
    Option<(Option<(i64, u32)>, Option<i32>, Option<bool>)>,
    Option<String>,
    Option<String>,
    Option<FilterProjection>,
    String,
    Vec<(Option<(i64, u32)>, Option<i32>, Option<String>)>,
    Vec<(Option<i32>, Option<String>, Option<i32>)>,
    Option<(Option<i32>, Option<i32>)>,
    Option<Option<i32>>,
);

/// The comparable projection of a filter: the four direct conditions, then the `<And>`.
type FilterProjection = (
    Option<String>,
    Option<(String, String)>,
    Option<i64>,
    Option<i64>,
    Option<(Option<String>, Vec<(String, String)>, Option<i64>, Option<i64>)>,
);

fn tag_projection(tag: &dto::Tag) -> (String, String) {
    (tag.key.as_str().to_owned(), tag.value.clone())
}

fn filter_projection(filter: &dto::LifecycleRuleFilter) -> FilterProjection {
    (
        filter.prefix.clone(),
        filter.tag.as_ref().map(tag_projection),
        filter.object_size_greater_than,
        filter.object_size_less_than,
        filter.and.as_ref().map(|and| {
            (
                and.prefix.clone(),
                and.tags.iter().map(tag_projection).collect(),
                and.object_size_greater_than,
                and.object_size_less_than,
            )
        }),
    )
}

fn projection(rules: &[dto::LifecycleRule]) -> Vec<RuleProjection> {
    rules
        .iter()
        .map(|rule| {
            (
                rule.expiration.as_ref().map(|expiration| {
                    (
                        expiration.date.map(|date| (date.secs(), date.subsec_nanos())),
                        expiration.days,
                        expiration.expired_object_delete_marker,
                    )
                }),
                rule.id.clone(),
                rule.prefix.clone(),
                rule.filter.as_ref().map(filter_projection),
                rule.status.as_str().to_owned(),
                rule.transitions
                    .iter()
                    .map(|transition| {
                        (
                            transition.date.map(|date| (date.secs(), date.subsec_nanos())),
                            transition.days,
                            transition.storage_class.as_ref().map(|class| class.as_str().to_owned()),
                        )
                    })
                    .collect(),
                rule.noncurrent_version_transitions
                    .iter()
                    .map(|transition| {
                        (
                            transition.noncurrent_days,
                            transition.storage_class.as_ref().map(|class| class.as_str().to_owned()),
                            transition.newer_noncurrent_versions,
                        )
                    })
                    .collect(),
                rule.noncurrent_version_expiration
                    .as_ref()
                    .map(|expiration| (expiration.noncurrent_days, expiration.newer_noncurrent_versions)),
                rule.abort_incomplete_multipart_upload
                    .as_ref()
                    .map(|abort| abort.days_after_initiation),
            )
        })
        .collect()
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// Midnight UTC on some day between 2001 and roughly 2033. The midnight rule is a refusal
/// (`q-lc-0009`) that `c-lifecycle-0022` owns, so a *legal* document never carries any other time
/// of day and this generator never produces one.
fn midnight_utc() -> impl Strategy<Value = rustfs_gateway_types::Timestamp> {
    (11_323i64..23_000).prop_map(|days| rustfs_gateway_types::Timestamp::from_secs(days * 86_400))
}

/// A storage class a transition may name. The set is open on the wire — `StorageClass` is a
/// newtype over `Cow<str>` precisely so an unknown value is not a build break — and the family is
/// deliberately lenient about which one (`q-lc-0014`'s reasoning applies), so the generator mixes
/// model constants with a spelling this build has no constant for.
fn storage_class() -> impl Strategy<Value = dto::StorageClass> {
    prop_oneof![
        Just(dto::StorageClass::STANDARD_IA),
        Just(dto::StorageClass::GLACIER),
        Just(dto::StorageClass::DEEP_ARCHIVE),
        Just(dto::StorageClass::INTELLIGENT_TIERING),
        Just(dto::StorageClass::custom("FUTURE_TIER")),
    ]
}

/// A rule identifier. The alphabet deliberately includes the five characters XML has to escape
/// plus two outside ASCII: an identifier is opaque text, and a writer that emitted `&` raw would
/// produce a document its own reader could not parse, while one that escaped on the way out and
/// forgot to unescape on the way in would hand the caller back `&amp;`. Length stays well under
/// the 255-character cap, which is a refusal `c-lifecycle-0025` owns.
fn rule_id() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü _-]{1,40}".prop_map(|value| value.trim().to_owned()).prop_filter(
        "an identifier that is empty or only spaces is the `omit`-on-empty case, which decodes as absent rather than as itself",
        |value| !value.is_empty(),
    )
}

/// A key prefix. The empty one is legal on the wire and is deliberately *not* generated: it is
/// the `omit`-on-empty boundary, where `<Prefix></Prefix>` decodes as absent rather than as
/// itself, so it is not an identity. Excluding it from the generator is not hiding it — it is
/// pinned exactly, in both of the places it can appear, by
/// [`an_empty_prefix_is_the_same_scope_as_no_prefix_and_the_rule_keeps_one`].
fn prefix() -> impl Strategy<Value = String> {
    "[a-z0-9&<>\"'é/_-]{1,24}"
}

/// A tag for a filter, on the direct `<Tag>` or inside an `<And>`.
///
/// Keys the object-key floor refuses are dropped rather than generated — a narrowing whose reason,
/// owner and expiry are spelled out on
/// [`n_a_tag_key_the_object_key_floor_refuses_is_a_known_divergence`], which pins the divergence so
/// that dropping it here hides nothing.
fn tag() -> impl Strategy<Value = dto::Tag> {
    ("[a-zA-Z0-9&<>_.-]{1,20}", "[a-zA-Z0-9&<>\"' _.-]{0,20}")
        .prop_filter(
            "a tag key the object-key floor refuses is a divergence this property does not own; see rustfs/backlog#1750",
            |(key, _)| rustfs_gateway_types::floor_check_key(key).is_ok(),
        )
        .prop_map(|(key, value)| dto::Tag {
            key: rustfs_gateway_types::ObjectKey::new(key).expect("a tag key inside the generated alphabet is a valid key"),
            value,
        })
}

/// A filter with exactly one direct child, or an `<And>` holding two or more conditions. Both
/// shapes are what the grammar allows; a filter with two direct children and an `<And>` holding
/// one are refusals owned by `c-lifecycle-0019` and `c-lifecycle-0020`, so neither is generated.
fn lifecycle_rule_filter() -> impl Strategy<Value = dto::LifecycleRuleFilter> {
    prop_oneof![
        // The empty filter: matches every object, and the case where every member is absent.
        Just(dto::LifecycleRuleFilter::default()),
        prefix().prop_map(|prefix| dto::LifecycleRuleFilter {
            prefix: Some(prefix),
            ..dto::LifecycleRuleFilter::default()
        }),
        tag().prop_map(|tag| dto::LifecycleRuleFilter {
            tag: Some(tag),
            ..dto::LifecycleRuleFilter::default()
        }),
        (1i64..1_048_576).prop_map(|bytes| dto::LifecycleRuleFilter {
            object_size_greater_than: Some(bytes),
            ..dto::LifecycleRuleFilter::default()
        }),
        (1i64..1_048_576).prop_map(|bytes| dto::LifecycleRuleFilter {
            object_size_less_than: Some(bytes),
            ..dto::LifecycleRuleFilter::default()
        }),
        (
            prop::option::of(prefix()),
            prop::collection::vec(tag(), 0..3),
            prop::option::of(1i64..1_048_576),
            prop::option::of(1i64..1_048_576),
        )
            .prop_filter(
                "an <And> exists only to combine, so a generated one always carries two conditions or more",
                |(prefix, tags, greater, less)| {
                    usize::from(prefix.is_some()) + tags.len() + usize::from(greater.is_some()) + usize::from(less.is_some()) >= 2
                },
            )
            .prop_map(|(prefix, tags, greater, less)| dto::LifecycleRuleFilter {
                and: Some(dto::LifecycleRuleAndOperator {
                    prefix,
                    tags,
                    object_size_greater_than: greater,
                    object_size_less_than: less,
                }),
                ..dto::LifecycleRuleFilter::default()
            }),
    ]
}

/// An expiration naming exactly one of `Days`, `Date` and `ExpiredObjectDeleteMarker`. The three
/// are mutually exclusive (`q-lc-0010`) and `Days` must be positive (`q-lc-0013`), both of which
/// are refusals the corpus owns, so a generated expiration is always a legal one.
fn expiration() -> impl Strategy<Value = dto::LifecycleExpiration> {
    prop_oneof![
        (1i32..3_650).prop_map(|days| dto::LifecycleExpiration {
            days: Some(days),
            ..dto::LifecycleExpiration::default()
        }),
        midnight_utc().prop_map(|date| dto::LifecycleExpiration {
            date: Some(date),
            ..dto::LifecycleExpiration::default()
        }),
        Just(dto::LifecycleExpiration {
            expired_object_delete_marker: Some(true),
            ..dto::LifecycleExpiration::default()
        }),
        Just(dto::LifecycleExpiration {
            expired_object_delete_marker: Some(false),
            ..dto::LifecycleExpiration::default()
        }),
    ]
}

fn transition() -> impl Strategy<Value = dto::Transition> {
    prop_oneof![
        ((1i32..3_650), storage_class()).prop_map(|(days, storage_class)| dto::Transition {
            days: Some(days),
            storage_class: Some(storage_class),
            ..dto::Transition::default()
        }),
        (midnight_utc(), storage_class()).prop_map(|(date, storage_class)| dto::Transition {
            date: Some(date),
            storage_class: Some(storage_class),
            ..dto::Transition::default()
        }),
    ]
}

fn noncurrent_version_transition() -> impl Strategy<Value = dto::NoncurrentVersionTransition> {
    ((1i32..3_650), storage_class(), prop::option::of(1i32..100)).prop_map(|(noncurrent_days, storage_class, newer)| {
        dto::NoncurrentVersionTransition {
            noncurrent_days: Some(noncurrent_days),
            storage_class: Some(storage_class),
            newer_noncurrent_versions: newer,
        }
    })
}

/// A rule scoped either by a `<Filter>` or by the legacy rule-level `<Prefix>`, never by neither.
///
/// A rule with no scope at all is refused (`q-lc-0008`, pinned by `c-lifecycle-0021`), and the
/// legacy spelling is generated rather than skipped because the whole reason it is still accepted
/// is that configurations stored under the pre-`Filter` API revision must keep parsing — which is
/// a round-trip claim, not just a parse claim.
fn lifecycle_rule() -> impl Strategy<Value = dto::LifecycleRule> {
    (
        prop::option::of(expiration()),
        prop::option::of(rule_id()),
        prop_oneof![
            lifecycle_rule_filter().prop_map(|filter| (None, Some(filter))),
            prefix().prop_map(|prefix| (Some(prefix), None)),
        ],
        prop_oneof![
            Just(dto::Status::ENABLED),
            Just(dto::Status::DISABLED),
            // Leniency is a durability promise, not an accident: a spelling outside the
            // documented pair is stored and echoed rather than refused (`q-lc-0014`), so it has
            // to survive the round trip too.
            Just(dto::Status::custom("enabled")),
        ],
        prop::collection::vec(transition(), 0..3),
        prop::collection::vec(noncurrent_version_transition(), 0..3),
        prop::option::of((prop::option::of(1i32..3_650), prop::option::of(1i32..100))),
        prop::option::of(prop::option::of(1i32..30)),
    )
        .prop_map(
            |(
                expiration,
                id,
                (prefix, filter),
                status,
                transitions,
                noncurrent_version_transitions,
                noncurrent_version_expiration,
                abort,
            )| dto::LifecycleRule {
                expiration,
                id,
                prefix,
                filter,
                status,
                transitions,
                noncurrent_version_transitions,
                noncurrent_version_expiration: noncurrent_version_expiration.map(|(days, newer)| {
                    dto::NoncurrentVersionExpiration {
                        noncurrent_days: days,
                        newer_noncurrent_versions: newer,
                    }
                }),
                abort_incomplete_multipart_upload: abort.map(|days| dto::AbortIncompleteMultipartUpload {
                    days_after_initiation: days,
                }),
            },
        )
}

/// One to four rules, with distinct identifiers.
///
/// Uniqueness is imposed rather than sampled because a duplicated `<ID>` is a refusal
/// (`q-lc-0012`, `c-lifecycle-0024`) — a generated document is a *legal* one, so the property
/// never leans on a value the family would refuse. The rule ceiling is a boundary rather than a
/// distribution, so it is pinned by
/// [`a_configuration_at_the_rule_ceiling_survives_the_round_trip`] instead of sampled here.
fn lifecycle_rules() -> impl Strategy<Value = Vec<dto::LifecycleRule>> {
    prop::collection::vec(lifecycle_rule(), 1..5).prop_map(|mut rules| {
        for (index, rule) in rules.iter_mut().enumerate() {
            if let Some(id) = rule.id.as_mut() {
                id.push_str(&format!("-{index}"));
            }
        }
        rules
    })
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the rules say, writing them and reading them back yields the same rules in the
    /// same order — and the document that carried them named the wire's root and no wrapper
    /// element.
    ///
    /// The four halves are one test on purpose. Identity alone is satisfied by any encoder and
    /// decoder that agree with each other, including a pair that agrees on a shape no SDK reads;
    /// the root and wrapper assertions are what stop the property from being self-fulfilling, and
    /// the legality assertion is what stops the generator from drifting into documents that would
    /// never reach a decoder in production anyway.
    #[test]
    fn a_lifecycle_configuration_survives_encode_then_decode(rules in lifecycle_rules()) {
        // The strategies claim to generate documents this family would store. If that claim ever
        // stops holding, the identity below would be exercising rules no client could install and
        // the property would be quietly testing less than it says.
        let generated = dto::BucketLifecycleConfiguration { rules: rules.clone() };
        prop_assert_eq!(
            validate_lifecycle(&generated),
            Ok(()),
            "the generator produced a document the family refuses"
        );

        let document = encode_read(rules.clone());

        prop_assert!(
            document.contains(WIRE_ROOT),
            "the written document does not open on the wire's root element: {}",
            document
        );
        prop_assert!(
            !document.contains(SHAPE_ROOT),
            "the written document is rooted on the model's shape name, which no SDK reads: {}",
            document
        );
        for wrapper in FORBIDDEN_WRAPPERS {
            prop_assert!(
                !document.contains(wrapper),
                "the written document carries the wrapper {wrapper}, which makes every SDK read zero rules: {document}"
            );
        }

        let decoded = decode_write(&document)
            .map_err(|error| {
                TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
            })?
            .ok_or_else(|| TestCaseError::fail(format!("the decoder read no configuration at all: {document}")))?;

        prop_assert_eq!(projection(&decoded.rules), projection(&rules), "document: {}", document);
    }
}

// ── the boundaries the property does not sample ──────────────────────────────────────────────

fn ceiling_rules(count: usize) -> Vec<dto::LifecycleRule> {
    (0..count)
        .map(|index| dto::LifecycleRule {
            id: Some(format!("rule-{index}")),
            filter: Some(dto::LifecycleRuleFilter {
                prefix: Some(format!("scope-{index}/")),
                ..dto::LifecycleRuleFilter::default()
            }),
            status: dto::Status::ENABLED,
            expiration: Some(dto::LifecycleExpiration {
                days: Some(30),
                ..dto::LifecycleExpiration::default()
            }),
            ..dto::LifecycleRule::default()
        })
        .collect()
}

/// The per-bucket ceiling. `c-lifecycle-0011` proves the write is accepted over the wire; this
/// proves no rule is dropped, reordered or merged on the way through, which a status alone cannot
/// see — and for a configuration that decides when objects are deleted, a silently dropped rule
/// is the difference between a retention policy and no retention policy.
#[test]
fn a_configuration_at_the_rule_ceiling_survives_the_round_trip() {
    let rules = ceiling_rules(MAX_LIFECYCLE_RULES);

    let document = encode_read(rules.clone());
    let decoded = decode_write(&document)
        .expect("a thousand rules is the documented ceiling, not an overflow")
        .expect("a document with rules decodes to a configuration");

    assert_eq!(decoded.rules.len(), MAX_LIFECYCLE_RULES, "every rule that went out came back");
    assert_eq!(projection(&decoded.rules), projection(&rules), "in the order they were written");
}

/// The companion to the ceiling: one rule more. `c-lifecycle-0026` asserts the same refusal over
/// the wire; here it sits next to the accepted case so the two cannot drift apart, because a cap
/// tested only from below is a cap nothing proves is a cap.
#[test]
fn n_a_configuration_one_rule_past_the_ceiling_is_refused() {
    let configuration = dto::BucketLifecycleConfiguration {
        rules: ceiling_rules(MAX_LIFECYCLE_RULES + 1),
    };

    assert_eq!(validate_lifecycle(&configuration), Err(LifecycleRejection::TooManyRules));
}

/// Reading is order-insensitive while writing is not. The element order inside a rule is pinned
/// by the `lifecycle/` goldens; a *sender* is under no such obligation, and an SDK that emits
/// `<Status>` before `<ID>` is sending the same rule. This matters more here than elsewhere
/// because the documents this decoder reads are not only fresh client writes: they are
/// configurations written by some earlier release, or by another implementation, and re-read.
#[test]
fn a_rule_whose_members_arrive_in_another_order_is_the_same_rule() {
    let canonical = "<LifecycleConfiguration><Rule><Expiration><Days>30</Days></Expiration><ID>r</ID>\
                     <Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status>\
                     <Transition><Days>10</Days><StorageClass>GLACIER</StorageClass></Transition>\
                     </Rule></LifecycleConfiguration>";
    let shuffled = "<LifecycleConfiguration><Rule><Status>Enabled</Status>\
                    <Transition><StorageClass>GLACIER</StorageClass><Days>10</Days></Transition>\
                    <Filter><Prefix>logs/</Prefix></Filter><ID>r</ID>\
                    <Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";

    let first = decode_write(canonical)
        .expect("the canonical order decodes")
        .expect("a document with a rule decodes to a configuration");
    let second = decode_write(shuffled)
        .expect("so does any other order")
        .expect("a document with a rule decodes to a configuration");

    assert_eq!(projection(&second.rules), projection(&first.rules));
}

/// Text the writer has to escape, and text a reader is tempted to normalise. An `ID` and a tag
/// value are opaque: a writer that emitted `&` raw would produce a document its own reader could
/// not parse, one that escaped on the way out and forgot to unescape on the way back would hand
/// the caller `&amp;`, and a reader that collapsed the run of spaces would hand back an
/// identifier the operator never wrote. The generator reaches these characters too; this pins the
/// exact strings so a failure names the character rather than a shrunk sample.
#[test]
fn an_identifier_of_awkward_text_comes_back_unchanged() {
    let awkward = "a & b < c > d \" e ' f  g";
    let rules = vec![dto::LifecycleRule {
        id: Some(awkward.to_owned()),
        filter: Some(dto::LifecycleRuleFilter {
            tag: Some(dto::Tag {
                key: rustfs_gateway_types::ObjectKey::new("k&y").expect("a tag key with an ampersand is a valid key"),
                value: awkward.to_owned(),
            }),
            ..dto::LifecycleRuleFilter::default()
        }),
        status: dto::Status::ENABLED,
        ..dto::LifecycleRule::default()
    }];

    let document = encode_read(rules.clone());
    assert!(!document.contains("a & b"), "the writer emitted a raw ampersand: {document}");

    let decoded = decode_write(&document)
        .expect("a document this codec wrote is one it must read")
        .expect("a document with a rule decodes to a configuration");

    assert_eq!(projection(&decoded.rules), projection(&rules));
}

/// The one place the round trip is deliberately not an identity, pinned rather than avoided.
///
/// An empty `<Prefix>` means "every object", and so does no `<Prefix>` at all, so the codec omits
/// the member on the way out and the value comes back absent rather than as `Some("")`. Inside a
/// `<Filter>` that is exactly right and costs nothing: the filter element remains, and an empty
/// filter is the same scope.
#[test]
fn an_empty_prefix_inside_a_filter_is_the_same_scope_as_no_prefix() {
    let rules = vec![dto::LifecycleRule {
        id: Some("in-filter".to_owned()),
        filter: Some(dto::LifecycleRuleFilter {
            prefix: Some(String::new()),
            ..dto::LifecycleRuleFilter::default()
        }),
        status: dto::Status::ENABLED,
        ..dto::LifecycleRule::default()
    }];
    let decoded = decode_write(&encode_read(rules))
        .expect("an empty filter is a legal scope")
        .expect("a document with a rule decodes to a configuration");

    let filter = decoded.rules[0].filter.as_ref().expect("the filter element survived");
    assert_eq!(filter.prefix, None, "an empty prefix comes back absent, which is the same scope");
}

/// The divergence this file found: a rule whose only scope is an *empty* rule-level `<Prefix>`.
///
/// The legacy pre-`Filter` spelling puts the scope directly on the rule, and the empty spelling
/// `<Prefix></Prefix>` is how that revision said "every object" — it is what AWS's own v1
/// examples carry. The **decoder** keeps it: the member arrives as `Some("")` and the rule has a
/// scope, so the write is accepted. The **encoder** does not: `omit`-on-empty drops the element,
/// and the document that comes out carries neither a `<Filter>` nor a `<Prefix>`. Read that
/// document back and the same rule is now `ScopeMissing`, a `400 MalformedXML`.
///
/// The two halves are asserted together because separately each looks correct. Together they are
/// this family's hard constraint pointing the wrong way: RustFS persists by parsing and
/// re-serialising, so a rule an operator successfully installed under the v1 spelling becomes,
/// after one read-modify-write, a stored document the next release refuses to load. It is at
/// least loud — a refusal rather than the silent leniency failure the family is built around —
/// but it is a configuration this codec wrote and cannot read.
///
/// Fixing it means the encoder writing `<Prefix></Prefix>` for a present-but-empty legacy prefix,
/// which is a codegen `omit`-on-empty change rather than a lifecycle change, so it is not this
/// slice's. The behaviour is pinned in the direction it actually has, with the issue that owns it
/// named; invert the second half in the change that fixes it.
///
/// Owner: rustfs/backlog#1719.
#[test]
fn n_an_empty_legacy_prefix_is_accepted_on_the_way_in_and_dropped_on_the_way_out() {
    let stored = "<LifecycleConfiguration><Rule><ID>legacy</ID><Prefix></Prefix>\
                  <Status>Enabled</Status></Rule></LifecycleConfiguration>";

    let decoded = decode_write(stored)
        .expect("the document is well formed; the scope rule is the validator's to apply")
        .expect("a document with a rule decodes to a configuration");
    assert_eq!(
        decoded.rules[0].prefix,
        Some(String::new()),
        "the decoder dropped the empty legacy prefix, so the rule never had a scope to lose"
    );
    assert_eq!(
        validate_lifecycle(&dto::BucketLifecycleConfiguration {
            rules: decoded.rules.clone(),
        }),
        Ok(()),
        "an empty legacy prefix is a scope, so the write is accepted"
    );

    let re_encoded = encode_read(decoded.rules);
    let reread = decode_write(&re_encoded)
        .expect("the re-encoded document is still well formed")
        .expect("a document with a rule decodes to a configuration");
    assert_eq!(
        validate_lifecycle(&dto::BucketLifecycleConfiguration { rules: reread.rules }),
        Err(LifecycleRejection::ScopeMissing),
        "the empty legacy prefix now survives the encode, so a v1 rule is readable after a \
         read-modify-write; invert this half and add the accepting conformance case in the same \
         change: {re_encoded}"
    );
}

/// The lossy edge this release owns, asserted rather than described.
///
/// `c-lifecycle-0018` pins the same fact over the wire; it is repeated here at the codec seam
/// because this is the layer where the loss actually happens and the layer a future ADR-0007
/// wiring would change. A member the decoder skips is a member the *re-encode* drops, and RustFS
/// persists by re-encoding — so leniency, which is the right answer for reading, is by itself the
/// wrong answer for storing. When the dialect vtables reach production this test is the one that
/// must be inverted, and until then it stops the loss from being rediscovered as a surprise.
#[test]
fn n_an_element_this_codec_does_not_know_is_gone_after_a_re_encode() {
    let stored = "<LifecycleConfiguration><Rule><Expiration><Days>7</Days></Expiration><ID>dialect</ID>\
                  <Filter><Prefix>del/</Prefix></Filter><Status>Enabled</Status>\
                  <DelMarkerExpiration><Days>7</Days></DelMarkerExpiration></Rule></LifecycleConfiguration>";

    let decoded = decode_write(stored)
        .expect("an unknown element is skipped, never a refusal — a stricter read turns retention off")
        .expect("a document with a rule decodes to a configuration");
    assert_eq!(decoded.rules.len(), 1, "the rule around the unknown element survived");

    let re_encoded = encode_read(decoded.rules);
    assert!(
        !re_encoded.contains("DelMarkerExpiration"),
        "the dialect member survived a re-encode, which means the codec grew a way to carry it; \
         invert this test and flip c-lifecycle-0018's read-back assertion in the same change: \
         {re_encoded}"
    );
}

/// Negative — a tag key the object-key floor refuses does not survive, and that is a divergence.
///
/// `Tag.Key` targets `com.amazonaws.s3#ObjectKey`, so the decoder runs `floor_check_key` — the path
/// floor refusing a leading `//` as UNC and any `..` segment as traversal — over what is a *label*,
/// while `ObjectKey::new` on the way *out* does not. The asymmetry sits inside one type: this codec
/// writes a document it will not read, and since the write path is parse-then-reserialise, a rule
/// scoped by such a key is one no operator can install at all.
///
/// rustfs/gateway#227 pinned the same divergence in the tagging round-trip; lifecycle reaches it by
/// a narrower door, since that alphabet carries `/` and this one does not, leaving `..` alone as the
/// single spelling [`tag`] can generate — about 3% of runs, hence the intermittent red. The keys
/// below are deliberately not all reachable from it: they are the shape of the rule, not a sample.
///
/// Pinned rather than fixed: the repair is a tag-key type that is not the object-key type, a model
/// and codegen change with its own blast radius, and the floor and its double-slash policy are
/// rustfs/backlog#1750's subject. This is what makes the narrowing in [`tag`] honest — it goes red
/// the day that lands, and whoever lands it deletes this and its tagging twin together.
#[test]
fn n_a_tag_key_the_object_key_floor_refuses_is_a_known_divergence() {
    // Both positions a tag can occupy, because both are fed by the one narrowed generator: a
    // repair reaching only the direct `<Tag>` would leave `<And>` diverging.
    for key in ["..", "//nightly", "../nightly", "a/../b"] {
        for filter in tag_filters(key) {
            // The rule is one this family accepts, so the refusal below is the codec's and not the
            // validator's — which is what makes it a divergence rather than a rule working.
            let rules = scoped_rule(filter);
            assert_eq!(
                validate_lifecycle(&dto::BucketLifecycleConfiguration { rules: rules.clone() }),
                Ok(()),
                "{key}: the semantic rules refuse this before the codec ever sees it"
            );
            let error = decode_write(&encode_read(rules)).expect_err("the floor refuses this label");
            assert_eq!(error.code().as_str(), "InvalidArgument", "{key}: {error:?}");
        }
    }

    // The floor is a prefix and segment rule, not a ban on the characters: a slash inside a label,
    // and a dot that is not a whole `..` segment, both round-trip. Without this half an over-broad
    // repair — one simply banning `/` or `.` in a tag key — would leave the loop above green.
    for key in ["a/b//c", "a/./b", ".", "...", "a.b"] {
        let [direct, _] = tag_filters(key);
        let rules = scoped_rule(direct);
        let decoded = decode_write(&encode_read(rules.clone()))
            .unwrap_or_else(|error| panic!("{key}: a label is not a path: {error:?}"))
            .expect("a document with a rule decodes to a configuration");
        assert_eq!(projection(&decoded.rules), projection(&rules), "{key}");
    }
}

/// One enabled rule scoped by `filter`, expiring on a plain day count.
fn scoped_rule(filter: dto::LifecycleRuleFilter) -> Vec<dto::LifecycleRule> {
    vec![dto::LifecycleRule {
        id: Some("floor".to_owned()),
        filter: Some(filter),
        status: dto::Status::ENABLED,
        expiration: Some(dto::LifecycleExpiration {
            days: Some(30),
            ..dto::LifecycleExpiration::default()
        }),
        ..dto::LifecycleRule::default()
    }]
}

/// The two filter shapes one tag key can occupy: the direct `<Tag>`, and the same tag inside an
/// `<And>` beside the prefix the grammar's two-condition minimum requires — the shape the shrunk
/// counterexample arrived in. `ObjectKey::new` does not run the floor `value::object_key` runs on
/// the way back in, and that gap is the whole divergence.
fn tag_filters(key: &str) -> [dto::LifecycleRuleFilter; 2] {
    let tag = || dto::Tag {
        key: rustfs_gateway_types::ObjectKey::new(key).expect("the encode side does not run the floor"),
        value: String::new(),
    };
    [
        dto::LifecycleRuleFilter {
            tag: Some(tag()),
            ..dto::LifecycleRuleFilter::default()
        },
        dto::LifecycleRuleFilter {
            and: Some(dto::LifecycleRuleAndOperator {
                prefix: Some("logs/".to_owned()),
                tags: vec![tag()],
                ..dto::LifecycleRuleAndOperator::default()
            }),
            ..dto::LifecycleRuleFilter::default()
        },
    ]
}
