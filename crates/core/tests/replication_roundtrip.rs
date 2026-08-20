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

//! Whether an arbitrary replication configuration survives the trip out and back, and on which
//! wire.
//!
//! Responsible for: the `decode ∘ encode` identity over `ReplicationConfiguration` —
//! `GetBucketReplication` writes a document, `PutBucketReplication` reads one, and a stored
//! configuration has to come back the same rules in the same order — together with the wire shape
//! that identity is only worth anything against, because an encoder and a decoder that agreed on
//! a *wrapped* rule list would round-trip perfectly and be unreadable by every SDK.
//! NOT responsible for: the enumeration of every semantic rule (the V1/V2 coupling, the filter
//! grammar, the rule cap, the `ID` bounds), which `ops::shared::replication` owns and the
//! `replication/` conformance cases exercise end to end; executing a rule, which is the
//! replication engine's question; and the bytes of any one fixed document, which the
//! `replication/` goldens pin.
//! Upstream: the generated codecs for `GetBucketReplication` and `PutBucketReplication`, and
//! `ops::shared::replication`. Downstream: nothing.
//!
//! # Why this family is the one where a lossy round trip is worst
//!
//! `ops::shared::replication` records that RustFS parses this configuration **fail-closed**: a
//! document that stops parsing does not switch replication off, it makes the bucket unusable.
//! Persistence is parse-then-reserialise, so any value the encoder will write and the decoder
//! will not accept converts one read-modify-write on an unrelated member into a stored document
//! the next read refuses — and here that refusal is an outage rather than a degradation.
//!
//! # What this property cannot see
//!
//! An identity is blind to anything both directions agree on. Element *order* inside a rule is
//! the clearest instance: the reader is order-insensitive by design, so an encoder that emitted
//! `Status` last would round-trip perfectly here. That is caught in the corpus, by the
//! `replication/` goldens, and the two guards are complementary rather than redundant — a golden
//! pins one document exactly, a property pins every document approximately.
//!
//! # The values the generator once could not sample, and now can
//!
//! Two members used to be excluded because the encoder wrote them and this codec would not read
//! them back as themselves, so sampling them made the property fail at random instead of saying
//! what was wrong. Both are repaired and both are sampled again: a filter tag key naming a
//! traversal segment (rustfs/gateway#247, the `Tag.Key`-as-`ObjectKey` typing) and an empty
//! legacy `<Prefix>` (rustfs/gateway#248, the `omit`-on-empty default). Each keeps a named test
//! below that says the value in full, because a shrunk sample names a character and a named test
//! names a defect.
//!
// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::replication::{ReplicationRejection, validate_replication};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// `PutBucketReplication` is `httpChecksumRequired`, so every read fixture has to make an
/// integrity claim before the body is looked at. The claim's *value* is settled below this layer
/// — the wire layer verifies an `x-amz-checksum-*` against the octets it read and
/// `value::verify_body_digest` settles a `Content-MD5` inside the decoder — and this fixture
/// hands the decoder an already-buffered body, so neither runs. That is deliberate: what is under
/// test here is the document, and a fixture that also had to carry a live digest would have to
/// recompute one per generated case for no assertion it makes.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The root element both directions must name.
const ROOT: &str = "<ReplicationConfiguration";

/// Every wrapper element name that must never appear on this wire.
///
/// `Rule` is flattened — the rules repeat as siblings directly under the root — and so is the tag
/// list inside an `<And>`. A wrapper makes every SDK read zero rules, and — the reason this
/// constant exists at all — an encoder and a decoder that both used one would satisfy the
/// round-trip identity while shipping a document no client can read.
const FORBIDDEN_WRAPPERS: &[&str] = &["<Rules>", "<Tags>", "<TagSet>"];

/// A plausible replication role, destination bucket and KMS key. None of them is sampled: they
/// are opaque ARNs this family neither parses nor constrains, and generating them would add
/// shrink surface to a failure that is never about their text.
const ROLE: &str = "arn:aws:iam::111122223333:role/replication";
const DESTINATION_ARN: &str = "arn:aws:s3:::replica-bucket";

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

/// Serialises the configuration the way `GetBucketReplication` answers a read.
fn encode_read(configuration: dto::ReplicationConfiguration) -> String {
    let request = accepted("GET", "/photos?replication", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketReplicationOutput {
        replication_configuration: Some(configuration),
    };
    let response = dto::GetBucketReplication::encode(output, &view, 200).expect("a configuration always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// Reads a document back the way `PutBucketReplication` reads a write.
fn decode_write(document: &str) -> Result<dto::ReplicationConfiguration, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?replication", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketReplication::decode(&view, body).map(|input| input.replication_configuration)
}

// ── the comparable projection ────────────────────────────────────────────────────────────────

/// The comparable projection of one rule. The replication DTOs carry no `PartialEq` — ADR-0004
/// keeps derived equality off the DTOs — so equality is spelled here, over every member, in
/// order. A member left out of this projection is a member the identity would stop covering,
/// which for this family means a member that can vanish between two releases with no test going
/// red, on the one configuration whose silent loss sends bytes to the wrong place or nowhere.
type RuleProjection = (
    Option<String>,
    Option<i32>,
    Option<String>,
    Option<FilterProjection>,
    String,
    Option<(Option<String>, Option<String>)>,
    Option<String>,
    DestinationProjection,
    Option<Option<String>>,
);

type FilterProjection = (Option<String>, Option<(String, String)>, Option<(Option<String>, Vec<(String, String)>)>);

type DestinationProjection = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<Option<String>>,
    Option<(String, Option<i32>)>,
    Option<(String, Option<Option<i32>>)>,
);

fn tag_projection(tag: &dto::Tag) -> (String, String) {
    (tag.key.as_str().to_owned(), tag.value.clone())
}

fn filter_projection(filter: &dto::ReplicationRuleFilter) -> FilterProjection {
    (
        filter.prefix.clone(),
        filter.tag.as_ref().map(tag_projection),
        filter
            .and
            .as_ref()
            .map(|and| (and.prefix.clone(), and.tags.iter().map(tag_projection).collect())),
    )
}

fn destination_projection(destination: &dto::Destination) -> DestinationProjection {
    (
        destination.bucket.clone(),
        destination.account.clone(),
        destination.storage_class.as_ref().map(|class| class.as_str().to_owned()),
        destination
            .access_control_translation
            .as_ref()
            .map(|translation| translation.owner.clone()),
        destination
            .encryption_configuration
            .as_ref()
            .map(|encryption| encryption.replica_kms_key_id.clone()),
        destination
            .replication_time
            .as_ref()
            .map(|time| (time.status.as_str().to_owned(), time.time.minutes)),
        destination.metrics.as_ref().map(|metrics| {
            (
                metrics.status.as_str().to_owned(),
                metrics.event_threshold.as_ref().map(|threshold| threshold.minutes),
            )
        }),
    )
}

fn projection(configuration: &dto::ReplicationConfiguration) -> (String, Vec<RuleProjection>) {
    (
        configuration.role.clone(),
        configuration
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.id.clone(),
                    rule.priority,
                    rule.prefix.clone(),
                    rule.filter.as_ref().map(filter_projection),
                    rule.status.as_str().to_owned(),
                    rule.source_selection_criteria.as_ref().map(|criteria| {
                        (
                            criteria
                                .sse_kms_encrypted_objects
                                .as_ref()
                                .map(|objects| objects.status.as_str().to_owned()),
                            criteria
                                .replica_modifications
                                .as_ref()
                                .map(|modifications| modifications.status.as_str().to_owned()),
                        )
                    }),
                    rule.existing_object_replication
                        .as_ref()
                        .map(|existing| existing.status.as_str().to_owned()),
                    destination_projection(&rule.destination),
                    rule.delete_marker_replication
                        .as_ref()
                        .map(|marker| marker.status.as_ref().map(|status| status.as_str().to_owned())),
                )
            })
            .collect(),
    )
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// Codegen collapses every `Enabled`/`Disabled` member of this family onto one open string
/// enum, so the same strategy serves the rule, the delete-marker, the metrics and the two
/// source-selection members.
fn status() -> impl Strategy<Value = dto::Status> {
    prop_oneof![Just(dto::Status::ENABLED), Just(dto::Status::DISABLED)]
}

/// A rule identifier. The alphabet deliberately includes the five characters XML has to escape
/// plus two outside ASCII: an identifier is opaque text, and a writer that emitted `&` raw would
/// produce a document its own reader could not parse, while one that escaped on the way out and
/// forgot to unescape on the way in would hand the caller back `&amp;`. Length stays well under
/// the 255-character cap, which is a refusal `ops::shared::replication` owns.
fn rule_id() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü _-]{1,40}".prop_map(|value| value.trim().to_owned()).prop_filter(
        "an identifier that is empty or only spaces is the `omit`-on-empty case, which decodes as absent rather than as itself",
        |value| !value.is_empty(),
    )
}

/// A key prefix, including the empty one.
///
/// The empty prefix had to be excluded while an optional member's empty value was dropped on the
/// way out: the encoder wrote no element and the value came back absent rather than as itself. A
/// generator that avoids the values its own encoder will not write back is a property that cannot
/// see the asymmetry it exists to find, so the narrowing comes out with the defect
/// (rustfs/gateway#248).
fn prefix() -> impl Strategy<Value = String> {
    "[a-z0-9&<>\"'é/_-]{0,24}"
}

/// A tag key. The alphabet carries `.` — and therefore reaches the `..` segment — which it could
/// not while `Tag.Key` was typed as an `ObjectKey`: the decoder ran the *path* floor over a label,
/// so a generated `..` made the property fail at random instead of saying what was wrong, and the
/// alphabet had to be narrowed around it. A generator that avoids the values its own decoder
/// cannot read is a property that cannot see the asymmetry it exists to find, so the narrowing
/// came out with the defect.
fn tag_key() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>._-]{1,20}"
}

fn tag() -> impl Strategy<Value = dto::Tag> {
    (tag_key(), "[a-zA-Z0-9&<>\"' _.-]{0,20}").prop_map(|(key, value)| dto::Tag { key, value })
}

/// A filter with exactly one direct child, or an `<And>` holding two or more conditions. A filter
/// with two direct children and an `<And>` holding one are refusals `validate_replication` owns,
/// so neither is generated; the empty filter is AWS's spelling for "every object" and is.
fn replication_rule_filter() -> impl Strategy<Value = dto::ReplicationRuleFilter> {
    prop_oneof![
        Just(dto::ReplicationRuleFilter::default()),
        prefix().prop_map(|prefix| dto::ReplicationRuleFilter {
            prefix: Some(prefix),
            ..dto::ReplicationRuleFilter::default()
        }),
        tag().prop_map(|tag| dto::ReplicationRuleFilter {
            tag: Some(tag),
            ..dto::ReplicationRuleFilter::default()
        }),
        (prop::option::of(prefix()), prop::collection::vec(tag(), 0..3))
            .prop_filter("an And below two conditions is a refusal, not a document", |(prefix, tags)| {
                usize::from(prefix.is_some()) + tags.len() >= 2
            })
            .prop_map(|(prefix, tags)| dto::ReplicationRuleFilter {
                and: Some(dto::ReplicationRuleAndOperator { prefix, tags }),
                ..dto::ReplicationRuleFilter::default()
            }),
    ]
}

/// A destination, with every optional member reachable, empty values included: an optional
/// member's empty value is written as an empty element now, so `Account` and `ReplicaKmsKeyID`
/// are sampled over the same range as everything else.
fn destination() -> impl Strategy<Value = dto::Destination> {
    (
        prop::option::of("[0-9]{0,12}"),
        prop::option::of(prop_oneof![
            Just("STANDARD".to_owned()),
            Just("STANDARD_IA".to_owned()),
            Just("GLACIER".to_owned()),
            // The set is open on the wire, and a value this build has no constant for must
            // survive the trip unchanged rather than being normalised away.
            Just("OUTER_RIM".to_owned()),
        ]),
        prop::option::of("arn:aws:kms:us-east-1:[0-9]{12}:key/[a-f0-9]{8}"),
        prop::option::of((status(), prop::option::of(1i32..900))),
        prop::option::of((status(), prop::option::of(1i32..900))),
        prop::bool::ANY,
    )
        .prop_map(
            |(account, storage_class, key_id, replication_time, metrics, translate_owner)| dto::Destination {
                bucket: DESTINATION_ARN.to_owned(),
                account,
                storage_class: storage_class.map(dto::StorageClass::custom),
                access_control_translation: translate_owner.then(|| dto::AccessControlTranslation {
                    owner: "Destination".to_owned(),
                }),
                encryption_configuration: key_id.map(|replica_kms_key_id| dto::EncryptionConfiguration {
                    replica_kms_key_id: Some(replica_kms_key_id),
                }),
                replication_time: replication_time.map(|(status, minutes)| dto::ReplicationTime {
                    status,
                    time: dto::ReplicationTimeValue { minutes },
                }),
                metrics: metrics.map(|(status, minutes)| dto::Metrics {
                    status,
                    event_threshold: Some(dto::ReplicationTimeValue { minutes }),
                }),
            },
        )
}

fn source_selection_criteria() -> impl Strategy<Value = dto::SourceSelectionCriteria> {
    (prop::option::of(status()), prop::option::of(status())).prop_map(|(sse, replica)| dto::SourceSelectionCriteria {
        sse_kms_encrypted_objects: sse.map(|status| dto::SseKmsEncryptedObjects { status }),
        replica_modifications: replica.map(|status| dto::ReplicaModifications { status }),
    })
}

/// A rule scoped either by a `<Filter>` — the V2 schema, which drags `Priority` and
/// `DeleteMarkerReplication` in beside it — or by the legacy rule-level `<Prefix>`, or by nothing
/// at all, which is AWS's own replicate-everything example. All three are shapes
/// `validate_replication` accepts; the mixed forms it refuses are not generated.
fn replication_rule() -> impl Strategy<Value = dto::ReplicationRule> {
    let v2 = (
        replication_rule_filter(),
        0i32..1000,
        prop::option::of(status()),
        status(),
        prop::option::of(source_selection_criteria()),
        prop::option::of(status()),
        destination(),
    )
        .prop_map(
            |(filter, priority, marker, status, criteria, existing, destination)| dto::ReplicationRule {
                filter: Some(filter),
                priority: Some(priority),
                delete_marker_replication: Some(dto::DeleteMarkerReplication { status: marker }),
                status,
                source_selection_criteria: criteria,
                existing_object_replication: existing.map(|status| dto::ExistingObjectReplication { status }),
                destination,
                ..dto::ReplicationRule::default()
            },
        );
    let legacy = (
        prop::option::of(prefix()),
        status(),
        prop::option::of(source_selection_criteria()),
        destination(),
    )
        .prop_map(|(prefix, status, criteria, destination)| dto::ReplicationRule {
            prefix,
            status,
            source_selection_criteria: criteria,
            destination,
            ..dto::ReplicationRule::default()
        });
    prop_oneof![v2, legacy]
}

/// One to four rules, with distinct identifiers.
///
/// Uniqueness is imposed rather than sampled because a duplicated `<ID>` is a refusal
/// `validate_replication` owns — a generated document is a *legal* one, so the property never
/// leans on a value the family would refuse. The thousand-rule ceiling is a boundary rather than
/// a distribution, so it is pinned by
/// [`a_configuration_at_the_rule_ceiling_survives_the_round_trip`] instead of sampled here.
fn replication_configuration() -> impl Strategy<Value = dto::ReplicationConfiguration> {
    prop::collection::vec((prop::option::of(rule_id()), replication_rule()), 1..5).prop_map(|entries| {
        let mut seen: Vec<String> = Vec::new();
        let rules = entries
            .into_iter()
            .map(|(id, mut rule)| {
                rule.id = id.map(|id| {
                    let mut unique = id;
                    while seen.contains(&unique) {
                        unique.push('x');
                    }
                    seen.push(unique.clone());
                    unique
                });
                rule
            })
            .collect();
        dto::ReplicationConfiguration {
            role: ROLE.to_owned(),
            rules,
        }
    })
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the configuration says, writing it and reading it back yields the same role and
    /// the same rules in the same order — and the document that carried them named the root the
    /// wire uses and no wrapper element.
    ///
    /// The three halves are one test on purpose. Identity alone is satisfied by any encoder and
    /// decoder that agree with each other, including a pair that agrees on a shape no SDK reads;
    /// the wire-shape assertion is what stops the property from being self-fulfilling, and the
    /// legality assertion is what stops the generator from drifting into documents that would
    /// never reach a decoder in production anyway.
    #[test]
    fn a_replication_configuration_survives_encode_then_decode(configuration in replication_configuration()) {
        prop_assert_eq!(
            validate_replication(&configuration),
            Ok(()),
            "the generator produced a configuration the family refuses"
        );

        let document = encode_read(configuration.clone());

        prop_assert!(
            document.contains(ROOT),
            "the written document does not name the root element every SDK looks for: {document}"
        );
        for wrapper in FORBIDDEN_WRAPPERS {
            prop_assert!(
                !document.contains(wrapper),
                "the written document carries the wrapper {wrapper}, which makes every SDK read zero rules: {document}"
            );
        }

        let decoded = decode_write(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(validate_replication(&decoded), Ok(()), "document: {}", document);
        prop_assert_eq!(projection(&decoded), projection(&configuration), "document: {}", document);
    }
}

// ── the boundaries the property does not sample ──────────────────────────────────────────────

fn ceiling_rules(count: usize) -> Vec<dto::ReplicationRule> {
    (0..count)
        .map(|index| dto::ReplicationRule {
            id: Some(format!("rule-{index}")),
            prefix: Some(format!("scope-{index}/")),
            status: dto::Status::ENABLED,
            destination: dto::Destination {
                bucket: DESTINATION_ARN.to_owned(),
                ..dto::Destination::default()
            },
            ..dto::ReplicationRule::default()
        })
        .collect()
}

/// The per-bucket ceiling. This proves no rule is dropped, reordered or merged on the way
/// through, which a status alone cannot see — and for the one configuration RustFS parses
/// fail-closed, a silently dropped rule is bytes that stop being copied with nothing to notice.
#[test]
fn a_configuration_at_the_rule_ceiling_survives_the_round_trip() {
    let configuration = dto::ReplicationConfiguration {
        role: ROLE.to_owned(),
        rules: ceiling_rules(1000),
    };

    let document = encode_read(configuration.clone());
    let decoded = decode_write(&document).expect("a thousand rules is the documented ceiling, not an overflow");

    assert_eq!(decoded.rules.len(), 1000, "every rule that went out came back");
    assert_eq!(projection(&decoded), projection(&configuration), "in the order they were written");
}

/// The companion to the ceiling: one rule more. A cap tested only from below is a cap nothing
/// proves is a cap, so the accepted and the refused case sit next to each other and cannot drift.
#[test]
fn n_a_configuration_one_rule_past_the_ceiling_is_refused() {
    let configuration = dto::ReplicationConfiguration {
        role: ROLE.to_owned(),
        rules: ceiling_rules(1001),
    };

    assert_eq!(validate_replication(&configuration), Err(ReplicationRejection::TooManyRules));
}

/// Reading is order-insensitive while writing is not. The element order inside a rule is pinned
/// by the `replication/` goldens; a *sender* is under no such obligation, and an SDK that emits
/// `Destination` before `Status` is sending the same rule.
#[test]
fn a_rule_whose_members_arrive_in_another_order_is_the_same_rule() {
    let canonical = "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replication</Role>\
                     <Rule><ID>r</ID><Prefix>logs/</Prefix><Status>Enabled</Status>\
                     <Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule>\
                     </ReplicationConfiguration>";
    let shuffled = "<ReplicationConfiguration>\
                    <Rule><Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination>\
                    <Status>Enabled</Status><Prefix>logs/</Prefix><ID>r</ID></Rule>\
                    <Role>arn:aws:iam::111122223333:role/replication</Role>\
                    </ReplicationConfiguration>";

    let first = decode_write(canonical).expect("the canonical order decodes");
    let second = decode_write(shuffled).expect("so does any other order");

    assert_eq!(projection(&second), projection(&first));
}

/// Text the writer has to escape, and text a reader is tempted to normalise. An `ID` is opaque:
/// a writer that emitted `&` raw would produce a document its own reader could not parse, one
/// that escaped on the way out and forgot to unescape on the way back would hand the caller
/// `&amp;`, and a reader that collapsed the run of spaces would hand back an identifier the
/// operator never wrote.
#[test]
fn an_identifier_of_awkward_text_comes_back_unchanged() {
    let awkward = "a & b < c > d \" e ' f  g";
    let configuration = dto::ReplicationConfiguration {
        role: ROLE.to_owned(),
        rules: vec![dto::ReplicationRule {
            id: Some(awkward.to_owned()),
            prefix: Some("logs/".to_owned()),
            status: dto::Status::ENABLED,
            destination: dto::Destination {
                bucket: DESTINATION_ARN.to_owned(),
                ..dto::Destination::default()
            },
            ..dto::ReplicationRule::default()
        }],
    };

    let document = encode_read(configuration);
    assert!(!document.contains("a & b"), "the ampersand reached the document unescaped: {document}");

    let decoded = decode_write(&document).expect("a document this codec wrote is one it must read");

    assert_eq!(decoded.rules[0].id.as_deref(), Some(awkward));
}

// ── the two gaps the generator does not sample, pinned in the direction they have ────────────

/// One rule scoped by a single tag, with the `<Priority>` the V2 schema demands made optional so
/// that the negative below can leave it out. Shared by the two tests that follow, which differ in
/// exactly that one member and would otherwise be the same forty lines twice.
fn configuration_scoped_by_tag(key: &str, priority: Option<i32>) -> dto::ReplicationConfiguration {
    dto::ReplicationConfiguration {
        role: ROLE.to_owned(),
        rules: vec![dto::ReplicationRule {
            filter: Some(dto::ReplicationRuleFilter {
                tag: Some(dto::Tag {
                    key: key.to_owned(),
                    value: "v".to_owned(),
                }),
                ..dto::ReplicationRuleFilter::default()
            }),
            priority,
            delete_marker_replication: Some(dto::DeleteMarkerReplication { status: None }),
            status: dto::Status::ENABLED,
            destination: dto::Destination {
                bucket: DESTINATION_ARN.to_owned(),
                ..dto::Destination::default()
            },
            ..dto::ReplicationRule::default()
        }],
    }
}

/// A tag key naming a path-traversal segment survives the round trip, because a tag key is a label
/// and not a path.
///
/// `Tag.Key` targeted `ObjectKey` in the pinned model — AWS's own modelling shortcut — so
/// `codec::value::object_key` ran `floor_check_key` over a label, and that floor refuses `..`, a
/// leading `//`, a leading backslash and a drive-rooted spelling. The encoder had no such floor, so
/// this gateway wrote a document it would not read, and a stored configuration whose filter named
/// such a tag stopped parsing on the next read — in a family that parses fail-closed. The member is
/// a plain string now (rustfs/backlog#1896); these four labels are what goes red if it is ever typed
/// back, and the sibling tests in `lifecycle_roundtrip.rs` and `tagging_roundtrip.rs` pin the same
/// labels on the two other families reached through the same shape.
#[test]
fn a_filter_tag_key_naming_a_traversal_segment_survives_the_round_trip() {
    for label in ["..", "//label", "a/../b", "C:\\label"] {
        let document = encode_read(configuration_scoped_by_tag(label, Some(1)));
        assert!(
            document.contains(&format!("<Key>{}</Key>", label.replace('&', "&amp;"))),
            "the encoder wrote the label unchanged: {document}"
        );

        let decoded = decode_write(&document)
            .unwrap_or_else(|error| panic!("{label}: a document this codec wrote is one it must read: {error:?}: {document}"));
        let key = decoded.rules[0]
            .filter
            .as_ref()
            .and_then(|filter| filter.tag.as_ref())
            .map(|tag| tag.key.as_str());
        assert_eq!(key, Some(label), "label: {label}: {document}");
    }
}

/// Negative — the V2 schema's own requirements still bind on a rule scoped by such a tag.
///
/// The repair moved one member off the `ObjectKey` type, and the failure mode of that shape of
/// change is applying it one member too widely. A `<Filter>` obliges the rule to carry a
/// `<Priority>` beside it, which is `validate_replication`'s rule and not the codec's; a rule whose
/// filter names a traversal-shaped tag key and omits the priority is the document that would show
/// the leniency having spread from the key to the grammar around it.
#[test]
fn n_a_traversal_shaped_tag_key_does_not_excuse_a_filter_without_a_priority() {
    let decoded = decode_write(&encode_read(configuration_scoped_by_tag("..", None))).expect("a tag key is text on this wire");
    assert_eq!(
        validate_replication(&decoded),
        Err(ReplicationRejection::PriorityMissingWithFilter),
        "the tag key repair must not have taken the V2 schema's requirements with it"
    );
}

/// The legacy rule-level `<Prefix>`, empty, comes back as itself.
///
/// Ingress always kept it as `Some("")`; the encoder dropped it, because an optional member
/// defaulted to `omit`-on-empty, and the second read therefore saw a rule that never named a
/// scope. Replication does not turn that into a refusal — a rule with no scope at all is legal
/// here, it is AWS's own replicate-everything example — so it was a silent change of the stored
/// document rather than an outage, which is why it needed a property to find it at all.
///
/// The document is walked twice on purpose. `decode ∘ encode` being the identity is the claim;
/// `decode ∘ encode ∘ decode ∘ encode == decode ∘ encode` was already true *while the defect was
/// live*, because the document changed once and then stabilised on a different one. Only the
/// first re-serialisation can see it. rustfs/gateway#248.
#[test]
fn an_empty_legacy_prefix_comes_back_as_itself() {
    let document = "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replication</Role>\
                    <Rule><Prefix></Prefix><Status>Enabled</Status>\
                    <Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule>\
                    </ReplicationConfiguration>";

    let once = decode_write(document).expect("an empty legacy prefix is accepted on ingress");
    let reserialised = encode_read(once.clone());
    let twice = decode_write(&reserialised).expect("and the re-read still parses");

    assert_eq!(once.rules[0].prefix.as_deref(), Some(""), "ingress keeps the empty prefix");
    assert!(
        reserialised.contains("<Prefix></Prefix>"),
        "the encoder writes back the member it was given: {reserialised}"
    );
    assert_eq!(
        twice.rules[0].prefix.as_deref(),
        Some(""),
        "so the second read sees the scope the operator wrote: {reserialised}"
    );
}

/// Negative — the repair does not run the other way. An absent `<Prefix>` stays absent.
///
/// A repair that reached for "always write a `<Prefix>`" would satisfy the test above and be a
/// different defect: here it would give every V2 rule a legacy scope beside its `<Filter>`, which
/// is the V1/V2 mixture `validate_replication` refuses. The control is what says the encoder
/// learned to write `Some("")` rather than to invent it.
#[test]
fn n_an_absent_prefix_does_not_come_back_as_an_empty_one() {
    let document = "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replication</Role>\
                    <Rule><Priority>1</Priority><Filter><Prefix>logs/</Prefix></Filter>\
                    <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>\
                    <Status>Enabled</Status>\
                    <Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule>\
                    </ReplicationConfiguration>";

    let once = decode_write(document).expect("a V2 rule scoped by a filter is well formed");
    assert_eq!(once.rules[0].prefix, None, "the rule never named a legacy prefix");

    let reserialised = encode_read(once);
    assert_eq!(
        reserialised.matches("<Prefix>").count(),
        1,
        "only the filter's prefix may be written; a rule-level one was invented: {reserialised}"
    );

    let twice = decode_write(&reserialised).expect("the re-encoded document is still well formed");
    assert_eq!(twice.rules[0].prefix, None, "and it is still absent on the second read");
    assert_eq!(
        validate_replication(&twice),
        Ok(()),
        "a rule mixing the legacy prefix with a filter is refused, so an invented one shows up here"
    );
}

// ── negative: the shapes that must never be stored ───────────────────────────────────────────

/// A wrapped rule list is the defect the flattened quirk exists for, seen from the read side.
/// If it survived, the round-trip property could be satisfied by a codec pair that had agreed on
/// the wrapper and the corpus goldens would be the only thing between the wrapper and a release.
#[test]
fn n_a_wrapped_rule_list_hides_every_rule_from_the_decoder() {
    let document = "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replication</Role>\
                    <Rules><Rule><Status>Enabled</Status>\
                    <Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule></Rules>\
                    </ReplicationConfiguration>";

    let error = decode_write(document).expect_err("a wrapper puts every rule out of the decoder's reach");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(
        error.member(),
        Some("Rules"),
        "the refusal names the member that has no entry, which is the whole rule list"
    );
}

/// The same defect one level down: the `<And>` is found, its tags are not. A wrapper is an
/// unknown element rather than a parse failure, so the rule reaches the validator with an `<And>`
/// holding one condition — which is where it is refused.
#[test]
fn n_a_wrapped_tag_list_inside_an_and_yields_an_and_with_no_tags() {
    let document = "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replication</Role>\
                    <Rule><Filter><And><Prefix>logs/</Prefix>\
                    <Tags><Tag><Key>k</Key><Value>v</Value></Tag></Tags></And></Filter>\
                    <Priority>1</Priority><DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>\
                    <Status>Enabled</Status>\
                    <Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule>\
                    </ReplicationConfiguration>";

    let configuration = decode_write(document).expect("a wrapper is an unknown element, not a parse failure");

    let and = configuration.rules[0]
        .filter
        .as_ref()
        .and_then(|filter| filter.and.as_ref())
        .expect("the And itself is found");
    assert!(and.tags.is_empty(), "the wrapper hid the only tag");
    assert_eq!(validate_replication(&configuration), Err(ReplicationRejection::AndBelowTwoConditions));
}

/// A document with no rule at all. The rule list is a required member the decoder can find
/// missing, so this is refused one layer earlier than any semantic rule — the asymmetry that
/// makes the round-trip property partial at zero rules rather than total, and the reason
/// `replication_configuration()` starts at one.
#[test]
fn n_a_configuration_with_no_rules_is_refused_by_the_decoder() {
    let document = "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replication</Role>\
                    </ReplicationConfiguration>";

    let error = decode_write(document).expect_err("a rule-less document is not a replication configuration");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(
        error.member(),
        Some("Rules"),
        "the refusal names the model member, which the wire spells Rule"
    );
}

/// The role is required, and a document without one is not a configuration this gateway could
/// ever execute — there would be nothing to assume. Refused by the decoder, not the validator.
#[test]
fn n_a_configuration_with_no_role_is_refused_by_the_decoder() {
    let document = "<ReplicationConfiguration><Rule><Status>Enabled</Status>\
                    <Destination><Bucket>arn:aws:s3:::replica-bucket</Bucket></Destination></Rule>\
                    </ReplicationConfiguration>";

    let error = decode_write(document).expect_err("a configuration with no role names no identity to replicate as");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(error.member(), Some("Role"));
}

/// The leniency this family chose, seen from the other side: an element the schema does not know
/// is skipped (`q-repl-0005`), so a `<Filter>` whose only child is misspelled — `<prefix>` for
/// `<Prefix>`, a wrapped `<Tags><Tag>…</Tag></Tags>` — decodes as the *empty* filter. An empty
/// filter is legal and means every object in the bucket, so a rule the sender wrote as narrow is
/// stored as universal and every object is copied to the destination, which may be another
/// account.
///
/// Nothing here is a bug in the decoder taken on its own: leniency about unknown elements is a
/// deliberate, documented choice, and `ops::shared::replication` explains why getting stricter is
/// an availability incident rather than a fix. What the round trip shows is that in *this* family
/// the choice fails open, because unlike lifecycle — where a rule with no scope is refused
/// outright — a scope-less replication rule is AWS's own replicate-everything example and cannot
/// be refused. Pinned in the direction it has and filed as rustfs/gateway#250.
#[test]
fn a_filter_whose_only_child_is_unknown_is_stored_as_replicate_everything() {
    for narrow in [
        // A single case typo in a hand-written configuration.
        "<Filter><prefix>logs/</prefix></Filter>",
        // The wrapper shape a nonconforming writer produces, which the corpus already knows makes
        // an SDK read zero members.
        "<Filter><Tags><Tag><Key>k</Key><Value>v</Value></Tag></Tags></Filter>",
    ] {
        let document = format!(
            "<ReplicationConfiguration><Role>{ROLE}</Role><Rule>{narrow}<Priority>1</Priority>\
             <DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>\
             <Status>Enabled</Status><Destination><Bucket>{DESTINATION_ARN}</Bucket></Destination>\
             </Rule></ReplicationConfiguration>"
        );

        let configuration = decode_write(&document).expect("an unknown element is skipped, not refused");
        let filter = configuration.rules[0]
            .filter
            .as_ref()
            .expect("the Filter element itself is found");

        assert_eq!(filter_projection(filter), (None, None, None), "every condition the sender wrote is gone");
        assert_eq!(
            validate_replication(&configuration),
            Ok(()),
            "and the scope-less rule that is left is one this family must accept"
        );
    }
}
