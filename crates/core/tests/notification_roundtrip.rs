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

//! Whether an arbitrary notification configuration survives the trip out and back, and under
//! which element names.
//!
//! Responsible for: the `decode ∘ encode` identity over `NotificationConfiguration` —
//! `GetBucketNotificationConfiguration` writes a document, `PutBucketNotificationConfiguration`
//! reads one, and a stored configuration has to come back the same destinations, in the same
//! order, subscribed to the same events — together with the wire shape that identity is only
//! worth anything against.
//! NOT responsible for: the semantic rules of `ops::shared::bucket_notification` — the floor of
//! one event per configuration, the non-empty destination, the `prefix`/`suffix` filter grammar
//! and the hundred-configuration cap — which that module owns. Nor **delivering** anything, which
//! its docs place on the notification engine. Nor the bytes of any one fixed document, which
//! `c-bucketconfig-0011` and `c-bucketconfig-0024` pin.
//! Upstream: the generated codecs for the family's two operations, and
//! `ops::shared::bucket_notification`. Downstream: nothing.
//!
//! # Why this family needs the shape half more than any other
//!
//! Every list here is **flattened** — the three destination lists, the event list inside each of
//! them, and the filter-rule list — which is the opposite of the website document's wrapped
//! `<RoutingRules>` one family over. And on top of that, **five members are renamed on the wire**
//! (`q-ntf-0004`): the model's `LambdaFunctionConfigurations` is `<CloudFunctionConfiguration>`,
//! `TopicArn` is `<Topic>`, `QueueArn` is `<Queue>`, `LambdaFunctionArn` is `<CloudFunction>`, and
//! the filter's `Key` is `<S3Key>`.
//!
//! That is nine chances to write a name the wire does not use, and a codec pair that agreed on any
//! of them would round-trip perfectly while every SDK read the document as delivering nothing —
//! the exact shape rustfs/gateway#206 found for CORS. The forbidden-name list below is therefore
//! not decoration: it is one entry per rename plus one per list that must not grow a wrapper, and
//! it is the only thing standing between the identity and a green light on an unreadable document.
//!
//! # What this property cannot see
//!
//! An identity is blind to anything both directions agree on: element order within one
//! configuration, and the `xmlns` on the root. Both are pinned by `c-bucketconfig-0011`, which is
//! the complementary guard — a case pins one document exactly, a property pins every document
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
use rustfs_gateway_core::ops::shared::bucket_notification::{NotificationRejection, validate_notification};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// The root element both directions must name.
const ROOT: &str = "NotificationConfiguration";

/// Every element name that must never appear, and each one is a real mistake rather than an
/// invented one.
///
/// The first six are the model's plural list names, which a writer keyed on the member rather than
/// on the wire would emit as wrappers; the last four are the model's names for the four **renamed**
/// scalars and the renamed filter member (`q-ntf-0004`). A document carrying any of them is one
/// every SDK reads as subscribing to nothing, and a decoder keyed on the same name would read it
/// back perfectly.
const FORBIDDEN_NAMES: &[&str] = &[
    "<TopicConfigurations>",
    "<QueueConfigurations>",
    "<LambdaFunctionConfigurations>",
    "<CloudFunctionConfigurations>",
    "<Events>",
    "<FilterRules>",
    "<TopicArn>",
    "<QueueArn>",
    "<LambdaFunctionArn>",
    "<Key>",
];

/// The two elements that are genuine nesting, not list wrappers, and so must appear when a filter
/// does. `<S3Key>` is the wire's name for the model's `Key`, which is why its absence and `<Key>`'s
/// presence are two halves of one claim.
const FILTER_ELEMENTS: &[&str] = &["<Filter>", "<S3Key>"];

fn accepted(method: &str, target: &str) -> WireRequest<()> {
    let request = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// Serialises the configuration the way a read answers.
fn encode_read(configuration: dto::NotificationConfiguration) -> String {
    let request = accepted("GET", "/photos?notification");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketNotificationConfigurationOutput {
        topic_configurations: configuration.topic_configurations,
        queue_configurations: configuration.queue_configurations,
        lambda_function_configurations: configuration.lambda_function_configurations,
        event_bridge_configuration: configuration.event_bridge_configuration,
    };
    let response = dto::GetBucketNotificationConfiguration::encode(output, &view, 200).expect("a configuration always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// Reads a document back the way a write reads one.
///
/// Unlike every sibling in this workspace, this fixture sets **no** `x-amz-checksum-*` header:
/// `PutBucketNotificationConfiguration` is one of the two writes with no integrity requirement,
/// and `q-ntf-0003` records that deliberately. Adding one here would be testing a request the
/// operation does not demand.
fn decode_write(document: &str) -> Result<dto::NotificationConfiguration, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?notification");
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketNotificationConfiguration::decode(&view, body).map(|input| input.notification_configuration)
}

/// The root element's name, read out of the document rather than searched for.
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

// ── the comparable projection ────────────────────────────────────────────────────────────────

/// The comparable projection. The DTOs carry no `PartialEq` — ADR-0004 keeps derived equality off
/// them — so equality is spelled here, over every member of every shape, in order. A member left
/// out of this projection is a member the identity would stop covering; that includes the
/// `EventBridgeConfiguration`, whose whole content is whether it is there at all.
type FilterProjection = Vec<(Option<String>, Option<String>)>;
type ConfigurationProjection = (Option<String>, String, Vec<String>, Option<FilterProjection>);
type NotificationProjection = (
    Vec<ConfigurationProjection>,
    Vec<ConfigurationProjection>,
    Vec<ConfigurationProjection>,
    bool,
);

fn filter_projection(filter: &dto::NotificationConfigurationFilter) -> Option<FilterProjection> {
    filter.key.as_ref().map(|key| {
        key.filter_rules
            .iter()
            .map(|rule| (rule.name.as_ref().map(|name| name.as_str().to_owned()), rule.value.clone()))
            .collect()
    })
}

fn events_projection(events: &[dto::Events]) -> Vec<String> {
    events.iter().map(|event| event.as_str().to_owned()).collect()
}

fn projection(configuration: &dto::NotificationConfiguration) -> NotificationProjection {
    (
        configuration
            .topic_configurations
            .iter()
            .map(|topic| {
                (
                    topic.id.clone(),
                    topic.topic_arn.clone(),
                    events_projection(&topic.events),
                    topic.filter.as_ref().and_then(filter_projection),
                )
            })
            .collect(),
        configuration
            .queue_configurations
            .iter()
            .map(|queue| {
                (
                    queue.id.clone(),
                    queue.queue_arn.clone(),
                    events_projection(&queue.events),
                    queue.filter.as_ref().and_then(filter_projection),
                )
            })
            .collect(),
        configuration
            .lambda_function_configurations
            .iter()
            .map(|lambda| {
                (
                    lambda.id.clone(),
                    lambda.lambda_function_arn.clone(),
                    events_projection(&lambda.events),
                    lambda.filter.as_ref().and_then(filter_projection),
                )
            })
            .collect(),
        configuration.event_bridge_configuration.is_some(),
    )
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// Event names, known and unknown together.
///
/// `q-ntf-0005` records that an unrecognised name is **stored and echoed as sent** rather than
/// refused, because AWS adds event types continuously. A generator that only sampled the names
/// this build happens to know would be a generator shaped around today's model, and it would stop
/// guarding that leniency the moment the model was re-pinned — the same failure the `acl` property
/// measured for the empty string.
fn event() -> impl Strategy<Value = dto::Events> {
    prop_oneof![
        Just(dto::Events::S3_OBJECTCREATED),
        Just(dto::Events::S3_OBJECTCREATED_PUT),
        Just(dto::Events::S3_OBJECTREMOVED_DELETE),
        Just(dto::Events::S3_REDUCEDREDUNDANCYLOSTOBJECT),
        "s3:[A-Za-z]{1,12}:[A-Za-z*]{1,10}".prop_map(dto::Events::custom),
    ]
}

/// A filter-rule value. The alphabet carries the five characters XML has to escape, two outside
/// ASCII and the empty string, because a prefix is text an operator chose and rustfs/gateway#272
/// made the empty string an identity for every optional member.
fn filter_value() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü/._-]{0,24}"
}

fn filter() -> impl Strategy<Value = dto::NotificationConfigurationFilter> {
    prop::option::of(prop::collection::vec(
        (
            prop::option::of(prop_oneof![Just(dto::Name::PREFIX), Just(dto::Name::SUFFIX)]),
            prop::option::of(filter_value()),
        )
            .prop_map(|(name, value)| dto::FilterRule { name, value }),
        0..3,
    ))
    .prop_map(|rules| dto::NotificationConfigurationFilter {
        key: rules.map(|filter_rules| dto::S3KeyFilter { filter_rules }),
    })
}

/// The three shapes share a member set, so they share a generator. `Id` is optional and the empty
/// string is in range for it; the ARN is required and its emptiness is
/// `bucket_notification.rs`'s refusal rather than this file's.
fn parts() -> impl Strategy<Value = (Option<String>, String, Vec<dto::Events>, Option<dto::NotificationConfigurationFilter>)> {
    (
        prop::option::of("[a-zA-Z0-9 _-]{0,16}"),
        "arn:aws:[a-z]{2,8}:us-east-1:[0-9]{12}:[a-z-]{1,12}",
        prop::collection::vec(event(), 1..4),
        prop::option::of(filter()),
    )
}

fn notification_configuration() -> impl Strategy<Value = dto::NotificationConfiguration> {
    (
        prop::collection::vec(parts(), 0..3),
        prop::collection::vec(parts(), 0..3),
        prop::collection::vec(parts(), 0..3),
        any::<bool>(),
    )
        .prop_map(|(topics, queues, lambdas, event_bridge)| dto::NotificationConfiguration {
            topic_configurations: topics
                .into_iter()
                .map(|(id, arn, events, filter)| dto::TopicConfiguration {
                    id,
                    topic_arn: arn,
                    events,
                    filter,
                })
                .collect(),
            queue_configurations: queues
                .into_iter()
                .map(|(id, arn, events, filter)| dto::QueueConfiguration {
                    id,
                    queue_arn: arn,
                    events,
                    filter,
                })
                .collect(),
            lambda_function_configurations: lambdas
                .into_iter()
                .map(|(id, arn, events, filter)| dto::LambdaFunctionConfiguration {
                    id,
                    lambda_function_arn: arn,
                    events,
                    filter,
                })
                .collect(),
            event_bridge_configuration: event_bridge.then(dto::EventBridgeConfiguration::default),
        })
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the configuration says, writing it and reading it back yields the same
    /// destinations in the same order with the same events and the same filters — and the
    /// document that carried them named `<NotificationConfiguration>` as its root and none of the
    /// ten names the model uses that the wire does not.
    ///
    /// The halves are one test on purpose. The identity alone is satisfied by any encoder and
    /// decoder that agree with each other, including a pair that agreed to call every lambda
    /// destination `<LambdaFunctionConfiguration>`; the name assertions are what stop the property
    /// from being self-fulfilling.
    #[test]
    fn a_notification_configuration_survives_encode_then_decode(configuration in notification_configuration()) {
        let document = encode_read(configuration.clone());

        prop_assert_eq!(root_element(&document), ROOT, "document: {}", document);
        for name in FORBIDDEN_NAMES {
            prop_assert!(
                !document.contains(name),
                "the document carries {name}, which the wire does not use: {document}"
            );
        }

        let read_back = decode_write(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(projection(&read_back), projection(&configuration), "document: {}", document);
    }
}

// ── the boundaries the property reaches only by luck ─────────────────────────────────────────

/// The five renamed members, named one at a time and asserted on the wire.
///
/// The property covers this, but a shrunk counterexample would name a whole configuration; this
/// names the rename. `q-ntf-0004` records all five, and each is a name a reader of the Rust type
/// would guess wrong.
#[test]
fn every_renamed_member_reaches_the_wire_under_its_wire_name() {
    let configuration = dto::NotificationConfiguration {
        topic_configurations: vec![dto::TopicConfiguration {
            id: Some("t".to_owned()),
            topic_arn: "arn:aws:sns:us-east-1:000000000000:t".to_owned(),
            events: vec![dto::Events::S3_OBJECTCREATED],
            filter: Some(dto::NotificationConfigurationFilter {
                key: Some(dto::S3KeyFilter {
                    filter_rules: vec![dto::FilterRule {
                        name: Some(dto::Name::PREFIX),
                        value: Some("photos/".to_owned()),
                    }],
                }),
            }),
        }],
        queue_configurations: vec![dto::QueueConfiguration {
            id: None,
            queue_arn: "arn:aws:sqs:us-east-1:000000000000:q".to_owned(),
            events: vec![dto::Events::S3_OBJECTREMOVED_DELETE],
            filter: None,
        }],
        lambda_function_configurations: vec![dto::LambdaFunctionConfiguration {
            id: None,
            lambda_function_arn: "arn:aws:lambda:us-east-1:000000000000:f".to_owned(),
            events: vec![dto::Events::S3_OBJECTCREATED_PUT],
            filter: None,
        }],
        event_bridge_configuration: None,
    };

    let document = encode_read(configuration.clone());

    for expected in [
        "<TopicConfiguration>",
        "<Topic>",
        "<QueueConfiguration>",
        "<Queue>",
        "<CloudFunctionConfiguration>",
        "<CloudFunction>",
        "<Event>",
        "<Filter>",
        "<S3Key>",
        "<FilterRule>",
    ] {
        assert!(document.contains(expected), "{expected} is missing: {document}");
    }
    for absent in FORBIDDEN_NAMES {
        assert!(!document.contains(absent), "{absent} reached the wire: {document}");
    }

    let read_back = decode_write(&document).expect("a document this codec wrote is one it must read");
    assert_eq!(projection(&read_back), projection(&configuration));
    assert_eq!(validate_notification(&read_back), Ok(()));
}

/// The `EventBridgeConfiguration`, whose entire content is whether it is present.
///
/// It is an empty struct, so `Some` and `None` render as one element and no element, and nothing
/// inside the document distinguishes them. That makes it the member most easily lost — a writer
/// that treated "no fields" as "nothing to write" would drop it, and a reader that never looked
/// for it would report a bucket as not delivering to EventBridge when it does.
#[test]
fn an_event_bridge_configuration_is_a_value_and_its_absence_is_another() {
    let with = dto::NotificationConfiguration {
        event_bridge_configuration: Some(dto::EventBridgeConfiguration::default()),
        ..dto::NotificationConfiguration::default()
    };
    let document = encode_read(with);
    assert!(
        document.contains("<EventBridgeConfiguration"),
        "the element never reached the wire: {document}"
    );
    assert!(
        decode_write(&document).expect("reads").event_bridge_configuration.is_some(),
        "and it did not come back: {document}"
    );

    let without = dto::NotificationConfiguration::default();
    let document = encode_read(without);
    assert!(
        !document.contains("<EventBridgeConfiguration"),
        "an absent member was written anyway: {document}"
    );
    assert!(decode_write(&document).expect("reads").event_bridge_configuration.is_none());
}

/// The empty configuration. `q-ntf-0001` records that a bucket with no notifications answers `200`
/// with `<NotificationConfiguration></NotificationConfiguration>` and never a `404`, so the empty
/// document is the family's normal case rather than an edge one — and it has to survive as an
/// empty document rather than as a body the reader refuses.
#[test]
fn an_empty_configuration_is_a_document_and_comes_back_as_one() {
    let document = encode_read(dto::NotificationConfiguration::default());

    assert_eq!(root_element(&document), ROOT, "{document}");

    let read_back = decode_write(&document).expect("an empty configuration is still a document");

    assert_eq!(projection(&read_back), (Vec::new(), Vec::new(), Vec::new(), false));
    assert_eq!(validate_notification(&read_back), Ok(()));
}

/// Reading is order-insensitive while writing is not. Element order inside a configuration is
/// pinned by `c-bucketconfig-0011`; a *sender* is under no such obligation.
#[test]
fn a_configuration_whose_members_arrive_in_another_order_is_the_same_configuration() {
    let canonical = "<NotificationConfiguration><TopicConfiguration><Id>t</Id><Topic>arn:t</Topic>\
                     <Event>s3:ObjectCreated:*</Event></TopicConfiguration></NotificationConfiguration>";
    let shuffled = "<NotificationConfiguration><TopicConfiguration><Event>s3:ObjectCreated:*</Event>\
                    <Topic>arn:t</Topic><Id>t</Id></TopicConfiguration></NotificationConfiguration>";

    let first = decode_write(canonical).expect("reads");
    let second = decode_write(shuffled).expect("reads");

    assert_eq!(projection(&second), projection(&first));
}

/// An unknown event name is stored and echoed as sent (`q-ntf-0005`), which is the one place this
/// family is deliberately more permissive than its own enum. The round trip is what proves the
/// name reached the wire unchanged rather than being normalised into something the delivery engine
/// would silently never match.
#[test]
fn an_event_name_this_build_does_not_know_survives_unchanged() {
    let unknown = "s3:ObjectTeleported:*";
    let configuration = dto::NotificationConfiguration {
        topic_configurations: vec![dto::TopicConfiguration {
            id: None,
            topic_arn: "arn:aws:sns:us-east-1:000000000000:t".to_owned(),
            events: vec![dto::Events::custom(unknown.to_owned())],
            filter: None,
        }],
        ..dto::NotificationConfiguration::default()
    };

    let document = encode_read(configuration.clone());
    assert!(document.contains(unknown), "{document}");

    let read_back = decode_write(&document).expect("reads");

    assert_eq!(projection(&read_back), projection(&configuration));
    assert_eq!(validate_notification(&read_back), Ok(()));
}

// ── negative: the shapes and values that must not be stored ──────────────────────────────────

/// A wrapped destination list — `<TopicConfigurations>` around the entries, which is what a writer
/// keyed on the model's member name would produce and the website family one door over genuinely
/// does. The decoder finds no `<TopicConfiguration>` under the root, so every destination is out of
/// reach and the bucket is stored as delivering nothing: the read side of the defect the
/// `FORBIDDEN_NAMES` assertion catches on the write side, and the reason that assertion is not
/// decoration.
#[test]
fn n_a_wrapped_destination_list_hides_every_destination_from_the_decoder() {
    let document = "<NotificationConfiguration><TopicConfigurations><TopicConfiguration>\
                    <Topic>arn:t</Topic><Event>s3:ObjectCreated:*</Event>\
                    </TopicConfiguration></TopicConfigurations></NotificationConfiguration>";

    let configuration = decode_write(document).expect("an unknown element is skipped, not refused");

    assert!(
        configuration.topic_configurations.is_empty(),
        "the wrapper took every destination with it"
    );
}

/// The same for the event list, one level down. A `<Events>` wrapper leaves the destination
/// visible and subscribed to nothing, which `validate_notification` then refuses — so the failure
/// is loud here and silent one level up, and both directions are worth pinning.
#[test]
fn n_a_wrapped_event_list_leaves_a_destination_subscribed_to_nothing() {
    let document = "<NotificationConfiguration><TopicConfiguration><Topic>arn:t</Topic>\
                    <Events><Event>s3:ObjectCreated:*</Event></Events>\
                    </TopicConfiguration></NotificationConfiguration>";

    let configuration = decode_write(document).expect("an unknown element is skipped, not refused");

    assert_eq!(configuration.topic_configurations.len(), 1);
    assert!(configuration.topic_configurations[0].events.is_empty());
    assert_eq!(validate_notification(&configuration), Err(NotificationRejection::NoEvents));
}

/// The model's name for each renamed scalar, sent in place of the wire's. Each is skipped, the
/// required member is missing, and the write is refused — which is what stops a decoder keyed on
/// the model name from being half of a pair that round-trips and speaks to nobody.
///
/// The refusal names `TopicArn` and `QueueArn` — the **model's** names, not `<Topic>` and
/// `<Queue>`, which are the elements the client actually had to send. That reaches the client:
/// `error_resolution.rs` turns `CodecError::member()` into the `<Resource>` of the error body, so
/// a developer who got the rename wrong is told to look for the name they already used. Filed as
/// rustfs/gateway#295 and pinned here in the direction it has, so the pin goes red when the
/// repair lands rather than the repair going unnoticed.
#[test]
fn n_the_model_names_for_the_renamed_scalars_are_not_wire_elements() {
    for (holder, element, refusal) in [
        ("TopicConfiguration", "<TopicArn>arn:t</TopicArn>", "TopicArn"),
        ("QueueConfiguration", "<QueueArn>arn:q</QueueArn>", "QueueArn"),
    ] {
        let document = format!(
            "<NotificationConfiguration><{holder}>{element}<Event>s3:ObjectCreated:*</Event></{holder}>\
             </NotificationConfiguration>"
        );

        let error = decode_write(&document).expect_err("the model name is not the wire element");

        assert_eq!(error.code().as_str(), "MalformedXML", "{error:?}");
        assert_eq!(
            error.member(),
            Some(refusal),
            "rustfs/gateway#295: the refusal names the model member rather than the wire element"
        );
    }
}

/// The model's name for the filter's `Key` member. `<Key>` is skipped and `<S3Key>` is what the
/// wire uses, so a filter written under the model name decodes as a filter with no key at all —
/// a configuration that says it filters and does not, stored without a word.
#[test]
fn n_the_model_name_for_the_filter_key_is_not_a_wire_element() {
    let document = "<NotificationConfiguration><TopicConfiguration><Topic>arn:t</Topic>\
                    <Event>s3:ObjectCreated:*</Event><Filter><Key><FilterRule><Name>prefix</Name>\
                    <Value>photos/</Value></FilterRule></Key></Filter>\
                    </TopicConfiguration></NotificationConfiguration>";

    let configuration = decode_write(document).expect("an unknown element is skipped, not refused");

    assert!(
        configuration.topic_configurations[0]
            .filter
            .as_ref()
            .and_then(|filter| filter.key.as_ref())
            .is_none(),
        "the filter kept a key it read from an element the wire does not use"
    );
}

/// A destination with no ARN element at all is refused by the **decoder**, not carried through as
/// an empty string. The distinction matters because `validate_notification` refuses an empty ARN
/// too — so a decoder that defaulted would produce the same refusal for a different reason, and
/// a later relaxation of the validator would silently start storing destinations that name nobody.
#[test]
fn n_a_destination_with_no_arn_is_refused_by_the_decoder() {
    let document = "<NotificationConfiguration><QueueConfiguration><Event>s3:ObjectCreated:*</Event>\
                    </QueueConfiguration></NotificationConfiguration>";

    let error = decode_write(document).expect_err("a destination is an ARN or it is nothing");

    assert_eq!(
        error.member(),
        Some("QueueArn"),
        "rustfs/gateway#295: the element the client had to send is <Queue>, and the refusal does not say so"
    );
}

/// A configuration nested inside an envelope. The root is the envelope, so the write is refused —
/// the case that separates "the root element is `NotificationConfiguration`" from "a
/// `<NotificationConfiguration>` appears somewhere in the body".
#[test]
fn n_a_configuration_wrapped_in_an_envelope_is_not_a_configuration() {
    let document = "<Envelope><NotificationConfiguration></NotificationConfiguration></Envelope>";

    let error = decode_write(document).expect_err("the envelope is the root");

    assert_eq!(error.member(), Some(ROOT), "{error:?}");
    assert_eq!(root_element(document), "Envelope");
}

/// A filter rule naming something other than `prefix` or `suffix` survives the decoder and is
/// refused after. What this adds to `bucket_notification.rs`'s own reasoning is *which layer*
/// produces the refusal: the decoder stores the name as sent, so a refactor moving the check into
/// it would change what a stored document means and would have to move this assertion too.
#[test]
fn n_a_filter_rule_name_outside_the_pair_survives_the_decoder_and_is_refused_after() {
    let document = "<NotificationConfiguration><TopicConfiguration><Topic>arn:t</Topic>\
                    <Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>contains</Name>\
                    <Value>x</Value></FilterRule></S3Key></Filter>\
                    </TopicConfiguration></NotificationConfiguration>";

    let configuration = decode_write(document).expect("Name is an open string enum on the wire");

    assert_eq!(
        configuration.topic_configurations[0]
            .filter
            .as_ref()
            .and_then(|filter| filter.key.as_ref())
            .map(|key| key.filter_rules[0].name.as_ref().map(dto::Name::as_str)),
        Some(Some("contains")),
        "the decoder is not the layer that closes the set"
    );
    assert_eq!(validate_notification(&configuration), Err(NotificationRejection::FilterNameUnknown));
}

/// Two rules of the same name in one `<S3Key>`. Both reach the DTO in order — the list is not
/// deduplicated on the way in — and the validator is what refuses them, so the round trip has to
/// carry the duplicate rather than quietly collapsing it into the one rule that would have passed.
#[test]
fn n_a_repeated_filter_name_is_carried_intact_and_refused() {
    let document = "<NotificationConfiguration><TopicConfiguration><Topic>arn:t</Topic>\
                    <Event>s3:ObjectCreated:*</Event><Filter><S3Key>\
                    <FilterRule><Name>prefix</Name><Value>a</Value></FilterRule>\
                    <FilterRule><Name>prefix</Name><Value>b</Value></FilterRule>\
                    </S3Key></Filter></TopicConfiguration></NotificationConfiguration>";

    let configuration = decode_write(document).expect("a repeated element is not a parse failure");

    let rules = configuration.topic_configurations[0]
        .filter
        .as_ref()
        .and_then(|filter| filter.key.as_ref())
        .map(|key| key.filter_rules.len());
    assert_eq!(rules, Some(2), "the second rule was dropped rather than carried");
    assert_eq!(validate_notification(&configuration), Err(NotificationRejection::FilterNameRepeated));
    for element in FILTER_ELEMENTS {
        assert!(document.contains(element));
    }
}

/// A document whose root is some other element entirely.
#[test]
fn n_a_document_whose_root_is_another_element_is_refused_by_name() {
    let document = "<Notification><TopicConfiguration><Topic>arn:t</Topic></TopicConfiguration></Notification>";

    let error = decode_write(document).expect_err("the wrong root is not a configuration");

    assert_eq!(error.member(), Some(ROOT), "{error:?}");
}
