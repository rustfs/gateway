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

//! Whether an arbitrary static-website document survives the trip out and back, and on which wire.
//!
//! Responsible for: the `decode ∘ encode` identity over `WebsiteConfiguration` —
//! `GetBucketWebsite` writes a document, `PutBucketWebsite` reads one, and a stored site
//! description has to come back saying the same thing — together with the wire shape that
//! identity is only worth anything against.
//! It also holds the seam between the two layers that together decide whether a document is
//! stored: the generated decoder answers syntax (`RoutingRule.Redirect` required, `q-web-0004`)
//! and `ops::shared::bucket_website::validate_website` answers semantics (the
//! whole-site-redirect exclusion, the closed `Protocol` set, the double key-rewrite refusal), so
//! a document the decoder accepts is not necessarily one a write would store.
//! NOT responsible for: the enumeration of every semantic rule, which `shared::bucket_website`'s
//! own module docs and the `bucketconfig/` conformance corpus own; the website endpoint's second
//! protocol face (resolving `/`, serving an error document, answering a redirect), explicitly out
//! of the family's scope per that module's docs; or the bytes of any one fixed document.
//! Upstream: the generated codecs for `GetBucketWebsite` and `PutBucketWebsite`, and
//! `ops::shared::bucket_website`. Downstream: nothing.
//!
//! # Why the wrapper assertion points the other way from this workspace's other properties
//!
//! Every list-wrapper defect this workspace has found so far (CORS #206, notification, tagging)
//! was an encoder that added a wrapper no SDK expects around a **flattened** list. This family's
//! `RoutingRules` is the mirror image: `q-web-0002` records that the list is deliberately
//! **wrapped** — `<RoutingRules>` containing repeated `<RoutingRule>` — and a writer that
//! flattened it the way the sibling families are correct to would produce a document every SDK
//! reads as having no rules. So this property asserts the wrapper's *presence*, not its absence,
//! and a mutation that deletes the `<RoutingRules>` open/close from the encoder is exactly the
//! defect class rustfs/gateway#231 was filed to catch here.
//!
//! # What this property cannot see
//!
//! An identity is blind to anything both directions agree on: element order within a document
//! (the reader is order-insensitive by design), and the `xmlns` on the root. Neither is pinned by
//! a golden in this family yet; this file adds no claim about either.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::bucket_website::{WebsiteRejection, validate_website};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// `PutBucketWebsite` is `httpChecksumRequired` (`q-web-0006`), so every read fixture has to make
/// an integrity claim before the body is looked at. The claim's *value* is settled below this
/// layer, and this fixture hands the decoder an already-buffered body, so neither the wire-layer
/// check nor `value::verify_body_digest` runs. What is under test here is the document.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The one root both operations use. Unlike the object-lock family, this family names no shape a
/// different root than its wire name.
const ROOT: &str = "WebsiteConfiguration";

/// The wrapper `q-web-0002` records as deliberate. Every generated document must carry it, in
/// both open and close form, exactly once — the opposite obligation from every sibling property
/// in this workspace, which forbids a wrapper rather than requiring one.
const REQUIRED_WRAPPER_OPEN: &str = "<RoutingRules>";
const REQUIRED_WRAPPER_CLOSE: &str = "</RoutingRules>";

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

/// The root element's name, read out of the document rather than searched for.
///
/// A `contains("<WebsiteConfiguration")` is satisfied by the shape appearing anywhere, including
/// nested inside an envelope no client expects. Naming the root is what makes the wire-shape half
/// of this property an assertion about the document rather than about one of its substrings.
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

/// Serialises the configuration the way `GetBucketWebsite` answers a read.
fn encode_read(configuration: dto::WebsiteConfiguration) -> String {
    let request = accepted("GET", "/photos?website", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketWebsiteOutput {
        redirect_all_requests_to: configuration.redirect_all_requests_to,
        index_document: configuration.index_document,
        error_document: configuration.error_document,
        routing_rules: configuration.routing_rules,
    };
    let response = dto::GetBucketWebsite::encode(output, &view, 200).expect("a configuration always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// Reads a document back the way `PutBucketWebsite` reads a write.
fn decode_write(document: &str) -> Result<dto::WebsiteConfiguration, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?website", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketWebsite::decode(&view, body).map(|input| input.website_configuration)
}

// ── the comparable projection ────────────────────────────────────────────────────────────────

/// None of these DTOs carry `PartialEq` — ADR-0004 keeps derived equality off the DTOs — so
/// equality is spelled here, over every member of every nested shape. A member left out of a
/// projection is a member the identity would stop covering.
type RedirectProjection = (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>);
type ConditionProjection = (Option<String>, Option<String>);
type RuleProjection = (Option<ConditionProjection>, RedirectProjection);
type WebsiteProjection = (Option<(String, Option<String>)>, Option<String>, Option<String>, Vec<RuleProjection>);

fn redirect_projection(redirect: &dto::Redirect) -> RedirectProjection {
    (
        redirect.host_name.clone(),
        redirect.http_redirect_code.clone(),
        redirect.protocol.as_ref().map(|protocol| protocol.as_str().to_owned()),
        redirect.replace_key_prefix_with.clone(),
        redirect.replace_key_with.clone(),
    )
}

fn condition_projection(condition: &dto::Condition) -> ConditionProjection {
    (condition.http_error_code_returned_equals.clone(), condition.key_prefix_equals.clone())
}

fn rule_projection(rule: &dto::RoutingRule) -> RuleProjection {
    (rule.condition.as_ref().map(condition_projection), redirect_projection(&rule.redirect))
}

fn website_projection(configuration: &dto::WebsiteConfiguration) -> WebsiteProjection {
    (
        configuration.redirect_all_requests_to.as_ref().map(|redirect| {
            (
                redirect.host_name.clone(),
                redirect.protocol.as_ref().map(|protocol| protocol.as_str().to_owned()),
            )
        }),
        configuration.index_document.as_ref().map(|index| index.suffix.clone()),
        configuration
            .error_document
            .as_ref()
            .map(|error| error.key.as_str().to_owned()),
        configuration.routing_rules.iter().map(rule_projection).collect(),
    )
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// Text the writer has to escape, and text a reader is tempted to normalise. The alphabet
/// deliberately includes the five characters XML has to escape plus two outside ASCII, the same
/// alphabet `cors_roundtrip.rs`'s `rule_id` samples for the identical reason: a writer that
/// emitted `&` raw would produce a document its own reader could not parse, and one that escaped
/// on the way out and forgot to unescape on the way in would hand the caller back `&amp;`.
fn awkward_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü _-]{0,24}"
}

/// A protocol, sampled including a value the closed set does not declare — the decoder is an
/// open string enum (`q-web-0002`'s sibling rows document `Protocol` bound to both operations),
/// and `validate_website` is the layer that closes it, not the codec.
fn protocol() -> impl Strategy<Value = dto::Protocol> {
    prop_oneof![
        Just(dto::Protocol::HTTP),
        Just(dto::Protocol::HTTPS),
        "[a-z]{1,8}".prop_map(dto::Protocol::custom)
    ]
}

fn redirect() -> impl Strategy<Value = dto::Redirect> {
    (
        prop::option::of(awkward_text()),
        prop::option::of("[0-9]{0,3}"),
        prop::option::of(protocol()),
        prop::option::of(awkward_text()),
        prop::option::of(awkward_text()),
    )
        .prop_map(
            |(host_name, http_redirect_code, protocol, replace_key_prefix_with, replace_key_with)| dto::Redirect {
                host_name,
                http_redirect_code,
                protocol,
                replace_key_prefix_with,
                replace_key_with,
            },
        )
}

fn condition() -> impl Strategy<Value = dto::Condition> {
    (prop::option::of(awkward_text()), prop::option::of(awkward_text())).prop_map(
        |(http_error_code_returned_equals, key_prefix_equals)| dto::Condition {
            http_error_code_returned_equals,
            key_prefix_equals,
        },
    )
}

fn routing_rule() -> impl Strategy<Value = dto::RoutingRule> {
    (prop::option::of(condition()), redirect()).prop_map(|(condition, redirect)| dto::RoutingRule { condition, redirect })
}

/// A non-empty key, respecting the two floors `ObjectKey` puts on every generated document: empty
/// is refused by the decoder (`value::object_key`), so a generator that produced it would be
/// testing a document `ErrorDocument` can never legally carry; and `..` — the alphabet's only way
/// to spell a whole-key traversal segment, since there is no `/` to make it one segment among
/// several — is refused by the same decoder's unconditional `floor_check_key`
/// (`n_an_error_document_key_naming_a_traversal_segment_is_refused` pins that this really is the
/// intended behaviour here, unlike `Tag.Key`'s `rustfs/backlog#1896` repair: `ErrorDocument.Key`
/// names an object a later `GetObject` fetches, so the traversal floor is doing its job).
///
/// No `/` in the alphabet. `ObjectKey::materialize_decoded` runs the deployment's `SlashPolicy`
/// on top of the emptiness floor, and a bare key generator hitting that policy's own boundaries
/// (a leading, trailing or doubled separator) would be exercising key normalisation, not this
/// family's document shape — that surface has its own tests.
fn object_key_text() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü _.-]{1,24}".prop_filter("the decoder's traversal floor refuses a whole-key `..`", |key| key != "..")
}

fn redirect_all_requests_to() -> impl Strategy<Value = dto::RedirectAllRequestsTo> {
    (awkward_text(), prop::option::of(protocol()))
        .prop_map(|(host_name, protocol)| dto::RedirectAllRequestsTo { host_name, protocol })
}

fn index_document() -> impl Strategy<Value = dto::IndexDocument> {
    awkward_text().prop_map(|suffix| dto::IndexDocument { suffix })
}

fn error_document() -> impl Strategy<Value = dto::ErrorDocument> {
    object_key_text().prop_map(|key| dto::ErrorDocument {
        key: rustfs_gateway_types::ObjectKey::new(key).expect("the strategy samples a non-empty key"),
    })
}

/// Every structural combination the codec is lenient about, mutual exclusion included — the
/// codec does not enforce `q-web-0003`'s refusal, `validate_website` does, so a property that
/// only sampled valid documents would never exercise the seam between the two layers.
fn website_configuration() -> impl Strategy<Value = dto::WebsiteConfiguration> {
    (
        prop::option::of(redirect_all_requests_to()),
        prop::option::of(index_document()),
        prop::option::of(error_document()),
        prop::collection::vec(routing_rule(), 0..3),
    )
        .prop_map(
            |(redirect_all_requests_to, index_document, error_document, routing_rules)| dto::WebsiteConfiguration {
                redirect_all_requests_to,
                index_document,
                error_document,
                routing_rules,
            },
        )
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the configuration says, writing it and reading it back yields the same
    /// document — and the document that carried it named `<WebsiteConfiguration>` as its root
    /// and carried the `<RoutingRules>` wrapper `q-web-0002` requires, whether or not any rule
    /// was present.
    #[test]
    fn a_website_configuration_survives_encode_then_decode(configuration in website_configuration()) {
        let document = encode_read(configuration.clone());

        prop_assert_eq!(root_element(&document), ROOT, "document: {}", document);
        prop_assert!(
            document.contains(REQUIRED_WRAPPER_OPEN) && document.contains(REQUIRED_WRAPPER_CLOSE),
            "the document omits the RoutingRules wrapper q-web-0002 requires: {document}"
        );

        let read_back = decode_write(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(website_projection(&read_back), website_projection(&configuration), "document: {}", document);
    }
}

// ── the boundaries the property reaches only by luck ────────────────────────────────────────

/// The empty document: every member of `WebsiteConfiguration` is optional or an empty list, so
/// this is legal to store, and it has to come back as itself — including the wrapper, which the
/// encoder writes unconditionally.
#[test]
fn an_empty_configuration_comes_back_empty_and_still_carries_the_wrapper() {
    let configuration = dto::WebsiteConfiguration::default();
    let document = encode_read(configuration.clone());

    assert_eq!(root_element(&document), ROOT, "{document}");
    assert!(document.contains("<RoutingRules></RoutingRules>"), "{document}");

    let read_back = decode_write(&document).expect("an empty configuration is still a configuration");
    assert_eq!(website_projection(&read_back), website_projection(&configuration));
}

/// A document this codec wrote is one a write would actually store: decode, then the family's
/// validator. A round trip that never validated would be comparing against a document no write
/// would ever have accepted.
#[test]
fn a_realistic_document_this_codec_wrote_is_one_the_family_accepts() {
    let configuration = dto::WebsiteConfiguration {
        redirect_all_requests_to: None,
        index_document: Some(dto::IndexDocument {
            suffix: "index.html".to_owned(),
        }),
        error_document: Some(dto::ErrorDocument {
            key: rustfs_gateway_types::ObjectKey::new("errors/404.html").expect("a literal key is valid"),
        }),
        routing_rules: vec![dto::RoutingRule {
            condition: Some(dto::Condition {
                http_error_code_returned_equals: Some("404".to_owned()),
                key_prefix_equals: None,
            }),
            redirect: dto::Redirect {
                host_name: None,
                http_redirect_code: None,
                protocol: None,
                replace_key_prefix_with: Some("report-404/".to_owned()),
                replace_key_with: None,
            },
        }],
    };

    let read_back = decode_write(&encode_read(configuration.clone())).expect("reads");
    assert_eq!(validate_website(&read_back), Ok(()));
    assert_eq!(website_projection(&read_back), website_projection(&configuration));
}

/// Reading is order-insensitive while writing is not: a `<WebsiteConfiguration>` whose top-level
/// members arrive in another order is the same document.
#[test]
fn a_document_whose_members_arrive_in_another_order_is_the_same_document() {
    let canonical = "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument>\
         <ErrorDocument><Key>404.html</Key></ErrorDocument></WebsiteConfiguration>";
    let shuffled = "<WebsiteConfiguration><ErrorDocument><Key>404.html</Key></ErrorDocument>\
         <IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";

    let first = decode_write(canonical).expect("reads");
    let second = decode_write(shuffled).expect("reads");

    assert_eq!(website_projection(&second), website_projection(&first));
}

// ── negative: shapes and values that must not be stored ─────────────────────────────────────

/// A document whose root is not `WebsiteConfiguration`. This is the read side of the identity: a
/// decoder keyed to any other root would satisfy a pair that agrees with itself and speaks to no
/// client that ever wrote an S3 website document.
#[test]
fn n_a_document_under_another_root_is_refused() {
    let document = "<Website><IndexDocument><Suffix>index.html</Suffix></IndexDocument></Website>";

    let error = decode_write(document).expect_err("the wire root is WebsiteConfiguration, not Website");

    assert_eq!(error.member(), Some("WebsiteConfiguration"), "{error:?}");
}

/// A `RoutingRule` with no `Redirect` is refused by the decoder rather than carried through as
/// one with an empty redirect (`q-web-0004`): the member is required in the pinned model, so a
/// rule that only says what to match and never what to do is a different request from one that
/// redirects to nothing, and the two must not collapse into the same stored document.
#[test]
fn n_a_routing_rule_with_no_redirect_is_refused_rather_than_defaulted() {
    let document = "<WebsiteConfiguration><RoutingRules><RoutingRule>\
                    <Condition><KeyPrefixEquals>images/</KeyPrefixEquals></Condition>\
                    </RoutingRule></RoutingRules></WebsiteConfiguration>";

    let error = decode_write(document).expect_err("Redirect is required on every routing rule");

    assert_eq!(error.member(), Some("Redirect"), "{error:?}");
}

/// A `RoutingRule` sent as a direct child of the root, without the `<RoutingRules>` wrapper, is
/// not read as a rule at all. This is the read side of `q-web-0002`: the decoder looks for rules
/// only inside the wrapper, so a document a flattening writer produced would be read back with
/// zero rules rather than the ones it named — the exact silent-drop failure mode a wrapper
/// mismatch produces, made visible here instead of only in the encoder.
#[test]
fn n_a_routing_rule_outside_the_wrapper_is_not_read_as_a_rule() {
    let document = "<WebsiteConfiguration><RoutingRule>\
                    <Redirect><HostName>example.com</HostName></Redirect>\
                    </RoutingRule></WebsiteConfiguration>";

    let configuration = decode_write(document).expect("a WebsiteConfiguration with an unknown element is still legal");

    assert!(
        configuration.routing_rules.is_empty(),
        "an unwrapped RoutingRule must not be read as a rule: {:?}",
        configuration.routing_rules
    );
}

/// `RedirectAllRequestsTo` beside `IndexDocument` survives the decoder — the codec is lenient by
/// design, per `shared::bucket_website`'s own module docs — and is refused only by the
/// validator. What this adds is *which layer* produces the refusal: a refactor moving the
/// exclusion into the decoder would change what a stored document means on the next release, and
/// would have to move this assertion too.
#[test]
fn n_redirect_all_requests_to_beside_documents_survives_the_decoder_and_is_refused_after() {
    let document = "<WebsiteConfiguration><RedirectAllRequestsTo><HostName>example.com</HostName>\
                    </RedirectAllRequestsTo><IndexDocument><Suffix>index.html</Suffix></IndexDocument>\
                    </WebsiteConfiguration>";

    let configuration = decode_write(document).expect("the decoder does not enforce the exclusion");

    assert!(configuration.redirect_all_requests_to.is_some());
    assert!(configuration.index_document.is_some());
    assert_eq!(validate_website(&configuration), Err(WebsiteRejection::RedirectAllWithDocuments));
}

/// A `Redirect` naming both `ReplaceKeyWith` and `ReplaceKeyPrefixWith` survives the decoder for
/// the same reason, and is refused by the validator rather than silently preferring one member.
#[test]
fn n_a_redirect_replacing_the_key_twice_survives_the_decoder_and_is_refused_after() {
    let document = "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument>\
                    <RoutingRules><RoutingRule><Redirect>\
                    <ReplaceKeyWith>a.html</ReplaceKeyWith><ReplaceKeyPrefixWith>b/</ReplaceKeyPrefixWith>\
                    </Redirect></RoutingRule></RoutingRules></WebsiteConfiguration>";

    let configuration = decode_write(document).expect("the decoder does not enforce the exclusion");

    assert_eq!(configuration.routing_rules.len(), 1);
    assert_eq!(validate_website(&configuration), Err(WebsiteRejection::RedirectReplacesKeyTwice));
}

/// An empty body is refused rather than read as an empty document. `WebsiteConfiguration` is a
/// required payload member (`REQUIRED_INPUT` names it), so "the client sent nothing" and "the
/// client sent an empty `<WebsiteConfiguration/>`" are different requests and must not collapse
/// into one.
#[test]
fn n_an_empty_body_is_not_an_empty_document() {
    assert!(decode_write("").is_err(), "an empty body is not a website configuration");
}

/// `ErrorDocument.Key` naming a path-traversal segment is refused by the decoder's floor
/// (`gateway#461`/`gateway#521`): `value::object_key` runs `floor_check_key` over every body-carried
/// key, and that floor refuses a key whose only segment is `..`, unconditionally, before
/// `validate_website` is ever consulted. Unlike `Tag.Key` (`rustfs/backlog#1896`), `ErrorDocument.Key`
/// really does name an object a `GetObject` will later fetch to serve the error page, so the floor is
/// the correct behaviour here rather than a bug to repair — `object_key_text()` below excludes `..`
/// from what the round-trip property samples for exactly this reason.
#[test]
fn n_an_error_document_key_naming_a_traversal_segment_is_refused() {
    let document = "<WebsiteConfiguration><ErrorDocument><Key>..</Key></ErrorDocument></WebsiteConfiguration>";

    let error = decode_write(document).expect_err("a key that is only a traversal segment must not be stored");

    assert_eq!(error.member(), Some("Key"), "{error:?}");
}

/// An unknown top-level element is skipped rather than refused, and — the half that matters — it
/// does not survive the round trip. The DTO has nowhere to put it, so a decoder that kept it
/// could not; the assertion is that the document that comes back is a truthful report of what was
/// stored rather than an echo of what was sent.
#[test]
fn n_an_unknown_element_is_skipped_and_does_not_come_back() {
    let document = "<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument>\
                    <HostingProvider>acme</HostingProvider></WebsiteConfiguration>";

    let configuration = decode_write(document).expect("an unknown element is skipped, not refused");
    let reserialised = encode_read(configuration);

    assert!(
        !reserialised.contains("<HostingProvider>"),
        "the unknown element was echoed rather than dropped: {reserialised}"
    );
    assert_eq!(root_element(&reserialised), ROOT);
}
