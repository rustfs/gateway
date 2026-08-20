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

//! Whether an arbitrary CORS configuration survives the trip out and back, and on which wire.
//!
//! Responsible for: the `decode ∘ encode` identity over `CORSConfiguration` — `GetBucketCors`
//! writes a document, `PutBucketCors` reads one, and a stored policy has to come back the same
//! rules in the same order — together with the wire shape that identity is only worth anything
//! against, because an encoder and a decoder that agreed on a *wrapped* list would round-trip
//! perfectly and be unreadable by every SDK.
//! It also holds the seam between the two layers that together decide whether a document is
//! stored: the generated decoder answers syntax and `ops::shared::cors::validate_cors` answers
//! semantics, and because a flattened list makes "member absent" and "member empty" the same
//! parse, a rule with no origin reaches the validator rather than being refused by the decoder.
//! A test that expected the decoder to refuse it would be asserting against the wrong layer.
//! NOT responsible for: the enumeration of every semantic rule (closed method set, wildcard
//! budget, rule ceiling), which the `cors/` conformance cases own end to end; the runtime
//! preflight, which is P6-05's; and the bytes of any one fixed document, which the `cors/`
//! goldens pin.
//! Upstream: the generated codecs for `GetBucketCors` and `PutBucketCors`, and
//! `ops::shared::cors`. Downstream: nothing.
//!
//! # What this property cannot see
//!
//! An identity is blind to anything both directions agree on. Element *order* inside a rule is
//! the clearest instance: the reader is order-insensitive by design, so an encoder that emitted
//! `ID` last would round-trip perfectly here. That is caught in the corpus, by the goldens of
//! `c-cors-0002` and `c-cors-0003`, and the two guards are complementary rather than redundant —
//! a golden pins one document exactly, a property pins every document approximately.
//!
//! # Why a property and not another table row
//!
//! The `cors/` corpus pins particular documents. A table cannot say what happens to the
//! *combinations* it does not list — a rule whose `ID` carries an ampersand next to a rule that
//! has none, a second `AllowedOrigin` after an `ExposeHeader`, a `MaxAgeSeconds` of zero, which
//! `omit`-on-empty member disappears when its neighbour is present. Each generated case here is
//! a document nobody wrote by hand, and the identity has to hold for all of them.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use proptest::prelude::*;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::ops::shared::cors::{CorsRejection, validate_cors};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::dto;

/// `PutBucketCors` is `httpChecksumRequired`, so every read fixture has to make an integrity
/// claim before the body is looked at. The claim's *value* is settled below this layer — the wire
/// layer verifies an `x-amz-checksum-*` against the octets it read (`c-checksum-0001`) and
/// `value::verify_body_digest` settles a `Content-MD5` inside the decoder (`c-cors-0059`) — and
/// this fixture hands the decoder an already-buffered body, so neither runs. That is deliberate:
/// what is under test here is the document, and a fixture that also had to carry a live digest
/// would have to recompute one per generated case for no assertion it makes.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// Every wrapper element name that must never appear on this wire. `CORSRule` and the four inner
/// lists are flattened: the rules repeat as siblings under the root and the members repeat as
/// siblings inside a rule. A wrapper makes every SDK read zero rules, and — the reason this
/// constant exists at all — an encoder and a decoder that both used one would satisfy the
/// round-trip identity while shipping a document no client can read.
const FORBIDDEN_WRAPPERS: &[&str] = &[
    "<CORSRules>",
    "<AllowedHeaders>",
    "<AllowedMethods>",
    "<AllowedOrigins>",
    "<ExposeHeaders>",
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

/// Serialises the rules the way `GetBucketCors` answers a read.
fn encode_read(rules: Vec<dto::CorsRule>) -> String {
    let request = accepted("GET", "/photos?cors", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let output = dto::GetBucketCorsOutput { cors_rules: rules };
    let response = dto::GetBucketCors::encode(output, &view, 200).expect("a configuration always encodes");
    match response.body {
        ResponseBody::Complete(bytes) => String::from_utf8(bytes.to_vec()).expect("the writer emits UTF-8"),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("a configuration read is a document, never a stream"),
    }
}

/// Reads a document back the way `PutBucketCors` reads a write.
fn decode_write(document: &str) -> Result<dto::CorsConfiguration, rustfs_gateway_core::codec::CodecError> {
    let request = accepted("PUT", "/photos?cors", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketCors::decode(&view, body).map(|input| input.cors_configuration)
}

/// The comparable projection of a rule list. `CorsRule` carries no `PartialEq` — ADR-0004 keeps
/// derived equality off the DTOs — so equality is spelled here, over every member, in order.
/// A member left out of this tuple is a member the identity would stop covering.
type Projection = Vec<(Option<String>, Vec<String>, Vec<String>, Vec<String>, Vec<String>, Option<i32>)>;

fn projection(rules: &[dto::CorsRule]) -> Projection {
    rules
        .iter()
        .map(|rule| {
            (
                rule.id.clone(),
                rule.allowed_headers.clone(),
                rule.allowed_methods.clone(),
                rule.allowed_origins.clone(),
                rule.expose_headers.clone(),
                rule.max_age_seconds,
            )
        })
        .collect()
}

// ── strategies ───────────────────────────────────────────────────────────────────────────────

/// The closed method set. A generated document is a *legal* one, so the property never leans on
/// a value `ops::shared::cors` would refuse; `c-cors-0016` and `c-cors-0017` own that direction.
fn allowed_method() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("GET".to_owned()),
        Just("PUT".to_owned()),
        Just("POST".to_owned()),
        Just("DELETE".to_owned()),
        Just("HEAD".to_owned()),
    ]
}

/// An origin inside the wildcard budget: bare `*`, an exact origin, or one interior wildcard.
fn allowed_origin() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("*".to_owned()),
        "https://[a-z]{1,8}\\.example\\.com",
        "https://\\*\\.[a-z]{1,8}\\.example\\.com",
    ]
}

/// A request header name, optionally with the one trailing wildcard the syntax allows.
fn allowed_header() -> impl Strategy<Value = String> {
    prop_oneof![Just("*".to_owned()), "x-[a-z-]{1,10}", "x-[a-z-]{1,6}\\*"]
}

/// An exposed header name. No wildcard is legal here, so none is generated.
fn expose_header() -> impl Strategy<Value = String> {
    "x-amz-[a-z-]{1,10}"
}

/// A rule identifier, the empty one included. The alphabet deliberately includes the five
/// characters XML has to escape plus two outside ASCII: an identifier is opaque text, and a writer
/// that emitted `&` raw would produce a document its own reader could not parse, while one that
/// escaped on the way out and forgot to unescape on the way in would hand the caller back `&amp;`.
///
/// The empty identifier had to be excluded while an optional member's empty value was dropped on
/// the way out — it came back absent rather than as itself — and the narrowing comes out with the
/// defect (rustfs/gateway#221).
fn rule_id() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9&<>\"'éü _-]{0,40}".prop_map(|value| value.trim().to_owned())
}

fn cors_rule() -> impl Strategy<Value = dto::CorsRule> {
    (
        prop::option::of(rule_id()),
        prop::collection::vec(allowed_header(), 0..3),
        prop::collection::vec(allowed_method(), 1..4),
        prop::collection::vec(allowed_origin(), 1..3),
        prop::collection::vec(expose_header(), 0..3),
        prop::option::of(0i32..86_400),
    )
        .prop_map(
            |(id, allowed_headers, allowed_methods, allowed_origins, expose_headers, max_age_seconds)| dto::CorsRule {
                id,
                allowed_headers,
                allowed_methods,
                allowed_origins,
                expose_headers,
                max_age_seconds,
            },
        )
}

/// One to four rules. The rule ceiling is a boundary, not a distribution, so it is pinned by
/// `a_configuration_at_the_rule_ceiling_survives_the_round_trip` rather than sampled here.
fn cors_rules() -> impl Strategy<Value = Vec<dto::CorsRule>> {
    prop::collection::vec(cors_rule(), 1..5)
}

// ── the property ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Whatever the rules say, writing them and reading them back yields the same rules in the
    /// same order — and the document that carried them named no wrapper element.
    ///
    /// The three halves are one test on purpose. Identity alone is satisfied by any encoder and
    /// decoder that agree with each other, including a pair that agrees on a shape no SDK reads;
    /// the wrapper assertion is what stops the property from being self-fulfilling, and the
    /// legality assertion is what stops the generator from drifting into documents that would
    /// never reach a decoder in production anyway.
    #[test]
    fn a_cors_configuration_survives_encode_then_decode(rules in cors_rules()) {
        // The strategies claim to generate documents this family would store. If that claim ever
        // stops holding, the identity below would be exercising rules no client could install and
        // the property would be quietly testing less than it says.
        let generated = dto::CorsConfiguration { cors_rules: rules.clone() };
        prop_assert_eq!(validate_cors(&generated), Ok(()), "the generator produced a rule set the family refuses");

        let document = encode_read(rules.clone());

        for wrapper in FORBIDDEN_WRAPPERS {
            prop_assert!(
                !document.contains(wrapper),
                "the written document carries the wrapper {wrapper}, which makes every SDK read zero rules: {document}"
            );
        }

        let decoded = decode_write(&document).map_err(|error| {
            TestCaseError::fail(format!("a document this codec wrote is one it must read: {error:?}: {document}"))
        })?;

        prop_assert_eq!(projection(&decoded.cors_rules), projection(&rules), "document: {}", document);
    }
}

// ── the boundaries the property does not sample ──────────────────────────────────────────────

/// The per-bucket ceiling. `c-cors-0010` proves the write is accepted over the wire; this proves
/// no rule is dropped, reordered or merged on the way through, which a status alone cannot see.
#[test]
fn a_configuration_at_the_rule_ceiling_survives_the_round_trip() {
    let rules: Vec<dto::CorsRule> = (0..100)
        .map(|index| dto::CorsRule {
            id: Some(format!("rule-{index}")),
            allowed_methods: vec!["GET".to_owned()],
            allowed_origins: vec![format!("https://host-{index}.example.com")],
            ..dto::CorsRule::default()
        })
        .collect();

    let document = encode_read(rules.clone());
    let decoded = decode_write(&document).expect("a hundred rules is the documented ceiling, not an overflow");

    assert_eq!(decoded.cors_rules.len(), 100, "every rule that went out came back");
    assert_eq!(projection(&decoded.cors_rules), projection(&rules), "in the order they were written");
}

/// The companion to the ceiling: one rule more. `c-cors-0023` asserts the same refusal over the
/// wire; here it sits next to the accepted case so the two cannot drift apart, because a cap
/// tested only from below is a cap nothing proves is a cap.
#[test]
fn n_a_configuration_one_rule_past_the_ceiling_is_refused() {
    let rules: Vec<dto::CorsRule> = (0..101)
        .map(|index| dto::CorsRule {
            allowed_methods: vec!["GET".to_owned()],
            allowed_origins: vec![format!("https://host-{index}.example.com")],
            ..dto::CorsRule::default()
        })
        .collect();

    let configuration = dto::CorsConfiguration { cors_rules: rules };

    assert_eq!(validate_cors(&configuration), Err(CorsRejection::TooManyRules));
}

/// Reading is order-insensitive while writing is not. The element order inside a rule is pinned
/// by the `cors/` goldens; a *sender* is under no such obligation, and an SDK that emits
/// `MaxAgeSeconds` before `AllowedMethod` is sending the same rule.
#[test]
fn a_rule_whose_members_arrive_in_another_order_is_the_same_rule() {
    let canonical = "<CORSConfiguration><CORSRule><ID>r</ID><AllowedHeader>x-a</AllowedHeader>\
                     <AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin>\
                     <ExposeHeader>x-amz-id</ExposeHeader><MaxAgeSeconds>60</MaxAgeSeconds></CORSRule></CORSConfiguration>";
    let shuffled = "<CORSConfiguration><CORSRule><MaxAgeSeconds>60</MaxAgeSeconds><AllowedOrigin>*</AllowedOrigin>\
                    <ExposeHeader>x-amz-id</ExposeHeader><AllowedMethod>GET</AllowedMethod>\
                    <AllowedHeader>x-a</AllowedHeader><ID>r</ID></CORSRule></CORSConfiguration>";

    let first = decode_write(canonical).expect("the canonical order decodes");
    let second = decode_write(shuffled).expect("so does any other order");

    assert_eq!(projection(&second.cors_rules), projection(&first.cors_rules));
}

/// Text the writer has to escape, and text a reader is tempted to normalise. An `ID` is opaque:
/// a writer that emitted `&` raw would produce a document its own reader could not parse, one
/// that escaped on the way out and forgot to unescape on the way back would hand the caller
/// `&amp;`, and a reader that collapsed the run of spaces would hand back an identifier the
/// operator never wrote. The generator reaches these characters too; this pins the exact strings
/// so a failure names the character rather than a shrunk sample.
#[test]
fn an_identifier_of_awkward_text_comes_back_unchanged() {
    let awkward = "a & b < c > d \" e ' f  g";
    let rules = vec![dto::CorsRule {
        id: Some(awkward.to_owned()),
        allowed_methods: vec!["GET".to_owned()],
        allowed_origins: vec!["*".to_owned()],
        ..dto::CorsRule::default()
    }];

    let document = encode_read(rules.clone());
    assert!(!document.contains("a & b"), "the ampersand reached the document unescaped: {document}");

    let decoded = decode_write(&document).expect("a document this codec wrote is one it must read");

    assert_eq!(decoded.cors_rules[0].id.as_deref(), Some(awkward));
}

// ── negative: the shapes that must never be stored ───────────────────────────────────────────

/// A wrapped rule list is the defect the flattened quirk exists for, seen from the read side.
/// If it survived, the round-trip property could be satisfied by a codec pair that had agreed on
/// the wrapper and the corpus goldens would be the only thing between the wrapper and a release.
///
/// The wrapper is not an element the schema knows, so the lenient policy (`q-cors-0007`) skips it
/// — and skipping it takes the only rule in the document with it, which is precisely why a
/// wrapper makes an SDK read zero rules. The decoder refuses at that point, naming the member it
/// found nothing for.
#[test]
fn n_a_wrapped_rule_list_hides_every_rule_from_the_decoder() {
    let document = "<CORSConfiguration><CORSRules><CORSRule><AllowedMethod>GET</AllowedMethod>\
                    <AllowedOrigin>*</AllowedOrigin></CORSRule></CORSRules></CORSConfiguration>";

    let error = decode_write(document).expect_err("a wrapper puts every rule out of the decoder's reach");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(
        error.member(),
        Some("CORSRules"),
        "the refusal names the member that has no entry, which is the whole rule list"
    );
}

/// The same defect one level down: the rule is found, its members are not.
#[test]
fn n_a_wrapped_member_list_yields_a_rule_with_no_members() {
    let document = "<CORSConfiguration><CORSRule><AllowedMethods><AllowedMethod>GET</AllowedMethod></AllowedMethods>\
                    <AllowedOrigins><AllowedOrigin>*</AllowedOrigin></AllowedOrigins></CORSRule></CORSConfiguration>";

    let configuration = decode_write(document).expect("a wrapper is an unknown element, not a parse failure");

    assert_eq!(validate_cors(&configuration), Err(CorsRejection::MissingAllowedMethod));
}

/// A rule with no origin is not a rule that allows nothing; it is a document the sender got
/// wrong, and storing it would leave the bucket with a policy that silently matches no request.
/// `c-cors-0020` asserts the same refusal over the wire; this pins which layer produces it, so a
/// refactor that moved the check into the decoder would have to move this assertion too.
#[test]
fn n_a_rule_without_an_origin_is_refused_by_the_validator_not_the_decoder() {
    let document = "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>";

    let configuration = decode_write(document).expect("a flattened member that is absent is an empty list, not a parse error");

    assert!(configuration.cors_rules[0].allowed_origins.is_empty());
    assert_eq!(validate_cors(&configuration), Err(CorsRejection::MissingAllowedOrigin));
    assert_eq!(
        CorsRejection::MissingAllowedOrigin.code().as_str(),
        "MalformedXML",
        "the wire code c-cors-0020 pins comes from this rejection"
    );
}

/// And the other required member, so neither is being carried by the presence of the other.
#[test]
fn n_a_rule_without_a_method_is_refused_by_the_validator_not_the_decoder() {
    let document = "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>";

    let configuration = decode_write(document).expect("a flattened member that is absent is an empty list, not a parse error");

    assert!(configuration.cors_rules[0].allowed_methods.is_empty());
    assert_eq!(validate_cors(&configuration), Err(CorsRejection::MissingAllowedMethod));
    assert_eq!(
        CorsRejection::MissingAllowedMethod.code().as_str(),
        "MalformedXML",
        "the wire code c-cors-0020 pins comes from this rejection"
    );
}

/// The root with no rule at all. Unlike a member inside a rule, the rule list itself is a member
/// the decoder can find missing, so this is refused one layer earlier than the two tests above —
/// the asymmetry that makes the round-trip property partial at zero rules rather than total, and
/// the reason `cors_rules()` starts at one. `c-cors-0024` pins the same refusal over the wire.
#[test]
fn n_a_configuration_with_no_rules_is_refused_by_the_decoder() {
    let error = decode_write("<CORSConfiguration></CORSConfiguration>").expect_err("a rule-less document is not a policy");

    assert_eq!(error.code().as_str(), "MalformedXML");
    assert_eq!(error.member(), Some("CORSRules"));
}
