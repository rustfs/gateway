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

//! Whether a character XML 1.0 cannot represent can reach a response body, from either end.
//!
//! Responsible for: the codec-level half of rustfs/gateway#256 — that a body string member
//! carrying such a character is refused on the way in whichever member it is, that the three
//! characters XML 1.0 *does* admit out of C0 stay legal, and that a value the gateway never had
//! the chance to refuse — one a backend already holds — still cannot be written into a document
//! its own reader would reject.
//! NOT responsible for: the predicate itself and the reader and writer that call it, which
//! `crates/xml/src/tests.rs` pins directly; the end-to-end wire answer, which
//! `conformance/cases/lifecycle/c-lifecycle-0033`…`0037` and `object/c-object-0036` pin; or the
//! round-trip identity over legal documents, which `lifecycle_roundtrip.rs` owns.
//! Upstream: the generated codecs for the lifecycle pair, and `rustfs-gateway-xml`. Downstream:
//! nothing.
//!
//! # Why this file uses one family to make a claim about every family
//!
//! The refusal is not per operation and not per member: every generated decoder of an XML body
//! reaches `rustfs_gateway_xml::parse`, and that is where the character range is enforced. So a
//! matrix over four members of one document is not four members' worth of evidence — it is
//! evidence that four *different kinds* of member (a free-text identifier, a key prefix, a tag
//! key, a tag value) reach the same refusal, which is what rustfs/gateway#256 asked for, and it
//! would be no stronger for enumerating the other seventy operations.
//!
//! # The two ends are asymmetric on purpose
//!
//! The refusal is at ingress and the substitution is at egress, and neither can stand in for the
//! other. Ingress alone leaves a value some other channel already stored able to break every
//! read of that document; egress alone silently rewrites what a caller sent, so the value read
//! back is not the value written, and the request that did it is answered `200`.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bytes::Bytes;
use http::Request;
use rustfs_gateway_core::codec::response::ResponseBody;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{ErrorCode, dto};

/// `PutBucketLifecycleConfiguration` is `httpChecksumRequired`, so every fixture has to make an
/// integrity claim before the body is looked at. Its *value* is settled a layer below and never
/// runs here, because the fixture hands the decoder an already-buffered body.
const INTEGRITY: &[(&str, &str)] = &[("x-amz-checksum-crc32", "AAAAAA==")];

/// The characters XML 1.0 excludes from a document entirely, one per class of the exclusion.
///
/// The six C0 controls are the ones rustfs/gateway#256 measured. `U+FFFE` and `U+FFFF` are here
/// because the rule is a range and not "control characters": both are ordinary-looking BMP code
/// points that no XML 1.0 document may contain.
const FORBIDDEN: &[(&str, char)] = &[
    ("NUL U+0000", '\u{0}'),
    ("SOH U+0001", '\u{1}'),
    ("BS  U+0008", '\u{8}'),
    ("VT  U+000B", '\u{b}'),
    ("FF  U+000C", '\u{c}'),
    ("US  U+001F", '\u{1f}'),
    ("U+FFFE", '\u{fffe}'),
    ("U+FFFF", '\u{ffff}'),
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

/// Reads a document the way `PutBucketLifecycleConfiguration` reads a write.
fn decode_write(document: &str) -> Result<Option<dto::BucketLifecycleConfiguration>, CodecError> {
    let request = accepted("PUT", "/photos?lifecycle", INTEGRITY);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("view");
    let body = RequestBody::Buffered(Bytes::copy_from_slice(document.as_bytes()));
    dto::PutBucketLifecycleConfiguration::decode(&view, body).map(|input| input.lifecycle_configuration)
}

/// Serialises rules the way `GetBucketLifecycleConfiguration` answers a read.
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

/// One legal document with each of the four string members filled from the caller.
fn document(id: &str, prefix: &str, key: &str, value: &str) -> String {
    format!(
        "<LifecycleConfiguration><Rule><ID>{id}</ID><Status>Enabled</Status>\
         <Filter><And><Prefix>{prefix}</Prefix><Tag><Key>{key}</Key><Value>{value}</Value></Tag>\
         </And></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
    )
}

/// The four members, each rendered with `payload` in its own position and the others left legal.
fn four_positions(payload: &str) -> [(&'static str, String); 4] {
    [
        ("ID", document(payload, "photos/", "team", "ops")),
        ("Filter.And.Prefix", document("r", payload, "team", "ops")),
        ("Filter.And.Tag.Key", document("r", "photos/", payload, "ops")),
        ("Filter.And.Tag.Value", document("r", "photos/", "team", payload)),
    ]
}

/// Negative — every one of the four string members refuses a character XML 1.0 cannot represent,
/// and refuses it with the code a body that is not well-formed earns.
///
/// Four members rather than one because that is precisely what rustfs/gateway#256 reported: `Key`
/// alone was refused, by accident, because it had been mistyped as an object key, and its three
/// siblings — plain `String` members all along — were not. A fix proven against one member would
/// have reproduced the same asymmetry.
#[test]
fn n_every_body_string_member_refuses_a_character_xml_cannot_represent() {
    for (name, character) in FORBIDDEN {
        for (position, body) in four_positions(&format!("a{character}b")) {
            let refusal = decode_write(&body)
                .err()
                .unwrap_or_else(|| panic!("{name} in {position} was accepted into the store"));
            assert_eq!(
                refusal.code(),
                &ErrorCode::MALFORMED_XML,
                "{name} in {position} was refused under the wrong code"
            );
        }
    }
}

/// Negative — the raw byte and its two escaped spellings are one refusal.
///
/// A guard written against the raw byte alone is bypassed by `&#1;`, which this gateway's reader
/// resolves by name; XML 1.0 makes a character reference to a character outside its `Char`
/// production a fatal error for exactly that reason. CDATA is the third bypass.
///
/// Real AWS answers this the same way and both spellings are captured, on `DeleteObjects`:
/// `aws/aws-sdk-java#333` shows a raw `U+0002` and the `&#2;` form of the same key each answered
/// `MalformedXML` / `400`.
#[test]
fn n_the_escaped_spellings_are_refused_with_the_raw_byte() {
    for spelling in ["a&#1;b", "a&#x1;b", "a&#xB;b", "a&#xFFFE;b", "<![CDATA[a\u{1}b]]>"] {
        for (position, body) in four_positions(spelling) {
            let refusal = decode_write(&body)
                .err()
                .unwrap_or_else(|| panic!("{spelling} in {position} was accepted into the store"));
            assert_eq!(refusal.code(), &ErrorCode::MALFORMED_XML, "{spelling} in {position}");
        }
    }
}

/// Positive — the rule is representability, not "no control characters".
///
/// Tab, newline and carriage return are the three C0 controls XML 1.0 admits, and `U+007F` is the
/// one an implementation written against XML 1.1 gets wrong: XML 1.1 requires DEL to be escaped,
/// XML 1.0 — which is what S3 speaks — admits it raw. Without this control, a fix that refused
/// every control character would pass every negative above while breaking every caller who stores
/// a tag value with a newline in it.
///
/// The carriage return is sent as `&#13;` rather than raw because an XML parser normalises a
/// literal one on the way in, so the raw form would not be a round trip for any implementation.
#[test]
fn the_controls_xml_admits_are_still_accepted_and_survive_the_round_trip() {
    let body = document("id\twith\ttabs", "photos/\u{7f}/", "line\nbreak", "carriage&#13;return");
    let configuration = decode_write(&body)
        .expect("tab, newline, DEL and a carriage-return reference are legal XML 1.0")
        .expect("the document carries a configuration");

    let rule = configuration.rules.first().expect("one rule");
    assert_eq!(rule.id.as_deref(), Some("id\twith\ttabs"));
    let and = rule
        .filter
        .as_ref()
        .and_then(|filter| filter.and.as_ref())
        .expect("the filter carries an <And>");
    assert_eq!(and.prefix.as_deref(), Some("photos/\u{7f}/"));
    let tag = and.tags.first().expect("one tag");
    assert_eq!(tag.key.as_str(), "line\nbreak");
    assert_eq!(tag.value, "carriage\rreturn");

    // And the same four values go back out unchanged — the tab and the newline raw, the carriage
    // return as the reference the writer has always used for it, which is legal XML 1.0.
    let rendered = encode_read(configuration.rules);
    assert!(rendered.contains("<ID>id\twith\ttabs</ID>"), "{rendered}");
    assert!(rendered.contains("<Prefix>photos/\u{7f}/</Prefix>"), "{rendered}");
    assert!(rendered.contains("<Key>line\nbreak</Key>"), "{rendered}");
    assert!(rendered.contains("<Value>carriage&#13;return</Value>"), "{rendered}");
}

/// Negative — a value the gateway never got to refuse still cannot break the document.
///
/// This is the half the ingress refusal cannot reach, and the reason the fix is at both ends. A
/// read answers from whatever the backend holds, not from the request that is asking; a value
/// stored through some other channel — an older release of this gateway, a direct write, a
/// migration — is handed to the encoder with no request to refuse. Writing it raw is what
/// rustfs/gateway#256 measured, and it makes the *whole* document unparseable, so one such value
/// hides every rule beside it.
///
/// The DTO is built here directly rather than decoded, deliberately: a value that can be decoded
/// is a value the ingress failed to refuse, and this assertion has to be about the other case.
/// That is also what keeps it from being satisfied by the ingress fix — delete the writer's guard
/// and this goes red with the reader's refusal fully in place.
#[test]
fn n_a_stored_value_the_ingress_never_saw_is_not_written_raw_into_a_read() {
    for (name, character) in FORBIDDEN {
        let rules = vec![dto::LifecycleRule {
            id: Some(format!("stored{character}id")),
            status: dto::Status::ENABLED,
            filter: Some(dto::LifecycleRuleFilter {
                prefix: Some(format!("stored{character}prefix")),
                tag: Some(dto::Tag {
                    key: format!("stored{character}key"),
                    value: format!("stored{character}value"),
                }),
                ..dto::LifecycleRuleFilter::default()
            }),
            expiration: Some(dto::LifecycleExpiration {
                days: Some(1),
                ..dto::LifecycleExpiration::default()
            }),
            ..dto::LifecycleRule::default()
        }];

        let rendered = encode_read(rules);
        assert!(
            !rendered.contains(*character),
            "{name} reached the response body raw, which makes the whole document unparseable"
        );
        // The strongest available statement of "parseable": this crate's own reader is the one
        // that refuses the character on the way in, so a document it accepts is a document that
        // carries none. A needle on the raw byte alone would pass for a writer that emitted
        // `&#x1;` — which is what real AWS emits, and which is equally unparseable.
        rustfs_gateway_xml::parse(rendered.as_bytes()).expect("what the writer wrote is well-formed XML");
        assert!(
            rendered.contains('\u{fffd}'),
            "the substitute is visible rather than a silent deletion: {rendered}"
        );
    }
}
