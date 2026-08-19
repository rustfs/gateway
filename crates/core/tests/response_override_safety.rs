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

//! What a `response-*` override may carry into a response header, one parameter at a time.
//!
//! Responsible for: the decode-time refusal of an override value the header grammar cannot hold —
//! the response-splitting class (CR, LF, CRLF) and the rest of the control class (NUL, DEL) — for
//! each of the six parameters separately, and for the two controls that keep the refusal from
//! becoming "the parameter is refused": a legal value still reaches its header, and a value that
//! is merely non-ASCII still reaches it too.
//! NOT responsible for: the wire-level proof that the refusal is a 400 with an `InvalidArgument`
//! document and no object bytes — `conformance/cases/object/c-object-0020` and `c-object-0031`
//! through `c-object-0035`, one per parameter, own that — or
//! for the `x-amz-meta-*` echo, which is a different rule with a different owner.
//! Upstream: `rustfs_gateway_core::codec` and the generated codecs. Downstream: nothing.
//!
//! # Why one test per parameter and not one test over the six
//!
//! Because the six do not behave alike, and a single test over the group cannot say which one
//! regressed. Before this file, five of them answered `200` with the header silently dropped while
//! `response-expires` answered `400` — not because anything checked for CR, but because a value
//! carrying one is not an HTTP date. A group assertion would have been satisfied by that accident
//! for one sixth of its inputs, and satisfied by nothing at all for the other five.
//!
//! That accident is also why every refusal here is asserted by *message* and not only by code:
//! `ResponseExpires` had a refusal already, with the same `InvalidArgument` code and the same
//! member name, and an assertion that read only those two would have been green on `main` for the
//! one parameter that was never the point.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use http::Request;
use rustfs_gateway_core::codec::{CodecError, MetaView, OperationCodec, RequestBody};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{ErrorCode, dto};

/// The message the override refusal carries, and no other refusal in the decoder does.
const REFUSAL: &str = "a response-* override carries a value the response header cannot hold";

/// One override parameter: its wire name, the model member it binds, the header it overwrites, and
/// a value that is legal for it.
struct Override {
    query: &'static str,
    member: &'static str,
    header: &'static str,
    legal: &'static str,
    /// The bytes `legal` must arrive in the header as, once decoded.
    carried: &'static str,
}

/// The six, in the order the IR lists them.
const OVERRIDES: &[Override] = &[
    Override {
        query: "response-cache-control",
        member: "ResponseCacheControl",
        header: "cache-control",
        legal: "no-store",
        carried: "no-store",
    },
    Override {
        query: "response-content-disposition",
        member: "ResponseContentDisposition",
        header: "content-disposition",
        legal: "attachment%3B%20filename%3D%22r.txt%22",
        carried: "attachment; filename=\"r.txt\"",
    },
    Override {
        query: "response-content-encoding",
        member: "ResponseContentEncoding",
        header: "content-encoding",
        legal: "identity",
        carried: "identity",
    },
    Override {
        query: "response-content-language",
        member: "ResponseContentLanguage",
        header: "content-language",
        legal: "fr-CA",
        carried: "fr-CA",
    },
    Override {
        query: "response-content-type",
        member: "ResponseContentType",
        header: "content-type",
        legal: "text%2Fplain",
        carried: "text/plain",
    },
    Override {
        query: "response-expires",
        member: "ResponseExpires",
        header: "expires",
        legal: "Thu%2C%2001%20Jan%201970%2000%3A00%3A00%20GMT",
        carried: "Thu, 01 Jan 1970 00:00:00 GMT",
    },
];

/// The byte sequences a header value may not carry, percent-encoded as a client would send them.
///
/// The first three are the response-splitting family: a CR or an LF terminates a header line, and
/// the pair terminates the header block. The last two are the rest of the class the grammar
/// excludes, and they are here because a check written against `\r\n` alone leaves a decoder that
/// forwards NUL into whatever parses the response next.
const INJECTIONS: &[(&str, &str)] = &[
    ("carriage return", "%0D"),
    ("line feed", "%0A"),
    ("the pair", "%0D%0A"),
    ("a NUL", "%00"),
    ("a DEL", "%7F"),
];

/// A request the wire layer accepted, owned so a `MetaView` can borrow it.
fn accepted(method: &str, target: &str) -> WireRequest<()> {
    let request = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

/// What `GetObject` makes of one query string.
fn decode_get(target: &str) -> Result<(), CodecError> {
    let request = accepted("GET", target);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::GetObject::decode(&view, RequestBody::None).map(|_| ())
}

/// What `HeadObject` makes of one query string.
fn decode_head(target: &str) -> Result<(), CodecError> {
    let request = accepted("HEAD", target);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::HeadObject::decode(&view, RequestBody::None).map(|_| ())
}

/// Asserts one refusal completely: the code, the member it names, and the reason it gives.
fn assert_refused(error: &CodecError, entry: &Override, what: &str) {
    assert_eq!(
        error.code(),
        &ErrorCode::INVALID_ARGUMENT,
        "{} carrying {what} must be InvalidArgument, got {}",
        entry.query,
        error.code()
    );
    assert_eq!(
        error.member(),
        Some(entry.member),
        "{} carrying {what} must name its own member",
        entry.query
    );
    assert_eq!(
        error.message(),
        REFUSAL,
        "{} carrying {what} must be refused for carrying it, not for some other reading of the value",
        entry.query
    );
}

/// The value a legal query string puts in the header, or `None` when the header is absent.
fn encoded_header(target: &str, header: &str) -> Option<Vec<u8>> {
    let request = accepted("GET", target);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::GetObject::decode(&view, RequestBody::None).expect("a legal override decodes");
    let response = dto::GetObject::encode(dto::GetObjectOutput::default(), &view, 200).expect("encodes");
    response.headers.get(header).map(|value| value.as_bytes().to_vec())
}

// ── negative: one test per parameter ─────────────────────────────────────────────────────────
//
// Six tests rather than a loop inside one, so that a red run names the parameter that regressed
// in its own line. Each covers the five sequences in both the positions an injection is written:
// appended to an otherwise legal value, which is the shape that would smuggle a whole second
// header, and alone, which is the shape a check that only looks at a value's tail would miss.

/// Every case one parameter has to answer.
fn refuses_every_injection(entry: &Override) {
    for (what, escape) in INJECTIONS {
        for (position, target) in [
            (
                "appended to a legal value",
                format!("/photos/key?{}={}{escape}X-Injected%3A%20yes", entry.query, entry.legal),
            ),
            ("alone", format!("/photos/key?{}={escape}", entry.query)),
        ] {
            let error = decode_get(&target).expect_err(&format!("{} carrying {what} {position} must be refused", entry.query));
            assert_refused(&error, entry, &format!("{what} {position}"));
        }
    }
}

#[test]
fn n_response_cache_control_refuses_a_value_a_header_cannot_hold() {
    refuses_every_injection(&OVERRIDES[0]);
}

#[test]
fn n_response_content_disposition_refuses_a_value_a_header_cannot_hold() {
    refuses_every_injection(&OVERRIDES[1]);
}

#[test]
fn n_response_content_encoding_refuses_a_value_a_header_cannot_hold() {
    refuses_every_injection(&OVERRIDES[2]);
}

#[test]
fn n_response_content_language_refuses_a_value_a_header_cannot_hold() {
    refuses_every_injection(&OVERRIDES[3]);
}

#[test]
fn n_response_content_type_refuses_a_value_a_header_cannot_hold() {
    refuses_every_injection(&OVERRIDES[4]);
}

#[test]
fn n_response_expires_refuses_a_value_a_header_cannot_hold() {
    refuses_every_injection(&OVERRIDES[5]);
}

/// Negative — `HeadObject` reads the same table, and a refusal it did not make is a refusal a
/// client can route around by changing one verb.
#[test]
fn n_head_object_refuses_the_same_six_values() {
    for entry in OVERRIDES {
        let target = format!("/photos/key?{}={}%0D%0AX-Injected%3A%20yes", entry.query, entry.legal);
        let error = decode_head(&target).expect_err("HEAD reads the same override table as GET");
        assert_refused(&error, entry, "the pair, over HEAD");
    }
}

/// Negative — the refusal is the *first* thing the decoder says, so no other member's reading can
/// answer in its place and no body is buffered before it.
///
/// `partNumber=abc` is refused on its own by the same operation, with the same code and a different
/// member, and its binding is read *after* every `response-*` binding. So a decoder that ran the
/// override check in binding order rather than first would answer `PartNumber` here, and one that
/// ran it last would too.
///
/// The first version of this test sent `partNumber=0`, which `value::integer` parses happily —
/// `GetObject.PartNumber` carries no range in the IR. It therefore asserted an ordering against a
/// request with only one fault in it, and stayed green with the check moved to the end of the
/// decoder. `abc` is the value that makes the second fault real.
#[test]
fn n_the_override_refusal_outranks_every_other_member_of_the_same_request() {
    let error = decode_get("/photos/key?partNumber=abc&response-content-type=text%2Fplain%0D%0AX%3A%20y")
        .expect_err("the request carries two faults and must be refused");
    assert_refused(&error, &OVERRIDES[4], "the pair, alongside an unparseable partNumber");
}

/// Negative — a refusal that fired on the parameter rather than on its value would take the whole
/// feature down, so this asserts the absent case is untouched: no parameter, no refusal.
#[test]
fn n_a_request_carrying_no_override_at_all_is_not_refused() {
    decode_get("/photos/key").expect("a request with no override parameter decodes");
}

// ── positive controls ────────────────────────────────────────────────────────────────────────

/// Positive — every legal value still decodes and still reaches its header, byte for byte.
///
/// The direction that keeps the six refusals above from being satisfied by a decoder that refuses
/// the parameters outright.
///
/// It asserts the bytes rather than the header's presence, and that is not pedantry: the first
/// version of this test read `carried.is_some()` and **survived** a mutation that replaced
/// `override_header_value` with a constant — a decoder writing a wholly wrong value passed it
/// while its docstring claimed the value "reaches its header". Presence is not the claim.
#[test]
fn every_legal_override_still_reaches_its_header() {
    for entry in OVERRIDES {
        let target = format!("/photos/key?{}={}", entry.query, entry.legal);
        let carried = encoded_header(&target, entry.header);
        assert_eq!(
            carried.as_deref(),
            Some(entry.carried.as_bytes()),
            "{} carrying a legal value must overwrite {} with exactly that value",
            entry.query,
            entry.header
        );
    }
}

/// Positive — a value that is merely non-ASCII is not a control character, and the header grammar
/// carries it as opaque bytes.
///
/// Without this, "refuse what the header cannot hold" and "refuse anything that is not plain
/// ASCII" are the same test, and the second one breaks every filename a browser is meant to save.
#[test]
fn a_non_ascii_override_is_carried_rather_than_refused() {
    let carried = encoded_header(
        "/photos/key?response-content-disposition=attachment%3B%20filename%3D%22caf%C3%A9.txt%22",
        "content-disposition",
    );
    assert_eq!(
        carried.as_deref(),
        Some("attachment; filename=\"café.txt\"".as_bytes()),
        "the refusal is about the control class, not about ASCII"
    );
}
