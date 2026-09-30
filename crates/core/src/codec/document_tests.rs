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

//! The RustFS profile's scalar reading, kind by kind: what legacy RustFS reads, what it refuses,
//! what this gateway cannot carry, and the spelling a generated decoder reads back.
//!
//! Responsible for: the grammar of every [`Scalar`] kind at its edges, and the code
//! [`super::request_document`] answers each refusal of either reading with.
//! NOT responsible for: whether the legacy stack really reads that way — the differential in
//! `rustfs-gateway-goldens` (`request_documents`) proves it against the pinned legacy service.
//! Upstream: [`super::rustfs_scalar`], [`super::request_document`]. Downstream: nothing.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use http::Request;
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::{ErrorCode, Timestamp, TimestampFormat};
use rustfs_gateway_xml::bound::{Arity, Content, Document, EmptyBody, Member, Scalar, ScalarRefusal, Shape, Unknown, Value};

use super::{DocumentReading, request_document, rustfs_scalar};
use crate::codec::MetaView;
use crate::route::TargetKind;

fn read(kind: Scalar, raw: &str) -> Result<String, ScalarRefusal> {
    rustfs_scalar(kind, raw)
}

fn reads_as(kind: Scalar, raw: &str, expected: &str) {
    assert_eq!(read(kind, raw).as_deref(), Ok(expected), "{kind:?} {raw:?}");
}

fn unreadable(kind: Scalar, raw: &str) {
    assert_eq!(read(kind, raw), Err(ScalarRefusal::Unreadable), "{kind:?} {raw:?}");
}

fn uncarriable(kind: Scalar, raw: &str) {
    assert_eq!(read(kind, raw), Err(ScalarRefusal::Uncarriable), "{kind:?} {raw:?}");
}

/// Positive — text of every kind that is text passes unchanged, spaces and carriage returns
/// included.
#[test]
fn text_passes_unchanged() {
    for raw in ["", " a ", "a\r\nb", "Enabled", "\u{540d}"] {
        reads_as(Scalar::Text, raw, raw);
    }
}

/// Positive — an integer is its optional sign and leading digits, spelled back in decimal.
#[test]
fn an_integer_is_its_leading_digits() {
    for (raw, value) in [
        ("30", "30"),
        ("+30", "30"),
        ("-7", "-7"),
        ("007", "7"),
        ("30.5", "30"),
        ("30 ", "30"),
        ("30abc", "30"),
        ("+", "0"),
        ("-", "0"),
        ("+x", "0"),
        ("2147483647", "2147483647"),
        ("-2147483648", "-2147483648"),
        ("00000000000000000000001", "1"),
    ] {
        reads_as(Scalar::Integer, raw, value);
    }
    reads_as(Scalar::Long, "9223372036854775807", "9223372036854775807");
    reads_as(Scalar::Long, "-9223372036854775808x", "-9223372036854775808");
}

/// Negative — no leading digit and no sign, white space first, and a value past the type's range.
#[test]
fn n_an_integer_without_leading_digits_or_past_its_range_is_unreadable() {
    for raw in [
        "",
        " 5",
        "\n5",
        "abc",
        "x1",
        "2147483648",
        "-2147483649",
        "99999999999999999999999999999999999999999",
    ] {
        unreadable(Scalar::Integer, raw);
    }
    for raw in ["", " 1", "9223372036854775808", "-9223372036854775809"] {
        unreadable(Scalar::Long, raw);
    }
}

/// Positive and negative — exactly four spellings of a boolean.
#[test]
fn n_a_boolean_is_one_of_four_spellings() {
    reads_as(Scalar::Boolean, "true", "true");
    reads_as(Scalar::Boolean, "TRUE", "true");
    reads_as(Scalar::Boolean, "false", "false");
    reads_as(Scalar::Boolean, "FALSE", "false");
    for raw in ["True", "tRUE", "False", " true", "true ", "1", "0", "yes", ""] {
        unreadable(Scalar::Boolean, raw);
    }
}

fn instant(spelled: &str) -> Timestamp {
    Timestamp::parse(spelled, TimestampFormat::Iso8601).expect("the spelling reads back")
}

/// Positive — a UTC date-time in every spelling legacy RustFS reads becomes the same instant,
/// spelled with nine fractional digits.
#[test]
fn a_utc_date_time_reads_in_every_legacy_spelling() {
    for (raw, spelled) in [
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05.000000000Z"),
        ("2026-01-02t03:04:05z", "2026-01-02T03:04:05.000000000Z"),
        ("2026-01-02 03:04:05Z", "2026-01-02T03:04:05.000000000Z"),
        ("2026-01-02x03:04:05Z", "2026-01-02T03:04:05.000000000Z"),
        ("2026-01-02T03:04:05.1Z", "2026-01-02T03:04:05.100000000Z"),
        ("2026-01-02T03:04:05.123456789123Z", "2026-01-02T03:04:05.123456789Z"),
        ("2026-01-02T03:04:05+00:00", "2026-01-02T03:04:05.000000000Z"),
        ("2026-01-02T03:04:05-00:00", "2026-01-02T03:04:05.000000000Z"),
        ("2024-02-29T00:00:00Z", "2024-02-29T00:00:00.000000000Z"),
        ("2026-06-30T23:59:60Z", "2026-06-30T23:59:59.999999999Z"),
        ("2026-06-30T23:59:60.25Z", "2026-06-30T23:59:59.999999999Z"),
    ] {
        reads_as(Scalar::DateTime, raw, spelled);
        let _ = instant(spelled);
    }
}

/// Negative — what legacy RustFS refuses: a wrong length or separator, an impossible calendar or
/// clock value, a leap second anywhere but the last second of a month, a fraction with no digit,
/// an offset without a colon, and anything after the zone.
#[test]
fn n_a_date_time_legacy_refuses_is_unreadable() {
    for raw in [
        "",
        "2026-01-02",
        "2026-01-02T03:04:05",
        "26-01-02T03:04:05Z",
        "2026/01/02T03:04:05Z",
        "2026-13-02T03:04:05Z",
        "2026-00-02T03:04:05Z",
        "2026-02-29T03:04:05Z",
        "2026-01-32T03:04:05Z",
        "2026-01-02T24:00:00Z",
        "2026-01-02T03:60:05Z",
        "2026-01-02T03:04:61Z",
        "2026-01-02T03:04:60Z",
        "2026-06-29T23:59:60Z",
        "2026-01-02T03:04:05.Z",
        "2026-01-02T03:04:05+0800",
        "2026-01-02T03:04:05+24:00",
        "2026-01-02T03:04:05+08:60",
        "2026-01-02T03:04:05ZZ",
        "2026-01-02T03:04:05 Z",
        "2026-01-02\u{e9}03:04:05Z",
    ] {
        unreadable(Scalar::DateTime, raw);
    }
}

/// Negative — a non-zero UTC offset reads, but the gateway's timestamp is a UTC instant and legacy
/// RustFS keeps the offset, so it is refused as uncarriable rather than stored differently; a leap
/// second is judged in UTC first.
#[test]
fn n_a_date_time_with_a_non_zero_offset_is_uncarriable() {
    for raw in [
        "2026-01-02T03:04:05+08:00",
        "2026-01-02T03:04:05-00:30",
        "2026-01-02T00:00:00.000+23:59",
        "2026-07-01T07:59:60+08:00",
    ] {
        uncarriable(Scalar::DateTime, raw);
    }
    unreadable(Scalar::DateTime, "2026-06-30T23:59:60+08:00");
}

/// Positive — an HTTP date in legacy RustFS's one layout, any day name, spelled back as the
/// gateway renders the same instant.
#[test]
fn an_http_date_reads_in_its_one_layout() {
    reads_as(Scalar::HttpDate, "Fri, 02 Jan 2026 03:04:05 GMT", "Fri, 02 Jan 2026 03:04:05 GMT");
    reads_as(Scalar::HttpDate, "Mon, 02 Jan 2026 03:04:05 GMT", "Fri, 02 Jan 2026 03:04:05 GMT");
    reads_as(Scalar::HttpDate, "Fri, 02 Jan +2026 03:04:05 GMT", "Fri, 02 Jan 2026 03:04:05 GMT");
}

/// Negative — the obsolete layouts, other cases, a missing zero and an impossible value.
#[test]
fn n_an_http_date_outside_its_layout_is_unreadable() {
    for raw in [
        "",
        "Friday, 02-Jan-26 03:04:05 GMT",
        "Fri Jan  2 03:04:05 2026",
        "fri, 02 Jan 2026 03:04:05 GMT",
        "Fri, 02 JAN 2026 03:04:05 GMT",
        "Fri, 2 Jan 2026 03:04:05 GMT",
        "Fri, 02 Jan 26 03:04:05 GMT",
        "Fri, 02 Jan 2026 03:04:05 UTC",
        "Fri, 02 Jan 2026 03:04:05 GMT ",
        "Fri, 30 Feb 2026 03:04:05 GMT",
        "Fri, 02 Jan 2026 24:04:05 GMT",
        "Fri, 02 Jan 2026 03:04:60 GMT",
        "Xyz, 02 Jan 2026 03:04:05 GMT",
    ] {
        unreadable(Scalar::HttpDate, raw);
    }
    uncarriable(Scalar::HttpDate, "Fri, 02 Jan -2026 03:04:05 GMT");
}

/// Positive — every entity tag legacy RustFS reads and the gateway's tag can hold, spelled quoted.
#[test]
fn an_entity_tag_reads_quoted_bare_and_weak() {
    for (raw, spelled) in [
        ("\"abc\"", "\"abc\""),
        ("abc", "\"abc\""),
        ("d41d8cd98f00b204e9800998ecf8427e-2", "\"d41d8cd98f00b204e9800998ecf8427e-2\""),
        ("W/\"abc\"", "W/\"abc\""),
        ("W/abc", "\"W/abc\""),
        (" abc ", "\" abc \""),
        ("a b", "\"a b\""),
    ] {
        reads_as(Scalar::EntityTag, raw, spelled);
    }
}

/// Negative — a character legacy RustFS refuses in a tag, and a tag the gateway cannot hold.
#[test]
fn n_an_entity_tag_legacy_refuses_is_unreadable_and_one_it_reads_but_cannot_be_held_is_uncarriable() {
    for raw in ["\"a\u{1}b\"", "W/\"a\u{7f}\"", "\"caf\u{e9}\"", "caf\u{e9}", "a\u{1}b"] {
        unreadable(Scalar::EntityTag, raw);
    }
    for raw in ["", "\"\"", "\"a\"b\"", "a\"b", "\""] {
        uncarriable(Scalar::EntityTag, raw);
    }
}

// ── the code each refusal is answered with ──────────────────────────────────────────────────

const fn text(element: &'static str, required: bool) -> Member {
    Member {
        element,
        arity: Arity::One,
        value: Value::Text(Scalar::Text),
        required,
        kept: true,
    }
}

/// `<Config>` skipping an unknown element and holding `<Rule>`, which refuses one and holds an
/// optional `<Note>`, and an `<Etag>` read as an entity tag.
static SHAPES: [Shape; 2] = [
    Shape {
        name: "Config",
        attribute: None,
        content: Content::Members {
            unknown: Unknown::Skip,
            members: &[
                Member {
                    element: "Rule",
                    arity: Arity::One,
                    value: Value::Shape(1),
                    required: false,
                    kept: true,
                },
                Member {
                    element: "Etag",
                    arity: Arity::One,
                    value: Value::Text(Scalar::EntityTag),
                    required: false,
                    kept: true,
                },
            ],
        },
    },
    Shape {
        name: "Rule",
        attribute: None,
        content: Content::Members {
            unknown: Unknown::Refuse,
            members: &[text("Note", false)],
        },
    },
];

static MISSING: Document = Document {
    roots: &["Config"],
    shapes: &SHAPES,
    empty: EmptyBody::Missing,
};

static REFUSED: Document = Document {
    roots: &["Config"],
    shapes: &SHAPES,
    empty: EmptyBody::Refused,
};

static ABSENT: Document = Document {
    roots: &["Config"],
    shapes: &SHAPES,
    empty: EmptyBody::Absent,
};

fn opened(reading: DocumentReading, body: &str, document: &'static Document) -> Result<(), ErrorCode> {
    let request = Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket?config")
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    let request = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_document_reading(reading);
    request_document(&view, body.as_bytes(), document)
        .map(|_| ())
        .map_err(|error| error.code().clone())
}

/// Positive — both readings open a document they both accept.
#[test]
fn a_document_both_readings_accept_opens_under_either() {
    for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
        assert_eq!(
            opened(reading, "<Config><Rule><Note>n</Note></Rule></Config>", &MISSING),
            Ok(()),
            "{reading:?}"
        );
    }
}

/// Negative — under the RustFS reading an unknown nested element, a repeated member and an
/// unreadable value are `MalformedXML`, where the tree reading opens the first two; an empty body
/// is what the document calls it (`MissingRequestBodyError`, `MalformedXML`, or `InvalidArgument`
/// for an absent document); an uncarriable value is `InvalidArgument`.
#[test]
fn n_each_refusal_of_the_rustfs_reading_carries_its_code() {
    let rustfs = DocumentReading::RustFs;
    for body in [
        "<Config><Rule><Other/></Rule></Config>",
        "<Config><Rule><Note>a</Note><Note>b</Note></Rule></Config>",
        "<Config><Etag>\"caf\u{e9}\"</Etag></Config>",
    ] {
        assert_eq!(opened(rustfs, body, &MISSING), Err(ErrorCode::MALFORMED_XML), "{body}");
    }
    for body in [
        "<Config><Rule><Other/></Rule></Config>",
        "<Config><Rule><Note>a</Note><Note>b</Note></Rule></Config>",
    ] {
        assert_eq!(opened(DocumentReading::Tree, body, &MISSING), Ok(()), "{body}");
    }
    assert_eq!(opened(rustfs, "", &MISSING), Err(ErrorCode::MISSING_REQUEST_BODY));
    assert_eq!(opened(rustfs, "", &REFUSED), Err(ErrorCode::MALFORMED_XML));
    assert_eq!(opened(rustfs, "", &ABSENT), Err(ErrorCode::INVALID_ARGUMENT));
    assert_eq!(
        opened(rustfs, "<Config><Etag>a\"b</Etag></Config>", &MISSING),
        Err(ErrorCode::INVALID_ARGUMENT)
    );
    assert_eq!(opened(DocumentReading::Tree, "", &ABSENT), Err(ErrorCode::MALFORMED_XML));
}

fn opened_under(reading: DocumentReading, body: &str, ceiling: Option<usize>) -> Result<(), ErrorCode> {
    let request = Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket?config")
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    let request = WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable");
    let view = MetaView::of(&request, TargetKind::Bucket)
        .expect("view")
        .with_document_reading(reading);
    let view = match ceiling {
        Some(bytes) => view.with_document_body_ceiling(bytes),
        None => view,
    };
    request_document(&view, body.as_bytes(), &MISSING)
        .map(|_| ())
        .map_err(|error| error.code().clone())
}

/// A document of `padding` bytes of white space between its root and its one rule.
fn padded(padding: usize) -> String {
    format!("<Config>{}<Rule><Note>n</Note></Rule></Config>", "\n".repeat(padding))
}

const MIB: usize = 1024 * 1024;

/// Positive — a view with a raised document ceiling opens a document past the S3 limits' 1 MiB
/// under either reading (rustfs/gateway#1173).
#[test]
fn a_document_past_one_mebibyte_opens_under_a_raised_ceiling() {
    for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
        assert_eq!(opened_under(reading, &padded(MIB + MIB / 2), Some(20 * MIB)), Ok(()), "{reading:?}");
    }
}

/// Negative — without a ceiling of its own, a view reads under the S3 limits and refuses the same
/// document `MalformedXML`, under either reading.
#[test]
fn n_a_document_past_one_mebibyte_is_malformed_without_a_raised_ceiling() {
    for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
        assert_eq!(
            opened_under(reading, &padded(MIB + MIB / 2), None),
            Err(ErrorCode::MALFORMED_XML),
            "{reading:?}"
        );
    }
}

/// Negative — a raised ceiling still bounds: a document past it is `MalformedXML`, and a zero
/// ceiling reads as the S3 limits, never as unlimited.
#[test]
fn n_a_raised_ceiling_still_bounds_and_zero_is_not_unlimited() {
    for reading in [DocumentReading::Tree, DocumentReading::RustFs] {
        assert_eq!(
            opened_under(reading, &padded(3 * MIB), Some(2 * MIB)),
            Err(ErrorCode::MALFORMED_XML),
            "{reading:?}"
        );
        assert_eq!(
            opened_under(reading, &padded(MIB + MIB / 2), Some(0)),
            Err(ErrorCode::MALFORMED_XML),
            "{reading:?}"
        );
    }
}
