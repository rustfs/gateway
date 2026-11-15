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

fn lifecycle_date_view() -> WireRequest<()> {
    let request = Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket?lifecycle")
        .header("host", "host.invalid")
        .header("x-amz-checksum-crc32", "AAAAAA==")
        .body(())
        .expect("a request");
    WireRequest::accept(request, &Limits::default()).expect("accepted request")
}

fn lifecycle_date_document(date: &str) -> String {
    format!(
        "<LifecycleConfiguration><Rule><ID>test</ID><Status>Enabled</Status>\
         <Expiration><Date>{date}</Date></Expiration></Rule></LifecycleConfiguration>"
    )
}

#[test]
fn lifecycle_date_capture_stays_with_one_dispatch() {
    use rustfs_gateway_types::dto::PutBucketLifecycleConfiguration as PutLifecycle;

    use crate::{OperationCodec, RequestBody, RequestContextView, SseEnforced};

    let request = lifecycle_date_view();
    let meta = MetaView::of(&request, TargetKind::Bucket)
        .expect("a bucket view")
        .with_document_reading(DocumentReading::RustFs);
    let body = |document: &str| RequestBody::Buffered(bytes::Bytes::copy_from_slice(document.as_bytes()));
    let direct = |document: &str| {
        PutLifecycle::decode(&meta, body(document))
            .err()
            .map(|error| error.code().clone())
    };
    let decode = |meta, document: &str, context| {
        let decoded = crate::static_dispatch::decode::<PutLifecycle>(meta, body(document))?;
        let authorized = crate::static_dispatch::authorize(decoded, &[]).expect("no derived resources");
        Ok::<_, crate::CodecError>(authorized.into_request(SseEnforced::empty_for_unit_test(), context))
    };
    let detached = || RequestContextView::detached(PutLifecycle::NAME);
    let first = lifecycle_date_document("2026-08-09T00:00:00+08:00");
    let second = lifecycle_date_document("2026-07-10T00:00:00-07:00");
    assert_eq!(direct(&first), Some(ErrorCode::INVALID_ARGUMENT));
    let first_handler = decode(&meta, &first, detached()).expect("first pipeline decode");
    assert_eq!(direct(&first), Some(ErrorCode::INVALID_ARGUMENT));
    let second_handler = decode(&meta, &second, detached()).expect("second pipeline decode");
    let first_dates = first_handler.context().lifecycle_request_dates().expect("first date facts");
    let second_dates = second_handler.context().lifecycle_request_dates().expect("second date facts");
    assert_eq!(first_dates.expiration(0), Some("2026-08-09T00:00:00.000000000+08:00"));
    assert_eq!(second_dates.expiration(0), Some("2026-07-10T00:00:00.000000000-07:00"));

    for xml in [
        first.replace("2026-08-09", "2026-02-30"),
        first.replace("<Date>", "<Unknown/><Date>"),
        first.replace("</Date>", "</Date><Unknown/>"),
        first.replace("</Date>", "</Date><Date>2026-07-10T00:00:00Z</Date>"),
    ] {
        assert_eq!(
            decode(&meta, &xml, detached()).expect_err("malformed document").code(),
            &ErrorCode::MALFORMED_XML
        );
        assert_eq!(direct(&xml), Some(ErrorCode::MALFORMED_XML));
        assert_eq!(direct(&first), Some(ErrorCode::INVALID_ARGUMENT));
    }
    let days = first.replace("<Date>2026-08-09T00:00:00+08:00</Date>", "<Days>30</Days>");
    let days_handler = decode(&meta, &days, detached()).expect("days-only pipeline decode");
    assert_eq!(
        days_handler
            .context()
            .lifecycle_request_dates()
            .and_then(|facts| facts.expiration(0)),
        None
    );
    let tree = MetaView::of(&request, TargetKind::Bucket).expect("a bucket view");
    let tree_handler =
        decode(&tree, &first, first_handler.context().clone_without_caller_secret()).expect("tree profile still reads the date");
    assert!(tree_handler.context().lifecycle_request_dates().is_none());
    let tree_handler = decode(&tree, &first, detached()).expect("tree decode from a fresh context");
    assert!(tree_handler.context().lifecycle_request_dates().is_none());
    assert!(
        RequestContextView::detached(PutLifecycle::NAME)
            .lifecycle_request_dates()
            .is_none()
    );
}

#[test]
fn lifecycle_date_capture_does_not_apply_to_the_object_lock_document_or_the_shared_view() {
    use rustfs_gateway_types::dto::{PutBucketLifecycleConfiguration as PutLifecycle, PutObjectRetention};

    use crate::{OperationCodec, RequestBody};

    let request = lifecycle_date_view();
    let meta = MetaView::of(&request, TargetKind::Bucket)
        .expect("a bucket view")
        .with_document_reading(DocumentReading::RustFs);
    let scoped = meta.with_lifecycle_date_capture();
    let xml = lifecycle_date_document("2026-08-09T00:00:00+08:00");
    let body = || RequestBody::Buffered(bytes::Bytes::copy_from_slice(xml.as_bytes()));
    std::thread::scope(|threads| {
        let direct = threads.spawn(|| PutLifecycle::decode(&meta, body()));
        PutLifecycle::decode(&scoped, body()).expect("the isolated view captures lifecycle dates");
        assert_eq!(
            direct.join().expect("parallel decoder").expect_err("direct refusal").code(),
            &ErrorCode::INVALID_ARGUMENT
        );
    });

    let retention = Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket/object?retention")
        .header("host", "host.invalid")
        .header("x-amz-checksum-crc32", "AAAAAA==")
        .body(())
        .expect("a request");
    let retention = WireRequest::accept(retention, &Limits::default()).expect("accepted request");
    let retention = MetaView::of(&retention, TargetKind::Object)
        .expect("an object view")
        .with_document_reading(DocumentReading::RustFs);
    let body = || {
        RequestBody::Buffered(bytes::Bytes::from_static(
            b"<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2026-08-09T00:00:00+08:00</RetainUntilDate></Retention>",
        ))
    };
    let handled =
        handler_request::<PutObjectRetention>(&retention, body(), crate::RequestContextView::detached(PutObjectRetention::NAME))
            .expect("retention offset reaches dispatch");
    assert_eq!(handled.context().object_lock_retain_until_offset_seconds(), Some(28_800));
    assert_eq!(
        handled.input().retention.retain_until_date,
        Some(Timestamp::parse("2026-08-08T16:00:00Z", TimestampFormat::Iso8601).expect("UTC instant"))
    );
    let error = PutObjectRetention::decode(&retention, body()).expect_err("direct decode refuses to drop the offset");
    assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
    let error = PutObjectRetention::decode(&retention.with_lifecycle_date_capture(), body())
        .expect_err("capture still refuses a different document");
    assert_eq!(error.code(), &ErrorCode::INVALID_ARGUMENT);
}

fn handler_request<O: crate::OperationCodec>(
    meta: &MetaView<'_>,
    body: crate::RequestBody,
    context: crate::RequestContextView,
) -> Result<crate::Req<O>, crate::CodecError> {
    let decoded = crate::static_dispatch::decode::<O>(meta, body)?;
    let authorized = crate::static_dispatch::authorize(decoded, &[]).expect("no derived resources");
    Ok(authorized.into_request(crate::SseEnforced::empty_for_unit_test(), context))
}

#[test]
fn retention_xml_preserves_offset_and_precision_with_strict_document_validation() {
    use rustfs_gateway_types::dto::PutObjectRetention;

    let request = Request::builder()
        .method("PUT")
        .uri("http://host.invalid/bucket/key?retention")
        .header("host", "host.invalid")
        .header("x-amz-checksum-crc32", "AAAAAA==")
        .body(())
        .expect("a request");
    let request = WireRequest::accept(request, &Limits::default()).expect("accepted request");
    let tree = MetaView::of(&request, TargetKind::Object).expect("an object view");
    let meta = MetaView::of(&request, TargetKind::Object)
        .expect("an object view")
        .with_document_reading(DocumentReading::RustFs);
    let fresh = || crate::RequestContextView::detached(PutObjectRetention::NAME);
    let body = |members: &str| crate::RequestBody::Buffered(bytes::Bytes::from(format!("<Retention>{members}</Retention>")));

    let date = "<RetainUntilDate>2026-12-31T23:50:00.123456789-00:30</RetainUntilDate>";
    let hidden_date = "<Unknown><RetainUntilDate>2027-01-01T00:00:00+10:00</RetainUntilDate></Unknown>";
    let handled = handler_request::<PutObjectRetention>(&meta, body(&format!("{hidden_date}{date}")), fresh())
        .expect("date reaches handler");
    assert_eq!(
        handled.input().retention.retain_until_date,
        Some(Timestamp::parse("2027-01-01T00:20:00.123456789Z", TimestampFormat::Iso8601).expect("UTC instant"))
    );
    let cloned = handled.context().clone_without_caller_secret();
    assert_eq!(cloned.object_lock_retain_until_offset_seconds(), Some(-1800));

    for malformed in [
        date.replace("2026-12-31", "2026-02-30"),
        date.replace("-00:30", "-00:60"),
        date.replace("-00:30", "-0030"),
        format!("{date}{date}"),
        format!("{date}</Unknown>"),
    ] {
        let error = handler_request::<PutObjectRetention>(&meta, body(&malformed), fresh()).expect_err("malformed retention");
        assert_eq!(error.code(), &ErrorCode::MALFORMED_XML, "{malformed}");
    }
    let missing =
        handler_request::<PutObjectRetention>(&meta, body(hidden_date), cloned).expect("an ignored wrapper supplies no date");
    assert_eq!(missing.context().object_lock_retain_until_offset_seconds(), None);
    let utc =
        handler_request::<PutObjectRetention>(&meta, body("<RetainUntilDate>2027-01-01T00:20:00Z</RetainUntilDate>"), fresh())
            .expect("UTC date decodes");
    assert_eq!(utc.context().object_lock_retain_until_offset_seconds(), Some(0));
    let default_profile =
        handler_request::<PutObjectRetention>(&tree, body(date), handled.context().clone_without_caller_secret())
            .expect("tree profile decodes dates");
    assert_eq!(default_profile.context().object_lock_retain_until_offset_seconds(), None);
}

#[test]
fn retention_header_preserves_offset_after_put_object_decode() {
    use rustfs_gateway_types::dto::{DeleteObject, PutObject};

    const HEADER: &str = "x-amz-object-lock-retain-until-date";
    let wire = |method: &str, dates: &[&str]| {
        let mut request = Request::builder()
            .method(method)
            .uri("http://host.invalid/bucket/key")
            .header("host", "host.invalid")
            .header("content-length", "0");
        for date in dates {
            request = request.header(HEADER, *date);
        }
        WireRequest::accept(request.body(()).expect("a request"), &Limits::default())
    };
    let put = |dates: &[&str], context: crate::RequestContextView, profile| {
        let request = wire("PUT", dates).expect("accepted request");
        let meta = MetaView::of(&request, TargetKind::Object)
            .expect("an object view")
            .with_empty_headers_absent()
            .with_document_reading(profile);
        handler_request::<PutObject>(&meta, crate::RequestBody::None, context)
    };
    let fresh = || crate::RequestContextView::detached(PutObject::NAME);
    let raw = "2027-01-01T01:00:00.987654321+0130";
    let handled = put(&[raw], fresh(), DocumentReading::RustFs).expect("compact offset date decodes");
    assert_eq!(
        handled.input().object_lock_retain_until_date,
        Some(Timestamp::parse("2026-12-31T23:30:00.987654321Z", TimestampFormat::Iso8601).expect("UTC instant")),
    );
    assert_eq!(handled.context().object_lock_retain_until_offset_seconds(), Some(5400));

    for dates in [
        &["2027-02-30T01:00:00+01:30"][..],
        &["2027-01-01T01:00:00+24:00"][..],
        &["2027-01-01T01:00:00+ab:00"][..],
        &[raw, raw][..],
    ] {
        let error = put(dates, fresh(), DocumentReading::RustFs).expect_err("unusable header");
        assert_eq!(error.member(), Some("ObjectLockRetainUntilDate"));
    }
    for (dates, profile) in [
        (&[][..], DocumentReading::RustFs),
        (&[""][..], DocumentReading::RustFs),
        (&[raw][..], DocumentReading::Tree),
    ] {
        let next = put(dates, handled.context().clone_without_caller_secret(), profile).expect("next request decodes");
        assert_eq!(next.context().object_lock_retain_until_offset_seconds(), None);
    }
    let other_request = wire("DELETE", &[raw]).expect("accepted request");
    let other = MetaView::of(&other_request, TargetKind::Object)
        .expect("an object view")
        .with_document_reading(DocumentReading::RustFs);
    let deleted =
        handler_request::<DeleteObject>(&other, crate::RequestBody::None, handled.context().clone_without_caller_secret())
            .expect("unrelated operation ignores the header");
    assert_eq!(deleted.context().object_lock_retain_until_offset_seconds(), None);
}
