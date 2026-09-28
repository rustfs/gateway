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

//! What a select or a restore hands a backend, and what its frames look like on the wire.
//!
//! Responsible for: proving that the members a select and a restore carry survive decoding into
//! the input a handler receives — the scan range, the progress switch, the version selector, the
//! nested select-on-restore query — and that the event-stream frames the facade exports are read
//! back correctly by a decoder that shares no code with the encoder.
//! NOT responsible for: what the validators decide (`rustfs-gateway-core`'s
//! `ops/shared/select.rs` and `ops/shared/restore.rs` inline tests), or what the wire answers
//! (`conformance/cases/select-restore/`).
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why this file exists
//!
//! Two reasons, and both are the same shape as `object_lock_intent.rs`'s.
//!
//! The first is that a decoded member nothing observes is invisible. The fixture's select answer
//! deliberately does not evaluate SQL, so the response cannot show whether every optional request
//! member survived; a restore likewise answers `202` whether or not its scan of the document kept
//! the version selector. The assertions below therefore read the decoded input directly.
//!
//! The second is the CRCs. `rustfs-gateway-core`'s own tests pin the frames against literal bytes
//! produced outside the workspace; this file goes the other way and *parses* the frames, with a
//! CRC-32 written here from the reflected polynomial and checked against the value every CRC
//! catalogue publishes. Two implementations that share no code and agree on the same two byte
//! ranges is the claim; an encoder validated by its own arithmetic is the claim it would be
//! otherwise, and that one is satisfied by a CRC over the wrong range.

use rustfs_gateway::{
    EVENT_STREAM_CONTENT_TYPE, EventKind, EventSequence, Limits, MetaView, OperationCodec, RequestBody, RestoreState,
    RestoreStatus, TargetKind, WireRequest, dto, encode_event, encode_exception, format_restore_status, parse_restore_status,
    stats_document,
};

// ── decoding a request ───────────────────────────────────────────────────────────────────────

/// A request as it reaches a decoder.
fn accepted(uri: &'static str) -> WireRequest<()> {
    let request = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "host.invalid")
        .body(())
        .expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

fn decoded_select(uri: &'static str, body: &str) -> dto::SelectObjectContentInput {
    let request = accepted(uri);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::SelectObjectContent::decode(&view, RequestBody::Buffered(body.as_bytes().to_vec().into()))
        .expect("a well-formed select is not a refusal")
}

fn decoded_restore(uri: &'static str, body: &str) -> dto::RestoreObjectInput {
    let request = accepted(uri);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path has both labels");
    dto::RestoreObject::decode(&view, RequestBody::Buffered(body.as_bytes().to_vec().into()))
        .expect("a well-formed restore is not a refusal")
}

const SELECT_URI: &str = "http://host.invalid/conf-select/rows.csv?select&select-type=2";
const RESTORE_URI: &str = "http://host.invalid/conf-restore/cold.txt?restore";

/// Every member of a select request reaches the handler, including the two optional ones.
///
/// The scan range and the progress switch are the two a `501` cannot see: the answer is the same
/// whether they arrived or not. Each expected value is derived from the document's own text, so a
/// binding that stopped populating its field turns this red rather than leaving it green.
#[test]
fn every_member_of_a_select_reaches_the_handler() {
    let body = "<SelectObjectContentRequest>\
                <Expression>SELECT s.a FROM S3Object s</Expression>\
                <ExpressionType>SQL</ExpressionType>\
                <RequestProgress><Enabled>true</Enabled></RequestProgress>\
                <InputSerialization><CSV><FileHeaderInfo>USE</FileHeaderInfo><FieldDelimiter>;</FieldDelimiter></CSV>\
                <CompressionType>GZIP</CompressionType></InputSerialization>\
                <OutputSerialization><JSON><RecordDelimiter>\n</RecordDelimiter></JSON></OutputSerialization>\
                <ScanRange><Start>7</Start><End>19</End></ScanRange>\
                </SelectObjectContentRequest>";
    let input = decoded_select(SELECT_URI, body);

    assert_eq!(input.bucket.as_str(), "conf-select");
    assert_eq!(input.key.as_str(), "rows.csv");
    assert_eq!(input.expression, "SELECT s.a FROM S3Object s");
    assert_eq!(input.expression_type, dto::ExpressionType::SQL);

    let progress = input.request_progress.as_ref().expect("the progress switch arrived");
    assert_eq!(progress.enabled, Some(true), "an enabled progress switch must not be dropped");

    let csv = input.input_serialization.csv.as_ref().expect("the CSV description arrived");
    assert_eq!(csv.field_delimiter.as_deref(), Some(";"), "a non-default delimiter must survive");
    assert_eq!(csv.file_header_info.as_ref(), Some(&dto::FileHeaderInfo::USE));
    assert_eq!(input.input_serialization.compression_type.as_ref(), Some(&dto::CompressionType::GZIP));
    assert!(input.input_serialization.json.is_none(), "only one format was named");

    assert!(input.output_serialization.json.is_some(), "the JSON output description arrived");
    assert!(input.output_serialization.csv.is_none());

    let range = input.scan_range.as_ref().expect("the scan range arrived");
    assert_eq!((range.start, range.end), (Some(7), Some(19)));
}

/// Negative — an absent scan range and an absent progress switch are distinguishable from
/// present ones.
///
/// The other direction, and the one that makes the case above mean something: a decoder that
/// hard-coded `Some(..)` would satisfy the first test and fail this, and one that hard-coded
/// `None` would do the reverse.
#[test]
fn n_an_absent_scan_range_is_not_an_empty_one() {
    let body = "<SelectObjectContentRequest>\
                <Expression>SELECT 1</Expression><ExpressionType>SQL</ExpressionType>\
                <InputSerialization><CSV></CSV></InputSerialization>\
                <OutputSerialization><CSV></CSV></OutputSerialization>\
                </SelectObjectContentRequest>";
    let input = decoded_select(SELECT_URI, body);
    assert!(input.scan_range.is_none(), "an omitted ScanRange is absent, not a zero window");
    assert!(input.request_progress.is_none(), "an omitted RequestProgress is absent, not disabled");
    assert!(
        input.input_serialization.compression_type.is_none(),
        "an omitted CompressionType is absent, so the documented default is the caller's to read"
    );
}

/// The version selector reaches the handler, and its absence is a different value.
///
/// A restore answers `202` whether or not the selector survived, so the response cannot see this
/// and the field is the only measurement available. Both directions are here because a binding
/// stuck on `Some(..)` satisfies the first half and one stuck on `None` satisfies the second.
#[test]
fn the_restore_version_selector_reaches_the_handler_in_both_directions() {
    let body = "<RestoreRequest><Days>1</Days></RestoreRequest>";
    let selected = decoded_restore("http://host.invalid/conf-restore/cold.txt?restore&versionId=v1", body);
    assert_eq!(selected.version_id.as_deref(), Some("v1"));

    let current = decoded_restore(RESTORE_URI, body);
    assert!(current.version_id.is_none(), "no selector means the current version");
}

/// A select-on-restore reaches the handler with its nested query intact.
///
/// The nested `SelectParameters` is four members deep inside a payload structure, and every one
/// of them has to arrive: the query, its type and both serializations. The output location is
/// what a caller reads the answer from, so a decoder that lost it would start a retrieval whose
/// result nobody can find.
#[test]
fn a_select_on_restore_reaches_the_handler_whole() {
    let body = "<RestoreRequest><Type>SELECT</Type>\
                <SelectParameters>\
                <InputSerialization><CSV><FileHeaderInfo>NONE</FileHeaderInfo></CSV></InputSerialization>\
                <ExpressionType>SQL</ExpressionType><Expression>SELECT * FROM S3Object</Expression>\
                <OutputSerialization><CSV></CSV></OutputSerialization>\
                </SelectParameters>\
                <OutputLocation><S3><BucketName>results</BucketName><Prefix>out/</Prefix></S3></OutputLocation>\
                <GlacierJobParameters><Tier>Bulk</Tier></GlacierJobParameters>\
                </RestoreRequest>";
    let input = decoded_restore(RESTORE_URI, body);
    let document = &input.restore_request;

    assert_eq!(document.r#type.as_ref(), Some(&dto::Type::SELECT));
    assert!(document.days.is_none(), "the select form carries no lifetime");
    let parameters = document.select_parameters.as_ref().expect("the nested query arrived");
    assert_eq!(parameters.expression, "SELECT * FROM S3Object");
    assert_eq!(parameters.expression_type, dto::ExpressionType::SQL);
    assert!(parameters.input_serialization.csv.is_some());
    assert!(parameters.output_serialization.csv.is_some());

    let location = document.output_location.as_ref().expect("the destination arrived");
    let s3 = location.s3.as_ref().expect("an S3 destination");
    assert_eq!(s3.bucket_name.as_str(), "results");
    assert_eq!(s3.prefix, "out/");

    let tier = document.glacier_job_parameters.as_ref().expect("the tier arrived");
    assert_eq!(tier.tier, dto::Tier::BULK);
}

/// The four restore outcomes reach a backend as data, not as numbers it has to remember.
///
/// Reachability through the facade, which is the whole reason the mapping is exported: a backend
/// outside this workspace has to be able to name the state and read the status back.
#[test]
fn the_restore_state_mapping_is_reachable_from_outside_the_workspace() {
    assert_eq!(RestoreState::Initiated.status(), Some(202));
    assert_eq!(RestoreState::AlreadyRestored.status(), Some(200));
    assert!(RestoreState::InProgress.error().is_some());
    assert!(RestoreState::NotArchived.error().is_some());

    let rendered = format_restore_status(&RestoreStatus::restored("Fri, 21 Dec 2012 00:00:00 GMT"));
    assert_eq!(rendered, "ongoing-request=\"false\", expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\"");
    assert_eq!(
        parse_restore_status(&rendered),
        Some(RestoreStatus::restored("Fri, 21 Dec 2012 00:00:00 GMT"))
    );
}

/// c-rst-0014 — [S] the public restore-status parser rejects malformed peer input.
///
/// Missing quotes is the mutation control for `q-restore-header-parser-0128`; the other entries
/// pin the same public boundary's separator, date, and size refusals.
#[test]
fn c_rst_0014_malformed_restore_header_is_rejected_through_public_api() {
    let quirk = "q-restore-header-parser-0128";
    let malformed = [
        "ongoing-request=true".to_owned(),
        "ongoing-request=\"false\",expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\"".to_owned(),
        "ongoing-request=\"false\", expiry-date=\"Sun, 31 Feb 2026 00:00:00 GMT\"".to_owned(),
        format!("ongoing-request=\"false\", expiry-date=\"{}\"", "A".repeat(4096)),
    ];
    for value in malformed {
        ::core::assert_eq!(parse_restore_status(&value), None, "{}: {value:?} must be refused", quirk);
    }
}

// ── reading the frames back ──────────────────────────────────────────────────────────────────

/// CRC-32/ISO-HDLC, written here rather than borrowed.
///
/// A bitwise implementation of the reflected polynomial, sharing no line with the table-driven
/// one the encoder reaches through `rustfs-gateway-types`. That independence is the point: two
/// implementations agreeing on the same two byte ranges is a measurement, and one implementation
/// agreeing with itself is not.
fn crc32(data: &[u8]) -> u32 {
    const POLYNOMIAL: u32 = 0xEDB8_8320;
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let carry = crc & 1;
            crc >>= 1;
            if carry != 0 {
                crc ^= POLYNOMIAL;
            }
        }
    }
    !crc
}

/// One message read off the wire, with both CRCs verified. Shared with `select_frame_records`.
pub(crate) struct Frame {
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) payload: Vec<u8>,
}

/// Reads the leading message out of `bytes`, returning it and whatever follows.
///
/// Every field is checked against the bytes rather than trusted: the declared total length must
/// be the frame's own length, both CRCs must cover exactly the ranges the framing appendix
/// specifies, and a header block that runs past its declared length is a refusal. A decoder that
/// skipped any of those would accept the mutations this file exists to catch.
fn read_frame(bytes: &[u8]) -> Result<(Frame, &[u8]), String> {
    if bytes.len() < 16 {
        return Err("a message is at least sixteen bytes".to_owned());
    }
    let total = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let headers_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    if total > bytes.len() {
        return Err(format!("the declared total {total} runs past the {} bytes available", bytes.len()));
    }
    let declared_prelude_crc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if crc32(&bytes[..8]) != declared_prelude_crc {
        return Err("the prelude CRC does not cover the eight prelude bytes".to_owned());
    }
    let message = &bytes[..total];
    let declared_message_crc =
        u32::from_be_bytes([message[total - 4], message[total - 3], message[total - 2], message[total - 1]]);
    if crc32(&message[..total - 4]) != declared_message_crc {
        return Err("the message CRC does not cover every byte before itself".to_owned());
    }
    if 16 + headers_len > total {
        return Err("the header block runs past the message".to_owned());
    }
    let mut cursor = &message[12..12 + headers_len];
    let mut headers = Vec::new();
    while !cursor.is_empty() {
        let name_len = usize::from(cursor[0]);
        if cursor.len() < 1 + name_len + 3 {
            return Err("a header runs past the block".to_owned());
        }
        let name = String::from_utf8(cursor[1..1 + name_len].to_vec()).map_err(|_| "a header name is not UTF-8".to_owned())?;
        let value_type = cursor[1 + name_len];
        if value_type != 7 {
            return Err(format!("header {name} is value type {value_type}, not a string"));
        }
        let value_len = usize::from(u16::from_be_bytes([cursor[2 + name_len], cursor[3 + name_len]]));
        let start = 4 + name_len;
        if cursor.len() < start + value_len {
            return Err("a header value runs past the block".to_owned());
        }
        let value =
            String::from_utf8(cursor[start..start + value_len].to_vec()).map_err(|_| "a header value is not UTF-8".to_owned())?;
        headers.push((name, value));
        cursor = &cursor[start + value_len..];
    }
    let payload = message[12 + headers_len..total - 4].to_vec();
    Ok((Frame { headers, payload }, &bytes[total..]))
}

/// Reads a whole stream, refusing anything a real client would.
pub(crate) fn read_stream(bytes: &[u8]) -> Result<Vec<Frame>, String> {
    let mut rest = bytes;
    let mut frames = Vec::new();
    while !rest.is_empty() {
        let (frame, remainder) = read_frame(rest)?;
        frames.push(frame);
        rest = remainder;
    }
    Ok(frames)
}

pub(crate) fn header_of<'a>(frame: &'a Frame, name: &str) -> Option<&'a str> {
    frame
        .headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// The independent digest is the published parameterisation.
///
/// Asserted first, because every claim below is measured with it: a second implementation of the
/// wrong CRC agrees with nothing useful.
#[test]
fn the_independent_digest_matches_the_published_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

/// A whole stream encodes and reads back, with both CRCs verified frame by frame.
#[test]
fn a_complete_stream_reads_back_frame_by_frame() {
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    sequence.records(b"a,b\n1,2\n", &mut out).expect("records first");
    sequence.cont(&mut out).expect("a keep-alive");
    sequence.stats(&stats_document(8, 8, 8), &mut out).expect("the accounting");
    sequence.end(&mut out).expect("the terminator");

    let frames = read_stream(&out).expect("an independent decoder reads the stream");
    let types: Vec<&str> = frames.iter().filter_map(|frame| header_of(frame, ":event-type")).collect();
    assert_eq!(types, ["Records", "Cont", "Stats", "End"]);

    for frame in &frames {
        assert_eq!(header_of(frame, ":message-type"), Some("event"));
    }
    assert_eq!(frames[0].payload, b"a,b\n1,2\n");
    assert_eq!(header_of(&frames[0], ":content-type"), Some("application/octet-stream"));
    assert!(frames[1].payload.is_empty(), "a keep-alive carries nothing");
    assert_eq!(
        String::from_utf8_lossy(&frames[2].payload),
        "<Stats><Details><BytesScanned>8</BytesScanned><BytesProcessed>8</BytesProcessed><BytesReturned>8</BytesReturned></Details></Stats>"
    );
    assert!(frames[3].payload.is_empty(), "the terminator carries nothing");
}

/// S3 Select puts an in-band failure entirely in three string headers.
/// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/RESTSelectObjectAppendix.html
#[test]
fn a_select_error_reads_back_as_headers_without_a_payload() {
    let mut out = Vec::new();
    encode_exception("ParseUnexpectedToken", "Unexpected token.", &mut out).expect("a small message");
    let frames = read_stream(&out).expect("an independent decoder reads the frame");
    assert_eq!(frames.len(), 1);
    assert_eq!(header_of(&frames[0], ":message-type"), Some("error"));
    assert_eq!(header_of(&frames[0], ":error-code"), Some("ParseUnexpectedToken"));
    assert_eq!(header_of(&frames[0], ":error-message"), Some("Unexpected token."));
    assert_eq!(frames[0].headers.len(), 3);
    assert!(frames[0].payload.is_empty());
}

#[test]
fn select_error_headers_preserve_utf8_at_the_wire_length_limit() {
    let maximum = "x".repeat(usize::from(u16::MAX) - 2) + "é";
    let remaining_header_space = "x".repeat(128 * 1024 - 55 - maximum.len());
    for (code, message) in [
        (maximum.as_str(), "Malformed CSV record."),
        ("CSVParsingError", maximum.as_str()),
        (maximum.as_str(), remaining_header_space.as_str()),
    ] {
        let mut out = Vec::new();
        encode_exception(code, message, &mut out).expect("each value fits the two-byte length");
        let frames = read_stream(&out).expect("both header values remain valid UTF-8");
        assert_eq!(frames.len(), 1);
        assert!(header_of(&frames[0], ":error-code") == Some(code), "error-code bytes changed");
        assert!(header_of(&frames[0], ":error-message") == Some(message), "error-message bytes changed");
        assert!(frames[0].payload.is_empty());
    }
}

/// Negative — every single-byte corruption of a frame is caught by one of the two CRCs.
///
/// The mutation this file was written for, applied exhaustively rather than at three chosen
/// offsets: flipping any bit of any byte must be refused. A decoder that checked neither CRC, or
/// checked one over the wrong range, passes some of these and is caught here.
#[test]
fn n_every_single_byte_corruption_of_a_frame_is_refused() {
    let mut out = Vec::new();
    encode_event(EventKind::Records, b"a,b\n", &mut out).expect("a small payload");
    read_stream(&out).expect("the unmodified frame reads back");

    for index in 0..out.len() {
        let mut corrupted = out.clone();
        corrupted[index] ^= 0x01;
        assert!(
            read_stream(&corrupted).is_err(),
            "flipping the low bit of byte {index} must be refused, and was not"
        );
    }
}

/// Negative — a prelude whose declared lengths disagree with the frame is refused.
///
/// Each field is mutated on its own and the prelude CRC is *recomputed* afterwards, so the
/// message survives the check the previous test relies on and has to be caught by the message
/// CRC or by the length arithmetic instead. Without the recomputation this would prove only that
/// the prelude CRC works, which the previous test already says.
#[test]
fn n_a_prelude_field_that_lies_about_the_frame_is_refused() {
    let mut out = Vec::new();
    encode_event(EventKind::Records, b"a,b\n", &mut out).expect("a small payload");

    for field in [0_usize, 4] {
        let mut corrupted = out.clone();
        let original = u32::from_be_bytes([
            corrupted[field],
            corrupted[field + 1],
            corrupted[field + 2],
            corrupted[field + 3],
        ]);
        corrupted[field..field + 4].copy_from_slice(&(original - 1).to_be_bytes());
        let repaired = crc32(&corrupted[..8]);
        corrupted[8..12].copy_from_slice(&repaired.to_be_bytes());
        assert!(
            read_stream(&corrupted).is_err(),
            "a prelude field at offset {field} that disagrees with the frame must be refused"
        );
    }
}

/// The content type a select response would carry is the one AWS names.
#[test]
fn the_stream_content_type_is_the_documented_one() {
    assert_eq!(EVENT_STREAM_CONTENT_TYPE, "application/vnd.amazon.event-stream");
}
