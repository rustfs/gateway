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

//! Byte-exact frames, and the order they are allowed to arrive in.
//!
//! Responsible for: proving the framing byte for byte — the two CRC ranges, the header block, the
//! five event types and the exception — and proving the order contract in both directions.
//! NOT responsible for: the sequence's use by anything real, because nothing in this workspace
//! sends a frame yet; nor for a decoder, which `crates/conformance` supplies independently.
//! Upstream: [`super`]. Downstream: nothing.
//!
//! Every expected value below is a **literal**, produced outside this workspace by an independent
//! CRC-32/ISO-HDLC implementation over the byte ranges the AWS framing appendix specifies. That
//! is the whole design of this file: a frame test that recomputes the digest with the encoder's
//! own primitive agrees with the encoder about a CRC over the wrong range, which is exactly the
//! defect that ships. The conformance crate reads the same frames back with a second independent
//! implementation, so the claim is checked from two directions that share no code.

use super::*;

/// Decodes a hex literal into bytes, so an expected frame reads as the wire does.
fn hex(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let text = core::str::from_utf8(pair).expect("the literal is ASCII");
        out.push(u8::from_str_radix(text, 16).expect("the literal is hexadecimal"));
    }
    out
}

/// The terminator, byte for byte.
///
/// 56 bytes: a 12-byte prelude, a 40-byte header block carrying `:message-type` and
/// `:event-type`, no payload, and the message CRC.
const END_FRAME: &str = "0000003800000028c1c684d4\
                         0d3a6d6573736167652d747970650700056576656e74\
                         0b3a6576656e742d74797065070003456e64\
                         cf97d392";

/// A keep-alive, byte for byte. Differs from the terminator only in the event name's length and
/// spelling, which is what makes the two CRCs a real discriminator.
const CONT_FRAME: &str = "00000039000000298ba19df2\
                          0d3a6d6573736167652d747970650700056576656e74\
                          0b3a6576656e742d74797065070004436f6e74\
                          9c864a0d";

/// A four-byte `Records` chunk, byte for byte, with its `:content-type`.
const RECORDS_FRAME: &str = "0000006900000055ea016f2e\
                             0d3a6d6573736167652d747970650700056576656e74\
                             0b3a6576656e742d747970650700075265636f726473\
                             0d3a636f6e74656e742d747970650700186170706c69636174696f6e2f6f637465742d73747265616d\
                             612c620a\
                             e367eb1d";

/// The accounting frame, byte for byte, including the document it carries.
const STATS_FRAME: &str = "000000d500000043cbe23f6a\
                           0d3a6d6573736167652d747970650700056576656e74\
                           0b3a6576656e742d7479706507000553746174730d3a636f6e74656e742d74797065070008746578742f786d6c\
                           3c53746174733e3c44657461696c733e3c42797465735363616e6e65643e313c2f42797465735363616e6e6564\
                           3e3c427974657350726f6365737365643e323c2f427974657350726f6365737365643e3c427974657352657475\
                           726e65643e333c2f427974657352657475726e65643e3c2f44657461696c733e3c2f53746174733e\
                           5a1bdc47";

/// An in-band exception, byte for byte. `:message-type` is `exception`, not `event`.
const EXCEPTION_FRAME: &str = "0000006d000000551f81c9ee\
                               0d3a6d6573736167652d74797065070009657863657074696f6e\
                               0f3a657863657074696f6e2d7479706507000f43535650617273696e674572726f72\
                               0d3a636f6e74656e742d74797065070008746578742f786d6c\
                               3c4572726f722f3e\
                               ba713e91";

/// The digest is the published parameterisation and not one of this project's invention.
///
/// If this ever moves, every frame above is wrong and every frame below is wrong in the same
/// direction, which is why it is asserted separately and first.
#[test]
fn the_digest_is_crc32_iso_hdlc() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

/// The terminator matches the independently computed bytes.
#[test]
fn the_end_frame_is_byte_exact() {
    let mut out = Vec::new();
    encode_event(EventKind::End, &[], &mut out).expect("no payload");
    assert_eq!(out, hex(END_FRAME));
}

/// The keep-alive matches, and is not the terminator.
///
/// The second assertion is the control: two frames that differ only in a header value must
/// differ in both CRCs, so a digest computed over a fixed range would fail one of them.
#[test]
fn the_cont_frame_is_byte_exact_and_differs_from_the_end_frame() {
    let mut out = Vec::new();
    encode_event(EventKind::Cont, &[], &mut out).expect("no payload");
    assert_eq!(out, hex(CONT_FRAME));
    assert_ne!(hex(CONT_FRAME), hex(END_FRAME));
}

/// A records chunk matches, content type and payload included.
#[test]
fn the_records_frame_is_byte_exact() {
    let mut out = Vec::new();
    encode_event(EventKind::Records, b"a,b\n", &mut out).expect("a small payload");
    assert_eq!(out, hex(RECORDS_FRAME));
}

/// The accounting frame and its document match.
#[test]
fn the_stats_frame_and_its_document_are_byte_exact() {
    let document = stats_document(1, 2, 3);
    assert_eq!(
        document,
        "<Stats><Details><BytesScanned>1</BytesScanned><BytesProcessed>2</BytesProcessed>\
         <BytesReturned>3</BytesReturned></Details></Stats>"
    );
    let mut out = Vec::new();
    encode_event(EventKind::Stats, document.as_bytes(), &mut out).expect("a small document");
    assert_eq!(out, hex(STATS_FRAME));
}

/// The progress document is the same three counters under the other root.
#[test]
fn the_progress_document_differs_from_the_stats_document_only_in_its_root() {
    assert_eq!(
        progress_document(4, 5, 6),
        "<Progress><Details><BytesScanned>4</BytesScanned><BytesProcessed>5</BytesProcessed>\
         <BytesReturned>6</BytesReturned></Details></Progress>"
    );
}

/// An exception frame matches, and says `exception` rather than `event`.
#[test]
fn the_exception_frame_is_byte_exact() {
    let mut out = Vec::new();
    encode_exception("CSVParsingError", "<Error/>", &mut out).expect("a small message");
    assert_eq!(out, hex(EXCEPTION_FRAME));
}

/// The prelude CRC covers eight bytes, and the message CRC covers everything before itself.
///
/// Read off the frame rather than off the encoder: the two ranges are recomputed here from the
/// literal bytes, so a change that widened either range fails this even if it also changed the
/// helper the encoder calls.
#[test]
fn the_two_crcs_cover_the_two_ranges_the_appendix_specifies() {
    let frame = hex(RECORDS_FRAME);
    let prelude = frame.get(..8).expect("a prelude");
    let declared_prelude_crc = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
    assert_eq!(crc32(prelude), declared_prelude_crc);

    let split = frame.len() - 4;
    let covered = frame.get(..split).expect("everything but the trailing digest");
    let declared_message_crc = u32::from_be_bytes([frame[split], frame[split + 1], frame[split + 2], frame[split + 3]]);
    assert_eq!(crc32(covered), declared_message_crc);

    // Negative, and the point of the whole file: the same digest over one byte more or one byte
    // fewer is a different number, so a CRC over the wrong range cannot pass by coincidence.
    assert_ne!(crc32(frame.get(..9).expect("nine bytes")), declared_prelude_crc);
    assert_ne!(crc32(frame.get(..7).expect("seven bytes")), declared_prelude_crc);
    assert_ne!(crc32(&frame), declared_message_crc);
}

/// The declared lengths describe the frame that was actually written.
#[test]
fn the_prelude_lengths_describe_the_frame() {
    let mut out = Vec::new();
    encode_event(EventKind::Records, b"a,b\n", &mut out).expect("a small payload");
    let total = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
    let headers = u32::from_be_bytes([out[4], out[5], out[6], out[7]]) as usize;
    assert_eq!(total, out.len());
    assert_eq!(out.len(), 16 + headers + 4);
}

/// Two frames appended to one buffer are two frames, not one longer one.
#[test]
fn frames_concatenate_without_a_separator() {
    let mut out = Vec::new();
    encode_event(EventKind::Cont, &[], &mut out).expect("no payload");
    encode_event(EventKind::End, &[], &mut out).expect("no payload");
    let mut expected = hex(CONT_FRAME);
    expected.extend_from_slice(&hex(END_FRAME));
    assert_eq!(out, expected);
}

/// Negative — a payload past the ceiling is refused, not truncated.
#[test]
fn n_a_payload_past_the_ceiling_is_refused() {
    let payload = vec![0_u8; MAX_PAYLOAD_BYTES + 1];
    let mut out = Vec::new();
    assert_eq!(
        encode_event(EventKind::Records, &payload, &mut out),
        Err(EventStreamError::PayloadTooLarge)
    );
    assert!(out.is_empty(), "a refused frame writes nothing");
}

/// A payload exactly at the ceiling is accepted — the other direction of the bound.
#[test]
fn a_payload_exactly_at_the_ceiling_is_accepted() {
    let payload = vec![0_u8; MAX_PAYLOAD_BYTES];
    let mut out = Vec::new();
    encode_event(EventKind::Records, &payload, &mut out).expect("the ceiling itself is legal");
    assert_eq!(u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize, out.len());
}

/// The legal order runs to completion and terminates.
#[test]
fn the_documented_order_is_accepted_end_to_end() {
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    sequence.records(b"one", &mut out).expect("records are legal first");
    sequence
        .progress(&progress_document(1, 1, 1), &mut out)
        .expect("progress interleaves");
    sequence.cont(&mut out).expect("a keep-alive interleaves");
    sequence.records(b"two", &mut out).expect("more records");
    sequence.stats(&stats_document(2, 2, 2), &mut out).expect("one accounting");
    sequence.end(&mut out).expect("one terminator");
    assert!(sequence.is_terminated());
    assert!(out.ends_with(&hex(END_FRAME)), "the stream ends with the terminator");
}

/// A stream with no records at all is still a complete stream.
#[test]
fn a_stream_with_no_records_still_terminates() {
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    sequence
        .stats(&stats_document(0, 0, 0), &mut out)
        .expect("an accounting with no records");
    sequence.end(&mut out).expect("a terminator");
    assert!(sequence.is_terminated());
}

/// Negative — records after the accounting are refused.
#[test]
fn n_records_after_the_accounting_are_refused() {
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    sequence.stats(&stats_document(0, 0, 0), &mut out).expect("an accounting");
    assert_eq!(sequence.records(b"late", &mut out), Err(EventStreamError::OutOfOrder));
    assert_eq!(sequence.progress("<Progress/>", &mut out), Err(EventStreamError::OutOfOrder));
    assert_eq!(sequence.cont(&mut out), Err(EventStreamError::OutOfOrder));
    sequence.end(&mut out).expect("still terminable");
}

/// Negative — a second accounting, and a terminator before one, are both refused.
#[test]
fn n_the_accounting_happens_exactly_once_and_before_the_terminator() {
    let mut out = Vec::new();
    let mut sequence = EventSequence::new();
    assert_eq!(sequence.end(&mut out), Err(EventStreamError::OutOfOrder), "no accounting yet");
    sequence
        .stats(&stats_document(0, 0, 0), &mut out)
        .expect("the first accounting");
    assert_eq!(
        sequence.stats(&stats_document(1, 1, 1), &mut out),
        Err(EventStreamError::OutOfOrder),
        "the second accounting"
    );
    sequence.end(&mut out).expect("a terminator");
    assert_eq!(sequence.end(&mut out), Err(EventStreamError::OutOfOrder), "the second terminator");
}

/// An exception terminates from either live phase, and nothing follows it.
#[test]
fn an_exception_terminates_from_either_phase() {
    let mut out = Vec::new();
    let mut early = EventSequence::new();
    early
        .exception("ParseUnexpectedToken", "<Error/>", &mut out)
        .expect("mid-scan");
    assert!(early.is_terminated());
    assert_eq!(early.end(&mut out), Err(EventStreamError::OutOfOrder));

    let mut late = EventSequence::new();
    late.stats(&stats_document(0, 0, 0), &mut out).expect("an accounting");
    late.exception("CSVParsingError", "<Error/>", &mut out)
        .expect("after the accounting");
    assert!(late.is_terminated());
    assert_eq!(
        late.exception("CSVParsingError", "<Error/>", &mut out),
        Err(EventStreamError::OutOfOrder),
        "a second exception"
    );
}

/// Negative — an unterminated sequence trips the debug assertion when it is dropped.
///
/// Runs only in a debug build, which is where `cargo test` runs. Written as a caught unwind
/// rather than `#[should_panic]` because the panic happens in `Drop`, and both directions are
/// asserted: a terminated sequence drops quietly.
#[test]
#[cfg(debug_assertions)]
fn n_dropping_an_unterminated_sequence_is_caught() {
    let unterminated = std::panic::catch_unwind(|| {
        let sequence = EventSequence::new();
        drop(sequence);
    });
    assert!(unterminated.is_err(), "an unterminated sequence must not drop quietly");

    let terminated = std::panic::catch_unwind(|| {
        let mut out = Vec::new();
        let mut sequence = EventSequence::new();
        sequence.stats(&stats_document(0, 0, 0), &mut out).expect("an accounting");
        sequence.end(&mut out).expect("a terminator");
        drop(sequence);
    });
    assert!(terminated.is_ok(), "a terminated sequence drops quietly");
}

/// The content type of the response, and of each event that carries one.
#[test]
fn the_content_types_are_the_documented_ones() {
    assert_eq!(EVENT_STREAM_CONTENT_TYPE, "application/vnd.amazon.event-stream");
    assert_eq!(EventKind::Records.content_type(), Some("application/octet-stream"));
    assert_eq!(EventKind::Stats.content_type(), Some("text/xml"));
    assert_eq!(EventKind::Progress.content_type(), Some("text/xml"));
    assert_eq!(EventKind::Cont.content_type(), None);
    assert_eq!(EventKind::End.content_type(), None);
}

/// Negative — a refusal message never carries a byte of what was being framed.
#[test]
fn n_a_refusal_message_is_a_constant() {
    for error in [EventStreamError::PayloadTooLarge, EventStreamError::OutOfOrder] {
        let text = error.message();
        assert!(!text.contains("SELECT"), "{text}");
        assert!(!text.is_empty());
        assert_eq!(text, error.to_string());
    }
}
