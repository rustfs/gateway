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

//! The legacy RustFS form grammar at the edges of a form: before the first boundary, on each
//! boundary line, and after the closing delimiter — and the gateway grammar, the default, unchanged
//! beside it.
//!
//! Responsible for: the preamble, transport padding, what may follow the closing delimiter with
//! and without a declared length, the boundary's characters and the request `Content-Type`
//! grammar, the prelude bound, the file name `${filename}` stands for, and that the gateway grammar
//! still reads each of those shapes as it did.
//! NOT responsible for: a part's header block and `Content-Disposition` (`form_grammar.rs`), the
//! gateway grammar's own cases and ceilings (`form_limits.rs`), or what a POST Object stores (the
//! gateway crate's `post_object_legacy_form.rs`).
//! Upstream: `rustfs-gateway-http`'s form reader. Downstream: nothing.
//!
//! Evidence: as `form_grammar.rs` states it.

use rustfs_gateway_http::{FormGrammar, FormLimits, FormReader, FormReject, FormStep};

use crate::support::form::*;

// ── positive — shapes legacy RustFS accepts ─────────────────────────────────────────────────

/// Positive — text before the first boundary is a preamble and is discarded, however it ends.
#[test]
fn a_preamble_before_the_first_boundary_is_skipped() {
    let tail = form(&[field("key", "k"), file("a.txt", "content")]);
    for preamble in [
        b"This is a multi-part message in MIME format.\r\n".as_slice(),
        b"\r\n",
        b"--",
        b"-- not quite the boundary --",
        b"x",
    ] {
        let body = [preamble, tail.as_slice()].concat();
        let parsed = read(&content_type(), &body).unwrap_or_else(|reject| panic!("{preamble:?}: {reject}"));
        assert_eq!(field_names(&parsed), ["key"], "{preamble:?}");
        assert_eq!(parsed.file, b"content", "{preamble:?}");
    }
}

/// Positive — spaces and tabs between a boundary and its line end are transport padding.
#[test]
fn transport_padding_after_a_boundary_is_skipped() {
    let body = [
        format!("--{BOUNDARY} \t \r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n").as_bytes(),
        format!("--{BOUNDARY}\t\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\ncontent\r\n").as_bytes(),
        format!("--{BOUNDARY}--\r\n").as_bytes(),
    ]
    .concat();
    let parsed = read(&content_type(), &body).expect("padding is accepted");
    assert_eq!(field_names(&parsed), ["key"]);
    assert_eq!(parsed.file, b"content");
}

/// Positive — a quoted parameter before `boundary` may hold `;` and `=` without being read as a
/// parameter of its own.
#[test]
fn a_quoted_parameter_is_one_parameter() {
    let content_type = format!("multipart/form-data; note=\"a;boundary=wrong\"; boundary=\"{BOUNDARY}\"; charset=utf-8");
    let body = form(&[field("key", "k"), file("a.txt", "c")]);
    assert_eq!(read(&content_type, &body).map(|parsed| parsed.file), Ok(b"c".to_vec()));
}

/// Positive — the file's name is its `filename`, or the part's own name as sent when it has none;
/// an empty `filename` stays empty.
///
/// `${filename}` in a `key` stands for this value. Legacy RustFS names a file part without a
/// `filename` after the part, so `uploads/${filename}` is stored as `uploads/file` there.
#[test]
fn the_file_name_falls_back_to_the_part_name() {
    for (disposition, expected) in [
        ("form-data; name=\"file\"; filename=\"a.txt\"", "a.txt"),
        ("form-data; name=\"File\"", "File"),
        ("form-data; name=FILE; filename*=UTF-8''a.txt", "FILE"),
        ("form-data; name=\"file\"; filename=\"\"", ""),
    ] {
        let body = with_file_disposition(disposition);
        let mut reader = legacy_reader(&content_type(), FormLimits::default()).expect("a well-formed content type");
        assert!(matches!(reader.push(&body), Ok(FormStep::FileReached { .. })), "{disposition}");
        assert_eq!(reader.file_name(), Some(expected), "{disposition}");
    }
    let reader = legacy_reader(&content_type(), FormLimits::default()).expect("a well-formed content type");
    assert_eq!(reader.file_name(), None, "no file part has been read");
}

/// Positive — the closing delimiter may be followed by padding before its CRLF when the request
/// did not declare its length (a chunked upload); with a declared length only the CRLF may follow.
#[test]
fn padding_after_the_close_is_accepted_without_a_declared_length() {
    let mut body = form(&[field("key", "k"), file("a.txt", "content")]);
    body.truncate(body.len() - 2);
    body.extend_from_slice(b" \t\r\n");
    let chunked = FormGrammar::LegacyRustfs { declared_length: false };
    for frame in [1, 3, body.len()] {
        let parsed = read_framed_under(&content_type(), &body, frame, chunked).expect("padding is accepted");
        assert_eq!(parsed.file, b"content", "{frame}");
    }
    assert_eq!(read(&content_type(), &body), Err(FormReject::ClosingNotLast));
}

/// Positive — the gateway grammar, the default, still accepts what it accepted: an epilogue after
/// the closing delimiter, a close with no CRLF, and a boundary outside RFC 2046's characters.
#[test]
fn the_gateway_grammar_still_accepts_what_the_legacy_one_refuses() {
    let mut epilogue = form(&[field("key", "k"), file("a.txt", "content")]);
    epilogue.extend_from_slice(b"an epilogue");
    let mut unterminated = form(&[field("key", "k"), file("a.txt", "content")]);
    unterminated.truncate(unterminated.len() - 2);
    for body in [epilogue, unterminated] {
        let parsed = read_framed_under(&content_type(), &body, body.len(), FormGrammar::Gateway);
        assert_eq!(parsed.map(|parsed| parsed.file), Ok(b"content".to_vec()));
    }
    let body = b"--a@b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nc\r\n--a@b--\r\n";
    let parsed = read_framed_under("multipart/form-data; boundary=a@b", body, body.len(), FormGrammar::Gateway);
    assert_eq!(parsed.map(|parsed| parsed.file), Ok(b"c".to_vec()));
}

/// Positive — of two `boundary` parameters the legacy grammar takes the first, where the gateway
/// grammar refuses the header.
#[test]
fn the_first_of_two_boundary_parameters_frames_the_form() {
    let content_type = format!("multipart/form-data; boundary={BOUNDARY}; boundary=other");
    let body = form(&[field("key", "k"), file("a.txt", "c")]);
    assert_eq!(read(&content_type, &body).map(|parsed| parsed.file), Ok(b"c".to_vec()));
    assert_eq!(
        FormReader::new(&content_type, FormLimits::default()).err(),
        Some(FormReject::MalformedContentType)
    );
}

// ── negative — shapes legacy RustFS refuses, and the bounds the new shapes stay under ─────────

/// Negative — the first occurrence of the boundary ends the preamble, even mid-line, and what
/// follows it must be a boundary line: there is no second search.
#[test]
fn the_first_boundary_occurrence_ends_the_preamble() {
    let tail = form(&[field("key", "k"), file("a.txt", "content")]);
    let body = [format!("preamble --{BOUNDARY}X\r\n").as_bytes(), tail.as_slice()].concat();
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
}

/// Negative — a body with no boundary at all is refused as malformed, not as truncated.
#[test]
fn a_body_without_a_boundary_is_malformed() {
    for body in [b"".as_slice(), b"no boundary here", b"--", b"-------"] {
        assert_eq!(read(&content_type(), body), Err(FormReject::MalformedPart), "{body:?}");
    }
}

/// Negative — padding must end in CRLF, and a boundary line may only continue with padding, CRLF
/// or the closing `--`.
#[test]
fn a_boundary_line_that_does_not_end_properly_is_refused() {
    for line in [" x\r\n", "\t\n", " \r", "\rx", "x\r\n", "-x", " --\r\n"] {
        let mut body = format!("--{BOUNDARY}{line}").into_bytes();
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n");
        body.extend_from_slice(&form(&[file("a.txt", "c")]));
        assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart), "{line:?}");
    }
}

/// Negative — the closing delimiter before any file is still a form without a file, with or
/// without a preamble.
#[test]
fn a_form_closed_before_its_file_is_still_refused() {
    for body in [
        format!("--{BOUNDARY}--\r\n"),
        format!("preamble\r\n--{BOUNDARY}--\r\n"),
        format!("--{BOUNDARY} \r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--{BOUNDARY}--"),
    ] {
        assert_eq!(read(&content_type(), body.as_bytes()), Err(FormReject::MissingFile), "{body:?}");
    }
}

/// Negative — a preamble and transport padding are spent from the whole-stream budget like any
/// other byte, so neither can be used to stream an unbounded body past the reader.
#[test]
fn a_preamble_and_padding_count_against_the_whole_stream_budget() {
    let limits = FormLimits::default().with_max_whole_stream_bytes(4096);
    let tail = form(&[field("key", "k"), file("a.txt", "content")]);
    let preamble = vec![b'p'; 8192];
    let mut reader = legacy_reader(&content_type(), limits).expect("a well-formed content type");
    assert_eq!(
        reader.push(&[preamble.as_slice(), tail.as_slice()].concat()).err(),
        Some(FormReject::WholeStreamTooLarge)
    );

    let mut body = format!("--{BOUNDARY}").into_bytes();
    body.extend_from_slice(&vec![b' '; 8192]);
    body.extend_from_slice(b"\r\n");
    let mut reader = legacy_reader(&content_type(), limits).expect("a well-formed content type");
    assert_eq!(reader.push(&body).err(), Some(FormReject::WholeStreamTooLarge));
}

/// Negative — a header block over the part-header ceiling is refused even when its lines end in
/// bare LF, and a long preamble never becomes a long header block.
#[test]
fn the_part_header_ceiling_still_holds() {
    let limits = FormLimits::default().with_max_part_header_bytes(128);
    let long = format!("Content-Disposition: form-data; name=\"key\"\nX-Pad: {}\n", "p".repeat(200));
    let body = form(&[part(&long, "k"), file("a.txt", "c")]);
    let mut reader = legacy_reader(&content_type(), limits).expect("a well-formed content type");
    assert_eq!(reader.push(&body).err(), Some(FormReject::PartHeaderTooLarge));

    let preamble = vec![b'p'; 4096];
    let body = [preamble.as_slice(), form(&[field("key", "k"), file("a.txt", "c")]).as_slice()].concat();
    let mut reader = legacy_reader(&content_type(), limits).expect("a well-formed content type");
    assert!(matches!(reader.push(&body), Ok(FormStep::FileReached { .. })));
}

/// Negative — an unterminated or trailing-garbage quoted parameter is not a boundary.
#[test]
fn a_malformed_quoted_parameter_is_refused() {
    for content_type in [
        format!("multipart/form-data; boundary=\"{BOUNDARY}"),
        format!("multipart/form-data; boundary=\"{BOUNDARY}\"x"),
        format!("multipart/form-data; note=\"unterminated; boundary={BOUNDARY}"),
    ] {
        assert_eq!(
            legacy_reader(&content_type, FormLimits::default()).err(),
            Some(FormReject::MalformedContentType),
            "{content_type}"
        );
    }
}

/// Negative — anything after the closing delimiter but its CRLF is refused: an epilogue, a second
/// CRLF, padding under a declared length, or a close that never ends its line.
#[test]
fn what_follows_the_closing_delimiter_is_refused() {
    let base = form(&[field("key", "k"), file("a.txt", "content")]);
    let close = base.len() - 2;
    for (tail, reject) in [
        (&b"\r\nan epilogue"[..], FormReject::ClosingNotLast),
        (b"\r\n\r\n", FormReject::ClosingNotLast),
        (b" \r\n", FormReject::ClosingNotLast),
        (b"\t\r\n", FormReject::ClosingNotLast),
        (b"\rx", FormReject::ClosingNotLast),
        (b"x", FormReject::ClosingNotLast),
        (b"--\r\n", FormReject::ClosingNotLast),
        (b"", FormReject::IncompleteStream),
        (b"\r", FormReject::IncompleteStream),
    ] {
        let body = [&base[..close], tail].concat();
        assert_eq!(read(&content_type(), &body), Err(reject), "{tail:?}");
    }
    let chunked = FormGrammar::LegacyRustfs { declared_length: false };
    let body = [&base[..close], b" \r\nx".as_slice()].concat();
    assert_eq!(
        read_framed_under(&content_type(), &body, body.len(), chunked),
        Err(FormReject::ClosingNotLast)
    );
}

/// Negative — a boundary outside RFC 2046's characters, or ending in a space, is refused, and so
/// is a `Content-Type` whose parameters the legacy header reader cannot read.
#[test]
fn a_boundary_or_content_type_legacy_rustfs_cannot_read_is_refused() {
    for content_type in [
        "multipart/form-data; boundary=\"a@b\"",
        "multipart/form-data; boundary=a*b",
        "multipart/form-data; boundary=\"semi;colon\"",
        "multipart/form-data; boundary=\"trailing \"",
        "multipart/form-data; boundary=a\"b",
        "multipart/form-data ; boundary=abc",
        "multipart/form-data;\tboundary=abc",
        "multipart/form-data; boundary = abc",
        "multipart/form-data; charset; boundary=abc",
    ] {
        assert_eq!(
            legacy_reader(content_type, FormLimits::default()).err(),
            Some(FormReject::MalformedContentType),
            "{content_type}"
        );
    }
}

/// Negative — the gateway grammar, the default, still refuses every shape the legacy grammar adds,
/// exactly as it did.
#[test]
fn the_gateway_grammar_still_refuses_what_the_legacy_one_adds() {
    let tail = form(&[field("key", "k"), file("a.txt", "c")]);
    for body in [
        with_file_disposition("form-data; name=\"file\"; filename=\"a;b.txt\""),
        with_file_disposition("form-data; name=\"file\"; filename*=UTF-8''a.txt"),
        form(&[part("Content-Disposition: form-data; name=key", "k"), file("a.txt", "c")]),
        [b"a preamble\r\n".as_slice(), tail.as_slice()].concat(),
        [format!("--{BOUNDARY} \r\n").as_bytes(), &tail[BOUNDARY.len() + 4..]].concat(),
    ] {
        assert_eq!(
            read_framed_under(&content_type(), &body, body.len(), FormGrammar::Gateway),
            Err(FormReject::MalformedPart),
            "{:?}",
            String::from_utf8_lossy(&body)
        );
    }
}

/// Negative — under the legacy grammar everything read before the file is bounded by
/// `FormLimits::max_prelude_bytes`: a preamble, or transport padding, longer than a form at every
/// ceiling could carry there is refused before authorization could ever run. A form within the
/// bound is read.
#[test]
fn a_preamble_or_padding_past_the_prelude_bound_is_refused() {
    let limits = FormLimits::default()
        .with_max_field_bytes(64)
        .with_max_policy_bytes(1024)
        .with_max_field_count(4)
        .with_max_part_header_bytes(256);
    let bound = usize::try_from(limits.max_prelude_bytes()).expect("a small bound");
    let tail = form(&[field("key", "k"), file("a.txt", "c")]);

    let within = [vec![b'p'; bound - 512], tail.clone()].concat();
    let mut reader = legacy_reader(&content_type(), limits).expect("a well-formed content type");
    assert!(matches!(reader.push(&within), Ok(FormStep::FileReached { .. })));

    // The refusal falls at the same byte however the body is framed.
    let preamble = [vec![b'p'; bound + 1], tail.clone()].concat();
    for frame in [1, 7, 50, preamble.len()] {
        let mut reader = legacy_reader(&content_type(), limits).expect("a well-formed content type");
        let refused = preamble.chunks(frame).find_map(|piece| reader.push(piece).err());
        assert_eq!(refused, Some(FormReject::PreludeTooLarge), "{frame}-byte frames");
    }

    let mut padded = format!("--{BOUNDARY}").into_bytes();
    padded.extend_from_slice(&vec![b' '; bound + 1]);
    padded.extend_from_slice(b"\r\n");
    let mut reader = legacy_reader(&content_type(), limits).expect("a well-formed content type");
    assert_eq!(reader.push(&padded).err(), Some(FormReject::PreludeTooLarge));

    // The gateway grammar has no preamble or padding, and its ceilings alone bound it.
    let mut reader = FormReader::new(&content_type(), limits).expect("a well-formed content type");
    assert!(matches!(reader.push(&tail), Ok(FormStep::FileReached { .. })));
}
