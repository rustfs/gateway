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

//! The legacy RustFS form grammar (`FormGrammar::LegacyRustfs`) inside a part: every header block
//! and `Content-Disposition` shape the POST Object parser RustFS serves today accepts, and the
//! shapes it refuses.
//!
//! Responsible for: the `Content-Disposition` parameter grammar (quoted and bare values, a `;`
//! inside quotes, escapes kept as sent, unknown parameters such as `filename*`, which duplicate
//! wins), the part header block (the three fields read, the empty block, bare-LF lines), and the
//! field rules both grammars keep on the names that grammar reads.
//! NOT responsible for: a form's edges — preamble, padding, closing tail, boundary and
//! `Content-Type` — and the gateway grammar beside them (`form_legacy_edges.rs`); the gateway
//! grammar's own cases and the ceilings (`form_limits.rs`); heap use (`form_allocations.rs`); what
//! a POST Object stores from a legacy form (the gateway crate's `post_object_legacy_form.rs`); or
//! policy semantics (`rustfs-gateway-sig`).
//! Upstream: `rustfs-gateway-http`'s form reader, through `support::form`. Downstream: nothing.
//!
//! Evidence: RustFS main serves POST Object through the S3 stack its `Cargo.toml:318` pins
//! (rustfs/rustfs at `1e7065101d`); every expectation here is that stack's answer for the same
//! bytes, confirmed by running it. Ruling R8 of rustfs/backlog#1677, as amended on 2026-09-29: the
//! RustFS profile reads a form exactly as legacy RustFS does, in both directions.

use rustfs_gateway_http::FormReject;

use crate::support::form::*;

// ── positive — shapes legacy RustFS accepts ─────────────────────────────────────────────────

/// Positive — a `;` inside a quoted filename is part of the filename.
///
/// Browsers escape only CR, LF and `"` in a filename, so a file called `a;b.txt` arrives with the
/// `;` bare inside the quotes. Splitting the header on every `;` refused that upload as malformed.
#[test]
fn a_semicolon_inside_a_quoted_value_belongs_to_the_value() {
    let parsed = read(&content_type(), &with_file_disposition("form-data; name=\"file\"; filename=\"a;b.txt\""));
    assert_eq!(parsed.map(|parsed| parsed.filename), Ok(Some("a;b.txt".to_owned())));

    let parsed = read(
        &content_type(),
        &with_first_part("Content-Disposition: form-data; name=\"x-amz-meta-a;b\""),
    );
    assert_eq!(parsed.map(|parsed| parsed.fields[0].0.clone()), Ok("x-amz-meta-a;b".to_owned()));
}

/// Positive — an RFC 2231 `filename*` is an unknown parameter: ignored, whether or not a plain
/// `filename` is also present.
#[test]
fn an_extended_filename_parameter_is_ignored() {
    let alone = read(
        &content_type(),
        &with_file_disposition("form-data; name=\"file\"; filename*=UTF-8''%E2%82%AC%20rates.txt"),
    );
    assert_eq!(alone.map(|parsed| parsed.filename), Ok(None));

    let both = read(
        &content_type(),
        &with_file_disposition("form-data; name=\"file\"; filename=\"rates.txt\"; filename*=UTF-8''%E2%82%AC%20rates.txt"),
    );
    assert_eq!(both.map(|parsed| parsed.filename), Ok(Some("rates.txt".to_owned())));
}

/// Positive — bare (token) values are read like quoted ones, trimmed of spaces and tabs.
#[test]
fn bare_parameter_values_are_accepted() {
    let parsed = read(
        &content_type(),
        &form(&[
            part("Content-Disposition: form-data; name=key", "uploads/a.txt"),
            part("Content-Disposition: form-data; name = policy ;", "eyJ9"),
            part("Content-Disposition: form-data; name=file; filename=a b.txt", "content"),
        ]),
    )
    .expect("bare values are accepted");
    assert_eq!(
        parsed.fields,
        vec![
            ("key".to_owned(), "uploads/a.txt".to_owned()),
            ("policy".to_owned(), "eyJ9".to_owned())
        ]
    );
    assert_eq!(parsed.filename.as_deref(), Some("a b.txt"));
    assert_eq!(parsed.file, b"content");
}

/// Positive — a quoted value keeps its backslash escapes exactly as sent; an escaped quote does
/// not end the value.
#[test]
fn a_quoted_value_keeps_its_escapes() {
    let parsed = read(
        &content_type(),
        &with_file_disposition(r#"form-data; name="file"; filename="say \"hi\" \\ bye.txt""#),
    );
    assert_eq!(parsed.map(|parsed| parsed.filename), Ok(Some(r#"say \"hi\" \\ bye.txt"#.to_owned())));
}

/// Positive — the first `name` and the first `filename` win.
#[test]
fn the_first_of_two_parameters_wins() {
    let parsed = read(
        &content_type(),
        &with_file_disposition("form-data; name=\"file\"; filename=\"first.txt\"; name=\"key\"; filename=\"second.txt\""),
    );
    assert_eq!(parsed.map(|parsed| parsed.filename), Ok(Some("first.txt".to_owned())));
}

/// Positive — parameter names and the disposition type are case-insensitive, whitespace around
/// them is optional, and the parameters may come in any order.
#[test]
fn case_whitespace_and_order_do_not_matter() {
    let parsed = read(
        &content_type(),
        &with_file_disposition(" FORM-DATA ;\tFILENAME = \"a.txt\" ; Name=\"FILE\" "),
    )
    .expect("the file part is recognised");
    assert_eq!(parsed.filename.as_deref(), Some("a.txt"));
}

/// Positive — what follows a closing quote up to the next `;` is ignored, and so is a malformed
/// parameter after `name`.
#[test]
fn junk_after_a_value_and_a_malformed_tail_are_ignored() {
    let parsed = read(
        &content_type(),
        &form(&[
            part("Content-Disposition: form-data; name=\"key\"junk; size=3", "k"),
            part("Content-Disposition: form-data; name=\"acl\"; badparam", "private"),
            part("Content-Disposition: form-data; name=\"file\"; filename=\"a.txt\"; filename*", "c"),
        ]),
    )
    .expect("the ignorable parts of each disposition are ignored");
    assert_eq!(field_names(&parsed), ["key", "acl"]);
    assert_eq!(parsed.filename.as_deref(), Some("a.txt"));
}

/// Positive — an empty name is a field like any other, and bytes that are not UTF-8 in a parameter
/// nobody reads do not matter.
#[test]
fn an_empty_name_and_unread_non_utf8_parameters_are_accepted() {
    let mut body = part("Content-Disposition: form-data; name=\"\"", "anonymous");
    body.extend_from_slice(&form(&[
        [
            b"--".as_slice(),
            BOUNDARY.as_bytes(),
            b"\r\nContent-Disposition: form-data; name=\"key\"; note=\"\xff\xfe\"\r\n\r\nk\r\n",
        ]
        .concat(),
        file("a.txt", "c"),
    ]));
    let parsed = read(&content_type(), &body).expect("both parts are accepted");
    assert_eq!(field_names(&parsed), ["", "key"]);
}

/// Positive — of two `Content-Disposition` fields, the last one names the part.
#[test]
fn the_last_disposition_field_names_the_part() {
    let parsed = read(
        &content_type(),
        &with_first_part("Content-Disposition: form-data; name=\"first\"\r\ncontent-disposition: form-data; name=\"second\""),
    );
    assert_eq!(parsed.map(|parsed| parsed.fields[0].0.clone()), Ok("second".to_owned()));
}

/// Positive — a part may carry more than three header fields when its disposition is among the
/// first three; lines past the fourth are never read.
#[test]
fn surplus_header_fields_after_the_disposition_are_ignored() {
    let parsed = read(
        &content_type(),
        &with_first_part(
            "Content-Disposition: form-data; name=\"key\"\r\nX-One: 1\r\nX-Two: 2\r\nX-Three: 3\r\nnot a header line \x01",
        ),
    );
    assert_eq!(parsed.map(|parsed| parsed.fields[0].0.clone()), Ok("key".to_owned()));
}

/// Positive — header lines may end in a bare LF, and a bare-LF blank line ends the block there:
/// what follows it is the part's content, even though the block was found by the first CRLF CRLF
/// further on, here the end of the next part's header block.
#[test]
fn bare_lf_header_lines_are_accepted() {
    let mut body =
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\nX-Note: 1\n\nuploads/a.txt\r\n").into_bytes();
    body.extend_from_slice(&form(&[file("a.txt", "c")]));
    let parsed = read(&content_type(), &body).expect("bare-LF lines are accepted");
    assert_eq!(parsed.fields, vec![("key".to_owned(), "uploads/a.txt".to_owned())]);
    assert_eq!(parsed.file, b"c");
}

/// Positive — the same rule on the file part: its content starts after the bare-LF blank line,
/// and the CRLF CRLF that located the block is file content.
#[test]
fn a_bare_lf_file_header_block_hands_its_tail_to_the_file() {
    let body = form(&[
        field("key", "k"),
        format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"\n\nhello\r\n\r\nworld\r\n").into_bytes(),
    ]);
    let parsed = read(&content_type(), &body).expect("the file part is recognised");
    assert_eq!(parsed.filename, None);
    assert_eq!(parsed.file, b"hello\r\n\r\nworld");
}

// ── negative — shapes legacy RustFS refuses, and the bounds the new shapes stay under ─────────

/// Negative — a parameter before `name` that has no `=` swallows the text up to the next `=`, so
/// `name` is never seen and the part has no name.
#[test]
fn a_bare_word_before_name_hides_the_name() {
    let body = with_first_part("Content-Disposition: form-data; junk; name=\"key\"");
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
}

/// Negative — an unterminated quote ends the parameters where it starts, before `name` is read.
#[test]
fn an_unterminated_quote_leaves_the_part_without_a_name() {
    for headers in [
        "Content-Disposition: form-data; name=\"key",
        "Content-Disposition: form-data; name=\"key\\\"",
        "Content-Disposition: form-data; filename=\"a.txt; name=\"key\"",
    ] {
        assert_eq!(
            read(&content_type(), &with_first_part(headers)),
            Err(FormReject::MalformedPart),
            "{headers}"
        );
    }
}

/// Negative — a disposition that is not `form-data`, or names nothing, gives the part no name.
#[test]
fn a_disposition_without_a_form_data_name_is_refused() {
    for headers in [
        "Content-Disposition: attachment; name=\"key\"",
        "Content-Disposition: form-data",
        "Content-Disposition: form-data;",
        "Content-Disposition: form-data; filename=\"a.txt\"",
        "Content-Disposition: form-datax; name=\"key\"",
        "Content-Disposition: ; name=\"key\"",
        "Content-Disposition: form-data; =\"key\"",
        "Content-Type: text/plain",
    ] {
        assert_eq!(
            read(&content_type(), &with_first_part(headers)),
            Err(FormReject::MalformedPart),
            "{headers}"
        );
    }
}

/// Negative — a `name` or `filename` that is not UTF-8 is refused.
#[test]
fn a_name_or_filename_that_is_not_utf8_is_refused() {
    for disposition in [
        b"form-data; name=\"\xffkey\"".as_slice(),
        b"form-data; name=\"file\"; filename=\"\xfe.txt\"",
    ] {
        let mut body = format!("--{BOUNDARY}\r\nContent-Disposition: ").into_bytes();
        body.extend_from_slice(disposition);
        body.extend_from_slice(b"\r\n\r\nvalue\r\n");
        body.extend_from_slice(&form(&[file("a.txt", "c")]));
        assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart), "{disposition:?}");
    }
}

/// Negative — a later disposition that names nothing unnames the part, even after a good one.
#[test]
fn a_later_disposition_without_a_name_unnames_the_part() {
    let body = with_first_part("Content-Disposition: form-data; name=\"key\"\r\nContent-Disposition: attachment");
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
}

/// Negative — an earlier disposition whose name is not UTF-8 is refused even when a later one
/// would have named the part.
#[test]
fn every_disposition_read_must_be_utf8() {
    let mut body = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"").into_bytes();
    body.extend_from_slice(b"\xff\"\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nvalue\r\n");
    body.extend_from_slice(&form(&[file("a.txt", "c")]));
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
}

/// Negative — only the first three header fields are read, so a disposition in fourth place is
/// never seen.
#[test]
fn a_disposition_after_three_other_fields_is_not_read() {
    let body = with_first_part("X-One: 1\r\nX-Two: 2\r\nX-Three: 3\r\nContent-Disposition: form-data; name=\"key\"");
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
}

/// Negative — the first four header fields must be well formed: a folded line, a name with
/// leading whitespace or a space before its colon, a control byte in a value, or a line with no
/// colon is refused.
#[test]
fn a_malformed_header_field_is_refused() {
    for headers in [
        "Content-Disposition: form-data;\r\n name=\"key\"",
        " Content-Disposition: form-data; name=\"key\"",
        "Content-Disposition : form-data; name=\"key\"",
        "Content-Disposition: form-data; name=\"key\"\r\nX-Bad: a\x01b",
        "Content-Disposition: form-data; name=\"key\"\r\nno colon here",
        "Content-Disposition: form-data; name=\"key\"\r\nX-1: 1\r\nX-2: 2\r\nX-Bad\x02: 3",
    ] {
        assert_eq!(
            read(&content_type(), &with_first_part(headers)),
            Err(FormReject::MalformedPart),
            "{headers:?}"
        );
    }
}

/// Negative — a part `Content-Type` that is not UTF-8 is refused.
#[test]
fn a_part_content_type_that_is_not_utf8_is_refused() {
    let mut body = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"key\"\r\nContent-Type: text/").into_bytes();
    body.extend_from_slice(b"\xff\r\n\r\nvalue\r\n");
    body.extend_from_slice(&form(&[file("a.txt", "c")]));
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
}

/// Negative — a part whose header block is empty has no name, even if a disposition line follows
/// the blank line.
#[test]
fn an_empty_header_block_is_refused() {
    let mut body = format!("--{BOUNDARY}\r\n\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nvalue\r\n").into_bytes();
    body.extend_from_slice(&form(&[file("a.txt", "c")]));
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
    // Decided at the blank line itself, not by waiting for a header block that never ends.
    let cut = format!("--{BOUNDARY}\r\n\r\nvalue");
    assert_eq!(read(&content_type(), cut.as_bytes()), Err(FormReject::MalformedPart));
}

/// Negative — the new spellings still name fields that the duplicate and control-character rules
/// apply to.
#[test]
fn a_bare_name_is_still_subject_to_the_field_rules() {
    let duplicate = form(&[
        field("policy", "a"),
        part("Content-Disposition: form-data; name=POLICY", "b"),
        file("a.txt", "c"),
    ]);
    assert_eq!(read(&content_type(), &duplicate), Err(FormReject::DuplicateField));

    let control = form(&[
        part("Content-Disposition: form-data; name=key", "a\u{1}b"),
        file("a.txt", "c"),
    ]);
    assert_eq!(read(&content_type(), &control), Err(FormReject::MalformedFieldValue));
}

/// Negative — a control byte in a field name is refused even where legacy RustFS reads one: on a
/// part with more than three header fields, a bare LF inside the first field's line carries the
/// next line into the name, and legacy RustFS then stores a metadata key holding that LF. The
/// gateway refuses the part instead (fail closed; recorded as an open item on rustfs/backlog#1677).
#[test]
fn a_control_byte_carried_into_a_name_is_refused() {
    let body = form(&[
        part(
            "Content-Disposition: form-data; name=x-amz-meta-a\nX-A: 1\r\nX-B: 2\r\nX-C: 3\r\nX-D: 4",
            "v",
        ),
        file("a.txt", "c"),
    ]);
    assert_eq!(read(&content_type(), &body), Err(FormReject::MalformedPart));
}
