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

//! The file part's length a declared body length fixes, read as legacy RustFS reads it
//! (`FormReader::declared_file_length`, rustfs/gateway#1167).
//!
//! Responsible for: the declared length less every byte before the file and the closing
//! `\r\n--boundary--\r\n` — however the head was framed, after a preamble and padding — and `None`
//! wherever nothing fixes it: before the file part, under the gateway grammar or without a
//! declared length, and for a declared length too short to hold what was read.
//! NOT responsible for: the file reader refusing a body that does not then end so (`form_legacy_edges.rs`).
//! Upstream: `rustfs-gateway-http`'s form reader. Downstream: nothing.

use rustfs_gateway_http::{FormGrammar, FormLimits, FormReader, FormStep};

use crate::support::form::{LEGACY, content_type, field, file, form};

/// Pushes `body` in `frame`-byte frames until the file part, returning the reader there.
fn at_file(body: &[u8], grammar: FormGrammar, frame: usize) -> FormReader {
    let mut reader = FormReader::with_grammar(&content_type(), FormLimits::default(), grammar).expect("a form content type");
    for piece in body.chunks(frame.max(1)) {
        if let FormStep::FileReached { .. } = reader.push(piece).expect("a readable head") {
            return reader;
        }
    }
    panic!("the form never reached its file part");
}

// ── positive — the length a declared body fixes ─────────────────────────────────────────────

/// Positive — the declared length fixes the file's exactly, after a preamble and padding and in
/// every framing.
#[test]
fn the_declared_length_fixes_the_file_length() {
    for preamble in ["", "preamble\r\n", "x"] {
        let mut body = preamble.as_bytes().to_vec();
        body.extend(form(&[
            field("key", "k"),
            field("x-amz-meta-a", "b"),
            file("a.txt", "the file content"),
        ]));
        for frame in [1, 7, 64, body.len()] {
            let reader = at_file(&body, LEGACY, frame);
            assert_eq!(
                reader.declared_file_length(body.len() as u64),
                Some("the file content".len() as u64),
                "{preamble:?} in {frame}-byte frames"
            );
        }
    }
}

/// Positive — an empty file is length zero.
#[test]
fn an_empty_file_is_length_zero() {
    let body = form(&[field("key", "k"), file("a.txt", "")]);
    assert_eq!(at_file(&body, LEGACY, body.len()).declared_file_length(body.len() as u64), Some(0));
}

// ── negative — wherever nothing fixes it ─────────────────────────────────────────────────────

/// Negative — the gateway grammar, and the legacy one without a declared length, fix nothing.
#[test]
fn n_only_the_legacy_grammar_with_a_declared_length_fixes_one() {
    let body = form(&[field("key", "k"), file("a.txt", "content")]);
    for grammar in [FormGrammar::Gateway, FormGrammar::LegacyRustfs { declared_length: false }] {
        assert_eq!(
            at_file(&body, grammar, body.len()).declared_file_length(body.len() as u64),
            None,
            "{grammar:?}"
        );
    }
}

/// Negative — before the file part there is no file to measure.
#[test]
fn n_no_length_before_the_file_part() {
    let body = form(&[field("key", "k"), file("a.txt", "content")]);
    let mut reader = FormReader::with_grammar(&content_type(), FormLimits::default(), LEGACY).expect("a form content type");
    let head = &body[..10];
    assert_eq!(reader.push(head), Ok(FormStep::NeedMore));
    assert_eq!(reader.declared_file_length(body.len() as u64), None);
}

/// Negative — a declared length that cannot hold the head and the closing delimiter fixes nothing.
#[test]
fn n_a_declared_length_too_short_fixes_nothing() {
    let body = form(&[field("key", "k"), file("a.txt", "content")]);
    let reader = at_file(&body, LEGACY, body.len());
    let exact = reader.declared_file_length(body.len() as u64).expect("a fixed length");
    let shortest = body.len() as u64 - exact;
    assert_eq!(reader.declared_file_length(shortest), Some(0));
    assert_eq!(reader.declared_file_length(shortest - 1), None);
    assert_eq!(reader.declared_file_length(0), None);
}
