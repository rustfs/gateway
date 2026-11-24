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

//! Responsible for: verifying how sanitizing a multipart POST changes the recorded wire length.
//! NOT responsible for: parsing multipart input or sending the captured request.
//! Upstream: the corpus form sanitizer and the strict store validator.
//! Downstream: the corpus crate's unit tests.

#![allow(clippy::unwrap_used)]

use crate::schema::{Capture, Chunk, Entry, Sut};
use crate::{CORPUS_SCHEMA_VERSION, base64, redact, store};

const FIELD: &[u8] = b"--xyz\r\nContent-Disposition: form-data; name=\"signature\"\r\n\r\n";
const FILE_HEADER: &[u8] = b"\r\n--xyz\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\n";

fn capture(value: &[u8]) -> Entry {
    let field = [FIELD, value, FILE_HEADER].concat();
    let file = b"blob\r\n--xyz--\r\n";
    Entry {
        v: CORPUS_SCHEMA_VERSION,
        op: "PostObject".into(),
        src: "handwritten:gateway".into(),
        recorded: "2026-11-24".into(),
        capture: Capture::HeadFull,
        sut: Sut::None,
        method: "POST".into(),
        target: "/bucket".into(),
        headers: vec![
            ("Content-Type".into(), "multipart/form-data; boundary=xyz".into()),
            ("Content-Length".into(), (file.len() + field.len()).to_string()),
        ],
        chunks: Some(vec![
            Chunk::Data {
                bytes_b64: base64::encode(&field),
                delay_ms: None,
            },
            Chunk::Data {
                bytes_b64: base64::encode(file),
                delay_ms: Some(12),
            },
        ]),
        resp: None,
        redacted: vec![],
    }
}

#[test]
fn complete_forms_remain_replayable_when_a_replacement_shrinks_or_grows() {
    for value in [b"synthetic-form-signature".as_slice(), b"short"] {
        let mut entry = capture(value);
        let (key, declared) = entry.headers[1].clone();
        let expected = declared.parse::<usize>().unwrap() - value.len() + redact::PLACEHOLDER.len();
        assert_eq!(redact::sanitize(&mut entry), ["form:signature"]);
        assert_eq!(entry.headers[1], (key, expected.to_string()));
        store::check_declared_length(&entry).unwrap();
        redact::admit(&entry).unwrap();
        let sanitized = entry.clone();
        assert!(redact::sanitize(&mut entry).is_empty());
        assert_eq!(entry, sanitized);
    }
}

#[test]
fn ambiguous_incomplete_or_framed_captures_keep_their_length_headers() {
    for case in [
        "missing",
        "duplicate",
        "malformed",
        "truncated",
        "partial",
        "closed",
        "chunked",
        "aws-chunked",
        "invalid-data",
    ] {
        let mut entry = capture(b"synthetic-form-signature");
        match case {
            "missing" => {
                entry.headers.pop();
            }
            "duplicate" => entry.headers.push(entry.headers[1].clone()),
            "malformed" => entry.headers[1].1.insert(0, '+'),
            "truncated" => entry.headers[1].1 = "2048".into(),
            "partial" => entry.capture = Capture::HeadPartial,
            "closed" => entry.chunks.as_mut().unwrap().push(Chunk::Control {
                action: "half_close".into(),
                delay_ms: None,
                duration_ms: None,
            }),
            "chunked" => entry.headers.push(("Transfer-Encoding".into(), "chunked".into())),
            "aws-chunked" => entry.headers.push(("Content-Encoding".into(), "aws-chunked".into())),
            "invalid-data" => entry.chunks.as_mut().unwrap().push(Chunk::Data {
                bytes_b64: "!".into(),
                delay_ms: None,
            }),
            _ => unreachable!(),
        }
        let headers = entry.headers.clone();
        let _ = redact::sanitize(&mut entry);
        assert_eq!(entry.headers, headers, "{case}");
        if case == "truncated" {
            assert!(store::check_declared_length(&entry).is_err());
        }
    }
}

#[test]
fn a_replacement_cannot_fill_missing_wire_bytes() {
    let mut entry = capture(b"a");
    let original = entry.headers[1].1.parse::<usize>().unwrap();
    entry.headers[1].1 = (original + redact::PLACEHOLDER.len() - 1).to_string();
    assert!(store::check_declared_length(&entry).is_err());
    let _ = redact::sanitize(&mut entry);
    assert!(store::check_declared_length(&entry).is_err());
    assert!(redact::admit(&entry).is_err());
}

#[test]
fn an_unproven_field_end_across_timed_chunks_keeps_the_wire_length() {
    let mut entry = capture(b"synthetic-form-signature");
    let first = [FIELD, b"synthetic-form-signature\r\n"].concat();
    let second = [&FILE_HEADER[2..], b"blob\r\n--xyz--\r\n"].concat();
    entry.chunks = Some(vec![
        Chunk::Data {
            bytes_b64: base64::encode(&first),
            delay_ms: None,
        },
        Chunk::Data {
            bytes_b64: base64::encode(&second),
            delay_ms: Some(12),
        },
    ]);
    let original = entry.headers.clone();
    store::check_declared_length(&entry).unwrap();
    let _ = redact::sanitize(&mut entry);
    assert_eq!(entry.headers, original);
    assert!(store::check_declared_length(&entry).is_err());
}
