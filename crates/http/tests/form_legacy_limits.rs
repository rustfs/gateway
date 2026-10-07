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

//! The ceilings legacy RustFS reads a POST Object form under (`FormLimits::legacy_rustfs`,
//! rustfs/gateway#1173), each at its edge, and the gateway's own ceilings unchanged beside them.
//!
//! Responsible for: one field's value and the `policy` field at 1 MiB, one part's header block at
//! 1 MiB, every field's value together at 20 MiB, and 1000 parts with the `file` part counted —
//! each accepted exactly at its ceiling and refused one past it — and the default ceilings still
//! refusing what they refused.
//! NOT responsible for: the grammar (`form_grammar.rs`, `form_legacy_edges.rs`), the gateway's
//! own ceilings at their edges (`form_limits.rs`), or the refusal a client is sent (the gateway
//! crate's RustFS-profile POST suites).
//! Upstream: `rustfs-gateway-http`'s form reader. Downstream: nothing.
//!
//! Evidence: RustFS leaves its legacy stack's form limits at their defaults
//! (`rustfs/src/server/http.rs:166-173` at rustfs/rustfs@95268a3b9): 1 MiB per field, which also
//! bounds a part's header block, 20 MiB of field values together, and 1000 parts counted as they
//! are read, the `file` part included; past each the stack answers `400 MalformedPOSTRequest`.

use rustfs_gateway_http::{FormLimits, FormReader, FormReject, FormStep};

use crate::support::form::{LEGACY, content_type, field, file, form, part};

const MIB: usize = 1024 * 1024;

/// Reads the head of `body` under `limits` in frames of `frame` bytes, up to the file part.
fn head_framed(body: &[u8], limits: FormLimits, frame: usize) -> Result<usize, FormReject> {
    let mut reader = FormReader::with_grammar(&content_type(), limits, LEGACY)?;
    for piece in body.chunks(frame.max(1)) {
        if let FormStep::FileReached { .. } = reader.push(piece)? {
            return Ok(reader.fields().len());
        }
    }
    Err(reader.finish())
}

/// Reads the head of `body` whole and in 64 KiB frames, and requires both framings to agree.
fn head(body: &[u8], limits: FormLimits) -> Result<usize, FormReject> {
    let whole = head_framed(body, limits, body.len());
    assert_eq!(head_framed(body, limits, 64 * 1024), whole, "framings disagree");
    whole
}

fn value(bytes: usize) -> String {
    "v".repeat(bytes)
}

/// `count` fields of `bytes` each, then a file.
fn fields(count: usize, bytes: usize) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = (0..count)
        .map(|index| field(&format!("x-amz-meta-f{index}"), &value(bytes)))
        .collect();
    parts.push(file("a.txt", "c"));
    form(&parts)
}

// ── one field ────────────────────────────────────────────────────────────────────────────────

/// Positive — a field value of exactly 1 MiB is read whole.
#[test]
fn a_field_of_one_mebibyte_is_read() {
    assert_eq!(head(&fields(1, MIB), FormLimits::legacy_rustfs()), Ok(1));
}

/// Negative — one byte more is refused as a field too large.
#[test]
fn n_a_field_past_one_mebibyte_is_refused() {
    assert_eq!(head(&fields(1, MIB + 1), FormLimits::legacy_rustfs()), Err(FormReject::FieldTooLarge));
}

/// Positive — the `policy` field is held to the same 1 MiB, above AWS's 20 KiB.
#[test]
fn a_policy_field_of_one_mebibyte_is_read() {
    let body = form(&[field("policy", &value(MIB)), file("a.txt", "c")]);
    assert_eq!(head(&body, FormLimits::legacy_rustfs()), Ok(1));
}

/// Negative — and refused one byte past it.
#[test]
fn n_a_policy_field_past_one_mebibyte_is_refused() {
    let body = form(&[field("policy", &value(MIB + 1)), file("a.txt", "c")]);
    assert_eq!(head(&body, FormLimits::legacy_rustfs()), Err(FormReject::PolicyTooLarge));
}

/// Negative — the default ceilings are unchanged: an 8 KiB field and a 20 KiB policy, no more.
#[test]
fn n_the_default_ceilings_still_refuse_what_they_refused() {
    let limits = FormLimits::default();
    assert_eq!(head(&fields(1, 8 * 1024 + 1), limits), Err(FormReject::FieldTooLarge));
    let policy = form(&[field("policy", &value(20 * 1024 + 1)), file("a.txt", "c")]);
    assert_eq!(head(&policy, limits), Err(FormReject::PolicyTooLarge));
    assert_eq!(head(&fields(65, 1), limits), Err(FormReject::TooManyFields));
    assert_eq!(limits.max_fields_bytes(), None);
}

// ── every field together ─────────────────────────────────────────────────────────────────────

/// Positive — twenty fields of 1 MiB, 20 MiB of values together, are read.
#[test]
fn twenty_mebibytes_of_field_values_are_read() {
    assert_eq!(head(&fields(20, MIB), FormLimits::legacy_rustfs()), Ok(20));
}

/// Negative — one byte more across them is refused as the fields together too large.
#[test]
fn n_field_values_past_twenty_mebibytes_are_refused() {
    let mut parts: Vec<Vec<u8>> = (0..20)
        .map(|index| field(&format!("x-amz-meta-f{index}"), &value(MIB)))
        .collect();
    parts.push(field("x-amz-meta-last", "v"));
    parts.push(file("a.txt", "c"));
    assert_eq!(head(&form(&parts), FormLimits::legacy_rustfs()), Err(FormReject::FieldsTooLarge));
}

// ── parts ────────────────────────────────────────────────────────────────────────────────────

/// Positive — 999 fields and the file, 1000 parts, are read.
#[test]
fn a_thousand_parts_with_the_file_are_read() {
    assert_eq!(head(&fields(999, 1), FormLimits::legacy_rustfs()), Ok(999));
}

/// Negative — a thousandth field, the 1001st part, is refused.
#[test]
fn n_a_thousand_fields_and_the_file_are_refused() {
    assert_eq!(head(&fields(1000, 1), FormLimits::legacy_rustfs()), Err(FormReject::TooManyFields));
}

// ── one part's header block ──────────────────────────────────────────────────────────────────

/// A field whose header block, its terminating blank line included, is `bytes` long.
fn padded_header(bytes: usize) -> Vec<u8> {
    let disposition = "Content-Disposition: form-data; name=\"key\"";
    let filler = "X-Filler: ";
    // The block is the headers, a CRLF between them, and the CRLF CRLF that ends it.
    let fixed = disposition.len() + 2 + filler.len() + 4;
    let headers = format!("{disposition}\r\n{filler}{}", "f".repeat(bytes - fixed));
    let mut parts = vec![part(&headers, "k")];
    parts.push(file("a.txt", "c"));
    form(&parts)
}

/// Positive — a header block of exactly 1 MiB is read.
#[test]
fn a_header_block_of_one_mebibyte_is_read() {
    assert_eq!(head(&padded_header(MIB), FormLimits::legacy_rustfs()), Ok(1));
}

/// Negative — one byte more is refused as a header block too large, and the default refuses far
/// less.
#[test]
fn n_a_header_block_past_one_mebibyte_is_refused() {
    assert_eq!(
        head(&padded_header(MIB + 1), FormLimits::legacy_rustfs()),
        Err(FormReject::PartHeaderTooLarge)
    );
    assert_eq!(
        head(&padded_header(4 * 1024 + 1), FormLimits::default()),
        Err(FormReject::PartHeaderTooLarge)
    );
}
