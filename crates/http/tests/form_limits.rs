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

//! The POST Object form's ceilings, and the order in which they are decided.
//!
//! Responsible for: `c-lim-0007`, `c-lim-0028`, `c-lim-0029`, `c-lim-0030` and `c-lim-0031`, plus
//! the framing negatives that surround them.
//! NOT responsible for: *how much memory* the reader uses — an assertion about ordering is not an
//! assertion about the heap, and `form_allocations.rs` measures the heap instead of describing it.
//! Nor for policy semantics, which are `rustfs-gateway-sig`'s.
//! Upstream: `rustfs-gateway-http`. Downstream: nothing.

use rustfs_gateway_http::{FileReader, FormLimits, FormReader, FormReject, FormStep};

/// A boundary of a realistic length, so the delimiter-straddling arithmetic is exercised at the
/// size it will actually meet.
const BOUNDARY: &str = "----RustFSFormBoundaryUgKDlSmVe0Ep8Wd";

fn content_type() -> String {
    format!("multipart/form-data; boundary={BOUNDARY}")
}

/// Builds a `multipart/form-data` body one part at a time.
#[derive(Default)]
struct Form {
    body: Vec<u8>,
}

impl Form {
    fn field(mut self, name: &str, value: &[u8]) -> Self {
        self.body
            .extend_from_slice(format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes());
        self.body.extend_from_slice(value);
        self.body.extend_from_slice(b"\r\n");
        self
    }

    fn file(mut self, filename: &str, content: &[u8]) -> Self {
        self.body.extend_from_slice(
            format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n\
                 Content-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        self.body.extend_from_slice(content);
        self.body.extend_from_slice(b"\r\n");
        self
    }

    fn end(mut self) -> Vec<u8> {
        self.body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        self.body
    }
}

/// What one complete drive of a form produced.
struct Outcome {
    fields: Vec<(String, String)>,
    filename: Option<String>,
    file: Vec<u8>,
    file_bytes: u64,
    /// How many file bytes had reached the sink at the moment the file part was handed over.
    ///
    /// The whole point of the module under test is that this is zero: a policy that has not been
    /// read cannot bound a file that has.
    file_bytes_at_handoff: usize,
}

/// Drives a whole form through the reader, framing the body in `chunks` sizes cyclically.
///
/// `ceiling` is handed the reader at the moment the file part is reached — which is the ordering
/// under test written as a signature: there is no earlier point at which it *could* be called with
/// the fields in hand, and no later one at which the answer would still bound anything.
fn drive(body: &[u8], chunks: &[usize], limits: FormLimits, ceiling: &dyn Fn(&FormReader) -> u64) -> Result<Outcome, FormReject> {
    let mut reader = Some(FormReader::new(&content_type(), limits)?);
    let mut file: Option<FileReader> = None;
    let mut collected: Vec<u8> = Vec::new();
    let mut fields = Vec::new();
    let mut filename = None;
    let mut file_bytes_at_handoff = usize::MAX;
    let mut cursor = 0usize;
    let mut frame = 0usize;

    while cursor < body.len() {
        let want = chunks.get(frame % chunks.len()).copied().unwrap_or(1).max(1);
        let take = want.min(body.len() - cursor);
        frame += 1;
        let mut slice = &body[cursor..cursor + take];
        cursor += take;

        if let Some(head) = reader.take() {
            let mut head = head;
            match head.push(slice)? {
                FormStep::NeedMore => {
                    reader = Some(head);
                    continue;
                }
                FormStep::FileReached { consumed } => {
                    fields = head
                        .fields()
                        .iter()
                        .map(|field| (field.name().to_owned(), field.value().to_owned()))
                        .collect();
                    filename = head.filename().map(str::to_owned);
                    file_bytes_at_handoff = collected.len();
                    let bound = ceiling(&head);
                    file = Some(head.into_file(bound)?);
                    slice = &slice[consumed..];
                }
            }
        }

        let Some(reading) = file.as_mut() else {
            unreachable!("the reader is either reading the head or the file");
        };
        let mut sink = |bytes: &[u8]| collected.extend_from_slice(bytes);
        reading.push(slice, &mut sink)?;
    }

    match (reader, file) {
        (Some(head), _) => Err(head.finish()),
        (None, Some(reading)) => {
            let file_bytes = reading.finish()?;
            Ok(Outcome {
                fields,
                filename,
                file: collected,
                file_bytes,
                file_bytes_at_handoff,
            })
        }
        (None, None) => Err(FormReject::IncompleteStream),
    }
}

/// Drives a form in one frame, with the ceiling taken from the deployment limit alone.
fn drive_whole(body: &[u8], limits: FormLimits) -> Result<Outcome, FormReject> {
    drive(body, &[body.len().max(1)], limits, &|_| limits.max_file_bytes())
}

/// The `content-length-range` maximum a policy carries, as the tests write it.
///
/// Real policies are base64 JSON and are parsed by `rustfs-gateway-sig`; what this crate is
/// responsible for is that *whatever* number comes out of that parse is the number the file is read
/// under. So the tests use a policy whose ceiling is trivially readable, and `crates/sig` binds the
/// real one.
fn declared_ceiling(reader: &FormReader) -> u64 {
    reader
        .field("policy")
        .and_then(|policy| policy.strip_prefix("content-length-range:"))
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// c-lim-0002 (the half this crate owns) — order
// ---------------------------------------------------------------------------------------------

/// Positive — a legal form yields every text field before one file byte is read.
///
/// The `file_bytes_at_handoff` assertion is the one that matters. A reader that framed the parts
/// correctly but read them into a buffer first would satisfy every other line here.
#[test]
fn a_legal_form_hands_over_every_field_before_the_first_file_byte() {
    let body = Form::default()
        .field("key", b"uploads/report.pdf")
        .field("policy", b"content-length-range:4096")
        .field("x-amz-signature", b"9f8e7d")
        .file("report.pdf", b"the object content")
        .end();

    let outcome = drive(&body, &[7], FormLimits::default(), &declared_ceiling).expect("a legal form is accepted");

    assert_eq!(outcome.file_bytes_at_handoff, 0, "file bytes reached the sink before the policy did");
    assert_eq!(
        outcome.fields,
        vec![
            ("key".to_owned(), "uploads/report.pdf".to_owned()),
            ("policy".to_owned(), "content-length-range:4096".to_owned()),
            ("x-amz-signature".to_owned(), "9f8e7d".to_owned()),
        ]
    );
    assert_eq!(outcome.filename.as_deref(), Some("report.pdf"));
    assert_eq!(outcome.file, b"the object content");
    assert_eq!(outcome.file_bytes, 18);
}

// ---------------------------------------------------------------------------------------------
// c-lim-0007 — a frame boundary is not the end of the stream
// ---------------------------------------------------------------------------------------------

/// Negative — no framing of a complete form is ever read as a truncated one.
///
/// # What this stands in for
///
/// `multer`'s issue #71 is that `poll_next_field` read `.eof` — a fact about the *stream* — as a
/// fact about the *buffer*, so roughly one parse in a hundred answered `IncompleteStream` for a
/// form that was complete. Under a multi-threaded runtime it showed up as a flake; the defect was
/// never about threads.
///
/// For a sans-io reader the same confusion is a pure function of where the frames fall, so this
/// runs a thousand *different* framings rather than a thousand identical parses hoping a race
/// appears — every one of them must produce the identical result. They are spread over threads as
/// well, which is what would catch a reader that had reached for shared state.
#[test]
fn c_lim_0007_no_framing_of_a_complete_form_reads_as_a_truncated_one() {
    const RUNS: u64 = 1000;
    let body = Form::default()
        .field("key", b"uploads/${filename}")
        .field("policy", b"content-length-range:65536")
        .field("x-amz-signature", b"0123456789abcdef")
        .file("payload.bin", &(0..4096u32).map(|index| (index % 251) as u8).collect::<Vec<u8>>())
        .end();
    let expected = drive_whole(&body, FormLimits::default()).expect("the one-frame drive is the reference");

    let threads = 4u64;
    let mut handles = Vec::new();
    for thread in 0..threads {
        let body = body.clone();
        let expected_file = expected.file.clone();
        handles.push(std::thread::spawn(move || {
            let mut incomplete = 0u64;
            let mut mismatched = 0u64;
            let mut seed = 0x9E3779B97F4A7C15u64 ^ thread;
            for _ in 0..RUNS / threads {
                // A distinct framing per run, and one that includes frames far shorter than the
                // boundary — the case where a delimiter is split across three frames.
                let mut chunks = Vec::new();
                for _ in 0..8 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                    chunks.push(((seed >> 33) % 97) as usize + 1);
                }
                match drive(&body, &chunks, FormLimits::default(), &declared_ceiling) {
                    Ok(outcome) => {
                        if outcome.file != expected_file || outcome.file_bytes_at_handoff != 0 {
                            mismatched += 1;
                        }
                    }
                    Err(FormReject::IncompleteStream) => incomplete += 1,
                    Err(_) => mismatched += 1,
                }
            }
            (incomplete, mismatched)
        }));
    }

    let mut incomplete = 0u64;
    let mut mismatched = 0u64;
    let mut ran = 0u64;
    for handle in handles {
        let Ok((thread_incomplete, thread_mismatched)) = handle.join() else {
            panic!("a framing worker panicked");
        };
        incomplete += thread_incomplete;
        mismatched += thread_mismatched;
        ran += RUNS / threads;
    }

    assert_eq!(ran, RUNS, "the run count is part of the claim");
    assert_eq!(incomplete, 0, "{incomplete} of {ran} framings read a complete form as truncated");
    assert_eq!(mismatched, 0, "{mismatched} of {ran} framings disagreed with the one-frame drive");
}

/// Negative — a form that really is truncated is still reported as truncated.
///
/// The control for the case above. A reader that simply never answers `IncompleteStream` would
/// pass that one and is refused here.
#[test]
fn a_truncated_form_is_reported_as_incomplete() {
    let mut body = Form::default()
        .field("policy", b"content-length-range:4096")
        .file("payload.bin", b"partial content")
        .end();
    body.truncate(body.len() - 12);

    let outcome = drive(&body, &[9], FormLimits::default(), &declared_ceiling);
    assert_eq!(outcome.err(), Some(FormReject::IncompleteStream));
}

// ---------------------------------------------------------------------------------------------
// c-lim-0028 — min(policy, deployment)
// ---------------------------------------------------------------------------------------------

/// Negative — a 1 KiB policy stops a much larger file at 1 KiB, not at the deployment ceiling.
///
/// The second assertion is the case: exactly `1024` bytes reached the sink. A reader that noticed
/// the violation after the part had been read would report the same rejection with the whole file
/// behind it.
#[test]
fn c_lim_0028_a_policy_ceiling_stops_the_file_at_the_policy_ceiling() {
    const POLICY_CEILING: usize = 1024;
    let content: Vec<u8> = (0..512 * 1024u32).map(|index| (index % 251) as u8).collect();
    let body = Form::default()
        .field("policy", format!("content-length-range:{POLICY_CEILING}").as_bytes())
        .file("payload.bin", &content)
        .end();

    let mut delivered = 0usize;
    let mut reader = FormReader::new(&content_type(), FormLimits::default()).expect("a well-formed content type");
    let FormStep::FileReached { consumed } = reader.push(&body).expect("the head parses") else {
        panic!("the file part was never reached");
    };
    assert_eq!(reader.field("policy"), Some("content-length-range:1024"));

    let ceiling = declared_ceiling(&reader);
    assert_eq!(ceiling, POLICY_CEILING as u64);
    let mut file = reader.into_file(ceiling).expect("the file part was reached");
    assert_eq!(file.ceiling(), POLICY_CEILING as u64, "min(policy, deployment) is the policy here");

    let mut sink = |bytes: &[u8]| delivered += bytes.len();
    let outcome = file.push(&body[consumed..], &mut sink);

    assert_eq!(outcome.err(), Some(FormReject::FileTooLarge));
    assert_eq!(
        delivered, POLICY_CEILING,
        "the reader delivered {delivered} bytes under a {POLICY_CEILING}-byte ceiling"
    );
    assert_eq!(file.file_bytes(), POLICY_CEILING as u64);
}

/// Negative — the deployment ceiling wins when it is the smaller of the two.
///
/// The other direction of `min`. Without it, `into_file` could be ignoring its argument entirely
/// and the case above would still pass.
#[test]
fn a_deployment_ceiling_below_the_policy_wins() {
    let limits = FormLimits::default().with_max_file_bytes(16);
    let content = vec![b'x'; 4096];
    let body = Form::default()
        .field("policy", b"content-length-range:4096")
        .file("payload.bin", &content)
        .end();

    let mut reader = FormReader::new(&content_type(), limits).expect("a well-formed content type");
    let FormStep::FileReached { consumed } = reader.push(&body).expect("the head parses") else {
        panic!("the file part was never reached");
    };
    let mut file = reader.into_file(4096).expect("the file part was reached");
    assert_eq!(file.ceiling(), 16);

    let mut delivered = 0usize;
    let mut sink = |bytes: &[u8]| delivered += bytes.len();
    assert_eq!(file.push(&body[consumed..], &mut sink).err(), Some(FormReject::FileTooLarge));
    assert_eq!(delivered, 16);
}

/// Positive — a file exactly at the ceiling is accepted.
///
/// The boundary in the other direction: an off-by-one that refused the last admissible byte would
/// pass every negative above.
#[test]
fn a_file_exactly_at_the_ceiling_is_accepted() {
    let content = vec![b'z'; 1024];
    let body = Form::default()
        .field("policy", b"content-length-range:1024")
        .file("payload.bin", &content)
        .end();

    let outcome = drive(&body, &[13], FormLimits::default(), &declared_ceiling).expect("a file at the ceiling is admitted");
    assert_eq!(outcome.file_bytes, 1024);
    assert_eq!(outcome.file, content);
}

// ---------------------------------------------------------------------------------------------
// c-lim-0029 — the policy field's own ceiling
// ---------------------------------------------------------------------------------------------

/// Negative — a 100 KiB `policy` field is refused, and never accumulated.
#[test]
fn c_lim_0029_an_oversized_policy_field_is_refused_by_name() {
    let policy = vec![b'p'; 100 * 1024];
    let body = Form::default().field("policy", &policy).file("payload.bin", b"content").end();

    let mut reader = FormReader::new(&content_type(), FormLimits::default()).expect("a well-formed content type");
    let outcome = reader.push(&body);

    assert_eq!(outcome.err(), Some(FormReject::PolicyTooLarge));
    assert_eq!(reader.current_field(), Some("policy"), "the operator's log line names the field");
    assert!(
        reader.bytes_seen() < 32 * 1024,
        "the reader consumed {} bytes of a 100 KiB field it had already decided to refuse",
        reader.bytes_seen()
    );
}

/// Negative — a `policy` at exactly the documented 20 KiB ceiling is still admitted.
#[test]
fn a_policy_field_at_the_documented_ceiling_is_admitted() {
    let policy = vec![b'p'; FormLimits::HARD_MAX_POLICY_BYTES];
    let body = Form::default().field("policy", &policy).file("payload.bin", b"content").end();

    let outcome = drive(&body, &[997], FormLimits::default(), &|_| 64).expect("a policy at the ceiling is admitted");
    assert_eq!(outcome.fields.len(), 1);
    assert_eq!(outcome.fields[0].1.len(), FormLimits::HARD_MAX_POLICY_BYTES);
}

/// Negative — no configuration can raise the policy ceiling above what AWS documents.
#[test]
fn the_policy_ceiling_cannot_be_configured_upwards() {
    let limits = FormLimits::default().with_max_policy_bytes(u32::MAX as usize);
    assert_eq!(limits.max_policy_bytes(), FormLimits::HARD_MAX_POLICY_BYTES);
}

/// Negative — an ordinary field over its own ceiling is refused as a field, not as a policy.
#[test]
fn an_oversized_ordinary_field_is_refused_as_a_field() {
    let limits = FormLimits::default().with_max_field_bytes(64);
    let body = Form::default()
        .field("success_action_redirect", &vec![b'u'; 4096])
        .file("payload.bin", b"content")
        .end();

    let mut reader = FormReader::new(&content_type(), limits).expect("a well-formed content type");
    assert_eq!(reader.push(&body).err(), Some(FormReject::FieldTooLarge));
    assert_eq!(reader.current_field(), Some("success_action_redirect"));
}

// ---------------------------------------------------------------------------------------------
// c-lim-0030 — the whole-form ceiling
// ---------------------------------------------------------------------------------------------

/// Negative — a form larger than the whole-stream budget is refused while it is still arriving.
#[test]
fn c_lim_0030_a_form_over_the_whole_stream_budget_is_refused() {
    let limits = FormLimits::default().with_max_whole_stream_bytes(4096);
    let body = Form::default()
        .field("policy", b"content-length-range:1048576")
        .file("payload.bin", &vec![b'q'; 64 * 1024])
        .end();

    let outcome = drive(&body, &[512], limits, &declared_ceiling);
    assert_eq!(outcome.err(), Some(FormReject::WholeStreamTooLarge));
}

/// Negative — the budget is spent by the text fields too, not only by the file.
///
/// Without this the whole-stream ceiling could be a second file ceiling wearing a different name.
#[test]
fn the_whole_stream_budget_counts_the_fields_as_well() {
    let limits = FormLimits::default().with_max_whole_stream_bytes(600);
    let body = Form::default()
        .field("one", &[b'a'; 200])
        .field("two", &[b'b'; 200])
        .field("three", &[b'c'; 200])
        .file("payload.bin", b"tiny")
        .end();

    let mut reader = FormReader::new(&content_type(), limits).expect("a well-formed content type");
    assert_eq!(reader.push(&body).err(), Some(FormReject::WholeStreamTooLarge));
    assert!(reader.filename().is_none(), "the file part was never reached");
}

/// Positive — the default whole-stream budget is above every ceiling it contains.
///
/// The shadowing check `limits.rs` documents at the query layer, applied here: a budget below one
/// of its own members would replace the specific refusal with the vague one.
#[test]
fn the_default_whole_stream_budget_is_above_what_it_contains() {
    let limits = FormLimits::default();
    assert!(limits.max_whole_stream_bytes() > limits.max_file_bytes());
    assert!(limits.max_whole_stream_bytes() > limits.max_policy_bytes() as u64);
    assert!(limits.max_whole_stream_bytes() > (limits.max_field_count() * limits.max_field_bytes()) as u64);
}

// ---------------------------------------------------------------------------------------------
// c-lim-0031 — `file` is last
// ---------------------------------------------------------------------------------------------

/// Negative — a form that puts `file` before `policy` is refused.
///
/// The two assertions together are the case: the form is refused, *and* the refusal is the
/// ordering one rather than an incidental framing complaint.
#[test]
fn c_lim_0031_a_field_after_the_file_part_is_refused() {
    let body = Form::default()
        .file("payload.bin", b"content that arrives too early")
        .field("policy", b"content-length-range:1048576")
        .field("x-amz-signature", b"0123456789abcdef")
        .end();

    let outcome = drive(&body, &[16], FormLimits::default(), &|_| FormLimits::DEFAULT_MAX_FILE_BYTES);
    assert_eq!(outcome.err(), Some(FormReject::FieldAfterFile));
}

/// Negative — the same form read in one frame is refused the same way.
///
/// Framing must not decide whether an ordering rule applies.
#[test]
fn a_field_after_the_file_part_is_refused_in_one_frame_too() {
    let body = Form::default()
        .file("payload.bin", b"content that arrives too early")
        .field("policy", b"content-length-range:1048576")
        .end();

    assert_eq!(drive_whole(&body, FormLimits::default()).err(), Some(FormReject::FieldAfterFile));
}

/// Negative — a form with no `file` part at all is refused rather than accepted as empty.
#[test]
fn a_form_without_a_file_part_is_refused() {
    let body = Form::default()
        .field("policy", b"content-length-range:1024")
        .field("x-amz-signature", b"0123456789abcdef")
        .end();

    assert_eq!(drive_whole(&body, FormLimits::default()).err(), Some(FormReject::MissingFile));
}

/// Negative — the file part cannot be entered before it has been announced.
///
/// The type's own claim, checked: `into_file` is the only door, and it refuses to open early.
#[test]
fn the_file_reader_cannot_be_built_before_the_file_part() {
    let reader = FormReader::new(&content_type(), FormLimits::default()).expect("a well-formed content type");
    assert_eq!(reader.into_file(1024).err(), Some(FormReject::MalformedPart));
}

// ---------------------------------------------------------------------------------------------
// Framing negatives
// ---------------------------------------------------------------------------------------------

/// Negative — a content type that is not `multipart/form-data` is refused.
#[test]
fn a_content_type_that_is_not_multipart_is_refused() {
    for content_type in [
        "application/octet-stream",
        "multipart/form-data",
        "multipart/form-data; boundary=",
        &format!("multipart/form-data; boundary={BOUNDARY}; boundary=other"),
        &format!("multipart/form-data; boundary={}", "b".repeat(71)),
        "multipart/form-data; boundary=\"has\ttab\"",
    ] {
        assert_eq!(
            FormReader::new(content_type, FormLimits::default()).err(),
            Some(FormReject::MalformedContentType),
            "`{content_type}` was accepted"
        );
    }
}

/// Negative — a body that does not open on the boundary is refused rather than searched.
#[test]
fn a_preamble_before_the_first_delimiter_is_refused() {
    let mut body = b"this is a preamble\r\n".to_vec();
    body.extend_from_slice(&Form::default().field("policy", b"x").file("f", b"y").end());

    assert_eq!(drive_whole(&body, FormLimits::default()).err(), Some(FormReject::MalformedPart));
}

/// Negative — a part header block over its ceiling is refused as a header, not as a field.
#[test]
fn an_oversized_part_header_is_refused() {
    let limits = FormLimits::default().with_max_part_header_bytes(128);
    let filename = "n".repeat(4096);
    let body = Form::default().file(&filename, b"content").end();

    assert_eq!(drive_whole(&body, limits).err(), Some(FormReject::PartHeaderTooLarge));
}

/// Negative — a repeated field name is refused rather than resolved.
#[test]
fn a_repeated_field_name_is_refused() {
    let body = Form::default()
        .field("policy", b"content-length-range:16")
        .field("policy", b"content-length-range:1048576")
        .file("payload.bin", b"content")
        .end();

    assert_eq!(drive_whole(&body, FormLimits::default()).err(), Some(FormReject::DuplicateField));
}

/// Negative — more fields than the ceiling permits is refused.
#[test]
fn too_many_fields_is_refused() {
    let limits = FormLimits::default().with_max_field_count(2);
    let body = Form::default()
        .field("one", b"1")
        .field("two", b"2")
        .field("three", b"3")
        .file("payload.bin", b"content")
        .end();

    assert_eq!(drive_whole(&body, limits).err(), Some(FormReject::TooManyFields));
}

/// Negative — a field value carrying CR, LF or another control byte is refused.
#[test]
fn a_field_value_with_a_control_character_is_refused() {
    let body = Form::default()
        .field("success_action_redirect", b"https://example.test/\x00done")
        .file("payload.bin", b"content")
        .end();

    assert_eq!(drive_whole(&body, FormLimits::default()).err(), Some(FormReject::MalformedFieldValue));
}

/// Negative — a part with no `Content-Disposition`, or a malformed one, is refused.
#[test]
fn a_part_without_a_usable_disposition_is_refused() {
    for block in [
        "Content-Type: text/plain",
        "Content-Disposition: attachment; name=\"policy\"",
        "Content-Disposition: form-data",
        "Content-Disposition: form-data; name=policy",
        "Content-Disposition: form-data; name=\"policy\"; name=\"other\"",
    ] {
        let mut body = format!("--{BOUNDARY}\r\n{block}\r\n\r\nvalue\r\n").into_bytes();
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        assert_eq!(
            drive_whole(&body, FormLimits::default()).err(),
            Some(FormReject::MalformedPart),
            "`{block}` was accepted"
        );
    }
}

/// Negative — a delimiter followed by neither `\r\n` nor `--` is refused.
#[test]
fn a_delimiter_with_an_unknown_marker_is_refused() {
    let mut body = Form::default().field("policy", b"x").file("f", b"y").body;
    body.extend_from_slice(format!("--{BOUNDARY}??").as_bytes());

    assert_eq!(drive_whole(&body, FormLimits::default()).err(), Some(FormReject::MalformedPart));
}

/// Negative — a head parsed one byte at a time finds every delimiter that straddles a frame.
///
/// The head reader resumes each search where the last one stopped rather than re-scanning the
/// whole pending value, because a 20 KiB `policy` fed one byte per frame would otherwise cost
/// twenty thousand scans of twenty thousand bytes — a ceiling that bounds memory and not work.
/// Resuming is only correct if the search restarts far enough back to see a needle that straddles
/// the resume point, and one-byte frames put a straddle at every single position.
#[test]
fn a_head_framed_one_byte_at_a_time_finds_every_delimiter() {
    let body = Form::default()
        .field("key", b"uploads/report.pdf")
        .field("policy", b"content-length-range:4096")
        .field("x-amz-signature", b"9f8e7d")
        .file("report.pdf", b"the object content")
        .end();

    let outcome = drive(&body, &[1], FormLimits::default(), &declared_ceiling).expect("a legal form is accepted");
    assert_eq!(outcome.fields.len(), 3);
    assert_eq!(outcome.fields[1].1, "content-length-range:4096");
    assert_eq!(outcome.filename.as_deref(), Some("report.pdf"));
    assert_eq!(outcome.file, b"the object content");
}

/// Negative — file content that happens to contain the boundary text is not cut short by it.
///
/// The delimiter is `\r\n--boundary`; the same bytes without the leading CRLF are content. A
/// scanner that looked for the boundary alone would truncate this upload silently, which is the
/// worst available outcome: a stored object missing its tail and a `200` to say so.
#[test]
fn boundary_text_inside_the_file_is_content() {
    let mut content = b"before--".to_vec();
    content.extend_from_slice(BOUNDARY.as_bytes());
    content.extend_from_slice(b"after");
    let body = Form::default()
        .field("policy", b"content-length-range:4096")
        .file("payload.bin", &content)
        .end();

    for chunk in [1usize, 3, 17, 64, 4096] {
        let outcome = drive(&body, &[chunk], FormLimits::default(), &declared_ceiling)
            .unwrap_or_else(|reject| panic!("chunk {chunk} refused a legal form: {reject}"));
        assert_eq!(outcome.file, content, "chunk {chunk} truncated the file");
    }
}

/// Negative — a part header block over its ceiling is refused however the body is framed, even
/// when it arrives in the same frame as a large field before it.
///
/// The reader keeps what follows a field in its buffer, and after a `policy` that can be twenty
/// kibibytes: a header block found inside those bytes was once accepted whole at any size, while
/// the same body sent a byte at a time was refused, so the ceiling held only for some framings.
#[test]
fn an_oversized_part_header_after_a_large_field_is_refused_in_every_framing() {
    let body = Form::default()
        .field("policy", &vec![b'p'; 12 * 1024])
        .file(&"n".repeat(FormLimits::DEFAULT_MAX_PART_HEADER_BYTES), b"content")
        .end();

    for chunk in [1usize, 7, 4096, body.len()] {
        let outcome = drive(&body, &[chunk], FormLimits::default(), &|_| 1024);
        assert_eq!(outcome.err(), Some(FormReject::PartHeaderTooLarge), "{chunk}-byte frames");
    }
}
