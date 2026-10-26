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

//! Uploaded setup-part wire and ownership controls.
//!
//! Responsible for: exact payloads and returned ETags, complete preflight, and failure cleanup.
//! NOT responsible for: authored multipart writes, completion, or a target's multipart semantics.
//! Upstream: external fixture planning and lifecycle; downstream: `parts_peer` recording sockets.

#[path = "parts_peer.rs"]
mod peer;

use std::path::Path;

use crate::sut::{Sut, SutError};

use super::{ONE_UPLOAD, initiated, response, setup};
use peer::{Peer, Step, TestRoot};

const CASE: &str = "s-external-uploaded-parts";
const UPLOAD_TARGET: &str = "/fixture-multipart/one?uploadId=owned%2F%2B%20%26%3F";
const PART: &str = "[[multipart_uploads.parts]]\npart_number = 1\nbody = { utf8 = \"part\" }\ncapture_etag_as = \"part_etag\"\n";

fn control(line: impl Into<String>, reply: Vec<u8>) -> Step {
    Step::new(line, &[], reply)
}

fn bootstrap() -> Vec<Step> {
    vec![
        control("HEAD /fixture-multipart HTTP/1.1", response(404, "")),
        control("PUT /fixture-multipart HTTP/1.1", response(200, "")),
        control("POST /fixture-multipart/one?uploads HTTP/1.1", initiated("owned/+ &amp;?")),
    ]
}

fn part_line(number: i32) -> String {
    format!("PUT {UPLOAD_TARGET}&partNumber={number} HTTP/1.1")
}

fn uploaded(headers: &str) -> Vec<u8> {
    format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n{headers}\r\n").into_bytes()
}

fn part(number: i32, bytes: &[u8], reply: Vec<u8>) -> Step {
    Step::new(part_line(number), bytes, reply)
}

fn cleanup() -> Vec<Step> {
    vec![
        control(format!("DELETE {UPLOAD_TARGET} HTTP/1.1"), response(204, "")),
        control("DELETE /fixture-multipart HTTP/1.1", response(204, "")),
    ]
}

fn assert_environment(result: Result<(), SutError>, context: &str) {
    assert!(matches!(result, Err(SutError::Environment(_))), "{context}");
}

#[test]
fn setup_parts_send_exact_payloads_to_returned_upload_id() {
    let root = TestRoot::new();
    std::fs::write(root.path().join("part.bin"), [0x00, 0xff, 0x42]).expect("write binary part source");
    let payloads: [(&str, &[u8]); 6] = [
        ("{ utf8 = \"snow: \u{96ea}\" }", "snow: \u{96ea}".as_bytes()),
        ("{ hex = \"00ff42\" }", &[0x00, 0xff, 0x42]),
        ("{ file = \"part.bin\" }", &[0x00, 0xff, 0x42]),
        ("{ size = 5, fill = \"ab\" }", &[0xab; 5]),
        ("{ size = 5, fill = \"xyz\" }", b"xyzxy"),
        ("{ size = 4 }", &[0x00, 0x01, 0x02, 0x03]),
    ];
    let mut source = ONE_UPLOAD.to_owned();
    let mut steps = bootstrap();
    for (index, (payload, bytes)) in payloads.into_iter().enumerate() {
        let number = i32::try_from(index + 1).expect("small test part number");
        source.push_str(&format!("[[multipart_uploads.parts]]\npart_number = {number}\nbody = {payload}\n"));
        steps.push(part(number, bytes, uploaded("ETag: \"remote-part\"\r\n")));
    }
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(root.path());
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    let observed = peer.finish();
    observed.verify(&steps);
    assert!(prepared.is_ok(), "all declared payload sources must prepare successfully");
    assert!(finished.is_ok(), "populated uploads must abort before bucket deletion");
}

#[test]
fn missing_and_empty_part_bodies_remain_empty() {
    let source = format!(
        "{ONE_UPLOAD}[[multipart_uploads.parts]]\npart_number = 1\n\
         [[multipart_uploads.parts]]\npart_number = 2\nbody = {{ utf8 = \"\" }}\n\
         [[multipart_uploads.parts]]\npart_number = 3\nbody = {{ size = 0 }}\n"
    );
    let mut steps = bootstrap();
    for number in 1..=3 {
        steps.push(part(number, &[], uploaded("ETag: \"empty-part\"\r\n")));
    }
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    peer.finish().verify(&steps);
    assert!(prepared.is_ok(), "omitted and explicit empty bodies are legal setup parts");
    assert!(finished.is_ok(), "empty parts must use ordinary upload cleanup");
}

#[test]
fn part_boundaries_and_repeated_numbers_preserve_declaration_order() {
    let mut source = ONE_UPLOAD.to_owned();
    let mut steps = bootstrap();
    for (number, body) in [(10000, "first"), (1, "lower"), (10000, "replacement")] {
        source.push_str(&format!(
            "[[multipart_uploads.parts]]\npart_number = {number}\nbody = {{ utf8 = \"{body}\" }}\n"
        ));
        steps.push(part(number, body.as_bytes(), uploaded("ETag: \"numbered-part\"\r\n")));
    }
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    peer.finish().verify(&steps);
    assert!(prepared.is_ok(), "both part bounds and repeated part numbers are supported");
    assert!(finished.is_ok(), "repeated numbers do not create separate cleanup ownership");
}

#[test]
fn returned_etags_are_captured_verbatim_in_declaration_order_without_changing_ownership() {
    let source = format!(
        "{ONE_UPLOAD}[[multipart_uploads.parts]]\npart_number = 1\nbody = {{ utf8 = \"same\" }}\ncapture_etag_as = \"remote_upload\"\n\
         [[multipart_uploads.parts]]\npart_number = 1\nbody = {{ utf8 = \"same\" }}\ncapture_etag_as = \"part_etag\"\n\
         [[multipart_uploads.parts]]\npart_number = 2\nbody = {{ utf8 = \"same\" }}\ncapture_etag_as = \"part_etag\"\n"
    );
    let mut steps = bootstrap();
    steps.extend([
        part(1, b"same", uploaded("eTaG: \"opaque-upload-alias/+==\"\r\n")),
        part(1, b"same", uploaded("ETag: \"opaque-first-part\"\r\n")),
        part(2, b"same", uploaded("ETag: \"opaque-last-part\"\r\n")),
    ]);
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    peer.finish().verify(&steps);
    let captures = prepared.expect("capture overwrite must not reject a valid setup");
    assert_eq!(captures.get("remote_upload").map(String::as_str), Some("\"opaque-upload-alias/+==\""));
    assert_eq!(captures.get("part_etag").map(String::as_str), Some("\"opaque-last-part\""));
    assert!(finished.is_ok(), "capture contents must not replace the cleanup UploadId");
}

fn preflight_refusal(tail: &str, reason: &str) {
    // A wrongly contacted peer answers immediately; absence is not inferred from a read timeout.
    let peer = Peer::new(vec![control("UNEXPECTED HTTP/1.1", response(500, ""))]);
    let mut target = peer.target(Path::new("."));
    let result = target.prepare(CASE, Some(&setup(&format!("{ONE_UPLOAD}{tail}"))));
    peer.finish().verify(&[]);
    let error = result.expect_err("invalid part declaration must fail before remote contact");
    assert!(
        matches!(error, SutError::Environment(_)),
        "invalid part declaration must be an environment refusal"
    );
    assert!(
        error.to_string().contains(reason),
        "preflight must name the invalid field or payload, not reject the uploaded-parts capability"
    );
}

#[test]
fn invalid_part_shapes_are_rejected_before_contact() {
    for (parts, reason) in [
        ("parts = {}\n", "array"),
        ("parts = [1]\n", "table"),
        ("parts = [{}]\n", "part_number"),
        ("parts = [{ part_number = 0 }]\n", "part_number"),
        ("parts = [{ part_number = 10001 }]\n", "part_number"),
        ("parts = [{ part_number = \"1\" }]\n", "part_number"),
        ("parts = [{ part_number = 1, unknown = true }]\n", "unknown"),
        ("parts = [{ part_number = 1, capture_etag_as = \"\" }]\n", "capture_etag_as"),
        ("parts = [{ part_number = 1, capture_etag_as = 7 }]\n", "capture_etag_as"),
    ] {
        preflight_refusal(parts, reason);
    }
}

#[test]
fn a_late_invalid_part_payload_prevents_all_remote_mutation() {
    for payload in ["{}", "{ hex = \"0g\" }", "{ file = \"missing-part-source.bin\" }"] {
        preflight_refusal(
            &format!(
                "[[multipart_uploads.parts]]\npart_number = 1\nbody = {{ utf8 = \"valid\" }}\n\
                 [[multipart_uploads.parts]]\npart_number = 2\nbody = {payload}\n"
            ),
            "payload",
        );
    }
}

fn failed_part(reply: Vec<u8>, reason: Option<&str>) {
    let mut steps = bootstrap();
    steps.push(part(1, b"part", reply));
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&format!("{ONE_UPLOAD}{PART}"))));
    let observed = peer.finish();
    observed.require_request(&part_line(1));
    observed.verify(&steps);
    let finished = target.finish(CASE);
    let error = prepared.expect_err("invalid part response must fail preparation");
    assert!(
        matches!(error, SutError::Environment(_)),
        "failed part response is an environment refusal"
    );
    if let Some(reason) = reason {
        assert!(
            error.to_string().contains(reason),
            "part response refusal must identify the observed failure"
        );
    }
    assert!(finished.is_ok(), "the known upload must already be removed by rollback");
}

#[test]
fn non_successful_part_response_rolls_back_known_upload() {
    for status in [403, 500, 204] {
        failed_part(response(status, ""), Some(&status.to_string()));
    }
}

#[test]
fn missing_part_etag_rolls_back_known_upload() {
    failed_part(uploaded(""), Some("ETag"));
}

#[test]
fn empty_part_etag_rolls_back_known_upload() {
    failed_part(uploaded("ETag: \r\n"), Some("ETag"));
}

#[test]
fn duplicate_part_etags_are_not_silently_selected() {
    failed_part(uploaded("ETag: \"first\"\r\netag: \"second\"\r\n"), Some("ETag"));
}

#[test]
fn interrupted_part_response_aborts_the_known_upload() {
    failed_part(
        b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\nETag: \"incomplete\"\r\nConnection: close\r\n\r\nshort".to_vec(),
        None,
    );
}

#[test]
fn later_part_failure_stops_remaining_parts_and_rolls_back_uploads() {
    let source = format!(
        "{ONE_UPLOAD}{PART}[[multipart_uploads]]\nbucket = \"fixture-multipart\"\nkey = \"two\"\n\
         [[multipart_uploads.parts]]\npart_number = 1\nbody = {{ utf8 = \"second\" }}\n\
         [[multipart_uploads.parts]]\npart_number = 2\nbody = {{ utf8 = \"failure\" }}\n\
         [[multipart_uploads.parts]]\npart_number = 3\nbody = {{ utf8 = \"must-not-send\" }}\n"
    );
    let mut steps = bootstrap();
    steps.extend([
        part(1, b"part", uploaded("ETag: \"first-upload\"\r\n")),
        control("POST /fixture-multipart/two?uploads HTTP/1.1", initiated("second-id")),
        Step::new(
            "PUT /fixture-multipart/two?uploadId=second-id&partNumber=1 HTTP/1.1",
            b"second",
            uploaded("ETag: \"second-upload\"\r\n"),
        ),
        Step::new(
            "PUT /fixture-multipart/two?uploadId=second-id&partNumber=2 HTTP/1.1",
            b"failure",
            response(500, ""),
        ),
        control("DELETE /fixture-multipart/two?uploadId=second-id HTTP/1.1", response(204, "")),
    ]);
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let observed = peer.finish();
    observed.require_request("PUT /fixture-multipart/two?uploadId=second-id&partNumber=2 HTTP/1.1");
    observed.verify(&steps);
    let finished = target.finish(CASE);
    assert_environment(prepared.map(|_| ()), "the later part failure must fail setup");
    assert!(finished.is_ok(), "rollback must remove both known uploads in reverse order");
}

#[test]
fn failed_abort_retains_ownership_blocks_reuse_and_allows_retry() {
    let mut steps = bootstrap();
    steps.extend([
        part(1, b"part", uploaded("ETag: \"stored-part\"\r\n")),
        control(format!("DELETE {UPLOAD_TARGET} HTTP/1.1"), response(500, "")),
    ]);
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&format!("{ONE_UPLOAD}{PART}"))));
    let first = target.finish(CASE);
    let blocked_setup = target.prepare("s-next-part-setup", Some(&setup("")));
    let blocked_without_setup = target.prepare("s-next-part-without-setup", None);
    let retried = target.finish(CASE);
    let next = target.prepare("s-next-part-after-cleanup", None);
    let observed = peer.finish();
    observed.require_request(&part_line(1));
    observed.verify(&steps);
    assert!(prepared.is_ok(), "populated upload must prepare before its abort can fail");
    assert_environment(first, "failed abort must fail cleanup");
    assert_environment(blocked_setup.map(|_| ()), "failed abort must block another setup");
    assert_environment(blocked_without_setup.map(|_| ()), "failed abort must block reuse without setup");
    assert!(retried.is_ok(), "retained upload identity must support an exact cleanup retry");
    assert!(next.is_ok(), "successful cleanup must release the case for reuse");
}

#[test]
fn failed_upload_cleanup_still_cleans_unrelated_owned_bucket() {
    let source = format!("[[buckets]]\nname = \"fixture-unrelated\"\n{ONE_UPLOAD}{PART}");
    let mut steps = bootstrap();
    steps.splice(
        2..2,
        [
            control("HEAD /fixture-unrelated HTTP/1.1", response(404, "")),
            control("PUT /fixture-unrelated HTTP/1.1", response(200, "")),
        ],
    );
    steps.extend([
        part(1, b"part", response(500, "")),
        control(format!("DELETE {UPLOAD_TARGET} HTTP/1.1"), response(500, "")),
        control("DELETE /fixture-unrelated HTTP/1.1", response(204, "")),
    ]);
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let blocked = target.prepare("s-next-part-unresolved", None);
    let observed = peer.finish();
    observed.require_request(&part_line(1));
    observed.verify(&steps);
    let error = prepared.expect_err("failed part and rollback must fail preparation");
    assert!(error.to_string().contains("rollback"), "failed rollback must remain explicit");
    assert_environment(blocked.map(|_| ()), "unresolved populated upload must prevent reuse");
}

#[test]
fn uncaptured_part_does_not_require_a_response_etag() {
    let source = format!("{ONE_UPLOAD}[[multipart_uploads.parts]]\npart_number = 1\nbody = {{ utf8 = \"part\" }}\n");
    let mut steps = bootstrap();
    steps.push(part(1, b"part", uploaded("")));
    steps.extend(cleanup());
    let peer = Peer::new(steps.clone());
    let mut target = peer.target(Path::new("."));
    let prepared = target.prepare(CASE, Some(&setup(&source)));
    let finished = target.finish(CASE);
    peer.finish().verify(&steps);
    assert!(prepared.is_ok(), "an uncaptured part does not require an ETag response header");
    assert!(finished.is_ok(), "an uncaptured part must retain ordinary upload cleanup");
}
