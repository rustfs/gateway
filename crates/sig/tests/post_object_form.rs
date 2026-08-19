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

//! The two halves of POST Object joined: the form reader below, the policy authority here.
//!
//! Responsible for: `c-lim-0002` — a legal POST form is proved before it is read, and the ceiling
//! the file is read under is the one the policy's `content-length-range` named — and the `c-lim-0028`
//! composition through the real `PostPolicy` rather than through a stand-in.
//! NOT responsible for: the framing rules, which `crates/http/tests/form_limits.rs` owns; the
//! allocation bound, which `crates/http/tests/form_allocations.rs` measures; or the HTTP status a
//! refusal becomes, which needs the POST Object operation and does not exist yet.
//! Upstream: `rustfs-gateway-sig`, `rustfs-gateway-http`. Downstream: nothing.
//!
//! # Why this file is in `sig` and not in `http`
//!
//! `rustfs-gateway-http` cannot see a policy: the base64, the JSON, the conditions and the
//! signature comparison all live one layer up. So the ordering claim — *the policy is proved
//! before an object byte is read* — is only checkable where both halves are visible, and that is
//! here. Everything below drives the production reader and the production policy type; there is no
//! stand-in on either side.

use rustfs_gateway_http::{FileStep, FormLimits, FormReader, FormReject, FormStep};
use rustfs_gateway_sig::{PostPolicy, PostPolicyError, PostPolicyLimits, RequestNow, SigningKey};

const BOUNDARY: &str = "----RustFSPostObjectBoundary8kQm2Xz";

/// A policy whose `content-length-range` maximum is 1024 bytes.
///
/// Base64 of a document with an expiration, a bucket condition, a `starts-with` on `$key`, the
/// algorithm, credential and date conditions, and `["content-length-range",0,1024]`.
const POLICY: &str = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9LFsiY29udGVudC1sZW5ndGgtcmFuZ2UiLDAsMTAyNF1dfQ==";

/// HMAC-SHA256 of [`POLICY`] under [`SIGNING_KEY`], which is what a browser form carries.
const SIGNATURE: &str = "9eb4faefbe4e1bd23ee9f29b6a1a1cd07c2496e2e439394c7ff2823593e07e7e";

/// The derived SigV4 signing key the policy is proved against.
const SIGNING_KEY: [u8; 32] = [7u8; 32];

/// A moment before the policy's expiration.
const NOW: i64 = 1_440_938_160;

/// The `content-length-range` maximum written into [`POLICY`].
const POLICY_CEILING: u64 = 1024;

/// Builds a POST Object form: the five required fields, `bucket`, `key`, then the file.
fn form(signature: &str, file: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in [
        ("key", "uploads/${filename}"),
        ("bucket", "example-bucket"),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-amz-signature", signature),
        ("policy", POLICY),
    ] {
        body.extend_from_slice(
            format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes(),
        );
    }
    body.extend_from_slice(
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"report.txt\"\r\n\
             Content-Type: text/plain\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(file);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    body
}

/// What one exchange observed, in the order the observations were possible.
struct Observed {
    /// File bytes delivered at the moment the policy signature was compared.
    ///
    /// Read from the same counter the sink increments, not written down as a constant: a zero
    /// somebody typed is not an observation.
    delivered_at_proof: u64,
    /// How many body bytes the head reader had consumed when the policy was proved.
    consumed_at_proof: u64,
    /// Where the file content begins in the body.
    head_bytes: u64,
    /// File bytes delivered in total.
    delivered: u64,
    /// The ceiling `into_file` was given.
    ceiling: u64,
    /// The final key the policy resolved.
    final_key: String,
    /// How the read ended.
    outcome: Result<u64, FormReject>,
}

/// Drives one POST form through the production reader and the production policy authority.
///
/// The ordering is not asserted at the end — it is the only order in which this function can be
/// written. `PostPolicy::parse` needs the fields, which only exist once the reader has stopped;
/// `into_file` needs a ceiling, which only exists once the policy has been read; and the sink is
/// only reachable through the reader `into_file` returns.
fn exchange(body: &[u8], frame: usize) -> Result<Observed, PostPolicyError> {
    let mut reader = FormReader::new(&format!("multipart/form-data; boundary={BOUNDARY}"), FormLimits::default())
        .expect("a well-formed content type");
    // Declared before the proof so that what the proof-time assertion reads is this counter and
    // not a literal. Nothing can increment it yet, which is the claim — but the claim is checked
    // against the variable the sink writes to.
    let mut delivered = 0u64;
    let mut cursor = 0usize;

    // Phase one: the head. Nothing here can deliver a file byte — there is no sink to deliver it
    // to until `into_file` has been called.
    let file_offset = loop {
        assert!(cursor < body.len(), "the form ended before its file part");
        let take = frame.min(body.len() - cursor);
        let step = reader.push(&body[cursor..cursor + take]).expect("a legal form head");
        cursor += take;
        if let FormStep::FileReached { consumed } = step {
            break cursor - take + consumed;
        }
    };

    // Phase two: the proof. Every field the policy needs is in hand, and no object byte has been
    // read — which is the whole of s3s#473 stated as a sequence point.
    let fields: Vec<(&str, &str)> = reader.fields().iter().map(|field| (field.name(), field.value())).collect();
    let filename = reader.filename().unwrap_or_default();
    let policy = PostPolicy::parse(&fields, filename, PostPolicyLimits::default(), RequestNow::from_unix_seconds(NOW))?;
    policy.verify(&SigningKey::from_array(SIGNING_KEY))?;
    let delivered_at_proof = delivered;
    let consumed_at_proof = reader.bytes_seen();

    // Phase three: the read, under the ceiling the policy just produced.
    let ceiling = policy.read_ceiling();
    let final_key = policy.final_key().to_owned();
    let mut file = reader.into_file(ceiling).expect("the file part was reached");
    let mut outcome = Err(FormReject::IncompleteStream);
    let mut at = file_offset;
    while at < body.len() {
        let take = frame.min(body.len() - at);
        let mut sink = |bytes: &[u8]| delivered += bytes.len() as u64;
        match file.push(&body[at..at + take], &mut sink) {
            Ok(FileStep::Complete { file_bytes }) => {
                outcome = Ok(file_bytes);
                break;
            }
            Ok(FileStep::NeedMore) => {}
            Err(reject) => {
                outcome = Err(reject);
                break;
            }
        }
        at += take;
    }

    Ok(Observed {
        delivered_at_proof,
        consumed_at_proof,
        head_bytes: file_offset as u64,
        delivered,
        ceiling,
        final_key,
        outcome,
    })
}

/// Positive — `c-lim-0002`: a legal POST form is proved before its file is read, and the file is
/// read under the ceiling the policy named.
///
/// # What is and is not observed here
///
/// Observed: the policy parses and its signature matches while zero object bytes have been read;
/// the ceiling handed to the reader is the policy's `content-length-range` maximum and not the
/// deployment's 5 GiB; the file is delivered whole; and the policy's final bucket, key and size
/// check passes afterwards.
///
/// Not observed: a `200`. POST Object is not a routed operation on this branch — there is no entry
/// in `crates/core/tests/golden/route-table.txt` and none in `OPERATIONS.md` — so there is no
/// status to read, and inventing one by asserting against a hand-built response would be reporting
/// an intention as an observation. That half of `c-lim-0002` stays open against the P5 operation.
#[test]
fn c_lim_0002_a_post_form_is_proved_before_its_file_is_read() {
    let content = b"a report small enough for the policy to admit".to_vec();
    let observed = exchange(&form(SIGNATURE, &content), 13).expect("a legal, correctly signed form");

    assert_eq!(observed.delivered_at_proof, 0, "object bytes were delivered before the policy was proved");
    assert!(
        observed.consumed_at_proof < observed.head_bytes + 13,
        "when the policy was proved the reader had consumed {} bytes of a body whose head is {} \
         long: more than one transport frame of the file had already been taken in",
        observed.consumed_at_proof,
        observed.head_bytes
    );
    assert_eq!(
        observed.ceiling, POLICY_CEILING,
        "the file was read under {} rather than under the policy's {POLICY_CEILING}",
        observed.ceiling
    );
    assert_eq!(observed.outcome, Ok(content.len() as u64));
    assert_eq!(observed.delivered, content.len() as u64);
    assert_eq!(observed.final_key, "uploads/report.txt");
}

/// Negative — a form whose signature does not match delivers no object byte at all.
///
/// The direction that matters for s3s#473: the refusal happens at the proof, which is before the
/// only object that can read a file byte has been constructed. A reader that had already collected
/// the part would be reporting a refusal about bytes it was holding.
#[test]
fn a_form_with_a_wrong_signature_reads_no_object_byte() {
    let content = vec![b'x'; 512];
    let wrong = "0".repeat(64);
    let outcome = exchange(&form(&wrong, &content), 64);

    assert_eq!(outcome.err(), Some(PostPolicyError::SignatureMismatch));
}

/// Negative — `c-lim-0028` through the real policy: 1 KiB declared, 512 KiB sent, 1 KiB read.
///
/// The `crates/http` version of this case reads the ceiling out of a stand-in policy string. This
/// one takes it from `PostPolicy::read_ceiling`, so the number that bounds the read is the one the
/// production JSON parser found in `content-length-range`.
#[test]
fn c_lim_0028_the_policy_range_and_not_the_deployment_bounds_the_read() {
    let content = vec![b'y'; 512 * 1024];
    let observed = exchange(&form(SIGNATURE, &content), 4096).expect("a correctly signed form");

    assert_eq!(observed.ceiling, POLICY_CEILING);
    assert_eq!(observed.outcome, Err(FormReject::FileTooLarge));
    assert_eq!(
        observed.delivered, POLICY_CEILING,
        "{} bytes of a 512 KiB file reached the sink under a {POLICY_CEILING}-byte policy",
        observed.delivered
    );
}

/// Negative — the policy's own final check refuses a size the reader admitted.
///
/// Two ceilings, deliberately not merged: the reader's stops the read, and
/// `PostPolicy::enforce_final` re-checks the size that was actually stored. A pipeline that
/// dropped the second one would still pass every assertion above.
#[test]
fn the_policy_rechecks_the_size_the_reader_admitted() {
    let fields: Vec<(&str, &str)> = vec![
        ("key", "uploads/${filename}"),
        ("bucket", "example-bucket"),
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-amz-signature", SIGNATURE),
        ("policy", POLICY),
    ];
    let policy = PostPolicy::parse(&fields, "report.txt", PostPolicyLimits::default(), RequestNow::from_unix_seconds(NOW))
        .expect("a well-formed policy");

    assert!(
        policy
            .enforce_final("example-bucket", "uploads/report.txt", POLICY_CEILING)
            .is_ok()
    );
    assert_eq!(
        policy
            .enforce_final("example-bucket", "uploads/report.txt", POLICY_CEILING + 1)
            .err(),
        Some(PostPolicyError::EntityTooLarge)
    );
    assert_eq!(
        policy.enforce_final("other-bucket", "uploads/report.txt", 16).err(),
        Some(PostPolicyError::ConditionFailed)
    );
}
