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

//! Responsible for: the whole-crate contract — what the redaction gate refuses, what the
//! fingerprint ignores, what the retention rule keeps, and what survives a case round trip.
//! Not responsible for: the corpus checked into `corpus/`, which the guard scripts own.
//! Upstream: `rustfs_gateway_corpus`.
//! Downstream: nothing; this is a leaf test target.
//!
//! Negative cases outnumber positive ones, as they must: every assertion here about a
//! refusal is the only thing standing between a recorded request and a repository leak.

use std::path::PathBuf;

use rustfs_gateway_corpus::base64;
use rustfs_gateway_corpus::case;
use rustfs_gateway_corpus::dedup;
use rustfs_gateway_corpus::redact;
use rustfs_gateway_corpus::schema::{self, Capture, Chunk, Entry, LoadError, Response, Sut};
use rustfs_gateway_corpus::store;

// A well-known AWS documentation example secret. It is 40 characters, mixed case, with a
// digit — the exact shape the scanner is built to refuse — and it authenticates nothing.
const EXAMPLE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn base_entry() -> Entry {
    Entry {
        v: schema::CORPUS_SCHEMA_VERSION,
        op: "PutObject".to_owned(),
        src: "client-matrix:boto3@1.42.96".to_owned(),
        recorded: "2026-09-02".to_owned(),
        capture: Capture::HeadFull,
        sut: Sut::GatewayFsReference,
        method: "PUT".to_owned(),
        target: "/bucket/key".to_owned(),
        headers: vec![
            ("host".to_owned(), "127.0.0.1:9000".to_owned()),
            (
                "x-amz-content-sha256".to_owned(),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
            ),
        ],
        chunks: None,
        resp: None,
        redacted: Vec::new(),
    }
}

fn with_header(name: &str, value: &str) -> Entry {
    let mut entry = base_entry();
    entry.headers.push((name.to_owned(), value.to_owned()));
    entry
}

fn with_body(text: &str) -> Entry {
    let mut entry = base_entry();
    entry.chunks = Some(vec![Chunk::Data {
        bytes_b64: base64::encode(text.as_bytes()),
        delay_ms: None,
    }]);
    entry
}

fn reasons(entry: &Entry) -> Vec<redact::Reason> {
    redact::scan(entry).into_iter().map(|finding| finding.reason).collect()
}

fn scratch_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("rustfs-gateway-corpus-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}

// ---------------------------------------------------------------------------
// Negative: the four vectors the gate exists to refuse.
// ---------------------------------------------------------------------------

#[test]
fn authorization_header_is_refused() {
    let entry = with_header(
        "authorization",
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260902/us-east-1/s3/aws4_request, \
         SignedHeaders=host;x-amz-date, \
         Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
    );
    let refusal = redact::admit(&entry).unwrap_err();
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::LiveCredentialField
                && finding.site == redact::Site::RequestHeader("authorization".to_owned())),
        "{refusal}"
    );
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::SigV4Signature),
        "{refusal}"
    );
}

#[test]
fn security_token_header_is_refused() {
    let entry = with_header("x-amz-security-token", "FwoGZXIvYXdzEBcaDLONGSESSIONTOKENVALUE==");
    let refusal = redact::admit(&entry).unwrap_err();
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::LiveCredentialField
                && finding.site == redact::Site::RequestHeader("x-amz-security-token".to_owned())),
        "{refusal}"
    );
}

#[test]
fn presigned_signature_query_parameter_is_refused() {
    let mut entry = base_entry();
    entry.target = "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900\
                    &X-Amz-Signature=1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
        .to_owned();
    let refusal = redact::admit(&entry).unwrap_err();
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::LiveCredentialField
                && finding.site == redact::Site::QueryParam("x-amz-signature".to_owned())),
        "{refusal}"
    );
}

#[test]
fn credential_in_a_body_field_is_refused() {
    let entry = with_body(&format!("{{\"aws_secret_access_key\": \"{EXAMPLE_SECRET}\"}}"));
    let refusal = redact::admit(&entry).unwrap_err();
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::CredentialAssignment),
        "{refusal}"
    );
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::AwsSecretAccessKey),
        "{refusal}"
    );
    assert_eq!(refusal.findings[0].site, redact::Site::RequestChunk(0));
}

#[test]
fn sanitize_cannot_rescue_a_body_credential() {
    let mut entry = with_body(&format!("aws_secret_access_key={EXAMPLE_SECRET}"));
    let touched = redact::sanitize(&mut entry);
    assert!(touched.is_empty(), "the sanitizer must not claim to have touched a body: {touched:?}");
    assert!(redact::admit(&entry).is_err(), "a body credential must stay a refusal under --sanitize");
}

// ---------------------------------------------------------------------------
// Negative: the remaining secret shapes and schema refusals.
// ---------------------------------------------------------------------------

#[test]
fn sse_c_customer_key_header_is_refused() {
    let entry = with_header(
        "x-amz-server-side-encryption-customer-key",
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
    );
    assert!(reasons(&entry).contains(&redact::Reason::LiveCredentialField));
}

#[test]
fn pem_private_key_in_a_body_is_refused() {
    let entry = with_body("-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----");
    assert!(reasons(&entry).contains(&redact::Reason::PrivateKeyPem));
}

#[test]
fn json_web_token_in_a_body_is_refused() {
    let entry = with_body("token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl");
    assert!(reasons(&entry).contains(&redact::Reason::JsonWebToken));
}

#[test]
fn aws_secret_in_a_metadata_header_is_refused() {
    let entry = with_header("x-amz-meta-note", EXAMPLE_SECRET);
    assert!(reasons(&entry).contains(&redact::Reason::AwsSecretAccessKey));
}

#[test]
fn a_secret_parked_in_a_control_chunk_action_is_refused() {
    let mut entry = base_entry();
    entry.chunks = Some(vec![Chunk::Control {
        action: format!("close aws_secret_access_key={EXAMPLE_SECRET}"),
        delay_ms: None,
        duration_ms: None,
    }]);
    let refusal = redact::admit(&entry).unwrap_err();
    assert_eq!(
        refusal.findings,
        vec![redact::Finding {
            site: redact::Site::ControlAction(0),
            reason: redact::Reason::CredentialAssignment
        }],
        "a control chunk's action is free text and must be scanned like any other field"
    );
}

#[test]
fn a_secret_parked_in_an_entry_metadata_field_is_refused() {
    // `recorded`, `op` and `method` are as writable as any header, and nothing else in the
    // pipeline looks at their contents: `op` is only compared with the file name and
    // `recorded` is never parsed at all.
    for (field, mutate) in [
        (
            "recorded",
            (|entry: &mut Entry| entry.recorded = format!("2026-09-02 {EXAMPLE_SECRET}")) as fn(&mut Entry),
        ),
        ("op", |entry: &mut Entry| entry.op = format!("PutObject {EXAMPLE_SECRET}")),
        ("method", |entry: &mut Entry| entry.method = format!("PUT {EXAMPLE_SECRET}")),
    ] {
        let mut entry = base_entry();
        mutate(&mut entry);
        let found = reasons(&entry);
        assert!(found.contains(&redact::Reason::AwsSecretAccessKey), "{field} was not scanned: {found:?}");
    }
}

#[test]
fn a_redaction_claim_the_entry_does_not_support_is_refused() {
    let mut entry = base_entry();
    entry.redacted = vec!["authorization".to_owned()];
    assert!(
        reasons(&entry).contains(&redact::Reason::UnprovenRedactionClaim),
        "claiming a field was redacted when it is absent must not pass"
    );
}

#[test]
fn a_redaction_claim_does_not_launder_a_live_value() {
    let mut entry = with_header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/x, Signature=deadbeef");
    entry.redacted = vec!["authorization".to_owned()];
    let refusal = redact::admit(&entry).unwrap_err();
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::LiveCredentialField)
    );
    assert!(
        refusal
            .findings
            .iter()
            .any(|finding| finding.reason == redact::Reason::UnprovenRedactionClaim)
    );
}

#[test]
fn a_newer_schema_version_is_refused_by_name() {
    let line = r#"{"v":2,"op":"PutObject","src":"handwritten:s3s-issues","recorded":"2026-09-02","capture":"head_full","sut":"none","method":"PUT","target":"/b/k"}"#;
    match schema::load_jsonl(line) {
        Err(LoadError::UnsupportedVersion { line, found, supported }) => {
            assert_eq!((line, found, supported), (1, 2, schema::CORPUS_SCHEMA_VERSION));
        }
        other => panic!("a v2 entry must not load into a v1 build: {other:?}"),
    }
}

#[test]
fn an_unknown_entry_field_is_refused() {
    let line = r#"{"v":1,"op":"PutObject","src":"handwritten:s3s-issues","recorded":"2026-09-02","capture":"head_full","sut":"none","method":"PUT","target":"/b/k","surprise":1}"#;
    assert!(matches!(schema::load_jsonl(line), Err(LoadError::Malformed { .. })));
}

#[test]
fn an_unknown_chunk_field_is_refused() {
    let line = r#"{"v":1,"op":"PutObject","src":"handwritten:s3s-issues","recorded":"2026-09-02","capture":"head_full","sut":"none","method":"PUT","target":"/b/k","chunks":[{"bytes_b64":"","surprise":1}]}"#;
    assert!(matches!(schema::load_jsonl(line), Err(LoadError::Malformed { .. })));
}

#[test]
fn a_chunk_that_is_both_data_and_control_is_refused() {
    let line = r#"{"v":1,"op":"PutObject","src":"handwritten:s3s-issues","recorded":"2026-09-02","capture":"head_full","sut":"none","method":"PUT","target":"/b/k","chunks":[{"bytes_b64":"","action":"close"}]}"#;
    assert!(matches!(schema::load_jsonl(line), Err(LoadError::Malformed { .. })));
}

#[test]
fn an_unknown_system_under_test_is_refused() {
    let line = r#"{"v":1,"op":"PutObject","src":"handwritten:gateway","recorded":"2026-09-02","capture":"head_full","sut":"somebody-elses-cluster","method":"PUT","target":"/b/k"}"#;
    assert!(
        matches!(schema::load_jsonl(line), Err(LoadError::Malformed { .. })),
        "the system under test is a closed vocabulary; an unrecognised spelling must not load"
    );
}

#[test]
fn production_provenance_is_refused() {
    let error = store::check_source("production").unwrap_err();
    assert!(error.contains("never production traffic"), "{error}");
    assert!(store::check_source("prod-mirror@abc").is_err());
    assert!(store::check_source("").is_err());
}

#[test]
fn a_client_matrix_source_without_a_pinned_revision_is_refused() {
    assert!(store::check_source("client-matrix:boto3").is_err());
    assert!(store::check_source("client-matrix:boto3@1.42.96").is_ok());
}

#[test]
fn a_partial_capture_cannot_become_a_case() {
    let mut entry = base_entry();
    entry.capture = Capture::HeadPartial;
    assert_eq!(case::to_case(&entry, "c-draft-0001").unwrap_err(), case::ConversionError::PartialCapture);
}

#[test]
fn an_unknown_control_action_cannot_become_a_case() {
    let mut entry = base_entry();
    entry.chunks = Some(vec![Chunk::Control {
        action: "detonate".to_owned(),
        delay_ms: None,
        duration_ms: None,
    }]);
    assert!(matches!(
        case::to_case(&entry, "c-draft-0001"),
        Err(case::ConversionError::UnknownAction { index: 0, .. })
    ));
}

#[test]
fn base64_decoding_is_strict() {
    assert!(base64::decode("QQ").is_err(), "an unpadded tail must not decode");
    assert!(base64::decode("QQ=QQQ==").is_err(), "padding before the final group must not decode");
    assert!(base64::decode("!!!!").is_err(), "a byte outside the alphabet must not decode");
    assert!(base64::from_hex("abc").is_err());
    assert!(base64::from_hex("zz").is_err());
}

#[test]
fn a_manifest_that_does_not_match_the_files_is_refused() {
    let root = scratch_dir("manifest-drift");
    let (buckets, _) = dedup::bucketize(vec![base_entry()], dedup::DEFAULT_BUCKET_CAP);
    store::write(&root, &buckets).unwrap();
    assert!(store::verify(&root).is_ok());

    let manifest = root.join(store::MANIFEST_FILE);
    let text = std::fs::read_to_string(&manifest)
        .unwrap()
        .replace("entries = 1", "entries = 7");
    std::fs::write(&manifest, text).unwrap();
    let violations = store::verify(&root).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("does not match the corpus")),
        "{violations:?}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn an_entry_filed_under_the_wrong_operation_is_refused() {
    let root = scratch_dir("wrong-op");
    let (buckets, _) = dedup::bucketize(vec![base_entry()], dedup::DEFAULT_BUCKET_CAP);
    store::write(&root, &buckets).unwrap();
    let stored = root.join("object/PutObject.jsonl");
    let text = std::fs::read_to_string(&stored)
        .unwrap()
        .replace("\"PutObject\"", "\"GetObject\"");
    std::fs::write(&stored, text).unwrap();
    let violations = store::verify(&root).unwrap_err();
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("does not match the file name")),
        "{violations:?}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_secret_written_straight_into_a_stored_bucket_is_refused() {
    let root = scratch_dir("planted-secret");
    let (buckets, _) = dedup::bucketize(vec![base_entry()], dedup::DEFAULT_BUCKET_CAP);
    store::write(&root, &buckets).unwrap();
    let stored = root.join("object/PutObject.jsonl");
    let text = std::fs::read_to_string(&stored)
        .unwrap()
        .replace("[\"host\"", &format!("[\"x-amz-meta-leak\",\"{EXAMPLE_SECRET}\"],[\"host\""));
    std::fs::write(&stored, text).unwrap();
    let violations = store::verify(&root).unwrap_err();
    assert!(
        violations.iter().any(|violation| violation.contains("AWS secret access key")),
        "verification must catch a secret that never went through ingest: {violations:?}"
    );
    std::fs::remove_dir_all(&root).unwrap();
}

// ---------------------------------------------------------------------------
// Positive: what the store must do once an entry is clean.
// ---------------------------------------------------------------------------

#[test]
fn sanitize_rewrites_the_carriers_it_knows_and_records_them() {
    let mut entry = with_header("authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/x, Signature=deadbeef");
    entry
        .headers
        .push(("x-amz-security-token".to_owned(), "FwoGZXIvYXdz".to_owned()));
    entry.target = "/bucket/key?X-Amz-Signature=abc123&list-type=2".to_owned();

    let touched = redact::sanitize(&mut entry);
    assert_eq!(touched, vec!["authorization", "x-amz-security-token", "x-amz-signature"]);
    assert_eq!(entry.redacted, touched);
    assert!(entry.target.contains("X-Amz-Signature=__REDACTED__"));
    assert!(entry.target.contains("list-type=2"), "a benign parameter must survive sanitization");
    redact::admit(&entry).unwrap();
}

#[test]
fn values_do_not_participate_in_the_fingerprint() {
    let mut first = base_entry();
    let mut fingerprints = std::collections::HashSet::new();
    for index in 0..1000 {
        first.target = format!("/bucket-{index:08x}/key-{index}");
        fingerprints.insert(dedup::fingerprint(&first));
    }
    assert_eq!(fingerprints.len(), 1, "a randomly named bucket must not mint a new corpus entry");

    let (buckets, report) = dedup::bucketize(
        (0..1000)
            .map(|index| {
                let mut entry = base_entry();
                entry.target = format!("/bucket-{index:08x}/key-{index}");
                entry
            })
            .collect(),
        dedup::DEFAULT_BUCKET_CAP,
    );
    assert_eq!(report.retained, 1);
    assert_eq!(report.duplicates, 999);
    assert_eq!(buckets[0].entries.len(), 1);
}

#[test]
fn shape_that_selects_a_different_operation_does_participate() {
    let plain = base_entry();
    let mut sub_resource = base_entry();
    sub_resource.target = "/bucket/key?uploads".to_owned();
    let mut chunked = base_entry();
    chunked
        .headers
        .push(("x-amz-decoded-content-length".to_owned(), "65536".to_owned()));
    chunked.headers[1].1 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_owned();

    let mut seen = std::collections::HashSet::new();
    for entry in [&plain, &sub_resource, &chunked] {
        assert!(seen.insert(dedup::fingerprint(entry)), "distinct request shapes must not collide");
    }
    assert!(chunked.has_chunk_framing());
    assert!(!plain.has_chunk_framing());
}

#[test]
fn the_retention_rule_keeps_the_rare_framing_when_the_cap_bites() {
    let mut entries: Vec<Entry> = (0..50)
        .map(|index| {
            let mut entry = base_entry();
            entry.headers.push((format!("x-amz-meta-n{index}"), "1".to_owned()));
            entry
        })
        .collect();
    let mut streaming = base_entry();
    streaming.headers[1].1 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_owned();
    streaming
        .headers
        .push(("x-amz-trailer".to_owned(), "x-amz-checksum-crc32c".to_owned()));
    entries.push(streaming);

    let (buckets, report) = dedup::bucketize(entries, 3);
    assert_eq!(report.retained, 3);
    assert_eq!(buckets[0].trailers(), 1, "the only trailer-declaring entry must survive the cap");
    assert_eq!(buckets[0].chunked(), 1);
    assert_eq!(buckets[0].over_cap, 48);
}

#[test]
fn a_case_draft_round_trips_timing_and_termination() {
    let mut entry = base_entry();
    entry.chunks = Some(vec![
        Chunk::Data {
            bytes_b64: base64::encode(b"hello"),
            delay_ms: Some(25),
        },
        Chunk::Control {
            action: "stall".to_owned(),
            delay_ms: Some(5),
            duration_ms: Some(750),
        },
        Chunk::Control {
            action: "half_close".to_owned(),
            delay_ms: None,
            duration_ms: None,
        },
    ]);
    entry.resp = Some(Response {
        status: 200,
        headers: Vec::new(),
        body_b64: None,
    });

    assert!(case::roundtrips(&entry).unwrap(), "delay_ms, duration_ms and action must all survive");
    let draft = case::to_case(&entry, "c-draft-0001").unwrap();
    let rendered = draft.render();
    assert!(rendered.contains("hex = \"68656c6c6f\""));
    assert!(rendered.contains("delay_ms = 25"));
    assert!(rendered.contains("duration_ms = 750"));
    assert!(rendered.contains("action = \"half_close\""));
    assert!(
        rendered.contains("rationale = \"\""),
        "a draft must stay unloadable until a human writes its rationale"
    );
}

#[test]
fn a_written_corpus_verifies_and_reports_what_it_holds() {
    let root = scratch_dir("write-verify");
    let mut streaming = base_entry();
    streaming.op = "UploadPart".to_owned();
    streaming.src = "client-matrix:restic@0.18.1".to_owned();
    streaming.headers[1].1 = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_owned();

    let (buckets, _) = dedup::bucketize(vec![base_entry(), streaming], dedup::DEFAULT_BUCKET_CAP);
    store::write(&root, &buckets).unwrap();
    assert!(root.join("object/PutObject.jsonl").is_file());
    assert!(root.join("multipart/UploadPart.jsonl").is_file());

    let report = store::verify(&root).unwrap();
    assert_eq!((report.buckets, report.entries, report.chunk_framed, report.sources), (2, 2, 1, 2));
    let manifest = std::fs::read_to_string(root.join(store::MANIFEST_FILE)).unwrap();
    assert!(manifest.contains("chunk_framed_entries = 1"));
    assert!(manifest.contains("id = \"client-matrix:restic@0.18.1\""));
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn base64_and_hex_round_trip_every_byte() {
    let all: Vec<u8> = (0..=255u8).collect();
    for length in 0..=8 {
        let slice = &all[..length];
        assert_eq!(base64::decode(&base64::encode(slice)).unwrap(), slice);
    }
    assert_eq!(base64::decode(&base64::encode(&all)).unwrap(), all);
    assert_eq!(base64::from_hex(&base64::to_hex(&all)).unwrap(), all);
    assert_eq!(base64::encode(b"hello"), "aGVsbG8=");
}

#[test]
fn the_family_table_is_ordered_so_the_first_match_is_the_right_one() {
    assert_eq!(dedup::family_of("ListBuckets"), "service");
    assert_eq!(dedup::family_of("CreateBucket"), "bucket");
    assert_eq!(dedup::family_of("ListMultipartUploads"), "multipart");
    assert_eq!(dedup::family_of("UploadPart"), "multipart");
    assert_eq!(dedup::family_of("PutObject"), "object");
    assert_eq!(dedup::family_of("SelectObjectContent"), "object");
    assert_eq!(dedup::family_of("Whatever"), "other");
}

#[test]
fn the_checked_in_corpus_verifies_and_carries_chunk_framing() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let report = match store::verify(&root) {
        Ok(report) => report,
        Err(violations) => panic!("corpus/ does not verify:\n  {}", violations.join("\n  ")),
    };
    assert!(report.entries > 0, "corpus/ holds no entries");
    assert!(
        report.chunk_framed > 0,
        "the corpus exists partly to close the aws-chunked blind spot; an entry set with no chunk \
         framing at all has not closed it"
    );
    assert!(report.bytes < store::SOFT_SIZE_LIMIT_BYTES);

    // rustfs/gateway#624: this repository has no runnable production server binary, so no
    // entry can honestly claim one. The manifest says so in a field rather than in prose.
    let manifest = std::fs::read_to_string(root.join(store::MANIFEST_FILE)).unwrap();
    assert!(manifest.contains("entries_from_production_server = 0"), "{manifest}");
    for entry in store::load_all(&root).unwrap() {
        assert_ne!(entry.sut, Sut::RustfsServer, "{} claims a production recording", entry.op);
    }

    // Every entry must survive a round trip into whatever conversion it is eligible for:
    // a full capture into a case draft, a partial one into an explicit refusal. A silent
    // third outcome is what this asserts does not exist.
    for entry in store::load_all(&root).unwrap() {
        match case::to_case(&entry, "c-draft-0001") {
            Ok(_) => assert!(case::roundtrips(&entry).unwrap(), "{} did not round trip", entry.op),
            Err(error) => assert_eq!(error, case::ConversionError::PartialCapture, "{}", entry.op),
        }
    }
}
