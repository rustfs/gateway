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

//! The runners and the corpus conversion: exit statuses, sampling, the budget, and every change a
//! recorded request goes through before both stacks see it.
//!
//! Responsible for: a-df-0021 (an empty or missing corpus is an environment exit, never a pass),
//! a-df-0023 (a run over its budget exits with the budget status and says how to split it), the
//! per-bucket sample, an unregistered difference in a recorded request failing the run, and each
//! corpus adjustment and skip named.
//! NOT responsible for: the diffs themselves.
//! Upstream: `runner.rs`, `corpus.rs`. Downstream: none.

use std::path::PathBuf;
use std::time::Duration;

use crate::corpus::{Adjustment, Skip, request_of};
use crate::runner::{EXIT_BUDGET, EXIT_DIFFERENCES, EXIT_ENVIRONMENT, EXIT_HARNESS, EXIT_PASSED, Inputs, Options, Report};

/// A fresh, empty directory under the system temporary directory.
fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("difftest-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

fn entry(line: &str) -> rustfs_gateway_corpus::schema::Entry {
    rustfs_gateway_corpus::schema::load_jsonl(line)
        .expect("a valid entry")
        .remove(0)
}

const HEAD: &str = r#""v":1,"src":"handwritten:gateway","recorded":"2026-09-02","sut":"none""#;

fn corpus_with(name: &str, file: &str, lines: &[String]) -> PathBuf {
    let root = scratch(name);
    let path = root.join(file);
    std::fs::create_dir_all(path.parent().expect("a family directory")).expect("the family directory");
    std::fs::write(&path, lines.join("\n") + "\n").expect("the bucket file");
    root
}

fn options(inputs: Inputs) -> Options {
    Options {
        inputs,
        per_bucket: None,
        budget: None,
    }
}

/// Negative (a-df-0021) — an empty corpus compares nothing and exits with the environment status,
/// saying so; it never reads as "zero differences".
#[test]
fn an_empty_corpus_is_an_environment_exit_not_a_pass() {
    let root = scratch("empty");
    let report = crate::runner::decode(&options(Inputs::Corpus(root))).expect("an empty directory reads");
    let (status, text) = report.conclude("decode-diff", None);
    assert_eq!(status, EXIT_ENVIRONMENT);
    assert!(text.contains("nothing was compared"), "{text}");
}

/// Negative (a-df-0021) — a corpus directory that does not exist is an environment error.
#[test]
fn a_missing_corpus_is_an_environment_error() {
    let missing = std::env::temp_dir().join("difftest-no-such-corpus-directory");
    let error = crate::runner::decode(&options(Inputs::Corpus(missing))).expect_err("refused");
    assert!(error.contains("does not exist"), "{error}");
}

/// Negative — the encode runner has no recorded outputs to read and says so instead of passing.
#[test]
fn the_encode_runner_refuses_a_corpus_it_has_no_outputs_for() {
    let error = crate::runner::encode(&options(Inputs::Corpus(PathBuf::from("corpus")))).expect_err("refused");
    assert!(error.contains("no output samples"), "{error}");
}

/// Negative — one recorded request with an unregistered difference fails the run; the same corpus
/// without it passes.
#[test]
fn an_unregistered_difference_in_the_corpus_fails_the_run() {
    let unregistered = format!(
        r#"{{{HEAD},"op":"GetObject","capture":"head_full","method":"GET","target":"/bkt/k?x-id=ListParts","headers":[["host","h"]]}}"#
    );
    let registered =
        format!(r#"{{{HEAD},"op":"GetObject","capture":"head_full","method":"GET","target":"/bkt/k","headers":[["host","h"]]}}"#);
    let failing = corpus_with("failing", "object/GetObject.jsonl", &[registered.clone(), unregistered]);
    let report = crate::runner::decode(&options(Inputs::Corpus(failing))).expect("the corpus reads");
    let (status, text) = report.conclude("decode-diff", None);
    assert_eq!(status, EXIT_DIFFERENCES, "{text}");
    assert!(text.contains("UNREGISTERED object/GetObject.jsonl:2"), "{text}");
    let passing = corpus_with("passing", "object/GetObject.jsonl", &[registered]);
    let report = crate::runner::decode(&options(Inputs::Corpus(passing))).expect("the corpus reads");
    assert_eq!(report.conclude("decode-diff", None).0, EXIT_PASSED);
}

/// Negative — the per-bucket sample keeps the first N entries of every operation and counts the
/// rest as skipped, never as compared.
#[test]
fn the_per_bucket_sample_keeps_the_first_entries_of_each_operation() {
    let line = |target: &str| {
        format!(
            r#"{{{HEAD},"op":"GetObject","capture":"head_full","method":"GET","target":"{target}","headers":[["host","h"]]}}"#
        )
    };
    let root = corpus_with("sampled", "object/GetObject.jsonl", &[line("/bkt/a"), line("/bkt/b"), line("/bkt/c")]);
    let report = crate::runner::decode(&Options {
        per_bucket: Some(1),
        ..options(Inputs::Corpus(root))
    })
    .expect("the corpus reads");
    assert_eq!(report.compared, 1);
    assert_eq!(report.skipped.get("outside the per-bucket sample"), Some(&2));
}

/// Negative — sampling counts only what is sent and keeps a counter per operation: an operation
/// whose first entry is skipped is still compared, and a second operation is sampled on its own.
#[test]
fn the_per_bucket_sample_counts_sent_inputs_per_operation() {
    let get = |target: &str| {
        format!(
            r#"{{{HEAD},"op":"GetObject","capture":"head_full","method":"GET","target":"{target}","headers":[["host","h"]]}}"#
        )
    };
    let skipped = format!(
        r#"{{{HEAD},"op":"GetObject","capture":"head_full","method":"GET","target":"/bkt/s","headers":[["content-length","9"]],"chunks":[{{"bytes_b64":"aGVsbG8="}}]}}"#
    );
    let head = format!(
        r#"{{{HEAD},"op":"HeadObject","capture":"head_full","method":"HEAD","target":"/bkt/h","headers":[["host","h"]]}}"#
    );
    let root = scratch("two-operations");
    for (file, lines) in [
        ("object/GetObject.jsonl", vec![skipped, get("/bkt/a"), get("/bkt/b")]),
        ("object/HeadObject.jsonl", vec![head]),
    ] {
        let path = root.join(file);
        std::fs::create_dir_all(path.parent().expect("a family directory")).expect("the family directory");
        std::fs::write(&path, lines.join("\n") + "\n").expect("the bucket file");
    }
    let report = crate::runner::decode(&Options {
        per_bucket: Some(1),
        ..options(Inputs::Corpus(root))
    })
    .expect("the corpus reads");
    assert_eq!(report.compared, 2, "{report:?}");
    assert_eq!(report.skipped.get("outside the per-bucket sample"), Some(&1));
    assert!(report.uncompared.is_empty(), "{report:?}");
}

/// Negative (a-df-0021) — a corpus whose every entry is skipped measured nothing: an environment
/// exit, and the operation is named.
#[test]
fn a_corpus_of_skipped_entries_is_an_environment_exit() {
    let line = format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_full","method":"PUT","target":"/bkt/k","headers":[["x-amz-content-sha256","STREAMING-AWS4-HMAC-SHA256-PAYLOAD"]]}}"#
    );
    let root = corpus_with("all-skipped", "object/PutObject.jsonl", &[line]);
    let report = crate::runner::decode(&options(Inputs::Corpus(root))).expect("the corpus reads");
    let (status, text) = report.conclude("decode-diff", None);
    assert_eq!(status, EXIT_ENVIRONMENT, "{text}");
    assert!(text.contains("UNCOMPARED PutObject"), "{text}");
}

/// Negative — a partial head capture that a stack routes elsewhere than its recorded operation is
/// a capture artifact: skipped with that reason, never judged against the register. A full
/// capture routed the same way is judged.
#[test]
fn a_partial_capture_routed_away_is_skipped_not_judged() {
    let line = |capture: &str| {
        format!(
            r#"{{{HEAD},"op":"PutObject","capture":"{capture}","method":"PUT","target":"/bkt/k?x-id=CopyObject","headers":[["x-amz-content-sha256","__UNRECORDED__"]]}}"#
        )
    };
    let partial = corpus_with("partial-away", "object/PutObject.jsonl", &[line("head_partial")]);
    let report = crate::runner::decode(&options(Inputs::Corpus(partial))).expect("the corpus reads");
    assert_eq!(report.compared, 0, "{report:?}");
    assert!(report.skipped.keys().any(|reason| reason.contains("routed away")), "{report:?}");
    let full = corpus_with("full-away", "object/PutObject.jsonl", &[line("head_full")]);
    let report = crate::runner::decode(&options(Inputs::Corpus(full))).expect("the corpus reads");
    assert_eq!(report.compared, 1, "{report:?}");
}

/// Negative (a-df-0023) — a run over its budget exits with the budget status and names the split.
#[test]
fn a_run_over_its_budget_exits_with_the_budget_status() {
    let report = Report {
        compared: 1,
        elapsed: Duration::from_secs(200),
        ..Report::default()
    };
    let (status, text) = report.conclude("decode-diff", Some(Duration::from_secs(180)));
    assert_eq!(status, EXIT_BUDGET);
    assert!(text.contains("--per-bucket") && text.contains("nightly"), "{text}");
    assert_eq!(report.conclude("decode-diff", Some(Duration::from_secs(300))).0, EXIT_PASSED);
    assert_eq!(report.conclude("decode-diff", Some(Duration::from_secs(200))).0, EXIT_PASSED);
}

/// Negative — a slow run with an unregistered difference reports the difference: the budget
/// advice would sample the failing input away.
#[test]
fn a_difference_outranks_the_budget() {
    let finding = crate::Finding {
        kind: crate::known::Kind::Decode,
        operation: "GetObject".to_owned(),
        item: crate::Item::Route,
        priority: crate::Priority::Route,
        gateway: "GetObject".to_owned(),
        s3s: "ListParts".to_owned(),
    };
    let report = Report {
        compared: 1,
        failures: vec![("x".to_owned(), finding)],
        elapsed: Duration::from_secs(200),
        ..Report::default()
    };
    assert_eq!(report.conclude("decode-diff", Some(Duration::from_secs(180))).0, EXIT_DIFFERENCES);
}

/// Negative — a harness failure is its own status, ahead of differences.
#[test]
fn a_harness_failure_is_its_own_status() {
    let report = Report {
        compared: 1,
        harness: vec![("x".to_owned(), "broken".to_owned())],
        ..Report::default()
    };
    assert_eq!(report.conclude("decode-diff", None).0, EXIT_HARNESS);
}

/// Negative — the command line refuses what it does not know and requires the inputs.
#[test]
fn the_command_line_refuses_unknown_and_incomplete_arguments() {
    let parse = |arguments: &[&str]| Options::parse(arguments.iter().map(|argument| (*argument).to_owned()));
    assert!(parse(&[]).is_err());
    assert!(parse(&["--corpus"]).is_err());
    assert!(parse(&["--builtin", "--per-bucket", "many"]).is_err());
    assert!(parse(&["--builtin", "--budget-seconds", "-1"]).is_err());
    assert!(parse(&["--builtin", "--frobnicate"]).is_err());
    let parsed = parse(&["--corpus", "c", "--per-bucket", "3", "--budget-seconds", "180"]).expect("parses");
    assert_eq!(parsed.inputs, Inputs::Corpus(PathBuf::from("c")));
    assert_eq!((parsed.per_bucket, parsed.budget), (Some(3), Some(Duration::from_secs(180))));
}

/// Positive — the recorded corpus in this repository passes, with its skips named.
#[test]
fn the_checked_in_corpus_has_no_unregistered_difference() {
    let root = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../corpus"));
    let report = crate::runner::decode(&options(Inputs::Corpus(root))).expect("the corpus reads");
    let (status, text) = report.conclude("decode-diff", None);
    assert_eq!(status, EXIT_PASSED, "{text}");
    assert!(report.compared > 30, "{text}");
}

/// Negative — a redacted signature, header or presigned query, is replaced by a fresh header
/// signature with the replay credential, and said so; the recorded value never reaches a stack.
#[test]
fn a_redacted_signature_is_signed_again_and_reported() {
    let header = entry(&format!(
        r#"{{{HEAD},"op":"GetObject","capture":"head_full","method":"GET","target":"/bkt/k","headers":[["host","h"],["x-amz-date","20260902T000000Z"],["x-amz-content-sha256","UNSIGNED-PAYLOAD"],["authorization","__REDACTED__"]],"redacted":["authorization"]}}"#
    ));
    let (request, adjustments) = request_of(&header).expect("sendable");
    let authorization = request
        .headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        .expect("signed again");
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDDIFFTEST/"), "{authorization}");
    assert!(request.headers.iter().all(|(_, value)| value != b"__REDACTED__"));
    for minted in ["authorization", "x-amz-date", "x-amz-content-sha256"] {
        assert_eq!(request.headers.iter().filter(|(name, _)| name == minted).count(), 1, "{minted} once");
    }
    assert!(
        request.headers.iter().all(|(_, value)| value != b"20260902T000000Z"),
        "the recorded date is replaced"
    );
    assert_eq!(adjustments, [Adjustment::SignedAgain]);
    let presigned = entry(&format!(
        r#"{{{HEAD},"op":"GetObject","capture":"head_full","method":"GET","target":"/bkt/k?versionId=v&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=__REDACTED__","headers":[["host","h"]],"redacted":["x-amz-signature"]}}"#
    ));
    let (request, adjustments) = request_of(&presigned).expect("sendable");
    assert_eq!(request.target, "/bkt/k?versionId=v");
    assert!(request.headers.iter().any(|(name, _)| name == "authorization"));
    assert_eq!(adjustments, [Adjustment::SignedAgain]);
    let diff = crate::decode_diff(&request).expect("the harness runs");
    assert_eq!((diff.error.gateway, diff.error.s3s), (None, None), "both stacks admit the signed replay");
}

/// Negative — a partial head capture's missing Content-Length is synthesised from the recorded
/// body; a full capture's is not, and an unrecorded placeholder header is removed.
#[test]
fn a_partial_capture_gets_its_length_and_loses_its_placeholders() {
    let partial = entry(&format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_partial","method":"PUT","target":"/bkt/k","headers":[["x-amz-content-sha256","__UNRECORDED__"]],"chunks":[{{"bytes_b64":"aGVsbG8="}}]}}"#
    ));
    let (request, adjustments) = request_of(&partial).expect("sendable");
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name == "content-length" && value == b"5")
    );
    assert_eq!(adjustments, [Adjustment::PlaceholderHeaderRemoved, Adjustment::ContentLengthSynthesised]);
    let full = entry(&format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_full","method":"PUT","target":"/bkt/k","headers":[["host","h"]],"chunks":[{{"bytes_b64":"aGVsbG8="}}]}}"#
    ));
    let (request, adjustments) = request_of(&full).expect("sendable");
    assert!(request.headers.iter().all(|(name, _)| name != "content-length"));
    assert!(adjustments.is_empty());
}

/// Negative — what cannot be replayed is skipped with its reason: a signed chunk framing whose
/// signatures were redacted, an abnormal end, a length that disagrees with the recorded body.
#[test]
fn what_cannot_be_replayed_is_skipped_with_its_reason() {
    let signed = entry(&format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_full","method":"PUT","target":"/bkt/k","headers":[["x-amz-content-sha256","STREAMING-AWS4-HMAC-SHA256-PAYLOAD"]]}}"#
    ));
    assert_eq!(request_of(&signed).map(|_| ()), Err(Skip::SignedFramingRedacted));
    let aborted = entry(&format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_full","method":"PUT","target":"/bkt/k","headers":[["content-length","5"]],"chunks":[{{"bytes_b64":"aGU="}},{{"action":"close"}}]}}"#
    ));
    assert_eq!(request_of(&aborted).map(|_| ()), Err(Skip::AbnormalBody("close".to_owned())));
    let short = entry(&format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_full","method":"PUT","target":"/bkt/k","headers":[["content-length","9"]],"chunks":[{{"bytes_b64":"aGVsbG8="}}]}}"#
    ));
    assert!(matches!(request_of(&short), Err(Skip::Malformed(reason)) if reason.contains("content-length 9 but 5")));
    let paced = entry(&format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_full","method":"PUT","target":"/bkt/k","headers":[["content-length","5"]],"chunks":[{{"bytes_b64":"aGVsbG8="}},{{"action":"flush"}}]}}"#
    ));
    assert_eq!(
        request_of(&paced).map(|(_, adjustments)| adjustments),
        Ok(vec![Adjustment::TimingIgnored])
    );
    let transferred = entry(&format!(
        r#"{{{HEAD},"op":"UploadPart","capture":"head_full","method":"PUT","target":"/bkt/k?partNumber=1&uploadId=u","headers":[["transfer-encoding","chunked"]],"chunks":[{{"bytes_b64":"aGVsbG8="}}]}}"#
    ));
    let (request, adjustments) = request_of(&transferred).expect("sendable");
    assert_eq!(adjustments, [Adjustment::TransferFramingReplaced]);
    assert!(request.headers.iter().all(|(name, _)| name != "transfer-encoding"));
    assert!(
        request
            .headers
            .iter()
            .any(|(name, value)| name == "content-length" && value == b"5")
    );
    let logical = entry(&format!(
        r#"{{{HEAD},"op":"PutObject","capture":"head_full","method":"PUT","target":"/bkt/k","headers":[["content-encoding","aws-chunked"],["x-amz-decoded-content-length","5"]],"chunks":[{{"bytes_b64":"aGVsbG8="}}]}}"#
    ));
    assert_eq!(request_of(&logical).map(|_| ()), Err(Skip::LogicalFraming));
}

/// Negative — a recorded request of an operation the diff does not project is skipped and named,
/// never compared: the gateway harness has no handler for it, so it would only ever be a 501.
#[test]
fn an_operation_outside_the_diffed_set_is_skipped_by_name() {
    let line = format!(
        r#"{{{HEAD},"op":"GetObjectTagging","capture":"head_full","method":"GET","target":"/bkt/k?tagging","headers":[["host","h"]]}}"#
    );
    let root = corpus_with("not-diffed", "object/GetObjectTagging.jsonl", &[line]);
    let report = crate::runner::decode(&options(Inputs::Corpus(root))).expect("the corpus reads");
    assert_eq!(report.compared, 0);
    assert!(report.skipped.keys().any(|reason| reason.ends_with("(GetObjectTagging)")), "{report:?}");
    assert_eq!(report.conclude("decode-diff", None).0, EXIT_ENVIRONMENT);
}
