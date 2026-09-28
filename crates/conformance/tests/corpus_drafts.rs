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

//! Responsible for: rustfs/backlog#1763's a-cp-0004 and a-cp-0022 — a conformance case draft
//! produced by `rustfs-gateway-corpus` from a recorded entry is loaded by this crate's own runner
//! once a human has written its rationale and evidence, and the chunk sequence it loads — payload
//! bytes, `delay_ms`, `duration_ms` and `action` — is the one the entry recorded.
//! Not responsible for: whether the drafted case passes against any target; a draft asserts only
//! the status the recording observed, and adopting it is a human judgement.
//! Upstream: `rustfs_gateway_corpus::case` (a dev-dependency: the corpus crate is ring 0 and must
//! not depend on this one, so the loader half of the round trip lives here).
//! Downstream: nothing; a leaf test module of the `integration` target.

use std::path::{Path, PathBuf};

use rustfs_gateway_conformance::diagnostic::Severity;
use rustfs_gateway_conformance::runner;
use rustfs_gateway_conformance::value::Value;
use rustfs_gateway_corpus::base64;
use rustfs_gateway_corpus::case;
use rustfs_gateway_corpus::schema::{self, Capture, Chunk, Entry, Response, Sut};

fn entry() -> Entry {
    Entry {
        v: schema::CORPUS_SCHEMA_VERSION,
        op: "PutObject".to_owned(),
        src: "handwritten:gateway".to_owned(),
        recorded: "2026-09-28".to_owned(),
        capture: Capture::HeadFull,
        sut: Sut::None,
        method: "PUT".to_owned(),
        target: "/bucket/key".to_owned(),
        headers: vec![
            ("host".to_owned(), "127.0.0.1:9000".to_owned()),
            ("content-length".to_owned(), "11".to_owned()),
        ],
        chunks: Some(vec![
            Chunk::Data {
                bytes_b64: base64::encode(b"hello"),
                delay_ms: Some(25),
            },
            Chunk::Control {
                action: "stall".to_owned(),
                delay_ms: Some(5),
                duration_ms: Some(750),
            },
            Chunk::Data {
                bytes_b64: base64::encode(b" world"),
                delay_ms: None,
            },
            Chunk::Control {
                action: "half_close".to_owned(),
                delay_ms: None,
                duration_ms: None,
            },
        ]),
        resp: Some(Response {
            status: 200,
            headers: Vec::new(),
            body_b64: None,
        }),
        redacted: Vec::new(),
    }
}

/// A scratch conformance root holding the frozen schema and one case file.
fn root_with(name: &str, case_toml: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("conformance-corpus-draft-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let cases = root.join("cases/draft");
    std::fs::create_dir_all(&cases).expect("a scratch corpus");
    let schema = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/case.schema.json");
    std::fs::copy(schema, root.join("case.schema.json")).expect("the frozen schema");
    std::fs::write(cases.join("c-draft-0001.toml"), case_toml).expect("a case file");
    root
}

/// The human half of adopting a draft: a rationale and one piece of evidence.
fn adopt(draft: &str) -> String {
    let adopted = draft
        .replacen(
            "rationale = \"\"",
            "rationale = \"A recorded upload that pauses mid-body and half-closes, kept to pin the chunk state machine.\"",
            1,
        )
        .replacen(
            "evidence = []",
            "evidence = [{ url = \"https://github.com/rustfs/backlog/issues/1763\", summary = \"The corpus recorded this request shape from a synthetic client run.\", kind = \"other\" }]",
            1,
        );
    assert_ne!(adopted, draft, "the draft no longer has the fields a human fills in");
    adopted
}

fn denials(root: &Path) -> Vec<String> {
    let corpus = runner::prepare_corpus(root).expect("the scratch corpus loads");
    let [case] = corpus.cases() else {
        panic!("expected exactly the one drafted case, found {}", corpus.cases().len());
    };
    case.diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == Severity::Deny)
        .map(|diagnostic| format!("{} {} {}", diagnostic.rule, diagnostic.pointer, diagnostic.message))
        .collect()
}

/// The loaded request chunks, back in the corpus vocabulary.
fn loaded_chunks(root: &Path) -> Vec<Chunk> {
    let corpus = runner::prepare_corpus(root).expect("the scratch corpus loads");
    let document = corpus.cases()[0].document.as_ref().expect("a parsed case");
    let Some(Value::Array(chunks)) = document.get("request").and_then(|request| request.get("chunks")) else {
        panic!("the loaded case has no request.chunks array");
    };
    let integer = |chunk: &Value, key: &str| {
        chunk
            .get(key)
            .and_then(Value::as_integer)
            .map(|value| u64::try_from(value).expect("a non-negative integer"))
    };
    chunks
        .iter()
        .map(|chunk| match chunk.get("action").and_then(Value::as_str) {
            Some(action) => Chunk::Control {
                action: action.to_owned(),
                delay_ms: integer(chunk, "delay_ms"),
                duration_ms: integer(chunk, "duration_ms"),
            },
            None => {
                let hex = chunk.get("hex").and_then(Value::as_str).expect("a hex data chunk");
                Chunk::Data {
                    bytes_b64: base64::encode(&base64::from_hex(hex).expect("valid hex")),
                    delay_ms: integer(chunk, "delay_ms"),
                }
            }
        })
        .collect()
}

/// Positive (a-cp-0004, a-cp-0022) — the adopted draft passes the runner's schema and lint gate,
/// and the chunk sequence the runner loads is exactly the recorded one: every payload byte, every
/// `delay_ms`, the `stall` duration and the `half_close` termination.
#[test]
fn an_adopted_draft_loads_in_the_runner_with_its_chunks_intact() {
    let recorded = entry();
    let draft = case::to_case(&recorded, "c-draft-0001")
        .expect("a head_full entry converts")
        .render();
    let root = root_with("adopted", &adopt(&draft));
    let denied = denials(&root);
    assert!(denied.is_empty(), "the runner refused the adopted draft:\n{}", denied.join("\n"));
    assert_eq!(
        Some(loaded_chunks(&root)),
        recorded.chunks,
        "the runner loaded a different chunk sequence"
    );
}

/// Negative — the draft as generated, with no rationale and no evidence, is refused by the runner:
/// a draft cannot be merged into `conformance/cases/` as if it were a reviewed case.
#[test]
fn n_an_unadopted_draft_is_refused_by_the_runner() {
    let draft = case::to_case(&entry(), "c-draft-0001")
        .expect("a head_full entry converts")
        .render();
    let root = root_with("unadopted", &draft);
    let denied = denials(&root);
    assert!(
        denied.iter().any(|denial| denial.contains("/case/rationale"))
            && denied.iter().any(|denial| denial.contains("/case/evidence")),
        "the runner must refuse the draft for its missing rationale and evidence, and refused: {denied:?}"
    );
}

/// Negative (a-cp-0022) — a draft that lost a chunk's timing or termination no longer loads as the
/// recorded sequence. This is the comparison the positive case relies on, shown to fail.
#[test]
fn n_a_draft_that_drops_timing_or_termination_does_not_load_as_recorded() {
    let recorded = entry();
    let draft = adopt(
        &case::to_case(&recorded, "c-draft-0001")
            .expect("a head_full entry converts")
            .render(),
    );
    for (label, damaged) in [
        ("delay_ms", draft.replacen("delay_ms = 25\n", "", 1)),
        ("duration_ms", draft.replacen("duration_ms = 750\n", "", 1)),
        ("action", draft.replacen("action = \"half_close\"", "action = \"close\"", 1)),
    ] {
        assert_ne!(damaged, draft, "{label}: the damage did not apply");
        let root = root_with(&format!("damaged-{label}"), &damaged);
        assert_ne!(Some(loaded_chunks(&root)), recorded.chunks, "{label}: the loss went unnoticed");
    }
}
