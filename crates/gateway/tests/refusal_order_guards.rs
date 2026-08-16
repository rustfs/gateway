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

//! Source-level guards for the one ordering the type system fixes but cannot advertise.
//!
//! Responsible for: proving that the proof type gating the request-body read keeps exactly one
//! non-test constructor, that the read is reachable only through it, and that the pipeline still
//! collects the body after the verifier rather than before.
//! NOT responsible for: what the pipeline does with either — `tests/pipeline.rs` measures that with
//! a body that counts its own bytes.
//! Upstream: this crate's own sources. Downstream: nothing.
//!
//! Why a source guard at all, when the compiler already refuses the wrong order: the compiler
//! refuses it *given the current signature*. Nothing stops a later change from adding
//! `Authenticated::assume()`, and that one line would silently restore the property to what it was
//! — a comment. Each guard below is paired with a proof that it can fire, because a guard never
//! shown to fail is indistinguishable from one that cannot.

use std::fs;
use std::path::Path;

/// The module that owns the proof and the bounded read.
fn gate() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gate.rs");
    fs::read_to_string(&path).expect("the gate module exists")
}

/// The assembled pipeline.
fn service() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/service.rs");
    fs::read_to_string(&path).expect("the service module exists")
}

/// Every function declared inside the proof's own `impl` block that hands one back.
///
/// Scoped to the block rather than to the file, because the file also holds `BodyCeilings::of` and
/// the refusal constructors, all of which return a `Self` that has nothing to do with the proof.
fn constructors_of_the_proof(text: &str) -> Vec<&str> {
    const OPENS: &str = "impl<'a> Authenticated<'a> {";
    let Some(start) = text.find(OPENS) else { return Vec::new() };
    let rest = text.get(start.saturating_add(OPENS.len())..).unwrap_or_default();
    // The block ends at the first line that is a lone closing brace in column zero.
    let end = rest.find("\n}\n").map_or(rest.len(), |at| at);
    rest.get(..end)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("fn ") || trimmed.starts_with("pub(crate) fn ") || trimmed.starts_with("pub(crate) const fn ")
        })
        .filter(|line| line.contains("-> Option<Self>") || line.contains("-> Self") || line.contains("-> Authenticated"))
        .collect()
}

/// Negative — the proof has exactly two constructors: the fallible one, and the `#[cfg(test)]` one
/// that carries its own justification. A third would be the line that turns this back into a
/// convention.
#[test]
fn the_proof_gains_no_third_constructor() {
    let source = gate();
    let found = constructors_of_the_proof(&source);
    assert_eq!(
        found.len(),
        2,
        "the proof type must keep exactly one real constructor and one test one, found: {found:#?}"
    );
    assert!(
        found.iter().any(|line| line.contains("of(verdict: &'a Verdict)")),
        "the real constructor must still read a verdict: {found:#?}"
    );
    assert!(
        source.contains("#[cfg(test)]\n    pub(crate) const fn granted_for_test()"),
        "the test constructor must stay behind `cfg(test)`"
    );
}

/// Negative — the guard above can fail. A source with one more constructor is rejected, which is
/// what makes the count above evidence rather than decoration.
#[test]
fn the_constructor_guard_can_fire() {
    let forged = "    pub(crate) fn assume() -> Self {\n        Self {}\n    }\n";
    let source = gate().replacen("    /// A proof for a test", &format!("{forged}    /// A proof for a test"), 1);
    assert_eq!(constructors_of_the_proof(&source).len(), 3);
}

/// Negative — the body read takes the proof. A signature that stopped taking it would compile
/// everywhere and mean nothing.
#[test]
fn the_body_read_still_demands_the_proof() {
    let source = gate();
    let signature = source
        .split_once("pub(crate) async fn read(")
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(parameters, _)| parameters)
        .expect("`SealedBody::read` must exist");
    // Matched on the parameter list rather than on a whole line, so that adding a parameter — the
    // chunk ingest did — reformats the signature across several lines without silently disarming
    // the guard. The guard is about the proof being taken, not about where rustfmt put it.
    assert!(
        signature.contains("_proof: &Authenticated<'_>"),
        "`SealedBody::read` must keep the proof in its signature: {signature:?}"
    );
}

/// Negative — the pipeline seals the body above the verifier and reads it below. The order is what
/// the type enforces; this asserts the two call sites are still on the sides that make the
/// enforcement mean something, so that a refactor which moved both together is visible.
#[test]
fn the_pipeline_seals_before_it_authenticates_and_reads_after() {
    let source = service();
    let sealed = source.find("SealedBody::seal(").expect("the body is sealed");
    let admitted = source.find(".floor.admit(").expect("the floor admits");
    let proof = source.find("Authenticated::of(&verdict)").expect("the proof is minted");
    let read = source.find(".read(&authenticated").expect("the body is read");
    assert!(sealed < admitted, "the body must be sealed before the floor sees the request");
    assert!(admitted < proof, "the proof must be minted from a verdict the floor produced");
    assert!(proof < read, "the body must be read after the proof exists, never before");
}

/// Negative — no other module may collect a request body. One reader is what makes the proof the
/// only door; a second one somewhere else would be a door with no lock on it.
#[test]
fn nothing_outside_the_gate_collects_a_request_body() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let entries = fs::read_dir(&root).expect("the crate has a src directory");
    for entry in entries {
        let path = entry.expect("readable directory entry").path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        // `gate.rs` is the one door. `probe.rs` is the instrument that *produces* a request body
        // and polls one only in its own tests; `wire.rs` drains responses, which is the other
        // direction entirely.
        if path
            .file_name()
            .is_some_and(|name| name == "gate.rs" || name == "probe.rs" || name == "wire.rs")
        {
            continue;
        }
        let text = fs::read_to_string(&path).expect("readable source file");
        if text.contains("http_body_util::Limited") || text.contains(".frame().await") {
            offenders.push(path);
        }
    }
    assert!(offenders.is_empty(), "a request body is drained outside the gate: {offenders:#?}");
}
