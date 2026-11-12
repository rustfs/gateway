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

//! The census binding [`super::in_process_only::IN_PROCESS_ONLY`] to the in-process sources.
//!
//! Responsible for: proving that every case-id literal in the non-test in-process sources is in
//! that table or in [`CONFIGURATION_ONLY`]; and, independently of how a hook spells its case,
//! that every corpus case whose `Sut::finish` verdict moves with a hook counter is in the table.
//! NOT responsible for: whether a configuration-only case is really answerable by an endpoint (a
//! reviewer judges each row of [`CONFIGURATION_ONLY`]) or the external skip (`crate::conn`).
//! Upstream: `crate::corpus` and the crate's own sources; downstream: nothing.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use super::InProcess;
use super::in_process_only::IN_PROCESS_ONLY;
use crate::sut::Sut;

/// Cases the in-process target configures by id whose verdict an external endpoint can still
/// give, because an operator can enable the same behaviour on a real server.
const CONFIGURATION_ONLY: &[&str] = &[
    // SigV2 presigned compatibility, which the RustFS preset enables.
    "c-sig-0545",
    "c-sig-0548",
    // The legacy POST form grammar, which the RustFS profile selects.
    "c-post-0022",
];

/// Case-id literals in `source` outside comments and its trailing `mod tests` block.
fn literals(source: &str) -> BTreeSet<String> {
    let code = source.split("#[cfg(test)]\nmod tests").next().unwrap_or(source);
    let mut found = BTreeSet::new();
    for line in code.lines() {
        let line = line.split("//").next().unwrap_or("");
        for quoted in line.split('"').skip(1).step_by(2) {
            let mut parts = quoted.split('-');
            let shaped = parts.next() == Some("c")
                && quoted.len() > 7
                && quoted
                    .rsplit('-')
                    .next()
                    .is_some_and(|tail| tail.len() == 4 && tail.bytes().all(|b| b.is_ascii_digit()))
                && quoted
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if shaped {
                found.insert(quoted.to_owned());
            }
        }
    }
    found
}

fn in_process_sources() -> Vec<(String, String)> {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = vec![src.join("inprocess.rs")];
    let mut nested: Vec<_> = std::fs::read_dir(src.join("inprocess"))
        .expect("the in-process module directory")
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "rs"))
        .filter(|path| !path.file_name().is_some_and(|name| name.to_string_lossy().contains("tests")))
        .filter(|path| !path.ends_with("in_process_only.rs"))
        .collect();
    nested.sort();
    files.extend(nested);
    files
        .into_iter()
        .map(|path| (path.display().to_string(), std::fs::read_to_string(&path).expect("a source file")))
        .collect()
}

/// Negative — a case id an in-process hook or configuration names is declared one way or the
/// other, so a new hook cannot leave its case running vacuously against an endpoint.
#[test]
fn every_case_id_the_in_process_sources_name_is_declared() {
    let declared: BTreeSet<&str> = IN_PROCESS_ONLY
        .iter()
        .map(|(id, _)| *id)
        .chain(CONFIGURATION_ONLY.iter().copied())
        .collect();
    let mut seen = 0;
    for (path, source) in in_process_sources() {
        for id in literals(&source) {
            seen += 1;
            assert!(declared.contains(id.as_str()), "{path} names {id}, which neither table declares");
        }
    }
    assert!(seen >= 25, "the scan found {seen} literals; it is not reading the sources");
    for id in CONFIGURATION_ONLY {
        assert!(!IN_PROCESS_ONLY.iter().any(|(other, _)| other == id), "{id} is in both tables");
    }
}

/// Negative — every table row names a corpus case, so a renamed case cannot leave a dead row.
#[test]
fn every_declared_case_exists_in_the_corpus() {
    let root = crate::corpus::Corpus::discover_root().expect("repository corpus");
    let corpus = crate::corpus::Corpus::load(&root).expect("corpus loads");
    let ids: BTreeSet<&str> = corpus.cases().iter().map(|case| case.id.as_str()).collect();
    for id in IN_PROCESS_ONLY
        .iter()
        .map(|(id, _)| *id)
        .chain(CONFIGURATION_ONLY.iter().copied())
    {
        assert!(ids.contains(id), "{id} is declared but not in the corpus");
    }
}

/// Whether `finish` for `case_id` fails with every hook counter set to `count`.
fn finish_fails(root: &std::path::Path, case_id: &str, count: usize) -> bool {
    let mut target = InProcess::new(root.to_path_buf());
    for counter in [
        &target.authz_backend_calls,
        &target.credential_backend_calls,
        &target.credential_governor_calls,
    ] {
        counter.store(count, Ordering::SeqCst);
    }
    target.credential_exchanges.store(count, Ordering::SeqCst);
    if count > 0
        && let Ok(mut lengths) = target.post_object_lengths.lock()
    {
        lengths.push((None, None));
    }
    target.finish(case_id).is_err()
}

/// Negative — derived from behaviour, not spelling: a corpus case whose `finish` fails with every
/// hook at zero or at a count no case expects reads a hook, and must be in the table.
#[test]
fn every_case_a_hook_counter_decides_is_in_process_only() {
    let root = crate::corpus::Corpus::discover_root().expect("repository corpus");
    let corpus = crate::corpus::Corpus::load(&root).expect("corpus loads");
    let hooked: Vec<&str> = corpus
        .cases()
        .iter()
        .map(|case| case.id.as_str())
        .filter(|id| finish_fails(&root, id, 0) || finish_fails(&root, id, 1_000_000))
        .collect();
    assert!(
        hooked.len() >= 10,
        "the census found {} hooked cases; it is not reaching finish",
        hooked.len()
    );
    for id in hooked {
        assert!(super::unavailable_externally(id).is_some(), "{id} reads a hook but runs externally");
    }
}

/// Negative — every reason names its case and the endpoint; near misses stay available.
#[test]
fn reasons_name_their_case_and_near_misses_stay_available() {
    for (id, _) in IN_PROCESS_ONLY {
        let reason = super::unavailable_externally(id).expect("a declared case");
        assert!(reason.starts_with(id) && reason.contains("external endpoint"), "{reason}");
    }
    for id in ["c-authz-00080", "C-AUTHZ-0008", "c-cred-002", "c-sig-0545", ""] {
        assert_eq!(super::unavailable_externally(id), None, "{id:?}");
    }
}
