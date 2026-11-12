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

//! The census binding [`super::unavailable_externally`] to the cases whose verdict reads a hook.
//!
//! Responsible for: deriving, from this target's own `Sut::finish`, which corpus cases a hook
//! counter decides, and proving that set equals the unavailable-externally set apart from the one
//! named fixture-capability case. A case's `finish` is run with every hook at zero and at a value
//! no case expects; one whose result moves, or fails either way, reads a hook.
//! NOT responsible for: hooks judged outside `finish` (a reviewer checks those, see below) or the
//! external skip itself (`crate::conn`). Upstream: `crate::corpus`; downstream: nothing.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use super::InProcess;
use crate::sut::Sut;

/// Unavailable externally for a fixture capability, not a hook: c-post-0026's refusal depends on
/// the bundled fixture having no KMS.
const CAPABILITY_ONLY: &str = "c-post-0026";

/// Whether `finish` for `case_id` fails with every hook set to `count`.
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
    if let Ok(mut lengths) = target.post_object_lengths.lock() {
        lengths.extend(std::iter::repeat_n((None, None), count.min(1)));
    }
    target.finish(case_id).is_err()
}

fn corpus_ids() -> (std::path::PathBuf, Vec<String>) {
    let root = crate::corpus::Corpus::discover_root().expect("repository corpus");
    let corpus = crate::corpus::Corpus::load(&root).expect("corpus loads");
    let ids = corpus.cases().iter().map(|case| case.id.clone()).collect();
    (root, ids)
}

/// Negative — every corpus case whose verdict a hook decides is skipped on an external endpoint,
/// and nothing else is, so a hook added to `finish` without a skip turns this red, and so does a
/// skip that hides a case no hook decides.
#[test]
fn every_case_a_hook_decides_is_unavailable_externally_and_no_other() {
    let (root, ids) = corpus_ids();
    let hooked: BTreeSet<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| finish_fails(&root, id, 0) || finish_fails(&root, id, 1_000_000))
        .collect();
    let unavailable: BTreeSet<&str> = ids
        .iter()
        .map(String::as_str)
        .filter(|id| super::unavailable_externally(id).is_some() && *id != CAPABILITY_ONLY)
        .collect();
    assert!(
        hooked.len() >= 10,
        "the census found {} hooked cases; the probe is not reaching finish",
        hooked.len()
    );
    assert_eq!(hooked, unavailable, "hooked cases and unavailable-externally cases differ");
    assert!(super::unavailable_externally(CAPABILITY_ONLY).is_some());
}

/// Negative — every reason names its case and says why an endpoint cannot answer.
#[test]
fn every_unavailable_reason_names_its_case_and_the_in_process_target() {
    let (_, ids) = corpus_ids();
    for id in &ids {
        if let Some(reason) = super::unavailable_externally(id) {
            assert!(reason.starts_with(id.as_str()), "{reason}");
            assert!(reason.contains("external endpoint"), "{reason}");
        }
    }
}

/// Negative — near misses of a counted id stay available, so the table matches exact ids.
#[test]
fn near_misses_of_a_counted_case_stay_available() {
    for id in ["c-authz-00080", "C-AUTHZ-0008", "c-cred-002", "c-authz-1019", ""] {
        assert_eq!(super::unavailable_externally(id), None, "{id:?}");
    }
}
