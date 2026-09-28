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

//! Responsible for: the compile-time line of defence, measured — a build of this crate without
//! `corpus-record` contains no recorder symbol, and the scan that says so finds the symbol when it
//! is there (a-cp-0009's gateway-side analogue).
//! Not responsible for: the RustFS release binary, which the RustFS repository greps itself.
//! Upstream: `rustc`, compiling `src/lib.rs` without the feature.
//! Downstream: nothing.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::support::scratch;

const SYMBOL: &[u8] = b"CorpusRecorderLayer";

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack.windows(needle.len()).filter(|window| *window == needle).count()
}

/// Compiles the crate root exactly as a build without the feature would, and returns the object
/// file. No `--extern` is passed: if a recorder item escaped its `cfg` gate, it would name a
/// dependency this compile does not have, and the compile itself would fail.
fn featureless_object() -> PathBuf {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let out = scratch("symbols").join("featureless.o");
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let status = Command::new(rustc)
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "rlib",
            "--crate-name",
            "rustfs_gateway_corpus_recorder",
        ])
        .args(["--emit", "obj", "-o"])
        .arg(&out)
        .arg(&crate_root)
        .status()
        .expect("rustc runs");
    assert!(status.success(), "the crate must compile with no feature and no dependency at all");
    out
}

/// Negative (compile-time gate) — without `corpus-record` the compiled crate carries no recorder
/// symbol at all.
#[test]
fn n_a_build_without_the_feature_contains_no_recorder_symbol() {
    let object = std::fs::read(featureless_object()).expect("an object file");
    assert_eq!(occurrences(&object, SYMBOL), 0);
}

/// Positive (the control) — the same scan finds the symbol in this test binary, which was built
/// with the feature. Without this, the negative above could pass by scanning for the wrong thing.
#[test]
fn the_symbol_scan_finds_the_recorder_in_a_featured_build() {
    let _ = rustfs_gateway_corpus_recorder::CorpusRecorderLayer::stats;
    let binary = std::fs::read(std::env::current_exe().expect("the test binary")).expect("readable");
    assert!(occurrences(&binary, SYMBOL) > 0);
}
