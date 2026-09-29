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

//! Fixed-seed replay of the `post_form` fuzz property inside the ordinary test gate.
//!
//! Responsible for: running every committed seed under `fuzz/seeds/post_form/` through the same
//! property file the fuzz target runs, pinning the exact outcome of each hand-written seed — both
//! form grammars on either side of each rule that separates them; the field, field-count, policy,
//! part-header, prelude and file ceilings; the field rules; and a SigV4 and a SigV2 policy each
//! parser accepts — and driving twenty thousand deterministic mutations of those seeds through the
//! property on stable, with coverage floors stated as counts. The whole-stream ceiling has no
//! seed: under the tight ceilings every body that reaches it first breaks the file, prelude or
//! closing rule, which is also why the property excuses it when framings race to it.
//! NOT responsible for: fuzzing (the nightly lane runs libFuzzer), the form grammar case by case
//! (`rustfs-gateway-http`'s `form_grammar.rs` and `form_limits.rs`), or the policy's signature.
//! Upstream: `fuzz/support/post_form.rs` and the committed seeds. Downstream: Cargo's harness.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustfs_gateway_http::FormReject;

#[path = "../../../fuzz/support/post_form.rs"]
mod post_form;

use post_form::{Outcome, Verdict, check};

/// Every hand-written seed and the outcome it pins: `Ok(field count)` for a read form, or the
/// refusal. Each must exist; none may be skipped.
const REQUIRED_SEEDS: [(&str, Result<usize, FormReject>); 25] = [
    ("gateway-browser-form", Ok(4)),
    ("legacy-browser-form", Ok(4)),
    ("legacy-preamble", Ok(4)),
    ("gateway-preamble-refused", Err(FormReject::MalformedPart)),
    ("legacy-epilogue-refused", Err(FormReject::ClosingNotLast)),
    ("gateway-epilogue-read", Ok(4)),
    ("legacy-close-padding-without-length", Ok(4)),
    ("legacy-close-padding-with-length-refused", Err(FormReject::ClosingNotLast)),
    ("legacy-bare-values-and-quoted-semicolon", Ok(1)),
    ("gateway-bare-name-refused", Err(FormReject::MalformedPart)),
    ("legacy-boundary-outside-bchars-refused", Err(FormReject::MalformedContentType)),
    ("gateway-boundary-outside-bchars-read", Ok(1)),
    ("tight-field-too-large", Err(FormReject::FieldTooLarge)),
    ("tight-too-many-fields", Err(FormReject::TooManyFields)),
    ("duplicate-field-refused", Err(FormReject::DuplicateField)),
    ("control-byte-value-refused", Err(FormReject::MalformedFieldValue)),
    ("signed-v4-policy", Ok(7)),
    ("signed-v4-policy-unknown-variable", Ok(7)),
    ("signed-v2-policy", Ok(5)),
    ("tight-part-header-too-large", Err(FormReject::PartHeaderTooLarge)),
    ("tight-policy-too-large", Err(FormReject::PolicyTooLarge)),
    ("file-over-ceiling-refused", Err(FormReject::FileTooLarge)),
    ("legacy-bare-lf-header", Ok(1)),
    ("legacy-control-byte-name-refused", Err(FormReject::MalformedPart)),
    ("legacy-preamble-past-prelude-bound-refused", Err(FormReject::PreludeTooLarge)),
];

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/post_form")
}

fn seed(name: &str) -> Vec<u8> {
    let path = seed_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|error| panic!("required seed {} is missing: {error}", path.display()))
}

fn replay(name: &str) -> Outcome {
    check(&seed(name)).unwrap_or_else(|| panic!("seed {name} is shorter than the selector"))
}

fn summary(outcome: &Outcome) -> Result<usize, FormReject> {
    match &outcome.verdict {
        Verdict::Read { fields, .. } => Ok(fields.len()),
        Verdict::Refused(reject) => Err(*reject),
    }
}

// ── positive ────────────────────────────────────────────────────────────────────────────────

/// Every hand-written seed reads, or is refused, exactly as pinned — each rule the two grammars
/// disagree on appears once on each side.
#[test]
fn every_required_seed_has_its_pinned_outcome() {
    for (name, expected) in REQUIRED_SEEDS {
        assert_eq!(summary(&replay(name)), expected, "{name}");
    }
}

/// The legacy grammar names the file the way `${filename}` needs, and the policy parsers see it.
#[test]
fn a_read_form_carries_its_file_and_names() {
    let Verdict::Read {
        filename,
        file_name,
        file,
        ..
    } = replay("legacy-bare-values-and-quoted-semicolon").verdict
    else {
        panic!("the seed is read");
    };
    assert_eq!(
        (filename.as_deref(), file_name.as_deref(), file.as_slice()),
        (Some("a;b.txt"), Some("a;b.txt"), &b"c"[..])
    );
    let Verdict::Read { file, .. } = replay("legacy-bare-lf-header").verdict else {
        panic!("the seed is read");
    };
    assert_eq!(file, b"\r\nhello");
}

/// Each signed seed is a policy exactly one parser accepts, so both parsers' invariants run.
#[test]
fn each_signed_seed_is_a_policy_its_parser_accepts() {
    let outcome = replay("signed-v4-policy");
    assert_eq!((outcome.sig_v4, outcome.sig_v2), (Some(true), Some(false)));
    let outcome = replay("signed-v2-policy");
    assert_eq!((outcome.sig_v4, outcome.sig_v2), (Some(false), Some(true)));
}

// ── negative ────────────────────────────────────────────────────────────────────────────────

/// The same policy with a key naming a variable other than `${filename}` is refused: a key must
/// never keep a variable nobody substituted.
#[test]
fn a_key_with_an_unknown_variable_is_no_policy() {
    let outcome = replay("signed-v4-policy-unknown-variable");
    assert_eq!((outcome.sig_v4, outcome.sig_v2), (Some(false), Some(false)));
}

/// Every committed seed, named or not, passes the property: none panics.
#[test]
fn every_committed_seed_passes_the_property() {
    let mut count = 0usize;
    for entry in std::fs::read_dir(seed_dir()).expect("the seed directory exists") {
        let path = entry.expect("a readable seed entry").path();
        let input = std::fs::read(&path).expect("a readable seed");
        let _ = check(&input);
        count += 1;
    }
    assert!(
        count >= REQUIRED_SEEDS.len(),
        "{count} seeds, fewer than the {} required",
        REQUIRED_SEEDS.len()
    );
}

/// Twenty thousand deterministic mutations of the seeds pass the property, and between them reach
/// both grammars' reads and every refusal the seeds pin.
#[test]
fn twenty_thousand_mutated_forms_pass_the_property() {
    const SAMPLES: usize = 20_000;
    let seeds: Vec<Vec<u8>> = REQUIRED_SEEDS.iter().map(|(name, _)| seed(name)).collect();
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let fragments: [&[u8]; 8] = [
        b"\r\n",
        b"--fuzzboundary",
        b"\r\n--fuzzboundary",
        b"\"",
        b";",
        b" ",
        b"\n",
        b"--",
    ];
    let mut reads: BTreeMap<bool, usize> = BTreeMap::new();
    let mut refusals: BTreeMap<&'static str, usize> = BTreeMap::new();
    for _ in 0..SAMPLES {
        let base = &seeds[(next() % seeds.len() as u64) as usize];
        let mut input = base.clone();
        // Re-select the grammar, content type, ceilings and framing half of the time.
        if next() % 2 == 0 {
            input[0] = next() as u8;
            input[1] = next() as u8;
        }
        for _ in 0..=(next() % 3) {
            let at = 2 + (next() as usize) % (input.len() - 1);
            match next() % 4 {
                0 => input.insert(at, next() as u8),
                1 if at < input.len() => {
                    input.remove(at);
                }
                2 => {
                    let fragment = fragments[(next() % fragments.len() as u64) as usize];
                    input.splice(at..at, fragment.iter().copied());
                }
                _ if at < input.len() => input[at] = next() as u8,
                _ => {}
            }
        }
        // Bits 0-1 of the selector: 1 and 2 are the legacy grammar, 0 and 3 the gateway grammar.
        let legacy = matches!(input[0] & 0b11, 1 | 2);
        match check(&input).map(|outcome| outcome.verdict) {
            Some(Verdict::Read { .. }) => *reads.entry(legacy).or_default() += 1,
            Some(Verdict::Refused(reject)) => *refusals.entry(reject.as_str()).or_default() += 1,
            None => {}
        }
    }
    for (legacy, grammar) in [(false, "gateway"), (true, "legacy")] {
        let read = reads.get(&legacy).copied().unwrap_or_default();
        assert!(
            read >= SAMPLES / 40,
            "only {read} of {SAMPLES} mutations were read under the {grammar} grammar"
        );
    }
    for (_, expected) in REQUIRED_SEEDS {
        if let Err(reject) = expected {
            assert!(
                refusals.contains_key(reject.as_str()),
                "no mutation was refused as {reject}: {refusals:?}"
            );
        }
    }
}
