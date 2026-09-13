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

//! Fixed-seed replay of the `policy_json` fuzz property inside the ordinary test gate.
//!
//! Responsible for: running every committed seed under `fuzz/seeds/policy_json/` through the same
//! property file the fuzz target runs, pinning the exact outcome of the twenty-four hand-written
//! seeds — each ceiling at and one past its boundary, repeated member names, the shapes a laxer
//! scanner let through, every non-object root, whitespace alone and a body that is not text — and
//! driving twenty thousand deterministic samples through that property on stable, with coverage
//! floors stated as counts.
//! NOT responsible for: fuzzing — `ci.yml` defers libFuzzer runs to a schedule — or the wire
//! answers, which conformance cases `c-bucketconfig-0051` to `-0057` pin.
//! Upstream: `fuzz/support/policy_json.rs` and the committed seeds. Downstream: Cargo's harness.

use std::path::{Path, PathBuf};

use rustfs_gateway_core::ops::shared::bucket_policy::{MAX_POLICY_BYTES, MAX_POLICY_DEPTH, PolicyRejection};

#[path = "../../../fuzz/support/policy_json.rs"]
mod policy_json;

use policy_json::{Outcome, Reading, Refusal, check, escaped_spelling, wrapped};

/// The seeds the property's two directions rest on. Each must exist; none may be skipped.
const REQUIRED_SEEDS: [&str; 24] = [
    "valid-policy",
    "valid-escapes-and-numbers",
    "sibling-objects-reuse-a-name",
    "duplicate-name",
    "duplicate-name-escaped-spelling",
    "name-not-a-string",
    "name-without-value",
    "missing-colon",
    "second-colon",
    "trailing-comma",
    "escape-json-lacks",
    "unpaired-surrogate",
    "number-leading-zero",
    "number-out-of-range",
    "trailing-form-feed",
    "array-root",
    "string-root",
    "whitespace-only",
    "not-utf8",
    "depth-at-ceiling",
    "depth-over-ceiling",
    "too-deep-before-broken",
    "size-at-ceiling",
    "size-over-ceiling",
];

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/policy_json")
}

fn replay(name: &str) -> Outcome {
    let path = seed_dir().join(name);
    let input = std::fs::read(&path).unwrap_or_else(|error| panic!("required seed {} is missing: {error}", path.display()));
    check(&input)
}

fn refusal(name: &str) -> PolicyRejection {
    match replay(name).verdict {
        Err(Refusal::Policy(rejection)) => rejection,
        other => panic!("seed {name} was answered {other:?}"),
    }
}

fn accepted(name: &str) -> Outcome {
    let outcome = replay(name);
    assert_eq!(outcome.verdict, Ok(()), "seed {name} was refused");
    outcome
}

// ---------------------------------------------------------------------------------------------
// Positive controls. Without them, a scanner that refused everything would pass every refusal.
// ---------------------------------------------------------------------------------------------

/// An AWS-shaped policy is accepted and every probe runs on it: stored and read back verbatim,
/// padded to the size ceiling, wrapped to the depth ceiling, its first name repeated under an
/// escaped spelling, and re-serialised.
#[test]
fn an_aws_shaped_policy_is_accepted_and_every_probe_runs() {
    let outcome = accepted("valid-policy");
    assert_eq!(
        outcome.reading,
        Some(Reading::Object {
            depth: 5,
            first_name: Some("Version".to_owned())
        })
    );
    assert!(
        outcome.probes.size && outcome.probes.depth && outcome.probes.duplicate && outcome.probes.canonical,
        "{:?}",
        outcome.probes
    );
}

/// Every escape JSON has, a surrogate pair, `-0`, a fraction, an underflowing exponent, an
/// upper-case exponent with a sign and an integer past `u64` are all JSON, and all accepted: the
/// strictness below is JSON's, not a narrower dialect.
#[test]
fn every_escape_and_number_form_json_has_is_accepted() {
    accepted("valid-escapes-and-numbers");
}

/// A name is unique within its object, not across the document: two statements each with a `Sid`
/// and an `Effect` is the ordinary shape of a policy.
#[test]
fn sibling_objects_may_reuse_a_member_name() {
    accepted("sibling-objects-reuse-a-name");
}

// ---------------------------------------------------------------------------------------------
// Repeated member names.
// ---------------------------------------------------------------------------------------------

/// `"Effect":"Allow","Effect":"Deny"` in one statement: first-wins and last-wins readers disagree
/// about what it grants, and RustFS's typed reader refuses it.
#[test]
fn a_repeated_member_name_is_refused() {
    assert_eq!(refusal("duplicate-name"), PolicyRejection::NotJson);
    assert!(matches!(replay("duplicate-name").reading, Some(Reading::Duplicate { .. })));
}

/// `"Version"` and `"\u0056ersion"` are one name. A scanner that compared raw bytes would store
/// both, and the reader would take whichever it happens to keep.
#[test]
fn a_member_name_repeated_under_an_escaped_spelling_is_refused() {
    assert_eq!(refusal("duplicate-name-escaped-spelling"), PolicyRejection::NotJson);
    assert_eq!(escaped_spelling("Version"), "\\u0056ersion");
    assert_eq!(escaped_spelling("\u{1f600}x"), "\\ud83d\\ude00x");
}

// ---------------------------------------------------------------------------------------------
// Shapes a bracket-balancing scanner lets through and a strict reader does not.
// ---------------------------------------------------------------------------------------------

/// Each of these was accepted by the scanner before this property existed.
#[test]
fn every_shape_a_strict_reader_refuses_is_refused_as_not_json() {
    for name in [
        "name-not-a-string",
        "name-without-value",
        "missing-colon",
        "second-colon",
        "trailing-comma",
        "escape-json-lacks",
        "unpaired-surrogate",
        "number-leading-zero",
        "number-out-of-range",
        "trailing-form-feed",
    ] {
        assert_eq!(refusal(name), PolicyRejection::NotJson, "{name}");
        assert!(matches!(replay(name).reading, Some(Reading::Invalid { .. })), "{name}");
    }
}

/// Well-formed JSON that is not an object is not a policy.
#[test]
fn a_root_that_is_not_an_object_is_refused_as_not_an_object() {
    assert_eq!(refusal("array-root"), PolicyRejection::NotAnObject);
    assert_eq!(refusal("string-root"), PolicyRejection::NotAnObject);
}

/// Whitespace alone is an empty write, which is `DeleteBucketPolicy`'s job.
#[test]
fn whitespace_alone_is_refused_as_empty() {
    assert_eq!(refusal("whitespace-only"), PolicyRejection::Empty);
}

/// A body that is not UTF-8 never reaches the checks: the codec refuses it as `MalformedPolicy`.
#[test]
fn a_body_that_is_not_text_is_refused_by_the_codec() {
    assert_eq!(replay("not-utf8").verdict, Err(Refusal::NotUtf8));
}

// ---------------------------------------------------------------------------------------------
// Each ceiling, at its boundary and one past it.
// ---------------------------------------------------------------------------------------------

/// A hundred nested objects is the ceiling, and is accepted.
#[test]
fn a_document_exactly_as_deep_as_the_ceiling_is_accepted() {
    let outcome = accepted("depth-at-ceiling");
    assert!(matches!(outcome.reading, Some(Reading::Object { depth, .. }) if depth == MAX_POLICY_DEPTH));
}

/// A hundred and one is refused by name.
#[test]
fn a_document_one_level_past_the_ceiling_is_refused_as_too_deep() {
    assert_eq!(refusal("depth-over-ceiling"), PolicyRejection::TooDeep);
}

/// The first rule broken, left to right, is the one reported: nesting past the ceiling is refused
/// at the level that crosses it, before the broken token after it is reached.
#[test]
fn nesting_past_the_ceiling_is_reported_before_later_broken_syntax() {
    assert_eq!(refusal("too-deep-before-broken"), PolicyRejection::TooDeep);
}

/// Exactly 20 KiB is accepted.
#[test]
fn a_document_exactly_at_the_size_ceiling_is_accepted() {
    let outcome = accepted("size-at-ceiling");
    assert!(outcome.probes.size, "the size probe runs at exactly the ceiling");
}

/// One byte more is refused by its length.
#[test]
fn a_document_one_byte_past_the_size_ceiling_is_refused_as_too_large() {
    assert_eq!(refusal("size-over-ceiling"), PolicyRejection::TooLarge);
    assert_eq!(
        std::fs::read(seed_dir().join("size-over-ceiling"))
            .map(|seed| seed.len())
            .ok(),
        Some(MAX_POLICY_BYTES + 1)
    );
}

/// Every committed seed — the twenty-four above and any minimised regression added later —
/// replays under the property's own assertions. A missing directory or required seed fails.
#[test]
fn every_committed_seed_replays_under_the_fuzz_property() {
    let dir = seed_dir();
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("seed directory {} is missing: {error}", dir.display()))
        .map(|entry| {
            entry
                .expect("a readable directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    for required in REQUIRED_SEEDS {
        assert!(names.iter().any(|name| name == required), "required seed {required} is missing");
    }
    for name in &names {
        replay(name);
    }
}

// ---------------------------------------------------------------------------------------------
// Twenty thousand deterministic samples.
// ---------------------------------------------------------------------------------------------

const NAMES: [&str; 12] = [
    "Version",
    "Statement",
    "Sid",
    "Effect",
    "Principal",
    "Action",
    "Resource",
    "Condition",
    "NotAction",
    "AWS",
    "aws:SourceIp",
    "\u{e9}t\u{e9}",
];
const STRINGS: [&str; 10] = [
    "\"2012-10-17\"",
    "\"Allow\"",
    "\"arn:aws:s3:::photos/*\"",
    "\"s3:GetObject\"",
    "\"\"",
    "\"a\\\"b\\\\c\\/d\"",
    "\"\\u00e9\\n\\t\"",
    "\"\\ud83d\\ude00\"",
    "\"\u{e9}\u{1f600}\"",
    "\"*\"",
];
const NUMBERS: [&str; 8] = ["0", "-0", "1", "42", "3.25", "-1e3", "1E+2", "1e-400"];
/// What a pick draws one time in [`HAZARD_ODDS`] instead: each is refused by a strict reader.
const HAZARDS: [&str; 12] = [
    "01",
    "1.",
    ".5",
    "+1",
    "1e",
    "1e400",
    "\"\\x\"",
    "\"\\ud800\"",
    "\"\\u12\"",
    "\"a\u{1}b\"",
    "tru",
    "\"\\udc00\"",
];
const HAZARD_ODDS: usize = 40;

/// A xorshift sequence: a failed sample is reproducible from its index alone.
struct Sampler(u64);

impl Sampler {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound).expect("a small bound")).expect("below a usize bound")
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn space(&mut self, out: &mut String) {
        if self.below(6) == 0 {
            out.push_str(self.pick(&[" ", "\n", "\t ", "\r\n"]));
        }
    }

    fn scalar(&mut self, out: &mut String) {
        if self.below(HAZARD_ODDS) == 0 {
            out.push_str(self.pick(&HAZARDS));
            return;
        }
        match self.below(4) {
            0 => out.push_str(self.pick(&NUMBERS)),
            1 => out.push_str(self.pick(&["true", "false", "null"])),
            _ => out.push_str(self.pick(&STRINGS)),
        }
    }

    fn value(&mut self, out: &mut String, depth: usize) {
        match self.below(if depth >= 5 { 1 } else { 5 }) {
            0 => self.scalar(out),
            1 => self.array(out, depth + 1),
            _ => self.object(out, depth + 1),
        }
    }

    fn array(&mut self, out: &mut String, depth: usize) {
        out.push('[');
        for index in 0..self.below(4) {
            if index > 0 {
                out.push(',');
            }
            self.space(out);
            self.value(out, depth);
        }
        out.push(']');
    }

    fn object(&mut self, out: &mut String, depth: usize) {
        out.push('{');
        // Consecutive names, so an object repeats one only when a hazard below asks for it.
        let first = self.below(NAMES.len());
        let members = self.below(5);
        for index in 0..members {
            if index > 0 {
                out.push(',');
            }
            self.space(out);
            let name = NAMES[(first + index) % NAMES.len()];
            match self.below(HAZARD_ODDS) {
                0 => out.push('7'),
                1 => out.push_str(&format!("\"{name}\":null,\"{name}\"")),
                2 => out.push_str(&format!("\"{name}\":null,\"{}\"", escaped_spelling(name))),
                _ => out.push_str(&format!("\"{name}\"")),
            }
            out.push(':');
            self.space(out);
            self.value(out, depth);
        }
        if members > 0 && self.below(HAZARD_ODDS) == 0 {
            out.push(',');
        }
        out.push('}');
    }

    /// One body: a generated document, mostly an object, sometimes nested near the depth ceiling,
    /// padded near the size ceiling, reduced to whitespace, or damaged by one byte or a truncation.
    fn sample(&mut self) -> Vec<u8> {
        let mut document = String::new();
        self.space(&mut document);
        match self.below(12) {
            0 => self.array(&mut document, 1),
            1 => self.scalar(&mut document),
            _ => self.object(&mut document, 1),
        }
        self.space(&mut document);
        match self.below(40) {
            0..=2 => document = wrapped(&document, MAX_POLICY_DEPTH - 6 + self.below(10)),
            3..=4 => {
                let target = MAX_POLICY_BYTES - 2 + self.below(5);
                let pad = target.saturating_sub(document.len());
                document.extend(std::iter::repeat_n(' ', pad));
            }
            5 => document = " \t\r\n".repeat(self.below(3)),
            _ => {}
        }
        let mut bytes = document.into_bytes();
        match self.below(14) {
            0 if !bytes.is_empty() => {
                let at = self.below(bytes.len());
                bytes[at] = self.next().to_le_bytes()[0];
            }
            1 if !bytes.is_empty() => {
                let keep = self.below(bytes.len());
                bytes.truncate(keep);
            }
            _ => {}
        }
        bytes
    }
}

/// Samples per shard. Four shards run on separate test threads.
const SHARD_SAMPLES: u32 = 5_000;

/// The property over one shard. The counts are the other half: a sampler that drifted into
/// producing only broken documents would pass every assertion while exercising nothing, so each
/// verdict, each kind of strict-reader refusal and each probe must be reached a stated number of
/// times.
fn hold_the_policy_property_over_a_shard(seed: u64) {
    let mut sampler = Sampler(seed);
    let mut counts = std::collections::BTreeMap::<&'static str, u32>::new();
    let mut bump = |name: &'static str| *counts.entry(name).or_default() += 1;
    for _ in 0..SHARD_SAMPLES {
        let outcome = check(&sampler.sample());
        match outcome.verdict {
            Ok(()) => bump("accepted"),
            Err(Refusal::NotUtf8) => bump("NotUtf8"),
            Err(Refusal::Policy(PolicyRejection::TooLarge)) => bump("TooLarge"),
            Err(Refusal::Policy(PolicyRejection::TooDeep)) => bump("TooDeep"),
            Err(Refusal::Policy(PolicyRejection::NotAnObject)) => bump("NotAnObject"),
            Err(Refusal::Policy(PolicyRejection::Empty)) => bump("Empty"),
            Err(Refusal::Policy(PolicyRejection::NotJson)) => bump("NotJson"),
        }
        match outcome.reading {
            Some(Reading::Duplicate { .. }) => bump("reader-duplicate"),
            Some(Reading::Invalid { .. }) => bump("reader-invalid"),
            _ => {}
        }
        for (ran, name) in [
            (outcome.probes.size, "probe-size"),
            (outcome.probes.depth, "probe-depth"),
            (outcome.probes.duplicate, "probe-duplicate"),
            (outcome.probes.canonical, "probe-canonical"),
        ] {
            if ran {
                bump(name);
            }
        }
    }
    for (name, floor) in [
        ("accepted", 1_000),
        ("NotJson", 1_700),
        ("TooDeep", 120),
        ("TooLarge", 60),
        ("NotAnObject", 330),
        ("Empty", 100),
        ("NotUtf8", 130),
        ("reader-duplicate", 850),
        ("reader-invalid", 900),
        ("probe-size", 1_000),
        ("probe-depth", 950),
        ("probe-duplicate", 500),
        ("probe-canonical", 1_000),
    ] {
        let count = counts.get(name).copied().unwrap_or(0);
        assert!(
            count >= floor,
            "seed {seed:#x}: {name} reached {count} times, floor {floor}; all: {counts:?}"
        );
    }
}

/// Twenty thousand fixed-seed samples, the first of four shards.
#[test]
fn fixed_seed_samples_hold_the_policy_property_shard_1_of_4() {
    hold_the_policy_property_over_a_shard(0x706f_6c69_6379_2d31);
}

/// Twenty thousand fixed-seed samples, the second of four shards.
#[test]
fn fixed_seed_samples_hold_the_policy_property_shard_2_of_4() {
    hold_the_policy_property_over_a_shard(0x6475_706c_6963_6174);
}

/// Twenty thousand fixed-seed samples, the third of four shards.
#[test]
fn fixed_seed_samples_hold_the_policy_property_shard_3_of_4() {
    hold_the_policy_property_over_a_shard(0x7374_7269_6374_2121);
}

/// Twenty thousand fixed-seed samples, the fourth of four shards.
#[test]
fn fixed_seed_samples_hold_the_policy_property_shard_4_of_4() {
    hold_the_policy_property_over_a_shard(0x3230_4b69_4221_2121);
}
