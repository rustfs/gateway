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

//! Fixed-seed replay of the `header_accept` fuzz property inside the ordinary test gate.
//!
//! Responsible for: running every committed seed under `fuzz/seeds/header_accept/` through the
//! same property file the fuzz target runs, pinning the exact outcome of the twelve hand-written
//! seeds — both ceilings at and one past their boundary, repeated and unreadable headers on both
//! sides of their rule, a nameless metadata header, and framing's precedence — and driving twenty
//! thousand deterministic samples through that property on stable, with coverage floors stated as
//! counts.
//! NOT responsible for: fuzzing — `ci.yml` defers libFuzzer runs to a schedule — or the named
//! wire cases in `header_and_query.rs` and `framing_smuggling.rs`, or turning a finding into a
//! conformance case, which needs a protocol oracle a crash does not carry.
//! Upstream: `fuzz/support/header_accept.rs` and the committed seeds. Downstream: Cargo's harness.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use http::HeaderName;
use rustfs_gateway_http::{LimitKind, MetadataReject, WireReject};

#[path = "../../../fuzz/support/header_accept.rs"]
mod header_accept;

use header_accept::{Outcome, VOCABULARY, check};

/// The seeds the property's two directions rest on. Each must exist; none may be skipped.
const REQUIRED_SEEDS: [&str; 12] = [
    "at-count-ceiling",
    "over-count-ceiling",
    "repeats-count-separately",
    "at-byte-ceiling",
    "over-byte-ceiling",
    "duplicate-x-amz-date",
    "duplicate-content-length",
    "duplicate-range-tolerated",
    "non-utf8-significant",
    "non-utf8-unrelated-tolerated",
    "metadata-without-a-name",
    "unrepresentable-name-skipped",
];

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/header_accept")
}

fn replay(name: &str) -> Outcome {
    let path = seed_dir().join(name);
    let input = std::fs::read(&path).unwrap_or_else(|error| panic!("required seed {} is missing: {error}", path.display()));
    check(&input).unwrap_or_else(|| panic!("seed {name} is shorter than the case header"))
}

// ── positive ────────────────────────────────────────────────────────────────────────────────

/// Count ceiling eight: `host` and seven more fields are accepted. Without this positive control,
/// an acceptance layer that refused every head would satisfy each refusal below.
#[test]
fn a_head_with_exactly_the_ceiling_of_fields_is_accepted() {
    let outcome = replay("at-count-ceiling");
    assert_eq!(outcome.verdict, Ok(()));
    assert_eq!(outcome.fields, 8);
}

/// Byte ceiling forty-eight: `host` (22 bytes) and a 26-byte field are accepted.
#[test]
fn a_head_exactly_at_the_byte_ceiling_is_accepted() {
    let outcome = replay("at-byte-ceiling");
    assert_eq!(outcome.verdict, Ok(()));
    assert_eq!(outcome.bytes, 48);
}

/// Two `Range` lines are one value the range grammar judges later (RFC 9110 §5.3); acceptance
/// does not refuse them.
#[test]
fn a_repeated_range_is_accepted() {
    assert_eq!(replay("duplicate-range-tolerated").verdict, Ok(()));
}

/// Non-UTF-8 bytes under a header a proxy added and this gateway never reads are accepted
/// (s3s#597).
#[test]
fn an_unreadable_unrelated_header_is_accepted() {
    assert_eq!(replay("non-utf8-unrelated-tolerated").verdict, Ok(()));
}

/// A name that is not a token never reaches the map, so it is not a field acceptance counts.
#[test]
fn a_name_http_cannot_hold_is_skipped_and_the_rest_accepted() {
    let outcome = replay("unrepresentable-name-skipped");
    assert_eq!(outcome.verdict, Ok(()));
    assert_eq!((outcome.fields, outcome.skipped), (2, 1));
}

/// Every committed seed — the twelve here and any minimised regression added later — replays
/// under the property's own assertions. A missing directory or required seed fails, not skips.
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

// ── negative ────────────────────────────────────────────────────────────────────────────────

/// Count ceiling eight: a ninth field is refused by name.
#[test]
fn one_field_past_the_count_ceiling_is_refused() {
    let outcome = replay("over-count-ceiling");
    assert_eq!(outcome.verdict, Err(WireReject::LimitExceeded(LimitKind::HeaderCount)));
    assert_eq!(outcome.fields, 9);
}

/// Count ceiling two: `host` and two `range` lines are three fields, not two names. A ceiling
/// that counted names would let one name carry any number of lines.
#[test]
fn repeated_lines_count_separately_against_the_count_ceiling() {
    let outcome = replay("repeats-count-separately");
    assert_eq!(outcome.verdict, Err(WireReject::LimitExceeded(LimitKind::HeaderCount)));
    assert_eq!(outcome.fields, 3);
}

/// Byte ceiling forty-eight: one more value byte is refused by name.
#[test]
fn one_byte_past_the_byte_ceiling_is_refused() {
    let outcome = replay("over-byte-ceiling");
    assert_eq!(outcome.verdict, Err(WireReject::LimitExceeded(LimitKind::HeaderBytes)));
    assert_eq!(outcome.bytes, 49);
}

/// Two `x-amz-date` lines are two answers to one question, and the refusal names the header.
#[test]
fn a_repeated_x_amz_date_is_refused_by_name() {
    assert_eq!(
        replay("duplicate-x-amz-date").verdict,
        Err(WireReject::DuplicateSingleValuedHeader("x-amz-date"))
    );
}

/// Two `Content-Length` lines — equal ones — are framing's W-4, decided before the header rule
/// that would also refuse them.
#[test]
fn a_repeated_content_length_is_refused_by_framing_first() {
    let outcome = replay("duplicate-content-length");
    assert_eq!(outcome.verdict, Err(WireReject::DuplicateContentLength));
    assert!(outcome.framing_refused);
}

/// An `x-amz-` header whose bytes are not UTF-8 would take part in a decision nobody could read.
#[test]
fn an_unreadable_significant_header_is_refused_by_name() {
    assert_eq!(
        replay("non-utf8-significant").verdict,
        Err(WireReject::NonUtf8SignificantHeader(HeaderName::from_static("x-amz-tagging")))
    );
}

/// `x-amz-meta-` with nothing after it names no metadata key.
#[test]
fn a_metadata_header_with_no_name_is_refused() {
    assert_eq!(
        replay("metadata-without-a-name").verdict,
        Err(WireReject::MalformedMetadata(MetadataReject::MalformedKey))
    );
}

// ── positive ────────────────────────────────────────────────────────────────────────────────
//
// Twenty thousand deterministic samples. Counted with the positive cases: every shard asserts
// refusals and acceptances alike, and claiming it for either side would be the guard's own
// question answered by fiat.

const VALUES: [&[u8]; 9] = [
    b"1",
    b"0",
    b"",
    b"bytes=0-4",
    b"chunked",
    b"=?UTF-8?B?w6k=?=",
    b"=?bogus?",
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    b"\xff\xfe",
];

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

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    /// Production's ceiling two times in three — the last entry of both tables, which 251 selects.
    fn selector(&mut self) -> u8 {
        if self.below(3) == 0 { self.byte() } else { 251 }
    }

    /// One input: two ceiling selectors, then up to a dozen fields named from the vocabulary, as
    /// custom tokens, or as raw bytes `http` usually cannot hold.
    fn sample(&mut self) -> Vec<u8> {
        let mut input = vec![self.selector(), self.selector()];
        for _ in 0..self.below(13) {
            match self.below(10) {
                0 => {
                    let length = self.below(8);
                    input.push(u8::try_from(length).expect("a short name"));
                    for _ in 0..length {
                        let byte = self.byte();
                        input.push(byte);
                    }
                }
                1 | 2 => {
                    let name = format!("x-custom-{}", self.below(4));
                    input.push(u8::try_from(name.len()).expect("a short name"));
                    input.extend_from_slice(name.as_bytes());
                }
                _ => input.push(0x80 | u8::try_from(self.below(VOCABULARY.len())).expect("a small index")),
            }
            let value: Vec<u8> = if self.below(16) == 0 {
                (0..self.below(6)).map(|_| self.byte()).collect()
            } else {
                VALUES[self.below(VALUES.len())].to_vec()
            };
            input.push(u8::try_from(value.len()).expect("a short value"));
            input.extend_from_slice(&value);
        }
        input
    }
}

/// Samples per shard. Four shards run on separate test threads.
const SHARD_SAMPLES: u32 = 5_000;

fn class(error: &WireReject) -> String {
    match error {
        WireReject::LimitExceeded(kind) => format!("{kind:?}"),
        other => {
            let debug = format!("{other:?}");
            debug.split('(').next().unwrap_or_default().to_owned()
        }
    }
}

/// The acceptance property over one shard. The counts are the other half: a sampler that drifted
/// into producing only framing refusals would pass every assertion while exercising no header
/// rule, so each header refusal, and acceptance itself, must be reached a stated number of times.
fn hold_the_header_property_over_a_shard(seed: u64) {
    let mut sampler = Sampler(seed);
    let (mut accepted, mut framing, mut skipped) = (0u32, 0u32, 0u32);
    let mut refused = BTreeMap::<String, u32>::new();
    for _ in 0..SHARD_SAMPLES {
        let input = sampler.sample();
        let outcome = check(&input).expect("every sample carries the case header");
        if outcome.skipped > 0 {
            skipped += 1;
        }
        match &outcome.verdict {
            Ok(()) => accepted += 1,
            Err(_) if outcome.framing_refused => framing += 1,
            Err(error) => *refused.entry(class(error)).or_default() += 1,
        }
    }
    let count = |name: &str| refused.get(name).copied().unwrap_or(0);
    assert!(accepted >= 1_000, "seed {seed:#x}: only {accepted} samples were accepted");
    assert!(framing >= 800, "seed {seed:#x}: only {framing} samples reached a framing refusal");
    assert!(skipped >= 1_600, "seed {seed:#x}: only {skipped} samples named a field http cannot hold");
    for (name, floor) in [
        ("HeaderCount", 160),
        ("HeaderBytes", 150),
        ("DuplicateSingleValuedHeader", 80),
        ("NonUtf8SignificantHeader", 490),
        ("MalformedMetadata", 210),
    ] {
        assert!(
            count(name) >= floor,
            "seed {seed:#x}: only {} samples were refused as {name}; all refusals: {refused:?}",
            count(name),
        );
    }
}

/// Twenty thousand fixed-seed samples, the first of four shards.
#[test]
fn fixed_seed_samples_hold_the_header_property_shard_1_of_4() {
    hold_the_header_property_over_a_shard(0x6865_6164_6572_7321);
}

/// Twenty thousand fixed-seed samples, the second of four shards.
#[test]
fn fixed_seed_samples_hold_the_header_property_shard_2_of_4() {
    hold_the_header_property_over_a_shard(0x6475_706c_6963_6174);
}

/// Twenty thousand fixed-seed samples, the third of four shards.
#[test]
fn fixed_seed_samples_hold_the_header_property_shard_3_of_4() {
    hold_the_header_property_over_a_shard(0x7574_662d_3821_2121);
}

/// Twenty thousand fixed-seed samples, the fourth of four shards.
#[test]
fn fixed_seed_samples_hold_the_header_property_shard_4_of_4() {
    hold_the_header_property_over_a_shard(0x6d65_7461_6461_7461);
}
