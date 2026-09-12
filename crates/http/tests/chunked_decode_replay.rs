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

//! Fixed-seed replay of the `chunked_decode` fuzz property inside the ordinary test gate.
//!
//! Responsible for: running every committed seed under `fuzz/seeds/chunked_decode/` through the
//! same property file the fuzz target runs, and pinning the exact outcome of the five hand-written
//! seeds: one accepted signed body and four refusals, across all three selectable chunk ceilings.
//! NOT responsible for: fuzzing — `ci.yml` defers libFuzzer runs to a schedule, and this replays a
//! fixed set on stable — or turning a fuzz finding into a conformance case, which needs a protocol
//! oracle a crash does not carry.
//! Upstream: `fuzz/support/chunked_decode.rs` and the committed seeds. Downstream: Cargo's harness.

use std::path::{Path, PathBuf};

use rustfs_gateway_http::{ChunkLimits, ChunkReject};

#[path = "../../../fuzz/support/chunked_decode.rs"]
mod chunked_decode;

use chunked_decode::{Outcome, check};

/// The seeds the property's two directions rest on. Each must exist; none may be skipped.
const REQUIRED_SEEDS: [&str; 5] = [
    "valid-signed",
    "oversized-chunk",
    "truncated-data",
    "bad-signature",
    "underflow-declared",
];

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/chunked_decode")
}

fn replay(name: &str) -> Outcome {
    let path = seed_dir().join(name);
    let input = std::fs::read(&path).unwrap_or_else(|error| panic!("required seed {} is missing: {error}", path.display()));
    check(&input).unwrap_or_else(|| panic!("seed {name} is shorter than the case header"))
}

/// Positive control. Without it, a pipeline that refused every body would satisfy each refusal
/// below — and so would a property that classified every outcome as a refusal.
#[test]
fn the_valid_signed_seed_is_delivered_whole_after_both_signatures_verify() {
    let outcome = replay("valid-signed");
    assert_eq!(outcome.verdict, Ok(b"hello".to_vec()));
    assert_eq!(outcome.delivered_bytes, 5);
    assert_eq!(outcome.chunks_verified, Some(2), "the data chunk and the terminal chunk both verify");
}

/// Negative, and the reason the target exists: a signed size line announcing one byte over the
/// production ceiling, followed by three data bytes, is refused at that line. At one byte per
/// read the wire is not asked for a single data byte, and the window never grows towards it.
#[test]
fn the_oversized_seed_is_refused_at_its_size_line_before_a_data_byte_is_read() {
    let outcome = replay("oversized-chunk");
    let max = ChunkLimits::DEFAULT_MAX_CHUNK_SIZE;
    assert_eq!(
        outcome.verdict,
        Err(ChunkReject::ChunkSizeTooLarge {
            declared: u64::from(max) + 1,
            max,
        })
    );
    assert_eq!(outcome.delivered_bytes, 0);
    assert_eq!(outcome.window_bytes, outcome.initial_window);
    let size_line = "100001;chunk-signature=".len() + 64 + 2;
    assert_eq!(outcome.bytes_read, size_line, "the wire was read past the size line");
}

/// Negative: a signed body cut off inside its first chunk's data is never an end-of-stream.
#[test]
fn the_truncated_seed_is_refused_as_truncated_with_nothing_delivered() {
    let outcome = replay("truncated-data");
    assert_eq!(outcome.verdict, Err(ChunkReject::TruncatedStream));
    assert_eq!(outcome.delivered_bytes, 0);
    assert_eq!(outcome.chunks_verified, Some(0));
}

/// Negative: one flipped hex digit in the first chunk's signature refuses that chunk, and none of
/// its bytes reach the consumer.
#[test]
fn the_bad_signature_seed_refuses_chunk_zero_with_nothing_delivered() {
    let outcome = replay("bad-signature");
    assert_eq!(outcome.verdict, Err(ChunkReject::SignatureChainBroken { chunk_index: 0 }));
    assert_eq!(outcome.delivered_bytes, 0);
    assert_eq!(outcome.chunks_verified, Some(0));
}

/// Negative, and the only seed in unsigned framing: a well-formed body that ends with its
/// terminal chunk one byte short of its declaration is refused, not committed short.
#[test]
fn the_underflow_seed_is_refused_one_byte_short_of_its_declaration() {
    let outcome = replay("underflow-declared");
    assert_eq!(outcome.verdict, Err(ChunkReject::DecodedLengthUnderflow { declared: 6, actual: 5 }));
    assert_eq!(outcome.chunks_verified, None, "unsigned framing has no signer");
}

/// Every committed seed — the five above and any minimised regression added later — replays
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
