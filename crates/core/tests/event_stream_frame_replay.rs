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

//! Fixed-seed replay of the `event_stream_frame` fuzz property inside the ordinary test gate.
//!
//! Responsible for: running every committed seed under `fuzz/seeds/event_stream_frame/` through
//! the same property file the fuzz target runs and pinning each seed's outcome; every
//! four-call sequence script; the exact payload and header ceilings (in bytes, not characters);
//! the independent CRC and frame reader against published and corrupted inputs; and fixed-seed
//! random scripts on stable.
//! NOT responsible for: fuzzing itself, or the wire, which the facade transport tests observe.
//! Upstream: `fuzz/support/event_stream_frame.rs` and the committed seeds. Downstream: Cargo's
//! harness.

use std::path::{Path, PathBuf};

use rustfs_gateway_core::ops::shared::event_stream::{EventKind, EventStreamError, MAX_PAYLOAD_BYTES};

#[path = "../../../fuzz/support/event_stream_frame.rs"]
mod property;

use property::{Op, Summary, check, decode, reference_crc32, reference_frame, run};

use EventStreamError::{HeaderTooLarge, OutOfOrder, PayloadTooLarge};

fn seed_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/event_stream_frame")
}

fn replay(name: &str) -> Summary {
    let path = seed_dir().join(name);
    let input = std::fs::read(&path).unwrap_or_else(|error| panic!("required seed {} is missing: {error}", path.display()));
    check(&input)
}

fn summary(frames: usize, refusals: &[EventStreamError], terminated: bool) -> Summary {
    Summary {
        frames,
        refusals: refusals.to_vec(),
        terminated,
    }
}

/// Each required seed and the outcome it must keep. Six accepted scripts, thirteen refusals.
fn required() -> Vec<(&'static str, Summary)> {
    vec![
        ("happy-path", summary(5, &[], true)),
        ("error-mid-stream", summary(2, &[], true)),
        ("error-after-stats", summary(2, &[], true)),
        ("code-at-limit", summary(1, &[], true)),
        ("multibyte-code-at-limit", summary(1, &[], true)),
        ("block-at-limit", summary(1, &[], true)),
        ("records-after-stats", summary(1, &[OutOfOrder], false)),
        ("progress-after-stats", summary(1, &[OutOfOrder], false)),
        ("cont-after-stats", summary(1, &[OutOfOrder], false)),
        ("stats-twice", summary(1, &[OutOfOrder], false)),
        ("end-before-stats", summary(0, &[OutOfOrder], false)),
        ("end-twice", summary(2, &[OutOfOrder], true)),
        ("after-end", summary(2, &[OutOfOrder; 4], true)),
        ("after-error", summary(1, &[OutOfOrder; 4], true)),
        ("code-over-limit", summary(0, &[HeaderTooLarge], false)),
        ("multibyte-code-over-limit", summary(0, &[HeaderTooLarge], false)),
        ("message-over-limit", summary(0, &[HeaderTooLarge], false)),
        ("block-over-limit-then-error", summary(1, &[HeaderTooLarge], true)),
        ("raw-error-over-limit", summary(0, &[HeaderTooLarge], false)),
    ]
}

#[test]
fn every_required_seed_keeps_its_outcome() {
    for (name, expected) in required() {
        assert_eq!(replay(name), expected, "seed {name}");
    }
}

#[test]
fn every_committed_seed_is_a_required_one() {
    let names: Vec<_> = required().into_iter().map(|(name, _)| name).collect();
    for entry in std::fs::read_dir(seed_dir()).expect("seed directory") {
        let name = entry.expect("seed entry").file_name().into_string().expect("ASCII seed name");
        assert!(names.contains(&name.as_str()), "unpinned seed {name}");
    }
}

#[test]
fn the_reference_crc_matches_the_published_check_value() {
    assert_eq!(reference_crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(reference_crc32(b""), 0);
}

#[test]
fn n_the_reference_reader_refuses_every_single_byte_corruption() {
    let mut frame = Vec::new();
    rustfs_gateway_core::ops::shared::event_stream::encode_event(EventKind::Records, b"payload", &mut frame)
        .expect("small frame");
    assert!(reference_frame(&frame).is_ok());
    for at in 0..frame.len() {
        let mut damaged = frame.clone();
        damaged[at] ^= 0x01;
        assert!(reference_frame(&damaged).is_err(), "corruption at {at} was read back");
    }
    assert!(reference_frame(&frame[..frame.len() - 1]).is_err());
}

#[test]
fn every_four_call_sequence_matches_the_model() {
    let alphabet = [
        Op::Records(b"r".to_vec()),
        Op::Progress("p".into()),
        Op::Cont,
        Op::Stats("s".into()),
        Op::End,
        Op::Exception("C".into(), "m".into()),
    ];
    let (mut refused, mut clean) = (0, 0);
    for index in 0..alphabet.len().pow(4) {
        let script: Vec<_> = (0..4)
            .map(|place| alphabet[index / alphabet.len().pow(place) % alphabet.len()].clone())
            .collect();
        if run(&script).refusals.is_empty() {
            clean += 1;
        } else {
            refused += 1;
        }
    }
    assert_eq!(refused + clean, 1296);
    assert!(refused > 0 && clean > 0);
}

#[test]
fn n_the_payload_ceiling_is_exact() {
    assert_eq!(MAX_PAYLOAD_BYTES, 16 * 1024 * 1024 - 1024);
    let at = vec![b'x'; MAX_PAYLOAD_BYTES];
    let over = vec![b'x'; MAX_PAYLOAD_BYTES + 1];
    assert_eq!(run(&[Op::RawEvent(EventKind::Records, at.clone())]), summary(1, &[], false));
    assert_eq!(
        run(&[Op::RawEvent(EventKind::Stats, over.clone())]),
        summary(0, &[PayloadTooLarge], false)
    );
    assert_eq!(run(&[Op::Records(at)]), summary(1, &[], false));
    assert_eq!(run(&[Op::Records(over)]), summary(0, &[PayloadTooLarge], false));
}

#[test]
fn n_decoded_scripts_are_bounded() {
    assert!(decode(&[0; 10_000]).len() <= 64);
    assert!(decode(&[]).is_empty());
}

#[test]
fn fixed_seed_scripts_match_the_model() {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut refused = 0;
    for _ in 0..3_000 {
        let len = (state % 48) as usize;
        let input: Vec<u8> = (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                // Keep fill counts small so the sample stays fast; seeds cover the ceilings.
                (state as u8) & 0x7F
            })
            .collect();
        refused += usize::from(!check(&input).refusals.is_empty());
    }
    assert!(refused > 0);
}
