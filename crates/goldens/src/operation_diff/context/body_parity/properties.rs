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

//! Body parity over generated uploads: object lengths, chunk sizes and transport splits.
//!
//! Responsible for: two properties, each driven from a fixed seed so a run is the same run
//! everywhere, and each ending with coverage floors so a generator that drifted into only easy
//! inputs fails instead of passing vacuously — (1) every untampered upload, in every payload mode,
//! reaches both handlers with the same bytes, each wire byte read exactly once, the same decoded
//! `ContentLength` and the same checksum trailer; (2) a signed upload with one bad chunk is refused
//! by both stacks with `SignatureDoesNotMatch` after handing both handlers exactly the verified
//! chunks before it and not one byte of the bad one.
//! NOT responsible for: fixed refusal rows (`tamper`) or divergences (`divergences`).
//! Upstream: the harness in `super`. Downstream: nothing.

use std::cell::Cell;

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};

use super::{Lookup, Mode, Tamper, Upload, both, crc32_base64};

/// The seed of the acceptance property; exactly 32 bytes.
const ACCEPT_SEED: &[u8; 32] = b"rustfs-backlog-1762-body-accept!";
/// The seed of the tamper property; exactly 32 bytes.
const TAMPER_SEED: &[u8; 32] = b"rustfs-backlog-1762-body-tamper!";

fn runner(seed: &[u8; 32], cases: u32) -> TestRunner {
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    TestRunner::new_with_rng(config, TestRng::from_seed(RngAlgorithm::ChaCha, seed))
}

fn object(length: usize, salt: u8) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(salt))
        .collect()
}

/// Transport pieces biased towards splits finer than a signed size line (83 bytes and more).
fn pieces() -> impl Strategy<Value = Vec<usize>> {
    proptest::collection::vec(prop_oneof![3 => 1..=16_usize, 2 => 17..=97_usize], 0..4)
}

/// `chunk`, raised so the upload stays inside the gateway's chunk-count bound — `ceil(n / 1 KiB) + 16`
/// chunk lines for `n` decoded bytes, terminal included — which rd-body-0005 pins separately.
fn admissible(chunk: usize, length: usize) -> usize {
    chunk.max(length.div_ceil(15)).max(1)
}

fn upload() -> impl Strategy<Value = Upload> {
    let length = prop_oneof![1 => Just(0_usize), 2 => 1..=16_usize, 5 => 17..=300_usize];
    (proptest::sample::select(Mode::ALL.to_vec()), length, any::<u8>(), 1..=64_usize, pieces()).prop_map(
        |(mode, length, salt, chunk, pieces)| {
            Upload::new(mode, &object(length, salt))
                .chunked(admissible(chunk, length))
                .pieces(&pieces)
        },
    )
}

fn count(cell: &Cell<usize>) {
    cell.set(cell.get() + 1);
}

#[derive(Default)]
struct AcceptCoverage {
    per_mode: [Cell<usize>; 5],
    empty: Cell<usize>,
    one_chunk: Cell<usize>,
    many_chunks: Cell<usize>,
    split: Cell<usize>,
    split_inside_metadata: Cell<usize>,
}

/// Property 1 — every untampered upload reaches both handlers identically.
#[test]
fn every_untampered_upload_reaches_both_handlers_byte_for_byte_and_once() {
    let coverage = AcceptCoverage::default();
    let result = runner(ACCEPT_SEED, 192).run(&upload(), |upload| {
        let pair = both(&upload).map_err(TestCaseError::fail)?;
        let length = i64::try_from(upload.object.len()).unwrap_or(i64::MAX);
        for side in [&pair.gateway, &pair.oracle] {
            prop_assert!(side.accepted(), "{:?}: {:?}", upload, side);
            prop_assert_eq!(side.bytes(), upload.object.as_slice());
            prop_assert_eq!(side.content_length(), Some(length));
            prop_assert_eq!(side.wire.delivered, pair.wire_length);
            prop_assert_eq!(side.wire.eof, 1);
            prop_assert_eq!(side.wire.polled_after_eof, 0);
        }
        if upload.mode.trailer() {
            let expected = Lookup::Present(crc32_base64(&upload.object));
            prop_assert_eq!(pair.gateway.trailer(), expected.clone());
            prop_assert_eq!(pair.oracle.trailer(), expected);
        }
        prop_assert_eq!(pair.gateway.closes, None);

        let mode = Mode::ALL.iter().position(|mode| *mode == upload.mode).unwrap_or(0);
        count(&coverage.per_mode[mode]);
        if upload.object.is_empty() {
            count(&coverage.empty);
        } else if upload.mode.framed() && upload.object.len() <= upload.chunk {
            count(&coverage.one_chunk);
        } else if upload.mode.framed() {
            count(&coverage.many_chunks);
        }
        if upload.pieces.first().is_some_and(|&piece| (piece as u64) < pair.wire_length) {
            count(&coverage.split);
            if upload.mode.framed() && upload.pieces.iter().any(|&piece| piece <= 16) {
                count(&coverage.split_inside_metadata);
            }
        }
        Ok(())
    });
    if let Err(failure) = result {
        panic!("{failure}");
    }
    for (mode, cell) in Mode::ALL.iter().zip(&coverage.per_mode) {
        assert!(cell.get() >= 25, "{mode:?} ran {} times, under the floor of 25", cell.get());
    }
    for (name, cell, floor) in [
        ("empty object", &coverage.empty, 8),
        ("one framed chunk", &coverage.one_chunk, 10),
        ("several framed chunks", &coverage.many_chunks, 60),
        ("body split by the transport", &coverage.split, 100),
        ("framed body split finer than its metadata", &coverage.split_inside_metadata, 40),
    ] {
        assert!(cell.get() >= floor, "{name}: {} cases, under the floor of {floor}", cell.get());
    }
}

#[derive(Default)]
struct TamperCoverage {
    per_mode: [Cell<usize>; 2],
    signature: Cell<usize>,
    data: Cell<usize>,
    first: Cell<usize>,
    last: Cell<usize>,
    middle: Cell<usize>,
}

fn tampered_upload() -> impl Strategy<Value = (Upload, usize, usize)> {
    (
        proptest::sample::select(Mode::CHUNK_SIGNED.to_vec()),
        1..=200_usize,
        any::<u8>(),
        1..=32_usize,
        pieces(),
        any::<u16>(),
        any::<bool>(),
    )
        .prop_map(|(mode, length, salt, chunk, pieces, selector, on_signature)| {
            let chunk = admissible(chunk, length);
            let chunks = length.div_ceil(chunk);
            let index = usize::from(selector) % chunks;
            let tamper = if on_signature {
                Tamper::ChunkSignature(index)
            } else {
                Tamper::ChunkData(index)
            };
            let upload = Upload::new(mode, &object(length, salt))
                .chunked(chunk)
                .pieces(&pieces)
                .tampered(tamper);
            (upload, index, chunks)
        })
}

/// Property 2 — one bad chunk is refused alike, after the same verified prefix.
#[test]
fn one_bad_chunk_is_refused_alike_after_the_same_verified_prefix() {
    let coverage = TamperCoverage::default();
    let result = runner(TAMPER_SEED, 128).run(&tampered_upload(), |(upload, index, chunks)| {
        let pair = both(&upload).map_err(TestCaseError::fail)?;
        for side in [&pair.gateway, &pair.oracle] {
            prop_assert_eq!(side.answer(), (403, Some("SignatureDoesNotMatch")), "{:?}: {:?}", upload, side);
            prop_assert_eq!(side.bytes(), upload.before_chunk(index));
            prop_assert!(side.ended().is_some_and(|end| end != super::BodyEnd::Eof));
        }
        prop_assert_eq!(pair.gateway.closes, Some(true));

        let mode = Mode::CHUNK_SIGNED.iter().position(|mode| *mode == upload.mode).unwrap_or(0);
        count(&coverage.per_mode[mode]);
        count(if matches!(upload.tamper, Tamper::ChunkSignature(_)) {
            &coverage.signature
        } else {
            &coverage.data
        });
        count(if index == 0 {
            &coverage.first
        } else if index + 1 == chunks {
            &coverage.last
        } else {
            &coverage.middle
        });
        Ok(())
    });
    if let Err(failure) = result {
        panic!("{failure}");
    }
    for (name, cell, floor) in [
        ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", &coverage.per_mode[0], 40),
        ("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", &coverage.per_mode[1], 40),
        ("bad signature", &coverage.signature, 40),
        ("bad data", &coverage.data, 40),
        ("first chunk", &coverage.first, 10),
        ("last chunk", &coverage.last, 10),
        ("a middle chunk", &coverage.middle, 30),
    ] {
        assert!(cell.get() >= floor, "{name}: {} cases, under the floor of {floor}", cell.get());
    }
}
