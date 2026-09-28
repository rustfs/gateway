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

//! Signed `aws-chunked` decode: allocation per chunk (blocking) and throughput (record only).
//!
//! Responsible for: rustfs/backlog#1766 `chunked/decode_64k` — the production `IngestPipeline`
//! decoding and verifying 64 KiB signed chunks with a cached key — held to zero heap blocks per
//! additional chunk, measured as the difference between a long and a short body so setup cancels.
//! NOT responsible for: decoding rules, which the ingest suites own, or a time threshold.
//! Upstream: `IngestPipeline`, the ingest suites' independent chunk signer. Downstream:
//! `perf-evidence.yml`.

#![allow(dead_code)] // The shared fixture module carries helpers this bench does not use.

use std::hint::black_box;
use std::time::Instant;

use rustfs_gateway_http::ChunkLimits;

#[path = "../tests/support/ingest.rs"]
mod ingest;

use ingest::{SignedChunker, drain_pipeline, no_observers, signed_pipeline};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const KEY: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];
const CHUNK: usize = 64 * 1024;

fn body(chunks: usize) -> (Vec<u8>, u64) {
    let payload = vec![b'z'; CHUNK];
    let mut chunker = SignedChunker::new(KEY, SEED);
    for _ in 0..chunks {
        chunker.push(&payload);
    }
    (chunker.finish(), (chunks * CHUNK) as u64)
}

/// Heap blocks one decode of `chunks` chunks allocates, pipeline construction excluded.
fn decode_blocks(chunks: usize) -> u64 {
    let (wire, declared) = body(chunks);
    let mut pipeline = signed_pipeline(wire, CHUNK, declared, KEY, SEED, no_observers(), ChunkLimits::default());
    let mut sink = vec![0_u8; CHUNK];
    let profiler = dhat::Profiler::builder().testing().build();
    let mut delivered = 0_u64;
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());
    loop {
        use rustfs_gateway_stream::{AsyncPayloadRead, ReadProgress};
        match core::pin::Pin::new(&mut pipeline).poll_fill(&mut context, &mut sink) {
            core::task::Poll::Ready(Ok(ReadProgress::Filled(read))) => delivered += read as u64,
            core::task::Poll::Ready(Ok(ReadProgress::Eof { .. })) => break,
            core::task::Poll::Ready(Err(error)) => panic!("a correctly signed body failed: {error}"),
            core::task::Poll::Pending => {}
        }
    }
    let stats = dhat::HeapStats::get();
    drop(profiler);
    assert_eq!(delivered, declared, "the decoder delivered the declared body");
    stats.total_blocks
}

fn main() {
    let short = decode_blocks(16);
    let long = decode_blocks(272);
    let per_chunk = (long.saturating_sub(short)) as f64 / 256.0;
    println!("chunked/decode_64k: {short} blocks for 16 chunks, {long} for 272; {per_chunk:.3} per additional chunk");
    println!("chunked/decode_64k_per_chunk: {} allocs", long.saturating_sub(short) / 256);
    // The first poll allocates the pipeline's scratch buffer once; seeing it proves the allocator
    // is installed, so the equality below is not two unmeasured zeroes.
    assert!(
        short >= 1,
        "the decode window observed no allocation at all; is the dhat allocator installed?"
    );
    assert_eq!(
        long,
        short,
        "decoding 256 more signed 64 KiB chunks allocated {} more heap blocks; the steady-state decode path must allocate nothing per chunk",
        long.saturating_sub(short)
    );

    let (wire, declared) = body(1024);
    let started = Instant::now();
    let mut pipeline = signed_pipeline(wire, CHUNK, declared, KEY, SEED, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, CHUNK).expect("a correctly signed body");
    let seconds = started.elapsed().as_secs_f64();
    black_box(&out);
    println!(
        "chunked/decode_64k: {:.2} GiB/s signed decode ({} MiB; record-only, non-blocking)",
        declared as f64 / seconds / f64::from(1_u32 << 30),
        declared >> 20
    );
}
