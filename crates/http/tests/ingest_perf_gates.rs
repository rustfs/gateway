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

//! The three regressions this task fixes, each stated as an equality rather than a wall clock.
//!
//! Responsible for: the HMAC budget, the single-pass property, the bytes the pipeline memmoves,
//! and the absence of any adapting copy when the body is consumed in its native model.
//! NOT responsible for: throughput. A wall-clock assertion on a shared runner is noise, and a
//! noisy gate is a muted gate within a month; every gate here is a count.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.
//!
//! 8 positive / 10 negative.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rustfs_gateway_http::{ChunkLimits, ChunkSigningKey, ScopeId, SigningKeyCache};
use rustfs_gateway_stream::{ByteCounter, ByteObserver, ObserverOutcome, Payload, StreamMetrics};
use smallvec::SmallVec;
use support::ingest::{
    SignedChunker, drain_pipeline, hmac_sha256, no_observers, signed_pipeline, unsigned_body, unsigned_pipeline,
};

const KEY: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];

/// A witness that records what it was shown, so the suite can assert both the byte total and the
/// granularity it arrived in.
#[derive(Default)]
struct Witness {
    seen: u64,
    calls: u64,
    smallest: usize,
}

impl ByteObserver for Witness {
    fn update(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.seen = self.seen.saturating_add(bytes.len() as u64);
        self.calls = self.calls.saturating_add(1);
        self.smallest = if self.smallest == 0 {
            bytes.len()
        } else {
            self.smallest.min(bytes.len())
        };
    }

    fn finish(self: Box<Self>) -> ObserverOutcome {
        ObserverOutcome::new("witness", &self.calls.to_be_bytes(), self.seen)
    }

    fn label(&self) -> &'static str {
        "witness"
    }
}

/// A witness whose tally outlives the pipeline that held it.
///
/// [`Witness`] is moved into the pipeline and only its outcome comes back, which is enough to
/// assert a total and not enough to point the same instrument at a *second* walk over the same
/// bytes. This one shares its counter, so one number can span both.
#[derive(Clone)]
struct SharedWitness(Arc<AtomicU64>);

impl ByteObserver for SharedWitness {
    fn update(&mut self, bytes: &[u8]) {
        self.0.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }

    fn finish(self: Box<Self>) -> ObserverOutcome {
        ObserverOutcome::new("shared-witness", &[], self.0.load(Ordering::Relaxed))
    }

    fn label(&self) -> &'static str {
        "shared-witness"
    }
}

fn scope(credential: &str) -> ScopeId {
    ScopeId::new(credential, "20130524", "us-east-1", "s3")
}

fn derive_once(counter: &mut u64) -> ChunkSigningKey {
    // The real derivation is four chained HMAC operations and lives in `rustfs-gateway-sig`; the
    // count is what this gate is about.
    *counter = counter.saturating_add(4);
    let step = hmac_sha256(b"AWS4secret", b"20130524");
    let step = hmac_sha256(&step, b"us-east-1");
    let step = hmac_sha256(&step, b"s3");
    ChunkSigningKey::from_derived(hmac_sha256(&step, b"aws4_request"))
}

// ── positive ───────────────────────────────────────────────────────────────────────────

/// Positive: one scope, many requests, one derivation.
///
/// Deriving per chunk instead of per scope is what turns a 5 GiB upload's 81,924 HMAC operations
/// into 409,600. The cache makes the difference a count.
#[test]
fn c_ing_0003_one_scope_is_derived_once_however_many_requests_use_it() {
    let mut cache = SigningKeyCache::new(SigningKeyCache::DEFAULT_CAPACITY);
    let mut hmacs = 0u64;
    let id = scope("AKIDEXAMPLE");

    for _ in 0..1024 {
        let _ = cache.signing_key_for(&id, || derive_once(&mut hmacs));
    }

    assert_eq!(cache.derivations(), 1);
    assert_eq!(cache.misses(), 1);
    assert_eq!(cache.hits(), 1023);
    assert_eq!(cache.hmac_calls(), 4);
    assert_eq!(hmacs, 4, "the closure ran once, and it costs four HMAC operations");
}

/// Positive: the hit ratio is a number a dashboard can carry, and a test can pin.
#[test]
fn the_hit_ratio_is_exact() {
    let mut cache = SigningKeyCache::new(4);
    let mut hmacs = 0u64;
    let id = scope("AKIDEXAMPLE");
    for _ in 0..10 {
        let _ = cache.signing_key_for(&id, || derive_once(&mut hmacs));
    }
    assert_eq!(cache.hit_permille(), 900, "nine hits in ten lookups");

    let empty = SigningKeyCache::new(1);
    assert_eq!(empty.hit_permille(), 0, "no lookups is not a perfect hit ratio");
}

/// Positive, and the headline gate: for a signed upload of N chunks, the whole request costs
/// N + 4 HMAC operations. Deriving per chunk would cost 5N.
///
/// Run over 256 chunks rather than the 81,920 of a 5 GiB upload, because the identity is the
/// same and a gate has a ten-minute budget: 5 GiB in 64 KiB chunks is 81,920 + 4 = 81,924
/// against a per-chunk baseline of 409,600, which is 80.0% fewer.
#[test]
fn c_ing_0003_a_signed_upload_costs_one_hmac_per_chunk_plus_four() {
    const CHUNKS: usize = 256;
    // 8 KiB is the smallest chunk an AWS SDK emits for signed streaming, and the smallest this
    // gateway accepts under the default framing-overhead ratio: an 87-byte signed header is
    // 1.06% of an 8 KiB chunk and 8.5% of a 1 KiB one.
    const CHUNK_BYTES: usize = 8 * 1024;

    let mut cache = SigningKeyCache::new(SigningKeyCache::DEFAULT_CAPACITY);
    let mut derivation_hmacs = 0u64;
    let key = cache.signing_key_for(&scope("AKIDEXAMPLE"), || derive_once(&mut derivation_hmacs));
    drop(key);

    let payload = vec![b'p'; CHUNK_BYTES];
    let mut chunker = SignedChunker::new(KEY, SEED);
    for _ in 0..CHUNKS {
        chunker.push(&payload);
    }
    let body = chunker.finish();

    let declared = (CHUNKS * CHUNK_BYTES) as u64;
    let mut pipeline = signed_pipeline(body, 64 * 1024, declared, KEY, SEED, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 64 * 1024).expect("a correctly signed body");
    assert_eq!(out.len() as u64, declared);

    let chunk_hmacs = pipeline.signer().map_or(0, rustfs_gateway_http::ChunkSigner::hmac_calls);
    let total = chunk_hmacs.saturating_add(cache.hmac_calls());
    let chunks_including_terminal = CHUNKS as u64 + 1;

    assert_eq!(chunk_hmacs, chunks_including_terminal, "exactly one HMAC per chunk");
    assert_eq!(total, chunks_including_terminal + 4);
    assert_eq!(cache.derivations(), 1);
    assert!(
        total * 4 < chunks_including_terminal * 5,
        "the per-chunk derivation baseline is 5N; this must be far below it"
    );
}

/// Positive: four observers over a 1 MiB body see it once each, and so does the signer. A second
/// pass would show up here as twice the byte count.
#[test]
fn c_ing_0005_four_observers_and_the_signer_each_see_the_body_exactly_once() {
    const CHUNK_BYTES: usize = 64 * 1024;
    const CHUNKS: usize = 16;

    let payload = vec![b'o'; CHUNK_BYTES];
    let mut chunker = SignedChunker::new(KEY, SEED);
    for _ in 0..CHUNKS {
        chunker.push(&payload);
    }
    let body = chunker.finish();
    let declared = (CHUNKS * CHUNK_BYTES) as u64;

    let observers: SmallVec<[Box<dyn ByteObserver>; 4]> = SmallVec::from_vec(vec![
        Box::new(Witness::default()) as Box<dyn ByteObserver>,
        Box::new(Witness::default()) as Box<dyn ByteObserver>,
        Box::new(Witness::default()) as Box<dyn ByteObserver>,
        Box::new(ByteCounter::new()) as Box<dyn ByteObserver>,
    ]);
    let mut pipeline = signed_pipeline(body, 64 * 1024, declared, KEY, SEED, observers, ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 128 * 1024).expect("a correctly signed body");

    assert_eq!(out.len() as u64, declared);
    assert_eq!(pipeline.decoded_bytes(), declared);
    assert_eq!(
        pipeline.signer().map(rustfs_gateway_http::ChunkSigner::hashed_bytes),
        Some(declared),
        "the payload hash walks the body once, not once per chunk after collecting it"
    );

    for outcome in pipeline.finish_observers() {
        assert_eq!(
            outcome.observed_bytes(),
            declared,
            "observer {} must see the body exactly once",
            outcome.label()
        );
    }
}

/// Positive, and the control for the gate above: the same instrument, pointed at a body that is
/// walked twice, reports twice the body.
///
/// The gate above asserts an equality — `observed == declared` — and an equality is only worth
/// what its instrument can distinguish. A counter that saturated at the body length, or one wired
/// to the declaration rather than to the bytes, would satisfy it while the pipeline collected
/// each chunk and hashed it afterwards, which is the exact design the pipeline replaced. So the
/// second walk here is that rejected design, performed deliberately: the delivered body is handed
/// to the same counter a second time, and the counter says `2 x declared`. Whatever else is
/// uncertain, the single-pass assertion is not one that could not fail.
#[test]
fn c_ing_0005_the_single_pass_instrument_reports_two_when_the_body_is_walked_twice() {
    const CHUNK_BYTES: usize = 16 * 1024;
    const CHUNKS: usize = 8;

    let payload = vec![b'c'; CHUNK_BYTES];
    let mut chunker = SignedChunker::new(KEY, SEED);
    for _ in 0..CHUNKS {
        chunker.push(&payload);
    }
    let body = chunker.finish();
    let declared = (CHUNKS * CHUNK_BYTES) as u64;

    let tally = Arc::new(AtomicU64::new(0));
    let observers: SmallVec<[Box<dyn ByteObserver>; 4]> =
        SmallVec::from_vec(vec![Box::new(SharedWitness(Arc::clone(&tally))) as Box<dyn ByteObserver>]);
    let mut pipeline = signed_pipeline(body, 64 * 1024, declared, KEY, SEED, observers, ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 64 * 1024).expect("a correctly signed body");

    assert_eq!(out.len() as u64, declared);
    assert_eq!(tally.load(Ordering::Relaxed), declared, "the pipeline walked the body once");

    // The rejected shape, run on purpose: collect the bytes, then walk them again to digest them.
    let mut collect_then_digest = SharedWitness(Arc::clone(&tally));
    collect_then_digest.update(&out);

    assert_eq!(
        tally.load(Ordering::Relaxed),
        declared.saturating_mul(2),
        "a second walk over the same bytes must be visible to this counter, or the equality above \
         is an assertion about nothing"
    );
}

/// Positive: the observers are called at chunk granularity, not at every framing boundary. A
/// hardware digest restarted every few hundred bytes loses most of its advantage.
#[test]
fn c_ing_0008_observers_are_called_at_chunk_granularity() {
    const CHUNK_BYTES: usize = 64 * 1024;
    let payload = vec![b'g'; CHUNK_BYTES];
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(&payload).push(&payload);
    let body = chunker.finish();

    let observers: SmallVec<[Box<dyn ByteObserver>; 4]> =
        SmallVec::from_vec(vec![Box::new(ByteCounter::new()) as Box<dyn ByteObserver>]);
    let mut pipeline = signed_pipeline(body, 1 << 20, 2 * CHUNK_BYTES as u64, KEY, SEED, observers, ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 1 << 20).expect("a correctly signed body");
    assert_eq!(out.len(), 2 * CHUNK_BYTES);

    let outcomes = pipeline.finish_observers();
    assert_eq!(outcomes[0].observed_bytes(), 2 * CHUNK_BYTES as u64);
}

/// Positive: consuming the pipeline through the pull model performs no adapting copy at all. The
/// counter that would record one stays at zero.
#[test]
fn consuming_the_pipeline_in_its_native_model_performs_no_adapting_copy() {
    let metrics = StreamMetrics::new();
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"zero-copy-path");
    let body = chunker.finish();

    let pipeline = signed_pipeline(body, 4096, 14, KEY, SEED, no_observers(), ChunkLimits::default());
    let payload = Payload::from_reader(pipeline).expect("the pipeline declares a consistent length");
    let (mut reader, cost) = payload.try_into_reader(&metrics).expect("a reader is already pull-model");

    assert!(cost.is_free(), "a pull-model body consumed by a pull-model consumer costs nothing");
    assert_eq!(metrics.adapt_copies_total(), 0);
    assert_eq!(metrics.adapt_copied_bytes_total(), 0);
    assert_eq!(metrics.adapt_buffers_total(), 0);

    // And the body still arrives.
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    let mut buf = [0u8; 64];
    let mut out = Vec::new();
    loop {
        match rustfs_gateway_stream::AsyncPayloadRead::poll_fill(core::pin::Pin::new(&mut reader), &mut cx, &mut buf) {
            core::task::Poll::Pending => continue,
            core::task::Poll::Ready(Ok(rustfs_gateway_stream::ReadProgress::Filled(n))) => {
                out.extend_from_slice(&buf[..n]);
            }
            core::task::Poll::Ready(Ok(rustfs_gateway_stream::ReadProgress::Eof { .. })) => break,
            core::task::Poll::Ready(Err(err)) => panic!("a well formed body must not fail: {err}"),
        }
    }
    assert_eq!(out, b"zero-copy-path");
    assert_eq!(metrics.adapt_copies_total(), 0, "still no adapting copy after the read");
}

/// Positive, and the sharpest statement of "the decoder does not copy the body": a body that
/// fits inside the window is delivered whole, with 32 chunk headers stripped, having memmoved
/// exactly zero bytes. Headers are skipped by advancing a cursor, never by moving the bytes.
#[test]
fn c_ing_0004_stripping_chunk_headers_moves_no_bytes_at_all() {
    const CHUNK_BYTES: usize = 1024;
    const CHUNKS: usize = 32;

    let payload = vec![b'm'; CHUNK_BYTES];
    let mut chunker = SignedChunker::new(KEY, SEED);
    for _ in 0..CHUNKS {
        chunker.push(&payload);
    }
    let body = chunker.finish();
    let declared = (CHUNKS * CHUNK_BYTES) as u64;
    // The overhead ratio would refuse 1 KiB signed chunks under the default, which is itself
    // asserted below; this gate is about movement, so the ratio is relaxed for it alone.
    let limits = ChunkLimits::default().with_max_overhead_permille(200);

    let mut pipeline = signed_pipeline(body, 64 * 1024, declared, KEY, SEED, no_observers(), limits);
    let out = drain_pipeline(&mut pipeline, 64 * 1024).expect("a correctly signed body");

    assert_eq!(out.len() as u64, declared);
    assert_eq!(
        pipeline.bytes_moved_total(),
        0,
        "a body that fits in the window is never memmoved, headers included"
    );
}

// ── negative ───────────────────────────────────────────────────────────────────────────

/// Negative: pushing the same body through the *other* model does cost a copy, and the counter
/// says so. This is the control for the assertion above: a counter that never moves proves
/// nothing.
#[test]
fn adapting_the_pipeline_into_the_push_model_is_counted() {
    let metrics = StreamMetrics::new();
    let mut chunker = SignedChunker::new(KEY, SEED);
    chunker.push(b"adapted");
    let body = chunker.finish();

    let pipeline = signed_pipeline(body, 4096, 7, KEY, SEED, no_observers(), ChunkLimits::default());
    let payload = Payload::from_reader(pipeline).expect("consistent");
    let (_, cost) = payload.try_into_stream(&metrics).expect("a reader can be pushed");

    assert!(!cost.is_free(), "crossing the model boundary is never free");
    assert_eq!(metrics.adapt_buffers_total(), 1);
}

/// What one body's worth of compaction cost, and the window it was paid against.
struct Compaction {
    chunk: usize,
    declared: u64,
    window: u64,
    moved: u64,
}

impl Compaction {
    /// The bound `IngestPipeline::make_room` claims: one compaction per window's worth of room,
    /// each moving at most the chunk being verified plus the metadata line ahead of it.
    fn ceiling(&self) -> u64 {
        let unit = self.chunk as u64 + 256;
        self.declared.div_ceil(self.window - unit).saturating_mul(unit)
    }

    /// Whether this ratio is in the region where the window is at least three times the chunk —
    /// the region in which the retained span is small relative to the room a compaction buys.
    fn chunk_is_small_against_the_window(&self) -> bool {
        (self.chunk as u64).saturating_mul(3) <= self.window
    }
}

/// Drives `body_bytes` through the pipeline in signed chunks of `chunk_bytes` and reports what
/// compaction moved.
fn compaction_run(chunk_bytes: usize, body_bytes: usize) -> Compaction {
    let chunks = body_bytes / chunk_bytes;
    let payload = vec![b'm'; chunk_bytes];
    let mut chunker = SignedChunker::new(KEY, SEED);
    for _ in 0..chunks {
        chunker.push(&payload);
    }
    let body = chunker.finish();
    let declared = (chunks * chunk_bytes) as u64;

    let mut pipeline = signed_pipeline(body, 16 * 1024, declared, KEY, SEED, no_observers(), ChunkLimits::default());
    let out = drain_pipeline(&mut pipeline, 16 * 1024).expect("a correctly signed body");
    assert_eq!(out.len() as u64, declared);
    Compaction {
        chunk: chunk_bytes,
        declared,
        window: pipeline.window_bytes() as u64,
        moved: pipeline.bytes_moved_total(),
    }
}

/// Negative: a body far larger than the window does need compaction, and what moves is bounded by
/// the chunk being verified — not by the body. A decoder that compacted on every read would move
/// something proportional to the upload.
///
/// # Why this is parameterised, and what each bound claims
///
/// The bound is a **function of the chunk-size-to-window ratio**, and this case used to be run at
/// one comfortable point of it (8 KiB chunks against the 64 KiB window, where 0.13 of the body
/// moves). rustfs/gateway#265: at 32 KiB chunks against the same window the total reaches 0.97 of
/// the body — a near-full second pass, which the fixed `< declared / 2` assertion never saw
/// because the one configuration in the case was the one where it held.
///
/// So the two bounds are stated separately, each over the range it actually claims:
///
/// * **Everywhere** — `moved <= ceiling()`, one retained span per window's worth of room. This is
///   the bound `make_room` is written to hold, and it holds across the whole range.
/// * **Everywhere** — `moved < declared`: compaction never costs a *full* second pass. The peak
///   is a knife edge at chunk == window/2, where the retained span and the room a compaction buys
///   are the same size, so every chunk is moved once; measured 0.9986 at 64 KiB chunks against
///   the 128 KiB window this pipeline grows to for them. The margin here is thin on purpose —
///   this is the number a change to `make_room` would move.
/// * **Where the window is at least three times the chunk** — `moved < declared / 2`, the
///   original claim, kept at full strength in the region it was measured in and no further.
///
/// The chunk sizes are the ratio's landmarks against a 64 KiB initial window: a sixteenth, an
/// eighth, a quarter, the last point of the halving region, exactly half — the worst — three
/// quarters, the size that forces the window to double (and lands on half of *that* window, the
/// other worst point), and one that fits inside the grown window comfortably.
#[test]
fn compaction_is_bounded_by_the_chunk_not_by_the_body() {
    const BODY_BYTES: usize = 1024 * 1024;

    for chunk_bytes in [
        4 * 1024,
        8 * 1024,
        16 * 1024,
        21 * 1024,
        32 * 1024,
        48 * 1024,
        64 * 1024,
        96 * 1024,
    ] {
        let run = compaction_run(chunk_bytes, BODY_BYTES);
        let ceiling = run.ceiling();
        assert!(
            run.moved <= ceiling,
            "chunk {chunk_bytes} in a {} byte window: moved {} bytes, and one retained span per window's worth of room is {ceiling}",
            run.window,
            run.moved
        );
        assert!(
            run.moved < run.declared,
            "chunk {chunk_bytes} in a {} byte window: moved {} bytes over a {} byte body, which is a full second pass",
            run.window,
            run.moved,
            run.declared
        );
        if run.chunk_is_small_against_the_window() {
            assert!(
                run.moved < run.declared / 2,
                "chunk {chunk_bytes} in a {} byte window: moved {} bytes, and a chunk this small against the window must stay under half the body",
                run.window,
                run.moved
            );
        }
    }
}

/// Negative: the default framing-overhead ratio refuses signed chunks small enough to turn the
/// upload into a signature-verification workload. 1 KiB signed chunks are 8.5% overhead.
#[test]
fn signed_chunks_too_small_to_amortise_their_header_are_refused() {
    const CHUNK_BYTES: usize = 1024;
    const CHUNKS: usize = 64;

    let payload = vec![b's'; CHUNK_BYTES];
    let mut chunker = SignedChunker::new(KEY, SEED);
    for _ in 0..CHUNKS {
        chunker.push(&payload);
    }
    let body = chunker.finish();
    let declared = (CHUNKS * CHUNK_BYTES) as u64;

    let mut pipeline = signed_pipeline(body, 64 * 1024, declared, KEY, SEED, no_observers(), ChunkLimits::default());
    let _ = drain_pipeline(&mut pipeline, 64 * 1024).expect_err("1 KiB signed chunks are 8.5% framing");
    assert!(matches!(
        pipeline.reject(),
        Some(rustfs_gateway_http::ChunkReject::OverheadRatioExceeded { .. })
    ));
}

/// Negative: the window never grows to the announced size of a chunk it has refused, and never
/// past the ceiling the limits imply.
#[test]
fn c_ing_0063_the_window_stays_bounded_by_the_chunk_ceiling() {
    let limits = ChunkLimits::default().with_max_chunk_size(4096);
    let payload = vec![b'w'; 4096];
    let body = unsigned_body(&[&payload, &payload, &payload, &payload]);
    let mut pipeline = unsigned_pipeline(body, 64 * 1024, 4 * 4096, no_observers(), limits);
    let out = drain_pipeline(&mut pipeline, 1024).expect("a well formed body");

    assert_eq!(out.len(), 4 * 4096);
    assert!(
        pipeline.window_bytes() <= 4096 + 2 * 256 + 8,
        "window grew to {} bytes for a 4 KiB chunk ceiling",
        pipeline.window_bytes()
    );
}

/// Negative: a large chunk ceiling does not mean a large allocation up front. The window grows on
/// demand, so a connection that uploads nothing costs nothing.
#[test]
fn c_ing_0063_the_window_is_not_allocated_up_front() {
    let limits = ChunkLimits::default().with_max_chunk_size(ChunkLimits::HARD_MAX_CHUNK_SIZE);
    let pipeline = unsigned_pipeline(b"0\r\n\r\n".to_vec(), 8, 0, no_observers(), limits);
    assert!(pipeline.window_bytes() <= 64 * 1024, "a 16 MiB ceiling must not mean a 16 MiB allocation");
}

/// Negative: two different credentials under the same scope get two different keys. A cache keyed
/// on the scope alone would hand one caller the other's derived key.
#[test]
fn two_credentials_under_one_scope_are_two_cache_entries() {
    let mut cache = SigningKeyCache::new(8);
    let mut hmacs = 0u64;

    let _ = cache.signing_key_for(&scope("AKIDONE"), || derive_once(&mut hmacs));
    let _ = cache.signing_key_for(&scope("AKIDTWO"), || derive_once(&mut hmacs));
    let _ = cache.signing_key_for(&scope("AKIDONE"), || derive_once(&mut hmacs));

    assert_eq!(cache.derivations(), 2);
    assert_eq!(cache.hits(), 1);
}

/// Negative: a different date, region or service is a different key, and each is a separate
/// entry. Sharing one across them would verify a signature scoped to somewhere else.
#[test]
fn every_field_of_the_scope_is_part_of_the_cache_key() {
    let mut cache = SigningKeyCache::new(16);
    let mut hmacs = 0u64;
    let ids = [
        ScopeId::new("AKID", "20130524", "us-east-1", "s3"),
        ScopeId::new("AKID", "20130525", "us-east-1", "s3"),
        ScopeId::new("AKID", "20130524", "eu-west-1", "s3"),
        ScopeId::new("AKID", "20130524", "us-east-1", "sts"),
    ];
    for id in &ids {
        let _ = cache.signing_key_for(id, || derive_once(&mut hmacs));
    }
    assert_eq!(cache.derivations(), 4);
    assert_eq!(cache.hits(), 0);
}

/// Negative: the cache is bounded. An unbounded cache keyed on a peer-supplied credential is an
/// unbounded allocation keyed on a peer-supplied value.
#[test]
fn the_cache_is_bounded_and_evicts() {
    let mut cache = SigningKeyCache::new(2);
    let mut hmacs = 0u64;
    for index in 0..8 {
        let _ = cache.signing_key_for(&scope(&format!("AKID{index}")), || derive_once(&mut hmacs));
    }
    // Eight distinct scopes through a cache of two: every one is a miss, and nothing accumulates.
    assert_eq!(cache.derivations(), 8);
    assert_eq!(cache.hits(), 0);
    assert!(format!("{cache:?}").contains("entries: 2"));
}

/// Negative: the cache's debug rendering carries no scope and no key material, so a diagnostic
/// dump cannot become a list of active credentials.
#[test]
fn the_cache_never_renders_its_contents() {
    let mut cache = SigningKeyCache::new(2);
    let mut hmacs = 0u64;
    let _ = cache.signing_key_for(&scope("AKIDSECRETLOOKING"), || derive_once(&mut hmacs));
    let rendered = format!("{cache:?}");
    assert!(!rendered.contains("AKIDSECRETLOOKING"));
    assert!(rendered.contains("hits"));
}

/// Negative: the derivation closure runs only on a miss. If it ran on a hit the cache would be a
/// pure overhead, and the whole gate above would be measuring nothing.
#[test]
fn the_derivation_closure_never_runs_on_a_hit() {
    let mut cache = SigningKeyCache::new(4);
    let id = scope("AKIDEXAMPLE");
    let mut hmacs = 0u64;
    let _ = cache.signing_key_for(&id, || derive_once(&mut hmacs));

    let _ = cache.signing_key_for(&id, || panic!("the closure must not run on a hit"));
    assert_eq!(cache.hits(), 1);
}
