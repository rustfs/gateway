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

//! What one `aws-chunked` upload costs, measured rather than described.
//!
//! Responsible for: proving the streaming path holds one copy of the body it is delivering and not
//! two — the wire body beside the decoded one.
//! NOT responsible for: how long the decode takes.
//! Upstream: `rustfs-gateway`, `dhat`. Downstream: nothing.

use crate::support;

use bytes::Bytes;
use rustfs_gateway::S3Service;

/// The two decoded sizes, and the ratio between them is the instrument.
const SMALL: usize = 64 * 1024;
/// Sixteen times the smaller body.
const LARGE: usize = 16 * SMALL;

/// The decoded bytes one `aws-chunked` chunk carries.
const CHUNK: usize = 32 * 1024;

/// The wire frame size the body is fed in, held constant across both runs.
const FRAME: usize = 8 * 1024;

const PROBE_ENV: &str = "RUSTFS_GATEWAY_CHUNKED_ALLOCATION_PROBE";
const PROBE_SENTINEL: &str = "rustfs-gateway chunked allocation probe: ";
const PROBE_TEST: &str = "chunked_allocations::c_ing_0063_an_aws_chunked_upload_holds_one_copy_of_its_body";

/// A body that hands each frame over as **its own allocation**, made while the profiler is
/// watching.
///
/// The obvious producer hands out `Bytes::slice` views of one buffer built before the window
/// opens. That producer makes this gate measure the wrong thing, and it was caught measuring it:
/// a reader that kept every frame it was given for the whole request — the wire body resident
/// beside the decoded one, which is the defect this file exists to refuse — cost 16 bytes per
/// retained refcount and the peak assertion stayed **green**. What that producer bounds is
/// *copying*, and copying is not the claim.
///
/// So each frame is a real allocation the consumer owns and drops. Retaining one now costs its
/// bytes, and the peak is a statement about residency. The price is one allocation and one copy of
/// the body added to every run, which is why [`COPIES_ALLOCATED`] is three rather than two and why
/// the block bound below is stated per frame; both cancel between the two runs except for the
/// frames the larger one has more of, which is exactly what [`HARNESS_BLOCKS_PER_FRAME`] accounts
/// for.
struct FramedBody {
    /// The wire body, allocated before the window and therefore not counted. Only the slices cut
    /// from it inside `poll_frame` are.
    wire: Bytes,
    cursor: usize,
}

impl FramedBody {
    /// How many frames a `wire`-byte body is delivered in.
    const fn frame_count(wire: usize) -> u64 {
        wire.div_ceil(FRAME) as u64
    }
}

impl http_body::Body for FramedBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: core::pin::Pin<&mut Self>,
        _context: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.cursor >= this.wire.len() {
            return core::task::Poll::Ready(None);
        }
        let take = FRAME.min(this.wire.len() - this.cursor);
        let frame = match this.wire.get(this.cursor..this.cursor + take) {
            Some(slice) => Bytes::copy_from_slice(slice),
            None => return core::task::Poll::Ready(None),
        };
        this.cursor += take;
        core::task::Poll::Ready(Some(Ok(http_body::Frame::data(frame))))
    }
}

/// One signed `aws-chunked` request of `len` decoded bytes, and the wire body it carries.
fn request(len: usize) -> (http::request::Parts, Bytes) {
    use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};

    let decoded: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();

    let credentials = SigningCredentials::new("AKIDEXAMPLE", b"secret").expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let mut signer = SigV4Signer::new(credentials, scope);

    let probe = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");

    // The wire length has to be known before the request is signed, because it is a signed header,
    // so the framing is built first and its own signature chain is seeded afterwards.
    let chunks = len.div_ceil(CHUNK);
    let wire_len = len + chunks * (format!("{CHUNK:x}").len() + 17 + 64 + 4) + 1 + 17 + 64 + 4;

    let mut map = http::HeaderMap::new();
    map.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    map.insert(
        http::header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&wire_len.to_string()).expect("a digit run"),
    );
    let signing = SigningRequest::new(
        &http::Method::POST,
        "/",
        "",
        &map,
        accepted.host().raw_for_signing(),
        PayloadMode::StreamingSigned {
            trailer: rustfs_gateway::sig::TrailerSet::None,
        },
        stamp,
    )
    .with_wire_content_length(wire_len as u64)
    .with_decoded_content_length(len as u64);
    let signed = signer.sign_headers(&signing).expect("a signable request");

    let mut chain = signer.chunk_signer(&signed).expect("a chunk chain");
    let mut wire = Vec::with_capacity(wire_len);
    for chunk in decoded.chunks(CHUNK) {
        wire.extend_from_slice(&chain.encode_chunk(chunk));
    }
    wire.extend_from_slice(&chain.encode_chunk(b""));
    assert_eq!(wire.len(), wire_len, "the signed wire length must be the one that was signed");

    let mut builder = http::Request::builder().method(http::Method::POST).uri("/");
    for (name, value) in signed.headers() {
        builder = builder.header(name, value);
    }
    let (parts, ()) = builder.body(()).expect("a valid request").into_parts();
    (parts, Bytes::from(wire))
}

/// Sends one prepared request and returns the status.
fn exchange(
    service: &S3Service,
    runtime: &tokio::runtime::Runtime,
    parts: http::request::Parts,
    wire: Bytes,
) -> http::StatusCode {
    let request = http::Request::from_parts(parts, FramedBody { wire, cursor: 0 });
    runtime.block_on(async {
        let response = service.call(request).await;
        let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
        collected.status()
    })
}

/// What one `len`-byte upload costs: blocks, bytes allocated, peak bytes held, and the number of
/// wire frames it arrived in.
///
/// Everything that is not the measured exchange — the service, the runtime, the signed request,
/// the wire body, and one warm-up exchange at the same size — happens before the profiler exists,
/// so the window holds one upload and nothing else.
fn cost(len: usize) -> (u64, u64, u64, u64) {
    let service = support::allocations::probe_service();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime");
    let (parts, wire) = request(len);

    let warm = exchange(&service, &runtime, parts.clone(), wire.clone());
    assert_eq!(warm, http::StatusCode::OK, "the {len}-byte upload was not accepted");

    let frames = FramedBody::frame_count(wire.len());
    let profiler = dhat::Profiler::builder().testing().build();
    let status = exchange(&service, &runtime, parts, wire);
    let stats = dhat::HeapStats::get();
    drop(profiler);

    assert_eq!(status, http::StatusCode::OK, "the measured {len}-byte upload was not accepted");
    (stats.total_blocks, stats.total_bytes, stats.max_bytes as u64, frames)
}

/// Runs one isolated probe process measuring both sizes, and reads back what it measured.
///
/// One process for two sizes, not two: `support::allocations` records why that is sound, and the
/// difference on this binary's CI runner is about twenty seconds.
fn measure() -> (Cost, Cost) {
    let rows = support::allocations::measure(PROBE_TEST, PROBE_ENV, PROBE_SENTINEL, &[SMALL, LARGE], 4);
    (Cost::from_row(&rows[0]), Cost::from_row(&rows[1]))
}

/// What one upload cost, as the four numbers the probe prints.
#[derive(Clone, Copy)]
struct Cost {
    blocks: u64,
    bytes: u64,
    peak: u64,
    frames: u64,
}

impl Cost {
    fn from_row(row: &[u64]) -> Self {
        Self {
            blocks: row[0],
            bytes: row[1],
            peak: row[2],
            frames: row[3],
        }
    }
}

/// How many copies of the body may be **resident at once** at the peak of an upload.
///
/// One: the decoded body, which is what the caller is handed. The wire body is not a second one —
/// it is pulled frame by frame into the pipeline's window, and each frame is dropped as it is
/// consumed. [`FramedBody`] is what makes that a measurement rather than a hope: every frame is
/// its own allocation, so a reader that held on to them would be holding the wire body and the
/// peak would say so.
///
/// Before rustfs/gateway#229 this was three. The whole wire body was collected into a `BytesMut`
/// first and the decode ran over it, so at the moment the decoded collector last grew the process
/// held the wire body, the decoded body and the decoded body's replacement buffer. Reinstating
/// that collect-then-decode, and separately retaining every frame in the reader, are two of the
/// mutations the pull request records against this line.
const COPIES_HELD: u64 = 1;

/// How many copies of the body the whole upload may **allocate**, resident or not.
///
/// Three, and none of them is a spare copy of the object. One is [`FramedBody`]'s per-frame
/// allocation, which is the harness paying for the residency measurement above. The other two are
/// one buffer: a `BytesMut` that grows by doubling allocates a little under twice its final size
/// across the growth steps that get it there, and the decoded collector is the one buffer left
/// that grows. Before #229 the same probe read 6.03 without the harness copy, because the wire
/// collector was a second such buffer.
///
/// The doubling is the `bytes` crate's growth policy rather than anything this repository decides,
/// so [`BYTES_HEADROOM`] deliberately leaves room above three for a policy that is less tight than
/// two — but not enough room for a fourth copy of the body, which is what the defect looks like.
const COPIES_ALLOCATED: u64 = 3;

/// Allocator and per-request bookkeeping that does not scale with the body, plus slack for a
/// `bytes` growth policy other than doubling.
///
/// The pipeline's own 64 KiB window is the same size in both runs, so it cancels rather than
/// needing room here.
const BYTES_HEADROOM: u64 = 512 * 1024;

/// How many heap blocks the harness itself spends per wire frame.
///
/// One: [`FramedBody::poll_frame`] allocates each frame. The larger run has more frames than the
/// smaller one — that is the point of holding [`FRAME`] constant — so the bound below is stated
/// per frame rather than as a flat number, which also stops it rotting if [`LARGE`] is raised.
///
/// One, not two. An allocation taken *inside* the read path is a second block per frame and puts
/// the larger run one whole frame-count above this line, which is the mutation the pull request
/// records.
const HARNESS_BLOCKS_PER_FRAME: u64 = 1;

/// Heap blocks that do not scale with the body at all.
///
/// Reasoned rather than measured. Both runs allocate the same fixed set — the window, the drain
/// buffer, the response — and the only thing that legitimately grows is the decoded collector's
/// doubling steps, of which the larger run takes four more.
const BLOCK_HEADROOM: u64 = 16;

/// What a run that measured nothing looks like, and the floor that refuses it.
///
/// `dhat::HeapStats::get()` does not panic when no `dhat::Alloc` is installed as the global
/// allocator — it answers zero — and two zeroes compared against each other satisfy every bound on
/// their difference. The declaration this file reads through lives in a sibling module of the same
/// test binary, so it can be removed without anything here failing to compile. A signed
/// `aws-chunked` exchange verifies a signature chain, decodes a body and encodes a response, which
/// costs tens of kibibytes across a hundred blocks; these floors sit an order of magnitude under
/// that.
const MEASURED_BLOCKS_FLOOR: u64 = 32;
/// The byte counterpart of [`MEASURED_BLOCKS_FLOOR`].
const MEASURED_BYTES_FLOOR: u64 = 4096;

/// Negative — an `aws-chunked` upload sixteen times larger does not hold sixteen times as much
/// heap *twice over*.
///
/// # What this proves that no status assertion can
///
/// `c-ing-0063` says the ingest pipeline works on a bounded window. That assertion is satisfied by
/// a caller which has already materialised the entire request beside the window: the status, the
/// decoded bytes and every log line are identical either way, and the pipeline's own counters —
/// `window_bytes`, `bytes_moved_total` — report the window truthfully while saying nothing about
/// what the caller is holding. A limit enforced on an inner loop and not on its caller is not a
/// limit, and the difference between the two lives on the heap. So that is where this looks.
///
/// # Why a ratio and not a number
///
/// "An upload allocates at most N bytes" is a gate against a constant somebody measured on one
/// machine, and the first platform whose allocator rounds differently turns it red for no defect.
/// These two runs are compared against each other, on whatever machine is running them, so what is
/// pinned is a shape: *the heap an `aws-chunked` upload holds is one copy of the object, not the
/// object plus the framing it arrived in*.
#[test]
fn c_ing_0063_an_aws_chunked_upload_holds_one_copy_of_its_body() {
    if let Some(sizes) = support::allocations::requested_sizes(PROBE_ENV) {
        for len in sizes {
            let (blocks, bytes, peak, frames) = cost(len);
            println!("{PROBE_SENTINEL}{blocks} {bytes} {peak} {frames}");
        }
        return;
    }

    let (small, large) = measure();
    println!(
        "small body {SMALL}: {} blocks, {} bytes, {} peak, {} frames",
        small.blocks, small.bytes, small.peak, small.frames
    );
    println!(
        "large body {LARGE}: {} blocks, {} bytes, {} peak, {} frames",
        large.blocks, large.bytes, large.peak, large.frames
    );

    // First: that anything was measured at all. Everything below is a statement about the
    // difference between two numbers, and two zeroes have no difference.
    for (label, blocks, bytes) in [("small", small.blocks, small.bytes), ("large", large.blocks, large.bytes)] {
        assert!(
            blocks >= MEASURED_BLOCKS_FLOOR && bytes >= MEASURED_BYTES_FLOOR,
            "the {label} probe recorded {blocks} blocks and {bytes} bytes, which is less than a \
             signed aws-chunked upload can possibly cost: the profiler saw nothing, so every bound \
             below is comparing one unmeasured run against another. Check that a \
             `#[global_allocator]` of `dhat::Alloc` is still declared somewhere in this test binary."
        );
    }
    // And that the larger run really was fed in more frames, which is what the block bound is
    // stated against. Two equal frame counts would make that bound a flat sixteen without saying
    // so, and would mean `FRAME` had stopped being the constant this file holds fixed.
    assert!(
        large.frames > small.frames,
        "both runs arrived in {} and {} frames; the larger body must be fed in more frames than \
         the smaller one for the per-frame bound below to mean anything",
        small.frames,
        large.frames
    );

    let payload_growth = (LARGE - SMALL) as u64;
    let frame_growth = large.frames - small.frames;
    let block_growth = large.blocks.saturating_sub(small.blocks);
    let byte_growth = large.bytes.saturating_sub(small.bytes);
    let peak_growth = large.peak.saturating_sub(small.peak);

    assert!(
        peak_growth <= payload_growth * COPIES_HELD + BYTES_HEADROOM,
        "a body {}x larger held {peak_growth} more bytes at its peak ({} -> {}) for \
         {payload_growth} more body, which is more than the {COPIES_HELD} copy this gate allows. \
         Something on the framed path is holding the wire body beside the decoded one, and the \
         ingest window is bounding only half of what the request costs.",
        LARGE / SMALL,
        small.peak,
        large.peak
    );
    assert!(
        byte_growth <= payload_growth * COPIES_ALLOCATED + BYTES_HEADROOM,
        "the aws-chunked path allocated {byte_growth} more bytes for {payload_growth} more body \
         ({} -> {}), which is more than the {COPIES_ALLOCATED} copies one doubling collector and \
         the harness's own per-frame allocation cost",
        small.bytes,
        large.bytes
    );
    let block_allowance = frame_growth * HARNESS_BLOCKS_PER_FRAME + BLOCK_HEADROOM;
    assert!(
        block_growth <= block_allowance,
        "a body {}x larger cost {block_growth} more allocations ({} -> {}) for {frame_growth} \
         more frames, not at most {block_allowance}: something on the streaming path allocates per \
         frame or per chunk on top of the one the harness spends",
        LARGE / SMALL,
        small.blocks,
        large.blocks
    );
}
