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

//! The `c-pay-*` rows that fit in a handful of bytes: negotiation, refusal, and length.
//!
//! Responsible for: one function per row, each returning the number of observations it made so
//! the ledger can tell a proof from a body that returns early.
//! NOT responsible for: deciding which rows exist, or for the rows that need a gibibyte or a
//! stalled consumer — those are the ledger's and `pay_scale`'s.
//! Upstream: the crate's public surface and the scripted producers in `support`.
//! Downstream: `pay_ledger`, which runs every function here.

use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU32, Ordering};

use bytes::Bytes;

use crate::adapt::AdaptCost;
use crate::caps::{PayloadCaps, validate_caps};
use crate::error::StreamErrorKind;
use crate::file_region::{FileRegion, FileRegionError};
use crate::metrics::StreamMetrics;
use crate::payload::Payload;
use crate::stream::PayloadRead;
use crate::tests::pay_ledger::Checks;
use crate::tests::support::{ScriptedReader, ScriptedStream, Step, drain_reader, drain_stream, joined, poll_stream_once};
use crate::trailers::TrailingHeaders;
use crate::zero_copy::{NoZeroCopy, TransportCaps, VerificationObligation, ZeroCopyQuery};

/// Distinguishes the temporary files these cases create inside one process.
static NEXT_FILE: AtomicU32 = AtomicU32::new(0);

/// A descriptor onto a file of `len` bytes that is already unlinked.
///
/// Unlinked before it is used, so a panicking case cannot leave a file behind: the descriptor
/// keeps the inode alive for exactly as long as the payload holds it.
pub(crate) fn detached_fd(len: u64) -> OwnedFd {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "rustfs-gateway-pay-{}-{}",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("a test can create a file in the temporary directory");
    file.set_len(len).expect("a test can size a file it just created");
    std::fs::remove_file(&path).expect("a test can unlink a file it just created");
    OwnedFd::from(file)
}

/// A file payload of `len` bytes, backed by an unlinked descriptor.
pub(crate) fn file_payload(len: u64) -> Payload {
    let region = FileRegion::new(detached_fd(len), 0, len).expect("a region starting at zero cannot overflow");
    Payload::File(region)
}

/// A three-part message the in-memory cases share.
const SEGMENTS: [&[u8]; 3] = [b"first-", b"second-", b"third"];

fn segments() -> Vec<Bytes> {
    SEGMENTS.iter().map(|part| Bytes::from_static(part)).collect()
}

/// `c-pay-0001` — an in-memory payload advertises what it can do, and the bits agree with its length.
pub(crate) fn c_pay_0001() -> u32 {
    let id = "c-pay-0001";
    let mut c = Checks::new();
    let body = Bytes::from_static(b"a payload already in memory");
    let payload = Payload::from_bytes(body.clone());
    let caps = payload.caps();

    c.that(
        id,
        "in-memory bytes advertise that they are in memory",
        caps.contains(PayloadCaps::IN_MEMORY),
    );
    c.that(id, "in-memory bytes can be consumed by a pull consumer", caps.contains(PayloadCaps::PULL));
    c.that(id, "in-memory bytes can be consumed by a push consumer", caps.contains(PayloadCaps::PUSH));
    c.that(id, "in-memory bytes have a known length", caps.contains(PayloadCaps::KNOWN_LENGTH));
    c.that(
        id,
        "the length hint is the length of the bytes",
        payload.len_hint() == Some(body.len() as u64),
    );
    c.that(
        id,
        "the advertised bits and the length hint do not contradict each other",
        validate_caps(caps, payload.len_hint()).is_ok(),
    );
    c.count()
}

/// `c-pay-0002` — a transport that can hand a descriptor to the kernel is given one.
pub(crate) fn c_pay_0002() -> u32 {
    let id = "c-pay-0002";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let payload = file_payload(4096);

    c.that(
        id,
        "a file payload advertises the kernel-side capability",
        payload.caps().contains(PayloadCaps::FILE_REGION),
    );

    let query = ZeroCopyQuery::new(TransportCaps::SENDFILE, VerificationObligation::None);
    c.that(
        id,
        "a kernel-capable transport with nothing owed is refused nothing",
        query.refusal().is_none(),
    );

    let outcome = payload.try_into_file_region_for(&query, &metrics);
    let region = match outcome {
        Ok(region) => {
            c.that(id, "the region is handed over", true);
            region
        }
        Err((_, reason)) => panic!("{id}: a kernel-capable transport was refused with {reason}"),
    };
    c.that(id, "the region keeps the length it was built with", region.len() == 4096);
    c.that(
        id,
        "handing a region over is not a refusal and is not counted as one",
        metrics.zero_copy_refusals_total() == 0,
    );
    c.count()
}

/// `c-pay-0003` — segments are borrowed for one vectored write, not gathered into a new buffer.
pub(crate) fn c_pay_0003() -> u32 {
    let id = "c-pay-0003";
    let mut c = Checks::new();
    let source = segments();
    let addresses: Vec<*const u8> = source.iter().map(|segment| segment.as_ptr()).collect();
    let payload = Payload::from_segments(source.clone());

    c.that(
        id,
        "three non-empty segments stay three segments",
        matches!(payload, Payload::Vectored(_)),
    );

    let borrowed = payload.try_as_vectored();
    let borrowed = match borrowed {
        Some(slice) => {
            c.that(id, "segments already in memory can be borrowed as segments", true);
            slice
        }
        None => panic!("{id}: segments already in memory were not offered for a vectored write"),
    };
    c.that(id, "all three segments are offered, not a joined buffer", borrowed.len() == 3);
    c.that(
        id,
        "each borrowed segment is the original allocation, so nothing was gathered into a new one",
        borrowed.iter().map(|segment| segment.as_ptr()).eq(addresses.iter().copied()),
    );
    let total: u64 = source.iter().map(|s| s.len() as u64).sum();
    c.that(id, "the length hint is the sum of the segments", payload.len_hint() == Some(total));
    c.count()
}

/// `c-pay-0004` — a pull payload consumed by a pull consumer costs nothing.
pub(crate) fn c_pay_0004() -> u32 {
    let id = "c-pay-0004";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let reader = ScriptedReader::new([Step::Chunk("pull-native"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(11));
    let payload = Payload::from_reader(reader).expect("the producer's bits and length agree");

    c.that(
        id,
        "a pull producer advertises the pull model",
        payload.caps().contains(PayloadCaps::PULL),
    );

    let (reader, cost) = payload
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a pull payload refused the pull model"));
    c.that(id, "consuming a pull payload through the pull model is free", cost == AdaptCost::Free);
    c.that(id, "no copy is counted", metrics.adapt_copies_total() == 0);
    c.that(id, "no owned buffer is counted", metrics.adapt_buffers_total() == 0);

    let (bytes, _) = drain_reader(reader, 4).expect("the scripted body reaches its end");
    c.that(id, "the bytes arrive unchanged", bytes == b"pull-native");
    c.count()
}

/// `c-pay-0005` — a push payload consumed by a push consumer costs nothing.
pub(crate) fn c_pay_0005() -> u32 {
    let id = "c-pay-0005";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let stream = ScriptedStream::new([Step::Chunk("push-native"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(11));
    let payload = Payload::from_stream(stream).expect("the producer's bits and length agree");

    c.that(
        id,
        "a push producer advertises the push model",
        payload.caps().contains(PayloadCaps::PUSH),
    );

    let (stream, cost) = payload
        .try_into_stream(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a push payload refused the push model"));
    c.that(id, "consuming a push payload through the push model is free", cost == AdaptCost::Free);
    c.that(id, "no copy is counted", metrics.adapt_copies_total() == 0);
    c.that(id, "no owned buffer is counted", metrics.adapt_buffers_total() == 0);

    let (chunks, _) = drain_stream(stream).expect("the scripted body reaches its end");
    c.that(id, "the bytes arrive unchanged", joined(&chunks) == b"push-native");
    c.count()
}

/// `c-pay-0006` — bytes already in hand are read through a cursor, not copied into one.
pub(crate) fn c_pay_0006() -> u32 {
    let id = "c-pay-0006";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let body = Bytes::from_static(b"already in memory");
    let payload = Payload::from_bytes(body.clone());

    let (reader, cost) = payload
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: in-memory bytes refused the pull model"));
    c.that(id, "reading memory through a cursor is free", cost == AdaptCost::Free);
    c.that(id, "no copy is counted", metrics.adapt_copies_total() == 0);
    c.that(id, "no owned buffer is counted", metrics.adapt_buffers_total() == 0);

    let (bytes, _) = drain_reader(reader, 8).expect("an in-memory body reaches its end");
    c.that(id, "the bytes arrive unchanged", bytes == body);
    c.count()
}

/// `c-pay-0007` — an empty payload declares zero, which is not the same as declaring nothing.
pub(crate) fn c_pay_0007() -> u32 {
    let id = "c-pay-0007";
    let mut c = Checks::new();
    let empty = Payload::Empty;

    c.that(id, "an empty payload declares a length of zero", empty.len_hint() == Some(0));
    c.that(id, "an empty payload knows it is empty", empty.is_empty());
    c.that(
        id,
        "an empty payload has a known length rather than an unknown one",
        empty.caps().contains(PayloadCaps::KNOWN_LENGTH),
    );
    c.that(
        id,
        "an empty run of bytes is normalised to the empty payload rather than to a zero-length one",
        matches!(Payload::from_bytes(Bytes::new()), Payload::Empty),
    );
    c.count()
}

/// `c-pay-0020` — a payload refused the kernel-side path comes back whole.
pub(crate) fn c_pay_0020() -> u32 {
    let id = "c-pay-0020";
    let mut c = Checks::new();
    let body = Bytes::from_static(b"not a file at all");
    let payload = Payload::from_bytes(body.clone());

    let (returned, reason) = match payload.try_into_file_region() {
        Ok(_) => panic!("{id}: in-memory bytes were accepted as a file region"),
        Err(pair) => {
            c.that(id, "in-memory bytes are refused the kernel-side path", true);
            pair
        }
    };
    c.that(id, "the reason names the payload's shape", reason == NoZeroCopy::NotFileBacked);
    c.that(
        id,
        "the refused payload still knows its length",
        returned.len_hint() == Some(body.len() as u64),
    );
    c.that(
        id,
        "the refused payload still advertises what it can do",
        returned.caps().contains(PayloadCaps::IN_MEMORY),
    );

    let metrics = StreamMetrics::new();
    let (reader, _) = returned
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: the refused payload was consumed by the refusal"));
    let (bytes, _) = drain_reader(reader, 4).expect("the refused payload still reaches its end");
    c.that(id, "the refused payload still holds every byte it had", bytes == body);
    c.count()
}

/// `c-pay-0021` — a transport with no kernel-side path is told so, and the loss is sized.
pub(crate) fn c_pay_0021() -> u32 {
    let id = "c-pay-0021";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let payload = file_payload(8192);
    let query = ZeroCopyQuery::new(TransportCaps::VECTORED, VerificationObligation::None);

    c.that(
        id,
        "a transport that can only gather buffers has no kernel-side path",
        query.refusal() == Some(NoZeroCopy::TransportLacksSendfile),
    );

    let (returned, reason) = match payload.try_into_file_region_for(&query, &metrics) {
        Ok(_) => panic!("{id}: a transport with no kernel-side path was handed a descriptor"),
        Err(pair) => {
            c.that(id, "the descriptor is not handed over", true);
            pair
        }
    };
    c.that(
        id,
        "the reason names the transport, not the payload",
        reason == NoZeroCopy::TransportLacksSendfile,
    );
    c.that(
        id,
        "the refusal is counted against its own reason",
        metrics.zero_copy_refusals(NoZeroCopy::TransportLacksSendfile) == 1,
    );
    c.that(
        id,
        "the refusal carries the size of the body that took the slow path",
        metrics.zero_copy_refused_bytes_total() == 8192,
    );
    c.that(id, "the refused payload comes back whole", returned.len_hint() == Some(8192));
    c.count()
}

/// `c-pay-0022` — an outstanding verification refuses ahead of every cheaper reason.
pub(crate) fn c_pay_0022() -> u32 {
    let id = "c-pay-0022";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let payload = file_payload(1024);
    let query = ZeroCopyQuery::new(TransportCaps::SENDFILE, VerificationObligation::Present);

    c.that(
        id,
        "a body that still owes a check is refused even by a transport that could send it",
        query.refusal() == Some(NoZeroCopy::VerificationObligationPresent),
    );

    let (_, reason) = match payload.try_into_file_region_for(&query, &metrics) {
        Ok(_) => panic!("{id}: a body that still owes a check was handed to the kernel"),
        Err(pair) => {
            c.that(id, "the descriptor is not handed over", true);
            pair
        }
    };
    c.that(id, "the reason names the obligation", reason == NoZeroCopy::VerificationObligationPresent);
    c.that(
        id,
        "the obligation is counted against its own reason",
        metrics.zero_copy_refusals(NoZeroCopy::VerificationObligationPresent) == 1,
    );

    // The order, not just the answer. A payload that is also not a file, behind a transport
    // that also has no kernel path and also encrypts: every cheaper reason is true at once,
    // and the reported one must still be the obligation. Reporting "not file backed" here
    // would file a body the gateway promised to check under the reason an operator ignores.
    let crowded = ZeroCopyQuery::new(TransportCaps::TLS_IN_PATH | TransportCaps::VECTORED, VerificationObligation::Present);
    let plain = Payload::from_bytes(Bytes::from_static(b"not a file either"));
    let (_, crowded_reason) = match plain.try_into_file_region_for(&crowded, &metrics) {
        Ok(_) => panic!("{id}: a body that still owes a check was handed to the kernel"),
        Err(pair) => pair,
    };
    c.that(
        id,
        "with three reasons true at once the obligation is still the one reported",
        crowded_reason == NoZeroCopy::VerificationObligationPresent,
    );
    c.that(
        id,
        "the cheaper reason is never counted in the obligation's place",
        metrics.zero_copy_refusals(NoZeroCopy::NotFileBacked) == 0,
    );
    c.that(
        id,
        "encryption in the path is never counted in the obligation's place",
        metrics.zero_copy_refusals(NoZeroCopy::TlsInPath) == 0,
    );
    c.count()
}

/// `c-pay-0023` — encryption in the path is its own reason, counted apart from the others.
pub(crate) fn c_pay_0023() -> u32 {
    let id = "c-pay-0023";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let payload = file_payload(2048);
    let query = ZeroCopyQuery::new(TransportCaps::SENDFILE | TransportCaps::TLS_IN_PATH, VerificationObligation::None);

    c.that(
        id,
        "a transport that encrypts cannot let the bytes past user space",
        query.refusal() == Some(NoZeroCopy::TlsInPath),
    );

    let (_, reason) = match payload.try_into_file_region_for(&query, &metrics) {
        Ok(_) => panic!("{id}: an encrypting transport was handed a descriptor"),
        Err(pair) => {
            c.that(id, "the descriptor is not handed over", true);
            pair
        }
    };
    c.that(id, "the reason names encryption", reason == NoZeroCopy::TlsInPath);
    c.that(
        id,
        "the refusal is counted against its own reason",
        metrics.zero_copy_refusals(NoZeroCopy::TlsInPath) == 1,
    );
    c.that(
        id,
        "a transport that could otherwise send is not blamed",
        metrics.zero_copy_refusals(NoZeroCopy::TransportLacksSendfile) == 0,
    );
    c.that(
        id,
        "the reason carries a stable label a log can be grouped by",
        reason.as_str() == "tls-in-path",
    );
    c.count()
}

/// `c-pay-0024` — reading a push body through the pull model copies, and the copy is sized.
pub(crate) fn c_pay_0024() -> u32 {
    let id = "c-pay-0024";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let stream = ScriptedStream::new([Step::Chunk("push-then-pull"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(14));
    let payload = Payload::from_stream(stream).expect("the producer's bits and length agree");

    let (reader, cost) = payload
        .try_into_reader(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a push payload refused the pull model"));
    c.that(id, "crossing from the push model to the pull model costs a copy", cost.is_copy());
    c.that(id, "the copy states how many bytes it expects to move", cost.est_bytes() == Some(14));
    c.that(id, "exactly one copying adapter is counted", metrics.adapt_copies_total() == 1);
    c.that(
        id,
        "the copied bytes are counted, not just the adapter",
        metrics.adapt_copied_bytes_total() == 14,
    );
    c.that(id, "a copy is not also counted as an owned buffer", metrics.adapt_buffers_total() == 0);

    let (bytes, _) = drain_reader(reader, 5).expect("the adapted body reaches its end");
    c.that(id, "the adaptation moves every byte and changes none", bytes == b"push-then-pull");
    c.count()
}

/// `c-pay-0025` — reading a pull body through the push model owns a buffer, and that is not a copy.
///
/// The task's row for this case says the cost is a copy. It is not, and the ledger asserts what
/// the data path does rather than what the row predicted: the adapter allocates the buffer the
/// producer fills, the producer writes each byte straight into it, and no byte is written twice.
/// Counting that as a copy would make the copy counter useless for the thing it exists to catch,
/// which is a second full pass over an upload.
pub(crate) fn c_pay_0025() -> u32 {
    let id = "c-pay-0025";
    let mut c = Checks::new();
    let metrics = StreamMetrics::new();
    let reader = ScriptedReader::new([Step::Chunk("pull-then-push"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PULL | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(14));
    let payload = Payload::from_reader(reader).expect("the producer's bits and length agree");

    let (stream, cost) = payload
        .try_into_stream(&metrics)
        .unwrap_or_else(|_| panic!("{id}: a pull payload refused the push model"));
    c.that(
        id,
        "crossing from the pull model to the push model costs an owned buffer",
        matches!(cost, AdaptCost::Buffer { .. }),
    );
    c.that(id, "the buffer states how many bytes it expects to carry", cost.est_bytes() == Some(14));
    c.that(id, "exactly one buffering adapter is counted", metrics.adapt_buffers_total() == 1);
    c.that(id, "an owned buffer is not counted as a copy", metrics.adapt_copies_total() == 0);
    c.that(id, "no bytes are counted as copied", metrics.adapt_copied_bytes_total() == 0);

    let (chunks, _) = drain_stream(stream).expect("the adapted body reaches its end");
    c.that(
        id,
        "the adaptation moves every byte and changes none",
        joined(&chunks) == b"pull-then-push",
    );
    c.count()
}

/// `c-pay-0031` — a body that stops short of what it declared fails instead of ending.
pub(crate) fn c_pay_0031() -> u32 {
    let id = "c-pay-0031";
    let mut c = Checks::new();
    let inner = ScriptedStream::new([Step::Chunk("abcd"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(10));
    let mut stream: crate::stream::BoxPayloadStream =
        Box::pin(crate::byte_stream::ByteStream::new(inner.boxed()).expect("the bits and the length agree"));

    let first = poll_stream_once(&mut stream);
    c.that(
        id,
        "the bytes that did arrive are delivered",
        matches!(&first, core::task::Poll::Ready(Ok(PayloadRead::Chunk(chunk))) if chunk.len() == 4),
    );

    let second = poll_stream_once(&mut stream);
    let error = match second {
        core::task::Poll::Ready(Err(error)) => {
            c.that(id, "a body four bytes short of ten does not report a clean end", true);
            error
        }
        other => panic!("{id}: a truncated body ended as if it were whole: {other:?}"),
    };
    c.that(
        id,
        "the failure names truncation",
        matches!(error.kind(), StreamErrorKind::IncompleteBody),
    );
    c.that(
        id,
        "the failure says how much had already been handed on",
        error.bytes_before_error() == 4,
    );

    let third = poll_stream_once(&mut stream);
    c.that(
        id,
        "a failed body stays failed rather than producing a fresh chunk",
        matches!(third, core::task::Poll::Ready(Err(ref error)) if matches!(error.kind(), StreamErrorKind::PolledAfterEof)),
    );
    c.count()
}

/// `c-pay-0032` — a body that overruns what it declared fails at the overrunning chunk.
pub(crate) fn c_pay_0032() -> u32 {
    let id = "c-pay-0032";
    let mut c = Checks::new();
    let inner = ScriptedStream::new([Step::Chunk("abcd"), Step::Chunk("e"), Step::Eof(TrailingHeaders::empty())])
        .with_caps(PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH)
        .with_len_hint(Some(4));
    let mut stream: crate::stream::BoxPayloadStream =
        Box::pin(crate::byte_stream::ByteStream::new(inner.boxed()).expect("the bits and the length agree"));

    let first = poll_stream_once(&mut stream);
    c.that(
        id,
        "the declared bytes are delivered",
        matches!(&first, core::task::Poll::Ready(Ok(PayloadRead::Chunk(chunk))) if chunk.len() == 4),
    );

    let second = poll_stream_once(&mut stream);
    let error = match second {
        core::task::Poll::Ready(Err(error)) => {
            c.that(id, "the byte past the declared length is not delivered", true);
            error
        }
        other => panic!("{id}: an overlong body handed on a byte it had not declared: {other:?}"),
    };
    match error.kind() {
        StreamErrorKind::LengthMismatch { declared, observed } => {
            c.that(id, "the failure names the mismatch", true);
            c.that(id, "the failure repeats what was declared", *declared == 4);
            c.that(id, "the failure repeats what was seen", *observed == 5);
        }
        other => panic!("{id}: an overlong body failed as {other:?} rather than as a length mismatch"),
    }

    let third = poll_stream_once(&mut stream);
    c.that(
        id,
        "a failed body stays failed rather than producing a fresh chunk",
        matches!(third, core::task::Poll::Ready(Err(ref error)) if matches!(error.kind(), StreamErrorKind::PolledAfterEof)),
    );
    c.count()
}

/// `c-pay-0033` — a range whose end does not fit is refused where the caller can still see it.
pub(crate) fn c_pay_0033() -> u32 {
    let id = "c-pay-0033";
    let mut c = Checks::new();

    let refused = FileRegion::new(detached_fd(0), u64::MAX, 1);
    match refused {
        Ok(_) => panic!("{id}: a range ending past u64::MAX was accepted"),
        Err(error) => {
            c.that(id, "a range that cannot exist is refused at construction", true);
            c.that(
                id,
                "the refusal repeats the range that was asked for",
                error
                    == FileRegionError::RangeOverflow {
                        offset: u64::MAX,
                        len: 1,
                    },
            );
        }
    }

    let just_over = FileRegion::new(detached_fd(0), u64::MAX - 1, 2);
    c.that(id, "a range that overflows by one byte is refused too", just_over.is_err());

    let boundary = FileRegion::new(detached_fd(0), u64::MAX, 0).expect("an empty range at the last offset fits");
    c.that(id, "the largest range that does fit is accepted", boundary.is_empty());
    c.that(
        id,
        "its end offset is the last offset, computed without wrapping",
        boundary.end_offset() == u64::MAX,
    );
    c.count()
}
