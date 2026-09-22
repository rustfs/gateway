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

//! Response fallback write controls.
//!
//! Responsible for: observing framing and vectored progress.
//! NOT responsible for: connection setup or request parsing.
//! Upstream: response writer. Downstream: deterministic test writers.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;

use super::*;

#[derive(Default)]
struct ObservedWriter {
    bytes: Vec<u8>,
    scalar_calls: usize,
    vectored_calls: usize,
    first_vectored_slices: Option<usize>,
    max_written: Option<usize>,
    reject_after: Option<usize>,
}

struct PartialThenErrorWriter {
    first: bool,
}

impl AsyncWrite for PartialThenErrorWriter {
    fn poll_write(mut self: Pin<&mut Self>, _context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if self.first {
            self.first = false;
            Poll::Ready(Ok(bytes.len().min(2)))
        } else {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture peer reset")))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ObservedWriter {
    fn poll_write(mut self: Pin<&mut Self>, _context: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.scalar_calls += 1;
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.vectored_calls += 1;
        self.first_vectored_slices.get_or_insert(buffers.len());
        if self.reject_after.is_some_and(|limit| self.bytes.len() >= limit) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture vector reset")));
        }
        let mut available = self
            .max_written
            .unwrap_or(usize::MAX)
            .min(self.reject_after.unwrap_or(usize::MAX).saturating_sub(self.bytes.len()));
        let mut written = 0;
        for buffer in buffers {
            let take = available.min(buffer.len());
            self.bytes.extend(buffer.iter().take(take).copied());
            written += take;
            available -= take;
        }
        Poll::Ready(Ok(written))
    }
}

#[tokio::test]
async fn vectored_payload_reaches_the_vectored_writer_once() {
    let mut writer = ObservedWriter::default();
    let segments = [
        Bytes::from_static(b"ab"),
        Bytes::from_static(b"cd"),
        Bytes::from_static(b"ef"),
    ];
    assert!(
        write_memory_segments(&mut writer, &segments, ResponseFraming::Fixed(6), None)
            .await
            .is_ok(),
        "observed writer accepts the payload"
    );
    assert_eq!(writer.vectored_calls, 1);
    assert_eq!(writer.scalar_calls, 0);
    assert_eq!(writer.first_vectored_slices, Some(3));
    assert_eq!(writer.bytes, b"abcdef");
}

#[tokio::test]
async fn chunk_prefix_data_and_delimiter_share_one_vectored_write() {
    let mut writer = ObservedWriter::default();
    assert!(
        write_chunk(&mut writer, b"hello", None).await.is_ok(),
        "observed writer accepts the chunk"
    );
    assert_eq!(writer.vectored_calls, 1);
    assert_eq!(writer.scalar_calls, 0);
    assert_eq!(writer.first_vectored_slices, Some(3));
    assert_eq!(writer.bytes, b"5\r\nhello\r\n");
}

#[test]
fn chunk_prefix_encodes_the_entire_protocol_length_range() {
    let mut storage = [0_u8; 18];
    assert_eq!(encode_chunk_prefix(u64::MAX, &mut storage).ok(), Some(&b"FFFFFFFFFFFFFFFF\r\n"[..]));
}

#[tokio::test]
async fn copied_payload_progress_survives_a_later_socket_error() {
    let mut writer = PartialThenErrorWriter { first: true };
    let metrics = ResponseTransportMetrics::new();
    let result =
        write_memory_segments(&mut writer, &[Bytes::from_static(b"four")], ResponseFraming::Fixed(4), Some(&metrics)).await;
    assert_eq!(result.as_ref().err().map(io::Error::kind), Some(io::ErrorKind::BrokenPipe));
    assert_eq!(metrics.copied_payload_bytes(), 2);
}

#[tokio::test]
async fn fragmented_memory_payload_bounds_each_vectored_call() {
    for length in [15_usize, 16, 17, 65] {
        let mut writer = ObservedWriter::default();
        let segments: Vec<_> = (0..length).flat_map(|_| [Bytes::new(), Bytes::from_static(b"x")]).collect();
        assert!(
            write_memory_segments(&mut writer, &segments, ResponseFraming::Fixed(length as u64), None)
                .await
                .is_ok()
        );
        assert_eq!(writer.first_vectored_slices, Some(length.min(16)));
        assert_eq!(writer.vectored_calls, length.div_ceil(16));
        assert_eq!(writer.bytes, vec![b'x'; length]);
    }
}

#[tokio::test]
async fn trailer_fields_use_vectored_framing() {
    let mut writer = ObservedWriter::default();
    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", http::HeaderValue::from_static("abc"));
    let body =
        http_body_util::StreamBody::new(futures_util::stream::iter([Ok::<_, io::Error>(http_body::Frame::trailers(trailers))]));
    assert!(write_body(&mut writer, body, ResponseFraming::Chunked, None).await.is_ok());
    assert_eq!(writer.vectored_calls, 1);
    assert_eq!(writer.scalar_calls, 2);
    assert_eq!(writer.bytes, b"0\r\nx-checksum: abc\r\n\r\n");
}

#[tokio::test]
async fn fragmented_chunked_payload_keeps_one_chunk_across_batches() {
    let mut writer = ObservedWriter::default();
    let segments = vec![Bytes::from_static(b"x"); 65];
    let metrics = ResponseTransportMetrics::new();
    assert!(
        write_memory_segments(&mut writer, &segments, ResponseFraming::Chunked, Some(&metrics))
            .await
            .is_ok()
    );
    assert_eq!(writer.first_vectored_slices, Some(16));
    assert_eq!(writer.bytes, [b"41\r\n".as_slice(), &[b'x'; 65], b"\r\n0\r\n\r\n"].concat());
    assert_eq!(metrics.copied_payload_bytes(), 65);
}

#[tokio::test]
async fn vectored_payload_rejects_zero_progress() {
    struct ZeroWriter;
    impl AsyncWrite for ZeroWriter {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(0))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let result = write_memory_segments(&mut ZeroWriter, &[Bytes::from_static(b"x")], ResponseFraming::Fixed(1), None).await;
    assert_eq!(result.as_ref().err().map(io::Error::kind), Some(io::ErrorKind::WriteZero));
}

#[tokio::test]
async fn chunk_prefix_error_does_not_count_framing_as_payload() {
    let mut writer = PartialThenErrorWriter { first: true };
    let metrics = ResponseTransportMetrics::new();
    let result =
        write_memory_segments(&mut writer, &[Bytes::from_static(b"data")], ResponseFraming::Chunked, Some(&metrics)).await;
    assert_eq!(result.as_ref().err().map(io::Error::kind), Some(io::ErrorKind::BrokenPipe));
    assert_eq!(metrics.copied_payload_bytes(), 0);
}

#[tokio::test]
async fn trailer_write_errors_are_propagated() {
    struct TrailerErrorWriter;
    impl AsyncWrite for TrailerErrorWriter {
        fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_write_vectored(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[IoSlice<'_>]) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "fixture trailer reset")))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let mut writer = TrailerErrorWriter;
    let mut trailers = HeaderMap::new();
    trailers.insert("x-checksum", http::HeaderValue::from_static("abc"));
    let body =
        http_body_util::StreamBody::new(futures_util::stream::iter([Ok::<_, io::Error>(http_body::Frame::trailers(trailers))]));
    let result = write_body(&mut writer, body, ResponseFraming::Chunked, None).await;
    assert_eq!(result.as_ref().err().map(io::Error::kind), Some(io::ErrorKind::BrokenPipe));
}

#[tokio::test]
async fn partial_chunked_writes_preserve_bytes_across_vector_batches() {
    let mut writer = ObservedWriter {
        max_written: Some(3),
        ..Default::default()
    };
    let segments = vec![Bytes::from_static(b"x"); 65];
    let metrics = ResponseTransportMetrics::new();
    assert!(
        write_memory_segments(&mut writer, &segments, ResponseFraming::Chunked, Some(&metrics))
            .await
            .is_ok()
    );
    assert_eq!(writer.bytes, [b"41\r\n".as_slice(), &[b'x'; 65], b"\r\n0\r\n\r\n"].concat());
    assert_eq!(metrics.copied_payload_bytes(), 65);
}

#[tokio::test]
async fn later_vector_errors_preserve_only_completed_payload_progress() {
    for (framing, limit, expected) in [
        (ResponseFraming::Fixed(65), 0, 0),
        (ResponseFraming::Fixed(65), 1, 1),
        (ResponseFraming::Fixed(65), 15, 15),
        (ResponseFraming::Fixed(65), 16, 16),
        (ResponseFraming::Fixed(65), 17, 17),
        (ResponseFraming::Fixed(65), 64, 64),
        (ResponseFraming::Chunked, 1, 0),
        (ResponseFraming::Chunked, 20, 16),
        (ResponseFraming::Chunked, 69, 65),
        (ResponseFraming::Chunked, 70, 65),
    ] {
        let mut writer = ObservedWriter {
            max_written: Some(3),
            reject_after: Some(limit),
            ..Default::default()
        };
        let segments = vec![Bytes::from_static(b"x"); 65];
        let metrics = ResponseTransportMetrics::new();
        let result = write_memory_segments(&mut writer, &segments, framing, Some(&metrics)).await;
        assert_eq!(result.as_ref().err().map(io::Error::kind), Some(io::ErrorKind::BrokenPipe));
        assert_eq!(metrics.copied_payload_bytes(), expected);
    }
}
