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

//! File-backed response bodies on transports that cannot send a file region.
//!
//! Responsible for: deciding, once per request, whether the connection it arrived on can take a
//! `Payload::File` body whole — only the self-held HTTP/1.1 driver can, and it says so with a
//! marker nobody outside this crate can construct — and otherwise replacing such a body with one
//! that copies the region through a blocking executor, counted and named (rustfs/backlog#1740
//! a-zc-0009 / 0010 / 0012, rustfs/gateway#949).
//! NOT responsible for: the kernel transfer itself (`crate::conn`), or the stream crate's refusal
//! to read a file without an i/o driver, which is why this module exists.
//! Upstream: `crate::service`, which calls [`FileBodyPath::adapt`] on every response.
//! Downstream: Hyper, and any other consumer of `S3Service` responses through `http_body`.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{Extensions, Response, Version};
use rustfs_gateway_stream::{Body, NoZeroCopy, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use tokio::io::{AsyncRead, ReadBuf};

/// Inserted into a request by the self-held driver, which is the one transport that sends
/// `Payload::File` bodies itself. Crate-private, so a request cannot claim it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KernelFileTransfer;

/// How a file-backed response body leaves this request's connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileBodyPath {
    /// The self-held driver sends it with `sendfile`, or copies it itself when it cannot.
    Kernel,
    /// Nothing downstream can read a file region; it is copied here, for this reason.
    Copied(NoZeroCopy),
}

impl FileBodyPath {
    /// Reads the request's transport facts. TLS outranks HTTP/2, which outranks a plain Hyper
    /// connection: the first reason in that order is the one an operator can act on.
    pub(crate) fn of(extensions: &Extensions, version: Version) -> Self {
        if extensions.get::<KernelFileTransfer>().is_some() {
            return Self::Kernel;
        }
        Self::Copied(copied_reason(tls_in_path(extensions), version))
    }

    /// Replaces a file-backed body with a copying one on a transport that cannot send it.
    pub(crate) fn adapt(self, response: Response<Body>) -> Response<Body> {
        let Self::Copied(reason) = self else {
            return response;
        };
        if response.body().file_region_end_offset().is_none() {
            return response;
        }
        let (parts, body) = response.into_parts();
        let body = match body.into_transport().try_into_copied_file_for(reason) {
            Ok(source) => {
                source.record_copy_adaptation();
                let len = source.len();
                let stream = source
                    .into_positioned_file()
                    .ok()
                    .and_then(|(file, remaining)| Body::from_stream(CopiedFileStream::new(file, remaining)).ok());
                // A file that cannot be positioned, or a stream whose length contradicts its caps,
                // ends in an error frame rather than an empty body that would read as complete.
                stream.unwrap_or_else(|| Body::from_stream(FailedStream(len)).unwrap_or_default())
            }
            Err(body) => body,
        };
        Response::from_parts(parts, body)
    }
}

fn copied_reason(tls: bool, version: Version) -> NoZeroCopy {
    if tls {
        NoZeroCopy::TlsInPath
    } else if version == Version::HTTP_2 {
        NoZeroCopy::Http2InPath
    } else {
        NoZeroCopy::TransportLacksSendfile
    }
}

#[cfg(feature = "server")]
fn tls_in_path(extensions: &Extensions) -> bool {
    extensions
        .get::<rustfs_gateway_server::ConnectionInfo>()
        .is_some_and(|connection| connection.transport() == rustfs_gateway_server::TransportKind::Tls)
}

#[cfg(not(feature = "server"))]
fn tls_in_path(_extensions: &Extensions) -> bool {
    false
}

/// The largest read one poll asks for.
const CHUNK: u64 = 64 * 1024;

/// A file region read through Tokio's file reader, one bounded read per poll.
///
/// Demand-driven: nothing is read until the consumer polls, and at most one read is in flight, so
/// a stalled client stops the reads rather than letting them run ahead.
struct CopiedFileStream {
    file: tokio::fs::File,
    remaining: u64,
    buffer: Vec<u8>,
}

impl CopiedFileStream {
    fn new(file: std::fs::File, remaining: u64) -> Self {
        Self {
            file: tokio::fs::File::from_std(file),
            remaining,
            buffer: Vec::new(),
        }
    }
}

impl PayloadStream for CopiedFileStream {
    fn poll_read(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        let this = self.get_mut();
        if this.remaining == 0 {
            return Poll::Ready(Ok(PayloadRead::Eof {
                trailers: TrailingHeaders::empty(),
            }));
        }
        let wanted = usize::try_from(this.remaining.min(CHUNK)).unwrap_or(0);
        if this.buffer.len() != wanted {
            this.buffer = vec![0_u8; wanted];
        }
        let mut read_buf = ReadBuf::new(&mut this.buffer);
        match Pin::new(&mut this.file).poll_read(context, &mut read_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(StreamError::upstream(Box::new(error)))),
            Poll::Ready(Ok(())) => {
                let read = read_buf.filled().len();
                if read == 0 {
                    return Poll::Ready(Err(StreamError::incomplete_body()));
                }
                let mut chunk = std::mem::take(&mut this.buffer);
                chunk.truncate(read);
                this.remaining = this.remaining.saturating_sub(read as u64);
                Poll::Ready(Ok(PayloadRead::Chunk(Bytes::from(chunk))))
            }
        }
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.remaining)
    }
}

/// A body that fails at once. Used only if the copied stream could not be wrapped at all.
struct FailedStream(u64);

impl PayloadStream for FailedStream {
    fn poll_read(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        Poll::Ready(Err(StreamError::incomplete_body()))
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// a-zc-0009 / a-zc-0010. Negative — each transport fact names its own reason, and TLS outranks
    /// HTTP/2 because it is the one an HTTP/1.1 deployment cannot switch off.
    #[test]
    fn every_copied_path_names_its_reason() {
        assert_eq!(copied_reason(true, Version::HTTP_2), NoZeroCopy::TlsInPath);
        assert_eq!(copied_reason(true, Version::HTTP_11), NoZeroCopy::TlsInPath);
        assert_eq!(copied_reason(false, Version::HTTP_2), NoZeroCopy::Http2InPath);
        assert_eq!(copied_reason(false, Version::HTTP_11), NoZeroCopy::TransportLacksSendfile);
    }

    /// Negative — only the crate-private marker selects the kernel path.
    #[test]
    fn only_the_self_held_marker_selects_the_kernel_path() {
        let mut extensions = Extensions::new();
        assert_eq!(
            FileBodyPath::of(&extensions, Version::HTTP_11),
            FileBodyPath::Copied(NoZeroCopy::TransportLacksSendfile)
        );
        extensions.insert(KernelFileTransfer);
        assert_eq!(FileBodyPath::of(&extensions, Version::HTTP_11), FileBodyPath::Kernel);
    }
}
