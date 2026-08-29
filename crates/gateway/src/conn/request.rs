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

//! HTTP/1.1 syntax parsing and streaming request-body frames for the self-held driver.
//!
//! Responsible for: strict parser-level syntax, lossless duplicate headers, fixed-length and
//! transfer-chunk decoding.
//! NOT responsible for: request acceptance, signing, routing or S3 body semantics.
//! Upstream: the accepted TCP socket.
//! Downstream: `S3Service`'s sole wire acceptance.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::str;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Uri, Version, header};
use http_body::{Frame, SizeHint};
use rustfs_gateway_server::PlaintextConnection;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

const MAX_HEADERS: usize = 128;
const MAX_CHUNK_LINE_BYTES: usize = 1024;
const MAX_TRAILER_BYTES: usize = 16 * 1024;
const READ_CHUNK_BYTES: usize = 16 * 1024;
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

type PendingRead = Pin<Box<dyn Future<Output = io::Result<BodyFrame>> + Send + 'static>>;

pub(super) struct ConnectionIo {
    pub(super) stream: PlaintextConnection,
    buffer: BytesMut,
    body: BodyState,
}

impl ConnectionIo {
    pub(super) fn new(stream: PlaintextConnection) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
            body: BodyState::Empty,
        }
    }

    pub(super) fn body_complete(&self) -> bool {
        matches!(self.body, BodyState::Empty | BodyState::Chunked(ChunkState { phase: ChunkPhase::Eof }))
            || matches!(self.body, BodyState::Fixed { remaining: 0 })
    }

    pub(super) async fn drain_request_body(&mut self, limit: u64) -> io::Result<bool> {
        let mut drained = 0_u64;
        while !self.body_complete() {
            match self.read_body_frame().await? {
                BodyFrame::Data(bytes) => {
                    drained = drained.saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                    if drained > limit {
                        return Ok(false);
                    }
                }
                BodyFrame::Trailers(_) => {}
                BodyFrame::Eof => return Ok(true),
            }
        }
        Ok(true)
    }

    async fn fill(&mut self) -> io::Result<bool> {
        self.buffer.reserve(READ_CHUNK_BYTES);
        self.stream.read_buf(&mut self.buffer).await.map(|read| read != 0)
    }

    async fn read_body_frame(&mut self) -> io::Result<BodyFrame> {
        let mut body = core::mem::replace(&mut self.body, BodyState::Empty);
        let result = match &mut body {
            BodyState::Empty => Ok(BodyFrame::Eof),
            BodyState::Invalid => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP/1.1 request framing")),
            BodyState::Fixed { remaining } => {
                if *remaining == 0 {
                    return Ok(BodyFrame::Eof);
                }
                if self.buffer.is_empty() && !self.fill().await? {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "fixed-length request body ended early"));
                }
                let available = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
                let take = usize::try_from((*remaining).min(available)).map_err(io::Error::other)?;
                *remaining -= u64::try_from(take).map_err(io::Error::other)?;
                Ok(BodyFrame::Data(self.buffer.split_to(take).freeze()))
            }
            BodyState::Chunked(state) => self.read_chunked_frame(state).await,
        };
        self.body = if result.is_err() { BodyState::Invalid } else { body };
        result
    }

    async fn read_chunked_frame(&mut self, state: &mut ChunkState) -> io::Result<BodyFrame> {
        loop {
            match state.phase {
                ChunkPhase::Size => {
                    let line = self.read_crlf_line(MAX_CHUNK_LINE_BYTES).await?;
                    let token = line.split(|byte| *byte == b';').next().unwrap_or_default();
                    if token.is_empty() || token.iter().any(|byte| !byte.is_ascii_hexdigit()) {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP/1.1 chunk size"));
                    }
                    let token = str::from_utf8(token)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 chunk size is not ASCII"))?;
                    let size = u64::from_str_radix(token, 16)
                        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 chunk size overflows"))?;
                    state.phase = if size == 0 {
                        ChunkPhase::Trailers
                    } else {
                        ChunkPhase::Data(size)
                    };
                }
                ChunkPhase::Data(remaining) => {
                    if self.buffer.is_empty() && !self.fill().await? {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk data ended early"));
                    }
                    let available = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
                    let take = usize::try_from(remaining.min(available)).map_err(io::Error::other)?;
                    let next = remaining - u64::try_from(take).map_err(io::Error::other)?;
                    state.phase = if next == 0 {
                        ChunkPhase::DataCrlf
                    } else {
                        ChunkPhase::Data(next)
                    };
                    return Ok(BodyFrame::Data(self.buffer.split_to(take).freeze()));
                }
                ChunkPhase::DataCrlf => {
                    self.require_crlf().await?;
                    state.phase = ChunkPhase::Size;
                }
                ChunkPhase::Trailers => {
                    let trailers = self.read_trailers().await?;
                    state.phase = ChunkPhase::Eof;
                    return if trailers.is_empty() {
                        Ok(BodyFrame::Eof)
                    } else {
                        Ok(BodyFrame::Trailers(trailers))
                    };
                }
                ChunkPhase::Eof => return Ok(BodyFrame::Eof),
            }
        }
    }

    async fn require_crlf(&mut self) -> io::Result<()> {
        while self.buffer.len() < 2 {
            if !self.fill().await? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "chunk delimiter ended early"));
            }
        }
        if self.buffer.get(..2) != Some(b"\r\n") {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk data is not followed by CRLF"));
        }
        self.buffer.advance(2);
        Ok(())
    }

    async fn read_crlf_line(&mut self, limit: usize) -> io::Result<Bytes> {
        loop {
            if let Some(end) = find_crlf(&self.buffer) {
                if end.saturating_add(2) > limit {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 line exceeds its limit"));
                }
                let line = self.buffer.split_to(end).freeze();
                self.buffer.advance(2);
                return Ok(line);
            }
            if contains_bare_lf(&self.buffer) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 line uses a bare LF"));
            }
            if self.buffer.len() >= limit {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 line exceeds its limit"));
            }
            if !self.fill().await? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "HTTP/1.1 line ended early"));
            }
        }
    }

    async fn read_trailers(&mut self) -> io::Result<HeaderMap> {
        loop {
            let complete_len = if self.buffer.starts_with(b"\r\n") {
                Some(2)
            } else {
                find_head_end(&self.buffer).map(|end| end.saturating_add(4))
            };
            if let Some(complete_len) = complete_len {
                if complete_len > MAX_TRAILER_BYTES {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 trailers exceed their limit"));
                }
                let section = self
                    .buffer
                    .get(..complete_len)
                    .ok_or_else(|| io::Error::other("complete trailer boundary exceeds its buffer"))?;
                if contains_bare_lf(section) {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 trailer uses a bare LF"));
                }
                let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
                let (used, parsed) = match httparse::parse_headers(&self.buffer, &mut slots)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                {
                    httparse::Status::Complete(result) => result,
                    httparse::Status::Partial => continue,
                };
                let mut trailers = HeaderMap::with_capacity(parsed.len());
                for parsed_header in parsed {
                    let name = HeaderName::from_bytes(parsed_header.name.as_bytes()).map_err(io::Error::other)?;
                    let value = HeaderValue::from_bytes(parsed_header.value).map_err(io::Error::other)?;
                    trailers.append(name, value);
                }
                self.buffer.advance(used);
                return Ok(trailers);
            }
            if contains_bare_lf(&self.buffer) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 trailer uses a bare LF"));
            }
            if self.buffer.len() >= MAX_TRAILER_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 trailers exceed their limit"));
            }
            if !self.fill().await? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "HTTP/1.1 trailers ended early"));
            }
        }
    }
}

/// Streaming request body produced by the self-held HTTP/1.1 parser.
pub struct SelfHeldRequestBody {
    io: Arc<Mutex<ConnectionIo>>,
    pending: Option<PendingRead>,
    remaining: Option<u64>,
    ended: bool,
}

impl SelfHeldRequestBody {
    fn new(io: Arc<Mutex<ConnectionIo>>, remaining: Option<u64>) -> Self {
        Self {
            io,
            pending: None,
            remaining,
            ended: remaining == Some(0),
        }
    }
}

impl http_body::Body for SelfHeldRequestBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if self.pending.is_none() {
            let io = Arc::clone(&self.io);
            self.pending = Some(Box::pin(async move { io.lock().await.read_body_frame().await }));
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Pending;
        };
        match pending.as_mut().poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                match result {
                    Err(error) => {
                        self.ended = true;
                        Poll::Ready(Some(Err(error)))
                    }
                    Ok(BodyFrame::Data(bytes)) => {
                        if let Some(remaining) = &mut self.remaining {
                            *remaining = remaining.saturating_sub(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                        }
                        Poll::Ready(Some(Ok(Frame::data(bytes))))
                    }
                    Ok(BodyFrame::Trailers(trailers)) => {
                        self.ended = true;
                        self.remaining = Some(0);
                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    }
                    Ok(BodyFrame::Eof) => {
                        self.ended = true;
                        self.remaining = Some(0);
                        Poll::Ready(None)
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.ended
    }

    fn size_hint(&self) -> SizeHint {
        let mut hint = SizeHint::new();
        if let Some(remaining) = self.remaining {
            hint.set_exact(remaining);
        }
        hint
    }
}

pub(super) struct ParsedRequest {
    pub(super) request: Request<SelfHeldRequestBody>,
    pub(super) close_after_response: bool,
    pub(super) expectation: Expectation,
    pub(super) body_expected: bool,
}

#[derive(Clone, Copy)]
pub(super) enum Expectation {
    None,
    Continue,
    Unsupported,
}

pub(super) enum HeaderTimeout {
    At(tokio::time::Instant),
    After(Duration),
}

pub(super) async fn read_request(
    io: Arc<Mutex<ConnectionIo>>,
    max_head_bytes: usize,
    timeout: HeaderTimeout,
) -> io::Result<Option<ParsedRequest>> {
    let read = read_request_inner(io, max_head_bytes);
    match timeout {
        HeaderTimeout::At(deadline) => tokio::time::timeout_at(deadline, read).await,
        HeaderTimeout::After(duration) => tokio::time::timeout(duration, read).await,
    }
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP/1.1 request head timed out"))?
}

async fn read_request_inner(io: Arc<Mutex<ConnectionIo>>, max_head_bytes: usize) -> io::Result<Option<ParsedRequest>> {
    let mut locked = io.lock().await;
    loop {
        if !locked.buffer.is_empty() && HTTP2_PREFACE.starts_with(&locked.buffer) {
            if locked.buffer.len() >= HTTP2_PREFACE.len() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/2 preface is not accepted"));
            }
        } else if let Some(complete_len) = find_head_end(&locked.buffer).map(|end| end.saturating_add(4)) {
            if complete_len > max_head_bytes {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 request head exceeds its limit"));
            }
            let section = locked
                .buffer
                .get(..complete_len)
                .ok_or_else(|| io::Error::other("complete request boundary exceeds its buffer"))?;
            let Some(head) = parse_head(section)? else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "complete HTTP/1.1 request head did not parse"));
            };
            locked.buffer.advance(head.used);
            let body_expected = head.body.expects_data();
            locked.body = head.body;
            let remaining = match locked.body {
                BodyState::Fixed { remaining } => Some(remaining),
                BodyState::Empty => Some(0),
                BodyState::Chunked(_) | BodyState::Invalid => None,
            };
            let body = SelfHeldRequestBody::new(Arc::clone(&io), remaining);
            let mut request = Request::new(body);
            *request.method_mut() = head.method;
            *request.uri_mut() = head.uri;
            *request.version_mut() = Version::HTTP_11;
            *request.headers_mut() = head.headers;
            return Ok(Some(ParsedRequest {
                request,
                close_after_response: head.close_after_response,
                expectation: head.expectation,
                body_expected,
            }));
        } else if contains_bare_lf(&locked.buffer) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 request uses a bare LF"));
        }
        if locked.buffer.len() >= max_head_bytes {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 request head exceeds its limit"));
        }
        let read = locked.fill().await?;
        if !read {
            return if locked.buffer.is_empty() {
                Ok(None)
            } else {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "HTTP/1.1 request head ended early"))
            };
        }
    }
}

struct ParsedHead {
    used: usize,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: BodyState,
    close_after_response: bool,
    expectation: Expectation,
}

fn parse_head(buffer: &[u8]) -> io::Result<Option<ParsedHead>> {
    if contains_bare_lf(buffer) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP/1.1 request uses a bare LF"));
    }
    let mut slots = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut slots);
    let used = match parsed
        .parse(buffer)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
    {
        httparse::Status::Complete(used) => used,
        httparse::Status::Partial => return Ok(None),
    };
    if parsed.version != Some(1) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "self-held transport requires HTTP/1.1"));
    }
    let method = Method::from_bytes(parsed.method.unwrap_or_default().as_bytes()).map_err(io::Error::other)?;
    let uri = Uri::try_from(parsed.path.unwrap_or_default()).map_err(io::Error::other)?;
    let mut headers = HeaderMap::with_capacity(parsed.headers.len());
    for parsed_header in parsed.headers.iter() {
        let name = HeaderName::from_bytes(parsed_header.name.as_bytes()).map_err(io::Error::other)?;
        let value = HeaderValue::from_bytes(parsed_header.value).map_err(io::Error::other)?;
        headers.append(name, value);
    }
    let close_after_response = header_has_token(&headers, header::CONNECTION, "close");
    let expectation = parse_expectation(&headers);
    let body = select_body_state(&headers);
    Ok(Some(ParsedHead {
        used,
        method,
        uri,
        headers,
        body,
        close_after_response,
        expectation,
    }))
}

fn parse_expectation(headers: &HeaderMap) -> Expectation {
    let mut seen = false;
    for value in headers.get_all(header::EXPECT) {
        let Ok(value) = value.to_str() else {
            return Expectation::Unsupported;
        };
        for token in value.split(',') {
            if !token.trim().eq_ignore_ascii_case("100-continue") {
                return Expectation::Unsupported;
            }
            seen = true;
        }
    }
    if seen { Expectation::Continue } else { Expectation::None }
}

fn select_body_state(headers: &HeaderMap) -> BodyState {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return BodyState::Chunked(ChunkState { phase: ChunkPhase::Size });
    }
    let Some(value) = headers.get(header::CONTENT_LENGTH) else {
        return BodyState::Empty;
    };
    let Ok(value) = value.to_str() else {
        return BodyState::Invalid;
    };
    let Ok(remaining) = value.parse::<u64>() else {
        return BodyState::Invalid;
    };
    BodyState::Fixed { remaining }
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value
            .to_str()
            .ok()
            .is_some_and(|value| value.split(',').any(|token| token.trim().eq_ignore_ascii_case(expected)))
    })
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn contains_bare_lf(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\n' && index.checked_sub(1).and_then(|previous| bytes.get(previous)) != Some(&b'\r'))
}

enum BodyState {
    Empty,
    Invalid,
    Fixed { remaining: u64 },
    Chunked(ChunkState),
}

impl BodyState {
    fn expects_data(&self) -> bool {
        matches!(self, Self::Fixed { remaining } if *remaining != 0) || matches!(self, Self::Chunked(_))
    }
}

struct ChunkState {
    phase: ChunkPhase,
}

#[derive(Clone, Copy)]
enum ChunkPhase {
    Size,
    Data(u64),
    DataCrlf,
    Trailers,
    Eof,
}

enum BodyFrame {
    Data(Bytes),
    Trailers(HeaderMap),
    Eof,
}
