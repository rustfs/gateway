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

//! Harness for the single-operation decode/encode diff against the s3s revision of the enclosing
//! compilation (`super::s3s`; see `operation_diff.rs`).
//!
//! Responsible for: sending one raw request through the real gateway route table and generated
//! codec and, separately, through that revision's s3s service; returning both decoded inputs and both
//! encoded responses in a comparable form; and counting every read of either copy of the body.
//! NOT responsible for: authentication or request context (`uri`, headers, extensions, credentials,
//! region), which the `context` submodule drives separately; RustFS storage; or production
//! wiring. This module only exists under `cfg(test)` (rustfs/backlog#1762).
//! Upstream: `rustfs-gateway-core` routing and codecs, the seam revision bound in `super`.
//! Downstream: the per-operation proofs beside it.
//!
//! # Why the s3s side runs the whole service
//!
//! The pinned s3s keeps its per-operation decoders private, so the only honest way to ask "what
//! does s3s decode from these bytes" is the path RustFS runs today: `S3Service::call` with an `S3`
//! implementation that records the input it was handed. No authentication is configured on either
//! side, so the requests are anonymous and nothing here depends on a signature.

use std::collections::{BTreeMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;

use super::s3s;
use bytes::Bytes;
use futures_core::Stream;
use rustfs_gateway_core::codec::{MetaView, OperationCodec, RequestBody, ResponseBody};
use rustfs_gateway_core::route::{HostClass, RouteRequestParts, RouteTable, SHADOWING, TargetKind, generated_entries};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_stream::{ByteStream, PayloadCaps, PayloadRead, PayloadStream, StreamError, TrailingHeaders};
use s3s::dto as oracle;
use s3s::stream::ByteStream as _;

/// The authority every fixture request is addressed to. Path-style, so the bucket is in the path.
pub(crate) const HOST: &str = "host.invalid";

/// One raw request, exactly as both stacks receive it.
#[derive(Clone, Debug)]
pub(crate) struct RawRequest {
    /// Path and query, starting at `/`.
    pub(crate) target: String,
    /// Header lines in order; a name may repeat.
    pub(crate) headers: Vec<(String, String)>,
    /// The body, split the way the transport delivers it. Empty chunks are dropped: a producer
    /// never emits one, because it is indistinguishable from progress.
    pub(crate) chunks: Vec<Bytes>,
    /// Trailer fields the body ends with, which only the gateway-side source can carry.
    pub(crate) trailers: Vec<(String, String)>,
    /// Fail the gateway-side source after the first chunk instead of ending it.
    pub(crate) fail_after_first_chunk: bool,
}

impl RawRequest {
    /// A `PUT` of `body` to `target`, delivered in `chunk`-sized pieces.
    pub(crate) fn put(target: &str, body: &[u8], chunk: usize) -> Self {
        let chunks = body.chunks(chunk.max(1)).map(Bytes::copy_from_slice).collect::<Vec<_>>();
        Self {
            target: target.to_owned(),
            headers: vec![("content-length".to_owned(), body.len().to_string())],
            chunks,
            trailers: Vec::new(),
            fail_after_first_chunk: false,
        }
    }

    /// The body bytes, joined.
    pub(crate) fn body(&self) -> Vec<u8> {
        self.chunks.iter().flat_map(|chunk| chunk.iter().copied()).collect()
    }

    /// Adds a header line.
    pub(crate) fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Removes every line of one header.
    pub(crate) fn without(mut self, name: &str) -> Self {
        self.headers.retain(|(present, _)| !present.eq_ignore_ascii_case(name));
        self
    }

    /// Replaces every line of one header with a single line.
    pub(crate) fn replace(self, name: &str, value: &str) -> Self {
        self.without(name).with(name, value)
    }

    fn http_head(&self) -> http::request::Builder {
        let mut builder = http::Request::builder()
            .method("PUT")
            .uri(format!("http://{HOST}{}", self.target))
            .header("host", HOST);
        for (name, value) in &self.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        builder
    }
}

// ── observing the body ────────────────────────────────────────────────────────────────────────

/// Every read one copy of the body saw.
#[derive(Debug, Default)]
pub(crate) struct BodyProbe {
    polls: AtomicUsize,
    delivered: AtomicU64,
    eof: AtomicUsize,
    polled_after_eof: AtomicUsize,
}

/// A snapshot of a [`BodyProbe`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BodyReads {
    /// Calls into the source, whatever they returned.
    pub(crate) polls: usize,
    /// Body bytes handed out.
    pub(crate) delivered: u64,
    /// End-of-body events handed out.
    pub(crate) eof: usize,
    /// Calls made after the end had already been handed out.
    pub(crate) polled_after_eof: usize,
}

impl BodyProbe {
    pub(crate) fn reads(&self) -> BodyReads {
        BodyReads {
            polls: self.polls.load(Ordering::SeqCst),
            delivered: self.delivered.load(Ordering::SeqCst),
            eof: self.eof.load(Ordering::SeqCst),
            polled_after_eof: self.polled_after_eof.load(Ordering::SeqCst),
        }
    }
}

/// The request body source both stacks read from, counting every read.
///
/// It is the transport's side of the body: whatever a stack does — stream it, buffer it, read it
/// twice — shows up here and nowhere else, which is what makes "the body was not read before the
/// handler" an observation rather than a claim about code.
struct ProbeSource {
    chunks: VecDeque<Bytes>,
    remaining: u64,
    trailers: Option<TrailingHeaders>,
    fail_after_first_chunk: bool,
    ended: bool,
    probe: Arc<BodyProbe>,
}

enum SourceEvent {
    Chunk(Bytes),
    End(TrailingHeaders),
    Fail,
    AfterEnd,
}

impl ProbeSource {
    fn new(request: &RawRequest, trailers: TrailingHeaders, probe: Arc<BodyProbe>) -> Self {
        let chunks: VecDeque<Bytes> = request.chunks.iter().filter(|chunk| !chunk.is_empty()).cloned().collect();
        let remaining = chunks.iter().map(|chunk| chunk.len() as u64).sum();
        Self {
            chunks,
            remaining,
            trailers: Some(trailers),
            fail_after_first_chunk: request.fail_after_first_chunk,
            ended: false,
            probe,
        }
    }

    fn next_event(&mut self) -> SourceEvent {
        self.probe.polls.fetch_add(1, Ordering::SeqCst);
        if self.ended {
            self.probe.polled_after_eof.fetch_add(1, Ordering::SeqCst);
            return SourceEvent::AfterEnd;
        }
        if self.fail_after_first_chunk && self.probe.delivered.load(Ordering::SeqCst) > 0 {
            self.ended = true;
            return SourceEvent::Fail;
        }
        match self.chunks.pop_front() {
            Some(chunk) => {
                self.remaining -= chunk.len() as u64;
                self.probe.delivered.fetch_add(chunk.len() as u64, Ordering::SeqCst);
                SourceEvent::Chunk(chunk)
            }
            None => {
                self.ended = true;
                self.probe.eof.fetch_add(1, Ordering::SeqCst);
                SourceEvent::End(self.trailers.take().unwrap_or_else(TrailingHeaders::empty))
            }
        }
    }
}

impl PayloadStream for ProbeSource {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<PayloadRead, StreamError>> {
        Poll::Ready(match self.get_mut().next_event() {
            SourceEvent::Chunk(chunk) => Ok(PayloadRead::Chunk(chunk)),
            SourceEvent::End(trailers) => Ok(PayloadRead::Eof { trailers }),
            SourceEvent::Fail => Err(StreamError::incomplete_body()),
            SourceEvent::AfterEnd => Err(StreamError::polled_after_eof()),
        })
    }

    fn caps(&self) -> PayloadCaps {
        PayloadCaps::PUSH | PayloadCaps::KNOWN_LENGTH
    }

    fn len_hint(&self) -> Option<u64> {
        Some(self.remaining)
    }
}

impl Stream for ProbeSource {
    type Item = Result<Bytes, s3s::StdError>;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(match self.get_mut().next_event() {
            SourceEvent::Chunk(chunk) => Some(Ok(chunk)),
            SourceEvent::End(_) | SourceEvent::AfterEnd => None,
            SourceEvent::Fail => Some(Err(Box::new(StreamError::incomplete_body()))),
        })
    }
}

impl s3s::stream::ByteStream for ProbeSource {
    fn remaining_length(&self) -> s3s::stream::RemainingLength {
        usize::try_from(self.remaining)
            .map_or_else(|_| s3s::stream::RemainingLength::unknown(), s3s::stream::RemainingLength::new_exact)
    }
}

/// Drains a converted or oracle-decoded body to the end, as a handler that stores it would.
pub(crate) fn drain(mut blob: oracle::StreamingBlob) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    block_on(poll_fn(|cx| {
        loop {
            match Pin::new(&mut blob).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => out.extend_from_slice(&chunk),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error.to_string())),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }))?;
    Ok(out)
}

/// The exact remaining length a body announces to the handler, if it announces one.
pub(crate) fn announced_length(blob: &oracle::StreamingBlob) -> Option<usize> {
    blob.remaining_length().exact()
}

// ── the gateway side ──────────────────────────────────────────────────────────────────────────

fn route_table() -> &'static RouteTable {
    static TABLE: OnceLock<RouteTable> = OnceLock::new();
    TABLE.get_or_init(|| {
        let entries = generated_entries().expect("the generated route rows parse");
        RouteTable::build(entries, &SHADOWING).expect("the generated route table builds under its shipped policy")
    })
}

fn gateway_wire(request: &RawRequest) -> Result<WireRequest<()>, String> {
    let head = request
        .http_head()
        .body(())
        .map_err(|error| format!("fixture head: {error}"))?;
    WireRequest::accept(head, &Limits::default()).map_err(|error| format!("wire refusal: {error:?}"))
}

/// Routes and decodes `request` exactly as the gateway pipeline does, handing the decoder a live
/// body that `probe` observes.
///
/// # Errors
///
/// The wire refusal, the operation a wrong route reached, or the codec's error code.
pub(crate) fn gateway_decode(
    request: &RawRequest,
    probe: &Arc<BodyProbe>,
) -> Result<rustfs_gateway_types::dto::PutObjectInput, String> {
    let wire = gateway_wire(request)?;
    let parts = RouteRequestParts {
        method: wire.method(),
        path: wire.raw_path().as_str(),
        target: TargetKind::Object,
        host_class: HostClass::Standard,
        arn_form: None,
        query: wire.query(),
        headers: wire.headers(),
    };
    match route_table().resolve(&parts).map(|entry| entry.op_name) {
        Some("PutObject") => {}
        other => return Err(format!("routed to {other:?}, not PutObject")),
    }
    let view = MetaView::of(&wire, TargetKind::Object).map_err(|error| error.code().as_str().to_owned())?;
    let stream = probe_stream(request, probe)?;
    rustfs_gateway_types::dto::PutObject::decode(&view, RequestBody::Stream(stream))
        .map_err(|error| error.code().as_str().to_owned())
}

/// Routes `request` through a router with the MinIO replication dialect installed — the RustFS
/// profile of rd-put-0007 — and decodes it with the replica codec, handing the decoder a live body
/// that `probe` observes.
///
/// # Errors
///
/// The wire refusal, the operation a wrong route reached, or the codec's error code.
pub(crate) fn gateway_decode_replica(
    request: &RawRequest,
    probe: &Arc<BodyProbe>,
) -> Result<rustfs_gateway_dialect_minio::PutObjectReplicaInput, String> {
    use rustfs_gateway_dialect_minio::{PutObjectReplica, replication, replication_dialect};

    let wire = gateway_wire(request)?;
    let parts = RouteRequestParts {
        method: wire.method(),
        path: wire.raw_path().as_str(),
        target: TargetKind::Object,
        host_class: HostClass::Standard,
        arn_form: None,
        query: wire.query(),
        headers: wire.headers(),
    };
    let dialect = replication_dialect().map_err(|errors| format!("the dialect was refused: {errors:?}"))?;
    let router = rustfs_gateway_core::registry::RouterBuilder::new()
        .dialect(&dialect)
        .build()
        .map_err(|error| format!("the router was refused: {error:?}"))?;
    match router.resolve(&parts).map(|entry| entry.op_name) {
        Some(replication::NAME) => {}
        other => return Err(format!("routed to {other:?}, not {}", replication::NAME)),
    }
    let view = MetaView::of(&wire, TargetKind::Object).map_err(|error| error.code().as_str().to_owned())?;
    let stream = probe_stream(request, probe)?;
    PutObjectReplica::decode(&view, RequestBody::Stream(stream)).map_err(|error| error.code().as_str().to_owned())
}

/// The fixture body as the live gateway stream, with its trailers, observed by `probe`.
fn probe_stream(request: &RawRequest, probe: &Arc<BodyProbe>) -> Result<ByteStream, String> {
    let mut trailers = http::HeaderMap::new();
    for (name, value) in &request.trailers {
        let name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|error| error.to_string())?;
        let value = http::HeaderValue::from_str(value).map_err(|error| error.to_string())?;
        trailers.append(name, value);
    }
    let source = ProbeSource::new(request, TrailingHeaders::from_header_map(trailers), Arc::clone(probe));
    ByteStream::new(Box::pin(source)).map_err(|error| error.to_string())
}

/// Encodes `output` exactly as the gateway pipeline does, as the answer to `request`.
///
/// # Errors
///
/// The wire refusal of the fixture, or the codec's error code.
pub(crate) fn gateway_encode(
    request: &RawRequest,
    output: rustfs_gateway_types::dto::PutObjectOutput,
) -> Result<WireAnswer, String> {
    let wire = gateway_wire(request)?;
    let view = MetaView::of(&wire, TargetKind::Object).map_err(|error| error.code().as_str().to_owned())?;
    let encoded =
        rustfs_gateway_types::dto::PutObject::encode(output, &view, 200).map_err(|error| error.code().as_str().to_owned())?;
    let body = match encoded.body {
        ResponseBody::Empty => Vec::new(),
        ResponseBody::Complete(bytes) => bytes,
        ResponseBody::Stream(_) => return Err("PutObject answered with a streaming body".to_owned()),
    };
    Ok(WireAnswer {
        status: encoded.status.as_u16(),
        headers: header_lines(&encoded.headers),
        body,
    })
}

// ── the s3s side ──────────────────────────────────────────────────────────────────────────────

/// Status, header lines and body bytes of one response: the only comparable form of an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WireAnswer {
    pub(crate) status: u16,
    /// Lowercase name to every value line, in arrival order.
    pub(crate) headers: BTreeMap<String, Vec<Vec<u8>>>,
    pub(crate) body: Vec<u8>,
}

impl WireAnswer {
    /// The `<Code>` of an S3 error document, when the body is one.
    pub(crate) fn error_code(&self) -> Option<String> {
        let text = std::str::from_utf8(&self.body).ok()?;
        let start = text.find("<Code>")? + "<Code>".len();
        let end = text[start..].find("</Code>")? + start;
        Some(text[start..end].to_owned())
    }
}

fn header_lines(headers: &http::HeaderMap) -> BTreeMap<String, Vec<Vec<u8>>> {
    let mut lines: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    for (name, value) in headers {
        lines
            .entry(name.as_str().to_owned())
            .or_default()
            .push(value.as_bytes().to_vec());
    }
    lines
}

/// What the pinned s3s service did with one request.
pub(crate) struct OracleExchange {
    /// The input its `put_object` handler was handed, or `None` when it refused first.
    pub(crate) input: Option<oracle::PutObjectInput>,
    /// The response it wrote.
    pub(crate) answer: WireAnswer,
}

/// An s3s backend with exactly one handler, which records its input and answers `output`.
struct RecordingS3 {
    captured: Arc<Mutex<Option<oracle::PutObjectInput>>>,
    output: oracle::PutObjectOutput,
}

impl s3s::S3 for RecordingS3 {
    // The pinned trait is declared with `#[async_trait]`; this is the signature that attribute
    // expands a `&self` method to, spelled out so the harness needs no proc-macro dependency.
    fn put_object<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::PutObjectInput>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<oracle::PutObjectOutput>>> + Send + 'future>>
    where
        'life0: 'future,
        Self: 'future,
    {
        let captured = Arc::clone(&self.captured);
        let output = self.output.clone();
        Box::pin(async move {
            if let Ok(mut slot) = captured.lock() {
                *slot = Some(request.input);
            }
            Ok(s3s::S3Response::new(output))
        })
    }
}

/// Sends `request` through the pinned s3s service, whose `put_object` answers `output`, handing
/// it a live body that `probe` observes.
///
/// # Errors
///
/// A harness failure — never a refusal, which comes back as an [`OracleExchange`] with no input.
pub(crate) fn s3s_exchange(
    request: &RawRequest,
    probe: &Arc<BodyProbe>,
    output: oracle::PutObjectOutput,
) -> Result<OracleExchange, String> {
    let captured = Arc::new(Mutex::new(None));
    let service = s3s::service::S3ServiceBuilder::new(RecordingS3 {
        captured: Arc::clone(&captured),
        output,
    })
    .build();
    let source: s3s::stream::DynByteStream = Box::pin(ProbeSource::new(request, TrailingHeaders::empty(), Arc::clone(probe)));
    let http_request = request
        .http_head()
        .body(s3s::Body::from(source))
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call(http_request)).map_err(|error| format!("s3s service failed: {error:?}"))?;
    let (parts, mut body) = response.into_parts();
    let body = block_on(body.store_all_limited(1 << 20)).map_err(|error| format!("s3s response body: {error}"))?;
    let input = captured
        .lock()
        .map_err(|_| "the recording slot is poisoned".to_owned())?
        .take();
    Ok(OracleExchange {
        input,
        answer: WireAnswer {
            status: parts.status.as_u16(),
            headers: header_lines(&parts.headers),
            body: body.to_vec(),
        },
    })
}

// ── an executor ───────────────────────────────────────────────────────────────────────────────

struct ParkSignal {
    thread: thread::Thread,
    woken: AtomicBool,
}

impl Wake for ParkSignal {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

/// Runs a future to completion on this thread. The workspace carries no runtime on purpose; both
/// services under test complete without one, and a hang here is a service that never answered.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    let signal = Arc::new(ParkSignal {
        thread: thread::current(),
        woken: AtomicBool::new(false),
    });
    let waker = Waker::from(Arc::clone(&signal));
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => return value,
            Poll::Pending => {
                while !signal.woken.swap(false, Ordering::Acquire) {
                    thread::park();
                }
            }
        }
    }
}
