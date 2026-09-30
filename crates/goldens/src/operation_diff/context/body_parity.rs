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

//! Harness for the signed and aws-chunked body parity diff: what each stack's PutObject handler is
//! handed when both receive the same signed raw upload (rustfs/backlog#1762, fourth slice).
//!
//! Responsible for: signing one PutObject once — in each of the five payload modes, optionally
//! tampered with after signing — splitting its wire body into the pieces a transport delivers,
//! and feeding the same pieces, through a counting source, to (a) an assembled gateway whose
//! handler drains `Req`'s body and (b) the s3s service with authentication configured, whose
//! handler drains the `StreamingBlob`; then recording, per stack, the bytes and `ContentLength`
//! the handler saw, the trailer fields as a RustFS `TrailerSource` would look them up, how the
//! body ended, the answer, and the connection verdict. Also (c) the RustFS adapter's path: a
//! gateway handler that converts through the seam and drains the converted body; and (d) the
//! RustFS profile's adapter path (rustfs/gateway#1148), which also hands the body a trailer handle
//! as the legacy stack attaches one, and records it as the legacy side records its own.
//! NOT responsible for: any assertion (`matrix`, `tamper`, `properties`, `divergences`), the
//! request context (the parent), or the input members (the decode diff).
//! Upstream: the parent (credential, owner source, authorizer, adapter context), the counting
//! source in `harness`, `compat::put_object`. Downstream: the four proofs beside it.
//!
//! # What each handler stands in for
//!
//! The gateway handler drains its body the way every gateway handler must: pull until end of body
//! or a stream error. A stream error hands the handler only `IncompleteBody`; the refusal the
//! gateway answers with is the body's own verdict, which the service substitutes for whatever the
//! handler returned (`request_body::VerifiedRequestBody`).
//!
//! The s3s handler stands in for a RustFS app body. s3s decodes the body itself but leaves the
//! answer to a body error to the implementation, so this one answers the code s3s names for it —
//! `AwsChunkedStreamError::to_s3_error_code` at 0.17.0, spelled out in [`oracle_code`] because the
//! baseline has no such method, and the AWS code for a payload digest mismatch, which s3s names
//! nowhere. The trailer fields are read from the s3s handle the way the RustFS A4 adapter reads
//! them (`rustfs/src/app/trailer_adapter.rs`, rustfs/backlog#1735): no handle, a handle not yet
//! filled (`Pending`), or the fields.

#[cfg(test)]
mod clock;
mod divergences;
mod matrix;
mod properties;
mod rustfs_profile;
mod tamper;
mod upload;

use std::future::poll_fn;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use bytes::Bytes;
use futures_core::Stream;
use http::{HeaderMap, Method};
use rustfs_gateway::dto;
use rustfs_gateway::{
    ConnectionIntent, Credentials, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, ServiceBuilder,
    SigV4Authenticator, StaticCredentials, connection_intent_of,
};
use rustfs_gateway_sig::{RegionSet, RequestNow, SecurityFloor};
use rustfs_gateway_stream::{ByteStream, PayloadRead, PayloadStream, StreamErrorKind};
use rustfs_gateway_types::ErrorCode;

use super::super::seam::put_object::input_to_s3s;
use super::super::seam::request_context::GatewayRequestContext;
use super::super::seam::trailers::{LegacyTrailers, legacy_checksum_algorithm};
use super::super::{BodyProbe, BodyReads, ProbeSource};
use super::adapter_request::{legacy_adapter_request, legacy_attaches_trailers};
use super::{ACCESS_KEY, AllowEveryStage, Answer, FixtureOwner, REGIONS, SECRET_KEY, adapter_request, block_on, oracle, s3s};
use upload::TARGET;
pub(crate) use upload::{Mode, TRAILER, Tamper, Upload, crc32_base64};

// ── what a handler saw ────────────────────────────────────────────────────────────────────────

/// Trailer fields as a RustFS `TrailerSource` finds them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Trailers {
    /// Nothing to look in: no handle was handed over, or no fields were delivered.
    Absent,
    /// A handle whose fields have not arrived.
    Pending,
    /// The fields, sorted by name.
    Fields(Vec<(String, String)>),
}

/// One `TrailerSource::lookup`, in rio's three states plus "no source".
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lookup {
    NoSource,
    Pending,
    Missing,
    Present(String),
}

impl Trailers {
    fn of(map: &HeaderMap) -> Self {
        let mut fields: Vec<(String, String)> = map
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), String::from_utf8_lossy(value.as_bytes()).into_owned()))
            .collect();
        fields.sort();
        Self::Fields(fields)
    }

    /// What rio's `lookup(name)` answers over this handle.
    pub(crate) fn lookup(&self, name: &str) -> Lookup {
        match self {
            Self::Absent => Lookup::NoSource,
            Self::Pending => Lookup::Pending,
            Self::Fields(fields) => fields
                .iter()
                .find(|(field, _)| field == name)
                .map_or(Lookup::Missing, |(_, value)| Lookup::Present(value.clone())),
        }
    }

    /// The field names delivered, sorted.
    pub(crate) fn names(&self) -> Vec<&str> {
        match self {
            Self::Fields(fields) => fields.iter().map(|(name, _)| name.as_str()).collect(),
            Self::Absent | Self::Pending => Vec::new(),
        }
    }
}

/// An upload input's checksum members as a RustFS body reads them: the algorithm, and the five
/// checksums it echoes by name (CRC32, CRC32C, SHA1, SHA256, CRC64NVME, in that order).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Checksums {
    pub(crate) algorithm: Option<String>,
    pub(crate) named: [Option<String>; 5],
}

impl Checksums {
    fn of(input: &oracle::PutObjectInput) -> Self {
        Self {
            algorithm: input
                .checksum_algorithm
                .as_ref()
                .map(|algorithm| algorithm.as_str().to_owned()),
            named: [
                input.checksum_crc32.clone(),
                input.checksum_crc32c.clone(),
                input.checksum_sha1.clone(),
                input.checksum_sha256.clone(),
                input.checksum_crc64nvme.clone(),
            ],
        }
    }
}

/// How a handler's body ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BodyEnd {
    Eof,
    /// The stream failed; the gateway's error kind, or the s3s stream error's variant.
    Failed(String),
}

/// What one handler saw of the body.
#[derive(Clone, Debug)]
pub(crate) struct HandlerView {
    pub(crate) content_length: Option<i64>,
    pub(crate) bytes: Vec<u8>,
    /// The trailer handle when the handler started, before any read.
    pub(crate) trailers_at_mount: Trailers,
    /// The trailer handle once the body ended.
    pub(crate) trailers: Trailers,
    pub(crate) end: BodyEnd,
    /// The input's checksum members, where the input is the legacy one (`None` on the gateway's own
    /// handler, whose input has no such spelling).
    pub(crate) checksums: Option<Checksums>,
}

/// What one stack did with the upload.
#[derive(Debug)]
pub(crate) struct Side {
    pub(crate) status: u16,
    pub(crate) code: Option<String>,
    /// `None` when the stack refused before its handler.
    pub(crate) handler: Option<HandlerView>,
    /// The gateway's connection verdict; `None` on s3s, which states none.
    pub(crate) closes: Option<bool>,
    /// Every read of the wire body.
    pub(crate) wire: BodyReads,
}

impl Side {
    /// The bytes the handler was handed, empty when it never ran.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.handler.as_ref().map_or(&[], |view| view.bytes.as_slice())
    }

    /// Whether the handler read the body to its end and the stack answered 200.
    pub(crate) fn accepted(&self) -> bool {
        self.status == 200 && self.ended() == Some(BodyEnd::Eof)
    }

    /// How the handler's body ended, when the handler ran.
    pub(crate) fn ended(&self) -> Option<BodyEnd> {
        self.handler.as_ref().map(|view| view.end.clone())
    }

    /// `(status, code)` of the answer.
    pub(crate) fn answer(&self) -> (u16, Option<&str>) {
        (self.status, self.code.as_deref())
    }

    /// The `ContentLength` the handler read.
    pub(crate) fn content_length(&self) -> Option<i64> {
        self.handler.as_ref().and_then(|view| view.content_length)
    }

    /// The declared trailer as rio would look it up once the body ended.
    pub(crate) fn trailer(&self) -> Lookup {
        self.handler
            .as_ref()
            .map_or(Lookup::NoSource, |view| view.trailers.lookup(TRAILER))
    }
}

fn record<T>(slot: &Mutex<Option<T>>, view: T) {
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(view);
    }
}

fn element(body: &[u8], name: &str) -> Option<String> {
    let body = String::from_utf8_lossy(body);
    let open = format!("<{name}>");
    let start = body.find(&open)? + open.len();
    let end = body.get(start..)?.find(&format!("</{name}>"))? + start;
    body.get(start..end).map(str::to_owned)
}

fn head(headers: &HeaderMap) -> http::request::Builder {
    let mut builder = http::Request::builder().method(Method::PUT).uri(TARGET);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
}

/// Drains an s3s body, on either side of the seam.
async fn drain_blob(body: Option<oracle::StreamingBlob>) -> (Vec<u8>, BodyEnd) {
    let mut bytes = Vec::new();
    let Some(mut blob) = body else {
        return (bytes, BodyEnd::Eof);
    };
    let end = poll_fn(|context| {
        loop {
            match Pin::new(&mut blob).poll_next(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => bytes.extend_from_slice(&chunk),
                Poll::Ready(Some(Err(error))) => return Poll::Ready(BodyEnd::Failed(variant(&*error))),
                Poll::Ready(None) => return Poll::Ready(BodyEnd::Eof),
            }
        }
    })
    .await;
    (bytes, end)
}

fn body_refusal() -> HandlerError {
    HandlerError::new(ErrorCode::INCOMPLETE_BODY, "the request body did not arrive as it was framed")
}

// ── the gateway side ──────────────────────────────────────────────────────────────────────────

struct GatewayBody {
    seen: Arc<Mutex<Option<HandlerView>>>,
}

impl Handler<dto::PutObject> for GatewayBody {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        let input = request.into_input();
        let mut bytes = Vec::new();
        let (end, trailers) = match input.body {
            None => (BodyEnd::Eof, Trailers::Absent),
            Some(mut stream) => {
                poll_fn(|context| {
                    loop {
                        match Pin::new(&mut stream).poll_read(context) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => bytes.extend_from_slice(&chunk),
                            Poll::Ready(Ok(PayloadRead::Eof { trailers })) => {
                                return Poll::Ready((BodyEnd::Eof, Trailers::of(trailers.as_header_map())));
                            }
                            Poll::Ready(Err(error)) => {
                                return Poll::Ready((BodyEnd::Failed(kind(error.kind())), Trailers::Absent));
                            }
                        }
                    }
                })
                .await
            }
        };
        let failed = end != BodyEnd::Eof;
        record(
            &self.seen,
            HandlerView {
                content_length: Some(input.content_length),
                bytes,
                // The gateway hands a handler no trailer handle: the fields arrive with end of body.
                trailers_at_mount: Trailers::Absent,
                trailers,
                end,
                checksums: None,
            },
        );
        if failed {
            return Err(body_refusal());
        }
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

fn kind(kind: &StreamErrorKind) -> String {
    match kind {
        StreamErrorKind::IncompleteBody => "IncompleteBody",
        StreamErrorKind::LengthMismatch { .. } => "LengthMismatch",
        StreamErrorKind::PolledAfterEof => "PolledAfterEof",
        StreamErrorKind::Io(_) => "Io",
        StreamErrorKind::Upstream(_) => "Upstream",
    }
    .to_owned()
}

/// What a RustFS app body behind the adapter sees: the context the seam builds and the body the
/// converted input carries.
#[derive(Debug)]
pub(crate) struct SeamView {
    /// `request_to_s3s` over the handler's context, or its refusal.
    pub(crate) context: Result<(), String>,
    pub(crate) content_length: Option<i64>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) end: BodyEnd,
}

/// The adapter's PutObject: convert through the seam, then drain the converted body.
struct SeamBody {
    seen: Arc<Mutex<Option<SeamView>>>,
}

impl Handler<dto::PutObject> for SeamBody {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        let context = adapter_request(request.context()).map(|_| ());
        let view = match input_to_s3s(request.into_input()) {
            Err(error) => SeamView {
                context,
                content_length: None,
                bytes: Vec::new(),
                end: BodyEnd::Failed(format!("input refused: {error}")),
            },
            Ok(input) => {
                let content_length = input.content_length;
                let (bytes, end) = drain_blob(input.body).await;
                SeamView {
                    context,
                    content_length,
                    bytes,
                    end,
                }
            }
        };
        let failed = view.end != BodyEnd::Eof;
        record(&self.seen, view);
        if failed {
            return Err(body_refusal());
        }
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

/// The assembled gateway over `backend`, handing the caller's secret to it as the adapter needs.
fn gateway_service<H>(backend: H, now: RequestNow) -> Result<S3Service, String>
where
    H: Handler<dto::PutObject> + Send + Sync + 'static,
{
    let credentials = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|error| format!("credential: {error:?}"))?;
    let regions = RegionSet::new(REGIONS).map_err(|error| format!("regions: {error:?}"))?;
    let authenticator =
        SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(credentials)), regions).hand_caller_secret_to_handlers();
    super::verifying_at(ServiceBuilder::new(), now)
        .authenticator(authenticator)
        .authorizer(AllowEveryStage)
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .bucket_owner_source(FixtureOwner)
        .register::<dto::PutObject, _>(Arc::new(backend))
        .hand_caller_secret_to_every_operation_after_listing_in_the_posture_report()
        .build()
        .map_err(|error| format!("assembly: {error:?}"))
}

/// Sends the pieces through `service`; the answer's status, code, verdict and wire reads.
fn gateway_answer(
    service: &S3Service,
    headers: &HeaderMap,
    pieces: Vec<Bytes>,
) -> Result<(u16, Option<String>, Option<bool>, BodyReads), String> {
    let probe = Arc::new(BodyProbe::default());
    let body = ByteStream::new(Box::pin(ProbeSource::from_pieces(pieces, Arc::clone(&probe))))
        .map_err(|error| format!("probe body: {error:?}"))?
        .into_body();
    let request = head(headers).body(body).map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call(request));
    let closes = connection_intent_of(&response).map(ConnectionIntent::must_close);
    let (parts, body) = response.into_parts();
    let body = block_on(http_body_util::BodyExt::collect(body))
        .map_err(|error| format!("gateway body: {error:?}"))?
        .to_bytes();
    Ok((parts.status.as_u16(), element(&body, "Code"), closes, probe.reads()))
}

fn gateway_side(headers: &HeaderMap, pieces: Vec<Bytes>, now: RequestNow) -> Result<Side, String> {
    let seen = Arc::new(Mutex::new(None));
    let service = gateway_service(GatewayBody { seen: Arc::clone(&seen) }, now)?;
    let (status, code, closes, wire) = gateway_answer(&service, headers, pieces)?;
    let handler = seen.lock().map_err(|_| "the recording slot is poisoned".to_owned())?.take();
    Ok(Side {
        status,
        code,
        handler,
        closes,
        wire,
    })
}

/// Sends `upload` through a gateway whose handler converts it the way the RustFS adapter does.
///
/// # Errors
///
/// A harness failure, or a refusal before the handler.
pub(crate) fn through_seam(upload: &Upload) -> Result<(u16, SeamView), String> {
    let now = RequestNow::capture();
    through_seam_at(upload, now, now)
}

/// [`through_seam`], signed at `signed` and verified by a gateway whose clock reads `verified`.
fn through_seam_at(upload: &Upload, signed: RequestNow, verified: RequestNow) -> Result<(u16, SeamView), String> {
    let wire = upload.wire(signed)?;
    let seen = Arc::new(Mutex::new(None));
    let service = gateway_service(SeamBody { seen: Arc::clone(&seen) }, verified)?;
    let (status, _, _, _) = gateway_answer(&service, &wire.headers, upload.split(&wire.body))?;
    let view = seen
        .lock()
        .map_err(|_| "the recording slot is poisoned".to_owned())?
        .take()
        .ok_or_else(|| format!("the gateway refused before its handler with status {status}"))?;
    Ok((status, view))
}

/// The RustFS profile's adapter PutObject (rustfs/gateway#1148): a trailer handle exactly where
/// the legacy stack attaches one, the context built with it, the input converted with the legacy
/// reading of its checksum algorithm and its body filling the handle, then the converted body
/// drained — recorded as the legacy side records its handler.
struct LegacySeamBody {
    seen: Arc<Mutex<Option<Result<HandlerView, String>>>>,
}

impl LegacySeamBody {
    async fn view(request: Req<dto::PutObject>) -> Result<HandlerView, String> {
        let trailers = legacy_attaches_trailers(request.context())?.then(LegacyTrailers::default);
        legacy_adapter_request(request.context(), trailers.clone())?;
        let headers = GatewayRequestContext::raw_headers(request.context().headers().iter_raw());
        let algorithm = legacy_checksum_algorithm(&headers).map_err(|error| format!("algorithm refused: {error}"))?;
        let mut input = request.into_input();
        if let Some(trailers) = &trailers {
            input.body = input.body.map(|body| trailers.publishing(body));
        }
        let mut input = input_to_s3s(input).map_err(|error| format!("input refused: {error}"))?;
        input.checksum_algorithm = algorithm;
        let handle = |trailers: &Option<LegacyTrailers>| match trailers {
            None => Trailers::Absent,
            Some(trailers) => trailers.read(Trailers::of).unwrap_or(Trailers::Pending),
        };
        let trailers_at_mount = handle(&trailers);
        let checksums = Checksums::of(&input);
        let content_length = input.content_length;
        let (bytes, end) = drain_blob(input.body).await;
        Ok(HandlerView {
            content_length,
            bytes,
            trailers_at_mount,
            trailers: handle(&trailers),
            end,
            checksums: Some(checksums),
        })
    }
}

impl Handler<dto::PutObject> for LegacySeamBody {
    async fn call(&self, request: Req<dto::PutObject>) -> HandlerResult<dto::PutObject> {
        let view = Self::view(request).await;
        let failed = !matches!(&view, Ok(view) if view.end == BodyEnd::Eof);
        record(&self.seen, view);
        if failed {
            return Err(body_refusal());
        }
        Ok(Resp::new(dto::PutObjectOutput::default()))
    }
}

/// Sends `upload` through a gateway whose handler converts it the way the RustFS profile's adapter
/// does (rustfs/gateway#1148), and the same signed pieces through the legacy service: the RustFS
/// body's view on each side, the first an `Err` naming what the seam refused.
///
/// # Errors
///
/// A harness failure, or a refusal before either handler.
pub(crate) fn through_legacy_seam(upload: &Upload) -> Result<(Result<HandlerView, String>, HandlerView), String> {
    let now = RequestNow::capture();
    let wire = upload.wire(now)?;
    let seen = Arc::new(Mutex::new(None));
    let service = gateway_service(LegacySeamBody { seen: Arc::clone(&seen) }, now)?;
    let (status, _, _, _) = gateway_answer(&service, &wire.headers, upload.split(&wire.body))?;
    let view = seen
        .lock()
        .map_err(|_| "the recording slot is poisoned".to_owned())?
        .take()
        .ok_or_else(|| format!("the gateway refused before its handler with status {status}"))?;
    let oracle = s3s_side(&wire.headers, upload.split(&wire.body))?;
    let oracle = oracle
        .handler
        .ok_or_else(|| format!("the legacy service refused before its handler with status {}", oracle.status))?;
    Ok((view, oracle))
}

// ── the s3s side ──────────────────────────────────────────────────────────────────────────────

struct OracleBody {
    seen: Arc<Mutex<Option<HandlerView>>>,
}

fn handle_state(handle: Option<&s3s::TrailingHeaders>) -> Trailers {
    match handle {
        None => Trailers::Absent,
        Some(handle) => handle.read(Trailers::of).unwrap_or(Trailers::Pending),
    }
}

/// The code a RustFS app body answers for an s3s body error, by the variant its `Display` spells:
/// `AwsChunkedStreamError::to_s3_error_code` at 0.17.0 (the baseline has the same variants but
/// `LengthMismatch`, and no mapping), and the AWS code for `UploadStreamError::Sha256Mismatch`,
/// for which s3s names none.
pub(crate) fn oracle_code(variant: &str) -> &'static str {
    match variant {
        "SignatureMismatch" => "SignatureDoesNotMatch",
        "Sha256Mismatch" => "XAmzContentSHA256Mismatch",
        "ChunkMetaTooLarge" | "ChunkDataTooLarge" => "EntityTooLarge",
        "FormatError" | "Incomplete" | "LengthMismatch" | "TrailersTooLarge" | "TooManyTrailerHeaders" => "IncompleteBody",
        _ => "InternalError",
    }
}

/// The variant of an s3s body error: `AwsChunkedStreamError: X` or `UploadStreamError: X`.
fn variant(error: &(dyn std::error::Error + Send + Sync)) -> String {
    let text = error.to_string();
    let rest = ["AwsChunkedStreamError: ", "UploadStreamError: "]
        .iter()
        .find_map(|prefix| text.strip_prefix(prefix));
    match rest {
        Some(rest) => rest.split(':').next().unwrap_or(rest).to_owned(),
        None => text,
    }
}

impl s3s::S3 for OracleBody {
    // The pinned trait is declared with `#[async_trait]`; this is the signature that attribute
    // expands a `&self` method to, spelled out as the parent does.
    fn put_object<'life0, 'future>(
        &'life0 self,
        request: s3s::S3Request<oracle::PutObjectInput>,
    ) -> Answer<'future, oracle::PutObjectOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        let seen = Arc::clone(&self.seen);
        Box::pin(async move {
            let handle = request.trailing_headers.clone();
            let trailers_at_mount = handle_state(handle.as_ref());
            let content_length = request.input.content_length;
            let checksums = Checksums::of(&request.input);
            let (bytes, end) = drain_blob(request.input.body).await;
            let answer = match &end {
                BodyEnd::Eof => Ok(s3s::S3Response::new(oracle::PutObjectOutput::default())),
                BodyEnd::Failed(variant) => {
                    let code = oracle_code(variant);
                    let code = s3s::S3ErrorCode::from_bytes(code.as_bytes()).unwrap_or(s3s::S3ErrorCode::InternalError);
                    Err(s3s::S3Error::with_message(code, "the request body stream failed"))
                }
            };
            record(
                &seen,
                HandlerView {
                    content_length,
                    bytes,
                    trailers_at_mount,
                    trailers: handle_state(handle.as_ref()),
                    end,
                    checksums: Some(checksums),
                },
            );
            answer
        })
    }
}

fn s3s_side(headers: &HeaderMap, pieces: Vec<Bytes>) -> Result<Side, String> {
    let seen = Arc::new(Mutex::new(None));
    let mut builder = s3s::service::S3ServiceBuilder::new(OracleBody { seen: Arc::clone(&seen) });
    builder.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
    let service = builder.build();
    let probe = Arc::new(BodyProbe::default());
    let source: s3s::stream::DynByteStream = Box::pin(ProbeSource::from_pieces(pieces, Arc::clone(&probe)));
    let request = head(headers)
        .body(s3s::Body::from(source))
        .map_err(|error| format!("fixture head: {error}"))?;
    let response = block_on(service.call(request)).map_err(|error| format!("s3s service failed: {error:?}"))?;
    let (parts, mut body) = response.into_parts();
    let body = block_on(body.store_all_limited(1 << 20)).map_err(|error| format!("s3s response body: {error}"))?;
    let handler = seen.lock().map_err(|_| "the recording slot is poisoned".to_owned())?.take();
    Ok(Side {
        status: parts.status.as_u16(),
        code: element(&body, "Code"),
        handler,
        closes: None,
        wire: probe.reads(),
    })
}

// ── both ──────────────────────────────────────────────────────────────────────────────────────

/// Both stacks' view of one upload.
#[derive(Debug)]
pub(crate) struct Pair {
    pub(crate) gateway: Side,
    pub(crate) oracle: Side,
    /// The wire body length both received.
    pub(crate) wire_length: u64,
}

/// Signs `upload` once and feeds the same pieces to both stacks.
///
/// # Errors
///
/// A harness failure; every refusal is a [`Side`].
pub(crate) fn both(upload: &Upload) -> Result<Pair, String> {
    let now = RequestNow::capture();
    let wire = upload.wire(now)?;
    let pieces = upload.split(&wire.body);
    Ok(Pair {
        gateway: gateway_side(&wire.headers, pieces.clone(), now)?,
        oracle: s3s_side(&wire.headers, pieces)?,
        wire_length: wire.body.len() as u64,
    })
}
