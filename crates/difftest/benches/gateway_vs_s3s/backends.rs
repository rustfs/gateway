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

//! Minimal in-memory benchmark backends and shared body type for `gateway_vs_s3s`.
//!
//! Responsible for: assembling identical `rustfs-gateway` and pinned `s3s` services backed by
//! zero-I/O handlers for `GetObject`, `PutObject`, `ListObjectsV2`, `DeleteObjects`, and
//! `PostObject`, plus the shared single-chunk body adapter.
//! NOT responsible for: request signing, timing, or allocation measurement (owned by
//! `benches/gateway_vs_s3s.rs`).
//! Upstream: `rustfs-gateway` and `rustfs-gateway-types`' `compat::s3s_0_17_0` seam.
//! Downstream: `benches/gateway_vs_s3s.rs`.

use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::hint::black_box;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_core::Stream;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use rustfs_gateway::dto::{
    self, DeleteObjects, DeleteObjectsOutput, DeletedObject, GetObject, GetObjectOutput, ListObjectsV2, ListObjectsV2Output,
    PostObject, PostObjectOutput, PutObject, PutObjectOutput,
};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Credentials, Decision, GovernorRates, Handler, HandlerError, HandlerResult,
    InputAuthzRequest, InputDecisions, Rate, Req, RequestContext, Resp, S3Service, ServiceBuilder, SigV4Authenticator,
    StaticCredentials, Unlimited,
};
use rustfs_gateway_sig::{RegionSet, SecurityFloor};
use rustfs_gateway_stream::{ByteStream, PayloadRead, PayloadStream};
use rustfs_gateway_types::compat::s3s_0_17_0::s3s;
use rustfs_gateway_types::{BucketName, ETag, ObjectKey, Timestamp};
use s3s::dto as oracle;

pub(super) const ACCESS_KEY: &str = "AKIDBENCHCOMPARE";
pub(super) const SECRET_KEY: &str = "bench-compare-secret-key";
pub(super) const REGION: &str = "us-east-1";
pub(super) const BUCKET: &str = "bench-bucket";
pub(super) const LIST_KEYS: usize = 100;

/// Single-chunk immutable body implementing both `http_body::Body` and `s3s::stream::ByteStream`.
pub(super) struct SingleChunkBody {
    chunk: Option<Bytes>,
    remaining: usize,
}

impl SingleChunkBody {
    pub(super) fn new(bytes: Bytes) -> Self {
        let remaining = bytes.len();
        let chunk = (!bytes.is_empty()).then_some(bytes);
        Self { chunk, remaining }
    }
}

impl Body for SingleChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let next = self.chunk.take().map(|bytes| {
            self.remaining = 0;
            Ok(Frame::data(bytes))
        });
        Poll::Ready(next)
    }

    fn is_end_stream(&self) -> bool {
        self.chunk.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining as u64)
    }
}

impl Stream for SingleChunkBody {
    type Item = Result<Bytes, s3s::StdError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = self.chunk.take().map(|bytes| {
            self.remaining = 0;
            Ok(bytes)
        });
        Poll::Ready(next)
    }
}

impl s3s::stream::ByteStream for SingleChunkBody {
    fn remaining_length(&self) -> s3s::stream::RemainingLength {
        s3s::stream::RemainingLength::new_exact(self.remaining)
    }
}

struct AllowAllAuthorizer;

impl Authorizer for AllowAllAuthorizer {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async { Decision::Allow })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// Shared no-op in-memory backend for `rustfs-gateway`.
pub(super) struct GatewayBackend {
    payload: Bytes,
    etag: ETag,
    bucket: BucketName,
    list_keys: Vec<ObjectKey>,
    list_etags: Vec<ETag>,
    pub(super) observed_bytes: AtomicUsize,
    pub(super) observed_deletes: AtomicUsize,
}

impl GatewayBackend {
    pub(super) fn new(payload: Bytes) -> Result<Self, Box<dyn Error>> {
        let etag = ETag::new("\"0123456789abcdef0123456789abcdef\"").map_err(|e| io::Error::other(format!("{e:?}")))?;
        let bucket = BucketName::new(BUCKET).map_err(|e| io::Error::other(format!("{e:?}")))?;
        let mut list_keys = Vec::with_capacity(LIST_KEYS);
        let mut list_etags = Vec::with_capacity(LIST_KEYS);
        for index in 0..LIST_KEYS {
            list_keys
                .push(ObjectKey::new(format!("photos/2026/09/{index:06}.jpg")).map_err(|e| io::Error::other(format!("{e:?}")))?);
            list_etags.push(ETag::new(format!("\"{index:032x}\"")).map_err(|e| io::Error::other(format!("{e:?}")))?);
        }
        Ok(Self {
            payload,
            etag,
            bucket,
            list_keys,
            list_etags,
            observed_bytes: AtomicUsize::new(0),
            observed_deletes: AtomicUsize::new(0),
        })
    }
}

async fn drain_gateway_stream(mut stream: ByteStream) -> Result<usize, HandlerError> {
    let mut total = 0usize;
    std::future::poll_fn(|cx| {
        loop {
            match Pin::new(&mut stream).poll_read(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(PayloadRead::Chunk(chunk))) => total += black_box(chunk.as_ref()).len(),
                Poll::Ready(Ok(PayloadRead::Eof { .. })) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(HandlerError::internal_error("benchmark gateway body failed")));
                }
            }
        }
    })
    .await?;
    Ok(total)
}

impl Handler<GetObject> for GatewayBackend {
    async fn call(&self, _request: Req<GetObject>) -> HandlerResult<GetObject> {
        let payload = self.payload.clone();
        Ok(Resp::new(GetObjectOutput {
            body: Some(ByteStream::from_bytes(payload)),
            content_length: Some(self.payload.len() as i64),
            content_type: Some("application/octet-stream".to_owned()),
            e_tag: Some(self.etag.clone()),
            last_modified: Some(Timestamp::from_secs(1_767_225_600)),
            ..GetObjectOutput::default()
        }))
    }
}

impl Handler<PutObject> for GatewayBackend {
    async fn call(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        let total = match request.into_input().body {
            Some(stream) => drain_gateway_stream(stream).await?,
            None => 0,
        };
        self.observed_bytes.store(total, Ordering::Relaxed);
        Ok(Resp::new(PutObjectOutput {
            e_tag: self.etag.clone(),
            ..PutObjectOutput::default()
        }))
    }
}

impl Handler<ListObjectsV2> for GatewayBackend {
    async fn call(&self, _request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        let contents = (0..LIST_KEYS)
            .map(|index| dto::Object {
                key: self.list_keys[index].clone(),
                last_modified: Timestamp::from_secs(1_767_225_600 + index as i64),
                e_tag: Some(self.list_etags[index].clone()),
                size: 4096 + index as i64,
                ..dto::Object::default()
            })
            .collect();
        Ok(Resp::new(ListObjectsV2Output {
            name: self.bucket.clone(),
            prefix: "photos/2026/".to_owned(),
            max_keys: LIST_KEYS as i32,
            key_count: LIST_KEYS as i32,
            is_truncated: false,
            contents,
            ..ListObjectsV2Output::default()
        }))
    }
}

impl Handler<DeleteObjects> for GatewayBackend {
    async fn call(&self, request: Req<DeleteObjects>) -> HandlerResult<DeleteObjects> {
        let objects = request
            .resources()
            .resolve_objects(request.read_proof())
            .ok_or_else(|| HandlerError::internal_error("benchmark delete proof missing"))?;
        self.observed_deletes.store(objects.len(), Ordering::Relaxed);
        let deleted = objects
            .map(|item| DeletedObject {
                key: item.key.object_key().cloned(),
                ..DeletedObject::default()
            })
            .collect();
        Ok(Resp::new(DeleteObjectsOutput {
            deleted,
            ..DeleteObjectsOutput::default()
        }))
    }
}

impl Handler<PostObject> for GatewayBackend {
    async fn call(&self, request: Req<PostObject>) -> HandlerResult<PostObject> {
        let mut body = request.into_input().body.into_body();
        let mut total = 0usize;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| HandlerError::internal_error("benchmark post body failed"))?;
            if let Ok(bytes) = frame.into_data() {
                total += black_box(bytes.as_ref()).len();
            }
        }
        self.observed_bytes.store(total, Ordering::Relaxed);
        Ok(Resp::new(PostObjectOutput {
            e_tag: Some(self.etag.clone()),
            version_id: None,
        }))
    }
}

struct AllowAllS3Access;

impl s3s::access::S3Access for AllowAllS3Access {
    fn check<'life0, 'life1, 'life2, 'future>(
        &'life0 self,
        _cx: &'life1 mut s3s::access::S3AccessContext<'life2>,
    ) -> Pin<Box<dyn Future<Output = s3s::S3Result<()>> + Send + 'future>>
    where
        'life0: 'future,
        'life1: 'future,
        'life2: 'future,
        Self: 'future,
    {
        Box::pin(async { Ok(()) })
    }
}

/// Minimal no-op in-memory backend for pinned `s3s`.
pub(super) struct S3sBackend {
    payload: Bytes,
    etag: oracle::ETag,
    list_keys: Vec<String>,
    list_etags: Vec<oracle::ETag>,
    observed_bytes: Arc<AtomicUsize>,
    observed_deletes: Arc<AtomicUsize>,
}

impl S3sBackend {
    pub(super) fn new(payload: Bytes, observed_bytes: Arc<AtomicUsize>, observed_deletes: Arc<AtomicUsize>) -> Self {
        let etag = oracle::ETag::Strong("0123456789abcdef0123456789abcdef".to_owned());
        let mut list_keys = Vec::with_capacity(LIST_KEYS);
        let mut list_etags = Vec::with_capacity(LIST_KEYS);
        for index in 0..LIST_KEYS {
            list_keys.push(format!("photos/2026/09/{index:06}.jpg"));
            list_etags.push(oracle::ETag::Strong(format!("{index:032x}")));
        }
        Self {
            payload,
            etag,
            list_keys,
            list_etags,
            observed_bytes,
            observed_deletes,
        }
    }
}

async fn drain_s3s_blob(mut blob: oracle::StreamingBlob) -> s3s::S3Result<usize> {
    let mut total = 0usize;
    std::future::poll_fn(|cx| {
        loop {
            match Pin::new(&mut blob).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(chunk))) => total += black_box(chunk.as_ref()).len(),
                Poll::Ready(Some(Err(_))) => {
                    return Poll::Ready(Err(s3s::S3Error::with_message(
                        s3s::S3ErrorCode::InternalError,
                        "benchmark s3s body failed",
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
            }
        }
    })
    .await?;
    Ok(total)
}

fn s3s_timestamp(secs: i64) -> oracle::Timestamp {
    let instant =
        time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or_else(|_| unreachable!("benchmark Unix timestamp is in range"));
    oracle::Timestamp::from(instant)
}

type S3sFuture<'a, T> = Pin<Box<dyn Future<Output = s3s::S3Result<s3s::S3Response<T>>> + Send + 'a>>;

impl s3s::S3 for S3sBackend {
    fn get_object<'life0, 'future>(
        &'life0 self,
        _req: s3s::S3Request<oracle::GetObjectInput>,
    ) -> S3sFuture<'future, oracle::GetObjectOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        let payload = self.payload.clone();
        let etag = self.etag.clone();
        Box::pin(async move {
            let len = payload.len() as i64;
            let stream: s3s::stream::DynByteStream = Box::pin(SingleChunkBody::new(payload));
            Ok(s3s::S3Response::new(oracle::GetObjectOutput {
                body: Some(oracle::StreamingBlob::from(stream)),
                content_length: Some(len),
                content_type: Some("application/octet-stream".to_owned()),
                e_tag: Some(etag),
                last_modified: Some(s3s_timestamp(1_767_225_600)),
                ..oracle::GetObjectOutput::default()
            }))
        })
    }

    fn put_object<'life0, 'future>(
        &'life0 self,
        req: s3s::S3Request<oracle::PutObjectInput>,
    ) -> S3sFuture<'future, oracle::PutObjectOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let total = match req.input.body {
                Some(blob) => drain_s3s_blob(blob).await?,
                None => 0,
            };
            self.observed_bytes.store(total, Ordering::Relaxed);
            Ok(s3s::S3Response::new(oracle::PutObjectOutput {
                e_tag: Some(self.etag.clone()),
                ..oracle::PutObjectOutput::default()
            }))
        })
    }

    fn list_objects_v2<'life0, 'future>(
        &'life0 self,
        _req: s3s::S3Request<oracle::ListObjectsV2Input>,
    ) -> S3sFuture<'future, oracle::ListObjectsV2Output>
    where
        'life0: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let contents = (0..LIST_KEYS)
                .map(|index| oracle::Object {
                    key: Some(self.list_keys[index].clone()),
                    last_modified: Some(s3s_timestamp(1_767_225_600 + index as i64)),
                    e_tag: Some(self.list_etags[index].clone()),
                    size: Some(4096 + index as i64),
                    ..oracle::Object::default()
                })
                .collect();
            Ok(s3s::S3Response::new(oracle::ListObjectsV2Output {
                name: Some(BUCKET.to_owned()),
                prefix: Some("photos/2026/".to_owned()),
                max_keys: Some(LIST_KEYS as i32),
                key_count: Some(LIST_KEYS as i32),
                is_truncated: Some(false),
                contents: Some(contents),
                ..oracle::ListObjectsV2Output::default()
            }))
        })
    }

    fn delete_objects<'life0, 'future>(
        &'life0 self,
        req: s3s::S3Request<oracle::DeleteObjectsInput>,
    ) -> S3sFuture<'future, oracle::DeleteObjectsOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let objects = req.input.delete.objects;
            self.observed_deletes.store(objects.len(), Ordering::Relaxed);
            let deleted = objects
                .into_iter()
                .map(|item| oracle::DeletedObject {
                    key: Some(item.key),
                    ..oracle::DeletedObject::default()
                })
                .collect();
            Ok(s3s::S3Response::new(oracle::DeleteObjectsOutput {
                deleted: Some(deleted),
                ..oracle::DeleteObjectsOutput::default()
            }))
        })
    }

    fn post_object<'life0, 'future>(
        &'life0 self,
        req: s3s::S3Request<oracle::PostObjectInput>,
    ) -> S3sFuture<'future, oracle::PostObjectOutput>
    where
        'life0: 'future,
        Self: 'future,
    {
        Box::pin(async move {
            let total = match req.input.body {
                Some(blob) => drain_s3s_blob(blob).await?,
                None => 0,
            };
            self.observed_bytes.store(total, Ordering::Relaxed);
            Ok(s3s::S3Response::new(oracle::PostObjectOutput {
                e_tag: Some(self.etag.clone()),
                ..oracle::PostObjectOutput::default()
            }))
        })
    }
}

pub(super) fn build_gateway(backend: &Arc<GatewayBackend>) -> Result<S3Service, Box<dyn Error>> {
    let creds = Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let regions = RegionSet::new([REGION]).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let authenticator = SigV4Authenticator::new(Arc::new(StaticCredentials::new().with(creds)), regions);
    let unlimited = Rate::unlimited();
    let service = ServiceBuilder::new()
        .framework_governor_rates(GovernorRates {
            aggregate: unlimited,
            per_ip: unlimited,
            credential_lookup: unlimited,
            cors_preflight: unlimited,
            unauthenticated: unlimited,
            tracked_clients: 1,
        })
        .governor(Unlimited)
        .authenticator(authenticator)
        .authorizer(AllowAllAuthorizer)
        .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
        .register::<GetObject, _>(Arc::clone(backend))
        .register::<PutObject, _>(Arc::clone(backend))
        .register::<ListObjectsV2, _>(Arc::clone(backend))
        .register::<DeleteObjects, _>(Arc::clone(backend))
        .register::<PostObject, _>(Arc::clone(backend))
        .build()
        .map_err(|e| io::Error::other(format!("gateway assembly failed: {e:?}")))?;
    Ok(service)
}

pub(super) fn build_s3s(backend: S3sBackend) -> s3s::service::S3Service {
    let mut builder = s3s::service::S3ServiceBuilder::new(backend);
    builder.set_auth(s3s::auth::SimpleAuth::from_single(ACCESS_KEY, SECRET_KEY));
    builder.set_access(AllowAllS3Access);
    builder.build()
}
