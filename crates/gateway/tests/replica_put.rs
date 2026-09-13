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

//! Who may choose a version id: `?versionId=` on a PUT through the assembled public service.
//!
//! Responsible for: proving at the wire that the query reaches a handler only through the
//! replication dialect (`minio:PutObjectReplica`) and only for a caller holding both
//! `s3:ReplicateObject` and `s3:PutObject` on the key, and that an assembly without the dialect
//! treats the query as it always did (rustfs/gateway#752).
//! NOT responsible for: the codec or the routing matrix (`rustfs-gateway-dialect-minio`'s tests),
//! or the agreement with s3s (`rd-put-0007` in the goldens register).
//! Upstream: `rustfs-gateway` and `rustfs-gateway-dialect-minio`. Downstream: nothing.

use crate::support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use rustfs_gateway::{Authorizer, ETag, Handler, HandlerError, HandlerResult, Req, Resp, S3Service, allow_when, dto};
use rustfs_gateway_dialect_minio::{PutObjectReplica, replication_dialect};

const TARGET: &str = "/photos/a.png";
const VERSION: &str = "0190b7a1-6d4e-7c3a-9f00-0123456789ab";
const BODY: &[u8] = b"hello";

/// A backend that records which write it was handed and the version id a replica carried.
#[derive(Default)]
struct Backend {
    plain: AtomicUsize,
    replicas: Mutex<Vec<String>>,
}

impl Backend {
    fn plain(&self) -> usize {
        self.plain.load(Ordering::SeqCst)
    }

    fn replicas(&self) -> Vec<String> {
        self.replicas.lock().expect("uncontended").clone()
    }

    fn plain_write(&self, request: Req<dto::PutObject>) -> impl Future<Output = HandlerResult<dto::PutObject>> + Send + use<> {
        self.plain.fetch_add(1, Ordering::SeqCst);
        let body = request.into_input().body;
        async move {
            drain(body).await?;
            Ok(Resp::new(stored(None)))
        }
    }

    fn replica_write(
        &self,
        request: Req<PutObjectReplica>,
    ) -> impl Future<Output = HandlerResult<PutObjectReplica>> + Send + use<> {
        let input = request.into_input();
        self.replicas.lock().expect("uncontended").push(input.version_id.clone());
        async move {
            drain(input.object.body).await?;
            Ok(Resp::new(stored(Some(input.version_id))))
        }
    }
}

fn stored(version_id: Option<String>) -> dto::PutObjectOutput {
    dto::PutObjectOutput {
        e_tag: ETag::new("5d41402abc4b2a76b9719d911017c592").expect("a well-formed tag"),
        version_id,
        ..Default::default()
    }
}

async fn drain(body: Option<rustfs_gateway::ByteStream>) -> Result<(), HandlerError> {
    let mut body = body
        .ok_or_else(|| HandlerError::internal_error("a write reached its handler without a body stream"))?
        .into_body();
    while let Some(frame) = body.frame().await {
        frame.map_err(|_| HandlerError::internal_error("the request body stream failed"))?;
    }
    Ok(())
}

impl Handler<dto::PutObject> for Backend {
    fn call(&self, request: Req<dto::PutObject>) -> impl Future<Output = HandlerResult<dto::PutObject>> + Send {
        self.plain_write(request)
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl Future<Output = HandlerResult<dto::PutObject>> + Send {
        self.plain_write(request)
    }
}

impl Handler<PutObjectReplica> for Backend {
    fn call(&self, request: Req<PutObjectReplica>) -> impl Future<Output = HandlerResult<PutObjectReplica>> + Send {
        self.replica_write(request)
    }

    fn call_with_context(
        &self,
        request: Req<PutObjectReplica>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl Future<Output = HandlerResult<PutObjectReplica>> + Send {
        self.replica_write(request)
    }
}

/// The signed-time fixture assembly with `authorizer`, and the replication dialect when asked.
fn service(installed: bool, authorizer: impl Authorizer) -> (S3Service, Arc<Backend>) {
    let backend = Arc::new(Backend::default());
    let mut builder = support::wired_at_signed_time()
        .authorizer(authorizer)
        .register::<dto::PutObject, _>(Arc::clone(&backend));
    if installed {
        builder = builder
            .register::<PutObjectReplica, _>(Arc::clone(&backend))
            .dialect(&replication_dialect().expect("the dialect assembles"));
    }
    (builder.build().expect("a complete assembly"), backend)
}

/// The status, the `x-amz-version-id` answered, and the body of one signed PUT to `target`.
async fn put(service: &S3Service, target: &str) -> (http::StatusCode, Option<String>, String) {
    let request = support::signed_target_with_body_and_headers(
        http::Method::PUT,
        target,
        &[("content-length", "5")],
        Bytes::from_static(BODY),
    );
    let response = service.call_bytes(request).await;
    let collected = rustfs_gateway::collect(response).await.expect("an in-memory body");
    let version = collected
        .headers()
        .iter()
        .find(|(name, _)| name.as_str() == "x-amz-version-id")
        .and_then(|(_, value)| value.to_str().ok())
        .map(str::to_owned);
    let body = String::from_utf8(collected.body().to_vec()).expect("utf-8");
    (collected.status(), version, body)
}

fn versioned(query: &str) -> String {
    format!("{TARGET}?{query}versionId={VERSION}")
}

/// Positive — a caller holding both actions writes under the version id it names.
#[tokio::test]
async fn a_replication_caller_writes_under_the_version_id_it_names() {
    let (service, backend) = service(true, allow_when(|_| true));
    let (status, version, body) = put(&service, &versioned("")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(version.as_deref(), Some(VERSION));
    assert_eq!(backend.replicas(), [VERSION]);
    assert_eq!(backend.plain(), 0);
}

/// Negative — an ordinary writer, holding `s3:PutObject` and nothing else, cannot choose a version
/// id: refused before any handler, and not quietly turned into an ordinary write either.
#[tokio::test]
async fn n_an_ordinary_writer_cannot_choose_a_version_id() {
    let (service, backend) = service(true, allow_when(|request| request.action == "s3:PutObject"));
    let (status, version, body) = put(&service, &versioned("")).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert_eq!(version, None);
    assert!(backend.replicas().is_empty());
    assert_eq!(backend.plain(), 0);
}

/// Negative — replication is not a licence to write: without `s3:PutObject` on the key the
/// replica write is refused as well.
#[tokio::test]
async fn n_a_replicator_without_put_object_on_the_key_is_refused() {
    let (service, backend) = service(true, allow_when(|request| request.action != "s3:PutObject"));
    let (status, _, body) = put(&service, &versioned("")).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert!(backend.replicas().is_empty());
}

/// Negative — the dialect is off by default: without it the query is ignored exactly as before,
/// the write is an ordinary one, and no version id the client named is answered.
#[tokio::test]
async fn n_without_the_dialect_a_version_id_on_a_put_is_ignored() {
    let (service, backend) = service(false, allow_when(|_| true));
    let (status, version, body) = put(&service, &versioned("")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(version, None);
    assert_eq!(backend.plain(), 1);
    assert!(backend.replicas().is_empty());
}

/// Negative — installing the dialect leaves a write that names no version alone.
#[tokio::test]
async fn n_with_the_dialect_a_put_naming_no_version_is_an_ordinary_write() {
    let (service, backend) = service(true, allow_when(|_| true));
    let (status, _, body) = put(&service, TARGET).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(backend.plain(), 1);
    assert!(backend.replicas().is_empty());
}

/// Negative — a sub-resource PUT naming a version keeps its own operation: here `PutObjectTagging`,
/// which this assembly does not implement, so the answer is `501` and no write handler runs.
#[tokio::test]
async fn n_a_tagging_put_naming_a_version_is_not_a_replica_write() {
    let (service, backend) = service(true, allow_when(|_| true));
    let (status, _, body) = put(&service, &versioned("tagging&")).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED, "{body}");
    assert!(backend.replicas().is_empty());
    assert_eq!(backend.plain(), 0);
}
