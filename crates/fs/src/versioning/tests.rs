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

//! The version lock, proven from the writer's side.
//!
//! Responsible for: the one test that needs the crate's private lock — holding it as a write in
//! flight would and proving the current-record enumeration waits rather than reads past it.
//! NOT responsible for: the versioning behaviour reachable through the wire, which
//! `tests/crud/versioning.rs` covers.
//! Upstream: `super`. Downstream: nothing.

#![allow(clippy::expect_used)]

use super::*;
use rustfs_gateway::{BucketName, Handler, Req, dto};

fn backend_with_bucket(tag: &str) -> (std::path::PathBuf, std::sync::Arc<FsBackend>) {
    let root = std::env::temp_dir().join(format!("rustfs-gateway-fs-versioning-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("a test root");
    let backend = FsBackend::open(&root).expect("a usable test root");
    for directory in [
        super::super::OBJECTS_DIR,
        super::super::UPLOADS_DIR,
        super::super::VERSIONS_DIR,
    ] {
        std::fs::create_dir_all(backend.bucket_path("racing").join(directory)).expect("a bucket layout");
    }
    (root, std::sync::Arc::new(backend))
}

/// Negative — the current-record enumeration waits for the version lock instead of reading
/// past it. A `.tmp-*` directory exists only while `publish_version` holds the lock, and
/// `version_records` refuses one as corruption, so an enumeration that did not take the lock
/// answered `500` for a write in flight. Here the test is the writer: it holds the lock with the
/// temporary directory in place, proves the enumeration has not answered, then finishes the
/// write — and the enumeration answers the healthy listing.
#[tokio::test]
async fn n_the_current_record_enumeration_waits_for_a_write_in_flight() {
    let (root, backend) = backend_with_bucket("waits");
    let temporary = backend.versions_path("racing").join(".tmp-1-1");
    let guard = backend.version_lock.lock().await;
    std::fs::create_dir(&temporary).expect("the temporary directory of a write in flight");

    let listing = tokio::spawn({
        let backend = std::sync::Arc::clone(&backend);
        async move { backend.current_object_records("racing").await.map(|records| records.len()) }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!listing.is_finished(), "the enumeration answered while the write held the lock");

    std::fs::remove_dir(&temporary).expect("the write finishes");
    drop(guard);
    let records = listing.await.expect("the enumeration does not panic");
    assert_eq!(records.map_err(|error| error.code().clone()), Ok(0));
    let _ = std::fs::remove_dir_all(root);
}

fn sse_proof() -> rustfs_gateway::SseEnforced {
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/")
        .header("host", "s3.example.com")
        .body(bytes::Bytes::new())
        .expect("a valid proof fixture");
    let wire = rustfs_gateway::WireRequest::accept(request, &rustfs_gateway::Limits::default()).expect("an accepted fixture");
    let meta = rustfs_gateway::MetaView::of(&wire, rustfs_gateway::TargetKind::Service).expect("a service fixture");
    rustfs_gateway::enforce_sse(&meta, rustfs_gateway::TransportSecurity::Encrypted, &rustfs_gateway::SseConfig::strict())
        .expect("an empty encrypted request passes SSE enforcement")
}

/// Negative — `DeleteBucket` waits for a write in flight instead of racing it. Without the lock a
/// version published between the emptiness check and the removal of `versions/` left `objects/`
/// gone and `versions/` not, and every later request on the bucket — a retry included — was
/// `500`. Here the test holds the lock as the writer would: the delete has not answered while it
/// is held, and answers `204` once the (empty) bucket is released to it.
#[tokio::test]
async fn n_delete_bucket_waits_for_a_write_in_flight() {
    let (root, backend) = backend_with_bucket("delete-waits");
    let guard = backend.version_lock.lock().await;
    let delete = tokio::spawn({
        let backend = std::sync::Arc::clone(&backend);
        async move {
            let input = dto::DeleteBucketInput {
                bucket: BucketName::new("racing").expect("a valid bucket"),
                ..dto::DeleteBucketInput::default()
            };
            Handler::<dto::DeleteBucket>::call(backend.as_ref(), Req::new(input, sse_proof()))
                .await
                .map(|response| response.status())
        }
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!delete.is_finished(), "the delete answered while the write held the lock");
    drop(guard);
    let status = delete.await.expect("the delete does not panic");
    assert_eq!(status.map_err(|error| error.code().clone()), Ok(204));
    assert!(!backend.bucket_path("racing").exists(), "the bucket is gone once the delete ran");
    let _ = std::fs::remove_dir_all(root);
}
