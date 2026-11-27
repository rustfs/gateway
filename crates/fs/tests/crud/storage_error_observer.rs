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

//! Isolated child-process integration test for the process-wide `set_storage_error_observer` hook
//! in `rustfs-gateway-fs` (rustfs/gateway#1083).
//!
//! Responsible for: spawning `std::env::current_exe()` for the single child probe so concurrent
//! negative tests inside `tests/crud.rs` cannot interfere with the process-wide `OnceLock`, proving
//! one-time install semantics, proving healthy CRUD operations emit zero observer notifications
//! (catching eager `storage_error()` construction), and proving a real internal storage error
//! notifies the observer with a `crates/fs/src/` call site.
//! NOT responsible for: log formatting (`rustfs-gateway-compat-sut`) or Mint report aggregation
//! (`ci/mint/report.py`).
//! Upstream: `rustfs_gateway_fs::{FsBackend, set_storage_error_observer}`. Downstream: nothing.

use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rustfs_gateway::dto::{
    CreateBucket, CreateBucketInput, DeleteBucket, DeleteBucketInput, DeleteObject, DeleteObjectInput, GetObject, GetObjectInput,
    HeadBucket, HeadBucketInput, PutObject, PutObjectInput,
};
use rustfs_gateway::{BucketName, ByteStream, ErrorCode, Handler, ObjectKey, Req};
use rustfs_gateway_fs::{FsBackend, set_storage_error_observer};

const CHILD_ENV: &str = "RUSTFS_FS_STORAGE_ERROR_OBSERVER_CHILD";

static GLOBAL_LOCATIONS: Mutex<Vec<(&'static str, u32)>> = Mutex::new(Vec::new());
static SECOND_CALLS: AtomicUsize = AtomicUsize::new(0);

fn record_global(location: &'static core::panic::Location<'static>) {
    GLOBAL_LOCATIONS
        .lock()
        .expect("not poisoned")
        .push((location.file(), location.line()));
}

fn record_second(_location: &'static core::panic::Location<'static>) {
    SECOND_CALLS.fetch_add(1, Ordering::Relaxed);
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

/// Runs the process-wide `set_storage_error_observer` assertions inside an isolated child process
/// of this test binary so concurrent `tests/crud.rs` cases cannot race on the global `OnceLock`.
#[test]
fn set_storage_error_observer_installs_once_and_fires_only_on_failure() {
    let exe = std::env::current_exe().expect("current test executable");
    let output = Command::new(exe)
        .arg("--exact")
        .arg("storage_error_observer::isolated_child_probe")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn isolated child probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "isolated observer child probe failed ({}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status
    );
    assert!(
        stdout.contains("1 passed; 0 failed"),
        "expected isolated child probe to execute 1 test:\n{stdout}"
    );
}

/// Child-process entry point invoked by [`set_storage_error_observer_installs_once_and_fires_only_on_failure`].
/// Returns immediately when run outside the child environment so it never mutates the parent
/// process's global `OnceLock`.
#[tokio::test]
async fn isolated_child_probe() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }

    assert!(set_storage_error_observer(record_global));
    assert!(!set_storage_error_observer(record_second));

    let root = std::env::temp_dir().join(format!("fs-storage-err-obs-child-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).expect("temp root");
    let backend = FsBackend::open(&root).expect("open backend");

    let bucket = BucketName::new("obs-bucket".to_owned()).expect("bucket");
    let key = ObjectKey::new("k".to_owned()).expect("key");
    Handler::<CreateBucket>::call(
        &backend,
        Req::new(
            CreateBucketInput {
                bucket: bucket.clone(),
                ..CreateBucketInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect("create bucket");
    Handler::<HeadBucket>::call(
        &backend,
        Req::new(
            HeadBucketInput {
                bucket: bucket.clone(),
                ..HeadBucketInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect("head bucket");
    Handler::<PutObject>::call(
        &backend,
        Req::new(
            PutObjectInput {
                bucket: bucket.clone(),
                key: key.clone(),
                body: Some(ByteStream::from_bytes(bytes::Bytes::from_static(b"ok"))),
                ..PutObjectInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect("healthy put");
    Handler::<GetObject>::call(
        &backend,
        Req::new(
            GetObjectInput {
                bucket: bucket.clone(),
                key: key.clone(),
                ..GetObjectInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect("healthy get");
    Handler::<DeleteObject>::call(
        &backend,
        Req::new(
            DeleteObjectInput {
                bucket: bucket.clone(),
                key: key.clone(),
                ..DeleteObjectInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect("healthy delete");
    Handler::<DeleteBucket>::call(
        &backend,
        Req::new(
            DeleteBucketInput {
                bucket: bucket.clone(),
                ..DeleteBucketInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect("healthy delete bucket");

    // Negative: healthy operations must never trigger the observer (catches eager evaluation).
    assert!(
        GLOBAL_LOCATIONS.lock().expect("not poisoned").is_empty(),
        "healthy operations must not notify storage_error observer"
    );
    assert_eq!(SECOND_CALLS.load(Ordering::Relaxed), 0);

    // Positive: recreate the bucket, remove its internal `objects/` subdir, and verify `PutObject`
    // returns `InternalError` and notifies the observer with `crates/fs/src/lib.rs`.
    Handler::<CreateBucket>::call(
        &backend,
        Req::new(
            CreateBucketInput {
                bucket: bucket.clone(),
                ..CreateBucketInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect("recreate bucket");
    let bucket_dir = std::fs::read_dir(&root)
        .expect("read root")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("b-"))
        })
        .expect("bucket dir");
    std::fs::remove_dir_all(bucket_dir.join("objects")).expect("remove objects dir");
    let err = Handler::<PutObject>::call(
        &backend,
        Req::new(
            PutObjectInput {
                bucket,
                key,
                body: Some(ByteStream::from_bytes(bytes::Bytes::from_static(b"fail"))),
                ..PutObjectInput::default()
            },
            sse_proof(),
        ),
    )
    .await
    .expect_err("broken bucket must fail with InternalError");
    assert_eq!(*err.code(), ErrorCode::INTERNAL_ERROR);
    let seen = GLOBAL_LOCATIONS.lock().expect("not poisoned").clone();
    assert!(!seen.is_empty(), "expected storage_error observer to fire on broken bucket");
    assert!(seen.iter().all(|(file, _)| file.ends_with("crates/fs/src/lib.rs")), "{seen:?}");
    assert_eq!(SECOND_CALLS.load(Ordering::Relaxed), 0);

    let _ = std::fs::remove_dir_all(&root);
}
