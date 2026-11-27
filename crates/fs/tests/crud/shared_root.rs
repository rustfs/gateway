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

//! Cross-process shared-root coordination controls for `rustfs-gateway-fs`.
//!
//! Responsible for: real separate-process exclusion over `<root>/.version-lock` across explicit
//! version deletion, null replacement, bulk deletion, and lifecycle expiration; fail-closed
//! malformed lock paths; independent-root progress; post-release liveness; and retained Object
//! Lock `501` refusals.
//! NOT responsible for: in-process unit mechanics (`src/versioning/tests.rs`) or Object Lock API
//! implementation (`#1512`).
//! Upstream: `tests/crud/versioning.rs` and `rustfs_gateway_fs::FsBackend`. Downstream: the crate
//! verification gate.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use md5::{Digest as _, Md5};

use super::*;

fn content_md5_header(body: &[u8]) -> http::HeaderValue {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digest = Md5::digest(body);
    let mut encoded = String::new();
    for chunk in digest.chunks(3) {
        let triple = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (index, byte)| acc | (u32::from(*byte) << (16 - 8 * index)));
        for index in 0..4 {
            if index <= chunk.len() {
                encoded.push(char::from(ALPHABET[((triple >> (18 - 6 * index)) & 0x3f) as usize]));
            } else {
                encoded.push('=');
            }
        }
    }
    http::HeaderValue::from_str(&encoded).expect("valid content-md5 header")
}

const PROBE_ACTION_ENV: &str = "RUSTFS_FS_SHARED_ROOT_PROBE_ACTION";
const PROBE_ROOT_ENV: &str = "RUSTFS_FS_SHARED_ROOT_PROBE_ROOT";
const PROBE_BUCKET_ENV: &str = "RUSTFS_FS_SHARED_ROOT_PROBE_BUCKET";
const PROBE_KEY_ENV: &str = "RUSTFS_FS_SHARED_ROOT_PROBE_KEY";
const PROBE_VERSION_ENV: &str = "RUSTFS_FS_SHARED_ROOT_PROBE_VERSION";
const PROBE_READY_ENV: &str = "RUSTFS_FS_SHARED_ROOT_PROBE_READY";
const PROBE_RESULT_ENV: &str = "RUSTFS_FS_SHARED_ROOT_PROBE_RESULT";

fn lock_file_path(root: &Path) -> PathBuf {
    root.join(".version-lock")
}

fn bucket_versions_dir(root: &Path, bucket: &str) -> PathBuf {
    root.join(format!("b-{}", hex::encode(bucket.as_bytes()))).join("versions")
}

fn find_single_version_dir(root: &Path, bucket: &str) -> PathBuf {
    let entries: Vec<PathBuf> = std::fs::read_dir(bucket_versions_dir(root, bucket))
        .expect("read versions dir")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("v-")))
        .collect();
    assert_eq!(entries.len(), 1, "expected exactly one version dir, found {entries:?}");
    entries.into_iter().next().expect("single version dir")
}

fn append_legal_hold(version_dir: &Path) {
    let record_path = version_dir.join("record");
    let mut text = std::fs::read_to_string(&record_path).expect("read version record");
    text.push_str("lock/1 1\nNONE - ON\n");
    std::fs::write(&record_path, text).expect("append legal hold protection");
}

fn open_and_lock_sentinel(root: &Path) -> std::fs::File {
    let path = lock_file_path(root);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("open shared-root lock sentinel");
    file.lock().expect("acquire OS exclusive lock on .version-lock");
    file
}

async fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("timed out waiting for marker file {}", path.display());
}

fn spawn_child_probe(
    action: &str,
    root: &Path,
    bucket: &str,
    key: &str,
    version_id: Option<&str>,
    ready_file: &Path,
    result_file: &Path,
) -> std::process::Child {
    let exe = std::env::current_exe().expect("current test executable");
    let mut cmd = Command::new(exe);
    cmd.arg("--exact")
        .arg("versioning::shared_root::shared_root_child_process_probe")
        .arg("--nocapture")
        .env(PROBE_ACTION_ENV, action)
        .env(PROBE_ROOT_ENV, root)
        .env(PROBE_BUCKET_ENV, bucket)
        .env(PROBE_KEY_ENV, key)
        .env(PROBE_READY_ENV, ready_file)
        .env(PROBE_RESULT_ENV, result_file);
    if let Some(version_id) = version_id {
        cmd.env(PROBE_VERSION_ENV, version_id);
    } else {
        cmd.env_remove(PROBE_VERSION_ENV);
    }
    cmd.spawn().expect("spawn child probe process")
}

/// Child-process entry point executed by the cross-process shared-root tests below.
/// When invoked normally by `cargo test` without `RUSTFS_FS_SHARED_ROOT_PROBE_ACTION`, it returns
/// immediately so no external side effects occur.
#[tokio::test]
async fn shared_root_child_process_probe() {
    let Ok(action) = std::env::var(PROBE_ACTION_ENV) else {
        return;
    };
    let root = PathBuf::from(std::env::var(PROBE_ROOT_ENV).expect("probe root"));
    let bucket = std::env::var(PROBE_BUCKET_ENV).expect("probe bucket");
    let key = std::env::var(PROBE_KEY_ENV).expect("probe key");
    let version = std::env::var(PROBE_VERSION_ENV).ok();
    let ready_file = PathBuf::from(std::env::var(PROBE_READY_ENV).expect("ready file"));
    let result_file = PathBuf::from(std::env::var(PROBE_RESULT_ENV).expect("result file"));

    let clock_secs = if action == "lifecycle_expire" {
        SIGNED_AT_SECONDS + 10 * 86_400
    } else {
        SIGNED_AT_SECONDS
    };
    let backend = Arc::new(
        FsBackend::open_with_clock(&root, Arc::new(FixedClock::at_unix_seconds(clock_secs))).expect("child open shared root"),
    );
    let (_, service) = service_with_backend(Arc::clone(&backend));

    std::fs::write(&ready_file, b"ready").expect("signal ready");

    let summary = match action.as_str() {
        "delete_version" => {
            let target = match version.as_deref() {
                Some(vid) => format!("/{bucket}/{key}?versionId={vid}"),
                None => format!("/{bucket}/{key}"),
            };
            let resp = exchange(&service, signed(http::Method::DELETE, &target, Bytes::new())).await;
            format!("{}:{}", resp.status().as_u16(), String::from_utf8_lossy(resp.body()))
        }
        "put_null" => {
            let target = format!("/{bucket}/{key}");
            let resp = exchange(&service, signed(http::Method::PUT, &target, Bytes::from_static(b"child-overwrite"))).await;
            format!("{}:{}", resp.status().as_u16(), String::from_utf8_lossy(resp.body()))
        }
        "bulk_delete" => {
            let xml = format!(
                "<Delete><Object><Key>{key}</Key>{}</Object></Delete>",
                version
                    .as_deref()
                    .map(|vid| format!("<VersionId>{vid}</VersionId>"))
                    .unwrap_or_default()
            );
            let body = Bytes::from(xml);
            let mut headers = http::HeaderMap::new();
            headers.insert(http::HeaderName::from_static("content-md5"), content_md5_header(&body));
            let target = format!("/{bucket}?delete");
            let resp = exchange(&service, signed_with_headers(http::Method::POST, &target, body, headers)).await;
            format!("{}:{}", resp.status().as_u16(), String::from_utf8_lossy(resp.body()))
        }
        "lifecycle_expire" => match backend.expire_lifecycle_once().await {
            Ok(count) => format!("ok:{count}"),
            Err(err) => format!("err:{}", err.code()),
        },
        other => panic!("unknown probe action: {other}"),
    };
    std::fs::write(&result_file, summary.as_bytes()).expect("write probe result");
}

/// Negative — a real child process deleting a named version must block on `<root>/.version-lock`
/// while the parent installs protection, and then observe `403 AccessDenied` after release.
#[tokio::test]
async fn n_cross_process_delete_waits_for_shared_root_lock_and_observes_protection() {
    let root = TestRoot::new();
    let control = TestRoot::new();
    let (_, service) = service(&root);

    create_bucket(&service, "shared").await;
    assert_eq!(set_versioning(&service, "shared", "Enabled").await.status(), 200);
    let put = exchange(&service, signed(http::Method::PUT, "/shared/k", Bytes::from_static(b"v1-data"))).await;
    assert_eq!(put.status(), 200);
    let version_id = put
        .headers()
        .iter()
        .find(|(name, _)| name.as_str().eq_ignore_ascii_case("x-amz-version-id"))
        .map(|(_, value)| value.to_str().expect("utf-8 version id").to_owned())
        .expect("version id header");
    let version_dir = find_single_version_dir(&root.0, "shared");

    let lock_guard = open_and_lock_sentinel(&root.0);
    let ready = control.0.join("ready");
    let result = control.0.join("result");
    let mut child = spawn_child_probe("delete_version", &root.0, "shared", "k", Some(&version_id), &ready, &result);

    wait_for_file(&ready, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        !result.exists(),
        "child process completed delete while parent held shared-root .version-lock"
    );
    assert!(version_dir.join("body").exists(), "child deleted bytes while lock was held");

    append_legal_hold(&version_dir);
    drop(lock_guard);

    let status = child.wait().expect("wait for child");
    assert!(status.success(), "child probe exited with {status}");
    let outcome = std::fs::read_to_string(&result).expect("read child result");
    assert!(
        outcome.starts_with("403:") && outcome.contains("<Code>AccessDenied</Code>"),
        "expected 403 AccessDenied after protection update, got: {outcome}"
    );
    assert!(version_dir.join("body").exists(), "protected version bytes must survive");
}

/// Negative — cross-process null replacement (`PutObject`) and bulk deletion (`DeleteObjects`)
/// must obey the same `<root>/.version-lock` boundary.
#[tokio::test]
async fn n_cross_process_null_replacement_and_bulk_delete_obey_shared_root_lock() {
    let root = TestRoot::new();
    let control = TestRoot::new();
    let (_, service) = service(&root);

    create_bucket(&service, "shared-null").await;
    assert_eq!(
        exchange(
            &service,
            signed(http::Method::PUT, "/shared-null/k", Bytes::from_static(b"original-null")),
        )
        .await
        .status(),
        200
    );
    let version_dir = find_single_version_dir(&root.0, "shared-null");

    // 1. Cross-process PutObject null replacement blocks until protection is installed.
    let lock_guard = open_and_lock_sentinel(&root.0);
    let ready_put = control.0.join("ready-put");
    let result_put = control.0.join("result-put");
    let mut child_put = spawn_child_probe("put_null", &root.0, "shared-null", "k", None, &ready_put, &result_put);
    wait_for_file(&ready_put, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!result_put.exists(), "child PutObject bypassed held .version-lock");
    append_legal_hold(&version_dir);
    drop(lock_guard);

    assert!(child_put.wait().expect("wait child_put").success());
    let put_outcome = std::fs::read_to_string(&result_put).expect("put outcome");
    assert!(
        put_outcome.starts_with("403:") && put_outcome.contains("<Code>AccessDenied</Code>"),
        "expected 403 AccessDenied on protected null replacement, got: {put_outcome}"
    );
    assert_eq!(std::fs::read(version_dir.join("body")).expect("body"), b"original-null");

    // 2. Cross-process DeleteObjects bulk deletion blocks on .version-lock and refuses protected null.
    let lock_guard = open_and_lock_sentinel(&root.0);
    let ready_bulk = control.0.join("ready-bulk");
    let result_bulk = control.0.join("result-bulk");
    let mut child_bulk = spawn_child_probe("bulk_delete", &root.0, "shared-null", "k", Some("null"), &ready_bulk, &result_bulk);
    wait_for_file(&ready_bulk, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!result_bulk.exists(), "child DeleteObjects bypassed held .version-lock");
    drop(lock_guard);

    assert!(child_bulk.wait().expect("wait child_bulk").success());
    let bulk_outcome = std::fs::read_to_string(&result_bulk).expect("bulk outcome");
    assert!(
        bulk_outcome.starts_with("200:") && bulk_outcome.contains("<Code>AccessDenied</Code>"),
        "expected DeleteObjects per-key AccessDenied error, got: {bulk_outcome}"
    );
    assert_eq!(std::fs::read(version_dir.join("body")).expect("body"), b"original-null");
}

/// Negative — cross-process lifecycle expiration must obey `<root>/.version-lock` and retain a
/// version whose protection is installed before the lock is released.
#[tokio::test]
async fn n_cross_process_lifecycle_expiration_obeys_shared_root_lock() {
    let root = TestRoot::new();
    let control = TestRoot::new();
    let (_, service) = service(&root);

    create_bucket(&service, "shared-lc").await;
    assert_eq!(
        exchange(&service, signed(http::Method::PUT, "/shared-lc/k", Bytes::from_static(b"expiring")),)
            .await
            .status(),
        200
    );
    let lifecycle_xml = Bytes::from_static(
        b"<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ID>r1</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
    );
    let mut headers = http::HeaderMap::new();
    headers.insert(http::HeaderName::from_static("content-md5"), content_md5_header(&lifecycle_xml));
    assert_eq!(
        exchange(
            &service,
            signed_with_headers(http::Method::PUT, "/shared-lc?lifecycle", lifecycle_xml, headers),
        )
        .await
        .status(),
        200
    );
    let version_dir = find_single_version_dir(&root.0, "shared-lc");

    let lock_guard = open_and_lock_sentinel(&root.0);
    let ready = control.0.join("ready-lc");
    let result = control.0.join("result-lc");
    let mut child = spawn_child_probe("lifecycle_expire", &root.0, "shared-lc", "k", None, &ready, &result);
    wait_for_file(&ready, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!result.exists(), "child lifecycle sweep bypassed held .version-lock");
    append_legal_hold(&version_dir);
    drop(lock_guard);

    assert!(child.wait().expect("wait child lifecycle").success());
    let outcome = std::fs::read_to_string(&result).expect("lifecycle outcome");
    assert_eq!(outcome, "err:AccessDenied", "protected null expiration must refuse removal");
    assert!(version_dir.join("body").exists(), "protected bytes must remain after lifecycle sweep");
}

/// Negative — malformed coordination state (a directory or symlink at `<root>/.version-lock`) must
/// fail closed with `400 InvalidRequest` and never modify a symlink target.
#[tokio::test]
async fn n_malformed_version_lock_symlink_and_directory_fail_closed() {
    // 1. Directory at .version-lock fails closed.
    let dir_root = TestRoot::new();
    let (_, dir_service) = service(&dir_root);
    create_bucket(&dir_service, "bkt").await;
    let lock_path = lock_file_path(&dir_root.0);
    let _ = std::fs::remove_file(&lock_path);
    std::fs::create_dir(&lock_path).expect("replace sentinel with directory");

    let put = exchange(&dir_service, signed(http::Method::PUT, "/bkt/obj", Bytes::from_static(b"data"))).await;
    assert_eq!(put.status(), 400, "directory at .version-lock must fail closed with 400");
    assert!(String::from_utf8_lossy(put.body()).contains("<Code>InvalidRequest</Code>"));

    let list_buckets = exchange(&dir_service, signed(http::Method::GET, "/", Bytes::new())).await;
    assert_eq!(list_buckets.status(), 400, "ListBuckets must reject directory .version-lock");

    // 2. Symlink at .version-lock fails closed without touching victim.
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let link_root = TestRoot::new();
        let outside = TestRoot::new();
        let victim = outside.0.join("victim.txt");
        std::fs::write(&victim, b"untouched").expect("victim file");

        let (_, link_service) = service(&link_root);
        create_bucket(&link_service, "bkt").await;
        let sentinel = lock_file_path(&link_root.0);
        let _ = std::fs::remove_file(&sentinel);
        symlink(&victim, &sentinel).expect("install symlink sentinel");

        let put = exchange(&link_service, signed(http::Method::PUT, "/bkt/obj", Bytes::from_static(b"data"))).await;
        assert_eq!(put.status(), 400, "symlink at .version-lock must fail closed with 400");
        assert!(String::from_utf8_lossy(put.body()).contains("<Code>InvalidRequest</Code>"));
        assert_eq!(std::fs::read(&victim).expect("victim intact"), b"untouched");

        let list_buckets = exchange(&link_service, signed(http::Method::GET, "/", Bytes::new())).await;
        assert_eq!(list_buckets.status(), 400, "ListBuckets must reject symlink .version-lock");
    }
}

/// Positive — another canonical root remains completely independent while one root's lock is held,
/// an unlocked version is deleted cleanly by a second process after lock release, `ListBuckets`
/// tolerates the regular `.version-lock` sentinel, and Object Lock refusals stay `501`.
#[tokio::test]
async fn independent_roots_and_post_release_cross_process_delete_succeed_while_object_lock_stays_501() {
    let root_a = TestRoot::new();
    let root_b = TestRoot::new();
    let control = TestRoot::new();
    let (_, service_a) = service(&root_a);
    let (_, service_b) = service(&root_b);

    create_bucket(&service_a, "alpha").await;
    create_bucket(&service_b, "beta").await;
    assert_eq!(
        exchange(&service_a, signed(http::Method::PUT, "/alpha/obj", Bytes::from_static(b"a")))
            .await
            .status(),
        200
    );

    // Hold root_a's lock; root_b operations must complete without waiting.
    let lock_a = open_and_lock_sentinel(&root_a.0);
    assert_eq!(
        exchange(&service_b, signed(http::Method::PUT, "/beta/obj", Bytes::from_static(b"b")))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service_b, signed(http::Method::GET, "/beta/obj", Bytes::new()))
            .await
            .status(),
        200
    );
    assert_eq!(
        exchange(&service_b, signed(http::Method::GET, "/", Bytes::new()))
            .await
            .status(),
        200
    );

    // Release root_a's lock; child process can now delete the unlocked object cleanly.
    drop(lock_a);
    let ready = control.0.join("ready-ok");
    let result = control.0.join("result-ok");
    let mut child = spawn_child_probe("delete_version", &root_a.0, "alpha", "obj", None, &ready, &result);
    assert!(child.wait().expect("wait child").success());
    let outcome = std::fs::read_to_string(&result).expect("outcome");
    assert!(
        outcome.starts_with("204:"),
        "unlocked object must delete after lock release, got: {outcome}"
    );

    // ListBuckets on root_a must still work with .version-lock present.
    let list_a = exchange(&service_a, signed(http::Method::GET, "/", Bytes::new())).await;
    assert_eq!(list_a.status(), 200);
    assert!(String::from_utf8_lossy(list_a.body()).contains("<Name>alpha</Name>"));

    // Object Lock creation succeeds on the shared root while unlocked-bucket lock writes fail 400
    // and unsupported event holds remain explicitly refused with 501 NotImplemented.
    let mut lock_bucket_headers = http::HeaderMap::new();
    lock_bucket_headers.insert(
        http::HeaderName::from_static("x-amz-bucket-object-lock-enabled"),
        http::HeaderValue::from_static("true"),
    );
    let lock_bucket = exchange(
        &service_a,
        signed_with_headers(http::Method::PUT, "/locked-bkt", Bytes::new(), lock_bucket_headers),
    )
    .await;
    assert_eq!(lock_bucket.status(), 200);

    let mut lock_put_headers = http::HeaderMap::new();
    lock_put_headers.insert(
        http::HeaderName::from_static("x-amz-object-lock-legal-hold"),
        http::HeaderValue::from_static("ON"),
    );
    let lock_put = exchange(
        &service_a,
        signed_with_headers(http::Method::PUT, "/alpha/obj2", Bytes::from_static(b"x"), lock_put_headers),
    )
    .await;
    assert_eq!(lock_put.status(), 400);

    let mut event_hold_headers = http::HeaderMap::new();
    event_hold_headers.insert(
        http::HeaderName::from_static("x-amz-object-lock-event-hold"),
        http::HeaderValue::from_static("ON"),
    );
    let event_hold_put = exchange(
        &service_a,
        signed_with_headers(http::Method::PUT, "/locked-bkt/obj3", Bytes::from_static(b"x"), event_hold_headers),
    )
    .await;
    assert_eq!(event_hold_put.status(), 501);
}
