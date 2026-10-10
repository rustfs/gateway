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

//! Upload-ID window reservation against its persisted counter (rustfs/gateway#1336).
//!
//! Responsible for: proving that the allocator persists a window of 64 IDs before it issues the
//! first of them and issues the rest from memory; that the persisted counter exceeds every issued
//! ID wherever a caller can observe it; that a crash at any offset inside a window never lets a
//! reopened backend re-issue an ID; and that a corrupt, truncated, symlinked, reset, exhausted or
//! unsafe temporary counter fails closed; and that successful bucket deletion retires only its own
//! window while refused deletion preserves it. NOT responsible for: the wire answers of
//! `CreateMultipartUpload` (`tests/crud/multipart_upload_ids.rs`) or upload records.
//! Upstream: `FsBackend::allocate_upload_id` and `DeleteBucket`. Downstream: the filesystem
//! verification gate.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{UPLOAD_ID_SEQUENCE, UPLOAD_ID_SEQUENCE_TEMP, persist_upload_id_sequence_with_sync};
use crate::FsBackend;

/// The decided window (rustfs/gateway#1336), written out so that a changed constant is a red test.
const WINDOW: u64 = 64;
const BUCKET: &str = "window";

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// A unique backend root, removed with everything under it when the test ends.
struct Root(PathBuf);

impl Root {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "rustfs-gateway-fs-upload-ids-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("a unique test root");
        Self(path)
    }

    /// A backend opened on this root as a new process would open it, with the bucket's upload
    /// directory in place. Dropping it is a crash: nothing runs on the way out.
    fn open(&self) -> FsBackend {
        let backend = FsBackend::open(&self.0).expect("a usable test root");
        std::fs::create_dir_all(backend.uploads_path(BUCKET)).expect("the bucket's upload directory");
        backend
    }

    fn authority(&self, name: &str) -> PathBuf {
        self.0.join(format!("b-{}", hex::encode(BUCKET))).join("uploads").join(name)
    }

    fn sequence(&self) -> PathBuf {
        self.authority(UPLOAD_ID_SEQUENCE)
    }

    fn temporary(&self) -> PathBuf {
        self.authority(UPLOAD_ID_SEQUENCE_TEMP)
    }

    fn persisted(&self) -> u64 {
        let encoded = std::fs::read_to_string(self.sequence()).expect("the persisted test counter");
        encoded
            .strip_suffix('\n')
            .and_then(|digits| digits.parse().ok())
            .expect("a canonical test counter")
    }

    fn write_counter(&self, bytes: impl AsRef<[u8]>) {
        std::fs::write(self.sequence(), bytes).expect("write the exact test counter");
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("the exact test root is removable");
    }
}

/// Allocates one ID and checks it where a caller first observes it: the persisted counter, which is
/// where a restart resumes, must already be above the ID being returned.
async fn allocate(backend: &FsBackend, root: &Root) -> u64 {
    let id = backend.allocate_upload_id(BUCKET).await.expect("an upload ID");
    let id = u64::from_str_radix(id.strip_prefix("fs-v2-").expect("the fs-v2 form"), 16).expect("a hexadecimal ID");
    let persisted = root.persisted();
    assert!(persisted > id, "the persisted counter {persisted} does not exceed the issued ID {id}");
    id
}

async fn refused(backend: &FsBackend) -> bool {
    backend.allocate_upload_id(BUCKET).await.is_err()
}

/// Positive — the first allocation persists exactly one window above the ID it returns; the next 63
/// are issued from memory and leave the counter file alone; the 65th reserves the next window
/// before it is returned. A reservation replaces the counter by rename, so an unchanged inode is
/// the evidence that nothing between two reservations wrote it.
#[cfg(unix)]
#[tokio::test]
async fn one_reservation_serves_a_whole_window() {
    use std::os::unix::fs::MetadataExt as _;

    let root = Root::new();
    let backend = root.open();
    let inode = || std::fs::symlink_metadata(root.sequence()).expect("the test counter").ino();

    assert_eq!(allocate(&backend, &root).await, 0);
    assert_eq!(root.persisted(), WINDOW);
    let reserved = inode();
    for expected in 1..WINDOW {
        assert_eq!(allocate(&backend, &root).await, expected);
        assert_eq!(inode(), reserved, "ID {expected} rewrote the counter");
    }
    assert_eq!(root.persisted(), WINDOW);
    assert_eq!(allocate(&backend, &root).await, WINDOW);
    assert_eq!(root.persisted(), 2 * WINDOW);
    assert_ne!(inode(), reserved, "the 65th ID did not reserve the next window");
}

/// Positive — a backend reopened exactly at a window boundary resumes at the boundary: nothing
/// issued is reused and nothing is skipped.
#[tokio::test]
async fn reopen_at_a_window_boundary_resumes_at_the_boundary() {
    let root = Root::new();
    let backend = root.open();
    for expected in 0..WINDOW {
        assert_eq!(allocate(&backend, &root).await, expected);
    }
    assert_eq!(root.persisted(), WINDOW);
    drop(backend);

    let reopened = root.open();
    assert_eq!(allocate(&reopened, &root).await, WINDOW);
    assert_eq!(root.persisted(), 2 * WINDOW);
}

/// Positive — sixteen tasks allocating at once on eight worker threads receive distinct IDs that
/// fill the reserved windows without a gap, and the counter ends on the boundary above them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_allocations_receive_distinct_contiguous_ids() {
    let root = Arc::new(Root::new());
    let backend = Arc::new(root.open());
    let tasks = (0..16)
        .map(|_| {
            let (backend, root) = (Arc::clone(&backend), Arc::clone(&root));
            tokio::spawn(async move {
                let mut ids = Vec::new();
                for _ in 0..40 {
                    ids.push(allocate(&backend, &root).await);
                }
                ids
            })
        })
        .collect::<Vec<_>>();
    let mut issued = HashSet::new();
    for task in tasks {
        for id in task.await.expect("an allocating task") {
            assert!(issued.insert(id), "ID {id} was issued twice");
        }
    }
    assert_eq!(issued, (0..640).collect::<HashSet<_>>());
    assert_eq!(root.persisted(), 640);
}

/// Positive — two backends on one root, as two processes would hold it, allocating in turn never
/// issue the same ID: each finds the counter moved by the other, treats its own window as void,
/// and reserves above the other's.
#[tokio::test]
async fn two_backends_allocating_in_turn_never_share_an_id() {
    let root = Root::new();
    let (first, second) = (root.open(), root.open());
    let mut issued = HashSet::new();
    for _ in 0..8 {
        for backend in [&first, &second] {
            let id = allocate(backend, &root).await;
            assert!(issued.insert(id), "ID {id} was issued twice");
        }
    }
}

/// Negative — a crash at any offset inside a window never lets the reopened backend re-issue an
/// ID: every ID issued after a reopen exceeds every ID issued before it, and the gap a crash leaves
/// is at most the 63 unissued IDs of one window. Dropping the backend is the whole crash: no
/// shutdown runs, so the counter and the upload directory are all a reopen has.
#[tokio::test]
async fn n_a_crash_inside_a_window_never_reissues_an_id() {
    let root = Root::new();
    let mut issued = HashSet::new();
    let mut highest: Option<u64> = None;
    for crash_after in [1, 2, 31, 63, 64, 65, 127, 128, 129] {
        let backend = root.open();
        for allocation in 0..crash_after {
            let id = allocate(&backend, &root).await;
            if let Some(highest) = highest {
                assert!(id > highest, "ID {id} after {highest} was re-issued or reordered");
                if allocation == 0 {
                    let skipped = id - highest - 1;
                    assert!(skipped < WINDOW, "the crash before this reopen skipped {skipped} IDs");
                }
            }
            assert!(issued.insert(id), "ID {id} was issued twice");
            highest = Some(id);
        }
        drop(backend);
    }
}

/// Negative — a counter corrupted while its window still holds unissued IDs refuses the next
/// allocation instead of issuing from memory, and leaves the bytes it found. Restoring the exact
/// high-water mark resumes the same window, so the refusals came from the corruption.
#[tokio::test]
async fn n_a_counter_corrupted_inside_a_window_fails_closed() {
    let root = Root::new();
    let backend = root.open();
    assert_eq!(allocate(&backend, &root).await, 0);
    let corruptions: [&[u8]; 6] = [
        b"not-a-counter\n",
        b"064\n",
        b"64\n64\n",
        b"-64\n",
        b" 64\n",
        b"18446744073709551616\n",
    ];
    for corrupt in corruptions {
        root.write_counter(corrupt);
        assert!(refused(&backend).await, "{:?} was accepted", String::from_utf8_lossy(corrupt));
        assert_eq!(std::fs::read(root.sequence()).expect("the corrupt test counter"), corrupt);
    }
    root.write_counter(b"64\n");
    assert_eq!(allocate(&backend, &root).await, 1);
}

/// Negative — a counter cut short is refused, never read as the smaller value it now spells. A
/// reservation writes the counter only through a synchronized temporary renamed over it, so a
/// short counter comes from outside; its missing terminator is what refuses it, before and after a
/// reopen. `128\n` cut to `12` would otherwise resume below IDs already issued.
#[tokio::test]
async fn n_a_counter_truncated_mid_write_fails_closed() {
    let root = Root::new();
    let backend = root.open();
    for expected in 0..=WINDOW {
        assert_eq!(allocate(&backend, &root).await, expected);
    }
    assert_eq!(root.persisted(), 2 * WINDOW);
    for cut in [&b"12"[..], b"1", b""] {
        root.write_counter(cut);
        assert!(refused(&backend).await, "{:?} was accepted", String::from_utf8_lossy(cut));
        assert!(
            refused(&root.open()).await,
            "{:?} was accepted after a reopen",
            String::from_utf8_lossy(cut)
        );
        assert_eq!(std::fs::read(root.sequence()).expect("the cut test counter"), cut);
    }
}

/// Negative — a symlink replacing the counter inside a window is refused even when its target
/// spells the window's exact high-water mark, by the running backend and after a reopen, and the
/// target is never written.
#[cfg(unix)]
#[tokio::test]
async fn n_a_counter_symlinked_inside_a_window_is_refused_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let root = Root::new();
    let outside = Root::new();
    let backend = root.open();
    assert_eq!(allocate(&backend, &root).await, 0);
    let target = outside.0.join("counter");
    std::fs::write(&target, b"64\n").expect("initialize the outside test file");
    std::fs::remove_file(root.sequence()).expect("remove the exact test counter");
    symlink(&target, root.sequence()).expect("replace the counter with a test symlink");

    assert!(refused(&backend).await);
    drop(backend);
    assert!(refused(&root.open()).await);
    assert_eq!(std::fs::read(&target).expect("read the outside test file"), b"64\n");
}

/// Negative — the last window below `u64::MAX` is issued in full and then refused: exhaustion is
/// reported when no full window can be reserved, the counter stays at its maximum, and nothing
/// wraps back to the first capability.
#[tokio::test]
async fn n_the_last_window_is_issued_and_then_refused_without_wrapping() {
    let root = Root::new();
    let backend = root.open();
    root.write_counter(format!("{}\n", u64::MAX - WINDOW));
    for expected in u64::MAX - WINDOW..u64::MAX {
        assert_eq!(allocate(&backend, &root).await, expected);
    }
    assert_eq!(root.persisted(), u64::MAX);
    assert!(refused(&backend).await);
    assert!(refused(&root.open()).await);
    assert_eq!(root.persisted(), u64::MAX);
}

/// Negative — a counter too close to `u64::MAX` to hold one more full window is refused before
/// anything is written or issued.
#[tokio::test]
async fn n_a_window_that_cannot_be_reserved_in_full_is_refused() {
    for start in [u64::MAX - WINDOW + 1, u64::MAX - 1, u64::MAX] {
        let root = Root::new();
        let backend = root.open();
        root.write_counter(format!("{start}\n"));
        assert!(refused(&backend).await, "a window from {start} was reserved");
        assert_eq!(root.persisted(), start);
        assert!(!root.temporary().exists());
    }
}

/// Negative — a counter removed inside a window, as a bucket deletion removes it, voids that
/// window: the next allocation recreates the counter and reserves from it, rather than issuing
/// from memory over a counter that restarts below the window.
#[tokio::test]
async fn n_a_removed_counter_voids_the_window_it_held() {
    let root = Root::new();
    let backend = root.open();
    for expected in 0..3 {
        assert_eq!(allocate(&backend, &root).await, expected);
    }
    std::fs::remove_file(root.sequence()).expect("remove the exact test counter");

    let id = allocate(&backend, &root).await;
    assert_eq!(root.persisted(), id + WINDOW, "ID {id} was not issued from a new reservation");
}

/// Negative — a reservation interrupted before rename leaves only its old counter authoritative.
/// A reopened backend discards the half-written temporary instead of adopting its value or requiring
/// manual cleanup, then reserves a whole window before returning the next ID.
#[tokio::test]
async fn n_a_reservation_interrupted_mid_write_recovers_from_the_counter() {
    let root = Root::new();
    let backend = root.open();
    for expected in 0..WINDOW {
        assert_eq!(allocate(&backend, &root).await, expected);
    }
    drop(backend);
    for stale in [&b"12"[..], b"999999", b""] {
        std::fs::write(root.temporary(), stale).expect("a crash-left test temporary");
        let expected = root.persisted();
        assert_eq!(allocate(&root.open(), &root).await, expected);
        assert_eq!(root.persisted(), expected + WINDOW);
        assert!(!root.temporary().exists(), "the stale temporary survived publication");
    }
}

/// Negative — recovery refuses a directory at the temporary path and leaves its contents alone.
#[tokio::test]
async fn n_a_temporary_directory_is_refused_without_removing_it() {
    let root = Root::new();
    let backend = root.open();
    root.write_counter(b"64\n");
    std::fs::create_dir(root.temporary()).expect("a directory occupying the test temporary");
    let child = root.temporary().join("kept");
    std::fs::write(&child, b"untouched").expect("the occupied directory's child");

    assert!(refused(&backend).await);
    assert_eq!(root.persisted(), WINDOW);
    assert_eq!(std::fs::read(child).expect("the retained child"), b"untouched");
}

/// Negative — recovery never follows or removes a temporary symlink, even to a regular file.
#[cfg(unix)]
#[tokio::test]
async fn n_a_temporary_symlink_is_refused_without_touching_it_or_its_target() {
    use std::os::unix::fs::symlink;

    let root = Root::new();
    let outside = Root::new();
    let backend = root.open();
    root.write_counter(b"64\n");
    let target = outside.0.join("temporary");
    std::fs::write(&target, b"untouched").expect("the outside test temporary");
    symlink(&target, root.temporary()).expect("a temporary symlink");

    assert!(refused(&backend).await);
    assert_eq!(root.persisted(), WINDOW);
    assert!(
        std::fs::symlink_metadata(root.temporary())
            .expect("the retained symlink")
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(target).expect("the retained target"), b"untouched");
}

/// Negative — a live writer holding the upload directory lock keeps its temporary file and counter.
/// Once the writer's handle closes (including after a crash), the next allocator can recover it.
#[cfg(unix)]
#[tokio::test]
async fn n_a_live_writer_is_not_mistaken_for_a_crash_left_temporary() {
    let root = Root::new();
    let backend = root.open();
    root.write_counter(b"64\n");
    let directory = std::fs::File::open(root.sequence().parent().expect("the counter directory"))
        .expect("a directory handle for the live test writer");
    directory.try_lock().expect("the live test writer's exclusive lock");

    assert!(refused(&backend).await, "allocation ignored the live writer's directory lock");
    assert_eq!(root.persisted(), WINDOW);
    std::fs::write(root.temporary(), b"128").expect("the live writer's incomplete temporary");
    assert!(refused(&backend).await);
    assert_eq!(root.persisted(), WINDOW);
    assert_eq!(std::fs::read(root.temporary()).expect("the live writer's temporary"), b"128");
    drop(directory);
    assert_eq!(allocate(&backend, &root).await, WINDOW);
    assert!(!root.temporary().exists());
}

/// Positive — the directory is synchronized after the new counter is published, exactly once.
/// The callback performs the real directory synchronization; ordering is observed from the files,
/// not inferred from a return value or from the allocator's intended sequence.
#[test]
fn directory_synchronization_observes_the_published_counter() {
    let root = Root::new();
    let _backend = root.open();
    root.write_counter(b"0\n");
    let mut synchronizations = 0;
    persist_upload_id_sequence_with_sync(root.sequence().parent().expect("the counter directory"), WINDOW, |directory| {
        assert_eq!(root.persisted(), WINDOW, "directory synchronization preceded publication");
        assert!(!root.temporary().exists(), "the temporary was not renamed before synchronization");
        std::fs::File::open(directory)?.sync_all()?;
        synchronizations += 1;
        Ok(())
    })
    .expect("the synchronized test reservation");
    assert_eq!(synchronizations, 1);
}

/// Negative — a directory synchronization failure is returned rather than treated as a durable
/// reservation. Its renamed counter still causes the next allocator to skip the unissued window.
#[tokio::test]
async fn n_directory_synchronization_failure_does_not_issue_the_unsynchronized_window() {
    let root = Root::new();
    let backend = root.open();
    root.write_counter(b"0\n");
    let result = persist_upload_id_sequence_with_sync(root.sequence().parent().expect("the counter directory"), WINDOW, |_| {
        Err(std::io::Error::other("injected directory synchronization failure"))
    });
    assert!(result.is_err());
    assert_eq!(root.persisted(), WINDOW);
    assert_eq!(allocate(&backend, &root).await, WINDOW);
}

fn bucket_request_proof() -> rustfs_gateway::SseEnforced {
    let request = http::Request::builder()
        .uri("/")
        .header("host", "s3.example.com")
        .body(bytes::Bytes::new())
        .expect("a valid bucket fixture");
    let wire = rustfs_gateway::WireRequest::accept(request, &rustfs_gateway::Limits::default()).expect("an accepted fixture");
    let meta = rustfs_gateway::MetaView::of(&wire, rustfs_gateway::TargetKind::Service).expect("a service fixture");
    rustfs_gateway::enforce_sse(&meta, rustfs_gateway::TransportSecurity::Encrypted, &rustfs_gateway::SseConfig::strict())
        .expect("an empty encrypted request passes SSE enforcement")
}

async fn create_bucket_with_window(backend: &FsBackend, bucket: &str) {
    use rustfs_gateway::{BucketName, Handler, Req, dto};
    let input = dto::CreateBucketInput {
        bucket: BucketName::new(bucket).expect("a valid test bucket"),
        ..dto::CreateBucketInput::default()
    };
    Handler::<dto::CreateBucket>::call(backend, Req::new(input, bucket_request_proof()))
        .await
        .expect("a created test bucket");
    backend.allocate_upload_id(bucket).await.expect("a reserved test window");
}

async fn delete_bucket(backend: &FsBackend, bucket: &str) -> Result<(), rustfs_gateway::HandlerError> {
    use rustfs_gateway::{BucketName, Handler, Req, dto};
    let input = dto::DeleteBucketInput {
        bucket: BucketName::new(bucket).expect("a valid test bucket"),
        ..dto::DeleteBucketInput::default()
    };
    Handler::<dto::DeleteBucket>::call(backend, Req::new(input, bucket_request_proof()))
        .await
        .map(|_| ())
}

/// Negative — distinct deleted names must not accumulate windows in a long-lived backend.
#[tokio::test]
async fn n_deleted_buckets_do_not_accumulate_windows() {
    let root = Root::new();
    let backend = FsBackend::open(&root.0).expect("a usable test root");
    for index in 0..16 {
        let bucket = format!("retired-{index}");
        create_bucket_with_window(&backend, &bucket).await;
        delete_bucket(&backend, &bucket).await.expect("a deleted test bucket");
        assert!(
            backend.upload_id_windows.lock().await.is_empty(),
            "deleted bucket {bucket} retained a window"
        );
    }
}

/// Negative — retiring one bucket must not discard another live bucket's reserved window.
#[tokio::test]
async fn n_deleting_one_bucket_preserves_another_window() {
    let root = Root::new();
    let backend = FsBackend::open(&root.0).expect("a usable test root");
    create_bucket_with_window(&backend, "retired").await;
    create_bucket_with_window(&backend, "retained").await;
    delete_bucket(&backend, "retired").await.expect("a deleted test bucket");
    assert_eq!(
        backend.allocate_upload_id("retained").await.expect("the next live ID"),
        "fs-v2-0000000000000001"
    );
}

/// Negative — a bucket refused at the emptiness check keeps its reserved window.
#[tokio::test]
async fn n_refused_bucket_deletion_preserves_its_window() {
    let root = Root::new();
    let backend = FsBackend::open(&root.0).expect("a usable test root");
    create_bucket_with_window(&backend, "retained").await;
    std::fs::write(backend.objects_path("retained").join("object"), b"content").expect("a nonempty test bucket");
    assert!(delete_bucket(&backend, "retained").await.is_err());
    assert_eq!(
        backend.allocate_upload_id("retained").await.expect("the next live ID"),
        "fs-v2-0000000000000001"
    );
}

/// Negative — retirement follows the final directory removal, not an earlier partial deletion.
#[tokio::test]
async fn n_failed_final_bucket_removal_preserves_its_window() {
    let root = Root::new();
    let backend = FsBackend::open(&root.0).expect("a usable test root");
    create_bucket_with_window(&backend, "retained").await;
    std::fs::write(backend.bucket_path("retained").join("unexplained"), b"content").expect("a blocked final removal");
    assert!(delete_bucket(&backend, "retained").await.is_err());
    assert!(backend.upload_id_windows.lock().await.contains_key("retained"));
}
