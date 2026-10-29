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

//! Version sequence reservation shared across cooperating backend processes.
//!
//! Responsible for: serializing the counter's read, increment and atomic publication.
//! NOT responsible for: version publication, deletion, crash durability or Object Lock.
//! Upstream: version publication; downstream: a durable per-bucket sequence record.

use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use rustfs_gateway::{ErrorCode, HandlerError};

use super::{FsBackend, SEQUENCE_FILE, VersionRecord, storage_error};

const WAITING: u8 = 0;
const RUNNING: u8 = 1;
const CANCELLED: u8 = 2;

struct CancelQueued(Arc<AtomicU8>);

impl Drop for CancelQueued {
    fn drop(&mut self) {
        let _ = self
            .0
            .compare_exchange(WAITING, CANCELLED, Ordering::SeqCst, Ordering::SeqCst);
    }
}

impl FsBackend {
    pub(super) async fn next_version_sequence(&self, bucket: &str, held: &[VersionRecord]) -> Result<u64, HandlerError> {
        let bucket_path = self.bucket_path(bucket);
        let lock_path = self.root.join(super::super::VERSION_SEQUENCE_LOCK_FILE);
        let fallback = held.iter().map(|record| record.sequence).max().unwrap_or(0);
        let temporary_id = self.temporary_id.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(AtomicU8::new(WAITING));
        let cancel_queued = CancelQueued(Arc::clone(&state));
        let worker =
            tokio::task::spawn_blocking(move || reserve_sequence(&bucket_path, &lock_path, fallback, temporary_id, &state));
        let result = worker.await.map_err(|_| storage_error())?;
        drop(cancel_queued);
        result
    }
}

fn reserve_sequence(
    bucket: &Path,
    lock_path: &Path,
    fallback: u64,
    temporary_id: u64,
    state: &AtomicU8,
) -> Result<u64, HandlerError> {
    let lock = open_sequence_lock(lock_path)?;
    loop {
        if state.load(Ordering::SeqCst) == CANCELLED {
            #[cfg(test)]
            observe_cancelled();
            return Err(storage_error());
        }
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                #[cfg(test)]
                observe_contention();
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(std::fs::TryLockError::Error(_)) => return Err(storage_error()),
        }
    }
    if state
        .compare_exchange(WAITING, RUNNING, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(storage_error());
    }
    // The worker owns the lock until this synchronous reservation finishes, even if the
    // awaiting request is dropped. A reservation already started may leave a gap.
    reserve_locked(bucket, fallback, temporary_id)
}

fn open_sequence_lock(path: &Path) -> Result<std::fs::File, HandlerError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => return Err(storage_error()),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(storage_error()),
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(|_| storage_error())
}

fn reserve_locked(bucket: &Path, fallback: u64, temporary_id: u64) -> Result<u64, HandlerError> {
    match std::fs::symlink_metadata(bucket) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(HandlerError::new(ErrorCode::INVALID_REQUEST, "the storage path is not a safe directory")),
        Err(_) => return Err(storage_error()),
    }
    let path = bucket.join(SEQUENCE_FILE);
    let previous = match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => fallback,
        Err(_) => return Err(storage_error()),
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => std::fs::read_to_string(&path)
            .map_err(|_| storage_error())?
            .strip_suffix('\n')
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(storage_error)?,
        Ok(_) => {
            return Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the version sequence path is not a safe regular file",
            ));
        }
    };
    #[cfg(test)]
    observe_sequence_read();
    let next = previous.max(fallback).checked_add(1).ok_or_else(storage_error)?;
    let (temporary, mut file) = (0..1024_u64)
        .find_map(|offset| {
            let id = temporary_id.checked_add(offset)?;
            let path = bucket.join(format!(".seq-tmp-{}-{id}", std::process::id()));
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => Some(Ok((path, file))),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => None,
                Err(_) => Some(Err(storage_error())),
            }
        })
        .unwrap_or_else(|| Err(storage_error()))?;
    let written = file
        .write_all(format!("{next}\n").as_bytes())
        .and_then(|()| sync_sequence_file(&file))
        .and_then(|()| std::fs::rename(&temporary, &path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(storage_error());
    }
    Ok(next)
}

fn sync_sequence_file(file: &std::fs::File) -> io::Result<()> {
    #[cfg(test)]
    if std::env::var_os("GATEWAY_TEST_SEQ_FAIL_SYNC").is_some() {
        return Err(io::Error::other("injected sequence sync failure"));
    }
    file.sync_all()
}

#[cfg(test)]
fn observe_contention() {
    if let Some(path) = std::env::var_os("GATEWAY_TEST_SEQ_BUSY") {
        let _ = std::fs::write(path, b"contended");
    }
}

#[cfg(test)]
fn observe_sequence_read() {
    if let (Some(ready), Some(release)) =
        (std::env::var_os("GATEWAY_TEST_SEQ_READY"), std::env::var_os("GATEWAY_TEST_SEQ_RELEASE"))
    {
        std::fs::write(ready, b"read").expect("signal sequence snapshot");
        let start = std::time::Instant::now();
        while !Path::new(&release).exists() {
            assert!(start.elapsed() < Duration::from_secs(15), "release sequence snapshot");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[cfg(test)]
fn observe_cancelled() {
    if let Some(path) = std::env::var_os("GATEWAY_TEST_SEQ_CANCELLED") {
        let _ = std::fs::write(path, b"cancelled");
    }
}
