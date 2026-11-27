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

//! RAII staging cleanup guards for cancellation-safe filesystem writes and multipart operations.
//!
//! Responsible for: ensuring temporary staging files, staging directories, and multipart tombstones
//! are synchronously cleaned up or restored if an async handler future returns early or is dropped
//! mid-flight, while never following or deleting symbolic links.
//! NOT responsible for: S3 object semantics, lock ordering, or durable crash recovery of committed
//! records.
//! Upstream: `buckets`, `completion`, `lib`, `uploads`, and `versioning`. Downstream: `std::fs`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustfs_gateway::{ErrorCode, HandlerError};

use super::{FsBackend, storage_error};

/// Process-wide monotonic counter for staging artifact names so multiple `FsBackend` instances
/// sharing one data root inside the same process never collide on `.tmp-*` / `.complete-*` names.
static NEXT_TEMPORARY_ID: AtomicU64 = AtomicU64::new(0);

/// Returns a unique staging identifier within the current process.
pub(super) fn next_temporary_id() -> u64 {
    NEXT_TEMPORARY_ID.fetch_add(1, Ordering::Relaxed)
}

/// Returns `true` only when `path` exists as a real, non-symlink directory.
pub(super) fn is_safe_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
}

/// Removes `path` recursively only if it is a real, non-symlink directory.
pub(super) fn remove_safe_dir(path: &Path) {
    if is_safe_dir(path) {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// Removes `path` only if it is a real, non-symlink regular file.
fn remove_safe_file(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink()) {
        let _ = std::fs::remove_file(path);
    }
}

/// Creates a new regular staging file synchronously and writes `bytes` to completion, flushing
/// Tokio's write-behind buffer before returning so a subsequent `rename` or read never observes
/// an in-flight, empty, or truncated write.
pub(super) async fn create_and_write_file(path: &Path, bytes: &[u8]) -> Result<(), HandlerError> {
    let std_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| storage_error())?;
    let mut file = tokio::fs::File::from_std(std_file);
    tokio::io::AsyncWriteExt::write_all(&mut file, bytes)
        .await
        .map_err(|_| storage_error())?;
    tokio::io::AsyncWriteExt::flush(&mut file)
        .await
        .map_err(|_| storage_error())?;
    Ok(())
}

/// Removes a staging directory on drop unless disarmed after publication or explicit removal.
pub(super) struct TempDirGuard {
    path: Option<PathBuf>,
}

impl TempDirGuard {
    /// Creates `path` synchronously and arms cleanup immediately so no `.await` sits between
    /// directory creation and guard registration.
    pub(super) fn create(path: PathBuf) -> Result<Self, HandlerError> {
        std::fs::create_dir(&path).map_err(|_| storage_error())?;
        Ok(Self { path: Some(path) })
    }

    /// Arms cleanup for a staging directory or tombstone that already exists on disk.
    pub(super) fn adopt(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Disarms cleanup once the directory has been atomically published or removed.
    pub(super) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            remove_safe_dir(&path);
        }
    }
}

/// Removes a staging regular file on drop unless disarmed after atomic rename.
pub(super) struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    /// Arms cleanup for a newly created temporary file.
    pub(super) fn adopt(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    /// Disarms cleanup once the temporary file has been atomically renamed into place.
    pub(super) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            remove_safe_file(&path);
        }
    }
}

enum TombstoneState {
    RestoreTo(PathBuf),
    Remove,
    Disarmed,
}

/// Guards a `.complete-*` multipart tombstone across async object publication and teardown.
///
/// Before publication succeeds, dropping the guard restores the tombstone back to its original
/// `u-*` upload path (falling back to safe removal if restoration fails, so `.complete-*` never
/// lingers to block `DeleteBucket`). Once publication succeeds, dropping the guard removes the
/// tombstone directly.
pub(super) struct CompletionTombstoneGuard {
    tombstone: PathBuf,
    state: TombstoneState,
}

impl CompletionTombstoneGuard {
    pub(super) fn new(tombstone: PathBuf, original: PathBuf) -> Self {
        Self {
            tombstone,
            state: TombstoneState::RestoreTo(original),
        }
    }

    /// Switches drop cleanup from restore to removal once the completed object is published.
    pub(super) fn mark_published(&mut self) {
        self.state = TombstoneState::Remove;
    }

    /// Disarms cleanup once the tombstone has been removed.
    pub(super) fn disarm(&mut self) {
        self.state = TombstoneState::Disarmed;
    }
}

impl Drop for CompletionTombstoneGuard {
    fn drop(&mut self) {
        match core::mem::replace(&mut self.state, TombstoneState::Disarmed) {
            TombstoneState::RestoreTo(original) => {
                if is_safe_dir(&self.tombstone) && std::fs::rename(&self.tombstone, &original).is_err() {
                    remove_safe_dir(&self.tombstone);
                }
            }
            TombstoneState::Remove => remove_safe_dir(&self.tombstone),
            TombstoneState::Disarmed => {}
        }
    }
}

impl FsBackend {
    /// Whether `versions/` holds no committed version records (only empty or safe interrupted
    /// `.tmp-*` staging directories). A symlink or non-directory `.tmp-*` fails closed.
    pub(super) fn versions_directory_allows_delete(&self, bucket: &str) -> Result<bool, HandlerError> {
        let versions = self.versions_path(bucket);
        let entries = std::fs::read_dir(&versions).map_err(|_| storage_error())?;
        for entry in entries {
            let entry = entry.map_err(|_| storage_error())?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                return Ok(false);
            };
            if name.starts_with(".tmp-") {
                let metadata = std::fs::symlink_metadata(entry.path()).map_err(|_| storage_error())?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(HandlerError::new(
                        ErrorCode::INVALID_REQUEST,
                        "the version path is not a safe record directory",
                    ));
                }
                continue;
            }
            return Ok(false);
        }
        Ok(true)
    }

    /// Removes any interrupted non-symlink `.tmp-*` staging directories before `versions/` is
    /// removed by `DeleteBucket`.
    pub(super) fn discard_interrupted_version_temps(&self, bucket: &str) -> Result<(), HandlerError> {
        let versions = self.versions_path(bucket);
        let entries = std::fs::read_dir(&versions).map_err(|_| storage_error())?;
        for entry in entries {
            let entry = entry.map_err(|_| storage_error())?;
            if entry.file_name().to_str().is_some_and(|name| name.starts_with(".tmp-")) {
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path).map_err(|_| storage_error())?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(HandlerError::new(
                        ErrorCode::INVALID_REQUEST,
                        "the version path is not a safe record directory",
                    ));
                }
                std::fs::remove_dir_all(&path).map_err(|_| storage_error())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod test_hooks {
    use std::future::poll_fn;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::Poll;

    struct PauseTarget {
        stage: &'static str,
        entered: Arc<AtomicBool>,
    }

    tokio::task_local! {
        static PAUSE_TARGET: PauseTarget;
    }

    /// Runs `future` with a task-local cancellation pause armed at `stage`, setting `entered` once
    /// the future reaches `stage`.
    pub(crate) async fn pause_at<F: std::future::Future>(stage: &'static str, entered: Arc<AtomicBool>, future: F) -> F::Output {
        PAUSE_TARGET.scope(PauseTarget { stage, entered }, future).await
    }

    /// Parks forever when the active test armed a cancellation pause for `stage`.
    pub(crate) async fn maybe_pause(stage: &'static str) {
        let should_pause = PAUSE_TARGET
            .try_with(|target| {
                if target.stage == stage {
                    target.entered.store(true, Ordering::SeqCst);
                    true
                } else {
                    false
                }
            })
            .unwrap_or(false);
        if should_pause {
            poll_fn(|_| Poll::<()>::Pending).await;
        }
    }
}
