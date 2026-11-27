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

//! Protection-safe duplicate-null version reconciliation and persistent null-replacement intent.
//!
//! Responsible for: writing and clearing the durable `supersedes-null` cleanup intent inside a
//! newly staged `null` version before rename, deterministically selecting the highest-sequence
//! `null` record regardless of directory iteration order, rechecking protection on every superseded
//! older `null`, and failing closed on protected or unremovable stale records so deleting the
//! newest `null` can never resurrect an older one.
//! NOT responsible for: version publication staging, multipart receipts, or shared-root locking
//! (`super::super::root_lock`).
//! Upstream: `super` (`versioning`), `super::super::reads`, `super::super::version_listing`, and
//! `super::lifecycle`. Downstream: `super::super::lock_record` and `std::fs`.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use rustfs_gateway::{ErrorCode, HandlerError};

use super::super::staging::{CompletionTombstoneGuard, TempDirGuard};
use super::super::{FsBackend, lock_record, storage_error};
use super::VersionRecord;

/// Durable sibling marker written inside a staged `null` version directory before rename whenever
/// that publication supersedes an earlier `null` version or legacy plain object file.
pub(super) const SUPERSEDES_NULL_FILE: &str = "supersedes-null";
const SUPERSEDES_NULL_HEADER: &str = "supersedes-null/1";

/// Writes a durable cleanup intent into `staging_dir` before atomic rename whenever the staged
/// `null` version replaces prior `null` record(s) or a legacy plain object file.
pub(super) fn write_supersedes_null_intent(
    staging_dir: &Path,
    superseded_nulls: &[&VersionRecord],
    supersedes_legacy: bool,
) -> Result<(), HandlerError> {
    if superseded_nulls.is_empty() && !supersedes_legacy {
        return Ok(());
    }
    let mut text = format!("{SUPERSEDES_NULL_HEADER}\n");
    if supersedes_legacy {
        text.push_str("legacy\n");
    }
    for record in superseded_nulls {
        if let Some(name) = record.path.file_name().and_then(|value| value.to_str()) {
            text.push_str(&format!("dir {name}\n"));
        }
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staging_dir.join(SUPERSEDES_NULL_FILE))
        .and_then(|mut file| io::Write::write_all(&mut file, text.as_bytes()))
        .map_err(|_| storage_error())
}

/// Checks whether `version_dir` carries a valid `supersedes-null` cleanup intent file, failing
/// closed if the path was replaced by a symbolic link or directory.
fn has_supersedes_null_intent(version_dir: &Path) -> Result<bool, HandlerError> {
    let path = version_dir.join(SUPERSEDES_NULL_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(storage_error()),
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "the null cleanup intent path is not a safe regular file",
        )),
    }
}

/// Removes the `supersedes-null` cleanup intent once every superseded `null` record and legacy
/// object has been safely retired.
pub(super) fn clear_supersedes_null_intent(version_dir: &Path) -> Result<(), HandlerError> {
    let path = version_dir.join(SUPERSEDES_NULL_FILE);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(storage_error()),
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => std::fs::remove_file(path).map_err(|_| storage_error()),
        Ok(_) => Err(HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "the null cleanup intent path is not a safe regular file",
        )),
    }
}

/// Removes one version directory only after confirming it is a real, non-symlink directory.
pub(super) fn remove_version_dir_strict(path: &Path) -> Result<(), HandlerError> {
    #[cfg(test)]
    test_hooks::maybe_fail_dir_remove(path)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(storage_error()),
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => std::fs::remove_dir_all(path).map_err(|_| storage_error()),
        Ok(_) => Err(HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "the version path is not a safe record directory",
        )),
    }
}

/// Removes one legacy plain object file if present, failing closed on symbolic links or directories.
pub(super) fn remove_legacy_object_sync(path: &Path) -> Result<(), HandlerError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(storage_error()),
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => std::fs::remove_file(path).map_err(|_| storage_error()),
        Ok(_) => Err(HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "the object path is not a safe regular file",
        )),
    }
}

/// Reconciles duplicate `null` versions and pending `supersedes-null` cleanup intent for one key
/// while the caller holds the shared-root version lock.
///
/// Selects the unique highest-sequence `null` record as authoritative, performs a fresh protection
/// check against `now` on every older `null` record, removes unprotected superseded records from
/// disk and from `records`, removes any superseded legacy plain file when `supersedes-null` is
/// present, and clears the intent marker. Fails closed on equal sequences, active protection
/// (`AccessDenied`), unsafe symlinks (`InvalidRequest`), or persistent removal errors (`InternalError`),
/// never deleting the newest `null` while a stale `null` remains on disk.
pub(super) fn reconcile_null_records_for_key(
    records: &mut Vec<VersionRecord>,
    key: &str,
    legacy_path: &Path,
    now: i64,
) -> Result<(), HandlerError> {
    let mut null_indices: Vec<usize> = records
        .iter()
        .enumerate()
        .filter_map(|(idx, record)| (record.key == key && record.version_id == "null").then_some(idx))
        .collect();
    if null_indices.is_empty() {
        return Ok(());
    }
    null_indices.sort_by_key(|&idx| records[idx].sequence);
    for pair in null_indices.windows(2) {
        if records[pair[0]].sequence == records[pair[1]].sequence {
            return Err(storage_error());
        }
    }
    let Some(&newest_idx) = null_indices.last() else {
        return Ok(());
    };
    let stale_indices = &null_indices[..null_indices.len() - 1];

    // Recheck protection on EVERY superseded older null before removing any directory.
    for &stale_idx in stale_indices {
        lock_record::ensure_deletable(records[stale_idx].lock.as_ref(), now)?;
    }

    let mut removed_paths = BTreeSet::new();
    for &stale_idx in stale_indices {
        let stale_path = records[stale_idx].path.clone();
        remove_version_dir_strict(&stale_path)?;
        removed_paths.insert(stale_path);
    }

    let newest_path = records[newest_idx].path.clone();
    if has_supersedes_null_intent(&newest_path)? {
        remove_legacy_object_sync(legacy_path)?;
        clear_supersedes_null_intent(&newest_path)?;
    }

    if !removed_paths.is_empty() {
        records.retain(|record| !removed_paths.contains(&record.path));
    }
    Ok(())
}

/// Reconciles every key in `records` that carries duplicate `null` records or an active
/// `supersedes-null` cleanup marker. Caller holds the shared-root version lock.
pub(super) fn reconcile_all_null_records(
    backend: &FsBackend,
    bucket: &str,
    records: &mut Vec<VersionRecord>,
    now: i64,
) -> Result<(), HandlerError> {
    let mut seen_null = BTreeSet::<String>::new();
    let mut candidates = BTreeSet::<String>::new();
    for record in records.iter() {
        if record.version_id == "null" && (!seen_null.insert(record.key.clone()) || has_supersedes_null_intent(&record.path)?) {
            candidates.insert(record.key.clone());
        }
    }
    for key in candidates {
        let legacy_path = backend.object_path(bucket, &key);
        reconcile_null_records_for_key(records, &key, &legacy_path, now)?;
    }
    Ok(())
}

/// Parameters for the blocking commit point that publishes a staged version and retires any
/// superseded `null` versions while the blocking worker owns the shared-root lock.
pub(super) struct CommitStagedVersion {
    pub(super) temporary: PathBuf,
    pub(super) destination: PathBuf,
    pub(super) temp_guard: TempDirGuard,
    pub(super) tombstone_guard: Option<CompletionTombstoneGuard>,
    pub(super) superseded_nulls: Vec<(PathBuf, Option<lock_record::LockState>)>,
    pub(super) legacy_object: Option<PathBuf>,
    pub(super) now: i64,
}

/// Atomically renames the staged version into place, immediately switches any multipart tombstone
/// guard from restore-to-upload to remove-tombstone so post-rename faults can never restore a
/// committed upload, and retires superseded `null` versions and legacy files before clearing the
/// durable `supersedes-null` intent.
pub(super) fn commit_staged_version(mut plan: CommitStagedVersion) -> Result<Option<CompletionTombstoneGuard>, HandlerError> {
    std::fs::rename(&plan.temporary, &plan.destination).map_err(|_| storage_error())?;
    plan.temp_guard.disarm();
    if let Some(tombstone_guard) = plan.tombstone_guard.as_mut() {
        tombstone_guard.mark_published();
    }
    for (old_path, old_lock) in &plan.superseded_nulls {
        lock_record::ensure_deletable(old_lock.as_ref(), plan.now)?;
        remove_version_dir_strict(old_path)?;
    }
    if let Some(legacy_path) = plan.legacy_object.as_deref() {
        remove_legacy_object_sync(legacy_path)?;
    }
    clear_supersedes_null_intent(&plan.destination)?;
    Ok(plan.tombstone_guard)
}

#[cfg(test)]
pub(super) mod test_hooks {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock, PoisonError};

    use rustfs_gateway::HandlerError;

    use super::super::super::storage_error;

    fn fail_targets() -> &'static Mutex<Vec<PathBuf>> {
        static TARGETS: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
        TARGETS.get_or_init(|| Mutex::new(Vec::new()))
    }

    pub(super) fn maybe_fail_dir_remove(path: &Path) -> Result<(), HandlerError> {
        let mut guard = fail_targets().lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(pos) = guard.iter().position(|target| target == path) {
            guard.remove(pos);
            return Err(storage_error());
        }
        Ok(())
    }

    pub(crate) fn fail_next_remove_of(path: PathBuf) {
        fail_targets().lock().unwrap_or_else(PoisonError::into_inner).push(path);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use rustfs_gateway::ErrorCode;

    use super::SUPERSEDES_NULL_FILE;
    use crate::etag;
    use crate::records::ObjectAttributes;
    use crate::versioning::tests::backend_with_bucket;

    /// Negative — bucket-wide reconciliation during listing must clean up a pending single-null
    /// `supersedes-null` legacy-object intent and fail closed when `supersedes-null` is a symlink.
    #[tokio::test]
    async fn n_listing_reconciles_single_null_supersedes_intent_and_refuses_symlink_intent() {
        let (root, backend) = backend_with_bucket("single-null-intent");
        let legacy_path = backend.object_path("racing", "legacy-key");
        std::fs::write(&legacy_path, b"old-legacy").expect("seed legacy plain object");
        let record = backend
            .publish_version(
                "racing",
                "legacy-key",
                Some("null"),
                Some(b"replacement"),
                Some(&etag(b"replacement").expect("etag")),
                &ObjectAttributes::default(),
            )
            .await
            .expect("publish single null version");
        let intent_path = record.path.join(SUPERSEDES_NULL_FILE);
        std::fs::write(&intent_path, b"supersedes-null/1\nlegacy\n").expect("write pending legacy intent");

        let listed = backend
            .current_object_records("racing")
            .await
            .expect("listing reconciles single-null supersedes-null intent");
        assert_eq!(listed.len(), 1);
        assert!(!legacy_path.exists(), "listing reconciliation must remove superseded legacy plain file");
        assert!(
            !intent_path.exists(),
            "listing reconciliation must clear supersedes-null once cleanup succeeds"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = std::env::temp_dir().join(format!("rustfs-gateway-fs-intent-link-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&outside);
            std::fs::create_dir_all(&outside).expect("outside dir");
            let victim = outside.join("victim");
            std::fs::write(&victim, b"safe").expect("victim file");
            symlink(&victim, &intent_path).expect("tamper supersedes-null with symlink");

            let err = backend
                .current_object_records("racing")
                .await
                .err()
                .expect("symlinked supersedes-null must fail closed during listing");
            assert_eq!(err.code(), &ErrorCode::INVALID_REQUEST);
            assert_eq!(std::fs::read(&victim).expect("victim intact"), b"safe");
            let _ = std::fs::remove_dir_all(outside);
        }
        let _ = std::fs::remove_dir_all(root);
    }
}
