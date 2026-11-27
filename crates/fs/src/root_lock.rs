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

//! Shared-root synchronization across same-process `FsBackend` instances and cooperating OS
//! processes.
//!
//! Responsible for: canonical-root process-wide mutex sharing (with weak-entry pruning), fail-closed
//! opening and exclusive OS file locking of `<canonical-root>/.version-lock` inside `spawn_blocking`,
//! bounded cancellation-safe acquisition, and transferring lock ownership into blocking filesystem
//! critical sections so dropping an async future cannot release the lock while I/O is in flight.
//! NOT responsible for: S3 object semantics, crash-consistent disk durability, or resisting hostile
//! non-cooperating filesystem modifications.
//! Upstream: `FsBackend::open_with_clock`. Downstream: all versioned read, write, delete, bucket,
//! multipart, tagging, ACL, and lifecycle handlers.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use rustfs_gateway::{ErrorCode, HandlerError};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock as AsyncRwLock};

use super::storage_error;

/// Sentinel file stored directly under each canonical backend root for cross-process exclusion.
pub(super) const LOCK_FILE: &str = ".version-lock";

/// Bounded wait ceiling when contending on `<root>/.version-lock` against another process.
const DEFAULT_LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(10);

const STATE_QUEUED: u8 = 0;
const STATE_ACQUIRED: u8 = 1;
const STATE_CANCELLED: u8 = 2;

#[derive(Clone, Copy)]
enum LockMode {
    Exclusive,
    Shared,
}

impl LockMode {
    fn try_lock(self, file: &std::fs::File) -> Result<(), std::fs::TryLockError> {
        match self {
            Self::Exclusive => file.try_lock(),
            Self::Shared => file.try_lock_shared(),
        }
    }
}

type RootRegistry = StdMutex<HashMap<PathBuf, Weak<AsyncRwLock<()>>>>;

fn registry() -> &'static RootRegistry {
    static REGISTRY: OnceLock<RootRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| StdMutex::new(HashMap::new()))
}

/// Coordinates all version, bucket, and metadata operations targeting one canonical data root.
///
/// Multiple `FsBackend` instances opened on the same canonical root within one process share one
/// `tokio::sync::RwLock`, and every lock acquisition also takes an OS advisory lock on
/// `<root>/.version-lock` via `std::fs::File::try_lock` (exclusive) or `try_lock_shared` (shared)
/// with bounded retries inside a blocking worker.
pub(super) struct RootVersionLock {
    lock_path: PathBuf,
    local: Arc<AsyncRwLock<()>>,
    wait_timeout: Duration,
}

/// Exclusive ownership of both the canonical-root process lock and `<root>/.version-lock`.
///
/// Field declaration order is load-bearing: `file` is unlocked and closed before `_local` wakes
/// the next in-process waiter so the successor's `try_lock` succeeds immediately without sleeping.
pub(super) struct RootVersionGuard {
    file: std::fs::File,
    _local: OwnedRwLockWriteGuard<()>,
}

impl Drop for RootVersionGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Shared ownership of both the canonical-root process lock and `<root>/.version-lock`.
///
/// Allows disjoint bucket operations (such as concurrent `CreateMultipartUpload` calls, which
/// coordinate their own upload-ID sequence lock) to overlap while still strictly excluding
/// exclusive bucket and version mutations both in-process and across OS processes.
///
/// Field declaration order is load-bearing: `file` is unlocked before `_local` wakes any waiting
/// exclusive writer.
pub(super) struct RootVersionReadGuard {
    file: std::fs::File,
    _local: OwnedRwLockReadGuard<()>,
}

impl Drop for RootVersionReadGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Flips a queued blocking acquirer's state to `STATE_CANCELLED` if the awaiting async future is
/// dropped before acquisition completes.
struct CancelAcquireOnDrop {
    state: Arc<AtomicU8>,
    armed: bool,
}

impl CancelAcquireOnDrop {
    fn new(state: Arc<AtomicU8>) -> Self {
        Self { state, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CancelAcquireOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = self
                .state
                .compare_exchange(STATE_QUEUED, STATE_CANCELLED, Ordering::AcqRel, Ordering::Acquire);
        }
    }
}

impl RootVersionLock {
    /// Returns the shared lock coordinator for an already-canonicalized root directory.
    pub(super) fn for_canonical_root(canonical_root: PathBuf) -> Self {
        let local = {
            let mut map = registry().lock().unwrap_or_else(PoisonError::into_inner);
            map.retain(|_, weak| weak.strong_count() > 0);
            if let Some(existing) = map.get(&canonical_root).and_then(Weak::upgrade) {
                existing
            } else {
                let created = Arc::new(AsyncRwLock::new(()));
                map.insert(canonical_root.clone(), Arc::downgrade(&created));
                created
            }
        };
        Self {
            lock_path: canonical_root.join(LOCK_FILE),
            local,
            wait_timeout: DEFAULT_LOCK_WAIT_TIMEOUT,
        }
    }

    /// Acquires exclusive ownership of the canonical root across in-process instances and
    /// cooperating OS processes.
    ///
    /// # Errors
    ///
    /// Fails closed with `InvalidRequest` when `<root>/.version-lock` is a symbolic link or non-file,
    /// and with `InternalError` when the sentinel cannot be opened, locked within the bounded wait
    /// budget, or when the blocking worker fails.
    pub(super) async fn lock(&self) -> Result<RootVersionGuard, HandlerError> {
        let local = Arc::clone(&self.local).write_owned().await;
        let file = self.acquire_os_lock(LockMode::Exclusive).await?;
        Ok(RootVersionGuard { file, _local: local })
    }

    /// Acquires shared access to the canonical root so concurrent disjoint bucket operations (such
    /// as `CreateMultipartUpload`, which coordinates its own upload-ID sequence lock) overlap while
    /// still strictly excluding exclusive bucket and version mutations in-process and across OS
    /// processes.
    ///
    /// # Errors
    ///
    /// Fails closed with `InvalidRequest` when `<root>/.version-lock` is a symbolic link or non-file,
    /// and with `InternalError` when the sentinel cannot be opened, locked within the bounded wait
    /// budget, or when the blocking worker fails.
    pub(super) async fn lock_shared(&self) -> Result<RootVersionReadGuard, HandlerError> {
        let local = Arc::clone(&self.local).read_owned().await;
        let file = self.acquire_os_lock(LockMode::Shared).await?;
        Ok(RootVersionReadGuard { file, _local: local })
    }

    async fn acquire_os_lock(&self, mode: LockMode) -> Result<std::fs::File, HandlerError> {
        let file = open_safe_lock_file(&self.lock_path)?;
        match mode.try_lock(&file) {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                #[cfg(test)]
                test_hooks::notify_would_block(&self.lock_path);
            }
            Err(_) => return Err(storage_error()),
        }
        let lock_path = self.lock_path.clone();
        let wait_timeout = self.wait_timeout;
        let state = Arc::new(AtomicU8::new(STATE_QUEUED));
        let mut cancel_guard = CancelAcquireOnDrop::new(Arc::clone(&state));
        let worker_state = Arc::clone(&state);

        let acquired = tokio::task::spawn_blocking(move || wait_for_os_lock(file, &lock_path, mode, wait_timeout, &worker_state))
            .await
            .map_err(|_| storage_error())??;

        cancel_guard.disarm();
        Ok(acquired)
    }

    #[cfg(test)]
    pub(super) fn with_wait_timeout(mut self, timeout: Duration) -> Self {
        self.wait_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub(super) fn shares_local_mutex_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.local, &other.local)
    }

    #[cfg(test)]
    pub(super) fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    #[cfg(test)]
    pub(super) fn registry_contains(canonical_root: &Path) -> bool {
        registry()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains_key(canonical_root)
    }
}

impl RootVersionGuard {
    /// Runs a blocking filesystem critical section while the worker thread owns `self`, so
    /// dropping the async caller's future cannot release the shared-root mutex or OS file lock
    /// before the filesystem mutation completes.
    pub(super) async fn run_blocking<T, F>(self, work: F) -> Result<(Self, T), HandlerError>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, HandlerError> + Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let outcome = work();
            (self, outcome)
        })
        .await
        .map_err(|_| storage_error())
        .and_then(|(guard, outcome)| outcome.map(|value| (guard, value)))
    }
}

fn open_safe_lock_file(path: &Path) -> Result<std::fs::File, HandlerError> {
    let invalid = || HandlerError::new(ErrorCode::INVALID_REQUEST, "the version lock path is not a safe regular file");
    let pre = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => Some(meta),
        Ok(_) => return Err(invalid()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(storage_error()),
    };
    let (file, expected_meta) = if let Some(meta) = pre {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|_| storage_error())?;
        (file, meta)
    } else {
        match std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(path) {
            Ok(file) => {
                let meta = std::fs::symlink_metadata(path).map_err(|_| storage_error())?;
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err(invalid());
                }
                (file, meta)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let meta = std::fs::symlink_metadata(path).map_err(|_| storage_error())?;
                if !meta.is_file() || meta.file_type().is_symlink() {
                    return Err(invalid());
                }
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)
                    .map_err(|_| storage_error())?;
                (file, meta)
            }
            Err(_) => return Err(storage_error()),
        }
    };
    let opened = file.metadata().map_err(|_| storage_error())?;
    if !opened.is_file() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if opened.dev() != expected_meta.dev() || opened.ino() != expected_meta.ino() {
            return Err(invalid());
        }
    }
    #[cfg(not(unix))]
    let _ = expected_meta;
    Ok(file)
}

fn wait_for_os_lock(
    file: std::fs::File,
    _path: &Path,
    mode: LockMode,
    wait_timeout: Duration,
    state: &AtomicU8,
) -> Result<std::fs::File, HandlerError> {
    let mut remaining = wait_timeout;
    let mut attempt: u32 = 1;
    loop {
        if state.load(Ordering::Acquire) == STATE_CANCELLED || remaining.is_zero() {
            return Err(storage_error());
        }
        let delay = Duration::from_millis(u64::from(attempt.min(10))).min(remaining);
        std::thread::sleep(delay);
        remaining = remaining.saturating_sub(delay);
        if state.load(Ordering::Acquire) == STATE_CANCELLED {
            return Err(storage_error());
        }
        match mode.try_lock(&file) {
            Ok(()) => {
                if state
                    .compare_exchange(STATE_QUEUED, STATE_ACQUIRED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    let _ = file.unlock();
                    return Err(storage_error());
                }
                return Ok(file);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                #[cfg(test)]
                test_hooks::notify_would_block(_path);
                attempt = attempt.saturating_add(1);
            }
            Err(_) => return Err(storage_error()),
        }
    }
}

#[cfg(test)]
pub(super) mod test_hooks {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};

    type ObserverMap = Mutex<HashMap<PathBuf, Arc<AtomicUsize>>>;

    fn observers() -> &'static ObserverMap {
        static OBSERVERS: OnceLock<ObserverMap> = OnceLock::new();
        OBSERVERS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(super) fn notify_would_block(path: &Path) {
        let observer = observers().lock().unwrap_or_else(PoisonError::into_inner).get(path).cloned();
        if let Some(counter) = observer {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub(crate) struct WouldBlockObserver {
        path: PathBuf,
        counter: Arc<AtomicUsize>,
    }

    impl WouldBlockObserver {
        pub(crate) fn install(path: PathBuf) -> Self {
            let counter = Arc::new(AtomicUsize::new(0));
            observers()
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(path.clone(), Arc::clone(&counter));
            Self { path, counter }
        }

        pub(crate) fn count(&self) -> usize {
            self.counter.load(Ordering::SeqCst)
        }
    }

    impl Drop for WouldBlockObserver {
        fn drop(&mut self) {
            observers().lock().unwrap_or_else(PoisonError::into_inner).remove(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use super::{LOCK_FILE, RootVersionLock};

    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rustfs-gateway-fs-root-lock-{tag}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create root lock scratch dir");
        std::fs::canonicalize(path).expect("canonicalize scratch dir")
    }

    /// Negative — shared root locks must allow concurrent shared holders while strictly blocking
    /// exclusive writers in-process and respecting external OS exclusive locks.
    #[tokio::test]
    async fn n_shared_root_lock_allows_concurrent_readers_and_blocks_exclusive_writers() {
        let root = scratch_dir("rw-exclusion");
        let lock_a = RootVersionLock::for_canonical_root(root.clone()).with_wait_timeout(Duration::from_millis(60));
        let lock_b = RootVersionLock::for_canonical_root(root.clone()).with_wait_timeout(Duration::from_millis(60));

        let shared_1 = lock_a.lock_shared().await.expect("first shared lock succeeds");
        let shared_2 = tokio::time::timeout(Duration::from_millis(150), lock_b.lock_shared())
            .await
            .expect("second concurrent shared lock must not block behind first shared lock")
            .expect("second shared lock succeeds");

        // An exclusive writer must remain blocked while any shared guard is held.
        let mut exclusive = Box::pin(lock_a.lock());
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut exclusive).await.is_err(),
            "exclusive lock must wait while two shared guards are held"
        );
        drop(shared_1);
        assert!(
            tokio::time::timeout(Duration::from_millis(40), &mut exclusive).await.is_err(),
            "exclusive lock must still wait while the second shared guard is held"
        );
        drop(shared_2);
        let writer = tokio::time::timeout(Duration::from_millis(200), exclusive)
            .await
            .expect("exclusive lock acquires once all shared guards drop")
            .expect("exclusive lock succeeds");
        drop(writer);

        // An external OS exclusive lock on `.version-lock` must fail closed on `lock_shared` when
        // the wait budget expires, and succeed once released.
        let external = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(LOCK_FILE))
            .expect("open lock file externally");
        external.try_lock().expect("acquire external exclusive OS lock");
        assert!(
            lock_a.lock_shared().await.is_err(),
            "shared lock must fail closed while an external OS exclusive lock is held"
        );
        external.unlock().expect("release external OS lock");
        let _after = lock_a.lock_shared().await.expect("shared lock succeeds after OS release");
        drop(_after);

        // Two-directional OS control: an external shared OS lock must allow `lock_shared` while
        // still failing closed on an exclusive `lock()` until released.
        external.try_lock_shared().expect("acquire external shared OS lock");
        let _co_shared = lock_a
            .lock_shared()
            .await
            .expect("shared lock must succeed beside an external shared OS lock");
        drop(_co_shared);
        assert!(
            lock_a.lock().await.is_err(),
            "exclusive lock must fail closed while an external OS shared lock is held"
        );
        external.unlock().expect("release external shared OS lock");
        let _after_shared = lock_a.lock().await.expect("exclusive lock succeeds after shared OS release");
        drop(_after_shared);
        drop(external);
        let _ = std::fs::remove_dir_all(root);
    }
}
