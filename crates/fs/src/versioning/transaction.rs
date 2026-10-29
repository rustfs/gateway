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

//! The cooperating-process boundary for explicitly named version deletion.
//!
//! Responsible for: cancellation-aware acquisition and lock-owned version removal.
//! NOT responsible for: publication, null versions, non-cooperating updates, or crash durability.
//! Upstream: named version deletion. Downstream: the root lock and filesystem removal.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rustfs_gateway::HandlerError;

use super::storage_error;

pub(crate) const LOCK_FILE: &str = ".gateway-version-transaction.lock";

struct CancelQueued(Arc<AtomicBool>);

impl Drop for CancelQueued {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

pub(super) async fn named_guard(root: &Path, version_id: Option<&str>) -> Result<Option<std::fs::File>, HandlerError> {
    if !version_id.is_some_and(|id| id != "null") {
        return Ok(None);
    }
    let path = root.join(LOCK_FILE);
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_on_drop = CancelQueued(Arc::clone(&cancelled));
    let worker = tokio::task::spawn_blocking(move || {
        let lock = open_lock(&path)?;
        loop {
            if cancelled.load(Ordering::SeqCst) {
                #[cfg(test)]
                signal("GATEWAY_TEST_TRANSACTION_STOPPED");
                return Err(storage_error());
            }
            match lock.try_lock() {
                Ok(()) => {
                    if cancelled.load(Ordering::SeqCst) {
                        #[cfg(test)]
                        signal("GATEWAY_TEST_TRANSACTION_STOPPED");
                        return Err(storage_error());
                    }
                    return Ok(lock);
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    #[cfg(test)]
                    signal("GATEWAY_TEST_TRANSACTION_BUSY");
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(std::fs::TryLockError::Error(_)) => return Err(storage_error()),
            }
        }
    });
    let lock = worker.await.map_err(|_| storage_error())??;
    drop(cancel_on_drop);
    Ok(Some(lock))
}

fn open_lock(path: &Path) -> Result<std::fs::File, HandlerError> {
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

pub(super) async fn remove_version(
    lock: Option<std::fs::File>,
    local_guard: tokio::sync::OwnedMutexGuard<()>,
    path: &Path,
) -> Result<(), HandlerError> {
    let Some(lock) = lock else {
        let result = tokio::fs::remove_dir_all(path).await.map_err(|_| storage_error());
        drop(local_guard);
        return result;
    };
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        observe_removal_start();
        let result = std::fs::remove_dir_all(path).map_err(|_| storage_error());
        drop(lock);
        drop(local_guard);
        result
    })
    .await
    .map_err(|_| storage_error())?
}

#[cfg(test)]
fn signal(variable: &str) {
    if let Some(path) = std::env::var_os(variable) {
        let _ = std::fs::write(path, b"observed");
    }
}

#[cfg(test)]
fn observe_removal_start() {
    if let (Some(ready), Some(release)) = (
        std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_READY"),
        std::env::var_os("GATEWAY_TEST_TRANSACTION_REMOVE_RELEASE"),
    ) {
        std::fs::write(ready, b"started").expect("signal removal worker");
        let start = std::time::Instant::now();
        while !Path::new(&release).exists() {
            assert!(start.elapsed() < Duration::from_secs(15), "release removal worker");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
