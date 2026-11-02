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

//! Process-local sharing of version mutexes for filesystem backends.
//!
//! Responsible for: one mutex per canonical backend root while any backend owns it.
//! NOT responsible for: synchronization across processes or cancelled filesystem operations.
//! Upstream: `FsBackend::open_with_clock`; downstream: version state access.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

static ROOT_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>> = OnceLock::new();

pub(super) fn for_root(root: &Path) -> io::Result<Arc<tokio::sync::Mutex<()>>> {
    let mut roots = ROOT_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| io::Error::other("the version-lock registry is poisoned"))?;
    roots.retain(|_, lock| lock.strong_count() != 0);
    if let Some(lock) = roots.get(root).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    roots.insert(root.to_owned(), Arc::downgrade(&lock));
    Ok(lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stale root keys must be pruned after their last mutex owner is gone.
    #[test]
    fn stale_root_entries_are_pruned_on_the_next_open() {
        let first = std::env::temp_dir().join(format!("gateway-registry-stale-{}", std::process::id()));
        let second = std::env::temp_dir().join(format!("gateway-registry-live-{}", std::process::id()));
        let abandoned = for_root(&first).expect("first root");
        drop(abandoned);
        let live = for_root(&second).expect("second root");
        let roots = ROOT_LOCKS.get().expect("initialized registry").lock().expect("registry lock");
        assert!(!roots.contains_key(&first), "a dropped root must not remain in the registry");
        assert!(roots.contains_key(&second), "the live root remains registered");
        drop(roots);
        drop(live);
    }
}
