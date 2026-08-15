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

//! Bounded cache entries and their least-recently-used index.
//!
//! Responsible for: keeping cached CORS documents and recency metadata consistent.
//! NOT responsible for: source reads, deadlines, or shared in-flight futures.
//! Upstream: `super::CachedCorsSource`. Downstream: cache hit and completion paths.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use rustfs_gateway_sig::RequestNow;
use rustfs_gateway_types::dto::CorsConfiguration;

#[derive(Default)]
pub(super) struct Cache {
    entries: HashMap<String, Entry>,
    recency: BTreeMap<u128, String>,
    next_recency: u128,
}

struct Entry {
    document: Option<Arc<CorsConfiguration>>,
    expires_at: i64,
    recency: u128,
}

impl Cache {
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn fresh(&mut self, key: &str, now: RequestNow) -> Option<Option<Arc<CorsConfiguration>>> {
        let entry = self.entries.get(key)?;
        (entry.expires_at > now.unix_seconds()).then_some(())?;
        let document = entry.document.clone();
        let previous = entry.recency;
        if self.recency.remove(&previous).as_deref() != Some(key) {
            self.clear_entries();
            return None;
        }
        let recency = self.claim_recency();
        if let Some(entry) = self.entries.get_mut(key) {
            entry.recency = recency;
        }
        self.recency.insert(recency, key.to_owned());
        Some(document)
    }

    pub(super) fn store(&mut self, key: &str, document: Option<Arc<CorsConfiguration>>, expires_at: i64) {
        if let Some(previous) = self.entries.get(key).map(|entry| entry.recency)
            && self.recency.remove(&previous).as_deref() != Some(key)
        {
            self.clear_entries();
        }
        let recency = self.claim_recency();
        let entry = Entry {
            document,
            expires_at,
            recency,
        };
        self.entries.insert(key.to_owned(), entry);
        self.recency.insert(recency, key.to_owned());
    }

    pub(super) fn evict_to(&mut self, limit: usize) {
        while self.entries.len() > limit {
            let Some((_, key)) = self.recency.pop_first() else {
                self.clear_entries();
                return;
            };
            self.entries.remove(&key);
        }
    }

    fn claim_recency(&mut self) -> u128 {
        while self.recency.contains_key(&self.next_recency) {
            self.next_recency = self.next_recency.wrapping_add(1);
        }
        let recency = self.next_recency;
        self.next_recency = self.next_recency.wrapping_add(1);
        recency
    }

    fn clear_entries(&mut self) {
        self.entries.clear();
        self.recency.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn n_a_missing_recency_index_cannot_break_the_entry_cap() {
        let mut state = Cache::default();
        state.store("alpha", None, 1);
        state.store("bravo", None, 1);
        state.recency.clear();
        state.evict_to(1);
        assert!(state.len() <= 1, "corrupt recency metadata bypassed the entry cap");
    }

    #[test]
    fn n_a_hit_with_missing_recency_discards_the_corrupt_cache() {
        let mut state = Cache::default();
        state.store("alpha", None, 1);
        state.recency.clear();
        assert!(state.fresh("alpha", RequestNow::from_unix_seconds(0)).is_none());
        assert_eq!(state.len(), 0, "a hit preserved corrupt recency metadata");
    }

    #[test]
    fn n_a_replacement_with_missing_recency_discards_the_corrupt_cache() {
        let mut state = Cache::default();
        state.store("alpha", None, 1);
        state.store("bravo", None, 1);
        let alpha_recency = state.entries.get("alpha").map_or(u128::MAX, |entry| entry.recency);
        state.recency.remove(&alpha_recency);
        state.store("alpha", None, 2);
        assert_eq!(state.len(), 1, "a replacement preserved an orphaned cache entry");
    }
}
