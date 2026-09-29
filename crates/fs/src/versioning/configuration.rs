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

//! A bucket's whole versioning configuration: every member persisted, and the keys MinIO's
//! excluded prefixes and folders take out of versioning, applied as legacy RustFS applies them
//! (rustfs/gateway#1078).
//!
//! Responsible for: [`CONFIGURATION_FILE`], written in legacy RustFS's persisted form so no member
//! a client sent is dropped, [`Exclusions`] and the wildcard match legacy RustFS reads an excluded
//! prefix with.
//! NOT responsible for: the versioning state itself (`STATUS_FILE`, the parent), or what a write
//! or delete does in each state (the parent's publication and deletion).
//! Upstream: the parent's handlers. Downstream: `rustfs_gateway::persistence`'s versioning codec.

use std::io;

use rustfs_gateway::persistence::{parse_versioning_dto, serialize_versioning_dto};
use rustfs_gateway::{ErrorCode, HandlerError};

use super::super::{FsBackend, storage_error};
use super::VersioningState;

/// The whole versioning configuration as last written, in the form legacy RustFS persists it
/// (`serialize_versioning_dto`): the status, `MfaDelete`, and MinIO's `ExcludeFolders` and
/// `ExcludedPrefixes`, so no member a client sent is dropped. The status is still read from
/// [`STATUS_FILE`]; a bucket configured before this file existed has none and excludes nothing.
pub(crate) const CONFIGURATION_FILE: &str = "versioning-configuration";

/// The keys an enabled bucket's versioning configuration excludes: MinIO's `ExcludeFolders` and
/// `ExcludedPrefixes`, read as legacy RustFS reads them (`VersioningApi::prefix_enabled` and
/// `prefix_suspended`, `crates/ecstore/src/bucket/versioning/mod.rs` at rustfs/rustfs@e870a6d25).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Exclusions {
    folders: bool,
    prefixes: Vec<String>,
}

impl Exclusions {
    /// Whether `key` is excluded: a key ending in `/` under `ExcludeFolders`, or a key the pattern
    /// `{prefix}*` matches for an excluded prefix. An entry without a `Prefix` excludes nothing.
    pub(super) fn excludes(&self, key: &str) -> bool {
        if key.is_empty() {
            return false;
        }
        if self.folders && key.ends_with('/') {
            return true;
        }
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS matches an excluded prefix as a
        // wildcard pattern, not as a prefix: `*` and `?` in it are wildcards, an empty prefix
        // excludes every key, and a `?` reached after the last byte of the key matches, so the
        // prefix `a?c/` excludes the key `a`. Kept so a bucket versions exactly the keys legacy
        // RustFS versions; the intended reading is a literal prefix, as MinIO documents it.
        self.prefixes
            .iter()
            .any(|prefix| matches_simple(format!("{prefix}*").as_bytes(), key.as_bytes()))
    }
}

/// Legacy RustFS's `match_simple` (`crates/utils/src/string.rs:75` at rustfs/rustfs@e870a6d25),
/// byte for byte: `*` matches any run of bytes and `?` any one byte, a `?` reached once the name is
/// exhausted matches, and every other byte matches itself.
///
/// Run as a set of reachable pattern positions rather than as the recursion legacy RustFS runs, so
/// a pattern of many stars costs at most the product of the two lengths instead of an exponential
/// walk; `configuration_tests.rs` holds the two to the same answer everywhere on a small alphabet.
pub(super) fn matches_simple(pattern: &[u8], name: &[u8]) -> bool {
    if pattern.is_empty() {
        return name.is_empty();
    }
    if pattern == b"*" {
        return true;
    }
    // A star may match nothing: the position after a reachable star is reachable too.
    let close = |reachable: &mut Vec<bool>| {
        for (at, byte) in pattern.iter().enumerate() {
            if *byte == b'*'
                && reachable.get(at).copied().unwrap_or(false)
                && let Some(next) = reachable.get_mut(at + 1)
            {
                *next = true;
            }
        }
    };
    let mut reachable = vec![false; pattern.len() + 1];
    if let Some(first) = reachable.first_mut() {
        *first = true;
    }
    close(&mut reachable);
    for &byte in name {
        let mut next = vec![false; pattern.len() + 1];
        for (at, wanted) in pattern.iter().enumerate() {
            if !reachable.get(at).copied().unwrap_or(false) {
                continue;
            }
            let target = match *wanted {
                b'*' => at,
                b'?' => at + 1,
                literal if literal == byte => at + 1,
                _ => continue,
            };
            if let Some(slot) = next.get_mut(target) {
                *slot = true;
            }
        }
        close(&mut next);
        if !next.contains(&true) {
            return false;
        }
        reachable = next;
    }
    reachable.last().copied().unwrap_or(false)
        || pattern
            .iter()
            .zip(&reachable)
            .any(|(byte, reached)| *reached && *byte == b'?')
}

impl FsBackend {
    /// The keys `bucket`'s versioning configuration excludes, as last written.
    async fn exclusions(&self, bucket: &str) -> Result<Exclusions, HandlerError> {
        let path = self.bucket_path(bucket).join(CONFIGURATION_FILE);
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Exclusions::default()),
            Err(_) => Err(storage_error()),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                let bytes = tokio::fs::read(path).await.map_err(|_| storage_error())?;
                let configuration = parse_versioning_dto(&bytes).map_err(|_| storage_error())?;
                Ok(Exclusions {
                    folders: configuration.exclude_folders.unwrap_or(false),
                    prefixes: configuration
                        .excluded_prefixes
                        .into_iter()
                        .filter_map(|entry| entry.prefix)
                        .collect(),
                })
            }
            Ok(_) => Err(HandlerError::new(
                ErrorCode::INVALID_REQUEST,
                "the versioning configuration path is not a safe regular file",
            )),
        }
    }

    /// Whether `key` is excluded from `bucket`'s versioning: only an enabled bucket excludes.
    pub(super) async fn excluded(&self, bucket: &str, key: &str, state: VersioningState) -> Result<bool, HandlerError> {
        if state != VersioningState::Enabled {
            return Ok(false);
        }
        Ok(self.exclusions(bucket).await?.excludes(key))
    }

    /// Persists the whole configuration, every member included, in legacy RustFS's persisted
    /// form. Written before the status, which stays the authority for the state.
    pub(super) async fn set_versioning_configuration(
        &self,
        bucket: &str,
        configuration: &rustfs_gateway::dto::VersioningConfiguration,
    ) -> Result<(), HandlerError> {
        let destination = self.bucket_path(bucket).join(CONFIGURATION_FILE);
        match tokio::fs::symlink_metadata(&destination).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_REQUEST,
                    "the versioning configuration path is not a safe regular file",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        self.write_atomic(&self.bucket_path(bucket), &destination, &serialize_versioning_dto(configuration))
            .await
    }
}

#[cfg(test)]
#[path = "configuration_tests.rs"]
mod tests;
