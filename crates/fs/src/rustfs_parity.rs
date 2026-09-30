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

//! The answers this backend gives as legacy RustFS gives them, each one asked for by name.
//!
//! Responsible for: the one set of switches a deployment standing this backend in for RustFS
//! turns on — the RustFS-profile launcher, `compat/sut`, is that deployment — and the builder
//! methods that turn each one on. Every switch is off by default, so a generic deployment keeps
//! the backend's own answers.
//! NOT responsible for: what a switch changes, which is decided where the operation is served —
//! `super::versioning::delete_conditions` for `If-Match` on a delete, `super::deletes` for the
//! batch-delete refusal.
//! Upstream: the deployment assembling the backend. Downstream: the handlers that read a switch.

use super::FsBackend;

/// The legacy-RustFS answers this backend was asked to give, all off by default.
#[derive(Clone, Copy, Default)]
pub(super) struct RustfsParity {
    /// The keys a batch delete answers on its own ([`FsBackend::refusing_batch_deletes_of`]).
    pub(super) batch_delete_refusal: Option<fn(&str) -> bool>,
    /// Whether `DeleteObject` evaluates `If-Match` ([`FsBackend::evaluating_delete_if_match`]).
    pub(super) delete_if_match: bool,
}

impl FsBackend {
    /// Evaluates `If-Match` on `DeleteObject` as legacy RustFS does, under the lock writers take.
    ///
    /// The object's own tag or `*` deletes it; another tag, a delete marker, or — in an
    /// unversioned bucket, or for a key its versioning configuration excludes — no object at all
    /// answers `412 PreconditionFailed` and deletes nothing. A named version is judged by its own
    /// tag, and an unknown one deletes nothing whatever the condition. Legacy RustFS's reading of
    /// the value is kept: whitespace and every surrounding quote are stripped, and a blank value is
    /// no condition. So is its one exception: a versioned or suspended bucket's key that holds no
    /// version at all is not judged, and the delete writes a marker (rustfs/gateway#1191).
    ///
    /// Off by default, when the header is not read and every delete proceeds as if it were
    /// absent. `DeleteObjects` is never conditional: its input carries no `If-Match`.
    #[must_use]
    pub const fn evaluating_delete_if_match(mut self) -> Self {
        self.rustfs_parity.delete_if_match = true;
        self
    }
}
