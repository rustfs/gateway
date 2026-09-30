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

//! The RustFS-profile switch that bounds the body a claimed route is sent at legacy RustFS's
//! ceiling for its admin surface (rustfs/gateway#1173).
//!
//! Responsible for: [`ServiceBuilder::bound_claimed_route_bodies_as_legacy_rustfs`] and
//! [`ClaimedBodies::ceiling`], the declared length past which a claimed route's request is
//! refused.
//! NOT responsible for: the refusal itself (`crate::gate`), which routes are claimed (the
//! dialects' `PathClaim`s), or any unclaimed operation's body.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! Legacy RustFS answers its admin surface — the prefixes the RustFS admin dialect claims — as a
//! custom route of the legacy stack, and that route refuses a request whose `Content-Length`
//! declares more than 1 MiB once its signature has been verified and before its access check or
//! handler runs: `400 EntityTooLarge` "Custom route request body exceeds the configured maximum
//! size.", whatever the route reads. RustFS leaves that ceiling at the legacy stack's default
//! (`rustfs/src/server/http.rs:166-173` on rustfs/rustfs `3268c42e00`). Observed against a legacy
//! RustFS build: `PUT /rustfs/admin/v3/add-user` declaring 1 MiB + 1 byte and
//! `GET /rustfs/admin/v3/info` declaring 2 MiB each answer that refusal with `Connection: close`;
//! a body of exactly 1 MiB reaches the handler. The core bounds a claimed route's body by its
//! body mode alone: a buffered one up to the assembly's buffered ceiling, an unread one not at all.

use super::ServiceBuilder;

/// Legacy RustFS's ceiling on the declared body of a request to its admin surface.
pub(crate) const LEGACY_RUSTFS_CLAIMED_ROUTE_BODY_BYTES: u64 = 1024 * 1024;

/// Whether a claimed route's declared body is bounded as legacy RustFS bounds it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum ClaimedBodies {
    /// Bounded by the route's body mode, as every operation's body is.
    #[default]
    ByBodyMode,
    /// Refused past [`LEGACY_RUSTFS_CLAIMED_ROUTE_BODY_BYTES`], as legacy RustFS refuses it.
    LegacyRustfs,
}

impl ClaimedBodies {
    /// The declared length past which a request is refused before its authorization: a claimed
    /// route's under the switch, and no request's otherwise.
    pub(crate) const fn ceiling(self, claimed: bool) -> Option<u64> {
        match (self, claimed) {
            (Self::LegacyRustfs, true) => Some(LEGACY_RUSTFS_CLAIMED_ROUTE_BODY_BYTES),
            _ => None,
        }
    }
}

impl ServiceBuilder {
    /// Refuses a request to a claimed route whose `Content-Length` declares more than 1 MiB
    /// ([`LEGACY_RUSTFS_CLAIMED_ROUTE_BODY_BYTES`]), as legacy RustFS refuses one to its admin
    /// surface: `400 EntityTooLarge` with legacy RustFS's sentence, once the signature has been
    /// verified and before authorization or any of the body is read, whatever the route reads
    /// (rustfs/gateway#1173).
    ///
    /// Off by default: the core bounds a claimed route's body by its body mode, as every
    /// operation's is. Unclaimed operations are unchanged, and a claimed route's body within the
    /// ceiling is read exactly as before.
    #[must_use]
    pub fn bound_claimed_route_bodies_as_legacy_rustfs(mut self) -> Self {
        self.view_policy.claimed_bodies = ClaimedBodies::LegacyRustfs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Positive — under the switch a claimed route is bounded at 1 MiB.
    #[test]
    fn the_switch_bounds_a_claimed_route_at_one_mebibyte() {
        assert_eq!(ClaimedBodies::LegacyRustfs.ceiling(true), Some(1024 * 1024));
    }

    /// Negative — an unclaimed operation is never bounded by it, and nothing is without the switch.
    #[test]
    fn n_an_unclaimed_operation_and_the_default_are_unbounded() {
        assert_eq!(ClaimedBodies::LegacyRustfs.ceiling(false), None);
        for claimed in [false, true] {
            assert_eq!(ClaimedBodies::ByBodyMode.ceiling(claimed), None, "{claimed}");
        }
        assert_eq!(ClaimedBodies::default(), ClaimedBodies::ByBodyMode);
    }
}
