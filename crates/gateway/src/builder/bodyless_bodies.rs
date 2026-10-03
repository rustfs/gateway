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

//! The RustFS-profile switch that leaves the body of an operation that takes none unread, as
//! legacy RustFS leaves it (rustfs/gateway#1173).
//!
//! Responsible for: [`ServiceBuilder::leave_bodies_of_bodyless_operations_unread`] and
//! [`BodylessBodies::leaves_unread`], which the pipeline asks before it would read such a body.
//! NOT responsible for: releasing the body (`crate::service` drops it where it would have read
//! it), draining it behind the answer (the embedding host, or the gateway's own server's lingering
//! close), or any operation that takes a body.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! The legacy stack reads a request body only for an operation that declares one, buffered or
//! streamed; for every other operation it never polls the body, so nothing about it is judged: not
//! its length, not its signed digest, not a `Content-MD5` or `x-amz-checksum-*` header, not its
//! aws-chunked framing. RustFS's `EarlyResponseBodyService` then drains the abandoned body behind
//! the answer with `Connection: close` (`rustfs/src/server/http.rs:706-1010` on rustfs/rustfs
//! `3268c42e00`). Observed against a legacy RustFS build: a `GetObject`, `HeadObject`,
//! `ListObjectsV2`, `DeleteObject` or `CreateMultipartUpload` carrying a body is answered as
//! without one; a `GetObject` declaring 100 MiB is answered `200` after 64 KiB arrived; a `Content-MD5`
//! that is not base64, a mismatched one on a `CopyObject`, and a trailer declaration on a
//! `GetObject` are all served. The core reads such a body to its end under the buffered ceiling
//! and holds it to every claim, as it holds any other body.

use rustfs_gateway_core::RequestBodyMode;

use super::ServiceBuilder;

/// Whether the body of an operation that takes none is read before the operation is answered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BodylessBodies {
    /// Read to its end under the buffered ceiling and held to its claims, as every body is.
    #[default]
    Read,
    /// Never polled, as legacy RustFS leaves it.
    Unread,
}

impl BodylessBodies {
    /// Whether a body sent to an operation read in `mode` is left unread.
    pub(crate) const fn leaves_unread(self, mode: RequestBodyMode) -> bool {
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS never looks at the body of an
        // operation that takes none, so a client's malformed or contradicting `Content-MD5`,
        // checksum, signed digest or aws-chunked framing on such a request goes unreported, and
        // the connection is closed behind the answer to drain it. Nothing is lost, since no
        // handler reads the body; kept so the clients RustFS serves today keep working. The
        // intended future behaviour is the core's: read it under the buffered ceiling and refuse
        // a claim it contradicts.
        matches!((self, mode), (Self::Unread, RequestBodyMode::None))
    }
}

impl ServiceBuilder {
    /// Leaves the request body of an operation that takes none unread, as legacy RustFS does: a
    /// `GetObject`, `HeadObject`, listing, `DeleteObject`, `CopyObject` or
    /// `CreateMultipartUpload` carrying a body is answered as it would be without one, and the
    /// body is never polled, so it holds no memory and no claim about it is judged
    /// (rustfs/gateway#1173).
    ///
    /// Off by default: the core reads such a body to its end under the assembly's buffered
    /// ceiling (`413 EntityTooLarge` past it) and refuses one that contradicts its signed digest,
    /// its `Content-MD5` or its checksum. The request head is judged exactly as before — the
    /// signature, the payload declaration and the aws-chunked head — and every operation that
    /// takes a body still reads and verifies it. The body left unread is the host's to drain
    /// behind the answer (`drain_unread_request_bodies`, or RustFS's own early-answer drain); the
    /// gateway's own server closes over it with its lingering close.
    #[must_use]
    pub fn leave_bodies_of_bodyless_operations_unread(mut self) -> Self {
        self.view_policy.bodyless_bodies = BodylessBodies::Unread;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_MODE: [RequestBodyMode; 5] = [
        RequestBodyMode::None,
        RequestBodyMode::Full,
        RequestBodyMode::Streaming,
        RequestBodyMode::PostObject,
        RequestBodyMode::Deferred,
    ];

    /// Positive — under the switch the body of an operation that takes none is left unread.
    #[test]
    fn the_switch_leaves_a_bodyless_operations_body_unread() {
        assert!(BodylessBodies::Unread.leaves_unread(RequestBodyMode::None));
    }

    /// Negative — every operation that takes a body is still read under the switch.
    #[test]
    fn n_every_body_an_operation_takes_is_still_read_under_the_switch() {
        for mode in EVERY_MODE.into_iter().filter(|mode| *mode != RequestBodyMode::None) {
            assert!(!BodylessBodies::Unread.leaves_unread(mode), "{mode:?}");
        }
    }

    /// Negative — without the switch every body is read, the bodyless operation's included.
    #[test]
    fn n_without_the_switch_every_body_is_read() {
        assert_eq!(BodylessBodies::default(), BodylessBodies::Read);
        for mode in EVERY_MODE {
            assert!(!BodylessBodies::Read.leaves_unread(mode), "{mode:?}");
        }
    }
}
