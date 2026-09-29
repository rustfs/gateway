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

//! The RustFS-profile switch that leaves the signed `x-amz-content-sha256` of a request without a
//! body uncompared, as legacy RustFS leaves it (rustfs/gateway#1099).
//!
//! Responsible for: [`ServiceBuilder::accept_mismatched_payload_digests_without_a_body`] and
//! [`BodylessDigest::apply`], which the pipeline applies to the digest a body read is held to.
//! NOT responsible for: reading the declaration (`crate::payload_header`), the comparison itself
//! (`crate::gate` and `crate::request_body`), or any operation that takes a body.
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, through
//! `super::view_policy::ViewPolicy`.
//!
//! # What legacy RustFS does
//!
//! The legacy stack compares a signed digest only while it reads a body, and it reads none for an
//! operation that takes none. A header-signed `GetObject`, `HeadObject`, `ListObjectsV2` or
//! `DeleteObject` whose `x-amz-content-sha256` is a well-formed digest of anything but the empty
//! body is served (`200`, `200`, `200`, `204`, observed against a legacy RustFS build on rustfs/rustfs
//! `e870a6d25b`); the gateway compares it with the empty body and answers `400
//! XAmzContentSHA256Mismatch`, as AWS does. An operation that takes a body is compared on both
//! stacks: a `PutObject` is `400 BadDigest` on both, and a buffered one such as
//! `PutObjectTagging` is `500 InternalError` on legacy and `400` here.

use rustfs_gateway_core::RequestBodyMode;

use super::ServiceBuilder;
use crate::gate::BodyDigestObligation;

/// Whether the signed digest of a request without a body is compared with its (empty) body.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BodylessDigest {
    /// Compared, as for every other request.
    #[default]
    Compared,
    /// Left uncompared, as legacy RustFS leaves it.
    Ignored,
}

impl BodylessDigest {
    /// The digest a body read in `mode` is held to: `digest`, or none for an operation that takes
    /// no body when this assembly reads such a request as legacy RustFS does.
    pub(crate) const fn apply(self, mode: RequestBodyMode, digest: BodyDigestObligation) -> BodyDigestObligation {
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS never compares the signed
        // `x-amz-content-sha256` of a request that carries no body, so a signed read or delete
        // declaring the digest of some other payload is served where AWS answers
        // `XAmzContentSHA256Mismatch`. Nothing is lost, since there is no body to protect, but the
        // client's mistake goes unreported. Kept so the clients RustFS serves today keep working;
        // the intended future behaviour is the core's comparison.
        match (self, mode) {
            (Self::Ignored, RequestBodyMode::None) => BodyDigestObligation::None,
            _ => digest,
        }
    }
}

impl ServiceBuilder {
    /// Leaves the signed `x-amz-content-sha256` of a request to an operation that takes no body
    /// uncompared, as legacy RustFS does: a header-signed `GetObject`, `HeadObject`, listing or
    /// `DeleteObject` declaring the digest of another payload is served instead of answered `400
    /// XAmzContentSHA256Mismatch` (rustfs/gateway#1099).
    ///
    /// Off by default: the core compares the declaration with the empty body, as AWS does. The
    /// signature still covers the declared value, and every operation that takes a body still
    /// compares it.
    #[must_use]
    pub fn accept_mismatched_payload_digests_without_a_body(mut self) -> Self {
        self.view_policy.bodyless_digest = BodylessDigest::Ignored;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: BodyDigestObligation = BodyDigestObligation::Sha256([7; 32]);

    /// Positive — under the switch a request to an operation that takes no body is held to no
    /// digest.
    #[test]
    fn the_switch_drops_the_digest_of_a_bodyless_operation() {
        assert_eq!(BodylessDigest::Ignored.apply(RequestBodyMode::None, DIGEST), BodyDigestObligation::None);
    }

    /// Negative — every operation that takes a body keeps its digest under the switch, and nothing
    /// changes without it.
    #[test]
    fn n_every_body_keeps_its_digest() {
        for mode in [
            RequestBodyMode::Streaming,
            RequestBodyMode::Full,
            RequestBodyMode::Deferred,
            RequestBodyMode::PostObject,
        ] {
            assert_eq!(BodylessDigest::Ignored.apply(mode, DIGEST), DIGEST, "{mode:?}");
        }
        for mode in [
            RequestBodyMode::None,
            RequestBodyMode::Streaming,
            RequestBodyMode::Full,
            RequestBodyMode::Deferred,
            RequestBodyMode::PostObject,
        ] {
            assert_eq!(BodylessDigest::Compared.apply(mode, DIGEST), DIGEST, "{mode:?}");
        }
        assert_eq!(BodylessDigest::default(), BodylessDigest::Compared);
    }
}
