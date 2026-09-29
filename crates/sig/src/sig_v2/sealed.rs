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

//! The post-floor SigV2 request: what the floor hands to a SigV2 verifier, and nothing else.
//!
//! Responsible for: [`SealedSigV2`] — the value [`crate::SecurityFloor::admit`] produces for an
//! admitted SigV2 request, carrying the parsed credential, the location, the receipts the floor
//! already minted, and the borrowed request.
//! NOT responsible for: building or comparing a signature (that is [`super::string_to_sign`] and
//! [`crate::Signature::ct_verify`]), or deciding whether the credential exists (that is the
//! deployment's credential source).
//! Upstream: [`crate::SecurityFloor`]. Downstream: `rustfs-gateway`'s authentication stage.
//!
//! # Why this is a separate type from [`crate::SealedAws`]
//!
//! Because the alternative is the downgrade. If a SigV2 request were admitted as a `SealedAws`,
//! the SigV4 verifier would receive it, read an `Authorization` header it cannot parse, and answer
//! from a path that was never written with SigV2 in mind. A distinct type means the SigV4 verifier
//! is never handed a SigV2 request at all — the same argument [`crate::CustomAuthRequest`] makes
//! for third-party schemes, applied to the second AWS algorithm.
//!
//! There is no public constructor and no conversion between the two. An assembly that does not
//! know what to do with a [`SealedSigV2`] cannot turn it into something it does know: it can only
//! refuse, which is the answer a request whose scheme nothing here handles has to get.

use core::fmt;

use crate::clock::{ClockChecked, RequestNow};
use crate::floor::WireView;
use crate::presigned_expiry::PresignedExpiryRule;
use crate::scheme::SigService;
use crate::signature::Signature;
use crate::verdict::CredentialPresence;

use super::SigV2Authorization;
use super::string_to_sign::SigV2Mode;

/// A SigV2 request the floor has admitted.
///
/// Holding one means the floor already ran for this request: duplicate signature parameters were
/// refused (H6), the credential surface was recorded (H4), the operation's allow-list accepted the
/// shape (H3), the [`SigV2Policy`](super::SigV2Policy) permits this location, the `Authorization` grammar or the
/// presigned parameter triple parsed, and — for header authentication — the timestamp passed the
/// skew window (H1). For a presigned URL the absolute `Expires` instant has been checked against
/// the same snapshot (SigV2's form of H2).
///
/// What is left is the string-to-sign and one [`crate::Signature::ct_verify`].
pub struct SealedSigV2<'a> {
    view: WireView<'a>,
    mode: SigV2Mode,
    presented: SigV2Authorization,
    clock: Option<ClockChecked>,
    now: RequestNow,
    expires_at: Option<u64>,
    presence: CredentialPresence,
    expected_service: SigService,
    expiry_rule: PresignedExpiryRule,
}

impl<'a> SealedSigV2<'a> {
    /// Header authentication, with the skew receipt the floor produced.
    pub(crate) const fn header(
        view: WireView<'a>,
        presented: SigV2Authorization,
        clock: ClockChecked,
        presence: CredentialPresence,
        expected_service: SigService,
    ) -> Self {
        Self {
            view,
            mode: SigV2Mode::HeaderAuth,
            presented,
            clock: Some(clock),
            now: clock.now(),
            expires_at: None,
            presence,
            expected_service,
            expiry_rule: PresignedExpiryRule::Aws,
        }
    }

    /// A presigned URL, with the absolute expiry instant the floor checked.
    ///
    /// There is no clock receipt here because a SigV2 presigned URL carries no signing timestamp
    /// to check one against: `Expires` *is* the whole time rule, and it was applied against the
    /// same `now` this value carries.
    pub(crate) const fn presigned(
        view: WireView<'a>,
        presented: SigV2Authorization,
        now: RequestNow,
        expires_at: u64,
        presence: CredentialPresence,
        expected_service: SigService,
    ) -> Self {
        Self {
            view,
            mode: SigV2Mode::PresignedUrl,
            presented,
            clock: None,
            now,
            expires_at: Some(expires_at),
            presence,
            expected_service,
            expiry_rule: PresignedExpiryRule::Aws,
        }
    }

    /// The same request, with the presigned-lifetime rule the floor read its `Expires` under, so
    /// the string-to-sign accepts exactly the spellings the floor did.
    #[must_use]
    pub(crate) const fn with_expiry_rule(mut self, rule: PresignedExpiryRule) -> Self {
        self.expiry_rule = rule;
        self
    }

    /// The presigned-lifetime rule the floor admitted this request under.
    #[must_use]
    pub const fn expiry_rule(&self) -> PresignedExpiryRule {
        self.expiry_rule
    }

    /// A browser POST form whose credential fields parsed and whose operation allows POST policy.
    ///
    /// Expiration and condition enforcement remain in the shared POST-policy authority; this
    /// constructor only seals the authentication surface away from the SigV4 verifier.
    pub(crate) const fn post_policy(
        view: WireView<'a>,
        presented: SigV2Authorization,
        now: RequestNow,
        presence: CredentialPresence,
        expected_service: SigService,
    ) -> Self {
        Self {
            view,
            mode: SigV2Mode::PostPolicy,
            presented,
            clock: None,
            now,
            expires_at: None,
            presence,
            expected_service,
            expiry_rule: PresignedExpiryRule::Aws,
        }
    }

    /// The request as it arrived.
    #[must_use]
    pub const fn view(&self) -> WireView<'a> {
        self.view
    }

    /// Which SigV2 location carried the signature. It also selects the `{Date}` slot.
    #[must_use]
    pub const fn mode(&self) -> SigV2Mode {
        self.mode
    }

    /// The access key id the request claims. A public identifier, not key material.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        self.presented.access_key_id()
    }

    /// The presented signature, for [`super::verify_presented`] and nothing else.
    #[must_use]
    pub fn presented(&self) -> &Signature {
        self.presented.presented()
    }

    /// The skew receipt, for header authentication. `None` for presigned and POST-policy forms.
    #[must_use]
    pub const fn clock(&self) -> Option<ClockChecked> {
        self.clock
    }

    /// The request's clock snapshot — the same instant every floor rule for this request saw.
    #[must_use]
    pub const fn now(&self) -> RequestNow {
        self.now
    }

    /// When a presigned URL stops working, as the absolute Unix second it was signed with.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> Option<u64> {
        self.expires_at
    }

    /// Which authentication surfaces the request touched.
    #[must_use]
    pub const fn presence(&self) -> CredentialPresence {
        self.presence
    }

    /// The service the routed operation belongs to.
    ///
    /// SigV2 has no credential scope, so there is nothing to cross-check it against — the value is
    /// carried so that the resulting [`crate::AuthScheme`] names the service the operation
    /// actually belongs to rather than a constant.
    #[must_use]
    pub const fn expected_service(&self) -> SigService {
        self.expected_service
    }
}

impl fmt::Debug for SealedSigV2<'_> {
    /// Hand-written and header-free, for the same reason as [`crate::SealedAws`]: a derived
    /// `Debug` would render every header value, one of which is the credential.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedSigV2")
            .field("mode", &self.mode)
            .field("expires_at", &self.expires_at)
            .field("expected_service", &self.expected_service)
            .finish_non_exhaustive()
    }
}
