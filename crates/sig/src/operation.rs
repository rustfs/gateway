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

//! What an operation tells the floor about itself: its service, its privilege, its allow-list.
//!
//! Responsible for: [`OperationFloor`] and the three fields the floor reads off it, the
//! [`AllowedSchemes`] allow-list and the [`SchemeSlot`] shapes it is written against,
//! [`SigV2Presigned`], and [`FloorConfigError`] — the refusals that happen when a server is built
//! rather than when a request arrives.
//! NOT responsible for: the operation registry itself (P4-04), routing, or any request-time
//! decision — [`crate::SecurityFloor::enforce_scheme_allowed`] is what reads these values.
//! Upstream: [`crate::scheme`]. Downstream: [`crate::floor`], and P4-04's registry.
//!
//! # The two defaults that carry the weight
//!
//! Every operation starts at [`AllowedSchemes::HEADER_ONLY`], so presigned and anonymous access
//! are opt-in. An operation registered by a third party additionally starts **privileged**, so it
//! refuses presigned requests until somebody says otherwise. Both defaults are the wrong way round
//! from convenience and the right way round from consequence: a custom operation that declared
//! nothing and was reachable by everything is attack scenario B (rustfs/rustfs#4845).

use core::fmt;

use crate::scheme::{AuthScheme, SigLocation, SigService};

/// Why a floor configuration was refused at build time.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FloorConfigError {
    /// A region set with no region in it, or with an ill-formed name.
    ///
    /// An empty set would fail every scope cross-check, and the usual repair for "everything is
    /// failing the scope check" is to stop doing the scope check.
    InvalidRegionSet,
    /// A privileged operation was asked to accept presigned requests.
    ///
    /// Refused at registration rather than at request time: rewriting a presigned URL onto an
    /// admin operation is MinIO #5411, and the fence is worth nothing if a registration can lift
    /// it.
    PresignedOnPrivilegedOperation,
}

impl fmt::Display for FloorConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidRegionSet => "the configured region set is empty or contains an ill-formed name",
            Self::PresignedOnPrivilegedOperation => "a privileged operation may not accept presigned requests",
        };
        f.write_str(text)
    }
}

impl core::error::Error for FloorConfigError {}

/// Which of the four authentication shapes a request used.
///
/// Separate from [`AuthScheme`] because an allow-list needs a small closed set to be written
/// against, and because anonymity is a shape an operation opts into rather than an algorithm.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SchemeSlot {
    /// A signature in the `Authorization` header, or a custom scheme's own header.
    Header,
    /// A presigned URL.
    Presigned,
    /// A signed browser POST policy.
    PostPolicy,
    /// No credentials at all.
    Anonymous,
}

impl SchemeSlot {
    /// The slot an [`AuthScheme`] falls into.
    #[must_use]
    pub const fn of(scheme: &AuthScheme) -> Self {
        if scheme.identity.is_anonymous() {
            return Self::Anonymous;
        }
        match scheme.location {
            SigLocation::Query => Self::Presigned,
            SigLocation::FormField => Self::PostPolicy,
            _ => Self::Header,
        }
    }
}

/// The authentication shapes one operation accepts.
///
/// The default is [`AllowedSchemes::HEADER_ONLY`], and the default is what an operation that never
/// said anything gets. Widening is a method call somebody has to write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AllowedSchemes {
    header: bool,
    presigned: bool,
    post_policy: bool,
    anonymous: bool,
}

impl AllowedSchemes {
    /// Header signatures only: no presigned URL, no POST policy, no anonymous access.
    pub const HEADER_ONLY: Self = Self {
        header: true,
        presigned: false,
        post_policy: false,
        anonymous: false,
    };

    /// Whether a shape is accepted.
    #[must_use]
    pub const fn allows(&self, slot: SchemeSlot) -> bool {
        match slot {
            SchemeSlot::Header => self.header,
            SchemeSlot::Presigned => self.presigned,
            SchemeSlot::PostPolicy => self.post_policy,
            SchemeSlot::Anonymous => self.anonymous,
            // `SchemeSlot` is `#[non_exhaustive]`; a shape this build has never heard of is not
            // allowed by an allow-list written before it existed.
            #[allow(unreachable_patterns)] // fail closed on a future variant
            _ => false,
        }
    }

    /// Whether header signatures are accepted.
    #[must_use]
    pub const fn allows_header(&self) -> bool {
        self.header
    }

    /// Whether presigned URLs are accepted.
    #[must_use]
    pub const fn allows_presigned(&self) -> bool {
        self.presigned
    }

    /// Whether signed POST policies are accepted.
    #[must_use]
    pub const fn allows_post_policy(&self) -> bool {
        self.post_policy
    }

    /// Whether the operation is reachable without credentials.
    #[must_use]
    pub const fn allows_anonymous(&self) -> bool {
        self.anonymous
    }
}

impl Default for AllowedSchemes {
    fn default() -> Self {
        Self::HEADER_ONLY
    }
}

/// The three fields of an operation the floor reads, and their defaults.
///
/// P4-04 owns the registry; this type owns the *meaning*. Two defaults are the load-bearing part:
///
/// * every operation starts at [`AllowedSchemes::HEADER_ONLY`], so presigned and anonymous access
///   are opt-in rather than opt-out;
/// * an operation registered by a third party starts **privileged**, so it refuses presigned
///   requests until somebody says otherwise. The conservative default is the wrong way round from
///   convenience and the right way round from consequence: attack scenario B is a custom operation
///   that declared nothing and was reachable by everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperationFloor {
    name: &'static str,
    service: SigService,
    privileged: bool,
    allowed_schemes: AllowedSchemes,
}

impl OperationFloor {
    /// A standard operation: not privileged, header signatures only.
    #[must_use]
    pub const fn builtin(name: &'static str, service: SigService) -> Self {
        Self {
            name,
            service,
            privileged: false,
            allowed_schemes: AllowedSchemes::HEADER_ONLY,
        }
    }

    /// A standard operation whose protocol specification explicitly permits presigned URLs.
    #[must_use]
    pub const fn builtin_presigned(name: &'static str, service: SigService) -> Self {
        Self {
            name,
            service,
            privileged: false,
            allowed_schemes: AllowedSchemes {
                header: true,
                presigned: true,
                post_policy: false,
                anonymous: false,
            },
        }
    }

    /// An operation registered by a third party: **privileged by default**, header signatures only.
    #[must_use]
    pub const fn custom(name: &'static str, service: SigService) -> Self {
        Self {
            name,
            service,
            privileged: true,
            allowed_schemes: AllowedSchemes::HEADER_ONLY,
        }
    }

    /// Marks the operation privileged: admin, configuration, credential issuance.
    ///
    /// A privileged operation refuses every presigned request, whatever its allow-list says.
    #[must_use]
    pub const fn mark_privileged(mut self) -> Self {
        self.privileged = true;
        self
    }

    /// Accepts presigned URLs.
    ///
    /// # Errors
    ///
    /// [`FloorConfigError::PresignedOnPrivilegedOperation`] for a privileged operation.
    pub const fn allow_presigned(mut self) -> Result<Self, FloorConfigError> {
        if self.privileged {
            return Err(FloorConfigError::PresignedOnPrivilegedOperation);
        }
        self.allowed_schemes.presigned = true;
        Ok(self)
    }

    /// Accepts signed browser POST policies.
    #[must_use]
    pub const fn allow_post_policy(mut self) -> Self {
        self.allowed_schemes.post_policy = true;
        self
    }

    /// Makes the operation reachable without credentials.
    ///
    /// The name is long because the obligation is real: an anonymously reachable operation must
    /// appear in the startup security-posture report, which is a log line and deliberately not an
    /// HTTP endpoint (an unauthenticated diagnostic endpoint is MinIO CVE-2023-28432).
    /// [`OperationFloor::allows_anonymous`] is what that report reads.
    #[must_use]
    pub const fn allow_anonymous_after_listing_in_the_posture_report(mut self) -> Self {
        self.allowed_schemes.anonymous = true;
        self
    }

    /// The operation name, as the posture report prints it.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The service this operation belongs to — the value a credential scope must name.
    #[must_use]
    pub const fn service(&self) -> SigService {
        self.service
    }

    /// Whether this operation is on the privileged surface.
    #[must_use]
    pub const fn privileged(&self) -> bool {
        self.privileged
    }

    /// The shapes this operation accepts.
    #[must_use]
    pub const fn allowed_schemes(&self) -> AllowedSchemes {
        self.allowed_schemes
    }

    /// Whether this operation is reachable without credentials.
    #[must_use]
    pub const fn allows_anonymous(&self) -> bool {
        self.allowed_schemes.anonymous
    }
}

/// Whether SigV2 presigned URLs are accepted at all.
///
/// Off by default and separately switchable, because SigV2's presigned form is the one an attacker
/// rewrites: MinIO #5411 was a SigV2 presigned URL edited to reach an admin operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SigV2Presigned {
    /// Refused, whatever the operation's allow-list says.
    #[default]
    Disabled,
    /// Accepted as far as the floor is concerned. Verification is still P2-06's.
    Enabled,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::floor::SecurityFloor;
    use crate::scheme::SigFamily;
    use crate::verdict::AuthError;

    /// Negative — the allow-list fails closed on a shape it has never heard of.
    #[test]
    fn the_default_allow_list_admits_only_header_signatures() {
        let allowed = AllowedSchemes::default();
        assert!(allowed.allows(SchemeSlot::Header));
        for slot in [SchemeSlot::Presigned, SchemeSlot::PostPolicy, SchemeSlot::Anonymous] {
            assert!(!allowed.allows(slot), "{slot:?} must be opt-in");
        }
    }

    /// Negative — a privileged operation cannot be given presigned access by any route.
    #[test]
    fn a_privileged_operation_cannot_be_widened_to_presigned() {
        let operation = OperationFloor::builtin("AdminSetConfig", SigService::S3).mark_privileged();
        assert_eq!(operation.allow_presigned().err(), Some(FloorConfigError::PresignedOnPrivilegedOperation));
        // And marking it privileged afterwards still refuses the request, allow-list or not.
        let widened = OperationFloor::builtin("Late", SigService::S3)
            .allow_presigned()
            .expect("not privileged yet")
            .mark_privileged();
        assert!(widened.allowed_schemes().allows_presigned());
        assert_eq!(
            SecurityFloor::new()
                .enforce_scheme_allowed(&widened, SchemeSlot::Presigned, SigFamily::V4)
                .err(),
            Some(AuthError::AccessDenied)
        );
    }
}
