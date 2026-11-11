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
//! Responsible for: [`OperationFloor`] and the fields the floor reads off it, the
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

use crate::bearer::QueryBearerClaim;
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
    /// Set by [`OperationFloor::require_sigv4_under_every_policy`].
    sigv4_required: bool,
    /// Set by [`OperationFloor::refuse_sigv2_under_every_policy`]. Read only through
    /// [`OperationFloor::refuses_sigv2_under_every_policy`], which `sigv4_required` also implies.
    sigv2_refused: bool,
    bearer: Option<QueryBearerClaim>,
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
            sigv4_required: false,
            sigv2_refused: false,
            bearer: None,
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
            sigv4_required: false,
            sigv2_refused: false,
            bearer: None,
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
            sigv4_required: false,
            sigv2_refused: false,
            bearer: None,
        }
    }

    /// Admits SigV4 only, header or presigned, as the allow-list says. Every other admission is
    /// refused whatever the security floor or the allow-list says:
    ///
    /// * a request that presented no credentials, under every [`AnonymousPolicy`], the
    ///   service-level [`AnonymousPolicy::DelegateToAuthorizer`] included;
    /// * a SigV2 request, header or presigned, under every [`crate::SigV2Policy`];
    /// * a request admitted by a registered custom scheme
    ///   ([`crate::SecurityFloor::with_custom_schemes`]);
    /// * a query bearer token ([`OperationFloor::with_query_bearer_claim`]). Registering an
    ///   operation whose floor combines the two is refused at build time by the registry, and the
    ///   floor refuses the token at request time as well.
    ///
    /// Only narrows. It is for a non-privileged operation — one that admits a presigned URL, which
    /// a privileged one cannot — whose owner requires a header or query SigV4 signature: without
    /// it, such an operation becomes anonymously reachable the moment a deployment delegates
    /// anonymous requests to its authorizer, and SigV2-reachable the moment it enables SigV2
    /// compatibility (rustfs/gateway#1576).
    #[must_use]
    pub const fn require_sigv4_under_every_policy(mut self) -> Self {
        self.sigv4_required = true;
        self
    }

    /// Refuses a SigV2 request — header, presigned URL or POST policy — under every
    /// [`crate::SigV2Policy`], at the floor and before its credential is parsed or resolved, with
    /// the [`crate::AuthError::AccessDenied`] that
    /// [`OperationFloor::require_sigv4_under_every_policy`] answers SigV2 with (ADR-0050).
    ///
    /// The narrower sibling of that requirement: it changes nothing else. SigV4 is admitted as the
    /// allow-list says; a request that presented no AWS credential — anonymous, a query bearer token
    /// ([`OperationFloor::with_query_bearer_claim`]) or a registered custom scheme — is decided
    /// exactly as without it. It is for an operation that must stay reachable without a signature
    /// but whose parameters SigV2 would not cover: SigV2 signs neither the body nor most of the
    /// query, so a SigV2 signature does not bind what such an operation acts on
    /// (rustfs/gateway#1592).
    ///
    /// Only narrows, and combines with the SigV4 requirement in either order: the stronger rule
    /// stands, and [`OperationFloor::requires_sigv4_under_every_policy`] is unchanged by it.
    #[must_use]
    pub const fn refuse_sigv2_under_every_policy(mut self) -> Self {
        self.sigv2_refused = true;
        self
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
    /// [`crate::SecurityFloor::admits_anonymous`] is what that report reads. A deployment whose
    /// `Authorizer` decides every anonymous request can delegate at service level instead, with
    /// [`crate::SecurityFloor::delegate_anonymous_to_authorizer_after_listing_in_the_posture_report`].
    #[must_use]
    pub const fn allow_anonymous_after_listing_in_the_posture_report(mut self) -> Self {
        self.allowed_schemes.anonymous = true;
        self
    }

    /// Admits a request that presents no AWS credential surface by `claim`'s query bearer token,
    /// which only the facade's explicitly installed [`crate::BearerTokenVerifier`] can turn into a
    /// verdict (ADR-0042). Without that verifier every such request is refused; nothing here makes
    /// the operation anonymous, and a signed request keeps its signature path.
    #[must_use]
    pub const fn with_query_bearer_claim(mut self, claim: QueryBearerClaim) -> Self {
        self.bearer = Some(claim);
        self
    }

    /// The query bearer claim this operation declared, when it declared one.
    #[must_use]
    pub const fn query_bearer_claim(&self) -> Option<QueryBearerClaim> {
        self.bearer
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

    /// Whether this operation admits SigV4 only, refusing anonymous and SigV2 requests under every
    /// policy ([`OperationFloor::require_sigv4_under_every_policy`]).
    #[must_use]
    pub const fn requires_sigv4_under_every_policy(&self) -> bool {
        self.sigv4_required
    }

    /// Whether this operation refuses every SigV2 request under every policy: it called
    /// [`OperationFloor::refuse_sigv2_under_every_policy`], or it requires SigV4 under every
    /// policy, which implies it. The one predicate the floor reads for the SigV2 refusal.
    #[must_use]
    pub const fn refuses_sigv2_under_every_policy(&self) -> bool {
        self.sigv2_refused || self.sigv4_required
    }

    /// Whether this operation admits a request that presented nothing, under `policy`.
    ///
    /// Its own opt-in always counts. Under [`AnonymousPolicy::DelegateToAuthorizer`], so does
    /// every non-privileged operation. A privileged one still has to opt in itself (ADR-0021).
    /// An operation that requires SigV4 under every policy admits none, whatever either of those
    /// says.
    #[must_use]
    pub const fn admits_anonymous_under(&self, policy: AnonymousPolicy) -> bool {
        !self.sigv4_required
            && (self.allowed_schemes.anonymous || (matches!(policy, AnonymousPolicy::DelegateToAuthorizer) && !self.privileged))
    }
}

/// Which operations admit a presigned URL (rustfs/backlog#1677, R7).
///
/// The default is [`PresignedPolicy::PerOperation`], and a floor nobody configured has it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PresignedPolicy {
    /// Only an operation that called [`OperationFloor::allow_presigned`] admits one.
    #[default]
    PerOperation,
    /// Every non-privileged operation admits one, as a deployment that authorizes every request
    /// itself (RustFS) does. A privileged operation still refuses every presigned URL, and cannot
    /// be made to accept one.
    EveryStandardOperation,
}

impl OperationFloor {
    /// Whether this operation admits a presigned URL under `policy`.
    ///
    /// A privileged operation never does, under either policy: rewriting a presigned URL onto an
    /// admin operation is MinIO #5411. Otherwise its own opt-in counts, and under
    /// [`PresignedPolicy::EveryStandardOperation`] so does being a standard operation at all.
    #[must_use]
    pub const fn admits_presigned_under(&self, policy: PresignedPolicy) -> bool {
        !self.privileged && (self.allowed_schemes.presigned || matches!(policy, PresignedPolicy::EveryStandardOperation))
    }
}

/// Who decides a request that presented no credentials (ADR-0021).
///
/// The default is [`AnonymousPolicy::PerOperation`], and a floor nobody configured has it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum AnonymousPolicy {
    /// Only an operation that called
    /// [`OperationFloor::allow_anonymous_after_listing_in_the_posture_report`] admits one.
    #[default]
    PerOperation,
    /// Every non-privileged operation admits one, and the `Authorizer` decides. A privileged
    /// operation still has to opt in itself.
    DelegateToAuthorizer,
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

    /// The presign-admitting floor that admits SigV4 only (rustfs/gateway#1576).
    fn signed_only() -> OperationFloor {
        OperationFloor::builtin_presigned("example:SignedOnly", SigService::S3).require_sigv4_under_every_policy()
    }

    /// Negative — an operation that requires SigV4 refuses a SigV2 header signature and a SigV2
    /// presigned URL on a floor that accepts both; the same floor without the refusal is the
    /// control that admits them.
    #[test]
    fn an_operation_requiring_sigv4_refuses_sigv2_under_every_policy() {
        let sigv2 = SecurityFloor::new().enable_sigv2_presigned_compatibility();
        let control = OperationFloor::builtin_presigned("example:SignedOnly", SigService::S3);
        for slot in [SchemeSlot::Header, SchemeSlot::Presigned] {
            assert_eq!(
                sigv2.enforce_scheme_allowed(&signed_only(), slot, SigFamily::V2).err(),
                Some(AuthError::AccessDenied),
                "{slot:?}"
            );
            assert_eq!(
                SecurityFloor::new()
                    .enforce_scheme_allowed(&signed_only(), slot, SigFamily::V2)
                    .err(),
                Some(AuthError::AccessDenied),
                "{slot:?}"
            );
            assert_eq!(sigv2.enforce_scheme_allowed(&control, slot, SigFamily::V2), Ok(()), "{slot:?}");
        }
    }

    /// Negative — an operation that requires SigV4 admits no anonymous request when the
    /// deployment delegates anonymous requests to its authorizer, and none when it opted in
    /// itself; the same floor without the refusal is the control that does admit one.
    #[test]
    fn an_operation_requiring_sigv4_admits_no_anonymous_request() {
        let delegating = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
        for floor in [SecurityFloor::new(), delegating.clone()] {
            for operation in [
                signed_only(),
                signed_only().allow_anonymous_after_listing_in_the_posture_report(),
            ] {
                assert!(operation.requires_sigv4_under_every_policy());
                assert!(!floor.admits_anonymous(&operation), "{floor:?}");
                assert_eq!(
                    floor
                        .enforce_scheme_allowed(&operation, SchemeSlot::Anonymous, SigFamily::V4)
                        .err(),
                    Some(AuthError::AccessDenied),
                    "{floor:?}"
                );
            }
        }
        let control = OperationFloor::builtin_presigned("example:SignedOnly", SigService::S3);
        assert!(!control.requires_sigv4_under_every_policy());
        assert!(delegating.admits_anonymous(&control));
        assert!(SecurityFloor::new().admits_anonymous(&control.allow_anonymous_after_listing_in_the_posture_report()));
    }

    /// Negative — the narrowing leaves a privileged operation privileged: still no presigned URL.
    #[test]
    fn requiring_sigv4_does_not_admit_a_presigned_url_to_a_privileged_operation() {
        let operation = OperationFloor::custom("example:Admin", SigService::S3).require_sigv4_under_every_policy();
        assert!(operation.privileged());
        assert_eq!(
            SecurityFloor::new()
                .admit_presigned_on_every_standard_operation_after_listing_in_the_posture_report()
                .enforce_scheme_allowed(&operation, SchemeSlot::Presigned, SigFamily::V4)
                .err(),
            Some(AuthError::AccessDenied)
        );
    }

    /// Negative — refusing SigV2 refuses both SigV2 locations and the POST policy under every SigV2
    /// policy, and leaves the anonymous opt-in and the delegation predicate alone; the same floor
    /// without the rule is the control that admits them (rustfs/gateway#1592).
    #[test]
    fn an_operation_refusing_sigv2_refuses_every_sigv2_slot_and_nothing_else() {
        let refusing = OperationFloor::builtin_presigned("example:NoSigV2", SigService::S3)
            .allow_post_policy()
            .refuse_sigv2_under_every_policy();
        let control = OperationFloor::builtin_presigned("example:NoSigV2", SigService::S3).allow_post_policy();
        assert!(refusing.refuses_sigv2_under_every_policy());
        assert!(!refusing.requires_sigv4_under_every_policy(), "refusing SigV2 is not requiring SigV4");
        assert!(!control.refuses_sigv2_under_every_policy());
        let sigv2 = SecurityFloor::new().enable_sigv2_presigned_compatibility();
        for slot in [SchemeSlot::Header, SchemeSlot::Presigned, SchemeSlot::PostPolicy] {
            assert_eq!(
                sigv2.enforce_scheme_allowed(&refusing, slot, SigFamily::V2).err(),
                Some(AuthError::AccessDenied),
                "{slot:?}"
            );
            assert_eq!(sigv2.enforce_scheme_allowed(&control, slot, SigFamily::V2), Ok(()), "{slot:?}");
            assert_eq!(sigv2.enforce_scheme_allowed(&refusing, slot, SigFamily::V4), Ok(()), "{slot:?}");
        }
        let delegating = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
        assert!(delegating.admits_anonymous(&refusing), "the rule does not touch anonymous admission");
    }

    /// Negative — requiring SigV4 implies refusing SigV2, and declaring both, in either order,
    /// keeps the stronger rule: neither call weakens the other.
    #[test]
    fn requiring_sigv4_implies_refusing_sigv2_in_either_order() {
        let base = OperationFloor::builtin_presigned("example:Both", SigService::S3);
        assert!(base.require_sigv4_under_every_policy().refuses_sigv2_under_every_policy());
        for both in [
            base.require_sigv4_under_every_policy().refuse_sigv2_under_every_policy(),
            base.refuse_sigv2_under_every_policy().require_sigv4_under_every_policy(),
        ] {
            assert!(both.requires_sigv4_under_every_policy());
            assert!(both.refuses_sigv2_under_every_policy());
            assert!(!both.admits_anonymous_under(AnonymousPolicy::DelegateToAuthorizer));
        }
    }

    /// Positive — the narrowing leaves SigV4 alone: header signatures and presigned URLs are
    /// admitted as before, on the default floor and on the delegating one.
    #[test]
    fn requiring_sigv4_keeps_sigv4_header_and_presigned_admitted() {
        let delegating = SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report();
        for floor in [SecurityFloor::new(), delegating] {
            assert!(floor.admits_presigned(&signed_only()));
            for slot in [SchemeSlot::Header, SchemeSlot::Presigned] {
                assert_eq!(floor.enforce_scheme_allowed(&signed_only(), slot, SigFamily::V4), Ok(()), "{slot:?}");
            }
        }
    }
}
