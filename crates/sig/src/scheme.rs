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

//! The frozen authentication scheme: four orthogonal dimensions, not one flat enum.
//!
//! Responsible for: [`AuthScheme`] and its four axes ([`SigFamily`], [`SigLocation`],
//! [`SigIdentity`], [`SigService`]), the parse of the `Authorization` algorithm token and of the
//! credential-scope service, and a redacting `Debug`.
//! NOT responsible for: locating those values in a request (P2-03), checking credential validity,
//! expiry, or the scope-versus-route cross-check (P2-04), or authorization (`rustfs-gateway-core`).
//! Upstream: [`crate::SigParseError`], [`crate::SessionToken`]. Downstream: P2-03's request
//! parser, P2-04's scope validation, and `rustfs-gateway-core`'s authn stage.

use core::fmt;

use crate::error::{SigParseError, Unimplemented};
use crate::secret::SessionToken;

/// The `Authorization` algorithm token for SigV4.
pub const ALGORITHM_SIGV4: &str = "AWS4-HMAC-SHA256";
/// The `Authorization` algorithm token for SigV4a; recognised, refused with `501`.
pub const ALGORITHM_SIGV4A: &str = "AWS4-ECDSA-P256-SHA256";
/// The `Authorization` scheme prefix for SigV2 (`AWS <access-key>:<signature>`).
pub const ALGORITHM_SIGV2_PREFIX: &str = "AWS";

/// The signing algorithm family.
///
/// `#[non_exhaustive]`, so a downstream `match` must keep a wildcard arm. Adding a future family
/// is then a normal change rather than a breaking one — which matters because the alternative is
/// semver pressure against adding a *security-relevant* variant at all:
///
/// ```compile_fail,E0004
/// use rustfs_gateway_sig::SigFamily;
/// fn describe(family: SigFamily) -> &'static str {
///     match family {
///         SigFamily::V2 => "v2",
///         SigFamily::V4 => "v4",
///         SigFamily::V4a => "v4a", // no wildcard arm: does not compile
///     }
/// }
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigFamily {
    /// SigV2: HMAC-SHA1 over a much smaller canonical form.
    V2,
    /// SigV4: `AWS4-HMAC-SHA256`.
    V4,
    /// SigV4a: `AWS4-ECDSA-P256-SHA256`, used by Multi-Region Access Points.
    ///
    /// The variant exists from day one so that adding it later is not a breaking change that
    /// semver pressure turns into "just route it through SigV4". Verification is not implemented;
    /// see [`SigFamily::is_verification_implemented`].
    V4a,
}

impl SigFamily {
    /// Maps an `Authorization` algorithm token onto a family.
    ///
    /// `AWS4-ECDSA-P256-SHA256` parses to [`SigFamily::V4a`] rather than failing, so that the
    /// caller can answer `501 NotImplemented` and can never silently fall through to the SigV4
    /// verifier — a SigV4a request verified as SigV4 is a signature-algorithm downgrade.
    ///
    /// # Errors
    ///
    /// [`SigParseError::UnknownAlgorithm`] for anything else, including differently-cased
    /// spellings of a known token.
    pub fn from_algorithm(token: &str) -> Result<Self, SigParseError> {
        match token {
            ALGORITHM_SIGV4 => Ok(Self::V4),
            ALGORITHM_SIGV4A => Ok(Self::V4a),
            ALGORITHM_SIGV2_PREFIX => Ok(Self::V2),
            _ => Err(SigParseError::UnknownAlgorithm),
        }
    }

    /// Whether this crate can verify signatures of this family.
    ///
    /// `false` for [`SigFamily::V4a`]. A caller that sees `false` must reject with
    /// [`SigParseError::NotImplemented`]; treating it as "try something else" is the downgrade
    /// this method exists to prevent.
    #[must_use]
    pub const fn is_verification_implemented(&self) -> bool {
        matches!(self, Self::V2 | Self::V4)
    }

    /// The rejection to return when this family is recognised but unimplemented.
    ///
    /// # Errors
    ///
    /// [`SigParseError::NotImplemented`] for [`SigFamily::V4a`]; `Ok(())` otherwise.
    pub const fn ensure_implemented(&self) -> Result<(), SigParseError> {
        if self.is_verification_implemented() {
            Ok(())
        } else {
            Err(SigParseError::NotImplemented(Unimplemented::SigV4a))
        }
    }
}

/// Where the signature travels.
///
/// This is a separate axis from [`SigFamily`], because "presigned" is a location, not an
/// algorithm: both SigV2 and SigV4 have header and query forms, and a flat
/// `SigV4Header | SigV4Presigned | SigV2Header | ...` enum has to enumerate the cross product and
/// silently gains a hole every time an axis grows.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigLocation {
    /// The `Authorization` header.
    Header,
    /// Query parameters (`X-Amz-Signature`, ...) — a presigned URL.
    Query,
    /// A browser POST form field, carrying a signed POST policy.
    FormField,
}

impl SigLocation {
    /// Whether this location is a presigned URL.
    #[must_use]
    pub const fn is_presigned(&self) -> bool {
        matches!(self, Self::Query)
    }
}

/// The credential-scope service, cross-checked against the routed operation in P2-04.
///
/// It is not enough to record it: a signature scoped to `sts` must not be accepted for an `s3`
/// operation. Getting this dimension wrong is how a signature minted for one service becomes
/// valid for another (s3s needed three attempts — #207, #208, #418 — to add it at all).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigService {
    /// `s3`
    S3,
    /// `sts`
    Sts,
    /// `s3express`
    S3Express,
    /// `s3-object-lambda`
    S3ObjectLambda,
    /// `s3-outposts`
    S3Outposts,
}

impl SigService {
    /// Parses a credential-scope service name.
    ///
    /// The comparison is exact and case-sensitive: the scope string is signed, so a differently
    /// cased spelling is a different signed string and must not be normalised into a match.
    ///
    /// # Errors
    ///
    /// [`SigParseError::UnknownService`] for any other value.
    pub fn parse(name: &str) -> Result<Self, SigParseError> {
        match name {
            "s3" => Ok(Self::S3),
            "sts" => Ok(Self::Sts),
            "s3express" => Ok(Self::S3Express),
            "s3-object-lambda" => Ok(Self::S3ObjectLambda),
            "s3-outposts" => Ok(Self::S3Outposts),
            _ => Err(SigParseError::UnknownService),
        }
    }

    /// The wire spelling, as it appears in the credential scope.
    ///
    /// These are the same five values as the IR's `service` enum
    /// (`spec/ir.schema.json`), and the cross-check in P2-04 compares the two directly.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Sts => "sts",
            Self::S3Express => "s3express",
            Self::S3ObjectLambda => "s3-object-lambda",
            Self::S3Outposts => "s3-outposts",
        }
    }
}

impl fmt::Display for SigService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which kind of identity the request claims.
///
/// Anonymous is an identity, not a fallback. A public bucket accepting an anonymous `PostObject`
/// is a legitimate request, so anonymity is expressed on this axis instead of being conflated
/// with the POST-policy location — and, critically, an anonymous verdict must never be reachable
/// by "signature verification failed, try anonymous".
#[non_exhaustive]
pub enum SigIdentity {
    /// No credentials were presented.
    Anonymous,
    /// Long-term credentials: an access key with no session token.
    LongTerm,
    /// Temporary credentials: an access key plus an STS session token.
    Session {
        /// The session token. It has no `Debug`, so it cannot be printed by accident.
        token: SessionToken,
    },
}

impl SigIdentity {
    /// Whether the request presented no credentials at all.
    #[must_use]
    pub const fn is_anonymous(&self) -> bool {
        matches!(self, Self::Anonymous)
    }

    /// The session token, when the identity is a temporary one.
    #[must_use]
    pub const fn session_token(&self) -> Option<&SessionToken> {
        match self {
            Self::Session { token } => Some(token),
            _ => None,
        }
    }
}

impl fmt::Debug for SigIdentity {
    /// Hand-written so that the token is named but never printed.
    ///
    /// A derived `Debug` here would put a live session token into every log line that formats an
    /// [`AuthScheme`].
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => f.write_str("Anonymous"),
            Self::LongTerm => f.write_str("LongTerm"),
            Self::Session { .. } => f.write_str("Session { token: <redacted> }"),
        }
    }
}

/// The frozen authentication scheme of a request.
///
/// Four orthogonal axes rather than one flat enum. The flat form cannot express SigV4a, cannot
/// express "presigned with a session token", and cannot express the service dimension at all —
/// and every one of those gaps has produced a real signature-verification defect.
///
/// The familiar flat names are still available as constructors: [`AuthScheme::sigv4_header`],
/// [`AuthScheme::sigv4_presigned`], [`AuthScheme::sigv2_header`], [`AuthScheme::sigv2_presigned`],
/// [`AuthScheme::post_policy`], [`AuthScheme::anonymous`].
#[non_exhaustive]
#[derive(Debug)]
pub struct AuthScheme {
    /// Which algorithm family signed the request.
    pub family: SigFamily,
    /// Where the signature was carried.
    pub location: SigLocation,
    /// Which kind of identity the request claims. Its `Debug` redacts the session token.
    pub identity: SigIdentity,
    /// The credential-scope service, to be cross-checked against the routed operation.
    pub service: SigService,
}

impl AuthScheme {
    /// Builds a scheme from its four axes.
    #[must_use]
    pub fn new(family: SigFamily, location: SigLocation, identity: SigIdentity, service: SigService) -> Self {
        Self {
            family,
            location,
            identity,
            service,
        }
    }

    /// An unauthenticated request. Always [`SigFamily::V4`]-shaped by convention; the family is
    /// irrelevant because nothing is verified, and the identity axis is what callers must branch on.
    #[must_use]
    pub fn anonymous(service: SigService) -> Self {
        Self::new(SigFamily::V4, SigLocation::Header, SigIdentity::Anonymous, service)
    }

    /// SigV4 in the `Authorization` header.
    #[must_use]
    pub fn sigv4_header(identity: SigIdentity, service: SigService) -> Self {
        Self::new(SigFamily::V4, SigLocation::Header, identity, service)
    }

    /// SigV4 in query parameters — a presigned URL.
    #[must_use]
    pub fn sigv4_presigned(identity: SigIdentity, service: SigService) -> Self {
        Self::new(SigFamily::V4, SigLocation::Query, identity, service)
    }

    /// SigV2 in the `Authorization` header.
    #[must_use]
    pub fn sigv2_header(identity: SigIdentity, service: SigService) -> Self {
        Self::new(SigFamily::V2, SigLocation::Header, identity, service)
    }

    /// SigV2 in query parameters.
    #[must_use]
    pub fn sigv2_presigned(identity: SigIdentity, service: SigService) -> Self {
        Self::new(SigFamily::V2, SigLocation::Query, identity, service)
    }

    /// A signed browser POST policy.
    ///
    /// The identity axis stays free: an anonymous POST to a public bucket and a signed POST by a
    /// session identity are both legitimate, and they differ only on that axis.
    #[must_use]
    pub fn post_policy(family: SigFamily, identity: SigIdentity, service: SigService) -> Self {
        Self::new(family, SigLocation::FormField, identity, service)
    }

    /// Whether this crate can verify this scheme today.
    #[must_use]
    pub const fn is_verification_implemented(&self) -> bool {
        self.family.is_verification_implemented()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4a_parses_to_its_own_family_and_stays_unimplemented() {
        let family = SigFamily::from_algorithm(ALGORITHM_SIGV4A).expect("recognised");
        assert_eq!(family, SigFamily::V4a);
        assert!(!family.is_verification_implemented());
        assert_eq!(family.ensure_implemented(), Err(SigParseError::NotImplemented(Unimplemented::SigV4a)));
    }

    #[test]
    fn identity_debug_never_prints_the_token() {
        let token = SessionToken::new("super-secret-token").expect("non-empty");
        let scheme = AuthScheme::sigv4_presigned(SigIdentity::Session { token }, SigService::Sts);
        let rendered = format!("{scheme:?}");
        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("<redacted>"));
    }
}
