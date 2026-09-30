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

//! The signature material a SigV4 request presented, read off whichever surface carried it.
//!
//! Responsible for: [`Presented`], one type for the header, presigned and POST-form surfaces, and
//! the reading each surface gets under the authenticator's credential rule.
//! NOT responsible for: checking anything it reads — the scope cross-check, the lookup and the
//! comparison are the parent's `SigV4Authenticator`, split out here at the 800-line limit.
//! Upstream: `rustfs-gateway-sig`'s parsers. Downstream: `super::SigV4Authenticator`.

use rustfs_gateway_sig::{
    AUTHORIZATION_HEADER, AmzDate, AuthError, CredentialScope, PostPolicy, PostPolicyError, PostPolicyLimits, PresignedParams,
    RegionRule, SealedAws, SessionToken, SigLocation, SigV4Authorization, Signature,
};

/// The signature material the client presented, from whichever surface carried it.
///
/// One type for both surfaces so that the verification body has no `match` on the location running
/// through the middle of it — the two differ in where the values are read and in nothing else.
pub(super) enum Presented {
    Header(Box<SigV4Authorization>),
    Query(Box<PresignedParams>),
    Form(Box<PostPolicy>),
}

impl Presented {
    pub(super) fn read(sealed: &SealedAws<'_>, location: SigLocation, rule: RegionRule) -> Result<Self, AuthError> {
        match location {
            SigLocation::Query => Ok(Self::Query(Box::new(PresignedParams::parse_with(&sealed.view().query(), rule)?))),
            SigLocation::FormField => {
                let fields = sealed.view().form_fields().ok_or(AuthError::AuthorizationHeaderMalformed)?;
                let policy = PostPolicy::parse_with(fields, "", PostPolicyLimits::default(), sealed.clock().now(), rule)
                    .map_err(PostPolicyError::auth_error)?;
                Ok(Self::Form(Box::new(policy)))
            }
            SigLocation::Header => {
                let raw = sealed
                    .view()
                    .headers()
                    .get(AUTHORIZATION_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                Ok(Self::Header(Box::new(SigV4Authorization::parse_with(raw, rule)?)))
            }
            _ => Err(AuthError::AuthorizationHeaderMalformed),
        }
    }

    pub(super) fn scope(&self) -> &CredentialScope {
        match self {
            Self::Header(parsed) => parsed.scope(),
            Self::Query(parsed) => parsed.scope(),
            Self::Form(policy) => policy.scope(),
        }
    }

    pub(super) fn canonical_parts(&self) -> Option<(&str, &Signature)> {
        match self {
            Self::Header(parsed) => Some((parsed.signed_headers(), parsed.signature())),
            Self::Query(parsed) => Some((parsed.signed_headers(), parsed.signature())),
            Self::Form(_) => None,
        }
    }

    pub(super) fn session_token(&self) -> Option<&SessionToken> {
        let Self::Form(policy) = self else { return None };
        policy.session_token()
    }

    /// The timestamp the string-to-sign is dated with.
    ///
    /// For a presigned URL it is the one in the query; for a header-signed request it is the
    /// receipt the skew check produced, which is the same value the floor validated.
    pub(super) fn signed_at(&self, sealed: &SealedAws<'_>) -> AmzDate {
        match self {
            Self::Header(_) => sealed.clock().signed_at(),
            Self::Query(parsed) => parsed.date(),
            Self::Form(policy) => policy.signed_at(),
        }
    }
}
