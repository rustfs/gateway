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
//! the reading and session admission each surface gets under the authenticator's credential rule.
//! NOT responsible for: scope cross-checks, credential lookup or signature comparison — those
//! remain the parent's `SigV4Authenticator`, split out here at the 800-line limit.
//! Upstream: `rustfs-gateway-sig`'s parsers. Downstream: `super::SigV4Authenticator`.

use rustfs_gateway_sig::{
    AUTHORIZATION_HEADER, AmzDate, AuthError, CredentialScope, PostPolicy, PostPolicyError, PostPolicyLimits, PresignedParams,
    RegionRule, SealedAws, SessionToken, SigLocation, SigV4Authorization, Signature,
};

pub(super) struct PostAuthentication<'a> {
    limits: Option<PostPolicyLimits>,
    filename: Option<&'a str>,
}

impl PostAuthentication<'_> {
    pub(super) const EMPTY: Self = Self {
        limits: None,
        filename: None,
    };
}

impl<'a> super::Authentication<'a> {
    pub(crate) const fn with_post_policy_limits(mut self, limits: Option<PostPolicyLimits>) -> Self {
        self.post_form.limits = limits;
        self
    }

    pub(crate) const fn with_post_form(mut self, limits: Option<PostPolicyLimits>, filename: Option<&'a str>) -> Self {
        self.post_form.limits = limits;
        self.post_form.filename = filename;
        self
    }

    pub(crate) const fn with_verbose_signature_errors(mut self, enabled: bool) -> Self {
        self.verbose_signature_errors = enabled;
        self
    }
}

/// The signature material the client presented, from whichever surface carried it.
///
/// One carrier for the signature surfaces keeps their reading and session checks outside the
/// shared verification body. Header and query forms also carry the 32-byte presented signature so
/// the authenticator can publish the verified seed directly into [`super::ChunkVerification`]
/// without downstream re-parsing of wire strings.
pub(super) enum Presented<'a> {
    Header(Box<SigV4Authorization>, [u8; 32]),
    Query(Box<PresignedParams>, [u8; 32]),
    Form(Box<PostPolicy>),
    UnroutedForm(&'a rustfs_gateway_sig::UnroutedPostPolicy),
}

impl<'a> Presented<'a> {
    pub(super) fn read(
        sealed: &SealedAws<'_>,
        location: SigLocation,
        rule: RegionRule,
        unrouted: Option<&'a rustfs_gateway_sig::UnroutedPostPolicy>,
        form: &PostAuthentication<'_>,
    ) -> Result<Self, AuthError> {
        match location {
            SigLocation::Query => {
                let query = sealed.view().query();
                let parsed = PresignedParams::parse_with(&query, rule)?;
                let raw_signature = query
                    .decoded_value(rustfs_gateway_sig::X_AMZ_SIGNATURE)
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?;
                let seed = decode_hex_lower_32(&raw_signature).ok_or(AuthError::AuthorizationHeaderMalformed)?;
                Ok(Self::Query(Box::new(parsed), seed))
            }
            SigLocation::FormField => {
                if let Some(policy) = unrouted {
                    return Ok(Self::UnroutedForm(policy));
                }

                let fields = sealed.view().form_fields().ok_or(AuthError::AuthorizationHeaderMalformed)?;
                let policy = PostPolicy::parse_with(
                    fields,
                    form.filename.unwrap_or_default(),
                    form.limits.unwrap_or_default(),
                    sealed.clock().now(),
                    rule,
                )
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
                let parsed = SigV4Authorization::parse_with(raw, rule)?;
                let seed = header_signature_seed(raw)?;
                Ok(Self::Header(Box::new(parsed), seed))
            }
            _ => Err(AuthError::AuthorizationHeaderMalformed),
        }
    }

    pub(super) fn scope(&self) -> &CredentialScope {
        match self {
            Self::Header(parsed, _) => parsed.scope(),
            Self::Query(parsed, _) => parsed.scope(),
            Self::Form(policy) => policy.scope(),
            Self::UnroutedForm(policy) => policy.scope(),
        }
    }

    pub(super) fn canonical_parts(&self) -> Option<(&str, &Signature)> {
        match self {
            Self::Header(parsed, _) => Some((parsed.signed_headers(), parsed.signature())),
            Self::Query(parsed, _) => Some((parsed.signed_headers(), parsed.signature())),
            Self::Form(_) | Self::UnroutedForm(_) => None,
        }
    }

    /// The 32-byte request-head signature decoded alongside the strict grammar parse, to be
    /// published into [`super::ChunkVerification`] only after constant-time verification succeeds.
    pub(super) const fn chunk_seed(&self) -> Option<[u8; 32]> {
        match self {
            Self::Header(_, seed) | Self::Query(_, seed) => Some(*seed),
            Self::Form(_) | Self::UnroutedForm(_) => None,
        }
    }

    pub(super) fn session_token(&self) -> Option<&SessionToken> {
        let Self::Form(policy) = self else { return None };
        policy.session_token()
    }

    /// Records session admission before comparison, as a refusal that only the comparison's proof
    /// can turn into anything but the uniform answer; the caller answers only after HMAC.
    pub(super) fn session_refusal(
        &self,
        credentials: &crate::ext::credentials::Credentials,
        sealed: &SealedAws<'_>,
        location: SigLocation,
    ) -> Option<crate::ext::PendingSessionRefusal> {
        // Legacy-compat (rustfs/backlog#2684): an unrouted form uses only the key and HMAC
        // before its method refusal. Session admission belongs to the upload path.
        if matches!(self, Self::UnroutedForm(_)) {
            return None;
        }
        use crate::ext::credentials::SessionSurface;

        let view = sealed.view();
        let now = sealed.clock().now();
        match location {
            SigLocation::FormField => {
                credentials.admit_surface_pending(self.session_token().map(SessionToken::expose), SessionSurface::Sts, now)
            }
            SigLocation::Query if view.query_contains(rustfs_gateway_sig::X_AMZ_SECURITY_TOKEN) => credentials
                .admit_query_param_pending(view.query(), rustfs_gateway_sig::X_AMZ_SECURITY_TOKEN, SessionSurface::Sts, now),
            SigLocation::Query if view.query_contains(rustfs_gateway_sig::X_AMZ_S3SESSION_TOKEN) => credentials
                .admit_query_param_pending(
                    view.query(),
                    rustfs_gateway_sig::X_AMZ_S3SESSION_TOKEN,
                    SessionSurface::S3Express,
                    now,
                ),
            _ => {
                if let Some(value) = view.headers().get(rustfs_gateway_sig::X_AMZ_S3SESSION_TOKEN_HEADER) {
                    credentials.admit_surface_pending(Some(value.as_bytes()), SessionSurface::S3Express, now)
                } else {
                    credentials.admit_surface_pending(
                        view.headers()
                            .get(rustfs_gateway_sig::X_AMZ_SECURITY_TOKEN_HEADER)
                            .map(http::HeaderValue::as_bytes),
                        SessionSurface::Sts,
                        now,
                    )
                }
            }
        }
    }

    /// The timestamp the string-to-sign is dated with.
    ///
    /// For a presigned URL it is the one in the query; for a header-signed request it is the
    /// receipt the skew check produced, which is the same value the floor validated.
    pub(super) fn signed_at(&self, sealed: &SealedAws<'_>) -> AmzDate {
        match self {
            Self::Header(_, _) => sealed.clock().signed_at(),
            Self::Query(parsed, _) => parsed.date(),
            Self::Form(policy) => policy.signed_at(),
            Self::UnroutedForm(policy) => policy.signed_at(),
        }
    }
}

/// Extracts the 32-byte `Signature` component from an already-validated `Authorization` header.
///
/// Mirrors `SigV4Authorization::parse_with`'s comma-separated `Key=Value` grammar so an
/// `AccessKeyId` containing `Signature=` in `Credential=...` is never confused with the real
/// `Signature=` field.
fn header_signature_seed(raw: &str) -> Result<[u8; 32], AuthError> {
    let rest = raw
        .strip_prefix("AWS4-HMAC-SHA256")
        .ok_or(AuthError::AuthorizationHeaderMalformed)?;
    for part in rest.trim_start().split(',') {
        if let Some((key, value)) = part.trim().split_once('=')
            && key.trim() == "Signature"
        {
            return decode_hex_lower_32(value.trim()).ok_or(AuthError::AuthorizationHeaderMalformed);
        }
    }
    Err(AuthError::AuthorizationHeaderMalformed)
}

fn decode_hex_lower_32(hex: &str) -> Option<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let [high_byte, low_byte] = *pair else {
            return None;
        };
        let high = hex_nibble_lower(high_byte)?;
        let low = hex_nibble_lower(low_byte)?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

const fn hex_nibble_lower(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}
