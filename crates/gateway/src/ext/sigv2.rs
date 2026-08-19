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

//! The SigV2 half of the built-in authenticator.
//!
//! Responsible for: [`SigV2Authentication`] — the question the pipeline asks about an admitted
//! SigV2 request — and [`super::SigV4Authenticator`]'s answer to it: build the string-to-sign,
//! derive HMAC-SHA1 with the stored secret, and hand the result to the one constant-time
//! comparison.
//! NOT responsible for: admitting the request (that is `SecurityFloor::admit`, which already ran),
//! the string-to-sign's contents (that is `rustfs-gateway-sig`'s `sig_v2::string_to_sign`), or the
//! POST-form SigV2 shape, which the floor refuses.
//! Upstream: `rustfs_gateway_sig::SealedSigV2`. Downstream: `crate::service`'s authentication
//! stage.
//!
//! # Why this lives beside the SigV4 authenticator rather than in its own extension point
//!
//! Because a second extension point is a second thing a deployment can forget to install, and the
//! forgetting is silent. [`super::Authenticator`] therefore has one SigV2 method whose **default
//! implementation refuses**: an authenticator written before SigV2 existed keeps compiling and
//! answers `501` to a SigV2 request, which is a refusal rather than a downgrade. Only an
//! implementation that deliberately overrides the method can authenticate one.
//!
//! # What SigV2 does not cover, and why the body is read unframed
//!
//! SigV2 has no streaming payload form and no `x-amz-content-sha256`: the only body binding it
//! offers is `Content-MD5`, and that is optional. So a SigV2 request has no framed body to decode
//! and no signed digest to check, and the pipeline reads its body plainly. A SigV2 request that
//! *declares* a framed payload is refused by the floor rather than silently read as if the
//! declaration were absent — a declared thing nobody acts on is the defect shape this repository
//! has recorded seven times.

use rustfs_gateway_core::BoxFuture;
use rustfs_gateway_sig::sig_v2::{SigV2Mode, SigV2StringToSignSpec, verify_presented};
use rustfs_gateway_sig::{
    AuthError, AuthScheme, SealedSigV2, SigIdentity, SignatureMatch, Verdict, X_AMZ_SECURITY_TOKEN_HEADER, timing,
};

use super::credentials::{CredentialLookup, CredentialProvider};
use super::{AuthenticationOutcome, SigV4Authenticator, Unavailable};

/// One admitted SigV2 request, with everything the string-to-sign needs that the floor did not
/// carry.
///
/// The path is the **raw** spelling, for the same reason [`super::Authentication`] takes one: SigV2
/// signs the encoded path exactly as it arrived, so a normalised value would give several distinct
/// requests one valid signature.
///
/// The virtual-host bucket is the resolver's answer, not a second parse of the `Host` header. A
/// second host parser is a second answer to "which bucket did this request address", and it is the
/// answer the signature is built from.
pub struct SigV2Authentication<'a> {
    sealed: &'a SealedSigV2<'a>,
    method: &'a http::Method,
    raw_path: &'a str,
    virtual_host_bucket: Option<&'a str>,
}

impl core::fmt::Debug for SigV2Authentication<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigV2Authentication")
            .field("sealed", &self.sealed)
            .field("method", &self.method)
            .field("raw_path", &self.raw_path)
            .field("virtual_host_bucket", &self.virtual_host_bucket)
            .finish()
    }
}

impl<'a> SigV2Authentication<'a> {
    /// Assembles the request a SigV2 authenticator is asked about.
    #[must_use]
    pub const fn new(
        sealed: &'a SealedSigV2<'a>,
        method: &'a http::Method,
        raw_path: &'a str,
        virtual_host_bucket: Option<&'a str>,
    ) -> Self {
        Self {
            sealed,
            method,
            raw_path,
            virtual_host_bucket,
        }
    }

    /// The admitted request. Holding one is proof the floor has run.
    #[must_use]
    pub const fn sealed(&self) -> &'a SealedSigV2<'a> {
        self.sealed
    }

    /// The request method, which is line one of the string-to-sign.
    #[must_use]
    pub const fn method(&self) -> &'a http::Method {
        self.method
    }

    /// The path exactly as it arrived, still percent-encoded.
    #[must_use]
    pub const fn raw_path(&self) -> &'a str {
        self.raw_path
    }

    /// The bucket a virtual-hosted-style request addressed, or `None` for path style.
    #[must_use]
    pub const fn virtual_host_bucket(&self) -> Option<&'a str> {
        self.virtual_host_bucket
    }
}

impl SigV4Authenticator {
    /// Answers one SigV2 request.
    ///
    /// The shape deliberately mirrors the SigV4 path, including the parts that look like
    /// inefficiency: an unknown access key derives against
    /// [`rustfs_gateway_sig::timing::placeholder_secret`] and completes the comparison before the
    /// uniform `InvalidAccessKeyId` is answered, and a credential that exists but may not be used
    /// gets that same answer after the same work. SigV2 having a cheaper HMAC than SigV4 is not a
    /// reason to give it a shorter rejection path — a second latency ladder is still a latency
    /// ladder.
    pub(super) async fn verify_sigv2(&self, request: &SigV2Authentication<'_>) -> Result<AuthenticationOutcome, Unavailable> {
        match self.try_verify_sigv2(request).await {
            Ok(Some(verdict)) => Ok(AuthenticationOutcome::ordinary(verdict)),
            Ok(None) => Err(Unavailable),
            Err(error) => Ok(AuthenticationOutcome::ordinary(Verdict::reject(error))),
        }
    }

    /// `Ok(None)` is the store outage; every other outcome is a verdict or a rejection.
    async fn try_verify_sigv2(&self, request: &SigV2Authentication<'_>) -> Result<Option<Verdict>, AuthError> {
        let sealed = request.sealed();
        let view = sealed.view();
        let resolved = self.credentials.lookup(sealed.access_key_id()).await;
        let key = match &resolved {
            Ok(CredentialLookup::Found(credentials)) => credentials.secret().clone_secret(),
            Ok(CredentialLookup::NotFound) | Err(_) => timing::placeholder_secret(),
        };

        // Decided here, answered at the bottom — the same ordering the SigV4 path uses, and for
        // the same reason: a session rule answered early is an expired token distinguishable from
        // a wrong secret by the clock alone.
        //
        // The header spelling only. SigV2's `CanonicalizedResource` covers 35 sub-resources and
        // `x-amz-security-token` is not one of them, so a session token in the *query* of a
        // presigned SigV2 URL is unsigned — anyone could attach one. A temporary credential
        // presented that way therefore finds no token here and is refused, which is the
        // fail-closed answer: SigV2 presigned cannot carry STS credentials safely, and the
        // deployment that wants them should use SigV4. In the header form the token is an
        // `x-amz-*` header and is inside the signature.
        let refusal = match &resolved {
            Ok(CredentialLookup::Found(credentials)) => credentials
                .admit(
                    view.headers()
                        .get(X_AMZ_SECURITY_TOKEN_HEADER)
                        .map(http::HeaderValue::as_bytes),
                    sealed.now(),
                )
                .err(),
            Ok(CredentialLookup::NotFound) | Err(_) => None,
        };

        let query = view.query();
        let spec = SigV2StringToSignSpec::new(
            sealed.mode(),
            request.method(),
            request.raw_path(),
            &query,
            view.headers(),
            request.virtual_host_bucket(),
        );
        let expected = spec.build()?.sign(&key);
        // The one comparison. `verify_presented` is a wrapper over `Signature::ct_verify`, and
        // there is no second one anywhere in the SigV2 path — `scripts/check_ct_eq.sh` rule 9
        // fails the build if one appears.
        let proof: Option<SignatureMatch> = verify_presented(sealed.presented(), &expected).ok();

        // The unknown-key branch has now paid for the same derivation a known key does. Only
        // after that is the uniform credential rejection answered.
        let Ok(CredentialLookup::Found(credentials)) = resolved else {
            return Err(AuthError::InvalidAccessKeyId);
        };
        let Some(proof) = proof else {
            // No mismatch detail is published. The SigV4 path can afford to echo a canonical
            // request behind an explicit verbose switch because that value is derived from what
            // the client sent; SigV2's string-to-sign is six lines long, so echoing it is a
            // materially better signing oracle for the same secret.
            return Err(if refusal.is_some() {
                AuthError::InvalidAccessKeyId
            } else {
                AuthError::SignatureDoesNotMatch
            });
        };
        // A credential that exists and is correctly signed for, and still may not be used:
        // switched off, expired, or presented without the token it is bound to. Answered as
        // `InvalidAccessKeyId`, the same bytes an unknown key gets.
        if refusal.is_some() {
            return Err(AuthError::InvalidAccessKeyId);
        }

        let identity_axis = match credentials.session_token() {
            Some(token) => SigIdentity::Session {
                token: token.clone_secret(),
            },
            None => SigIdentity::LongTerm,
        };
        let scheme = match sealed.mode() {
            SigV2Mode::PresignedUrl => AuthScheme::sigv2_presigned(identity_axis, sealed.expected_service()),
            // `SigV2Mode` is `#[non_exhaustive]`; header authentication is the named arm and a
            // location added later must not silently borrow the header scheme's meaning.
            _ => AuthScheme::sigv2_header(identity_axis, sealed.expected_service()),
        };
        Ok(Some(Verdict::authenticated(credentials.identity().clone(), scheme, proof)))
    }
}

/// The bucket a virtual-hosted-style request addressed, for SigV2's `CanonicalizedResource`.
///
/// SigV2 prefixes `/{bucket}` for a virtual-hosted-style request and not for a path-style one,
/// where the bucket is already inside the raw path. So this is the *host's* bucket only, taken
/// from the resolver's answer rather than from a second parse of the `Host` header — a second host
/// parser is a second answer to "which bucket did this request address", and it is the answer the
/// signature is built from.
pub(crate) fn vhost_signing_bucket(resolved: &super::ResolvedHost) -> Option<String> {
    resolved.bucket().map(|bucket| bucket.as_str().to_owned())
}

/// The refusal every [`super::Authenticator`] answers a SigV2 request with until it overrides the
/// method.
///
/// A free function rather than an inline `async` block in the trait's default body, so that "the
/// default is a refusal" is one greppable name instead of a closure nobody reads.
pub(crate) fn refuse_sigv2<'a>() -> BoxFuture<'a, Result<AuthenticationOutcome, Unavailable>> {
    Box::pin(async {
        Ok(AuthenticationOutcome::ordinary(Verdict::reject(AuthError::NotImplemented(
            rustfs_gateway_sig::Unimplemented::SigV2,
        ))))
    })
}
