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

//! The SigV4a (`AWS4-ECDSA-P256-SHA256`) verification path of [`super::SigV4Authenticator`].
//!
//! Responsible for: parsing SigV4a header and presigned query credentials alongside
//! `x-amz-region-set` / `X-Amz-Region-Set`, enforcing H5 scope checks via
//! [`rustfs_gateway_sig::enforce_sigv4a_scope`], refusing cross-algorithm streaming pairings,
//! maintaining timing parity for unknown access keys, verifying ASN.1 DER ECDSA P-256 signatures,
//! and publishing public-key chunk-verification material into [`super::ChunkSink`].
//! NOT responsible for: security-floor checks H1–H6 (already run before `SealedAws`), SigV4 HMAC
//! verification (`super::authenticator`), or `aws-chunked` framing decode (`crate::chunked`).
//! Upstream: `super::SigV4Authenticator::try_verify`. Downstream: `rustfs-gateway-sig` SigV4a
//! verifier and `crate::chunked`.

use http::header::HeaderName;
use rustfs_gateway_sig::{
    AUTHORIZATION_HEADER, AmzDate, AuthError, AuthScheme, CanonicalRequestSpec, EcdsaDerSignature, ExpectedScope, PayloadMode,
    PresentedRegionSet, ServiceReading, SigIdentity, SigLocation, SigV4aAuthorization, SigV4aCredentialScope,
    SigV4aPresignedParams, SigV4aVerifyingKey, SignatureMatch, SignatureMismatchDetail, Unimplemented, Verdict,
    X_AMZ_REGION_SET_HEADER, X_AMZ_S3SESSION_TOKEN, X_AMZ_S3SESSION_TOKEN_HEADER, X_AMZ_SECURITY_TOKEN,
    X_AMZ_SECURITY_TOKEN_HEADER, enforce_sigv4a_scope, timing, verify_sigv4a_signature,
};

use super::super::credentials::{CredentialLookup, CredentialProvider, Credentials, SessionSurface};
use super::super::{PendingSessionRefusal, session_answer};
use super::{Authentication, ChunkVerification, SigV4Authenticator, VerificationFailure, VerifiedWithSecret};

enum PresentedSigV4a {
    Header {
        auth: Box<SigV4aAuthorization>,
        region_set: PresentedRegionSet,
    },
    Query(Box<SigV4aPresignedParams>),
}

impl PresentedSigV4a {
    fn read(
        sealed: &rustfs_gateway_sig::SealedAws<'_>,
        location: SigLocation,
        services: ServiceReading,
    ) -> Result<Self, AuthError> {
        let view = sealed.view();
        match location {
            SigLocation::Header => {
                let raw_auth = view
                    .headers()
                    .get(AUTHORIZATION_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                let auth = SigV4aAuthorization::parse_with(raw_auth, services)?;
                let raw_region_set = view
                    .headers()
                    .get(X_AMZ_REGION_SET_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                let region_set = PresentedRegionSet::parse(raw_region_set)?;
                Ok(Self::Header {
                    auth: Box::new(auth),
                    region_set,
                })
            }
            SigLocation::Query => {
                let params = SigV4aPresignedParams::parse_with(&view.query(), services)?;
                Ok(Self::Query(Box::new(params)))
            }
            // AWS does not define SigV4a browser POST policies; refuse cleanly rather than
            // degrading to SigV4 POST policy verification.
            SigLocation::FormField => Err(AuthError::NotImplemented(Unimplemented::SigV4a)),
            _ => Err(AuthError::AuthorizationHeaderMalformed),
        }
    }

    fn scope(&self) -> &SigV4aCredentialScope {
        match self {
            Self::Header { auth, .. } => auth.scope(),
            Self::Query(params) => params.scope(),
        }
    }

    fn region_set(&self) -> &PresentedRegionSet {
        match self {
            Self::Header { region_set, .. } => region_set,
            Self::Query(params) => params.region_set(),
        }
    }

    fn signed_headers(&self) -> &str {
        match self {
            Self::Header { auth, .. } => auth.signed_headers(),
            Self::Query(params) => params.signed_headers(),
        }
    }

    fn signature(&self) -> &EcdsaDerSignature {
        match self {
            Self::Header { auth, .. } => auth.signature(),
            Self::Query(params) => params.signature(),
        }
    }

    fn signed_at(&self, sealed: &rustfs_gateway_sig::SealedAws<'_>) -> AmzDate {
        match self {
            Self::Header { .. } => sealed.clock().signed_at(),
            Self::Query(params) => params.date(),
        }
    }

    fn session_refusal(
        credentials: &Credentials,
        sealed: &rustfs_gateway_sig::SealedAws<'_>,
        location: SigLocation,
    ) -> Option<PendingSessionRefusal> {
        let view = sealed.view();
        let now = sealed.clock().now();
        match location {
            SigLocation::Query if view.query_contains(X_AMZ_SECURITY_TOKEN) => {
                credentials.admit_query_param_pending(view.query(), X_AMZ_SECURITY_TOKEN, SessionSurface::Sts, now)
            }
            SigLocation::Query if view.query_contains(X_AMZ_S3SESSION_TOKEN) => {
                credentials.admit_query_param_pending(view.query(), X_AMZ_S3SESSION_TOKEN, SessionSurface::S3Express, now)
            }
            _ => {
                if let Some(value) = view.headers().get(X_AMZ_S3SESSION_TOKEN_HEADER) {
                    credentials.admit_surface_pending(Some(value.as_bytes()), SessionSurface::S3Express, now)
                } else {
                    credentials.admit_surface_pending(
                        view.headers()
                            .get(X_AMZ_SECURITY_TOKEN_HEADER)
                            .map(http::HeaderValue::as_bytes),
                        SessionSurface::Sts,
                        now,
                    )
                }
            }
        }
    }
}

impl SigV4Authenticator {
    /// Verifies a SigV4a (`AWS4-ECDSA-P256-SHA256`) header or presigned request.
    pub(super) async fn try_verify_sigv4a(
        &self,
        request: &Authentication<'_>,
    ) -> Result<VerifiedWithSecret, VerificationFailure> {
        // Cross-algorithm refusal: SigV4a cannot pair with HMAC-SHA256 streaming chunks, and
        // presigned SigV4a cannot carry streaming chunked payloads.
        let sealed = request.sealed();
        let location = sealed.marker().location();
        if matches!(request.payload(), PayloadMode::StreamingSigned { .. })
            || (location.is_presigned() && request.payload().is_ecdsa_streaming())
        {
            return Err(AuthError::AuthorizationHeaderMalformed.into());
        }

        let view = sealed.view();
        let service = sealed.expected_service();
        let services = if self.scope_policy.legacy_services {
            ServiceReading::AnyName
        } else {
            ServiceReading::Known
        };

        let presented = PresentedSigV4a::read(sealed, location, services)?;

        // H5 — cross-check scope day, region set, and service before any verification.
        let expected = self.scope_policy.apply(ExpectedScope::new(service, &self.regions));
        let verified = enforce_sigv4a_scope(presented.scope(), presented.region_set(), sealed.clock(), &expected)
            .map_err(VerificationFailure::Scope)?;

        let akid = presented.scope().access_key_id().access_key_id();
        let resolved = self.credentials.lookup(akid).await;
        // Timing parity (T1): unknown access keys still derive a P-256 verifying key and verify
        // every path candidate against the placeholder secret before answering uniformly.
        let secret = match &resolved {
            Ok(CredentialLookup::Found(credentials)) => credentials.secret().clone_secret(),
            Ok(CredentialLookup::NotFound) | Err(_) => timing::placeholder_secret(),
        };

        let session_refusal = match &resolved {
            Ok(CredentialLookup::Found(credentials)) => PresentedSigV4a::session_refusal(credentials, sealed, location),
            Ok(CredentialLookup::NotFound) | Err(_) => {
                if let Some(placeholder) = session_answer::placeholder_session() {
                    let _ = PresentedSigV4a::session_refusal(placeholder, sealed, location);
                }
                None
            }
        };

        let payload = request.payload();
        let signed =
            self.read_signed_headers(presented.signed_headers(), view.headers(), request.declared_content_length(), location)?;
        // Header SigV4a must always cover `x-amz-region-set` in SignedHeaders, even under legacy
        // header-list rules.
        if location == SigLocation::Header && !signed.contains(&HeaderName::from_static(X_AMZ_REGION_SET_HEADER)) {
            return Err(AuthError::SignatureDoesNotMatch.into());
        }

        let paths = self.path_candidates(request.raw_path(), request.claimed)?;
        let query = view.query();
        let mut spec = CanonicalRequestSpec::new(
            request.method(),
            &paths,
            &query,
            view.headers(),
            &signed,
            request.host(),
            payload.canonical_payload_token(),
        )
        .for_service(service);
        if location.is_presigned() {
            spec = spec.presigned();
        }

        let verifying_key = SigV4aVerifyingKey::derive(akid, &secret).map_err(|_| AuthError::InvalidAccessKeyId)?;
        let date = presented.signed_at(sealed);
        let mut matched: Option<SignatureMatch> = None;
        let mut mismatch_detail: Option<SignatureMismatchDetail> = None;
        for candidate in spec.candidates()? {
            let string_to_sign = candidate.string_to_sign_v4a(&date, presented.scope());
            mismatch_detail = Some(SignatureMismatchDetail::new(&candidate, &string_to_sign));
            if let Ok(proof) = verify_sigv4a_signature(&verifying_key, &verified, &string_to_sign, presented.signature()) {
                matched = matched.or(Some(proof));
            }
        }

        let Ok(CredentialLookup::Found(credentials)) = resolved else {
            return Err(self.unresolved_lookup(&resolved));
        };
        let Some(proof) = matched.take() else {
            if let Some(pending) = session_refusal {
                return Err(pending.uniform().into());
            }
            if let Some(detail) = mismatch_detail {
                let _ = request.signature_mismatch.set(detail);
            }
            return Err(AuthError::SignatureDoesNotMatch.into());
        };
        if let Some(pending) = session_refusal {
            return Err(pending.answer(&proof).into());
        }

        let identity_axis = match credentials.session_token() {
            Some(token) => SigIdentity::Session {
                token: token.clone_secret(),
            },
            None => SigIdentity::LongTerm,
        };
        let scheme = match location {
            SigLocation::Query => AuthScheme::sigv4a_presigned(identity_axis, service),
            SigLocation::Header => AuthScheme::sigv4a_header(identity_axis, service),
            _ => return Err(AuthError::AuthorizationHeaderMalformed.into()),
        };

        // Publish only the 33-byte compressed SEC1 public verifying key and the verified head DER
        // signature bytes for streaming SigV4a (never the private scalar, and never re-parsed from
        // the raw Authorization string).
        if payload.is_ecdsa_streaming()
            && let Some(sink) = request.chunk_sink()
        {
            sink.publish(ChunkVerification::new_ecdsa(
                verifying_key.compressed_sec1(),
                presented.signature().verified_der_bytes(&proof),
                verified.scope_string(),
                date.as_str().to_owned(),
            ));
        }

        let secret_out = self.hand_secret.then(|| credentials.secret().clone_secret());
        let verdict = Verdict::authenticated_in_sigv4a_scope(credentials.identity().clone(), scheme, &verified, proof);
        Ok((verdict, secret_out))
    }
}
