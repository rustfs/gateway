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

//! The SigV2 admission branch of [`SecurityFloor::admit`].
//!
//! Responsible for: admitting SigV2 header, presigned-URL, and POST-policy requests into
//! [`SealedSigV2`] under the configured [`SigV2Policy`] and rejecting framed SigV2 payloads.
//! NOT responsible for: SigV4 admission, S3 Express session-token rules, or verifying SigV2
//! signatures (that belongs to [`crate::sig_v2`]).
//! Upstream: [`SecurityFloor::admit`]. Downstream: `Admission::SealedSigV2`.

use super::*;
use crate::mode::{
    STREAMING_ECDSA, STREAMING_ECDSA_TRAILER, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER, STREAMING_UNSIGNED_TRAILER,
};

/// Refuses a SigV2 request that declares a framed payload.
///
/// `x-amz-content-sha256` is not part of SigV2 at all; a client that sends one has it signed as an
/// ordinary `x-amz-*` header and nothing else. The token spellings below name `aws-chunked`
/// framing whose chunk signatures are SigV4 values, so a SigV2 request cannot have produced them.
///
/// # Errors
///
/// [`AuthError::NotImplemented`] carrying [`crate::error::Unimplemented::StreamingSigV2`], and
/// [`AuthError::AuthorizationHeaderMalformed`] for a declaration that is not even text.
fn refuse_framed_sigv2_payload(view: &WireView<'_>) -> Result<(), AuthError> {
    let Some(raw) = view.headers().get(X_AMZ_CONTENT_SHA256_HEADER) else {
        return Ok(());
    };
    let token = raw.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
    if matches!(
        token,
        STREAMING_SIGNED | STREAMING_SIGNED_TRAILER | STREAMING_UNSIGNED_TRAILER | STREAMING_ECDSA | STREAMING_ECDSA_TRAILER
    ) {
        return Err(AuthError::NotImplemented(crate::error::Unimplemented::StreamingSigV2));
    }
    Ok(())
}

impl SecurityFloor {
    /// The SigV2 branch of [`SecurityFloor::admit`], and the only route to a [`SealedSigV2`].
    ///
    /// # Errors
    ///
    /// * [`AuthError::AccessDenied`] when the [`SigV2Policy`] does not admit this location.
    /// * [`AuthError::AuthorizationHeaderMalformed`] for a credential this crate cannot parse, and
    ///   [`AuthError::AuthorizationQueryParametersError`] for its presigned spelling.
    /// * [`AuthError::RequestTimeTooSkewed`] from the same H1 window SigV4 uses, and
    ///   [`AuthError::RequestExpired`] for an elapsed presigned URL.
    pub(super) fn admit_sigv2<'a>(
        &self,
        view: WireView<'a>,
        marker: AwsCredentialMarker,
        operation: &OperationFloor,
        presence: CredentialPresence,
        now: RequestNow,
    ) -> Result<Admission<'a>, AuthError> {
        let mode = match marker.location() {
            SigLocation::Header => SigV2Mode::HeaderAuth,
            SigLocation::Query => SigV2Mode::PresignedUrl,
            SigLocation::FormField => SigV2Mode::PostPolicy,
        };
        if !self.sigv2.allows(mode) {
            return Err(AuthError::AccessDenied);
        }
        refuse_framed_sigv2_payload(&view)?;
        match mode {
            SigV2Mode::PostPolicy => {
                let legacy = self.recognition == recognition::Recognition::LegacyRustfs;
                if legacy
                    && [AWS_ACCESS_KEY_ID_PARAM, "policy"]
                        .iter()
                        .any(|name| view.form_value(name).is_none())
                {
                    return Err(AuthError::MissingPostFormField);
                }
                let access_key_id = view
                    .form_value(AWS_ACCESS_KEY_ID_PARAM)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?;
                let signature = view.form_value("signature").ok_or(AuthError::AuthorizationHeaderMalformed)?;
                let unreadable = if legacy {
                    crate::sig_v2::UnreadableFormSignature::Unmatchable
                } else {
                    crate::sig_v2::UnreadableFormSignature::Refused
                };
                let presented = crate::sig_v2::parse_post_policy_credential(access_key_id, signature, unreadable)?;
                Ok(Admission::SealedSigV2(SealedSigV2::post_policy(
                    view,
                    presented,
                    now,
                    presence,
                    operation.service(),
                )))
            }
            SigV2Mode::PresignedUrl => {
                let access_key_id = self.sigv2_query_value(&view, AWS_ACCESS_KEY_ID_PARAM)?;
                let signature = self.sigv2_query_value(&view, SIGV2_SIGNATURE_PARAM)?;
                let expires_at = self.expiry.sigv2_expires_of(&view, now)?;
                let presented = crate::sig_v2::parse_presigned_credential(&access_key_id, &signature)?;
                Ok(Admission::SealedSigV2(
                    SealedSigV2::presigned(view, presented, now, expires_at, presence, operation.service())
                        .with_expiry_rule(self.expiry),
                ))
            }
            SigV2Mode::HeaderAuth => {
                let raw = view
                    .headers()
                    .get(AUTHORIZATION_HEADER)
                    .ok_or(AuthError::AuthorizationHeaderMalformed)?
                    .to_str()
                    .map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
                let presented = crate::sig_v2::parse_authorization(raw)?;
                let signed_at = crate::sig_v2::signed_timestamp(view.headers())?;
                let clock = enforce_clock_skew(&signed_at, now, self.skew)?;
                Ok(Admission::SealedSigV2(SealedSigV2::header(
                    view,
                    presented,
                    clock,
                    presence,
                    operation.service(),
                )))
            }
        }
    }

    /// Reads one SigV2 query parameter that must be present exactly once.
    fn sigv2_query_value(&self, view: &WireView<'_>, name: &str) -> Result<String, AuthError> {
        view.query()
            .decoded_value(name)
            .map_err(|_| AuthError::AuthorizationQueryParametersError)?
            .ok_or(AuthError::AuthorizationQueryParametersError)
    }
}
