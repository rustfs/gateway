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

//! RustFS's STS-scoped header signature over a bounded body (rustfs/gateway#1230).
//!
//! Responsible for: asking the private reader only after a key is found, using the body's digest
//! when the payload header is absent, and preserving a body-read refusal before signature comparison.
//! NOT responsible for: reading body frames or selecting an STS operation.
//! Upstream: `crate::service` and `super::SigV4Authenticator`. Downstream: the canonical request
//! verifier in `super` and the proof-gated replay in `crate::gate`.

use super::{AuthError, Authentication, AuthenticationOutcome, CredentialLookup, PayloadMode, Presented, SigLocation};
use super::{SigV4Authenticator, Unavailable, VerificationFailure};
use crate::gate::{BodyTimeouts, StsBodyReader};

pub(super) struct StsBodyReading<'a> {
    reader: &'a dyn StsBodyReader,
    timeouts: BodyTimeouts,
}

impl<'a> Authentication<'a> {
    /// Offered by the pipeline; only the built-in verification path asks the private reader.
    pub(crate) fn with_sts_body_reader(mut self, reader: Option<&'a dyn StsBodyReader>, timeouts: BodyTimeouts) -> Self {
        self.sts_body = reader.map(|reader| StsBodyReading { reader, timeouts });
        self
    }
}

impl SigV4Authenticator {
    pub(super) async fn verify(&self, request: &Authentication<'_>) -> Result<AuthenticationOutcome, Unavailable> {
        match self.try_verify(request).await {
            Ok(Some((verdict, secret))) => Ok(AuthenticationOutcome::authenticated(verdict, secret)),
            Ok(None) => Err(Unavailable),
            Err(VerificationFailure::Ordinary(error)) => {
                Ok(AuthenticationOutcome::ordinary(rustfs_gateway_sig::Verdict::reject(error)))
            }
            Err(VerificationFailure::Scope(rejection)) => Ok(AuthenticationOutcome::scope_rejected(rejection)),
            Err(VerificationFailure::Body(refusal)) => {
                let _ = request.body_refusal.set(refusal);
                Ok(AuthenticationOutcome::ordinary(rustfs_gateway_sig::Verdict::reject(
                    AuthError::AccessDenied,
                )))
            }
        }
    }

    /// Every other signature keeps its original payload token and never asks for body bytes.
    pub(super) async fn sts_payload(
        &self,
        request: &Authentication<'_>,
        presented: &Presented<'_>,
        resolved: &Result<CredentialLookup, super::super::credentials::ProviderError>,
    ) -> Result<Option<PayloadMode>, VerificationFailure> {
        if !self.scope_policy.legacy_services
            || request.sealed().marker().location() != SigLocation::Header
            || presented.scope().service() != Some(rustfs_gateway_sig::SigService::Sts)
            || request.sealed().view().headers().contains_key("x-amz-content-sha256")
        {
            return Ok(None);
        }
        // This early lookup rejection is part of the legacy profile: an unknown key must not
        // trigger a read or have its credential refusal replaced by the body's length refusal.
        if !matches!(resolved, Ok(CredentialLookup::Found(_))) {
            return Err(AuthError::InvalidAccessKeyId.into());
        }
        let reading = request.sts_body.as_ref().ok_or(AuthError::SignatureDoesNotMatch)?;
        let digest = reading
            .reader
            .digest(reading.timeouts)
            .await
            .map_err(VerificationFailure::Body)?;
        Ok(Some(PayloadMode::ExactSha256(digest)))
    }
}
