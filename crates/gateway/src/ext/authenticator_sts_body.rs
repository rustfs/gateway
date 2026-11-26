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

//! Header signatures whose payload digest is computed from a bounded request body.
//!
//! Responsible for: reading S3 Vectors bodies within the service's limits and preserving RustFS's
//! STS body reading after credential lookup, using the body's digest when the payload header is
//! absent, retaining a body-read refusal before signature comparison, turning a verification
//! failure into the trait's answer, and reporting whether a header signature covers the body.
//! NOT responsible for: reading body frames or selecting an STS operation.
//! Upstream: `crate::service` and `super::SigV4Authenticator`. Downstream: the canonical request
//! verifier in `super` and the proof-gated replay in `crate::gate`.

use std::sync::OnceLock;

use super::{AuthError, Authentication, AuthenticationOutcome, CredentialLookup, PayloadMode, Presented, SigLocation};
use super::{SigV4Authenticator, Unavailable, VerificationFailure};
use crate::gate::{BodyCeilings, BodyTimeouts, StsBodyReader};

pub(super) struct StsBodyReading<'a> {
    reader: &'a dyn StsBodyReader,
    ceilings: BodyCeilings,
    timeouts: BodyTimeouts,
    /// Set once the body's own digest became the payload token a comparison runs over.
    digested: OnceLock<[u8; 32]>,
    /// Set once a comparison over that digest succeeded: only then does the signature cover the
    /// body. A rejected comparison leaves it unset, so an authenticator that falls back to another
    /// verification after this one refused cannot inherit a signed body.
    signed: OnceLock<[u8; 32]>,
}

impl<'a> Authentication<'a> {
    /// Offered by the pipeline; only the built-in verification path asks the private reader.
    pub(crate) fn with_sts_body_reader(
        mut self,
        reader: Option<&'a dyn StsBodyReader>,
        operation: &str,
        config: &crate::ServiceConfig,
    ) -> Self {
        self.sts_body = reader.map(|reader| StsBodyReading {
            reader,
            ceilings: BodyCeilings::of(operation, config.max_buffered_body_bytes()),
            timeouts: config.request_body_deadlines(),
            digested: OnceLock::new(),
            signed: OnceLock::new(),
        });
        self
    }

    /// Whether a header signature over this request covers the body the handler will be handed:
    /// the body's digest computed here, a declared digest the facade compares with the body it
    /// reads, or an aws-chunked chain of chunk signatures. `UNSIGNED-PAYLOAD`, unsigned streaming,
    /// the empty-payload token, and every query or form signature do not (rustfs/gateway#1587).
    /// Meaningful only once the verdict authenticated the request.
    pub(crate) fn signs_its_body(&self) -> bool {
        self.sealed().marker().location() == SigLocation::Header
            && (self.sts_body.as_ref().is_some_and(|reading| reading.signed.get().is_some())
                || self.payload().digest().is_some()
                || matches!(self.payload(), PayloadMode::StreamingSigned { .. }))
    }
    /// The verified SHA-256 digest of a bounded STS or S3 Vectors body hashed when
    /// `x-amz-content-sha256` was absent, once the signature comparison over that digest succeeded.
    pub(crate) fn signed_sts_body_digest(&self) -> Option<[u8; 32]> {
        self.sts_body.as_ref().and_then(|reading| reading.signed.get().copied())
    }
}

impl SigV4Authenticator {
    pub(super) async fn verify(&self, request: &Authentication<'_>) -> Result<AuthenticationOutcome, Unavailable> {
        match self.try_verify(request).await {
            Ok((verdict, secret)) => {
                // The comparison succeeded, over the body's digest if one was the token.
                if let Some(reading) = &request.sts_body
                    && let Some(&digest) = reading.digested.get()
                {
                    let _ = reading.signed.set(digest);
                }
                Ok(AuthenticationOutcome::authenticated(verdict, secret))
            }
            Err(VerificationFailure::Unavailable) => Err(Unavailable),
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
        let vectors = request.sealed().expected_service() == rustfs_gateway_sig::SigService::S3Vectors;
        let legacy_sts =
            self.scope_policy.legacy_services && presented.scope().service() == Some(rustfs_gateway_sig::SigService::Sts);
        if (!vectors && !legacy_sts)
            || request.sealed().marker().location() != SigLocation::Header
            || request.sealed().view().headers().contains_key("x-amz-content-sha256")
        {
            return Ok(None);
        }
        // An unknown key must never trigger a body read (which would let an unauthenticated caller
        // force buffering up to the service ceiling) or have its credential refusal replaced by a
        // body-length refusal. A store fault is answered at the same point, so both keep one
        // latency class here; both answer before the body read and signature comparison.
        if !matches!(resolved, Ok(CredentialLookup::Found(_))) {
            return Err(self.unresolved_lookup(resolved));
        }
        let reading = request.sts_body.as_ref().ok_or(AuthError::SignatureDoesNotMatch)?;
        let digest = reading
            .reader
            .digest(reading.timeouts, vectors.then_some(reading.ceilings))
            .await
            .map_err(VerificationFailure::Body)?;
        let _ = reading.digested.set(digest);
        Ok(Some(PayloadMode::ExactSha256(digest)))
    }
}

#[cfg(test)]
#[path = "authenticator_sts_body_tests.rs"]
mod tests;
