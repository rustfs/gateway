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

//! S3 Express session-token admission rules in [`SecurityFloor::admit`].
//!
//! Responsible for: validating `x-amz-s3session-token` (header) and `X-Amz-S3session-Token`
//! (presigned query) surface rules, refusing session-token auth on disallowed schemes/operations
//! (including `CreateSession`, SigV2, POST policies, and non-S3 services), and selecting
//! [`SigService::S3Express`] as the sealed credential-scope service when a valid S3 Express
//! session token is presented.
//! NOT responsible for: looking up credentials, comparing tokens against stored sessions, or
//! verifying SigV4 signatures (the authenticator owns those).
//! Upstream: [`SecurityFloor::admit`]. Downstream: [`SealedAws::expected_service`].

use super::*;
use crate::scheme::SigService;

/// The S3 Express session-token parameter, in its presigned query spelling.
pub const X_AMZ_S3SESSION_TOKEN: &str = "X-Amz-S3session-Token";
/// The S3 Express session-token header, lowercased.
pub const X_AMZ_S3SESSION_TOKEN_HEADER: &str = "x-amz-s3session-token";

impl SecurityFloor {
    /// Validates an S3 Express session token surface and resolves the expected signing service.
    ///
    /// When no `x-amz-s3session-token` was presented, returns `operation.service()` unchanged.
    /// When one was presented:
    /// * carrying it on more than one surface (header, query, form) is malformed;
    /// * SigV2 and browser POST policies cannot carry S3 Express session tokens (`AccessDenied`);
    /// * operations that declare [`OperationFloor::refuse_s3_express_session_auth`] (notably
    ///   `CreateSession`) and non-S3 services refuse it (`AccessDenied`);
    /// * a query token requires a presigned query signature and a valid non-empty decoded value;
    /// * a header token requires valid non-empty UTF-8 text;
    /// * admitted requests seal [`SigService::S3Express`] so the scope check enforces `s3express`.
    pub(super) fn admit_s3_express_session(
        &self,
        view: &WireView<'_>,
        operation: &OperationFloor,
        marker: AwsCredentialMarker,
        presence: CredentialPresence,
    ) -> Result<SigService, AuthError> {
        if !presence.has_s3_express_session_token() {
            return Ok(operation.service());
        }
        let header = view.headers().get(X_AMZ_S3SESSION_TOKEN_HEADER);
        let query = view.query_contains(X_AMZ_S3SESSION_TOKEN);
        let form = view.form_contains(X_AMZ_S3SESSION_TOKEN_HEADER);
        if u8::from(header.is_some()) + u8::from(query) + u8::from(form) > 1 {
            return Err(AuthError::AuthorizationHeaderMalformed);
        }
        if form || marker.location() == SigLocation::FormField || matches!(marker.family(), SigFamily::V2) {
            return Err(AuthError::AccessDenied);
        }
        if operation.refuses_s3_express_session_auth() || !matches!(operation.service(), SigService::S3 | SigService::S3Express) {
            return Err(AuthError::AccessDenied);
        }
        if query {
            if marker.location() != SigLocation::Query {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
            let decoded = view
                .query()
                .decoded_value(X_AMZ_S3SESSION_TOKEN)
                .map_err(|_| AuthError::AuthorizationQueryParametersError)?
                .ok_or(AuthError::AuthorizationQueryParametersError)?;
            if decoded.is_empty() {
                return Err(AuthError::AuthorizationQueryParametersError);
            }
        } else if let Some(raw) = header {
            let text = raw.to_str().map_err(|_| AuthError::AuthorizationHeaderMalformed)?;
            if text.is_empty() {
                return Err(AuthError::AuthorizationHeaderMalformed);
            }
        }
        Ok(SigService::S3Express)
    }
}
