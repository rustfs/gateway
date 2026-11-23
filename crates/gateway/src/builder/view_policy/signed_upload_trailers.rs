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

//! A deployment can authenticate an unframed upload before refusing its announced trailers.
//! This reading does not accept a payload or decode a body. The service owns those boundaries.
//! Upstream: `ServiceBuilder`. Downstream: header authentication and route authorization.

use super::{ServiceBuilder, ViewPolicy, header_signatures::SignedHead};
use crate::{
    gate::BodyDigestObligation,
    payload_header::{self, PayloadRefusal},
    render::S3Error,
};
use rustfs_gateway_sig::{PayloadMode, SigLocation};

impl ServiceBuilder {
    /// Verifies a header-signed `PutObject` or `UploadPart` before refusing a signed checksum
    /// trailer declared on an unframed payload. The route authorizer may supply its own refusal;
    /// even an allowed route still returns the original declaration error without reading the body
    /// or calling storage. By default the gateway refuses the declaration before authentication.
    #[must_use]
    pub fn authenticate_before_rejecting_unframed_upload_trailers(mut self) -> Self {
        self.view_policy.defer_unframed_upload_trailers = true;
        self
    }
}

impl ViewPolicy {
    pub(crate) fn signed_payload(
        self,
        head: &SignedHead<'_>,
        operation: &str,
        location: SigLocation,
        refusal: &mut Option<S3Error>,
    ) -> Result<(PayloadMode, BodyDigestObligation), PayloadRefusal> {
        let defer = self.defer_unframed_upload_trailers
            && head.method == http::Method::PUT
            && matches!(operation, "PutObject" | "UploadPart");
        match payload_header::signed_payload(head.headers, location, self.presigned_payload_unsigned()) {
            Err(PayloadRefusal::Head(original)) if defer && location == SigLocation::Header => {
                let Some(declaration) = payload_header::unframed_upload_with_signed_trailers(head.headers) else {
                    return Err(PayloadRefusal::Head(original));
                };
                *refusal = Some(original);
                Ok(declaration)
            }
            result => result,
        }
    }

    /// Whether a presigned request's payload declaration is read as legacy RustFS reads it
    /// ([`ServiceBuilder::sign_presigned_payloads_as_unsigned`]).
    pub(crate) const fn presigned_payload_unsigned(&self) -> bool {
        self.presigned_payload_unsigned
    }
}
