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

//! The client half of SigV2: what a legacy SDK puts on the wire.
//!
//! Responsible for: rendering the two values a SigV2 client sends — the `Authorization` header and
//! the presigned `Signature` parameter — from the same [`SigV2StringToSignSpec`] the server builds
//! its expectation from.
//! NOT responsible for: verifying anything, choosing a timestamp, or assembling a request. It
//! renders one value and the caller puts it where it goes.
//! Upstream: [`SigV2StringToSignSpec`], [`crate::codec`]. Downstream: the gateway's SigV2 runtime
//! evidence, and the conformance runner when SigV2 cases land.
//!
//! # Why the server needs a client at all
//!
//! "A correctly signed SigV2 request authenticates" is not a claim that can be made by asserting
//! against a string the implementation also produced. It needs a signature computed the way a
//! client computes one, over a request that then travels the whole pipeline. This is that
//! computation, kept on the client side of the boundary: it renders base64 and never compares
//! anything.
//!
//! It is also the reason this type is public rather than test-only. A signer that only exists
//! under `cfg(test)` cannot be driven by the conformance suite, which is the harness that has to
//! prove the wire behaviour against something other than this crate's own opinion of it.

use crate::codec::encode_base64_exact;
use crate::secret::SecretBytes;
use crate::signature::Signature;
use crate::verdict::{AuthError, Identity};

use super::string_to_sign::{SigV2StringToSign, SigV2StringToSignSpec};

/// A SigV2 client-side signer.
///
/// It has no `Debug`: it holds a [`SecretBytes`], and a signer printed into a test log is a secret
/// in a test log.
pub struct SigV2Signer {
    access_key_id: Identity,
    key: SecretBytes,
}

impl SigV2Signer {
    /// Builds a signer over one long-term credential.
    ///
    /// The access key id goes through [`Identity::new`], which is the same rule the verifier
    /// applies to the value that arrives on the wire — so a credential this signer accepts is one
    /// the server can read back, and a test cannot accidentally sign with an id no request could
    /// carry.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidAccessKeyId`] when the access key id is empty, over-long, or not an
    /// ASCII-graphic string.
    pub fn new(access_key_id: &str, secret_access_key: &[u8]) -> Result<Self, AuthError> {
        Ok(Self {
            access_key_id: Identity::new(access_key_id).map_err(|_| AuthError::InvalidAccessKeyId)?,
            key: SecretBytes::new(secret_access_key),
        })
    }

    /// The access key id this signer signs as.
    #[must_use]
    pub fn access_key_id(&self) -> &Identity {
        &self.access_key_id
    }

    /// The `Authorization: AWS <access-key>:<signature>` value for a request.
    ///
    /// # Errors
    ///
    /// Whatever [`SigV2StringToSignSpec::build`] reports — the preimage cannot be built, so there
    /// is nothing to sign.
    pub fn authorization(&self, spec: &SigV2StringToSignSpec<'_>) -> Result<String, AuthError> {
        let rendered = self.render(&spec.build()?)?;
        let id = self.access_key_id.access_key_id();
        Ok(format!("AWS {id}:{rendered}"))
    }

    /// The presigned `Signature` parameter value, before percent-encoding.
    ///
    /// Standard base64 contains `+`, `/` and `=`, all of which a URL must escape. Escaping is the
    /// caller's, because the caller is the one assembling the query string and a signer that
    /// escaped would produce a value that cannot be put anywhere else.
    ///
    /// # Errors
    ///
    /// Whatever [`SigV2StringToSignSpec::build`] reports.
    pub fn presigned_signature(&self, spec: &SigV2StringToSignSpec<'_>) -> Result<String, AuthError> {
        self.render(&spec.build()?)
    }

    /// Standard base64 of the twenty HMAC-SHA1 bytes.
    ///
    /// A client's signature over its own request travels in the clear, so rendering it is the
    /// protocol rather than a leak. Nothing here renders a *computed expectation*, which is the
    /// value that would turn a diagnostic into a signing oracle.
    fn render(&self, preimage: &SigV2StringToSign) -> Result<String, AuthError> {
        match preimage.sign(&self.key) {
            Signature::HmacSha1(bytes) => Ok(encode_base64_exact(bytes.as_array())),
            _ => Err(AuthError::SignatureDoesNotMatch),
        }
    }
}
