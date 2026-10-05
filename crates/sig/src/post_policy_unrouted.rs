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

//! Signature material for a RustFS object-path form that has no operation (rustfs/gateway#1184).
//!
//! Responsible for: bounded policy syntax and credential bindings before that request is refused.
//! Not responsible for: upload-policy enforcement, routing, or HTTP errors. Upstream: the form
//! prelude. Downstream: the existing authenticator; this type cannot produce upload enforcement.

use super::{
    ALGORITHM, Condition, FieldSet, JsonParser, PostPolicyError, PostPolicyLimits, decode_base64, hmac_sha256, parse_expiration,
    parse_policy, parse_signature,
};
use crate::{
    AmzDate, CredentialScope, CtBytes, EmptyRegion, RegionLength, RegionRule, ServiceReading, Signature, SignatureMatch,
    SigningKey,
};

/// A metadata refusal before an unrouted form's signature is checked.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnroutedPostPolicyError {
    /// The fields cannot be represented without ambiguity.
    InvalidFields,
    /// The algorithm field is absent.
    MissingAlgorithm,
    /// The credential field is absent.
    MissingCredential,
    /// The date field is absent.
    MissingDate,
    /// The policy field is absent.
    MissingPolicy,
    /// The algorithm is unsupported.
    UnsupportedAlgorithm,
    /// The credential scope cannot be read.
    InvalidCredential,
    /// The date cannot be read.
    InvalidDate,
    /// The policy is not bounded base64.
    InvalidEncoding,
    /// The policy document or its expiration is malformed.
    InvalidDocument,
    /// The policy has no exact condition binding the form date.
    DateNotBound,
    /// The policy has no exact condition binding the form credential.
    CredentialNotBound,
}

/// Credential material of a form that will be refused without running an upload operation.
///
/// This is deliberately separate from [`super::PostPolicy`]: a signature match here says nothing
/// about the policy's expiry, bucket, key, or file limits, and cannot produce
/// [`super::PostPolicyEnforcement`]. Sensitive fields are not printable.
pub struct UnroutedPostPolicy {
    encoded: String,
    scope: CredentialScope,
    signed_at: AmzDate,
    signature: Option<Signature>,
}

impl UnroutedPostPolicy {
    /// Reads the material legacy RustFS checks before refusing an object-path POST form.
    ///
    /// A form without a SigV4 signature marker returns `None`: the method refusal precedes anonymous access
    /// checks. Expiry and non-credential policy conditions belong to the upload operation, which
    /// this request never reaches. The ordinary [`super::PostPolicy`] path remains strict.
    ///
    /// # Errors
    ///
    /// Returns a closed metadata cause; no request value or signature is carried by the error.
    pub fn read(fields: &[(&str, &str)], limits: PostPolicyLimits) -> Result<Option<Self>, UnroutedPostPolicyError> {
        use UnroutedPostPolicyError as Error;
        let fields = FieldSet::parse(fields).map_err(|_| Error::InvalidFields)?;
        let Some(signature) = fields.get("x-amz-signature") else { return Ok(None) };
        let algorithm = fields.get("x-amz-algorithm").ok_or(Error::MissingAlgorithm)?;
        let credential = fields.get("x-amz-credential").ok_or(Error::MissingCredential)?;
        let date = fields.get("x-amz-date").ok_or(Error::MissingDate)?;
        let encoded = fields.get("policy").ok_or(Error::MissingPolicy)?;
        if algorithm != ALGORITHM {
            return Err(Error::UnsupportedAlgorithm);
        }
        let rule = RegionRule::STRICT
            .with_empty(EmptyRegion::Admitted)
            .with_length(RegionLength::Unbounded)
            .with_services(ServiceReading::AnyName);
        let scope = CredentialScope::parse_with(credential, rule).map_err(|_| Error::InvalidCredential)?;
        let signed_at = AmzDate::parse(date).map_err(|_| Error::InvalidDate)?;
        if encoded.len() > limits.max_encoded_bytes {
            return Err(Error::InvalidEncoding);
        }
        let decoded = decode_base64(encoded, limits.max_decoded_bytes).map_err(|_| Error::InvalidEncoding)?;
        let root =
            JsonParser::parse(&decoded, limits.max_json_depth, limits.max_json_elements).map_err(|_| Error::InvalidDocument)?;
        let (expiration, conditions) = parse_policy(root).map_err(|_| Error::InvalidDocument)?;
        parse_expiration(&expiration).map_err(|_| Error::InvalidDocument)?;
        let bound = |name: &str, value: &str| {
            conditions
                .iter()
                .any(|condition| matches!(condition, Condition::Exact(field, expected) if field == name && expected == value))
        };
        if !bound("x-amz-date", date) {
            return Err(Error::DateNotBound);
        }
        if !bound("x-amz-credential", credential) {
            return Err(Error::CredentialNotBound);
        }
        // Legacy-compat (rustfs/backlog#2684): the method check follows the form HMAC, while
        // expiry and upload conditions follow the method check. Keep only credential material
        // here; the intended ordinary upload path enforces every policy condition.
        Ok(Some(Self {
            encoded: encoded.to_owned(),
            scope,
            signed_at,
            signature: parse_signature(signature).ok(),
        }))
    }

    /// The scope to cross-check before deriving a signing key.
    #[must_use]
    pub const fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    /// The timestamp to cross-check against the request's clock.
    #[must_use]
    pub const fn signed_at(&self) -> AmzDate {
        self.signed_at
    }

    /// Compares the policy signature in constant time, after the existing scope and key lookup.
    ///
    /// A malformed signature still pays for derivation and comparison, then fails as a signature
    /// mismatch rather than becoming a metadata parsing error.
    ///
    /// # Errors
    ///
    /// Returns [`PostPolicyError::SignatureMismatch`] when the signature is malformed or differs.
    pub fn verify(&self, key: &SigningKey) -> Result<SignatureMatch, PostPolicyError> {
        let expected = Signature::HmacSha256(CtBytes::from_array(hmac_sha256(key.expose(), self.encoded.as_bytes())));
        let absent = Signature::HmacSha256(CtBytes::from_array([0; 32]));
        let matched = self.signature.as_ref().unwrap_or(&absent).ct_verify(&expected);
        if self.signature.is_none() {
            return Err(PostPolicyError::SignatureMismatch);
        }
        matched.map_err(|_| PostPolicyError::SignatureMismatch)
    }
}
