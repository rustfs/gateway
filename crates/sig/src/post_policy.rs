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

//! Browser POST-policy parsing and proof.
//!
//! Responsible for: strict policy decoding, field conditions, filename substitution, size limits,
//! and policy signature comparisons. Not responsible for: multipart framing, object-key typing, or
//! HTTP responses. Upstream: the bounded form parser. Downstream: the built-in authenticator.

#[path = "post_policy_unrouted.rs"]
mod unrouted;
pub use unrouted::{UnroutedPostPolicy, UnroutedPostPolicyError};

#[path = "post_policy_conditions.rs"]
mod conditions;
use conditions::{Condition, parse_policy};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::post_policy_json::JsonParser;
use crate::{
    AmzDate, AuthError, CredentialScope, CtBytes, EmptyRegion, RegionRule, RequestNow, SecretBytes, SessionToken, Signature,
    SignatureMatch, SigningKey, VerifyRejection,
};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const REQUIRED_FIELDS: [&str; 5] = [
    "policy",
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-signature",
];
const EXEMPT_FIELDS: [&str; 9] = [
    "x-amz-signature",
    "x-amz-algorithm",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-security-token",
    "policy",
    "file",
    "awsaccesskeyid",
    "signature",
];

/// Resource ceilings applied while decoding and enforcing one POST policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostPolicyLimits {
    /// Maximum base64 policy length.
    pub max_encoded_bytes: usize,
    /// Maximum decoded JSON policy length.
    pub max_decoded_bytes: usize,
    /// Maximum JSON nesting depth.
    pub max_json_depth: usize,
    /// Maximum total JSON array elements and object members.
    pub max_json_elements: usize,
    /// Deployment file-size ceiling, combined with `content-length-range`.
    pub max_file_bytes: u64,
}

impl Default for PostPolicyLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 32 * 1024,
            max_decoded_bytes: 24 * 1024,
            max_json_depth: 16,
            max_json_elements: 256,
            max_file_bytes: 5 * 1024 * 1024 * 1024,
        }
    }
}

/// Why a POST policy was refused.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostPolicyError {
    /// The base64, JSON, credential, signature, field, or filename shape was invalid.
    Malformed,
    /// The policy expiration is in the past.
    Expired,
    /// A declared field condition or final bucket/key check failed.
    ConditionFailed,
    /// The final file size is below `content-length-range`.
    EntityTooSmall,
    /// The final file size exceeds either policy or deployment limits.
    EntityTooLarge,
    /// The policy signature did not match.
    SignatureMismatch,
}

impl fmt::Display for PostPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the POST policy could not be parsed",
            Self::Expired => "the POST policy has expired",
            Self::ConditionFailed => "a POST policy condition was not satisfied",
            Self::EntityTooSmall => "the POST body is smaller than the policy permits",
            Self::EntityTooLarge => "the POST body is larger than the policy permits",
            Self::SignatureMismatch => "the POST policy signature did not match",
        })
    }
}

impl std::error::Error for PostPolicyError {}

impl PostPolicyError {
    /// Collapses policy details onto the existing authentication error surface.
    #[must_use]
    pub const fn auth_error(self) -> AuthError {
        match self {
            Self::Malformed => AuthError::AuthorizationHeaderMalformed,
            Self::SignatureMismatch => AuthError::SignatureDoesNotMatch,
            Self::Expired | Self::ConditionFailed | Self::EntityTooSmall | Self::EntityTooLarge => AuthError::AccessDenied,
        }
    }
}

/// Proof that final bucket, key, and file-size enforcement completed.
pub struct PostPolicyEnforcement(());

/// A strictly parsed POST policy whose sensitive wire values are never printable.
pub struct PostPolicy {
    encoded: String,
    scope: CredentialScope,
    signed_at: AmzDate,
    signature: Signature,
    session_token: Option<SessionToken>,
    bucket: BucketBinding,
    final_key: String,
    minimum_file_bytes: u64,
    maximum_file_bytes: u64,
}

impl fmt::Debug for PostPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostPolicy")
            .field("has_session_token", &self.session_token.is_some())
            .field("read_ceiling", &self.maximum_file_bytes)
            .finish_non_exhaustive()
    }
}

impl PostPolicy {
    /// Parses and enforces all pre-file POST-policy conditions.
    ///
    /// `raw_filename` is separate from `fields`: multipart metadata must not masquerade as a form
    /// field. Pass an empty string when no file metadata is available; a `${filename}` template is
    /// then rejected rather than evaluated against an invented name.
    ///
    /// # Errors
    ///
    /// Returns [`PostPolicyError`] for malformed or expired policies and failed conditions.
    pub fn parse(
        fields: &[(&str, &str)],
        raw_filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
    ) -> Result<Self, PostPolicyError> {
        Self::parse_with(fields, raw_filename, limits, now, EmptyRegion::Refused)
    }

    /// [`PostPolicy::parse`], with the `x-amz-credential` field's region read by `rule`
    /// ([`CredentialScope::parse_with`]).
    ///
    /// # Errors
    ///
    /// As [`PostPolicy::parse`].
    pub fn parse_with(
        fields: &[(&str, &str)],
        raw_filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
        rule: impl Into<RegionRule>,
    ) -> Result<Self, PostPolicyError> {
        let fields = FieldSet::parse(fields)?;
        for required in REQUIRED_FIELDS {
            fields.required(required)?;
        }
        if fields.required("x-amz-algorithm")? != ALGORITHM {
            return Err(PostPolicyError::Malformed);
        }
        let (encoded, conditions) = parse_policy_document(&fields, limits, now, false)?;

        let credential = fields.required("x-amz-credential")?;
        let scope = CredentialScope::parse_with(credential, rule).map_err(|_| PostPolicyError::Malformed)?;
        let signed_at = AmzDate::parse(fields.required("x-amz-date")?).map_err(|_| PostPolicyError::Malformed)?;
        if scope.date().as_str() != &signed_at.as_str()[..8] {
            return Err(PostPolicyError::Malformed);
        }
        let signature = parse_signature(fields.required("x-amz-signature")?)?;
        let common = enforce_policy_fields(&fields, raw_filename, limits, encoded, &conditions)?;

        Ok(Self {
            encoded: common.encoded,
            scope,
            signed_at,
            signature,
            session_token: fields
                .get("x-amz-security-token")
                .map(SessionToken::new)
                .transpose()
                .map_err(|_| PostPolicyError::Malformed)?,
            bucket: common.bucket,
            final_key: common.final_key,
            minimum_file_bytes: common.minimum_file_bytes,
            maximum_file_bytes: common.maximum_file_bytes,
        })
    }

    /// The credential scope carried by the form.
    #[must_use]
    pub const fn scope(&self) -> &CredentialScope {
        &self.scope
    }

    /// The signed timestamp carried by the form.
    #[must_use]
    pub const fn signed_at(&self) -> AmzDate {
        self.signed_at
    }

    /// The optional session token, kept out of [`Debug`](fmt::Debug).
    #[must_use]
    pub const fn session_token(&self) -> Option<&SessionToken> {
        self.session_token.as_ref()
    }

    /// The final key after safe filename substitution.
    #[must_use]
    pub fn final_key(&self) -> &str {
        &self.final_key
    }

    /// Maximum bytes the multipart reader may accept before stopping.
    #[must_use]
    pub const fn read_ceiling(&self) -> u64 {
        self.maximum_file_bytes
    }

    /// Compares the policy signature in constant time.
    ///
    /// # Errors
    ///
    /// Returns [`PostPolicyError::SignatureMismatch`] when comparison fails.
    pub fn verify(&self, key: &SigningKey) -> Result<SignatureMatch, PostPolicyError> {
        let expected = Signature::HmacSha256(CtBytes::from_array(hmac_sha256(key.expose(), self.encoded.as_bytes())));
        self.signature
            .ct_verify(&expected)
            .map_err(|_: VerifyRejection| PostPolicyError::SignatureMismatch)
    }

    /// Rechecks final routing values and the observed file size.
    ///
    /// # Errors
    ///
    /// Returns [`PostPolicyError`] when bucket, key, or size does not satisfy the parsed policy.
    pub fn enforce_final(&self, bucket: &str, key: &str, file_bytes: u64) -> Result<PostPolicyEnforcement, PostPolicyError> {
        enforce_final_values(
            &self.bucket,
            &self.final_key,
            self.minimum_file_bytes,
            self.maximum_file_bytes,
            bucket,
            key,
            file_bytes,
        )
    }
}

/// A SigV2 browser POST policy using [`PostPolicy`]'s field, JSON, and size authority.
pub struct SigV2PostPolicy {
    encoded: String,
    bucket: BucketBinding,
    final_key: String,
    minimum_file_bytes: u64,
    maximum_file_bytes: u64,
}

impl fmt::Debug for SigV2PostPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigV2PostPolicy")
            .field("read_ceiling", &self.maximum_file_bytes)
            .finish_non_exhaustive()
    }
}

impl SigV2PostPolicy {
    /// Verifies the encoded policy before interpreting its JSON, expiry, or field conditions.
    /// Only the encoded and decoded byte ceilings in `limits` apply at this stage.
    /// A successful proof does not authorize an upload: callers must still use [`Self::parse`]
    /// and [`Self::enforce_final`] before committing the object.
    /// # Errors
    /// Returns [`PostPolicyError::Malformed`] for invalid base64 or exceeded byte ceilings,
    /// or [`PostPolicyError::SignatureMismatch`] when the signature comparison fails.
    pub fn verify_encoded(
        encoded: &str,
        limits: PostPolicyLimits,
        secret: &SecretBytes,
        presented: &Signature,
    ) -> Result<SignatureMatch, PostPolicyError> {
        if encoded.len() > limits.max_encoded_bytes {
            return Err(PostPolicyError::Malformed);
        }
        decode_base64(encoded, limits.max_decoded_bytes)?;
        let preimage = crate::sig_v2::SigV2StringToSign::from_post_policy(encoded);
        let expected = preimage.sign(secret);
        crate::sig_v2::verify_presented(presented, &expected).map_err(|_| PostPolicyError::SignatureMismatch)
    }

    /// Parses and enforces the shared pre-file POST-policy conditions for a SigV2 form.
    /// # Errors
    /// Returns [`PostPolicyError`] for malformed or expired policies and failed conditions.
    pub fn parse(
        fields: &[(&str, &str)],
        raw_filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
    ) -> Result<Self, PostPolicyError> {
        Self::parse_impl(fields, raw_filename, limits, now, false)
    }

    /// Parses a SigV2 policy with ASCII-case-insensitive condition operator names.
    ///
    /// Only `eq`, `starts-with`, and `content-length-range` ignore ASCII case. Field values,
    /// document member names, resource limits, and the original signed bytes are unchanged.
    /// The default [`Self::parse`] keeps exact operator spelling.
    /// # Errors
    /// Returns [`PostPolicyError`] for malformed or expired policies and failed conditions.
    pub fn parse_with_case_insensitive_operators(
        fields: &[(&str, &str)],
        raw_filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
    ) -> Result<Self, PostPolicyError> {
        Self::parse_impl(fields, raw_filename, limits, now, true)
    }

    fn parse_impl(
        fields: &[(&str, &str)],
        raw_filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
        ascii_case_insensitive: bool,
    ) -> Result<Self, PostPolicyError> {
        let fields = FieldSet::parse(fields)?;
        fields.required("awsaccesskeyid")?;
        fields.required("signature")?;
        let (encoded, conditions) = parse_policy_document(&fields, limits, now, ascii_case_insensitive)?;
        let common = enforce_policy_fields(&fields, raw_filename, limits, encoded, &conditions)?;
        Ok(Self {
            encoded: common.encoded,
            bucket: common.bucket,
            final_key: common.final_key,
            minimum_file_bytes: common.minimum_file_bytes,
            maximum_file_bytes: common.maximum_file_bytes,
        })
    }

    /// The final key after safe filename substitution.
    #[must_use]
    pub fn final_key(&self) -> &str {
        &self.final_key
    }

    /// Maximum bytes the multipart reader may accept before stopping.
    #[must_use]
    pub const fn read_ceiling(&self) -> u64 {
        self.maximum_file_bytes
    }

    /// Compares the SigV2 policy signature through the one constant-time SigV2 entry point.
    /// # Errors
    /// Returns [`PostPolicyError::SignatureMismatch`] when comparison fails.
    pub fn verify(&self, secret: &SecretBytes, presented: &Signature) -> Result<SignatureMatch, PostPolicyError> {
        let preimage = crate::sig_v2::SigV2StringToSign::from_post_policy(&self.encoded);
        let expected = preimage.sign(secret);
        crate::sig_v2::verify_presented(presented, &expected).map_err(|_| PostPolicyError::SignatureMismatch)
    }

    /// Rechecks final routing values and the observed file size.
    /// # Errors
    /// Returns [`PostPolicyError`] when bucket, key, or size does not satisfy the parsed policy.
    pub fn enforce_final(&self, bucket: &str, key: &str, file_bytes: u64) -> Result<PostPolicyEnforcement, PostPolicyError> {
        enforce_final_values(
            &self.bucket,
            &self.final_key,
            self.minimum_file_bytes,
            self.maximum_file_bytes,
            bucket,
            key,
            file_bytes,
        )
    }
}

struct CommonPolicy {
    encoded: String,
    bucket: BucketBinding,
    final_key: String,
    minimum_file_bytes: u64,
    maximum_file_bytes: u64,
}

struct FieldSet<'a>(BTreeMap<String, &'a str>);

impl<'a> FieldSet<'a> {
    fn parse(fields: &'a [(&'a str, &'a str)]) -> Result<Self, PostPolicyError> {
        let mut parsed = BTreeMap::new();
        for &(name, value) in fields {
            if name.is_empty() || !name.is_ascii() {
                return Err(PostPolicyError::Malformed);
            }
            if parsed.insert(name.to_ascii_lowercase(), value).is_some() {
                return Err(PostPolicyError::Malformed);
            }
        }
        Ok(Self(parsed))
    }

    fn get(&self, name: &str) -> Option<&'a str> {
        self.0.get(name).copied()
    }

    fn required(&self, name: &str) -> Result<&'a str, PostPolicyError> {
        self.get(name).ok_or(PostPolicyError::Malformed)
    }

    fn names(&self) -> impl Iterator<Item = &String> {
        self.0.keys()
    }
}

fn parse_policy_document(
    fields: &FieldSet<'_>,
    limits: PostPolicyLimits,
    now: RequestNow,
    ascii_case_insensitive: bool,
) -> Result<(String, Vec<Condition>), PostPolicyError> {
    let encoded = fields.required("policy")?;
    if encoded.is_empty() || encoded.len() > limits.max_encoded_bytes {
        return Err(PostPolicyError::Malformed);
    }
    let decoded = decode_base64(encoded, limits.max_decoded_bytes)?;
    let root = JsonParser::parse(&decoded, limits.max_json_depth, limits.max_json_elements)?;
    let (expiration, conditions) = parse_policy(root, ascii_case_insensitive)?;
    let expiry = parse_expiration(&expiration)?;
    if now.unix_seconds() >= crate::clock::unix_seconds(&expiry).ok_or(PostPolicyError::Malformed)? {
        return Err(PostPolicyError::Expired);
    }
    Ok((encoded.to_owned(), conditions))
}

fn enforce_policy_fields(
    fields: &FieldSet<'_>,
    raw_filename: &str,
    limits: PostPolicyLimits,
    encoded: String,
    conditions: &[Condition],
) -> Result<CommonPolicy, PostPolicyError> {
    let filename = if raw_filename.is_empty() {
        None
    } else {
        Some(clean_filename(raw_filename)?)
    };
    let final_key = substitute_filename(fields.required("key")?, filename.as_deref())?;
    let mut mentioned = BTreeSet::new();
    let mut minimum_file_bytes = 0;
    let mut maximum_file_bytes = limits.max_file_bytes;
    let bucket_field = fields.get("bucket");
    let mut bucket_rules = Vec::new();
    for condition in conditions {
        match condition {
            // Without a `bucket` field the URL names the bucket, which is not known here: the
            // condition binds the routed bucket and `enforce_final` checks it.
            Condition::Exact(name, expected) if name == "bucket" && bucket_field.is_none() => {
                mentioned.insert(name.clone());
                bucket_rules.push(BucketRule::Exact(expected.clone()));
            }
            Condition::StartsWith(name, prefix) if name == "bucket" && bucket_field.is_none() => {
                mentioned.insert(name.clone());
                bucket_rules.push(BucketRule::StartsWith(prefix.clone()));
            }
            Condition::Exact(name, expected) => {
                mentioned.insert(name.clone());
                if condition_value(fields, name, &final_key)? != expected {
                    return Err(PostPolicyError::ConditionFailed);
                }
            }
            Condition::StartsWith(name, prefix) => {
                mentioned.insert(name.clone());
                let value = condition_value(fields, name, &final_key)?;
                let matches = if name == "content-type" {
                    value.split(',').all(|item| item.starts_with(prefix))
                } else {
                    value.starts_with(prefix)
                };
                if !matches {
                    return Err(PostPolicyError::ConditionFailed);
                }
            }
            Condition::ContentLengthRange(minimum, maximum) => {
                if minimum > maximum {
                    return Err(PostPolicyError::Malformed);
                }
                minimum_file_bytes = minimum_file_bytes.max(*minimum);
                maximum_file_bytes = maximum_file_bytes.min(*maximum);
            }
        }
    }
    if minimum_file_bytes > maximum_file_bytes {
        return Err(PostPolicyError::ConditionFailed);
    }
    for name in fields.names() {
        if !EXEMPT_FIELDS.contains(&name.as_str()) && !name.starts_with("x-ignore-") && !mentioned.contains(name) {
            return Err(PostPolicyError::ConditionFailed);
        }
    }

    if bucket_field.is_none() && bucket_rules.is_empty() {
        return Err(PostPolicyError::ConditionFailed);
    }

    Ok(CommonPolicy {
        encoded,
        bucket: BucketBinding {
            field: bucket_field.map(str::to_owned),
            rules: bucket_rules,
        },
        final_key,
        minimum_file_bytes,
        maximum_file_bytes,
    })
}

fn enforce_final_values(
    expected_bucket: &BucketBinding,
    expected_key: &str,
    minimum_file_bytes: u64,
    maximum_file_bytes: u64,
    bucket: &str,
    key: &str,
    file_bytes: u64,
) -> Result<PostPolicyEnforcement, PostPolicyError> {
    if !expected_bucket.admits(bucket) || key != expected_key {
        return Err(PostPolicyError::ConditionFailed);
    }
    if file_bytes < minimum_file_bytes {
        return Err(PostPolicyError::EntityTooSmall);
    }
    if file_bytes > maximum_file_bytes {
        return Err(PostPolicyError::EntityTooLarge);
    }
    Ok(PostPolicyEnforcement(()))
}

/// How a policy binds the bucket its form is routed to.
///
/// A browser form names its bucket in the URL, and the `bucket` form field is optional: minio-java
/// sends none (rustfs/gateway#756). With the field, the routed bucket must equal it, and the
/// policy's `$bucket` conditions were checked against it at parse time. Without it, those
/// conditions are kept here and checked against the routed bucket. A form bound by neither is
/// refused at parse time, so a signature never authorizes an upload into whichever bucket the URL
/// happens to name.
struct BucketBinding {
    field: Option<String>,
    rules: Vec<BucketRule>,
}

enum BucketRule {
    Exact(String),
    StartsWith(String),
}

impl BucketBinding {
    fn admits(&self, bucket: &str) -> bool {
        self.field.as_deref().is_none_or(|field| field == bucket)
            && self.rules.iter().all(|rule| match rule {
                BucketRule::Exact(expected) => bucket == expected,
                BucketRule::StartsWith(prefix) => bucket.starts_with(prefix.as_str()),
            })
    }
}

fn condition_value<'a>(fields: &'a FieldSet<'a>, name: &str, final_key: &'a str) -> Result<&'a str, PostPolicyError> {
    if name == "key" {
        Ok(final_key)
    } else {
        fields.get(name).ok_or(PostPolicyError::ConditionFailed)
    }
}

fn clean_filename(raw: &str) -> Result<String, PostPolicyError> {
    if raw.chars().any(char::is_control) {
        return Err(PostPolicyError::Malformed);
    }
    let leaf = raw
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .ok_or(PostPolicyError::Malformed)?;
    let clean = leaf.replace("..", "");
    if clean.is_empty() || clean.contains(['/', '\\']) {
        return Err(PostPolicyError::Malformed);
    }
    Ok(clean)
}

fn substitute_filename(template: &str, filename: Option<&str>) -> Result<String, PostPolicyError> {
    if template.contains("${filename}") {
        let filename = filename.ok_or(PostPolicyError::ConditionFailed)?;
        let substituted = template.replace("${filename}", filename);
        if substituted.contains("${") {
            return Err(PostPolicyError::Malformed);
        }
        Ok(substituted)
    } else if template.contains("${") {
        Err(PostPolicyError::Malformed)
    } else {
        Ok(template.to_owned())
    }
}

/// Reads the policy's `expiration`: an ISO 8601 UTC instant, `YYYY-MM-DDTHH:MM:SS`, an optional
/// fraction of one to nine digits, then `Z`.
///
/// The documented policy example writes milliseconds (`2007-12-01T12:00:00.000Z`), and minio-js
/// and minio-java send that form, so refusing a fraction refused every form those SDKs sign
/// (rustfs/gateway#756). The fraction is truncated, never rounded up: a policy is not honoured
/// past the whole second it names.
fn parse_expiration(value: &str) -> Result<AmzDate, PostPolicyError> {
    let bytes = value.as_bytes();
    if !value.is_ascii()
        || bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[bytes.len() - 1] != b'Z'
    {
        return Err(PostPolicyError::Malformed);
    }
    let fraction = &value[19..value.len() - 1];
    if !fraction.is_empty() {
        let digits = fraction.strip_prefix('.').ok_or(PostPolicyError::Malformed)?;
        if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(PostPolicyError::Malformed);
        }
    }
    let compact = format!(
        "{}{}{}T{}{}{}Z",
        &value[0..4],
        &value[5..7],
        &value[8..10],
        &value[11..13],
        &value[14..16],
        &value[17..19]
    );
    let parsed = AmzDate::parse(&compact).map_err(|_| PostPolicyError::Malformed)?;
    // Validate the calendar even when an unrouted form does not enforce expiration.
    crate::clock::unix_seconds(&parsed).ok_or(PostPolicyError::Malformed)?;
    Ok(parsed)
}

fn parse_signature(value: &str) -> Result<Signature, PostPolicyError> {
    if value.len() != 64 {
        return Err(PostPolicyError::Malformed);
    }
    let mut decoded = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(Signature::HmacSha256(CtBytes::from_array(decoded)))
}

fn hex_nibble(byte: u8) -> Result<u8, PostPolicyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PostPolicyError::Malformed),
    }
}

fn decode_base64(encoded: &str, maximum: usize) -> Result<Vec<u8>, PostPolicyError> {
    let bytes = encoded.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(PostPolicyError::Malformed);
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 4 * 3);
    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = chunk_index + 1 == bytes.len() / 4;
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let pad2 = chunk[2] == b'=';
        let pad3 = chunk[3] == b'=';
        if pad2 && (!pad3 || !last || b & 0x0f != 0) {
            return Err(PostPolicyError::Malformed);
        }
        if pad3 && (!last || (!pad2 && base64_value(chunk[2])? & 0x03 != 0)) {
            return Err(PostPolicyError::Malformed);
        }
        if !last && (pad2 || pad3) {
            return Err(PostPolicyError::Malformed);
        }
        let c = if pad2 { 0 } else { base64_value(chunk[2])? };
        let d = if pad3 { 0 } else { base64_value(chunk[3])? };
        decoded.push((a << 2) | (b >> 4));
        if !pad2 {
            decoded.push((b << 4) | (c >> 2));
        }
        if !pad3 {
            decoded.push((c << 6) | d);
        }
        if decoded.len() > maximum {
            return Err(PostPolicyError::Malformed);
        }
    }
    Ok(decoded)
}

fn base64_value(byte: u8) -> Result<u8, PostPolicyError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(PostPolicyError::Malformed),
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[path = "post_policy_redirect.rs"]
mod redirect;
pub use redirect::build_success_action_redirect;

#[cfg(test)]
#[path = "post_policy_tests.rs"]
mod tests;
