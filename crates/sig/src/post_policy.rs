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
//! and the SigV4 policy comparison. Not responsible for: multipart framing, object-key typing, or
//! HTTP responses. Upstream: the bounded form parser. Downstream: the built-in authenticator.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::post_policy_json::{JsonParser, JsonValue};
use crate::{
    AmzDate, AuthError, CredentialScope, CtBytes, RequestNow, SecretBytes, SessionToken, Signature, SignatureMatch, SigningKey,
    VerifyRejection,
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
    bucket: String,
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
        let fields = FieldSet::parse(fields)?;
        for required in REQUIRED_FIELDS {
            fields.required(required)?;
        }
        if fields.required("x-amz-algorithm")? != ALGORITHM {
            return Err(PostPolicyError::Malformed);
        }
        let (encoded, conditions) = parse_policy_document(&fields, limits, now)?;

        let credential = fields.required("x-amz-credential")?;
        let scope = CredentialScope::parse(credential).map_err(|_| PostPolicyError::Malformed)?;
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
    bucket: String,
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
    /// Parses and enforces the shared pre-file POST-policy conditions for a SigV2 form.
    /// # Errors
    /// Returns [`PostPolicyError`] for malformed or expired policies and failed conditions.
    pub fn parse(
        fields: &[(&str, &str)],
        raw_filename: &str,
        limits: PostPolicyLimits,
        now: RequestNow,
    ) -> Result<Self, PostPolicyError> {
        let fields = FieldSet::parse(fields)?;
        fields.required("awsaccesskeyid")?;
        fields.required("signature")?;
        let (encoded, conditions) = parse_policy_document(&fields, limits, now)?;
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
    bucket: String,
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
) -> Result<(String, Vec<Condition>), PostPolicyError> {
    let encoded = fields.required("policy")?;
    if encoded.is_empty() || encoded.len() > limits.max_encoded_bytes {
        return Err(PostPolicyError::Malformed);
    }
    let decoded = decode_base64(encoded, limits.max_decoded_bytes)?;
    let root = JsonParser::parse(&decoded, limits.max_json_depth, limits.max_json_elements)?;
    let (expiration, conditions) = parse_policy(root)?;
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
    for condition in conditions {
        match condition {
            Condition::Exact(name, expected) => {
                mentioned.insert(name.clone());
                if condition_value(fields, name, &final_key)? != expected {
                    return Err(PostPolicyError::ConditionFailed);
                }
            }
            Condition::StartsWith(name, prefix) => {
                mentioned.insert(name.clone());
                if !condition_value(fields, name, &final_key)?.starts_with(prefix) {
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
        if !EXEMPT_FIELDS.contains(&name.as_str()) && !mentioned.contains(name) {
            return Err(PostPolicyError::ConditionFailed);
        }
    }

    Ok(CommonPolicy {
        encoded,
        bucket: fields.required("bucket")?.to_owned(),
        final_key,
        minimum_file_bytes,
        maximum_file_bytes,
    })
}

fn enforce_final_values(
    expected_bucket: &str,
    expected_key: &str,
    minimum_file_bytes: u64,
    maximum_file_bytes: u64,
    bucket: &str,
    key: &str,
    file_bytes: u64,
) -> Result<PostPolicyEnforcement, PostPolicyError> {
    if bucket != expected_bucket || key != expected_key {
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

enum Condition {
    Exact(String, String),
    StartsWith(String, String),
    ContentLengthRange(u64, u64),
}

fn parse_policy(root: JsonValue) -> Result<(String, Vec<Condition>), PostPolicyError> {
    let JsonValue::Object(mut members) = root else {
        return Err(PostPolicyError::Malformed);
    };
    if members.len() != 2 {
        return Err(PostPolicyError::Malformed);
    }
    let expiration = take_member(&mut members, "expiration")?.into_string()?;
    let conditions = take_member(&mut members, "conditions")?.into_array()?;
    let parsed = conditions.into_iter().map(parse_condition).collect::<Result<Vec<_>, _>>()?;
    if parsed.is_empty() {
        return Err(PostPolicyError::Malformed);
    }
    Ok((expiration, parsed))
}

fn take_member(members: &mut Vec<(String, JsonValue)>, name: &str) -> Result<JsonValue, PostPolicyError> {
    let index = members
        .iter()
        .position(|(key, _)| key == name)
        .ok_or(PostPolicyError::Malformed)?;
    Ok(members.swap_remove(index).1)
}

fn parse_condition(value: JsonValue) -> Result<Condition, PostPolicyError> {
    match value {
        JsonValue::Object(mut members) if members.len() == 1 => {
            let (name, value) = members.pop().ok_or(PostPolicyError::Malformed)?;
            Ok(Condition::Exact(normalize_condition_name(&name)?, value.into_string()?))
        }
        JsonValue::Array(values) if values.len() == 3 => {
            let mut values = values.into_iter();
            let operator = values.next().ok_or(PostPolicyError::Malformed)?.into_string()?;
            let second = values.next().ok_or(PostPolicyError::Malformed)?;
            let third = values.next().ok_or(PostPolicyError::Malformed)?;
            match operator.as_str() {
                "eq" => Ok(Condition::Exact(normalize_variable(second.into_string()?)?, third.into_string()?)),
                "starts-with" => Ok(Condition::StartsWith(normalize_variable(second.into_string()?)?, third.into_string()?)),
                "content-length-range" => Ok(Condition::ContentLengthRange(second.into_u64()?, third.into_u64()?)),
                _ => Err(PostPolicyError::Malformed),
            }
        }
        _ => Err(PostPolicyError::Malformed),
    }
}

fn normalize_variable(value: String) -> Result<String, PostPolicyError> {
    normalize_condition_name(value.strip_prefix('$').ok_or(PostPolicyError::Malformed)?)
}

fn normalize_condition_name(name: &str) -> Result<String, PostPolicyError> {
    if name.is_empty() || !name.is_ascii() || name.eq_ignore_ascii_case("file") {
        return Err(PostPolicyError::Malformed);
    }
    Ok(name.to_ascii_lowercase())
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

fn parse_expiration(value: &str) -> Result<AmzDate, PostPolicyError> {
    let bytes = value.as_bytes();
    if !value.is_ascii()
        || bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return Err(PostPolicyError::Malformed);
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
    AmzDate::parse(&compact).map_err(|_| PostPolicyError::Malformed)
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

/// Q7: Safe construction of `success_action_redirect`.
///
/// Rules:
/// 1. Only `http` and `https` schemes are allowed.
/// 2. Control characters (including CR, LF) are rejected.
/// 3. `bucket`, `key`, and `etag` are appended as query parameters.
/// 4. Parameters are inserted **before** any existing fragment.
/// 5. An optional host allowlist is checked.
/// 6. Validation failure returns 400, **never** falls back to `success_action_status`.
///
/// # Errors
///
/// [`PostPolicyError::Malformed`] when the URL is invalid, has a disallowed scheme,
/// contains control characters, or the host is not in the allowlist.
pub fn build_success_action_redirect(
    raw: &str,
    bucket: &str,
    key: &str,
    etag: &str,
    allowed_hosts: Option<&[&str]>,
) -> Result<String, PostPolicyError> {
    // Reject control characters (CR, LF, NUL, etc.) before URL parsing.
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(PostPolicyError::Malformed);
    }

    // Parse the URL. We use a simple manual parse to avoid adding a `url` crate dependency
    // for this single use case. The URL must start with http:// or https://.
    let scheme_end = raw.find("://").ok_or(PostPolicyError::Malformed)?;
    let scheme = &raw[..scheme_end];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Err(PostPolicyError::Malformed);
    }

    // Extract host for allowlist check.
    let after_scheme = &raw[scheme_end + 3..];
    let host_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let host = &after_scheme[..host_end];

    // Strip port for allowlist comparison.
    let host_without_port = host.rsplit_once(':').map_or(host, |(h, _)| h);

    if let Some(allowed) = allowed_hosts
        && !allowed.iter().any(|h| h.eq_ignore_ascii_case(host_without_port))
    {
        return Err(PostPolicyError::Malformed);
    }

    // Build the redirect URL with bucket, key, and etag as query parameters.
    // Parameters must be inserted before any fragment.
    let (base, fragment) = match raw.find('#') {
        Some(pos) => (&raw[..pos], Some(&raw[pos..])),
        None => (raw, None),
    };

    let separator = if base.contains('?') { '&' } else { '?' };
    let mut result = String::with_capacity(base.len() + 128);
    result.push_str(base);
    result.push(separator);
    result.push_str("bucket=");
    push_percent_encoded(&mut result, bucket.as_bytes());
    result.push_str("&key=");
    push_percent_encoded(&mut result, key.as_bytes());
    result.push_str("&etag=");
    push_percent_encoded(&mut result, etag.as_bytes());

    if let Some(frag) = fragment {
        result.push_str(frag);
    }

    Ok(result)
}

/// Percent-encodes bytes into the output string using RFC 3986 unreserved rules.
fn push_percent_encoded(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
}

#[cfg(test)]
#[path = "post_policy_tests.rs"]
mod tests;
