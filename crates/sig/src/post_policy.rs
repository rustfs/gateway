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
    AmzDate, AuthError, CredentialScope, CtBytes, RequestNow, SessionToken, Signature, SignatureMatch, SigningKey,
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

        let credential = fields.required("x-amz-credential")?;
        let scope = CredentialScope::parse(credential).map_err(|_| PostPolicyError::Malformed)?;
        let signed_at = AmzDate::parse(fields.required("x-amz-date")?).map_err(|_| PostPolicyError::Malformed)?;
        if scope.date().as_str() != &signed_at.as_str()[..8] {
            return Err(PostPolicyError::Malformed);
        }
        let signature = parse_signature(fields.required("x-amz-signature")?)?;
        let filename = if raw_filename.is_empty() {
            None
        } else {
            Some(clean_filename(raw_filename)?)
        };
        let final_key = substitute_filename(fields.required("key")?, filename.as_deref())?;

        let mut mentioned = BTreeSet::new();
        let mut minimum_file_bytes = 0;
        let mut maximum_file_bytes = limits.max_file_bytes;
        for condition in &conditions {
            match condition {
                Condition::Exact(name, expected) => {
                    mentioned.insert(name.clone());
                    if condition_value(&fields, name, &final_key)? != expected {
                        return Err(PostPolicyError::ConditionFailed);
                    }
                }
                Condition::StartsWith(name, prefix) => {
                    mentioned.insert(name.clone());
                    if !condition_value(&fields, name, &final_key)?.starts_with(prefix) {
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

        Ok(Self {
            encoded: encoded.to_owned(),
            scope,
            signed_at,
            signature,
            session_token: fields
                .get("x-amz-security-token")
                .map(SessionToken::new)
                .transpose()
                .map_err(|_| PostPolicyError::Malformed)?,
            bucket: fields.required("bucket")?.to_owned(),
            final_key,
            minimum_file_bytes,
            maximum_file_bytes,
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
        if bucket != self.bucket || key != self.final_key {
            return Err(PostPolicyError::ConditionFailed);
        }
        if file_bytes < self.minimum_file_bytes {
            return Err(PostPolicyError::EntityTooSmall);
        }
        if file_bytes > self.maximum_file_bytes {
            return Err(PostPolicyError::EntityTooLarge);
        }
        Ok(PostPolicyEnforcement(()))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0=";

    #[test]
    fn c_sig_0417_valid_policy_produces_a_proof_and_final_receipt() {
        let key = SigningKey::from_array([7u8; 32]);
        let signature = hex_encode(&hmac_sha256(key.expose(), POLICY.as_bytes()));
        let fields = valid_fields(&signature);
        let policy = parse(&fields, "../report.txt").expect("valid policy");
        assert_eq!(policy.final_key(), "uploads/report.txt");
        assert!(policy.verify(&key).is_ok());
        assert!(policy.enforce_final("example-bucket", "uploads/report.txt", 1).is_ok());
    }

    #[test]
    fn c_sig_0418_case_only_duplicate_fields_are_rejected() {
        let signature = "0".repeat(64);
        let mut fields = valid_fields(&signature);
        fields.push(("X-Amz-Date", "20150830T123600Z"));
        assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
    }

    #[test]
    fn c_sig_0419_missing_filename_for_a_template_is_rejected() {
        let signature = "0".repeat(64);
        assert_eq!(parse(&valid_fields(&signature), "").err(), Some(PostPolicyError::ConditionFailed));
    }

    #[test]
    fn c_sig_0420_control_character_in_filename_is_rejected() {
        let signature = "0".repeat(64);
        assert_eq!(parse(&valid_fields(&signature), "bad\0name").err(), Some(PostPolicyError::Malformed));
    }

    #[test]
    fn c_sig_0421_wrong_field_value_is_rejected() {
        let signature = "0".repeat(64);
        let mut fields = valid_fields(&signature);
        fields[1].1 = "other-bucket";
        assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::ConditionFailed));
    }

    #[test]
    fn c_sig_0422_bad_base64_padding_is_rejected() {
        let signature = "0".repeat(64);
        let mut fields = valid_fields(&signature);
        fields[6].1 = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0gIB==";
        assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
    }

    #[test]
    fn c_sig_0423_duplicate_json_keys_are_rejected() {
        let signature = "0".repeat(64);
        let mut fields = valid_fields(&signature);
        fields[6].1 = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsic3RhcnRzLXdpdGgiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0=";
        assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
    }

    #[test]
    fn c_sig_0424_unknown_condition_operators_are_rejected() {
        let signature = "0".repeat(64);
        let mut fields = valid_fields(&signature);
        fields[6].1 = "eyJleHBpcmF0aW9uIjoiMjAxNS0wOC0zMFQxMzozNjowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJleGFtcGxlLWJ1Y2tldCJ9LFsiY29udGFpbnMiLCIka2V5IiwidXBsb2Fkcy8iXSx7IngtYW16LWFsZ29yaXRobSI6IkFXUzQtSE1BQy1TSEEyNTYifSx7IngtYW16LWNyZWRlbnRpYWwiOiJBS0lERVhBTVBMRS8yMDE1MDgzMC91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAxNTA4MzBUMTIzNjAwWiJ9XX0=";
        assert_eq!(parse(&fields, "report.txt").err(), Some(PostPolicyError::Malformed));
    }

    #[test]
    fn c_sig_0425_expired_policy_is_rejected() {
        let signature = "0".repeat(64);
        let fields = valid_fields(&signature);
        let result = PostPolicy::parse(
            &fields,
            "report.txt",
            PostPolicyLimits::default(),
            RequestNow::from_unix_seconds(1_440_941_761),
        );
        assert_eq!(result.err(), Some(PostPolicyError::Expired));
    }

    #[test]
    fn c_sig_0426_wrong_signature_is_rejected() {
        let signature = "0".repeat(64);
        let policy = parse(&valid_fields(&signature), "report.txt").expect("policy shape is valid");
        assert_eq!(
            policy.verify(&SigningKey::from_array([7u8; 32])).err(),
            Some(PostPolicyError::SignatureMismatch)
        );
    }

    #[test]
    fn c_sig_0427_final_size_bounds_are_enforced_both_ways() {
        let signature = "0".repeat(64);
        let mut policy = parse(&valid_fields(&signature), "report.txt").expect("policy shape is valid");
        policy.minimum_file_bytes = 2;
        policy.maximum_file_bytes = 3;
        assert_eq!(
            policy.enforce_final("example-bucket", "uploads/report.txt", 1).err(),
            Some(PostPolicyError::EntityTooSmall)
        );
        assert_eq!(
            policy.enforce_final("example-bucket", "uploads/report.txt", 4).err(),
            Some(PostPolicyError::EntityTooLarge)
        );
    }

    fn parse(fields: &[(&str, &str)], filename: &str) -> Result<PostPolicy, PostPolicyError> {
        PostPolicy::parse(
            fields,
            filename,
            PostPolicyLimits::default(),
            RequestNow::from_unix_seconds(1_440_938_160),
        )
    }

    fn valid_fields(signature: &str) -> Vec<(&str, &str)> {
        vec![
            ("key", "uploads/${filename}"),
            ("bucket", "example-bucket"),
            ("x-amz-algorithm", ALGORITHM),
            ("x-amz-credential", "AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request"),
            ("x-amz-date", "20150830T123600Z"),
            ("x-amz-signature", signature),
            ("policy", POLICY),
        ]
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
