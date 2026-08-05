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

//! Bucket names and object keys: the two identifiers authorization and storage must agree on.
//!
//! Responsible for: the default AWS validation rules for both names, the *single* decoding path
//! for an object key, and the predicates the wire layer needs (`needs_url_encoding`,
//! `is_vhost_safe`).
//! NOT responsible for: pluggable naming policy — a `NameValidator` extension point arrives later
//! and will consume [`validate_bucket_name`] as its default — and for percent-decoding the request
//! target as a whole, which is the HTTP layer's job up to the point where it hands over one key.
//! Upstream: [`super::parse_error`]. Downstream: routing, authorization, and every operation that
//! names a bucket or an object.
//!
//! # One decoding path, for a security reason
//!
//! Two published advisories against S3 implementations have the same shape: the value the
//! authorization check reads is not byte-identical to the value the storage layer uses, because
//! one of them decoded, normalised, or collapsed something the other did not. A policy that denies
//! `secret/*` does not deny `secret//x` if only one side collapses the double slash.
//!
//! Therefore: [`ObjectKey`] never normalises. Duplicate slashes stay, `.` and `..` segments stay,
//! Unicode is not case-folded and not NFC-normalised. Decoding happens exactly once, in
//! [`ObjectKey::from_encoded_path`], which also keeps the original encoded bytes — the signature
//! canonicalisation needs those, and re-encoding a decoded key is not guaranteed to reproduce
//! them.

use percent_encoding::percent_decode_str;

use super::parse_error::{ParseError, rules};

/// Maximum object key length, in UTF-8 bytes.
const MAX_KEY_BYTES: usize = 1024;
/// Bucket name length bounds.
const MIN_BUCKET_BYTES: usize = 3;
const MAX_BUCKET_BYTES: usize = 63;

/// An object key: 1..=1024 UTF-8 bytes, never normalised.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectKey {
    key: Box<str>,
    /// The original percent-encoded spelling, kept only when it differs from `key`.
    encoded: Option<Box<str>>,
}

impl ObjectKey {
    /// Builds a key from an already decoded value.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the key is empty, longer than 1024 bytes, or contains a NUL.
    pub fn new(key: impl Into<String>) -> Result<Self, ParseError> {
        let key = key.into();
        validate_object_key(&key)?;
        Ok(Self {
            key: key.into_boxed_str(),
            encoded: None,
        })
    }

    /// Builds a key from the percent-encoded path segment the request carried.
    ///
    /// The encoded spelling is retained: SigV4 canonicalises the *encoded* path, so a signature
    /// check that re-encodes a decoded key can disagree with the client over any byte the client
    /// chose to encode differently.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] when the decoded bytes are not UTF-8, or fail
    /// [`ObjectKey::new`]'s rules.
    pub fn from_encoded_path(encoded: &str) -> Result<Self, ParseError> {
        let decoded = percent_decode_str(encoded)
            .decode_utf8()
            .map_err(|_| ParseError::new("ObjectKey", rules::AWS_OBJECT_KEY, "the percent-decoded key is not valid UTF-8"))?;
        validate_object_key(&decoded)?;
        let encoded = if decoded == encoded {
            None
        } else {
            Some(encoded.to_owned().into_boxed_str())
        };
        Ok(Self {
            key: decoded.into_owned().into_boxed_str(),
            encoded,
        })
    }

    /// The decoded key, exactly as supplied. This is the value both authorization and storage must
    /// use; there is no second, differently normalised spelling to choose from.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// The encoded spelling the request carried, for signature canonicalisation.
    #[must_use]
    pub fn as_encoded(&self) -> &str {
        self.encoded.as_deref().unwrap_or(&self.key)
    }

    /// The key's length in UTF-8 bytes.
    #[must_use]
    pub fn len_bytes(&self) -> usize {
        self.key.len()
    }

    /// Whether a response listing this key must use `encoding-type=url`.
    ///
    /// True for control characters, which XML 1.0 cannot represent at all, and for `&` and `<`,
    /// which can be escaped but which several client XML parsers mishandle inside key elements.
    /// Emitting such a key unencoded produces a body the client cannot parse, which reads to the
    /// user as a corrupt listing rather than as a bad key.
    #[must_use]
    pub fn needs_url_encoding(&self) -> bool {
        self.key.chars().any(|c| c.is_control() || c == '&' || c == '<')
    }
}

/// The default AWS object key rules.
///
/// # Errors
///
/// Returns a [`ParseError`] for an empty key, a key longer than 1024 UTF-8 bytes, or a key
/// containing NUL.
pub fn validate_object_key(key: &str) -> Result<(), ParseError> {
    let err = |reason: &'static str| ParseError::new("ObjectKey", rules::AWS_OBJECT_KEY, reason);
    if key.is_empty() {
        return Err(err("an object key must not be empty"));
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(err("an object key must not exceed 1024 UTF-8 bytes"));
    }
    if key.contains('\0') {
        return Err(err("an object key must not contain a NUL byte"));
    }
    Ok(())
}

/// A bucket name that satisfies the default AWS rules.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BucketName(Box<str>);

impl BucketName {
    /// Validates and wraps a bucket name.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] naming the rule that rejected the name; see
    /// [`validate_bucket_name`].
    pub fn new(name: impl Into<String>) -> Result<Self, ParseError> {
        let name = name.into();
        validate_bucket_name(&name)?;
        Ok(Self(name.into_boxed_str()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the name is safe to use in a virtual-hosted-style HTTPS URL.
    ///
    /// A name containing a dot produces a host with an extra label, which the wildcard certificate
    /// AWS presents does not cover, so TLS verification fails at the client. Such buckets are
    /// legal and still exist, so this is a predicate the routing layer consults to fall back to
    /// path style — not a validation rule. Rejecting them here would make existing data
    /// unreachable.
    #[must_use]
    pub fn is_vhost_safe(&self) -> bool {
        !self.0.contains('.')
    }
}

/// The default AWS bucket naming rules.
///
/// # Errors
///
/// Returns a [`ParseError`] when the name is outside 3..=63 characters, uses a character outside
/// `[a-z0-9.-]`, does not start and end with a letter or digit, contains `..`, is formatted as an
/// IPv4 address, or uses one of the reserved prefixes or suffixes.
pub fn validate_bucket_name(name: &str) -> Result<(), ParseError> {
    let err = |reason: &'static str| ParseError::new("BucketName", rules::AWS_BUCKET_NAMING, reason);

    if !(MIN_BUCKET_BYTES..=MAX_BUCKET_BYTES).contains(&name.len()) {
        return Err(err("a bucket name must be between 3 and 63 characters long"));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(err("a bucket name may only contain lowercase letters, digits, hyphens and dots"));
    }
    let first_last_ok = |b: Option<u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !first_last_ok(name.bytes().next()) || !first_last_ok(name.bytes().next_back()) {
        return Err(err("a bucket name must begin and end with a letter or a digit"));
    }
    if name.contains("..") {
        return Err(err("a bucket name must not contain two consecutive dots"));
    }
    if is_ipv4_shaped(name) {
        return Err(err("a bucket name must not be formatted as an IPv4 address"));
    }
    if name.starts_with("xn--") || name.starts_with("sthree-") {
        return Err(err("a bucket name must not use a reserved prefix"));
    }
    if name.ends_with("-s3alias") || name.ends_with("--ol-s3") {
        return Err(err("a bucket name must not use a reserved suffix"));
    }
    Ok(())
}

/// Whether the name is four dot-separated decimal octets, which would make a path-style URL
/// ambiguous with an address.
fn is_ipv4_shaped(name: &str) -> bool {
    let mut labels = 0usize;
    for label in name.split('.') {
        labels += 1;
        let valid = !label.is_empty()
            && label.len() <= 3
            && label.bytes().all(|b| b.is_ascii_digit())
            && label.parse::<u16>().is_ok_and(|value| value <= 255);
        if !valid {
            return false;
        }
    }
    labels == 4
}
