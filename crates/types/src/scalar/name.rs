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
//! Responsible for: the two name types themselves, their wire-shape rules, the ingress
//! constructors that run [`super::naming`]'s single normalisation, and the predicates the wire
//! layer needs (`needs_url_encoding`, `is_vhost_safe`).
//! NOT responsible for: the normalisation and the safety floor themselves, which live in
//! [`super::naming`] so that there is exactly one of each; percent-decoding the request target as
//! a whole, which the HTTP layer does up to the point where it hands over one label.
//! Upstream: [`super::parse_error`], [`super::naming`]. Downstream: routing, authorization, and
//! every operation that names a bucket or an object.
//!
//! # Two constructors, and the difference between them
//!
//! Three published advisories against S3 implementations have the same shape: the value the
//! authorization check reads is not byte-identical to the value the storage layer uses, because
//! one of them decoded, normalised, or collapsed something the other did not. A policy that denies
//! `secret/*` does not deny `secret//x` if only one side collapses the double slash.
//!
//! So a name a *client chose* is built by [`ObjectKey::materialize`] or
//! [`BucketName::materialize`] — the ingress constructors, which decode once, apply the
//! [`SlashPolicy`], run the safety floor and then the deployment's [`NameValidator`]. Every stage
//! downstream reads that one value.
//!
//! [`ObjectKey::new`] and [`BucketName::new`] are the *representation* constructors. They enforce
//! the rules a value must satisfy to be expressible at all — non-empty, within the length limit,
//! no NUL — and nothing else, because a key that already exists in a backend may hold bytes no
//! client would be allowed to name today, and a listing has to be able to answer with it.
//! `conformance/cases/list/c-list-0035` is exactly that object. Anything reading a name off the
//! wire uses `materialize`; a `new` on a request path would be the second normalisation site this
//! module exists to prevent.
//!
//! Within both: [`ObjectKey`] never rewrites bytes beyond the [`SlashPolicy`]. `.` segments stay,
//! Unicode is not case-folded and not NFC-normalised. The encoded spelling is retained separately
//! — the signature canonicalisation needs it, and re-encoding a decoded key is not guaranteed to
//! reproduce it.

use super::naming::{
    MAX_KEY_BYTES, NamePolicy, NameRejection, aws_bucket_rules, check_bucket, check_decoded_key, floor_check_bucket,
    normalize_key,
};
use super::parse_error::{ParseError, rules};
use crate::placeholder::WirePlaceholder;

#[cfg(doc)]
use super::naming::{NameValidator, SlashPolicy};

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

    /// **The single ingress.** Builds a key from the percent-encoded label the request carried.
    ///
    /// Decodes exactly once, refuses a residual encoded separator, applies the policy's
    /// [`SlashPolicy`], runs the unconditional safety floor and then the deployment's
    /// [`NameValidator`]. The value it returns is the one authorization, auditing and storage all
    /// read; there is no second, differently normalised spelling to choose from.
    ///
    /// The encoded spelling is retained: SigV4 canonicalises the *encoded* path, so a signature
    /// check that re-encodes a decoded key can disagree with the client over any byte the client
    /// chose to encode differently.
    ///
    /// # Errors
    ///
    /// The [`NameRejection`] naming the first rule that refused the label.
    pub fn materialize(encoded: &str, policy: &NamePolicy) -> Result<Self, NameRejection> {
        let key = normalize_key(encoded, policy)?;
        let encoded = if key == encoded {
            None
        } else {
            Some(encoded.to_owned().into_boxed_str())
        };
        Ok(Self {
            key: key.into_boxed_str(),
            encoded,
        })
    }

    /// The ingress for a key some other reader has already decoded — a body element or a query
    /// parameter, whose decode belongs to the XML or query reader that produced it.
    ///
    /// No decode happens here. Decoding a value that was already decoded is the double-decode bug
    /// [`super::naming`] exists to prevent, so this applies the floor and the validator to what it
    /// was given.
    ///
    /// # Errors
    ///
    /// The [`NameRejection`] naming the rule that refused it.
    pub fn materialize_decoded(decoded: &str, policy: &NamePolicy) -> Result<Self, NameRejection> {
        check_decoded_key(decoded, policy)?;
        Ok(Self {
            key: decoded.to_owned().into_boxed_str(),
            encoded: None,
        })
    }

    /// Builds a key from the percent-encoded label under the default policy.
    ///
    /// Equivalent to [`ObjectKey::materialize`] with [`NamePolicy::default`]. Kept for the call
    /// sites that have no policy to hand and documented as the default rather than as a second
    /// rule: it calls the same normalisation, so there is still only one.
    ///
    /// # Errors
    ///
    /// A [`ParseError`] carrying the rejection's reason.
    pub fn from_encoded_path(encoded: &str) -> Result<Self, ParseError> {
        Self::materialize(encoded, &NamePolicy::default())
            .map_err(|rejection| ParseError::new("ObjectKey", rules::AWS_OBJECT_KEY, rejection.reason()))
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

    /// Whether a response listing this key must percent-encode it even when the request did not
    /// ask for `encoding-type=url`.
    ///
    /// True exactly when the key carries a character no XML 1.0 document may contain — see
    /// [`is_xml_representable`]. Emitting such a key produces a body the client's parser rejects
    /// outright, so one badly named object hides every other object in the bucket.
    ///
    /// `&`, `<` and `"` are **not** here, deliberately. They are representable, the writer escapes
    /// the ones that need it, and `c-list-0036` pins that a key carrying all three comes back
    /// XML-escaped rather than percent-encoded. Forcing encoding on them would silently change a
    /// key every client can already read.
    #[must_use]
    pub fn needs_url_encoding(&self) -> bool {
        !is_xml_representable(&self.key)
    }
}

/// Whether every character of a value can appear in an XML 1.0 document at all.
///
/// XML 1.0 admits tab, newline and carriage return out of the C0 controls and excludes the rest
/// entirely — escaped or not, `&#1;` is as illegal as the raw byte. A value carrying one has no
/// XML spelling, so the only answer that leaves the response parseable is to percent-encode it.
///
/// This is about *representability*, not about escaping: `&`, `<`, `>` and `"` are all
/// representable and are the writer's business, not this predicate's.
#[must_use]
pub fn is_xml_representable(value: &str) -> bool {
    !value.chars().any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

impl Default for ObjectKey {
    /// The empty key — a placeholder that is **invalid on the wire**, and exists for one reason.
    ///
    /// ADR-0004 P10: a required member of a generated dto uses a bare type, and every generated
    /// dto derives `Default` so that `..Default::default()` keeps compiling when AWS adds a
    /// member. That combination needs a `Default` here. The value it produces is rejected by
    /// [`validate_object_key`], so it can never be a key any client sent or any backend stored.
    ///
    /// **The decoding path never produces it.** A request that omits the key is rejected by the
    /// binding that looked for it, and the generated `check_required` fails closed on any that
    /// slips through. Treat a value that compares equal to this one as a bug, never as a key.
    fn default() -> Self {
        Self {
            key: Box::from(""),
            encoded: None,
        }
    }
}

impl WirePlaceholder for ObjectKey {
    fn is_wire_placeholder(&self) -> bool {
        self.key.is_empty()
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

    /// **The single ingress.** Validates a bucket label against the floor and then the
    /// deployment's [`NameValidator`].
    ///
    /// A bucket label is never percent-decoded — the floor refuses one containing `%` — and no
    /// [`SlashPolicy`] applies to it, because a label containing a separator is not a label.
    ///
    /// # Errors
    ///
    /// The [`NameRejection`] naming the rule that refused it.
    pub fn materialize(name: &str, policy: &NamePolicy) -> Result<Self, NameRejection> {
        check_bucket(name, policy)?;
        Ok(Self(name.to_owned().into_boxed_str()))
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

impl Default for BucketName {
    /// The empty name — a placeholder that is **invalid on the wire**, and exists for one reason.
    ///
    /// ADR-0004 P10: a required member of a generated dto uses a bare type, and every generated
    /// dto derives `Default` so that `..Default::default()` keeps compiling when AWS adds a
    /// member. That combination needs a `Default` here. The value it produces is three characters
    /// short of the shortest legal name and is rejected by [`validate_bucket_name`], so it can
    /// never name a bucket that exists.
    ///
    /// **The decoding path never produces it.** A request that omits the bucket is rejected by
    /// routing before a dto is built, and the generated `check_required` fails closed on any that
    /// slips through. Treat a value that compares equal to this one as a bug, never as a bucket —
    /// in particular, never let one reach an authorization check.
    fn default() -> Self {
        Self(Box::from(""))
    }
}

impl WirePlaceholder for BucketName {
    fn is_wire_placeholder(&self) -> bool {
        self.0.is_empty()
    }
}

/// The default bucket naming rules: the safety floor, then the AWS rules on top of it.
///
/// This is [`BucketName::materialize`] under [`NamePolicy::default`], expressed as a free function
/// for the call sites that predate the policy. It calls the same two implementations, so there is
/// no second copy of either rule set to drift from this one.
///
/// # Errors
///
/// Returns a [`ParseError`] when the name breaks a floor rule, is outside 3..=63 bytes, uses a
/// character outside `[a-z0-9.-]`, does not start and end with a letter or digit, contains `..`,
/// is formatted as an IPv4 address, or uses one of the reserved prefixes or suffixes.
pub fn validate_bucket_name(name: &str) -> Result<(), ParseError> {
    floor_check_bucket(name)
        .and_then(|()| aws_bucket_rules(name))
        .map_err(|rejection| ParseError::new("BucketName", rules::AWS_BUCKET_NAMING, rejection.reason()))
}
