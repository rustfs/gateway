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

//! The request key, condition and error echo used by DeleteObjects.
//!
//! Responsible for: carrying entry identities, rejected inputs, and response text.
//! NOT responsible for: interpreting the XML document or selecting the entry outcome.
//! Upstream: generated DTOs and codecs. Downstream: authorization and operation handlers.

use crate::scalar::MAX_KEY_BYTES;
use crate::{ETag, NamePolicy, NameRejection, ObjectKey, ParseError, WirePlaceholder, is_xml_representable};

/// Why a decoded RustFS DeleteObjects entry has no executable key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteObjectKeyRejection {
    /// The entry explicitly sent an empty key.
    Empty,
    /// The decoded key exceeds the object key's UTF-8 byte ceiling.
    TooLong,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum DeleteObjectKeyValue {
    #[default]
    Unset,
    Object(ObjectKey),
    Rejected(DeleteObjectKeyRejection, Box<str>),
}

/// The key carried by a DeleteObjects entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteObjectKey(DeleteObjectKeyValue);

impl DeleteObjectKey {
    /// Reads an already decoded RustFS request member using the deployment's key policy.
    ///
    /// Explicit empty and overlength keys can be reported as entry rejections.
    ///
    /// # Errors
    ///
    /// Returns the naming policy's rejection for other invalid keys.
    pub fn materialize_rustfs_decoded(value: &str, names: &NamePolicy) -> Result<Self, NameRejection> {
        use DeleteObjectKeyRejection::{Empty, TooLong};
        let rejection = match ObjectKey::materialize_decoded(value, names) {
            Ok(key) => return Ok(key.into()),
            Err(NameRejection::Empty) if value.is_empty() => Empty,
            Err(NameRejection::TooLong)
                if value.len() > MAX_KEY_BYTES && is_xml_representable(value) && !value.chars().any(char::is_control) =>
            {
                TooLong
            }
            Err(error) => return Err(error),
        };
        Ok(Self(DeleteObjectKeyValue::Rejected(rejection, value.into())))
    }

    /// Returns the key an authorization resource or storage operation may use.
    #[must_use]
    pub fn object_key(&self) -> Option<&ObjectKey> {
        match &self.0 {
            DeleteObjectKeyValue::Object(key) => Some(key),
            DeleteObjectKeyValue::Rejected(..) | DeleteObjectKeyValue::Unset => None,
        }
    }

    /// Returns the rejection carried by an explicitly rejected entry, if any.
    #[must_use]
    pub fn rejection(&self) -> Option<DeleteObjectKeyRejection> {
        match self.0 {
            DeleteObjectKeyValue::Rejected(rejection, _) => Some(rejection),
            DeleteObjectKeyValue::Object(_) | DeleteObjectKeyValue::Unset => None,
        }
    }

    /// Returns the decoded entry text, including the spelling of a rejected key.
    ///
    /// For an unset placeholder this is empty. Use [`Self::object_key`] to obtain an
    /// identity for authorization or storage.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            DeleteObjectKeyValue::Object(key) => key.as_str(),
            DeleteObjectKeyValue::Rejected(_, raw) => raw,
            DeleteObjectKeyValue::Unset => "",
        }
    }
}

impl From<ObjectKey> for DeleteObjectKey {
    fn from(value: ObjectKey) -> Self {
        if value.is_wire_placeholder() {
            Self::default()
        } else {
            Self(DeleteObjectKeyValue::Object(value))
        }
    }
}

impl WirePlaceholder for DeleteObjectKey {
    fn is_wire_placeholder(&self) -> bool {
        matches!(self.0, DeleteObjectKeyValue::Unset)
    }
}

/// An entity-tag condition or the explicitly strong-empty condition a RustFS entry can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteObjectETag(Option<ETag>);

impl DeleteObjectETag {
    /// The explicitly quoted, strong-empty condition reported by a RustFS DeleteObjects entry.
    pub const STRONG_EMPTY: Self = Self(None);

    /// Returns the entity tag available for ordinary condition evaluation.
    #[must_use]
    pub fn etag(&self) -> Option<&ETag> {
        self.0.as_ref()
    }

    /// Returns whether this is the explicitly strong-empty condition.
    #[must_use]
    pub fn is_strong_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl From<ETag> for DeleteObjectETag {
    fn from(value: ETag) -> Self {
        Self(Some(value))
    }
}

/// The exact XML text of a DeleteObjects response error's Key member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteKeyEcho(Box<str>);

impl DeleteKeyEcho {
    /// Builds an echo from XML-representable text, including an empty or oversized key.
    ///
    /// # Errors
    ///
    /// Returns a parse error if XML 1.0 cannot carry the text.
    pub fn new(value: impl Into<String>) -> Result<Self, ParseError> {
        let value = value.into();
        if !is_xml_representable(&value) {
            return Err(ParseError::new(
                "DeleteKeyEcho",
                "xml:character-range",
                "the text contains a character XML 1.0 cannot carry",
            ));
        }
        Ok(Self(value.into_boxed_str()))
    }

    /// Returns the text for the XML writer to escape.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<ObjectKey> for DeleteKeyEcho {
    type Error = ParseError;

    fn try_from(key: ObjectKey) -> Result<Self, Self::Error> {
        Self::new(key.as_str())
    }
}
