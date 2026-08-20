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

//! Why a document was refused.
//!
//! Responsible for: [`XmlError`], one variant per refusal, and nothing else.
//! NOT responsible for: mapping a refusal onto an S3 error code — that is the caller's, because
//! the same malformed body is `MalformedXML` on one operation and `InvalidArgument` on another.
//! Upstream: nothing. Downstream: [`crate::read`].
//!
//! No variant carries a fragment of the document. A parser error that quotes the input is a
//! reflection surface on a body an unauthenticated caller controls.

use core::fmt;

/// Why a document could not be read.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XmlError {
    /// The buffered document is larger than the configured byte ceiling.
    BodyTooLarge,
    /// The bytes are not well-formed XML.
    Malformed,
    /// The document is not UTF-8.
    NotUtf8,
    /// A `DOCTYPE` declaration is present.
    ///
    /// Refused unconditionally rather than parsed and ignored: a `DOCTYPE` is the entry point for
    /// entity expansion, and "we do not expand entities" is a property of the parser this crate
    /// happens to use today, not a promise the wire format makes.
    DocTypeDeclaration,
    /// An entity reference other than the five XML predefines.
    UnsupportedEntity,
    /// The document nests deeper than [`crate::MAX_DEPTH`].
    TooDeep,
    /// The document holds more elements than [`crate::MAX_ELEMENTS`].
    TooManyElements,
    /// One element holds more attributes than [`crate::MAX_ATTRIBUTES_PER_ELEMENT`].
    TooManyAttributes,
    /// One attribute value is larger than [`crate::MAX_ATTRIBUTE_BYTES`].
    AttributeTooLong,
    /// The document has no root element.
    Empty,
    /// A character XML 1.0 cannot represent appears in the document.
    ///
    /// Not a lenience question. XML 1.0 admits tab, newline and carriage return out of the C0
    /// controls and excludes the rest entirely, so a document carrying one is not well-formed and
    /// a conforming parser refuses it. `quick-xml` does not check the character range, which is
    /// why this variant exists: without it the value is read, stored and echoed into a response
    /// that the client's own parser then rejects in full.
    ///
    /// The three spellings are one refusal: the raw byte, `&#1;` and `&#x1;` all name a character
    /// outside the `Char` production, and a character reference to such a character is itself a
    /// fatal error.
    ForbiddenCharacter,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::BodyTooLarge => "the XML body is larger than the parser accepts",
            Self::Malformed => "the body is not well-formed XML",
            Self::NotUtf8 => "the body is not UTF-8",
            Self::DocTypeDeclaration => "the body carries a DOCTYPE declaration",
            Self::UnsupportedEntity => "the body carries an entity reference that is not one of the five XML predefines",
            Self::TooDeep => "the body nests deeper than the parser accepts",
            Self::TooManyElements => "the body holds more elements than the parser accepts",
            Self::TooManyAttributes => "an element holds more attributes than the parser accepts",
            Self::AttributeTooLong => "an attribute value is larger than the parser accepts",
            Self::Empty => "the body has no root element",
            Self::ForbiddenCharacter => "the body carries a character XML cannot represent",
        };
        f.write_str(text)
    }
}

impl core::error::Error for XmlError {}
