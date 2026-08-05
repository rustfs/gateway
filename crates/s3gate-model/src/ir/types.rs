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

//! The scalar and composite type vocabulary of the IR.
//!
//! Responsible for: [`Type`] plus the three enums only it needs — timestamp rendering, entity-tag
//! rendering, and value suppression.
//! NOT responsible for: the document structure (that is [`super`]) or JSON rendering (that is
//! [`super::emit`]).
//! Upstream: [`crate::lower`]. Downstream: `s3gate-codegen`.
//!
//! Nothing here has a default rendering. An `ETag` in a header and an `ETag` in an XML body are
//! two different wire forms, so the context is a parameter of the type rather than a convention
//! a call site is expected to remember.

use super::ChecksumAlgo;

/// The scalar and composite vocabulary. The IR names a type; `s3gate-types` implements it.
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    /// A UTF-8 string.
    String,
    /// Round-tripped byte for byte, never parsed.
    OpaqueString,
    /// 32-bit integer.
    Integer,
    /// 64-bit integer.
    Long,
    /// Boolean.
    Boolean,
    /// A date in one of four renderings.
    Timestamp(TimestampFormat),
    /// An entity tag in one of three rendering contexts.
    ETag(ETagRender),
    /// A single checksum value.
    Checksum(ChecksumAlgo),
    /// The packed algorithm-plus-value form.
    ChecksumSpec,
    /// An object key.
    ObjectKey,
    /// A bucket name.
    BucketName,
    /// A byte range.
    Range,
    /// An open string enumeration.
    StringEnum(Vec<String>),
    /// A nested structure.
    Structure(String),
    /// A list.
    List {
        /// Element type.
        member: Box<Type>,
        /// Whether the element repeats with no wrapper.
        flattened: bool,
        /// Wrapper element name when not flattened.
        wrapper_name: Option<String>,
    },
    /// A map.
    Map {
        /// Key type.
        key: Box<Type>,
        /// Value type.
        value: Box<Type>,
    },
    /// A blob.
    Blob {
        /// Whether it streams.
        streaming: bool,
    },
    /// A nested union.
    Union(String),
}

/// The four timestamp renderings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampFormat {
    /// RFC 9110 `IMF-fixdate`.
    HttpDate,
    /// Extended ISO 8601.
    Iso8601,
    /// Basic ISO 8601, as used by the SigV4 credential scope.
    Iso8601Basic,
    /// Seconds since the epoch.
    EpochSeconds,
}

impl TimestampFormat {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            TimestampFormat::HttpDate => "HttpDate",
            TimestampFormat::Iso8601 => "Iso8601",
            TimestampFormat::Iso8601Basic => "Iso8601Basic",
            TimestampFormat::EpochSeconds => "EpochSeconds",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "HttpDate" => TimestampFormat::HttpDate,
            "Iso8601" => TimestampFormat::Iso8601,
            "Iso8601Basic" => TimestampFormat::Iso8601Basic,
            "EpochSeconds" => TimestampFormat::EpochSeconds,
            _ => return None,
        })
    }
}

/// The three entity-tag rendering contexts. There is no default on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ETagRender {
    /// Quoted, in a header.
    HeaderQuoted,
    /// Quoted, in an XML element.
    XmlQuoted,
    /// Bare, in an XML element.
    XmlBare,
}

impl ETagRender {
    /// The IR spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            ETagRender::HeaderQuoted => "HeaderQuoted",
            ETagRender::XmlQuoted => "XmlQuoted",
            ETagRender::XmlBare => "XmlBare",
        }
    }

    /// Parses an IR spelling.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "HeaderQuoted" => ETagRender::HeaderQuoted,
            "XmlQuoted" => ETagRender::XmlQuoted,
            "XmlBare" => ETagRender::XmlBare,
            _ => return None,
        })
    }
}

/// When a present value must still not be written to the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OmitWhen {
    /// The value is empty.
    Empty,
    /// The value equals the wire default.
    Default,
    /// The value equals this literal.
    ValueEquals(String),
    /// A request field has this value.
    RequestField {
        /// The request field consulted.
        field: String,
        /// The value that suppresses emission.
        equals: String,
    },
}
