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

//! A decoded input as comparable field paths, and the one text form each member value takes.
//!
//! Responsible for: [`Fields`] — member path to value — and the [`Render`] rule that spells a
//! value of either stack's type in one canonical text, so equal meaning is equal text and a
//! lossy spelling on one side shows up as a difference rather than being normalised away.
//! NOT responsible for: which members an operation has (`project/*.rs`), or comparing (`decode.rs`).
//! Upstream: the gateway DTO scalars and the pinned s3s DTO scalars. Downstream: `project/*.rs`.
//!
//! # The canonical spellings
//!
//! Text and enumerations are their wire text. Integers and booleans are Rust's `Display`. An
//! instant is `<unix seconds>.<nine fractional digits>`, so nanoseconds are compared exactly and a
//! side that truncates is caught. An entity-tag condition is its header text. A byte range is its
//! header text when it parsed to one range; the gateway keeps an unparseable or multi-range header
//! verbatim (RFC 9110 says ignore it), and that is spelled `ignored:` or `multi:` plus the text.

use std::collections::BTreeMap;
use std::fmt;

use crate::s3s;
use s3s::dto as oracle;

/// One member's value on one side.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FieldValue {
    /// This side's input has no such member at all.
    NoMember,
    /// The member exists and is unset.
    Absent,
    /// The member holds this value, canonically spelled.
    Present(String),
}

impl fmt::Display for FieldValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMember => formatter.write_str("<no member>"),
            Self::Absent => formatter.write_str("<unset>"),
            Self::Present(value) => write!(formatter, "{value:?}"),
        }
    }
}

/// A decoded input: member path to value. A path this side has no member for is simply not here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    members: BTreeMap<String, FieldValue>,
}

impl Fields {
    /// Records one member.
    pub(crate) fn set(&mut self, path: impl Into<String>, value: FieldValue) {
        self.members.insert(path.into(), value);
    }

    /// Records one member from anything [`Render`] spells.
    pub(crate) fn put<T: Render + ?Sized>(&mut self, path: &str, value: &T) {
        self.set(path, FieldValue::Present(value.render()));
    }

    /// Records one optional member.
    pub(crate) fn opt<T: Render>(&mut self, path: &str, value: Option<&T>) {
        self.set(path, value.map_or(FieldValue::Absent, |value| FieldValue::Present(value.render())));
    }

    /// The value at `path`, or [`FieldValue::NoMember`] when this side has none.
    #[must_use]
    pub fn get(&self, path: &str) -> FieldValue {
        self.members.get(path).cloned().unwrap_or(FieldValue::NoMember)
    }

    /// Every member this side holds, in path order.
    pub(crate) fn entries(&self) -> impl Iterator<Item = (&str, &FieldValue)> {
        self.members.iter().map(|(path, value)| (path.as_str(), value))
    }

    /// Every path either side holds, in order.
    pub(crate) fn union<'a>(&'a self, other: &'a Self) -> impl Iterator<Item = &'a str> {
        let mut paths: Vec<&str> = self.members.keys().chain(other.members.keys()).map(String::as_str).collect();
        paths.sort_unstable();
        paths.dedup();
        paths.into_iter()
    }
}

/// One canonical text for a member value, whichever stack's type holds it.
pub(crate) trait Render {
    fn render(&self) -> String;
}

impl Render for str {
    fn render(&self) -> String {
        self.to_owned()
    }
}

impl Render for String {
    fn render(&self) -> String {
        self.clone()
    }
}

macro_rules! render_display {
    ($($ty:ty),+ $(,)?) => {
        $(impl Render for $ty {
            fn render(&self) -> String {
                self.to_string()
            }
        })+
    };
}

render_display!(bool, i32, i64, u32, u64);

/// Types whose canonical text is their `as_str()`: every gateway name and enumeration, and every
/// s3s string-backed enumeration.
macro_rules! render_as_str {
    ($($ty:ty),+ $(,)?) => {
        $(impl Render for $ty {
            fn render(&self) -> String {
                self.as_str().to_owned()
            }
        })+
    };
}

render_as_str!(
    rustfs_gateway_types::BucketName,
    rustfs_gateway_types::ObjectKey,
    rustfs_gateway_types::OpaqueString,
    rustfs_gateway_types::dto::Acl,
    rustfs_gateway_types::dto::ChecksumAlgorithm,
    rustfs_gateway_types::dto::ChecksumMode,
    rustfs_gateway_types::dto::ChecksumType,
    rustfs_gateway_types::dto::EncodingType,
    rustfs_gateway_types::dto::LocationConstraint,
    rustfs_gateway_types::dto::MetadataDirective,
    rustfs_gateway_types::dto::MfaDelete,
    rustfs_gateway_types::dto::ObjectLockEventHold,
    rustfs_gateway_types::dto::ObjectLockLegalHoldStatus,
    rustfs_gateway_types::dto::ObjectLockMode,
    rustfs_gateway_types::dto::ObjectOwnership,
    rustfs_gateway_types::dto::RequestPayer,
    rustfs_gateway_types::dto::ServerSideEncryption,
    rustfs_gateway_types::dto::Status,
    rustfs_gateway_types::dto::StorageClass,
    rustfs_gateway_types::dto::TaggingDirective,
    oracle::AnnotationDirective,
    oracle::BucketNamespace,
    oracle::BucketType,
    oracle::DataRedundancy,
    oracle::LocationType,
    oracle::MFADelete,
    oracle::BucketCannedACL,
    oracle::BucketLocationConstraint,
    oracle::BucketVersioningStatus,
    oracle::ChecksumAlgorithm,
    oracle::ChecksumMode,
    oracle::ChecksumType,
    oracle::EncodingType,
    oracle::MFADeleteStatus,
    oracle::MetadataDirective,
    oracle::ObjectCannedACL,
    oracle::ObjectLockLegalHoldStatus,
    oracle::ObjectLockMode,
    oracle::ObjectOwnership,
    oracle::OptionalObjectAttributes,
    oracle::RequestPayer,
    oracle::ServerSideEncryption,
    oracle::StorageClass,
    oracle::TaggingDirective,
);

/// `<unix seconds>.<nine fractional digits>`.
fn instant(nanos: i128) -> String {
    let secs = nanos.div_euclid(1_000_000_000);
    let frac = nanos.rem_euclid(1_000_000_000);
    format!("{secs}.{frac:09}")
}

impl Render for rustfs_gateway_types::Timestamp {
    fn render(&self) -> String {
        instant(i128::from(self.secs()) * 1_000_000_000 + i128::from(self.subsec_nanos()))
    }
}

impl Render for oracle::Timestamp {
    fn render(&self) -> String {
        let at: time::OffsetDateTime = self.clone().into();
        instant(at.unix_timestamp_nanos())
    }
}

impl Render for oracle::ETagCondition {
    fn render(&self) -> String {
        match self.to_http_header() {
            Ok(value) => String::from_utf8_lossy(value.as_bytes()).into_owned(),
            Err(_) => format!("unrepresentable:{self:?}"),
        }
    }
}

impl Render for rustfs_gateway_types::ETag {
    fn render(&self) -> String {
        self.render(rustfs_gateway_types::EtagRender::HeaderQuoted).into_owned()
    }
}

impl Render for oracle::ETag {
    fn render(&self) -> String {
        match self {
            Self::Strong(value) => format!("\"{value}\""),
            Self::Weak(value) => format!("W/\"{value}\""),
        }
    }
}

impl Render for oracle::Range {
    fn render(&self) -> String {
        self.to_header_string()
    }
}

impl Render for rustfs_gateway_types::RangeSpec {
    fn render(&self) -> String {
        use rustfs_gateway_types::{ByteRange, RangeParse};
        match self.parsed() {
            RangeParse::Absent => "absent".to_owned(),
            RangeParse::Ignore => format!("ignored:{}", self.as_str()),
            RangeParse::MultiRange => format!("multi:{}", self.as_str()),
            RangeParse::One(ByteRange::FromTo { first, last }) => format!("bytes={first}-{last}"),
            RangeParse::One(ByteRange::From { first }) => format!("bytes={first}-"),
            RangeParse::One(ByteRange::Suffix { length }) => format!("bytes=-{length}"),
        }
    }
}

/// A map member, as sorted `name=value` lines joined by `\n`.
pub(crate) fn render_map<'a>(entries: impl Iterator<Item = (&'a str, &'a str)>) -> String {
    let mut lines: Vec<String> = entries.map(|(name, value)| format!("{name}={value}")).collect();
    lines.sort_unstable();
    lines.join("\n")
}
