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

//! The encode diff's output conversion: the s3s output a RustFS handler returns, as the gateway
//! output the gateway codec writes.
//!
//! Responsible for: the shared helpers every family file uses — required members, enumerations,
//! instants, entity tags, owners, the ten checksum members folded into the gateway's one — and
//! [`Unconvertible`], which names a member the gateway output cannot hold instead of dropping it.
//! The direction is the migration's: RustFS keeps returning s3s outputs, the gateway writes them.
//! NOT responsible for: the production seam (`rustfs_gateway_types::compat`), which only PutObject
//! and GetBucketLocation have today; where it exists the encode diff uses it instead of a
//! conversion here, so the diff measures what RustFS will run.
//! Upstream: the two DTOs. Downstream: `encode.rs` through the operation table.

use std::fmt;

use rustfs_gateway_types::{ChecksumAlgorithm, ChecksumSpec, ETag, OpaqueString, Timestamp, dto};

use crate::s3s::dto as oracle;

pub(crate) mod bucket;
pub(crate) mod listing;
pub(crate) mod multipart;
pub(crate) mod object;

/// A member of the s3s output the gateway output cannot hold, by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unconvertible {
    /// The s3s member, or the gateway member that could not be filled.
    pub member: &'static str,
    /// Why.
    pub reason: &'static str,
}

impl fmt::Display for Unconvertible {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.member, self.reason)
    }
}

pub(crate) type Converted<T> = Result<T, Unconvertible>;

/// A member the gateway output requires and the s3s output left unset.
pub(crate) fn required<T>(member: &'static str, value: Option<T>) -> Converted<T> {
    value.ok_or(Unconvertible {
        member,
        reason: "the gateway output requires it and the s3s output left it unset",
    })
}

/// A member only the s3s output has: carried only while unset.
pub(crate) fn absent<T>(member: &'static str, value: Option<&T>) -> Converted<()> {
    match value {
        None => Ok(()),
        Some(_) => Err(Unconvertible {
            member,
            reason: "the gateway output has no such member",
        }),
    }
}

/// A gateway enumeration built from its wire text.
pub(crate) trait FromWire: Sized {
    fn from_wire(text: &str) -> Self;
}

macro_rules! from_wire {
    ($($ty:ty),+ $(,)?) => {
        $(impl FromWire for $ty {
            fn from_wire(text: &str) -> Self {
                <$ty>::custom(text.to_owned())
            }
        })+
    };
}

from_wire!(
    dto::ArchiveStatus,
    dto::ChecksumAlgorithm,
    dto::ChecksumType,
    dto::EncodingType,
    dto::LocationConstraint,
    dto::MfaDelete,
    dto::ObjectLockLegalHoldStatus,
    dto::ObjectLockMode,
    dto::ReplicationStatus,
    dto::RequestCharged,
    dto::ServerSideEncryption,
    dto::Status,
    dto::StorageClass,
);

/// Anything with the s3s enumeration shape: its wire text.
pub(crate) trait WireText {
    fn wire_text(&self) -> &str;
}

macro_rules! wire_text {
    ($($ty:ty),+ $(,)?) => {
        $(impl WireText for $ty {
            fn wire_text(&self) -> &str {
                self.as_str()
            }
        })+
    };
}

wire_text!(
    oracle::ArchiveStatus,
    oracle::BucketLocationConstraint,
    oracle::BucketVersioningStatus,
    oracle::ChecksumAlgorithm,
    oracle::ChecksumType,
    oracle::EncodingType,
    oracle::MFADeleteStatus,
    oracle::ObjectLockLegalHoldStatus,
    oracle::ObjectLockMode,
    oracle::ObjectStorageClass,
    oracle::ObjectVersionStorageClass,
    oracle::ReplicationStatus,
    oracle::RequestCharged,
    oracle::ServerSideEncryption,
    oracle::StorageClass,
);

/// An optional s3s enumeration as the gateway's.
pub(crate) fn enumeration<T: FromWire, S: WireText>(value: Option<S>) -> Option<T> {
    value.map(|value| T::from_wire(value.wire_text()))
}

/// An s3s instant as the gateway's, nanoseconds included.
pub(crate) fn instant(member: &'static str, value: Option<oracle::Timestamp>) -> Converted<Option<Timestamp>> {
    value
        .map(|value| {
            let at: time::OffsetDateTime = value.into();
            let nanos = at.unix_timestamp_nanos();
            let secs = i64::try_from(nanos.div_euclid(1_000_000_000)).ok();
            let subsec = u32::try_from(nanos.rem_euclid(1_000_000_000)).ok();
            secs.zip(subsec)
                .and_then(|(secs, subsec)| Timestamp::from_secs_nanos(secs, subsec).ok())
                .ok_or(Unconvertible {
                    member,
                    reason: "an instant outside what the gateway output can hold",
                })
        })
        .transpose()
}

/// An s3s entity tag as the gateway's.
pub(crate) fn entity_tag(member: &'static str, value: Option<oracle::ETag>) -> Converted<Option<ETag>> {
    value
        .map(|value| {
            match value {
                oracle::ETag::Strong(tag) => ETag::new(tag),
                oracle::ETag::Weak(tag) => ETag::new_weak(tag),
            }
            .map_err(|_| Unconvertible {
                member,
                reason: "not an entity tag the gateway can write",
            })
        })
        .transpose()
}

/// An owner as the gateway's.
pub(crate) fn owner(value: Option<oracle::Owner>) -> Option<dto::Owner> {
    value.map(|oracle::Owner { display_name, id }| dto::Owner { display_name, id })
}

/// An initiator as the gateway's.
pub(crate) fn initiator(value: Option<oracle::Initiator>) -> Option<dto::Initiator> {
    value.map(|oracle::Initiator { display_name, id }| dto::Initiator { display_name, id })
}

/// Text the gateway keeps opaque.
pub(crate) fn opaque(value: Option<String>) -> Option<OpaqueString> {
    value.map(OpaqueString::from)
}

/// The ten s3s checksum members of one output, in the gateway's algorithm order.
pub(crate) struct Checksums {
    pub(crate) crc32: Option<String>,
    pub(crate) crc32c: Option<String>,
    pub(crate) crc64nvme: Option<String>,
    pub(crate) md5: Option<String>,
    pub(crate) sha1: Option<String>,
    pub(crate) sha256: Option<String>,
    pub(crate) sha512: Option<String>,
    pub(crate) xxhash128: Option<String>,
    pub(crate) xxhash3: Option<String>,
    pub(crate) xxhash64: Option<String>,
}

impl Checksums {
    fn present(self) -> impl Iterator<Item = (&'static str, ChecksumAlgorithm, String)> {
        [
            ("checksum_crc32", ChecksumAlgorithm::Crc32, self.crc32),
            ("checksum_crc32c", ChecksumAlgorithm::Crc32c, self.crc32c),
            ("checksum_crc64nvme", ChecksumAlgorithm::Crc64Nvme, self.crc64nvme),
            ("checksum_md5", ChecksumAlgorithm::Md5, self.md5),
            ("checksum_sha1", ChecksumAlgorithm::Sha1, self.sha1),
            ("checksum_sha256", ChecksumAlgorithm::Sha256, self.sha256),
            ("checksum_sha512", ChecksumAlgorithm::Sha512, self.sha512),
            ("checksum_xxhash128", ChecksumAlgorithm::XxHash128, self.xxhash128),
            ("checksum_xxhash3", ChecksumAlgorithm::XxHash3, self.xxhash3),
            ("checksum_xxhash64", ChecksumAlgorithm::XxHash64, self.xxhash64),
        ]
        .into_iter()
        .filter_map(|(member, algorithm, value)| value.map(|value| (member, algorithm, value)))
    }

    /// The gateway's one checksum: none, or exactly one well-formed value.
    pub(crate) fn into_spec(self) -> Converted<Option<ChecksumSpec>> {
        let mut present = self.present();
        match (present.next(), present.next()) {
            (None, _) => Ok(None),
            (Some(_), Some(_)) => Err(Unconvertible {
                member: "checksum_spec",
                reason: "the gateway output carries one checksum, so a second would be lost",
            }),
            (Some((member, algorithm, value)), None) => ChecksumSpec::parse_header(algorithm.header_name(), &value)
                .map(Some)
                .map_err(|_| Unconvertible {
                    member,
                    reason: "not a checksum value of this algorithm's width",
                }),
        }
    }
}

/// A bucket name the gateway output holds.
pub(crate) fn bucket_name(member: &'static str, value: Option<String>) -> Converted<rustfs_gateway_types::BucketName> {
    rustfs_gateway_types::BucketName::new(required(member, value)?).map_err(|_| Unconvertible {
        member,
        reason: "not a bucket name the gateway output can hold",
    })
}

/// An object key the gateway output holds.
pub(crate) fn object_key(member: &'static str, value: Option<String>) -> Converted<Option<rustfs_gateway_types::ObjectKey>> {
    value
        .map(|value| {
            rustfs_gateway_types::ObjectKey::new(value).map_err(|_| Unconvertible {
                member,
                reason: "not an object key the gateway output can hold",
            })
        })
        .transpose()
}
