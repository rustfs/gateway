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

//! S3 scalar types, operation inputs/outputs, and their generated codecs.
//!
//! Responsible for: `ETag`, `Checksum`, `Timestamp`, names, `Range`, error codes, and the
//! generated per-operation DTOs plus their XML/header codec impls.
//! NOT responsible for: wire framing, signing, routing.
//! Upstream: `rustfs-gateway-xml`, `rustfs-gateway-stream`. Downstream: `rustfs-gateway-http` and everything above.
//!
//! # Two facades over one set of types
//!
//! [`ops`] is the module-per-operation layout: `ops::put_object::{Input, Output}`. [`dto`] is the
//! flat alias surface: `dto::PutObjectInput`. They are the same types under two names — the first
//! keeps rustdoc navigable once the operation whitelist is complete, the second keeps `grep` and
//! an in-flight migration from `s3s::dto` working. Neither declares anything: both are generated
//! by `cargo xtask codegen` into `generated/dto/`, which is why they are mounted with `#[path]`
//! instead of living under `src/`.
//!
//! The `#[path]` targets go through `crates/types/generated`, a symlink to `generated/dto`. It is
//! load-bearing for publishing, not cosmetic: `include`/`#[path]` may not reach outside the package
//! directory in a `.crate` tarball, and the symlink is what puts the generated tree inside it. See
//! ADR-0005.
//!
//! Constructing a dto: public fields plus `..Default::default()`, or the per-operation builder.
//! Never destructure one exhaustively — see ADR-0004 P1 and P3 for why that is the only usage a
//! new model member breaks.
//!
//! # Required members are bare, optional members are `Option`
//!
//! `PutObjectInput::bucket` is a [`BucketName`], not an `Option<BucketName>`: requiredness is
//! expressed by the type, and a handler never unwraps a value the wire contract says is always
//! there. The price is that every scalar reachable from a required member has a `Default`, whose
//! value is deliberately **invalid on the wire** — see [`placeholder`] for what that means, why it
//! is safe, and the guard that keeps one off the decode path.
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod placeholder;
pub mod persistence {
    //! Bucket-configuration codecs for byte-observable persistence data.
    //!
    //! Responsible for: parsing and writing the exact XML representation stored below the HTTP layer.
    //! NOT responsible for: request integrity headers, operation routing, or the temporary s3s oracle.
    //! Upstream: `rustfs-gateway-xml`. Downstream: RustFS metadata persistence and migration goldens.

    use core::fmt;

    use rustfs_gateway_xml::{XmlError, XmlLimits, XmlWriter, parse_with_limits};

    /// The complete Versioning configuration persisted by the old RustFS path.
    ///
    /// The two extension fields are part of the persistence format even though they are not AWS
    /// HTTP operation members. Dropping either while normalizing old bytes would silently change
    /// MinIO compatibility behavior.
    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    pub struct PersistedVersioningConfiguration {
        /// Bucket versioning state (`Enabled` or `Suspended`) when present.
        pub status: Option<String>,
        /// MFA delete state (`Enabled` or `Disabled`) when present.
        pub mfa_delete: Option<String>,
        /// MinIO's folder-exclusion extension.
        pub exclude_folders: Option<bool>,
        /// MinIO's flattened excluded-prefix entries; a missing nested `Prefix` remains `None`.
        pub excluded_prefixes: Option<Vec<Option<String>>>,
    }

    impl PersistedVersioningConfiguration {
        /// Whether the stored configuration enables object versioning.
        #[must_use]
        pub fn versioning_enabled(&self) -> bool {
            self.status.as_deref() == Some("Enabled")
        }
    }

    /// A refusal from a persistence codec.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub enum PersistenceCodecError {
        /// The document is not well-formed, bounded XML.
        Xml(XmlError),
        /// The root is not the configuration family being decoded.
        WrongRoot,
        /// `ExcludeFolders` is present but is not the lowercase XML boolean `true` or `false`.
        InvalidExcludeFolders,
        /// A scalar field appeared more than once where the old decoder rejects duplicates.
        DuplicateField,
    }

    impl fmt::Display for PersistenceCodecError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Xml(error) => write!(formatter, "persisted XML is unreadable: {error}"),
                Self::WrongRoot => formatter.write_str("persisted Versioning XML has the wrong root"),
                Self::InvalidExcludeFolders => {
                    formatter.write_str("persisted Versioning XML has an invalid ExcludeFolders value")
                }
                Self::DuplicateField => formatter.write_str("persisted Versioning XML has a duplicate scalar field"),
            }
        }
    }

    impl std::error::Error for PersistenceCodecError {}

    impl From<XmlError> for PersistenceCodecError {
        fn from(error: XmlError) -> Self {
            Self::Xml(error)
        }
    }

    /// Parses persisted Versioning bytes without applying HTTP request policy.
    ///
    /// Unknown children are ignored because persisted configuration must remain forward-readable
    /// during rolling upgrades. Repeated scalar children are rejected like the pinned old decoder;
    /// the flattened prefix extension retains every occurrence.
    ///
    /// # Errors
    ///
    /// Returns [`PersistenceCodecError`] for malformed/bounded XML, a wrong root, an invalid
    /// `ExcludeFolders` boolean, or a repeated scalar field.
    pub fn parse_versioning(input: &[u8]) -> Result<PersistedVersioningConfiguration, PersistenceCodecError> {
        // Persistence input is already buffered. Deriving every parser ceiling from that buffer
        // prevents HTTP request limits from rejecting metadata the old persistence codec accepted.
        let bound = input.len().max(1);
        let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
            unreachable!("max(1) makes every persistence XML limit non-zero");
        };
        let root = parse_with_limits(input, limits)?;
        if root.name != "VersioningConfiguration" {
            return Err(PersistenceCodecError::WrongRoot);
        }
        let exclude_folders_text = optional_child_text(&root, "ExcludeFolders")?;
        let exclude_folders = match exclude_folders_text.as_deref() {
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(_) => return Err(PersistenceCodecError::InvalidExcludeFolders),
            None => None,
        };
        let excluded_prefixes = root
            .children_named("ExcludedPrefixes")
            .map(|entry| optional_child_text(entry, "Prefix"))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PersistedVersioningConfiguration {
            status: optional_child_text(&root, "Status")?,
            mfa_delete: optional_child_text(&root, "MfaDelete")?,
            exclude_folders,
            excluded_prefixes: (!excluded_prefixes.is_empty()).then_some(excluded_prefixes),
        })
    }

    fn optional_child_text(parent: &rustfs_gateway_xml::XmlNode, name: &str) -> Result<Option<String>, PersistenceCodecError> {
        let mut children = parent.children_named(name);
        let value = children.next().map(|child| child.text.clone());
        if children.next().is_some() {
            return Err(PersistenceCodecError::DuplicateField);
        }
        Ok(value)
    }

    /// Serializes Versioning into the exact old persistence field order and element form.
    #[must_use]
    pub fn serialize_versioning(value: &PersistedVersioningConfiguration) -> Vec<u8> {
        let mut writer = XmlWriter::fragment();
        writer.open("VersioningConfiguration", None);
        if let Some(exclude_folders) = value.exclude_folders {
            writer.element_bool("ExcludeFolders", exclude_folders);
        }
        if let Some(prefixes) = value.excluded_prefixes.as_deref() {
            for prefix in prefixes {
                writer.open("ExcludedPrefixes", None);
                if let Some(prefix) = prefix {
                    writer.element("Prefix", prefix);
                }
                writer.close();
            }
        }
        if let Some(mfa_delete) = value.mfa_delete.as_deref() {
            writer.element("MfaDelete", mfa_delete);
        }
        if let Some(status) = value.status.as_deref() {
            writer.element("Status", status);
        }
        writer.close();
        writer.finish().into_bytes()
    }
}
mod scalar;

/// Temporary, feature-gated adapters to the pinned s3s persistence oracle.
///
/// This module is deliberately the only s3s dependency surface in the protocol kernel. It exposes
/// owned gateway-neutral values rather than s3s types, so consumers cannot spread the old DTOs.
/// It invokes the old XML codec but owns no gateway XML behavior, golden assertion, or production
/// persistence decision. Its upstream is pinned s3s revision `9c4690d8`; only
/// `rustfs-gateway-goldens` consumes it.
#[cfg(feature = "compat-s3s")]
pub mod compat {
    use core::fmt;

    use crate::persistence::PersistedVersioningConfiguration;
    use s3s::dto::{BucketVersioningStatus, ExcludedPrefix, MFADelete, VersioningConfiguration};
    use s3s::xml::{Deserialize, Deserializer, Serialize, Serializer};

    /// One old-codec observation before the golden harness normalizes either side.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct S3sVersioningObservation {
        /// Complete parsed persistence structure.
        pub structure: PersistedVersioningConfiguration,
        /// Whether the pinned old implementation interprets the status as enabled.
        pub versioning_enabled: bool,
        /// The exact old versioning status used by its behavior decision.
        pub versioning_status: Option<String>,
        /// The exact old MFA delete state used by its behavior decision.
        pub mfa_delete: Option<String>,
    }

    /// Failure raised by the pinned old persistence codec.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct CompatCodecError {
        message: String,
    }

    impl CompatCodecError {
        fn old_codec(error: impl fmt::Display) -> Self {
            Self {
                message: format!("pinned s3s persistence codec failed: {error}"),
            }
        }
    }

    impl fmt::Display for CompatCodecError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(&self.message)
        }
    }

    impl std::error::Error for CompatCodecError {}

    /// Parses Versioning bytes with the pinned s3s persistence decoder.
    ///
    /// # Errors
    ///
    /// Returns [`CompatCodecError`] when s3s rejects the document or trailing input.
    pub fn parse_s3s_versioning(input: &[u8]) -> Result<S3sVersioningObservation, CompatCodecError> {
        let mut deserializer = Deserializer::new(input);
        let value = VersioningConfiguration::deserialize(&mut deserializer).map_err(CompatCodecError::old_codec)?;
        deserializer.expect_eof().map_err(CompatCodecError::old_codec)?;
        let versioning_status = value.status.as_ref().map(|status| status.as_str().to_owned());
        let mfa_delete = value.mfa_delete.as_ref().map(|status| status.as_str().to_owned());
        Ok(S3sVersioningObservation {
            versioning_enabled: value
                .status
                .as_ref()
                .is_some_and(|status| status.as_str() == BucketVersioningStatus::ENABLED),
            versioning_status: versioning_status.clone(),
            mfa_delete: mfa_delete.clone(),
            structure: PersistedVersioningConfiguration {
                status: versioning_status,
                mfa_delete,
                exclude_folders: value.exclude_folders,
                excluded_prefixes: value
                    .excluded_prefixes
                    .map(|prefixes| prefixes.into_iter().map(|prefix| prefix.prefix).collect()),
            },
        })
    }

    /// Serializes a Versioning value with the pinned s3s persistence encoder.
    ///
    /// # Errors
    ///
    /// Returns [`CompatCodecError`] when s3s cannot render the value.
    pub fn serialize_s3s_versioning(value: &PersistedVersioningConfiguration) -> Result<Vec<u8>, CompatCodecError> {
        #[allow(clippy::needless_update)] // Keep a default tail for the generated old DTO.
        let old_value = VersioningConfiguration {
            exclude_folders: value.exclude_folders,
            excluded_prefixes: value
                .excluded_prefixes
                .clone()
                .map(|prefixes| prefixes.into_iter().map(|prefix| ExcludedPrefix { prefix }).collect()),
            status: value.status.clone().map(BucketVersioningStatus::from),
            mfa_delete: value.mfa_delete.clone().map(MFADelete::from),
            ..VersioningConfiguration::default()
        };
        let mut output = Vec::with_capacity(256);
        let mut serializer = Serializer::new(&mut output);
        old_value.serialize(&mut serializer).map_err(CompatCodecError::old_codec)?;
        Ok(output)
    }
}

#[cfg(test)]
mod tests;

/// The generated operation dto, one module per operation.
#[path = "../generated/ops/mod.rs"]
pub mod ops;

/// Flat aliases for every generated type: `dto::PutObjectInput` is `ops::put_object::Input`.
#[path = "../generated/flat.rs"]
pub mod dto;

pub use crate::placeholder::{PlaceholderDefault, WirePlaceholder, reject_placeholder};
pub use crate::scalar::{
    AwsNameValidator, BucketName, ByteRange, ChecksumAlgorithm, ChecksumDigest, ChecksumError, ChecksumSpec, ChecksumType,
    Checksummer, ContentMd5, ETag, ErrorCode, EtagRender, Md5Digest, NamePolicy, NameRejection, NameValidator, ObjectKey,
    OpaqueString, ParseError, RangeOutcome, RangeParse, RangeSpec, RecordedUpload, ResolvedUploadId, SlashPolicy, Stricter,
    Timestamp, TimestampFormat, UploadIdClaim, UploadRejection, aws_bucket_rules, decode_once, floor_check_bucket,
    floor_check_key, is_xml_representable, parse_request_checksum, resolve_upload, rules, validate_bucket_name,
    validate_object_key,
};
