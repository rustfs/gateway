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

/// The complete Object Lock configuration persisted by the old RustFS path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedObjectLockConfiguration {
    /// Object Lock state, including unknown values accepted by the old string newtype.
    pub object_lock_enabled: Option<String>,
    /// Optional default-retention rule.
    pub rule: Option<PersistedObjectLockRule>,
}

impl PersistedObjectLockConfiguration {
    /// Whether Object Lock is enabled for the bucket.
    #[must_use]
    pub fn object_lock_enabled(&self) -> bool {
        self.object_lock_enabled.as_deref() == Some("Enabled")
    }
}

/// The persisted Object Lock rule wrapper.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedObjectLockRule {
    /// Optional default retention applied to newly written objects.
    pub default_retention: Option<PersistedDefaultRetention>,
}

/// The persisted default-retention policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedDefaultRetention {
    /// Retention mode, including unknown values accepted by the old string newtype.
    pub mode: Option<String>,
    /// Retention duration in days.
    pub days: Option<i32>,
    /// Retention duration in years.
    pub years: Option<i32>,
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
    /// An Object Lock duration is present but is not a signed 32-bit integer.
    InvalidObjectLockDuration,
    /// A nested Object Lock element is not recognized by the pinned old decoder.
    UnexpectedObjectLockElement,
    /// A scalar field appeared more than once where the old decoder rejects duplicates.
    DuplicateField,
}

impl fmt::Display for PersistenceCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(error) => write!(formatter, "persisted XML is unreadable: {error}"),
            Self::WrongRoot => formatter.write_str("persisted configuration XML has the wrong root"),
            Self::InvalidExcludeFolders => formatter.write_str("persisted Versioning XML has an invalid ExcludeFolders value"),
            Self::InvalidObjectLockDuration => formatter.write_str("persisted Object Lock XML has an invalid retention duration"),
            Self::UnexpectedObjectLockElement => {
                formatter.write_str("persisted Object Lock XML has an unexpected nested element")
            }
            Self::DuplicateField => {
                formatter.write_str("persisted configuration XML has a duplicate scalar field or structural field")
            }
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

/// Parses persisted Object Lock bytes without applying HTTP request policy.
///
/// Unknown top-level elements and attributes are ignored because the pinned old decoder accepts
/// them. Unknown children inside `Rule` and `DefaultRetention`, and repeated known fields, are
/// rejected to preserve that decoder's narrower nested behavior.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed XML, a wrong root, an unexpected nested
/// element, a repeated known field, or an invalid retention duration.
pub fn parse_object_lock(input: &[u8]) -> Result<PersistedObjectLockConfiguration, PersistenceCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let root = parse_with_limits(input, limits)?;
    if root.name != "ObjectLockConfiguration" {
        return Err(PersistenceCodecError::WrongRoot);
    }
    let rule = optional_child(&root, "Rule")?.map(parse_object_lock_rule).transpose()?;
    Ok(PersistedObjectLockConfiguration {
        object_lock_enabled: optional_child_text(&root, "ObjectLockEnabled")?,
        rule,
    })
}

fn parse_object_lock_rule(rule: &rustfs_gateway_xml::XmlNode) -> Result<PersistedObjectLockRule, PersistenceCodecError> {
    reject_unknown_children(rule, &["DefaultRetention"])?;
    let default_retention = optional_child(rule, "DefaultRetention")?
        .map(parse_default_retention)
        .transpose()?;
    Ok(PersistedObjectLockRule { default_retention })
}

fn parse_default_retention(retention: &rustfs_gateway_xml::XmlNode) -> Result<PersistedDefaultRetention, PersistenceCodecError> {
    reject_unknown_children(retention, &["Mode", "Days", "Years"])?;
    Ok(PersistedDefaultRetention {
        mode: optional_child_text(retention, "Mode")?,
        days: optional_i32_child(retention, "Days")?,
        years: optional_i32_child(retention, "Years")?,
    })
}

fn reject_unknown_children(parent: &rustfs_gateway_xml::XmlNode, allowed: &[&str]) -> Result<(), PersistenceCodecError> {
    if parent.children.iter().any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(PersistenceCodecError::UnexpectedObjectLockElement);
    }
    Ok(())
}

fn optional_i32_child(parent: &rustfs_gateway_xml::XmlNode, name: &str) -> Result<Option<i32>, PersistenceCodecError> {
    optional_child_text(parent, name)?
        .map(|value| value.parse().map_err(|_| PersistenceCodecError::InvalidObjectLockDuration))
        .transpose()
}

fn optional_child<'a>(
    parent: &'a rustfs_gateway_xml::XmlNode,
    name: &'a str,
) -> Result<Option<&'a rustfs_gateway_xml::XmlNode>, PersistenceCodecError> {
    let mut children = parent.children_named(name);
    let value = children.next();
    if children.next().is_some() {
        return Err(PersistenceCodecError::DuplicateField);
    }
    Ok(value)
}

/// Serializes Object Lock into the exact old persistence field order and element form.
#[must_use]
pub fn serialize_object_lock(value: &PersistedObjectLockConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("ObjectLockConfiguration", None);
    if let Some(enabled) = value.object_lock_enabled.as_deref() {
        writer.element("ObjectLockEnabled", enabled);
    }
    if let Some(rule) = value.rule.as_ref() {
        writer.open("Rule", None);
        if let Some(retention) = rule.default_retention.as_ref() {
            writer.open("DefaultRetention", None);
            if let Some(days) = retention.days {
                writer.element("Days", &days.to_string());
            }
            if let Some(mode) = retention.mode.as_deref() {
                writer.element("Mode", mode);
            }
            if let Some(years) = retention.years {
                writer.element("Years", &years.to_string());
            }
            writer.close();
        }
        writer.close();
    }
    writer.close();
    writer.finish().into_bytes()
}
