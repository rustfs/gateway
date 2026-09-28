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
use std::borrow::Cow;

use rustfs_gateway_xml::{XmlError, XmlLimits, XmlWriter, parse_with_limits};

mod accelerate_payment;
mod dto_bridge;
mod lifecycle;
mod logging_website;
mod notification;
mod replication;

pub use accelerate_payment::{
    PersistedAccelerateConfiguration, PersistedRequestPaymentConfiguration, parse_accelerate, parse_request_payment,
    serialize_accelerate, serialize_request_payment,
};
pub use dto_bridge::*;
pub use lifecycle::*;
pub use logging_website::{
    PersistedBucketLoggingStatus, PersistedErrorDocument, PersistedGrantee, PersistedIndexDocument, PersistedLoggingEnabled,
    PersistedLoggingGrant, PersistedRedirect, PersistedRedirectAllRequestsTo, PersistedRoutingRule,
    PersistedRoutingRuleCondition, PersistedTargetObjectKeyFormat, PersistedWebsiteConfiguration, parse_bucket_logging,
    parse_website, serialize_bucket_logging, serialize_website,
};
pub use notification::*;
pub use replication::*;

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

/// The complete default-encryption configuration persisted by the old RustFS path.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedBucketEncryptionConfiguration {
    /// Flattened `Rule` entries, preserving their stored order.
    pub rules: Vec<PersistedBucketEncryptionRule>,
}

/// The runtime-relevant decisions of one stored encryption rule: default algorithm, default KMS
/// key, bucket-key switch, and the encryption types the rule blocks for new writes (`None` when
/// the rule carries no `BlockedEncryptionTypes`).
pub type EncryptionRuleBehavior = (Option<String>, Option<String>, Option<bool>, Option<Vec<String>>);

impl PersistedBucketEncryptionConfiguration {
    /// Runtime-relevant default-encryption decisions, one tuple per stored rule.
    #[must_use]
    pub fn encryption_behavior(&self) -> Vec<EncryptionRuleBehavior> {
        self.rules
            .iter()
            .map(|rule| {
                let default = rule.apply_server_side_encryption_by_default.as_ref();
                (
                    default.map(|value| value.sse_algorithm.clone()),
                    default.and_then(|value| value.kms_master_key_id.clone()),
                    rule.bucket_key_enabled,
                    rule.blocked_encryption_types
                        .as_ref()
                        .map(|blocked| blocked.encryption_types.clone()),
                )
            })
            .collect()
    }
}

/// One persisted bucket default-encryption rule.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedBucketEncryptionRule {
    /// Encryption algorithm and optional KMS key applied by default.
    pub apply_server_side_encryption_by_default: Option<PersistedEncryptionByDefault>,
    /// Whether the rule enables an S3 bucket key.
    pub bucket_key_enabled: Option<bool>,
    /// Encryption types new object writes may not use, as written by s3s `bdcb6259` and later
    /// (RustFS 1.0.0-rc.6 and `main`). Carried rather than skipped: dropping it would silently
    /// unblock SSE-C for a bucket whose owner blocked it (rustfs/gateway#740).
    pub blocked_encryption_types: Option<PersistedBlockedEncryptionTypes>,
}

/// The persisted `BlockedEncryptionTypes` wrapper of one encryption rule.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedBlockedEncryptionTypes {
    /// Flattened `EncryptionType` entries in stored order, including values unknown to this
    /// release; an empty list is an explicit empty wrapper.
    pub encryption_types: Vec<String>,
}

/// The persisted encryption defaults nested inside one rule.
///
/// `Debug` is written by hand: the KMS key identifier is a secret (it names the key a bucket's
/// objects are encrypted under), and persisted values are rendered with `{:?}` by the migration
/// goldens' diagnostics. It prints whether a key id is stored and how long it is, never its text.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct PersistedEncryptionByDefault {
    /// Stored algorithm string, including values unknown to the current implementation.
    pub sse_algorithm: String,
    /// Optional KMS key identifier.
    pub kms_master_key_id: Option<String>,
}

impl fmt::Debug for PersistedEncryptionByDefault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedEncryptionByDefault")
            .field("sse_algorithm", &self.sse_algorithm)
            .field("kms_master_key_id", &RedactedKeyId(self.kms_master_key_id.as_deref()))
            .finish()
    }
}

/// The `Debug` stand-in for an optional stored secret identifier — a KMS key id, or the
/// replication destination account id `q-repl-0010` classifies beside it: `None`, or
/// `Some(<redacted N bytes>)`. Presence and length keep a two-sided diagnostic readable (absent
/// against present, or two ids of different length); the text itself never reaches the output.
pub(crate) struct RedactedKeyId<'a>(pub(crate) Option<&'a str>);

impl fmt::Debug for RedactedKeyId<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(key_id) => write!(formatter, "Some(<redacted {} bytes>)", key_id.len()),
            None => formatter.write_str("None"),
        }
    }
}

/// `Debug` for one [`EncryptionRuleBehavior`] tuple with its KMS key id redacted by
/// [`RedactedKeyId`]; every other decision renders exactly as the tuple's own `Debug` would.
///
/// Its only caller is `crate::compat`, so it is compiled under the same features: ungated it is
/// dead code in every build without them, which `-D warnings` refuses.
#[cfg(any(feature = "compat-s3s", feature = "compat-s3s-0-17-0"))]
pub(crate) struct RedactedEncryptionRuleBehavior<'a>(pub(crate) &'a EncryptionRuleBehavior);

#[cfg(any(feature = "compat-s3s", feature = "compat-s3s-0-17-0"))]
impl fmt::Debug for RedactedEncryptionRuleBehavior<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (algorithm, key_id, bucket_key_enabled, blocked) = self.0;
        formatter
            .debug_tuple("")
            .field(algorithm)
            .field(&RedactedKeyId(key_id.as_deref()))
            .field(bucket_key_enabled)
            .field(blocked)
            .finish()
    }
}

/// The complete persisted Public Access Block configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistedPublicAccessBlockConfiguration {
    /// Whether public ACLs are rejected when supplied.
    pub block_public_acls: Option<bool>,
    /// Whether existing public ACLs are ignored.
    pub ignore_public_acls: Option<bool>,
    /// Whether public bucket policies are rejected.
    pub block_public_policy: Option<bool>,
    /// Whether public bucket access is restricted.
    pub restrict_public_buckets: Option<bool>,
}

impl PersistedPublicAccessBlockConfiguration {
    /// The four effective access decisions; omitted persisted switches default to `false`.
    #[must_use]
    pub fn effective_switches(&self) -> (bool, bool, bool, bool) {
        (
            self.block_public_acls.unwrap_or(false),
            self.ignore_public_acls.unwrap_or(false),
            self.block_public_policy.unwrap_or(false),
            self.restrict_public_buckets.unwrap_or(false),
        )
    }
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
    /// A Lifecycle integer is outside its signed width or has a noncanonical lexeme.
    InvalidLifecycleInteger,
    /// A Lifecycle boolean is not the lowercase XML spelling `true` or `false`.
    InvalidLifecycleBoolean,
    /// A Lifecycle timestamp is not an old-readable DateTime value.
    InvalidLifecycleTimestamp,
    /// A Replication integer is outside its signed width or has a noncanonical lexeme.
    InvalidReplicationInteger,
    /// A Lifecycle rule omitted its required status.
    MissingLifecycleStatus,
    /// A Lifecycle configuration contains no rules.
    MissingLifecycleRule,
    /// A Replication configuration contains no rules.
    MissingReplicationRule,
    /// A nested Object Lock element is not recognized by the pinned old decoder.
    UnexpectedObjectLockElement,
    /// A nested Lifecycle element is not recognized by the pinned old decoder.
    UnexpectedLifecycleElement,
    /// A nested Replication element is not recognized by the pinned old decoder.
    UnexpectedReplicationElement,
    /// A scalar element contains nested XML where the pinned old decoder expects text.
    UnexpectedScalarElement,
    /// A required persisted configuration member is absent.
    MissingRequiredField,
    /// A scalar field appeared more than once where the old decoder rejects duplicates.
    DuplicateField,
    /// A persisted XML boolean is not one of the exact lexical forms the pinned old decoder
    /// accepts: `true`, `false`, `TRUE`, or `FALSE`. Mixed case, numerals, surrounding
    /// whitespace, and empty text are all refused.
    InvalidBoolean,
    /// A nested Bucket Encryption element is not recognized by the pinned old decoder.
    UnexpectedBucketEncryptionElement,
    /// A nested Bucket Logging element is not recognized by the pinned old decoder.
    UnexpectedLoggingElement,
    /// A nested Notification element is not recognized by the pinned old decoder.
    UnexpectedNotificationElement,
    /// A nested Website element is not recognized by the pinned old decoder.
    UnexpectedWebsiteElement,
}

impl fmt::Display for PersistenceCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xml(error) => write!(formatter, "persisted XML is unreadable: {error}"),
            Self::WrongRoot => formatter.write_str("persisted configuration XML has the wrong root"),
            Self::InvalidExcludeFolders => formatter.write_str("persisted Versioning XML has an invalid ExcludeFolders value"),
            Self::InvalidObjectLockDuration => formatter.write_str("persisted Object Lock XML has an invalid retention duration"),
            Self::InvalidLifecycleInteger => formatter.write_str("persisted Lifecycle XML has an invalid integer"),
            Self::InvalidLifecycleBoolean => formatter.write_str("persisted Lifecycle XML has an invalid boolean"),
            Self::InvalidLifecycleTimestamp => formatter.write_str("persisted Lifecycle XML has an invalid timestamp"),
            Self::InvalidReplicationInteger => formatter.write_str("persisted Replication XML has an invalid integer"),
            Self::MissingLifecycleStatus => formatter.write_str("persisted Lifecycle XML has a rule without Status"),
            Self::MissingLifecycleRule => formatter.write_str("persisted Lifecycle XML has no Rule"),
            Self::MissingReplicationRule => formatter.write_str("persisted Replication XML has no Rule"),
            Self::UnexpectedObjectLockElement => {
                formatter.write_str("persisted Object Lock XML has an unexpected nested element")
            }
            Self::UnexpectedLifecycleElement => formatter.write_str("persisted Lifecycle XML has an unexpected nested element"),
            Self::UnexpectedReplicationElement => {
                formatter.write_str("persisted Replication XML has an unexpected nested element")
            }
            Self::UnexpectedScalarElement => {
                formatter.write_str("persisted configuration XML has a nested element inside a scalar field")
            }
            Self::DuplicateField => {
                formatter.write_str("persisted configuration XML has a duplicate scalar field or structural field")
            }
            Self::InvalidBoolean => formatter.write_str("persisted configuration XML has an invalid boolean value"),
            Self::UnexpectedBucketEncryptionElement => {
                formatter.write_str("persisted Bucket Encryption XML has an unexpected nested element")
            }
            Self::MissingRequiredField => formatter.write_str("persisted configuration XML is missing a required field"),
            Self::UnexpectedLoggingElement => {
                formatter.write_str("persisted Bucket Logging XML has an unexpected nested element")
            }
            Self::UnexpectedNotificationElement => {
                formatter.write_str("persisted Notification XML has an unexpected nested element")
            }
            Self::UnexpectedWebsiteElement => formatter.write_str("persisted Website XML has an unexpected nested element"),
        }
    }
}

impl std::error::Error for PersistenceCodecError {}

impl From<XmlError> for PersistenceCodecError {
    fn from(error: XmlError) -> Self {
        Self::Xml(error)
    }
}

/// Removes the exact inert document-type preamble accepted by the historical persistence codec.
pub(super) fn strip_inert_doctype<'a>(input: &'a [u8], expected: &str) -> Cow<'a, [u8]> {
    let mut cursor = usize::from(input.starts_with(b"\xef\xbb\xbf")) * 3;
    while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if input.get(cursor..).is_some_and(|body| body.starts_with(b"<?xml")) {
        let Some(end) = input[cursor..].windows(2).position(|window| window == b"?>") else {
            return Cow::Borrowed(input);
        };
        cursor += end + 2;
        while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
    }
    let declaration_start = cursor;
    let Some(body) = input.get(cursor..).and_then(|body| body.strip_prefix(b"<!DOCTYPE")) else {
        return Cow::Borrowed(input);
    };
    cursor = input.len() - body.len();
    if !input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        return Cow::Borrowed(input);
    }
    while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    let Some(body) = input.get(cursor..).and_then(|body| body.strip_prefix(expected.as_bytes())) else {
        return Cow::Borrowed(input);
    };
    cursor = input.len() - body.len();
    while input.get(cursor).is_some_and(u8::is_ascii_whitespace) {
        cursor += 1;
    }
    if input.get(cursor) != Some(&b'>') {
        return Cow::Borrowed(input);
    }
    let declaration_end = cursor + 1;
    if declaration_start == 0 {
        return Cow::Borrowed(&input[declaration_end..]);
    }
    let mut without_declaration = Vec::with_capacity(input.len() - (declaration_end - declaration_start));
    without_declaration.extend_from_slice(&input[..declaration_start]);
    without_declaration.extend_from_slice(&input[declaration_end..]);
    Cow::Owned(without_declaration)
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

/// Parses persisted Bucket Encryption bytes without applying HTTP request policy.
///
/// Unknown root-level elements and attributes are ignored for rolling-upgrade compatibility.
/// Repeated scalar or structural fields fail closed exactly where the old decoder does.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed XML, a wrong root, an invalid boolean,
/// an unexpected nested element, or a repeated known field.
pub fn parse_bucket_encryption(input: &[u8]) -> Result<PersistedBucketEncryptionConfiguration, PersistenceCodecError> {
    let root = parse_persistence_root(input, "ServerSideEncryptionConfiguration")?;
    let rules = root
        .children_named("Rule")
        .map(parse_bucket_encryption_rule)
        .collect::<Result<Vec<_>, _>>()?;
    if rules.is_empty() {
        return Err(PersistenceCodecError::MissingRequiredField);
    }
    Ok(PersistedBucketEncryptionConfiguration { rules })
}

fn parse_bucket_encryption_rule(
    rule: &rustfs_gateway_xml::XmlNode,
) -> Result<PersistedBucketEncryptionRule, PersistenceCodecError> {
    reject_unknown_encryption_children(
        rule,
        &[
            "ApplyServerSideEncryptionByDefault",
            "BucketKeyEnabled",
            "BlockedEncryptionTypes",
        ],
    )?;
    let apply_server_side_encryption_by_default = optional_child(rule, "ApplyServerSideEncryptionByDefault")?
        .map(parse_encryption_by_default)
        .transpose()?;
    let blocked_encryption_types = optional_child(rule, "BlockedEncryptionTypes")?
        .map(parse_blocked_encryption_types)
        .transpose()?;
    Ok(PersistedBucketEncryptionRule {
        apply_server_side_encryption_by_default,
        bucket_key_enabled: optional_bool_child(rule, "BucketKeyEnabled")?,
        blocked_encryption_types,
    })
}

/// Reads the wrapper the way s3s `bdcb6259`/`0.17.0` do: only flattened `EncryptionType`
/// children, each kept as its stored text, and anything else refused.
fn parse_blocked_encryption_types(
    blocked: &rustfs_gateway_xml::XmlNode,
) -> Result<PersistedBlockedEncryptionTypes, PersistenceCodecError> {
    reject_unknown_encryption_children(blocked, &["EncryptionType"])?;
    let encryption_types = blocked
        .children_named("EncryptionType")
        .map(|entry| {
            if entry.children.is_empty() {
                Ok(entry.text.clone())
            } else {
                Err(PersistenceCodecError::UnexpectedScalarElement)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PersistedBlockedEncryptionTypes { encryption_types })
}

fn parse_encryption_by_default(
    default: &rustfs_gateway_xml::XmlNode,
) -> Result<PersistedEncryptionByDefault, PersistenceCodecError> {
    reject_unknown_encryption_children(default, &["SSEAlgorithm", "KMSMasterKeyID"])?;
    let Some(sse_algorithm) = optional_child_text(default, "SSEAlgorithm")? else {
        return Err(PersistenceCodecError::MissingRequiredField);
    };
    Ok(PersistedEncryptionByDefault {
        sse_algorithm,
        kms_master_key_id: optional_child_text(default, "KMSMasterKeyID")?,
    })
}

fn reject_unknown_encryption_children(
    parent: &rustfs_gateway_xml::XmlNode,
    allowed: &[&str],
) -> Result<(), PersistenceCodecError> {
    if parent.children.iter().any(|child| !allowed.contains(&child.name.as_str())) {
        return Err(PersistenceCodecError::UnexpectedBucketEncryptionElement);
    }
    Ok(())
}

/// Serializes Bucket Encryption into the exact old persistence field order and element form.
#[must_use]
pub fn serialize_bucket_encryption(value: &PersistedBucketEncryptionConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("ServerSideEncryptionConfiguration", None);
    for rule in &value.rules {
        writer.open("Rule", None);
        if let Some(default) = rule.apply_server_side_encryption_by_default.as_ref() {
            writer.open("ApplyServerSideEncryptionByDefault", None);
            if let Some(key_id) = default.kms_master_key_id.as_deref() {
                writer.element("KMSMasterKeyID", key_id);
            }
            writer.element("SSEAlgorithm", &default.sse_algorithm);
            writer.close();
        }
        // s3s writes the rule's members alphabetically, so the wrapper sits between the default
        // action and the bucket-key switch.
        if let Some(blocked) = rule.blocked_encryption_types.as_ref() {
            writer.open("BlockedEncryptionTypes", None);
            for encryption_type in &blocked.encryption_types {
                writer.element("EncryptionType", encryption_type);
            }
            writer.close();
        }
        if let Some(enabled) = rule.bucket_key_enabled {
            writer.element_bool("BucketKeyEnabled", enabled);
        }
        writer.close();
    }
    writer.close();
    writer.finish().into_bytes()
}

/// Parses persisted Public Access Block bytes without applying HTTP request policy.
///
/// # Errors
///
/// Returns [`PersistenceCodecError`] for malformed XML, a wrong root, a repeated switch, or an
/// invalid boolean lexical form.
pub fn parse_public_access_block(input: &[u8]) -> Result<PersistedPublicAccessBlockConfiguration, PersistenceCodecError> {
    let root = parse_persistence_root(input, "PublicAccessBlockConfiguration")?;
    Ok(PersistedPublicAccessBlockConfiguration {
        block_public_acls: optional_bool_child(&root, "BlockPublicAcls")?,
        ignore_public_acls: optional_bool_child(&root, "IgnorePublicAcls")?,
        block_public_policy: optional_bool_child(&root, "BlockPublicPolicy")?,
        restrict_public_buckets: optional_bool_child(&root, "RestrictPublicBuckets")?,
    })
}

fn optional_bool_child(parent: &rustfs_gateway_xml::XmlNode, name: &str) -> Result<Option<bool>, PersistenceCodecError> {
    match optional_child_text(parent, name)?.as_deref() {
        Some("true" | "TRUE") => Ok(Some(true)),
        Some("false" | "FALSE") => Ok(Some(false)),
        Some(_) => Err(PersistenceCodecError::InvalidBoolean),
        None => Ok(None),
    }
}

fn parse_persistence_root(input: &[u8], expected_root: &str) -> Result<rustfs_gateway_xml::XmlNode, PersistenceCodecError> {
    let bound = input.len().max(1);
    let Some(limits) = XmlLimits::new(bound, bound, bound, bound, bound) else {
        unreachable!("max(1) makes every persistence XML limit non-zero");
    };
    let root = parse_with_limits(input, limits)?;
    if root.name != expected_root {
        return Err(PersistenceCodecError::WrongRoot);
    }
    Ok(root)
}

/// Serializes Public Access Block into the exact old persistence field order and element form.
#[must_use]
pub fn serialize_public_access_block(value: &PersistedPublicAccessBlockConfiguration) -> Vec<u8> {
    let mut writer = XmlWriter::fragment();
    writer.open("PublicAccessBlockConfiguration", None);
    if let Some(enabled) = value.block_public_acls {
        writer.element_bool("BlockPublicAcls", enabled);
    }
    if let Some(enabled) = value.block_public_policy {
        writer.element_bool("BlockPublicPolicy", enabled);
    }
    if let Some(enabled) = value.ignore_public_acls {
        writer.element_bool("IgnorePublicAcls", enabled);
    }
    if let Some(enabled) = value.restrict_public_buckets {
        writer.element_bool("RestrictPublicBuckets", enabled);
    }
    writer.close();
    writer.finish().into_bytes()
}
