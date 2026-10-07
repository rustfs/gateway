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

//! The on-disk grammar of a version record, and the user-metadata section it may carry.
//!
//! Responsible for: the byte-level form of one persisted version record, the versioned trailing
//! section that carries user metadata, and the storability rules a metadata pair must satisfy
//! before it is written anywhere durable.
//! NOT responsible for: filesystem safety checks, publication order, version selection, or the
//! acceptance-time metadata rules, which `rustfs-gateway-http` applies to the request long before
//! a byte reaches this module.
//! Upstream: `super::versioning`, which reads and writes the record file, and `super::uploads`,
//! which reuses the same section for the metadata a `CreateMultipartUpload` carries. Downstream:
//! nothing — this module performs no I/O.
//!
//! # The compatibility story, stated once
//!
//! A record is a sequence of newline-terminated lines. Lines one to eight are the original,
//! unversioned form and are unchanged: sequence, hex key, hex version id, kind, modified, entity
//! tag, size, hex storage class. A record whose object carries **no** optional sections is written
//! with exactly those eight lines and is therefore byte-identical to what every earlier build
//! wrote, so a downgrade keeps reading it.
//!
//! Metadata is a **named, versioned trailing section**: line nine is `meta/1 <count>`, followed by
//! `count` lines of `<hex key> <hex value>`. Two properties follow, and both are load-bearing:
//!
//! * a build that predates this section refuses the record outright — its reader already treats
//!   any ninth line as a corrupt record — so a new record is never silently read as an object with
//!   no metadata by an older reader;
//! * a section name this build does not know is refused here by name rather than skipped, for the
//!   same reason. An object that reads back without the metadata it was stored with, and no error,
//!   is data loss wearing the costume of a successful read.
//!
//! The stored representation headers — `Content-Type`, `Content-Encoding`, `Content-Disposition`,
//! `Content-Language`, `Cache-Control`, and `Expires` — are a second optional section,
//! `headers/1 <count>`, after the metadata section when both are present, with one
//! `<header name> <hex value>` line per stored header in a fixed order. The same two properties
//! hold for it: an object carrying no optional sections is still the eight-line form, and an older reader
//! refuses a record that carries some rather than answering it without them (rustfs/gateway#718).
//!
//! A stored full-object checksum adds `checksum/1 1` followed by `<algorithm> <base64 value>`,
//! after metadata and headers when present. Old records carry no checksum. Older builds refuse
//! this section: preserve a pre-upgrade data copy before downgrading, rather than stripping the
//! checksum from new records. Multipart initiation records must not contain this section.
//!
//! Completed multipart checksums use `checksum/2 1` and `<algorithm> <type> <value>` instead.
//! The type must agree with the value's composite suffix. It is explicit even for FULL_OBJECT,
//! so a completed upload can report its type without inventing one for an older plain PUT.
//! Both versions remain readable, at most one checksum section is allowed, and builds that only
//! understand `checksum/1` refuse the new section. A rollback therefore still needs a data copy
//! made before the upgrade; dropping the type is not a migration.
//!
//! Completed objects may end with `parts/1 <count>` followed by one unsigned decimal length
//! per part, in completed order. The count is 1..10000, agrees with the multipart entity tag,
//! and the checked sum equals the stored object size. No section may follow it. Older readers
//! reject this section, so rollback requires a pre-upgrade data copy. Older multipart records
//! without a table remain readable whole but cannot provide part windows.
//!
//! Every refusal below carries its own sentence rather than one shared "storage failed", because
//! the point of failing closed is that whoever reads the log can tell a half-written record apart
//! from one written by a build this one does not understand.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rustfs_gateway::dto::StorageClass;
use rustfs_gateway::{ChecksumAlgorithm, ChecksumSpec, ChecksumType, ErrorCode, HandlerError};

use super::checksums::StoredChecksum;

use super::content_headers::{
    CONTENT_HEADERS_SECTION, ContentHeaders, decode_content_header_entries, encode_content_headers_section,
    validate_content_headers,
};
use super::storage_error;

/// The name and version of the trailing section that carries user metadata.
const METADATA_SECTION: &str = "meta/1";
const CHECKSUM_SECTION: &str = "checksum/1";
const TYPED_CHECKSUM_SECTION: &str = "checksum/2";

/// Everything a write stores beside an object version's bytes.
///
/// A multipart upload record persists only `metadata` and `headers`; its tags are a `tags` file
/// beside the record (rustfs/gateway#1000), and its storage class is not carried to completion yet.
#[derive(Clone, Debug, Default)]
pub(super) struct ObjectAttributes {
    /// The `x-amz-meta-*` map, keyed by the lowercase suffix.
    pub(super) metadata: BTreeMap<String, String>,
    /// The standard representation headers.
    pub(super) headers: ContentHeaders,
    /// The checksum stored with these object bytes, absent on older records.
    pub(super) checksum: Option<StoredChecksum>,
    /// Completed part lengths in ordinal order, absent on older records.
    pub(super) part_lengths: Option<Vec<u64>>,
    /// Original upload numbers and verified part checksums; absent on older records.
    pub(super) part_metadata: Option<Vec<super::part_metadata::PartMetadata>>,
    /// The storage class the write named; `None` records `STANDARD`.
    pub(super) storage_class: Option<StorageClass>,
    /// The validated tag set the write carried, written beside the version atomically with it.
    pub(super) tags: Vec<(String, String)>,
}

/// Refuses attributes this backend will not persist.
///
/// # Errors
///
/// The refusals of [`validate_user_metadata`] and [`validate_content_headers`].
pub(super) fn validate_attributes(attributes: &ObjectAttributes) -> Result<(), HandlerError> {
    validate_user_metadata(&attributes.metadata)?;
    validate_content_headers(&attributes.headers)
}

/// The prefix a stored key becomes on the wire, spelled here because it is not reachable.
///
/// `rustfs-gateway-http` owns the canonical `METADATA_PREFIX`, but the `rustfs-gateway` facade
/// this crate depends on does not re-export it, and a reference backend that reached past the
/// facade would stop being evidence that the public API is sufficient. The two spellings are
/// pinned together by `a_metadata_key_is_stored_and_returned_lowercased`, which asserts a stored
/// key comes back under this exact prefix through the real service.
const METADATA_HEADER_PREFIX: &str = "x-amz-meta-";

/// The combined key and value budget one object's user metadata may occupy, in bytes.
///
/// AWS documents 2 KB for the user-defined metadata within a `PUT` request's headers
/// (<https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingMetadata.html>): the summary in
/// this repository's words is that user metadata is capped separately from, and well below, the
/// request's overall header allowance. This constant applies that number to the **stored** form —
/// the RFC 2047-decoded Unicode this backend persists — and not to the encoded header bytes the
/// wire carried, because those bytes are gone by the time a handler runs. The two differ for a
/// non-ASCII value, where the encoded form is the larger of the pair, so this ceiling is the more
/// permissive of the two measurements and is deliberately not presented as the wire-form check.
/// Bounding the wire form belongs above this crate, where the header bytes still exist.
const MAX_USER_METADATA_BYTES: usize = 2048;

/// Whether a persisted version holds object bytes or records a deletion.
#[derive(Clone, Copy)]
pub(super) enum RecordKind {
    /// The version holds object bytes.
    Object,
    /// The version is a delete marker.
    DeleteMarker,
}

/// One persisted version, as it exists on disk plus the directory it was read from.
#[derive(Clone)]
pub(super) struct VersionRecord {
    pub(super) path: PathBuf,
    pub(super) sequence: u64,
    pub(super) key: String,
    pub(super) version_id: String,
    pub(super) kind: RecordKind,
    pub(super) modified: i64,
    pub(super) e_tag: String,
    pub(super) size: i64,
    pub(super) storage_class: StorageClass,
    pub(super) metadata: BTreeMap<String, String>,
    pub(super) headers: ContentHeaders,
    /// The checksum stored with these object bytes, absent on older records.
    pub(super) checksum: Option<StoredChecksum>,
    /// Completed part lengths in ordinal order, absent on older records.
    pub(super) part_lengths: Option<Vec<u64>>,
    /// Original upload numbers and verified part checksums; absent on older records.
    pub(super) part_metadata: Option<Vec<super::part_metadata::PartMetadata>>,
}

/// Refuses a metadata pair this backend could store but could never hand back.
///
/// The two rules are the response encoder's own: `set_prefixed_header` builds
/// `x-amz-meta-<key>` as a [`http::HeaderName`] and the value as a [`http::HeaderValue`], and
/// **drops the header** when either fails. Persisting a pair that would be dropped on the way out
/// converts a bad request into an object whose metadata silently disappears on every later read,
/// so the pair is refused at the door instead.
///
/// A key carrying an ASCII uppercase letter is refused rather than lowercased. `HeaderName`
/// normalises case, so accepting one here would let `Mtime` and `mtime` name the same stored entry
/// while the map that arrived held two — a merge this layer has no authority to perform. Case
/// normalisation is the codec's, and it has already happened: `x-amz-meta-*` reaches a handler as
/// the lowercase suffix of a parsed header name.
///
/// # Errors
///
/// [`ErrorCode::INVALID_REQUEST`] naming which half of the pair is unusable.
fn validate_pair(key: &str, value: &str) -> Result<(), HandlerError> {
    if key.is_empty() || key.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "a user metadata key must be a non-empty lowercase header token",
        ));
    }
    let name = format!("{METADATA_HEADER_PREFIX}{key}");
    if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
        return Err(HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "a user metadata key must be a non-empty lowercase header token",
        ));
    }
    if http::HeaderValue::from_str(value).is_err() {
        return Err(HandlerError::new(
            ErrorCode::INVALID_REQUEST,
            "a user metadata value must be free of control characters",
        ));
    }
    Ok(())
}

/// Refuses a metadata map this backend will not persist.
///
/// # Errors
///
/// [`ErrorCode::METADATA_TOO_LARGE`] past [`MAX_USER_METADATA_BYTES`], and the pair refusals of
/// [`validate_pair`].
pub(super) fn validate_user_metadata(metadata: &BTreeMap<String, String>) -> Result<(), HandlerError> {
    let mut total = 0usize;
    for (key, value) in metadata {
        validate_pair(key, value)?;
        total = total.saturating_add(key.len()).saturating_add(value.len());
    }
    if total > MAX_USER_METADATA_BYTES {
        return Err(HandlerError::new(
            ErrorCode::METADATA_TOO_LARGE,
            "the user metadata exceeds the size this backend stores for one object",
        ));
    }
    Ok(())
}

/// Renders the trailing metadata section, or nothing at all for an object without metadata.
///
/// The empty answer preserves the eight-line form when the other optional sections are absent.
pub(super) fn encode_metadata_section(metadata: &BTreeMap<String, String>) -> String {
    if metadata.is_empty() {
        return String::new();
    }
    let mut section = format!("{METADATA_SECTION} {}\n", metadata.len());
    for (key, value) in metadata {
        section.push_str(&hex::encode(key));
        section.push(' ');
        section.push_str(&hex::encode(value));
        section.push('\n');
    }
    section
}

/// Renders the metadata and header sections shared by object and upload records.
///
/// The object-record encoder appends its checksum separately; uploads must not carry it.
pub(super) fn encode_trailing_sections(attributes: &ObjectAttributes) -> String {
    let mut sections = encode_metadata_section(&attributes.metadata);
    sections.push_str(&encode_content_headers_section(&attributes.headers));
    sections
}

fn section_header(line: &str) -> Result<(&str, &str), HandlerError> {
    line.split_once(' ')
        .ok_or_else(|| HandlerError::internal_error("the persisted record carries a trailing section without a name and length"))
}

/// Reads every trailing section out of a record's remaining lines.
///
/// Absence means no stored attributes — the eight-line form. The sections are `meta/1`,
/// `headers/1`, then one checksum section, `parts/1` and `part-meta/1`, each optional,
/// with nothing after them. Part metadata requires the matching completed length table.
///
/// # Errors
///
/// A distinct diagnosis for each way a section can be wrong: an unknown section name, a malformed
/// header, a declared count the file does not contain, an entry that is not a name and a hex
/// value, a value this backend would refuse to store, a repeated or out-of-order entry, and lines
/// after the last section.
pub(super) fn decode_trailing_sections(lines: &mut std::str::Lines<'_>) -> Result<ObjectAttributes, HandlerError> {
    let mut attributes = ObjectAttributes::default();
    let mut trailing_error = "the persisted record carries a trailing section this build does not understand";
    let mut next = lines.next();
    if let Some(line) = next {
        let (name, count) = section_header(line)?;
        if name == METADATA_SECTION {
            attributes.metadata = decode_metadata_entries(lines, count)?;
            next = lines.next();
            trailing_error = "the persisted metadata section is followed by lines this build cannot read";
        }
    }
    if let Some(line) = next
        && let Ok((CONTENT_HEADERS_SECTION, count)) = section_header(line)
    {
        attributes.headers = decode_content_header_entries(lines, count)?;
        next = lines.next();
        trailing_error = "the persisted representation-header section is followed by lines this build cannot read";
    }
    if let Some(line) = next
        && let Ok((name, count)) = section_header(line)
        && matches!(name, CHECKSUM_SECTION | TYPED_CHECKSUM_SECTION)
    {
        if count != "1" {
            return Err(HandlerError::internal_error("the persisted checksum section must contain one checksum"));
        }
        let (algorithm, value) = lines
            .next()
            .and_then(|line| line.split_once(' '))
            .ok_or_else(|| HandlerError::internal_error("the persisted checksum has no algorithm and value"))?;
        let algorithm = ChecksumAlgorithm::from_wire_name(algorithm)
            .ok_or_else(|| HandlerError::internal_error("the persisted checksum algorithm is not supported"))?;
        let (kind, value) = if name == TYPED_CHECKSUM_SECTION {
            let (kind, value) = value
                .split_once(' ')
                .ok_or_else(|| HandlerError::internal_error("the persisted checksum has no type and value"))?;
            let kind = ChecksumType::parse(kind)
                .map_err(|_| HandlerError::internal_error("the persisted checksum type is not supported"))?;
            (Some(kind), value)
        } else {
            (None, value)
        };
        let value = ChecksumSpec::parse_header(algorithm.header_name(), value)
            .map_err(|_| HandlerError::internal_error("the persisted checksum value is malformed"))?;
        attributes.checksum = Some(match kind {
            Some(kind) => StoredChecksum::multipart(
                value
                    .with_type(kind)
                    .map_err(|_| HandlerError::internal_error("the persisted checksum type contradicts its value"))?,
            ),
            None => StoredChecksum::plain(value),
        });
        next = lines.next();
        trailing_error = "the persisted checksum section is followed by lines this build cannot read";
    }
    if let Some(line) = next
        && let Ok(("parts/1", count)) = section_header(line)
    {
        attributes.part_lengths = Some(super::part_lengths::decode(lines, count)?);
        next = lines.next();
        trailing_error = "the persisted part table is followed by lines this build cannot read";
    }
    if let Some(line) = next
        && let Ok(("part-meta/1", count)) = section_header(line)
    {
        let parts = super::part_metadata::decode(lines, count)?;
        super::part_metadata::validate(&parts, attributes.part_lengths.as_deref(), attributes.checksum)?;
        attributes.part_metadata = Some(parts);
        next = lines.next();
        trailing_error = "the persisted part metadata is followed by lines this build cannot read";
    }
    if next.is_some() {
        return Err(HandlerError::internal_error(trailing_error));
    }
    Ok(attributes)
}

fn encode_checksum_section(checksum: Option<StoredChecksum>) -> String {
    checksum.map_or_else(String::new, |checksum| {
        let value = checksum.value;
        if checksum.report_type {
            format!(
                "{TYPED_CHECKSUM_SECTION} 1\n{} {} {}\n",
                value.algorithm().wire_name(),
                value.checksum_type().wire_name(),
                value.render_base64()
            )
        } else {
            format!("{CHECKSUM_SECTION} 1\n{} {}\n", value.algorithm().wire_name(), value.render_base64())
        }
    })
}

fn decode_metadata_entries(lines: &mut std::str::Lines<'_>, count: &str) -> Result<BTreeMap<String, String>, HandlerError> {
    let count = count
        .parse::<usize>()
        .map_err(|_| HandlerError::internal_error("the persisted metadata section does not declare a decimal entry count"))?;
    let mut metadata = BTreeMap::new();
    for _ in 0..count {
        let entry = lines
            .next()
            .ok_or_else(|| HandlerError::internal_error("the persisted metadata section declares more entries than it holds"))?;
        let (key, value) = entry
            .split_once(' ')
            .ok_or_else(|| HandlerError::internal_error("a persisted metadata entry is not a hex key and a hex value"))?;
        let key = decode_hex_text(key)
            .ok_or_else(|| HandlerError::internal_error("a persisted metadata entry is not a hex key and a hex value"))?;
        let value = decode_hex_text(value)
            .ok_or_else(|| HandlerError::internal_error("a persisted metadata entry is not a hex key and a hex value"))?;
        validate_pair(&key, &value)
            .map_err(|_| HandlerError::internal_error("a persisted metadata entry cannot be returned as a header"))?;
        if metadata.insert(key, value).is_some() {
            return Err(HandlerError::internal_error("the persisted metadata section repeats a key"));
        }
    }
    validate_user_metadata(&metadata)
        .map_err(|_| HandlerError::internal_error("the persisted metadata section exceeds the size this backend stores"))?;
    Ok(metadata)
}

/// Renders one version record in its complete on-disk form.
pub(super) fn encode_version_record(record: &VersionRecord) -> String {
    let kind = match record.kind {
        RecordKind::Object => "object",
        RecordKind::DeleteMarker => "delete",
    };
    format!(
        "{}\n{}\n{}\n{kind}\n{}\n{}\n{}\n{}\n{}",
        record.sequence,
        hex::encode(&record.key),
        hex::encode(&record.version_id),
        record.modified,
        record.e_tag,
        record.size,
        hex::encode(record.storage_class.as_str()),
        encode_metadata_section(&record.metadata),
    ) + &encode_content_headers_section(&record.headers)
        + &encode_checksum_section(record.checksum)
        + &super::part_lengths::encode(record.part_lengths.as_deref())
        + &super::part_metadata::encode(record.part_metadata.as_deref())
}

/// Parses one version record's bytes, pairing them with the directory they came from.
///
/// # Errors
///
/// [`storage_error`] for every malformed line of the original eight, and the named metadata
/// diagnoses of [`decode_metadata_section`] for the trailing section.
pub(super) fn decode_version_record(path: PathBuf, encoded: &str) -> Result<VersionRecord, HandlerError> {
    let mut lines = encoded.lines();
    let sequence = lines
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(storage_error)?;
    let key = lines.next().and_then(decode_hex_text).ok_or_else(storage_error)?;
    let version_id = lines.next().and_then(decode_hex_text).ok_or_else(storage_error)?;
    let kind = match lines.next() {
        Some("object") => RecordKind::Object,
        Some("delete") => RecordKind::DeleteMarker,
        _ => return Err(storage_error()),
    };
    let modified = lines
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(storage_error)?;
    let e_tag = lines.next().map(ToOwned::to_owned).ok_or_else(storage_error)?;
    let size = lines
        .next()
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or_else(storage_error)?;
    let storage_class = match lines.next() {
        None => StorageClass::STANDARD,
        Some(value) => decode_hex_text(value)
            .and_then(super::transitions::persisted_storage_class)
            .ok_or_else(storage_error)?,
    };
    let attributes = decode_trailing_sections(&mut lines)?;
    if let Some(lengths) = attributes.part_lengths.as_deref() {
        if !matches!(kind, RecordKind::Object) {
            return Err(storage_error());
        }
        super::part_lengths::validate(lengths, size, &e_tag)?;
    }
    if version_id.is_empty() {
        return Err(storage_error());
    }
    Ok(VersionRecord {
        path,
        sequence,
        key,
        version_id,
        kind,
        modified,
        e_tag,
        size,
        storage_class,
        metadata: attributes.metadata,
        headers: attributes.headers,
        checksum: attributes.checksum,
        part_lengths: attributes.part_lengths,
        part_metadata: attributes.part_metadata,
    })
}

/// Decodes one hex-encoded UTF-8 field.
pub(super) fn decode_hex_text(value: &str) -> Option<String> {
    String::from_utf8(hex::decode(value).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_headers::DEFAULT_CONTENT_TYPE;

    fn pairs(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn record(metadata: BTreeMap<String, String>) -> VersionRecord {
        VersionRecord {
            path: PathBuf::from("/nonexistent"),
            sequence: 1,
            key: "report.txt".to_owned(),
            version_id: "null".to_owned(),
            kind: RecordKind::Object,
            modified: 1_767_323_045,
            e_tag: "6838544f7fc78fc87f155007ba725b65".to_owned(),
            size: 12,
            storage_class: StorageClass::STANDARD,
            metadata,
            headers: ContentHeaders::default(),
            checksum: None,
            part_lengths: None,
            part_metadata: None,
        }
    }

    fn decode_section(text: &str) -> Result<BTreeMap<String, String>, HandlerError> {
        decode_trailing_sections(&mut text.lines()).map(|attributes| attributes.metadata)
    }

    fn decode_headers(text: &str) -> Result<ContentHeaders, HandlerError> {
        decode_trailing_sections(&mut text.lines()).map(|attributes| attributes.headers)
    }

    fn typed() -> ContentHeaders {
        ContentHeaders {
            content_type: Some("text/plain".to_owned()),
            cache_control: Some("max-age=60".to_owned()),
            ..ContentHeaders::default()
        }
    }

    /// Positive — stored representation headers round-trip after the metadata section.
    #[test]
    fn representation_headers_round_trip_after_metadata() {
        let mut stored = record(pairs(&[("mtime", "1")]));
        stored.headers = typed();
        let encoded = encode_version_record(&stored);
        assert_eq!(encoded.lines().nth(8), Some("meta/1 1"));
        assert_eq!(encoded.lines().nth(10), Some("headers/1 2"));
        let decoded = decode_version_record(PathBuf::from("/nonexistent"), &encoded).expect("a round-tripped record");
        assert_eq!(decoded.headers, typed());
        assert_eq!(decoded.metadata, pairs(&[("mtime", "1")]));
    }

    /// Positive — the headers section stands alone when the object carries no user metadata.
    #[test]
    fn representation_headers_stand_alone_without_metadata() {
        let mut stored = record(BTreeMap::new());
        stored.headers = typed();
        let encoded = encode_version_record(&stored);
        assert_eq!(encoded.lines().nth(8), Some("headers/1 2"));
        let decoded = decode_version_record(PathBuf::from("/nonexistent"), &encoded).expect("a round-tripped record");
        assert_eq!(decoded.headers, typed());
        assert!(decoded.metadata.is_empty());
    }

    /// Negative — the model's default media type is not stored, so an untyped write keeps the
    /// eight-line form, and a read still answers the default.
    #[test]
    fn the_default_content_type_is_not_stored() {
        let headers = ContentHeaders::from_request(None, None, None, None, Some(DEFAULT_CONTENT_TYPE.to_owned()), None);
        assert_eq!(headers, ContentHeaders::default());
        assert_eq!(headers.served_content_type(), DEFAULT_CONTENT_TYPE);
        let mut stored = record(BTreeMap::new());
        stored.headers = headers;
        assert_eq!(encode_version_record(&stored).lines().count(), 8);
    }

    /// Negative — an unknown header name is refused rather than dropped.
    #[test]
    fn an_unknown_persisted_header_name_is_refused() {
        let error = decode_headers(&format!("headers/1 1\nx-amz-acl {}\n", hex::encode("private")))
            .expect_err("an unknown name is refused");
        assert_eq!(error.message(), "a persisted representation header is not a known name and a hex value");
    }

    /// Negative — a repeated or reordered header entry is refused.
    #[test]
    fn a_reordered_persisted_header_is_refused() {
        let value = hex::encode("x");
        let error = decode_headers(&format!("headers/1 2\ncontent-type {value}\ncache-control {value}\n"))
            .expect_err("a reordered entry is refused");
        assert_eq!(
            error.message(),
            "the persisted representation-header section repeats or reorders an entry"
        );
        let error = decode_headers(&format!("headers/1 2\ncontent-type {value}\ncontent-type {value}\n"))
            .expect_err("a repeated entry is refused");
        assert_eq!(
            error.message(),
            "the persisted representation-header section repeats or reorders an entry"
        );
    }

    /// Negative — a truncated headers section and lines after it are both refused.
    #[test]
    fn a_truncated_or_trailed_headers_section_is_refused() {
        let error = decode_headers("headers/1 1\n").expect_err("a truncated section is refused");
        assert_eq!(
            error.message(),
            "the persisted representation-header section declares more entries than it holds"
        );
        let error = decode_headers(&format!("headers/1 1\ncontent-type {}\nmeta/1 0\n", hex::encode("a/b")))
            .expect_err("a section after the headers is refused");
        assert_eq!(
            error.message(),
            "the persisted representation-header section is followed by lines this build cannot read"
        );
    }

    /// Negative — a header value that could never be answered is refused on read and on write.
    #[test]
    fn an_unreturnable_header_value_is_refused() {
        let error = decode_headers(&format!("headers/1 1\ncontent-type {}\n", hex::encode("a\r\nb")))
            .expect_err("a control character is refused");
        assert_eq!(error.message(), "a persisted representation header cannot be returned as a header");
        let headers = ContentHeaders {
            content_type: Some("a\nb".to_owned()),
            ..ContentHeaders::default()
        };
        let error = validate_content_headers(&headers).expect_err("an unstorable value is refused");
        assert_eq!(error.code(), &ErrorCode::INVALID_REQUEST);
    }

    /// Negative — a count that is not decimal is refused by name.
    #[test]
    fn a_headers_section_without_a_decimal_count_is_refused() {
        let error = decode_headers("headers/1 two\n").expect_err("a non-decimal count is refused");
        assert_eq!(
            error.message(),
            "the persisted representation-header section does not declare a decimal entry count"
        );
    }

    /// Positive — an object without metadata keeps the exact eight-line form earlier builds wrote.
    #[test]
    fn a_record_without_metadata_is_the_original_eight_lines() {
        let encoded = encode_version_record(&record(BTreeMap::new()));
        assert_eq!(
            encoded,
            "1\n7265706f72742e747874\n6e756c6c\nobject\n1767323045\n6838544f7fc78fc87f155007ba725b65\n12\n5354414e44415244\n"
        );
        assert_eq!(encoded.lines().count(), 8);
    }

    /// Positive — a record with metadata round-trips through both halves of the grammar.
    #[test]
    fn a_metadata_record_round_trips() {
        let metadata = pairs(&[("mtime", "1767323045.5"), ("owner", "aurélie")]);
        let encoded = encode_version_record(&record(metadata.clone()));
        assert_eq!(encoded.lines().nth(8), Some("meta/1 2"));
        let decoded = decode_version_record(PathBuf::from("/nonexistent"), &encoded).expect("a round-tripped record");
        assert_eq!(decoded.metadata, metadata);
        assert_eq!(decoded.storage_class.as_str(), "STANDARD");
    }

    /// Negative — a section name this build does not know is refused by name, never skipped.
    #[test]
    fn an_unknown_trailing_section_is_refused_by_name() {
        let error = decode_section("meta/2 1\n6d74696d65 31\n").expect_err("an unknown section is refused");
        assert_eq!(
            error.message(),
            "the persisted record carries a trailing section this build does not understand"
        );
    }

    /// Negative — a section header without a length is refused rather than read as a bare name.
    #[test]
    fn a_section_header_without_a_length_is_refused() {
        let error = decode_section("meta/1\n").expect_err("a header without a count is refused");
        assert_eq!(
            error.message(),
            "the persisted record carries a trailing section without a name and length"
        );
    }

    /// Negative — a declared count larger than the file's entries is a truncated record.
    #[test]
    fn a_truncated_metadata_section_is_refused() {
        let error = decode_section("meta/1 2\n6d74696d65 31\n").expect_err("a truncated section is refused");
        assert_eq!(error.message(), "the persisted metadata section declares more entries than it holds");
    }

    /// Negative — a count of zero followed by an entry is not silently trimmed.
    #[test]
    fn entries_past_the_declared_count_are_refused() {
        let error = decode_section("meta/1 0\n6d74696d65 31\n").expect_err("a trailing entry is refused");
        assert_eq!(
            error.message(),
            "the persisted metadata section is followed by lines this build cannot read"
        );
    }

    /// Negative — an entry that is not two hex fields is refused.
    #[test]
    fn a_malformed_metadata_entry_is_refused() {
        let error = decode_section("meta/1 1\n6d74696d65\n").expect_err("a single-field entry is refused");
        assert_eq!(error.message(), "a persisted metadata entry is not a hex key and a hex value");
        let error = decode_section("meta/1 1\nzz 31\n").expect_err("a non-hex key is refused");
        assert_eq!(error.message(), "a persisted metadata entry is not a hex key and a hex value");
    }

    /// Negative — a persisted key that could never be returned as a header is refused.
    #[test]
    fn an_unreturnable_persisted_entry_is_refused() {
        let uppercase = format!("meta/1 1\n{} 31\n", hex::encode("Mtime"));
        let error = decode_section(&uppercase).expect_err("an uppercase key is refused");
        assert_eq!(error.message(), "a persisted metadata entry cannot be returned as a header");
        let control = format!("meta/1 1\n{} {}\n", hex::encode("mtime"), hex::encode("one\rtwo"));
        let error = decode_section(&control).expect_err("a control character is refused");
        assert_eq!(error.message(), "a persisted metadata entry cannot be returned as a header");
    }

    /// Negative — a repeated key is refused rather than resolved by last-write-wins.
    #[test]
    fn a_repeated_persisted_key_is_refused() {
        let repeated = format!("meta/1 2\n{key} 31\n{key} 32\n", key = hex::encode("mtime"));
        let error = decode_section(&repeated).expect_err("a repeated key is refused");
        assert_eq!(error.message(), "the persisted metadata section repeats a key");
    }

    /// Negative — a persisted section past the stored ceiling is refused on read as well as write.
    #[test]
    fn an_oversized_persisted_section_is_refused() {
        let value = "v".repeat(MAX_USER_METADATA_BYTES);
        let section = format!("meta/1 1\n{} {}\n", hex::encode("mtime"), hex::encode(&value));
        let error = decode_section(&section).expect_err("an oversized section is refused");
        assert_eq!(error.message(), "the persisted metadata section exceeds the size this backend stores");
    }

    /// Negative — the combined key and value budget is what the ceiling measures.
    #[test]
    fn the_ceiling_counts_keys_and_values_together() {
        let under = pairs(&[("mtime", &"v".repeat(MAX_USER_METADATA_BYTES - "mtime".len()))]);
        validate_user_metadata(&under).expect("the exact ceiling is storable");
        let over = pairs(&[("mtime", &"v".repeat(MAX_USER_METADATA_BYTES - "mtime".len() + 1))]);
        let error = validate_user_metadata(&over).expect_err("one byte past the ceiling is refused");
        assert_eq!(error.code(), &ErrorCode::METADATA_TOO_LARGE);
    }

    /// Negative — an unstorable pair is refused before anything is written.
    #[test]
    fn an_unstorable_pair_is_refused_before_it_is_written() {
        let error = validate_user_metadata(&pairs(&[("m time", "1")])).expect_err("a space in a key is refused");
        assert_eq!(error.message(), "a user metadata key must be a non-empty lowercase header token");
        let error = validate_user_metadata(&pairs(&[("", "1")])).expect_err("an empty key is refused");
        assert_eq!(error.message(), "a user metadata key must be a non-empty lowercase header token");
        let error = validate_user_metadata(&pairs(&[("mtime", "one\ntwo")])).expect_err("a newline value is refused");
        assert_eq!(error.message(), "a user metadata value must be free of control characters");
    }
}

#[cfg(test)]
#[path = "part_metadata_tests.rs"]
mod part_metadata_tests;
