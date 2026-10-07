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

//! Version-aware object reads, and the window a `Range` header selects out of them.
//!
//! Responsible for: selecting the representation a `GET` or `HEAD` describes — an explicit
//! version, the newest version, or the plain object file — turning the request's range selectors
//! into a decision, and putting that decision's status, `Content-Range` and bytes on the wire,
//! with the current version's `x-amz-expiration` (`super::lifecycle` predicts it).
//! NOT responsible for: deciding range semantics, which belongs to
//! [`rustfs_gateway::evaluate_range`]; version publication, delete markers, or the version census,
//! which belong to `super::versioning`.
//! Upstream: the persisted version records and the plain object files. Downstream: the production
//! `GetObject`, `HeadObject`, and `CopyObject` registrations.
//!
//! # Why the decision is not made here
//!
//! Suffix ranges, the clamp of a window that runs past the end, the `416` an unsatisfiable range
//! answers, the whole-object answer to a multi-range request, and the `If-Range` switch are all
//! [`rustfs_gateway::evaluate_range`]'s. A second implementation of them in a backend is the
//! defect rustfs/gateway#15 recorded — the contract sat one crate away, unreachable, while a
//! backend re-derived it and got it wrong. This module turns wire values into that contract's
//! inputs and its answer into bytes, and decides nothing about ranges itself.

use bytes::Bytes;
use rustfs_gateway::dto::{GetObject, GetObjectOutput, HeadObject, HeadObjectOutput};
use rustfs_gateway::{
    ByteStream, ConditionalOutcome, ETag, Handler, HandlerError, HandlerResult, IfRange, ObjectValidators, RangeDecision,
    RangeSelectors, Req, Resp, Timestamp, evaluate_range,
};

use super::conditions::{conditions, guard_read};
use super::content_headers::ContentHeaders;
use super::encryption::refuse_read_encryption;
use super::lifecycle::ExpiringObject;
use super::records::RecordKind;
use super::storage_error;
use super::versioning::{delete_marker_error, explicit_for_key, missing_version, newest_for_key};

/// The representation a read describes, before any range is applied.
pub(super) struct Representation {
    pub(super) bytes: Vec<u8>,
    pub(super) e_tag: ETag,
    pub(super) last_modified: Timestamp,
    storage_class: Option<rustfs_gateway::dto::StorageClass>,
    pub(super) version_id: Option<String>,
    /// The user metadata stored with this version, keyed by the lowercase `x-amz-meta-` suffix.
    ///
    /// This is the map the DTO already declares — `BTreeMap<String, String>` on both
    /// `GetObjectOutput` and `HeadObjectOutput` — carried through unchanged. The response encoder
    /// re-applies RFC 2047 on the way out, so what is stored and what is returned are the same
    /// Unicode value rather than two encodings of it.
    pub(super) metadata: std::collections::BTreeMap<String, String>,
    /// The representation headers stored with this version.
    pub(super) headers: ContentHeaders,
    pub(super) checksum: Option<super::checksums::StoredChecksum>,
    part_lengths: Option<Vec<u64>>,
    /// Whether this is the key's current version — read without a version id, named by the id of
    /// the newest record, or a plain object file — which alone answers `x-amz-expiration`.
    latest: bool,
    /// The version directory this representation was read from, or `None` for a plain object file.
    ///
    /// Carried so that `CopyObject` can read the source's tags under the default tagging
    /// directive. The tags are not read here: a read of the object must not fail because its tag
    /// document is unreadable (`n_corrupt_tag_authority_is_not_treated_as_an_empty_set`).
    pub(super) directory: Option<std::path::PathBuf>,
}

/// How many tags the version carries, as `x-amz-tagging-count` reports it (rustfs/gateway#1000).
///
/// `None` for a version with no tags, a plain object file, and a tag document that cannot be
/// read: the count is advisory, and a read must not fail on it
/// (`n_corrupt_tag_authority_is_not_treated_as_an_empty_set`).
async fn tag_count(representation: &Representation) -> Option<i32> {
    let directory = representation.directory.as_deref()?;
    let tags = super::tagging::read_persisted_tags(directory).await.ok()?;
    i32::try_from(tags.len()).ok().filter(|count| *count > 0)
}

impl super::FsBackend {
    /// The `x-amz-expiration` a read of `key` answers: the current version's predicted expiration,
    /// and nothing for a noncurrent one, as legacy RustFS answers it (rustfs/gateway#999). Advisory
    /// like the tag count: a tag document that cannot be read answers no header.
    async fn read_expiration(&self, bucket: &str, key: &str, representation: &Representation) -> Option<String> {
        if !representation.latest {
            return None;
        }
        let tags = match representation.directory.as_deref() {
            Some(directory) => super::tagging::read_persisted_tags(directory).await.ok()?,
            None => Vec::new(),
        };
        let object = ExpiringObject {
            key,
            size: i64::try_from(representation.bytes.len()).ok()?,
            tags: &tags,
            modified: representation.last_modified.secs(),
        };
        self.expiration_header(bucket, &object).await
    }
}

/// The window a read serves, and the answer's status.
struct Window {
    start: usize,
    end_exclusive: usize,
    content_range: Option<String>,
    parts_count: Option<i32>,
    status: u16,
}

impl Window {
    /// The number of bytes this window covers.
    const fn len(&self) -> usize {
        self.end_exclusive.saturating_sub(self.start)
    }
}

/// Resolves the request's range selectors against a representation.
///
/// GET resolves a part selector against persisted lengths through the core part-table contract.
/// HEAD retains its explicit unsupported result. Both still pass the selector to `evaluate_range`,
/// so a Range sent beside partNumber cannot accidentally become an ordinary range.
///
/// # Errors
///
/// The contract's own refusals: `Range` together with `partNumber`, and an unsatisfiable range,
/// which becomes the `416` carrying `Content-Range: bytes */<length>`. GET also refuses invalid or
/// unavailable parts and older multipart records without boundaries; HEAD part reads remain unsupported.
fn resolve_window(
    range: Option<&str>,
    if_range: Option<&IfRange>,
    part_number: Option<i32>,
    representation: &Representation,
    resolve_parts: bool,
) -> Result<Window, HandlerError> {
    let length = representation.bytes.len();
    let selectors = RangeSelectors {
        range,
        part_number: part_number.map(|number| u32::try_from(number).unwrap_or(0)),
        if_range,
    };
    let validators = ObjectValidators {
        exists: true,
        etag: Some(representation.e_tag.clone()),
        last_modified: Some(representation.last_modified),
    };
    let decision = evaluate_range(&selectors, &validators, length as u64)
        .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
    let parts_count = representation
        .part_lengths
        .as_ref()
        .and_then(|lengths| decision.part_count_header(lengths.len() as u32))
        .and_then(|count| i32::try_from(count).ok());
    let decision = match decision {
        RangeDecision::Part { part_number } if resolve_parts => super::part_lengths::window(
            part_number,
            representation.part_lengths.as_deref(),
            &representation.e_tag,
            length as u64,
        )?,
        decision => decision,
    };
    let content_range = decision.content_range();
    let served = decision.content_length(length as u64);
    let status = decision.status().as_u16();
    match decision {
        RangeDecision::Whole => Ok(Window {
            start: 0,
            end_exclusive: length,
            content_range: None,
            parts_count,
            status,
        }),
        RangeDecision::Partial { start, .. } => {
            let start = usize::try_from(start).unwrap_or(length).min(length);
            let served = usize::try_from(served).unwrap_or(length);
            Ok(Window {
                start,
                end_exclusive: start.saturating_add(served).min(length),
                content_range,
                parts_count,
                status,
            })
        }
        RangeDecision::Part { .. } => Err(HandlerError::not_implemented(
            "HEAD partNumber reads are not implemented by this reference backend",
        )),
        RangeDecision::Unsatisfiable {
            actual_object_size,
            range_requested,
        } => Err(HandlerError::unsatisfiable_range(range_requested, actual_object_size)),
    }
}

impl super::FsBackend {
    /// The representation a read describes: an explicit version, the newest one, or the plain file.
    ///
    /// The two paths exist because an object written before versioning was ever enabled has no
    /// version record. Both must answer the same shape, or a range honoured on one of them is a
    /// range ignored on the other — which is exactly how rustfs/gateway#626 could have been half
    /// fixed.
    pub(super) async fn representation(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<Representation, HandlerError> {
        let _guard = self.version_lock.lock().await;
        match self.select_locked(bucket, key, version_id).await? {
            Selected::Found(representation) => Ok(*representation),
            Selected::Absent(error) => Err(error),
        }
    }

    /// [`Self::representation`] with absence as a value, for a caller that already holds the
    /// version lock: a conditional request is evaluated against a key that holds no object
    /// (rustfs/gateway#808), and a conditional write holds the lock from that verdict to its
    /// publication.
    pub(super) async fn select_locked(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<Selected, HandlerError> {
        let reports_null = self.reports_null_version(bucket).await?;
        let records = self.version_records(bucket).await?;
        let selected = version_id
            .and_then(|id| explicit_for_key(&records, key, id))
            .or_else(|| version_id.is_none().then(|| newest_for_key(&records, key)).flatten());
        if let Some(record) = selected {
            if matches!(record.kind, RecordKind::DeleteMarker) {
                return Ok(Selected::Absent(delete_marker_error(record, key, version_id.is_some())));
            }
            // A `HEAD` still reads the bytes: the record carries the length, but the entity tag
            // and the window arithmetic are decided against the representation, and a length taken
            // from one source while the bytes come from another is how the two drift apart.
            let bytes = self.read_version_body(record).await?;
            let latest = version_id.is_none() || newest_for_key(&records, key).is_some_and(|newest| newest.path == record.path);
            return Ok(Selected::Found(Box::new(Representation {
                latest,
                bytes,
                e_tag: ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?,
                last_modified: Timestamp::from_secs(record.modified),
                storage_class: Some(record.storage_class.clone()),
                version_id: (record.version_id != "null" || reports_null).then(|| record.version_id.clone()),
                metadata: record.metadata.clone(),
                headers: record.headers.clone(),
                checksum: record.checksum,
                part_lengths: record.part_lengths.clone(),
                directory: Some(record.path.clone()),
            })));
        }
        if version_id.is_some_and(|id| id != "null") {
            return Ok(Selected::Absent(missing_version(key)));
        }
        let Some((bytes, file_metadata)) = self.read_object_if_present(bucket, key).await? else {
            return Ok(Selected::Absent(super::no_such_key(key)));
        };
        Ok(Selected::Found(Box::new(Representation {
            latest: true,
            e_tag: super::etag(&bytes)?,
            last_modified: super::last_modified(&file_metadata),
            bytes,
            storage_class: None,
            version_id: None,
            // A plain object file predates the version records entirely and carries no metadata
            // section, so the honest answer is the empty map rather than a guess.
            metadata: std::collections::BTreeMap::new(),
            headers: ContentHeaders::default(),
            checksum: None,
            part_lengths: None,
            directory: None,
        })))
    }

    /// The representation a conditional read serves, or the `304` it answers instead.
    ///
    /// The conditions are evaluated before absence is reported, so `If-Match` against a missing key
    /// is a `412` and only an unconditional miss is a `NoSuchKey`.
    async fn conditional_read(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        conditions: &rustfs_gateway::Preconditions,
    ) -> Result<(Representation, ConditionalOutcome), HandlerError> {
        let _guard = self.version_lock.lock().await;
        match self.select_locked(bucket, key, version_id).await? {
            Selected::Found(representation) => {
                let outcome = guard_read(Some(&representation), conditions)?;
                Ok((*representation, outcome))
            }
            Selected::Absent(error) => {
                guard_read(None, conditions)?;
                Err(error)
            }
        }
    }
}

/// What a lookup found: the representation, or the error an unconditional request is answered with.
pub(super) enum Selected {
    Found(Box<Representation>),
    Absent(HandlerError),
}

impl Handler<GetObject> for super::FsBackend {
    async fn call(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        refuse_read_encryption(request.sse())?;
        let input = request.input();
        let conditions = conditions(
            input.if_match.as_deref(),
            input.if_unmodified_since,
            input.if_none_match.as_deref(),
            input.if_modified_since,
            Timestamp::from_secs(self.clock.now().unix_seconds()),
        )?;
        let (representation, outcome) = self
            .conditional_read(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref(), &conditions)
            .await?;
        if outcome == ConditionalOutcome::NotModified {
            // The validators and the caching headers, and no body: the client's copy is current.
            return Ok(Resp::with_status(
                GetObjectOutput {
                    e_tag: outcome.includes_selected_etag().then_some(representation.e_tag),
                    last_modified: Some(representation.last_modified),
                    cache_control: representation.headers.cache_control,
                    expires: representation.headers.expires.map(Into::into),
                    ..GetObjectOutput::default()
                },
                304,
            ));
        }
        // `If-Range` is read through the contract's own total parse. A fallible read flattened into
        // an `Option` would turn a validator this server cannot confirm into "no `If-Range` was
        // sent", which honours the range against a representation nobody checked.
        let if_range = input.if_range.as_deref().map(IfRange::parse);
        let window = resolve_window(
            input.range.as_ref().map(|range| range.as_str()),
            if_range.as_ref(),
            input.part_number,
            &representation,
            true,
        )?;
        let encryption = representation.headers.encryption();
        let tag_count = tag_count(&representation).await;
        let expiration = self
            .read_expiration(input.bucket.as_str(), input.key.as_str(), &representation)
            .await
            .map(Into::into);
        let body = representation
            .bytes
            .get(window.start..window.end_exclusive)
            .unwrap_or_default()
            .to_vec();
        let mut output = GetObjectOutput {
            expiration,
            content_length: i64::try_from(body.len()).ok(),
            parts_count: window.parts_count,
            content_range: window.content_range,
            accept_ranges: Some("bytes".to_owned()),
            // The validators describe the representation, never the window, so a 206 reports
            // the entity tag and modification time of the whole object — which is what lets a
            // resumed download notice the object changed underneath it.
            e_tag: Some(representation.e_tag),
            last_modified: Some(representation.last_modified),
            storage_class: representation.storage_class,
            version_id: representation.version_id,
            metadata: representation.metadata,
            tag_count,
            content_type: Some(representation.headers.served_content_type()),
            cache_control: representation.headers.cache_control,
            content_disposition: representation.headers.content_disposition,
            content_encoding: representation.headers.content_encoding,
            content_language: representation.headers.content_language,
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            expires: representation.headers.expires.map(Into::into),
            body: Some(ByteStream::from_bytes(Bytes::from(body))),
            ..GetObjectOutput::default()
        };
        let checksum = (input.checksum_mode.as_ref() == Some(&rustfs_gateway::dto::ChecksumMode::ENABLED)
            && input.range.is_none()
            && input.part_number.is_none())
        .then_some(representation.checksum)
        .flatten();
        set_object_checksum!(output, checksum);
        output.checksum_type = checksum.and_then(super::checksums::StoredChecksum::dto_type);
        Ok(Resp::with_status(output, window.status))
    }
}

impl Handler<HeadObject> for super::FsBackend {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        refuse_read_encryption(request.sse())?;
        let input = request.input();
        let conditions = conditions(
            input.if_match.as_deref(),
            input.if_unmodified_since,
            input.if_none_match.as_deref(),
            input.if_modified_since,
            Timestamp::from_secs(self.clock.now().unix_seconds()),
        )?;
        let (representation, outcome) = self
            .conditional_read(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref(), &conditions)
            .await?;
        if outcome == ConditionalOutcome::NotModified {
            return Ok(Resp::with_status(
                HeadObjectOutput {
                    e_tag: outcome.includes_selected_etag().then_some(representation.e_tag),
                    last_modified: Some(representation.last_modified),
                    cache_control: representation.headers.cache_control,
                    expires: representation.headers.expires.map(Into::into),
                    ..HeadObjectOutput::default()
                },
                304,
            ));
        }
        // `HeadObject` declares no `If-Range`: RFC 9110 attaches the switch to a retrieval, and the
        // operation's IR carries no such field, so there is nothing to read rather than something
        // being ignored.
        let window = resolve_window(
            input.range.as_ref().map(|range| range.as_str()),
            None,
            input.part_number,
            &representation,
            false,
        )?;
        let tag_count = tag_count(&representation).await;
        let expiration = self
            .read_expiration(input.bucket.as_str(), input.key.as_str(), &representation)
            .await
            .map(Into::into);
        let encryption = representation.headers.encryption();
        let mut output = HeadObjectOutput {
            expiration,
            content_length: i64::try_from(window.len()).ok(),
            content_range: window.content_range,
            accept_ranges: Some("bytes".to_owned()),
            e_tag: Some(representation.e_tag),
            last_modified: Some(representation.last_modified),
            storage_class: representation.storage_class,
            version_id: representation.version_id,
            metadata: representation.metadata,
            tag_count,
            content_type: Some(representation.headers.served_content_type()),
            cache_control: representation.headers.cache_control,
            content_disposition: representation.headers.content_disposition,
            content_encoding: representation.headers.content_encoding,
            content_language: representation.headers.content_language,
            server_side_encryption: encryption.reported_algorithm(),
            ssekms_key_id: encryption.kms_key_id,
            expires: representation.headers.expires.map(Into::into),
            ..HeadObjectOutput::default()
        };
        let checksum = (input.checksum_mode.as_ref() == Some(&rustfs_gateway::dto::ChecksumMode::ENABLED)
            && input.range.is_none())
        .then_some(representation.checksum)
        .flatten();
        set_object_checksum!(output, checksum);
        output.checksum_type = checksum.and_then(super::checksums::StoredChecksum::dto_type);
        Ok(Resp::with_status(output, window.status))
    }
}
