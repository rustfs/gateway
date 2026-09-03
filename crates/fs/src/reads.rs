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
//! into a decision, and putting that decision's status, `Content-Range` and bytes on the wire.
//! NOT responsible for: deciding range semantics, which belongs to
//! [`rustfs_gateway::evaluate_range`]; version publication, delete markers, or the version census,
//! which belong to `super::versioning`.
//! Upstream: the persisted version records and the plain object files. Downstream: the production
//! `GetObject` and `HeadObject` registrations.
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
    ByteStream, ETag, Handler, HandlerError, HandlerResult, IfRange, ObjectValidators, RangeDecision, RangeSelectors, Req, Resp,
    Timestamp, evaluate_range,
};

use super::records::RecordKind;
use super::storage_error;
use super::versioning::{delete_marker_error, explicit_for_key, missing_version, newest_for_key};

/// The representation a read describes, before any range is applied.
struct Representation {
    bytes: Vec<u8>,
    e_tag: ETag,
    last_modified: Timestamp,
    storage_class: Option<rustfs_gateway::dto::StorageClass>,
    version_id: Option<String>,
    /// The user metadata stored with this version, keyed by the lowercase `x-amz-meta-` suffix.
    ///
    /// This is the map the DTO already declares — `BTreeMap<String, String>` on both
    /// `GetObjectOutput` and `HeadObjectOutput` — carried through unchanged. The response encoder
    /// re-applies RFC 2047 on the way out, so what is stored and what is returned are the same
    /// Unicode value rather than two encodings of it.
    metadata: std::collections::BTreeMap<String, String>,
}

/// The window a read serves, and the answer's status.
struct Window {
    start: usize,
    end_exclusive: usize,
    content_range: Option<String>,
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
/// `part_number` is passed through even though this backend cannot answer one: its presence is
/// what makes `evaluate_range` refuse a `Range` sent beside it, and dropping it here would
/// silently un-refuse the combination S3 answers neither half of.
///
/// # Errors
///
/// The contract's own refusals: `Range` together with `partNumber`, and an unsatisfiable range,
/// which becomes the `416` carrying `Content-Range: bytes */<length>`. A `partNumber` on its own
/// is refused by name — this backend stores an object's assembled bytes and no part table, so a
/// window for a part is a fact it does not hold, and answering one would be inventing it.
fn resolve_window(
    range: Option<&str>,
    if_range: Option<&IfRange>,
    part_number: Option<i32>,
    representation: &Representation,
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
    let content_range = decision.content_range();
    let served = decision.content_length(length as u64);
    let status = decision.status().as_u16();
    match decision {
        RangeDecision::Whole => Ok(Window {
            start: 0,
            end_exclusive: length,
            content_range: None,
            status,
        }),
        RangeDecision::Partial { start, .. } => {
            let start = usize::try_from(start).unwrap_or(length).min(length);
            let served = usize::try_from(served).unwrap_or(length);
            Ok(Window {
                start,
                end_exclusive: start.saturating_add(served).min(length),
                content_range,
                status,
            })
        }
        RangeDecision::Part { .. } => Err(HandlerError::not_implemented(
            "this reference backend stores an object's assembled bytes and no part table, so a partNumber \
             selector names a window it cannot resolve",
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
    async fn representation(&self, bucket: &str, key: &str, version_id: Option<&str>) -> Result<Representation, HandlerError> {
        let _guard = self.version_lock.lock().await;
        self.require_readable_versioning(bucket).await?;
        let records = self.version_records(bucket).await?;
        let selected = version_id
            .and_then(|id| explicit_for_key(&records, key, id))
            .or_else(|| version_id.is_none().then(|| newest_for_key(&records, key)).flatten());
        if let Some(record) = selected {
            if matches!(record.kind, RecordKind::DeleteMarker) {
                return Err(delete_marker_error(record, key, version_id.is_some()));
            }
            // A `HEAD` still reads the bytes: the record carries the length, but the entity tag
            // and the window arithmetic are decided against the representation, and a length taken
            // from one source while the bytes come from another is how the two drift apart.
            let bytes = self.read_version_body(record).await?;
            return Ok(Representation {
                bytes,
                e_tag: ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?,
                last_modified: Timestamp::from_secs(record.modified),
                storage_class: Some(record.storage_class.clone()),
                version_id: (record.version_id != "null").then(|| record.version_id.clone()),
                metadata: record.metadata.clone(),
            });
        }
        if version_id.is_some_and(|id| id != "null") {
            return Err(missing_version(key));
        }
        let (bytes, file_metadata) = self.read_object(bucket, key).await?;
        Ok(Representation {
            e_tag: super::etag(&bytes)?,
            last_modified: super::last_modified(&file_metadata),
            bytes,
            storage_class: None,
            version_id: None,
            // A plain object file predates the version records entirely and carries no metadata
            // section, so the honest answer is the empty map rather than a guess.
            metadata: std::collections::BTreeMap::new(),
        })
    }
}

impl Handler<GetObject> for super::FsBackend {
    async fn call(&self, request: Req<GetObject>) -> HandlerResult<GetObject> {
        let input = request.input();
        let representation = self
            .representation(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        // `If-Range` is read through the contract's own total parse. A fallible read flattened into
        // an `Option` would turn a validator this server cannot confirm into "no `If-Range` was
        // sent", which honours the range against a representation nobody checked.
        let if_range = input.if_range.as_deref().map(IfRange::parse);
        let window = resolve_window(
            input.range.as_ref().map(|range| range.as_str()),
            if_range.as_ref(),
            input.part_number,
            &representation,
        )?;
        let body = representation
            .bytes
            .get(window.start..window.end_exclusive)
            .unwrap_or_default()
            .to_vec();
        Ok(Resp::with_status(
            GetObjectOutput {
                content_length: i64::try_from(body.len()).ok(),
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
                body: Some(ByteStream::from_bytes(Bytes::from(body))),
                ..GetObjectOutput::default()
            },
            window.status,
        ))
    }
}

impl Handler<HeadObject> for super::FsBackend {
    async fn call(&self, request: Req<HeadObject>) -> HandlerResult<HeadObject> {
        let input = request.input();
        let representation = self
            .representation(input.bucket.as_str(), input.key.as_str(), input.version_id.as_deref())
            .await?;
        // `HeadObject` declares no `If-Range`: RFC 9110 attaches the switch to a retrieval, and the
        // operation's IR carries no such field, so there is nothing to read rather than something
        // being ignored.
        let window = resolve_window(input.range.as_ref().map(|range| range.as_str()), None, input.part_number, &representation)?;
        Ok(Resp::with_status(
            HeadObjectOutput {
                content_length: i64::try_from(window.len()).ok(),
                content_range: window.content_range,
                accept_ranges: Some("bytes".to_owned()),
                e_tag: Some(representation.e_tag),
                last_modified: Some(representation.last_modified),
                storage_class: representation.storage_class,
                version_id: representation.version_id,
                metadata: representation.metadata,
                ..HeadObjectOutput::default()
            },
            window.status,
        ))
    }
}
