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

//! Persistent current-object listing for the filesystem reference backend.
//!
//! Responsible for: ListObjects V1/V2 and ListMultipartUploads filtering, delimiter rollup, page
//! sizing, marker resumption, and opaque V2 cursor minting over persisted storage authorities.
//! NOT responsible for: version selection, multipart completion, or lifecycle.
//! Upstream: `versioning::current_object_records`, multipart upload records, and the shared List
//! pagination contract. Downstream: production handlers registered by
//! [`super::FsBackend::register_listing`].

use std::cmp::Ordering;
use std::collections::BTreeSet;

use rustfs_gateway::dto::{
    CommonPrefix, ListMultipartUploads, ListMultipartUploadsOutput, ListObjects, ListObjectsOutput, ListObjectsV2,
    ListObjectsV2Output, MultipartUpload, Object, Owner,
};
use rustfs_gateway::{
    CursorSpec, ETag, ErrorCode, Handler, HandlerError, HandlerResult, ObjectKey, Req, Resp, Timestamp, key_count,
};
use sha2::{Digest as _, Sha256};

use super::uploads::UploadRecord;
use super::versioning::CurrentObjectRecord;
use super::{FsBackend, storage_error};

const CONTINUATION_CURSOR: CursorSpec = CursorSpec::opaque("continuation-token");

enum Candidate {
    Object(CurrentObjectRecord),
    CommonPrefix(String),
}

impl Candidate {
    fn name(&self) -> &str {
        match self {
            Self::Object(record) => &record.key,
            Self::CommonPrefix(prefix) => prefix,
        }
    }

    fn kind_tag(&self) -> &str {
        match self {
            Self::Object(_) => "object",
            Self::CommonPrefix(_) => "prefix",
        }
    }

    fn version_identity(&self) -> (&str, u64) {
        match self {
            Self::Object(record) => (&record.version_id, record.sequence),
            Self::CommonPrefix(_) => ("", 0),
        }
    }
}

fn candidate_order(left: &Candidate, right: &Candidate) -> Ordering {
    left.name()
        .as_bytes()
        .cmp(right.name().as_bytes())
        .then_with(|| left.kind_tag().cmp(right.kind_tag()))
}

pub(super) fn rolled_up_prefix(name: &str, prefix: &str, delimiter: Option<&str>) -> Option<String> {
    let delimiter = delimiter.filter(|value| !value.is_empty())?;
    let remainder = name.strip_prefix(prefix)?;
    let index = remainder.find(delimiter)?;
    Some(format!("{prefix}{}", &remainder[..index + delimiter.len()]))
}

fn build_candidates(records: Vec<CurrentObjectRecord>, prefix: &str, delimiter: Option<&str>) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut common_prefixes = BTreeSet::<String>::new();
    for record in records {
        if !record.key.starts_with(prefix) {
            continue;
        }
        if let Some(common_prefix) = rolled_up_prefix(&record.key, prefix, delimiter) {
            common_prefixes.insert(common_prefix);
            continue;
        }
        candidates.push(Candidate::Object(record));
    }
    candidates.extend(common_prefixes.into_iter().map(Candidate::CommonPrefix));
    candidates.sort_by(candidate_order);
    candidates
}

fn cursor_for(bucket: &str, prefix: &str, delimiter: Option<&str>, candidate: &Candidate) -> String {
    let (version_id, sequence) = candidate.version_identity();
    hex::encode(Sha256::digest(
        format!(
            "fs-list-v2\0{bucket}\0{prefix}\0{}\0{}\0{}\0{version_id}\0{sequence}",
            delimiter.unwrap_or_default(),
            candidate.kind_tag(),
            candidate.name()
        )
        .as_bytes(),
    ))
}

fn cursor_error() -> HandlerError {
    HandlerError::new(
        ErrorCode::INVALID_ARGUMENT,
        "the continuation token does not name a position in this listing",
    )
}

fn start_index(
    candidates: &[Candidate],
    bucket: &str,
    prefix: &str,
    delimiter: Option<&str>,
    continuation: Option<&str>,
    start_after: Option<&str>,
) -> Result<usize, HandlerError> {
    if let Some(raw) = continuation {
        let accepted = CONTINUATION_CURSOR.accept(raw).map_err(|_| cursor_error())?;
        return candidates
            .iter()
            .position(|candidate| cursor_for(bucket, prefix, delimiter, candidate) == accepted)
            .map(|index| index + 1)
            .ok_or_else(cursor_error);
    }
    let Some(start_after) = start_after else { return Ok(0) };
    Ok(candidates.partition_point(|candidate| candidate.name().as_bytes() <= start_after.as_bytes()))
}

fn marker_index(candidates: &[Candidate], marker: &str) -> usize {
    candidates.partition_point(|candidate| candidate.name().as_bytes() <= marker.as_bytes())
}

fn page_entries(page: &[Candidate], owner: Option<&Owner>) -> Result<(Vec<Object>, Vec<CommonPrefix>), HandlerError> {
    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    for candidate in page {
        match candidate {
            Candidate::Object(record) => contents.push(Object {
                key: ObjectKey::new(record.key.clone()).map_err(|_| storage_error())?,
                last_modified: Timestamp::from_secs(record.modified),
                e_tag: ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?,
                size: record.size,
                storage_class: record.storage_class.clone(),
                owner: owner.cloned(),
                ..Object::default()
            }),
            Candidate::CommonPrefix(prefix) => common_prefixes.push(CommonPrefix { prefix: prefix.clone() }),
        }
    }
    Ok((contents, common_prefixes))
}

fn page_size(value: i32, parameter: &str) -> Result<usize, HandlerError> {
    usize::try_from(value)
        .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, format!("{parameter} must be a non-negative integer")))
}

impl Handler<ListObjects> for FsBackend {
    async fn call(&self, request: Req<ListObjects>) -> HandlerResult<ListObjects> {
        let input = request.into_input();
        let bucket = input.bucket;
        let prefix = input.prefix.unwrap_or_default();
        let delimiter = input.delimiter;
        let marker = input.marker.unwrap_or_default();
        let max_keys_value = input.max_keys.unwrap_or(1000);
        let max_keys = page_size(max_keys_value, "max-keys")?;
        let records = self.current_object_records(bucket.as_str()).await?;
        let candidates = build_candidates(records, &prefix, delimiter.as_deref());
        let start = marker_index(&candidates, &marker);
        let available = candidates.len().saturating_sub(start);
        let page_len = available.min(max_keys);
        let is_truncated = max_keys > 0 && available > page_len;
        let page = &candidates[start..start + page_len];
        let next_marker = is_truncated
            .then(|| page.last().map(|candidate| candidate.name().to_owned()))
            .flatten();
        let (contents, common_prefixes) = page_entries(page, self.reported_owner())?;

        Ok(Resp::new(ListObjectsOutput {
            is_truncated,
            marker,
            next_marker,
            contents,
            name: bucket,
            prefix,
            delimiter,
            max_keys: max_keys_value,
            common_prefixes,
            encoding_type: input.encoding_type,
            ..ListObjectsOutput::default()
        }))
    }
}

impl Handler<ListObjectsV2> for FsBackend {
    async fn call(&self, request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        let input = request.into_input();
        let bucket = input.bucket;
        let prefix = input.prefix.unwrap_or_default();
        let delimiter = input.delimiter;
        let max_keys_value = input.max_keys.unwrap_or(1000);
        let max_keys = page_size(max_keys_value, "max-keys")?;
        let records = self.current_object_records(bucket.as_str()).await?;
        let candidates = build_candidates(records, &prefix, delimiter.as_deref());
        let continuation = input.continuation_token.as_ref().map(|token| token.as_str());
        let start = start_index(
            &candidates,
            bucket.as_str(),
            &prefix,
            delimiter.as_deref(),
            continuation,
            input.start_after.as_deref(),
        )?;
        let available = candidates.len().saturating_sub(start);
        let page_len = available.min(max_keys);
        let is_truncated = max_keys > 0 && available > page_len;
        let page = &candidates[start..start + page_len];
        let next_continuation_token = is_truncated
            .then(|| {
                page.last()
                    .map(|candidate| cursor_for(bucket.as_str(), &prefix, delimiter.as_deref(), candidate))
            })
            .flatten()
            .map(Into::into);

        let owner = if input.fetch_owner.unwrap_or(false) {
            self.reported_owner()
        } else {
            None
        };
        let (contents, common_prefixes) = page_entries(page, owner)?;
        let returned_count = key_count(contents.len(), common_prefixes.len());

        Ok(Resp::new(ListObjectsV2Output {
            is_truncated,
            contents,
            name: bucket,
            prefix,
            delimiter,
            max_keys: max_keys_value,
            common_prefixes,
            encoding_type: input.encoding_type,
            key_count: returned_count,
            continuation_token: input.continuation_token,
            next_continuation_token,
            start_after: input.start_after,
            ..ListObjectsV2Output::default()
        }))
    }
}

enum UploadCandidate {
    Upload(UploadRecord),
    CommonPrefix(String),
}

impl UploadCandidate {
    fn name(&self) -> &str {
        match self {
            Self::Upload(record) => &record.key,
            Self::CommonPrefix(prefix) => prefix,
        }
    }

    fn upload_id(&self) -> Option<&str> {
        match self {
            Self::Upload(record) => record.upload_id.as_deref(),
            Self::CommonPrefix(_) => None,
        }
    }
}

fn upload_candidate_order(left: &UploadCandidate, right: &UploadCandidate) -> Ordering {
    left.name().as_bytes().cmp(right.name().as_bytes()).then_with(|| {
        left.upload_id()
            .unwrap_or_default()
            .as_bytes()
            .cmp(right.upload_id().unwrap_or_default().as_bytes())
    })
}

fn build_upload_candidates(records: Vec<UploadRecord>, prefix: &str, delimiter: Option<&str>) -> Vec<UploadCandidate> {
    let mut candidates = Vec::new();
    let mut common_prefixes = BTreeSet::<String>::new();
    for record in records {
        if !record.key.starts_with(prefix) {
            continue;
        }
        if let Some(common_prefix) = rolled_up_prefix(&record.key, prefix, delimiter) {
            common_prefixes.insert(common_prefix);
            continue;
        }
        candidates.push(UploadCandidate::Upload(record));
    }
    candidates.extend(common_prefixes.into_iter().map(UploadCandidate::CommonPrefix));
    candidates.sort_by(upload_candidate_order);
    candidates
}

fn upload_marker_index(candidates: &[UploadCandidate], key_marker: &str, upload_id_marker: &str) -> Result<usize, HandlerError> {
    if key_marker.is_empty() && !upload_id_marker.is_empty() {
        return Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, "upload-id-marker requires key-marker"));
    }
    Ok(
        candidates.partition_point(|candidate| match candidate.name().as_bytes().cmp(key_marker.as_bytes()) {
            Ordering::Less => true,
            Ordering::Greater => false,
            Ordering::Equal if upload_id_marker.is_empty() => true,
            Ordering::Equal => candidate
                .upload_id()
                .is_none_or(|upload_id| upload_id.as_bytes() <= upload_id_marker.as_bytes()),
        }),
    )
}

fn upload_entries(page: &[UploadCandidate]) -> Result<(Vec<MultipartUpload>, Vec<CommonPrefix>), HandlerError> {
    let mut uploads = Vec::new();
    let mut common_prefixes = Vec::new();
    for candidate in page {
        match candidate {
            UploadCandidate::Upload(record) => uploads.push(MultipartUpload {
                upload_id: record.upload_id.clone(),
                key: Some(ObjectKey::new(record.key.clone()).map_err(|_| storage_error())?),
                initiated: record.initiated.map(Timestamp::from_secs),
                ..MultipartUpload::default()
            }),
            UploadCandidate::CommonPrefix(prefix) => common_prefixes.push(CommonPrefix { prefix: prefix.clone() }),
        }
    }
    Ok((uploads, common_prefixes))
}

impl Handler<ListMultipartUploads> for FsBackend {
    async fn call(&self, request: Req<ListMultipartUploads>) -> HandlerResult<ListMultipartUploads> {
        let input = request.into_input();
        let bucket = input.bucket;
        let prefix = input.prefix.unwrap_or_default();
        let delimiter = input.delimiter;
        let key_marker = input.key_marker.unwrap_or_default();
        let upload_id_marker = input.upload_id_marker.unwrap_or_default();
        let max_uploads_value = input.max_uploads.unwrap_or(1000);
        // AWS documents a 1..=1000 request range (https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html).
        if !(1..=1000).contains(&max_uploads_value) {
            return Err(HandlerError::new(ErrorCode::INVALID_ARGUMENT, "max-uploads must be between 1 and 1000"));
        }
        let max_uploads = page_size(max_uploads_value, "max-uploads")?;
        let records = self.active_upload_records(bucket.as_str()).await?;
        let candidates = build_upload_candidates(records, &prefix, delimiter.as_deref());
        let start = upload_marker_index(&candidates, &key_marker, &upload_id_marker)?;
        let available = candidates.len().saturating_sub(start);
        let page_len = available.min(max_uploads);
        let is_truncated = max_uploads > 0 && available > page_len;
        let page = &candidates[start..start + page_len];
        let (next_key_marker, next_upload_id_marker) = if is_truncated {
            page.last().map_or((None, None), |candidate| {
                (Some(candidate.name().to_owned()), candidate.upload_id().map(str::to_owned))
            })
        } else {
            (None, None)
        };
        let (uploads, common_prefixes) = upload_entries(page)?;

        Ok(Resp::new(ListMultipartUploadsOutput {
            bucket,
            key_marker: Some(key_marker),
            upload_id_marker: Some(upload_id_marker),
            next_key_marker,
            prefix: Some(prefix),
            delimiter,
            next_upload_id_marker,
            max_uploads: max_uploads_value,
            is_truncated,
            uploads,
            common_prefixes,
            encoding_type: input.encoding_type,
            ..ListMultipartUploadsOutput::default()
        }))
    }
}
