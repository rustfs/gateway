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
//! Responsible for: ListObjectsV2 filtering, delimiter rollup, page sizing, and opaque cursor
//! minting/resumption over the version store's one current-object snapshot.
//! NOT responsible for: version selection, ListObjects V1, upload listing, or lifecycle.
//! Upstream: `versioning::current_object_records` and the shared pagination contract. Downstream:
//! the production ListObjectsV2 handler registered by [`super::FsBackend::register_listing`].

use std::cmp::Ordering;
use std::collections::BTreeSet;

use rustfs_gateway::dto::{CommonPrefix, ListObjectsV2, ListObjectsV2Output, Object, StorageClass};
use rustfs_gateway::{
    CursorSpec, ETag, ErrorCode, Handler, HandlerError, HandlerResult, ObjectKey, Req, Resp, Timestamp, key_count,
};
use sha2::{Digest as _, Sha256};

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

fn build_candidates(records: Vec<CurrentObjectRecord>, prefix: &str, delimiter: Option<&str>) -> Vec<Candidate> {
    let delimiter = delimiter.filter(|value| !value.is_empty());
    let mut candidates = Vec::new();
    let mut common_prefixes = BTreeSet::<String>::new();
    for record in records {
        let Some(remainder) = record.key.strip_prefix(prefix) else {
            continue;
        };
        if let Some(delimiter) = delimiter
            && let Some(index) = remainder.find(delimiter)
        {
            let end = index + delimiter.len();
            common_prefixes.insert(format!("{prefix}{}", &remainder[..end]));
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

impl Handler<ListObjectsV2> for FsBackend {
    async fn call(&self, request: Req<ListObjectsV2>) -> HandlerResult<ListObjectsV2> {
        let input = request.into_input();
        let bucket = input.bucket;
        let prefix = input.prefix.unwrap_or_default();
        let delimiter = input.delimiter;
        let max_keys_value = input.max_keys.unwrap_or(1000);
        let max_keys = usize::try_from(max_keys_value)
            .map_err(|_| HandlerError::new(ErrorCode::INVALID_ARGUMENT, "max-keys must be a non-negative integer"))?;
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

        let mut contents = Vec::new();
        let mut common_prefixes = Vec::new();
        for candidate in page {
            match candidate {
                Candidate::Object(record) => contents.push(Object {
                    key: ObjectKey::new(record.key.clone()).map_err(|_| storage_error())?,
                    last_modified: Timestamp::from_secs(record.modified),
                    e_tag: ETag::new(record.e_tag.clone()).map_err(|_| storage_error())?,
                    size: record.size,
                    storage_class: StorageClass::STANDARD,
                    ..Object::default()
                }),
                Candidate::CommonPrefix(prefix) => common_prefixes.push(CommonPrefix { prefix: prefix.clone() }),
            }
        }
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
