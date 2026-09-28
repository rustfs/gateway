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

//! Bucket tagging on the reference backend (rustfs/gateway#1004).
//!
//! Responsible for: `PutBucketTagging`, `GetBucketTagging` and `DeleteBucketTagging`, answered as
//! RustFS answers them: the set stored and read back, `404 NoSuchTagSet` when there is none, and
//! an idempotent `204` delete.
//! NOT responsible for: the tag rules (the shared `validate_tag_set` under the bucket scope), their
//! persisted grammar (`rustfs_gateway::persistence`), or object tags (`super::tagging`).
//! Upstream: the shared tagging contract. Downstream: the tagging registry.

use rustfs_gateway::dto::{
    DeleteBucketTagging, DeleteBucketTaggingOutput, GetBucketTagging, GetBucketTaggingOutput, PutBucketTagging,
    PutBucketTaggingOutput,
};
use rustfs_gateway::persistence::{parse_tagging_dto, serialize_tagging_dto};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, TagScope, validate_tag_set};

use super::{FsBackend, storage_error};

pub(super) const BUCKET_TAGGING_FILE: &str = "bucket-tagging";

impl Handler<PutBucketTagging> for FsBackend {
    async fn call(&self, request: Req<PutBucketTagging>) -> HandlerResult<PutBucketTagging> {
        let input = request.input();
        let bucket = input.bucket.as_str();
        self.require_bucket(bucket).await?;
        let pairs = input
            .tagging
            .tag_set
            .iter()
            .map(|tag| (tag.key.clone(), tag.value.clone()))
            .collect::<Vec<_>>();
        validate_tag_set(&pairs, TagScope::Bucket)
            .map_err(|rejection| HandlerError::new(rejection.code().clone(), rejection.reason()))?;
        self.write_bucket_record(bucket, BUCKET_TAGGING_FILE, serialize_tagging_dto(&input.tagging).as_ref())
            .await?;
        Ok(Resp::new(PutBucketTaggingOutput::default()))
    }
}

impl Handler<GetBucketTagging> for FsBackend {
    async fn call(&self, request: Req<GetBucketTagging>) -> HandlerResult<GetBucketTagging> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        let bytes = self
            .read_bucket_record(&self.bucket_path(bucket).join(BUCKET_TAGGING_FILE))
            .await?
            .ok_or_else(|| HandlerError::new(ErrorCode::NO_SUCH_TAG_SET, "The TagSet does not exist"))?;
        let tagging = parse_tagging_dto(&bytes).map_err(|_| storage_error())?;
        Ok(Resp::new(GetBucketTaggingOutput {
            tag_set: tagging.tag_set,
        }))
    }
}

impl Handler<DeleteBucketTagging> for FsBackend {
    async fn call(&self, request: Req<DeleteBucketTagging>) -> HandlerResult<DeleteBucketTagging> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        self.delete_bucket_record(bucket, BUCKET_TAGGING_FILE).await?;
        Ok(Resp::new(DeleteBucketTaggingOutput::default()))
    }
}
