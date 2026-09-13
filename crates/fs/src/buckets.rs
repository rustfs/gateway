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

//! Bucket lifetime, and the one region this backend serves.
//!
//! Responsible for: creating and removing a bucket's storage directories, refusing a creation whose
//! `LocationConstraint` does not name the served region, and answering `HeadBucket` and
//! `GetBucketLocation` out of that same region.
//! NOT responsible for: the constraint's parsing rules — the `EU` alias, the empty-element spelling
//! and the us-east-1 omission are
//! [`rustfs_gateway::resolve_location_constraint`]'s — or the XML shape of the location answer,
//! which is the operation's IR and the codec's.
//! Upstream: the filesystem safety primitives. Downstream: the production bucket registrations.
//!
//! # One region, read in three places
//!
//! `HeadBucket`'s `x-amz-bucket-region`, `GetBucketLocation`'s body, and the constraint a
//! `CreateBucket` is allowed to name are three renderings of one fact. Before rustfs/gateway#627
//! the first was the literal `"us-east-1"` and the third was not checked at all, so a bucket could
//! be created for a region the deployment could neither sign for nor report. They now read
//! [`FsBackend::region`], and a region this backend cannot name is refused when the backend is
//! assembled rather than when a client asks.

use std::io;
use std::time::UNIX_EPOCH;

use rustfs_gateway::dto::{
    Bucket, CreateBucket, CreateBucketOutput, DeleteBucket, DeleteBucketOutput, GetBucketLocation, GetBucketLocationOutput,
    HeadBucket, HeadBucketOutput, ListBuckets, ListBucketsOutput, LocationConstraint,
};
use rustfs_gateway::{
    BucketName, CursorSpec, ErrorCode, Handler, HandlerError, HandlerResult, REGION_MATCH_POLICY, Req, Resp, Timestamp,
    US_EAST_1, resolve_location_constraint,
};
use sha2::{Digest as _, Sha256};

use super::{FsBackend, OBJECTS_DIR, UPLOADS_DIR, VERSIONS_DIR, lifecycle, storage_error, versioning};

/// The cursor `ListBuckets` pages with: a value this backend minted, never a bucket name.
const BUCKET_CURSOR: CursorSpec = CursorSpec::opaque("continuation-token");

/// The largest page `max-buckets` may ask for.
const MAX_BUCKETS_PER_PAGE: i32 = 10_000;

fn bucket_cursor(prefix: &str, bucket: &str) -> String {
    hex::encode(Sha256::digest(format!("fs-list-buckets\0{prefix}\0{bucket}").as_bytes()))
}

fn bucket_cursor_error() -> HandlerError {
    HandlerError::new(
        ErrorCode::INVALID_ARGUMENT,
        "the continuation token does not name a position in this bucket listing",
    )
}

impl FsBackend {
    /// When the bucket's directory came into being, which is when `CreateBucket` made it.
    ///
    /// The filesystem's birth time is used where the platform keeps one, and the modification time
    /// otherwise; the directory's own entries are created with it, so the two agree for a bucket
    /// this backend made.
    async fn bucket_creation_date(&self, bucket: &str) -> Result<Timestamp, HandlerError> {
        let metadata = tokio::fs::symlink_metadata(self.bucket_path(bucket))
            .await
            .map_err(|_| storage_error())?;
        let created = metadata
            .created()
            .or_else(|_| metadata.modified())
            .map_err(|_| storage_error())?;
        let seconds = created
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or_default();
        Ok(Timestamp::from_secs(seconds))
    }
}

impl Handler<ListBuckets> for FsBackend {
    /// Every bucket under the data root, in byte order, filtered and paged as the request asks.
    ///
    /// The data root is single-tenant, so every bucket in it is the configured owner's. A
    /// `bucket-region` filter naming any region but the one this backend serves matches nothing.
    async fn call(&self, request: Req<ListBuckets>) -> HandlerResult<ListBuckets> {
        let input = request.into_input();
        let prefix = input.prefix.clone().unwrap_or_default();
        let page_size = match input.max_buckets {
            None => usize::MAX,
            Some(requested) if (1..=MAX_BUCKETS_PER_PAGE).contains(&requested) => {
                usize::try_from(requested).map_err(|_| storage_error())?
            }
            Some(_) => {
                return Err(HandlerError::new(
                    ErrorCode::INVALID_ARGUMENT,
                    "max-buckets must be an integer between 1 and 10000",
                ));
            }
        };
        let in_region = input.bucket_region.as_deref().is_none_or(|region| region == self.region());
        let mut names = if in_region {
            self.lifecycle_buckets().await?
        } else {
            Vec::new()
        };
        names.retain(|name| name.starts_with(prefix.as_str()));
        let start = match input.continuation_token.as_ref() {
            None => 0,
            Some(token) => {
                let accepted = BUCKET_CURSOR.accept(token.as_str()).map_err(|_| bucket_cursor_error())?;
                names
                    .iter()
                    .position(|name| bucket_cursor(&prefix, name) == accepted)
                    .map(|index| index + 1)
                    .ok_or_else(bucket_cursor_error)?
            }
        };
        let available = names.len().saturating_sub(start);
        let page_len = available.min(page_size);
        let page = &names[start..start + page_len];
        let continuation_token = (available > page_len)
            .then(|| page.last().map(|name| bucket_cursor(&prefix, name)))
            .flatten()
            .map(Into::into);
        let mut buckets = Vec::with_capacity(page.len());
        for name in page {
            buckets.push(Bucket {
                name: BucketName::new(name.clone()).map_err(|_| storage_error())?,
                creation_date: self.bucket_creation_date(name).await?,
                ..Bucket::default()
            });
        }
        Ok(Resp::new(ListBucketsOutput {
            buckets,
            // The model makes the listing's owner element mandatory, so an unconfigured owner is
            // answered as an owner with no id rather than an omitted element.
            owner: self.reported_owner().cloned().unwrap_or_default(),
            continuation_token,
            prefix: input.prefix,
        }))
    }
}

impl Handler<CreateBucket> for FsBackend {
    async fn call(&self, request: Req<CreateBucket>) -> HandlerResult<CreateBucket> {
        let input = request.input();
        // Judged before anything is written. A refused constraint that has already created
        // directories leaves a bucket the caller was told does not exist.
        resolve_location_constraint(
            input
                .create_bucket_configuration
                .as_ref()
                .and_then(|configuration| configuration.location_constraint.as_ref())
                .map(LocationConstraint::as_str),
            &self.regions,
            REGION_MATCH_POLICY,
        )?;
        let bucket = input.bucket.as_str();
        let path = self.bucket_path(bucket);
        match tokio::fs::create_dir(&path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                self.require_bucket(bucket).await?;
                return Ok(Resp::new(CreateBucketOutput {
                    location: Some(format!("/{bucket}")),
                }));
            }
            Err(_) => return Err(storage_error()),
        }
        if tokio::fs::create_dir(path.join(OBJECTS_DIR)).await.is_err() {
            let _ = tokio::fs::remove_dir(&path).await;
            return Err(storage_error());
        }
        if tokio::fs::create_dir(path.join(UPLOADS_DIR)).await.is_err() {
            let _ = tokio::fs::remove_dir(path.join(OBJECTS_DIR)).await;
            let _ = tokio::fs::remove_dir(&path).await;
            return Err(storage_error());
        }
        if tokio::fs::create_dir(path.join(VERSIONS_DIR)).await.is_err() {
            let _ = tokio::fs::remove_dir(path.join(UPLOADS_DIR)).await;
            let _ = tokio::fs::remove_dir(path.join(OBJECTS_DIR)).await;
            let _ = tokio::fs::remove_dir(&path).await;
            return Err(storage_error());
        }
        Ok(Resp::new(CreateBucketOutput {
            location: Some(format!("/{bucket}")),
        }))
    }
}

impl Handler<HeadBucket> for FsBackend {
    async fn call(&self, request: Req<HeadBucket>) -> HandlerResult<HeadBucket> {
        self.require_bucket(request.input().bucket.as_str()).await?;
        Ok(Resp::new(HeadBucketOutput {
            bucket_region: self.region().to_owned(),
        }))
    }
}

impl Handler<GetBucketLocation> for FsBackend {
    /// The bucket's region, with the us-east-1 answer being no constraint at all.
    ///
    /// `us-east-1` is excluded by name and not by comparison with anything else: AWS's null
    /// constraint is a fact about that one region, not about wherever a deployment happens to
    /// live. The `None` becomes `<LocationConstraint></LocationConstraint>` and not an omitted
    /// element, because `GetBucketLocation.xml.empty_value.LocationConstraint` is `emit`
    /// (`q-empty-0002`) — the emitting is the codec's, the choice of value is this handler's.
    ///
    /// The bucket is resolved first. The empty element is a *successful* answer, so serving it for
    /// a bucket that is not there would tell a client the bucket exists and is in us-east-1.
    async fn call(&self, request: Req<GetBucketLocation>) -> HandlerResult<GetBucketLocation> {
        self.require_bucket(request.input().bucket.as_str()).await?;
        let region = self.region();
        let location_constraint = if region == US_EAST_1 {
            None
        } else {
            Some(
                LocationConstraint::VALUES
                    .iter()
                    .find(|known| **known == region)
                    .copied()
                    .map(LocationConstraint::from)
                    // Unreachable through `FsBackend::with_region`, which refuses a region the
                    // enumeration cannot name. Reported rather than defaulted, because the default
                    // would be "this bucket is in us-east-1" — a wrong answer wearing a valid shape.
                    .ok_or_else(storage_error)?,
            )
        };
        Ok(Resp::new(GetBucketLocationOutput { location_constraint }))
    }
}

impl Handler<DeleteBucket> for FsBackend {
    async fn call(&self, request: Req<DeleteBucket>) -> HandlerResult<DeleteBucket> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        let objects = self.objects_path(bucket);
        let uploads = self.uploads_path(bucket);
        let versions = self.versions_path(bucket);
        if !self.directory_is_empty(&objects).await?
            || !self.upload_directory_is_empty_for_delete(bucket)?
            || !self.directory_is_empty(&versions).await?
        {
            return Err(HandlerError::new(
                ErrorCode::BUCKET_NOT_EMPTY,
                "The bucket you tried to delete is not empty",
            ));
        }
        tokio::fs::remove_dir(&objects).await.map_err(|_| storage_error())?;
        self.remove_upload_id_authority_for_delete(bucket)?;
        tokio::fs::remove_dir(&uploads).await.map_err(|_| storage_error())?;
        tokio::fs::remove_dir(&versions).await.map_err(|_| storage_error())?;
        match tokio::fs::remove_file(self.bucket_path(bucket).join(versioning::STATUS_FILE)).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        match tokio::fs::remove_file(self.bucket_path(bucket).join(versioning::SEQUENCE_FILE)).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        match tokio::fs::remove_file(self.bucket_path(bucket).join(lifecycle::RECORD_FILE)).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        tokio::fs::remove_dir(self.bucket_path(bucket))
            .await
            .map_err(|_| storage_error())?;
        Ok(Resp::new(DeleteBucketOutput::default()))
    }
}
