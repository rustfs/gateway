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

//! The bucket-policy family, stored and answered as RustFS stores and answers it.
//!
//! Responsible for: `PutBucketPolicy`, `GetBucketPolicy`, `DeleteBucketPolicy`,
//! `GetBucketPolicyStatus`, `PutPublicAccessBlock`, `GetPublicAccessBlock` and
//! `DeletePublicAccessBlock` on the reference backend, and the [`FsBackend::bucket_policy`] read
//! the launcher's authorizer evaluates a request against.
//! NOT responsible for: the document's syntax rules (the shared `validate_policy`), the statement
//! rules and the evaluation ([`evaluate`]), or deciding a request (`compat-sut`).
//! Upstream: the shared bucket-policy contract, [`evaluate`]. Downstream: the production routes
//! and `compat-sut::ownership::decide`.
//!
//! # RustFS's answers, which are the ones given here
//!
//! - The policy is stored as the bytes written and read back verbatim; a bucket without one is
//!   `404 NoSuchBucketPolicy`, and its deletion is `204` whether or not one was there.
//! - A write is `MalformedPolicy` when the shared syntax contract or RustFS's statement rules
//!   refuse it, and `AccessDenied` when it grants everyone something while the stored public-access
//!   block says `BlockPublicPolicy` (`execute_put_bucket_policy` upstream).
//! - `GetBucketPolicyStatus` is `IsPublic` = an anonymous `s3:ListBucket` or `s3:PutObject` on the
//!   bucket is allowed — computed from the stored policy, `false` for a bucket without one, never
//!   a `404` (`execute_get_bucket_policy_status`). AWS answers `NoSuchBucketPolicy` there; the
//!   conformance fixture pins AWS, this backend pins RustFS, and the difference is the launcher's
//!   to report.
//! - The public-access block is stored as the four switches and read back with every switch
//!   present; a bucket without one is `404 NoSuchPublicAccessBlockConfiguration`.
//!
//! `GetBucketOwnershipControls` stays unregistered: RustFS has no handler for it.

pub mod evaluate;

use std::io;

use rustfs_gateway::dto::{
    DeleteBucketPolicy, DeleteBucketPolicyOutput, DeletePublicAccessBlock, DeletePublicAccessBlockOutput, GetBucketPolicy,
    GetBucketPolicyOutput, GetBucketPolicyStatus, GetBucketPolicyStatusOutput, GetPublicAccessBlock, GetPublicAccessBlockOutput,
    PolicyStatus, PublicAccessBlockConfiguration, PutBucketPolicy, PutBucketPolicyOutput, PutPublicAccessBlock,
    PutPublicAccessBlockOutput,
};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, validate_policy, validate_public_access_block};

use self::evaluate::{BucketPolicy, PolicyRequest};
use super::{FsBackend, storage_error};

pub(super) const POLICY_FILE: &str = "policy";
pub(super) const PUBLIC_ACCESS_BLOCK_FILE: &str = "public-access-block";

/// The four switches as one line each, in a fixed order, so the record is its own schema.
const SWITCHES: [&str; 4] = [
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
];

fn no_such_bucket_policy() -> HandlerError {
    HandlerError::new(ErrorCode::NO_SUCH_BUCKET_POLICY, "The bucket policy does not exist")
}

fn no_such_public_access_block() -> HandlerError {
    HandlerError::new(
        ErrorCode::NO_SUCH_PUBLIC_ACCESS_BLOCK_CONFIGURATION,
        "The public access block configuration was not found",
    )
}

fn unsafe_record() -> HandlerError {
    HandlerError::new(ErrorCode::INVALID_REQUEST, "the policy storage path is not a safe regular file")
}

impl FsBackend {
    /// The stored policy document, verbatim, when the bucket has one.
    ///
    /// Exposed for the launcher's authorizer, which evaluates a request against it before the
    /// request reaches any handler; an unreadable record is an error and not an absent policy, so
    /// a corrupt file fails closed rather than opening the bucket.
    ///
    /// # Errors
    ///
    /// `NoSuchBucket` for a bucket that does not exist, a storage error for an unreadable record.
    pub async fn bucket_policy(&self, bucket: &str) -> Result<Option<String>, HandlerError> {
        self.require_bucket(bucket).await?;
        match self.read_bucket_record(&self.bucket_path(bucket).join(POLICY_FILE)).await? {
            Some(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|_| storage_error())?)),
            None => Ok(None),
        }
    }

    /// The stored policy, parsed; `None` when the bucket has none.
    async fn parsed_policy(&self, bucket: &str) -> Result<Option<BucketPolicy>, HandlerError> {
        match self.bucket_policy(bucket).await? {
            Some(document) => Ok(Some(BucketPolicy::parse(&document).map_err(|_| storage_error())?)),
            None => Ok(None),
        }
    }

    async fn public_access_block(&self, bucket: &str) -> Result<Option<PublicAccessBlockConfiguration>, HandlerError> {
        self.require_bucket(bucket).await?;
        let Some(bytes) = self
            .read_bucket_record(&self.bucket_path(bucket).join(PUBLIC_ACCESS_BLOCK_FILE))
            .await?
        else {
            return Ok(None);
        };
        let text = String::from_utf8(bytes).map_err(|_| storage_error())?;
        let mut switches = [false; 4];
        for line in text.lines() {
            let (name, value) = line.split_once('=').ok_or_else(storage_error)?;
            let index = SWITCHES.iter().position(|switch| *switch == name).ok_or_else(storage_error)?;
            switches[index] = match value {
                "true" => true,
                "false" => false,
                _ => return Err(storage_error()),
            };
        }
        Ok(Some(PublicAccessBlockConfiguration {
            block_public_acls: Some(switches[0]),
            ignore_public_acls: Some(switches[1]),
            block_public_policy: Some(switches[2]),
            restrict_public_buckets: Some(switches[3]),
        }))
    }

    /// A bucket-level record's bytes, `None` when the file is absent; a symlink or a non-file is
    /// refused rather than read, as every record path in this backend is.
    async fn read_bucket_record(&self, path: &std::path::Path) -> Result<Option<Vec<u8>>, HandlerError> {
        match tokio::fs::symlink_metadata(path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(storage_error()),
        }
        tokio::fs::read(path).await.map(Some).map_err(|_| storage_error())
    }

    async fn write_bucket_record(&self, bucket: &str, file: &str, bytes: &[u8]) -> Result<(), HandlerError> {
        let destination = self.bucket_path(bucket).join(file);
        match tokio::fs::symlink_metadata(&destination).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(storage_error()),
        }
        self.write_atomic(&self.bucket_path(bucket), &destination, bytes).await
    }

    async fn delete_bucket_record(&self, bucket: &str, file: &str) -> Result<(), HandlerError> {
        let path = self.bucket_path(bucket).join(file);
        match tokio::fs::symlink_metadata(&path).await {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                tokio::fs::remove_file(path).await.map_err(|_| storage_error())
            }
            Ok(_) => Err(unsafe_record()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(storage_error()),
        }
    }
}

impl Handler<PutBucketPolicy> for FsBackend {
    async fn call(&self, request: Req<PutBucketPolicy>) -> HandlerResult<PutBucketPolicy> {
        let input = request.input();
        let bucket = input.bucket.as_str();
        self.require_bucket(bucket).await?;
        // The shared contract first — size, JSON, depth, an object — then RustFS's statement rules;
        // both are MalformedPolicy on the wire, as RustFS answers every is_valid failure.
        validate_policy(&input.policy).map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let policy = BucketPolicy::parse(&input.policy)
            .map_err(|shape| HandlerError::new(ErrorCode::MALFORMED_POLICY, shape.to_string()))?;
        if policy.grants_everyone()
            && self
                .public_access_block(bucket)
                .await?
                .is_some_and(|block| block.block_public_policy == Some(true))
        {
            return Err(HandlerError::new(ErrorCode::ACCESS_DENIED, "Access Denied"));
        }
        self.write_bucket_record(bucket, POLICY_FILE, input.policy.as_bytes()).await?;
        Ok(Resp::new(PutBucketPolicyOutput::default()))
    }
}

impl Handler<GetBucketPolicy> for FsBackend {
    async fn call(&self, request: Req<GetBucketPolicy>) -> HandlerResult<GetBucketPolicy> {
        let policy = self
            .bucket_policy(request.input().bucket.as_str())
            .await?
            .ok_or_else(no_such_bucket_policy)?;
        Ok(Resp::new(GetBucketPolicyOutput { policy: Some(policy) }))
    }
}

impl Handler<DeleteBucketPolicy> for FsBackend {
    async fn call(&self, request: Req<DeleteBucketPolicy>) -> HandlerResult<DeleteBucketPolicy> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        self.delete_bucket_record(bucket, POLICY_FILE).await?;
        Ok(Resp::new(DeleteBucketPolicyOutput::default()))
    }
}

impl Handler<GetBucketPolicyStatus> for FsBackend {
    /// `IsPublic` as RustFS computes it: whether an anonymous caller may list the bucket or write
    /// an object to it under the stored policy; a bucket with no policy is not public.
    async fn call(&self, request: Req<GetBucketPolicyStatus>) -> HandlerResult<GetBucketPolicyStatus> {
        let bucket = request.input().bucket.as_str();
        let is_public = match self.parsed_policy(bucket).await? {
            None => false,
            Some(policy) => ["s3:ListBucket", "s3:PutObject"].iter().any(|action| {
                policy.allows(PolicyRequest {
                    account: None,
                    is_owner: false,
                    action,
                    bucket,
                    key: None,
                })
            }),
        };
        Ok(Resp::new(GetBucketPolicyStatusOutput {
            policy_status: Some(PolicyStatus {
                is_public: Some(is_public),
            }),
        }))
    }
}

impl Handler<PutPublicAccessBlock> for FsBackend {
    async fn call(&self, request: Req<PutPublicAccessBlock>) -> HandlerResult<PutPublicAccessBlock> {
        let input = request.input();
        let bucket = input.bucket.as_str();
        self.require_bucket(bucket).await?;
        let configuration = &input.public_access_block_configuration;
        validate_public_access_block(configuration)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason()))?;
        let values = [
            configuration.block_public_acls,
            configuration.ignore_public_acls,
            configuration.block_public_policy,
            configuration.restrict_public_buckets,
        ];
        let record = SWITCHES
            .iter()
            .zip(values)
            .map(|(name, value)| format!("{name}={}\n", value.unwrap_or(false)))
            .collect::<String>();
        self.write_bucket_record(bucket, PUBLIC_ACCESS_BLOCK_FILE, record.as_bytes())
            .await?;
        Ok(Resp::new(PutPublicAccessBlockOutput::default()))
    }
}

impl Handler<GetPublicAccessBlock> for FsBackend {
    async fn call(&self, request: Req<GetPublicAccessBlock>) -> HandlerResult<GetPublicAccessBlock> {
        let stored = self
            .public_access_block(request.input().bucket.as_str())
            .await?
            .ok_or_else(no_such_public_access_block)?;
        Ok(Resp::new(GetPublicAccessBlockOutput {
            public_access_block_configuration: Some(stored),
        }))
    }
}

impl Handler<DeletePublicAccessBlock> for FsBackend {
    async fn call(&self, request: Req<DeletePublicAccessBlock>) -> HandlerResult<DeletePublicAccessBlock> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        self.delete_bucket_record(bucket, PUBLIC_ACCESS_BLOCK_FILE).await?;
        Ok(Resp::new(DeletePublicAccessBlockOutput::default()))
    }
}
