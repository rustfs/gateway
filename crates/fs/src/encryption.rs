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

//! The default-encryption family, stored and answered as RustFS stores and answers it.
//!
//! Responsible for: `PutBucketEncryption`, `GetBucketEncryption` and `DeleteBucketEncryption` on
//! the reference backend, [`FsBackend::bucket_encryption`], and the encryption an object write
//! records and every later read reports: the request's managed algorithm, else the bucket
//! default, refused where RustFS refuses it; and the refusal of a read that names one.
//! NOT responsible for: the document's shared rules (`validate_encryption`), its persisted grammar
//! (`rustfs_gateway::persistence`), or encrypting anything.
//! Upstream: the shared encryption contract and the persistence codec. Downstream: the production
//! routes.
//!
//! # Configuration only, by decision (rustfs/gateway#812)
//!
//! This backend stores the configuration and reports it; it never encrypts a byte. A reference
//! backend exists so that `compat-sut` measures the protocol surface RustFS offers, and RustFS
//! offers this family, so answering `501` would hide every suite case that sets a default. Real
//! encryption would add key management to a test backend and measure nothing about the wire.
//!
//! # RustFS's answers, which are the ones given here (`bucket_usecase.rs` upstream)
//!
//! - A bucket without a configuration is `404 ServerSideEncryptionConfigurationNotFoundError`;
//!   deletion is `204` whether or not one was there; a later write replaces the stored document.
//! - After the shared contract, RustFS refuses what its write path could not honour, each
//!   `MalformedXML`: a document with no rule, a rule with no `ApplyServerSideEncryptionByDefault`,
//!   and an algorithm other than `AES256` or `aws:kms` (`validate_bucket_encryption_configuration`).
//! - An `aws:kms` default without a key id is filled with the KMS's default key; with no KMS
//!   configured RustFS answers `500 InternalError`. This backend has no KMS, so it answers that.
//!
//! # Objects (`sse.rs` upstream)
//!
//! - A write stores the algorithm the request named, and the KMS key id beside `aws:kms`; a write
//!   naming none takes the bucket default's first rule. A copy takes its own request's, never the
//!   source's; a multipart upload takes it at initiation. The write and every `GET`/`HEAD` report
//!   it.
//! - An algorithm other than `AES256`/`aws:kms` is `400 InvalidArgument`
//!   (`validate_sse_headers_for_write`), and `aws:kms` with no key id to use is the same
//!   no-KMS `500` as above. The framework has already refused a key id with no algorithm.
//! - A `GET` or `HEAD` naming a managed algorithm is `400 InvalidArgument`
//!   (`validate_sse_headers_for_read`).

use rustfs_gateway::dto::{
    DeleteBucketEncryption, DeleteBucketEncryptionOutput, GetBucketEncryption, GetBucketEncryptionOutput, PutBucketEncryption,
    PutBucketEncryptionOutput, ServerSideEncryption, ServerSideEncryptionConfiguration,
};
use rustfs_gateway::persistence::{parse_bucket_encryption_dto, serialize_bucket_encryption_dto};
use rustfs_gateway::{ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, validate_encryption};

use super::{FsBackend, storage_error};

pub(super) const ENCRYPTION_FILE: &str = "encryption";

/// The two algorithms RustFS's write path applies; every other documented one is refused.
const RUSTFS_ALGORITHMS: [&str; 2] = ["AES256", "aws:kms"];

fn not_found() -> HandlerError {
    HandlerError::new(
        ErrorCode::SERVER_SIDE_ENCRYPTION_CONFIGURATION_NOT_FOUND,
        "The server side encryption configuration was not found",
    )
}

fn no_kms() -> HandlerError {
    HandlerError::new(ErrorCode::INTERNAL_ERROR, "KMS default key not configured")
}

fn malformed(reason: &'static str) -> HandlerError {
    HandlerError::new(ErrorCode::MALFORMED_XML, reason)
}

/// RustFS's rules beyond the shared contract, first refusal wins.
fn refuse_what_rustfs_cannot_honour(configuration: &ServerSideEncryptionConfiguration) -> Result<(), HandlerError> {
    if configuration.rules.is_empty() {
        return Err(malformed("ServerSideEncryptionConfiguration must contain at least one Rule"));
    }
    for rule in &configuration.rules {
        let Some(by_default) = &rule.apply_server_side_encryption_by_default else {
            return Err(malformed("Rule must contain ApplyServerSideEncryptionByDefault"));
        };
        let algorithm = by_default.sse_algorithm.as_str();
        if !RUSTFS_ALGORITHMS.contains(&algorithm) {
            return Err(malformed("SSEAlgorithm is not supported; expected AES256 or aws:kms"));
        }
        if algorithm == "aws:kms" && by_default.kms_master_key_id.as_deref().is_none_or(str::is_empty) {
            return Err(no_kms());
        }
    }
    Ok(())
}

impl FsBackend {
    /// The bucket's stored default-encryption configuration, `None` when it has none.
    ///
    /// # Errors
    ///
    /// `NoSuchBucket` for a bucket that does not exist, a storage error for an unreadable record:
    /// a corrupt document is never read as "no default".
    pub async fn bucket_encryption(&self, bucket: &str) -> Result<Option<ServerSideEncryptionConfiguration>, HandlerError> {
        self.require_bucket(bucket).await?;
        match self
            .read_bucket_record(&self.bucket_path(bucket).join(ENCRYPTION_FILE))
            .await?
        {
            Some(bytes) => Ok(Some(parse_bucket_encryption_dto(&bytes).map_err(|_| storage_error())?)),
            None => Ok(None),
        }
    }
}

/// The server-managed encryption one object version is written under, as stored and reported.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct ObjectEncryption {
    pub(super) algorithm: Option<String>,
    pub(super) kms_key_id: Option<String>,
}

impl ObjectEncryption {
    /// The algorithm as the response member spells it.
    pub(super) fn reported_algorithm(&self) -> Option<ServerSideEncryption> {
        self.algorithm.clone().map(ServerSideEncryption::custom)
    }
}

/// Refuses a read that names a managed algorithm: RustFS answers every such read `400`.
pub(super) fn refuse_read_encryption(sse: &rustfs_gateway::SseEnforced) -> Result<(), HandlerError> {
    if sse.managed_algorithm().is_some() {
        return Err(HandlerError::new(
            ErrorCode::INVALID_ARGUMENT,
            "Server-side encryption headers are not accepted on a read of an object encrypted with managed keys",
        ));
    }
    Ok(())
}

impl FsBackend {
    /// The encryption an object write records: the request's managed algorithm and key id, or the
    /// bucket default's first rule when the request named none.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for an algorithm RustFS's write path cannot apply, the no-KMS
    /// `InternalError` for `aws:kms` with no key id, and the bucket's own read errors.
    pub(super) async fn write_encryption(
        &self,
        bucket: &str,
        requested: Option<&str>,
        requested_key_id: Option<&str>,
    ) -> Result<ObjectEncryption, HandlerError> {
        let (algorithm, key_id) = match requested {
            Some(algorithm) => (Some(algorithm.to_owned()), requested_key_id.map(ToOwned::to_owned)),
            None => match self.bucket_encryption(bucket).await? {
                Some(configuration) => configuration
                    .rules
                    .first()
                    .and_then(|rule| rule.apply_server_side_encryption_by_default.as_ref())
                    .map_or((None, None), |by_default| {
                        (Some(by_default.sse_algorithm.as_str().to_owned()), by_default.kms_master_key_id.clone())
                    }),
                None => (None, None),
            },
        };
        match algorithm.as_deref() {
            None => Ok(ObjectEncryption::default()),
            Some("AES256") => Ok(ObjectEncryption {
                algorithm,
                kms_key_id: None,
            }),
            Some("aws:kms") if key_id.as_deref().is_some_and(|id| !id.is_empty()) => Ok(ObjectEncryption {
                algorithm,
                kms_key_id: key_id,
            }),
            Some("aws:kms") => Err(no_kms()),
            Some(_) => Err(HandlerError::new(
                ErrorCode::INVALID_ARGUMENT,
                "The SSE algorithm specified is not supported. The valid values are AES256 or aws:kms.",
            )),
        }
    }
}

impl Handler<PutBucketEncryption> for FsBackend {
    async fn call(&self, request: Req<PutBucketEncryption>) -> HandlerResult<PutBucketEncryption> {
        let input = request.input();
        let bucket = input.bucket.as_str();
        self.require_bucket(bucket).await?;
        let configuration = &input.server_side_encryption_configuration;
        validate_encryption(configuration)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason().to_owned()))?;
        refuse_what_rustfs_cannot_honour(configuration)?;
        let bytes = serialize_bucket_encryption_dto(configuration).map_err(|_| storage_error())?;
        self.write_bucket_record(bucket, ENCRYPTION_FILE, &bytes).await?;
        Ok(Resp::new(PutBucketEncryptionOutput::default()))
    }
}

impl Handler<GetBucketEncryption> for FsBackend {
    async fn call(&self, request: Req<GetBucketEncryption>) -> HandlerResult<GetBucketEncryption> {
        let stored = self
            .bucket_encryption(request.input().bucket.as_str())
            .await?
            .ok_or_else(not_found)?;
        Ok(Resp::new(GetBucketEncryptionOutput {
            server_side_encryption_configuration: Some(stored),
        }))
    }
}

impl Handler<DeleteBucketEncryption> for FsBackend {
    async fn call(&self, request: Req<DeleteBucketEncryption>) -> HandlerResult<DeleteBucketEncryption> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        self.delete_bucket_record(bucket, ENCRYPTION_FILE).await?;
        Ok(Resp::new(DeleteBucketEncryptionOutput::default()))
    }
}
