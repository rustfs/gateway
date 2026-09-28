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

//! Bucket CORS configuration on the reference backend (rustfs/gateway#1004).
//!
//! Responsible for: `PutBucketCors`, `GetBucketCors` and `DeleteBucketCors` — the document stored
//! and read back, `404 NoSuchCORSConfiguration` when absent, an idempotent `204` delete — and the
//! backend's [`CorsSource`], which hands the stored document to the gateway's CORS evaluation.
//! NOT responsible for: evaluating a preflight or writing `Access-Control-*` headers (the gateway,
//! which RustFS also sits behind), the document rules (the shared `validate_cors`), or its
//! persisted grammar (`rustfs_gateway::persistence`).
//! Upstream: the shared CORS contract. Downstream: the CORS registry and `compat-sut`.

use rustfs_gateway::dto::{
    CorsConfiguration, DeleteBucketCors, DeleteBucketCorsOutput, GetBucketCors, GetBucketCorsOutput, PutBucketCors,
    PutBucketCorsOutput,
};
use rustfs_gateway::persistence::{parse_cors_dto, serialize_cors_dto};
use rustfs_gateway::{
    BoxFuture, BucketName, CorsSource, CorsSourceError, ErrorCode, Handler, HandlerError, HandlerResult, Req, Resp, validate_cors,
};

use super::{FsBackend, storage_error};

pub(super) const CORS_FILE: &str = "cors";

impl FsBackend {
    async fn stored_cors(&self, bucket: &str) -> Result<Option<CorsConfiguration>, HandlerError> {
        self.require_bucket(bucket).await?;
        match self.read_bucket_record(&self.bucket_path(bucket).join(CORS_FILE)).await? {
            Some(bytes) => Ok(Some(parse_cors_dto(&bytes).map_err(|_| storage_error())?)),
            None => Ok(None),
        }
    }
}

impl CorsSource for FsBackend {
    /// The stored document; `None` for a bucket without one and for a bucket that does not
    /// exist, as the trait requires, and an error only for an unreadable record.
    fn load<'a>(&'a self, bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        Box::pin(async move {
            match self.stored_cors(bucket.as_str()).await {
                Ok(document) => Ok(document),
                Err(error) if error.code() == &ErrorCode::NO_SUCH_BUCKET => Ok(None),
                Err(_) => Err(CorsSourceError),
            }
        })
    }
}

impl Handler<PutBucketCors> for FsBackend {
    async fn call(&self, request: Req<PutBucketCors>) -> HandlerResult<PutBucketCors> {
        let input = request.input();
        let bucket = input.bucket.as_str();
        self.require_bucket(bucket).await?;
        validate_cors(&input.cors_configuration)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason().to_owned()))?;
        self.write_bucket_record(bucket, CORS_FILE, &serialize_cors_dto(&input.cors_configuration))
            .await?;
        Ok(Resp::new(PutBucketCorsOutput::default()))
    }
}

impl Handler<GetBucketCors> for FsBackend {
    async fn call(&self, request: Req<GetBucketCors>) -> HandlerResult<GetBucketCors> {
        let stored = self
            .stored_cors(request.input().bucket.as_str())
            .await?
            .ok_or_else(|| HandlerError::new(ErrorCode::NO_SUCH_CORS_CONFIGURATION, "The CORS configuration does not exist"))?;
        Ok(Resp::new(GetBucketCorsOutput {
            cors_rules: stored.cors_rules,
        }))
    }
}

impl Handler<DeleteBucketCors> for FsBackend {
    async fn call(&self, request: Req<DeleteBucketCors>) -> HandlerResult<DeleteBucketCors> {
        let bucket = request.input().bucket.as_str();
        self.require_bucket(bucket).await?;
        self.delete_bucket_record(bucket, CORS_FILE).await?;
        Ok(Resp::new(DeleteBucketCorsOutput::default()))
    }
}
