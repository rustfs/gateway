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

//! Object, multipart, listing, and event Handler entries for the conformance fixture.
//!
//! Responsible for: adapting authorized typed requests to the fixture's existing object behavior.
//! NOT responsible for: fixture state, routing, authorization, or protocol decisions.
//! Upstream: `super::Stub` and typed gateway requests. Downstream: gateway Handler dispatch.

use super::*;

// Browser `POST` uploads, beside the other object writes: `fixture.rs` is at its size allowance.
#[path = "post_object.rs"]
mod post_object;

impl Stub {
    /// The bucket's stored `BlockedEncryptionTypes` applied to one object write: a write that
    /// presented an SSE-C key to a bucket that blocks SSE-C is refused with `403 AccessDenied`
    /// before anything is stored. The decision is the facade's shared rule; this only supplies the
    /// stored document. A bucket that does not exist has no document, so the handler's own
    /// `NoSuchBucket` still answers.
    fn refuse_blocked_encryption_type(&self, bucket: &str, sse: &SseEnforced) -> Result<(), HandlerError> {
        let fixture = self.borrow()?;
        refuse_blocked_encryption_type(fixture.encryption(bucket), sse)
            .map_err(|rejection| HandlerError::new(rejection.code(), rejection.reason().to_owned()))
    }
}

impl Handler<dto::GetObject> for Stub {
    fn call(&self, request: Req<dto::GetObject>) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        let outcome = self.get_object(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObject>> + Send {
        let outcome = self.get_object(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetObjectAttributes> for Stub {
    fn call(
        &self,
        request: Req<dto::GetObjectAttributes>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectAttributes>> + Send {
        let outcome = self.get_object_attributes(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObjectAttributes>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectAttributes>> + Send {
        let outcome = self.get_object_attributes(request.input());
        async move { outcome }
    }
}

impl Handler<dto::HeadObject> for Stub {
    fn call(&self, request: Req<dto::HeadObject>) -> impl core::future::Future<Output = HandlerResult<dto::HeadObject>> + Send {
        let outcome = self.head_object(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::HeadObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::HeadObject>> + Send {
        let outcome = self.head_object(request.input());
        async move { outcome }
    }
}

impl Handler<dto::CopyObject> for Stub {
    fn call(&self, request: Req<dto::CopyObject>) -> impl core::future::Future<Output = HandlerResult<dto::CopyObject>> + Send {
        // The target's key is the write the bucket may block; the copy source's key only reads.
        let outcome = self
            .refuse_blocked_encryption_type(request.input().bucket.as_str(), request.sse())
            .and_then(|()| match request.resources().source().resolve(request.read_proof()) {
                Some(resolved) => self.copy_object_with_source(request.input(), CopySource::from_resolved(&resolved)),
                None => Err(HandlerError::internal_error("the copy-source authorization proof did not match")),
            });
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::CopyObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CopyObject>> + Send {
        let outcome = self
            .refuse_blocked_encryption_type(request.input().bucket.as_str(), request.sse())
            .and_then(|()| match request.resources().source().resolve(request.read_proof()) {
                Some(resolved) => self.copy_object_with_source(request.input(), CopySource::from_resolved(&resolved)),
                None => Err(HandlerError::internal_error("the copy-source authorization proof did not match")),
            });
        async move { outcome }
    }
}

impl Handler<dto::UploadPartCopy> for Stub {
    fn call(
        &self,
        request: Req<dto::UploadPartCopy>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::UploadPartCopy>> + Send {
        let outcome = match request.resources().source().resolve(request.read_proof()) {
            Some(resolved) => self.upload_part_copy_with_source(request.input(), CopySource::from_resolved(&resolved)),
            None => Err(HandlerError::internal_error("the copy-source authorization proof did not match")),
        };
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::UploadPartCopy>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::UploadPartCopy>> + Send {
        let outcome = match request.resources().source().resolve(request.read_proof()) {
            Some(resolved) => self.upload_part_copy_with_source(request.input(), CopySource::from_resolved(&resolved)),
            None => Err(HandlerError::internal_error("the copy-source authorization proof did not match")),
        };
        async move { outcome }
    }
}

impl Handler<dto::DeleteObject> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteObject>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObject>> + Send {
        let outcome = self.delete_object(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObject>> + Send {
        let outcome = self.delete_object(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetObjectTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::GetObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectTagging>> + Send {
        let outcome = self.get_object_tagging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObjectTagging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectTagging>> + Send {
        let outcome = self.get_object_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObjectTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::PutObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectTagging>> + Send {
        let outcome = self.put_object_tagging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutObjectTagging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectTagging>> + Send {
        let outcome = self.put_object_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteObjectTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteObjectTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObjectTagging>> + Send {
        let outcome = self.delete_object_tagging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteObjectTagging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObjectTagging>> + Send {
        let outcome = self.delete_object_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketAcl> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketAcl>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketAcl>> + Send {
        let outcome = self.get_bucket_acl(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketAcl>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketAcl>> + Send {
        let outcome = self.get_bucket_acl(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketAcl> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketAcl>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketAcl>> + Send {
        let outcome = self.put_bucket_acl(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketAcl>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketAcl>> + Send {
        let outcome = self.put_bucket_acl(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetObjectAcl> for Stub {
    fn call(
        &self,
        request: Req<dto::GetObjectAcl>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectAcl>> + Send {
        let outcome = self.get_object_acl(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObjectAcl>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectAcl>> + Send {
        let outcome = self.get_object_acl(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObjectAcl> for Stub {
    fn call(
        &self,
        request: Req<dto::PutObjectAcl>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectAcl>> + Send {
        let outcome = self.put_object_acl(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutObjectAcl>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectAcl>> + Send {
        let outcome = self.put_object_acl(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketTagging>> + Send {
        let outcome = self.get_bucket_tagging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketTagging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketTagging>> + Send {
        let outcome = self.get_bucket_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketTagging>> + Send {
        let outcome = self.put_bucket_tagging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketTagging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketTagging>> + Send {
        let outcome = self.put_bucket_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketTagging> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketTagging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketTagging>> + Send {
        let outcome = self.delete_bucket_tagging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucketTagging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketTagging>> + Send {
        let outcome = self.delete_bucket_tagging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteObjects> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteObjects>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObjects>> + Send {
        let input = request.input();
        let outcome = match request.resources().resolve(request.read_proof()) {
            Some(objects) => self.delete_objects(&input.bucket, input.delete.quiet.unwrap_or(false), objects),
            None => Err(HandlerError::internal_error("the batch-delete authorization proof did not match")),
        };
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteObjects>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteObjects>> + Send {
        let input = request.input();
        let outcome = match request.resources().resolve(request.read_proof()) {
            Some(objects) => self.delete_objects(&input.bucket, input.delete.quiet.unwrap_or(false), objects),
            None => Err(HandlerError::internal_error("the batch-delete authorization proof did not match")),
        };
        async move { outcome }
    }
}

impl Handler<dto::SelectObjectContent> for Stub {
    fn call(
        &self,
        request: Req<dto::SelectObjectContent>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::SelectObjectContent>> + Send {
        let outcome = self.select_object_content(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::SelectObjectContent>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::SelectObjectContent>> + Send {
        let outcome = self.select_object_content(request.input());
        async move { outcome }
    }
}

impl Handler<dto::CreateMultipartUpload> for Stub {
    fn call(
        &self,
        request: Req<dto::CreateMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CreateMultipartUpload>> + Send {
        // Refused at initiation, so no SSE-C upload exists for its parts to join.
        let outcome = self
            .refuse_blocked_encryption_type(request.input().bucket.as_str(), request.sse())
            .and_then(|()| self.create_multipart_upload(request.input()));
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::CreateMultipartUpload>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CreateMultipartUpload>> + Send {
        let outcome = self
            .refuse_blocked_encryption_type(request.input().bucket.as_str(), request.sse())
            .and_then(|()| self.create_multipart_upload(request.input()));
        async move { outcome }
    }
}

impl Handler<dto::AbortMultipartUpload> for Stub {
    fn call(
        &self,
        request: Req<dto::AbortMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::AbortMultipartUpload>> + Send {
        let outcome = self.abort_multipart_upload(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::AbortMultipartUpload>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::AbortMultipartUpload>> + Send {
        let outcome = self.abort_multipart_upload(request.input());
        async move { outcome }
    }
}

impl Handler<dto::CompleteMultipartUpload> for Stub {
    fn call(
        &self,
        request: Req<dto::CompleteMultipartUpload>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CompleteMultipartUpload>> + Send {
        let outcome = self.complete_multipart_upload(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::CompleteMultipartUpload>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CompleteMultipartUpload>> + Send {
        let outcome = self.complete_multipart_upload(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListMultipartUploads> for Stub {
    fn call(
        &self,
        request: Req<dto::ListMultipartUploads>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListMultipartUploads>> + Send {
        let outcome = self.list_multipart_uploads(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::ListMultipartUploads>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListMultipartUploads>> + Send {
        let outcome = self.list_multipart_uploads(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListParts> for Stub {
    fn call(&self, request: Req<dto::ListParts>) -> impl core::future::Future<Output = HandlerResult<dto::ListParts>> + Send {
        let outcome = self.list_parts(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::ListParts>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListParts>> + Send {
        let outcome = self.list_parts(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListBuckets> for Stub {
    fn call(&self, request: Req<dto::ListBuckets>) -> impl core::future::Future<Output = HandlerResult<dto::ListBuckets>> + Send {
        let outcome = self.list_buckets(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::ListBuckets>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListBuckets>> + Send {
        let outcome = self.list_buckets(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListObjects> for Stub {
    fn call(&self, request: Req<dto::ListObjects>) -> impl core::future::Future<Output = HandlerResult<dto::ListObjects>> + Send {
        let outcome = self.list_objects(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::ListObjects>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListObjects>> + Send {
        let outcome = self.list_objects(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListObjectsV2> for Stub {
    fn call(
        &self,
        request: Req<dto::ListObjectsV2>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListObjectsV2>> + Send {
        let outcome = self.list_objects_v2(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::ListObjectsV2>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListObjectsV2>> + Send {
        let outcome = self.list_objects_v2(request.input());
        async move { outcome }
    }
}

impl Handler<dto::ListObjectVersions> for Stub {
    fn call(
        &self,
        request: Req<dto::ListObjectVersions>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListObjectVersions>> + Send {
        let outcome = self.list_object_versions(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::ListObjectVersions>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::ListObjectVersions>> + Send {
        let outcome = self.list_object_versions(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObject> for Stub {
    fn call(&self, request: Req<dto::PutObject>) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let blocked = self.refuse_blocked_encryption_type(request.input().bucket.as_str(), request.sse());
        let state = Arc::clone(&self.state);
        let input = request.into_input();
        async move { put_object(&state, input, blocked).await }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObject>> + Send {
        let blocked = self.refuse_blocked_encryption_type(request.input().bucket.as_str(), request.sse());
        let state = Arc::clone(&self.state);
        let input = request.into_input();
        async move { put_object(&state, input, blocked).await }
    }
}

impl Handler<dto::UploadPart> for Stub {
    fn call(&self, request: Req<dto::UploadPart>) -> impl core::future::Future<Output = HandlerResult<dto::UploadPart>> + Send {
        let state = Arc::clone(&self.state);
        let input = request.into_input();
        async move { upload_part(&state, input).await }
    }

    fn call_with_context(
        &self,
        request: Req<dto::UploadPart>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::UploadPart>> + Send {
        let state = Arc::clone(&self.state);
        let input = request.into_input();
        async move { upload_part(&state, input).await }
    }
}

impl Handler<dto::GetObjectLegalHold> for Stub {
    fn call(
        &self,
        request: Req<dto::GetObjectLegalHold>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectLegalHold>> + Send {
        let outcome = self.get_object_legal_hold(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObjectLegalHold>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectLegalHold>> + Send {
        let outcome = self.get_object_legal_hold(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObjectLegalHold> for Stub {
    fn call(
        &self,
        request: Req<dto::PutObjectLegalHold>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectLegalHold>> + Send {
        let outcome = self.put_object_legal_hold(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutObjectLegalHold>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectLegalHold>> + Send {
        let outcome = self.put_object_legal_hold(request.input());
        async move { outcome }
    }
}

impl Handler<dto::RestoreObject> for Stub {
    fn call(
        &self,
        request: Req<dto::RestoreObject>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::RestoreObject>> + Send {
        let outcome = self.restore_object(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::RestoreObject>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::RestoreObject>> + Send {
        let outcome = self.restore_object(request.input());
        async move { outcome }
    }
}
