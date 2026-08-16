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

//! Bucket configuration and lifecycle Handler entries for the conformance fixture.
//!
//! Responsible for: adapting authorized typed requests to the fixture's existing bucket behavior.
//! NOT responsible for: fixture state, routing, authorization, or protocol decisions.
//! Upstream: `super::Stub` and typed gateway requests. Downstream: gateway Handler dispatch.

use super::*;

impl Handler<dto::GetBucketLocation> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketLocation>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketLocation>> + Send {
        let outcome = self.get_bucket_location(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketLocation>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketLocation>> + Send {
        let outcome = self.get_bucket_location(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketCors> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketCors>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketCors>> + Send {
        let outcome = self.get_bucket_cors(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketCors>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketCors>> + Send {
        let outcome = self.get_bucket_cors(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketCors> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketCors>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketCors>> + Send {
        let outcome = self.put_bucket_cors(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketCors>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketCors>> + Send {
        let outcome = self.put_bucket_cors(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketCors> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketCors>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketCors>> + Send {
        let outcome = self.delete_bucket_cors(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucketCors>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketCors>> + Send {
        let outcome = self.delete_bucket_cors(request.input());
        async move { outcome }
    }
}

impl Handler<dto::CreateBucket> for Stub {
    fn call(
        &self,
        request: Req<dto::CreateBucket>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CreateBucket>> + Send {
        let outcome = self.create_bucket(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::CreateBucket>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::CreateBucket>> + Send {
        let outcome = self.create_bucket(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucket> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucket>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucket>> + Send {
        let outcome = self.delete_bucket(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucket>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucket>> + Send {
        let outcome = self.delete_bucket(request.input());
        async move { outcome }
    }
}

impl Handler<dto::HeadBucket> for Stub {
    fn call(&self, request: Req<dto::HeadBucket>) -> impl core::future::Future<Output = HandlerResult<dto::HeadBucket>> + Send {
        let outcome = self.head_bucket(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::HeadBucket>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::HeadBucket>> + Send {
        let outcome = self.head_bucket(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketLifecycleConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketLifecycleConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketLifecycleConfiguration>> + Send {
        let outcome = self.get_bucket_lifecycle_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketLifecycleConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketLifecycleConfiguration>> + Send {
        let outcome = self.get_bucket_lifecycle_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketLifecycleConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketLifecycleConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketLifecycleConfiguration>> + Send {
        let outcome = self.put_bucket_lifecycle_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketLifecycleConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketLifecycleConfiguration>> + Send {
        let outcome = self.put_bucket_lifecycle_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketLifecycle> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketLifecycle>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketLifecycle>> + Send {
        let outcome = self.delete_bucket_lifecycle(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucketLifecycle>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketLifecycle>> + Send {
        let outcome = self.delete_bucket_lifecycle(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketEncryption> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketEncryption>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketEncryption>> + Send {
        let outcome = self.get_bucket_encryption(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketEncryption>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketEncryption>> + Send {
        let outcome = self.get_bucket_encryption(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketEncryption> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketEncryption>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketEncryption>> + Send {
        let outcome = self.put_bucket_encryption(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketEncryption>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketEncryption>> + Send {
        let outcome = self.put_bucket_encryption(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketEncryption> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketEncryption>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketEncryption>> + Send {
        let outcome = self.delete_bucket_encryption(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucketEncryption>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketEncryption>> + Send {
        let outcome = self.delete_bucket_encryption(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketReplication> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketReplication>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketReplication>> + Send {
        let outcome = self.get_bucket_replication(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketReplication>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketReplication>> + Send {
        let outcome = self.get_bucket_replication(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketReplication> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketReplication>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketReplication>> + Send {
        let outcome = self.put_bucket_replication(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketReplication>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketReplication>> + Send {
        let outcome = self.put_bucket_replication(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketReplication> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketReplication>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketReplication>> + Send {
        let outcome = self.delete_bucket_replication(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucketReplication>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketReplication>> + Send {
        let outcome = self.delete_bucket_replication(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketVersioning> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketVersioning>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketVersioning>> + Send {
        let outcome = self.get_bucket_versioning(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketVersioning>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketVersioning>> + Send {
        let outcome = self.get_bucket_versioning(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketVersioning> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketVersioning>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketVersioning>> + Send {
        let outcome = self.put_bucket_versioning(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketVersioning>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketVersioning>> + Send {
        let outcome = self.put_bucket_versioning(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketAccelerateConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketAccelerateConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketAccelerateConfiguration>> + Send {
        let outcome = self.get_bucket_accelerate_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketAccelerateConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketAccelerateConfiguration>> + Send {
        let outcome = self.get_bucket_accelerate_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketAccelerateConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketAccelerateConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketAccelerateConfiguration>> + Send {
        let outcome = self.put_bucket_accelerate_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketAccelerateConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketAccelerateConfiguration>> + Send {
        let outcome = self.put_bucket_accelerate_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketRequestPayment> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketRequestPayment>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketRequestPayment>> + Send {
        let outcome = self.get_bucket_request_payment(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketRequestPayment>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketRequestPayment>> + Send {
        let outcome = self.get_bucket_request_payment(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketRequestPayment> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketRequestPayment>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketRequestPayment>> + Send {
        let outcome = self.put_bucket_request_payment(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketRequestPayment>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketRequestPayment>> + Send {
        let outcome = self.put_bucket_request_payment(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketLogging> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketLogging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketLogging>> + Send {
        let outcome = self.get_bucket_logging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketLogging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketLogging>> + Send {
        let outcome = self.get_bucket_logging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketLogging> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketLogging>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketLogging>> + Send {
        let outcome = self.put_bucket_logging(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketLogging>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketLogging>> + Send {
        let outcome = self.put_bucket_logging(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketNotificationConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketNotificationConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketNotificationConfiguration>> + Send {
        let outcome = self.get_bucket_notification_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketNotificationConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketNotificationConfiguration>> + Send {
        let outcome = self.get_bucket_notification_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketNotificationConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketNotificationConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketNotificationConfiguration>> + Send {
        let outcome = self.put_bucket_notification_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketNotificationConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketNotificationConfiguration>> + Send {
        let outcome = self.put_bucket_notification_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketWebsite> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketWebsite>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketWebsite>> + Send {
        let outcome = self.get_bucket_website(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketWebsite>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketWebsite>> + Send {
        let outcome = self.get_bucket_website(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketWebsite> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketWebsite>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketWebsite>> + Send {
        let outcome = self.put_bucket_website(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketWebsite>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketWebsite>> + Send {
        let outcome = self.put_bucket_website(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketWebsite> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketWebsite>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketWebsite>> + Send {
        let outcome = self.delete_bucket_website(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucketWebsite>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketWebsite>> + Send {
        let outcome = self.delete_bucket_website(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketPolicy> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketPolicy>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketPolicy>> + Send {
        let outcome = self.get_bucket_policy(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketPolicy>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketPolicy>> + Send {
        let outcome = self.get_bucket_policy(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutBucketPolicy> for Stub {
    fn call(
        &self,
        request: Req<dto::PutBucketPolicy>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketPolicy>> + Send {
        let outcome = self.put_bucket_policy(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutBucketPolicy>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutBucketPolicy>> + Send {
        let outcome = self.put_bucket_policy(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeleteBucketPolicy> for Stub {
    fn call(
        &self,
        request: Req<dto::DeleteBucketPolicy>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketPolicy>> + Send {
        let outcome = self.delete_bucket_policy(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeleteBucketPolicy>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeleteBucketPolicy>> + Send {
        let outcome = self.delete_bucket_policy(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetBucketPolicyStatus> for Stub {
    fn call(
        &self,
        request: Req<dto::GetBucketPolicyStatus>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketPolicyStatus>> + Send {
        let outcome = self.get_bucket_policy_status(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetBucketPolicyStatus>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetBucketPolicyStatus>> + Send {
        let outcome = self.get_bucket_policy_status(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetPublicAccessBlock> for Stub {
    fn call(
        &self,
        request: Req<dto::GetPublicAccessBlock>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetPublicAccessBlock>> + Send {
        let outcome = self.get_public_access_block(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetPublicAccessBlock>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetPublicAccessBlock>> + Send {
        let outcome = self.get_public_access_block(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutPublicAccessBlock> for Stub {
    fn call(
        &self,
        request: Req<dto::PutPublicAccessBlock>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutPublicAccessBlock>> + Send {
        let outcome = self.put_public_access_block(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutPublicAccessBlock>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutPublicAccessBlock>> + Send {
        let outcome = self.put_public_access_block(request.input());
        async move { outcome }
    }
}

impl Handler<dto::DeletePublicAccessBlock> for Stub {
    fn call(
        &self,
        request: Req<dto::DeletePublicAccessBlock>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeletePublicAccessBlock>> + Send {
        let outcome = self.delete_public_access_block(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::DeletePublicAccessBlock>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::DeletePublicAccessBlock>> + Send {
        let outcome = self.delete_public_access_block(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetObjectLockConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::GetObjectLockConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectLockConfiguration>> + Send {
        let outcome = self.get_object_lock_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObjectLockConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectLockConfiguration>> + Send {
        let outcome = self.get_object_lock_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObjectLockConfiguration> for Stub {
    fn call(
        &self,
        request: Req<dto::PutObjectLockConfiguration>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectLockConfiguration>> + Send {
        let outcome = self.put_object_lock_configuration(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutObjectLockConfiguration>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectLockConfiguration>> + Send {
        let outcome = self.put_object_lock_configuration(request.input());
        async move { outcome }
    }
}

impl Handler<dto::GetObjectRetention> for Stub {
    fn call(
        &self,
        request: Req<dto::GetObjectRetention>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectRetention>> + Send {
        let outcome = self.get_object_retention(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::GetObjectRetention>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::GetObjectRetention>> + Send {
        let outcome = self.get_object_retention(request.input());
        async move { outcome }
    }
}

impl Handler<dto::PutObjectRetention> for Stub {
    fn call(
        &self,
        request: Req<dto::PutObjectRetention>,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectRetention>> + Send {
        let outcome = self.put_object_retention(request.input());
        async move { outcome }
    }

    fn call_with_context(
        &self,
        request: Req<dto::PutObjectRetention>,
        _context: rustfs_gateway::HandlerContext,
    ) -> impl core::future::Future<Output = HandlerResult<dto::PutObjectRetention>> + Send {
        let outcome = self.put_object_retention(request.input());
        async move { outcome }
    }
}
