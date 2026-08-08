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

//! The bucket-configuration band's writes and deletes: the eight `PUT` rows and three `DELETE`
//! rows at 201-242 against everything they are tried before.
//!
//! Responsible for: every [`ShadowingDecl`] whose winner is one of the band's writes or deletes —
//! against each other, and against the older subresource bands' method twins at 320-398.
//! NOT responsible for: the band's reads (`shadowing_bucket_config.rs`, which also owns the three
//! constructors used here), any pair whose winner is outside the band (`shadowing_bucket.rs`), or
//! object-target pairs (`shadowing_object.rs`).
//! Upstream: `super::evidence` and `super::shadowing_bucket_config`. Downstream:
//! `super::shadowing`, the only reader.
//!
//! # Why the listings do not appear here
//!
//! Every listing is a `GET`, so no write in this band overlaps one. The bucket CRUD rows at 710
//! and 720 do not appear either, and for a stronger reason: `CreateBucket` and `DeleteBucket`
//! pin a `QueryAbsent` for every subresource key under their method, this band's eight and three
//! included, so the selectors are provably disjoint rather than merely ordered. That is what
//! keeps `PUT /b?versioning` from being a bucket creation whether or not this band exists.

use super::evidence::*;
use super::shadowing::ShadowingDecl;
use super::shadowing_bucket_config::pair;

/// The bucket-configuration write and delete declarations, in the band order the table tries them.
pub(super) const DECLS: &[ShadowingDecl] = &[
    // PutBucketAccelerateConfiguration at 201, against everything it is tried before.
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketLogging",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_LOGGING_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketNotificationConfiguration",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_NOTIFICATION_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketPolicy",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_POLICY_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutPublicAccessBlock",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketRequestPayment",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketVersioning",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketWebsite",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_WEBSITE_DOC],
    ),
    // PutBucketLogging at 206, against everything it is tried before.
    pair(
        "PutBucketLogging",
        "PutBucketNotificationConfiguration",
        &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_NOTIFICATION_DOC],
    ),
    pair("PutBucketLogging", "PutBucketPolicy", &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_POLICY_DOC]),
    pair(
        "PutBucketLogging",
        "PutPublicAccessBlock",
        &[PUT_BUCKET_LOGGING_DOC, PUT_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "PutBucketLogging",
        "PutBucketRequestPayment",
        &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "PutBucketLogging",
        "PutBucketVersioning",
        &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_VERSIONING_DOC],
    ),
    pair("PutBucketLogging", "PutBucketWebsite", &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_WEBSITE_DOC]),
    // PutBucketNotificationConfiguration at 211, against everything it is tried before.
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketPolicy",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_POLICY_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutPublicAccessBlock",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketRequestPayment",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketVersioning",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketWebsite",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_WEBSITE_DOC],
    ),
    // PutBucketPolicy at 216, against everything it is tried before.
    pair(
        "PutBucketPolicy",
        "PutPublicAccessBlock",
        &[PUT_BUCKET_POLICY_DOC, PUT_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "PutBucketPolicy",
        "PutBucketRequestPayment",
        &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "PutBucketPolicy",
        "PutBucketVersioning",
        &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_VERSIONING_DOC],
    ),
    pair("PutBucketPolicy", "PutBucketWebsite", &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_WEBSITE_DOC]),
    // PutPublicAccessBlock at 226, against everything it is tried before.
    pair(
        "PutPublicAccessBlock",
        "PutBucketRequestPayment",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "PutPublicAccessBlock",
        "PutBucketVersioning",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "PutPublicAccessBlock",
        "PutBucketWebsite",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_WEBSITE_DOC],
    ),
    // PutBucketRequestPayment at 231, against everything it is tried before.
    pair(
        "PutBucketRequestPayment",
        "PutBucketVersioning",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "PutBucketRequestPayment",
        "PutBucketWebsite",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_WEBSITE_DOC],
    ),
    // PutBucketVersioning at 236, against everything it is tried before.
    pair(
        "PutBucketVersioning",
        "PutBucketWebsite",
        &[PUT_BUCKET_VERSIONING_DOC, PUT_BUCKET_WEBSITE_DOC],
    ),
    // PutBucketAccelerateConfiguration at 201, against everything it is tried before.
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketCors",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_CORS_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketTagging",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_TAGGING_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketLifecycleConfiguration",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketEncryption",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketReplication",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutBucketAccelerateConfiguration",
        "PutObjectLockConfiguration",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // PutBucketLogging at 206, against everything it is tried before.
    pair("PutBucketLogging", "PutBucketCors", &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_CORS_DOC]),
    pair("PutBucketLogging", "PutBucketTagging", &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_TAGGING_DOC]),
    pair(
        "PutBucketLogging",
        "PutBucketLifecycleConfiguration",
        &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutBucketLogging",
        "PutBucketEncryption",
        &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutBucketLogging",
        "PutBucketReplication",
        &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutBucketLogging",
        "PutObjectLockConfiguration",
        &[PUT_BUCKET_LOGGING_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // PutBucketNotificationConfiguration at 211, against everything it is tried before.
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketCors",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_CORS_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketTagging",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_TAGGING_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketLifecycleConfiguration",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketEncryption",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketReplication",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutBucketNotificationConfiguration",
        "PutObjectLockConfiguration",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // PutBucketPolicy at 216, against everything it is tried before.
    pair("PutBucketPolicy", "PutBucketCors", &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_CORS_DOC]),
    pair("PutBucketPolicy", "PutBucketTagging", &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_TAGGING_DOC]),
    pair(
        "PutBucketPolicy",
        "PutBucketLifecycleConfiguration",
        &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutBucketPolicy",
        "PutBucketEncryption",
        &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutBucketPolicy",
        "PutBucketReplication",
        &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutBucketPolicy",
        "PutObjectLockConfiguration",
        &[PUT_BUCKET_POLICY_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // PutPublicAccessBlock at 226, against everything it is tried before.
    pair(
        "PutPublicAccessBlock",
        "PutBucketCors",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_CORS_DOC],
    ),
    pair(
        "PutPublicAccessBlock",
        "PutBucketTagging",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_TAGGING_DOC],
    ),
    pair(
        "PutPublicAccessBlock",
        "PutBucketLifecycleConfiguration",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutPublicAccessBlock",
        "PutBucketEncryption",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutPublicAccessBlock",
        "PutBucketReplication",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutPublicAccessBlock",
        "PutObjectLockConfiguration",
        &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // PutBucketRequestPayment at 231, against everything it is tried before.
    pair(
        "PutBucketRequestPayment",
        "PutBucketCors",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_CORS_DOC],
    ),
    pair(
        "PutBucketRequestPayment",
        "PutBucketTagging",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_TAGGING_DOC],
    ),
    pair(
        "PutBucketRequestPayment",
        "PutBucketLifecycleConfiguration",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutBucketRequestPayment",
        "PutBucketEncryption",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutBucketRequestPayment",
        "PutBucketReplication",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutBucketRequestPayment",
        "PutObjectLockConfiguration",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // PutBucketVersioning at 236, against everything it is tried before.
    pair("PutBucketVersioning", "PutBucketCors", &[PUT_BUCKET_VERSIONING_DOC, PUT_BUCKET_CORS_DOC]),
    pair(
        "PutBucketVersioning",
        "PutBucketTagging",
        &[PUT_BUCKET_VERSIONING_DOC, PUT_BUCKET_TAGGING_DOC],
    ),
    pair(
        "PutBucketVersioning",
        "PutBucketLifecycleConfiguration",
        &[PUT_BUCKET_VERSIONING_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutBucketVersioning",
        "PutBucketEncryption",
        &[PUT_BUCKET_VERSIONING_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutBucketVersioning",
        "PutBucketReplication",
        &[PUT_BUCKET_VERSIONING_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutBucketVersioning",
        "PutObjectLockConfiguration",
        &[PUT_BUCKET_VERSIONING_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // PutBucketWebsite at 241, against everything it is tried before.
    pair("PutBucketWebsite", "PutBucketCors", &[PUT_BUCKET_WEBSITE_DOC, PUT_BUCKET_CORS_DOC]),
    pair("PutBucketWebsite", "PutBucketTagging", &[PUT_BUCKET_WEBSITE_DOC, PUT_BUCKET_TAGGING_DOC]),
    pair(
        "PutBucketWebsite",
        "PutBucketLifecycleConfiguration",
        &[PUT_BUCKET_WEBSITE_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "PutBucketWebsite",
        "PutBucketEncryption",
        &[PUT_BUCKET_WEBSITE_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "PutBucketWebsite",
        "PutBucketReplication",
        &[PUT_BUCKET_WEBSITE_DOC, PUT_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "PutBucketWebsite",
        "PutObjectLockConfiguration",
        &[PUT_BUCKET_WEBSITE_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    // DeleteBucketPolicy at 217, against everything it is tried before.
    pair(
        "DeleteBucketPolicy",
        "DeletePublicAccessBlock",
        &[DELETE_BUCKET_POLICY_DOC, DELETE_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "DeleteBucketPolicy",
        "DeleteBucketWebsite",
        &[DELETE_BUCKET_POLICY_DOC, DELETE_BUCKET_WEBSITE_DOC],
    ),
    // DeletePublicAccessBlock at 227, against everything it is tried before.
    pair(
        "DeletePublicAccessBlock",
        "DeleteBucketWebsite",
        &[DELETE_PUBLIC_ACCESS_BLOCK_DOC, DELETE_BUCKET_WEBSITE_DOC],
    ),
    // DeleteBucketPolicy at 217, against everything it is tried before.
    pair(
        "DeleteBucketPolicy",
        "DeleteBucketCors",
        &[DELETE_BUCKET_POLICY_DOC, DELETE_BUCKET_CORS_DOC],
    ),
    pair(
        "DeleteBucketPolicy",
        "DeleteBucketTagging",
        &[DELETE_BUCKET_POLICY_DOC, DELETE_BUCKET_TAGGING_DOC],
    ),
    pair(
        "DeleteBucketPolicy",
        "DeleteBucketLifecycle",
        &[DELETE_BUCKET_POLICY_DOC, DELETE_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "DeleteBucketPolicy",
        "DeleteBucketEncryption",
        &[DELETE_BUCKET_POLICY_DOC, DELETE_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "DeleteBucketPolicy",
        "DeleteBucketReplication",
        &[DELETE_BUCKET_POLICY_DOC, DELETE_BUCKET_REPLICATION_DOC],
    ),
    // DeletePublicAccessBlock at 227, against everything it is tried before.
    pair(
        "DeletePublicAccessBlock",
        "DeleteBucketCors",
        &[DELETE_PUBLIC_ACCESS_BLOCK_DOC, DELETE_BUCKET_CORS_DOC],
    ),
    pair(
        "DeletePublicAccessBlock",
        "DeleteBucketTagging",
        &[DELETE_PUBLIC_ACCESS_BLOCK_DOC, DELETE_BUCKET_TAGGING_DOC],
    ),
    pair(
        "DeletePublicAccessBlock",
        "DeleteBucketLifecycle",
        &[DELETE_PUBLIC_ACCESS_BLOCK_DOC, DELETE_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "DeletePublicAccessBlock",
        "DeleteBucketEncryption",
        &[DELETE_PUBLIC_ACCESS_BLOCK_DOC, DELETE_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "DeletePublicAccessBlock",
        "DeleteBucketReplication",
        &[DELETE_PUBLIC_ACCESS_BLOCK_DOC, DELETE_BUCKET_REPLICATION_DOC],
    ),
    // DeleteBucketWebsite at 242, against everything it is tried before.
    pair(
        "DeleteBucketWebsite",
        "DeleteBucketCors",
        &[DELETE_BUCKET_WEBSITE_DOC, DELETE_BUCKET_CORS_DOC],
    ),
    pair(
        "DeleteBucketWebsite",
        "DeleteBucketTagging",
        &[DELETE_BUCKET_WEBSITE_DOC, DELETE_BUCKET_TAGGING_DOC],
    ),
    pair(
        "DeleteBucketWebsite",
        "DeleteBucketLifecycle",
        &[DELETE_BUCKET_WEBSITE_DOC, DELETE_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "DeleteBucketWebsite",
        "DeleteBucketEncryption",
        &[DELETE_BUCKET_WEBSITE_DOC, DELETE_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "DeleteBucketWebsite",
        "DeleteBucketReplication",
        &[DELETE_BUCKET_WEBSITE_DOC, DELETE_BUCKET_REPLICATION_DOC],
    ),
    // The `?acl` write at 260, the same edge as the read half's. `PutBucketAcl` is the only
    // bucket `PUT` this band did not already order against, and it is the one where getting the
    // order backwards would be worst: a permissions write answered by a configuration write
    // stores neither and reports success for both.
    pair(
        "PutBucketAccelerateConfiguration",
        "PutBucketAcl",
        &[PUT_BUCKET_ACCELERATE_DOC, PUT_BUCKET_ACL_DOC],
    ),
    pair("PutBucketLogging", "PutBucketAcl", &[PUT_BUCKET_LOGGING_DOC, PUT_BUCKET_ACL_DOC]),
    pair(
        "PutBucketNotificationConfiguration",
        "PutBucketAcl",
        &[PUT_BUCKET_NOTIFICATION_DOC, PUT_BUCKET_ACL_DOC],
    ),
    pair("PutBucketPolicy", "PutBucketAcl", &[PUT_BUCKET_POLICY_DOC, PUT_BUCKET_ACL_DOC]),
    pair("PutPublicAccessBlock", "PutBucketAcl", &[PUT_PUBLIC_ACCESS_BLOCK_DOC, PUT_BUCKET_ACL_DOC]),
    pair(
        "PutBucketRequestPayment",
        "PutBucketAcl",
        &[PUT_BUCKET_REQUEST_PAYMENT_DOC, PUT_BUCKET_ACL_DOC],
    ),
    pair("PutBucketVersioning", "PutBucketAcl", &[PUT_BUCKET_VERSIONING_DOC, PUT_BUCKET_ACL_DOC]),
    pair("PutBucketWebsite", "PutBucketAcl", &[PUT_BUCKET_WEBSITE_DOC, PUT_BUCKET_ACL_DOC]),
];
