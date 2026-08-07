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

//! The bucket-configuration band's reads: the nine `GET` rows at 200-240 against everything they
//! are tried before.
//!
//! Responsible for: every [`ShadowingDecl`] whose winner is one of the nine configuration reads in
//! the `?accelerate` / `?logging` / `?notification` / `?policy` / `?policyStatus` /
//! `?publicAccessBlock` / `?requestPayment` / `?versioning` / `?website` band — against each other,
//! against the seven older subresource reads at 300-397, and against the four bucket listings. It
//! also owns the three declaration constructors this band and its write half share.
//! NOT responsible for: the band's writes and deletes
//! (`shadowing_bucket_config_write.rs`), any pair whose winner is outside the band
//! (`shadowing_bucket.rs`), object-target pairs (`shadowing_object.rs`), the declaration types or
//! the policy (`shadowing.rs`), or computing overlap (`lattice.rs`).
//! Upstream: `super::evidence`, the URL constants every declaration cites. Downstream:
//! `super::shadowing`, the only reader.
//!
//! # Why there are a hundred and thirty-five of them
//!
//! Nine `GET` rows arriving in front of eleven bucket `GET` rows that were already there is
//! ninety-nine pairs before the band is compared with itself, and thirty-six more after. The
//! strict shadowing policy asks for a declaration per ordered pair, and this band is where that
//! policy first becomes quadratic in earnest: `ShadowingPolicy`'s own documentation predicted it,
//! and the count is why the band's paperwork needed two files of its own rather than a place in
//! `shadowing_bucket.rs`.
//!
//! Every pair is real. Two bucket subresource selectors differ only in which query key they pin,
//! so a request carrying both keys satisfies both rows, and something has to decide which one
//! answers. What is *not* real is the idea that each of those decisions is a separate piece of
//! reasoning: there are exactly three reasons here, and they are the three constructors below.
//! Writing the same paragraph a hundred times would not be more reviewed — it would be less,
//! because a reader would stop reading them.
//!
//! # The three reasons
//!
//! * [`pair`] — two subresource keys sent at once. AWS documents no such combination, so the
//!   answer is fixed by precedence rather than left to source order.
//! * [`over_listing`] — a subresource key sent together with `?uploads`, `?versions` or
//!   `list-type=2`. The subresource is the narrower question and is tried first.
//! * [`over_fallback`] — the same against `ListObjects`, which pins no query key at all. This is
//!   the one that matters: it is why the band is at 200 and not behind 700, and reversing it makes
//!   every operation here unreachable. Those nine lines are the debt-register entries this family
//!   retires.

use super::evidence::*;
use super::shadowing::ShadowingDecl;

/// Two bucket subresources named in one request.
///
/// The winner is the earlier row; nothing about the pair is specific to which two subresources
/// they are, which is why one reason serves all of them.
pub(super) const fn pair(winner: &'static str, shadowed: &'static str, evidence: &'static [&'static str]) -> ShadowingDecl {
    ShadowingDecl {
        winner,
        shadowed,
        reason: "Two bucket subresource keys in one request ask two questions at once. AWS \
                 documents no such combination, so the answer is fixed by precedence rather than \
                 left to source order: the earlier row answers and the later reading is ignored \
                 rather than merged into it.",
        evidence,
    }
}

/// A bucket subresource against a listing that pins a key of its own.
pub(super) const fn over_listing(
    winner: &'static str,
    shadowed: &'static str,
    evidence: &'static [&'static str],
) -> ShadowingDecl {
    ShadowingDecl {
        winner,
        shadowed,
        reason: "A subresource key and a listing key in one request name a configuration document \
                 and a page of the bucket's contents at the same time. The subresource is the \
                 narrower question and is tried first; the listing is ignored rather than merged \
                 into the answer.",
        evidence,
    }
}

/// A bucket subresource against `ListObjects`, which pins nothing.
pub(super) const fn over_fallback(
    winner: &'static str,
    shadowed: &'static str,
    evidence: &'static [&'static str],
) -> ShadowingDecl {
    ShadowingDecl {
        winner,
        shadowed,
        reason: "ListObjects is what a GET on a bucket means when no other row claimed it, so its \
                 selector pins no query key and every subresource read satisfies it too. That is \
                 not a conflict but the design, and it is the whole reason this band sits at 200: \
                 a row behind the fallback would hand every configuration read back to the key \
                 listing, which is the defect the band exists to retire.",
        evidence,
    }
}

/// The bucket-configuration read declarations, in the band order the table tries them.
pub(super) const DECLS: &[ShadowingDecl] = &[
    // GetBucketAccelerateConfiguration at 200, against everything it is tried before.
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketLogging",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_LOGGING_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketNotificationConfiguration",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_NOTIFICATION_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketPolicy",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_POLICY_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketPolicyStatus",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_POLICY_STATUS_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetPublicAccessBlock",
        &[GET_BUCKET_ACCELERATE_DOC, GET_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketRequestPayment",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketVersioning",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketWebsite",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_WEBSITE_DOC],
    ),
    // GetBucketLogging at 205, against everything it is tried before.
    pair(
        "GetBucketLogging",
        "GetBucketNotificationConfiguration",
        &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_NOTIFICATION_DOC],
    ),
    pair("GetBucketLogging", "GetBucketPolicy", &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_POLICY_DOC]),
    pair(
        "GetBucketLogging",
        "GetBucketPolicyStatus",
        &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_POLICY_STATUS_DOC],
    ),
    pair(
        "GetBucketLogging",
        "GetPublicAccessBlock",
        &[GET_BUCKET_LOGGING_DOC, GET_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "GetBucketLogging",
        "GetBucketRequestPayment",
        &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "GetBucketLogging",
        "GetBucketVersioning",
        &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_VERSIONING_DOC],
    ),
    pair("GetBucketLogging", "GetBucketWebsite", &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_WEBSITE_DOC]),
    // GetBucketNotificationConfiguration at 210, against everything it is tried before.
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketPolicy",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_POLICY_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketPolicyStatus",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_POLICY_STATUS_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetPublicAccessBlock",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketRequestPayment",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketVersioning",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketWebsite",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_WEBSITE_DOC],
    ),
    // GetBucketPolicy at 215, against everything it is tried before.
    pair(
        "GetBucketPolicy",
        "GetBucketPolicyStatus",
        &[GET_BUCKET_POLICY_DOC, GET_BUCKET_POLICY_STATUS_DOC],
    ),
    pair(
        "GetBucketPolicy",
        "GetPublicAccessBlock",
        &[GET_BUCKET_POLICY_DOC, GET_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "GetBucketPolicy",
        "GetBucketRequestPayment",
        &[GET_BUCKET_POLICY_DOC, GET_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "GetBucketPolicy",
        "GetBucketVersioning",
        &[GET_BUCKET_POLICY_DOC, GET_BUCKET_VERSIONING_DOC],
    ),
    pair("GetBucketPolicy", "GetBucketWebsite", &[GET_BUCKET_POLICY_DOC, GET_BUCKET_WEBSITE_DOC]),
    // GetBucketPolicyStatus at 220, against everything it is tried before.
    pair(
        "GetBucketPolicyStatus",
        "GetPublicAccessBlock",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_PUBLIC_ACCESS_BLOCK_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketRequestPayment",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketVersioning",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketWebsite",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_WEBSITE_DOC],
    ),
    // GetPublicAccessBlock at 225, against everything it is tried before.
    pair(
        "GetPublicAccessBlock",
        "GetBucketRequestPayment",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_REQUEST_PAYMENT_DOC],
    ),
    pair(
        "GetPublicAccessBlock",
        "GetBucketVersioning",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "GetPublicAccessBlock",
        "GetBucketWebsite",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_WEBSITE_DOC],
    ),
    // GetBucketRequestPayment at 230, against everything it is tried before.
    pair(
        "GetBucketRequestPayment",
        "GetBucketVersioning",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_VERSIONING_DOC],
    ),
    pair(
        "GetBucketRequestPayment",
        "GetBucketWebsite",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_WEBSITE_DOC],
    ),
    // GetBucketVersioning at 235, against everything it is tried before.
    pair(
        "GetBucketVersioning",
        "GetBucketWebsite",
        &[GET_BUCKET_VERSIONING_DOC, GET_BUCKET_WEBSITE_DOC],
    ),
    // GetBucketAccelerateConfiguration at 200, against everything it is tried before.
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketLocation",
        &[GET_BUCKET_ACCELERATE_DOC, LOCATION_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketCors",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_CORS_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketTagging",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_TAGGING_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketEncryption",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketReplication",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketAccelerateConfiguration",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_ACCELERATE_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing(
        "GetBucketAccelerateConfiguration",
        "ListMultipartUploads",
        &[GET_BUCKET_ACCELERATE_DOC, UPLOADS_DOC],
    ),
    over_listing(
        "GetBucketAccelerateConfiguration",
        "ListObjectsV2",
        &[GET_BUCKET_ACCELERATE_DOC, LIST_V2_DOC],
    ),
    over_listing(
        "GetBucketAccelerateConfiguration",
        "ListObjectVersions",
        &[GET_BUCKET_ACCELERATE_DOC, VERSIONS_DOC],
    ),
    over_fallback(
        "GetBucketAccelerateConfiguration",
        "ListObjects",
        &[GET_BUCKET_ACCELERATE_DOC, LIST_V1_DOC],
    ),
    // GetBucketLogging at 205, against everything it is tried before.
    pair("GetBucketLogging", "GetBucketLocation", &[GET_BUCKET_LOGGING_DOC, LOCATION_DOC]),
    pair("GetBucketLogging", "GetBucketCors", &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_CORS_DOC]),
    pair("GetBucketLogging", "GetBucketTagging", &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_TAGGING_DOC]),
    pair(
        "GetBucketLogging",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketLogging",
        "GetBucketEncryption",
        &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketLogging",
        "GetBucketReplication",
        &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketLogging",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_LOGGING_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing("GetBucketLogging", "ListMultipartUploads", &[GET_BUCKET_LOGGING_DOC, UPLOADS_DOC]),
    over_listing("GetBucketLogging", "ListObjectsV2", &[GET_BUCKET_LOGGING_DOC, LIST_V2_DOC]),
    over_listing("GetBucketLogging", "ListObjectVersions", &[GET_BUCKET_LOGGING_DOC, VERSIONS_DOC]),
    over_fallback("GetBucketLogging", "ListObjects", &[GET_BUCKET_LOGGING_DOC, LIST_V1_DOC]),
    // GetBucketNotificationConfiguration at 210, against everything it is tried before.
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketLocation",
        &[GET_BUCKET_NOTIFICATION_DOC, LOCATION_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketCors",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_CORS_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketTagging",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_TAGGING_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketEncryption",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketReplication",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketNotificationConfiguration",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing(
        "GetBucketNotificationConfiguration",
        "ListMultipartUploads",
        &[GET_BUCKET_NOTIFICATION_DOC, UPLOADS_DOC],
    ),
    over_listing(
        "GetBucketNotificationConfiguration",
        "ListObjectsV2",
        &[GET_BUCKET_NOTIFICATION_DOC, LIST_V2_DOC],
    ),
    over_listing(
        "GetBucketNotificationConfiguration",
        "ListObjectVersions",
        &[GET_BUCKET_NOTIFICATION_DOC, VERSIONS_DOC],
    ),
    over_fallback(
        "GetBucketNotificationConfiguration",
        "ListObjects",
        &[GET_BUCKET_NOTIFICATION_DOC, LIST_V1_DOC],
    ),
    // GetBucketPolicy at 215, against everything it is tried before.
    pair("GetBucketPolicy", "GetBucketLocation", &[GET_BUCKET_POLICY_DOC, LOCATION_DOC]),
    pair("GetBucketPolicy", "GetBucketCors", &[GET_BUCKET_POLICY_DOC, GET_BUCKET_CORS_DOC]),
    pair("GetBucketPolicy", "GetBucketTagging", &[GET_BUCKET_POLICY_DOC, GET_BUCKET_TAGGING_DOC]),
    pair(
        "GetBucketPolicy",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_POLICY_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketPolicy",
        "GetBucketEncryption",
        &[GET_BUCKET_POLICY_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketPolicy",
        "GetBucketReplication",
        &[GET_BUCKET_POLICY_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketPolicy",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_POLICY_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing("GetBucketPolicy", "ListMultipartUploads", &[GET_BUCKET_POLICY_DOC, UPLOADS_DOC]),
    over_listing("GetBucketPolicy", "ListObjectsV2", &[GET_BUCKET_POLICY_DOC, LIST_V2_DOC]),
    over_listing("GetBucketPolicy", "ListObjectVersions", &[GET_BUCKET_POLICY_DOC, VERSIONS_DOC]),
    over_fallback("GetBucketPolicy", "ListObjects", &[GET_BUCKET_POLICY_DOC, LIST_V1_DOC]),
    // GetBucketPolicyStatus at 220, against everything it is tried before.
    pair(
        "GetBucketPolicyStatus",
        "GetBucketLocation",
        &[GET_BUCKET_POLICY_STATUS_DOC, LOCATION_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketCors",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_CORS_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketTagging",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_TAGGING_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketEncryption",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketReplication",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketPolicyStatus",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing(
        "GetBucketPolicyStatus",
        "ListMultipartUploads",
        &[GET_BUCKET_POLICY_STATUS_DOC, UPLOADS_DOC],
    ),
    over_listing("GetBucketPolicyStatus", "ListObjectsV2", &[GET_BUCKET_POLICY_STATUS_DOC, LIST_V2_DOC]),
    over_listing(
        "GetBucketPolicyStatus",
        "ListObjectVersions",
        &[GET_BUCKET_POLICY_STATUS_DOC, VERSIONS_DOC],
    ),
    over_fallback("GetBucketPolicyStatus", "ListObjects", &[GET_BUCKET_POLICY_STATUS_DOC, LIST_V1_DOC]),
    // GetPublicAccessBlock at 225, against everything it is tried before.
    pair("GetPublicAccessBlock", "GetBucketLocation", &[GET_PUBLIC_ACCESS_BLOCK_DOC, LOCATION_DOC]),
    pair(
        "GetPublicAccessBlock",
        "GetBucketCors",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_CORS_DOC],
    ),
    pair(
        "GetPublicAccessBlock",
        "GetBucketTagging",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_TAGGING_DOC],
    ),
    pair(
        "GetPublicAccessBlock",
        "GetBucketLifecycleConfiguration",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetPublicAccessBlock",
        "GetBucketEncryption",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetPublicAccessBlock",
        "GetBucketReplication",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetPublicAccessBlock",
        "GetObjectLockConfiguration",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing(
        "GetPublicAccessBlock",
        "ListMultipartUploads",
        &[GET_PUBLIC_ACCESS_BLOCK_DOC, UPLOADS_DOC],
    ),
    over_listing("GetPublicAccessBlock", "ListObjectsV2", &[GET_PUBLIC_ACCESS_BLOCK_DOC, LIST_V2_DOC]),
    over_listing("GetPublicAccessBlock", "ListObjectVersions", &[GET_PUBLIC_ACCESS_BLOCK_DOC, VERSIONS_DOC]),
    over_fallback("GetPublicAccessBlock", "ListObjects", &[GET_PUBLIC_ACCESS_BLOCK_DOC, LIST_V1_DOC]),
    // GetBucketRequestPayment at 230, against everything it is tried before.
    pair(
        "GetBucketRequestPayment",
        "GetBucketLocation",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, LOCATION_DOC],
    ),
    pair(
        "GetBucketRequestPayment",
        "GetBucketCors",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_CORS_DOC],
    ),
    pair(
        "GetBucketRequestPayment",
        "GetBucketTagging",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_TAGGING_DOC],
    ),
    pair(
        "GetBucketRequestPayment",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketRequestPayment",
        "GetBucketEncryption",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketRequestPayment",
        "GetBucketReplication",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketRequestPayment",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing(
        "GetBucketRequestPayment",
        "ListMultipartUploads",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, UPLOADS_DOC],
    ),
    over_listing("GetBucketRequestPayment", "ListObjectsV2", &[GET_BUCKET_REQUEST_PAYMENT_DOC, LIST_V2_DOC]),
    over_listing(
        "GetBucketRequestPayment",
        "ListObjectVersions",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, VERSIONS_DOC],
    ),
    over_fallback("GetBucketRequestPayment", "ListObjects", &[GET_BUCKET_REQUEST_PAYMENT_DOC, LIST_V1_DOC]),
    // GetBucketVersioning at 235, against everything it is tried before.
    pair("GetBucketVersioning", "GetBucketLocation", &[GET_BUCKET_VERSIONING_DOC, LOCATION_DOC]),
    pair("GetBucketVersioning", "GetBucketCors", &[GET_BUCKET_VERSIONING_DOC, GET_BUCKET_CORS_DOC]),
    pair(
        "GetBucketVersioning",
        "GetBucketTagging",
        &[GET_BUCKET_VERSIONING_DOC, GET_BUCKET_TAGGING_DOC],
    ),
    pair(
        "GetBucketVersioning",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_VERSIONING_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketVersioning",
        "GetBucketEncryption",
        &[GET_BUCKET_VERSIONING_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketVersioning",
        "GetBucketReplication",
        &[GET_BUCKET_VERSIONING_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketVersioning",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_VERSIONING_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing("GetBucketVersioning", "ListMultipartUploads", &[GET_BUCKET_VERSIONING_DOC, UPLOADS_DOC]),
    over_listing("GetBucketVersioning", "ListObjectsV2", &[GET_BUCKET_VERSIONING_DOC, LIST_V2_DOC]),
    over_listing("GetBucketVersioning", "ListObjectVersions", &[GET_BUCKET_VERSIONING_DOC, VERSIONS_DOC]),
    over_fallback("GetBucketVersioning", "ListObjects", &[GET_BUCKET_VERSIONING_DOC, LIST_V1_DOC]),
    // GetBucketWebsite at 240, against everything it is tried before.
    pair("GetBucketWebsite", "GetBucketLocation", &[GET_BUCKET_WEBSITE_DOC, LOCATION_DOC]),
    pair("GetBucketWebsite", "GetBucketCors", &[GET_BUCKET_WEBSITE_DOC, GET_BUCKET_CORS_DOC]),
    pair("GetBucketWebsite", "GetBucketTagging", &[GET_BUCKET_WEBSITE_DOC, GET_BUCKET_TAGGING_DOC]),
    pair(
        "GetBucketWebsite",
        "GetBucketLifecycleConfiguration",
        &[GET_BUCKET_WEBSITE_DOC, GET_BUCKET_LIFECYCLE_DOC],
    ),
    pair(
        "GetBucketWebsite",
        "GetBucketEncryption",
        &[GET_BUCKET_WEBSITE_DOC, GET_BUCKET_ENCRYPTION_DOC],
    ),
    pair(
        "GetBucketWebsite",
        "GetBucketReplication",
        &[GET_BUCKET_WEBSITE_DOC, GET_BUCKET_REPLICATION_DOC],
    ),
    pair(
        "GetBucketWebsite",
        "GetObjectLockConfiguration",
        &[GET_BUCKET_WEBSITE_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    ),
    over_listing("GetBucketWebsite", "ListMultipartUploads", &[GET_BUCKET_WEBSITE_DOC, UPLOADS_DOC]),
    over_listing("GetBucketWebsite", "ListObjectsV2", &[GET_BUCKET_WEBSITE_DOC, LIST_V2_DOC]),
    over_listing("GetBucketWebsite", "ListObjectVersions", &[GET_BUCKET_WEBSITE_DOC, VERSIONS_DOC]),
    over_fallback("GetBucketWebsite", "ListObjects", &[GET_BUCKET_WEBSITE_DOC, LIST_V1_DOC]),
    // The `?acl` band at 250/260 arrived between this band and the older subresources, and it is
    // the one neighbour whose selector is not a configuration document at all: `?accelerate` and
    // `?acl` in one request ask a transfer question and a permissions question at once. The band
    // is still earlier, so each read below wins, and there is no pair against the *object* ACL
    // rows at 550/560 — a different target — nor against `?restore` and `?select` at 570/580,
    // which are POST and meet nothing here in the lattice.
    pair(
        "GetBucketAccelerateConfiguration",
        "GetBucketAcl",
        &[GET_BUCKET_ACCELERATE_DOC, GET_BUCKET_ACL_DOC],
    ),
    pair("GetBucketLogging", "GetBucketAcl", &[GET_BUCKET_LOGGING_DOC, GET_BUCKET_ACL_DOC]),
    pair(
        "GetBucketNotificationConfiguration",
        "GetBucketAcl",
        &[GET_BUCKET_NOTIFICATION_DOC, GET_BUCKET_ACL_DOC],
    ),
    pair("GetBucketPolicy", "GetBucketAcl", &[GET_BUCKET_POLICY_DOC, GET_BUCKET_ACL_DOC]),
    pair(
        "GetBucketPolicyStatus",
        "GetBucketAcl",
        &[GET_BUCKET_POLICY_STATUS_DOC, GET_BUCKET_ACL_DOC],
    ),
    pair("GetPublicAccessBlock", "GetBucketAcl", &[GET_PUBLIC_ACCESS_BLOCK_DOC, GET_BUCKET_ACL_DOC]),
    pair(
        "GetBucketRequestPayment",
        "GetBucketAcl",
        &[GET_BUCKET_REQUEST_PAYMENT_DOC, GET_BUCKET_ACL_DOC],
    ),
    pair("GetBucketVersioning", "GetBucketAcl", &[GET_BUCKET_VERSIONING_DOC, GET_BUCKET_ACL_DOC]),
    pair("GetBucketWebsite", "GetBucketAcl", &[GET_BUCKET_WEBSITE_DOC, GET_BUCKET_ACL_DOC]),
];
