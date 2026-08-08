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

//! The bucket-target shadowing pairs of the `?acl` band.
//!
//! Responsible for: every [`ShadowingDecl`] whose winner or loser is `GetBucketAcl` or
//! `PutBucketAcl` — which, because the band is the earliest bucket subresource in the table, is
//! one pair against every other bucket-level `GET` and one against every other bucket-level
//! `PUT`.
//! NOT responsible for: the object-target ACL pairs (`shadowing_object.rs`), any pair this
//! family is not part of (`shadowing_bucket.rs`), the declaration types or the policy
//! (`shadowing.rs`), or computing overlap (`lattice.rs`).
//! Upstream: `super::evidence`, the URL constants every declaration cites. Downstream:
//! `super::shadowing`, the only reader.
//!
//! # Why the bucket half is two files
//!
//! The seam is still the request target — this file is bucket-target, exactly like
//! `shadowing_bucket.rs`. The split is a size one: seventeen declarations arrived at once,
//! because a band that sits ahead of everything overlaps everything, and one more family in that
//! position would have taken `shadowing_bucket.rs` half again over the 800-line ceiling.
//! `ShadowingDecls` reads the groups end to end, so nothing downstream can tell the two apart.

use super::evidence::*;
use super::shadowing::ShadowingDecl;

/// The `?acl` band's bucket-target declarations, in the band order the table tries them.
///
/// The band is 250 (GET) and 260 (PUT), placed ahead of `?location` rather than inside the packed
/// 39x corner because the family had nowhere else to go and one edge is load-bearing: the table
/// is first-match and `ListObjects` at 700 pins no query key, so an ACL read behind the listings
/// is a key listing. Being first makes `GetBucketAcl` the winner of every bucket-`GET` pair below
/// and `PutBucketAcl` the winner of every bucket-`PUT` pair, which is a decision and not an
/// accident: a request naming `?acl` and a configuration subresource at once is undocumented, and
/// reading it as the access-control question is the narrower of the two readings.
pub(super) const DECLS: &[ShadowingDecl] = &[
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetBucketLocation",
        reason: "?acl and ?location name two subresources of one bucket, and a request sending \
                 both asks two questions at once. AWS documents no such combination, so the band \
                 order decides: 250 is tried before 300, and the location reading is ignored.",
        evidence: &[GET_BUCKET_ACL_DOC, LOCATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetBucketCors",
        reason: "Two subresources of one bucket named together, the same shape as the pair \
                 above with the CORS document in place of the region. 250 before 310.",
        evidence: &[GET_BUCKET_ACL_DOC, GET_BUCKET_CORS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetBucketTagging",
        reason: "?acl and ?tagging name two subresources of one bucket; the access-control \
                 reading is tried first (250 before 340) and the tag set is not merged into it.",
        evidence: &[GET_BUCKET_ACL_DOC, GET_BUCKET_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetBucketLifecycleConfiguration",
        reason: "Two configuration reads named in one GET. The ACL row is tried first (250 \
                 before 370); the lifecycle document is ignored rather than answered instead.",
        evidence: &[GET_BUCKET_ACL_DOC, GET_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetBucketEncryption",
        reason: "The encryption twin of the pair above: two documents named in one GET, and the \
                 ACL row is tried first (250 before 391).",
        evidence: &[GET_BUCKET_ACL_DOC, GET_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetBucketReplication",
        reason: "The replication twin of the two pairs above, decided the same way: 250 before \
                 394, and the replication document is ignored.",
        evidence: &[GET_BUCKET_ACL_DOC, GET_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "GetObjectLockConfiguration",
        reason: "?acl and ?object-lock are two bucket-level documents, and a request naming both \
                 reaches both rows. The ACL row is tried first (250 before 397); the WORM \
                 configuration is ignored rather than answered under the ACL's root element.",
        evidence: &[GET_BUCKET_ACL_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "ListMultipartUploads",
        reason: "?acl and ?uploads name a document and a listing of one bucket. The subresource \
                 is the narrower question and is tried first (250 before 460).",
        evidence: &[GET_BUCKET_ACL_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "ListObjectsV2",
        reason: "A request carrying ?acl and list-type=2 asks for the access control policy and \
                 for a page of keys at once. The ACL row is tried first (250 before 600).",
        evidence: &[GET_BUCKET_ACL_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "ListObjectVersions",
        reason: "The version-listing twin of the pair above: ?acl and ?versions together, and \
                 the ACL row is tried first (250 before 610).",
        evidence: &[GET_BUCKET_ACL_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketAcl",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?acl request satisfies it too. This is \
                 the pair the row's position exists for: behind the listing fallback the ACL \
                 read would be answered with a page of object keys, which is the \
                 GetBucketAcl -> ListObjects line the debt register carried.",
        evidence: &[GET_BUCKET_ACL_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketAcl",
        shadowed: "PutBucketCors",
        reason: "One PUT carrying one body and naming two configuration documents. The earlier \
                 band wins (260 before 320), so the body is read as an access control policy and \
                 the CORS reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_ACL_DOC, PUT_BUCKET_CORS_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketAcl",
        shadowed: "PutBucketTagging",
        reason: "The tagging twin of the pair above: one body, two documents named, and the ACL \
                 row tried first (260 before 350).",
        evidence: &[PUT_BUCKET_ACL_DOC, PUT_BUCKET_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketAcl",
        shadowed: "PutBucketLifecycleConfiguration",
        reason: "The lifecycle twin of the two pairs above, decided the same way: 260 before \
                 380, and the body is read as an access control policy.",
        evidence: &[PUT_BUCKET_ACL_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketAcl",
        shadowed: "PutBucketEncryption",
        reason: "The encryption twin of the three pairs above: 260 before 392, one body, and the \
                 access-control reading wins.",
        evidence: &[PUT_BUCKET_ACL_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketAcl",
        shadowed: "PutBucketReplication",
        reason: "The replication twin of the four pairs above: 260 before 395, one body, and the \
                 access-control reading wins.",
        evidence: &[PUT_BUCKET_ACL_DOC, PUT_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketAcl",
        shadowed: "PutObjectLockConfiguration",
        reason: "?acl and ?object-lock named in one PUT that carries one body. The ACL row is \
                 tried first (260 before 398), so a WORM configuration is never written from a \
                 body the client meant as an access control policy.",
        evidence: &[PUT_BUCKET_ACL_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    },
];
