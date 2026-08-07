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

//! The bucket-target half of the reviewed shadowing table.
//!
//! Responsible for: every [`ShadowingDecl`] whose overlapping selectors address a bucket — the
//! listing family, the `?cors`, `?tagging`, `?lifecycle` and `?encryption` bands, and the
//! `?object-lock` pair. Split out of `shadowing.rs` along the request-target seam when the
//! table outgrew the 800-line file ceiling; `shadowing.rs` joins the two halves back into the
//! one slice every consumer reads.
//! NOT responsible for: object-target pairs (`shadowing_object.rs`), the declaration types or
//! the policy (`shadowing.rs`), or computing overlap (`lattice.rs`).
//! Upstream: `super::evidence`, the URL constants every declaration cites. Downstream:
//! `super::shadowing`, the only reader.

use super::evidence::*;
use super::shadowing::ShadowingDecl;

/// The bucket-target declarations, in the band order the table tries them.
pub(super) const DECLS: &[ShadowingDecl] = &[
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "ListObjectsV2",
        reason: "A request carrying both ?location and ?list-type=2 asks two questions at once. \
                 AWS documents neither combination, so the answer is fixed here rather than left to \
                 source order: the subresource band (300) is tried before the listing band (600), so \
                 ?location wins and the listing is ignored.",
        evidence: &[
            // Both URLs are AWS's own operation references. The one-sentence summaries are written
            // here rather than quoted, per the provenance rule.
            LOCATION_DOC,
            LIST_V2_DOC,
        ],
    },
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "ListObjectVersions",
        reason: "Same shape as the pair above with the version listing in place of the key \
                 listing: only a client sending ?location and ?versions together reaches it, AWS \
                 documents no such combination, and the subresource band is tried first.",
        evidence: &[LOCATION_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?location request also satisfies it. That \
                 is not a conflict but the design: the subresource is the specific reading and the \
                 key listing is the fallback, which is why the fallback sits at the end of the \
                 band. Reversing the two would make ?location unreachable.",
        evidence: &[LOCATION_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "ListMultipartUploads",
        reason: "The same both-keys-at-once shape as the three pairs above: ?location and ?uploads \
                 name two different subresources of one bucket. ?location is the narrower question \
                 and is tried first (300 before 460); the upload listing is ignored rather than \
                 merged into the answer.",
        evidence: &[LOCATION_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "ListMultipartUploads",
        shadowed: "ListObjectsV2",
        reason: "?uploads and ?list-type=2 together ask for the in-progress uploads and for a page \
                 of committed keys at the same time. The upload listing is the more specific \
                 reading and is tried first; the key listing is ignored.",
        evidence: &[UPLOADS_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "ListMultipartUploads",
        shadowed: "ListObjectVersions",
        reason: "?uploads and ?versions together name two different listings of the same bucket. \
                 The upload listing is tried first for the same reason as the pair above.",
        evidence: &[UPLOADS_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "ListMultipartUploads",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so a ?uploads request satisfies it too. The upload \
                 listing is the specific reading and wins; the fallback stays last in the band.",
        evidence: &[UPLOADS_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "ListObjectsV2",
        shadowed: "ListObjectVersions",
        reason: "A request carrying list-type=2 and ?versions asks for a page of current keys and \
                 for every version of them at once. The two are different operations with \
                 different response roots, so one has to win: list-type=2 is an explicit value \
                 rather than a bare subresource key, and it is tried first.",
        evidence: &[LIST_V2_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "ListObjectsV2",
        shadowed: "ListObjects",
        reason: "This is the pair the version discriminator exists for: list-type=2 selects the \
                 second listing and its absence selects the first. Because the first pins no query \
                 key, the selection is entirely a matter of which is tried first, and getting it \
                 backwards would make the second version unreachable.",
        evidence: &[LIST_V2_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "ListObjectVersions",
        shadowed: "ListObjects",
        reason: "?versions selects the version listing, and its absence leaves the key listing. \
                 Same fallback relationship as the pair above, with the subresource in place of \
                 the version discriminator.",
        evidence: &[VERSIONS_DOC, LIST_V1_DOC],
    },
    // The bucket tagging band is the bucket-subresource shape again, one band behind `?cors`. The
    // GET meets `?location` and `?cors` above it and every bucket listing below it; the PUT and
    // DELETE meet only their `?cors` method twins, which is the bucket band's first cross-family
    // pair outside the GET method.
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "GetBucketTagging",
        reason: "?location and ?tagging name two subresources of one bucket, and a request sending \
                 both asks two questions at once. AWS documents no such combination, so the answer \
                 is fixed here rather than left to source order: 300 is tried before 340, and the \
                 tagging reading is ignored rather than merged into the answer.",
        evidence: &[LOCATION_DOC, GET_BUCKET_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "GetBucketTagging",
        reason: "?cors and ?tagging name two configuration documents of one bucket, and a request \
                 sending both keys reaches both rows. AWS documents no such combination, so the \
                 band order decides: ?cors at 310 arrived first and is tried before ?tagging at \
                 340; the tagging reading is ignored rather than merged into the answer.",
        evidence: &[GET_BUCKET_CORS_DOC, GET_BUCKET_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketCors",
        shadowed: "PutBucketTagging",
        reason: "PUT /b?cors&tagging carries one body and names two documents to replace with it, \
                 which cannot both be meant. The same arrival order as the GET pair decides (320 \
                 before 350): the body is read as the CORS document it would have to be for the \
                 winning row, and the tagging reading is ignored rather than applied to a document \
                 of the wrong shape.",
        evidence: &[PUT_BUCKET_CORS_DOC, PUT_BUCKET_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketCors",
        shadowed: "DeleteBucketTagging",
        reason: "DELETE /b?cors&tagging asks to remove two configurations at once, which AWS does \
                 not document; one 204 cannot report two removals. The arrival order decides (330 \
                 before 360) and only the CORS configuration is removed — consistent with the GET \
                 and PUT pairs, so the whole cross-family decision is one rule in three methods.",
        evidence: &[DELETE_BUCKET_CORS_DOC, DELETE_BUCKET_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "ListMultipartUploads",
        reason: "?tagging and ?uploads together name a subresource and a listing of the same \
                 bucket. The subresource band (340) is tried before the upload listing (460), the \
                 same order the ?location pair above settled.",
        evidence: &[GET_BUCKET_TAGGING_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "ListObjectsV2",
        reason: "A request carrying both ?tagging and ?list-type=2 asks for the bucket's labels \
                 and for a page of its keys at once. The subresource is the narrower question and \
                 is tried first (340 before 600); the listing is ignored.",
        evidence: &[GET_BUCKET_TAGGING_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "ListObjectVersions",
        reason: "Same shape as the pair above with the version listing in place of the key \
                 listing: only a client sending ?tagging and ?versions together reaches it, and \
                 the subresource band is tried first.",
        evidence: &[GET_BUCKET_TAGGING_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?tagging request also satisfies it — and \
                 before the row at 340 existed, that is exactly what happened: a request for the \
                 bucket's labels was answered with a page of its keys. The subresource is the \
                 specific reading and wins; the fallback stays last in the band.",
        evidence: &[GET_BUCKET_TAGGING_DOC, LIST_V1_DOC],
    },
    // The `?cors` band was the first bucket-subresource triple, and when it landed only its GET
    // row overlapped anything — PUT and DELETE on a bucket had no other row to meet until the
    // `?lifecycle` band below arrived (those pairs are declared with that band). Four of the five
    // pairs here are the familiar both-keys-at-once accident; the fifth — against ListObjects —
    // is the fallback relationship, and it is the pair the debt register recorded as
    // `GetBucketCors -> ListObjects` until this band landed.
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "GetBucketCors",
        reason: "A request carrying both ?location and ?cors asks two subresource questions at \
                 once. AWS documents no such combination, so the answer is fixed here rather than \
                 left to source order: ?location at 300 is tried before ?cors at 310, and the CORS \
                 reading is ignored rather than merged into the answer.",
        evidence: &[LOCATION_DOC, GET_BUCKET_CORS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "ListMultipartUploads",
        reason: "?cors and ?uploads together name a configuration document and a listing of one \
                 bucket. The subresource band (310) is tried before the upload listing (460), the \
                 same order ?location settled against the same neighbour.",
        evidence: &[GET_BUCKET_CORS_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "ListObjectsV2",
        reason: "A request carrying ?cors and ?list-type=2 asks for the CORS document and a page \
                 of keys at once. The configuration subresource is the narrower question and is \
                 tried first (310 before 600); the listing is ignored.",
        evidence: &[GET_BUCKET_CORS_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "ListObjectVersions",
        reason: "Same shape as the pair above with the version listing in place of the key page: \
                 only a client sending ?cors and ?versions together reaches it, and the \
                 subresource band is tried first (310 before 610).",
        evidence: &[GET_BUCKET_CORS_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?cors request also satisfies it. Until \
                 this row existed that was not a latent overlap but the served behaviour: a CORS \
                 document request was answered with a key listing. The subresource is the specific \
                 reading and wins (310 before 700); the fallback stays last in the band.",
        evidence: &[GET_BUCKET_CORS_DOC, LIST_V1_DOC],
    },
    // The `?lifecycle` band repeats the `?cors` shape two bands later, with one new wrinkle: it
    // lands *beside* two other subresource triples, so its PUT and DELETE rows now have
    // neighbours to meet — a request naming ?cors or ?tagging together with ?lifecycle overlaps
    // in all three methods, not only in GET. Every pair is the both-keys-at-once accident except
    // the last, against ListObjects, which is the fallback relationship the debt register
    // recorded as `GetBucketLifecycleConfiguration -> ListObjects` until this band landed.
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "GetBucketLifecycleConfiguration",
        reason: "A request carrying both ?location and ?lifecycle asks two subresource questions \
                 at once. AWS documents no such combination, so the answer is fixed here rather \
                 than left to source order: ?location at 300 is tried before ?lifecycle at 370, \
                 and the lifecycle reading is ignored rather than merged into the answer.",
        evidence: &[LOCATION_DOC, GET_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "GetBucketLifecycleConfiguration",
        reason: "Two configuration subresources named in one GET. Neither is the narrower \
                 question, so the earlier band wins: ?cors at 310 is tried before ?lifecycle at \
                 370, the same first-band-wins rule ?location settled against ?cors.",
        evidence: &[GET_BUCKET_CORS_DOC, GET_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "GetBucketLifecycleConfiguration",
        reason: "Two configuration subresources named in one GET, the same shape as the ?cors \
                 pair above with the tagging band in its place. The earlier band wins: ?tagging \
                 at 340 is tried before ?lifecycle at 370, and the lifecycle reading is ignored.",
        evidence: &[GET_BUCKET_TAGGING_DOC, GET_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLifecycleConfiguration",
        shadowed: "ListMultipartUploads",
        reason: "?lifecycle and ?uploads together name a configuration document and a listing of \
                 one bucket. The subresource band (370) is tried before the upload listing (460), \
                 the same order the ?cors band settled against the same neighbour.",
        evidence: &[GET_BUCKET_LIFECYCLE_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLifecycleConfiguration",
        shadowed: "ListObjectsV2",
        reason: "A request carrying ?lifecycle and ?list-type=2 asks for the lifecycle document \
                 and a page of keys at once. The configuration subresource is the narrower \
                 question and is tried first (370 before 600); the listing is ignored.",
        evidence: &[GET_BUCKET_LIFECYCLE_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLifecycleConfiguration",
        shadowed: "ListObjectVersions",
        reason: "Same shape as the pair above with the version listing in place of the key page: \
                 only a client sending ?lifecycle and ?versions together reaches it, and the \
                 subresource band is tried first (370 before 610).",
        evidence: &[GET_BUCKET_LIFECYCLE_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLifecycleConfiguration",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?lifecycle request also satisfies it. \
                 Until this row existed that was not a latent overlap but the served behaviour: a \
                 lifecycle document request was answered with a key listing. The subresource is \
                 the specific reading and wins (370 before 700); the fallback stays last in the \
                 band.",
        evidence: &[GET_BUCKET_LIFECYCLE_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketCors",
        shadowed: "PutBucketLifecycleConfiguration",
        reason: "Two configuration writes named in one PUT: a request carrying ?cors and \
                 ?lifecycle satisfies both selectors, and AWS documents no such combination. The \
                 earlier band wins (320 before 380), so the body is read as a CORS document and \
                 the lifecycle reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_CORS_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketTagging",
        shadowed: "PutBucketLifecycleConfiguration",
        reason: "Two configuration writes named in one PUT, the tagging twin of the ?cors pair \
                 above. The earlier band wins (350 before 380), so the body is read as a tagging \
                 document and the lifecycle reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_TAGGING_DOC, PUT_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketCors",
        shadowed: "DeleteBucketLifecycle",
        reason: "Two configuration deletes named in one DELETE. The earlier band wins (330 before \
                 390), so only the CORS document is removed: a request that destroys two \
                 configurations because it named two query keys would turn a typo into data loss.",
        evidence: &[DELETE_BUCKET_CORS_DOC, DELETE_BUCKET_LIFECYCLE_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketTagging",
        shadowed: "DeleteBucketLifecycle",
        reason: "Two configuration deletes named in one DELETE, the tagging twin of the pair \
                 above. The earlier band wins (360 before 390), so only the tag set is removed: \
                 a request that destroys two configurations because it named two query keys \
                 would turn a typo into data loss.",
        evidence: &[DELETE_BUCKET_TAGGING_DOC, DELETE_BUCKET_LIFECYCLE_DOC],
    },
    // The `?encryption` band repeats the `?lifecycle` shape one band later, packed at 391-393
    // because the tens-aligned subresource slots before the multipart band are spoken for. Three
    // subresource triples now sit ahead of it, so all three of its rows have same-method
    // neighbours to order against — nine both-keys-at-once pairs — plus `?location` and the four
    // listings on the GET side. The last pair, against ListObjects, is the fallback relationship
    // the debt register recorded as `GetBucketEncryption -> ListObjects` until this band landed.
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "GetBucketEncryption",
        reason: "A request carrying both ?location and ?encryption asks two subresource questions \
                 at once. AWS documents no such combination, so the answer is fixed here rather \
                 than left to source order: ?location at 300 is tried before ?encryption at 391, \
                 and the encryption reading is ignored rather than merged into the answer.",
        evidence: &[LOCATION_DOC, GET_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "GetBucketEncryption",
        reason: "Two configuration subresources named in one GET. Neither is the narrower \
                 question, so the earlier band wins: ?cors at 310 is tried before ?encryption at \
                 391, the same first-band-wins rule ?location settled against ?cors.",
        evidence: &[GET_BUCKET_CORS_DOC, GET_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "GetBucketEncryption",
        reason: "Two configuration subresources named in one GET, the same shape as the ?cors \
                 pair above with the tagging band in its place. The earlier band wins: ?tagging \
                 at 340 is tried before ?encryption at 391, and the encryption reading is \
                 ignored.",
        evidence: &[GET_BUCKET_TAGGING_DOC, GET_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLifecycleConfiguration",
        shadowed: "GetBucketEncryption",
        reason: "Two configuration subresources named in one GET, the third same-method \
                 neighbour. The earlier band wins: ?lifecycle at 370 is tried before ?encryption \
                 at 391, in the arrival order every subresource pair in the table follows.",
        evidence: &[GET_BUCKET_LIFECYCLE_DOC, GET_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketEncryption",
        shadowed: "ListMultipartUploads",
        reason: "?encryption and ?uploads together name a configuration document and a listing of \
                 one bucket. The subresource band (391) is tried before the upload listing (460), \
                 the same order the ?cors and ?lifecycle bands settled against the same \
                 neighbour.",
        evidence: &[GET_BUCKET_ENCRYPTION_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketEncryption",
        shadowed: "ListObjectsV2",
        reason: "A request carrying ?encryption and ?list-type=2 asks for the encryption document \
                 and a page of keys at once. The configuration subresource is the narrower \
                 question and is tried first (391 before 600); the listing is ignored.",
        evidence: &[GET_BUCKET_ENCRYPTION_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketEncryption",
        shadowed: "ListObjectVersions",
        reason: "Same shape as the pair above with the version listing in place of the key page: \
                 only a client sending ?encryption and ?versions together reaches it, and the \
                 subresource band is tried first (391 before 610).",
        evidence: &[GET_BUCKET_ENCRYPTION_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketEncryption",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?encryption request also satisfies it. \
                 Until this row existed that was not a latent overlap but the served behaviour: \
                 an encryption document request was answered with a key listing. The subresource \
                 is the specific reading and wins (391 before 700); the fallback stays last in \
                 the band.",
        evidence: &[GET_BUCKET_ENCRYPTION_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketCors",
        shadowed: "PutBucketEncryption",
        reason: "Two configuration writes named in one PUT: a request carrying ?cors and \
                 ?encryption satisfies both selectors, and AWS documents no such combination. The \
                 earlier band wins (320 before 392), so the body is read as a CORS document and \
                 the encryption reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_CORS_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketTagging",
        shadowed: "PutBucketEncryption",
        reason: "Two configuration writes named in one PUT, the tagging twin of the ?cors pair \
                 above. The earlier band wins (350 before 392), so the body is read as a tagging \
                 document and the encryption reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_TAGGING_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketLifecycleConfiguration",
        shadowed: "PutBucketEncryption",
        reason: "Two configuration writes named in one PUT, the lifecycle twin of the two pairs \
                 above. The earlier band wins (380 before 392), so the body is read as a \
                 lifecycle document and the encryption reading is ignored rather than \
                 double-written.",
        evidence: &[PUT_BUCKET_LIFECYCLE_DOC, PUT_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketCors",
        shadowed: "DeleteBucketEncryption",
        reason: "Two configuration deletes named in one DELETE. The earlier band wins (330 \
                 before 393), so only the CORS document is removed: a request that destroys two \
                 configurations because it named two query keys would turn a typo into data \
                 loss.",
        evidence: &[DELETE_BUCKET_CORS_DOC, DELETE_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketTagging",
        shadowed: "DeleteBucketEncryption",
        reason: "Two configuration deletes named in one DELETE, the tagging twin of the pair \
                 above. The earlier band wins (360 before 393), so only the tag set is removed \
                 and the encryption document stays: turning a typo into the silent loss of a \
                 security configuration is the worst spelling of the data-loss rule.",
        evidence: &[DELETE_BUCKET_TAGGING_DOC, DELETE_BUCKET_ENCRYPTION_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketLifecycle",
        shadowed: "DeleteBucketEncryption",
        reason: "Two configuration deletes named in one DELETE, the lifecycle twin of the two \
                 pairs above. The earlier band wins (390 before 393), so only the lifecycle \
                 document is removed and the bucket keeps its default encryption.",
        evidence: &[DELETE_BUCKET_LIFECYCLE_DOC, DELETE_BUCKET_ENCRYPTION_DOC],
    },
    // The `?replication` band repeats the `?encryption` shape one slot later, packed at 394-396
    // for the same tens-aligned-slots-are-full reason. Four subresource triples now sit ahead of
    // it, so all three of its rows have same-method neighbours to order against — twelve
    // both-keys-at-once pairs — plus `?location` and the four listings on the GET side. The
    // last pair, against ListObjects, is the fallback relationship the debt register recorded
    // as `GetBucketReplication -> ListObjects` until this band landed.
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "GetBucketReplication",
        reason: "A request carrying both ?location and ?replication asks two subresource \
                 questions at once. AWS documents no such combination, so the answer is fixed \
                 here rather than left to source order: ?location at 300 is tried before \
                 ?replication at 394, and the replication reading is ignored rather than merged \
                 into the answer.",
        evidence: &[LOCATION_DOC, GET_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "GetBucketReplication",
        reason: "Two configuration subresources named in one GET. Neither is the narrower \
                 question, so the earlier band wins: ?cors at 310 is tried before ?replication \
                 at 394, the same first-band-wins rule ?location settled against ?cors.",
        evidence: &[GET_BUCKET_CORS_DOC, GET_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "GetBucketReplication",
        reason: "Two configuration subresources named in one GET, the same shape as the ?cors \
                 pair above with the tagging band in its place. The earlier band wins: ?tagging \
                 at 340 is tried before ?replication at 394, and the replication reading is \
                 ignored.",
        evidence: &[GET_BUCKET_TAGGING_DOC, GET_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLifecycleConfiguration",
        shadowed: "GetBucketReplication",
        reason: "Two configuration subresources named in one GET, the third same-method \
                 neighbour. The earlier band wins: ?lifecycle at 370 is tried before \
                 ?replication at 394, in the arrival order every subresource pair in the table \
                 follows.",
        evidence: &[GET_BUCKET_LIFECYCLE_DOC, GET_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketEncryption",
        shadowed: "GetBucketReplication",
        reason: "Two configuration subresources named in one GET, the fourth same-method \
                 neighbour — the first band to have one band packed directly behind it. The \
                 earlier band wins: ?encryption at 391 is tried before ?replication at 394, and \
                 the replication reading is ignored.",
        evidence: &[GET_BUCKET_ENCRYPTION_DOC, GET_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketReplication",
        shadowed: "ListMultipartUploads",
        reason: "?replication and ?uploads together name a configuration document and a listing \
                 of one bucket. The subresource band (394) is tried before the upload listing \
                 (460), the same order every earlier configuration band settled against the \
                 same neighbour.",
        evidence: &[GET_BUCKET_REPLICATION_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketReplication",
        shadowed: "ListObjectsV2",
        reason: "A request carrying ?replication and ?list-type=2 asks for the replication \
                 document and a page of keys at once. The configuration subresource is the \
                 narrower question and is tried first (394 before 600); the listing is ignored.",
        evidence: &[GET_BUCKET_REPLICATION_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketReplication",
        shadowed: "ListObjectVersions",
        reason: "Same shape as the pair above with the version listing in place of the key page: \
                 only a client sending ?replication and ?versions together reaches it, and the \
                 subresource band is tried first (394 before 610).",
        evidence: &[GET_BUCKET_REPLICATION_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketReplication",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?replication request also satisfies it. \
                 Until this row existed that was not a latent overlap but the served behaviour: \
                 a replication document request was answered with a key listing. The subresource \
                 is the specific reading and wins (394 before 700); the fallback stays last in \
                 the band.",
        evidence: &[GET_BUCKET_REPLICATION_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketCors",
        shadowed: "PutBucketReplication",
        reason: "Two configuration writes named in one PUT: a request carrying ?cors and \
                 ?replication satisfies both selectors, and AWS documents no such combination. \
                 The earlier band wins (320 before 395), so the body is read as a CORS document \
                 and the replication reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_CORS_DOC, PUT_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketTagging",
        shadowed: "PutBucketReplication",
        reason: "Two configuration writes named in one PUT, the tagging twin of the ?cors pair \
                 above. The earlier band wins (350 before 395), so the body is read as a \
                 tagging document and the replication reading is ignored rather than \
                 double-written.",
        evidence: &[PUT_BUCKET_TAGGING_DOC, PUT_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketLifecycleConfiguration",
        shadowed: "PutBucketReplication",
        reason: "Two configuration writes named in one PUT, the lifecycle twin of the two pairs \
                 above. The earlier band wins (380 before 395), so the body is read as a \
                 lifecycle document and the replication reading is ignored rather than \
                 double-written.",
        evidence: &[PUT_BUCKET_LIFECYCLE_DOC, PUT_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketEncryption",
        shadowed: "PutBucketReplication",
        reason: "Two configuration writes named in one PUT, the encryption twin of the three \
                 pairs above. The earlier band wins (392 before 395), so the body is read as an \
                 encryption document and the replication reading is ignored rather than \
                 double-written.",
        evidence: &[PUT_BUCKET_ENCRYPTION_DOC, PUT_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketCors",
        shadowed: "DeleteBucketReplication",
        reason: "Two configuration deletes named in one DELETE. The earlier band wins (330 \
                 before 396), so only the CORS document is removed: a request that destroys two \
                 configurations because it named two query keys would turn a typo into data \
                 loss.",
        evidence: &[DELETE_BUCKET_CORS_DOC, DELETE_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketTagging",
        shadowed: "DeleteBucketReplication",
        reason: "Two configuration deletes named in one DELETE, the tagging twin of the pair \
                 above. The earlier band wins (360 before 396), so only the tag set is removed \
                 and the replication document stays: silently severing cross-site replication \
                 because of a typo is the availability spelling of the data-loss rule.",
        evidence: &[DELETE_BUCKET_TAGGING_DOC, DELETE_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketLifecycle",
        shadowed: "DeleteBucketReplication",
        reason: "Two configuration deletes named in one DELETE, the lifecycle twin of the two \
                 pairs above. The earlier band wins (390 before 396), so only the lifecycle \
                 document is removed and the bucket keeps replicating.",
        evidence: &[DELETE_BUCKET_LIFECYCLE_DOC, DELETE_BUCKET_REPLICATION_DOC],
    },
    ShadowingDecl {
        winner: "DeleteBucketEncryption",
        shadowed: "DeleteBucketReplication",
        reason: "Two configuration deletes named in one DELETE, the encryption twin of the \
                 three pairs above. The earlier band wins (393 before 396), so only the \
                 encryption document is removed and the replication document stays.",
        evidence: &[DELETE_BUCKET_ENCRYPTION_DOC, DELETE_BUCKET_REPLICATION_DOC],
    },
    // The `?object-lock` pair packs behind the `?encryption` band at 397/398 — the next gap
    // slot, with 394-396 reserved for the family in flight beside it — and brings the fourth
    // subresource family's shape with a difference: there is no DELETE row, because the pinned
    // model defines no delete for a lock configuration. Object lock, once enabled, has no wire
    // spelling for "off", so the pair meets four same-method neighbours per method at most. The
    // last GET pair, against ListObjects, is the fallback relationship the debt register
    // recorded as `GetObjectLockConfiguration -> ListObjects` until this pair landed.
    ShadowingDecl {
        winner: "GetBucketLocation",
        shadowed: "GetObjectLockConfiguration",
        reason: "A request carrying both ?location and ?object-lock asks two subresource \
                 questions at once. AWS documents no such combination, so the answer is fixed \
                 here rather than left to source order: ?location at 300 is tried before \
                 ?object-lock at 397, and the lock reading is ignored rather than merged into \
                 the answer.",
        evidence: &[LOCATION_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketCors",
        shadowed: "GetObjectLockConfiguration",
        reason: "Two configuration subresources named in one GET. Neither is the narrower \
                 question, so the earlier band wins: ?cors at 310 is tried before ?object-lock \
                 at 397, the same first-band-wins rule every subresource pair follows.",
        evidence: &[GET_BUCKET_CORS_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketTagging",
        shadowed: "GetObjectLockConfiguration",
        reason: "Two configuration subresources named in one GET, the same shape as the ?cors \
                 pair above with the tagging band in its place. The earlier band wins: ?tagging \
                 at 340 is tried before ?object-lock at 397, and the lock reading is ignored.",
        evidence: &[GET_BUCKET_TAGGING_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketLifecycleConfiguration",
        shadowed: "GetObjectLockConfiguration",
        reason: "Two configuration subresources named in one GET, the third same-method \
                 neighbour. The earlier band wins: ?lifecycle at 370 is tried before \
                 ?object-lock at 397, in the arrival order every subresource pair follows.",
        evidence: &[GET_BUCKET_LIFECYCLE_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketEncryption",
        shadowed: "GetObjectLockConfiguration",
        reason: "Two configuration subresources named in one GET, the fourth same-method \
                 neighbour and the nearest: ?encryption at 391 is tried before ?object-lock at \
                 397, in the same packed corner of the band, and the lock reading is ignored.",
        evidence: &[GET_BUCKET_ENCRYPTION_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "GetBucketReplication",
        shadowed: "GetObjectLockConfiguration",
        reason: "Two configuration subresources named in one GET, and the closest pair in the \
                 table: ?replication at 394 and ?object-lock at 397 are three slots apart in the \
                 same packed corner. Neither is the narrower question, so the earlier band wins \
                 and the lock reading is ignored.",
        evidence: &[GET_BUCKET_REPLICATION_DOC, GET_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectLockConfiguration",
        shadowed: "ListMultipartUploads",
        reason: "?object-lock and ?uploads together name a configuration document and a listing \
                 of one bucket. The subresource band (397) is tried before the upload listing \
                 (460), the same order the three earlier configuration bands settled against \
                 the same neighbour.",
        evidence: &[GET_OBJECT_LOCK_CONFIGURATION_DOC, UPLOADS_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectLockConfiguration",
        shadowed: "ListObjectsV2",
        reason: "A request carrying ?object-lock and ?list-type=2 asks for the lock document \
                 and a page of keys at once. The configuration subresource is the narrower \
                 question and is tried first (397 before 600); the listing is ignored.",
        evidence: &[GET_OBJECT_LOCK_CONFIGURATION_DOC, LIST_V2_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectLockConfiguration",
        shadowed: "ListObjectVersions",
        reason: "Same shape as the pair above with the version listing in place of the key \
                 page: only a client sending ?object-lock and ?versions together reaches it, \
                 and the subresource band is tried first (397 before 610).",
        evidence: &[GET_OBJECT_LOCK_CONFIGURATION_DOC, VERSIONS_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectLockConfiguration",
        shadowed: "ListObjects",
        reason: "ListObjects pins no query key, so every ?object-lock request also satisfies \
                 it. Until this row existed that was not a latent overlap but the served \
                 behaviour: a WORM configuration request was answered with a key listing. The \
                 subresource is the specific reading and wins (397 before 700); the fallback \
                 stays last in the band.",
        evidence: &[GET_OBJECT_LOCK_CONFIGURATION_DOC, LIST_V1_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketCors",
        shadowed: "PutObjectLockConfiguration",
        reason: "Two configuration writes named in one PUT: a request carrying ?cors and \
                 ?object-lock satisfies both selectors, and AWS documents no such combination. \
                 The earlier band wins (320 before 398), so the body is read as a CORS document \
                 and the lock reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_CORS_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketTagging",
        shadowed: "PutObjectLockConfiguration",
        reason: "Two configuration writes named in one PUT, the tagging twin of the ?cors pair \
                 above. The earlier band wins (350 before 398), so the body is read as a \
                 tagging document and the lock reading is ignored rather than double-written.",
        evidence: &[PUT_BUCKET_TAGGING_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketLifecycleConfiguration",
        shadowed: "PutObjectLockConfiguration",
        reason: "Two configuration writes named in one PUT, the lifecycle twin of the two pairs \
                 above. The earlier band wins (380 before 398), so the body is read as a \
                 lifecycle document and the lock reading is ignored.",
        evidence: &[PUT_BUCKET_LIFECYCLE_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketEncryption",
        shadowed: "PutObjectLockConfiguration",
        reason: "Two configuration writes named in one PUT, the nearest neighbour in the packed \
                 corner of the band. The earlier band wins (392 before 398), so the body is \
                 read as an encryption document and the lock reading is ignored.",
        evidence: &[PUT_BUCKET_ENCRYPTION_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    },
    ShadowingDecl {
        winner: "PutBucketReplication",
        shadowed: "PutObjectLockConfiguration",
        reason: "Two configuration writes named in one PUT, the replication twin of the pair \
                 above. The earlier band wins (395 before 398), so the body is read as a \
                 replication document and the lock reading is ignored rather than \
                 double-written.",
        evidence: &[PUT_BUCKET_REPLICATION_DOC, PUT_OBJECT_LOCK_CONFIGURATION_DOC],
    },
];
