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

//! The reviewed record of which route wins when two of them accept the same request.
//!
//! Responsible for: [`ShadowingDecl`] (winner, shadowed, reason, evidence), the collection type
//! the table consults, and [`ShadowingPolicy`] — how much of the overlap surface must be declared.
//! NOT responsible for: computing overlap (`lattice`), or the same-precedence case, which is never
//! a declaration and always a build failure (`table`).
//! Upstream: nothing. Downstream: `table`, `explain`.
//!
//! # Where these belong
//!
//! The issue places the declarations in `model/overlays/route.toml`, the one sanctioned
//! hand-written protocol-exception source, loaded by codegen. That file is outside this task's
//! file scope, so [`PROVISIONAL_SHADOWING`] carries the declarations the generated table needs
//! today, in the same four fields the overlay will use, with the loader left to P4-06. It is one
//! declaration; the type, not the storage, is what the rest of the crate depends on.

/// One reviewed decision: this operation wins over that one, and here is why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowingDecl {
    /// The operation with the lower (earlier) precedence.
    pub winner: &'static str,
    /// The operation it hides for the overlapping requests.
    pub shadowed: &'static str,
    /// Why this order is correct. Written by a human; read by whoever changes the order.
    pub reason: &'static str,
    /// Where the reason comes from. Must be non-empty: an unsourced ordering is a guess.
    pub evidence: &'static [&'static str],
}

/// How much of the cross-precedence overlap surface must be declared.
///
/// # The trade-off, stated rather than buried
///
/// [`EveryOverlap`](ShadowingPolicy::EveryOverlap) is what the design asks for and what this crate
/// defaults to: every cross-precedence overlap is a reviewed decision. It is also quadratic. Once
/// all thirty-odd bucket subresources are in the table, every `?acl` / `?tagging` pair overlaps —
/// a client would have to send both keys in one request to reach it — and the strict policy asks
/// for several hundred declarations that all say the same thing.
///
/// [`TotalOnly`](ShadowingPolicy::TotalOnly) keeps the guarantee that matters and drops the
/// paperwork that does not: a declaration is required only when the shadowed selector accepts
/// *nothing* the winner does not also accept, which is the case where the shadowed route is
/// unreachable — a dead operation, the `?analytics` with and without `id` defect. Partial overlaps
/// remain legal, are still reported by `explain`, and are still stable across releases because
/// precedence, not source order, decides them.
///
/// Switching the default is a maintainer decision, which is why both exist and neither is hidden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ShadowingPolicy {
    /// Every cross-precedence overlap needs a declaration.
    #[default]
    EveryOverlap,
    /// Only an overlap that makes the shadowed route unreachable needs a declaration.
    TotalOnly,
}

/// The declarations a table is checked against.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShadowingDecls {
    decls: &'static [ShadowingDecl],
    policy: ShadowingPolicy,
}

impl ShadowingDecls {
    /// An empty set: every cross-precedence overlap will be reported as undeclared.
    pub const NONE: Self = Self {
        decls: &[],
        policy: ShadowingPolicy::EveryOverlap,
    };

    /// Wraps a static declaration list.
    #[must_use]
    pub const fn new(decls: &'static [ShadowingDecl]) -> Self {
        Self {
            decls,
            policy: ShadowingPolicy::EveryOverlap,
        }
    }

    /// The same declarations under a different policy. See [`ShadowingPolicy`].
    #[must_use]
    pub const fn with_policy(mut self, policy: ShadowingPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> ShadowingPolicy {
        self.policy
    }

    /// Every declaration, in source order.
    #[must_use]
    pub const fn all(&self) -> &'static [ShadowingDecl] {
        self.decls
    }

    /// The declaration covering this ordered pair, if there is one.
    #[must_use]
    pub fn find(&self, winner: &str, shadowed: &str) -> Option<&'static ShadowingDecl> {
        self.decls
            .iter()
            .find(|decl| decl.winner == winner && decl.shadowed == shadowed)
    }
}

/// The declarations the generated table needs today.
///
/// Every entry is the same shape: two bucket-level operations distinguished by different query
/// keys, reachable together only by a client that sends both keys at once. Precedence, which
/// codegen assigns, decides the winner; a row here records that somebody looked at it and agreed.
///
/// The listing family adds one wrinkle the subresources do not have. `ListObjects` is the meaning
/// of a `GET` on a bucket that nothing else claimed, so its selector pins no query key and it
/// therefore overlaps every other bucket-level `GET` in the table. It is last in the band for
/// exactly that reason, and the rows below are what "last" is allowed to mean.
pub static PROVISIONAL_SHADOWING: &[ShadowingDecl] = &[
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
    // The multipart family adds the second shape. `PUT /b/k?partNumber&uploadId` is every request
    // `PutObject` accepts, plus two query keys — a strict refinement of a plain object operation
    // rather than two subresources meeting by accident. The overlap is the design, and each row
    // below records that the narrow entry is deliberately tried first.
    ShadowingDecl {
        winner: "UploadPart",
        shadowed: "PutObject",
        reason: "Every part upload is a PUT to an object key, so PutObject's selector accepts it \
                 too. The model spells this operation /{Bucket}/{Key+}?x-id=UploadPart and x-id is \
                 inert, so partNumber and uploadId are declared as its discriminators in the \
                 overlay and put it at 410, ahead of PutObject at 800. The other order is not a \
                 style choice: it would write a part over the object it is a part of.",
        evidence: &[UPLOAD_PART_DOC, PUT_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "CompleteMultipartUpload",
        shadowed: "CreateMultipartUpload",
        reason: "A POST to an object key carrying both ?uploads and ?uploadId asks to start and to \
                 finish an upload at once. Completion is the narrower question — it names an upload \
                 that already exists — so it is tried first (420 before 450), and the initiation is \
                 ignored rather than performed as a side effect.",
        evidence: &[COMPLETE_MPU_DOC, CREATE_MPU_DOC],
    },
    ShadowingDecl {
        winner: "AbortMultipartUpload",
        shadowed: "DeleteObject",
        reason: "The same refinement as UploadPart over PutObject, in the DELETE method: an abort \
                 is a DELETE to the object key plus ?uploadId, and DeleteObject accepts every such \
                 request. Abort is tried first (430 before 1000). The other order would delete the \
                 object the upload was never merged into, and answer a success for it.",
        evidence: &[ABORT_MPU_DOC, DELETE_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "ListParts",
        shadowed: "GetObject",
        reason: "Listing the parts of an upload is a GET to the object key plus ?uploadId, and \
                 GetObject accepts every such request. ListParts is tried first (440 before 900). \
                 The other order would answer a listing request with the object's bytes — or, in \
                 the common case where the object does not exist yet, with a not-found error.",
        evidence: &[LIST_PARTS_DOC, GET_OBJECT_DOC],
    },
    // The attributes operation is the fourth shape, and the reason it is in the table at all.
    // `?attributes` is one query key away from a plain object read, so with no row of its own the
    // request is not refused — it is answered by `GetObject`, with the object's bytes. Both rows
    // below record that the narrow reading is deliberately tried first, whether or not this build
    // has a handler for it: an operation the protocol defines answers "not implemented", never
    // another operation's payload.
    ShadowingDecl {
        winner: "ListParts",
        shadowed: "GetObjectAttributes",
        reason: "A GET on an object key carrying both ?uploadId and ?attributes asks for the parts \
                 of an in-progress upload and for the attributes of the committed object at once. \
                 AWS documents no such combination, so the answer is fixed here rather than left to \
                 source order: the multipart band (440) is tried before the attributes row (470), \
                 and the attributes reading is ignored rather than merged into the answer.",
        evidence: &[LIST_PARTS_DOC, OBJECT_ATTRIBUTES_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectAttributes",
        shadowed: "GetObject",
        reason: "Reading an object's attributes is a GET to the object key plus ?attributes, and \
                 GetObject accepts every such request. GetObjectAttributes is tried first (470 \
                 before 900). The other order is not a mis-route but a disclosure: the caller asked \
                 for metadata and would receive the object's bytes, under GetObject's content type \
                 and entity tag, with no signal that a different operation answered.",
        evidence: &[OBJECT_ATTRIBUTES_DOC, GET_OBJECT_DOC],
    },
    // The `?tagging` band is the attributes shape again, in all three methods at once — and it is
    // the family where the missing rows cost more than a disclosure. `PutObject` and `DeleteObject`
    // pin nothing but a method and a target, so before these rows existed a tagging write stored the
    // `<Tagging>` document *as the object* and a tagging delete removed *the object*. The nine rows
    // below record both edges of the band: the multipart operations are still tried first, and the
    // subresource still beats the plain object operation it is one query key away from.
    ShadowingDecl {
        winner: "ListParts",
        shadowed: "GetObjectTagging",
        reason: "A GET on an object key carrying both ?uploadId and ?tagging asks for the parts of \
                 an in-progress upload and for the committed object's tag set at once. AWS documents \
                 no such combination, so the multipart band (440) is tried before the tagging row \
                 (480) — the same order the attributes row settled at 470, kept rather than inverted \
                 for one family.",
        evidence: &[LIST_PARTS_DOC, GET_OBJECT_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectAttributes",
        shadowed: "GetObjectTagging",
        reason: "?attributes and ?tagging are two subresources of one object, and a request sending \
                 both asks for two different documents. Neither is a refinement of the other, so the \
                 band decides: attributes at 470 is tried before tagging at 480. The order is \
                 arbitrary in the sense that AWS documents neither, and fixed here so that it is not \
                 decided by source order instead.",
        evidence: &[OBJECT_ATTRIBUTES_DOC, GET_OBJECT_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectTagging",
        shadowed: "GetObject",
        reason: "Reading a tag set is a GET to the object key plus ?tagging, and GetObject accepts \
                 every such request. GetObjectTagging is tried first (480 before 900). The other \
                 order is the disclosure the attributes row already recorded, under a second \
                 subresource: the caller asked for labels and would receive the object's bytes.",
        evidence: &[GET_OBJECT_TAGGING_DOC, GET_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "UploadPartCopy",
        shadowed: "PutObjectTagging",
        reason: "A PUT naming a part, an upload, a copy source and ?tagging satisfies both. The part \
                 copy is the reading with three discriminators to the tagging row's one, and the \
                 multipart band (400) is tried first. The tagging reading is ignored rather than \
                 applied to the part.",
        evidence: &[UPLOAD_PART_COPY_DOC, PUT_OBJECT_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "UploadPart",
        shadowed: "PutObjectTagging",
        reason: "The same pair without the copy source: ?partNumber and ?uploadId alongside ?tagging \
                 name a part upload and a tag-set replacement at once. AWS documents no such \
                 request; the multipart band (410) is tried before the tagging row (490), so the \
                 body is read as the part it is framed as rather than parsed as XML.",
        evidence: &[UPLOAD_PART_DOC, PUT_OBJECT_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectTagging",
        shadowed: "CopyObject",
        reason: "A PUT to an object key carrying x-amz-copy-source and ?tagging satisfies both, and \
                 neither selector refines the other. The tagging row is tried first (490 before \
                 790), which is the safe half of the pair: the other order would perform the copy, \
                 overwrite the destination from the source, and discard the tagging document the \
                 request actually carried. x-amz-tagging-directive is how a copy manages tags; the \
                 ?tagging subresource is a different operation and not a modifier of this one.",
        evidence: &[PUT_OBJECT_TAGGING_DOC, COPY_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectTagging",
        shadowed: "PutObject",
        reason: "Replacing a tag set is a PUT to the object key plus ?tagging, and PutObject's \
                 selector is the method and the target and nothing else. PutObjectTagging is tried \
                 first (490 before 800). The other order is destruction rather than a mis-route: \
                 PutObject would store the <Tagging> document as the object's body and answer 200, \
                 so a caller relabelling an object would lose it.",
        evidence: &[PUT_OBJECT_TAGGING_DOC, PUT_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "AbortMultipartUpload",
        shadowed: "DeleteObjectTagging",
        reason: "A DELETE on an object key carrying both ?uploadId and ?tagging asks to discard an \
                 upload and to clear the committed object's tags at once. The multipart band (430) \
                 is tried before the tagging row (500), matching the GET and PUT halves of this \
                 band.",
        evidence: &[ABORT_MPU_DOC, DELETE_OBJECT_TAGGING_DOC],
    },
    ShadowingDecl {
        winner: "DeleteObjectTagging",
        shadowed: "DeleteObject",
        reason: "Clearing a tag set is a DELETE to the object key plus ?tagging, and DeleteObject \
                 accepts every such request. DeleteObjectTagging is tried first (500 before 1000). \
                 The other order is the worst outcome in the table: the object itself is removed, \
                 and the 204 a successful untag answers with is indistinguishable from the 204 the \
                 delete answers with.",
        evidence: &[DELETE_OBJECT_TAGGING_DOC, DELETE_OBJECT_DOC],
    },
    // The `?cors` band is the bucket-subresource shape in one method: only the GET row overlaps
    // anything, because PUT and DELETE on a bucket have no other row to meet. Four of the five
    // pairs are the familiar both-keys-at-once accident; the fifth — against ListObjects — is the
    // fallback relationship, and it is the pair the debt register recorded as
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
    // The copy family adds the third shape: one header's presence, and nothing else, separates two
    // operations that share a method and a path. Every row but the last is a refinement — the
    // winner's selector is the loser's plus `x-amz-copy-source` — so the overlap is the design
    // rather than an accident, and the order is what keeps a copy from being executed as a write
    // of an empty body.
    ShadowingDecl {
        winner: "CopyObject",
        shadowed: "PutObject",
        reason: "A copy is a PUT to an object key carrying x-amz-copy-source, so PutObject's \
                 selector accepts it too. The header is the whole discriminator, which puts \
                 CopyObject at 790, ahead of PutObject at 800. The other order is data loss rather \
                 than a mis-route: a copy carries no request body, so PutObject would answer a \
                 success after replacing the destination with zero bytes.",
        evidence: &[COPY_OBJECT_DOC, PUT_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "UploadPartCopy",
        shadowed: "UploadPart",
        reason: "A part copy is a part upload plus x-amz-copy-source, so UploadPart accepts every \
                 request UploadPartCopy does. The copy is the narrower reading and is tried first \
                 (400 before 410) — the precedence ops/multipart.toml reserved for it. The other \
                 order would store the empty request body as the part and report its digest as the \
                 copied range's.",
        evidence: &[UPLOAD_PART_COPY_DOC, UPLOAD_PART_DOC],
    },
    ShadowingDecl {
        winner: "UploadPartCopy",
        shadowed: "CopyObject",
        reason: "A part copy carries x-amz-copy-source, which is the whole of CopyObject's own \
                 discriminator, so the two meet on any PUT that also names a part and an upload. \
                 The part copy is the narrower reading and wins at 400. The other order would \
                 commit the copy as a whole object at the upload's key, bypassing the upload.",
        evidence: &[UPLOAD_PART_COPY_DOC, COPY_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "UploadPartCopy",
        shadowed: "PutObject",
        reason: "The transitive case of the two rows above: a part copy satisfies PutObject's \
                 selector as well, because PutObject pins nothing but the method and the target. \
                 It is recorded rather than inferred, so that removing either intermediate row \
                 cannot silently leave this pair undeclared.",
        evidence: &[UPLOAD_PART_COPY_DOC, PUT_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "UploadPart",
        shadowed: "CopyObject",
        reason: "A PUT naming a part, an upload and a copy source satisfies both. This is the one \
                 pair in the family neither selector resolves by refinement — neither contains the \
                 other — so it is resolved by the band: the multipart band (410) is tried before \
                 the object band (790). In practice UploadPartCopy at 400 claims every such \
                 request first, and this row records what the table would do if it did not.",
        evidence: &[UPLOAD_PART_DOC, COPY_OBJECT_DOC],
    },
];

/// AWS's own reference for the server-side object copy.
const COPY_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html \
     — a copy is a PUT to the destination key whose source is named by a header, and which carries no request body.";

/// AWS's own reference for the part copy.
const UPLOAD_PART_COPY_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html \
     — a part copy is a part upload whose bytes come from a source object named by a header rather than from the body.";

/// AWS's own reference for the CORS document read.
const GET_BUCKET_CORS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketCors.html \
     — GetBucketCors is selected by the ?cors subresource alone and answers with the stored configuration document.";

/// AWS's own reference for the operation selected by the `?location` subresource.
const LOCATION_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html \
     — GetBucketLocation is selected by the ?location subresource alone and takes no other query input.";

/// AWS's own reference for the version listing.
const VERSIONS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectVersions.html \
     — ListObjectVersions is selected by the ?versions subresource and ignores query keys it does not define.";

/// AWS's own reference for the first key listing.
const LIST_V1_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjects.html \
     — ListObjects is what a GET on a bucket means when no other subresource claimed it, so it pins no query key.";

/// AWS's own reference for the second key listing.
const LIST_V2_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html \
     — ListObjectsV2 is selected by list-type=2 and treats unrecognised query keys as inert.";

/// AWS's own reference for the in-progress upload listing.
const UPLOADS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html \
     — ListMultipartUploads is selected by the ?uploads subresource and defines no other selector.";

/// AWS's own reference for the part upload.
const UPLOAD_PART_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html \
     — a part upload is a PUT to the object key carrying the part number and the upload id as query parameters.";

/// AWS's own reference for the plain object write.
const PUT_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html \
     — a plain object write is the same method and path with neither of those parameters.";

/// AWS's own reference for the completion of an upload.
const COMPLETE_MPU_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html \
     — completion is a POST to the object key carrying the upload id.";

/// AWS's own reference for the initiation of an upload.
const CREATE_MPU_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html \
     — initiation is a POST to the object key carrying the ?uploads subresource and no upload id.";

/// AWS's own reference for discarding an upload.
const ABORT_MPU_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html \
     — an abort is a DELETE to the object key carrying the upload id as a query parameter.";

/// AWS's own reference for the plain object delete.
const DELETE_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObject.html \
     — an object delete is the same method and path with no upload id.";

/// AWS's own reference for the part listing.
const LIST_PARTS_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html \
     — a part listing is a GET to the object key carrying the upload id as a query parameter.";

/// AWS's own reference for the attributes read.
const OBJECT_ATTRIBUTES_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html \
     — an attributes read is a GET to the object key carrying the ?attributes subresource, and it answers with metadata rather than with the object.";

/// AWS's own reference for the tag-set read.
const GET_OBJECT_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectTagging.html \
     — a tag-set read is a GET to the object key carrying the ?tagging subresource, and it answers with the tag set rather than with the object.";

/// AWS's own reference for the tag-set replacement.
const PUT_OBJECT_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectTagging.html \
     — a tag-set write is a PUT to the object key carrying the ?tagging subresource, and its body is a tagging document rather than object data.";

/// AWS's own reference for the tag-set removal.
const DELETE_OBJECT_TAGGING_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteObjectTagging.html \
     — a tag-set removal is a DELETE to the object key carrying the ?tagging subresource, and it leaves the object in place.";

/// AWS's own reference for the plain object read.
const GET_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html \
     — an object read is the same method and path with no upload id.";
