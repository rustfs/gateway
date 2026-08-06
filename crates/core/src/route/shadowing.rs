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
];

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

/// AWS's own reference for the plain object read.
const GET_OBJECT_DOC: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html \
     — an object read is the same method and path with no upload id.";
