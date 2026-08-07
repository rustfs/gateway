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

//! The object-target half of the reviewed shadowing table.
//!
//! Responsible for: every [`ShadowingDecl`] whose overlapping selectors address an object — the
//! multipart refinements, the attributes row, the object `?tagging` band, the copy family, and
//! the `?retention` / `?legal-hold` rows. Split out of `shadowing.rs` along the request-target
//! seam when the table outgrew the 800-line file ceiling; `shadowing.rs` joins the two halves
//! back into the one slice every consumer reads.
//! NOT responsible for: bucket-target pairs (`shadowing_bucket.rs`), the declaration types or
//! the policy (`shadowing.rs`), or computing overlap (`lattice.rs`).
//! Upstream: `super::evidence`, the URL constants every declaration cites. Downstream:
//! `super::shadowing`, the only reader.

use super::evidence::*;
use super::shadowing::ShadowingDecl;

/// The object-target declarations, in the band order the table tries them.
pub(super) const DECLS: &[ShadowingDecl] = &[
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
    // The `?retention` and `?legal-hold` rows are the `?tagging` band's shape again, at
    // 510-540, with the same data-loss stakes and a compliance meaning on top: before these
    // rows existed a retention write stored the `<Retention>` document *as the object* —
    // destroying the object it meant to protect — and the reads answered the object's bytes.
    // Four rows, two methods each for two subresources, and no DELETE: lifting a hold is
    // spelled `Status: OFF`, not a delete. The twenty pairs below record both edges of the
    // band — multipart is still tried first, the subresource still beats the plain object
    // operation — plus the two both-keys-at-once orders inside the family.
    ShadowingDecl {
        winner: "ListParts",
        shadowed: "GetObjectRetention",
        reason: "A GET on an object key carrying both ?uploadId and ?retention asks for the \
                 parts of an in-progress upload and for the committed object's retention at \
                 once. AWS documents no such combination, so the multipart band (440) is tried \
                 before the retention row (510) — the same order the attributes and tagging \
                 rows settled, kept rather than inverted for one family.",
        evidence: &[LIST_PARTS_DOC, GET_OBJECT_RETENTION_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectAttributes",
        shadowed: "GetObjectRetention",
        reason: "?attributes and ?retention are two subresources of one object, and a request \
                 sending both asks for two different documents. Neither is a refinement of the \
                 other, so the band decides: attributes at 470 is tried before retention at \
                 510, fixed here so that source order does not decide it instead.",
        evidence: &[OBJECT_ATTRIBUTES_DOC, GET_OBJECT_RETENTION_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectTagging",
        shadowed: "GetObjectRetention",
        reason: "?tagging and ?retention are two subresources of one object. The earlier band \
                 wins: tagging at 480 is tried before retention at 510, the same arrival-order \
                 rule the attributes pair above follows.",
        evidence: &[GET_OBJECT_TAGGING_DOC, GET_OBJECT_RETENTION_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectRetention",
        shadowed: "GetObjectLegalHold",
        reason: "?retention and ?legal-hold together name both halves of the object-lock state \
                 in one GET. AWS documents no such combination, and the two answers have \
                 different roots, so one must win: the retention row arrived first in the band \
                 (510 before 530), and the hold reading is ignored.",
        evidence: &[GET_OBJECT_RETENTION_DOC, GET_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectRetention",
        shadowed: "GetObject",
        reason: "Reading a retention document is a GET to the object key plus ?retention, and \
                 GetObject accepts every such request. GetObjectRetention is tried first (510 \
                 before 900). The other order is the disclosure the attributes and tagging rows \
                 already recorded: the caller asked for a compliance document and would receive \
                 the object's bytes.",
        evidence: &[GET_OBJECT_RETENTION_DOC, GET_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "ListParts",
        shadowed: "GetObjectLegalHold",
        reason: "The retention pair's shape one subresource over: ?uploadId and ?legal-hold \
                 together reach both rows, AWS documents no such combination, and the multipart \
                 band (440) is tried before the legal-hold row (530).",
        evidence: &[LIST_PARTS_DOC, GET_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectAttributes",
        shadowed: "GetObjectLegalHold",
        reason: "?attributes and ?legal-hold are two subresources of one object. The band \
                 decides: attributes at 470 is tried before legal-hold at 530.",
        evidence: &[OBJECT_ATTRIBUTES_DOC, GET_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectTagging",
        shadowed: "GetObjectLegalHold",
        reason: "?tagging and ?legal-hold are two subresources of one object. The earlier band \
                 wins: tagging at 480 is tried before legal-hold at 530.",
        evidence: &[GET_OBJECT_TAGGING_DOC, GET_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "GetObjectLegalHold",
        shadowed: "GetObject",
        reason: "Reading a legal hold is a GET to the object key plus ?legal-hold, and \
                 GetObject accepts every such request. GetObjectLegalHold is tried first (530 \
                 before 900); the other order answers a hold-status request with the object's \
                 bytes.",
        evidence: &[GET_OBJECT_LEGAL_HOLD_DOC, GET_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "UploadPartCopy",
        shadowed: "PutObjectRetention",
        reason: "A PUT naming a part, an upload, a copy source and ?retention satisfies both. \
                 The part copy is the reading with three discriminators to the retention row's \
                 one, and the multipart band (400) is tried first. The retention reading is \
                 ignored rather than applied to the part.",
        evidence: &[UPLOAD_PART_COPY_DOC, PUT_OBJECT_RETENTION_DOC],
    },
    ShadowingDecl {
        winner: "UploadPart",
        shadowed: "PutObjectRetention",
        reason: "The same pair without the copy source: ?partNumber and ?uploadId alongside \
                 ?retention name a part upload and a retention write at once. The multipart \
                 band (410) is tried before the retention row (520), so the body is read as the \
                 part it is framed as rather than parsed as XML.",
        evidence: &[UPLOAD_PART_DOC, PUT_OBJECT_RETENTION_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectTagging",
        shadowed: "PutObjectRetention",
        reason: "PUT /b/k?tagging&retention carries one body and names two documents to \
                 replace with it, which cannot both be meant. The earlier band wins (490 before \
                 520): the body is read as the tagging document it would have to be for the \
                 winning row, and the retention reading is ignored rather than applied to a \
                 document of the wrong shape.",
        evidence: &[PUT_OBJECT_TAGGING_DOC, PUT_OBJECT_RETENTION_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectRetention",
        shadowed: "PutObjectLegalHold",
        reason: "?retention and ?legal-hold in one PUT name both halves of the object-lock \
                 state and carry one body. The retention row arrived first in the band (520 \
                 before 540), matching the GET pair, so the body is read as a Retention \
                 document and the hold reading is ignored.",
        evidence: &[PUT_OBJECT_RETENTION_DOC, PUT_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectRetention",
        shadowed: "CopyObject",
        reason: "A PUT to an object key carrying x-amz-copy-source and ?retention satisfies \
                 both, and neither selector refines the other. The retention row is tried first \
                 (520 before 790), which is the safe half of the pair: the other order would \
                 perform the copy, overwrite the destination from the source, and discard the \
                 retention document the request actually carried.",
        evidence: &[PUT_OBJECT_RETENTION_DOC, COPY_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectRetention",
        shadowed: "PutObject",
        reason: "Placing a retention is a PUT to the object key plus ?retention, and \
                 PutObject's selector is the method and the target and nothing else. \
                 PutObjectRetention is tried first (520 before 800). The other order is \
                 destruction with a compliance meaning: PutObject would store the <Retention> \
                 document as the object's body and answer 200, so a caller protecting an object \
                 would destroy it.",
        evidence: &[PUT_OBJECT_RETENTION_DOC, PUT_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "UploadPartCopy",
        shadowed: "PutObjectLegalHold",
        reason: "The retention pair's shape one subresource over: a part copy carrying \
                 ?legal-hold reaches both rows, and the multipart band (400) is tried first.",
        evidence: &[UPLOAD_PART_COPY_DOC, PUT_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "UploadPart",
        shadowed: "PutObjectLegalHold",
        reason: "?partNumber and ?uploadId alongside ?legal-hold name a part upload and a hold \
                 write at once. The multipart band (410) is tried before the legal-hold row \
                 (540), so the body is read as the part it is framed as.",
        evidence: &[UPLOAD_PART_DOC, PUT_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectTagging",
        shadowed: "PutObjectLegalHold",
        reason: "PUT /b/k?tagging&legal-hold carries one body and names two documents. The \
                 earlier band wins (490 before 540), the same rule as the retention twin.",
        evidence: &[PUT_OBJECT_TAGGING_DOC, PUT_OBJECT_LEGAL_HOLD_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectLegalHold",
        shadowed: "CopyObject",
        reason: "A PUT carrying x-amz-copy-source and ?legal-hold satisfies both, and neither \
                 selector refines the other. The legal-hold row is tried first (540 before \
                 790): the other order would perform the copy and discard the hold document the \
                 request actually carried.",
        evidence: &[PUT_OBJECT_LEGAL_HOLD_DOC, COPY_OBJECT_DOC],
    },
    ShadowingDecl {
        winner: "PutObjectLegalHold",
        shadowed: "PutObject",
        reason: "Placing a legal hold is a PUT to the object key plus ?legal-hold, and \
                 PutObject accepts every such request. PutObjectLegalHold is tried first (540 \
                 before 800). The other order stores the <LegalHold> document as the object's \
                 body — destroying the object a court told somebody to keep, with a 200.",
        evidence: &[PUT_OBJECT_LEGAL_HOLD_DOC, PUT_OBJECT_DOC],
    },
];
