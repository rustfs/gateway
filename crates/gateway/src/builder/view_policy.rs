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

//! The RustFS-profile readings an assembly applies to the view every codec reads, and the codes
//! it answers a body-integrity refusal with (rustfs/backlog#1677): the switches that make a RustFS
//! deployment answer a request the way RustFS answers it today, where the core keeps the AWS-model
//! answer as its default.
//!
//! Responsible for: [`ServiceBuilder::clamp_oversized_max_keys`],
//! [`ServiceBuilder::answer_checksum_failures_with_bad_digest`],
//! [`ServiceBuilder::ignore_unknown_checksum_algorithms`],
//! [`ServiceBuilder::sign_presigned_payloads_as_unsigned`],
//! [`ServiceBuilder::sign_base64_payload_digests_as_hex`],
//! [`ServiceBuilder::accept_empty_uploads_without_content_length`],
//! [`ServiceBuilder::url_encode_listings_like_rustfs`] and
//! [`ServiceBuilder::read_empty_headers_as_absent`], the closed sets of operations the first and
//! the listing and upload switches cover, and the per-request decisions the assembly applies — the client checksum
//! waivers of `super::client_quirks` included.
//! NOT responsible for: reading the parameter ([`rustfs_gateway_core::MetaView::query`]) or the
//! modelled range the default refuses outside of (the generated codec).
//! Upstream: `super::ServiceBuilder`. Downstream: `crate::service`, which applies [`ViewPolicy`]
//! to the view every decoder reads.
//!
//! # Why an oversized `max-keys` is clamped, and on exactly these listings
//!
//! Legacy RustFS takes `max-keys` as any 32-bit integer, refuses a negative one with
//! `InvalidArgument`, and lowers anything above 1000 to 1000 before it lists or echoes it
//! (rustfs/rustfs@1e7065101d `rustfs/src/storage/s3_api/bucket.rs:40-42` `normalize_max_keys`,
//! `:121-145` and `:147-165`, the two `parse_list_*_params` functions; the clamped value is the
//! one listed and echoed, `rustfs/src/app/bucket_usecase.rs:1071` and `:1160`). `ListObjects`
//! goes through the same ListObjectsV2 path (`bucket_usecase.rs:3109-3119`). Hadoop S3A pages
//! at 5000 by default, and the RustFS e2e suite pages ListObjectsV2 at 1001.
//!
//! The core keeps `q-max-keys-0073` as the default: ListObjectsV2 refuses a value above the ceiling
//! (`c-list-0028`). The RustFS profile clamps it instead, and clamps the other two listings too,
//! which the core hands to the backend as sent, so the page a backend serves and the
//! `<MaxKeys>` it echoes are the ones RustFS serves and echoes.
//!
//! `max-uploads` and `max-parts` are deliberately not here: RustFS refuses a value outside
//! `1..=1000` for both (`rustfs/src/storage/s3_api/multipart.rs`, `parse_list_parts_params` and
//! `parse_list_multipart_uploads_params`) after its access check, and the core hands both to the
//! backend as sent, so a RustFS backend already gives RustFS's answer in RustFS's order. Clamping
//! them here would serve a page RustFS refuses.
//!
//! # Why an upload with no length is read as empty, and only when the transport says it is
//!
//! A `PutObject` or `UploadPart` with neither `Content-Length` nor `Transfer-Encoding` has a
//! zero-length body on HTTP/1.1 (RFC 9112 §6.3), and an HTTP/2 request whose headers ended the
//! stream has none either. Legacy RustFS stores such an upload as an empty object: a signed empty
//! `PutObject` without `Content-Length` answers `200` with the empty-body `ETag`, and `HEAD` then
//! reports `Content-Length: 0` (rustfs/rustfs#6849, pinned by RustFS's
//! `crates/e2e_test/src/put_object_no_content_length_test.rs:90-129` on rustfs/rustfs
//! `e870a6d25b`; observed against a legacy RustFS build over HTTP/1.1 and HTTP/2). The core keeps
//! the AWS answer, `411 MissingContentLength` (`q-length-0007`, rd-put-0003). The RustFS profile
//! reads the absent header as `0` instead — only for [`EMPTY_UPLOAD_OPERATIONS`], and only when
//! the request carries no transfer coding and the body itself reports an exact length of zero,
//! so a chunked transfer or an HTTP/2 stream still carrying data is refused with `411` exactly as
//! RustFS refuses it.

// Declared here rather than in `builder.rs`, which is at its size limit: the POST form grammar is one
// more RustFS-profile switch this policy holds.
#[path = "post_forms.rs"]
pub(crate) mod post_forms;

use super::ServiceBuilder;
use super::bodyless_digest::BodylessDigest;
use super::client_quirks::ChecksumWaiver;
use super::credential_sentences::CredentialSentences;
use super::legacy_heads::AnswerHeads;
use super::legacy_sentences::BodySentences;
use super::sigv4_header_guard::SigV4HeaderGuard;
use crate::integrity::IntegrityCodes;
use crate::render::{S3Error, from_wire_reject};
use rustfs_gateway_core::codec::value::RustFsListing;
use rustfs_gateway_core::{EncodedResponse, HandlerError, MetaView, PageSizeCeiling};
use rustfs_gateway_http::{HeaderView, WireReject};
use rustfs_gateway_sig::PayloadMode;

mod date_conditions;
pub(crate) mod header_signatures;
pub use self::date_conditions::STRICT_DATE_CONDITION_HEADERS;

/// The page size RustFS lowers an oversized `max-keys` to (`S3_MAX_KEYS`).
pub const RUSTFS_MAX_KEYS_CEILING: i32 = 1000;

/// The listings whose `max-keys` the RustFS profile clamps, and no others.
pub const CLAMPED_MAX_KEYS_OPERATIONS: [&str; 3] = ["ListObjects", "ListObjectVersions", "ListObjectsV2"];

/// The `max-keys` ceiling, as the view applies it.
const MAX_KEYS: PageSizeCeiling = PageSizeCeiling::new("max-keys", RUSTFS_MAX_KEYS_CEILING);

/// The uploads whose absent `Content-Length` the RustFS profile reads as `0` when the transport
/// already ended the body empty, and no others: the two that require the header.
pub const EMPTY_UPLOAD_OPERATIONS: [&str; 2] = ["PutObject", "UploadPart"];
/// The operations whose MinIO body literal the RustFS profile reads, and no others: the two whose
/// IR says `xml.body_literal`, as legacy RustFS reads them (rustfs/backlog#1677, R6).
pub const BODY_LITERAL_OPERATIONS: [&str; 2] = ["PutBucketVersioning", "PutObjectLockConfiguration"];

/// Legacy RustFS's `encoding-type=url` rule, per listing: the members it percent-encodes (a root
/// member by name, a nested one as `Shape.Member`) and whether it echoes `encoding-type`.
///
/// rustfs/rustfs@1e7065101d: ListObjectsV2 encodes only each key and each rolled-up prefix
/// (`rustfs/src/storage/s3_api/bucket.rs:296-333`); ListObjects inherits those and encodes
/// `NextMarker` (`:361-411`); ListObjectVersions encodes every key-shaped member (`:212-279`); all
/// three echo the request's value (`:267`, `:353`, `:92`). ListMultipartUploads drops the
/// parameter and neither encodes nor echoes (`rustfs/src/app/multipart_usecase.rs:1519-1527`,
/// `rustfs/src/storage/s3_api/multipart.rs:164-205`), and ListParts has no parameter at all.
pub const RUSTFS_LISTING_ENCODINGS: [(&str, RustFsListing); 5] = [
    (
        "ListObjects",
        RustFsListing::new(&["Object.Key", "CommonPrefix.Prefix", "NextMarker"], true),
    ),
    ("ListObjectsV2", RustFsListing::new(&["Object.Key", "CommonPrefix.Prefix"], true)),
    (
        "ListObjectVersions",
        RustFsListing::new(
            &[
                "Prefix",
                "Delimiter",
                "KeyMarker",
                "NextKeyMarker",
                "ObjectVersion.Key",
                "DeleteMarkerEntry.Key",
                "CommonPrefix.Prefix",
            ],
            true,
        ),
    ),
    ("ListMultipartUploads", RustFsListing::new(&[], false)),
    ("ListParts", RustFsListing::new(&[], false)),
];

/// Which RustFS-profile readings this assembly applies to a routed view.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ViewPolicy {
    /// The client checksum waivers (`super::client_quirks`).
    pub(super) checksum_waiver: ChecksumWaiver,
    /// The sentences a request-body refusal is answered with (`super::legacy_sentences`).
    pub(super) body_sentences: BodySentences,
    /// The sentences a credential refusal carries (`super::credential_sentences`).
    pub(super) credential_sentences: CredentialSentences,
    /// Which grammar POST Object forms are read with (`post_forms`).
    pub(crate) post_forms: post_forms::PostFormGrammar,
    /// Whether the legacy RustFS SigV4 header guard answers first (`super::sigv4_header_guard`).
    pub(super) sigv4_header_guard: SigV4HeaderGuard,
    /// Whether a bodyless request's signed digest is compared (`super::bodyless_digest`).
    pub(crate) bodyless_digest: BodylessDigest,
    head_refusals_without_length: bool,
    /// Which object headers a `304` keeps (`super::not_modified_headers`).
    pub(crate) not_modified_headers: super::not_modified_headers::NotModifiedHeaders,
    /// Which heads a successful answer is written with (`super::legacy_heads`).
    pub(super) answer_heads: AnswerHeads,
    clamp_max_keys: bool,
    integrity_codes: IntegrityCodes,
    presigned_payload_unsigned: bool,
    base64_digests_as_hex: bool,
    empty_uploads_without_length: bool,
    rustfs_listings: bool,
    /// Whether date conditions are read in legacy RustFS's one spelling (`date_conditions`).
    pub(super) strict_date_conditions: bool,
    body_literals: bool,
    unknown_checksum_algorithms_ignored: bool,
    empty_headers_absent: bool,
    /// Who answers a header signature's pre-lookup refusals (`header_signatures`).
    pub(crate) header_signatures: header_signatures::HeaderRefusals,
}

impl ViewPolicy {
    /// The sentences this assembly answers a credential refusal with
    /// ([`ServiceBuilder::answer_credential_refusals_with_legacy_rustfs_sentences`]).
    pub(crate) const fn credential_sentences(&self) -> CredentialSentences {
        self.credential_sentences
    }

    /// Whether a presigned request's payload declaration is read as legacy RustFS reads it
    /// ([`ServiceBuilder::sign_presigned_payloads_as_unsigned`]).
    pub(crate) const fn presigned_payload_unsigned(&self) -> bool {
        self.presigned_payload_unsigned
    }

    /// The guard this assembly asks before routing
    /// ([`ServiceBuilder::refuse_unsigned_amz_headers_before_routing`]).
    pub(crate) const fn sigv4_header_guard(&self) -> SigV4HeaderGuard {
        self.sigv4_header_guard
    }

    /// The payload mode a signature is checked over: `payload`, with a base64 digest signed as its
    /// hex under [`ServiceBuilder::sign_base64_payload_digests_as_hex`]. The digest the body is held
    /// to is the same either way.
    pub(crate) fn signed_payload_mode(&self, payload: PayloadMode) -> PayloadMode {
        match payload {
            // Legacy-compat (rustfs/backlog#2684): legacy RustFS signs a base64 payload digest as
            // its lowercase hex, so the base64 text a generic SigV4 signer signs is refused and a
            // signature over a spelling the request never carried is served. The intended future
            // behaviour is the core's: the value as sent.
            PayloadMode::Base64Sha256(digest) if self.base64_digests_as_hex => PayloadMode::ExactSha256(digest),
            payload => payload,
        }
    }

    /// The routed view of `operation`, with this assembly's readings applied to it.
    ///
    /// `body` is the request body before anything reads it, consulted only for the length the
    /// transport already knows it has.
    pub(crate) fn apply<'a, B: http_body::Body>(self, operation: &str, meta: MetaView<'a>, body: Option<&B>) -> MetaView<'a> {
        let meta = self.checksum_waiver.apply(operation, meta);
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS stores an upload that carries no
        // `Content-Length` and whose transport ended it empty as a zero-length object, where AWS
        // answers `411 MissingContentLength`. Kept so the clients RustFS serves today keep
        // working; the intended future behaviour is the core default (`q-length-0007`).
        let meta = if self.empty_uploads_without_length
            && EMPTY_UPLOAD_OPERATIONS.contains(&operation)
            && meta.header("content-length").is_none()
            && meta.header("transfer-encoding").is_none()
            && body.is_some_and(|body| body.size_hint().exact() == Some(0))
        {
            meta.with_transport_ended_empty_body()
        } else {
            meta
        };
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS silently lowers an oversized
        // `max-keys` to 1000 on every listing instead of refusing it, so a client asking for more
        // cannot tell a short page from its own mistake. Kept so RustFS clients (Hadoop S3A pages
        // at 5000) see no change; the intended future behaviour is the core default, a
        // `400 InvalidArgument` for a page size outside the modelled range (`q-max-keys-0073`).
        let meta = if self.clamp_max_keys && CLAMPED_MAX_KEYS_OPERATIONS.contains(&operation) {
            meta.with_page_size_ceiling(MAX_KEYS)
        } else {
            meta
        };
        let meta = if self.strict_date_conditions && date_conditions::covers(operation) {
            meta.with_strict_date_conditions()
        } else {
            meta
        };
        let meta = if self.body_literals && BODY_LITERAL_OPERATIONS.contains(&operation) {
            meta.with_body_literals()
        } else {
            meta
        };
        let meta = match self.integrity_codes {
            IntegrityCodes::RustFs => meta.with_checksum_failures_as_bad_digest(),
            IntegrityCodes::Model => meta,
        };
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS ignores a checksum header naming an
        // algorithm it does not implement, so a client sending one gets no answer about it and the
        // body is stored unverified. Kept because nothing such a header claims can be verified, so
        // storing the body damages nothing; the intended future behaviour is the core's refusal.
        let meta = if self.unknown_checksum_algorithms_ignored {
            meta.with_unknown_checksum_algorithms_ignored()
        } else {
            meta
        };
        // Legacy-compat (rustfs/backlog#2684): legacy RustFS reads an optional header whose one
        // line is empty as absent, so an empty `x-amz-expected-bucket-owner` skips the owner check
        // and an empty `Content-MD5`, checksum or SSE header claims nothing, where the core reads
        // the empty value and refuses what it cannot read. Questionable because an empty claim is
        // taken for no claim; kept so the clients RustFS serves today keep being served; the
        // intended future behaviour is the core default (rustfs/gateway#1087).
        let meta = if self.empty_headers_absent {
            meta.with_empty_headers_absent()
        } else {
            meta
        };
        let listing = RUSTFS_LISTING_ENCODINGS
            .iter()
            .find(|(listed, _)| self.rustfs_listings && *listed == operation);
        match listing {
            Some((_, listing)) => meta.with_rustfs_listing_encoding(*listing),
            None => meta,
        }
    }

    /// The settled answer to `operation`, with this assembly's heads (`super::legacy_heads`).
    pub(crate) fn settle(self, operation: &str, encoded: &mut EncodedResponse) {
        self.answer_heads.settle(operation, encoded);
    }

    /// A refusal of the request body, answered with this assembly's sentences.
    pub(crate) fn body_refusal(self, refusal: S3Error) -> S3Error {
        self.body_sentences.restyle(refusal)
    }

    /// Whether a refused `HEAD` goes out without the `Content-Length` of the document it does not
    /// carry ([`ServiceBuilder::answer_head_refusals_without_content_length`]).
    pub(crate) const fn head_refusals_without_length(&self) -> bool {
        self.head_refusals_without_length
    }

    /// A refusal of the request head's framing, answered with this assembly's sentences.
    pub(crate) fn wire_refusal(self, reject: WireReject) -> S3Error {
        self.body_sentences.restyle(from_wire_reject(reject))
    }

    /// The refusal this assembly owes `operation` before decode, when there is one the codec
    /// cannot phrase: legacy RustFS's answer to a date condition it cannot read, which quotes the
    /// value, when the RustFS profile reads them strictly. `headers` is the accepted head the codec
    /// binds from.
    ///
    /// Unrendered: the service renders it where it renders every other refusal, after
    /// authorization and before the body read and the codec — where legacy RustFS's own decode
    /// refuses it, after its signature check and before its access check and handler.
    pub(crate) fn refusal_before_decode(self, operation: &str, headers: &HeaderView<'_>) -> Option<HandlerError> {
        if self.strict_date_conditions {
            date_conditions::refusal(operation, headers)
        } else {
            None
        }
    }
}

impl ServiceBuilder {
    /// Clamps a `max-keys` above [`RUSTFS_MAX_KEYS_CEILING`] to it on exactly
    /// [`CLAMPED_MAX_KEYS_OPERATIONS`], as RustFS does, instead of refusing it (ListObjectsV2's
    /// modelled range) or handing it to the backend as sent (the other two).
    ///
    /// Off by default: the core answers ListObjectsV2's modelled range, `400 InvalidArgument` for a
    /// page size above a thousand (`c-list-0028`). The RustFS profile turns it on so that Hadoop
    /// S3A's 5000-key pages and every other client RustFS serves today keep working. A negative or
    /// unparseable value is still refused, as RustFS refuses it.
    #[must_use]
    pub fn clamp_oversized_max_keys(mut self) -> Self {
        self.view_policy.clamp_max_keys = true;
        self
    }

    /// Answers a request-body checksum that is not valid for its algorithm, a declared trailer
    /// checksum that never arrived, a checksum that does not match the body, and a streamed body
    /// that does not match its signed `x-amz-content-sha256` with `400 BadDigest`, as legacy
    /// RustFS does (rustfs/gateway#1057).
    ///
    /// Off by default: the core answers the AWS model's codes, `400 InvalidRequest` for an
    /// unreadable value and `400 XAmzContentChecksumMismatch` / `XAmzContentSHA256Mismatch` for a
    /// mismatch. Only the code changes: the request is refused at the same point either way (before
    /// any handler for a head or buffered body, as the terminal verdict a handler's commit waits on
    /// for a streamed one), and `Content-MD5` keeps its own codes (`InvalidDigest`, `BadDigest`)
    /// under both.
    #[must_use]
    pub fn answer_checksum_failures_with_bad_digest(mut self) -> Self {
        self.view_policy.integrity_codes = IntegrityCodes::RustFs;
        self
    }

    /// Answers a refused `HEAD` with no `Content-Length`, as legacy RustFS does
    /// (rustfs/gateway#1120).
    ///
    /// Every `HEAD` answer already goes out without content (the response invariants). By default
    /// a refusal keeps the length of the error document a `GET` would have carried — RFC 9110
    /// §9.3.2 lets a server send the header, and the core does. Legacy RustFS writes the document,
    /// then drops it for a `HEAD` without ever stating its length (`HeadRequestBodyFixLayer`,
    /// `rustfs/src/server/layer.rs:1248-1316`), so its refused `HEAD` carries `Content-Type` and no
    /// `Content-Length`; this switch does the same. A `HEAD` that succeeds keeps the length it
    /// reports, whatever the setting.
    #[must_use]
    pub fn answer_head_refusals_without_content_length(mut self) -> Self {
        self.view_policy.head_refusals_without_length = true;
        self
    }

    /// Ignores a checksum header that names an algorithm this build does not implement — an
    /// `x-amz-checksum-<name>` header no algorithm answers to, or an `x-amz-sdk-checksum-algorithm`
    /// naming none — as legacy RustFS does, on every operation (rustfs/backlog#1677).
    ///
    /// Off by default: the core refuses one, `400 InvalidRequest`, so a new AWS algorithm arrives
    /// as a code change and never as a claim silently left unverified. The RustFS profile turns it
    /// on because legacy RustFS stores the body either way and nothing such a header claims can be
    /// verified. Every other claim is still verified: a known `x-amz-checksum-*` or a
    /// `Content-MD5` beside the unknown header is compared, and a mismatch is still refused. An
    /// ignored header claims nothing, so on an operation that requires an integrity check it does
    /// not stand in for one; the RustFS profile waives that requirement separately
    /// ([`ServiceBuilder::accept_all_checksum_omissions`]).
    #[must_use]
    pub fn ignore_unknown_checksum_algorithms(mut self) -> Self {
        self.view_policy.unknown_checksum_algorithms_ignored = true;
        self
    }

    /// Reads a presigned request's `x-amz-content-sha256` as legacy RustFS does: the signature
    /// always covers `UNSIGNED-PAYLOAD`, a declared digest (lowercase hex or base64) is verified
    /// against the body instead, any other value is `403 SignatureDoesNotMatch`, and a streaming
    /// mode is `501 NotImplemented` (rustfs/rustfs#2379; the reading is
    /// `crate::payload_header::signed_payload`).
    ///
    /// Off by default: the core signs the declared digest itself, as AWS does (`c-sig-0430`). The
    /// RustFS profile turns it on so that a presigned upload signed the way RustFS verifies it today
    /// keeps working. A body that does not match its declared digest is still refused before it
    /// can be stored; header-signed requests are unaffected.
    #[must_use]
    pub fn sign_presigned_payloads_as_unsigned(mut self) -> Self {
        self.view_policy.presigned_payload_unsigned = true;
        self
    }

    /// Signs a header-signed `x-amz-content-sha256` given as the base64 of a SHA-256 digest as the
    /// digest's lowercase hex, as legacy RustFS does (rustfs/gateway#1130): a signature over the hex
    /// is verified and one over the base64 text as sent is `403 SignatureDoesNotMatch`. The body is
    /// verified against the digest either way, and a mismatch is refused before anything is
    /// stored.
    ///
    /// Off by default: the core signs the value as sent, as a generic SigV4 signer does. A hex
    /// digest, `UNSIGNED-PAYLOAD` and the streaming modes are read the same under both.
    #[must_use]
    pub fn sign_base64_payload_digests_as_hex(mut self) -> Self {
        self.view_policy.base64_digests_as_hex = true;
        self
    }

    /// Reads an absent `Content-Length` as `0` on exactly [`EMPTY_UPLOAD_OPERATIONS`] when the
    /// transport already ended the body empty, as RustFS does, instead of refusing the upload with
    /// `411 MissingContentLength`.
    ///
    /// Off by default: the core answers the AWS model's `411` (`q-length-0007`). The RustFS
    /// profile turns it on so that a client uploading an empty object without `Content-Length`
    /// keeps working (rustfs/rustfs#6849). A body whose length the transport does not know — a
    /// chunked transfer, an HTTP/2 stream still carrying data — is still refused with `411`, and
    /// a length the request does carry is read exactly as sent.
    #[must_use]
    pub fn accept_empty_uploads_without_content_length(mut self) -> Self {
        self.view_policy.empty_uploads_without_length = true;
        self
    }

    /// Renders the listings of [`RUSTFS_LISTING_ENCODINGS`] under `encoding-type=url` exactly as
    /// legacy RustFS does (rustfs/gateway#1059): only for exactly `url`, only the members its
    /// table names, each with `/` kept literal, and the request's `encoding-type` echoed verbatim
    /// where legacy echoes it.
    ///
    /// Off by default: the core encodes every member the AWS model declares, `/` included, for
    /// `url` in any case, and echoes the canonical `url`. The RustFS profile turns it on so that
    /// `ContinuationToken`, `Prefix`, `Delimiter` and the multipart listings come back as RustFS
    /// clients read them today. A value no XML document can carry still forces the core's
    /// encoding of the whole response. Behind a RustFS handler, the handler must hand back raw
    /// values (the request's `encoding-type` withheld from it), or the members would be encoded
    /// twice.
    #[must_use]
    pub fn url_encode_listings_like_rustfs(mut self) -> Self {
        self.view_policy.rustfs_listings = true;
        self
    }

    /// Reads MinIO's bare body literal on exactly [`BODY_LITERAL_OPERATIONS`] as legacy RustFS
    /// does: a PutBucketVersioning or PutObjectLockConfiguration body whose ASCII-trimmed bytes are
    /// `Enabled` is the document with that one member set to `Enabled` (rustfs/backlog#1677, R6).
    ///
    /// Off by default: the core answers the S3 model, `400 MalformedXML` for a body that is not the
    /// document (`c-bucketconfig-0060`). The RustFS profile turns it on so a client of RustFS's
    /// MinIO dialect keeps working. Only the literal itself is read so: `enabled`, a bare
    /// `Suspended` and every other body are still the document or `MalformedXML`, and a
    /// `Content-MD5` or checksum is still verified over the bytes that arrived.
    #[must_use]
    pub fn accept_minio_body_literals(mut self) -> Self {
        self.view_policy.body_literals = true;
        self
    }

    /// Reads a request header whose one field line is empty as absent, on every operation, as
    /// legacy RustFS reads every optional header (rustfs/gateway#1087): for every input member,
    /// the SSE headers, the integrity claims (`Content-MD5`, `x-amz-checksum-*`,
    /// `x-amz-sdk-checksum-algorithm`, `x-amz-checksum-type`, `x-amz-trailer`) and the expected
    /// bucket owner, whose check an empty line then skips.
    ///
    /// Off by default: the core reads an empty line as a value and refuses what it cannot read —
    /// an empty `x-amz-expected-bucket-owner` is `403 AccessDenied`, an empty `Content-MD5`
    /// `400 InvalidDigest`. The RustFS profile turns it on so a client sending an empty optional
    /// header keeps being served. A value, a repeated line and `x-amz-meta-*` read as before, the
    /// signature covers the line as it arrived, and a handler is handed the raw lines unchanged.
    #[must_use]
    pub fn read_empty_headers_as_absent(mut self) -> Self {
        self.view_policy.empty_headers_absent = true;
        self
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use rustfs_gateway_core::TargetKind;
    use rustfs_gateway_http::{Limits, WireRequest};

    fn lengthless_put() -> WireRequest<Full<Bytes>> {
        let request = http::Request::builder()
            .method(http::Method::PUT)
            .uri("/bucket/key")
            .header(http::header::HOST, "s3.example.com")
            .body(Full::new(Bytes::new()))
            .expect("a valid request");
        WireRequest::accept(request, &Limits::default()).expect("an acceptable request")
    }

    fn content_length_read(policy: ViewPolicy, operation: &str, body: Option<&Full<Bytes>>) -> Option<String> {
        let wire = lengthless_put();
        let meta = MetaView::of(&wire, TargetKind::Object).expect("a view");
        policy
            .apply(operation, meta, body)
            .header("content-length")
            .map(|value| value.into_owned())
    }

    #[test]
    fn the_empty_upload_reading_answers_only_its_operations_and_only_when_on() {
        let on = ViewPolicy {
            empty_uploads_without_length: true,
            ..ViewPolicy::default()
        };
        let empty = Full::new(Bytes::new());
        for operation in EMPTY_UPLOAD_OPERATIONS {
            assert_eq!(content_length_read(on, operation, Some(&empty)).as_deref(), Some("0"), "{operation}");
            assert_eq!(content_length_read(ViewPolicy::default(), operation, Some(&empty)), None, "{operation}");
            assert_eq!(content_length_read(on, operation, None), None, "{operation}: no body to consult");
            let data = Full::new(Bytes::from_static(b"abc"));
            assert_eq!(content_length_read(on, operation, Some(&data)), None, "{operation}: a body with data");
        }
        for operation in ["CopyObject", "PutBucketPolicy", "CompleteMultipartUpload", "DeleteObjects"] {
            assert_eq!(content_length_read(on, operation, Some(&empty)), None, "{operation}");
        }
    }

    #[test]
    fn the_policy_is_off_by_default_and_its_set_is_closed() {
        assert_eq!(ViewPolicy::default().body_sentences, BodySentences::Gateway);
        assert_eq!(ViewPolicy::default().bodyless_digest, BodylessDigest::Compared);
        assert!(!ViewPolicy::default().clamp_max_keys);
        assert_eq!(ViewPolicy::default().integrity_codes, IntegrityCodes::Model);
        assert!(!ViewPolicy::default().presigned_payload_unsigned());
        assert!(!ViewPolicy::default().empty_uploads_without_length);
        assert!(!ViewPolicy::default().rustfs_listings);
        assert_eq!(ViewPolicy::default().answer_heads, AnswerHeads::Model);
        assert!(!ViewPolicy::default().strict_date_conditions);
        assert!(!ViewPolicy::default().body_literals);
        assert!(!ViewPolicy::default().empty_headers_absent);
        for operation in ["ListMultipartUploads", "ListParts", "ListBuckets", "GetObject", "PutObject"] {
            assert!(!CLAMPED_MAX_KEYS_OPERATIONS.contains(&operation), "{operation}");
        }
        for operation in [
            "CopyObject",
            "UploadPartCopy",
            "PutBucketPolicy",
            "PostObject",
            "CompleteMultipartUpload",
        ] {
            assert!(!EMPTY_UPLOAD_OPERATIONS.contains(&operation), "{operation}");
        }
        assert_eq!(MAX_KEYS.parameter(), "max-keys");
        assert_eq!(MAX_KEYS.ceiling(), 1000);
    }

    /// Positive — under the switch a base64 digest is signed as its hex, over the same digest.
    #[test]
    fn a_base64_digest_is_signed_as_its_hex_only_under_the_switch() {
        let on = ViewPolicy {
            base64_digests_as_hex: true,
            ..ViewPolicy::default()
        };
        let digest = [0x5a; 32];
        assert_eq!(
            on.signed_payload_mode(PayloadMode::Base64Sha256(digest)),
            PayloadMode::ExactSha256(digest)
        );
        assert_eq!(
            ViewPolicy::default().signed_payload_mode(PayloadMode::Base64Sha256(digest)),
            PayloadMode::Base64Sha256(digest)
        );
    }

    /// Negative — every other mode is signed as before, under the switch and off it.
    #[test]
    fn n_every_other_payload_mode_is_signed_as_before() {
        let on = ViewPolicy {
            base64_digests_as_hex: true,
            ..ViewPolicy::default()
        };
        for payload in [
            PayloadMode::Empty,
            PayloadMode::Unsigned,
            PayloadMode::ExactSha256([7; 32]),
            PayloadMode::StreamingSigned {
                trailer: rustfs_gateway_sig::TrailerSet::None,
            },
        ] {
            assert_eq!(on.signed_payload_mode(payload.clone()), payload);
            assert_eq!(ViewPolicy::default().signed_payload_mode(payload.clone()), payload);
        }
        assert!(!ViewPolicy::default().base64_digests_as_hex);
    }
}
