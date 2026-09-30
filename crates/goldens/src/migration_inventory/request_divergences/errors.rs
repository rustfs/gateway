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

//! The error-response slice of the request-divergence register: `rd-err-NNNN`.
//!
//! Responsible for: the thirteen pinned divergences in how the two stacks answer a refused request —
//! status, code, `<Resource>`, `<RequestId>`, headers — each with its ruling and its pinned test
//! in `operation_diff/context/error_parity/divergences.rs`.
//! NOT responsible for: the register's validation and rendering, which the parent module does over
//! every slice at once, or the other slices (`body`, and the operation, context and configuration
//! entries in the parent).
//! Upstream: the parent module's types and evidence constants. Downstream: the parent's
//! `REQUEST_DIVERGENCES`, which concatenates the slices at compile time.

use super::{DivergenceFollowUp, DivergenceRuling, ERROR_PARITY, ERROR_RESPONSES, RequestDivergence};

pub(super) const ERROR_DIVERGENCES: [RequestDivergence; 13] = [
    RequestDivergence {
        id: "rd-err-0001",
        operation: "every operation",
        request: "any refused request",
        aws: "the document carries RequestId and HostId, and the head the same values in x-amz-request-id and x-amz-id-2",
        aws_evidence: ERROR_RESPONSES,
        s3s: "writes neither; RustFS adds x-amz-request-id and x-request-id in a layer outside s3s (rustfs/src/server/layer.rs), \
              never a document element or x-amz-id-2",
        gateway: "RequestId and HostId are the last two document elements, and the head carries the same two values",
        client_impact: "the header RustFS already sends keeps its name; a client reading the document or x-amz-id-2 now finds \
                        the id, and log joins must accept the gateway's 16-hex-digit form",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "only_the_gateway_identifies_the_request_in_its_head_and_document",
    },
    RequestDivergence {
        id: "rd-err-0002",
        operation: "GetObject",
        request: "a key the app body reports missing (NoSuchKey)",
        aws: "the NoSuchKey document names the key in <Key>",
        aws_evidence: ERROR_RESPONSES,
        s3s: "writes Code and Message only",
        gateway: "writes <Key> after Message (HandlerErrorContext::missing_object_for, which the adapter calls with the request's key)",
        client_impact: "none for SDKs, which branch on the code; a client reading <Key> gets the AWS element",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "a_missing_key_is_named_in_the_document_only_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-err-0003",
        operation: "PutObject",
        request: "a refusal that leaves request octets unread: a failed signature with a body owed, a length past 5 GiB, no Content-Length",
        aws: "a server that does not read the whole body closes the connection after the response",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc9112#section-9.3",
        s3s: "states no connection verdict; hyper decides",
        gateway: "the refusal carries ConnectionIntent::Close and the tower adapter announces Connection: close (close.rs)",
        client_impact: "the next request opens a new connection; no answer changes, and the unread octets can never be read as a request",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "a_refusal_that_leaves_its_body_owed_closes_only_on_the_gateway",
    },
    RequestDivergence {
        id: "rd-err-0004",
        operation: "PutObject",
        request: "an app body that refuses before reading a non-empty streaming body (PutObject, UploadPart)",
        aws: "the handler's refusal is the answer, whatever happened to the body",
        aws_evidence: ERROR_RESPONSES,
        s3s: "writes the app body's refusal",
        gateway: "writes the app body's refusal, in process and on both production drivers, and keeps the connection with the \
                  unread octets left to the transport's linger (request_deadline::unread_body_answer, rustfs/gateway#794). A \
                  body dropped after it was read, and a success over one never read, are still 400 IncompleteBody",
        client_impact: "none: the bucket, access or throttling refusal reaches the client as itself",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Landed("c-mpu-0053"),
        test_file: ERROR_PARITY,
        test: "the_app_bodys_refusal_before_reading_a_streaming_body_is_the_answer_on_both_stacks",
    },
    RequestDivergence {
        id: "rd-err-0005",
        operation: "GetObject",
        request: "a conditional read the app body answers NotModified",
        aws: "304 with no body and the ETag of the representation",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc9110#section-15.4.5",
        s3s: "304 with no ETag: RustFS returns S3Error::new(NotModified); an ETag header on the error is written as is",
        gateway: "the seam reads the tag from the error's ETag header (Refusal::NotModified) and the adapter answers \
                  HandlerErrorContext::not_modified(etag), the AWS 304; an error with no tag is refused, so the RustFS body must attach it",
        client_impact: "a revalidating GET gets its ETag back once the RustFS body attaches it, and a 500 until then; not on M1's two operations",
        ruling: DivergenceRuling::AlignAws,
        follow_up: DivergenceFollowUp::Landed("c-cond-0007"),
        test_file: ERROR_PARITY,
        test: "a_not_modified_carrying_its_entity_tag_is_304_with_it_on_both_stacks",
    },
    RequestDivergence {
        id: "rd-err-0006",
        operation: "GetObject",
        request: "a range the app body answers InvalidRange",
        aws: "416 with Content-Range: bytes */<length>, RangeRequested and ActualObjectSize",
        aws_evidence: "https://www.rfc-editor.org/rfc/rfc9110#section-15.5.17",
        s3s: "416 with the RustFS range message and no Content-Range; a Content-Range header on the error is written as is",
        gateway: "the seam reads the length from the error's Content-Range: bytes */<length> (Refusal::UnsatisfiableRange) and \
                  the adapter answers HandlerError::unsatisfiable_range(request Range, length), the AWS 416; an error with no \
                  length is refused, so the RustFS body must attach it",
        client_impact: "a read past the end gets 416 with the length once the RustFS body attaches it, and a 500 until then; \
                        not on M1's two operations",
        ruling: DivergenceRuling::AlignAws,
        follow_up: DivergenceFollowUp::Landed("c-range-0009"),
        test_file: ERROR_PARITY,
        test: "an_invalid_range_carrying_its_length_is_416_with_content_range_on_both_stacks",
    },
    RequestDivergence {
        id: "rd-err-0007",
        operation: "GetBucketLocation",
        request: "an app body message longer than 1024 bytes",
        aws: "no documented bound; AWS messages are one sentence",
        aws_evidence: ERROR_RESPONSES,
        s3s: "writes the whole message",
        gateway: "the seam cuts it to 1024 bytes on a character boundary, the most the gateway admits (a longer one would be a 500)",
        client_impact: "only a RustFS reason past 1 KiB loses its tail; code and status are unchanged",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "a_message_past_1024_bytes_is_cut_only_on_the_gateway",
    },
    RequestDivergence {
        id: "rd-err-0008",
        operation: "GetObject",
        request: "an app body NoSuchKey or MethodNotAllowed carrying x-amz-delete-marker, x-amz-version-id and Last-Modified",
        aws: "404 NoSuchKey, or 405 on a read naming the marker, with x-amz-delete-marker: true and the version id",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/userguide/DeleteMarker.html",
        s3s: "writes the code and every header of the error (RustFS with_delete_marker_read_headers)",
        gateway: "the seam reads the three headers (Refusal::CurrentDeleteMarker, VersionedDeleteMarker) and the delete-marker \
                  contexts render all three; a marker error with no Last-Modified (RustFS's current-marker 404 today) is refused",
        client_impact: "a read of a deleted key is the 404 or 405 with the marker flag and version id once the RustFS body \
                        writes Last-Modified on both, and a 500 until then; not on M1's two operations",
        ruling: DivergenceRuling::AlignS3s,
        follow_up: DivergenceFollowUp::Landed("c-object-0063"),
        test_file: ERROR_PARITY,
        test: "an_error_carrying_delete_marker_headers_crosses_as_the_marker_read",
    },
    RequestDivergence {
        id: "rd-err-0009",
        operation: "every operation",
        request: "a refusal before any handler: authentication, clock skew, presigned expiry, an unrepresentable member",
        aws: "Message is prose for people; SDKs branch on Code",
        aws_evidence: ERROR_RESPONSES,
        s3s: "describes the cause and can echo request input (invalid query: response-expires: notadate)",
        gateway: "one fixed sentence per cause naming nothing from the request (scripts/check_preauth_static_msg.sh); the code agrees",
        client_impact: "none for SDKs; a person sees a shorter sentence, and nothing the caller sent is reflected back",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "a_refusal_before_the_handler_carries_the_gateways_own_sentence",
    },
    RequestDivergence {
        id: "rd-err-0010",
        operation: "GetObject",
        request: "a member value the codec refuses (response-expires=notadate)",
        aws: "Resource names the bucket or object the request addressed",
        aws_evidence: ERROR_RESPONSES,
        s3s: "writes no Resource: its serializer leaves the element commented out",
        gateway: "writes the refused model member as Resource (ResponseExpires), as its conformance cases pin",
        client_impact: "none for SDKs, which do not parse Resource; a client that does reads a member name, not a path",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "a_codec_refusal_names_its_member_as_the_resource_only_on_the_gateway",
    },
    RequestDivergence {
        id: "rd-err-0011",
        operation: "every buffered write: PutBucketVersioning, every other configuration write, DeleteObjects, PutObjectTagging",
        request: "a Content-MD5 or x-amz-checksum-* that does not match the body or cannot be read, or two different checksums",
        aws: "400 BadDigest, XAmzContentChecksumMismatch, InvalidDigest or InvalidRequest; nothing is stored",
        aws_evidence: ERROR_RESPONSES,
        s3s: "compares none of them on a buffered body and hands the write to the handler; legacy RustFS applies it (observed on \
              twelve buffered writes, e870a6d25b)",
        gateway: "refuses before the handler: the decoder compares Content-MD5, the body gate the checksum; under the RustFS \
                  profile a mismatch is 400 BadDigest",
        client_impact: "a client whose digest contradicts its body is refused instead of having the document applied; kept under \
                        rustfs/backlog#1677's hard constraint, since storing a body that contradicts its declared checksum is \
                        data damage",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "a_buffered_write_that_contradicts_its_integrity_claim_is_refused_only_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-err-0012",
        operation: "PutObject, UploadPart",
        request: "a Content-MD5 that is not base64 of sixteen bytes",
        aws: "400 InvalidDigest",
        aws_evidence: ERROR_RESPONSES,
        s3s: "hands it to the RustFS body, whose storage reader fails to decode it: 500 InternalError, nothing stored \
              (observed, e870a6d25b)",
        gateway: "400 InvalidDigest before the handler",
        client_impact: "a malformed header is a client error the SDK does not retry, instead of a server error it does; a \
                        legacy bug, not a decision",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "an_unreadable_content_md5_on_an_upload_is_a_client_error_only_on_the_gateway",
    },
    RequestDivergence {
        id: "rd-err-0013",
        operation: "every buffered write: PutBucketVersioning, CreateBucket, PutObjectTagging",
        request: "a header-signed body that does not hash to its x-amz-content-sha256",
        aws: "400 XAmzContentSHA256Mismatch; nothing is stored",
        aws_evidence: ERROR_RESPONSES,
        s3s: "500 InternalError; legacy RustFS applies nothing (observed on CreateBucket and PutObjectTagging, e870a6d25b)",
        gateway: "400 XAmzContentSHA256Mismatch before the handler",
        client_impact: "a corrupted body is a client error the SDK does not retry, instead of a server error it does; nothing \
                        is applied either way; a legacy bug, not a decision",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ERROR_PARITY,
        test: "a_buffered_body_that_does_not_hash_to_its_signed_digest_is_a_client_error_only_on_the_gateway",
    },
];
