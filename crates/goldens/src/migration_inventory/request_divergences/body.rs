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

//! The signed-body slice of the request-divergence register: every place the gateway and s3s hand
//! a PutObject handler a different body, trailer or verdict for the same signed upload
//! (rustfs/backlog#1762, fourth slice), each ruled.
//!
//! Responsible for: the `rd-body-*` entries. NOT responsible for: validating them (the parent's
//! `check_register` does, over the whole register) or observing them (the named tests in
//! `operation_diff/context/body_parity/divergences.rs`).
//! Upstream: those named tests. Downstream: the parent's `REQUEST_DIVERGENCES`.

use super::{BODY_PARITY, DivergenceFollowUp, DivergenceRuling, ERROR_RESPONSES, RequestDivergence};

const STREAMING_UPLOADS: &str = "https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html";
const OBJECT_INTEGRITY: &str = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html";

/// The `rd-body-*` entries, in id order.
pub(super) const BODY_DIVERGENCES: [RequestDivergence; 11] = [
    RequestDivergence {
        id: "rd-body-0001",
        operation: "PutObject",
        request: "a trailer upload whose x-amz-checksum-* trailer does not match the decoded body (value altered, or an unsigned data byte altered)",
        aws: "the service computes the checksum over the payload and refuses a mismatch; nothing is stored",
        aws_evidence: OBJECT_INTEGRITY,
        s3s: "ends the body and publishes the trailer unverified; the RustFS app body (rio via the A4 TrailerSource adapter) must compare and refuse",
        gateway: "400 XAmzContentChecksumMismatch in place of end of body, before the handler may commit; connection kept",
        client_impact: "none for a correct SDK; a corrupted upload is refused by the stack instead of by RustFS storage",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "a_checksum_trailer_that_does_not_match_the_body_is_refused_only_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-body-0002",
        operation: "PutObject",
        request: "x-amz-trailer declares a checksum and the body ends after the terminal chunk with no trailer section",
        aws: "a declared trailer is part of the signed payload framing and must arrive",
        aws_evidence: STREAMING_UPLOADS,
        s3s: "accepts; the trailer handle is never filled, so the A4 adapter reads Pending at end of body and rio refuses",
        gateway: "signed: 403 SignatureDoesNotMatch, closing; unsigned: 400 InvalidRequest, connection kept",
        client_impact: "none for a correct SDK; a truncated trailer upload is refused by the stack rather than by RustFS storage",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "a_declared_trailer_that_never_arrives_is_refused_only_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-body-0003",
        operation: "PutObject",
        request: "an aws-chunked body cut short after its last data chunk (terminal chunk or trailer section incomplete), Content-Length matching",
        aws: "the body ends with a zero-length final chunk (and its trailer section); anything shorter is an incomplete body",
        aws_evidence: STREAMING_UPLOADS,
        s3s: "signed: accepts a cut terminal chunk; unsigned trailer: accepts and publishes the cut trailer value; signed trailer: 403 SignatureDoesNotMatch",
        gateway: "400 IncompleteBody in place of end of body, closing",
        client_impact: "none for a correct SDK; a truncated upload is never stored as complete",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "a_body_cut_short_after_its_last_data_chunk_is_accepted_only_by_s3s",
    },
    RequestDivergence {
        id: "rd-body-0004",
        operation: "PutObject",
        request: "an aws-chunked chunk larger than one mebibyte",
        aws: "documents no chunk-size ceiling; SDKs frame 64 KiB to 1 MiB chunks (botocore 1 MiB)",
        aws_evidence: STREAMING_UPLOADS,
        s3s: "buffers signed chunks up to 256 MiB and streams unsigned chunks of any size",
        gateway: "400 InvalidChunkSizeError at the size line, before a data byte is read, closing; the ceiling is ChunkLimits (1 MiB default, 16 MiB hard)",
        client_impact: "a client configured for chunks over 1 MiB is refused unless the operator raises ChunkLimits; no AWS SDK default exceeds it",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "a_chunk_over_one_mebibyte_is_refused_only_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-body-0005",
        operation: "PutObject",
        request: "an aws-chunked body in more chunks than ceil(decoded / 1 KiB) + 16, or with framing over 5% of the payload past 4 KiB",
        aws: "every chunk but the last must carry at least 8 KiB",
        aws_evidence: STREAMING_UPLOADS,
        s3s: "accepts any number of chunks",
        gateway: "400 InvalidRequest at the first chunk line past the bound, closing",
        client_impact: "none for an SDK, whose chunks are far above the bound; a micro-chunk flood is refused",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "a_micro_chunk_flood_is_refused_only_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-body-0006",
        operation: "PutObject",
        request: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER, read by the handler after end of body",
        aws: "the trailer signature authenticates the trailer section and is not object metadata",
        aws_evidence: STREAMING_UPLOADS,
        s3s: "strips x-amz-trailer-signature from the published fields",
        gateway: "hands the verified x-amz-trailer-signature to the handler beside the checksum",
        client_impact: "none: rio looks trailers up by checksum name, and no handler persists the signature",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "the_gateway_hands_the_verified_trailer_signature_to_the_handler_and_s3s_does_not",
    },
    RequestDivergence {
        id: "rd-body-0007",
        operation: "PutObject",
        request: "an upload that declares no trailer, read by the handler after end of body",
        aws: "no trailer is sent, so there is nothing to look up",
        aws_evidence: STREAMING_UPLOADS,
        s3s: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD: a handle that stays Pending forever; a plain body: no handle",
        gateway: "an empty trailer set at end of body, so every lookup is Missing",
        client_impact: "none: rio consults a trailer source only when a trailing checksum was declared",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "an_upload_without_a_trailer_leaves_the_s3s_handle_pending_or_absent",
    },
    RequestDivergence {
        id: "rd-body-0008",
        operation: "PutObject",
        request: "a header-signed body that does not hash to its x-amz-content-sha256 (c-sig-0596)",
        aws: "400 XAmzContentSHA256Mismatch; nothing is stored",
        aws_evidence: ERROR_RESPONSES,
        s3s: "refuses, withholding the final transport piece from the handler until the digest is checked",
        gateway: "refuses (compared since this slice), handing the handler every byte and an error in place of end of body",
        client_impact: "none: neither handler sees end of body, so neither commits",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "a_payload_digest_refusal_follows_every_unverified_byte_only_on_the_gateway",
    },
    RequestDivergence {
        id: "rd-body-0009",
        operation: "PutObject",
        request: "STREAMING-UNSIGNED-PAYLOAD-TRAILER cut inside its last data chunk",
        aws: "an incomplete body is refused with IncompleteBody",
        aws_evidence: ERROR_RESPONSES,
        s3s: "400 IncompleteBody after streaming the part of the cut chunk that arrived",
        gateway: "400 IncompleteBody after handing over only complete chunks, closing",
        client_impact: "none: both refuse and neither handler sees end of body",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "an_unsigned_chunk_cut_short_is_streamed_in_part_only_by_s3s",
    },
    RequestDivergence {
        id: "rd-body-0010",
        operation: "PutObject",
        request: "x-amz-decoded-content-length larger than the wire Content-Length can hold once minimal framing is counted",
        aws: "the decoded length is the object size carried inside the framed body",
        aws_evidence: STREAMING_UPLOADS,
        s3s: "reads the body and refuses it as 400 IncompleteBody",
        gateway: "400 InvalidRequest at the head, before the handler and before a body byte is read",
        client_impact: "none for an SDK; the impossible declaration is refused earlier and more cheaply",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "a_decoded_length_the_wire_cannot_hold_is_refused_at_the_head_only_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-body-0011",
        operation: "PutObject",
        request: "a trailer upload whose x-amz-checksum-* trailer value is not base64 at all",
        aws: "a checksum value must be base64 of its algorithm's width; nothing is stored",
        aws_evidence: OBJECT_INTEGRITY,
        s3s: "ends the body and publishes the value; legacy RustFS's storage reader fails to decode it: 500 InternalError, \
              nothing stored (observed, e870a6d25b)",
        gateway: "400 in place of end of body, before the handler may commit: InvalidRequest, or BadDigest under the RustFS \
                  profile, the code legacy RustFS gives every other unreadable checksum",
        client_impact: "a broken trailer is a client error the SDK does not retry, instead of a server error it does; a legacy \
                        bug, not a decision",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: BODY_PARITY,
        test: "an_unreadable_checksum_trailer_is_refused_only_by_the_gateway",
    },
];
