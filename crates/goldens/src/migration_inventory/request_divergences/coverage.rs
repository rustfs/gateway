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

//! The signature-coverage slice of the request-divergence register: the headers a SigV4 signature
//! must name in `SignedHeaders`, the payload declaration covered by `HashedPayload`, and the
//! operations a presigned URL may reach (rustfs/gateway#1130 and #1239).
//!
//! Responsible for: `rd-loc-0009` (`host` left unsigned) and `rd-loc-0010` (`x-amz-content-sha256`
//! covered only by the payload line), each with its ruling and its pinned test in
//! `operation_diff/context/get_bucket_location.rs`, and `rd-adm-0001` (a presigned URL on a RustFS
//! admin route), pinned in `rustfs_admin_dialect/tests.rs`. The Host and presigned-admin refusals
//! remain security floors under both profiles (rustfs/backlog#2684, GHSA-xm99-m3gq-83g8 and
//! MinIO #5411). The payload declaration follows AWS header-authentication rules: its canonical
//! payload line provides coverage without a second entry in `SignedHeaders`.
//! NOT responsible for: the register's validation and rendering, which the parent module does over
//! every slice at once, or the other slices.
//! Upstream: the parent module's types. Downstream: the parent's `REQUEST_DIVERGENCES`, which
//! concatenates the slices at compile time.

use super::{ADMIN_DIALECT, DivergenceFollowUp, DivergenceRuling, LOCATION_CONTEXT, RequestDivergence};

/// Where AWS states which headers a SigV4 signature must cover.
const SIGNED_REQUEST: &str = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html";

/// Where AWS states that a presigned URL grants what its signer could do, to whoever holds it.
const PRESIGNED_URLS: &str = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html";

pub(super) const COVERAGE_DIVERGENCES: [RequestDivergence; 3] = [
    RequestDivergence {
        id: "rd-loc-0009",
        operation: "GetBucketLocation",
        request: "a header-signed SigV4 request whose SignedHeaders leaves out host",
        aws: "host is one of the headers every SigV4 signature must cover",
        aws_evidence: SIGNED_REQUEST,
        s3s: "verifies the signature over the headers the list names, and host need not be one of them; legacy RustFS serves \
              the request",
        gateway: "403 SignatureDoesNotMatch under both profiles: SignedHeaderSet refuses a list without host, because a \
                  signature that does not cover the host holds for every host the request could be re-addressed to, so a \
                  captured virtual-hosted request replays against another bucket",
        client_impact: "no SDK leaves host unsigned; a hand-built client that does is served by legacy RustFS and refused by the \
                        gateway. Kept on security grounds by the coordinator's ruling (rustfs/backlog#2684, intentionally not \
                        kept; the class of GHSA-xm99-m3gq-83g8)",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: LOCATION_CONTEXT,
        test: "a_signature_leaving_host_unsigned_is_verified_by_the_legacy_stack_and_refused_by_the_gateway",
    },
    RequestDivergence {
        id: "rd-loc-0010",
        operation: "GetBucketLocation",
        request: "a header-signed SigV4 request whose SignedHeaders leaves out x-amz-content-sha256",
        aws: "header authentication may omit x-amz-content-sha256 from SignedHeaders because HashedPayload already covers it",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html",
        s3s: "exempts x-amz-content-sha256 from its rule that every x-amz-* header must be signed, uses its value as the \
              canonical payload line and serves the request; legacy RustFS's own unsigned-header guard exempts it too",
        gateway: "200 under both profiles: header authentication uses HashedPayload coverage for this declaration; Host and \
                  semantic x-amz-* headers remain required, and presigned requests retain full header coverage",
        client_impact: "a valid client signing the payload digest once is accepted, as AWS documents; changed declarations \
                        fail signature verification and changed body bytes fail payload verification",
        ruling: DivergenceRuling::AlignAws,
        follow_up: DivergenceFollowUp::Landed("c-sig-0601"),
        test_file: LOCATION_CONTEXT,
        test: "a_signature_covering_the_payload_hash_only_in_the_payload_line_is_verified_by_both_stacks",
    },
    RequestDivergence {
        id: "rd-adm-0001",
        operation: "every RustFS admin operation",
        request: "a SigV4 presigned URL, correctly signed by a credential the admin operation authorizes, on a RustFS admin \
                 route (/rustfs/admin/v3/..., the table catalog)",
        aws: "no S3 operation is administrative; a presigned URL grants its holder whatever its signer could do until it \
             expires, which is why S3-compatible servers keep administrative APIs off it",
        aws_evidence: PRESIGNED_URLS,
        s3s: "verifies a presigned URL on any request before it routes it, then serves the admin route to the verified \
              credential: GET /rustfs/admin/v3/info presigned by the root credential answers 200 with the server information \
              (observed against rustfs/rustfs e870a6d25b)",
        gateway: "403 AccessDenied at the security floor, before the credential is looked up, under every profile: every admin \
                 operation is privileged and header-signed only, and the RustFS profile's floor admits a presigned URL on every \
                 standard operation and on no privileged one. The same request header-signed is served",
        client_impact: "a tool that presigns an admin URL is refused; none is known (mc, the console and the RustFS clients sign \
                       admin requests in the header). Kept on security grounds: a leaked or edited presigned URL must not reach \
                       an admin operation (MinIO #5411)",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: ADMIN_DIALECT,
        test: "a_presigned_admin_request_is_refused_under_the_rustfs_profile_floor",
    },
];
