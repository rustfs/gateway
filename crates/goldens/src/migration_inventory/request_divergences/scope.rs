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

//! The signing-region slice of the request-divergence register: the scope regions legacy RustFS
//! reads differently from the gateway, beyond ADR-0023's `rd-loc-0004` (rustfs/backlog#1677, R2).
//!
//! Responsible for: `rd-loc-0005` (an empty scope region), `rd-loc-0006` (a region outside
//! `[a-z0-9-]+`), `rd-loc-0007` (a region past the parser's 64-byte ceiling) and `rd-loc-0008` (a
//! region carrying one of the `Authorization` header's separators), each with its ruling and its
//! pinned test in `operation_diff/context/get_bucket_location.rs`.
//! NOT responsible for: the register's validation and rendering, which the parent module does over
//! every slice at once, or the other slices.
//! Upstream: the parent module's types and evidence constants. Downstream: the parent's
//! `REQUEST_DIVERGENCES`, which concatenates the slices at compile time.

use super::{DivergenceFollowUp, DivergenceRuling, ERROR_RESPONSES, LOCATION_CONTEXT, RequestDivergence};

pub(super) const SCOPE_DIVERGENCES: [RequestDivergence; 4] = [
    RequestDivergence {
        id: "rd-loc-0005",
        operation: "GetBucketLocation",
        request: "a SigV4 credential scope whose region field is empty (Credential=AKID/<date>//s3/aws4_request)",
        aws: "the region is part of the credential scope; an empty one names no region AWS serves",
        aws_evidence: "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html",
        s3s: "verifies the signature and hands the handler no region (the virtual host's, if it named one); RustFS's replication \
              client signs with the bucket target's region, empty unless the operator set one \
              (rustfs/rustfs@1e7065101d crates/ecstore/src/bucket/bucket_target_sys.rs:112, remote_s3_client.rs:299)",
        gateway: "403 InvalidAccessKeyId by default: the credential parser refuses an empty region field and every unreadable \
                  credential is normalised to one answer. With SigV4Authenticator::accept_empty_signing_region the parsers \
                  admit it (EmptyRegion::Admitted), ExpectedScope::accepting_empty_region admits it at the scope check, the key \
                  is derived from the empty region, and the migration seam hands the handler no region",
        client_impact: "replication between RustFS deployments (and to a RustFS target) fails on HeadBucket without the profile: \
                        nine staging e2e replication_extension_test cases",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Landed("c-sig-0597"),
        test_file: LOCATION_CONTEXT,
        test: "an_empty_scope_region_is_verified_only_under_the_rustfs_profile",
    },
    RequestDivergence {
        id: "rd-loc-0006",
        operation: "GetBucketLocation",
        request: "a SigV4 credential scope naming a region outside [a-z0-9-]+ (US-EAST-1, rustfs_local)",
        aws: "400 AuthorizationHeaderMalformed naming the region to use",
        aws_evidence: ERROR_RESPONSES,
        s3s: "verifies the signature, then refuses the region: 400 InvalidRequest (403 SignatureDoesNotMatch if the signature is \
              wrong)",
        gateway: "400 AuthorizationHeaderMalformed with <Region>, at the scope check before any key is derived, by default \
                  (ADR-0023 keeps the configured-name grammar); under the RustFS profile \
                  SigV4Authenticator::refuse_unreadable_signing_regions_after_verification verifies the signature over the \
                  region and then answers 400 InvalidRequest (403 SignatureDoesNotMatch if the signature is wrong), as \
                  legacy RustFS does",
        client_impact: "none can succeed on either stack. By default only the code and the order differ (an SDK region \
                        redirector may retry the gateway answer with the named region); under the RustFS profile the answers \
                        are legacy RustFS's",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Landed("c-sig-0599"),
        test_file: LOCATION_CONTEXT,
        test: "a_scope_region_outside_the_legacy_grammar_is_refused_as_legacy_refuses_it_only_under_the_rustfs_profile",
    },
    RequestDivergence {
        id: "rd-loc-0007",
        operation: "GetBucketLocation",
        request: "a SigV4 credential scope whose region is [a-z0-9-]+ longer than 64 bytes",
        aws: "the region is part of the credential scope; no region AWS serves is that long, so it is a wrong region: \
              400 AuthorizationHeaderMalformed naming the region to use",
        aws_evidence: ERROR_RESPONSES,
        s3s: "reads the region up to the next / at any length, verifies the signature over it and serves it, handing the \
              handler the client's region (403 SignatureDoesNotMatch if the signature is wrong)",
        gateway: "403 InvalidAccessKeyId by default: the credential parser refuses a region past its 64-byte ceiling and \
                  every unreadable credential is normalised to one answer. With \
                  SigV4Authenticator::accept_signing_regions_of_any_length the parsers read it (RegionLength::Unbounded), \
                  ADR-0023's grammar applies at any length, and it is verified and served as legacy RustFS serves it",
        client_impact: "none known: no region is that long. A client configured with one is served by legacy RustFS and \
                        refused by the gateway without the profile",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Landed("c-sig-0600"),
        test_file: LOCATION_CONTEXT,
        test: "a_scope_region_past_the_ceiling_is_verified_only_under_the_rustfs_profile",
    },
    RequestDivergence {
        id: "rd-loc-0008",
        operation: "GetBucketLocation",
        request: "a SigV4 Authorization header whose credential scope region carries a space or a comma",
        aws: "the Authorization header separates its components with commas and spaces, so such a credential cannot be \
              read; it is malformed",
        aws_evidence: "https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html",
        s3s: "reads the region up to the next /, separators included, verifies the signature over it and then refuses the \
              region: 400 InvalidRequest (403 SignatureDoesNotMatch if the signature is wrong)",
        gateway: "403 InvalidAccessKeyId under both profiles: the header is split at its separators before the credential is \
                  read, a region byte outside ASCII-graphic is unreadable, and every unreadable credential is normalised to \
                  one answer. The RustFS profile keeps refusing a credential scope it cannot read unambiguously \
                  (rustfs/backlog#1677 ruling R2)",
        client_impact: "none can succeed on either stack; only the code and the status band differ (400 on legacy RustFS, \
                        403 on the gateway)",
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        test_file: LOCATION_CONTEXT,
        test: "a_scope_region_with_a_header_separator_is_refused_by_both_stacks_with_different_codes",
    },
];
