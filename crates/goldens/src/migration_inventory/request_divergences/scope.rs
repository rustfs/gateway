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
//! Responsible for: `rd-loc-0005` (an empty scope region) and `rd-loc-0006` (a region outside
//! `[a-z0-9-]+`), each with its ruling and its pinned test in
//! `operation_diff/context/get_bucket_location.rs`.
//! NOT responsible for: the register's validation and rendering, which the parent module does over
//! every slice at once, or the other slices.
//! Upstream: the parent module's types and evidence constants. Downstream: the parent's
//! `REQUEST_DIVERGENCES`, which concatenates the slices at compile time.

use super::{DivergenceFollowUp, DivergenceRuling, ERROR_RESPONSES, LOCATION_CONTEXT, RequestDivergence};

pub(super) const SCOPE_DIVERGENCES: [RequestDivergence; 2] = [
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
        gateway: "400 AuthorizationHeaderMalformed with <Region>, at the scope check before any key is derived, by default and \
                  under the RustFS profile (ADR-0023 keeps the configured-name grammar)",
        client_impact: "none can succeed on either stack and both answer 400; only the code differs, and an SDK region redirector \
                        may retry the gateway answer with the named region",
        ruling: DivergenceRuling::RustfsProfile,
        follow_up: DivergenceFollowUp::Open("https://github.com/rustfs/gateway/issues/1075"),
        test_file: LOCATION_CONTEXT,
        test: "a_scope_region_outside_the_legacy_grammar_is_refused_by_both_stacks_with_different_codes",
    },
];
