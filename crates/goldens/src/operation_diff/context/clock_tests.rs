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

//! Responsible for: proving the context harness verifies a request with the same fixture time it
//! was signed with, and still refuses a signature outside the skew window of that time (#896).
//! NOT responsible for: the s3s oracle, which keeps its own wall clock, or the compared context.
//! Upstream: the context harness's signing and gateway side. Downstream: the gateway's SigV4 check.

use rustfs_gateway_sig::RequestNow;

use super::{ContextRequest, PATH_HOST, gateway_side};

/// A signing time far outside any skew window of the host clock, so only an injected clock
/// that matches it can accept the request.
const HISTORICAL: i64 = 1_440_938_160;
/// Past the fifteen-minute window SigV4 allows between the signature and the verifier.
const BEYOND_WINDOW: i64 = 16 * 60;

fn put() -> ContextRequest {
    ContextRequest::put(PATH_HOST, "/photos/a.txt", b"hello").signed("us-east-1")
}

fn gateway_at(signed: i64, verified: i64) -> Result<&'static str, String> {
    let request = put();
    let headers = request.wire_headers(RequestNow::from_unix_seconds(signed))?;
    gateway_side(&request, &headers, RequestNow::from_unix_seconds(verified)).map(|side| side.operation)
}

#[test]
fn a_request_signed_at_the_fixture_time_reaches_the_handler_whatever_the_host_clock_reads() {
    assert_eq!(gateway_at(HISTORICAL, HISTORICAL), Ok("PutObject"));
}

#[test]
fn a_signature_older_than_the_window_of_the_fixture_time_is_refused() {
    let refused = gateway_at(HISTORICAL, HISTORICAL + BEYOND_WINDOW).expect_err("a stale signature was accepted");
    assert!(refused.contains("status 403"), "{refused}");
}

#[test]
fn a_signature_newer_than_the_window_of_the_fixture_time_is_refused() {
    let refused = gateway_at(HISTORICAL + BEYOND_WINDOW, HISTORICAL).expect_err("a future signature was accepted");
    assert!(refused.contains("status 403"), "{refused}");
}
