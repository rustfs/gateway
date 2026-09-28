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

//! Responsible for: proving the error-parity harness verifies a scenario with the time it was
//! signed at, and still refuses one signed outside the skew window of that time (#896).
//! NOT responsible for: the s3s oracle, which keeps its own wall clock, or the error comparison.
//! Upstream: the error-parity harness. Downstream: the gateway's SigV4 check.

use rustfs_gateway_sig::RequestNow;

use super::matrix::location;
use super::{Reply, Scenario, gateway_reply};

/// A signing time far outside any skew window of the host clock.
const HISTORICAL: i64 = 1_440_938_160;
/// Past the fifteen-minute window SigV4 allows between the signature and the verifier.
const BEYOND_WINDOW: i64 = 16 * 60;

fn gateway_at(signed: i64, verified: i64) -> Reply {
    let scenario = Scenario::new(location().signed("us-east-1"));
    let (target, headers) = scenario
        .wire(RequestNow::from_unix_seconds(signed))
        .expect("the scenario signs");
    gateway_reply(&scenario, &target, &headers, RequestNow::from_unix_seconds(verified)).expect("the gateway answers")
}

#[test]
fn a_scenario_signed_at_the_fixture_time_reaches_the_gateway_handler() {
    let reply = gateway_at(HISTORICAL, HISTORICAL);
    assert!(reply.reached, "{} {:?}", reply.status, reply.code());
}

#[test]
fn a_scenario_signed_outside_the_window_of_the_fixture_time_is_refused_before_the_handler() {
    for (signed, verified) in [
        (HISTORICAL, HISTORICAL + BEYOND_WINDOW),
        (HISTORICAL + BEYOND_WINDOW, HISTORICAL),
    ] {
        let reply = gateway_at(signed, verified);
        assert_eq!(
            (reply.status, reply.code(), reply.reached),
            (403, Some("RequestTimeTooSkewed"), false),
            "signed {signed} verified {verified}"
        );
    }
}
