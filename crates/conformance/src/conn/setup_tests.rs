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

//! Responsible for: proving the time a transport spends starting its own server is charged to the
//! harness, not to the case's target budget (rustfs/gateway#909, c-h2-0003 on a loaded runner).
//! NOT responsible for: the target's own hang or deadline behaviour, which the corpus cases judge.
//! Upstream: `Conn::exchange` and its server start. Downstream: the runner's timeout accounting.

use std::time::{Duration, Instant};

use super::tests::{ANONYMOUS_GET_ROOT_HPACK, h2_plan, h2_request};
use super::*;
use crate::toml;

/// Longer than the whole target budget below, as a loaded host can make a server start.
const SETUP_STALL: Duration = Duration::from_millis(600);
const TARGET_BUDGET: Duration = Duration::from_millis(150);

fn stalled(mut conn: Conn, stall: Duration) -> Conn {
    conn.setup_delay = stall;
    conn
}

#[cfg(feature = "production-transports")]
#[test]
fn a_slow_production_h2_start_does_not_spend_the_target_budget() {
    let mut conn = stalled(Conn::production(".".into(), ProductionDriver::Hyper), SETUP_STALL);
    conn.prepare("s-h2-setup", None).expect("the empty fixture prepares");
    let mut plan = h2_plan("s-h2-setup", h2_request(ANONYMOUS_GET_ROOT_HPACK), None);
    plan.deadline = Some(Instant::now() + TARGET_BUDGET);
    let observation = conn
        .exchange(&plan)
        .expect("starting the harness's server did not expire the target's deadline");
    assert_eq!(observation.status, Some(403), "{observation:?}");
    assert!(
        observation.harness_wait_ms >= 600,
        "the server start was not charged to the harness: {observation:?}"
    );
}

fn plain_get(conn: &mut Conn) -> crate::observation::Observation {
    conn.prepare("s-setup-0001", None).expect("the empty fixture prepares");
    let request = toml::parse("method = \"GET\"\ntarget = \"/\"\n").expect("valid TOML");
    let plan = ExchangePlan {
        case_id: "s-setup-0001",
        index: 0,
        request,
        clock: None,
        connection: None,
        timeout_ms: Some(2_000),
        deadline: None,
        transport: rustfs_gateway::Transport::Hyper,
        profile: crate::sut::Profile::Aws,
    };
    conn.exchange(&plan).expect("the exchange runs")
}

#[test]
fn a_slow_http1_listener_start_is_charged_to_the_harness() {
    let observation = plain_get(&mut stalled(Conn::new(".".into()), SETUP_STALL));
    assert_eq!(observation.status, Some(403), "{observation:?}");
    assert!(
        observation.harness_wait_ms >= 600,
        "the listener start was not charged to the harness: {observation:?}"
    );
}

#[test]
fn an_unstalled_start_charges_the_harness_only_what_it_spent() {
    let observation = plain_get(&mut Conn::new(".".into()));
    assert_eq!(observation.status, Some(403), "{observation:?}");
    assert!(
        observation.harness_wait_ms < 600,
        "harness time is reported without a stall: {observation:?}"
    );
}
