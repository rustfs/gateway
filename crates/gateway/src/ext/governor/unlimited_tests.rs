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

//! What a layer the host lifted with [`Rate::unlimited`] does, decided without a pipeline.
//!
//! Responsible for: an unlimited layer admitting without keeping state, and every bounded layer
//! beside it still limiting and still getting a verified request's charge back.
//! NOT responsible for: the token arithmetic (`super::meter`, which also shows the widest finite
//! rate running dry) or how the posture names a lifted layer (`tests/assembly.rs`).
//! Upstream: `super` (`crate::ext::governor::default`). Downstream: nothing.

use std::net::{IpAddr, Ipv4Addr};

use super::super::{ClassKind, ClientAddr, Governor, GovernorRates, GovernorRequest, Rate};
use super::DefaultGovernor;

fn everything_unlimited() -> GovernorRates {
    let unlimited = Rate::unlimited();
    GovernorRates {
        aggregate: unlimited,
        per_ip: unlimited,
        credential_lookup: unlimited,
        cors_preflight: unlimited,
        unauthenticated: unlimited,
        tracked_clients: 64,
    }
}

fn request(address: Option<IpAddr>) -> GovernorRequest<'static> {
    GovernorRequest::new("GetObject", None, None, address.map(ClientAddr::from_peer), ClassKind::CredentialLookup)
}

fn admits(governor: &DefaultGovernor, address: Option<IpAddr>) -> bool {
    governor.try_acquire_sync(&request(address)).is_some()
}

fn address(index: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(0x0a00_0000_u32.saturating_add(index)))
}

/// Negative — an unlimited per-client layer admits every peer and remembers none of them, where
/// the widest finite rate fills its bounded address table like any other limit.
#[test]
fn n_an_unlimited_per_client_layer_keeps_no_address_state() {
    let (unlimited, _) = DefaultGovernor::manually_clocked(everything_unlimited());
    for index in 0..10_000 {
        assert!(admits(&unlimited, Some(address(index))));
    }
    assert_eq!(unlimited.tracked_clients(), 0, "an unlimited layer kept address entries");

    let widest = Rate::new(u32::MAX, u32::MAX);
    let (bounded, _) = DefaultGovernor::manually_clocked(GovernorRates {
        per_ip: widest,
        ..everything_unlimited()
    });
    for index in 0..10_000 {
        assert!(admits(&bounded, Some(address(index))));
    }
    assert_eq!(bounded.tracked_clients(), 64, "the control did not track its peers");
}

/// Negative — lifting some layers leaves every bounded one beside them limiting.
#[test]
fn n_a_bounded_layer_still_limits_beside_unlimited_ones() {
    let one = Rate::new(1, 0);
    for rates in [
        GovernorRates {
            aggregate: one,
            ..everything_unlimited()
        },
        GovernorRates {
            credential_lookup: one,
            ..everything_unlimited()
        },
        GovernorRates {
            per_ip: one,
            ..everything_unlimited()
        },
    ] {
        let (governor, _) = DefaultGovernor::manually_clocked(rates);
        assert!(admits(&governor, Some(address(1))));
        assert!(!admits(&governor, Some(address(1))), "a bounded layer stopped limiting: {rates:?}");
    }
}

/// Negative — a verified request still returns its charge to the bounded layer beside unlimited
/// ones, and exactly one charge.
#[test]
fn n_a_verified_refund_reaches_the_bounded_layer_beside_unlimited_ones() {
    let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
        per_ip: Rate::new(1, 0),
        ..everything_unlimited()
    });
    assert!(admits(&governor, Some(address(2))));
    governor.verified(&request(Some(address(2))));
    assert!(admits(&governor, Some(address(2))), "the bounded layer kept a verified charge");
    assert!(!admits(&governor, Some(address(2))), "the bounded layer returned more than one charge");
}
