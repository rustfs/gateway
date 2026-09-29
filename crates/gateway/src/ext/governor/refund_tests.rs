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

//! What [`Governor::verified`] returns to the framework's meters, decided without a pipeline.
//!
//! Responsible for: one token back to each layer an admission drew from, never past a burst,
//! never to an address that took over the charged one's slot; and the verdict reaching the
//! framework through `LayeredGovernor` and an `Arc`, with a deployment governor's panic contained.
//! NOT responsible for: when the service reports a verdict (`tests/governor_runtime.rs`, through a
//! whole assembly) or the token arithmetic itself (`super::meter`).
//! Upstream: `super` (`crate::ext::governor::default`). Downstream: nothing.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use rustfs_gateway_core::BoxFuture;

use super::super::{ClassKind, ClientAddr, Governor, GovernorRates, GovernorRequest, Lease, Rate, Unlimited};
use super::{CLIENT_SHARDS, DefaultGovernor, LayeredGovernor};

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn roomy() -> GovernorRates {
    GovernorRates {
        aggregate: Rate::new(1_000, 0),
        per_ip: Rate::new(1_000, 0),
        credential_lookup: Rate::new(1_000, 0),
        cors_preflight: Rate::new(1_000, 0),
        unauthenticated: Rate::new(1_000, 0),
        tracked_clients: 64,
    }
}

/// The rates with exactly one layer at `rate`.
fn one_layer(layer: &str, rate: Rate) -> GovernorRates {
    let mut rates = roomy();
    match layer {
        "aggregate" => rates.aggregate = rate,
        "credential_lookup" => rates.credential_lookup = rate,
        "per_ip" => rates.per_ip = rate,
        other => panic!("no layer named {other}"),
    }
    rates
}

const LAYERS: [&str; 3] = ["aggregate", "credential_lookup", "per_ip"];

fn request(address: Option<IpAddr>) -> GovernorRequest<'static> {
    GovernorRequest::new("GetObject", None, None, address.map(ClientAddr::from_peer), ClassKind::CredentialLookup)
}

fn admits(governor: &DefaultGovernor, address: Option<IpAddr>) -> bool {
    governor.try_acquire_sync(&request(address)).is_some()
}

/// Negative — an admission nobody reports as verified stays spent, on every layer. This is the
/// answer for every request that does not verify, and it needs no code path at all to be right.
#[test]
fn an_unverified_admission_stays_spent_on_every_layer() {
    for layer in LAYERS {
        for address in [Some(PEER), None] {
            let (governor, _) = DefaultGovernor::manually_clocked(one_layer(layer, Rate::new(1, 0)));
            assert!(admits(&governor, address));
            assert!(!admits(&governor, address), "{layer} recovered a charge nobody returned");
        }
    }
}

/// Positive — a verified request gives exactly one token back to each layer it drew from, the
/// unknown-client meter included, and not a second one.
#[test]
fn a_verified_request_returns_one_token_to_each_layer() {
    for layer in LAYERS {
        for address in [Some(PEER), None] {
            let (governor, _) = DefaultGovernor::manually_clocked(one_layer(layer, Rate::new(1, 0)));
            assert!(admits(&governor, address));
            governor.verified(&request(address));
            assert!(admits(&governor, address), "{layer} kept a verified request's charge");
            assert!(!admits(&governor, address), "{layer} returned more than one token");
        }
    }
}

/// Negative — charges returned to a meter that has already refilled cannot lift it past its
/// burst: otherwise every verified request would bank one extra admission for the next
/// unverified one. Two verified requests, the meter refilled between them, both returned at the
/// same instant.
#[test]
fn a_refund_never_lifts_a_meter_past_its_burst() {
    for layer in LAYERS {
        let (governor, clock) = DefaultGovernor::manually_clocked(one_layer(layer, Rate::new(2, 1)));
        assert!(admits(&governor, Some(PEER)));
        clock.advance_seconds(1);
        assert!(admits(&governor, Some(PEER)), "the refilled meter admits");
        governor.verified(&request(Some(PEER)));
        governor.verified(&request(Some(PEER)));
        assert!(admits(&governor, Some(PEER)));
        assert!(admits(&governor, Some(PEER)));
        assert!(!admits(&governor, Some(PEER)), "{layer} banked a refund past its burst");
    }
}

/// Negative — an address evicted after it was charged handed its debt to the address that took
/// its slot. Its refund must not credit that other address with a token it never earned.
#[test]
fn a_refund_after_eviction_credits_no_other_address() {
    let (governor, _) = DefaultGovernor::manually_clocked(GovernorRates {
        per_ip: Rate::new(2, 0),
        tracked_clients: CLIENT_SHARDS,
        ..roomy()
    });
    let shard = governor.clients.shard_index(PEER);
    let other = (2..=u16::MAX)
        .map(|tail| IpAddr::V4(Ipv4Addr::new(198, 51, (tail >> 8) as u8, tail as u8)))
        .find(|address| governor.clients.shard_index(*address) == shard)
        .expect("another address maps to the same shard");

    assert!(admits(&governor, Some(PEER)));
    assert!(admits(&governor, Some(other)), "the evicting address inherits one token");
    governor.verified(&request(Some(PEER)));
    assert!(
        !admits(&governor, Some(other)),
        "the evicted address's refund credited the address that replaced it"
    );
}

/// Counts the verdicts a deployment governor hears, and can panic on them.
struct Hearing {
    verified: Arc<Mutex<usize>>,
    panics: bool,
}

fn heard(count: &Mutex<usize>) -> usize {
    *count.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Governor for Hearing {
    fn try_acquire<'a>(&'a self, _request: &'a GovernorRequest<'a>) -> BoxFuture<'a, Result<Lease, ()>> {
        Box::pin(async { Ok(Lease::admit()) })
    }

    fn verified(&self, _request: &GovernorRequest<'_>) {
        *self.verified.lock().unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        assert!(!self.panics, "a deployment governor's verdict hook panicked");
    }
}

/// Negative — behind `LayeredGovernor` the framework still gets its charge back, and the
/// deployment governor hears the verdict exactly once.
#[tokio::test]
async fn a_layered_governor_returns_the_framework_charge_and_passes_the_verdict_on() {
    let count = Arc::new(Mutex::new(0));
    let layered = LayeredGovernor::new(
        DefaultGovernor::with_rates(one_layer("credential_lookup", Rate::new(1, 0))),
        Arc::new(Hearing {
            verified: Arc::clone(&count),
            panics: false,
        }),
    );
    assert!(layered.try_acquire(&request(Some(PEER))).await.is_ok());
    assert!(layered.try_acquire(&request(Some(PEER))).await.is_err());
    layered.verified(&request(Some(PEER)));
    assert_eq!(heard(&count), 1);
    assert!(
        layered.try_acquire(&request(Some(PEER))).await.is_ok(),
        "the layered governor kept the framework's charge"
    );
}

/// Negative — a deployment governor that panics on the verdict changes nothing the framework
/// returned, and the panic does not escape into the request.
#[tokio::test]
async fn a_panicking_deployment_verdict_hook_is_contained() {
    let count = Arc::new(Mutex::new(0));
    let layered = LayeredGovernor::new(
        DefaultGovernor::with_rates(one_layer("credential_lookup", Rate::new(1, 0))),
        Arc::new(Hearing {
            verified: Arc::clone(&count),
            panics: true,
        }),
    );
    assert!(layered.try_acquire(&request(Some(PEER))).await.is_ok());
    layered.verified(&request(Some(PEER)));
    assert_eq!(heard(&count), 1);
    assert!(layered.try_acquire(&request(Some(PEER))).await.is_ok());
}

/// Negative — the service holds its governor behind an `Arc`; the verdict must pass through it
/// rather than stop at the trait's default, which returns nothing.
#[tokio::test]
async fn an_arc_forwards_the_verdict() {
    let governor: Arc<dyn Governor> = Arc::new(DefaultGovernor::with_rates(one_layer("credential_lookup", Rate::new(1, 0))));
    let wrapped: Arc<Arc<dyn Governor>> = Arc::new(Arc::clone(&governor));
    assert!(wrapped.try_acquire(&request(Some(PEER))).await.is_ok());
    assert!(wrapped.try_acquire(&request(Some(PEER))).await.is_err());
    Governor::verified(&wrapped, &request(Some(PEER)));
    assert!(wrapped.try_acquire(&request(Some(PEER))).await.is_ok(), "the Arc dropped the verdict");
}

/// Negative — a governor that does not override the hook keeps whatever it counted.
#[tokio::test]
async fn the_default_verdict_hook_returns_nothing() {
    let unlimited = Unlimited;
    unlimited.verified(&request(Some(PEER)));
    assert!(unlimited.try_acquire(&request(Some(PEER))).await.is_ok());
}
