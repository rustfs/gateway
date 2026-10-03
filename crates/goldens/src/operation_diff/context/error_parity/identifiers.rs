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

//! The RustFS profile's request identifiers side by side with legacy RustFS's
//! (rustfs/backlog#1677, ruling R10; the RustFS-profile half of `rd-err-0001`).
//!
//! Responsible for: that under `identify_requests_as_legacy_rustfs`, with RustFS's identifier handed
//! over, the gateway's answer carries the identifier headers legacy RustFS's answer carries — the
//! legacy stack's own answer, measured to carry no identifier, with a model of RustFS's
//! request-context layer's two header writes applied over it — and no other: the same value in
//! `x-amz-request-id` and `x-request-id`, no `x-amz-id-2`, no `<HostId>`; and that the one place the
//! two differ is the ruling's, an error document's `<RequestId>` naming the request the head names,
//! which legacy RustFS's document does not carry.
//! NOT responsible for: the default answer (`divergences`, `rd-err-0001`'s pinned test) or the
//! identifier types (`rustfs-gateway`).
//! Upstream: `super`, `super::matrix`. Downstream: none.

use super::matrix::{location, object_get};
use super::s3s;
use super::{Pair, RUSTFS_REQUEST_ID, Reply, Scenario, both};
use s3s::{S3Error, S3ErrorCode};

fn answered(scenario: Scenario) -> Pair {
    both(&scenario.rustfs_identified()).expect("both stacks answer")
}

/// Both answers carry RustFS's identifier in its two headers, once each, and no host identifier.
fn heads_identified_alike(pair: &Pair) {
    for reply in [&pair.gateway, &pair.oracle] {
        assert_eq!(
            reply.headers.get("x-amz-request-id").map(Vec::as_slice),
            Some(&[RUSTFS_REQUEST_ID.to_owned()][..]),
            "{pair:#?}"
        );
        assert_eq!(
            reply.headers.get("x-request-id").map(Vec::as_slice),
            Some(&[RUSTFS_REQUEST_ID.to_owned()][..]),
            "{pair:#?}"
        );
        assert!(!reply.headers.contains_key("x-amz-id-2"), "{pair:#?}");
        assert_eq!(reply.element("HostId"), None, "{pair:#?}");
    }
}

/// The gateway document's elements with its trailing `<RequestId>` taken off, which must be the one
/// naming RustFS's identifier.
fn without_ruled_request_id(gateway: &Reply) -> Vec<&str> {
    let mut elements = gateway.elements();
    assert_eq!(elements.pop(), Some("RequestId"), "{gateway:#?}");
    assert_eq!(gateway.element("RequestId"), Some(RUSTFS_REQUEST_ID), "{gateway:#?}");
    elements
}

/// Negative — a refusal the gateway makes itself is identified as legacy RustFS identifies it; the
/// documents differ only by the ruled `<RequestId>`, which the legacy stack never writes.
#[test]
fn the_rustfs_profile_identifies_its_own_refusal_as_legacy_rustfs() {
    let pair = answered(Scenario::new(location()));
    assert_eq!((pair.gateway.status, pair.oracle.status), (403, 403), "{pair:#?}");
    heads_identified_alike(&pair);
    assert_eq!(pair.oracle.element("RequestId"), None, "{pair:#?}");
    assert_eq!(without_ruled_request_id(&pair.gateway), pair.oracle.elements(), "{pair:#?}");
}

/// Negative — a refusal the RustFS body makes is identified the same way on both stacks.
#[test]
fn the_rustfs_profile_identifies_an_app_body_refusal_as_legacy_rustfs() {
    let scenario = Scenario::new(object_get().signed("us-east-1"))
        .app_refuses(|| S3Error::with_message(S3ErrorCode::NoSuchBucket, "The specified bucket does not exist"));
    let pair = answered(scenario);
    assert_eq!((pair.gateway.status, pair.oracle.status), (404, 404), "{pair:#?}");
    heads_identified_alike(&pair);
    assert_eq!(pair.oracle.element("RequestId"), None, "{pair:#?}");
    assert_eq!(without_ruled_request_id(&pair.gateway), pair.oracle.elements(), "{pair:#?}");
}

/// Positive — a success is identified alike, head for head, and neither body names the request.
#[test]
fn the_rustfs_profile_identifies_a_success_as_legacy_rustfs() {
    let pair = answered(Scenario::new(location().signed("us-east-1")));
    assert_eq!((pair.gateway.status, pair.oracle.status), (200, 200), "{pair:#?}");
    heads_identified_alike(&pair);
    for reply in [&pair.gateway, &pair.oracle] {
        assert_eq!(reply.element("RequestId"), None, "{pair:#?}");
    }
}
