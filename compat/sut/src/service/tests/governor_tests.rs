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

//! The framework governor as the RustFS-profile launcher sizes it (rustfs/gateway#1067).
//!
//! Responsible for: bursts far beyond the generic shipped rates — anonymous, wrongly signed and
//! correctly signed, all from one peer — answered by the assembly rather than refused with
//! `503 SlowDown`, because legacy RustFS answers every one of them.
//! NOT responsible for: the limiter's arithmetic or the refund of a verified request's charge
//! (`rustfs-gateway`'s own governor tests).
//! Upstream: the parent module's two-identity assembly. Downstream: nothing.

use super::*;

/// Well past every generic shipped burst: 256 for anonymous requests and one peer, 128 for
/// requests carrying credentials.
const BURST: usize = 300;

/// Sends the whole burst at once to a fresh RustFS-profile assembly. A refused authentication is
/// answered only after the failure floor's delay, so sent one after another the burst would take
/// long enough for a generic meter to refill and this could not tell the RustFS sizing from the
/// generic one.
async fn statuses(request: impl Fn() -> http::Request<Bytes>) -> Vec<u16> {
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let mut burst = tokio::task::JoinSet::new();
    for _ in 0..BURST {
        let service = service.clone();
        let request = request();
        burst.spawn(async move { exchange(&service, request).await.status().as_u16() });
    }
    burst.join_all().await
}

/// Negative — an anonymous burst from one peer is answered (`403`, no bucket policy grants it),
/// never refused for load. The generic unauthenticated class would refuse it after 256.
#[tokio::test]
async fn n_an_anonymous_burst_is_answered_and_not_throttled() {
    let anonymous = || {
        http::Request::builder()
            .uri("/")
            .header(http::header::HOST, "s3.example.com")
            .body(Bytes::new())
            .expect("an anonymous request")
    };
    let statuses = statuses(anonymous).await;
    assert!(statuses.iter().all(|status| *status == 403), "{statuses:?}");
}

/// Negative — a burst signed with the wrong secret is answered `403 SignatureDoesNotMatch` every
/// time, as legacy RustFS answers it. The generic credential class would refuse it after 128.
#[tokio::test]
async fn n_a_wrongly_signed_burst_is_answered_and_not_throttled() {
    let statuses = statuses(|| signed(MAIN_KEY, ALT_SECRET, http::Method::GET, "/", Bytes::new(), &[])).await;
    assert!(statuses.iter().all(|status| *status == 403), "{statuses:?}");
}

/// Positive — a correctly signed burst from one peer is served in full.
#[tokio::test]
async fn a_signed_burst_is_served() {
    let statuses = statuses(|| as_main(http::Method::GET, "/", Bytes::new())).await;
    assert!(statuses.iter().all(|status| *status == 200), "{statuses:?}");
}

/// Negative — every framework layer is lifted, not sized: the served assembly's posture names all
/// five, exactly as the RustFS bridge's must, and none is a finite rate standing in for no limit.
#[test]
fn n_every_framework_governor_layer_is_unlimited() {
    let rates = super::super::rustfs_governor_rates();
    for rate in [
        rates.aggregate,
        rates.per_ip,
        rates.credential_lookup,
        rates.cors_preflight,
        rates.unauthenticated,
    ] {
        assert!(rate.admits_everything(), "{rate:?}");
    }
    let root = TestRoot::new();
    let (_backend, service) = assembled(&two_identity_options(&root, &[]));
    let report = service.security_posture().to_string();
    assert!(report.contains("per-IP bucket: unlimited"), "{report}");
    assert!(
        report.contains("unlimited pre-authentication layers: aggregate, credential lookup, CORS preflight, unauthenticated"),
        "{report}"
    );
}
