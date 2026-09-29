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

//! What the limiter does through a whole assembly, rather than to a `GovernorRequest`.
//!
//! Responsible for: the three properties that are only true of the assembled service — that an
//! assembly nobody configured has a limiter in it, that both places the pipeline can refuse for
//! load render the same bytes, and that a refusal happens before a single body byte is read.
//! NOT responsible for: the arithmetic (`crate::ext::governor::default`'s inline tests, which
//! drive a hand-advanced clock), or the position of the hook in the source order
//! (`tests/pipeline.rs`, which counts the bytes an already-refused body was read for).
//! Upstream: `rustfs-gateway`. Downstream: nothing.
//!
//! # Why the conformance suite is not where this lives
//!
//! A rate limit is observable on the wire — `503 SlowDown` is a response like any other — so a
//! case looks possible. It is not, and the reason is worth writing down so that nobody adds one
//! that cannot fail. The in-process target rebuilds the service for every exchange, because the
//! clock is a per-case declaration; every case therefore meets a limiter with a full burst. A
//! case has no way to install a governor, no way to set a rate, and no way to advance the
//! monotonic clock the limiter measures with — the `[clock]` block moves the wall clock, which is
//! a different clock on purpose. A case written against the shipped defaults would need several
//! thousand requests in one exchange to reach a refusal, which the case format cannot express
//! either. So the suite would hold a case that is green for the same reason an unlimited service
//! would make it green, which is the defect this repository has produced seven times.
//!
//! # Why there is no wall-clock assertion below
//!
//! The one test here that uses real time asserts an inequality that gets *weaker* as the machine
//! gets slower: the admissions observed are bounded by the burst plus the refill over the elapsed
//! time the test measured for itself. A slow runner cannot make it fail, and no amount of load
//! changes the answer for an unlimited governor, which admits more than any such bound.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use crate::support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use futures_util::future::join_all;
use rustfs_gateway::dto::CorsConfiguration;
use rustfs_gateway::{
    BoxFuture, BucketName, ClientAddr, Clock, ClockSkewAck, CorsSource, CorsSourceError, CredentialLookup, CredentialProvider,
    DefaultGovernor, GovernorRates, ManualMonotonic, MonotonicClock, ProviderError, Rate, RegionSet, S3Service,
    SigV4Authenticator, SystemMonotonic, Unlimited, WireResponse,
};
use support::{Backend, CountingBody, Ping, wired};

/// The bucket every request below addresses.
const BUCKET: &str = "governed";

/// A preflight that no assembly here can answer with anything but a refusal — `NoCors` is the
/// default source. What it costs is the point, not what it answers.
fn preflight(bucket: &str) -> http::Request<Bytes> {
    http::Request::builder()
        .method(http::Method::OPTIONS)
        .uri(format!("/{bucket}/key.txt"))
        .header("host", "s3.example.com")
        .header("origin", "https://app.example.com")
        .header("access-control-request-method", "GET")
        .body(Bytes::new())
        .expect("a well-formed preflight")
}

async fn send(service: &S3Service, request: http::Request<Bytes>) -> WireResponse {
    rustfs_gateway::collect(service.call_bytes(request).await)
        .await
        .expect("an in-memory body")
}

/// Negative — an assembly that installs no governor is **not** an assembly with no limit. The
/// bound is the rate contract evaluated against the elapsed time this test measured for itself,
/// so a slow machine widens the bound rather than failing the assertion; an unlimited governor
/// admits every one of the requests below and fails it on any machine.
#[tokio::test]
async fn an_assembly_that_configures_nothing_still_has_a_limit() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .build()
        .expect("a complete assembly");

    let rates = GovernorRates::default();
    let attempts = 8_192_u32;
    let clock = SystemMonotonic::new();
    let started = clock.monotonic();
    let responses = join_all((0..attempts).map(|_| send(&service, preflight(BUCKET)))).await;
    let mut admitted = 0_u32;
    let mut refused = 0_u32;
    for response in responses {
        if response.status().as_u16() == 503 {
            refused += 1;
        } else {
            admitted += 1;
        }
    }
    let elapsed_millis = clock.monotonic().saturating_millis_since(started);
    let refilled = elapsed_millis.saturating_mul(u64::from(rates.cors_preflight.per_second())) / 1_000;
    let ceiling = u64::from(rates.cors_preflight.burst()).saturating_add(refilled);
    assert!(
        u64::from(admitted) <= ceiling,
        "{admitted} preflights were admitted in {elapsed_millis}ms, and the configured rate allows at most {ceiling}"
    );
    assert!(refused > 0, "no request was refused, so nothing was limiting anything");
    assert_eq!(admitted + refused, attempts);
}

/// Negative — the two places the pipeline refuses for load render the same bytes. A limiter whose
/// refusal named the layer that was full would answer "which of my buckets is nearly full" for
/// anybody willing to send traffic and read the difference, and the preflight path and the routed
/// path are reachable by different callers.
#[tokio::test]
async fn every_refusal_for_load_renders_the_same_bytes() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(GovernorRates {
            aggregate: Rate::new(1_000, 0),
            per_ip: Rate::new(1_000, 0),
            credential_lookup: Rate::none(),
            cors_preflight: Rate::none(),
            unauthenticated: Rate::none(),
            tracked_clients: 64,
        })
        .build()
        .expect("a complete assembly");

    let credential = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("authorization", "AWS4-HMAC-SHA256 malformed")
        .body(Bytes::new())
        .expect("a request");
    let from_credential = send(&service, credential).await;
    let from_preflight = send(&service, preflight(BUCKET)).await;
    let from_routed = send(&service, support::plain(http::Method::POST, "/")).await;

    for response in [&from_credential, &from_preflight, &from_routed] {
        assert_eq!(response.status().as_u16(), 503);
        assert_eq!(
            response.header("retry-after"),
            None,
            "a Retry-After header tells the caller the recovery rate"
        );
    }
    let strip = |response: &WireResponse| {
        let body = String::from_utf8(response.body().to_vec()).expect("utf-8");
        // The request identifier and the host identifier are minted per request and differ by
        // construction; everything else must not.
        let mut lines = Vec::new();
        for element in ["Code", "Message", "Resource"] {
            lines.push(support::element_text(&body, element).map(str::to_owned));
        }
        (response.status(), body.len(), lines)
    };
    assert_eq!(strip(&from_credential), strip(&from_preflight));
    assert_eq!(strip(&from_preflight), strip(&from_routed));
    let routed_body = String::from_utf8(from_routed.body().to_vec()).expect("utf-8");
    assert_eq!(support::element_text(&routed_body, "Code"), Some("SlowDown"));
}

/// Negative — the limiter refuses before the body is read, and the byte counter is what makes
/// that a measurement. A limiter consulted after the read would have paid for the upload it
/// refused, which is the whole reason the hook sits where it does.
#[tokio::test]
async fn a_refusal_for_load_reads_no_body() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .governor(DefaultGovernor::with_rates(GovernorRates {
            aggregate: Rate::none(),
            ..GovernorRates::default()
        }))
        .build()
        .expect("a complete assembly");

    let (body, read) = CountingBody::new(Bytes::from(vec![0_u8; 4096]));
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("content-length", "4096")
        .body(body)
        .expect("a valid request");

    let response = service.call(request).await;
    assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(read.load(Ordering::SeqCst), 0, "the refused body was read anyway");
}

/// Negative — the limiter recovers on the clock it was given and on nothing else. Through a whole
/// assembly, because "the service starts answering again" is the claim an operator cares about,
/// and a hand-advanced clock is what makes it an assertion rather than a sleep.
#[tokio::test]
async fn a_limited_assembly_recovers_when_its_clock_advances_and_not_before() {
    let clock = Arc::new(ManualMonotonic::at_millis(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .governor(DefaultGovernor::with_rates_and_clock(
            GovernorRates {
                aggregate: Rate::new(1, 1),
                ..GovernorRates::default()
            },
            Arc::clone(&clock) as Arc<dyn MonotonicClock>,
        ))
        .build()
        .expect("a complete assembly");

    assert_eq!(send(&service, preflight(BUCKET)).await.status().as_u16(), 403);
    for _ in 0..16 {
        assert_eq!(
            send(&service, preflight(BUCKET)).await.status().as_u16(),
            503,
            "the service recovered without its clock moving"
        );
    }
    clock.advance_seconds(1);
    assert_eq!(send(&service, preflight(BUCKET)).await.status().as_u16(), 403);
    assert_eq!(send(&service, preflight(BUCKET)).await.status().as_u16(), 503);
}

fn closed_credential_rates() -> GovernorRates {
    GovernorRates {
        aggregate: Rate::new(1_000, 0),
        per_ip: Rate::new(1_000, 0),
        credential_lookup: Rate::none(),
        cors_preflight: Rate::new(1_000, 0),
        unauthenticated: Rate::new(1_000, 0),
        tracked_clients: 64,
    }
}

/// Negative — installing a user governor does not remove the framework's unauthenticated limits.
#[tokio::test]
async fn a_user_governor_is_anded_with_the_framework_default() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(GovernorRates {
            aggregate: Rate::none(),
            ..closed_credential_rates()
        })
        .governor(Unlimited)
        .build()
        .expect("a complete assembly");

    assert_eq!(
        send(&service, support::plain(http::Method::POST, "/"))
            .await
            .status()
            .as_u16(),
        503
    );
}

/// Negative — credential-looking, preflight, and anonymous requests draw on distinct class meters.
#[tokio::test]
async fn the_three_preauthentication_classes_are_metered_separately() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(closed_credential_rates())
        .build()
        .expect("a complete assembly");

    let credential = http::Request::builder()
        .method(http::Method::POST)
        .uri("/")
        .header("host", "s3.example.com")
        .header("authorization", "AWS4-HMAC-SHA256 malformed")
        .body(Bytes::new())
        .expect("a request");
    assert_eq!(send(&service, credential).await.status().as_u16(), 503);
    assert_ne!(send(&service, preflight(BUCKET)).await.status().as_u16(), 503);
    assert_ne!(
        send(&service, support::plain(http::Method::POST, "/"))
            .await
            .status()
            .as_u16(),
        503
    );
}

fn from(ip: &str, forwarded: &str) -> http::Request<Bytes> {
    let mut request = support::plain(http::Method::POST, "/");
    request
        .headers_mut()
        .insert("x-forwarded-for", http::HeaderValue::from_str(forwarded).expect("a header value"));
    request
        .extensions_mut()
        .insert(ClientAddr::from_peer(ip.parse().expect("an IP address")));
    request
}

/// Negative — the peer address is the key; changing an untrusted forwarding header cannot reset it.
#[tokio::test]
async fn an_untrusted_forwarding_header_cannot_reset_the_per_ip_meter() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(GovernorRates {
            aggregate: Rate::new(1_000, 0),
            per_ip: Rate::new(1, 0),
            credential_lookup: Rate::new(1_000, 0),
            cors_preflight: Rate::new(1_000, 0),
            unauthenticated: Rate::new(1_000, 0),
            tracked_clients: 64,
        })
        .build()
        .expect("a complete assembly");

    assert_ne!(send(&service, from("192.0.2.7", "198.51.100.1")).await.status().as_u16(), 503);
    assert_eq!(send(&service, from("192.0.2.7", "203.0.113.9")).await.status().as_u16(), 503);
    assert_ne!(send(&service, from("192.0.2.8", "203.0.113.9")).await.status().as_u16(), 503);
}

struct CountingCredentials {
    calls: Arc<AtomicUsize>,
}

impl CredentialProvider for CountingCredentials {
    fn lookup<'a>(&'a self, _access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(ProviderError::Backend) })
    }
}

struct CountingCors {
    calls: Arc<AtomicUsize>,
}

impl CorsSource for CountingCors {
    fn load<'a>(&'a self, _bucket: &'a BucketName) -> BoxFuture<'a, Result<Option<CorsConfiguration>, CorsSourceError>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(None) })
    }
}

fn load_bound_rates() -> GovernorRates {
    GovernorRates {
        aggregate: Rate::new(1_000, 0),
        per_ip: Rate::new(1_000, 0),
        credential_lookup: Rate::new(2, 0),
        cors_preflight: Rate::new(3, 0),
        unauthenticated: Rate::new(4, 0),
        tracked_clients: 64,
    }
}

/// Negative — forged signed requests cannot drive more credential-store calls than the class burst.
#[tokio::test]
async fn credential_provider_calls_are_bounded_by_the_credential_class() {
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(CountingCredentials {
        calls: Arc::clone(&calls),
    });
    let service = wired()
        .authenticator(SigV4Authenticator::new(provider, RegionSet::new(["us-east-1"]).expect("one region")))
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(load_bound_rates())
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly");

    for _ in 0..10 {
        let _ = send(&service, support::signed(http::Method::POST, "/")).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// Negative — distinct bucket names cannot drive more CORS-store calls than the class burst.
#[tokio::test]
async fn cors_source_calls_are_bounded_by_the_preflight_class() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .cors_source(CountingCors {
            calls: Arc::clone(&calls),
        })
        .framework_governor_rates(load_bound_rates())
        .build()
        .expect("a complete assembly");

    for index in 0..10 {
        let _ = send(&service, preflight(&format!("bucket-{index}"))).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

/// Negative — anonymous traffic cannot drive more handler calls than the class burst.
#[tokio::test]
async fn backend_calls_are_bounded_by_the_unauthenticated_class() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&calls)))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(load_bound_rates())
        .build()
        .expect("a complete assembly");

    for _ in 0..10 {
        let _ = send(&service, support::plain(http::Method::POST, "/")).await;
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

struct CountingClock {
    calls: Arc<AtomicUsize>,
    reading: rustfs_gateway::sig::RequestNow,
}

impl Clock for CountingClock {
    fn now(&self) -> rustfs_gateway::sig::RequestNow {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.reading
    }
}

/// Negative — the whole request pipeline receives one wall-clock snapshot, not fresh readings.
#[tokio::test]
async fn one_request_reads_the_wall_clock_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .clock_with_skew_ack(
            CountingClock {
                calls: Arc::clone(&calls),
                reading: Clock::now(&rustfs_gateway::system_clock()),
            },
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly");
    calls.store(0, Ordering::SeqCst);

    let _ = send(&service, support::plain(http::Method::POST, "/")).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// c-gov-0004. Negative — a signed request, whose admission reads the clock for the skew check,
/// the scope date and the `Date` header, still takes exactly one reading, and that reading is the
/// one the signature was judged against: the request is admitted only because the snapshot equals
/// its signing time, and the response is dated from the same snapshot.
#[tokio::test]
async fn a_signed_request_is_judged_and_dated_from_one_reading() {
    let calls = Arc::new(AtomicUsize::new(0));
    let reading = Clock::now(&support::fixed_clock());
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .clock_with_skew_ack(
            CountingClock {
                calls: Arc::clone(&calls),
                reading,
            },
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly");
    calls.store(0, Ordering::SeqCst);

    let response = send(&service, support::signed(http::Method::POST, "/")).await;
    assert_eq!(response.status().as_u16(), 200, "the signature was judged against the snapshot");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a signed request read the wall clock more than once");
    let date = response
        .headers()
        .iter()
        .find(|(name, _)| *name == http::header::DATE)
        .and_then(|(_, value)| value.to_str().ok())
        .expect("the response is dated");
    // `SIGNED_AT_STAMP` (20260102T030405Z) in the IMF-fixdate form, written out rather than derived
    // so the assertion does not share a formatter with the code under test.
    assert_eq!(date, "Fri, 02 Jan 2026 03:04:05 GMT", "the Date header came from a different reading");
}

/// Records what the framework put in front of a deployment governor.
struct RecordingGovernor {
    seen: std::sync::Mutex<Vec<(Option<String>, Option<ClientAddr>)>>,
}

impl rustfs_gateway::Governor for RecordingGovernor {
    fn try_acquire<'a>(
        &'a self,
        request: &'a rustfs_gateway::GovernorRequest<'a>,
    ) -> BoxFuture<'a, Result<rustfs_gateway::Lease, ()>> {
        self.seen
            .lock()
            .expect("never poisoned")
            .push((request.bucket().map(|bucket| bucket.as_str().to_owned()), request.client_addr()));
        Box::pin(async { Ok(rustfs_gateway::Lease::admit()) })
    }
}

/// c-gov-0003. Negative — the bucket a governor sees is the one routing resolved from the path,
/// and the peer is the listener's, whatever the request's headers claim.
#[tokio::test]
async fn a_governor_sees_the_resolved_bucket_and_the_transport_peer() {
    let recorder = Arc::new(RecordingGovernor {
        seen: std::sync::Mutex::new(Vec::new()),
    });
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .governor(Arc::clone(&recorder) as Arc<dyn rustfs_gateway::Governor>)
        .build()
        .expect("a complete assembly");
    let peer: std::net::IpAddr = "192.0.2.44".parse().expect("an IP address");
    let mut request = preflight(BUCKET);
    for (name, value) in [
        ("x-forwarded-for", "198.51.100.9"),
        ("x-amz-bucket", "forged"),
        ("forwarded", "for=198.51.100.9"),
    ] {
        request.headers_mut().insert(name, http::HeaderValue::from_static(value));
    }
    request.extensions_mut().insert(ClientAddr::from_peer(peer));
    let _ = send(&service, request).await;
    let seen = recorder.seen.lock().expect("never poisoned").clone();
    assert_eq!(seen, [(Some(BUCKET.to_owned()), Some(ClientAddr::from_peer(peer)))]);
}

/// Every framework layer at a burst of one that never refills, so the second request charged to
/// any of them is the first one refused.
fn one_request_budget() -> GovernorRates {
    GovernorRates {
        aggregate: Rate::new(1, 0),
        per_ip: Rate::new(1, 0),
        credential_lookup: Rate::new(1, 0),
        cors_preflight: Rate::new(1_000, 0),
        unauthenticated: Rate::new(1, 0),
        tracked_clients: 64,
    }
}

fn one_request_assembly() -> rustfs_gateway::ServiceBuilder {
    wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(one_request_budget())
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
}

fn anonymous_from(peer: &str) -> http::Request<Bytes> {
    let mut request = support::plain(http::Method::POST, "/");
    request
        .extensions_mut()
        .insert(ClientAddr::from_peer(peer.parse().expect("an IP address")));
    request
}

fn signed_from(peer: &str) -> http::Request<Bytes> {
    let mut request = support::signed(http::Method::POST, "/");
    request
        .extensions_mut()
        .insert(ClientAddr::from_peer(peer.parse().expect("an IP address")));
    request
}

/// A correctly shaped signed request whose signature does not verify: the last hex digit of the
/// `Signature=` value is changed, so only the verifier can tell it from [`signed_from`].
fn forged_from(peer: &str) -> http::Request<Bytes> {
    let mut request = signed_from(peer);
    let authorization = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .expect("a signed request carries an Authorization header")
        .to_owned();
    let (head, last) = authorization.split_at(authorization.len() - 1);
    let flipped = if last == "0" { "1" } else { "0" };
    request.headers_mut().insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("{head}{flipped}")).expect("a header value"),
    );
    request
}

/// Positive — a request whose signature verifies gives back what it drew from every framework
/// layer, so a signed client is never throttled by a limiter that exists to bound unverified work.
/// Before the refund the second request was `503`: one global credential class, one aggregate and
/// one peer meter each paid for verified traffic and never got it back.
#[tokio::test]
async fn verified_requests_do_not_spend_the_preauthentication_budget() {
    let service = one_request_assembly().build().expect("a complete assembly");
    for attempt in 0..8 {
        let response = send(&service, signed_from("192.0.2.10")).await;
        assert_eq!(response.status().as_u16(), 200, "verified request {attempt} was refused");
    }
}

/// Negative — a signature that fails keeps its charge: the class still bounds the verification
/// work a caller without the secret can force, and that caller's refusal is the next caller's
/// `503`, exactly as before the refund.
#[tokio::test]
async fn a_failed_signature_keeps_its_charge() {
    let service = one_request_assembly().build().expect("a complete assembly");
    assert_eq!(send(&service, forged_from("192.0.2.11")).await.status().as_u16(), 403);
    assert_eq!(
        send(&service, forged_from("192.0.2.11")).await.status().as_u16(),
        503,
        "a failed verification was refunded"
    );
    assert_eq!(
        send(&service, signed_from("192.0.2.12")).await.status().as_u16(),
        503,
        "the spent class and aggregate stopped bounding the next caller"
    );
}

/// Negative — an anonymous request never verifies anything, so nothing is returned for it.
#[tokio::test]
async fn an_anonymous_request_keeps_its_charge() {
    let service = one_request_assembly().build().expect("a complete assembly");
    assert_ne!(send(&service, anonymous_from("192.0.2.13")).await.status().as_u16(), 503);
    assert_eq!(send(&service, anonymous_from("192.0.2.13")).await.status().as_u16(), 503);
}

/// Negative — the credential lookup a forged request forced is not refunded by a verified request
/// from the same peer that follows it: the verified one returns its own charge and no more.
#[tokio::test]
async fn a_verified_request_returns_only_its_own_charge() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(GovernorRates {
            aggregate: Rate::new(1_000, 0),
            per_ip: Rate::new(1_000, 0),
            credential_lookup: Rate::new(2, 0),
            ..one_request_budget()
        })
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly");
    assert_eq!(send(&service, forged_from("192.0.2.14")).await.status().as_u16(), 403);
    assert_eq!(send(&service, signed_from("192.0.2.14")).await.status().as_u16(), 200);
    assert_eq!(send(&service, forged_from("192.0.2.14")).await.status().as_u16(), 403);
    assert_eq!(
        send(&service, forged_from("192.0.2.14")).await.status().as_u16(),
        503,
        "a verified request returned more than it drew"
    );
}

/// Negative — a dual-stack listener reports an IPv4 client as an IPv4-mapped IPv6 address. That
/// is the same peer as the plain IPv4 address, and not one member of a `/64` shared by every IPv4
/// client on the internet.
#[tokio::test]
async fn an_ipv4_mapped_peer_is_metered_as_its_ipv4_address() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .framework_governor_rates(GovernorRates {
            aggregate: Rate::new(1_000, 0),
            per_ip: Rate::new(1, 0),
            credential_lookup: Rate::new(1_000, 0),
            cors_preflight: Rate::new(1_000, 0),
            unauthenticated: Rate::new(1_000, 0),
            tracked_clients: 64,
        })
        .build()
        .expect("a complete assembly");

    assert_ne!(send(&service, anonymous_from("::ffff:192.0.2.20")).await.status().as_u16(), 503);
    assert_ne!(
        send(&service, anonymous_from("::ffff:192.0.2.21")).await.status().as_u16(),
        503,
        "two IPv4 clients behind a dual-stack listener shared one meter"
    );
    assert_eq!(
        send(&service, anonymous_from("192.0.2.20")).await.status().as_u16(),
        503,
        "the mapped and the plain spelling of one IPv4 client had separate meters"
    );
}

/// Counts the verdicts the framework reports to a deployment governor.
struct VerdictCounter {
    verified: AtomicUsize,
}

impl rustfs_gateway::Governor for VerdictCounter {
    fn try_acquire<'a>(
        &'a self,
        _request: &'a rustfs_gateway::GovernorRequest<'a>,
    ) -> BoxFuture<'a, Result<rustfs_gateway::Lease, ()>> {
        Box::pin(async { Ok(rustfs_gateway::Lease::admit()) })
    }

    fn verified(&self, _request: &rustfs_gateway::GovernorRequest<'_>) {
        self.verified.fetch_add(1, Ordering::SeqCst);
    }
}

/// Negative — the pipeline reports a verdict once per verified request, and never for a request
/// whose signature failed or that carried no credentials: a second report would refund work that
/// was paid once, and a report for either of the others would unbound exactly the work the
/// framework limits.
#[tokio::test]
async fn the_pipeline_reports_each_verified_request_once_and_nothing_else() {
    let counter = Arc::new(VerdictCounter {
        verified: AtomicUsize::new(0),
    });
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .governor(Arc::clone(&counter) as Arc<dyn rustfs_gateway::Governor>)
        .clock_with_skew_ack(
            support::fixed_clock(),
            ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .build()
        .expect("a complete assembly");

    for _ in 0..3 {
        assert_eq!(send(&service, signed_from("192.0.2.30")).await.status().as_u16(), 200);
    }
    assert_eq!(counter.verified.load(Ordering::SeqCst), 3);
    assert_eq!(send(&service, forged_from("192.0.2.30")).await.status().as_u16(), 403);
    assert_ne!(send(&service, anonymous_from("192.0.2.30")).await.status().as_u16(), 503);
    assert_eq!(
        counter.verified.load(Ordering::SeqCst),
        3,
        "an unverified request was reported as verified"
    );
}
