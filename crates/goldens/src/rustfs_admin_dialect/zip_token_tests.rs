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

//! The zip download's `token` query bearer claim through the assembled service (ADR-0042,
//! rustfs/gateway#1400).
//!
//! Responsible for: a token-only download admitted only through an installed host verifier, under
//! both aliases, with the token's principal in both authorization stages and the handler and the
//! host's state in the handler; refusal, before the authorizer, of a missing, empty, repeated,
//! unknown, expired or other-download token, a wrong suffix, a token on any other route, a token
//! with no verifier installed, and a malformed presented credential; the signed download, with and
//! without a verifier; and no context, response or refusal holding the token.
//! NOT responsible for: the token's cryptography (the host's), or the archive (the host handler's).
//! Upstream: `super`'s harness. Downstream: nothing.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderValue, Request};
use rustfs_gateway::{BearerGrant, BearerRefused, BearerTokenRequest, BearerTokenVerifier, Identity};

use rustfs_gateway::{ClockSkewAck, FixedClock, SecurityFloor};

use super::{Assembled, Exchange, REGION, assemble, assemble_on, assemble_with_bearer_verifier, rustfs_profile_floor, wire};
use crate::operation_diff::s3s_0_17_0::context::{ACCESS_KEY, ContextRequest, PATH_HOST};

pub(super) const ZIP_GET: &str = "rustfs:GetV3ObjectZipDownloadsByIdZip";
/// A token for download `abc`, issued to the shared credential.
pub(super) const GOOD: &str = "tok-abc-sentinel";
/// A token for download `xyz`, issued to the shared credential.
pub(super) const OTHER_DOWNLOAD: &str = "tok-xyz-sentinel";
/// A token for download `abc` that expired in 2001.
pub(super) const EXPIRED: &str = "tok-expired-sentinel";
/// A token for download `abc`, issued to another principal.
const OTHER_PRINCIPAL: &str = "tok-other-principal-sentinel";
/// A token for download `abc` whose decoded value holds a literal `+`.
pub(super) const PLUS: &str = "tok+plus-sentinel";
/// A token whose verification panics inside the host.
pub(super) const PANICS: &str = "tok-panics-sentinel";
const OTHER_KEY: &str = "AKIAOTHERPRINCIPAL01";

/// A decrypt-only host verifier with its known tokens that records what it was asked.
///
/// It deliberately checks neither the download nor the expiry: it reports what the token says,
/// and the kernel must compare both against the request (ADR-0042). A host that forgets those
/// checks is exactly the host this fixture stands for.
#[derive(Clone, Default)]
pub(super) struct FixtureVerifier {
    asked: Arc<Mutex<Vec<String>>>,
}

impl BearerTokenVerifier for FixtureVerifier {
    fn verify(&self, request: &BearerTokenRequest<'_>) -> Result<BearerGrant, BearerRefused> {
        assert_ne!(request.token(), PANICS, "the fixture host's own failure");
        self.asked.lock().expect("uncontended").push(request.resource().to_owned());
        let (resource, key, expires_at) = match request.token() {
            GOOD | PLUS => ("abc", ACCESS_KEY, i64::MAX),
            OTHER_DOWNLOAD => ("xyz", ACCESS_KEY, i64::MAX),
            // Long past against the request clock the kernel hands over, whatever that is now.
            EXPIRED => ("abc", ACCESS_KEY, 1_000_000_000),
            OTHER_PRINCIPAL => ("abc", OTHER_KEY, i64::MAX),
            _ => return Err(BearerRefused),
        };
        let identity = Identity::new(key).map_err(|_| BearerRefused)?;
        Ok(BearerGrant::new(identity, resource, expires_at, Arc::new(format!("archive-{resource}"))))
    }
}

/// The default floor and the RustFS profile's floor, which reads a query or form as signed only
/// when it carries the signature (rustfs/gateway#1130). Every bearer test runs under both.
pub(super) fn floors() -> [(&'static str, SecurityFloor); 2] {
    [
        ("default", SecurityFloor::new()),
        ("rustfs-profile", rustfs_profile_floor().recognize_signatures_as_legacy_rustfs()),
    ]
}

/// [`assemble_with_bearer_verifier`] behind `floor`.
pub(super) fn with_verifier(
    floor: SecurityFloor,
    policy: impl Fn(&str, &str) -> bool + Send + Sync + 'static,
    verifier: impl BearerTokenVerifier,
) -> Assembled {
    super::assemble_installing(floor, policy, false, None, |builder| builder.bearer_token_verifier(verifier))
}

pub(super) fn unsigned(method: &str, uri: &str) -> Request<Bytes> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("host", PATH_HOST)
        .body(Bytes::new())
        .expect("a fixture request")
}

pub(super) fn signed_get(path: &str, query: &str) -> Request<Bytes> {
    wire(&ContextRequest::get(PATH_HOST, path, query).signed(REGION))
}

/// `403`, no handler, no authorizer question, and no token anywhere in the answer, in any case.
pub(super) fn refused_without_asking(exchange: &Exchange, at: &str) {
    assert_eq!(exchange.status, 403, "{at}: {}", exchange.body);
    assert!(exchange.reached.is_empty(), "{at}: a handler ran: {:?}", exchange.reached);
    assert!(exchange.asked.is_empty(), "{at}: the authorizer was asked {:?}", exchange.asked);
    let body = exchange.body.to_ascii_lowercase();
    assert!(!body.contains("sentinel"), "{at}: the refusal holds a token: {}", exchange.body);
}

pub(super) fn asked_of(verifier: &FixtureVerifier) -> Vec<String> {
    std::mem::take(&mut *verifier.asked.lock().expect("uncontended"))
}

/// Positive — the minted token-only URL under each alias reaches the download as the token's
/// principal: both stages are asked about that caller under the bearer scheme, the handler holds
/// the host's state and no signed principal, and no context holds the token.
#[test]
fn a_verified_token_admits_the_download_as_its_principal_under_both_aliases() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, action| action == "rustfs:DownloadObjectZip", verifier.clone());
        for prefix in ["/rustfs/admin", "/minio/admin"] {
            let uri = format!("{prefix}/v3/object-zip-downloads/abc.zip?note=a&token={GOOD}");
            let exchange = assembled.exchange(unsigned("GET", &uri));
            assert_eq!(exchange.status, 200, "{uri}: {}", exchange.body);
            assert_eq!(exchange.reached, [ZIP_GET], "{uri}");
            assert_eq!(asked_of(&verifier), ["abc"], "{uri}: verified once, bound to the raw id");
            let handed = &exchange.handed[0];
            assert_eq!(handed.params, [("id".to_owned(), "abc.zip".to_owned())], "{uri}");
            assert_eq!(handed.principal, None, "{uri}: no signature, so no signed principal");
            assert_eq!(handed.bearer, Some((ACCESS_KEY.to_owned(), Some("archive-abc".to_owned()))), "{uri}");
            assert!(!handed.anonymous, "{uri}: a bearer request is not anonymous");
            assert_eq!(handed.raw_query, "note=a", "{uri}: the handler never holds the token");
            assert!(!exchange.asked.is_empty(), "{uri}: the authorizer was asked");
            for asked in &exchange.asked {
                assert_eq!(asked.caller.as_deref(), Some(ACCESS_KEY), "{uri}: {asked:?}");
                assert_eq!(asked.scheme, "Bearer", "{uri}: {asked:?}");
                assert_eq!(asked.query.as_deref(), Some("note=a"), "{uri}: {asked:?}");
            }
            assert!(!exchange.body.to_ascii_lowercase().contains("sentinel"), "{uri}: {}", exchange.body);
        }
    }
}

/// Negative — a verified token does not bypass authorization: a denied download action stops the
/// request before its handler.
#[test]
fn n_a_verified_token_is_still_refused_by_the_authorizer() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, _| false, verifier.clone());
        let exchange =
            assembled.exchange(unsigned("GET", &format!("/rustfs/admin/v3/object-zip-downloads/abc.zip?token={GOOD}")));
        assert_eq!(exchange.status, 403, "{}", exchange.body);
        assert!(exchange.reached.is_empty(), "{:?}", exchange.reached);
        assert_eq!(exchange.asked[0].caller.as_deref(), Some(ACCESS_KEY));
    }
}

/// Negative — with the verifier installed, a missing, empty, repeated, unknown, expired or
/// other-download token, a wrong suffix and a suffixless id are all refused before the authorizer.
#[test]
fn n_an_unverifiable_token_only_download_is_refused_without_asking() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, _| true, verifier.clone());
        let zip = "/rustfs/admin/v3/object-zip-downloads";
        for (uri, reaches_verifier) in [
            (format!("{zip}/abc.zip"), false),
            (format!("{zip}/abc.zip?token="), false),
            (format!("{zip}/abc.zip?token={GOOD}&token={GOOD}"), false),
            (format!("{zip}/abc.zip?token={GOOD}&token=invalid"), false),
            (format!("{zip}/abc.zip?token=invalid"), true),
            (format!("{zip}/abc.zip?token={EXPIRED}"), true),
            (format!("{zip}/abc.zip?token={OTHER_DOWNLOAD}"), true),
            (format!("{zip}/xyz.zip?token={GOOD}"), true),
            (format!("{zip}/abc.tar?token={GOOD}"), false),
            (format!("{zip}/abc?token={GOOD}"), false),
            (format!("{zip}/abc%2Ezip?token={GOOD}"), false),
            // The id is bound raw: neither decoded nor case-folded before the host compares it.
            (format!("{zip}/%61bc.zip?token={GOOD}"), true),
            (format!("{zip}/ABC.zip?token={GOOD}"), true),
        ] {
            refused_without_asking(&assembled.exchange(unsigned("GET", &uri)), &uri);
            assert_eq!(!asked_of(&verifier).is_empty(), reaches_verifier, "{uri}");
        }
    }
}

/// Negative — a tampered token is handed to the host byte for byte and refused: one character
/// flipped, case-folded, truncated, extended, and an appended encoded NUL. Each reaches the
/// verifier, so the refusal is the host's answer to the exact presented value, not a parse error.
#[test]
fn n_a_tampered_token_is_refused() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, _| true, verifier.clone());
        let zip = "/rustfs/admin/v3/object-zip-downloads/abc.zip";
        let tampered = [
            GOOD.replacen("abc", "abd", 1),
            GOOD.to_ascii_uppercase(),
            GOOD[..GOOD.len() - 1].to_owned(),
            format!("{GOOD}0"),
            format!("{GOOD}%00"),
        ];
        for token in tampered {
            assert_ne!(token, GOOD, "the fixture must tamper");
            let uri = format!("{zip}?token={token}");
            refused_without_asking(&assembled.exchange(unsigned("GET", &uri)), &uri);
            assert_eq!(asked_of(&verifier), ["abc"], "{uri}: the host decided");
        }
    }
}

/// The wall clock the clock-binding case pins, in the past, so the system clock is later.
const PINNED_AT: i64 = 1_700_000_000;
/// A token for download `abc` that expires exactly at [`PINNED_AT`].
const EXPIRES_NOW: &str = "tok-expires-now-sentinel";
/// A token for download `abc` that expires one second after [`PINNED_AT`].
const EXPIRES_NEXT: &str = "tok-expires-next-sentinel";

/// A decrypt-only host verifier that records the clock reading it was handed.
#[derive(Clone, Default)]
struct ClockedVerifier {
    seen: Arc<Mutex<Vec<i64>>>,
}

impl BearerTokenVerifier for ClockedVerifier {
    fn verify(&self, request: &BearerTokenRequest<'_>) -> Result<BearerGrant, BearerRefused> {
        let now = request.now().unix_seconds();
        self.seen.lock().expect("uncontended").push(now);
        let expires_at = match request.token() {
            EXPIRES_NOW => PINNED_AT,
            EXPIRES_NEXT => PINNED_AT + 1,
            _ => return Err(BearerRefused),
        };
        // Decrypt-only: the kernel applies `expires_at <= now` against its own clock reading.
        let identity = Identity::new(ACCESS_KEY).map_err(|_| BearerRefused)?;
        Ok(BearerGrant::new(identity, "abc", expires_at, Arc::new("archive-abc".to_owned())))
    }
}

/// Negative — the verifier is handed the service's own single clock reading, not an independent
/// one: under a clock pinned at [`PINNED_AT`] a token expiring at that instant is refused before
/// the authorizer, and one expiring a second later is admitted.
#[test]
fn n_expiry_is_judged_on_the_request_clock_at_its_exact_boundary() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = ClockedVerifier::default();
        let seen = Arc::clone(&verifier.seen);
        let assembled = super::assemble_installing(
            floor.clone(),
            |_, _| true,
            false,
            None,
            |builder| {
                builder.bearer_token_verifier(verifier).clock_with_skew_ack(
                    FixedClock::at_unix_seconds(PINNED_AT),
                    ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
                )
            },
        );
        let zip = "/rustfs/admin/v3/object-zip-downloads/abc.zip";
        let at_boundary = format!("{zip}?token={EXPIRES_NOW}");
        refused_without_asking(&assembled.exchange(unsigned("GET", &at_boundary)), &at_boundary);
        let next = assembled.exchange(unsigned("GET", &format!("{zip}?token={EXPIRES_NEXT}")));
        assert_eq!(next.status, 200, "{}", next.body);
        assert_eq!(next.reached, [ZIP_GET]);
        assert_eq!(
            *seen.lock().expect("uncontended"),
            [PINNED_AT, PINNED_AT],
            "the request's own clock reading"
        );
    }
}

/// Every `tracing` event and span field emitted on this thread, each rendered whole.
#[derive(Clone, Default)]
pub(super) struct Capture(pub(super) Arc<Mutex<Vec<String>>>);

struct Rendered(String);

impl tracing::field::Visit for Rendered {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
        self.0.push_str(&format!("{}={value:?};", field.name()));
    }
}

impl tracing::Subscriber for Capture {
    fn register_callsite(&self, _metadata: &'static tracing::Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut rendered = Rendered(String::from("span:"));
        span.record(&mut rendered);
        self.0.lock().expect("uncontended").push(rendered.0);
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, values: &tracing::span::Record<'_>) {
        let mut rendered = Rendered(String::from("record:"));
        values.record(&mut rendered);
        self.0.lock().expect("uncontended").push(rendered.0);
    }

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut rendered = Rendered(format!("{}:", event.metadata().target()));
        event.record(&mut rendered);
        self.0.lock().expect("uncontended").push(rendered.0);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// The process-wide subscriber: records nothing and never caches a callsite as uninteresting, so a
/// callsite first reached on another test's thread still asks this thread's capture.
pub(super) struct Undecided;

impl tracing::Subscriber for Undecided {
    fn register_callsite(&self, _metadata: &'static tracing::Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {}

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// Negative — nothing logged while the service admits a token-only download, refuses an expired
/// token, refuses a token without a verifier and refuses a header-signed download with another
/// principal's token holds any token. The refusals are among what was captured, so the scan saw
/// the request path's events.
#[test]
fn n_no_log_event_holds_a_token() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        // Another case may have installed one first; one only has to exist.
        let _ = tracing::subscriber::set_global_default(Undecided);
        let capture = Capture::default();
        let zip = "/rustfs/admin/v3/object-zip-downloads/abc.zip";
        let statuses = tracing::subscriber::with_default(capture.clone(), || {
            tracing::callsite::rebuild_interest_cache();
            let with_verifier = with_verifier(floor.clone(), |_, _| true, FixtureVerifier::default());
            let without = assemble_on(floor.clone(), |_, _| true);
            [
                with_verifier.exchange(unsigned("GET", &format!("{zip}?token={GOOD}"))).status,
                with_verifier
                    .exchange(unsigned("GET", &format!("{zip}?token={EXPIRED}")))
                    .status,
                without.exchange(unsigned("GET", &format!("{zip}?token={GOOD}"))).status,
                with_verifier
                    .exchange(signed_get(zip, &format!("token={OTHER_PRINCIPAL}")))
                    .status,
            ]
        });
        assert_eq!(statuses, [200, 403, 403, 403]);
        let events = capture.0.lock().expect("uncontended").clone();
        let refusals = events
            .iter()
            .filter(|event| event.contains("gateway_request_refused"))
            .count();
        assert_eq!(refusals, 3, "{events:#?}");
        for event in &events {
            let lowered = event.to_ascii_lowercase();
            assert!(!lowered.contains("sentinel"), "a log event holds a token: {event}");
            assert!(!lowered.contains("tok-"), "a log event holds a token: {event}");
        }
    }
}

/// Negative — no route but the zip download reads the token: a valid token on the minting `POST`,
/// on another admin operation and on the admin fallback is refused, and the verifier is never asked.
#[test]
fn n_a_token_on_any_other_route_is_refused_and_never_verified() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, _| true, verifier.clone());
        for (method, uri) in [
            ("POST", format!("/rustfs/admin/v3/object-zip-downloads?token={GOOD}")),
            ("PUT", format!("/rustfs/admin/v3/object-zip-downloads/abc.zip?token={GOOD}")),
            ("GET", format!("/rustfs/admin/v3/info?token={GOOD}")),
            ("GET", format!("/rustfs/admin/v3/no-such-route/abc.zip?token={GOOD}")),
        ] {
            let at = format!("{method} {uri}");
            refused_without_asking(&assembled.exchange(unsigned(method, &uri)), &at);
            assert!(asked_of(&verifier).is_empty(), "{at}: the verifier was asked");
        }
    }
}

/// Negative — without an installed verifier the claim refuses every token, the valid one included.
#[test]
fn n_without_a_verifier_a_valid_token_is_refused() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let assembled = assemble_on(floor.clone(), |_, _| true);
        for prefix in ["/rustfs/admin", "/minio/admin"] {
            let uri = format!("{prefix}/v3/object-zip-downloads/abc.zip?token={GOOD}");
            refused_without_asking(&assembled.exchange(unsigned("GET", &uri)), &uri);
        }
    }
}

/// Negative — a presented credential surface is never laundered through a good token: a malformed
/// `Authorization` header and a bad header signature are refused, and the verifier is never asked.
#[test]
fn n_a_bad_presented_credential_is_not_rescued_by_a_good_token() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, _| true, verifier.clone());
        let path = "/rustfs/admin/v3/object-zip-downloads/abc.zip";
        let query = format!("token={GOOD}");
        let mut malformed = unsigned("GET", &format!("{path}?{query}"));
        malformed
            .headers_mut()
            .insert(http::header::AUTHORIZATION, HeaderValue::from_static("Bearer something"));
        let mut tampered = signed_get(path, &query);
        let authorization = tampered.headers()[http::header::AUTHORIZATION]
            .to_str()
            .expect("ascii")
            .to_owned();
        let flipped = if authorization.ends_with('0') { '1' } else { '0' };
        let tampered_value = format!("{}{flipped}", &authorization[..authorization.len() - 1]);
        tampered.headers_mut().insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&tampered_value).expect("a header value"),
        );
        for (at, request) in [("malformed authorization", malformed), ("tampered signature", tampered)] {
            let exchange = assembled.exchange(request);
            assert!(matches!(exchange.status, 400 | 403), "{at}: {} {}", exchange.status, exchange.body);
            assert!(exchange.reached.is_empty(), "{at}: {:?}", exchange.reached);
            assert!(exchange.asked.is_empty(), "{at}: {:?}", exchange.asked);
            assert!(asked_of(&verifier).is_empty(), "{at}: the verifier was asked");
        }
    }
}

/// Positive — a header-signed download keeps its signature path. Without a verifier nothing about
/// it changes; with one, a token issued to the signed principal is verified alongside, the signed
/// principal stays the principal, and no context holds the token.
#[test]
fn a_signed_download_still_works_with_and_without_a_verifier() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let path = "/rustfs/admin/v3/object-zip-downloads/abc.zip";
        let plain = assemble_on(floor.clone(), |_, _| true).exchange(signed_get(path, &format!("token={GOOD}")));
        assert_eq!(plain.status, 200, "{}", plain.body);
        assert_eq!(plain.handed[0].principal.as_deref(), Some(ACCESS_KEY));
        assert_eq!(plain.handed[0].bearer, None);
        assert_eq!(plain.handed[0].raw_query, format!("token={GOOD}"));
        assert!(!plain.asked.is_empty());
        assert!(
            plain
                .asked
                .iter()
                .all(|asked| asked.query.as_deref() == Some(format!("token={GOOD}").as_str()))
        );
        assert!(plain.asked.iter().all(|asked| asked.scheme == "SigV4Header"), "{:?}", plain.asked);

        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, _| true, verifier.clone());
        let exchange = assembled.exchange(signed_get(path, &format!("token={GOOD}")));
        assert_eq!(exchange.status, 200, "{}", exchange.body);
        assert_eq!(asked_of(&verifier), ["abc"]);
        let handed = &exchange.handed[0];
        assert_eq!(handed.principal.as_deref(), Some(ACCESS_KEY));
        assert_eq!(handed.bearer, Some((ACCESS_KEY.to_owned(), Some("archive-abc".to_owned()))));
        assert_eq!(handed.raw_query, "");
        for asked in &exchange.asked {
            assert_eq!(asked.scheme, "SigV4Header", "{asked:?}");
            assert_eq!(asked.query.as_deref(), Some(""), "{asked:?}");
        }
    }
}

/// Negative — with the verifier installed, a signed download must also carry a token the verifier
/// accepts for this download and for the signed principal.
#[test]
fn n_with_a_verifier_a_signed_download_needs_its_own_principals_token() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = with_verifier(floor.clone(), |_, _| true, verifier);
        let path = "/rustfs/admin/v3/object-zip-downloads/abc.zip";
        for query in [
            String::new(),
            "token=invalid".to_owned(),
            format!("token={OTHER_PRINCIPAL}"),
            format!("token={OTHER_DOWNLOAD}"),
            format!("token={EXPIRED}"),
        ] {
            refused_without_asking(&assembled.exchange(signed_get(path, &query)), &query);
        }
    }
}

/// The real assembly reports the declared route and whether its verifier is installed.
#[test]
fn startup_posture_reports_bearer_claims_and_the_installed_verifier() {
    let absent = assemble(|_, _| true);
    let installed = assemble_with_bearer_verifier(|_, _| true, FixtureVerifier::default());
    let declared = "bearer_claimed_ops=[rustfs:GetV3ObjectZipDownloadsByIdZip]";
    let absent_report = absent.service.startup_posture();
    let installed_report = installed.service.startup_posture();
    assert!(absent_report.contains(declared), "{absent_report}");
    assert!(absent_report.contains("bearer_verifier=none"), "{absent_report}");
    assert!(installed_report.contains(declared), "{installed_report}");
    assert!(installed_report.contains("bearer_verifier=installed"), "{installed_report}");
    assert!(!installed_report.contains("bearer_verifier=none"), "{installed_report}");
}
