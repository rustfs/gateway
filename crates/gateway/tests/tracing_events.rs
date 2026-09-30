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

//! The `tracing` events the facade emits, captured from a real assembly and a real request
//! (rustfs/gateway#1162).
//!
//! Responsible for: that the start-up report, a dangerous assembly and a panicking report callback
//! each arrive as one event at the level `docs/observability.md` gives it, under the one target, in
//! RustFS's field order (`event`, `component`, `subsystem` first), with the sentence the start-up
//! log always carried; and that no event anything here emits carries credential material.
//! NOT responsible for: the lines themselves (`src/posture.rs` and the other posture modules pin
//! their text) or installing a subscriber in a host.
//! Upstream: `rustfs-gateway`, `tracing`, `support`. Downstream: nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use rustfs_gateway::{
    ClockSkewAck, Credentials, Observer, PresignedExpiryRule, RegionSet, RequestEvent, S3Service, SecurityFloor, ServiceBuilder,
    SigV4Authenticator, StaticCredentials,
};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};

use crate::support::{self, Backend, Ping};

/// The target every event of the facade is emitted under.
const TARGET: &str = "rustfs_gateway";

/// One captured event: its level, target, and fields in declaration order, `message` included.
#[derive(Clone, Debug)]
struct Captured {
    level: Level,
    target: String,
    fields: Vec<(String, String)>,
}

impl Captured {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }

    fn names(&self) -> Vec<&str> {
        self.fields.iter().map(|(name, _)| name.as_str()).collect()
    }

    fn rendered(&self) -> String {
        format!("{self:?}")
    }
}

/// A subscriber that keeps every event, and nothing about spans.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Captured>>>);

impl Capture {
    fn events(&self) -> Vec<Captured> {
        self.0.lock().expect("not poisoned").clone()
    }

    fn named(&self, event: &str) -> Vec<Captured> {
        self.events()
            .into_iter()
            .filter(|captured| captured.field("event") == Some(event))
            .collect()
    }
}

struct Fields(Vec<(String, String)>);

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.push((field.name().to_owned(), value.to_owned()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn core::fmt::Debug) {
        self.0.push((field.name().to_owned(), format!("{value:?}")));
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut fields = Fields(Vec::new());
        event.record(&mut fields);
        self.0.lock().expect("not poisoned").push(Captured {
            level: *event.metadata().level(),
            target: event.metadata().target().to_owned(),
            fields: fields.0,
        });
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// The process-wide subscriber while these cases run: records nothing, and never decides for good
/// whether a callsite is of interest.
///
/// `tracing` caches each callsite's interest process-wide. A callsite first reached by another
/// case's thread while no subscriber anywhere wanted it — every assembly with a custom clock reaches
/// the dangerous-assembly event — can be cached as never interesting, racing the registration of
/// a capture on this thread, and the capture then misses the event. With this global subscriber
/// every interest is "sometimes", so each event asks the dispatcher of the thread it is emitted on.
struct Undecided;

impl Subscriber for Undecided {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Runs `work` on this thread with a fresh capture as the default subscriber, on a current-thread
/// runtime so every event the service emits is emitted here.
fn captured<T>(work: impl FnOnce(&tokio::runtime::Runtime) -> T) -> (T, Capture) {
    static UNDECIDED: OnceLock<()> = OnceLock::new();
    UNDECIDED.get_or_init(|| {
        // A global subscriber installed first by another case would do as well; one only has to exist.
        let _ = tracing::subscriber::set_global_default(Undecided);
    });
    // And a callsite whose registration straddled the installation is decided again now.
    tracing::callsite::rebuild_interest_cache();
    let capture = Capture::default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a test runtime");
    let value = tracing::subscriber::with_default(capture.clone(), || work(&runtime));
    (value, capture)
}

fn ping_service(builder: ServiceBuilder) -> S3Service {
    builder
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&support::ping_dialect())
        .build()
        .expect("a complete assembly")
}

/// Holds `captured` to the shape every event of the facade has: the one target, a message, and
/// `event`, `component` and `subsystem` as the first named fields, in RustFS's order. (`tracing`
/// records the message ahead of every named field whatever the call site's order, which is why the
/// message is not held to a position.)
fn rustfs_shaped(captured: &Captured, subsystem: &str) {
    assert_eq!(captured.target, TARGET, "{captured:?}");
    let named: Vec<&str> = captured.names().into_iter().filter(|name| *name != "message").collect();
    assert_eq!(named.get(..3), Some(&["event", "component", "subsystem"][..]), "{captured:?}");
    assert_eq!(captured.field("component"), Some("gateway"), "{captured:?}");
    assert_eq!(captured.field("subsystem"), Some(subsystem), "{captured:?}");
    assert!(captured.field("message").is_some_and(|message| !message.is_empty()), "{captured:?}");
}

/// Negative — a default assembly reports its posture as three `info` events carrying the start-up
/// lines, and nothing at `warn` or above: a default is not a dangerous choice.
#[test]
fn a_default_assembly_reports_its_posture_in_three_info_events() {
    let (_service, capture) = captured(|_| ping_service(support::wired()));
    for (event, prefix) in [
        ("gateway_security_posture", "SECURITY_POSTURE anonymous_reachable_ops=["),
        ("gateway_dialect_posture", "DIALECT_POSTURE claimed_prefixes=["),
        ("gateway_naming_posture", "NAMING_POSTURE slash_policy="),
    ] {
        let events = capture.named(event);
        assert_eq!(events.len(), 1, "{event}: {:?}", capture.events());
        let posture = &events[0];
        assert_eq!(posture.level, Level::INFO, "{posture:?}");
        rustfs_shaped(posture, "posture");
        assert!(posture.field("message").is_some_and(|line| line.starts_with(prefix)), "{posture:?}");
    }
    assert!(capture.named("gateway_presigned_expiry_posture").is_empty(), "{:?}", capture.events());
    let loud: Vec<Captured> = capture
        .events()
        .into_iter()
        .filter(|captured| captured.level <= Level::WARN)
        .collect();
    assert!(loud.is_empty(), "{loud:?}");
}

/// Negative — a widened presigned-lifetime rule is reported on its own line, and only when it is on.
#[test]
fn a_widened_presigned_lifetime_rule_is_reported() {
    let floor = SecurityFloor::new().with_presigned_expiry_rule(PresignedExpiryRule::LegacyRustfs);
    let (_service, capture) = captured(|_| ping_service(support::wired().security_floor(floor)));
    let events = capture.named("gateway_presigned_expiry_posture");
    assert_eq!(events.len(), 1, "{:?}", capture.events());
    assert_eq!(events[0].level, Level::INFO);
    rustfs_shaped(&events[0], "posture");
    assert_eq!(events[0].field("message"), Some("PRESIGNED_EXPIRY_POSTURE rule=legacy-rustfs"));
}

/// Negative — a custom wall clock is one `warn` event naming its reason, with the sentence the
/// start-up log always carried for it.
#[test]
fn a_custom_wall_clock_is_one_warn_event_naming_its_reason() {
    let clock = support::fixed_clock();
    let ack = ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry();
    let (_service, capture) = captured(|_| ping_service(support::wired().clock_with_skew_ack(clock, ack)));
    let events = capture.named("gateway_dangerous_assembly");
    assert_eq!(events.len(), 1, "{:?}", capture.events());
    let warning = &events[0];
    assert_eq!(warning.level, Level::WARN);
    rustfs_shaped(warning, "assembly");
    assert_eq!(warning.field("reason"), Some("custom_wall_clock"));
    assert_eq!(
        warning.field("message"),
        Some("a custom wall clock is installed; signature expiry and clock skew follow it, not the system clock")
    );
}

/// What a panicking observer panics with: text a log line must never repeat.
const PANIC_PAYLOAD: &str = "observer payload wJalrXUtnFEMI/K7MDENG";

struct PanickingObserver;

impl Observer for PanickingObserver {
    fn on_response(&self, _event: &RequestEvent<'_>) {
        std::panic::panic_any(PANIC_PAYLOAD.to_owned());
    }
}

/// Negative — a panicking observer is one `error` event naming the callback and saying the answer
/// went out unchanged; the payload, which is deployment text, is in no field. (The process's panic
/// hook still sees the panic; under the test harness its output is captured with the test's.)
#[test]
fn a_panicking_observer_is_one_error_event_without_its_payload() {
    let (status, capture) = captured(|runtime| {
        let service = ping_service(support::wired().observer(PanickingObserver));
        runtime.block_on(async {
            let response = service.call_bytes(support::plain(http::Method::POST, "/")).await;
            response.status()
        })
    });
    assert_eq!(status, http::StatusCode::OK);
    let events = capture.named("gateway_report_panicked");
    assert_eq!(events.len(), 1, "{:?}", capture.events());
    let panicked = &events[0];
    assert_eq!(panicked.level, Level::ERROR);
    rustfs_shaped(panicked, "report");
    assert_eq!(panicked.field("result"), Some("contained"));
    assert_eq!(panicked.field("callback"), Some("request observer"));
    assert_eq!(panicked.field("suppressed"), Some("0"));
    assert_eq!(panicked.field("message"), Some("request observer panicked; the response was not changed"));
    for captured in capture.events() {
        assert!(!captured.rendered().contains("wJalrXUtnFEMI"), "{captured:?}");
    }
}

/// Every field value of every event, for the credential scan.
fn every_value(capture: &Capture) -> BTreeMap<String, String> {
    capture
        .events()
        .into_iter()
        .enumerate()
        .flat_map(|(index, captured)| {
            captured
                .fields
                .into_iter()
                .map(move |(name, value)| (format!("{index}.{name}"), value))
        })
        .collect()
}

/// The secret the scanned service verifies with and the scanned requests are signed with: text
/// no event has any other reason to contain.
const SCAN_SECRET: &[u8] = b"tracing-scan-secret-7Qv2Lr9Xw4";

/// Whether `value` holds 64 hexadecimal digits in a row: the shape of a SigV4 signature, whether
/// the caller's or the one the verifier computed, and of a payload hash.
fn holds_a_signature(value: &str) -> bool {
    let mut run = 0;
    value.chars().any(|character| {
        run = if character.is_ascii_hexdigit() { run + 1 } else { 0 };
        run >= 64
    })
}

/// The bucket and key of the scanned scenario's denied read: caller text no event may repeat.
const SCAN_BUCKET: &str = "scan-bucket-5b1e";
const SCAN_KEY: &str = "scan-private-key-8c3d";

/// A body-less request signed with [`SCAN_SECRET`], as `support::signed` signs with the shared one.
fn signed_with_scan_secret(method: &http::Method, path: &str) -> http::Request<Bytes> {
    use rustfs_gateway::sig::{AmzDate, PayloadMode, SigService, SigV4Signer, SigningCredentials, SigningRequest, SigningScope};

    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, http::HeaderValue::from_static("s3.example.com"));
    let probe = http::Request::builder()
        .uri("/")
        .header("host", "s3.example.com")
        .body(Bytes::new())
        .expect("a valid request");
    let accepted = rustfs_gateway::WireRequest::accept(probe, &rustfs_gateway::Limits::default()).expect("an acceptable host");
    let credentials = SigningCredentials::new("AKIDEXAMPLE", SCAN_SECRET).expect("valid credentials");
    let stamp = AmzDate::parse(support::SIGNED_AT_STAMP).expect("a SigV4 stamp");
    let scope = SigningScope::new(stamp.day(), "us-east-1", SigService::S3).expect("a well-formed scope");
    let signing = SigningRequest::new(method, path, "", &headers, accepted.host().raw_for_signing(), PayloadMode::Empty, stamp);
    let signed = SigV4Signer::new(credentials, scope)
        .sign_headers(&signing)
        .expect("a signable request");
    let mut request = http::Request::builder().method(method.clone()).uri(path);
    for (name, value) in signed.headers() {
        request = request.header(name, value);
    }
    request.body(Bytes::new()).expect("a valid request")
}

/// What the scanned scenario was answered: a signed request, the same request with its signature
/// forged, and a signed read the authorizer denies.
type ScanAnswers = (http::StatusCode, http::StatusCode, http::StatusCode);

/// The scanned scenario: assemble a service that verifies with [`SCAN_SECRET`], answer a request
/// signed with it, refuse the same request with its signature forged, and refuse a signed read of
/// [`SCAN_KEY`] in [`SCAN_BUCKET`] at authorization.
fn scan_scenario(observer: Option<PoisoningObserver>) -> (ScanAnswers, Capture) {
    captured(|runtime| {
        let credentials =
            Arc::new(StaticCredentials::new().with(Credentials::new("AKIDEXAMPLE", SCAN_SECRET).expect("a valid access key id")));
        let mut builder = ServiceBuilder::new()
            .authenticator(SigV4Authenticator::new(credentials, RegionSet::new(["us-east-1"]).expect("non-empty")))
            .authorizer(rustfs_gateway::decide_with(|request| {
                if request.key.map(|key| key.as_str()) == Some(SCAN_KEY) {
                    rustfs_gateway::Decision::Deny
                } else {
                    rustfs_gateway::Decision::Allow
                }
            }))
            .clock_with_skew_ack(
                support::fixed_clock(),
                ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
            )
            .register::<rustfs_gateway::dto::GetObject, _>(Arc::new(Present));
        if let Some(observer) = observer {
            builder = builder.observer(observer);
        }
        let service = ping_service(builder);
        runtime.block_on(async {
            let accepted = service.call_bytes(signed_with_scan_secret(&http::Method::POST, "/")).await;
            let denied = service
                .call_bytes(signed_with_scan_secret(&http::Method::GET, &format!("/{SCAN_BUCKET}/{SCAN_KEY}")))
                .await;
            let mut forged = signed_with_scan_secret(&http::Method::POST, "/");
            let authorization = forged
                .headers()
                .get(http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .expect("a signed request carries its authorization");
            let (kept, _) = authorization.split_at(authorization.len() - 64);
            let forged_authorization = format!("{kept}{}", "0".repeat(64));
            forged.headers_mut().insert(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_str(&forged_authorization).expect("a header value"),
            );
            let refused = service.call_bytes(forged).await;
            (accepted.status(), refused.status(), denied.status())
        })
    })
}

/// The field that carries credential material or caller text, if any: the access key, the secret,
/// an `Authorization` value or any piece of one, a signature (the caller's, the forged one or the
/// one the verifier computed), a string to sign, a canonical request, or the bucket and key a
/// refused read named.
fn credential_material(capture: &Capture) -> Option<(String, String)> {
    let secret = std::str::from_utf8(SCAN_SECRET).expect("an ASCII secret");
    every_value(capture).into_iter().find(|(_, value)| {
        [
            "AKIDEXAMPLE",
            secret,
            SCAN_BUCKET,
            SCAN_KEY,
            "Authorization",
            "AWS4-HMAC-SHA256",
            "Signature=",
            "Credential=",
            "SignedHeaders=",
            "StringToSign",
            "CanonicalRequest",
            "x-amz-security-token",
        ]
        .iter()
        .any(|needle| value.contains(needle))
            || holds_a_signature(value)
    })
}

/// Emits credential material from inside the request path, where every event of the scanned
/// scenario is emitted: the control that the scan sees such a field when one exists.
struct PoisoningObserver;

impl Observer for PoisoningObserver {
    fn on_response(&self, _event: &RequestEvent<'_>) {
        tracing::warn!(
            target: TARGET,
            event = "poison",
            value = "Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request"
        );
    }
}

/// Negative — nothing the facade emits while it assembles, answers a signed request, refuses a
/// forged one and refuses a denied read carries credential material or the caller's bucket and key,
/// and both refusals are among what was scanned. The poison control proves the scan sees a field
/// emitted on the request path when one carries it.
#[test]
fn no_event_carries_credential_material() {
    use http::StatusCode;

    let (answers, capture) = scan_scenario(None);
    assert_eq!(answers, (StatusCode::OK, StatusCode::FORBIDDEN, StatusCode::FORBIDDEN));
    let subsystems: Vec<Option<String>> = capture
        .named("gateway_request_refused")
        .iter()
        .map(|refusal| refusal.field("subsystem").map(str::to_owned))
        .collect();
    assert_eq!(subsystems.len(), 2, "{:?}", capture.events());
    assert!(subsystems.contains(&Some("authentication".to_owned())), "{subsystems:?}");
    assert!(subsystems.contains(&Some("authorization".to_owned())), "{subsystems:?}");
    assert_eq!(credential_material(&capture), None);

    let (answers, poisoned) = scan_scenario(Some(PoisoningObserver));
    assert_eq!(answers, (StatusCode::OK, StatusCode::FORBIDDEN, StatusCode::FORBIDDEN));
    assert!(credential_material(&poisoned).is_some(), "{:?}", poisoned.events());
}

/// A `GetObject` handler that finds the object: `GetObject` is the operation that asks the
/// `s3:ListBucket` visibility question.
struct Present;

impl rustfs_gateway::Handler<rustfs_gateway::dto::GetObject> for Present {
    async fn call(
        &self,
        _request: rustfs_gateway::Req<rustfs_gateway::dto::GetObject>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::GetObject> {
        Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::GetObjectOutput::default()))
    }
}

/// The refusal and panic events (rustfs/gateway#1162), split out at the 800-line limit.
#[path = "tracing_events/refusals.rs"]
mod refusals;
