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

//! The zip download's bearer contract under both security floors (ADR-0042, rustfs/gateway#1400).
//!
//! Responsible for: the kernel's own download and expiry comparison against a decrypt-only host,
//! under the default floor and under the RustFS profile's legacy signature recognition; refusal of
//! a token beside any AWS credential surface (partial, presigned SigV4, SigV2, session token);
//! the questions both authorization stages are asked; the pinned decoding of a literal `+`; no
//! token in audit or observer events; and a panicking host verifier failing closed.
//! NOT responsible for: the parsing and context rows `zip_token_tests` pins, or the token's
//! cryptography (the host's).
//! Upstream: `super`'s harness and `zip_token_tests`' fixture. Downstream: nothing.

use std::sync::{Arc, Mutex};

use http::HeaderValue;
use rustfs_gateway::{AuthzAuditEvent, AuthzAuditSink, Observer, RequestEvent, SecurityFloor};

use super::zip_token_tests::{
    Capture, EXPIRED, FixtureVerifier, GOOD, OTHER_DOWNLOAD, PANICS, PLUS, Undecided, ZIP_GET, asked_of, floors,
    refused_without_asking, unsigned,
};
use super::{Assembled, assemble_installing};
use crate::operation_diff::s3s_0_17_0::context::ACCESS_KEY;

const ZIP: &str = "/rustfs/admin/v3/object-zip-downloads";
const DOWNLOAD_ACTION: &str = "rustfs:DownloadObjectZip";

fn behind(floor: SecurityFloor, verifier: FixtureVerifier) -> Assembled {
    assemble_installing(
        floor,
        |_, action| action == DOWNLOAD_ACTION,
        false,
        None,
        |builder| builder.bearer_token_verifier(verifier),
    )
}

/// Positive — under both floors the token-only URL is admitted as the token's principal.
#[test]
fn a_token_only_download_is_admitted_under_both_floors() {
    for (name, floor) in floors() {
        let verifier = FixtureVerifier::default();
        let assembled = behind(floor, verifier.clone());
        let exchange = assembled.exchange(unsigned("GET", &format!("{ZIP}/abc.zip?token={GOOD}")));
        assert_eq!(exchange.status, 200, "{name}: {}", exchange.body);
        assert_eq!(exchange.reached, [ZIP_GET], "{name}");
        assert_eq!(asked_of(&verifier), ["abc"], "{name}");
    }
}

/// Negative — the kernel, not the host, binds the token to its download and its lifetime: a
/// decrypt-only host's grant for download `xyz` is refused on `abc`, its grant for `abc` on
/// `xyz`, and an expired grant on its own download, under both floors.
#[test]
fn n_a_grant_for_another_download_or_past_its_expiry_is_refused_by_the_kernel() {
    for (name, floor) in floors() {
        let verifier = FixtureVerifier::default();
        let assembled = behind(floor, verifier.clone());
        for (uri, bound) in [
            (format!("{ZIP}/abc.zip?token={OTHER_DOWNLOAD}"), "abc"),
            (format!("{ZIP}/xyz.zip?token={GOOD}"), "xyz"),
            (format!("{ZIP}/abc.zip?token={EXPIRED}"), "abc"),
        ] {
            let at = format!("{name}: {uri}");
            refused_without_asking(&assembled.exchange(unsigned("GET", &uri)), &at);
            assert_eq!(asked_of(&verifier), [bound], "{at}: the host decrypted, the kernel refused");
        }
    }
}

/// Negative — a token never rescues an AWS credential surface, complete or partial, under either
/// floor: a credential without its signature, a presigned SigV4 query, a SigV2 query, and a
/// session token in the query or a header are all refused, and the verifier is never asked.
#[test]
fn n_a_token_beside_any_aws_credential_surface_is_refused_under_both_floors() {
    let credential = "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20260101%2Fus-east-1%2Fs3%2Faws4_request";
    let presigned = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&{credential}&X-Amz-Date=20260101T000000Z&X-Amz-Expires=300\
         &X-Amz-SignedHeaders=host&X-Amz-Signature={}",
        "0".repeat(64)
    );
    let queries = [
        ("partial SigV4 credential", credential.to_owned()),
        ("presigned SigV4", presigned),
        (
            "SigV2 query",
            "AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1900000000&Signature=AAAAAAAAAAAAAAAAAAAAAAAAAAA%3D".to_owned(),
        ),
        ("SigV2 access key only", "AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE".to_owned()),
        ("query session token", "X-Amz-Security-Token=FwoGZXIvYXdz".to_owned()),
    ];
    for (name, floor) in floors() {
        let verifier = FixtureVerifier::default();
        let assembled = behind(floor, verifier.clone());
        for (surface, query) in &queries {
            let at = format!("{name}: {surface}");
            let exchange = assembled.exchange(unsigned("GET", &format!("{ZIP}/abc.zip?token={GOOD}&{query}")));
            assert!(matches!(exchange.status, 400 | 403), "{at}: {} {}", exchange.status, exchange.body);
            assert!(exchange.reached.is_empty(), "{at}: {:?}", exchange.reached);
            assert!(exchange.asked.is_empty(), "{at}: {:?}", exchange.asked);
            assert!(asked_of(&verifier).is_empty(), "{at}: the verifier was asked");
        }
        let mut header_token = unsigned("GET", &format!("{ZIP}/abc.zip?token={GOOD}"));
        header_token
            .headers_mut()
            .insert("x-amz-security-token", HeaderValue::from_static("FwoGZXIvYXdz"));
        let exchange = assembled.exchange(header_token);
        assert!(matches!(exchange.status, 400 | 403), "{name}: header session token: {}", exchange.status);
        assert!(exchange.reached.is_empty(), "{name}: header session token");
        assert!(asked_of(&verifier).is_empty(), "{name}: header session token: the verifier was asked");
    }
}

/// Negative — both authorization stages are asked, once each, about the token's principal, the
/// download action and the routed operation under the bearer scheme. (A denial stopping the
/// handler is `zip_token_tests::n_a_verified_token_is_still_refused_by_the_authorizer`.)
#[test]
fn n_both_authorization_stages_judge_the_bearer_principal() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let assembled = behind(floor.clone(), FixtureVerifier::default());
        let exchange = assembled.exchange(unsigned("GET", &format!("{ZIP}/abc.zip?token={GOOD}")));
        assert_eq!(exchange.status, 200, "{}", exchange.body);
        let stages: Vec<&str> = exchange.asked.iter().map(|asked| asked.stage).collect();
        assert_eq!(stages, ["route", "input"], "{:?}", exchange.asked);
        for asked in &exchange.asked {
            assert_eq!(asked.operation, ZIP_GET, "{asked:?}");
            assert_eq!(asked.action, DOWNLOAD_ACTION, "{asked:?}");
            assert_eq!(asked.caller.as_deref(), Some(ACCESS_KEY), "{asked:?}");
            assert_eq!(asked.scheme, "Bearer", "{asked:?}");
        }
    }
}

/// Negative — a token is decoded once by RFC 3986 rules: a literal `+` stays a `+` (no form
/// decoding), `%2B` decodes to the same `+`, and `%20` is a different token.
#[test]
fn n_a_literal_plus_in_a_token_is_not_a_space() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let verifier = FixtureVerifier::default();
        let assembled = behind(floor.clone(), verifier.clone());
        for uri in [
            format!("{ZIP}/abc.zip?token={PLUS}"),
            format!("{ZIP}/abc.zip?token=tok%2Bplus-sentinel"),
        ] {
            let exchange = assembled.exchange(unsigned("GET", &uri));
            assert_eq!(exchange.status, 200, "{uri}: {}", exchange.body);
            assert_eq!(asked_of(&verifier), ["abc"], "{uri}");
        }
        let spaced = format!("{ZIP}/abc.zip?token=tok%20plus-sentinel");
        refused_without_asking(&assembled.exchange(unsigned("GET", &spaced)), &spaced);
        assert_eq!(asked_of(&verifier), ["abc"], "{spaced}: the host saw a different token");
    }
}

/// One rendered audit or observer event, with the access key of the identity it named.
type Recorded = (String, Option<String>);

/// Every audit and observer event of the scanned requests.
#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<Recorded>>>);

impl AuthzAuditSink for Events {
    fn on_decision(&self, event: &AuthzAuditEvent<'_>) {
        let identity = event.identity.map(|identity| identity.access_key_id().to_owned());
        self.0
            .lock()
            .expect("uncontended")
            .push((format!("audit {event:?}"), identity));
    }
}

impl Observer for Events {
    fn on_response(&self, event: &RequestEvent<'_>) {
        let identity = event.identity.map(|identity| identity.access_key_id().to_owned());
        self.0
            .lock()
            .expect("uncontended")
            .push((format!("observer {event:?}"), identity));
    }
}

/// Negative — audit and observer events for an admitted bearer request name the verified
/// principal under the bearer scheme, the refused one names nobody, and no event holds a token.
#[test]
fn n_audit_and_observer_events_name_the_principal_and_hold_no_token() {
    for (floor_name, floor) in floors() {
        eprintln!("floor: {floor_name}");
        let events = Events::default();
        let (audit, observed) = (events.clone(), events.clone());
        let assembled = assemble_installing(
            floor.clone(),
            |_, _| true,
            false,
            None,
            |builder| {
                builder
                    .bearer_token_verifier(FixtureVerifier::default())
                    .authz_audit(audit)
                    .observer(observed)
            },
        );
        let admitted = assembled.exchange(unsigned("GET", &format!("{ZIP}/abc.zip?token={GOOD}")));
        assert_eq!(admitted.status, 200, "{}", admitted.body);
        let recorded = std::mem::take(&mut *events.0.lock().expect("uncontended"));
        let audits: Vec<_> = recorded.iter().filter(|(event, _)| event.starts_with("audit ")).collect();
        let observers: Vec<_> = recorded.iter().filter(|(event, _)| event.starts_with("observer ")).collect();
        assert_eq!(audits.len(), 2, "{recorded:#?}");
        assert_eq!(observers.len(), 1, "{recorded:#?}");
        for (event, identity) in &recorded {
            assert_eq!(identity.as_deref(), Some(ACCESS_KEY), "{event}");
            assert!(!event.to_ascii_lowercase().contains("sentinel"), "{event}");
        }
        for (event, _) in &audits {
            assert!(event.contains("auth_scheme: Bearer"), "{event}");
        }

        let refused = assembled.exchange(unsigned("GET", &format!("{ZIP}/abc.zip?token={EXPIRED}")));
        assert_eq!(refused.status, 403, "{}", refused.body);
        let recorded = std::mem::take(&mut *events.0.lock().expect("uncontended"));
        assert_eq!(recorded.len(), 1, "{recorded:#?}");
        let (event, identity) = &recorded[0];
        assert!(event.starts_with("observer "), "{event}");
        assert_eq!(identity, &None, "{event}");
        assert!(!event.to_ascii_lowercase().contains("sentinel"), "{event}");
    }
}

/// Negative — a host verifier that panics fails closed: `403`, no authorizer question, no
/// handler, no token in the answer, under both floors; the same service answers the next valid
/// token normally, so the panic left nothing shared poisoned; and the panic is reported as one
/// `gateway_extension_panicked` event naming the bearer verifier, with no token in any event.
#[test]
fn n_a_panicking_verifier_fails_closed_and_poisons_nothing() {
    let _ = tracing::subscriber::set_global_default(Undecided);
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), || {
        tracing::callsite::rebuild_interest_cache();
        for (floor_name, floor) in floors() {
            eprintln!("floor: {floor_name}");
            let verifier = FixtureVerifier::default();
            let assembled = behind(floor.clone(), verifier.clone());
            let uri = format!("{ZIP}/abc.zip?token={PANICS}");
            refused_without_asking(&assembled.exchange(unsigned("GET", &uri)), &uri);
            let next = assembled.exchange(unsigned("GET", &format!("{ZIP}/abc.zip?token={GOOD}")));
            assert_eq!(next.status, 200, "{}", next.body);
            assert_eq!(next.reached, [ZIP_GET]);
            assert_eq!(asked_of(&verifier), ["abc"]);
        }
    });
    // One contained-panic event names the bearer verifier and its `403`; the second floor's panic
    // falls inside the event's five-second throttle, and no other test panics this verifier.
    let events = capture.0.lock().expect("uncontended").clone();
    let panicked: Vec<&String> = events
        .iter()
        .filter(|event| event.contains("gateway_extension_panicked"))
        .collect();
    assert_eq!(panicked.len(), 1, "{events:#?}");
    assert!(panicked[0].contains("extension=\"bearer_verifier\""), "{}", panicked[0]);
    assert!(panicked[0].contains("answered 403"), "{}", panicked[0]);
    assert!(panicked[0].contains("suppressed=0"), "{}", panicked[0]);
    for event in &events {
        assert!(!event.to_ascii_lowercase().contains("sentinel"), "{event}");
    }
}
