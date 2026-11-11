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

//! The STS form endpoint's SigV2 refusal through the assembled service (ADR-0052,
//! rustfs/gateway#1592), with a credential provider that records every lookup.
//!
//! Responsible for: every SigV2 shape the route can see — header and presigned, signed with the
//! shared secret or a forged one, on ordinary `AssumeRole` and on Web Identity — refused
//! `403 AccessDenied` on the default floor and the RustFS profile's, with no credential lookup, no
//! authorizer question and no handler; one answer for a known and an unknown access key; and the
//! controls in both directions — SigV4 `AssumeRole` and unsigned Web Identity still reach the
//! handler, and an operation without the rule (`HeadObject`) still admits SigV2 and does consult
//! the provider, so the recorder is shown to see a lookup when one happens; the odd spellings
//! rustfs/gateway#1592's review probed, each pinned to "no principal reaches the handler"; and the
//! RustFS profile's header-signature view policy, which answers a SigV2 header's missing, unreadable
//! or skewed date before the floor, with an answer that depends on neither key nor signature.
//! NOT responsible for: the floor's own rule (`rustfs-gateway-sig`'s `sigv2_refused_floor`), or
//! the comparison with legacy RustFS (`super`). A SigV2 POST policy cannot reach this route: the
//! STS claim takes only an `application/x-www-form-urlencoded` body, so the floor-level suite
//! covers that shape.
//! Upstream: `super`'s assembly and signers, `super::sec1`'s ordinary S3 fixtures. Downstream:
//! nothing.

use std::sync::atomic::{AtomicUsize, Ordering};

use http::HeaderValue;
use rustfs_gateway::dto::HeadObject;
use rustfs_gateway::{CredentialLookup, CredentialProvider, ProviderError};

use super::sec1::{ObjectAuthorizer, ObjectHandler, sign_v2};
use super::*;

const WEB_IDENTITY: &[u8] = b"Action=AssumeRoleWithWebIdentity&Version=2011-06-15&WebIdentityToken=fixture";
const UNKNOWN_KEY: &str = "AKIDNOSUCHKEY";

/// Records every access key it is asked for; knows only the shared credential.
#[derive(Clone, Default)]
struct Recording(Arc<Mutex<Vec<String>>>);

impl Recording {
    fn lookups(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().expect("uncontended"))
    }
}

impl CredentialProvider for Recording {
    fn lookup<'a>(&'a self, access_key_id: &'a str) -> BoxFuture<'a, Result<CredentialLookup, ProviderError>> {
        self.0.lock().expect("uncontended").push(access_key_id.to_owned());
        let found = if access_key_id == ACCESS_KEY {
            CredentialLookup::Found(Credentials::new(ACCESS_KEY, SECRET_KEY.as_bytes()).expect("a fixture credential"))
        } else {
            CredentialLookup::NotFound
        };
        Box::pin(async move { Ok(found) })
    }
}

/// The two floors: the default one, and the RustFS profile's.
fn floors() -> [(&'static str, SecurityFloor); 2] {
    [
        ("default floor", SecurityFloor::new()),
        ("RustFS profile floor", rustfs_profile_floor()),
    ]
}

/// What the STS assembly answered, what its authorizer was asked (action and caller), and which
/// access keys its provider was asked for.
type Observed = (Answered, Vec<(String, Option<String>)>, Vec<String>);

/// What the STS assembly behind `floor` answered `request`, what its authorizer was asked, and
/// which access keys its provider was asked for.
fn sts_answer(floor: SecurityFloor, request: Request<Bytes>, now: RequestNow) -> Observed {
    let provider = Recording::default();
    let handed = Arc::new(Mutex::new(None));
    let asked = Arc::new(Mutex::new(Vec::new()));
    let service = gateway_builder_on(now, &asked, floor, Arc::new(provider.clone()))
        .register::<StsFormPost, _>(Arc::new(Sts {
            handed: Arc::clone(&handed),
        }))
        .build()
        .expect("an STS assembly");
    let response = block_on(service.call_bytes(request));
    let collected = block_on(rustfs_gateway::collect(response)).expect("an in-memory answer");
    let handed = handed.lock().expect("uncontended").take();
    let asked = std::mem::take(&mut *asked.lock().expect("uncontended"));
    let identified = collected
        .headers()
        .iter()
        .any(|(name, _)| IDENTIFIERS.contains(&name.as_str()));
    (
        answered(collected.status().as_u16(), identified, collected.body(), handed),
        asked,
        provider.lookups(),
    )
}

/// Every SigV2 request the matrix sends: header and presigned, on both actions, with the shared
/// secret, and a forged header.
fn sigv2_requests() -> Vec<Sent> {
    let mut sent = Vec::new();
    for body in [None, Some(WEB_IDENTITY)] {
        for signing in [
            Signing::V2Header { secret: SECRET_KEY },
            Signing::V2Header { secret: FORGED },
            Signing::V2Presigned,
        ] {
            let request = Sent::new(signing);
            sent.push(match body {
                Some(body) => request.body(Bytes::from_static(body)),
                None => request,
            });
        }
    }
    sent
}

/// `request` with its SigV2 access key replaced by one nobody issued, in the header or the query.
fn with_unknown_key(mut request: Request<Bytes>) -> Request<Bytes> {
    if let Some(authorization) = request.headers().get(http::header::AUTHORIZATION) {
        let rewritten = authorization
            .to_str()
            .expect("text")
            .replace(&format!("AWS {ACCESS_KEY}:"), &format!("AWS {UNKNOWN_KEY}:"));
        request
            .headers_mut()
            .insert(http::header::AUTHORIZATION, HeaderValue::from_str(&rewritten).expect("a header"));
    }
    let uri = request
        .uri()
        .to_string()
        .replace(&format!("AWSAccessKeyId={ACCESS_KEY}"), &format!("AWSAccessKeyId={UNKNOWN_KEY}"));
    *request.uri_mut() = uri.parse().expect("a fixture URI");
    request
}

/// Negative — every SigV2 request is refused `403 AccessDenied` on both floors, before any
/// credential lookup, authorizer question or handler.
#[test]
fn n_every_sigv2_request_is_refused_before_any_credential_lookup() {
    for (at, floor) in floors() {
        for sent in sigv2_requests() {
            let now = RequestNow::capture();
            let (answer, asked, lookups) = sts_answer(floor.clone(), sent.request(now), now);
            assert_eq!(
                (answer.status, answer.code.as_deref()),
                (403, Some("AccessDenied")),
                "{at}: {sent:?}: {answer:?}"
            );
            assert!(answer.handed.is_none(), "{at}: {sent:?}");
            assert!(asked.is_empty(), "{at}: {sent:?}: {asked:?}");
            assert!(lookups.is_empty(), "{at}: {sent:?}: the provider was asked for {lookups:?}");
        }
    }
}

/// Negative — a SigV2 request naming an access key nobody issued gets exactly the answer the same
/// request naming the issued key gets — status, code, message and identifiers — with no lookup.
#[test]
fn n_a_known_and_an_unknown_sigv2_key_get_one_answer() {
    for (at, floor) in floors() {
        for sent in sigv2_requests() {
            let now = RequestNow::capture();
            let known = sent.request(now);
            let unknown = with_unknown_key(known.clone());
            assert_ne!(format!("{known:?}"), format!("{unknown:?}"), "{at}: {sent:?}: the key was not rewritten");
            let (known, _, known_lookups) = sts_answer(floor.clone(), known, now);
            let (unknown, _, unknown_lookups) = sts_answer(floor.clone(), unknown, now);
            assert_eq!(known, unknown, "{at}: {sent:?}");
            assert!(known_lookups.is_empty() && unknown_lookups.is_empty(), "{at}: {sent:?}");
        }
    }
}

/// Positive — the rule leaves SigV4 and the unsigned request alone: a SigV4 header `AssumeRole`
/// reaches the handler as the caller after one lookup, and an unsigned Web Identity form reaches it
/// with no caller and no lookup, on both floors.
#[test]
fn sigv4_assume_role_and_unsigned_web_identity_still_reach_the_handler() {
    for (at, floor) in floors() {
        let now = RequestNow::capture();
        let signed = Sent::new(Signing::Header {
            service: "sts",
            send_digest: false,
            secret: SECRET_KEY,
        });
        let (answer, _, lookups) = sts_answer(floor.clone(), signed.request(now), now);
        assert_eq!(answer.status, 200, "{at}: {answer:?}");
        assert!(answer.handed == handed(Some(ACCESS_KEY), &signed), "{at}");
        assert_eq!(lookups, [ACCESS_KEY], "{at}");
        let unsigned = Sent::new(Signing::Anonymous).body(Bytes::from_static(WEB_IDENTITY));
        let (answer, _, lookups) = sts_answer(floor, unsigned.request(now), now);
        assert_eq!(answer.status, 200, "{at}: {answer:?}");
        assert!(answer.handed == handed(None, &unsigned), "{at}");
        assert!(lookups.is_empty(), "{at}: {lookups:?}");
    }
}

/// Positive — the control in the other direction: `HeadObject`, whose floor does not refuse SigV2,
/// still admits the SigV2 header signature on both floors, and the provider is asked for its key,
/// so the empty lookup lists above are the STS floor's refusal and not a deaf recorder.
#[test]
fn an_operation_without_the_rule_still_admits_sigv2_and_looks_its_key_up() {
    for (at, floor) in floors() {
        let now = RequestNow::capture();
        let provider = Recording::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let service = gateway_builder_on(now, &Arc::new(Mutex::new(Vec::new())), floor, Arc::new(provider.clone()))
            .authorizer(ObjectAuthorizer)
            .register::<HeadObject, _>(Arc::new(ObjectHandler(Arc::clone(&calls))))
            .build()
            .expect("an ordinary S3 assembly");
        let mut request = Sent::new(Signing::V2Header { secret: SECRET_KEY })
            .host("photos.example.test")
            .path("/object")
            .content_type(None)
            .body(Bytes::new())
            .request(now);
        *request.method_mut() = Method::HEAD;
        sign_v2(&mut request, Some("photos"));
        let response = block_on(service.call_bytes(request));
        let response = block_on(rustfs_gateway::collect(response)).expect("an in-memory response");
        assert_eq!((response.status().as_u16(), calls.load(Ordering::SeqCst)), (200, 1), "{at}");
        assert_eq!(provider.lookups(), [ACCESS_KEY], "{at}");
    }
}

/// `request` with its URI rewritten by `edit`.
fn with_uri(mut request: Request<Bytes>, edit: impl Fn(&str) -> String) -> Request<Bytes> {
    let uri = edit(&request.uri().to_string());
    *request.uri_mut() = uri.parse().expect("a fixture URI");
    request
}

/// A named rewrite of a request URI.
type UriEdit = fn(&str) -> String;

/// Whether no principal reached the STS handler: it did not run, or ran with no caller.
fn no_principal(answer: &Answered) -> bool {
    answer.handed.as_ref().is_none_or(|handed| handed.caller.is_none())
}

/// `sent` with `body`, when there is one.
fn with_body(sent: Sent, body: Option<&'static [u8]>) -> Sent {
    match body {
        Some(body) => sent.body(Bytes::from_static(body)),
        None => sent,
    }
}

/// Negative — a SigV2 presigned request whose parameter names are percent-encoded, `%53ignature`
/// alone or every name, is refused before the handler on both floors, never with a principal and
/// never after a credential lookup. Through this assembly the service's query reader answers
/// `400 InvalidArgument` before the floor. The floor itself decodes the names and refuses the
/// request as SigV2 (`rustfs-gateway-sig`'s `sigv2_refused_floor`), so neither layer turns the URL
/// into an anonymous one.
#[test]
fn n_a_percent_encoded_sigv2_query_is_refused_with_no_principal() {
    let spellings: [(&str, UriEdit); 2] = [
        ("%53ignature", |uri| uri.replace("&Signature=", "&%53ignature=")),
        ("every name encoded", |uri| {
            uri.replace("AWSAccessKeyId=", "%41WSAccessKeyId=")
                .replace("&Expires=", "&%45xpires=")
                .replace("&Signature=", "&%53ignature=")
        }),
    ];
    for (at, floor) in floors() {
        for (spelling, edit) in spellings {
            for body in [None, Some(WEB_IDENTITY)] {
                let now = RequestNow::capture();
                let sent = with_body(Sent::new(Signing::V2Presigned), body);
                let original = sent.request(now);
                let request = with_uri(original.clone(), edit);
                assert_ne!(request.uri(), original.uri(), "{spelling}: not rewritten");
                let (answer, asked, lookups) = sts_answer(floor.clone(), request, now);
                assert!((400..500).contains(&answer.status), "{at} {spelling}: {answer:?}");
                assert!(answer.handed.is_none() && no_principal(&answer), "{at} {spelling}");
                assert!(asked.is_empty() && lookups.is_empty(), "{at} {spelling}: {asked:?} {lookups:?}");
            }
        }
    }
}

/// Negative and positive — `AWSAccessKeyId` alone, with no signature: under the RustFS profile's
/// legacy recognition it is an unsigned request, so a Web Identity form reaches its handler with
/// no principal and ordinary `AssumeRole` is refused by the codec; under the default floor it is a
/// SigV2 presigned marker, refused by the rule. No principal reaches the handler on either.
#[test]
fn an_access_key_id_alone_is_anonymous_on_the_profile_and_refused_on_the_default_floor() {
    const ASSUME_ROLE: &[u8] = b"Action=AssumeRole&Version=2011-06-15";
    let alone = |body: &'static [u8], now| {
        let request = Sent::new(Signing::Anonymous).body(Bytes::from_static(body)).request(now);
        with_uri(request, |uri| format!("{uri}?AWSAccessKeyId={ACCESS_KEY}"))
    };
    let now = RequestNow::capture();
    let (answer, _, lookups) = sts_answer(rustfs_profile_floor(), alone(WEB_IDENTITY, now), now);
    assert_eq!(answer.status, 200, "{answer:?}");
    assert!(answer.handed.is_some() && no_principal(&answer), "{answer:?}");
    assert!(lookups.is_empty(), "{lookups:?}");
    let (answer, _, lookups) = sts_answer(rustfs_profile_floor(), alone(ASSUME_ROLE, now), now);
    assert_eq!((answer.status, answer.code.as_deref()), (403, Some("AccessDenied")), "{answer:?}");
    assert!(answer.handed.is_none() && lookups.is_empty(), "{answer:?} {lookups:?}");
    for body in [WEB_IDENTITY, ASSUME_ROLE] {
        let (answer, asked, lookups) = sts_answer(SecurityFloor::new(), alone(body, now), now);
        assert_eq!((answer.status, answer.code.as_deref()), (403, Some("AccessDenied")), "{answer:?}");
        assert!(answer.handed.is_none() && asked.is_empty() && lookups.is_empty(), "{answer:?}");
    }
}

/// Negative — a lowercase `aws` scheme is not a SigV2 marker: the floor seals it for the SigV4
/// path, which cannot read it. In this assembly the RustFS header-signature view policy refuses the
/// unreadable value first. Either way it is never served, and never with a principal, on either
/// floor.
#[test]
fn n_a_lowercase_sigv2_scheme_is_refused_with_no_principal() {
    for (at, floor) in floors() {
        for body in [None, Some(WEB_IDENTITY)] {
            let now = RequestNow::capture();
            let mut request = with_body(Sent::new(Signing::V2Header { secret: SECRET_KEY }), body).request(now);
            let lowered = request.headers()[http::header::AUTHORIZATION]
                .to_str()
                .expect("text")
                .replacen("AWS ", "aws ", 1);
            request
                .headers_mut()
                .insert(http::header::AUTHORIZATION, HeaderValue::from_str(&lowered).expect("a header"));
            let (answer, _, _) = sts_answer(floor.clone(), request, now);
            assert!((400..500).contains(&answer.status), "{at}: {answer:?}");
            assert!(answer.handed.is_none() && no_principal(&answer), "{at}: {answer:?}");
        }
    }
}

/// Negative — under the RustFS profile's header-signature view policy
/// (`answer_header_signatures_as_legacy_rustfs`, on in this assembly), a SigV2 header whose date is
/// missing or unreadable is answered `400 InvalidRequest`, and one whose date is skewed
/// `403 RequestTimeTooSkewed`, before the floor's SigV2 refusal. That answer is the same for a known
/// and an unknown key, with no lookup and no handler: the order leaks nothing about the credential.
#[test]
fn n_the_header_view_policy_answers_a_bad_sigv2_date_first_whatever_the_key() {
    let now = RequestNow::capture();
    let fresh = || Sent::new(Signing::V2Header { secret: SECRET_KEY }).request(now);
    let mut missing = fresh();
    missing.headers_mut().remove(http::header::DATE);
    let mut unreadable = fresh();
    unreadable
        .headers_mut()
        .insert(http::header::DATE, HeaderValue::from_static("not a date"));
    let an_hour_ago = RequestNow::from_unix_seconds(now.unix_seconds() - 3_600);
    let skewed = Sent::new(Signing::V2Header { secret: SECRET_KEY }).request(an_hour_ago);
    for (at, floor) in floors() {
        for (case, request, expected) in [
            ("missing date", &missing, (400, "InvalidRequest")),
            ("unreadable date", &unreadable, (400, "InvalidRequest")),
            ("skewed date", &skewed, (403, "RequestTimeTooSkewed")),
        ] {
            let (known, _, known_lookups) = sts_answer(floor.clone(), request.clone(), now);
            let (unknown, _, unknown_lookups) = sts_answer(floor.clone(), with_unknown_key(request.clone()), now);
            assert_eq!(
                (known.status, known.code.as_deref()),
                (expected.0, Some(expected.1)),
                "{at} {case}: {known:?}"
            );
            assert_eq!(known, unknown, "{at} {case}");
            assert!(known.handed.is_none(), "{at} {case}");
            assert!(known_lookups.is_empty() && unknown_lookups.is_empty(), "{at} {case}");
        }
    }
}
