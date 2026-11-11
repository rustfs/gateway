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

//! The host boundary of the header token claim through the assembled service (ADR-0054,
//! rustfs/gateway#1586).
//!
//! Responsible for: a refused alias of the claimed header answered `403` before any verifier,
//! whatever the host's outer layer established; each of many interleaved requests served as the
//! identity its own extensions carry; a host-reported name that does not inherit the policy of
//! the access key it is spelled like; the cache headers on an answer served by a token; and the
//! one refusal a token beside an AWS credential gets under the RustFS profile's own answers.
//! NOT responsible for: admission and the verifier's answers (`header_token.rs`), where the token
//! may appear (`header_token_secrecy.rs`), or the fixtures (`header_token/fixtures.rs`).
//! Upstream: `rustfs_gateway::ServiceBuilder`, `support`. Downstream: nothing.

use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use rustfs_gateway::sig::{Identity, SecurityFloor};
use rustfs_gateway::{
    Authorizer, AuthzRequest, BoxFuture, Decision, IdentityOrigin, InputAuthzRequest, InputDecisions, PolicySnapshot,
    RequestContext, policy_from,
};

use crate::header_token::fixtures::{
    Answer, HEADER, PRINCIPAL, RequestCase, SIGNED_PRINCIPAL, aliased, aliased_claim, assemble, assemble_aliased, assemble_with,
    claim, established_as, floors, status_and_code, token_only, with_bare_token, with_token,
};
use crate::support;

// ── refused aliases ────────────────────────────────────────────────────────────────────────────

/// Negative — a request carrying a refused alias is `403` before any verifier, lookup, authorizer
/// question or handler, although the host's outer layer established an identity from it, and
/// whether it stands alone, beside a valid signature or beside the claimed token. On a service
/// whose claim lists no alias the same requests are served: as nobody, and as the signer. That is
/// the split identity the alias closes, and what makes each refusal the alias's doing.
#[tokio::test]
async fn n_a_refused_alias_is_a_closed_403_whatever_the_host_established() {
    let alone = |method: http::Method| move || established_as(PRINCIPAL, aliased(support::plain(method.clone(), "/")));
    let cases: Vec<RequestCase> = vec![
        ("the alias alone", Box::new(alone(http::Method::GET))),
        ("the alias alone, on an anonymous operation", Box::new(alone(http::Method::POST))),
        (
            "the alias beside a valid signature",
            Box::new(|| established_as(PRINCIPAL, aliased(support::signed(http::Method::GET, "/")))),
        ),
        (
            "the alias beside the claimed token",
            Box::new(|| aliased(token_only(http::Method::POST, "/"))),
        ),
        (
            "the alias with nothing established",
            Box::new(|| aliased(support::plain(http::Method::POST, "/"))),
        ),
    ];
    for (name, request) in &cases {
        let fixture = assemble_aliased(Answer::Accepts);
        let response = fixture.exchange(request()).await;
        fixture.refused_before_any_verifier(&response, name);
    }

    // The controls, under a claim that refuses no alias.
    let unaliased = assemble(Some(Answer::Accepts));
    let response = unaliased.exchange(cases[1].1()).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let handed = unaliased.backend.take();
    assert!(handed[0].anonymous, "{:?}", handed[0]);
    assert_eq!(
        handed[0].established,
        Some(PRINCIPAL),
        "served as nobody while the host holds an identity"
    );
    let _ = unaliased.stages.take();
    let response = unaliased.exchange(cases[2].1()).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(unaliased.backend.take()[0].signed.as_deref(), Some(SIGNED_PRINCIPAL));
    assert_eq!(unaliased.verifier_calls.load(Ordering::SeqCst), 0);
}

/// Positive — refusing aliases changes nothing for a request that carries none: the claimed token
/// is served as its principal, and an anonymous and a signed request are served as before.
#[tokio::test]
async fn a_claim_that_refuses_aliases_serves_every_other_request_as_before() {
    let fixture = assemble_aliased(Answer::Accepts);
    let response = fixture.exchange(token_only(http::Method::GET, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(fixture.backend.take()[0].header_token.as_deref(), Some(PRINCIPAL));

    let response = fixture.exchange(support::plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(fixture.backend.take()[0].anonymous);

    let response = fixture.exchange(support::signed(http::Method::GET, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(fixture.backend.take()[0].signed.as_deref(), Some(SIGNED_PRINCIPAL));
}

// ── the identity is the one this request carries ───────────────────────────────────────────────

/// Allows everything after yielding, so requests that are in flight together change places
/// between verification and their handler.
struct YieldsThenAllows;

impl Authorizer for YieldsThenAllows {
    fn authorize_route<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        _request: &'a AuthzRequest<'a>,
    ) -> BoxFuture<'a, Decision> {
        Box::pin(async {
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
            Decision::Allow
        })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move {
            tokio::task::yield_now().await;
            decisions
        })
    }
}

/// Positive and negative — ninety-six requests in flight together on four threads, a third as
/// Alice, a third as Bob and a third with a token and nothing established. Every handler that
/// runs reads the identity its own request's extensions carry and no other, and every request
/// that carried nothing is refused: one verifier never hands a request another request's name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interleaved_requests_are_each_served_as_what_their_own_request_carries() {
    let fixture = Arc::new(assemble_with(SecurityFloor::new(), Some((claim(), Answer::Accepts)), |builder| {
        builder.authorizer(YieldsThenAllows)
    }));
    let mut flights = Vec::new();
    for index in 0..96_usize {
        let fixture = Arc::clone(&fixture);
        flights.push(tokio::spawn(async move {
            let request = with_bare_token(support::plain(http::Method::POST, "/"));
            let (expected, request) = match index % 3 {
                0 => (200, established_as("ALICE", request)),
                1 => (200, established_as("BOB", request)),
                _ => (403, request),
            };
            (expected, fixture.exchange(request).await.status().as_u16())
        }));
    }
    for flight in flights {
        let (expected, status) = flight.await.expect("the request task did not panic");
        assert_eq!(status, expected);
    }
    let handed = fixture.backend.take();
    assert_eq!(handed.len(), 64, "only the requests that carried an identity reached a handler");
    for handler in &handed {
        assert_eq!(handler.header_token.as_deref(), handler.established, "{handler:?}");
        assert!(!handler.anonymous && handler.signed.is_none(), "{handler:?}");
    }
    for name in ["ALICE", "BOB"] {
        assert_eq!(handed.iter().filter(|handler| handler.established == Some(name)).count(), 32, "{name}");
    }
    assert_eq!(
        fixture.verifier_calls.load(Ordering::SeqCst),
        64,
        "never asked about a request that carried nothing"
    );
}

// ── the origin of the reported name ────────────────────────────────────────────────────────────

/// What a policy reading grants its caller.
struct Granted(bool);

/// Allows a request exactly when its policy reading grants it, and records each principal asked.
#[derive(Default)]
struct ByPolicy(Mutex<Vec<(String, IdentityOrigin)>>);

impl Authorizer for ByPolicy {
    fn authorize_route<'a>(&'a self, context: &'a RequestContext<'a>, request: &'a AuthzRequest<'a>) -> BoxFuture<'a, Decision> {
        if let Some(identity) = request.identity {
            let asked = (identity.access_key_id().to_owned(), identity.origin());
            self.0.lock().expect("not poisoned").push(asked);
        }
        let granted = context.policy().get::<Granted>().is_some_and(|granted| granted.0);
        Box::pin(async move { if granted { Decision::Allow } else { Decision::Deny } })
    }

    fn authorize_input<'a>(
        &'a self,
        _context: &'a RequestContext<'a>,
        request: &'a InputAuthzRequest<'a>,
    ) -> BoxFuture<'a, InputDecisions> {
        let decisions = request.decide_all(Decision::Allow, |_| Decision::Allow);
        Box::pin(async move { decisions })
    }
}

/// Negative — a host-reported name spelled exactly like an access key does not inherit that
/// key's policy from a store keyed on the identity the kernel hands it: the kernel marked where
/// the name came from, and the two are different keys. The signed request of that access key is
/// granted by the same store, and a store that looks the bare spelling up grants both — which is
/// the confusion the mark exists to prevent, and what makes the denial the mark's doing.
#[tokio::test]
async fn n_a_reported_name_does_not_inherit_the_policy_of_an_access_key_of_the_same_spelling() {
    let service = |by_bare_name: bool| {
        let asked = Arc::new(ByPolicy::default());
        let recorded = Arc::clone(&asked);
        let fixture = assemble_with(SecurityFloor::new(), Some((claim(), Answer::Accepts)), move |builder| {
            let access_key = Identity::new(SIGNED_PRINCIPAL).expect("a legal access key");
            let granted: HashSet<Identity> = HashSet::from([access_key]);
            builder
                .policy_source(policy_from(move |identity| {
                    let hit = identity.is_some_and(|identity| {
                        if by_bare_name {
                            granted.iter().any(|entry| entry.access_key_id() == identity.access_key_id())
                        } else {
                            granted.contains(identity)
                        }
                    });
                    Ok(PolicySnapshot::of(Arc::new(Granted(hit))))
                }))
                .authorizer(recorded)
        });
        (fixture, asked)
    };
    let token_spelled_like_the_key = || established_as(SIGNED_PRINCIPAL, with_bare_token(support::plain(http::Method::GET, "/")));

    let (fixture, asked) = service(false);
    let response = fixture.exchange(token_spelled_like_the_key()).await;
    assert_eq!(status_and_code(&response), (403, Some("AccessDenied".to_owned())));
    assert!(
        fixture.backend.take().is_empty(),
        "the reported name was served under the access key's policy"
    );
    assert_eq!(
        *asked.0.lock().expect("not poisoned"),
        [(SIGNED_PRINCIPAL.to_owned(), IdentityOrigin::HostToken)]
    );

    let response = fixture.exchange(support::signed(http::Method::GET, "/")).await;
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "the control: the access key finds its own policy"
    );
    assert_eq!(
        asked.0.lock().expect("not poisoned").last(),
        Some(&(SIGNED_PRINCIPAL.to_owned(), IdentityOrigin::AccessKey))
    );

    let (confused, _) = service(true);
    let response = confused.exchange(token_spelled_like_the_key()).await;
    assert_eq!(
        response.status(),
        http::StatusCode::OK,
        "the control: a store keyed on the bare spelling cannot tell them apart"
    );
}

// ── shared caches ──────────────────────────────────────────────────────────────────────────────

fn header_values(response: &rustfs_gateway::WireResponse, name: &str) -> Vec<String> {
    response
        .headers()
        .iter()
        .filter(|(header, _)| header.as_str() == name)
        .map(|(_, value)| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect()
}

/// Positive and negative — the answer to a request served by its token varies on the claimed
/// header and is private, so a shared cache does not hand it to a caller without the token. An
/// anonymous and a signed answer of the same service carry neither, a refused token carries
/// neither, and without the claim nothing is added to any answer.
#[tokio::test]
async fn an_answer_served_by_a_token_is_kept_out_of_a_shared_cache() {
    let fixture = assemble(Some(Answer::Accepts));
    for method in [http::Method::GET, http::Method::POST] {
        let served = fixture.exchange(token_only(method.clone(), "/")).await;
        assert_eq!(served.status(), http::StatusCode::OK, "{method}");
        assert_eq!(header_values(&served, "vary"), [HEADER], "{method}");
        assert_eq!(header_values(&served, "cache-control"), ["private"], "{method}");
    }
    let others: [(&str, http::Request<Bytes>); 3] = [
        ("anonymous", support::plain(http::Method::POST, "/")),
        ("signed", support::signed(http::Method::GET, "/")),
        (
            "a token with nothing established",
            with_bare_token(support::plain(http::Method::POST, "/")),
        ),
    ];
    for (name, request) in others {
        let response = fixture.exchange(request).await;
        assert!(header_values(&response, "vary").is_empty(), "{name}");
        assert!(header_values(&response, "cache-control").is_empty(), "{name}");
    }
    let unclaimed = assemble(None);
    let response = unclaimed.exchange(token_only(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert!(header_values(&response, "vary").is_empty() && header_values(&response, "cache-control").is_empty());
}

/// Serves every object as one whose uploader stored this `Cache-Control` on it.
struct Stored(&'static str);

impl rustfs_gateway::Handler<rustfs_gateway::dto::GetObject> for Stored {
    async fn call(
        &self,
        _request: rustfs_gateway::Req<rustfs_gateway::dto::GetObject>,
    ) -> rustfs_gateway::HandlerResult<rustfs_gateway::dto::GetObject> {
        Ok(rustfs_gateway::Resp::new(rustfs_gateway::dto::GetObjectOutput {
            cache_control: Some(self.0.to_owned()),
            ..Default::default()
        }))
    }
}

/// The `Cache-Control` and `Vary` answers to a token request and to a signed request for an
/// object stored with `cache_control`.
async fn stored_object_answers(cache_control: &'static str) -> [(Vec<String>, Vec<String>); 2] {
    let fixture = assemble_with(SecurityFloor::new(), Some((claim(), Answer::Accepts)), move |builder| {
        builder.register::<rustfs_gateway::dto::GetObject, _>(Arc::new(Stored(cache_control)))
    });
    let mut answers = Vec::new();
    for request in [
        token_only(http::Method::GET, "/bucket/object"),
        support::signed(http::Method::GET, "/bucket/object"),
    ] {
        let response = fixture.exchange(request).await;
        assert_eq!(response.status(), http::StatusCode::OK, "{cache_control}: {:?}", response.body());
        answers.push((header_values(&response, "cache-control"), header_values(&response, "vary")));
    }
    assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 1, "{cache_control}");
    [answers.remove(0), answers.remove(0)]
}

/// Negative — an object stored with a lifetime and nothing that decides sharing goes out
/// `private` to a caller served by its token. Without it a shared cache could store the answer
/// and replay it past the token's revocation, because a request with no `Authorization` header
/// has no protection under RFC 9111 section 3.5. The signed request for the same object is the
/// control: its `Cache-Control` is the stored one, untouched, and it does not vary.
#[tokio::test]
async fn n_a_stored_lifetime_goes_out_private_on_an_answer_served_by_a_token() {
    for stored in ["max-age=3600", "Max-Age=3600, immutable", "no-cache"] {
        let [by_token, signed] = stored_object_answers(stored).await;
        assert_eq!(
            by_token,
            (vec![stored.to_owned(), "private".to_owned()], vec![HEADER.to_owned()]),
            "{stored}"
        );
        assert_eq!(signed, (vec![stored.to_owned()], Vec::new()), "{stored}: the control");
    }
}

/// Negative, pinning a stated residual — an object whose stored metadata says `public`,
/// `s-maxage` or `must-revalidate`, in any letter case, goes out with exactly that to a caller
/// served by its token: the gateway keeps what the handler answered and adds only `Vary` on the
/// claimed header. A cache that ignores `Vary` can then serve one caller's object to another, as
/// it can for a header-signed request, where those directives also permit storing; ADR-0054
/// states it as the deployment's. The signed request is the control.
#[tokio::test]
async fn n_a_stored_public_cache_control_is_kept_on_an_answer_served_by_a_token() {
    for stored in ["public, max-age=60", "PUBLIC", "s-maxage=60", "max-age=60, must-revalidate"] {
        let [by_token, signed] = stored_object_answers(stored).await;
        assert_eq!(by_token, (vec![stored.to_owned()], vec![HEADER.to_owned()]), "{stored}");
        assert_eq!(signed, (vec![stored.to_owned()], Vec::new()), "{stored}: the control");
    }
}

// ── one refusal, under the RustFS profile's own answers too ────────────────────────────────────

/// Negative — under the RustFS profile, whose view policies answer a malformed header signature
/// or presigned URL in legacy RustFS's own words before the floor runs, a token beside any AWS
/// credential surface still gets the floor's one answer: `403 AccessDenied`, with no verifier,
/// lookup, authorizer question or handler, and byte for byte the body the floor gives a token
/// beside another scheme's `Authorization`. The same malformed credentials without the token keep
/// the profile's answers, in the profile's words, and at least one of those is not
/// `AccessDenied`, so the one answer is the token's doing and not the profile's.
#[tokio::test]
async fn n_the_token_beside_an_aws_credential_is_one_refusal_under_the_rustfs_profile_too() {
    let authorization = |value: &'static str| {
        move || {
            let mut request = support::plain(http::Method::GET, "/");
            request
                .headers_mut()
                .insert("authorization", http::HeaderValue::from_static(value));
            request
        }
    };
    let query = |query: &'static str| move || support::plain(http::Method::GET, query);
    let cases: Vec<RequestCase> = vec![
        ("a valid header signature", Box::new(|| support::signed(http::Method::GET, "/"))),
        ("an unreadable authorization", Box::new(authorization("garbage"))),
        ("an empty authorization", Box::new(authorization(""))),
        (
            "a truncated SigV4 authorization",
            Box::new(authorization("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE")),
        ),
        (
            "a SigV4 authorization with no signed headers",
            Box::new(authorization(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260102/us-east-1/s3/aws4_request, Signature=00",
            )),
        ),
        (
            "a SigV2 authorization",
            Box::new(authorization("AWS AKIDEXAMPLE:frJIUN8DYpKDtOLCwo//yllqDzg=")),
        ),
        ("a SigV2 authorization with no signature", Box::new(authorization("AWS AKIDEXAMPLE"))),
        (
            "a presigned URL with no signature",
            Box::new(query(
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20260102%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260102T030405Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host",
            )),
        ),
        (
            "an expired presigned URL",
            Box::new(query(
                "/?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20200102%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20200102T030405Z&X-Amz-Expires=1&X-Amz-SignedHeaders=host&X-Amz-Signature=00",
            )),
        ),
        // The pre-routing guard reads this name in any letter case; the floor must too, or a token
        // request, which skips the guard, would be admitted where the guard refused.
        ("a lowercase presigned signature", Box::new(query("/?x-amz-signature=00"))),
        ("a mixed-case presigned signature", Box::new(query("/?X-AMZ-Signature=00&note=a"))),
        ("a presigned algorithm alone", Box::new(query("/?X-Amz-Algorithm=AWS4-HMAC-SHA256"))),
        ("a presigned date alone", Box::new(query("/?X-Amz-Date=20260102T030405Z"))),
        ("a presigned lifetime alone", Box::new(query("/?X-Amz-Expires=60"))),
        ("presigned signed headers alone", Box::new(query("/?X-Amz-SignedHeaders=host"))),
        (
            "a SigV2 presigned URL with no expiry",
            Box::new(query("/?AWSAccessKeyId=AKIDEXAMPLE&Signature=frJIUN8D")),
        ),
        (
            "an unsigned x-amz header",
            Box::new(|| {
                let mut request = support::plain(http::Method::GET, "/");
                request
                    .headers_mut()
                    .insert("x-amz-security-token", http::HeaderValue::from_static("session"));
                request
            }),
        ),
    ];
    let profiled = |floor: SecurityFloor| {
        assemble_with(floor, Some((aliased_claim(), Answer::Accepts)), |builder| {
            builder.rustfs_profile().refuse_unsigned_amz_headers_before_routing()
        })
    };
    // The floor's own refusal, taken where no view policy has anything to say.
    let reference = {
        let mut request = token_only(http::Method::GET, "/");
        let other_scheme = http::HeaderValue::from_static("Bearer opaque");
        request.headers_mut().insert("authorization", other_scheme);
        profiled(SecurityFloor::new()).exchange(request).await.body().to_vec()
    };
    let mut bodies_without_the_token = HashSet::new();
    let mut answers_without_the_token = HashSet::new();
    for (floor_name, floor) in floors() {
        for (name, request) in &cases {
            let at = format!("{floor_name}: {name}");
            let fixture = profiled(floor.clone());
            let response = fixture.exchange(with_token(request())).await;
            fixture.refused_before_any_verifier(&response, &at);
            assert_eq!(response.body(), reference.as_slice(), "{at}: not the floor's own answer");

            let fixture = profiled(floor.clone());
            let response = fixture.exchange(aliased(request())).await;
            fixture.refused_before_any_verifier(&response, &format!("{at}, beside the alias"));

            let fixture = profiled(floor.clone());
            let alone = fixture.exchange(request()).await;
            answers_without_the_token.insert(status_and_code(&alone));
            bodies_without_the_token.insert(alone.body().to_vec());
        }
    }
    assert!(
        answers_without_the_token
            .iter()
            .any(|answer| answer != &(403, Some("AccessDenied".to_owned())) && answer.0 >= 400),
        "the profile answered every malformed credential AccessDenied by itself: {answers_without_the_token:?}"
    );
    assert!(
        bodies_without_the_token.len() > 3,
        "the profile words these refusals itself, so one body for all of them is the floor's doing"
    );
}
