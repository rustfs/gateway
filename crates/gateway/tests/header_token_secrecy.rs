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

//! Where a host-verified header token may not appear, and what its request's body is held to
//! (ADR-0051, rustfs/gateway#1586).
//!
//! Responsible for: no log event, answer, audit or observer event, start-up line, `Debug`
//! rendering, authorization context or handler context holding the token, found by searching
//! everything a set of admitted, refused and panicking requests produced for its bytes; the
//! claimed header absent from both contexts once the claim is installed; a stage filter able
//! neither to supply nor to erase a token; one contained-panic event for a panicking verifier;
//! and the request's body decoded and refused exactly as an anonymous request's is.
//! NOT responsible for: admission and the verifier's answers (`header_token.rs`), or the floor's
//! rules (`rustfs-gateway-sig`'s `tests/header_token.rs`).
//! Upstream: `header_token.rs`'s fixtures, `tracing_events.rs`'s capture,
//! `anonymous_chunked_upload.rs`'s upload fixtures. Downstream: nothing.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use rustfs_gateway::sig::SecurityFloor;
use rustfs_gateway::{S3Service, WireHead, dto, wire_filter};

use crate::anonymous_chunked_upload::{Backend as Uploads, OBJECT, OBJECT_CRC32, Recorded, anonymous_put, unsigned_framing};
use crate::header_token::fixtures::{
    Answer, Asked, Established, Fixture, HEADER, Handed, Lines, PRINCIPAL, RequestCase, TOKEN, aliased, assemble,
    assemble_aliased, builder, claim, token_only, with_bare_token, with_token,
};
use crate::support;
use crate::tracing_events::captured;

/// Everything one fixture produced that a token could have leaked into, as text.
fn produced(fixture: &Fixture, responses: &[rustfs_gateway::WireResponse], asked: &[Asked], handed: &[Handed]) -> Vec<String> {
    let mut text = Vec::new();
    for response in responses {
        text.push(String::from_utf8_lossy(response.body()).into_owned());
        for (name, value) in response.headers() {
            text.push(format!("{name}: {}", String::from_utf8_lossy(value.as_bytes())));
        }
    }
    let lines = |lines: &Lines| {
        lines
            .iter()
            .map(|(name, value)| format!("{name}: {}", String::from_utf8_lossy(value)))
            .collect::<Vec<_>>()
    };
    for stage in asked {
        text.push(stage.rendered.clone());
        text.extend(lines(&stage.headers));
    }
    for handler in handed {
        text.push(handler.rendered.clone());
        text.extend(lines(&handler.headers));
    }
    text.extend(fixture.events.rendered.lock().expect("not poisoned").iter().cloned());
    text.push(format!("{:?}", fixture.service));
    text.push(fixture.service.startup_posture().to_owned());
    text.push(fixture.service.security_posture().to_string());
    text
}

/// Negative — nothing an admitted, a refused, an excluded or a panicking header-token request
/// produces holds the token: no log event at any level, no answer, no audit or observer event,
/// no start-up line, no `Debug` rendering, and no line of either context, in any letter case.
/// Once the claim is installed neither context carries the claimed header at all, while every
/// other line still arrives.
#[test]
fn n_no_log_event_answer_or_context_holds_the_token() {
    let (text, capture) = captured(|runtime| {
        runtime.block_on(async {
            let mut text = Vec::new();
            let mut contexts = 0;
            // A panicking host is `n_a_panicking_verifier_is_reported_as_one_contained_panic_event`'s
            // alone: its event is throttled process-wide, so only one case may raise it.
            let scenarios: [(Answer, Vec<http::Request<Bytes>>); 2] = [
                (
                    Answer::Accepts,
                    vec![
                        token_only(http::Method::GET, "/"),
                        token_only(http::Method::POST, "/?note=kept"),
                        token_only(http::Method::HEAD, "/example/admin/probe"),
                        with_token(support::signed(http::Method::GET, "/")),
                        support::signed_with(http::Method::GET, "/", &[(HEADER, TOKEN)]),
                        token_only(http::Method::GET, "/?X-Amz-Algorithm=AWS4-HMAC-SHA256"),
                        // Nothing established, and a refused alias holding the same bytes.
                        with_bare_token(support::plain(http::Method::POST, "/")),
                        aliased(support::plain(http::Method::POST, "/")),
                        aliased(token_only(http::Method::GET, "/")),
                    ],
                ),
                (
                    Answer::Refuses,
                    vec![token_only(http::Method::GET, "/"), token_only(http::Method::POST, "/")],
                ),
            ];
            for (answer, requests) in scenarios {
                let fixture = assemble_aliased(answer);
                let mut responses = Vec::new();
                for request in requests {
                    responses.push(fixture.exchange(request).await);
                }
                let (asked, handed) = (fixture.stages.take(), fixture.backend.take());
                for (name, _) in asked
                    .iter()
                    .flat_map(|stage| &stage.headers)
                    .chain(handed.iter().flat_map(|handler| &handler.headers))
                {
                    assert_ne!(name.as_str(), HEADER, "{answer:?}: a context carries the claimed header");
                }
                // Not an empty search: the contexts were built, and their other lines arrived.
                for lines in asked
                    .iter()
                    .map(|stage| &stage.headers)
                    .chain(handed.iter().map(|handler| &handler.headers))
                {
                    assert!(lines.iter().any(|(name, _)| name == "host"), "{answer:?}: {lines:?}");
                    contexts += 1;
                }
                text.extend(produced(&fixture, &responses, &asked, &handed));
            }
            assert!(
                contexts >= 6,
                "both stages and the handler of the admitted requests were searched: {contexts}"
            );
            text
        })
    });
    let events = capture.events();
    assert!(
        events
            .iter()
            .any(|event| event.field("event") == Some("gateway_request_refused")),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|event| event.field("event") == Some("gateway_header_token_posture")),
        "{events:?}"
    );
    let searched: Vec<String> = text.into_iter().chain(events.iter().map(|event| event.rendered())).collect();
    assert!(
        searched.iter().any(|text| text.contains(PRINCIPAL)),
        "the search reads what names the principal"
    );
    for text in &searched {
        let lowered = text.to_ascii_lowercase();
        assert!(!lowered.contains("sentinel"), "the token appears in: {text}");
        assert!(!lowered.contains(&TOKEN.to_ascii_lowercase()), "the token appears in: {text}");
    }
}

/// Negative — a panicking verifier is reported as one contained-panic event that names the
/// extension and the `403` it was answered with, and carries nothing of the panic, the request or
/// the token; nor does anything else the refused request produced.
#[test]
fn n_a_panicking_verifier_is_reported_as_one_contained_panic_event() {
    let (text, capture) = captured(|runtime| {
        runtime.block_on(async {
            let fixture = assemble(Some(Answer::PanicsOnce));
            let response = fixture.exchange(token_only(http::Method::GET, "/")).await;
            assert_eq!(response.status(), http::StatusCode::FORBIDDEN);
            produced(&fixture, &[response], &fixture.stages.take(), &fixture.backend.take())
        })
    });
    let panicked = capture.named("gateway_extension_panicked");
    assert_eq!(panicked.len(), 1, "{:?}", capture.events());
    assert_eq!(panicked[0].field("extension"), Some("header_token_verifier"), "{:?}", panicked[0]);
    assert_eq!(panicked[0].field("operation"), Some("ListBuckets"), "{:?}", panicked[0]);
    let message = panicked[0].field("message").expect("a message");
    assert!(message.contains("answered 403"), "{message}");
    for text in text.into_iter().chain(capture.events().iter().map(|event| event.rendered())) {
        assert!(
            !text.contains("the fixture host's own failure"),
            "the panic payload is never logged: {text}"
        );
        assert!(!text.to_ascii_lowercase().contains("sentinel"), "the token appears in: {text}");
    }
}

/// Negative — a stage filter can neither supply nor erase a token. The floor reads the head as
/// the caller sent it: a header a filter writes authenticates nobody and reaches no context, and
/// a header a filter deletes is still the caller's credential.
#[tokio::test]
async fn n_a_stage_filter_can_neither_supply_nor_erase_a_token() {
    let name = || http::HeaderName::from_static(HEADER);

    let (supplying, recorders) = builder(SecurityFloor::new());
    let supplying = supplying.stage_filter(wire_filter(move |head: &mut WireHead<'_>| {
        head.set_header(name(), http::HeaderValue::from_static("written-by-a-filter"))
            .map_err(Into::into)
    }));
    let fixture = Fixture::of(
        supplying.host_verified_header_token(claim(), AcceptsAnything(Arc::clone(&recorders.verifier_calls))),
        recorders,
    );
    let response = fixture.exchange(support::plain(http::Method::POST, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        fixture.verifier_calls.load(Ordering::SeqCst),
        0,
        "a filter's header is nobody's credential"
    );
    let handed = fixture.backend.take();
    assert!(handed[0].anonymous && handed[0].header_token.is_none(), "{:?}", handed[0]);
    assert!(handed[0].headers.iter().all(|(line, _)| line != HEADER), "{:?}", handed[0]);
    let refused = fixture.exchange(support::plain(http::Method::GET, "/")).await;
    assert_eq!(
        refused.status(),
        http::StatusCode::FORBIDDEN,
        "still the anonymous request it was sent as"
    );

    let (erasing, recorders) = builder(SecurityFloor::new());
    let erasing = erasing.stage_filter(wire_filter(move |head: &mut WireHead<'_>| {
        head.remove_header(&name()).map_err(Into::into)
    }));
    let fixture = Fixture::of(
        erasing.host_verified_header_token(claim(), AcceptsAnything(Arc::clone(&recorders.verifier_calls))),
        recorders,
    );
    let response = fixture.exchange(token_only(http::Method::GET, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(fixture.verifier_calls.load(Ordering::SeqCst), 1, "the caller's token is still verified");
    assert_eq!(fixture.backend.take()[0].header_token.as_deref(), Some(PRINCIPAL));
}

/// Reports [`PRINCIPAL`] for every request it is asked about, and counts them.
struct AcceptsAnything(Arc<std::sync::atomic::AtomicUsize>);

impl rustfs_gateway::HeaderTokenVerifier for AcceptsAnything {
    type Established = Established;

    fn identity(
        &self,
        _established: &Established,
        _now: rustfs_gateway::RequestNow,
    ) -> Result<rustfs_gateway::Identity, rustfs_gateway::HeaderTokenRefused> {
        self.0.fetch_add(1, Ordering::SeqCst);
        rustfs_gateway::Identity::new(PRINCIPAL).map_err(|_| rustfs_gateway::HeaderTokenRefused)
    }
}

// ── the payload ────────────────────────────────────────────────────────────────────────────────

/// A `PutObject` service: with the header token claim installed, or admitting anonymous requests.
fn upload_service(header_token: bool, leave_undecoded: bool) -> (S3Service, Arc<Recorded>) {
    let recorded = Arc::new(Recorded::default());
    let mut builder = support::wired_at_signed_time();
    builder = if header_token {
        builder.host_verified_header_token(claim(), AcceptsAnything(Arc::default()))
    } else {
        builder.security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
    };
    if leave_undecoded {
        builder = builder.leave_anonymous_streaming_payloads_undecoded();
    }
    let service = builder
        .register::<dto::PutObject, _>(Arc::new(Uploads(Arc::clone(&recorded))))
        .build()
        .expect("a complete PutObject assembly");
    (service, recorded)
}

/// What one upload produced: the status, the error code, and the bodies the handler read.
type Outcome = (u16, Option<String>, Vec<(i64, Vec<u8>)>);

async fn upload(header_token: bool, leave_undecoded: bool, request: http::Request<Bytes>) -> Outcome {
    let (service, recorded) = upload_service(header_token, leave_undecoded);
    let request = if header_token { with_token(request) } else { request };
    let (status, body) = support::exchange(&service, request).await;
    let bodies = recorded.bodies.lock().expect("the record is never poisoned").clone();
    (status.as_u16(), support::element_text(&body, "Code").map(str::to_owned), bodies)
}

fn plain_put(extra: &[(&str, &str)]) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .method(http::Method::PUT)
        .uri("/bucket/object")
        .header("host", "s3.example.com")
        .header("content-length", OBJECT.len().to_string());
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(Bytes::from_static(OBJECT)).expect("a valid request")
}

/// Positive and negative — a header-token request's body is held to exactly what an anonymous
/// request's is: every upload shape is decoded, stored or refused identically by a service that
/// verified the token and by one that admitted the same request anonymously, with and without the
/// RustFS profile's switch. No signed-payload obligation is added and none is lifted.
#[tokio::test]
async fn the_body_of_a_header_token_request_is_held_to_what_an_anonymous_body_is() {
    let shapes: Vec<RequestCase> = vec![
        ("a plain body", Box::new(|| plain_put(&[]))),
        (
            "a plain body declaring a digest it does not have",
            Box::new(|| plain_put(&[("x-amz-content-sha256", &"0".repeat(64))])),
        ),
        (
            "a plain body declared unsigned",
            Box::new(|| plain_put(&[("x-amz-content-sha256", "UNSIGNED-PAYLOAD")])),
        ),
        (
            "an unsigned streaming upload",
            Box::new(|| anonymous_put("STREAMING-UNSIGNED-PAYLOAD-TRAILER", OBJECT.len(), unsigned_framing(OBJECT_CRC32))),
        ),
        (
            "a wrong trailer checksum",
            Box::new(|| anonymous_put("STREAMING-UNSIGNED-PAYLOAD-TRAILER", OBJECT.len(), unsigned_framing("AAAAAA=="))),
        ),
        (
            "a wrong decoded length",
            Box::new(|| anonymous_put("STREAMING-UNSIGNED-PAYLOAD-TRAILER", OBJECT.len() + 1, unsigned_framing(OBJECT_CRC32))),
        ),
        (
            "a chunk-signed streaming upload",
            Box::new(|| anonymous_put("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", OBJECT.len(), unsigned_framing(OBJECT_CRC32))),
        ),
        (
            "a chunk-signed streaming upload with a trailer",
            Box::new(|| {
                anonymous_put("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", OBJECT.len(), unsigned_framing(OBJECT_CRC32))
            }),
        ),
    ];
    let mut stored = 0;
    let mut refused = 0;
    for leave_undecoded in [false, true] {
        for (name, request) in &shapes {
            let at = format!("{name}, leave_undecoded={leave_undecoded}");
            let by_token = upload(true, leave_undecoded, request()).await;
            let anonymously = upload(false, leave_undecoded, request()).await;
            assert_eq!(by_token, anonymously, "{at}");
            match by_token.0 {
                200 => stored += 1,
                _ => refused += 1,
            }
        }
    }
    // Both answers occur, so the comparison is not between two services that refuse everything.
    assert!(stored >= 4 && refused >= 4, "stored {stored}, refused {refused}");
    let decoded = upload(true, false, shapes[3].1()).await;
    assert_eq!(
        decoded,
        (200, None, vec![(OBJECT.len() as i64, OBJECT.to_vec())]),
        "decoded as a signed upload is"
    );
}

/// Negative — the claimed header's name in a trailer is not a token: trailers are read by the
/// payload decoder and never by the floor. An upload that declares and sends the name as a
/// trailer, from a request in which the host established an identity, is answered exactly as the
/// same upload is by a service without the claim, and the verifier is not asked. The same upload
/// with the header in its head is the control: there the verifier is asked.
#[tokio::test]
async fn n_the_claimed_name_as_a_trailer_is_not_a_token() {
    let trailered = || {
        let mut body = format!("{:x}\r\n", OBJECT.len()).into_bytes();
        body.extend_from_slice(OBJECT);
        body.extend_from_slice(b"\r\n0\r\n");
        body.extend_from_slice(format!("x-amz-checksum-crc32:{OBJECT_CRC32}\r\n{HEADER}:{TOKEN}\r\n\r\n").as_bytes());
        let mut request = anonymous_put("STREAMING-UNSIGNED-PAYLOAD-TRAILER", OBJECT.len(), body);
        let declared = http::HeaderValue::from_static("x-amz-checksum-crc32,x-auth-token");
        request.headers_mut().insert("x-amz-trailer", declared);
        request.extensions_mut().insert(Established(PRINCIPAL));
        request
    };
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let claimed = |asked: &Arc<std::sync::atomic::AtomicUsize>| {
        support::wired_at_signed_time()
            .security_floor(SecurityFloor::new().delegate_anonymous_to_authorizer_after_listing_in_the_posture_report())
            .host_verified_header_token(claim(), AcceptsAnything(Arc::clone(asked)))
            .register::<dto::PutObject, _>(Arc::new(Uploads(Arc::new(Recorded::default()))))
            .build()
            .expect("a complete PutObject assembly")
    };
    let (status, body) = support::exchange(&claimed(&asked), trailered()).await;
    let answer = (status.as_u16(), support::element_text(&body, "Code").map(str::to_owned));
    let (unclaimed_status, unclaimed_code, _) = upload(false, false, trailered()).await;
    assert_eq!(answer, (unclaimed_status, unclaimed_code), "the trailer changed the answer");
    assert_eq!(asked.load(Ordering::SeqCst), 0, "a trailer was read as a token");
    assert!(!body.to_ascii_lowercase().contains("sentinel"), "{body}");

    let _ = support::exchange(&claimed(&asked), with_token(plain_put(&[]))).await;
    assert_eq!(asked.load(Ordering::SeqCst), 1, "the control: the header in the head is a token");
}

/// Positive and negative — the claimed header is withheld before acceptance, so its bytes are
/// bounded by the floor and not counted in the head's ceiling, and `S3Service::classify` agrees
/// with `call`: a head that only exceeds the ceiling by its token is served when the claim is
/// installed, and refused for its size by both when it is not, exactly as before.
#[tokio::test]
async fn the_withheld_token_is_outside_the_accepted_head_and_classification_agrees() {
    let request = || {
        let mut request = support::plain(http::Method::GET, "/");
        let filler = http::HeaderValue::from_str(&"f".repeat(12 * 1024)).expect("a header value");
        let token = http::HeaderValue::from_str(&"t".repeat(rustfs_gateway::HeaderTokenClaim::MAX_TOKEN_BYTES));
        request.headers_mut().insert("x-filler", filler);
        request.headers_mut().insert(HEADER, token.expect("a header value"));
        request.extensions_mut().insert(Established(PRINCIPAL));
        request
    };
    let (head, _) = request().into_parts();

    let claimed = assemble(Some(Answer::Accepts));
    assert_eq!(claimed.service.classify(&head), rustfs_gateway::Classification::Operation("ListBuckets"));
    let response = claimed.exchange(request()).await;
    assert_eq!(response.status(), http::StatusCode::OK, "{:?}", response.body());
    assert_eq!(claimed.backend.take()[0].header_token.as_deref(), Some(PRINCIPAL));

    let unclaimed = assemble(None);
    let response = unclaimed.exchange(request()).await;
    assert!(response.status().is_client_error(), "{:?}", response.status());
    assert!(unclaimed.backend.take().is_empty());
    let rustfs_gateway::Classification::Refused { status, .. } = unclaimed.service.classify(&head) else {
        panic!("an oversized head is refused before any operation is chosen");
    };
    assert_eq!(status, response.status());
}
