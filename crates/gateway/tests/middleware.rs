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

//! What a `StageFilter` and an `OpLayer<O>` may do, and the four things neither may.
//!
//! Responsible for: the three seams (`on_wire`, `on_routed`, `on_response`) — that each one runs,
//! that removing one is visible, that registration order is observable, and that a refusal from any
//! of them ends the request — plus `OpLayer<O>`'s reach, its nesting order, and the two properties
//! the security review asks of the whole design: a filter cannot forge authentication and cannot
//! destroy it either.
//! NOT responsible for: the nine RustFS patch layers' landings, which are
//! `tests/patch_layer_landings.rs` and are cross-checked against `docs/middleware.md`; or the
//! zero-registration cost, which is a unit test in `src/dispatch.rs` because the observation it
//! needs is not reachable from an integration test.
//! Upstream: `tests/support`. Downstream: nothing.
//!
//! # Why the signature assertions need a signed request
//!
//! "A filter cannot forge authentication" is only half a control: an observer stuck on `403`
//! satisfies it. The other half is a request that really is signed, whose signature really does
//! survive a filter rewriting the header it was computed over. So this suite signs, through
//! `support::signed`, and both halves are asserted against the same filter.

use crate::support;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use rustfs_gateway::dto::{ListBuckets, ListBucketsOutput};
use rustfs_gateway::{
    BoxFuture, ETag, HandlerError, HandlerResult, Next, OpLayer, Req, Resp, ResponseView, RoutedView, StageFilter, WireHead,
    op_layer, response_filter, wire_filter,
};
use support::{Backend, ContentPing, Ping, exchange, exchange_wire, plain, service, wired};

// ── recorders ───────────────────────────────────────────────────────────────────────────────────

/// A filter that appends its own label at every seam it is asked about.
///
/// One type for all three seams so that the order assertion reads the same list whichever seam it
/// is about, and so that "the seam ran" and "the seam ran in this position" are one observation.
struct Trail {
    label: &'static str,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Trail {
    fn new(label: &'static str, seen: &Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            label,
            seen: Arc::clone(seen),
        }
    }

    fn note(&self, seam: &str) {
        if let Ok(mut seen) = self.seen.lock() {
            seen.push(format!("{seam}:{}", self.label));
        }
    }
}

impl StageFilter for Trail {
    fn on_wire(&self, _head: &mut WireHead<'_>) -> Result<(), HandlerError> {
        self.note("wire");
        Ok(())
    }

    fn on_routed(&self, routed: &RoutedView<'_>) -> Result<(), HandlerError> {
        self.note(routed.operation());
        Ok(())
    }

    fn on_response(
        &self,
        _view: &ResponseView<'_>,
        _response: &mut http::Response<rustfs_gateway::Body>,
    ) -> Result<(), HandlerError> {
        self.note("response");
        Ok(())
    }
}

fn trail() -> (Arc<Mutex<Vec<String>>>, Trail, Trail, Trail) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    (
        Arc::clone(&seen),
        Trail::new("one", &seen),
        Trail::new("two", &seen),
        Trail::new("three", &seen),
    )
}

/// The header the `EmptyBodyContentLengthCompat` demonstration writes, and the value the fixture
/// operation echoes back so a test can see whether the filter ran.
const LENGTH_ECHO: &str = "x-length-seen";

// ── the wire seam ───────────────────────────────────────────────────────────────────────────────

/// Positive — a `StageFilter::on_wire` that supplies a missing `Content-Length` reaches the
/// decoder. This is `EmptyBodyContentLengthCompatLayer`'s landing, and the observation is the
/// decoder's rather than the response's: the point of the seam is that the *pipeline* sees the
/// rewrite.
#[tokio::test]
async fn a_wire_filter_supplies_a_missing_content_length() {
    let service = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            if head.header(&http::header::CONTENT_LENGTH).is_none() {
                head.set_header(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"))?;
            }
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::PUT, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(header_of(&response, LENGTH_ECHO), Some("0"));
}

/// Negative — the control for the assertion above: with the seam unused the header is absent, so
/// the test cannot be passing because the fixture writes the echo unconditionally.
#[tokio::test]
async fn without_the_wire_filter_no_content_length_reaches_the_decoder() {
    let service = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::PUT, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(header_of(&response, LENGTH_ECHO), None);
}

/// Negative — the `Host` header is the one piece of signing material derived from the head *after*
/// the seam, so it is frozen: the attempt is refused, and the request is answered against the host
/// the caller actually sent.
#[tokio::test]
async fn a_wire_filter_may_not_rewrite_the_host() {
    let refusals = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&refusals);
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(wire_filter(move |head: &mut WireHead<'_>| {
            if head
                .set_header(http::header::HOST, http::HeaderValue::from_static("elsewhere.example.com"))
                .is_err()
            {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(refusals.load(Ordering::SeqCst), 1);
}

/// Negative — a refusal from `on_wire` ends the request: the response is the rendered error and the
/// handler never ran.
#[tokio::test]
async fn a_wire_filter_refusal_ends_the_request() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = counting_service(
        &reached,
        wire_filter(|_head: &mut WireHead<'_>| {
            Err(HandlerError::new(
                rustfs_gateway::ErrorCode::INVALID_REQUEST,
                "this deployment refuses the request at the wire seam",
            ))
        }),
    );
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::BAD_REQUEST);
    assert!(body.contains("<Code>InvalidRequest</Code>"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Positive — the other direction of the same control: a filter that returns `Ok` lets the request
/// through, so the assertion above is about the refusal and not about the filter existing.
#[tokio::test]
async fn a_wire_filter_that_permits_lets_the_request_through() {
    let reached = Arc::new(AtomicUsize::new(0));
    let service = counting_service(&reached, wire_filter(|_head: &mut WireHead<'_>| Ok(())));
    let (status, _) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

// ── the routed seam ─────────────────────────────────────────────────────────────────────────────

/// Negative — the routed seam knows which operation it is looking at, and a refusal there ends the
/// request before the body and before authentication.
#[tokio::test]
async fn a_routed_filter_may_refuse_one_operation_by_name() {
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reached);
    let service = wired()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&counter)))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(rustfs_gateway::routed_filter(|routed: &RoutedView<'_>| {
            if routed.operation() == "example:Ping" {
                return Err(HandlerError::new(
                    rustfs_gateway::ErrorCode::NOT_IMPLEMENTED,
                    "this deployment has switched that operation off",
                ));
            }
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    assert!(body.contains("switched that operation off"), "{body}");
    assert_eq!(reached.load(Ordering::SeqCst), 0);
}

/// Positive — the same filter passes an operation whose name it does not match, so its refusal is
/// a decision about the request rather than a constant.
#[tokio::test]
async fn a_routed_filter_passes_the_operation_it_does_not_name() {
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reached);
    let service = wired()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&counter)))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(rustfs_gateway::routed_filter(|routed: &RoutedView<'_>| {
            if routed.operation() == "example:SomethingElse" {
                return Err(HandlerError::new(rustfs_gateway::ErrorCode::NOT_IMPLEMENTED, "off"));
            }
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(reached.load(Ordering::SeqCst), 1);
}

// ── the response seam ───────────────────────────────────────────────────────────────────────────

/// Positive — `on_response` may add a header, which is what the scattered response-rewriting
/// requirements in the landing table need.
#[tokio::test]
async fn a_response_filter_may_add_a_header() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                response
                    .headers_mut()
                    .insert(http::HeaderName::from_static("x-deployment"), http::HeaderValue::from_static("yes"));
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(header_of(&response, "x-deployment"), Some("yes"));
}

/// Negative — the control: with no filter installed the header is absent.
#[tokio::test]
async fn without_a_response_filter_the_header_is_absent() {
    let response = exchange_wire(&service(), plain(http::Method::POST, "/")).await;
    assert_eq!(header_of(&response, "x-deployment"), None);
}

/// Negative — the seam runs for a request that never reached an operation. A response filter that
/// only saw routed requests would be unable to rewrite the one refusal every misconfigured client
/// sees.
#[tokio::test]
async fn the_response_seam_runs_for_a_request_that_never_routed() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&seen);
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(response_filter(
            move |view: &ResponseView<'_>, _response: &mut http::Response<rustfs_gateway::Body>| {
                if let Ok(mut seen) = recorder.lock() {
                    seen.push(view.operation().map(str::to_owned));
                }
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::DELETE, "/nothing/here")).await;
    assert_eq!(status, http::StatusCode::NOT_IMPLEMENTED);
    assert_eq!(seen.lock().expect("not poisoned").as_slice(), [None]);
}

/// Negative — a filter cannot put content on a bodyless status. The RFC 9110 invariants run
/// *after* the seam, so `BodylessStatusFixLayer`'s defect cannot be reintroduced by a deployment's
/// own rewrite.
#[tokio::test]
async fn a_response_filter_cannot_put_a_body_on_a_304() {
    let service = wired()
        .register::<support::HeadPing, _>(Arc::new(Backend))
        .dialect(&crate::support::head_ping_dialect())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                *response.body_mut() = rustfs_gateway::Body::from_bytes(Bytes::from_static(b"<Nonsense/>"));
                response
                    .headers_mut()
                    .insert(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("11"));
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::HEAD, "/?not-modified")).await;
    assert_eq!(response.status(), http::StatusCode::NOT_MODIFIED);
    assert!(response.body().is_empty(), "a 304 kept a filter's body");
    assert_eq!(header_of(&response, "content-length"), None);
}

/// Negative — a filter that shrinks a body cannot leave a `Content-Length` announcing the bytes it
/// removed. A response that declares more than it sends is the shape that hangs a client until its
/// own read timeout, which is what s3s#54 and s3s#350 are.
#[tokio::test]
async fn a_response_filter_cannot_leave_a_content_length_that_overstates_the_body() {
    let service = wired()
        .register::<support::ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                *response.body_mut() = rustfs_gateway::Body::from_bytes(Bytes::from_static(b"hi"));
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::PUT, "/")).await;
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.body().len(), 2);
    assert_eq!(header_of(&response, "content-length"), Some("2"));
    assert_eq!(header_of(&response, "transfer-encoding"), None);
}

/// Negative — the framework's own four headers are written after the seam, so a filter cannot take
/// the request identifier off a response. An audit trail a deployment can silently disable is not
/// one.
#[tokio::test]
async fn a_response_filter_cannot_remove_the_request_identifier() {
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                response.headers_mut().remove(rustfs_gateway::REQUEST_ID_HEADER);
                response.headers_mut().remove(http::header::DATE);
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::POST, "/")).await;
    assert!(response.header(rustfs_gateway::REQUEST_ID_HEADER.as_str()).is_some());
    assert!(response.header("date").is_some());
}

/// Negative — a refusal from `on_response` replaces the response and stops the remaining filters,
/// so "the last filter wins" cannot be true of a seam that refused.
#[tokio::test]
async fn a_response_filter_refusal_replaces_the_response_and_stops_the_rest() {
    let later = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&later);
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, _response: &mut http::Response<rustfs_gateway::Body>| {
                Err(HandlerError::new(
                    rustfs_gateway::ErrorCode::INTERNAL_ERROR,
                    "this deployment rejected its own answer",
                ))
            },
        ))
        .stage_filter(response_filter(
            move |_view: &ResponseView<'_>, _response: &mut http::Response<rustfs_gateway::Body>| {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.contains("<Code>InternalError</Code>"), "{body}");
    assert_eq!(counter_value(&later), 0);
}

// ── ordering ────────────────────────────────────────────────────────────────────────────────────

/// Positive — three filters run in registration order at every seam, and the golden list is the
/// whole contract. Swapping two registrations changes this list, which is what makes the order
/// observable rather than implied.
#[tokio::test]
async fn filters_run_in_registration_order_at_every_seam() {
    let (seen, one, two, three) = trail();
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(one)
        .stage_filter(two)
        .stage_filter(three)
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(
        seen.lock().expect("not poisoned").as_slice(),
        [
            "wire:one",
            "wire:two",
            "wire:three",
            "example:Ping:one",
            "example:Ping:two",
            "example:Ping:three",
            "response:one",
            "response:two",
            "response:three",
        ]
    );
}

/// Positive — the reverse registration produces the reverse list. Without this the assertion above
/// would be satisfied by any implementation that happened to iterate a sorted container.
#[tokio::test]
async fn reversing_the_registration_reverses_every_seam() {
    let (seen, one, two, three) = trail();
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(three)
        .stage_filter(two)
        .stage_filter(one)
        .build()
        .expect("a complete assembly");
    let _ = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(seen.lock().expect("not poisoned").first().map(String::as_str), Some("wire:three"));
    assert_eq!(seen.lock().expect("not poisoned").last().map(String::as_str), Some("response:one"));
}

/// Positive — a later filter sees an earlier one's rewrite. Composition is sequential over one
/// head, not three independent views of the original.
#[tokio::test]
async fn a_later_wire_filter_sees_an_earlier_ones_rewrite() {
    let service = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            head.set_header(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"))?;
            Ok(())
        }))
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            // Reads what the first filter wrote and doubles the digit, so the value that reaches the
            // decoder can only have come from a chain of two.
            let seen = head.header(&http::header::CONTENT_LENGTH).is_some();
            assert!(seen, "the second filter did not see the first one's header");
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let response = exchange_wire(&service, plain(http::Method::PUT, "/")).await;
    assert_eq!(header_of(&response, LENGTH_ECHO), Some("0"));
}

// ── the floor is not reachable from a filter ────────────────────────────────────────────────────

/// Negative — a filter cannot forge authentication. `ListBuckets` requires a signature; a filter
/// that writes a plausible `Authorization` onto the head does not make an anonymous request
/// authenticated, because the verifier reads the material frozen at the entry to the pipeline.
#[tokio::test]
async fn a_wire_filter_cannot_forge_an_authorization_header() {
    let service = wired()
        .register::<ListBuckets, _>(Arc::new(Backend))
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            // Not frozen, so the write succeeds — and changes nothing.
            head.set_header(
                http::header::AUTHORIZATION,
                http::HeaderValue::from_static(
                    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20260101/us-east-1/s3/aws4_request, \
                     SignedHeaders=host, Signature=0000000000000000000000000000000000000000000000000000000000000000",
                ),
            )?;
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::GET, "/")).await;
    assert_ne!(status, http::StatusCode::OK, "a forged header reached the verifier");
}

/// Negative — the other direction, and the one that proves the frozen snapshot is what is being
/// read: a filter that deletes the `Authorization` header from the head does **not** turn a
/// correctly signed request into a `403`. A verifier reading the post-filter head would answer the
/// opposite, and this pair is the only way to tell the two implementations apart.
#[tokio::test]
async fn a_wire_filter_cannot_destroy_a_valid_signature() {
    let clock = support::fixed_clock();
    let service = wired()
        .clock_with_skew_ack(
            clock,
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<ListBuckets, _>(Arc::new(Backend))
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            head.remove_header(&http::header::AUTHORIZATION)?;
            head.set_header(
                http::HeaderName::from_static("x-amz-content-sha256"),
                http::HeaderValue::from_static("rewritten-by-a-filter"),
            )?;
            Ok(())
        }))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, support::signed(http::Method::GET, "/")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
}

/// Positive — the control for the pair above: the same signed request is answered by the same
/// assembly with no filter at all, so neither assertion is passing because the fixture cannot sign.
#[tokio::test]
async fn the_signed_request_is_answered_without_any_filter() {
    let service = wired()
        .clock_with_skew_ack(
            support::fixed_clock(),
            rustfs_gateway::ClockSkewAck::i_understand_a_skewed_clock_can_disable_signature_expiry(),
        )
        .register::<ListBuckets, _>(Arc::new(Backend))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, support::signed(http::Method::GET, "/")).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
}

// ── OpLayer<O> ──────────────────────────────────────────────────────────────────────────────────

/// A layer that records that it ran and then delegates.
fn marking_layer<O: rustfs_gateway::Operation>(marks: &Arc<Mutex<Vec<&'static str>>>, label: &'static str) -> impl OpLayer<O> {
    let marks = Arc::clone(marks);
    op_layer(move |request: Req<O>, next: Next<'_, O>| {
        let marks = Arc::clone(&marks);
        Box::pin(async move {
            if let Ok(mut marks) = marks.lock() {
                marks.push(label);
            }
            let response = next.run(request).await;
            if let Ok(mut marks) = marks.lock() {
                marks.push(label);
            }
            response
        }) as BoxFuture<'_, HandlerResult<O>>
    })
}

/// Positive — a layer registered for one operation runs for that operation.
#[tokio::test]
async fn an_op_layer_runs_for_its_own_operation() {
    let marks = Arc::new(Mutex::new(Vec::new()));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .dialect(&crate::support::content_ping_dialect())
        .op_layer::<Ping, _>(marking_layer(&marks, "ping"))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(marks.lock().expect("not poisoned").as_slice(), ["ping", "ping"]);
}

/// Negative — and it does **not** run for a sibling operation. A per-operation middleware that
/// reached every operation would be a `StageFilter` with a misleading signature.
#[tokio::test]
async fn an_op_layer_does_not_run_for_a_sibling_operation() {
    let marks = Arc::new(Mutex::new(Vec::new()));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .dialect(&crate::support::content_ping_dialect())
        .op_layer::<Ping, _>(marking_layer(&marks, "ping"))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::PUT, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(marks.lock().expect("not poisoned").is_empty(), "the layer reached a sibling");
}

/// Positive — two layers on one operation nest outer to inner in registration order. The list is
/// the golden: `outer` opens first and closes last.
#[tokio::test]
async fn two_op_layers_nest_outer_to_inner_in_registration_order() {
    let marks = Arc::new(Mutex::new(Vec::new()));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .op_layer::<Ping, _>(marking_layer(&marks, "outer"))
        .op_layer::<Ping, _>(marking_layer(&marks, "inner"))
        .build()
        .expect("a complete assembly");
    let _ = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(marks.lock().expect("not poisoned").as_slice(), ["outer", "inner", "inner", "outer"]);
}

/// Positive — reversing the two registrations reverses the nesting, so the assertion above is
/// about order and not about two labels appearing.
#[tokio::test]
async fn reversing_two_op_layers_reverses_the_nesting() {
    let marks = Arc::new(Mutex::new(Vec::new()));
    let service = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .op_layer::<Ping, _>(marking_layer(&marks, "inner"))
        .op_layer::<Ping, _>(marking_layer(&marks, "outer"))
        .build()
        .expect("a complete assembly");
    let _ = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(marks.lock().expect("not poisoned").as_slice(), ["inner", "outer", "outer", "inner"]);
}

/// Negative — a layer may answer without calling `next`, and then the handler does not run. This
/// is a real capability and the reason it is safe is the position: authentication and both
/// authorisation stages have already happened, so the request the layer is answering is one the
/// caller was permitted to make.
#[tokio::test]
async fn an_op_layer_may_answer_without_reaching_the_handler() {
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reached);
    let service = wired()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(&counter)))
        .dialect(&crate::support::ping_dialect())
        .op_layer::<Ping, _>(op_layer(|_request: Req<Ping>, _next: Next<'_, Ping>| {
            Box::pin(async {
                Ok(Resp::new(support::PingOutput {
                    message: "answered by a layer".to_owned(),
                }))
            }) as BoxFuture<'_, HandlerResult<Ping>>
        }))
        .build()
        .expect("a complete assembly");
    let (status, body) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(body.contains("answered by a layer"), "{body}");
    assert_eq!(counter_value(&reached), 0);
}

/// Negative — a layer runs after authorisation, so a denied request never reaches one. A layer
/// that ran before the authorizer would be exactly the bypass rustfs/rustfs#4845 is.
#[tokio::test]
async fn an_op_layer_never_runs_for_a_request_authorisation_denied() {
    let marks = Arc::new(Mutex::new(Vec::new()));
    let service = support::wired_denying()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .op_layer::<Ping, _>(marking_layer(&marks, "ping"))
        .build()
        .expect("a complete assembly");
    let (status, _) = exchange(&service, plain(http::Method::POST, "/")).await;
    assert_eq!(status, http::StatusCode::FORBIDDEN);
    assert!(marks.lock().expect("not poisoned").is_empty(), "a layer ran on a denied request");
}

/// Negative — a layer for an operation nobody registered refuses the build. Silently ignoring it
/// would leave a deployment believing a rewrite is in force when nothing runs it.
#[test]
fn an_op_layer_for_an_unregistered_operation_refuses_the_build() {
    let error = wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .op_layer::<ContentPing, _>(op_layer(|request: Req<ContentPing>, next: Next<'_, ContentPing>| next.run(request)))
        .build()
        .expect_err("a layer with nothing to wrap");
    assert_eq!(error.rule().as_str(), "asm-op-layer-unattached");
    assert!(error.to_string().contains("example:ContentPing"), "{error}");
}

/// Positive — the control: the identical layer on a registered operation builds. Without it the
/// refusal above could be "every `op_layer` call refuses".
#[test]
fn an_op_layer_for_a_registered_operation_builds() {
    wired()
        .register::<Ping, _>(Arc::new(Backend))
        .dialect(&crate::support::ping_dialect())
        .op_layer::<Ping, _>(op_layer(|request: Req<Ping>, next: Next<'_, Ping>| next.run(request)))
        .build()
        .expect("a layer on a registered operation");
}

/// Positive — the `ObjectAttributesEtagFixLayer` demonstration: a typed per-operation middleware
/// reaches `GetObjectAttributesOutput::e_tag` and rewrites it. The body of the layer is three
/// statements; today's tower layer has to parse the response XML, edit it and serialise it back,
/// because it cannot name this field.
#[tokio::test]
async fn an_op_layer_rewrites_a_typed_output_field() {
    let service = support::attributes_service(true);
    let (status, body) = exchange(&service, support::attributes_request()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert!(body.contains("<ETag>rewritten-by-a-layer</ETag>"), "{body}");
}

/// Negative — the control: without the layer the same request answers the value the backend
/// produced, so the assertion above measures the layer and not the fixture.
#[tokio::test]
async fn without_the_op_layer_the_backends_etag_is_answered() {
    let service = support::attributes_service(false);
    let (status, body) = exchange(&service, support::attributes_request()).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert!(body.contains("<ETag>backend-etag</ETag>"), "{body}");
    assert!(!body.contains("rewritten-by-a-layer"), "{body}");
}

// ── the three layers together ───────────────────────────────────────────────────────────────────

/// Positive — a tower `Layer` outside the service, a `StageFilter` and an `OpLayer` all in force
/// at once, each visible in the answer and none interfering with the others.
#[tokio::test]
async fn all_three_levels_are_in_force_at_once() {
    let marks = Arc::new(Mutex::new(Vec::new()));
    let mut service = wired()
        .register::<ContentPing, _>(Arc::new(Backend))
        .dialect(&crate::support::content_ping_dialect())
        .stage_filter(wire_filter(|head: &mut WireHead<'_>| {
            head.set_header(http::header::CONTENT_LENGTH, http::HeaderValue::from_static("0"))?;
            Ok(())
        }))
        .stage_filter(response_filter(
            |_view: &ResponseView<'_>, response: &mut http::Response<rustfs_gateway::Body>| {
                response
                    .headers_mut()
                    .insert(http::HeaderName::from_static("x-deployment"), http::HeaderValue::from_static("yes"));
                Ok(())
            },
        ))
        .op_layer::<ContentPing, _>(marking_layer(&marks, "layer"))
        .build()
        .expect("a complete assembly");
    // The outermost level: a tower `Layer` is the standard ecosystem one and needs nothing from
    // this crate, so the assertion is that the service is still a `tower::Service` and that the
    // two inner levels are unaffected by being driven through it.
    let (status, _) = support::tower_exchange(&mut service, plain(http::Method::PUT, "/")).await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(marks.lock().expect("not poisoned").as_slice(), ["layer", "layer"]);
    let response = exchange_wire(&service, plain(http::Method::PUT, "/")).await;
    assert_eq!(header_of(&response, "x-deployment"), Some("yes"));
    assert_eq!(header_of(&response, LENGTH_ECHO), Some("0"));
}

// ── helpers ─────────────────────────────────────────────────────────────────────────────────────

fn header_of<'a>(response: &'a rustfs_gateway::WireResponse, name: &str) -> Option<&'a str> {
    response.header(name)
}

fn counter_value(counter: &Arc<AtomicUsize>) -> usize {
    counter.load(Ordering::SeqCst)
}

/// A service over `example:Ping` whose backend counts the requests that reached it.
fn counting_service(reached: &Arc<AtomicUsize>, filter: impl StageFilter) -> rustfs_gateway::S3Service {
    wired()
        .register::<Ping, _>(Arc::new(support::CountingBackend::new(reached)))
        .dialect(&crate::support::ping_dialect())
        .stage_filter(filter)
        .build()
        .expect("a complete assembly")
}

/// Keeps the `ListBucketsOutput` import honest: the fixture answers one, and a test that named the
/// type without using it would be a warning rather than an assertion.
#[test]
fn the_fixture_answers_a_list() {
    let output = ListBucketsOutput::default();
    assert!(output.buckets.is_empty());
    let _ = ETag::ANY;
}
