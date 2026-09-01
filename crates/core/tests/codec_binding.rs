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

//! What registration binds together, and what it refuses to leave half-bound.
//!
//! Responsible for: the codec half of registration — that `register_handler` installs a decoder,
//! a handler and an encoder in one call; that a name reaches all three; that the escape hatch is
//! visible from the outside; and that neither a duplicate registration nor a wrongly typed payload
//! can produce a mismatched pair.
//! NOT responsible for: what any generated codec does to bytes (`src/codec/tests.rs`), the
//! registration rules about names, actions, specs and floors (`tests/registration.rs`), or routing
//! (`tests/route_table.rs`).
//! Upstream: `support`. Downstream: nothing.
//!
//! # The headline
//!
//! The pipeline holds an operation *name*. `OperationCodec::decode` and `OperationCodec::encode`
//! are generic per operation. The only place that holds both the name and the type is
//! `register_handler::<O, B>`, so that is where the bridge is built — and it is built for all
//! three at once, or not at all.

// The crate denies these so that no request path can panic on a caller's bytes. A test asserts
// against a fixture it wrote itself, where a panic is the failure report; AGENTS.md exempts test
// code from the rule, and this is where that exemption is spelled.
#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use crate::support;

use std::future::Future;
use std::sync::Arc;

use http::{Request, StatusCode};
use rustfs_gateway_core::codec::ResponseBody;
use rustfs_gateway_core::handler::{Handler, HandlerResult, Req, Resp};
use rustfs_gateway_core::op::Operation;
use rustfs_gateway_core::registry::{ErasedResponse, Registry, RegistryError, RouterBuilder};
use rustfs_gateway_core::route::TargetKind;
use rustfs_gateway_core::{MetaView, RequestBody};
use rustfs_gateway_http::{Limits, WireRequest};
use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{
    GetBucketLocation, GetBucketLocationOutput, LocationConstraint, PutObject, PutObjectOutput, UploadPart, UploadPartOutput,
};
use support::{block_on, sse_proof};

// ── a backend ────────────────────────────────────────────────────────────────────────────────

/// Answers three operations, one of them with a status of its own choosing.
#[derive(Debug)]
struct Fs {
    region: &'static str,
}

impl Fs {
    fn new(region: &'static str) -> Arc<Self> {
        Arc::new(Self { region })
    }
}

impl Handler<GetBucketLocation> for Fs {
    async fn call(&self, request: Req<GetBucketLocation>) -> HandlerResult<GetBucketLocation> {
        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
    }

    fn call_with_context(
        &self,
        _request: Req<GetBucketLocation>,
        _context: rustfs_gateway_core::HandlerContext,
    ) -> impl Future<Output = HandlerResult<GetBucketLocation>> + Send {
        let region = self.region;
        async move {
            Ok(Resp::new(GetBucketLocationOutput {
                location_constraint: Some(LocationConstraint::custom(region)),
            }))
        }
    }
}

impl Handler<PutObject> for Fs {
    async fn call(&self, request: Req<PutObject>) -> HandlerResult<PutObject> {
        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
    }

    async fn call_with_context(
        &self,
        _request: Req<PutObject>,
        _context: rustfs_gateway_core::HandlerContext,
    ) -> HandlerResult<PutObject> {
        Ok(Resp::new(PutObjectOutput::default()))
    }
}

/// Answers with a status the spec does not declare, which is what `Resp::with_status` is for.
impl Handler<UploadPart> for Fs {
    async fn call(&self, request: Req<UploadPart>) -> HandlerResult<UploadPart> {
        let (_source, context) = rustfs_gateway_core::HandlerCancellationSource::pair();
        self.call_with_context(request, context).await
    }

    async fn call_with_context(
        &self,
        _request: Req<UploadPart>,
        _context: rustfs_gateway_core::HandlerContext,
    ) -> HandlerResult<UploadPart> {
        Ok(Resp::with_status(UploadPartOutput::default(), 206))
    }
}

/// An accepted request, owned so a `MetaView` can borrow it.
fn accepted(method: &str, target: &str, headers: &[(&str, &str)]) -> WireRequest<()> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://host.invalid{target}"))
        .header("host", "host.invalid");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(()).expect("the fixture request is well formed");
    WireRequest::accept(request, &Limits::default()).expect("the fixture request is acceptable")
}

fn body_text(body: &ResponseBody) -> String {
    match body {
        ResponseBody::Complete(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        ResponseBody::Empty => String::new(),
        ResponseBody::Stream(_) => panic!("this response carries a stream, not a document"),
    }
}

// ── positive ─────────────────────────────────────────────────────────────────────────────────

/// Positive — one name reaches the decoder, the handler and the encoder, and the three compose.
///
/// This is the whole point of the change: nothing below holds an operation type, and a request
/// still becomes an answer.
#[test]
fn a_name_alone_carries_a_request_through_decode_handler_and_encode() {
    let fs = Fs::new("eu-central-1");
    let router = RouterBuilder::new()
        .handle::<GetBucketLocation, _>(Arc::clone(&fs))
        .build()
        .expect("the builder accepts a well-formed registration");

    let request = accepted("GET", "/photos?location", &[]);
    let view = MetaView::of(&request, TargetKind::Bucket).expect("the path names a bucket");

    let entry = router.registry().wire("GetBucketLocation").expect("registered with a codec");
    assert_eq!(entry.spec.name, "GetBucketLocation");

    let decoded = (entry.decode)(&view, RequestBody::None).expect("the erased decoder reads the request");
    let resources = (entry.resources)(&decoded).expect("derived resources");
    let decisions = vec![rustfs_gateway_core::Decision::Allow; resources.len()];
    let authorized = (entry.authorize)(decoded, &decisions).expect("input authorization");
    let answer = block_on((entry.handler)(authorized, sse_proof())).expect("the erased handler answers");
    let response = (entry.encode)(answer, &view).expect("the erased encoder writes the answer");

    assert_eq!(response.status, StatusCode::OK);
    assert!(body_text(&response.body).contains("eu-central-1"), "{:?}", response.body);
}

/// Positive — the codec arrives with the handler, and it names the operation it was erased from.
#[test]
fn one_registration_installs_the_handler_and_the_codec_together() {
    let fs = Fs::new("us-east-1");
    let mut registry = Registry::new();
    registry
        .register_handler::<PutObject, _>(Arc::clone(&fs))
        .expect("the generated codec makes this registrable");

    assert!(registry.handler("PutObject").is_some());
    let codec = registry.codec("PutObject").expect("the same call installed the codec");
    assert_eq!(codec.operation_name(), "PutObject");
    assert_eq!(registry.handlers().names_without_codec().count(), 0);
}

/// Positive — the status the encoder writes is the one the handler chose, not the declared one.
///
/// `OperationCodec::encode` takes a status because it encodes an `O::Output`; the erased form does
/// not, because a `Resp<O>` already carries the answer to that question. A `206` from a ranged read
/// has to survive the erasure, and the way to find out is to send one through it.
#[test]
fn the_encoder_takes_the_status_from_the_answer_and_not_from_the_spec() {
    let fs = Fs::new("us-east-1");
    let mut registry = Registry::new();
    registry
        .register_handler::<UploadPart, _>(Arc::clone(&fs))
        .expect("registrable");
    assert_eq!(UploadPart::spec().success_status, 200, "the spec's declared status");

    let request = accepted("PUT", "/photos/key?partNumber=1&uploadId=u", &[("content-length", "0")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("the path names an object");
    let entry = registry.wire("UploadPart").expect("registered with a codec");

    let decoded = (entry.decode)(&view, RequestBody::None).expect("decodes");
    let resources = (entry.resources)(&decoded).expect("derived resources");
    let decisions = vec![rustfs_gateway_core::Decision::Allow; resources.len()];
    let authorized = (entry.authorize)(decoded, &decisions).expect("input authorization");
    let answer = block_on((entry.handler)(authorized, sse_proof())).expect("answers");
    let response = (entry.encode)(answer, &view).expect("encodes");

    assert_eq!(response.status, StatusCode::PARTIAL_CONTENT);
}

// ── negative ─────────────────────────────────────────────────────────────────────────────────

/// Negative — the escape hatch leaves a handler with no codec, and says so out loud.
///
/// The state exists on purpose, for an operation whose wire form this crate does not define. What
/// must not exist is a *silent* one: a service that starts, routes the operation, and then has
/// nothing able to read the request.
#[test]
fn n_an_operation_registered_without_a_codec_is_visible_as_such() {
    let fs = Fs::new("us-east-1");
    let mut registry = Registry::new();
    registry
        .register_handler_without_codec::<PutObject, _>(Arc::clone(&fs))
        .expect("registrable without a codec");

    assert!(registry.handler("PutObject").is_some(), "the handler is installed");
    assert!(registry.codec("PutObject").is_none(), "and no codec came with it");
    assert!(registry.wire("PutObject").is_none(), "so the wire path finds nothing");
    assert_eq!(registry.handlers().names_without_codec().collect::<Vec<_>>(), vec!["PutObject"]);
}

/// Negative — a duplicate cannot downgrade a registration that already has a codec.
///
/// The refusal is the same one `tests/registration.rs` asserts for handlers. What is asserted here
/// is what survives it: a second call taking the uncoded path must not strip the codec off the
/// first, which is the way a "registered but unreadable" operation would appear after start-up.
#[test]
fn n_a_second_registration_cannot_strip_the_codec_off_the_first() {
    let first = Fs::new("first-region");
    let second = Fs::new("second-region");
    let mut registry = Registry::new();
    registry
        .register_handler::<GetBucketLocation, _>(Arc::clone(&first))
        .expect("the first registration");

    let error = registry
        .register_handler_without_codec::<GetBucketLocation, _>(Arc::clone(&second))
        .expect_err("the second must be refused");
    assert_eq!(
        error,
        RegistryError::Duplicate {
            name: "GetBucketLocation"
        }
    );
    assert!(
        registry.codec("GetBucketLocation").is_some(),
        "a refused registration must not have removed the codec that was already there"
    );
}

/// Negative — nor can one add a codec to a registration that went without.
///
/// The pair is assembled at registration or never. There is no method that attaches a codec to an
/// entry that exists, and re-registering is not one either.
#[test]
fn n_a_codec_cannot_be_attached_to_an_uncoded_registration_afterwards() {
    let fs = Fs::new("us-east-1");
    let mut registry = Registry::new();
    registry
        .register_handler_without_codec::<PutObject, _>(Arc::clone(&fs))
        .expect("the first registration");

    let error = registry
        .register_handler::<PutObject, _>(Arc::clone(&fs))
        .expect_err("the second must be refused");
    assert_eq!(error, RegistryError::Duplicate { name: "PutObject" });
    assert!(registry.codec("PutObject").is_none(), "and the entry is unchanged");
}

/// Negative — an erased encode with another operation's answer is an error, not a panic.
///
/// Unreachable through [`Registry::wire`], which finds the decoder, the handler and the encoder of
/// one operation together. It is reachable from a pipeline that kept the wrong box, and a
/// framework bug must not be able to take the process down.
#[test]
fn n_an_erased_encode_with_the_wrong_answer_is_an_error_not_a_panic() {
    let fs = Fs::new("us-east-1");
    let mut registry = Registry::new();
    registry
        .register_handler::<PutObject, _>(Arc::clone(&fs))
        .expect("registrable");

    let request = accepted("PUT", "/photos/key", &[("content-length", "0")]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let codec = registry.codec("PutObject").expect("registered with a codec");

    let wrong: ErasedResponse = Box::new(Resp::<GetBucketLocation>::new(GetBucketLocationOutput {
        location_constraint: None,
    }));
    let error = codec.encode(wrong, &view).expect_err("the answer is another operation's");
    assert_eq!(error.code(), &ErrorCode::INTERNAL_ERROR, "a defect here, not a caller mistake");
}

/// Negative — a decode failure keeps the code the operation declares for it.
///
/// The erasure is a call-through and nothing else: it must not turn a `411 MissingContentLength`
/// into an internal error on the way past, because the status a client sees would then be a
/// property of the framework rather than of the operation.
#[test]
fn n_a_decode_failure_reaches_the_caller_with_its_own_code() {
    let fs = Fs::new("us-east-1");
    let mut registry = Registry::new();
    registry
        .register_handler::<PutObject, _>(Arc::clone(&fs))
        .expect("registrable");

    let request = accepted("PUT", "/photos/key", &[]);
    let view = MetaView::of(&request, TargetKind::Object).expect("view");
    let entry = registry.wire("PutObject").expect("registered with a codec");

    let error = (entry.decode)(&view, RequestBody::None).expect_err("Content-Length is required");
    assert_eq!(error.code().as_str(), "MissingContentLength");
    assert_eq!(error.status(), StatusCode::LENGTH_REQUIRED);
    assert_eq!(error.member(), Some("ContentLength"));
}

/// Negative — an unregistered operation reaches none of the three.
#[test]
fn n_an_unregistered_operation_has_no_codec_and_no_wire_entry() {
    let registry = Registry::new();
    assert!(registry.handler("GetBucketLocation").is_none());
    assert!(registry.codec("GetBucketLocation").is_none());
    assert!(registry.wire("GetBucketLocation").is_none());
    assert!(registry.handlers().names_without_codec().next().is_none());
}
