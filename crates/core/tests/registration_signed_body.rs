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

//! The registration refusal of a caller-secret opt-in over a signed body whose request body is not
//! read whole before the handler runs (rustfs/gateway#1587, ADR-0053).
//!
//! Responsible for: `Registry::register_handler` and `register_handler_without_codec` for one
//! signed-body opt-in under every request-body mode, and the plain opt-in as the control.
//! NOT responsible for: what the facade hands over at request time (`rustfs-gateway`'s
//! `dialect_claims_signed_body` tests).
//! Upstream: `rustfs_gateway_core::registry::Registry` and its codec types. Downstream: nothing.

use std::sync::Arc;

use rustfs_gateway_sig::{OperationFloor, SigService};

use rustfs_gateway_core::codec::{CodecError, EncodedResponse, MetaView, OperationCodec, RequestBody, RequestBodyMode};
use rustfs_gateway_core::handler::{Handler, HandlerResult, Req, Resp};
use rustfs_gateway_core::op::{AuthRequirement, Operation, ResourceShape};
use rustfs_gateway_core::registry::{HandlerDeadlineClass, OperationSpec, Registry, RegistryError};

const MODES: [RequestBodyMode; 5] = [
    RequestBodyMode::Full,
    RequestBodyMode::Streaming,
    RequestBodyMode::Deferred,
    RequestBodyMode::None,
    RequestBodyMode::PostObject,
];
const NAMES: [&str; 5] = [
    "acme:FormFull",
    "acme:FormStreaming",
    "acme:FormDeferred",
    "acme:FormNone",
    "acme:FormPost",
];
const PLAIN: [&str; 5] = [
    "acme:PlainFull",
    "acme:PlainStreaming",
    "acme:PlainDeferred",
    "acme:PlainNone",
    "acme:PlainPost",
];

const fn base(name: &'static str) -> OperationSpec {
    OperationSpec::builder(name, 200, None)
        .handler_deadline_class(HandlerDeadlineClass::Standard)
        .required_params(&[])
        .auth(AuthRequirement::new("acme:Write", ResourceShape::Service))
}

static SIGNED: [OperationSpec; 5] = [
    base(NAMES[0]).hand_caller_secret_to_handler_over_a_signed_body().build(),
    base(NAMES[1]).hand_caller_secret_to_handler_over_a_signed_body().build(),
    base(NAMES[2]).hand_caller_secret_to_handler_over_a_signed_body().build(),
    base(NAMES[3]).hand_caller_secret_to_handler_over_a_signed_body().build(),
    base(NAMES[4]).hand_caller_secret_to_handler_over_a_signed_body().build(),
];
static PLAIN_SPECS: [OperationSpec; 5] = [
    base(PLAIN[0]).hand_caller_secret_to_handler().build(),
    base(PLAIN[1]).hand_caller_secret_to_handler().build(),
    base(PLAIN[2]).hand_caller_secret_to_handler().build(),
    base(PLAIN[3]).hand_caller_secret_to_handler().build(),
    base(PLAIN[4]).hand_caller_secret_to_handler().build(),
];
static SIGNED_FLOORS: [OperationFloor; 5] = [
    OperationFloor::custom(NAMES[0], SigService::S3),
    OperationFloor::custom(NAMES[1], SigService::S3),
    OperationFloor::custom(NAMES[2], SigService::S3),
    OperationFloor::custom(NAMES[3], SigService::S3),
    OperationFloor::custom(NAMES[4], SigService::S3),
];
static PLAIN_FLOORS: [OperationFloor; 5] = [
    OperationFloor::custom(PLAIN[0], SigService::S3),
    OperationFloor::custom(PLAIN[1], SigService::S3),
    OperationFloor::custom(PLAIN[2], SigService::S3),
    OperationFloor::custom(PLAIN[3], SigService::S3),
    OperationFloor::custom(PLAIN[4], SigService::S3),
];

/// One vendor operation per body mode; `SIGNED_BODY` picks the opt-in form.
struct Form<const N: usize, const SIGNED_BODY: bool>;

impl<const N: usize, const SIGNED_BODY: bool> Operation for Form<N, SIGNED_BODY> {
    const NAME: &'static str = if SIGNED_BODY { NAMES[N] } else { PLAIN[N] };
    type Input = ();
    type Output = ();
    type DerivedResources = rustfs_gateway_core::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, rustfs_gateway_core::DerivedResourceError> {
        Ok(rustfs_gateway_core::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        if SIGNED_BODY { &SIGNED[N] } else { &PLAIN_SPECS[N] }
    }

    fn floor() -> &'static OperationFloor {
        if SIGNED_BODY { &SIGNED_FLOORS[N] } else { &PLAIN_FLOORS[N] }
    }
}

impl<const N: usize, const SIGNED_BODY: bool> OperationCodec for Form<N, SIGNED_BODY> {
    const REQUEST_BODY: RequestBodyMode = MODES[N];

    fn decode(_request: &MetaView<'_>, _body: RequestBody) -> Result<(), CodecError> {
        Ok(())
    }

    fn encode(_output: (), _request: &MetaView<'_>, status: u16) -> Result<EncodedResponse, CodecError> {
        Ok(EncodedResponse::of(status))
    }
}

struct Backend;

impl<const N: usize, const SIGNED_BODY: bool> Handler<Form<N, SIGNED_BODY>> for Backend {
    async fn call(&self, _request: Req<Form<N, SIGNED_BODY>>) -> HandlerResult<Form<N, SIGNED_BODY>> {
        Ok(Resp::new(()))
    }
}

fn register<const N: usize, const SIGNED_BODY: bool>() -> Result<(), RegistryError> {
    Registry::new().register_handler::<Form<N, SIGNED_BODY>, _>(Arc::new(Backend))
}

fn refused(name: &'static str) -> Result<(), RegistryError> {
    Err(RegistryError::SignedBodySecretWithoutAWholeBody { name })
}

/// Positive — a signed-body opt-in registers when its body is read whole before the handler, and
/// the plain opt-in registers under every body mode.
#[test]
fn a_signed_body_opt_in_registers_over_a_body_read_whole() {
    assert_eq!(register::<0, true>(), Ok(()));
    assert_eq!(register::<0, false>(), Ok(()));
    assert_eq!(register::<1, false>(), Ok(()));
    assert_eq!(register::<2, false>(), Ok(()));
    assert_eq!(register::<3, false>(), Ok(()));
    assert_eq!(register::<4, false>(), Ok(()));
}

/// Negative — a signed-body opt-in is refused for a streamed, deferred, absent or POST-form body,
/// where the handler runs before the digest or the last chunk signature is checked, or never sees a
/// body the signature could cover.
#[test]
fn n_a_signed_body_opt_in_over_a_body_not_read_whole_is_refused() {
    assert_eq!(register::<1, true>(), refused(NAMES[1]));
    assert_eq!(register::<2, true>(), refused(NAMES[2]));
    assert_eq!(register::<3, true>(), refused(NAMES[3]));
    assert_eq!(register::<4, true>(), refused(NAMES[4]));
}

/// Negative — without a codec the body mode is unknown, so the signed-body opt-in is refused there
/// too; the plain opt-in is not.
#[test]
fn n_a_signed_body_opt_in_without_a_codec_is_refused() {
    assert_eq!(
        Registry::new().register_handler_without_codec::<Form<0, true>, _>(Arc::new(Backend)),
        refused(NAMES[0])
    );
    assert_eq!(
        Registry::new().register_handler_without_codec::<Form<0, false>, _>(Arc::new(Backend)),
        Ok(())
    );
}

/// Negative — the refusal names the operation and why.
#[test]
fn n_the_refusal_says_which_operation_and_why() {
    let message = RegistryError::SignedBodySecretWithoutAWholeBody { name: NAMES[1] }.to_string();
    assert!(message.contains("acme:FormStreaming"), "{message}");
    assert!(message.contains("read the body whole"), "{message}");
}
