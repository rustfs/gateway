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

//! `SelectObjectContent`: a query over one object, whose answer is a frame sequence.
//!
//! Responsible for: the spec, the security floor and the [`Operation`] implementation for
//! `SelectObjectContent`, plus the [`HasOperation`] reverse mapping from its input type.
//! NOT responsible for: the wire bindings, generated into
//! `generated/codec/ops/select_object_content.rs` — this is the first operation in the supported
//! surface whose XML members sit at **operation level** rather than inside an `httpPayload`
//! structure, so the document rooted at `SelectObjectContentRequest` is opened by the decoder
//! itself; nor for the request's semantic rules — the one-of-three input serialization, the
//! one-of-two output serialization, the `ScanRange` grammar and the expression ceiling — which
//! live once in [`shared::select`](super::shared::select); nor for the frame encoding of the
//! answer, which is [`shared::event_stream`](super::shared::event_stream)'s; nor, emphatically,
//! for **evaluating** the expression: SQL parsing and execution belong to the storage side, and
//! nothing in this crate reads a character of it.
//! Upstream: `rustfs-gateway-types`' generated dto. Downstream: `crate::registry`.
//!
//! Shares: event_stream, select.
//!
//! # What is decoded here and what is deliberately not answered
//!
//! The request half is complete: expression, expression type, all three input serializations
//! with their sub-members, both output serializations, the progress switch and the scan range
//! reach a handler decoded and validated. The response half is **not wired**, and the reason is
//! a type rather than an omission. `Resp<O>` has two shapes — a settled answer and a committed
//! one — and an event stream is a third: a status line sent before the first record exists,
//! then a sequence of self-framed messages, with failures expressed *inside* the stream while
//! the status line already says `200`. Adding that shape changes `Resp`, `EncodedResponse` and
//! the facade's response type at once, which is a contract decision this family is not entitled
//! to take alone; the task issue says so in as many words.
//!
//! What this family does deliver towards it is the framing itself:
//! [`shared::event_stream`](super::shared::event_stream) encodes a `Records` / `Stats` /
//! `Progress` / `Cont` / `End` / exception message byte for byte, both CRC-32s included, and is
//! exported through the facade. So the piece that a hand-rolled implementation gets subtly
//! wrong — a CRC over the wrong range produces a stream every SDK rejects and no unit test of
//! the producer's own notices — is written once and proved against an independent decoder. The
//! piece that is missing is the plumbing that would put those bytes on a socket, and until it
//! exists no request to this operation returns a stream. That is recorded in the overlay
//! (`q-select-0009`), here, and in `crates/core/MAP.md`.
//!
//! # Why the row exists before a backend does
//!
//! Same as [`RestoreObject`](super::restore_object)'s: `POST /{Bucket}/{Key+}` was known to the
//! table only as the multipart band, so `POST /b/k?select&select-type=2` matched nothing. The
//! row lands at 580 and pins **both** query predicates, because `select-type` is the version of
//! the request grammar and not decoration — a row that pinned only `?select` would hand a
//! version this decoder has never validated to the version-2 operation.

use rustfs_gateway_sig::{OperationFloor, SigService};
use rustfs_gateway_types::dto::{SelectObjectContent, SelectObjectContentInput, SelectObjectContentOutput};

use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// Nothing on the request head: `select` and `select-type=2` are routing discriminators, and
/// every other member of the request is in the body, where the decoder refuses a missing
/// required element with `MalformedXML`. The success status is the `200` the head carries before
/// the first frame exists — see the module note on why no frame follows it yet.
static SPEC: OperationSpec = OperationSpec {
    name: "SelectObjectContent",
    success_status: 200,
    required_params: &[],
    not_configured_error: None,
    auth: Some(AuthRequirement::new("s3:GetObject", ResourceShape::Object)),
};

/// Header signatures only, and not privileged.
static FLOOR: OperationFloor = OperationFloor::builtin("SelectObjectContent", SigService::S3);

impl Operation for SelectObjectContent {
    const NAME: &'static str = "SelectObjectContent";
    const ORIGIN: OperationOrigin = OperationOrigin::Standard(StandardOperation::TOKEN);

    type Input = SelectObjectContentInput;
    type Output = SelectObjectContentOutput;
    type DerivedResources = crate::authz::NoDerived;

    fn derive_resources(_input: &Self::Input) -> Result<Self::DerivedResources, crate::authz::DerivedResourceError> {
        Ok(crate::authz::NoDerived)
    }

    fn seal_derived_input(_input: &mut Self::Input) {}

    fn spec() -> &'static OperationSpec {
        &SPEC
    }

    fn floor() -> &'static OperationFloor {
        &FLOOR
    }
}

impl HasOperation for SelectObjectContentInput {
    type Op = SelectObjectContent;
}
