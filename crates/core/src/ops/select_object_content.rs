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
//! # Request decoding and the event-stream answer
//!
//! The request half is complete: expression, expression type, all three input serializations
//! with their sub-members, both output serializations, the progress switch and the scan range
//! reach a handler decoded and validated. The handler returns the third [`crate::Answer`] shape,
//! [`crate::Resp::event_stream`]: a status line sent before the first record exists, then a
//! sequence of self-framed messages, with failures expressed *inside* the stream while the status
//! line remains `200`. The facade preserves that shape through type erasure and writes it through
//! the same service exit as an ordinary response, without invoking the generated empty-output
//! encoder.
//!
//! [`shared::event_stream`](super::shared::event_stream) encodes a `Records` / `Stats` /
//! `Progress` / `Cont` / `End` / exception message byte for byte, both CRC-32s included, and is
//! exported through the facade. The conformance target parses those frames independently. So the
//! piece that a hand-rolled implementation gets subtly
//! wrong — a CRC over the wrong range produces a stream every SDK rejects and no unit test of
//! the producer's own notices — is written once and proved against an independent decoder
//! (`q-select-0009`).
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

use crate::contracts::{SELECT_EVENT_STATUS, SelectEventStatusPolicy};
use crate::op::{AuthRequirement, HasOperation, Operation, OperationOrigin, ResourceShape, StandardOperation};
use crate::registry::OperationSpec;

/// What this operation requires of a request once routing has chosen it.
///
/// Nothing on the request head: `select` and `select-type=2` are routing discriminators, and
/// every other member of the request is in the body, where the decoder refuses a missing
/// required element with `MalformedXML`. The success status is the `200` the head carries before
/// the first frame exists — see the module note on why no frame follows it yet.
static SPEC: OperationSpec = OperationSpec::standard("SelectObjectContent")
    .required_params(&[])
    .auth(AuthRequirement::new("s3:GetObject", ResourceShape::Object))
    .build();

/// The event-stream status policy and the lowered IR name the same head status.
///
/// The status used to be written here as a `match` on [`SELECT_EVENT_STATUS`], which made this
/// file a second authority for a value `model/overlays/` already declares — the shape gateway#242
/// recorded. The contract switch still exists, because a deployment that moves to the deferred
/// `202` posture has to move both; this assertion is what makes "both" enforced rather than
/// remembered, and it fails the build at this line rather than serving a status no case expects.
const _: () = {
    let expected = match SELECT_EVENT_STATUS {
        SelectEventStatusPolicy::Success200 => 200,
        SelectEventStatusPolicy::Success202 => 202,
    };
    match crate::route::row_of("SelectObjectContent") {
        Some(row) => assert!(
            row.success_status == expected,
            "SELECT_EVENT_STATUS and the generated success status for SelectObjectContent disagree"
        ),
        None => panic!("SelectObjectContent has no row in the generated route table"),
    }
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
