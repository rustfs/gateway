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

//! Generated live Select payloads and rejected unsupported streaming unions.
//!
//! Responsible for: output carrier and codec contracts, and fail-closed stream admission.
//! NOT responsible for: frame bytes or producer polling, which the core runtime tests cover.
//! Upstream: operation payload metadata. Downstream: generated types and response codecs.

#![allow(clippy::expect_used, clippy::panic)]

use rustfs_gateway_model::ir::{Binding, Buffering, Field, OperationIr, PayloadKind, Shape, ShapeKind, ShapeXml, Type};

use super::codegen_tests::{artifacts, body};
use crate::emit::dto::registry::Registry;

#[test]
fn select_output_keeps_its_live_payload_without_a_document_writer() {
    let generated = artifacts();
    let dto = body(&generated, "generated/dto/ops/select_object_content.rs");
    let codec = body(&generated, "generated/codec/ops/select_object_content.rs");
    assert_eq!(
        [
            dto.contains("pub payload: Option<crate::SelectEventStream>"),
            dto.contains("#[derive(Debug, Default)]\npub struct Output"),
            codec.contains("ResponseBody::Stream("),
            codec.contains("fn write_select_object_content_event_stream("),
            codec.contains("fn write_records_event("),
            codec.contains("set_header(\"content-type\""),
        ],
        [true, true, true, false, false, false],
        "Select must own one lazy payload; its event shapes are not a settled XML document"
    );
}

fn stream_ir() -> OperationIr {
    let mut ir = artifacts()
        .operations
        .into_iter()
        .find(|ir| ir.operation == "SelectObjectContent")
        .expect("Select is included");
    ir.output = vec![Field {
        name: "Payload".to_owned(),
        wire_name: None,
        required: false,
        binding: Binding::Payload,
        ty: Type::Union("SelectObjectContentEventStream".to_owned()),
        hot: false,
        default: None,
        omit_when: None,
        missing_error: None,
        quirk_refs: Vec::new(),
    }];
    ir.shapes.insert(
        "SelectObjectContentEventStream".to_owned(),
        Shape {
            kind: ShapeKind::Union,
            fields: Vec::new(),
            xml: ShapeXml {
                element_order: Vec::new(),
                empty_value_policy: Vec::new(),
                attributes: Vec::new(),
            },
        },
    );
    ir.payload.response.kind = PayloadKind::EventStream;
    ir.payload.response.buffering = Buffering::Streaming;
    ir
}

#[test]
fn unsupported_stream_contracts_fail_before_emitting_a_carrier() {
    let valid = stream_ir();
    let mut wrong_operation = valid.clone();
    wrong_operation.operation = "FutureStreamOperation".to_owned();
    let mut wrong_union = valid.clone();
    wrong_union.output[0].ty = Type::Union("FutureEventStream".to_owned());
    wrong_union
        .shapes
        .insert("FutureEventStream".to_owned(), valid.shapes["SelectObjectContentEventStream"].clone());
    let mut required = valid.clone();
    required.output[0].required = true;
    let mut unbound = valid.clone();
    unbound.output[0].binding = Binding::BodyXml;
    let mut inbound = valid.clone();
    inbound.input = inbound.output.clone();
    inbound.payload.request = inbound.payload.response.clone();
    for (name, ir, accepted) in [
        ("select", valid, true),
        ("other operation", wrong_operation, false),
        ("other union", wrong_union, false),
        ("required stream", required, false),
        ("unbound stream", unbound, false),
        ("inbound stream", inbound, false),
    ] {
        assert_eq!(Registry::collect(&[&ir]).is_ok(), accepted, "{name}");
    }
}
