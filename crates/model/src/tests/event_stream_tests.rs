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

//! Streaming-union payload inference in both directions.
//!
//! Responsible for: distinguishing event streams from settled unions and streaming blobs,
//! keeping non-payload fields outside that inference, and preserving explicit overlay choices.
//! NOT responsible for: event DTOs, frame encoding or legacy stream conversion.
//! Upstream: model lowering. Downstream: the model regression suite.
//! Evidence: <https://smithy.io/2.0/spec/streaming.html#streaming-trait>.

use super::lower_tests::overlay_from;
use crate::ir::{Buffering, PayloadKind, PayloadSpec};
use crate::lower::lower;
use crate::smithy::Model;

const MODEL: &str = r#"{
  "smithy": "2.0",
  "shapes": {
    "ns#Svc": { "type": "service", "version": "2006-03-01", "operations": [{"target": "ns#ReadEvents"}] },
    "ns#ReadEvents": {
      "type": "operation",
      "input": { "target": "ns#ReadEventsRequest" },
      "output": { "target": "ns#ReadEventsOutput" },
      "traits": { "smithy.api#http": { "method": "POST", "uri": "/{Bucket}?events", "code": 200 } }
    },
    "ns#ReadEventsRequest": {
      "type": "structure",
      "members": {
        "Bucket": { "target": "ns#BucketName", "traits": { "smithy.api#httpLabel": {}, "smithy.api#required": {} } },
        "Payload": { "target": "ns#Events", "traits": MEMBER_TRAITS }
      }
    },
    "ns#ReadEventsOutput": {
      "type": "structure",
      "members": { "Payload": { "target": "ns#Events", "traits": MEMBER_TRAITS } }
    },
    "ns#Events": PAYLOAD_SHAPE,
    "ns#Record": { "type": "structure", "members": { "Text": { "target": "ns#Str" } } },
    "ns#BucketName": { "type": "string" },
    "ns#Str": { "type": "string" }
  }
}"#;

const OVERLAY: &str = r#"
include = ["ReadEvents"]
[op.ReadEvents]
precedence = 100
auth_action = "s3:ReadEvents"
"#;

const STREAMING_UNION: &str =
    r#"{"type":"union","traits":{"smithy.api#streaming":{}},"members":{"Record":{"target":"ns#Record"}}}"#;

#[test]
fn payload_bound_streaming_unions_keep_their_event_contract() {
    let union = STREAMING_UNION;
    let plain_union = union.replace("\"traits\":{\"smithy.api#streaming\":{}},", "");
    let unrelated_trait = union.replace("smithy.api#streaming", "smithy.api#sensitive");
    let blob = r#"{"type":"blob","traits":{"smithy.api#streaming":{}}}"#;
    let payload = r#"{"smithy.api#httpPayload":{}}"#;
    let overridden = r#"
request_kind = "Literal"
request_buffering = "Full"
request_max_bytes = 7
response_kind = "Literal"
response_buffering = "Full"
response_max_bytes = 7
"#;
    for (name, shape, member_traits, extra_overlay, kind, buffering, max_bytes) in [
        (
            "streaming union",
            union,
            payload,
            "",
            PayloadKind::EventStream,
            Buffering::Streaming,
            None,
        ),
        (
            "streaming blob",
            blob,
            r#"{"smithy.api#httpPayload":{},"smithy.api#required":{}}"#,
            "",
            PayloadKind::StreamingBlob,
            Buffering::Streaming,
            None,
        ),
        (
            "ordinary union",
            plain_union.as_str(),
            payload,
            "",
            PayloadKind::XmlBody,
            Buffering::Full,
            None,
        ),
        (
            "unrelated trait",
            unrelated_trait.as_str(),
            payload,
            "",
            PayloadKind::XmlBody,
            Buffering::Full,
            None,
        ),
        (
            "non-payload ordinary union",
            plain_union.as_str(),
            "{}",
            "",
            PayloadKind::XmlBody,
            Buffering::Full,
            None,
        ),
        (
            "dropped payload",
            union,
            payload,
            "input_drop = [\"Payload\"]\noutput_drop = [\"Payload\"]\n",
            PayloadKind::None,
            Buffering::None,
            None,
        ),
        (
            "explicit overlay",
            union,
            payload,
            overridden,
            PayloadKind::Literal,
            Buffering::Full,
            Some(7),
        ),
    ] {
        let model = Model::from_json(&MODEL.replace("PAYLOAD_SHAPE", shape).replace("MEMBER_TRAITS", member_traits)).expect(name);
        let overlay = overlay_from(&format!("{OVERLAY}{extra_overlay}")).expect(name);
        let lowered = lower(&model, &overlay).expect(name);
        let actual = &lowered.operations[0].payload;
        let expected = PayloadSpec {
            kind,
            buffering,
            max_bytes,
        };
        assert_eq!((&actual.request, &actual.response), (&expected, &expected), "{name}");
    }
}

#[test]
fn streaming_unions_refuse_missing_or_shared_http_payload_bindings() {
    for (name, member_traits, extra_member, expected) in [
        ("unbound event stream", "{}", "", "streaming union must use httpPayload"),
        (
            "header event stream",
            r#"{"smithy.api#httpHeader":"x-events"}"#,
            "",
            "streaming union must use httpPayload",
        ),
        (
            "two payload members",
            r#"{"smithy.api#httpPayload":{}}"#,
            r#""Other":{"target":"ns#Str","traits":{"smithy.api#httpPayload":{}}},"#,
            "event stream must be the only payload member",
        ),
    ] {
        let text = MODEL
            .replace("PAYLOAD_SHAPE", STREAMING_UNION)
            .replace("MEMBER_TRAITS", member_traits)
            .replace("\"Payload\":", &format!("{extra_member}\"Payload\":"));
        let model = Model::from_json(&text).expect(name);
        for dropped in ["input_drop", "output_drop"] {
            let overlay = overlay_from(&format!("{OVERLAY}{dropped} = [\"Payload\"]\n")).expect(name);
            let error = lower(&model, &overlay).err().map(|error| error.to_string());
            assert!(
                error.as_ref().is_some_and(|error| error.contains(expected)),
                "{name}: {error:?} ({dropped})"
            );
        }
    }
}
