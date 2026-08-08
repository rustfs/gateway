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

//! The pieces of lowering that do not need the whole context.
//!
//! Responsible for: parsing a Smithy `http` uri, the derived defaults (payload discipline,
//! empty-value policy, XML root, checksum algorithms, error codes), and the `validate` pass that
//! rejects an IR the frozen schema would reject.
//! NOT responsible for: walking shapes or resolving types — that needs the model, the overlay and
//! the route at once, and lives in [`super`].
//! Upstream: [`super`]. Downstream: nothing; every item here is crate-internal.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::ir::*;
use crate::json::Value;
use crate::overlay::{FieldOverlay, OpOverlay, PayloadOverlay};
use crate::smithy::{Model, local_name, target_of, trait_of};

use super::IGNORED_QUERY_KEYS;

/// A parsed Smithy `http` uri: the path shape, its labels, and the literal query it pins.
pub(super) struct Uri {
    segments: Vec<String>,
    /// Labels declared greedy by `{Name+}`; a greedy label swallows slashes.
    pub(super) greedy_labels: Vec<String>,
    label_count: usize,
    /// The literal query this uri pins, `key` to `Some(value)` or `None` for a bare key.
    pub(super) query: Vec<(String, Option<String>)>,
}

impl Uri {
    pub(super) fn parse(uri: &str) -> Self {
        let (path, query) = match uri.split_once('?') {
            Some((p, q)) => (p, q),
            None => (uri, ""),
        };
        let mut segments = Vec::new();
        let mut greedy_labels = Vec::new();
        let mut label_count = 0;
        for segment in path.split('/').filter(|s| !s.is_empty()) {
            if let Some(inner) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                label_count += 1;
                if let Some(name) = inner.strip_suffix('+') {
                    greedy_labels.push(name.to_owned());
                    segments.push(format!("{{{name}+}}"));
                } else {
                    segments.push(format!("{{{inner}}}"));
                }
            } else {
                segments.push(segment.to_owned());
            }
        }
        let mut pairs = Vec::new();
        for item in query.split('&').filter(|s| !s.is_empty()) {
            let (key, value) = match item.split_once('=') {
                Some((k, v)) => (k.to_owned(), Some(v.to_owned())),
                None => (item.to_owned(), None),
            };
            if IGNORED_QUERY_KEYS.contains(&key.as_str()) {
                continue;
            }
            pairs.push((key, value));
        }
        Uri {
            segments,
            greedy_labels,
            label_count,
            query: pairs,
        }
    }

    pub(super) fn target(&self) -> TargetKind {
        match self.label_count {
            0 => TargetKind::Service,
            1 => TargetKind::Bucket,
            _ => TargetKind::Object,
        }
    }

    pub(super) fn path_shape(&self) -> String {
        if self.segments.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", self.segments.join("/"))
        }
    }
}

pub(super) fn parse_binding(text: &str, greedy: bool) -> Option<Binding> {
    Some(match text {
        "Header" => Binding::Header,
        "Query" => Binding::Query,
        "UriLabel" => Binding::UriLabel { greedy },
        "PrefixHeaders" => Binding::PrefixHeaders,
        "Payload" => Binding::Payload,
        "BodyXml" => Binding::BodyXml,
        "StatusCode" => Binding::StatusCode,
        "FormField" => Binding::FormField,
        _ => return None,
    })
}

pub(super) fn default_of(ov: &FieldOverlay) -> Option<Value> {
    if let Some(s) = &ov.default_string {
        return Some(Value::Str(s.clone()));
    }
    if let Some(i) = ov.default_int {
        return Some(Value::Int(i));
    }
    ov.default_bool.map(Value::Bool)
}

pub(super) fn omit_when_of(ov: &FieldOverlay) -> Result<Option<OmitWhen>> {
    let Some(kind) = ov.omit_when.as_deref() else {
        return Ok(None);
    };
    Ok(Some(match kind {
        "Empty" => OmitWhen::Empty,
        "Default" => OmitWhen::Default,
        "ValueEquals" => OmitWhen::ValueEquals(
            ov.omit_when_value
                .clone()
                .ok_or_else(|| Error::Overlay(format!("field `{}`: ValueEquals needs omit_when_value", ov.name)))?,
        ),
        "RequestField" => OmitWhen::RequestField {
            field: ov
                .omit_when_field
                .clone()
                .ok_or_else(|| Error::Overlay(format!("field `{}`: RequestField needs omit_when_field", ov.name)))?,
            equals: ov
                .omit_when_equals
                .clone()
                .ok_or_else(|| Error::Overlay(format!("field `{}`: RequestField needs omit_when_equals", ov.name)))?,
        },
        other => return Err(Error::Overlay(format!("field `{}`: unknown omit_when `{other}`", ov.name))),
    }))
}

pub(super) fn body_members(fields: &[Field]) -> Vec<String> {
    fields
        .iter()
        .filter(|f| f.binding == Binding::BodyXml)
        .map(|f| f.name.clone())
        .collect()
}

/// A required member is always written, even when empty; an optional one is dropped. The overlay
/// overrides individual members, which is what `q-empty-*` quirks are for.
pub(super) fn empty_value_policy(fields: &[Field], overrides: &[(String, EmptyValue)]) -> Vec<(String, EmptyValue)> {
    let mut out: Vec<(String, EmptyValue)> = fields
        .iter()
        .filter(|f| f.binding == Binding::BodyXml)
        .map(|f| {
            let policy = overrides
                .iter()
                .find(|(name, _)| *name == f.name)
                .map(|(_, p)| *p)
                .unwrap_or(if f.required { EmptyValue::Emit } else { EmptyValue::Omit });
            (f.name.clone(), policy)
        })
        .collect();
    for (name, policy) in overrides {
        if !out.iter().any(|(n, _)| n == name) {
            out.push((name.clone(), *policy));
        }
    }
    out
}

pub(super) fn xml_root(model: &Model, shape_id: Option<&str>, fields: &[Field]) -> Option<String> {
    if !fields.iter().any(|f| f.binding == Binding::BodyXml) {
        return None;
    }
    let id = shape_id?;
    let shape = model.shape(id)?;
    Some(
        trait_of(shape, "smithy.api#xmlName")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| local_name(id).to_owned()),
    )
}

pub(super) fn payload_spec(fields: &[Field], ov: &PayloadOverlay, operation: &str) -> Result<PayloadSpec> {
    let streaming = fields
        .iter()
        .any(|f| f.binding == Binding::Payload && matches!(f.ty, Type::Blob { streaming: true }));
    let has_payload = fields.iter().any(|f| f.binding == Binding::Payload);
    let has_body_xml = fields.iter().any(|f| f.binding == Binding::BodyXml);
    let (kind, buffering) = if streaming {
        (PayloadKind::StreamingBlob, Buffering::Streaming)
    } else if has_payload || has_body_xml {
        (PayloadKind::XmlBody, Buffering::Full)
    } else {
        (PayloadKind::None, Buffering::None)
    };
    let kind = match &ov.kind {
        Some(k) => PayloadKind::parse(k).ok_or_else(|| Error::ir(operation, format!("unknown payload kind `{k}`")))?,
        None => kind,
    };
    let buffering = match &ov.buffering {
        Some(b) => Buffering::parse(b).ok_or_else(|| Error::ir(operation, format!("unknown buffering `{b}`")))?,
        None => buffering,
    };
    Ok(PayloadSpec {
        kind,
        buffering,
        max_bytes: ov.max_bytes,
    })
}

/// The request checksum algorithms an operation accepts, read off `aws.protocols#httpChecksum`.
///
/// The model's algorithm enum is wider than the IR's closed set (it already carries SHA512, MD5
/// and three XXHASH variants), so anything the IR cannot name is filtered out here rather than
/// failing the run — the IR's five are a deliberate subset, and widening it is an IR-FREEZE
/// decision, not a codegen one.
pub(super) fn model_request_algorithms(model: &Model, op: &Value) -> Vec<ChecksumAlgo> {
    let Some(trait_value) = trait_of(op, "aws.protocols#httpChecksum") else {
        return Vec::new();
    };
    let Some(member_name) = trait_value.get("requestAlgorithmMember").and_then(Value::as_str) else {
        return Vec::new();
    };
    let Some(input_id) = op.get("input").and_then(target_of) else {
        return Vec::new();
    };
    let Some(input) = model.shape(input_id) else {
        return Vec::new();
    };
    let Some((_, member)) = model.members(input).into_iter().find(|(n, _)| *n == member_name) else {
        return Vec::new();
    };
    let Some(target) = target_of(member) else {
        return Vec::new();
    };
    let mut algorithms: Vec<ChecksumAlgo> = model
        .enum_values(target)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| ChecksumAlgo::parse(v))
        .collect();
    algorithms.sort();
    algorithms.dedup();
    algorithms
}

/// Overlay order first, then any modelled error the overlay forgot, so a model bump that adds an
/// error shape shows up in the diff instead of disappearing.
pub(super) fn error_codes(op: &Value, ov: &OpOverlay) -> Vec<String> {
    let mut codes = ov.error_codes.clone();
    let mut extra: Vec<String> = op
        .get("errors")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|e| e.get("target").and_then(Value::as_str))
                .map(|t| local_name(t).to_owned())
                .filter(|code| !codes.contains(code))
                .collect()
        })
        .unwrap_or_default();
    extra.sort();
    extra.dedup();
    codes.extend(extra);
    codes
}

/// The schema rules that are cheap to check here and expensive to debug later.
pub(super) fn validate(ir: &OperationIr) -> Result<()> {
    let op = &ir.operation;
    if ir.auth.requirement == AuthRequirement::Privileged && ir.auth.presigned_allowed {
        return Err(Error::ir(op, "a privileged operation must not be reachable through a presigned URL"));
    }
    if ir.xml.unwrapped_output && !ir.xml.element_order.is_empty() {
        return Err(Error::ir(op, "an unwrapped output has no sibling order to fix"));
    }
    for field in ir.input.iter().chain(ir.output.iter()) {
        let needs_name = !matches!(field.binding, Binding::Payload | Binding::StatusCode);
        if needs_name && field.wire_name.as_deref().unwrap_or("").is_empty() {
            return Err(Error::ir(op, format!("field `{}` has no wire name", field.name)));
        }
        if !needs_name && field.wire_name.is_some() {
            return Err(Error::ir(op, format!("field `{}` must not have a wire name", field.name)));
        }
        if field.missing_error.is_some() && !field.required {
            return Err(Error::ir(op, format!("field `{}` is optional but declares a missing_error", field.name)));
        }
    }
    let referenced = ir.referenced_quirk_ids();
    let resolved: Vec<String> = ir.quirks.iter().map(|q| q.id.clone()).collect();
    if referenced != resolved {
        return Err(Error::ir(op, "the resolved quirk set does not equal the referenced quirk ids"));
    }
    if !ir.xml.unwrapped_output {
        let body: BTreeSet<String> = body_members(&ir.output).into_iter().collect();
        let ordered: BTreeSet<String> = ir.xml.element_order.iter().cloned().collect();
        if body != ordered {
            let missing: Vec<&String> = body.difference(&ordered).collect();
            let extra: Vec<&String> = ordered.difference(&body).collect();
            return Err(Error::ir(
                op,
                format!("element_order must cover exactly the body members (missing {missing:?}, unknown {extra:?})"),
            ));
        }
    }
    for shape_name in ir.shapes.keys() {
        let shape = &ir.shapes[shape_name];
        // A member the shape carries as an XML attribute is not one of its child elements, so it
        // is not in the element order and must not be demanded of it.
        let carried: BTreeSet<&str> = shape
            .xml
            .attributes
            .iter()
            .filter_map(|attribute| match &attribute.source {
                crate::ir::AttributeSource::Field(member) => Some(member.as_str()),
                crate::ir::AttributeSource::Constant(_) => None,
            })
            .collect();
        let body: BTreeSet<String> = body_members(&shape.fields)
            .into_iter()
            .filter(|member| !carried.contains(member.as_str()))
            .collect();
        let ordered: BTreeSet<String> = shape.xml.element_order.iter().cloned().collect();
        if body != ordered {
            return Err(Error::ir(
                op,
                format!("shape `{shape_name}`: element_order must cover exactly its body members"),
            ));
        }
    }
    Ok(())
}
