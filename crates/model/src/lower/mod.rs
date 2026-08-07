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

//! Model plus overlay into IR.
//!
//! Responsible for: every derivation rule that turns a Smithy operation into an [`OperationIr`],
//! and for failing loudly wherever the model cannot answer the question.
//! NOT responsible for: rendering anything (that is `rustfs-gateway-codegen`).
//! Upstream: [`crate::smithy`], [`crate::overlay`]. Downstream: `rustfs-gateway-codegen`.
//!
//! The split of authority is fixed: **structure** comes from the model (bindings, wire names,
//! enum values, list flattening), **decisions** come from the overlay (route precedence, IAM
//! action, hot/cold, body caps, element order, error codes). Where the model has no opinion and
//! the overlay is silent, lowering stops rather than guessing.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Error, Result};
use crate::ir::*;
use crate::json::Value;
use crate::overlay::{FieldOverlay, OpOverlay, Overlay, ShapeOverlay, Side};
use crate::smithy::{Model, has_trait, local_name, target_of, trait_of};

mod support;

use support::{
    Uri, body_members, default_of, empty_value_policy, error_codes, model_request_algorithms, omit_when_of, parse_binding,
    payload_spec, validate, xml_root,
};

/// Query keys that exist only to disambiguate AWS SDK client caches and never take part in
/// server-side routing. `x-id` is written by the SDKs on every request.
const IGNORED_QUERY_KEYS: &[&str] = &["x-id"];

/// Smithy's marker for "this operation has no input/output structure". It is a prelude shape the
/// service model never declares, so it is read as the absence of a shape rather than looked up.
const UNIT_SHAPE: &str = "smithy.api#Unit";

/// The result of one codegen run's lowering phase.
#[derive(Debug)]
pub struct Lowered {
    /// One IR per included operation, ordered by operation name.
    pub operations: Vec<OperationIr>,
    /// Operations deliberately not generated, with their reason.
    pub deferred: BTreeMap<String, String>,
}

/// Lowers every whitelisted operation.
///
/// Fails when the model carries an operation that is neither included nor deferred: an upstream
/// addition is a protocol event that needs a human decision, not a silent omission.
pub fn lower(model: &Model, overlay: &Overlay) -> Result<Lowered> {
    let model_ops: BTreeSet<String> = model.operation_names().into_iter().collect();

    for name in &overlay.include {
        if !model_ops.contains(name) {
            return Err(Error::Overlay(format!("included operation `{name}` is not in the model")));
        }
    }
    for name in overlay.deferred.keys() {
        if !model_ops.contains(name) {
            return Err(Error::Overlay(format!("deferred operation `{name}` is not in the model")));
        }
    }
    let undecided: Vec<&String> = model_ops
        .iter()
        .filter(|n| !overlay.include.contains(n) && !overlay.deferred.contains_key(*n))
        .collect();
    if !undecided.is_empty() {
        return Err(Error::Overlay(format!(
            "{} operation(s) are in the model but neither included nor deferred: {}. \
             Add each to `include` or to a [[deferred]] group with a reason.",
            undecided.len(),
            undecided.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }

    let mut names: Vec<String> = overlay.include.clone();
    names.sort();
    names.dedup();
    let mut operations = Vec::with_capacity(names.len());
    for name in &names {
        operations.push(lower_one(model, overlay, name)?);
    }
    Ok(Lowered {
        operations,
        deferred: overlay.deferred.clone(),
    })
}

fn lower_one(model: &Model, overlay: &Overlay, name: &str) -> Result<OperationIr> {
    let empty = OpOverlay::default();
    let op = model
        .shape_local(name)
        .ok_or_else(|| Error::Model(format!("no operation shape `{name}`")))?;
    let ov = overlay.ops.get(name).unwrap_or(&empty);

    let http_trait =
        trait_of(op, "smithy.api#http").ok_or_else(|| Error::ir(name, "the operation carries no smithy.api#http trait"))?;
    let method_text = http_trait
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::ir(name, "smithy.api#http has no method"))?;
    let method = Method::parse(method_text).ok_or_else(|| Error::ir(name, format!("unknown method `{method_text}`")))?;
    let uri = http_trait
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::ir(name, "smithy.api#http has no uri"))?;
    let route = Uri::parse(uri);

    let target = match &ov.target {
        Some(t) => TargetKind::parse(t).ok_or_else(|| Error::ir(name, format!("unknown target `{t}`")))?,
        None => route.target(),
    };

    let mut predicates = vec![Predicate::Method(method), Predicate::Target(target)];
    for (key, value) in &route.query {
        match value {
            Some(v) => predicates.push(Predicate::QueryEquals(key.clone(), v.clone())),
            None => predicates.push(Predicate::QueryPresent(key.clone())),
        }
    }
    for key in &ov.query_present {
        if route.query.iter().any(|(existing, _)| existing == key) {
            return Err(Error::ir(
                name,
                format!("`query_present` repeats `{key}`, which the model's uri already pins"),
            ));
        }
        predicates.push(Predicate::QueryPresent(key.clone()));
    }
    for key in &ov.query_absent {
        predicates.push(Predicate::QueryAbsent(key.clone()));
    }
    for header in &ov.header_present {
        predicates.push(Predicate::HeaderPresent {
            header: header.clone(),
            negated: false,
        });
    }
    for header in &ov.header_absent {
        predicates.push(Predicate::HeaderPresent {
            header: header.clone(),
            negated: true,
        });
    }

    let success_status = ov.success_status.unwrap_or_else(|| {
        http_trait
            .get("code")
            .and_then(|c| match c {
                Value::Int(i) => u16::try_from(*i).ok(),
                _ => None,
            })
            .unwrap_or(200)
    });

    // `smithy.api#Unit` is Smithy's "no input/output at all" marker, not a shape the model
    // declares — DeleteBucketCors and DeleteBucketTagging are the included operations whose output
    // is spelled this way. Reading it as `None` gives such an operation an empty field list, which
    // is what the marker means, rather than an "unknown shape" failure.
    let input_shape = op
        .get("input")
        .and_then(target_of)
        .filter(|id| *id != UNIT_SHAPE)
        .map(str::to_owned);
    let output_shape = op
        .get("output")
        .and_then(target_of)
        .filter(|id| *id != UNIT_SHAPE)
        .map(str::to_owned);

    let mut ctx = Ctx {
        model,
        overlay,
        operation: name,
        route: &route,
        ov,
    };
    let input = ctx.fields(input_shape.as_deref(), Side::Input)?;
    let output = ctx.fields(output_shape.as_deref(), Side::Output)?;
    ctx.check_overlay_targets(input_shape.as_deref(), Side::Input)?;
    ctx.check_overlay_targets(output_shape.as_deref(), Side::Output)?;

    let mut shapes = BTreeMap::new();
    for field in input.iter().chain(output.iter()) {
        ctx.collect_shapes(&field.ty, &mut shapes)?;
    }

    let http = Http {
        method,
        target,
        precedence: ov
            .precedence
            .ok_or_else(|| Error::ir(name, "no route precedence; add `precedence` to the operation's overlay entry"))?,
        predicates,
        success_status,
        alt_success_statuses: ov.alt_success_statuses.clone(),
        path_shape: ov.path_shape.clone().unwrap_or_else(|| route.path_shape()),
    };

    let auth = Auth {
        requirement: match &ov.auth_requirement {
            Some(r) => AuthRequirement::parse(r).ok_or_else(|| Error::ir(name, format!("unknown auth requirement `{r}`")))?,
            None => AuthRequirement::Required,
        },
        action: ov
            .auth_action
            .clone()
            .ok_or_else(|| Error::ir(name, "no IAM action; an operation without one must not be registered"))?,
        presigned_allowed: ov.auth_presigned.unwrap_or(true),
        service: ov.auth_service.clone().unwrap_or_else(|| "s3".to_owned()),
    };

    let payload = Payload {
        request: payload_spec(&input, &ov.request, name)?,
        response: payload_spec(&output, &ov.response, name)?,
    };

    let checksum = Checksum {
        http_checksum_required: ov
            .http_checksum_required
            .unwrap_or_else(|| has_trait(op, "smithy.api#httpChecksumRequired")),
        request_algorithms: match &ov.request_algorithms {
            Some(list) => list.clone(),
            None => model_request_algorithms(model, op),
        },
        response_algorithms: ov.response_algorithms.clone().unwrap_or_default(),
    };

    let unwrapped = ov
        .unwrapped_output
        .unwrap_or_else(|| has_trait(op, "aws.customizations#s3UnwrappedXmlOutput"));
    let xml = Xml {
        request_root: ov
            .request_root
            .clone()
            .or_else(|| xml_root(model, input_shape.as_deref(), &input)),
        request_root_aliases: ov.request_root_aliases.clone(),
        response_root: ov
            .response_root
            .clone()
            .or_else(|| xml_root(model, output_shape.as_deref(), &output)),
        xmlns: match &ov.xmlns {
            Some(x) => Xmlns::parse(x).ok_or_else(|| Error::ir(name, format!("unknown xmlns policy `{x}`")))?,
            None => Xmlns::Emit,
        },
        unwrapped_output: unwrapped,
        element_order: if unwrapped {
            Vec::new()
        } else if ov.element_order.is_empty() {
            body_members(&output)
        } else {
            ov.element_order.clone()
        },
        empty_value_policy: empty_value_policy(&output, &ov.empty_value),
        url_encoded_fields: ov.url_encoded_fields.clone(),
        attributes: Vec::new(),
        body_literal: ov.body_literal.unwrap_or(false),
    };

    let errors = Errors {
        not_configured: ov.not_configured.clone(),
        allows_error_after_200: ov.allows_error_after_200.unwrap_or(false),
        codes: error_codes(op, ov),
    };

    let mut ir = OperationIr {
        operation: name.to_owned(),
        http,
        auth,
        payload,
        checksum,
        input,
        output,
        shapes,
        xml,
        errors,
        derived_resources: Vec::new(),
        head_mirrors: ov.head_mirrors.clone(),
        quirk_refs: sort_quirk_ids(ov.quirk_refs.clone()),
        quirks: Vec::new(),
        ext_points: Vec::new(),
    };

    for id in ir.referenced_quirk_ids() {
        let quirk = overlay
            .quirks
            .get(&id)
            .ok_or_else(|| Error::ir(name, format!("quirk `{id}` is referenced but not declared in the overlay")))?;
        ir.quirks.push(quirk.clone());
    }
    validate(&ir)?;
    Ok(ir)
}

struct Ctx<'a> {
    model: &'a Model,
    overlay: &'a Overlay,
    operation: &'a str,
    route: &'a Uri,
    ov: &'a OpOverlay,
}

impl Ctx<'_> {
    fn fields(&mut self, shape_id: Option<&str>, side: Side) -> Result<Vec<Field>> {
        let (drops, requireds, hots) = match side {
            Side::Input => (&self.ov.input_drop, &self.ov.input_required, &self.ov.input_hot),
            Side::Output => (&self.ov.output_drop, &self.ov.output_required, &self.ov.output_hot),
        };
        let mut fields = Vec::new();
        if let Some(id) = shape_id {
            let shape = self
                .model
                .shape(id)
                .ok_or_else(|| Error::ir(self.operation, format!("unknown shape `{id}`")))?;
            for (member_name, member) in self.model.members(shape) {
                if drops.iter().any(|d| d == member_name) {
                    continue;
                }
                let ov = self.field_overlay(side, member_name);
                let binding = self.binding_of(member, member_name, ov.and_then(|o| o.binding.as_deref()))?;
                let required = ov
                    .and_then(|o| o.required)
                    .unwrap_or_else(|| has_trait(member, "smithy.api#required") || requireds.iter().any(|r| r == member_name));
                let hot = ov.and_then(|o| o.hot).unwrap_or_else(|| {
                    matches!(binding, Binding::UriLabel { .. } | Binding::Payload) || hots.iter().any(|h| h == member_name)
                });
                let target = target_of(member)
                    .ok_or_else(|| Error::ir(self.operation, format!("member `{member_name}` has no target")))?;
                let ty = match ov.and_then(|o| o.ty.as_deref()) {
                    Some(spelling) => self.scalar(spelling, &binding)?,
                    None => self.type_of(target, member, &binding)?,
                };
                fields.push(Field {
                    name: member_name.to_owned(),
                    wire_name: self.wire_name(member, member_name, &binding, ov),
                    required,
                    binding,
                    ty,
                    hot,
                    default: ov.and_then(default_of),
                    omit_when: ov.map(omit_when_of).transpose()?.flatten(),
                    missing_error: ov.and_then(|o| o.missing_error.clone()).filter(|_| required),
                    quirk_refs: sort_quirk_ids(ov.map(|o| o.quirks.clone()).unwrap_or_default()),
                });
            }
        }
        self.synthesize(&mut fields, side)?;
        Ok(fields)
    }

    /// Inserts overlay fields that have no model member behind them, at the declared position.
    fn synthesize(&self, fields: &mut Vec<Field>, side: Side) -> Result<()> {
        for ov in self.ov.fields.iter().filter(|f| f.synthesize && f.side == side) {
            let binding_text = ov
                .binding
                .as_deref()
                .ok_or_else(|| Error::ir(self.operation, format!("synthesized field `{}` needs a binding", ov.name)))?;
            let binding = parse_binding(binding_text, false)
                .ok_or_else(|| Error::ir(self.operation, format!("unknown binding `{binding_text}`")))?;
            let spelling = ov
                .ty
                .as_deref()
                .ok_or_else(|| Error::ir(self.operation, format!("synthesized field `{}` needs a type", ov.name)))?;
            let field = Field {
                name: ov.name.clone(),
                wire_name: ov.wire_name.clone(),
                required: ov.required.unwrap_or(false),
                ty: self.scalar(spelling, &binding)?,
                binding,
                hot: ov.hot.unwrap_or(false),
                default: default_of(ov),
                omit_when: omit_when_of(ov)?,
                missing_error: ov.missing_error.clone(),
                quirk_refs: sort_quirk_ids(ov.quirks.clone()),
            };
            match &ov.after {
                Some(after) => {
                    let at = fields
                        .iter()
                        .position(|f| f.name == *after)
                        .ok_or_else(|| Error::ir(self.operation, format!("`after = \"{after}\"` names no field")))?;
                    fields.insert(at + 1, field);
                }
                None => fields.push(field),
            }
        }
        Ok(())
    }

    /// Fails when an overlay entry names a member the model does not have.
    ///
    /// Without this a typo in `model/overlays/operations.toml` is silently ignored, and the quirk or the
    /// requirement it was carrying quietly stops applying — the worst possible failure mode for
    /// the one hand-written file in the pipeline.
    fn check_overlay_targets(&self, shape_id: Option<&str>, side: Side) -> Result<()> {
        let members: BTreeSet<String> = match shape_id.and_then(|id| self.model.shape(id)) {
            Some(shape) => self.model.members(shape).into_iter().map(|(n, _)| n.to_owned()).collect(),
            None => BTreeSet::new(),
        };
        let (drops, requireds, hots) = match side {
            Side::Input => (&self.ov.input_drop, &self.ov.input_required, &self.ov.input_hot),
            Side::Output => (&self.ov.output_drop, &self.ov.output_required, &self.ov.output_hot),
        };
        let label = match side {
            Side::Input => "input",
            Side::Output => "output",
        };
        for (list, key) in [(drops, "drop"), (requireds, "required"), (hots, "hot")] {
            for name in list {
                if !members.contains(name) {
                    return Err(Error::ir(
                        self.operation,
                        format!("`{label}_{key}` names `{name}`, which is not a member of the {label} shape"),
                    ));
                }
            }
        }
        for field in self.ov.fields.iter().filter(|f| f.side == side && !f.synthesize) {
            if !members.contains(&field.name) {
                return Err(Error::ir(
                    self.operation,
                    format!("field overlay targets `{}`, which is not a member of the {label} shape", field.name),
                ));
            }
            if drops.contains(&field.name) {
                return Err(Error::ir(
                    self.operation,
                    format!("field overlay targets `{}`, which is also dropped", field.name),
                ));
            }
        }
        Ok(())
    }

    fn field_overlay(&self, side: Side, name: &str) -> Option<&FieldOverlay> {
        self.ov
            .fields
            .iter()
            .find(|f| f.side == side && f.name == name && !f.synthesize)
    }

    fn binding_of(&self, member: &Value, name: &str, forced: Option<&str>) -> Result<Binding> {
        if let Some(text) = forced {
            let greedy = self.route.greedy_labels.contains(&name.to_owned());
            return parse_binding(text, greedy).ok_or_else(|| Error::ir(self.operation, format!("unknown binding `{text}`")));
        }
        if has_trait(member, "smithy.api#httpLabel") {
            return Ok(Binding::UriLabel {
                greedy: self.route.greedy_labels.contains(&name.to_owned()),
            });
        }
        if has_trait(member, "smithy.api#httpQuery") {
            return Ok(Binding::Query);
        }
        if has_trait(member, "smithy.api#httpHeader") {
            return Ok(Binding::Header);
        }
        if has_trait(member, "smithy.api#httpPrefixHeaders") {
            return Ok(Binding::PrefixHeaders);
        }
        if has_trait(member, "smithy.api#httpPayload") {
            return Ok(Binding::Payload);
        }
        if has_trait(member, "smithy.api#httpResponseCode") {
            return Ok(Binding::StatusCode);
        }
        Ok(Binding::BodyXml)
    }

    fn wire_name(&self, member: &Value, name: &str, binding: &Binding, ov: Option<&FieldOverlay>) -> Option<String> {
        if let Some(explicit) = ov.and_then(|o| o.wire_name.clone()) {
            return Some(explicit);
        }
        match binding {
            Binding::Payload | Binding::StatusCode => None,
            // Header names are case-insensitive on the wire and the model spells them in title
            // case. Lowercasing here is what makes the header reverse index in OPERATIONS.md a
            // set rather than a set of spellings.
            Binding::Header => trait_of(member, "smithy.api#httpHeader")
                .and_then(Value::as_str)
                .map(str::to_lowercase)
                .or_else(|| Some(name.to_lowercase())),
            Binding::PrefixHeaders => trait_of(member, "smithy.api#httpPrefixHeaders")
                .and_then(Value::as_str)
                .map(str::to_lowercase)
                .or_else(|| Some(name.to_lowercase())),
            Binding::Query => trait_of(member, "smithy.api#httpQuery")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| Some(name.to_owned())),
            Binding::UriLabel { .. } | Binding::BodyXml | Binding::FormField => trait_of(member, "smithy.api#xmlName")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| Some(name.to_owned())),
        }
    }

    fn type_of(&self, target: &str, member: &Value, binding: &Binding) -> Result<Type> {
        if let Some(spelling) = self.overlay.scalars.get(local_name(target)) {
            return self.scalar(spelling, binding);
        }
        let kind = self.model.kind_of(target);
        Ok(match kind {
            "string" => Type::String,
            "integer" => Type::Integer,
            "long" => Type::Long,
            "boolean" => Type::Boolean,
            "blob" => Type::Blob {
                streaming: self
                    .model
                    .shape(target)
                    .map(|s| has_trait(s, "smithy.api#streaming"))
                    .unwrap_or(false),
            },
            "timestamp" => Type::Timestamp(self.timestamp_format(target, member, binding)),
            "enum" => Type::StringEnum(self.model.enum_values(target).unwrap_or_default()),
            "structure" => Type::Structure(local_name(target).to_owned()),
            "union" => Type::Union(local_name(target).to_owned()),
            "list" => {
                let shape = self
                    .model
                    .shape(target)
                    .ok_or_else(|| Error::ir(self.operation, format!("unknown list shape `{target}`")))?;
                let list_member = shape
                    .get("member")
                    .ok_or_else(|| Error::ir(self.operation, format!("list `{target}` has no member")))?;
                let item = target_of(list_member)
                    .ok_or_else(|| Error::ir(self.operation, format!("list `{target}` member has no target")))?;
                let flattened = has_trait(member, "smithy.api#xmlFlattened") || has_trait(shape, "smithy.api#xmlFlattened");
                let wrapper_name = if flattened {
                    None
                } else {
                    Some(
                        trait_of(list_member, "smithy.api#xmlName")
                            .and_then(Value::as_str)
                            .unwrap_or("member")
                            .to_owned(),
                    )
                };
                Type::List {
                    member: Box::new(self.type_of(item, list_member, &Binding::BodyXml)?),
                    flattened,
                    wrapper_name,
                }
            }
            "map" => {
                let shape = self
                    .model
                    .shape(target)
                    .ok_or_else(|| Error::ir(self.operation, format!("unknown map shape `{target}`")))?;
                let key = shape.get("key").and_then(target_of).unwrap_or("smithy.api#String");
                let value = shape.get("value").and_then(target_of).unwrap_or("smithy.api#String");
                Type::Map {
                    key: Box::new(self.type_of(key, member, &Binding::BodyXml)?),
                    value: Box::new(self.type_of(value, member, &Binding::BodyXml)?),
                }
            }
            other => {
                return Err(Error::ir(
                    self.operation,
                    format!("shape `{target}` has kind `{other}`, which the IR has no type for"),
                ));
            }
        })
    }

    /// Explicit trait wins; otherwise the Smithy default for the binding position.
    fn timestamp_format(&self, target: &str, member: &Value, binding: &Binding) -> TimestampFormat {
        let declared = trait_of(member, "smithy.api#timestampFormat")
            .or_else(|| {
                self.model
                    .shape(target)
                    .and_then(|s| trait_of(s, "smithy.api#timestampFormat"))
            })
            .and_then(Value::as_str);
        match declared {
            Some("http-date") => TimestampFormat::HttpDate,
            Some("date-time") => TimestampFormat::Iso8601,
            Some("epoch-seconds") => TimestampFormat::EpochSeconds,
            _ => match binding {
                Binding::Header => TimestampFormat::HttpDate,
                _ => TimestampFormat::Iso8601,
            },
        }
    }

    fn scalar(&self, spelling: &str, binding: &Binding) -> Result<Type> {
        let (kind, argument) = match spelling.split_once(':') {
            Some((k, a)) => (k, Some(a)),
            None => (spelling, None),
        };
        Ok(match kind {
            "String" => Type::String,
            "OpaqueString" => Type::OpaqueString,
            "Integer" => Type::Integer,
            "Long" => Type::Long,
            "Boolean" => Type::Boolean,
            "ObjectKey" => Type::ObjectKey,
            "BucketName" => Type::BucketName,
            "Range" => Type::Range,
            "ChecksumSpec" => Type::ChecksumSpec,
            "ETag" => {
                let render = match argument {
                    Some(a) => {
                        ETagRender::parse(a).ok_or_else(|| Error::ir(self.operation, format!("unknown ETag rendering `{a}`")))?
                    }
                    // No default rendering exists; the binding position is what decides it.
                    None => match binding {
                        Binding::BodyXml => ETagRender::XmlQuoted,
                        _ => ETagRender::HeaderQuoted,
                    },
                };
                Type::ETag(render)
            }
            "Timestamp" => {
                let format = argument
                    .and_then(TimestampFormat::parse)
                    .ok_or_else(|| Error::ir(self.operation, "Timestamp needs an explicit format"))?;
                Type::Timestamp(format)
            }
            "Checksum" => {
                let algo = argument
                    .and_then(ChecksumAlgo::parse)
                    .ok_or_else(|| Error::ir(self.operation, "Checksum needs an explicit algorithm"))?;
                Type::Checksum(algo)
            }
            other => return Err(Error::ir(self.operation, format!("unknown scalar spelling `{other}`"))),
        })
    }

    fn collect_shapes(&mut self, ty: &Type, out: &mut BTreeMap<String, Shape>) -> Result<()> {
        match ty {
            Type::Structure(name) | Type::Union(name) => {
                if out.contains_key(name) {
                    return Ok(());
                }
                let shape = self
                    .model
                    .shape_local(name)
                    .ok_or_else(|| Error::ir(self.operation, format!("unknown nested shape `{name}`")))?;
                let default = ShapeOverlay::default();
                let ov = self.overlay.shapes.get(name).unwrap_or(&default);
                // Reserve the slot before recursing so a self-referential shape terminates.
                out.insert(
                    name.clone(),
                    Shape {
                        kind: ShapeKind::Structure,
                        fields: Vec::new(),
                        xml: ShapeXml {
                            element_order: Vec::new(),
                            empty_value_policy: Vec::new(),
                            attributes: Vec::new(),
                        },
                    },
                );
                let members: BTreeSet<String> = self.model.members(shape).into_iter().map(|(n, _)| n.to_owned()).collect();
                for (list, key) in [(&ov.drop, "drop"), (&ov.required, "required"), (&ov.hot, "hot")] {
                    for member in list {
                        if !members.contains(member) {
                            return Err(Error::ir(
                                self.operation,
                                format!("shape `{name}`: `{key}` names `{member}`, which is not one of its members"),
                            ));
                        }
                    }
                }
                for field in &ov.fields {
                    if !members.contains(&field.name) {
                        return Err(Error::ir(
                            self.operation,
                            format!("shape `{name}`: field overlay targets `{}`, which is not one of its members", field.name),
                        ));
                    }
                }
                let mut fields = Vec::new();
                for (member_name, member) in self.model.members(shape) {
                    if ov.drop.iter().any(|d| d == member_name) {
                        continue;
                    }
                    let fov = ov.fields.iter().find(|f| f.name == member_name);
                    let target = target_of(member)
                        .ok_or_else(|| Error::ir(self.operation, format!("member `{member_name}` has no target")))?;
                    let binding = Binding::BodyXml;
                    let ty = match fov.and_then(|f| f.ty.as_deref()) {
                        Some(spelling) => self.scalar(spelling, &binding)?,
                        None => self.type_of(target, member, &binding)?,
                    };
                    fields.push(Field {
                        name: member_name.to_owned(),
                        wire_name: self.wire_name(member, member_name, &binding, fov),
                        required: fov.and_then(|f| f.required).unwrap_or_else(|| {
                            has_trait(member, "smithy.api#required") || ov.required.iter().any(|r| r == member_name)
                        }),
                        binding,
                        ty,
                        hot: fov
                            .and_then(|f| f.hot)
                            .unwrap_or_else(|| ov.hot.iter().any(|h| h == member_name)),
                        default: fov.and_then(default_of),
                        omit_when: fov.map(omit_when_of).transpose()?.flatten(),
                        missing_error: fov.and_then(|f| f.missing_error.clone()),
                        quirk_refs: sort_quirk_ids(fov.map(|f| f.quirks.clone()).unwrap_or_default()),
                    });
                }
                let kind = if self.model.kind_of(&format!("{}#{name}", namespace(self.model))) == "union" {
                    ShapeKind::Union
                } else {
                    ShapeKind::Structure
                };
                let xml = ShapeXml {
                    element_order: if ov.element_order.is_empty() {
                        body_members(&fields)
                    } else {
                        ov.element_order.clone()
                    },
                    empty_value_policy: empty_value_policy(&fields, &ov.empty_value),
                    attributes: Vec::new(),
                };
                let nested: Vec<Type> = fields.iter().map(|f| f.ty.clone()).collect();
                out.insert(name.clone(), Shape { kind, fields, xml });
                for ty in &nested {
                    self.collect_shapes(ty, out)?;
                }
            }
            Type::List { member, .. } => self.collect_shapes(member, out)?,
            Type::Map { key, value } => {
                self.collect_shapes(key, out)?;
                self.collect_shapes(value, out)?;
            }
            _ => {}
        }
        Ok(())
    }
}

fn namespace(model: &Model) -> &str {
    model.service_id().split('#').next().unwrap_or("")
}
