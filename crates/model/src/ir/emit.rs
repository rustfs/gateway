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

//! Rendering an [`OperationIr`] as a JSON value.
//!
//! Responsible for: key order and the exact shape `spec/ir.schema.json` demands.
//! NOT responsible for: layout (that is [`crate::json::write_canonical`]) or deciding content.
//! Upstream: [`super`]. Downstream: `rustfs-gateway-codegen`.
//!
//! Key order follows the schema's `required` list rather than alphabetical order, so a generated
//! document and a hand-written sample line up when read side by side.

use super::{
    AttributeSource, Auth, Binding, Checksum, DerivedResource, Errors, Evidence, ExtPoint, Field, Http, IR_VERSION, OmitWhen,
    OperationIr, Payload, PayloadSpec, Predicate, Quirk, Shape, ShapeXml, Type, Xml, XmlAttribute,
};
use crate::json::Value;

fn s(v: &str) -> Value {
    Value::Str(v.to_owned())
}

fn strings(items: &[String]) -> Value {
    Value::Array(items.iter().map(|i| s(i)).collect())
}

fn opt_string(v: &Option<String>) -> Value {
    match v {
        Some(x) => s(x),
        None => Value::Null,
    }
}

/// Renders one operation IR as a JSON value.
pub fn to_json(ir: &OperationIr) -> Value {
    Value::object([
        ("ir_version".into(), s(IR_VERSION)),
        ("operation".into(), s(&ir.operation)),
        ("http".into(), http(&ir.http)),
        ("auth".into(), auth(&ir.auth)),
        ("payload".into(), payload(&ir.payload)),
        ("checksum".into(), checksum(&ir.checksum)),
        ("input".into(), field_set(&ir.input)),
        ("output".into(), field_set(&ir.output)),
        (
            "shapes".into(),
            Value::Object(ir.shapes.iter().map(|(k, v)| (k.clone(), shape(v))).collect()),
        ),
        ("xml".into(), xml(&ir.xml)),
        ("errors".into(), errors(&ir.errors)),
        (
            "derived_resources".into(),
            Value::Array(ir.derived_resources.iter().map(derived_resource).collect()),
        ),
        ("head_mirrors".into(), opt_string(&ir.head_mirrors)),
        ("quirk_refs".into(), strings(&ir.quirk_refs)),
        ("quirks".into(), Value::Array(ir.quirks.iter().map(quirk).collect())),
        ("ext_points".into(), Value::Array(ir.ext_points.iter().map(ext_point).collect())),
    ])
}

fn http(h: &Http) -> Value {
    Value::object([
        ("method".into(), s(h.method.as_str())),
        ("target".into(), s(h.target.as_str())),
        ("precedence".into(), Value::Int(i64::from(h.precedence))),
        ("predicates".into(), Value::Array(h.predicates.iter().map(predicate).collect())),
        ("success_status".into(), Value::Int(i64::from(h.success_status))),
        (
            "alt_success_statuses".into(),
            Value::Array(h.alt_success_statuses.iter().map(|c| Value::Int(i64::from(*c))).collect()),
        ),
        ("path_shape".into(), s(&h.path_shape)),
    ])
}

fn predicate(p: &Predicate) -> Value {
    match p {
        Predicate::Method(m) => Value::object([("kind".into(), s("Method")), ("method".into(), s(m.as_str()))]),
        Predicate::Target(t) => Value::object([("kind".into(), s("Target")), ("target".into(), s(t.as_str()))]),
        Predicate::QueryPresent(k) => Value::object([("kind".into(), s("QueryPresent")), ("key".into(), s(k))]),
        Predicate::QueryEquals(k, v) => Value::object([
            ("kind".into(), s("QueryEquals")),
            ("key".into(), s(k)),
            ("value".into(), s(v)),
        ]),
        Predicate::QueryAbsent(k) => Value::object([("kind".into(), s("QueryAbsent")), ("key".into(), s(k))]),
        Predicate::HeaderPresent { header, negated } => {
            let mut pairs = vec![("kind".to_owned(), s("HeaderPresent")), ("header".to_owned(), s(header))];
            if *negated {
                pairs.push(("negated".to_owned(), Value::Bool(true)));
            }
            Value::Object(pairs)
        }
        Predicate::HeaderPrefix { header, prefix } => Value::object([
            ("kind".into(), s("HeaderPrefix")),
            ("header".into(), s(header)),
            ("prefix".into(), s(prefix)),
        ]),
        Predicate::PathLiteral(path) => Value::object([("kind".into(), s("PathLiteral")), ("path".into(), s(path))]),
    }
}

fn auth(a: &Auth) -> Value {
    Value::object([
        ("requirement".into(), s(a.requirement.as_str())),
        ("action".into(), s(&a.action)),
        ("presigned_allowed".into(), Value::Bool(a.presigned_allowed)),
        ("service".into(), s(&a.service)),
    ])
}

fn payload(p: &Payload) -> Value {
    Value::object([
        ("request".into(), payload_spec(&p.request)),
        ("response".into(), payload_spec(&p.response)),
    ])
}

fn payload_spec(p: &PayloadSpec) -> Value {
    Value::object([
        ("kind".into(), s(p.kind.as_str())),
        ("buffering".into(), s(p.buffering.as_str())),
        (
            "max_bytes".into(),
            match p.max_bytes {
                Some(n) => Value::Int(n as i64),
                None => Value::Null,
            },
        ),
    ])
}

fn checksum(c: &Checksum) -> Value {
    Value::object([
        ("http_checksum_required".into(), Value::Bool(c.http_checksum_required)),
        (
            "request_algorithms".into(),
            Value::Array(c.request_algorithms.iter().map(|a| s(a.as_str())).collect()),
        ),
        (
            "response_algorithms".into(),
            Value::Array(c.response_algorithms.iter().map(|a| s(a.as_str())).collect()),
        ),
    ])
}

fn field_set(fields: &[Field]) -> Value {
    Value::object([("fields".into(), Value::Array(fields.iter().map(field).collect()))])
}

fn field(f: &Field) -> Value {
    let mut pairs = vec![
        ("name".to_owned(), s(&f.name)),
        ("wire_name".to_owned(), opt_string(&f.wire_name)),
        ("required".to_owned(), Value::Bool(f.required)),
        ("binding".to_owned(), binding(&f.binding)),
        ("type".to_owned(), ty(&f.ty)),
        ("hot".to_owned(), Value::Bool(f.hot)),
    ];
    if let Some(default) = &f.default {
        pairs.push(("default".to_owned(), default.clone()));
    }
    if let Some(omit) = &f.omit_when {
        pairs.push(("omit_when".to_owned(), omit_when(omit)));
    }
    if let Some(code) = &f.missing_error {
        pairs.push(("missing_error".to_owned(), s(code)));
    }
    pairs.push(("quirk_refs".to_owned(), strings(&f.quirk_refs)));
    Value::Object(pairs)
}

fn binding(b: &Binding) -> Value {
    match b {
        Binding::UriLabel { greedy } => Value::object([("kind".into(), s("UriLabel")), ("greedy".into(), Value::Bool(*greedy))]),
        other => Value::object([("kind".into(), s(other.kind_str()))]),
    }
}

fn ty(t: &Type) -> Value {
    match t {
        Type::String => Value::object([("kind".into(), s("String"))]),
        Type::OpaqueString => Value::object([("kind".into(), s("OpaqueString"))]),
        Type::Integer => Value::object([("kind".into(), s("Integer"))]),
        Type::Long => Value::object([("kind".into(), s("Long"))]),
        Type::Boolean => Value::object([("kind".into(), s("Boolean"))]),
        Type::Timestamp(f) => Value::object([("kind".into(), s("Timestamp")), ("format".into(), s(f.as_str()))]),
        Type::ETag(r) => Value::object([("kind".into(), s("ETag")), ("render".into(), s(r.as_str()))]),
        Type::Checksum(a) => Value::object([("kind".into(), s("Checksum")), ("algo".into(), s(a.as_str()))]),
        Type::ChecksumSpec => Value::object([("kind".into(), s("ChecksumSpec"))]),
        Type::ObjectKey => Value::object([("kind".into(), s("ObjectKey"))]),
        Type::BucketName => Value::object([("kind".into(), s("BucketName"))]),
        Type::Range => Value::object([("kind".into(), s("Range"))]),
        Type::Capability { exchange } => Value::object([("kind".into(), s("Capability")), ("exchange".into(), s(exchange))]),
        Type::StringEnum(values) => Value::object([("kind".into(), s("StringEnum")), ("values".into(), strings(values))]),
        Type::Structure(shape) => Value::object([("kind".into(), s("Structure")), ("shape".into(), s(shape))]),
        Type::Union(shape) => Value::object([("kind".into(), s("Union")), ("shape".into(), s(shape))]),
        Type::List {
            member,
            flattened,
            wrapper_name,
        } => Value::object([
            ("kind".into(), s("List")),
            ("member".into(), ty(member)),
            ("flattened".into(), Value::Bool(*flattened)),
            ("wrapper_name".into(), opt_string(wrapper_name)),
        ]),
        Type::Map { key, value } => Value::object([
            ("kind".into(), s("Map")),
            ("key".into(), ty(key)),
            ("value".into(), ty(value)),
        ]),
        Type::Blob { streaming } => Value::object([("kind".into(), s("Blob")), ("streaming".into(), Value::Bool(*streaming))]),
    }
}

fn omit_when(o: &OmitWhen) -> Value {
    match o {
        OmitWhen::Empty => Value::object([("kind".into(), s("Empty"))]),
        OmitWhen::Default => Value::object([("kind".into(), s("Default"))]),
        OmitWhen::ValueEquals(v) => Value::object([("kind".into(), s("ValueEquals")), ("value".into(), s(v))]),
        OmitWhen::RequestField { field, equals } => Value::object([
            ("kind".into(), s("RequestField")),
            ("field".into(), s(field)),
            ("equals".into(), s(equals)),
        ]),
    }
}

fn shape(sh: &Shape) -> Value {
    Value::object([
        ("kind".into(), s(sh.kind.as_str())),
        ("fields".into(), Value::Array(sh.fields.iter().map(field).collect())),
        ("xml".into(), shape_xml(&sh.xml)),
    ])
}

fn shape_xml(x: &ShapeXml) -> Value {
    Value::object([
        ("element_order".into(), strings(&x.element_order)),
        (
            "empty_value_policy".into(),
            Value::Object(x.empty_value_policy.iter().map(|(k, v)| (k.clone(), s(v.as_str()))).collect()),
        ),
        ("attributes".into(), Value::Array(x.attributes.iter().map(xml_attribute).collect())),
    ])
}

fn xml_attribute(a: &XmlAttribute) -> Value {
    let source = match &a.source {
        AttributeSource::Field(f) => Value::object([("kind".into(), s("Field")), ("field".into(), s(f))]),
        AttributeSource::Constant(v) => Value::object([("kind".into(), s("Constant")), ("value".into(), s(v))]),
    };
    Value::object([
        ("element".into(), s(&a.element)),
        ("name".into(), s(&a.name)),
        ("source".into(), source),
    ])
}

fn xml(x: &Xml) -> Value {
    Value::object([
        ("request_root".into(), opt_string(&x.request_root)),
        ("request_root_aliases".into(), strings(&x.request_root_aliases)),
        ("response_root".into(), opt_string(&x.response_root)),
        ("xmlns".into(), s(x.xmlns.as_str())),
        ("unwrapped_output".into(), Value::Bool(x.unwrapped_output)),
        ("element_order".into(), strings(&x.element_order)),
        (
            "empty_value_policy".into(),
            Value::Object(x.empty_value_policy.iter().map(|(k, v)| (k.clone(), s(v.as_str()))).collect()),
        ),
        ("url_encoded_fields".into(), strings(&x.url_encoded_fields)),
        ("attributes".into(), Value::Array(x.attributes.iter().map(xml_attribute).collect())),
        ("body_literal".into(), Value::Bool(x.body_literal)),
    ])
}

fn errors(e: &Errors) -> Value {
    Value::object([
        ("not_configured".into(), opt_string(&e.not_configured)),
        ("allows_error_after_200".into(), Value::Bool(e.allows_error_after_200)),
        ("codes".into(), strings(&e.codes)),
    ])
}

fn derived_resource(d: &DerivedResource) -> Value {
    Value::object([
        ("name".into(), s(&d.name)),
        ("source_field".into(), s(&d.source_field)),
        ("kind".into(), s(&d.kind)),
        ("action".into(), s(&d.action)),
        ("required".into(), Value::Bool(d.required)),
    ])
}

fn quirk(q: &Quirk) -> Value {
    Value::object([
        ("id".into(), s(&q.id)),
        ("kind".into(), s(&q.kind)),
        ("target".into(), s(&q.target)),
        ("summary".into(), s(&q.summary)),
        ("evidence".into(), Value::Array(q.evidence.iter().map(evidence).collect())),
        ("cases".into(), strings(&q.cases)),
    ])
}

fn evidence(e: &Evidence) -> Value {
    Value::object([
        ("kind".into(), s(&e.kind)),
        ("ref".into(), s(&e.reference)),
        ("summary".into(), s(&e.summary)),
    ])
}

fn ext_point(e: &ExtPoint) -> Value {
    Value::object([
        ("id".into(), s(&e.id)),
        ("parent_shape".into(), s(&e.parent_shape)),
        ("local_name".into(), s(&e.local_name)),
        ("dialect".into(), s(&e.dialect)),
        ("strategy".into(), s(&e.strategy)),
        ("cfg_feature".into(), opt_string(&e.cfg_feature)),
        ("position".into(), s(&e.position)),
        ("unknown_policy".into(), s(&e.unknown_policy)),
    ])
}
