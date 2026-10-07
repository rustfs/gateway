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

//! The s3s values the generated round trips start from (rustfs/backlog#2759): one fixture per
//! covered operation input and output and one per reached shape, every member both sides hold
//! set to a value the other side can hold, and the tests that drive them.
//!
//! Responsible for: the fixture literal of a structure or union from the pairing of each member —
//! the same `target` the conversions use — the member paths the fixture claims to hold (`HELD`,
//! spelled as the census `present` reports them), the justification of every member left unset
//! (legacy-only, runtime, or the other algorithms of one checksum fan-out; anything else fails
//! generation), the per-operation round-trip tests, for every top-level member whose backward
//! conversion can refuse the test that it refuses by that member's name, and for every member
//! only the legacy decoder reads the test that it is handed back beside the input.
//! NOT responsible for: the conversions themselves ([`super::render`], [`super::files`]).
//! Upstream: [`super::expr`], [`super::overrides`], the IR. Downstream:
//! `generated/dto/seam/fixtures/**`, test-only.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Field, OperationIr, Shape, ShapeKind, Type};

use super::expr::Ctx;
use super::facts::S3sType;
use super::overrides::Rule;
use super::render::{self, CHECKSUM_FAN_OUT, HEADER, NestedParents, Target, bare_name, find, member_rule, push_field, target};
use crate::emit::dto::naming;

/// One rendered fixture: the s3s literal, and the member paths it holds, spelled as the census
/// `present` reports them, sorted, each once.
#[derive(Debug)]
pub struct Fixture {
    /// The s3s struct or union literal.
    pub literal: String,
    /// Every member path the literal holds a value at.
    pub held: Vec<String>,
}

/// How deep a fixture may nest before generation refuses it as a cycle.
const MAX_DEPTH: usize = 16;

/// The fixture instant: a millisecond value, the finest s3s spells, so it crosses both ways whole.
const INSTANT: &str =
    "s3s::dto::Timestamp::parse(s3s::dto::TimestampFormat::EpochSeconds, \"1700000000.123\").expect(\"a fixture instant\")";

/// An instant before the year 0, which neither side spells in its four-digit form.
const BEFORE_YEAR_ZERO: &str = "s3s::dto::Timestamp::parse(s3s::dto::TimestampFormat::EpochSeconds, \"-70000000000\").expect(\"an instant before the year 0\")";

const COPY_SOURCE: &str = "s3s::dto::CopySource::Bucket { bucket: \"source-bucket\".into(), key: \"source-key\".into(), version_id: Some(\"source-version\".into()) }";

/// What one fixture value is, for the paths it contributes.
enum Kind {
    /// One census path, the member's own.
    Leaf,
    /// A body the census never compares: set, never claimed.
    Stream,
    /// A nested structure: its own paths under the member, or the member alone when it has none.
    Structure(Vec<String>),
    /// A list of one element: a structure's paths under `member[]`, or `member[]` alone.
    List(Option<Vec<String>>),
    /// A map of one entry: the member's own path.
    Map,
}

struct Value {
    expr: String,
    kind: Kind,
}

/// The s3s literal of `owner` from the gateway `fields`, every paired member set.
///
/// `shape_path` is where the nested shapes' fixture modules are reached from the file the literal
/// lands in.
///
/// # Errors
///
/// A member neither paired nor justified unset, a pair the table has no fixture for, a nested
/// shape the IR lacks, or a structure nesting deeper than a cycle guard allows.
pub fn struct_literal(
    ctx: &Ctx<'_>,
    shapes: &BTreeMap<&str, &Shape>,
    owner: &str,
    fields: &[Field],
    shape_path: &str,
) -> Result<Fixture, Vec<String>> {
    struct_at(ctx, shapes, owner, fields, shape_path, 0)
}

/// The s3s literal of the union `raw` holding its first variant's fixture.
///
/// # Errors
///
/// As [`struct_literal`], or a union with no variant on either side.
pub fn union_literal(
    ctx: &Ctx<'_>,
    shapes: &BTreeMap<&str, &Shape>,
    raw: &str,
    fields: &[Field],
    shape_path: &str,
) -> Result<Fixture, Vec<String>> {
    union_at(ctx, shapes, raw, fields, shape_path, 0)
}

/// Whether an s3s member may stay at its `Default` in a fixture: a runtime member, or one only
/// the legacy side holds.
fn unset_is_justified(owner: &str, member: &str, ty: &S3sType) -> bool {
    matches!(ty.unwrap_option().0, S3sType::Opaque)
        || matches!(
            member_rule(owner, member),
            Some(Rule::S3sOnly(_) | Rule::FromQuery(_) | Rule::FromBoolHeader(_))
        )
}

fn wrap(optional: bool, expr: String) -> String {
    if optional { format!("Some({expr})") } else { expr }
}

fn claim(held: &mut Vec<String>, prefix: &str, member: &str, kind: &Kind) {
    match kind {
        Kind::Stream => {}
        Kind::Leaf | Kind::Map => held.push(format!("{prefix}{member}")),
        Kind::Structure(paths) if paths.is_empty() => held.push(format!("{prefix}{member}")),
        Kind::Structure(paths) => held.extend(paths.iter().map(|path| format!("{prefix}{member}.{path}"))),
        Kind::List(None) => held.push(format!("{prefix}{member}[]")),
        Kind::List(Some(paths)) if paths.is_empty() => held.push(format!("{prefix}{member}[]")),
        Kind::List(Some(paths)) => held.extend(paths.iter().map(|path| format!("{prefix}{member}[].{path}"))),
    }
}

/// The bytes a checksum of `algorithm` (its `ChecksumAlgorithm` variant name) holds.
fn digest_len(algorithm: &str) -> Result<usize, String> {
    Ok(match algorithm {
        "Crc32" | "Crc32c" => 4,
        "Crc64Nvme" | "XxHash64" | "XxHash3" => 8,
        "Md5" | "XxHash128" => 16,
        "Sha1" => 20,
        "Sha256" => 32,
        "Sha512" => 64,
        other => return Err(format!("no digest width for checksum algorithm {other}")),
    })
}

/// The base64 of `len` zero bytes: a digest of exactly its algorithm's width.
fn zero_digest(len: usize) -> String {
    let mut out = "AAAA".repeat(len / 3);
    out.push_str(match len % 3 {
        1 => "AA==",
        2 => "AAA=",
        _ => "",
    });
    out
}

#[allow(clippy::too_many_lines)]
fn struct_at(
    ctx: &Ctx<'_>,
    shapes: &BTreeMap<&str, &Shape>,
    owner: &str,
    fields: &[Field],
    shape_path: &str,
    depth: usize,
) -> Result<Fixture, Vec<String>> {
    if depth > MAX_DEPTH {
        return Err(vec![format!("{owner}: nests deeper than {MAX_DEPTH} levels")]);
    }
    let Some(s3s) = ctx.facts.structs.get(owner) else {
        return Err(vec![format!("{owner}: not an s3s struct")]);
    };
    let mut errors = Vec::new();
    let mut assigned: Vec<(String, String)> = Vec::new();
    let mut held: Vec<String> = Vec::new();
    let mut nested: NestedParents<'_> = Vec::new();
    let mut fan_out = false;
    for field in fields {
        let name = bare_name(field);
        match target(ctx, owner, field, s3s) {
            Err(error) => errors.push(error),
            Ok(Target::GatewayOnly(_) | Target::CarriedByHeaders) => {}
            Ok(Target::ChecksumFanOut) => fan_out = true,
            Ok(Target::Member(member, ty) | Target::Supplied(member, ty)) => {
                let (core, optional) = ty.unwrap_option();
                match value(ctx, shapes, &field.ty, core, member, shape_path, depth) {
                    Err(error) => {
                        errors.push(format!("{owner}.{name}: {error}"));
                        // Claimed, so the member is reported once, for the pair, not again as unfilled.
                        assigned.push((member.to_owned(), String::new()));
                    }
                    Ok(found) => {
                        claim(&mut held, "", member, &found.kind);
                        assigned.push((member.to_owned(), wrap(optional, found.expr)));
                    }
                }
            }
            Ok(Target::Nested(parent, nested_struct, ty, member)) => {
                let (core, optional) = ty.unwrap_option();
                match value(ctx, shapes, &field.ty, core, member, shape_path, depth) {
                    Err(error) => {
                        errors.push(format!("{owner}.{name}: {error}"));
                        assigned.push((parent.to_owned(), String::new()));
                    }
                    Ok(found) => {
                        claim(&mut held, &format!("{parent}."), member, &found.kind);
                        let expr = wrap(optional, found.expr);
                        match nested.iter_mut().find(|(p, _, _)| *p == parent) {
                            Some((_, _, taken)) => taken.push((member, expr)),
                            None => nested.push((parent, nested_struct, vec![(member, expr)])),
                        }
                    }
                }
            }
        }
    }
    for (parent, nested_struct, taken) in &nested {
        let Some(nested_fields) = ctx.facts.structs.get(*nested_struct) else {
            errors.push(format!("{owner}.{parent}: `{nested_struct}` is not an s3s struct"));
            continue;
        };
        let mut inner = String::new();
        for (member, ty) in nested_fields {
            if let Some((_, expr)) = taken.iter().find(|(m, _)| m == member) {
                let _ = writeln!(inner, "            {member}: {expr},");
            } else if unset_is_justified(nested_struct, member, ty) {
                let _ = writeln!(inner, "            {member}: Default::default(),");
            } else {
                errors.push(format!("{nested_struct}.{member}: an s3s member no gateway member fills"));
            }
        }
        let literal = format!("s3s::dto::{nested_struct} {{\n{inner}        }}");
        let parent_optional = find(s3s, parent).is_some_and(|(_, ty)| ty.unwrap_option().1);
        assigned.push(((*parent).to_owned(), wrap(parent_optional, literal)));
    }
    let mut body = String::new();
    let mut fanned = false;
    for (member, ty) in s3s {
        if let Some((_, expr)) = assigned.iter().find(|(m, _)| m == member) {
            push_field(&mut body, member, expr);
            continue;
        }
        if fan_out && let Some((_, algorithm)) = CHECKSUM_FAN_OUT.iter().find(|(m, _)| m == member) {
            // The gateway carries one checksum: the first algorithm present is set, the rest unset.
            if fanned {
                push_field(&mut body, member, "None");
            } else {
                fanned = true;
                match digest_len(algorithm) {
                    Ok(len) => push_field(&mut body, member, &format!("Some(\"{}\".to_owned())", zero_digest(len))),
                    Err(error) => errors.push(format!("{owner}.{member}: {error}")),
                }
                held.push(member.clone());
            }
            continue;
        }
        if unset_is_justified(owner, member, ty) {
            push_field(&mut body, member, "Default::default()");
            continue;
        }
        errors.push(format!("{owner}.{member}: an s3s member no gateway member fills"));
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    held.sort();
    held.dedup();
    Ok(Fixture {
        literal: format!("s3s::dto::{owner} {{\n{body}    }}"),
        held,
    })
}

fn union_at(
    ctx: &Ctx<'_>,
    shapes: &BTreeMap<&str, &Shape>,
    raw: &str,
    fields: &[Field],
    shape_path: &str,
    depth: usize,
) -> Result<Fixture, Vec<String>> {
    if depth > MAX_DEPTH {
        return Err(vec![format!("{raw}: nests deeper than {MAX_DEPTH} levels")]);
    }
    let Some(variants) = ctx.facts.unions.get(raw) else {
        return Err(vec![format!("{raw}: not an s3s union")]);
    };
    let Some(field) = fields.first() else {
        return Err(vec![format!("{raw}: a union with no variant")]);
    };
    let variant = naming::type_name(&field.name);
    let Some((s3s_variant, ty)) = variants.iter().find(|(v, _)| naming::type_name(v) == variant) else {
        return Err(vec![format!("{raw}::{variant}: the s3s union has no such variant")]);
    };
    let found = value(ctx, shapes, &field.ty, ty, &bare_name(field), shape_path, depth)
        .map_err(|error| vec![format!("{raw}::{variant}: {error}")])?;
    Ok(Fixture {
        literal: format!("s3s::dto::{raw}::{s3s_variant}({})", found.expr),
        held: Vec::new(),
    })
}

/// One fixture value for the (gateway type, s3s type) pair of `member`.
#[allow(clippy::too_many_lines)]
fn value(
    ctx: &Ctx<'_>,
    shapes: &BTreeMap<&str, &Shape>,
    gw: &Type,
    s3s: &S3sType,
    member: &str,
    shape_path: &str,
    depth: usize,
) -> Result<Value, String> {
    let leaf = |expr: String| Ok(Value { expr, kind: Kind::Leaf });
    let text = format!("\"{member}\".to_owned()");
    match (gw, s3s) {
        (
            Type::String | Type::OpaqueString | Type::ObjectKey | Type::Capability { .. } | Type::StringEnum(_),
            S3sType::Leaf(l),
        ) if l == "String" => leaf(text),
        (Type::BucketName, S3sType::Leaf(l)) if l == "String" => leaf("\"fixture-bucket\".to_owned()".to_owned()),
        (Type::String | Type::StringEnum(_), S3sType::Enum(name)) => leaf(format!("s3s::dto::{name}::from({text})")),
        (Type::StringEnum(_), S3sType::Leaf(l)) if l == "Event" => {
            leaf("s3s::dto::Event::from(\"s3:ObjectCreated:*\".to_owned())".to_owned())
        }
        (Type::String, S3sType::Leaf(l)) if l == "i32" => leaf("7".to_owned()),
        (Type::String, S3sType::Leaf(l)) if l == "CopySource" => leaf(COPY_SOURCE.to_owned()),
        (Type::String, S3sType::Leaf(l)) if l == "ETagCondition" => {
            leaf(format!("s3s::dto::ETagCondition::ETag(s3s::dto::ETag::Strong({text}))"))
        }
        (Type::Integer | Type::Long, S3sType::Leaf(l)) if l == "i32" || l == "i64" => leaf("7".to_owned()),
        (Type::Boolean, S3sType::Leaf(l)) if l == "bool" => leaf("true".to_owned()),
        (Type::Timestamp(_), S3sType::Leaf(l)) if l == "Timestamp" => leaf(INSTANT.to_owned()),
        (Type::ETag(_), S3sType::Leaf(l)) if l == "ETag" => leaf(format!("s3s::dto::ETag::Strong({text})")),
        (Type::Checksum(algorithm), S3sType::Leaf(l)) if l == "String" => {
            leaf(format!("\"{}\".to_owned()", zero_digest(digest_len(&format!("{algorithm:?}"))?)))
        }
        (Type::Range, S3sType::Leaf(l)) if l == "Range" => leaf("s3s::dto::Range::Int { first: 0, last: Some(9) }".to_owned()),
        (Type::Blob { streaming: true }, S3sType::Leaf(l)) if l == "StreamingBlob" => Ok(Value {
            expr: "s3s::dto::StreamingBlob::from_bytes(bytes::Bytes::from_static(b\"body\"))".to_owned(),
            kind: Kind::Stream,
        }),
        (Type::Blob { streaming: false }, S3sType::Leaf(l)) if l == "Bytes" => {
            leaf(format!("bytes::Bytes::from_static(b\"{member}\")"))
        }
        (Type::Structure(raw), S3sType::Struct(name)) if raw == name => {
            let shape = shapes
                .get(raw.as_str())
                .ok_or_else(|| format!("shape {raw} is not in the IR"))?;
            let nested = struct_at(ctx, shapes, raw, &shape.fields, shape_path, depth + 1).map_err(|errors| errors.join("; "))?;
            Ok(Value {
                expr: format!("{shape_path}::{}::value()", naming::module_ident(raw)),
                kind: Kind::Structure(nested.held),
            })
        }
        (Type::Union(raw), S3sType::Union(name)) if raw == name => {
            let shape = shapes
                .get(raw.as_str())
                .ok_or_else(|| format!("shape {raw} is not in the IR"))?;
            union_at(ctx, shapes, raw, &shape.fields, shape_path, depth + 1).map_err(|errors| errors.join("; "))?;
            leaf(format!("{shape_path}::{}::value()", naming::module_ident(raw)))
        }
        (Type::List { member: inner, .. }, S3sType::Vec(s3s_inner)) => {
            let element = value(ctx, shapes, inner, s3s_inner, member, shape_path, depth)?;
            let nested = match element.kind {
                Kind::Structure(paths) => Some(paths),
                _ => None,
            };
            Ok(Value {
                expr: format!("vec![{}]", element.expr),
                kind: Kind::List(nested),
            })
        }
        (Type::Map { key, value: val }, S3sType::Map(s3s_key, s3s_value)) => {
            let k = value(ctx, shapes, key, s3s_key, member, shape_path, depth)?;
            let v = value(ctx, shapes, val, s3s_value, member, shape_path, depth)?;
            Ok(Value {
                expr: format!("std::collections::HashMap::from([({}, {})])", k.expr, v.expr),
                kind: Kind::Map,
            })
        }
        _ => Err(format!("no fixture for {gw:?} as {s3s:?}")),
    }
}

/// One generated negative: setting `member` to `bad` makes the backward conversion refuse,
/// naming `field`.
struct Refusal {
    member: String,
    field: String,
    suffix: &'static str,
    bad: String,
    why: &'static str,
}

/// A value of the s3s type `ty` for a member set only to be refused, when one can be spelled.
fn set_expr(ty: &S3sType) -> Option<String> {
    let inner = |ty: &S3sType| {
        Some(match ty {
            S3sType::Leaf(l) if l == "String" => "String::new()".to_owned(),
            S3sType::Leaf(l) if l == "bool" => "true".to_owned(),
            S3sType::Leaf(l) if l == "i32" || l == "i64" => "1".to_owned(),
            S3sType::Leaf(l) if l == "Timestamp" => INSTANT.to_owned(),
            S3sType::Enum(name) => format!("s3s::dto::{name}::from(String::new())"),
            S3sType::Struct(name) => format!("s3s::dto::{name}::default()"),
            _ => return None,
        })
    };
    match ty {
        S3sType::Option(held) => inner(held).map(|expr| format!("Some({expr})")),
        S3sType::Vec(held) => inner(held).map(|expr| format!("vec![{expr}]")),
        _ => None,
    }
}

/// A value the backward leaf for the pair refuses, when the pair has a validating leaf.
fn invalid(gw: &Type, core: &S3sType) -> Option<(String, &'static str)> {
    let S3sType::Leaf(l) = core else { return None };
    Some(match (gw, l.as_str()) {
        (Type::BucketName, "String") => ("\"Bad Bucket!\".to_owned()".to_owned(), "not a bucket name the gateway can write"),
        (Type::ObjectKey, "String") => ("String::new()".to_owned(), "not an object key the gateway can write"),
        (Type::ETag(_), "ETag") => (
            "s3s::dto::ETag::Strong(String::new())".to_owned(),
            "not an entity tag the gateway can write",
        ),
        (Type::Timestamp(_), "Timestamp") => (BEFORE_YEAR_ZERO.to_owned(), "an instant neither side spells with four digits"),
        (Type::Integer, "i64") => ("i64::MAX".to_owned(), "not a 32-bit integer"),
        _ => return None,
    })
}

/// Every top-level member of `owner` whose backward conversion refuses a value, with that value.
fn refusals(ctx: &Ctx<'_>, owner: &str, fields: &[Field]) -> Result<Vec<Refusal>, Vec<String>> {
    let Some(s3s) = ctx.facts.structs.get(owner) else {
        return Err(vec![format!("{owner}: not an s3s struct")]);
    };
    let mut out = Vec::new();
    let mut fan_out = false;
    for field in fields {
        let name = bare_name(field);
        match target(ctx, owner, field, s3s) {
            Ok(Target::ChecksumFanOut) => fan_out = true,
            Ok(Target::Member(member, ty)) => {
                let (core, optional) = ty.unwrap_option();
                if field.required && optional && !render::is_container(&field.ty) {
                    let (bad, why) = if matches!(member_rule(owner, member), Some(Rule::AbsentAsEmpty(_))) {
                        ("Some(String::new())", "an empty legacy value the gateway would write as unset")
                    } else {
                        ("None", "a member the gateway shape requires")
                    };
                    out.push(Refusal {
                        member: member.to_owned(),
                        field: name.clone(),
                        suffix: "unset",
                        bad: bad.to_owned(),
                        why,
                    });
                }
                if let Some((bad, why)) = invalid(&field.ty, core) {
                    out.push(Refusal {
                        member: member.to_owned(),
                        field: name.clone(),
                        suffix: "invalid",
                        bad: wrap(optional, bad),
                        why,
                    });
                }
            }
            // A supplied member never refuses backward; a nested one is not top-level; the rest
            // hold no s3s value; an undecided pair is reported by the literal.
            Ok(Target::Supplied(..) | Target::Nested(..) | Target::GatewayOnly(_) | Target::CarriedByHeaders) | Err(_) => {}
        }
    }
    let mut fanned = false;
    for (member, ty) in s3s {
        if fan_out && CHECKSUM_FAN_OUT.iter().any(|(m, _)| m == member) {
            if !fanned {
                fanned = true;
                out.push(Refusal {
                    member: member.clone(),
                    field: member.clone(),
                    suffix: "width",
                    bad: "Some(\"AAA=\".to_owned())".to_owned(),
                    why: "a digest of another width than its algorithm's",
                });
            }
            continue;
        }
        if matches!(member_rule(owner, member), Some(Rule::S3sOnly(_)))
            && let Some(bad) = set_expr(ty)
        {
            out.push(Refusal {
                member: member.clone(),
                field: member.clone(),
                suffix: "set",
                bad,
                why: "a member the gateway shape cannot hold, refused rather than dropped",
            });
        }
    }
    Ok(out)
}

/// One generated positive: setting a legacy-only input member to `set` hands it back beside the
/// gateway input, unchanged.
struct HandBack {
    member: String,
    set: String,
}

/// Every member of the s3s input `owner` only the legacy decoder reads, with a value to set.
fn hand_backs(ctx: &Ctx<'_>, owner: &str) -> Result<Vec<HandBack>, Vec<String>> {
    let Some(s3s) = ctx.facts.structs.get(owner) else {
        return Err(vec![format!("{owner}: not an s3s struct")]);
    };
    let mut out = Vec::new();
    for (member, ty) in render::legacy_members(owner, s3s) {
        let set = match ty {
            S3sType::Option(inner) if matches!(inner.as_ref(), S3sType::Leaf(l) if l == "String") => {
                "Some(\"legacy\".to_owned())"
            }
            S3sType::Option(inner) if matches!(inner.as_ref(), S3sType::Leaf(l) if l == "bool") => "Some(true)",
            other => return Err(vec![format!("{owner}.{member}: no hand-back fixture for {other:?}")]),
        };
        out.push(HandBack {
            member: member.to_owned(),
            set: set.to_owned(),
        });
    }
    Ok(out)
}

fn hand_back_tests(module: &str, hand_backs: &[HandBack]) -> String {
    let mut out = String::new();
    for hand_back in hand_backs {
        let _ = write!(
            out,
            "\n    #[test]\n    fn input_hands_back_{}() {{\n        let mut value = super::input();\n        value.{} = {};\n        let (_, legacy) = ops::{module}::input_from_s3s(value).expect(\"a legacy-only member is handed back, never dropped\");\n        assert_eq!(legacy.{}, {});\n    }}\n",
            hand_back.member, hand_back.member, hand_back.set, hand_back.member, hand_back.set
        );
    }
    out
}

fn held_lines(held: &[String]) -> String {
    held.iter().map(|path| format!("    \"{path}\",\n")).collect()
}

/// The fixture file of one reached shape.
///
/// # Errors
///
/// As [`struct_literal`].
pub fn shape_file(ctx: &Ctx<'_>, shapes: &BTreeMap<&str, &Shape>, raw: &str, shape: &Shape) -> Result<String, Vec<String>> {
    let fixture = match shape.kind {
        ShapeKind::Structure => struct_literal(ctx, shapes, raw, &shape.fields, "super")?,
        ShapeKind::Union => union_literal(ctx, shapes, raw, &shape.fields, "super")?,
    };
    Ok(format!(
        "{HEADER}\n//! The `{raw}` fixture: one s3s value with every member both sides hold set.\n\n\
         use super::super::super::s3s;\n\n\
         /// Every member path the fixture holds, as the census `present` spells them.\n\
         pub const HELD: &[&str] = &[\n{}];\n\n\
         /// The fixture value.\n#[must_use]\npub fn value() -> s3s::dto::{raw} {{\n    {}\n}}\n",
        held_lines(&fixture.held),
        fixture.literal
    ))
}

fn refusal_tests(direction: &str, module: &str, refusals: &[Refusal]) -> String {
    let mut out = String::new();
    for refusal in refusals {
        let _ = write!(
            out,
            "\n    #[test]\n    fn n_{direction}_refuses_{}_{}() {{\n        let mut value = super::{direction}();\n        value.{} = {};\n        let error = ops::{module}::{direction}_from_s3s(value).expect_err(\"{}\");\n        assert_eq!(error.field, \"{}\", \"{}\");\n    }}\n",
            refusal.member, refusal.suffix, refusal.member, refusal.bad, refusal.why, refusal.field, refusal.why
        );
    }
    out
}

/// The fixture file of one covered operation: its input and output fixtures, what each holds, and
/// the tests — the round trip each way, and every top-level refusal by member name.
///
/// # Errors
///
/// As [`struct_literal`], for either structure.
pub fn op_file(
    ctx: &Ctx<'_>,
    shapes: &BTreeMap<&str, &Shape>,
    ir: &OperationIr,
    params: &[(String, String)],
) -> Result<String, Vec<String>> {
    let op = &ir.operation;
    let module = naming::module_ident(op);
    let input_name = format!("{op}Input");
    let output_name = format!("{op}Output");
    let input = struct_literal(ctx, shapes, &input_name, &ir.input, "super::super::shapes");
    let output = struct_literal(ctx, shapes, &output_name, &ir.output, "super::super::shapes");
    let (input, output) = match (input, output) {
        (Ok(input), Ok(output)) => (input, output),
        (input, output) => {
            let mut errors = input.err().unwrap_or_default();
            errors.extend(output.err().unwrap_or_default());
            return Err(errors.into_iter().map(|e| format!("{op} fixture: {e}")).collect());
        }
    };
    let input_refusals = refusals(ctx, &input_name, &ir.input)?;
    let output_refusals = refusals(ctx, &output_name, &ir.output)?;
    let handed = hand_backs(ctx, &input_name)?;
    let gateway_binding = if handed.is_empty() { "gateway" } else { "(gateway, _)" };
    let mut setup = String::new();
    let mut args = String::new();
    for (name, _) in params {
        match name.as_str() {
            "copy_source" => {
                setup.push_str("        let copy_source = leaf::copy_source_to_s3s(\"copy_source\", &gateway.copy_source).expect(\"the fixture's copy source\");\n");
                args.push_str(", copy_source");
            }
            "wire" => {
                setup.push_str("        let headers = http::HeaderMap::new();\n        let wire = leaf::RequestWire { raw_query: \"\", headers: &headers };\n");
                args.push_str(", &wire");
            }
            other => return Err(vec![format!("{op} fixture: no round-trip spelling for the parameter `{other}`")]),
        }
    }
    let round_trip = |direction: &str, forward: &str, census: &str, held: &str, setup: &str, args: &str, binding: &str| {
        format!(
            "\n    #[test]\n    fn {direction}_round_trips() {{\n        \
             let {binding} = ops::{module}::{direction}_from_s3s(super::{direction}()).expect(\"the fixture converts into the gateway {direction}\");\n\
             {setup}        \
             let back = ops::{module}::{forward}(gateway{args}).expect(\"and back into the s3s {direction}\");\n        \
             let value = super::{direction}();\n        \
             let mut differences = Vec::new();\n        \
             census::{census}::differences(\"\", &value, &back, &mut differences);\n        \
             assert!(differences.is_empty(), \"members the round trip changed: {{differences:?}}\");\n        \
             let mut present = Vec::new();\n        \
             census::{census}::present(\"\", &value, &mut present);\n        \
             assert_eq!(super::super::super::held(present), super::{held}, \"the fixture holds exactly what it claims\");\n    }}\n"
        )
    };
    Ok(format!(
        "{HEADER}\n//! The `{op}` fixtures and round trips: the s3s input and output with every member both sides\n\
         //! hold set, each converted into the gateway shape and back (rustfs/backlog#2759).\n\n\
         use super::super::super::s3s;\n\n\
         /// Every member path the input fixture holds, as the census `present` spells them.\n\
         pub const INPUT_HELD: &[&str] = &[\n{}];\n\n\
         /// Every member path the output fixture holds.\n\
         pub const OUTPUT_HELD: &[&str] = &[\n{}];\n\n\
         /// The s3s input fixture.\n#[must_use]\npub fn input() -> s3s::dto::{op}Input {{\n    {}\n}}\n\n\
         /// The s3s output fixture.\n#[must_use]\npub fn output() -> s3s::dto::{op}Output {{\n    {}\n}}\n\n\
         #[cfg(test)]\nmod tests {{\n    #![allow(clippy::expect_used, clippy::unwrap_used)]\n\n    \
         #[allow(unused_imports)] // Not every operation has a parameter or a refusal to spell.\n    \
         use super::super::super::super::{{census, leaf, ops, s3s}};\n{}{}{}{}{}}}\n",
        held_lines(&input.held),
        held_lines(&output.held),
        input.literal,
        output.literal,
        round_trip(
            "input",
            "input_to_s3s",
            &naming::module_ident(&input_name),
            "INPUT_HELD",
            &setup,
            &args,
            gateway_binding
        ),
        round_trip(
            "output",
            "output_to_s3s",
            &naming::module_ident(&output_name),
            "OUTPUT_HELD",
            "",
            "",
            "gateway"
        ),
        hand_back_tests(&module, &handed),
        refusal_tests("input", &module, &input_refusals),
        refusal_tests("output", &module, &output_refusals),
    ))
}

/// The fixtures root.
#[must_use]
pub fn root() -> String {
    format!(
        "{HEADER}\n//! The s3s fixtures the seam round trips start from (rustfs/backlog#2759): one module per\n\
         //! covered operation (`ops`) and one per reached shape (`shapes`), test-only.\n\n\
         pub mod ops;\npub mod shapes;\n\n\
         /// The member paths the census `present` reported, each once, sorted: what a fixture is held to.\n\
         #[must_use]\npub fn held(mut present: Vec<String>) -> Vec<String> {{\n    present.sort();\n    present.dedup();\n    present\n}}\n"
    )
}
