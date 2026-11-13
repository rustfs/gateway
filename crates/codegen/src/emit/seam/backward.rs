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

//! The backward half of the generated seam's struct literals: the s3s value as the gateway
//! value, and each operation's `answer_from_legacy` header body.
//!
//! Responsible for: destructuring an s3s value exhaustively, converting each paired member back
//! with the wrapping the two sides' optionality needs, refusing by name what the gateway shape
//! cannot hold, handing a legacy-only input member back as `LegacyInput` ([`LegacyMembers`]), and
//! clearing the output members a header the RustFS body set itself replaces.
//! NOT responsible for: pairing a gateway member with its s3s member ([`super::render::target`]),
//! the forward direction ([`super::render`]), or the type pairing ([`super::expr`]).
//! Upstream: [`super::files`]. Downstream: `generated/dto/seam/**`.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Binding, Field, Type};

use super::expr::Ctx;
use super::facts::S3sType;
use super::overrides::Rule;
use super::render::{
    CHECKSUM_FAN_OUT, Target, bare_name, is_bare_container, is_container, member_rule, missing, placeholder_pairing, push_field,
    target,
};
use crate::emit::dto::naming;
use crate::emit::dto::registry::Registry;

/// Why a member only the legacy decoder reads is refused when an s3s value holds it and the
/// conversion has no side channel to hand it back on.
pub(super) const LEGACY_DECODER_ONLY: &str =
    "a member only the legacy decoder reads and no gateway member holds, refused rather than dropped";

/// What a backward conversion does with a member only the legacy decoder reads
/// ([`Rule::FromQuery`], [`Rule::FromBoolHeader`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LegacyMembers {
    /// Refused when set: a shape or output with no side channel.
    Refuse,
    /// Bound and handed back beside the gateway value as the operation's `LegacyInput`, for the
    /// ported use case to apply as the legacy stack did (rustfs/backlog#2749).
    HandBack,
}
/// The gateway struct literal of type `gw_type` for the destructured s3s value, a member only the
/// legacy decoder reads refused when set.
pub(super) fn backward_struct(
    ctx: &Ctx<'_>,
    owner: &str,
    fields: &[Field],
    gw_type: &str,
    src: &str,
) -> Result<String, Vec<String>> {
    backward_struct_with(ctx, owner, fields, gw_type, src, LegacyMembers::Refuse)
}

/// [`backward_struct`], with the legacy-only members handled as `legacy` says: handed back, the
/// literal is the pair `(gateway value, LegacyInput { .. })`.
pub(super) fn backward_struct_with(
    ctx: &Ctx<'_>,
    owner: &str,
    fields: &[Field],
    gw_type: &str,
    src: &str,
    legacy: LegacyMembers,
) -> Result<String, Vec<String>> {
    let Some(s3s) = ctx.facts.structs.get(owner) else {
        return Err(vec![format!("{owner}: not an s3s struct")]);
    };
    let mut errors = Vec::new();
    let mut used: Vec<&str> = Vec::new();
    let mut handed: Vec<&str> = Vec::new();
    // Nested parents: (s3s member, nested struct, nested members taken).
    let mut nested: Vec<(&str, &str, Vec<&str>)> = Vec::new();
    let mut body = String::new();
    for field in fields {
        let name = bare_name(field);
        let gw_name = naming::field_name(&field.name);
        match target(ctx, owner, field, s3s) {
            Err(error) => errors.push(error),
            Ok(Target::GatewayOnly(_) | Target::CarriedByHeaders) => {
                if field.required && !is_container(&field.ty) {
                    errors.push(format!("{owner}.{name}: a required gateway member cannot be gateway-only"));
                }
                let _ = writeln!(body, "        {gw_name}: Default::default(),");
            }
            Ok(Target::ChecksumFanOut) => {
                let present: Vec<&str> = CHECKSUM_FAN_OUT
                    .iter()
                    .filter(|(m, _)| s3s.iter().any(|(s, _)| s == m))
                    .map(|(m, _)| *m)
                    .collect();
                used.extend(present.iter().copied());
                let list = CHECKSUM_FAN_OUT
                    .iter()
                    .filter(|(m, _)| present.contains(m))
                    .map(|(m, a)| format!("(\"{m}\", crate::ChecksumAlgorithm::{a}, {m})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let wrap = if field.required { "?.unwrap_or_default()" } else { "?" };
                let _ = writeln!(body, "        {gw_name}: leaf::checksum_spec_from_s3s([{list}]){wrap},");
            }
            Ok(Target::Nested(parent, nested_struct, ty, member)) => {
                match nested.iter_mut().find(|(p, _, _)| *p == parent) {
                    Some((_, _, taken)) => taken.push(member),
                    None => {
                        used.push(parent);
                        nested.push((parent, nested_struct, vec![member]));
                    }
                }
                let (core, optional) = ty.unwrap_option();
                match ctx.backward(core, &field.ty, &field.name, "x", &name) {
                    Err(error) => errors.push(format!("{owner}.{name}: {error}")),
                    Ok(conv) => {
                        let source = format!("{parent}.{member}");
                        let value = wrap_backward((owner, field), optional, &source, &conv, &name);
                        push_field(&mut body, &gw_name, &value);
                    }
                }
            }
            // A supplied member is a parameter forward; backward the s3s value converts like any other.
            Ok(Target::Member(member, ty) | Target::Supplied(member, ty)) => {
                used.push(member);
                let (core, optional) = ty.unwrap_option();
                // The SSE-C customer key is a plain string in the s3s input and a secret type on the
                // gateway side; it is rewrapped, never read.
                let conv = if crate::emit::dto::registry::is_secret_string_field(field) && super::expr::is_string(core) {
                    Ok("crate::SseCustomerKey::new(x)".to_owned())
                } else if owner.ends_with("Input") && crate::emit::dto::is_required_copy_source_header(field) {
                    match core {
                        S3sType::Leaf(ty) if ty == "CopySource" => Ok("super::super::copy_source::from_s3s(x)".to_owned()),
                        _ => Err(format!("no s3s → gateway conversion from {core:?} to CopySourceValue")),
                    }
                } else {
                    ctx.backward(core, &field.ty, &field.name, "x", &name)
                };
                match conv {
                    Err(error) => errors.push(format!("{owner}.{name}: {error}")),
                    Ok(conv) if field.required && matches!(member_rule(owner, member), Some(Rule::AbsentAsEmpty(_))) => {
                        match absent_as_empty(field, optional, member, &conv, &name) {
                            Ok(value) => push_field(&mut body, &gw_name, &value),
                            Err(error) => errors.push(format!("{owner}.{name}: {error}")),
                        }
                    }
                    Ok(conv) if matches!(member_rule(owner, member), Some(Rule::AbsentAsPlaceholder(_))) => {
                        match absent_as_placeholder_backward((owner, field), optional, member, &conv, &name) {
                            Ok(value) => push_field(&mut body, &gw_name, &value),
                            Err(error) => errors.push(format!("{owner}.{name}: {error}")),
                        }
                    }
                    Ok(conv) => {
                        let value = wrap_backward((owner, field), optional, member, &conv, &name);
                        push_field(&mut body, &gw_name, &value);
                    }
                }
            }
        }
    }
    let mut pattern = String::new();
    let mut refusals = String::new();
    for (member, ty) in s3s {
        if used.contains(&member.as_str()) {
            let _ = writeln!(pattern, "        {member},");
        } else if matches!(ty, S3sType::Option(inner) if matches!(inner.as_ref(), S3sType::Opaque)) {
            // A runtime value with no wire form, such as the deferred completion a legacy body may
            // hand the legacy writer to stream behind keep-alive whitespace: the gateway writes an
            // output once and cannot carry it, so a set one is refused by name rather than dropped
            // (rustfs/gateway#1076); an unset one crosses as nothing.
            let _ = writeln!(pattern, "        {member},");
            let _ = writeln!(
                refusals,
                "    if {member}.is_some() {{\n        {};\n    }}",
                missing(member, "a runtime value with no wire form, which the gateway output cannot carry")
            );
        } else if matches!(ty.unwrap_option().0, S3sType::Opaque) {
            // A cache the legacy type derives from the members beside it: nothing is lost with it.
            let _ = writeln!(pattern, "        {member}: _,");
        } else if legacy == LegacyMembers::HandBack
            && matches!(member_rule(owner, member), Some(Rule::FromQuery(_) | Rule::FromBoolHeader(_)))
        {
            // No gateway member holds it; the use case takes it beside the input, never dropped.
            let _ = writeln!(pattern, "        {member},");
            handed.push(member);
        } else if let Some(reason) = match member_rule(owner, member) {
            // The gateway shape cannot hold it, so a value is refused by name rather than dropped
            // (rustfs/gateway#1076); an unset one crosses as nothing, as it would have.
            Some(Rule::S3sOnly(_)) => Some("a legacy member the gateway shape cannot hold, refused rather than dropped"),
            // Decoded from the raw request forward; backward no gateway member holds it either.
            Some(Rule::FromQuery(_) | Rule::FromBoolHeader(_)) => Some(LEGACY_DECODER_ONLY),
            _ => None,
        } {
            let present = match ty {
                S3sType::Option(_) => format!("{member}.is_some()"),
                S3sType::Vec(_) => format!("!{member}.is_empty()"),
                other => {
                    errors.push(format!(
                        "{owner}.{member}: a required legacy-only member {other:?} cannot be refused when set"
                    ));
                    continue;
                }
            };
            let _ = writeln!(pattern, "        {member},");
            let _ = writeln!(refusals, "    if {present} {{\n        {};\n    }}", missing(member, reason));
        } else {
            errors.push(format!("{owner}.{member}: an s3s member no gateway member takes"));
        }
    }
    let mut unnest = String::new();
    for (parent, nested_struct, taken) in &nested {
        let Some(nested_fields) = ctx.facts.structs.get(*nested_struct) else {
            continue;
        };
        for (member, ty) in nested_fields {
            let runtime = matches!(ty.unwrap_option().0, S3sType::Opaque);
            if !taken.contains(&member.as_str())
                && !runtime
                && !matches!(member_rule(nested_struct, member), Some(Rule::S3sOnly(_)))
            {
                errors.push(format!("{nested_struct}.{member}: a nested s3s member no gateway member takes"));
            }
        }
        let _ = writeln!(unnest, "    let {parent} = {parent}.unwrap_or_default();");
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let value = format!("{gw_type} {{\n{body}    }}");
    let result = if handed.is_empty() {
        value
    } else {
        format!("({value}, LegacyInput {{ {} }})", handed.join(", "))
    };
    Ok(format!(
        "    let s3s::dto::{owner} {{\n{pattern}    }} = {src};\n{refusals}{unnest}    Ok({result})\n"
    ))
}

/// [`Rule::AbsentAsEmpty`] on a required gateway member: an unset legacy string is the empty gateway
/// string, and a set empty one is refused by name, since the gateway would write it as unset. On an
/// optional gateway member the rule changes nothing, and the member converts as any other: an unset
/// legacy value is already the unset gateway value.
fn absent_as_empty(field: &Field, s3s_optional: bool, member: &str, conv: &str, name: &str) -> Result<String, String> {
    if !(s3s_optional && matches!(field.ty, Type::String) && conv == "x") {
        return Err("AbsentAsEmpty applies only to a gateway string whose legacy member is an optional string".to_owned());
    }
    Ok(format!(
        "match {member} {{ Some(x) if x.is_empty() => {}, Some(x) => x, None => String::new() }}",
        missing(name, "an empty legacy value the gateway would write as unset")
    ))
}

/// [`Rule::AbsentAsPlaceholder`] backward: an unset legacy member is the placeholder, and a set one
/// that converts to it is refused, since the RustFS layout would then write it as unset.
fn absent_as_placeholder_backward(
    owned: (&str, &Field),
    s3s_optional: bool,
    member: &str,
    conv: &str,
    name: &str,
) -> Result<String, String> {
    placeholder_pairing(owned, s3s_optional)?;
    Ok(format!(
        "match {member} {{ Some(x) => {{ let v = {conv}; if crate::WirePlaceholder::is_wire_placeholder(&v) {{ {}; }} v }}, None => Default::default() }}",
        missing(name, "a legacy value the gateway would write as unheld")
    ))
}

fn wrap_backward((owner, field): (&str, &Field), s3s_optional: bool, member: &str, conv: &str, name: &str) -> String {
    let direct = conv == "x";
    let apply = |v: &str| {
        if direct {
            v.to_owned()
        } else if v == "x" {
            conv.to_owned()
        } else {
            format!("{{ let x = {v}; {conv} }}")
        }
    };
    if is_bare_container(owner, field) {
        return if s3s_optional && direct {
            format!("{member}.unwrap_or_default()")
        } else if s3s_optional {
            format!("match {member} {{ Some(x) => {}, None => Default::default() }}", apply("x"))
        } else {
            apply(member)
        };
    }
    match (Registry::is_bare(owner, field), s3s_optional) {
        (false, true) if direct => member.to_owned(),
        (false, true) => format!("{member}.map(|x| -> Result<_, ConversionError> {{ Ok({conv}) }}).transpose()?"),
        (false, false) => format!("Some({})", apply(member)),
        (true, false) => apply(member),
        (true, true) => format!(
            "match {member} {{ Some(x) => {}, None => {} }}",
            apply("x"),
            missing(name, "the gateway shape requires this member")
        ),
    }
}

/// The body of an operation's `answer_from_legacy`: every legacy output member a response header
/// the RustFS body set itself would replace on the legacy wire is cleared, so the gateway writes
/// that header as the body set it and no second value of it (rustfs/gateway#1076).
///
/// The legacy writer puts the output's headers on the response and then extends it with the
/// body's own, and extending a header map replaces every value of a name it already holds. The
/// gateway instead refuses a handler header its encoder already wrote (rustfs/gateway#1043), so a
/// member the body's header replaces must not reach the encoder.
pub(super) fn headers_body(ctx: &Ctx<'_>, owner: &str, fields: &[Field]) -> Result<String, Vec<String>> {
    let Some(s3s) = ctx.facts.structs.get(owner) else {
        return Err(vec![format!("{owner}: not an s3s struct")]);
    };
    let mut errors = Vec::new();
    let mut body = String::new();
    for field in fields {
        let Some(wire) = field.wire_name.as_deref() else { continue };
        let header = wire.to_ascii_lowercase();
        match field.binding {
            Binding::Header => {}
            Binding::PrefixHeaders if !matches!(field.ty, Type::ChecksumSpec) => {
                match target(ctx, owner, field, s3s) {
                    Ok(Target::Member(member, S3sType::Option(inner))) if matches!(inner.as_ref(), S3sType::Map(..)) => {
                        let _ = writeln!(
                            body,
                            "    if let Some(map) = output.{member}.as_mut() {{\n        map.retain(|key, _| !headers.contains_key(format!(\"{header}{{key}}\").as_str()));\n    }}"
                        );
                    }
                    Ok(_) => errors.push(format!(
                        "{owner}.{}: a prefixed header member that is not an optional map",
                        bare_name(field)
                    )),
                    Err(error) => errors.push(error),
                }
                continue;
            }
            Binding::PrefixHeaders => {}
            _ => continue,
        }
        match target(ctx, owner, field, s3s) {
            Ok(Target::ChecksumFanOut) => {
                for (member, _) in CHECKSUM_FAN_OUT {
                    if s3s.iter().any(|(present, _)| present == member) {
                        let suffix = member.trim_start_matches("checksum_");
                        let _ = writeln!(
                            body,
                            "    if headers.contains_key(\"x-amz-checksum-{suffix}\") {{ output.{member} = None; }}"
                        );
                    }
                }
            }
            Ok(Target::Member(member, ty)) => {
                if matches!(ty, S3sType::Option(_)) {
                    let _ = writeln!(body, "    if headers.contains_key(\"{header}\") {{ output.{member} = None; }}");
                } else {
                    let _ = writeln!(
                        body,
                        "    if headers.contains_key(\"{header}\") {{\n        {};\n    }}",
                        missing(member, "a response header the RustFS body set would replace this required member")
                    );
                }
            }
            Ok(Target::GatewayOnly(_) | Target::CarriedByHeaders | Target::Supplied(..) | Target::Nested(..)) => {}
            Err(error) => errors.push(error),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(body)
}
