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

//! The files of the generated seam: each operation's module, each shape's module, the facades and
//! the root, laid out under `generated/dto/seam/**` and naming `s3s` and `leaf` relative to the
//! revision module that mounts the tree, so one tree compiles once per seam revision.
//!
//! Responsible for: the text around the struct literals — the signatures of the four operation
//! conversions (`input_to_s3s`, `input_from_s3s`, `output_from_s3s`, `output_to_s3s`) and of
//! `answer_from_legacy`, the shape conversions in both directions, union arms, the facades and the
//! root with its re-export of the mounting revision's bindings.
//! NOT responsible for: member matching and wrapping ([`super::render`]), the pairing table
//! ([`super::expr`]), or the fixtures ([`super::fixture`]).
//! Upstream: [`super`]. Downstream: `generated/dto/seam/**`.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Field, OperationIr, Shape, ShapeKind};

use super::expr::{Ctx, gateway_shape};
use super::render::{self, Forward, HEADER, LegacyMembers};
use crate::emit::dto::naming;

/// What every operation and shape file opens with: the mounting revision's `s3s` and `leaf`,
/// re-exported by the generated root one level up, and the shared error.
pub(super) const IMPORTS: &str = "\
#[allow(unused_imports)] // Not every conversion needs a leaf function.
use super::super::{leaf, s3s};
use crate::compat::ConversionError;
";

const ALLOWS: &str = "#[allow(clippy::too_many_lines, clippy::needless_question_mark, clippy::redundant_closure_call)]";

/// The `LegacyInput` struct of an operation whose s3s input holds members only the legacy decoder
/// reads, and the return type `input_from_s3s` hands them back in; empty text and the bare
/// gateway input otherwise.
fn legacy_input(ctx: &Ctx<'_>, input: &str, gw_input: &str) -> Result<(String, String), Vec<String>> {
    let Some(s3s) = ctx.facts.structs.get(input) else {
        return Err(vec![format!("{input}: not an s3s struct")]);
    };
    let members = render::legacy_members(input, s3s);
    if members.is_empty() {
        return Ok((String::new(), gw_input.to_owned()));
    }
    let mut fields = String::new();
    for (member, ty) in members {
        let ty = render::type_text(ty).map_err(|error| vec![format!("{input}.{member}: {error}")])?;
        let _ = writeln!(
            fields,
            "    /// The legacy `{member}` member, as the legacy decoder read it.\n    pub {member}: {ty},"
        );
    }
    let text = format!(
        "/// Members only the legacy decoder reads (MinIO's `?versionId=`, `x-minio-force-delete`), which\n\
         /// no gateway member holds: handed back beside the gateway input by [`input_from_s3s`], never\n\
         /// dropped, for the ported use case to apply as the legacy stack did (rustfs/backlog#2749).\n\
         /// Forward, [`input_to_s3s`] decodes them from the raw request it takes.\n\
         #[derive(Clone, Debug, Default, PartialEq, Eq)]\n\
         pub struct LegacyInput {{\n{fields}}}\n\n"
    );
    Ok((text, format!("({gw_input}, LegacyInput)")))
}

/// One rendered operation: its module name, its text, and the parameters `input_to_s3s` takes
/// besides the input, in order.
pub(super) type Rendered = (String, String, Vec<(String, String)>);

/// One operation module, as [`Rendered`].
pub(super) fn operation(ctx: &Ctx<'_>, ir: &OperationIr) -> Result<Rendered, Vec<String>> {
    let op = &ir.operation;
    let module = naming::module_name(op);
    let gw = format!("crate::ops::{}", naming::module_ident(op));
    let input = format!("{op}Input");
    let output = format!("{op}Output");
    ctx.supplied.borrow_mut().clear();
    let forward = render::forward_struct(ctx, &input, &ir.input, "input");
    let params: Vec<(String, String)> = ctx.supplied.borrow_mut().drain(..).collect();
    let param_text: String = params.iter().map(|(name, ty)| format!(", {name}: {ty}")).collect();
    let legacy = legacy_input(ctx, &input, &format!("{gw}::Input"));
    let input_back =
        render::backward_struct_with(ctx, &input, &ir.input, &format!("{gw}::Input"), "input", LegacyMembers::HandBack);
    let backward = render::backward_struct(ctx, &output, &ir.output, &format!("{gw}::Output"), "output");
    let output_forward = render::forward_struct_as(ctx, &output, &ir.output, "output", Forward::Output).and_then(|text| {
        // A parameter is a legacy-only input member decoded from the raw request; an output has none.
        let taken: Vec<String> = ctx.supplied.borrow_mut().drain(..).map(|(name, _)| name).collect();
        if taken.is_empty() {
            Ok(text)
        } else {
            Err(taken
                .into_iter()
                .map(|name| format!("{output}.{name}: an output conversion takes no parameter"))
                .collect())
        }
    });
    let headers = render::headers_body(ctx, &output, &ir.output);
    let (forward, input_back, backward, output_forward, headers, (legacy_struct, input_back_type)) =
        match (forward, input_back, backward, output_forward, headers, legacy) {
            (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e), Ok(f)) => (a, b, c, d, e, f),
            (a, b, c, d, e, f) => {
                let mut errors = Vec::new();
                for found in [a.err(), b.err(), c.err(), d.err(), e.err(), f.err()] {
                    errors.extend(found.unwrap_or_default());
                }
                errors.sort();
                errors.dedup();
                return Err(errors.into_iter().map(|e| format!("{op}: {e}")).collect());
            }
        };
    let mutable = if headers.is_empty() { "" } else { "mut " };
    let mut out = String::from(HEADER);
    let _ = write!(
        out,
        "\n//! The `{op}` seam: the gateway input as the s3s input and back, the s3s output as the gateway\n\
         //! output and back.\n\n{IMPORTS}\n\
         /// Converts a decoded gateway `{op}` input into the s3s input the RustFS app body receives.\n\
         ///\n/// # Errors\n///\n/// [`ConversionError`] naming a member the s3s input cannot hold.\n\
         {ALLOWS}\n\
         pub fn input_to_s3s(input: {gw}::Input{param_text}) -> Result<s3s::dto::{op}Input, ConversionError> {{\n{forward}}}\n\n\
         {legacy_struct}\
         /// Converts the s3s `{op}` input the legacy stack decoded into the gateway input a ported\n\
         /// RustFS use case takes (rustfs/backlog#2749). A member only the legacy decoder reads, which\n\
         /// no gateway member holds, is handed back beside it as `LegacyInput`, never dropped. A member\n\
         /// the gateway input requires and the legacy decoder may leave unset (an upload's\n\
         /// `content_length` with no wire `Content-Length`) is refused by name: resolve it before\n\
         /// converting, as the legacy stack resolves an upload's size from the decoded length.\n\
         ///\n/// # Errors\n///\n/// [`ConversionError`] naming a member the gateway input cannot hold.\n\
         {ALLOWS}\n\
         pub fn input_from_s3s(input: s3s::dto::{op}Input) -> Result<{input_back_type}, ConversionError> {{\n{input_back}}}\n\n\
         /// Converts the s3s output a RustFS app body returned into the gateway `{op}` output.\n\
         ///\n/// # Errors\n///\n/// [`ConversionError`] naming a member the gateway output cannot hold.\n\
         {ALLOWS}\n\
         pub fn output_from_s3s(output: s3s::dto::{op}Output) -> Result<{gw}::Output, ConversionError> {{\n{backward}}}\n\n\
         /// Converts the gateway `{op}` output a ported RustFS use case returned into the s3s output\n\
         /// the legacy stack writes (rustfs/backlog#2749).\n\
         ///\n/// # Errors\n///\n/// [`ConversionError`] naming a member the s3s output cannot hold.\n\
         {ALLOWS}\n\
         pub fn output_to_s3s(output: {gw}::Output) -> Result<s3s::dto::{op}Output, ConversionError> {{\n{output_forward}}}\n\n\
         /// Converts a RustFS app body's whole answer — its output and the response headers it set\n\
         /// beside it — into the gateway `{op}` output and the extra headers the gateway writes after\n\
         /// it (`Resp::with_extra_headers`). The legacy writer lets such a header replace the one an\n\
         /// output member writes, so a member whose header the body set is left to that header.\n\
         ///\n/// # Errors\n///\n/// [`ConversionError`] as [`output_from_s3s`], or naming a required member one of the\n\
         /// headers would replace.\n\
         #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]\n\
         pub fn answer_from_legacy({mutable}output: s3s::dto::{op}Output, headers: http::HeaderMap) -> Result<({gw}::Output, http::HeaderMap), ConversionError> {{\n{headers}    Ok((output_from_s3s(output)?, headers))\n}}\n"
    );
    Ok((module, out, params))
}

/// One direction of one nested shape's conversion.
pub(super) fn shape_fn(ctx: &Ctx<'_>, raw: &str, shape: &Shape, forward: bool) -> Result<String, Vec<String>> {
    let gw = gateway_shape(raw);
    let name = format!("{}_{}", naming::module_name(raw), if forward { "to_s3s" } else { "from_s3s" });
    ctx.supplied.borrow_mut().clear();
    let body = match (shape.kind, forward) {
        (ShapeKind::Structure, true) => render::forward_struct(ctx, raw, &shape.fields, "value")?,
        (ShapeKind::Structure, false) => render::backward_struct(ctx, raw, &shape.fields, &gw, "value")?,
        (ShapeKind::Union, forward) => union(ctx, raw, &shape.fields, forward)?,
    };
    if !ctx.supplied.borrow().is_empty() {
        return Err(vec![format!(
            "{raw}: a nested shape's conversion takes no parameter; supply or decode the member at the operation"
        )]);
    }
    let (from, to) = if forward {
        (gw.clone(), format!("s3s::dto::{raw}"))
    } else {
        (format!("s3s::dto::{raw}"), gw.clone())
    };
    Ok(format!(
        "/// Converts one `{raw}` {}.\n///\n/// # Errors\n///\n/// [`ConversionError`] naming a member the other side cannot hold.\n\
         {ALLOWS}\n\
         pub fn {name}(value: {from}) -> Result<{to}, ConversionError> {{\n{body}}}\n",
        if forward {
            "from the gateway shape to the s3s shape"
        } else {
            "from the s3s shape to the gateway shape"
        }
    ))
}

fn union(ctx: &Ctx<'_>, raw: &str, fields: &[Field], forward: bool) -> Result<String, Vec<String>> {
    let Some(variants) = ctx.facts.unions.get(raw) else {
        return Err(vec![format!("{raw}: not an s3s union")]);
    };
    let gw = gateway_shape(raw);
    let mut errors = Vec::new();
    let mut arms = String::new();
    for field in fields {
        let variant = naming::type_name(&field.name);
        let Some((s3s_variant, ty)) = variants.iter().find(|(v, _)| naming::type_name(v) == variant) else {
            errors.push(format!("{raw}::{variant}: the s3s union has no such variant"));
            continue;
        };
        let conv = if forward {
            ctx.forward(&field.ty, ty, "x", &variant)
        } else {
            ctx.backward(ty, &field.ty, &field.name, "x", &variant)
        };
        match conv {
            Err(error) => errors.push(format!("{raw}::{variant}: {error}")),
            Ok(conv) if forward => {
                let _ = writeln!(arms, "        {gw}::{variant}(x) => s3s::dto::{raw}::{s3s_variant}({conv}),");
            }
            Ok(conv) => {
                let _ = writeln!(arms, "        s3s::dto::{raw}::{s3s_variant}(x) => {gw}::{variant}({conv}),");
            }
        }
    }
    if !forward {
        let _ = writeln!(
            arms,
            "        _ => {},",
            render::missing(raw, "an s3s variant the gateway model does not declare")
        );
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(format!("    Ok(match value {{\n{arms}    }})\n"))
}

/// The file holding every direction of one shape's conversion.
pub(super) fn shape_file(raw: &str, bodies: &[String]) -> String {
    format!("{HEADER}\n//! The `{raw}` shape conversions.\n\n{IMPORTS}\n{}", bodies.join("\n"))
}

/// A facade that mounts one module per name.
pub(super) fn facade(what: &str, modules: &[String]) -> String {
    let mut out = format!("{HEADER}\n//! Generated seam {what}, one module each.\n\n");
    for module in modules {
        let _ = writeln!(out, "pub mod {module};");
    }
    out
}

/// The seam's generated root.
pub(super) fn root() -> String {
    format!(
        "{HEADER}\n//! The generated half of the migration seam (rustfs/gateway#967): one module per covered\n\
         //! operation and one per nested shape it reaches, converting against the seam revision module\n\
         //! that mounts this tree — its `s3s` and `leaf`, re-exported here for every module beneath, so\n\
         //! one tree compiles once per revision (rustfs/backlog#2759).\n\
         //!\n\
         //! `census` holds the member census of every pinned structure they reach (rustfs/gateway#1076)\n\
         //! and the error-code census; `fixtures`, test-only, the s3s values the round trips start from.\n\n\
         // The mounting revision's bindings, reached by every module below as `super::super::{{leaf, s3s}}`.\n\
         use super::{{leaf, s3s}};\n\n\
         pub mod census;\n#[cfg(test)]\npub mod fixtures;\npub mod ops;\npub mod shapes;\n"
    )
}
