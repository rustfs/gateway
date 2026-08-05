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

//! One file per operation, plus the two module facades.
//!
//! Responsible for: `generated/dto/ops/<snake_op>.rs` (marker, `Input`, `Output`, `InputBuilder`),
//! `generated/dto/ops/mod.rs` and `generated/dto/flat.rs`.
//! NOT responsible for: the shared enumeration and shape modules, which are [`super::shared`].
//! Upstream: [`rustfs_gateway_model::ir`] and [`super::registry`]. Downstream: `rustfs-gateway-types`.
//!
//! Both facades exist on purpose. `ops::put_object::Input` is what makes 421 generated structs
//! navigable in rustdoc; `dto::PutObjectInput` is what lets an existing `use s3s::dto::…` line
//! migrate by changing only the crate name.

use std::fmt::Write as _;

use rustfs_gateway_model::ir::{Field, OperationIr};

use super::registry::Registry;
use super::{DtoReport, LICENSE, check_required_impl, debug_impl, derives, field_decl, name_list, naming, registry, use_group};

/// Renders one operation's module.
pub fn operation(ir: &OperationIr, registry: &Registry, report: &mut DtoReport) -> String {
    let op = &ir.operation;
    let marker = naming::type_name(op);
    let mut out = String::from(LICENSE);

    let _ = write!(
        out,
        "\n//! `{op}` — its request and response types.\n\
         //!\n\
         //! Responsible for: the two data-transfer objects of this one operation, plus the marker\n\
         //! type that names it and the builder that is the recommended construction path.\n\
         //! NOT responsible for: reading or writing the wire — the bindings behind these fields are\n\
         //! recorded in `spec/operations/{op}.toml`, and the codecs belong to the operation family.\n\
         //! Upstream: `generated/ir/{op}.json`. Downstream: the `{op}` handler and the flat alias\n\
         //! module `crate::dto`.\n\n"
    );

    let _ = write!(
        out,
        "/// The `{op}` operation, as a type.\n\
         ///\n\
         /// Carries the operation's identity and the wire facts a caller may need before it has a\n\
         /// request in hand. Field bindings live in `spec/operations/{op}.toml`.\n\
         #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]\n\
         pub struct {marker};\n\n"
    );

    let _ = write!(
        out,
        "impl {marker} {{\n    \
             /// The AWS operation name.\n    \
             pub const NAME: &'static str = \"{op}\";\n\n    \
             /// Input members the wire contract requires, under their model names.\n    \
             pub const REQUIRED_INPUT: &'static [&'static str] = {};\n\n    \
             /// Output members the wire contract requires, under their model names.\n    \
             pub const REQUIRED_OUTPUT: &'static [&'static str] = {};\n\n    \
             /// Input members the IR keeps on the hot path.\n    \
             pub const HOT_INPUT: &'static [&'static str] = {};\n\n    \
             /// Output members the IR keeps on the hot path.\n    \
             pub const HOT_OUTPUT: &'static [&'static str] = {};\n\
         }}\n\n",
        name_list(&selected(&ir.input, |f| f.required), 4),
        name_list(&selected(&ir.output, |f| f.required), 4),
        name_list(&selected(&ir.input, |f| f.hot), 4),
        name_list(&selected(&ir.output, |f| f.hot), 4),
    );

    out.push_str(&data_struct(
        "Input",
        &format!("The `{op}` request."),
        &ir.input,
        registry,
        report,
        &format!("{marker}Input"),
    ));
    out.push_str(&data_struct(
        "Output",
        &format!("The `{op}` response."),
        &ir.output,
        registry,
        report,
        &format!("{marker}Output"),
    ));
    out.push_str(&builder(&ir.input, registry));
    report.builders += 1;
    out
}

/// Renders one `Input` or `Output` struct with its policy note.
fn data_struct(
    name: &str,
    summary: &str,
    fields: &[Field],
    registry: &Registry,
    report: &mut DtoReport,
    baseline_name: &str,
) -> String {
    let clonable = fields.iter().all(|f| registry.is_clonable(&f.ty));
    let has_secret = fields.iter().any(registry::is_redacted);
    let mut out = String::new();

    let _ = write!(
        out,
        "/// {summary}\n\
         ///\n\
         /// Public fields plus `Default`, and never `#[non_exhaustive]` — ADR-0004 P1. Construct it\n\
         /// with functional update syntax (`{name} {{ .. }}` with `..Default::default()`) or with the\n\
         /// builder; a member added upstream stays a minor version bump either way. Do not\n\
         /// destructure it exhaustively (P3): that is the one usage a new member breaks.\n\
         ///\n\
         /// A required member is a bare type and an optional one is `Option<T>`, so requiredness is\n\
         /// read off the type instead of unwrapped. `Default` fills a required member with a\n\
         /// wire-invalid placeholder (P10), and [`{name}::check_required`] is what keeps one from\n\
         /// leaving the decode path.\n"
    );
    if !clonable {
        out.push_str("///\n/// Not `Clone`: it owns a streaming body.\n");
    }
    out.push_str(&derives(clonable, has_secret));
    let _ = writeln!(out, "pub struct {name} {{");
    for field in fields {
        out.push_str(&field_decl(field));
    }
    out.push_str("}\n\n");
    out.push_str(&check_required_impl(name, baseline_name, fields));
    out.push('\n');
    if has_secret {
        out.push_str(&debug_impl(name, fields));
        out.push('\n');
    }
    report.structs += 1;
    report.field_counts.insert(baseline_name.to_owned(), fields.len());
    out
}

/// Renders the input builder. ADR-0004 P7: recommended, never the only path.
fn builder(fields: &[Field], registry: &Registry) -> String {
    let mut out = String::new();
    out.push_str(
        "/// A builder for [`Input`].\n\
         ///\n\
         /// The recommended construction path, not the only one — the public fields stay public\n\
         /// (ADR-0004 P7), so a caller that prefers a struct literal keeps it.\n\
         #[derive(Default)]\n\
         pub struct InputBuilder {\n    input: Input,\n}\n\n\
         impl Input {\n    \
             /// Starts a builder.\n    \
             #[must_use]\n    \
             pub fn builder() -> InputBuilder {\n        InputBuilder::default()\n    }\n}\n\n\
         impl InputBuilder {\n",
    );
    for field in fields {
        let name = naming::field_name(&field.name);
        let inner = Registry::type_with_enums(&field.ty, &field.name);
        // A container and a required member are both stored bare, so only an optional one is
        // wrapped. The setter's argument is the unwrapped type in every case.
        let bare = Registry::is_container(&field.ty) || field.required;
        let (argument, assignment) = if bare {
            (inner.clone(), format!("self.input.{name} = value;"))
        } else {
            (inner.clone(), format!("self.input.{name} = Some(value);"))
        };
        let _ = write!(
            out,
            "    /// Sets `{}`.\n    \
             #[must_use]\n    \
             pub fn {name}(mut self, value: {argument}) -> Self {{\n        {assignment}\n        self\n    }}\n\n",
            field.name
        );
    }
    out.push_str(
        "    /// Finishes the builder.\n    \
         #[must_use]\n    \
         pub fn build(self) -> Input {\n        self.input\n    }\n}\n",
    );
    let _ = registry;
    out
}

/// Renders `generated/dto/ops/mod.rs`.
pub fn ops_mod(operations: &[&OperationIr]) -> String {
    let mut out = String::from(LICENSE);
    out.push_str(
        "\n//! The module-per-operation dto layout.\n\
         //!\n\
         //! Responsible for: mounting one module per generated operation, plus the two shared\n\
         //! vocabulary modules every operation points at.\n\
         //! NOT responsible for: the flat aliases, which are `crate::dto`.\n\
         //! Upstream: `cargo xtask codegen`. Downstream: `rustfs-gateway-types`.\n\n\
         pub mod enums;\n\
         pub mod shapes;\n\n",
    );
    for ir in operations {
        let _ = writeln!(out, "pub mod {};", naming::module_name(&ir.operation));
    }
    out
}

/// Renders `generated/dto/flat.rs`, the migration-compatible alias surface.
pub fn flat(operations: &[&OperationIr], registry: &Registry) -> String {
    let mut out = String::from(LICENSE);
    out.push_str(
        "\n//! Flat aliases for every generated type.\n\
         //!\n\
         //! Responsible for: one `<Operation>Input` / `<Operation>Output` name per operation, so that\n\
         //! `grep GetObjectInput` finds something and an existing `use s3s::dto::…` line migrates by\n\
         //! changing the crate name alone.\n\
         //! NOT responsible for: declaring any type. Every name here is an alias of a type declared\n\
         //! under `crate::ops`, so the two spellings can never drift apart.\n\
         //! Upstream: `crate::ops`. Downstream: every consumer mid-migration.\n\n",
    );
    if !registry.enums.is_empty() {
        out.push_str(&use_group("crate::ops::enums", &registry.enums.keys().cloned().collect::<Vec<_>>()));
    }
    if !registry.shapes.is_empty() {
        out.push_str(&use_group("crate::ops::shapes", &registry.shapes.keys().cloned().collect::<Vec<_>>()));
    }
    out.push('\n');
    for ir in operations {
        let module = naming::module_name(&ir.operation);
        let marker = naming::type_name(&ir.operation);
        out.push_str(&use_group(
            &format!("crate::ops::{module}"),
            &[
                marker.clone(),
                format!("Input as {marker}Input"),
                format!("InputBuilder as {marker}InputBuilder"),
                format!("Output as {marker}Output"),
            ],
        ));
    }
    out
}

fn selected(fields: &[Field], predicate: impl Fn(&Field) -> bool) -> Vec<String> {
    fields.iter().filter(|f| predicate(f)).map(|f| f.name.clone()).collect()
}
