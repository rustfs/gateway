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

//! The two shared vocabulary trees: `ops::enums` and `ops::shapes`.
//!
//! Responsible for: rendering every string enumeration as a `Cow` newtype with associated
//! constants (ADR-0004 P4), every nested structure as a plain struct, and every structural union
//! as a real `enum` with `#[non_exhaustive]` (P5) — one file per type, with a `mod.rs` that
//! re-exports them flat.
//! NOT responsible for: deciding which of them exist — that is [`super::registry`].
//! Upstream: [`super::registry`]. Downstream: every generated operation module.
//!
//! The two attributes are deliberately opposite. A downstream consumer *constructs* a dto, so
//! `#[non_exhaustive]` there would reject `..Default::default()` (E0639). It only ever *matches*
//! on a union, so the attribute is correct there and nowhere else.
//!
//! One type per file for the same reason the operations get one file each: `LocationConstraint`
//! alone declares 38 constants, and a single `enums.rs` would pass the 800-line ceiling long
//! before the operation whitelist is complete.

use std::fmt::Write as _;

use s3gate_model::ir::ShapeKind;

use super::registry::{EnumDef, Registry, ShapeDef};
use super::{DtoReport, LICENSE, debug_impl, derives, field_decl, naming, registry};

/// Renders `ops/enums/mod.rs` plus one file per string enumeration.
pub fn enums(registry: &Registry, report: &mut DtoReport) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut facade = String::from(LICENSE);
    facade.push_str(
        "\n//! The open string enumerations the operations bind.\n\
         //!\n\
         //! Responsible for: mounting one newtype over `Cow<'static, str>` per S3 string\n\
         //! enumeration, and re-exporting them flat so that `crate::ops::enums::StorageClass` is the\n\
         //! one spelling everything else uses.\n\
         //! NOT responsible for: validating that a value is acceptable for a given operation — an\n\
         //! unknown value is representable on purpose.\n\
         //! Upstream: `cargo xtask codegen`. Downstream: the generated dto and its codecs.\n\
         //!\n\
         //! # Why none of these is an `enum`\n\
         //!\n\
         //! AWS adds values to these sets continuously. A real `enum` would force a `_ =>` arm into\n\
         //! every consumer and make each new value a breaking change; a newtype with associated\n\
         //! constants turns the same event into a one-line minor bump (ADR-0004 P4). Known values\n\
         //! cost no allocation, and an unknown one stays a first-class value instead of a parse\n\
         //! failure. Note that `crate::ChecksumAlgorithm` is a different thing: it is the closed set\n\
         //! this implementation can actually compute, while `enums::ChecksumAlgorithm` is whatever\n\
         //! the wire may carry.\n\n",
    );
    for def in registry.enums.values() {
        let module = naming::module_name(&def.name);
        let _ = writeln!(facade, "mod {module};");
        files.push((format!("{module}.rs"), string_enum(def)));
        report.string_enums += 1;
    }
    facade.push('\n');
    for def in registry.enums.values() {
        let _ = writeln!(facade, "pub use self::{}::{};", naming::module_name(&def.name), def.name);
    }
    files.push(("mod.rs".to_owned(), facade));
    files
}

fn string_enum(def: &EnumDef) -> String {
    let name = &def.name;
    let sources = def.sources.iter().cloned().collect::<Vec<_>>().join(", ");
    let mut out = String::from(LICENSE);
    let _ = write!(
        out,
        "\n//! The `{name}` string enumeration.\n\
         //!\n\
         //! Responsible for: one open value set, as a newtype with one constant per value the\n\
         //! pinned model declares.\n\
         //! NOT responsible for: deciding which values an operation accepts.\n\
         //! Upstream: `cargo xtask codegen`. Downstream: `crate::ops::enums`.\n\n\
         use std::borrow::Cow;\n\n\
         /// The `{name}` string enumeration. Bound by: {sources}.\n\
         ///\n\
         /// An open set: compare against the associated constants, and build a value the pinned\n\
         /// model does not declare with [`{name}::custom`]. Adding a constant is a minor version\n\
         /// bump, which is the whole reason this is not an `enum` (ADR-0004 P4).\n\
         #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]\n\
         pub struct {name}(Cow<'static, str>);\n\n\
         impl {name} {{\n"
    );
    for value in &def.values {
        let _ = write!(
            out,
            "    /// `{value}`\n    pub const {}: Self = Self(Cow::Borrowed(\"{value}\"));\n",
            naming::const_name(value)
        );
    }
    let values = super::slice_literal(&def.values.iter().map(|v| format!("\"{v}\"")).collect::<Vec<_>>(), 4);
    let _ = write!(
        out,
        "\n    /// Every value the pinned model declares, in model order.\n    \
             pub const VALUES: &'static [&'static str] = {values};\n\n    \
             /// Wraps a value this build has no constant for.\n    \
             #[must_use]\n    \
             pub fn custom(value: impl Into<Cow<'static, str>>) -> Self {{\n        Self(value.into())\n    }}\n\n    \
             /// The wire spelling.\n    \
             #[must_use]\n    \
             pub fn as_str(&self) -> &str {{\n        &self.0\n    }}\n\n    \
             /// Whether the value is one the pinned model declares.\n    \
             #[must_use]\n    \
             pub fn is_known(&self) -> bool {{\n        Self::VALUES.contains(&self.as_str())\n    }}\n\
         }}\n\n\
         impl From<&'static str> for {name} {{\n    \
             fn from(value: &'static str) -> Self {{\n        Self(Cow::Borrowed(value))\n    }}\n\
         }}\n\n\
         impl std::fmt::Display for {name} {{\n    \
             fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n        \
                 f.write_str(&self.0)\n    }}\n\
         }}\n"
    );
    out
}

/// Renders `ops/shapes/mod.rs` plus one file per nested shape.
pub fn shapes(registry: &Registry, report: &mut DtoReport) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut facade = String::from(LICENSE);
    facade.push_str(
        "\n//! The nested body shapes the operations share.\n\
         //!\n\
         //! Responsible for: mounting one Rust type per nested Smithy structure or union reachable\n\
         //! from a generated operation, declared once however many operations reach it, and\n\
         //! re-exporting them flat.\n\
         //! NOT responsible for: the XML element order and empty-value policy that decide how these\n\
         //! are written — those live in `spec/operations/<Op>.toml`.\n\
         //! Upstream: `cargo xtask codegen`. Downstream: the generated dto and its codecs.\n\n",
    );
    for def in registry.shapes.values() {
        let module = naming::module_name(&def.name);
        let _ = writeln!(facade, "mod {module};");
        let body = match def.kind {
            ShapeKind::Structure => {
                report.structs += 1;
                structure(def, registry, report)
            }
            ShapeKind::Union => {
                report.structural_enums += 1;
                union(def, registry)
            }
        };
        files.push((format!("{module}.rs"), body));
    }
    facade.push('\n');
    for def in registry.shapes.values() {
        let _ = writeln!(facade, "pub use self::{}::{};", naming::module_name(&def.name), def.name);
    }
    files.push(("mod.rs".to_owned(), facade));
    files
}

fn shape_header(name: &str, what: &str) -> String {
    format!(
        "\n//! The `{name}` {what}.\n\
         //!\n\
         //! Responsible for: one nested body shape, declared once for every operation that reaches\n\
         //! it.\n\
         //! NOT responsible for: how it is written to the wire.\n\
         //! Upstream: `cargo xtask codegen`. Downstream: `crate::ops::shapes`.\n\n"
    )
}

fn structure(def: &ShapeDef, registry: &Registry, report: &mut DtoReport) -> String {
    let name = &def.name;
    let sources = def.sources.iter().cloned().collect::<Vec<_>>().join(", ");
    let clonable = def.fields.iter().all(|f| registry.is_clonable(&f.ty));
    let has_secret = def.fields.iter().any(registry::is_redacted);

    let mut out = String::from(LICENSE);
    out.push_str(&shape_header(name, "body shape"));
    let _ = write!(
        out,
        "/// The `{name}` body shape. Reached from: {sources}.\n\
         ///\n\
         /// Public fields plus `Default`, and never `#[non_exhaustive]` — ADR-0004 P1. Do not\n\
         /// destructure it exhaustively (P3).\n"
    );
    out.push_str(&derives(clonable, has_secret));
    let _ = writeln!(out, "pub struct {name} {{");
    for field in &def.fields {
        out.push_str(&field_decl(field));
    }
    out.push_str("}\n");
    if has_secret {
        out.push('\n');
        out.push_str(&debug_impl(name, &def.fields));
    }
    report.field_counts.insert(name.clone(), def.fields.len());
    out
}

fn union(def: &ShapeDef, registry: &Registry) -> String {
    let name = &def.name;
    let sources = def.sources.iter().cloned().collect::<Vec<_>>().join(", ");
    let clonable = def.fields.iter().all(|f| registry.is_clonable(&f.ty));

    let mut out = String::from(LICENSE);
    out.push_str(&shape_header(name, "structural union"));
    let _ = write!(
        out,
        "/// The `{name}` structural union. Reached from: {sources}.\n\
         ///\n\
         /// `#[non_exhaustive]` on purpose, and a union is the only shape that carries it: a\n\
         /// consumer matches on one but never constructs one, so a new variant is a minor bump here\n\
         /// while the same attribute on a dto struct would reject `..Default::default()`\n\
         /// (ADR-0004 P5).\n"
    );
    out.push_str(if clonable {
        "#[derive(Debug, Clone)]\n#[non_exhaustive]\n"
    } else {
        "#[derive(Debug)]\n#[non_exhaustive]\n"
    });
    let _ = writeln!(out, "pub enum {name} {{");
    for field in &def.fields {
        let _ = write!(
            out,
            "    /// {}\n    {}({}),\n",
            super::field_doc(field),
            naming::type_name(&field.name),
            Registry::type_with_enums(&field.ty, &field.name)
        );
    }
    out.push_str("}\n");
    out
}
