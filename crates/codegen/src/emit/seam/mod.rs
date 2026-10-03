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

//! `generated/dto/seam/**`: the migration seam's s3s conversions for every RustFS operation.
//!
//! Responsible for: one module per covered operation — `input_to_s3s` (gateway input → s3s input)
//! and `output_from_s3s` (s3s output → gateway output) — and one module per nested shape either
//! direction reaches, mounted by `rustfs-gateway-types` as `compat::s3s_0_17_0::generated` and
//! converting against that module's `s3s` and hand-written `leaf` functions.
//! NOT responsible for: request context, errors, or the hand-written operations
//! ([`overrides::HAND_WRITTEN`]).
//! Upstream: the IR and [`facts`]. Downstream: the RustFS ring-2 adapter (rustfs/backlog#1752,
//! rustfs/gateway#967). Deleted by P9-09 with the rest of `compat-s3s`.
//!
//! # The one rule
//!
//! A gateway member converts into the s3s member of the same name, through the pairing table in
//! [`expr`]. The exceptions are the checksum fan-out (one gateway `ChecksumSpec` against the
//! per-algorithm s3s members), s3s runtime members with no wire value, and the reviewed
//! [`overrides::MEMBERS`]. Anything else fails generation naming the member: a dropped member is
//! a decision, never a default. s3s structs are built and destructured exhaustively, so an s3s
//! re-pin that adds a member is a compile error until the fact file and this table say what it is.

pub mod census;
pub mod expr;
pub mod facts;
pub mod overrides;
mod render;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rustfs_gateway_model::ir::{OperationIr, Shape};

use expr::Ctx;
use facts::S3sFacts;

/// The s3s release RustFS links, as facts.
const FACTS: &str = include_str!("s3s_0_17_0.facts");

/// The legacy stack's DTO facts, parsed once: each structure's members in the order the legacy
/// stack declares them, which is the order it writes them in — the codec's legacy response layout
/// (rustfs/gateway#1078) reads it from here.
///
/// # Errors
///
/// The checked-in fact file does not parse.
pub fn legacy_facts() -> Result<&'static S3sFacts, String> {
    static PARSED: std::sync::OnceLock<Result<S3sFacts, String>> = std::sync::OnceLock::new();
    PARSED.get_or_init(|| S3sFacts::parse(FACTS)).as_ref().map_err(Clone::clone)
}

/// Renders every seam artefact.
///
/// # Errors
///
/// A covered operation missing from the IR or from the s3s facts, or any member the pairing
/// table and the override table leave undecided — all listed at once.
pub fn emit(operations: &[OperationIr], generated_dir: &Path) -> Result<Vec<(PathBuf, String)>, String> {
    let facts = S3sFacts::parse(FACTS)?;
    let ctx = Ctx {
        facts: &facts,
        reached: Default::default(),
        supplied: Default::default(),
    };
    let by_name: BTreeMap<&str, &OperationIr> = operations.iter().map(|ir| (ir.operation.as_str(), ir)).collect();
    let mut shapes: BTreeMap<&str, &Shape> = BTreeMap::new();
    for ir in operations {
        for (name, shape) in &ir.shapes {
            shapes.entry(name.as_str()).or_insert(shape);
        }
    }
    let dir = generated_dir.join("dto").join("seam");
    let mut files = Vec::new();
    let mut errors = Vec::new();
    let mut modules = Vec::new();
    for operation in overrides::OPERATIONS {
        if overrides::HAND_WRITTEN.iter().any(|(name, _)| name == operation) {
            continue;
        }
        let Some(ir) = by_name.get(operation) else {
            errors.push(format!("{operation}: not in the IR"));
            continue;
        };
        match render::operation(&ctx, ir) {
            Ok((module, body)) => {
                files.push((dir.join("ops").join(format!("{module}.rs")), body));
                modules.push(module);
            }
            Err(mut found) => errors.append(&mut found),
        }
    }
    // Shapes reach further shapes; iterate to the fixed point.
    let mut rendered: BTreeMap<(String, bool), ()> = BTreeMap::new();
    let mut shape_modules: BTreeMap<String, Vec<String>> = BTreeMap::new();
    loop {
        let pending: Vec<(String, bool)> = {
            let reached = ctx.reached.borrow();
            reached
                .forward
                .iter()
                .map(|name| (name.clone(), true))
                .chain(reached.backward.iter().map(|name| (name.clone(), false)))
                .filter(|key| !rendered.contains_key(key))
                .collect()
        };
        if pending.is_empty() {
            break;
        }
        for (name, forward) in pending {
            rendered.insert((name.clone(), forward), ());
            let Some(shape) = shapes.get(name.as_str()) else {
                errors.push(format!("shape {name}: not in the IR"));
                continue;
            };
            match render::shape_fn(&ctx, &name, shape, forward) {
                Ok(body) => shape_modules.entry(name).or_default().push(body),
                Err(mut found) => errors.append(&mut found),
            }
        }
    }
    if !errors.is_empty() {
        errors.sort();
        errors.dedup();
        return Err(format!(
            "seam: {} member(s) have no conversion; decide each in crates/codegen/src/emit/seam/overrides.rs:\n  {}",
            errors.len(),
            errors.join("\n  ")
        ));
    }
    let mut shape_names = Vec::new();
    for (name, bodies) in shape_modules {
        let module = crate::emit::dto::naming::module_name(&name);
        files.push((dir.join("shapes").join(format!("{module}.rs")), render::shape_file(&name, &bodies)));
        shape_names.push(module);
    }
    files.extend(census::emit(&facts, overrides::OPERATIONS, &dir.join("census"))?);
    files.push((dir.join("ops").join("mod.rs"), render::facade("ops", &modules)));
    files.push((dir.join("shapes").join("mod.rs"), render::facade("shapes", &shape_names)));
    files.push((dir.join("mod.rs"), render::root()));
    Ok(files)
}
