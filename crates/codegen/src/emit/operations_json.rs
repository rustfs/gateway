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

//! `generated/OPERATIONS.json`: the machine-readable half of the wire reverse index.
//!
//! Responsible for: seven wire facts per operation, and one index inverting each of them.
//! NOT responsible for: the human rendering (`operations_md`), field-level bindings
//! (`spec/operations/<Op>.toml`), or any fact this file does not already read out of the IR.
//! Upstream: [`rustfs_gateway_model::ir`]. Downstream: tools that start from wire evidence.
//!
//! # Why a second rendering of the same facts
//!
//! `OPERATIONS.md` is what an agent reads; a Markdown table is what a program has to guess at.
//! The seven fields here are the ones a failing request hands you — a method, a path shape, a
//! query key, a header, a host-class constraint, an error code, a position in the ordered table —
//! and each is a key you can enter the document by. Both files are emitted from the same IR in
//! the same run, so neither can drift without `cargo xtask spec verify` saying so, and
//! `OPERATIONS.md` stays the file a human or an agent reads: this one is under `generated/`,
//! which `AGENTS.md` puts on the do-not-read list, precisely because it is for programs.
//!
//! It has no in-repository consumer today beyond its own guard. That is stated rather than
//! dressed up: the file is the artefact `rustfs/backlog#1693` specifies, and the first tool that
//! needs to go from wire evidence to an operation without parsing Markdown is what it is for.

use std::collections::BTreeMap;

use rustfs_gateway_model::ir::{OperationIr, Predicate};
use rustfs_gateway_model::json::{self, Value};

use super::operations_md::key_headers;

/// The seven wire fields every operation entry carries, in the order they are written.
///
/// The order is the field order of an entry, and the guard
/// `scripts/check_operations_json_fields.sh` asserts it: a consumer that read the fields
/// positionally would be reading a different document after a silent reorder.
pub const FIELDS: [&str; 7] = [
    "method",
    "path_shape",
    "query_keys",
    "key_headers",
    "host_classes",
    "error_codes",
    "precedence",
];

/// The index inverting each field, in the same order.
pub const INDEXES: [&str; 7] = [
    "by_method",
    "by_path_shape",
    "by_query_key",
    "by_key_header",
    "by_host_class",
    "by_error_code",
    "by_precedence",
];

/// One operation's seven wire facts.
///
/// A named struct rather than a tuple because the reverse indexes are built from it and tested
/// against synthetic values: the pinned model constrains no operation's host class, so a set
/// this emitter can only ever compute one way is a set nothing proves is computed at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The operation name; the key of the forward table.
    pub operation: String,
    /// The request method.
    pub method: String,
    /// The reverse-index path shape.
    pub path_shape: String,
    /// Every query key the operation routes on or reads.
    pub query_keys: Vec<String>,
    /// The headers with protocol weight. A name ending in `-` is a prefix family, not a header.
    pub key_headers: Vec<String>,
    /// The endpoint families the selector constrains the operation to; empty means unconstrained.
    pub host_classes: Vec<String>,
    /// The error codes the overlays declare for this operation.
    ///
    /// Operation-scoped, so it is not every code a request to this operation can be answered with:
    /// signature, skew and admission refusals happen before an operation is selected and belong to
    /// no operation.
    pub error_codes: Vec<String>,
    /// Position in the ordered first-match table; lower is tried first.
    pub precedence: u32,
}

/// The seven facts of one lowered operation.
pub fn entry(ir: &OperationIr) -> Entry {
    Entry {
        operation: ir.operation.clone(),
        method: ir.http.method.as_str().to_owned(),
        path_shape: ir.http.path_shape.clone(),
        query_keys: ir.query_keys(),
        key_headers: key_headers(ir),
        host_classes: host_classes(ir),
        error_codes: ir.errors.codes.clone(),
        precedence: ir.http.precedence,
    }
}

/// Renders the document for the whole generated set.
pub fn render(operations: &[OperationIr]) -> String {
    let entries: Vec<Entry> = operations.iter().map(entry).collect();
    render_entries(&entries)
}

/// Renders the document from already-derived entries.
pub fn render_entries(entries: &[Entry]) -> String {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.operation.cmp(&b.operation));

    let mut forward: Vec<(String, Value)> = Vec::with_capacity(sorted.len());
    let mut indexes: Vec<(String, BTreeMap<String, Vec<String>>)> =
        INDEXES.iter().map(|name| ((*name).to_owned(), BTreeMap::new())).collect();

    for entry in &sorted {
        let mut members: Vec<(String, Value)> = Vec::with_capacity(FIELDS.len());
        for (position, (name, value, keys)) in wire_fields(entry).into_iter().enumerate() {
            members.push((name.to_owned(), value));
            let Some((_, inverted)) = indexes.get_mut(position) else {
                continue;
            };
            for key in keys {
                let operations = inverted.entry(key).or_default();
                if !operations.contains(&entry.operation) {
                    operations.push(entry.operation.clone());
                }
            }
        }
        forward.push((entry.operation.clone(), Value::Object(members)));
    }

    let mut document: Vec<(String, Value)> = vec![
        ("generated_by".to_owned(), Value::Str("cargo xtask codegen".to_owned())),
        ("note".to_owned(), Value::Str(NOTE.to_owned())),
        ("operations".to_owned(), Value::Object(forward)),
    ];
    for (name, inverted) in indexes {
        document.push((
            name,
            Value::Object(
                inverted
                    .into_iter()
                    .map(|(key, mut operations)| {
                        operations.sort();
                        (key, list(&operations))
                    })
                    .collect(),
            ),
        ));
    }
    json::write_canonical(&Value::Object(document))
}

/// What the document says about itself.
const NOTE: &str = "Generated from the pinned model and model/overlays by `cargo xtask codegen`; \
                    edit an overlay and regenerate, never this file. OPERATIONS.md is the same \
                    facts for a human reader. `host_classes` is the constraint the route selector \
                    carries, not a reachability set, and is empty for every operation today. A \
                    `key_headers` entry ending in `-` is a header prefix family, not a header name.";

/// One row per wire field: its name, its rendered value, and the index keys it contributes.
///
/// `FIELDS` and `INDEXES` are the same seven, in the same order, and this is the only place a
/// field's value and its inversion are written down. Declaring them apart is how an index comes to
/// be built from the wrong field — the shape `check_operations_json_fields.sh` looks for in the
/// artefact, prevented here in the producer.
fn wire_fields(entry: &Entry) -> [(&'static str, Value, Vec<String>); 7] {
    [
        ("method", Value::Str(entry.method.clone()), vec![entry.method.clone()]),
        ("path_shape", Value::Str(entry.path_shape.clone()), vec![entry.path_shape.clone()]),
        ("query_keys", list(&entry.query_keys), entry.query_keys.clone()),
        ("key_headers", list(&entry.key_headers), entry.key_headers.clone()),
        ("host_classes", list(&entry.host_classes), entry.host_classes.clone()),
        ("error_codes", list(&entry.error_codes), entry.error_codes.clone()),
        ("precedence", Value::Int(i64::from(entry.precedence)), vec![entry.precedence.to_string()]),
    ]
}

/// The field names [`wire_fields`] actually produces, for the test that holds `FIELDS` to them.
#[cfg(test)]
pub(crate) fn rendered_field_names(entry: &Entry) -> Vec<&'static str> {
    wire_fields(entry).into_iter().map(|(name, _, _)| name).collect()
}

/// The host-class constraints this operation's route selector carries.
///
/// Empty means the selector names no endpoint family — **not** that no endpoint family reaches the
/// operation. The distinction is the whole point of reporting the constraint rather than a
/// reachability set: reachability also depends on which endpoint families this build serves at
/// all, which is a dialect decision (`crates/core/src/dialect/overlay.rs` reserves four of the
/// seven), and codegen cannot see it. Emitting "reachable on all seven" from here would state the
/// opposite of what that layer enforces.
///
/// Every entry is empty today, and that is a fact about the pinned model rather than a placeholder:
/// `rustfs-gateway-model`'s [`Predicate`] has no `HostClass` variant (`rustfs/gateway#3`), so no
/// operation can carry the constraint. The `match` below is exhaustive so that adding the variant
/// does not compile until this function decides what it means.
fn host_classes(ir: &OperationIr) -> Vec<String> {
    let mut constraints: Vec<String> = ir
        .http
        .predicates
        .iter()
        .filter_map(|predicate| match predicate {
            Predicate::Method(_)
            | Predicate::Target(_)
            | Predicate::QueryPresent(_)
            | Predicate::QueryEquals(..)
            | Predicate::QueryAbsent(_)
            | Predicate::HeaderPresent { .. }
            | Predicate::HeaderPrefix { .. }
            | Predicate::PathLiteral(_) => None,
        })
        .collect();
    constraints.sort();
    constraints.dedup();
    constraints
}

fn list(items: &[String]) -> Value {
    Value::Array(items.iter().map(|item| Value::Str(item.clone())).collect())
}
