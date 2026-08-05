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

//! Reverse tracing: why is this behaviour the way it is?
//!
//! Responsible for: turning a quirk id, an operation, an error code, a header or a query key into
//! the evidence behind it — the source links, the conformance cases, and who else is affected.
//! NOT responsible for: generating anything.
//! Upstream: the IR documents. Downstream: `cargo xtask why`.
//!
//! This exists because `git blame` cannot answer the question. Squash-merges erase the trail, and
//! a `git log -S` plus three commit reads costs an agent more context than the answer is worth.
//! The evidence therefore lives beside the rule, and this command is how it is read back.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use s3gate_model::ir::{Binding, Evidence, OperationIr, Quirk};

use crate::{Error, Result};

/// What the argument turned out to name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhyTarget {
    /// A quirk id.
    Quirk(String),
    /// An operation name.
    Operation(String),
    /// An error code.
    ErrorCode(String),
    /// A header name.
    Header(String),
    /// A query key.
    QueryKey(String),
}

/// Resolves an argument against every namespace and renders the answer as Markdown.
///
/// Fails with the closest candidates when nothing matches; returning an empty answer would let a
/// typo read as "this behaviour has no reason", which is the one outcome worth ruling out.
pub fn why(operations: &[OperationIr], argument: &str) -> Result<String> {
    let targets = resolve(operations, argument);
    if targets.is_empty() {
        let candidates = nearest(operations, argument);
        return Err(Error::NotFound(format!(
            "`{argument}` is not a known quirk id, operation, error code, header or query key.\n\
             Closest candidates: {}",
            if candidates.is_empty() {
                "none".to_owned()
            } else {
                candidates.join(", ")
            }
        )));
    }
    let mut out = String::new();
    for target in targets {
        match target {
            WhyTarget::Quirk(id) => render_quirk(&mut out, operations, &id),
            WhyTarget::Operation(name) => render_operation(&mut out, operations, &name),
            WhyTarget::ErrorCode(code) => render_error_code(&mut out, operations, &code),
            WhyTarget::Header(header) => render_header(&mut out, operations, &header),
            WhyTarget::QueryKey(key) => render_query_key(&mut out, operations, &key),
        }
    }
    Ok(out)
}

fn resolve(operations: &[OperationIr], argument: &str) -> Vec<WhyTarget> {
    let mut targets = Vec::new();
    if operations.iter().any(|ir| ir.quirks.iter().any(|q| q.id == argument)) {
        targets.push(WhyTarget::Quirk(argument.to_owned()));
    }
    if let Some(ir) = operations.iter().find(|ir| ir.operation.eq_ignore_ascii_case(argument)) {
        targets.push(WhyTarget::Operation(ir.operation.clone()));
    }
    if operations.iter().any(|ir| ir.errors.codes.iter().any(|c| c == argument)) {
        targets.push(WhyTarget::ErrorCode(argument.to_owned()));
    }
    let lower = argument.to_lowercase();
    if operations.iter().any(|ir| ir.headers().contains(&lower)) {
        targets.push(WhyTarget::Header(lower.clone()));
    }
    if operations.iter().any(|ir| ir.query_keys().contains(&argument.to_owned())) {
        targets.push(WhyTarget::QueryKey(argument.to_owned()));
    }
    targets
}

fn render_quirk(out: &mut String, operations: &[OperationIr], id: &str) {
    let Some(quirk) = operations.iter().find_map(|ir| ir.quirks.iter().find(|q| q.id == id)) else {
        return;
    };
    let users: Vec<&str> = operations
        .iter()
        .filter(|ir| ir.referenced_quirk_ids().iter().any(|q| q == id))
        .map(|ir| ir.operation.as_str())
        .collect();

    let _ = writeln!(out, "## Quirk `{}`\n", quirk.id);
    let _ = writeln!(out, "- kind: `{}`", quirk.kind);
    let _ = writeln!(out, "- target: `{}`", quirk.target);
    let _ = writeln!(out, "- operations: {}", users.join(", "));
    let _ = writeln!(out, "\n{}\n", quirk.summary);
    render_evidence(out, quirk);
    let _ = writeln!(
        out,
        "\n**Conformance cases** (each would fail if the quirk were flipped)\n\n{}",
        quirk.cases.iter().map(|c| format!("- `{c}`")).collect::<Vec<_>>().join("\n")
    );
    let _ = writeln!(
        out,
        "\n**Governing decisions**: `docs/adr/0001-licensing-and-provenance-boundary.md` (evidence is a URL plus a\n\
         self-written sentence, never upstream prose), `model/overlays/aws-quirks.toml` (the entry itself).\n"
    );
}

fn render_evidence(out: &mut String, quirk: &Quirk) {
    let _ = writeln!(out, "**Evidence**\n");
    for e in &quirk.evidence {
        let _ = writeln!(out, "- [{}] {} — {}", e.kind, render_reference(e), e.summary);
    }
}

/// Renders an evidence reference as something clickable or openable.
///
/// The `s3s-issue` / `s3s-pr` kinds record a number or a URL and nothing else: upstream issue
/// prose stays under its author's copyright, so the repository stores a link plus our own
/// sentence. Never paste the issue text.
pub fn render_reference(e: &Evidence) -> String {
    let reference = e.reference.trim();
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return reference.to_owned();
    }
    match e.kind.as_str() {
        "s3s-issue" => format!("https://github.com/s3s-project/s3s/issues/{reference}"),
        "s3s-pr" => format!("https://github.com/s3s-project/s3s/pull/{reference}"),
        _ => reference.to_owned(),
    }
}

fn render_operation(out: &mut String, operations: &[OperationIr], name: &str) {
    let Some(ir) = operations.iter().find(|ir| ir.operation == name) else {
        return;
    };
    let _ = writeln!(out, "## Operation `{}`\n", ir.operation);
    let _ = writeln!(
        out,
        "`{} {}` &rarr; {} · precedence {} · action `{}`\n",
        ir.http.method.as_str(),
        ir.http.path_shape,
        ir.http.success_status,
        ir.http.precedence,
        ir.auth.action
    );
    let _ = writeln!(out, "- shape and wire index: `OPERATIONS.md#{}`", ir.operation.to_lowercase());
    let _ = writeln!(out, "- field bindings: `spec/operations/{}.toml`", ir.operation);
    let quirks = ir.referenced_quirk_ids();
    if quirks.is_empty() {
        let _ = writeln!(out, "- quirks: none\n");
    } else {
        let _ = writeln!(
            out,
            "- quirks: {}\n",
            quirks.iter().map(|q| format!("`{q}`")).collect::<Vec<_>>().join(", ")
        );
        for id in quirks {
            render_quirk(out, operations, &id);
        }
    }
}

fn render_error_code(out: &mut String, operations: &[OperationIr], code: &str) {
    let producers: Vec<&str> = operations
        .iter()
        .filter(|ir| ir.errors.codes.iter().any(|c| c == code))
        .map(|ir| ir.operation.as_str())
        .collect();
    let _ = writeln!(out, "## Error code `{code}`\n");
    let _ = writeln!(out, "Produced by: {}\n", producers.join(", "));
    for ir in operations {
        if ir.errors.not_configured.as_deref() == Some(code) {
            let _ = writeln!(out, "- `{}` returns it when the subresource was never configured", ir.operation);
        }
        for field in &ir.input {
            if field.missing_error.as_deref() == Some(code) {
                let _ = writeln!(
                    out,
                    "- `{}` returns it when the required field `{}` (`{}`) is absent",
                    ir.operation,
                    field.name,
                    field.wire_name.as_deref().unwrap_or("-")
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "\nThe code to HTTP status mapping lives in `s3gate-types::ErrorCode`, not in generated code.\n"
    );
}

fn render_header(out: &mut String, operations: &[OperationIr], header: &str) {
    let _ = writeln!(out, "## Header `{header}`\n");
    for ir in operations {
        for (side, fields) in [("request", &ir.input), ("response", &ir.output)] {
            for field in fields.iter().filter(|f| f.wire_name.as_deref() == Some(header)) {
                let prefix = if field.binding == Binding::PrefixHeaders {
                    " (prefix family)"
                } else {
                    ""
                };
                let _ = writeln!(
                    out,
                    "- `{}` {side} field `{}`{prefix}, required {}, quirks {}",
                    ir.operation,
                    field.name,
                    field.required,
                    if field.quirk_refs.is_empty() {
                        "none".to_owned()
                    } else {
                        field.quirk_refs.join(", ")
                    }
                );
            }
        }
    }
    let _ = writeln!(out);
}

fn render_query_key(out: &mut String, operations: &[OperationIr], key: &str) {
    let _ = writeln!(out, "## Query key `{key}`\n");
    for ir in operations {
        if ir.query_keys().contains(&key.to_owned()) {
            let routed = ir.http.predicates.iter().any(|p| {
                use s3gate_model::ir::Predicate::*;
                matches!(p, QueryPresent(k) | QueryAbsent(k) | QueryEquals(k, _) if k == key)
            });
            let _ = writeln!(
                out,
                "- `{}`: {}",
                ir.operation,
                if routed { "route predicate" } else { "request parameter" }
            );
        }
    }
    let _ = writeln!(out);
}

fn nearest(operations: &[OperationIr], argument: &str) -> Vec<String> {
    let mut universe: BTreeSet<String> = BTreeSet::new();
    for ir in operations {
        universe.insert(ir.operation.clone());
        universe.extend(ir.errors.codes.iter().cloned());
        universe.extend(ir.headers());
        universe.extend(ir.query_keys());
        universe.extend(ir.quirks.iter().map(|q| q.id.clone()));
    }
    let needle = argument.to_lowercase();
    let mut scored: Vec<(usize, String)> = universe
        .into_iter()
        .map(|candidate| (distance(&needle, &candidate.to_lowercase()), candidate))
        .collect();
    scored.sort();
    scored.into_iter().take(3).map(|(_, c)| c).collect()
}

/// Levenshtein distance, two rows at a time.
fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            current[j + 1] = (previous[j] + cost).min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[b.len()]
}
