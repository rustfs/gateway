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

//! The semantic diff: what changed on the wire, not what changed in the bytes.
//!
//! Responsible for: reducing a regeneration to the handful of dimensions a reviewer must actually
//! look at — operations, route selectors, field optionality and binding, XML names and order,
//! error codes.
//! NOT responsible for: byte-level drift, which is [`crate::verify`]'s job.
//! Upstream: the IR documents under `generated/ir/`. Downstream: the PR body.
//!
//! A twenty-line semantic summary is reviewable; forty thousand lines of generated `impl` are not.
//! That asymmetry is the whole reason this module exists.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use rustfs_gateway_model::json::{self, Value};

use crate::golden;
use crate::{Error, Result, io};

/// The wire dimension a change falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dimension {
    /// An operation appeared.
    OperationAdded,
    /// An operation disappeared.
    OperationRemoved,
    /// Method, target, precedence or a route predicate moved.
    RouteSelector,
    /// A field became required or optional.
    Optionality,
    /// A field's binding or wire name moved.
    Binding,
    /// A field's type changed.
    FieldType,
    /// A field appeared or disappeared.
    FieldSet,
    /// An XML root, element order or empty-value policy moved.
    Xml,
    /// The error surface moved.
    ErrorCodes,
    /// Anything else the IR carries.
    Other,
}

impl Dimension {
    /// A heading for the summary.
    pub fn title(self) -> &'static str {
        match self {
            Dimension::OperationAdded => "operations added",
            Dimension::OperationRemoved => "operations removed",
            Dimension::RouteSelector => "route selectors",
            Dimension::Optionality => "field optionality",
            Dimension::Binding => "field bindings and wire names",
            Dimension::FieldType => "field types",
            Dimension::FieldSet => "fields added or removed",
            Dimension::Xml => "xml names, order and empty-value policy",
            Dimension::ErrorCodes => "error codes",
            Dimension::Other => "other",
        }
    }
}

/// One classified change.
#[derive(Debug, Clone)]
pub struct Change {
    /// Operation the change belongs to.
    pub operation: String,
    /// Which wire dimension moved.
    pub dimension: Dimension,
    /// Human-readable detail.
    pub detail: String,
}

/// The whole diff.
#[derive(Debug, Default)]
pub struct SemanticDiff {
    /// Every classified change, sorted by dimension then operation.
    pub changes: Vec<Change>,
}

impl SemanticDiff {
    /// Whether anything on the wire moved.
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The Markdown summary that belongs in a PR body.
    pub fn render(&self) -> String {
        if self.is_empty() {
            return "No wire-affecting change.\n".to_owned();
        }
        let mut out = String::from("### Semantic diff\n\n");
        let mut current: Option<Dimension> = None;
        for change in &self.changes {
            if current != Some(change.dimension) {
                let _ = writeln!(out, "**{}**\n", change.dimension.title());
                current = Some(change.dimension);
            }
            let _ = writeln!(out, "- `{}`: {}", change.operation, change.detail);
        }
        out
    }
}

/// Loads every `<Op>.json` in a directory. A missing directory reads as an empty set, which is
/// what makes the first run's diff "everything added" rather than an error.
pub fn load_ir_dir(dir: &Path) -> Result<BTreeMap<String, Value>> {
    let mut out = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for entry in entries {
        let entry = entry.map_err(|e| io(dir, e))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| io(&path, e))?;
        let value = json::parse(&text).map_err(Error::Model)?;
        let name = value
            .get("operation")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| path.file_stem().and_then(|s| s.to_str()).unwrap_or("?").to_owned());
        out.insert(name, value);
    }
    Ok(out)
}

/// Compares two sets of IR documents.
pub fn compare_sets(old: &BTreeMap<String, Value>, new: &BTreeMap<String, Value>) -> SemanticDiff {
    let mut changes = Vec::new();
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for name in names {
        match (old.get(name), new.get(name)) {
            (None, Some(_)) => changes.push(Change {
                operation: name.clone(),
                dimension: Dimension::OperationAdded,
                detail: "new operation".into(),
            }),
            (Some(_), None) => changes.push(Change {
                operation: name.clone(),
                dimension: Dimension::OperationRemoved,
                detail: "operation no longer generated".into(),
            }),
            (Some(a), Some(b)) => {
                for difference in golden::compare(a, b) {
                    changes.push(Change {
                        operation: name.clone(),
                        dimension: classify(&difference.path),
                        detail: format!("{} — was {}, now {}", difference.path, difference.golden, difference.generated),
                    });
                }
            }
            (None, None) => {}
        }
    }
    changes.sort_by(|a, b| (a.dimension, &a.operation).cmp(&(b.dimension, &b.operation)));
    SemanticDiff { changes }
}

fn classify(path: &str) -> Dimension {
    if path.starts_with("http") {
        return Dimension::RouteSelector;
    }
    if path.starts_with("errors") {
        return Dimension::ErrorCodes;
    }
    if path.starts_with("xml") || path.contains(".xml.") {
        return Dimension::Xml;
    }
    if path.ends_with(".required") {
        return Dimension::Optionality;
    }
    if path.contains(".binding") || path.ends_with(".wire_name") {
        return Dimension::Binding;
    }
    if path.contains(".type") {
        return Dimension::FieldType;
    }
    let field_container = path.starts_with("input") || path.starts_with("output") || path.starts_with("shapes");
    if field_container && (path.ends_with(']') || path.contains("[order]")) {
        return Dimension::FieldSet;
    }
    Dimension::Other
}
