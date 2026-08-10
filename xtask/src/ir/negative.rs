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

//! Negative IR corpus validation.
//!
//! Responsible for: the exact 14-case manifest, deterministic JSON mutations, and exact expected
//! diagnostic matching. NOT responsible for: schema or semantic rule definitions. Upstream:
//! `spec/ir/samples/invalid/`. Downstream: `cargo xtask ir validate --expect-fail`.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use rustfs_gateway_model::Overlay;
use serde::Deserialize;
use serde_json::Value;

use super::{
    Diagnostic, SAMPLE_NAMES, compile_schema, load_positive_samples, load_schema, operation_names, read_json, schema_diagnostics,
    semantic,
};

pub(super) struct Report {
    pub(super) samples: usize,
    pub(super) rejected: usize,
}

pub(super) fn validate_expected_failures(root: &Path, dir: &Path) -> Result<Report, String> {
    let schema = load_schema(root)?;
    let validator = compile_schema(&schema)?;
    let positive = load_positive_samples(root)?;
    let operations = operation_names(&positive)?;
    let overlay = Overlay::load(&root.join("model/overlays")).map_err(|error| error.to_string())?;
    let corpus = root.join(dir);
    let mut paths = json_files(&corpus)?;
    paths.sort();
    let mut failures = Vec::new();
    let mut rejected = 0;
    let mut case_ids = BTreeSet::new();

    for path in &paths {
        let case: NegativeCase = read_json(path)?;
        check_case_identity(path, &case.case_id, &mut case_ids, &mut failures);
        let base_name = case
            .base
            .to_str()
            .ok_or_else(|| format!("{}: base is not UTF-8", path.display()))?;
        if !SAMPLE_NAMES.iter().any(|name| base_name == format!("{name}.json")) {
            failures.push(format!("{}: base must name one of the three IR goldens", path.display()));
            continue;
        }
        let base = root.join("spec/ir/samples").join(&case.base);
        let mut doc: Value = read_json(&base)?;
        apply_mutation(&mut doc, &case.mutation).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut diagnostics = schema_diagnostics(&validator, &doc);
        diagnostics.extend(semantic::diagnostics(&doc, &operations, &overlay));
        if diagnostics.iter().any(|diagnostic| case.expected.matches(diagnostic)) {
            rejected += 1;
        } else {
            failures.push(format!(
                "{}: expected where={} rule={} but got [{}]",
                case.case_id,
                case.expected.at,
                case.expected.rule,
                diagnostics.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
            ));
        }
    }
    if paths.len() != 14 {
        failures.push(format!("expected 14 negative samples, found {}", paths.len()));
    }
    let expected = expected_case_ids();
    if case_ids != expected {
        let missing: Vec<&String> = expected.difference(&case_ids).collect();
        let extra: Vec<&String> = case_ids.difference(&expected).collect();
        failures.push(format!("negative case ids differ: missing={missing:?}, extra={extra:?}"));
    }
    if failures.is_empty() {
        Ok(Report {
            samples: paths.len(),
            rejected,
        })
    } else {
        Err(failures.join("\n"))
    }
}

fn check_case_identity(path: &Path, case_id: &str, seen: &mut BTreeSet<String>, failures: &mut Vec<String>) {
    if !seen.insert(case_id.to_owned()) {
        failures.push(format!("duplicate negative case id `{case_id}`"));
    }
    let stem = path.file_stem().and_then(|stem| stem.to_str());
    if stem != Some(case_id) {
        failures.push(format!("{}: file stem must equal case_id `{case_id}`", path.display()));
    }
}

fn expected_case_ids() -> BTreeSet<String> {
    (1..=14).map(|index| format!("c-ir-n{index:03}")).collect()
}

fn json_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    entries
        .map(|entry| entry.map_err(|error| error.to_string()))
        .filter_map(|entry| match entry {
            Ok(path) if path.path().extension().and_then(|ext| ext.to_str()) == Some("json") => Some(Ok(path.path())),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct NegativeCase {
    case_id: String,
    base: PathBuf,
    mutation: Mutation,
    #[serde(rename = "expect")]
    expected: ExpectedDiagnostic,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Mutation {
    Add { path: String, value: Value },
    Replace { path: String, value: Value },
    Remove { path: String },
    Copy { from: String, path: String },
}

#[derive(Debug, Deserialize)]
struct ExpectedDiagnostic {
    at: String,
    rule: String,
}

impl ExpectedDiagnostic {
    fn matches(&self, diagnostic: &Diagnostic) -> bool {
        diagnostic.at == self.at && diagnostic.rule == self.rule
    }
}

fn apply_mutation(doc: &mut Value, mutation: &Mutation) -> Result<(), String> {
    let (op, path, value) = match mutation {
        Mutation::Add { path, value } => ("add", path, Some(value.clone())),
        Mutation::Replace { path, value } => ("replace", path, Some(value.clone())),
        Mutation::Remove { path } => ("remove", path, None),
        Mutation::Copy { from, path } => (
            "copy",
            path,
            Some(
                doc.pointer(from)
                    .ok_or_else(|| format!("copy source `{from}` does not exist"))?
                    .clone(),
            ),
        ),
    };
    let (parent, token) = path.rsplit_once('/').ok_or("mutation path must be a JSON Pointer")?;
    let parent = if parent.is_empty() {
        doc
    } else {
        doc.pointer_mut(parent)
            .ok_or_else(|| format!("parent `{parent}` does not exist"))?
    };
    let token = token.replace("~1", "/").replace("~0", "~");
    match (parent, op, value) {
        (Value::Object(object), "remove", None) => object
            .remove(&token)
            .map(|_| ())
            .ok_or_else(|| format!("property `{token}` does not exist")),
        (Value::Object(object), "replace", Some(value)) => {
            let slot = object
                .get_mut(&token)
                .ok_or_else(|| format!("property `{token}` does not exist"))?;
            *slot = value;
            Ok(())
        }
        (Value::Object(object), "add" | "copy", Some(value)) => {
            object.insert(token, value);
            Ok(())
        }
        (Value::Array(array), "remove", None) => {
            let index = parse_index(&token, array.len())?;
            array.remove(index);
            Ok(())
        }
        (Value::Array(array), "replace", Some(value)) => {
            let index = parse_index(&token, array.len())?;
            array[index] = value;
            Ok(())
        }
        (Value::Array(array), "add" | "copy", Some(value)) if token == "-" => {
            array.push(value);
            Ok(())
        }
        (Value::Array(array), "add" | "copy", Some(value)) => {
            let index = token
                .parse::<usize>()
                .map_err(|_| format!("`{token}` is not an array index"))?;
            if index > array.len() {
                return Err(format!("array insertion index {index} exceeds length {}", array.len()));
            }
            array.insert(index, value);
            Ok(())
        }
        _ => Err(format!("mutation `{op}` is incompatible with `{path}`")),
    }
}

fn parse_index(token: &str, len: usize) -> Result<usize, String> {
    let index = token
        .parse::<usize>()
        .map_err(|_| format!("`{token}` is not an array index"))?;
    if index >= len {
        Err(format!("array index {index} exceeds length {len}"))
    } else {
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_diagnostic_requires_exact_pointer_and_rule() {
        let expected = ExpectedDiagnostic {
            at: "/http".to_owned(),
            rule: "schema:#/$defs/http/required".to_owned(),
        };
        assert!(expected.matches(&Diagnostic::new("failed", "/http", "schema:#/$defs/http/required")));
        assert!(!expected.matches(&Diagnostic::new("failed", "/http/method", "schema:#/$defs/http/required")));
        assert!(!expected.matches(&Diagnostic::new("failed", "/http", "schema:#/required")));
    }

    #[test]
    fn manifest_rejects_duplicate_case_ids() {
        let mut seen = BTreeSet::new();
        let mut failures = Vec::new();
        check_case_identity(Path::new("c-ir-n001.json"), "c-ir-n001", &mut seen, &mut failures);
        check_case_identity(Path::new("copy.json"), "c-ir-n001", &mut seen, &mut failures);
        assert!(failures.iter().any(|failure| failure.contains("duplicate negative case id")));
    }

    #[test]
    fn manifest_rejects_missing_case_ids() {
        let actual: BTreeSet<String> = (1..=13).map(|index| format!("c-ir-n{index:03}")).collect();
        assert_eq!(expected_case_ids().difference(&actual).cloned().collect::<Vec<_>>(), vec!["c-ir-n014"]);
    }

    #[test]
    fn manifest_rejects_renamed_files() {
        let mut seen = BTreeSet::new();
        let mut failures = Vec::new();
        check_case_identity(Path::new("renamed.json"), "c-ir-n014", &mut seen, &mut failures);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("file stem must equal case_id"))
        );
    }
}
