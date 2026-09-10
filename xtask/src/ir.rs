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

//! Frozen operation-IR validation.
//!
//! Responsible for: validating the schema, hand-written goldens, and semantic invariants that
//! JSON Schema cannot express. NOT responsible for: lowering the model or generating artifacts.
//! Upstream: `spec/ir.schema.json`, `spec/ir/samples/`, and `model/overlays/`. Downstream: the
//! `cargo xtask ir validate` repository gate.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use jsonschema::Validator;
use jsonschema::error::ValidationErrorKind;
use rustfs_gateway_model::Overlay;
use serde_json::Value;

mod negative;
mod semantic;

const SAMPLE_NAMES: [&str; 3] = ["GetBucketLocation", "PutObject", "ListObjectsV2"];

#[derive(Debug)]
struct Report {
    samples: usize,
    quirk_refs: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Diagnostic {
    what: String,
    at: String,
    rule: String,
}

impl Diagnostic {
    fn new(what: impl Into<String>, at: impl Into<String>, rule: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            at: at.into(),
            rule: rule.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "what: {} | where: {} | rule: {}", self.what, self.at, self.rule)
    }
}

pub(super) fn command(args: &[String]) -> ExitCode {
    let root = crate::repo_root::repo_root();
    let root = root.as_path();
    let started = Instant::now();
    let result = match args {
        [validate] if validate == "validate" => validate_samples(root).map(|report| {
            println!("ir.schema.json: valid (draft 2020-12)");
            println!("samples: {} ok ({})", report.samples, SAMPLE_NAMES.join(", "));
            println!("quirk refs: 100% resolved ({})", report.quirk_refs);
        }),
        [validate, flag, dir] if validate == "validate" && flag == "--expect-fail" => {
            negative::validate_expected_failures(root, Path::new(dir)).map(|report| {
                println!(
                    "{} samples, {} rejected as expected, {} unexpectedly accepted",
                    report.samples,
                    report.rejected,
                    report.samples - report.rejected
                );
            })
        }
        _ => Err("usage: cargo xtask ir validate [--expect-fail <dir>]".to_owned()),
    };
    match result {
        Ok(()) => {
            println!("ok in {:.3}s", started.elapsed().as_secs_f64());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn validate_samples(root: &Path) -> Result<Report, String> {
    let schema = load_schema(root)?;
    let validator = compile_schema(&schema)?;
    let docs = load_positive_samples(root)?;
    let operations = operation_names(&docs)?;
    let overlay = Overlay::load(&root.join("model/overlays")).map_err(|error| error.to_string())?;
    let mut diagnostics = Vec::new();
    let mut quirk_refs = 0;

    for (path, doc) in &docs {
        diagnostics.extend(schema_diagnostics(&validator, doc));
        let semantic = semantic::diagnostics(doc, &operations, &overlay);
        quirk_refs += semantic::referenced_quirks(doc).len();
        diagnostics.extend(semantic);
        diagnostics.extend(golden_diagnostics(doc));
        if !diagnostics.is_empty() {
            return Err(render_diagnostics(path, &diagnostics));
        }
    }
    Ok(Report {
        samples: docs.len(),
        quirk_refs,
    })
}

fn load_schema(root: &Path) -> Result<Value, String> {
    let path = root.join("spec/ir.schema.json");
    let schema: Value = read_json(&path)?;
    validate_meta_schema(&schema).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(schema)
}

fn validate_meta_schema(schema: &Value) -> Result<(), String> {
    jsonschema::draft202012::meta::validate(schema).map_err(|error| format!("invalid draft 2020-12 schema: {error}"))
}

fn compile_schema(schema: &Value) -> Result<Validator, String> {
    jsonschema::draft202012::new(schema).map_err(|error| format!("cannot compile IR schema: {error}"))
}

fn load_positive_samples(root: &Path) -> Result<Vec<(PathBuf, Value)>, String> {
    SAMPLE_NAMES
        .iter()
        .map(|name| {
            let path = root.join(format!("spec/ir/samples/{name}.json"));
            let doc = read_json(&path)?;
            check_sample_identity(&path, &doc)?;
            Ok((path, doc))
        })
        .collect()
}

fn check_sample_identity(path: &Path, doc: &Value) -> Result<(), String> {
    let operation = doc
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{}: missing string operation", path.display()))?;
    let stem = path.file_stem().and_then(|value| value.to_str());
    if stem == Some(operation) {
        Ok(())
    } else {
        Err(format!("{}: file stem must equal operation `{operation}`", path.display()))
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let input = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_str(&input).map_err(|error| format!("{}: {error}", path.display()))
}

fn schema_diagnostics(validator: &Validator, doc: &Value) -> Vec<Diagnostic> {
    validator
        .iter_errors(doc)
        .map(|error| {
            let mut at = error.instance_path().to_string();
            if at.is_empty() {
                at.push('/');
            }
            if let ValidationErrorKind::AdditionalProperties { unexpected } = error.kind()
                && let Some(property) = unexpected.first()
            {
                if at == "/" {
                    at.clear();
                }
                at.push('/');
                at.push_str(&escape_pointer(property));
            }
            Diagnostic::new(error.to_string(), at, format!("schema:#{}", error.schema_path()))
        })
        .collect()
}

fn golden_diagnostics(doc: &Value) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    match doc.get("operation").and_then(Value::as_str) {
        Some("GetBucketLocation") => {
            require_value(
                doc,
                "/xml/response_root",
                &Value::String("LocationConstraint".into()),
                "c-ir-0002",
                &mut diagnostics,
            );
            require_value(
                doc,
                "/xml/empty_value_policy/LocationConstraint",
                &Value::String("emit".into()),
                "c-ir-0002",
                &mut diagnostics,
            );
        }
        Some("PutObject") => {
            let payloads: Vec<&Value> = doc
                .pointer("/input/fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|field| field.pointer("/binding/kind").and_then(Value::as_str) == Some("Payload"))
                .collect();
            if payloads.len() != 1
                || payloads[0].pointer("/type/kind").and_then(Value::as_str) != Some("Blob")
                || payloads[0].pointer("/type/streaming").and_then(Value::as_bool) != Some(true)
            {
                diagnostics.push(Diagnostic::new(
                    "PutObject must have one streaming Blob Payload field",
                    "/input/fields",
                    "c-ir-0003",
                ));
            }
        }
        Some("ListObjectsV2") => {
            let contents = find_field(doc.pointer("/output/fields"), "Contents");
            if contents
                .and_then(|field| field.pointer("/type/flattened"))
                .and_then(Value::as_bool)
                != Some(true)
            {
                diagnostics.push(Diagnostic::new("Contents must be a flattened list", "/output/fields", "c-ir-0004"));
            }
            let encoded = doc.pointer("/xml/url_encoded_fields").and_then(Value::as_array);
            if encoded.is_none_or(Vec::is_empty) {
                diagnostics.push(Diagnostic::new(
                    "url_encoded_fields must not be empty",
                    "/xml/url_encoded_fields",
                    "c-ir-0004",
                ));
            }
            let order = doc.pointer("/xml/element_order").and_then(Value::as_array);
            let position = |name: &str| order.and_then(|items| items.iter().position(|item| item.as_str() == Some(name)));
            if !matches!((position("Name"), position("Contents")), (Some(name), Some(contents)) if name < contents) {
                diagnostics.push(Diagnostic::new("Name must precede Contents", "/xml/element_order", "c-ir-0004"));
            }
        }
        _ => {}
    }
    diagnostics
}

fn require_value(doc: &Value, pointer: &str, expected: &Value, rule: &str, diagnostics: &mut Vec<Diagnostic>) {
    if doc.pointer(pointer) != Some(expected) {
        diagnostics.push(Diagnostic::new(format!("expected {expected}"), pointer, rule));
    }
}

fn find_field<'a>(fields: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    fields
        .and_then(Value::as_array)?
        .iter()
        .find(|field| field.get("name").and_then(Value::as_str) == Some(name))
}

fn operation_names(docs: &[(PathBuf, Value)]) -> Result<BTreeSet<String>, String> {
    docs.iter()
        .map(|(path, doc)| {
            doc.get("operation")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("{}: missing string operation", path.display()))
        })
        .collect()
}

fn render_diagnostics(path: &Path, diagnostics: &[Diagnostic]) -> String {
    format!(
        "{}:\n{}",
        path.display(),
        diagnostics
            .iter()
            .map(|diagnostic| format!("  {diagnostic}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        crate::repo_root::repo_root()
    }

    #[test]
    fn c_ir_0001_through_0005_validate() {
        let report = validate_samples(&root()).expect("schema and positive samples must validate");
        assert_eq!(report.samples, 3);
        assert!(report.quirk_refs > 0);
    }

    #[test]
    fn c_ir_n001_through_n014_are_rejected_for_the_named_rule() {
        let report = negative::validate_expected_failures(&root(), Path::new("spec/ir/samples/invalid"))
            .expect("all negative samples must be rejected for their named rule");
        assert_eq!(report.samples, 14);
        assert_eq!(report.rejected, 14);
    }

    #[test]
    fn every_schema_object_is_closed() {
        fn inspect(value: &Value, objects: &mut usize, missing: &mut usize) {
            match value {
                Value::Object(object) => {
                    if object.get("type").and_then(Value::as_str) == Some("object") {
                        *objects += 1;
                        if object.get("additionalProperties") != Some(&Value::Bool(false)) {
                            *missing += 1;
                        }
                    }
                    for child in object.values() {
                        inspect(child, objects, missing);
                    }
                }
                Value::Array(array) => {
                    for child in array {
                        inspect(child, objects, missing);
                    }
                }
                _ => {}
            }
        }
        let schema: Value = read_json(&root().join("spec/ir.schema.json")).expect("schema must parse");
        let (mut objects, mut missing) = (0, 0);
        inspect(&schema, &mut objects, &mut missing);
        assert!(objects > 0);
        assert_eq!(missing, 0);
    }

    #[test]
    fn schema_meta_validation_rejects_an_invalid_type_keyword() {
        let mut schema: Value = read_json(&root().join("spec/ir.schema.json")).expect("schema must parse");
        schema["type"] = Value::String("not-a-json-schema-type".to_owned());
        assert!(validate_meta_schema(&schema).is_err());
    }

    #[test]
    fn ir_version_other_than_two_gets_the_exact_const_diagnostic() {
        let schema = load_schema(&root()).expect("schema must load");
        let validator = compile_schema(&schema).expect("schema must compile");
        let mut doc: Value =
            read_json(&root().join("spec/ir/samples/GetBucketLocation.json")).expect("positive sample must parse");
        doc["ir_version"] = Value::String("1".to_owned());
        let diagnostics = schema_diagnostics(&validator, &doc);
        assert!(
            diagnostics.iter().any(|diagnostic| {
                diagnostic.at == "/ir_version" && diagnostic.rule == "schema:#/properties/ir_version/const"
            })
        );
    }

    #[test]
    fn ir_v2_accepts_an_owned_upload_id_capability() {
        let schema = load_schema(&root()).expect("schema must load");
        let validator = compile_schema(&schema).expect("schema must compile");
        let mut doc: Value =
            read_json(&root().join("spec/ir/samples/GetBucketLocation.json")).expect("positive sample must parse");
        doc["ir_version"] = Value::String("2".to_owned());
        doc["input"]["fields"][0]["type"] = serde_json::json!({
            "kind": "Capability",
            "exchange": "upload_id",
        });

        let diagnostics = schema_diagnostics(&validator, &doc);
        assert!(diagnostics.is_empty(), "IR v2 capability diagnostics: {diagnostics:?}");
    }

    #[test]
    fn n_ir_v2_rejects_an_unknown_capability_exchange() {
        let schema = load_schema(&root()).expect("schema must load");
        let validator = compile_schema(&schema).expect("schema must compile");
        let mut doc: Value =
            read_json(&root().join("spec/ir/samples/GetBucketLocation.json")).expect("positive sample must parse");
        doc["input"]["fields"][0]["type"] = serde_json::json!({
            "kind": "Capability",
            "exchange": "unknown",
        });

        let diagnostics = schema_diagnostics(&validator, &doc);
        assert!(!diagnostics.is_empty(), "an unknown exchange must fail closed");
    }

    #[test]
    fn n_ir_v2_rejects_extra_capability_properties() {
        let schema = load_schema(&root()).expect("schema must load");
        let validator = compile_schema(&schema).expect("schema must compile");
        let mut doc: Value =
            read_json(&root().join("spec/ir/samples/GetBucketLocation.json")).expect("positive sample must parse");
        doc["input"]["fields"][0]["type"] = serde_json::json!({
            "kind": "Capability",
            "exchange": "upload_id",
            "raw": "must-not-cross-the-IR",
        });

        let diagnostics = schema_diagnostics(&validator, &doc);
        assert!(!diagnostics.is_empty(), "capability objects must stay closed");
    }

    #[test]
    fn diagnostic_renders_the_required_triple() {
        let rendered = Diagnostic::new("failed", "/http", "schema:#/required").to_string();
        assert_eq!(rendered, "what: failed | where: /http | rule: schema:#/required");
    }

    #[test]
    fn positive_sample_rejects_swapped_filename() {
        let doc: Value = read_json(&root().join("spec/ir/samples/GetBucketLocation.json")).expect("positive sample must parse");
        let error =
            check_sample_identity(Path::new("PutObject.json"), &doc).expect_err("a sample filename must name its operation");
        assert!(error.contains("file stem must equal operation `GetBucketLocation`"));
    }

    #[test]
    fn ir_readme_stays_bounded() {
        let readme = fs::read_to_string(root().join("spec/ir/README.md")).expect("README must be readable");
        assert!(readme.lines().count() <= 80);
    }
}
