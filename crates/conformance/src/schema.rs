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

//! Validation of a parsed case against the frozen `conformance/case.schema.json`.
//!
//! Responsible for: the JSON Schema draft 2020-12 subset the frozen schema uses, evaluated
//! against the parsed TOML itself. The schema file is the contract, so it is read at run time
//! rather than mirrored into Rust structs: a mirror is a second copy of a frozen document, and a
//! second copy is a copy that drifts. An unknown keyword is refused at compile time for the same
//! reason — silently ignoring one turns a frozen contract into an unchecked one.
//! NOT responsible for: the conventions the schema deliberately cannot express (naming, golden
//! references, capture wiring); those live in `crate::lint`.
//! Upstream: `crate::json`, `crate::pattern`, `crate::value`. Downstream: `crate::corpus`.

use crate::json;
use crate::pattern::Pattern;
use crate::value::Value;
use core::fmt;
use std::collections::BTreeMap;

/// The schema version this runner understands.
///
/// A case whose `schema_version` is not this value is refused with an explicit "update the
/// runner" error. It is never skipped and its unknown fields are never ignored.
pub const SCHEMA_VERSION: i64 = 1;

/// The schema file could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    /// What went wrong.
    pub message: String,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for SchemaError {}

/// One failed assertion, located by a JSON pointer into the case document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// JSON pointer into the instance, e.g. `/case/evidence/0/summary`.
    pub pointer: String,
    /// The schema keyword that failed.
    pub keyword: String,
    /// Expected versus actual, in a form that names the field.
    pub message: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let location = if self.pointer.is_empty() {
            "(document root)"
        } else {
            self.pointer.as_str()
        };
        write!(f, "{location}: {} ({})", self.message, self.keyword)
    }
}

/// A compiled JSON Schema.
#[derive(Debug, Clone)]
pub struct Schema {
    root: Value,
    patterns: BTreeMap<String, Pattern>,
}

impl Schema {
    /// Compiles a schema document.
    ///
    /// Every `pattern` in the document is compiled up front, so an expression this runner cannot
    /// evaluate is reported when the schema is loaded rather than silently passing every case.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaError`] when the document is not JSON, when it uses a keyword this subset
    /// does not implement, or when a `pattern` is outside the supported regular-expression subset.
    pub fn compile(source: &str) -> Result<Schema, SchemaError> {
        let root = json::parse(source).map_err(|error| SchemaError {
            message: error.to_string(),
        })?;
        let mut patterns = BTreeMap::new();
        collect_patterns(&root, &mut patterns)?;
        reject_unknown_keywords(&root, "")?;
        Ok(Schema { root, patterns })
    }

    /// The `x-schema-version` annotation the schema document declares, when it has one.
    #[must_use]
    pub fn declared_version(&self) -> Option<i64> {
        self.root.get("x-schema-version").and_then(Value::as_integer)
    }

    /// Validates an instance, returning every violation found.
    ///
    /// An empty vector means the instance satisfies the schema.
    #[must_use]
    pub fn validate(&self, instance: &Value) -> Vec<Violation> {
        let mut out = Vec::new();
        self.check(&self.root, instance, "", &mut out);
        out
    }

    fn resolve<'a>(&'a self, reference: &str) -> Option<&'a Value> {
        let path = reference.strip_prefix("#/")?;
        self.root.path(path)
    }

    #[allow(clippy::too_many_lines)] // One keyword per block; splitting it would only hide the list.
    fn check(&self, schema: &Value, instance: &Value, pointer: &str, out: &mut Vec<Violation>) {
        match schema {
            Value::Bool(true) => return,
            Value::Bool(false) => {
                out.push(Violation {
                    pointer: pointer.to_owned(),
                    keyword: "false".to_owned(),
                    message: "this field must not be present here".to_owned(),
                });
                return;
            }
            Value::Table(_) => {}
            other => {
                out.push(Violation {
                    pointer: pointer.to_owned(),
                    keyword: "schema".to_owned(),
                    message: format!("schema node is {}, which is not a schema", other.type_name()),
                });
                return;
            }
        }

        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            match self.resolve(reference) {
                Some(target) => self.check(target, instance, pointer, out),
                None => out.push(Violation {
                    pointer: pointer.to_owned(),
                    keyword: "$ref".to_owned(),
                    message: format!("`{reference}` does not resolve inside the schema"),
                }),
            }
        }

        if let Some(expected) = schema.get("type").and_then(Value::as_str)
            && !type_matches(expected, instance)
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "type".to_owned(),
                message: format!("expected {expected}, found {}", instance.type_name()),
            });
            return;
        }

        if let Some(expected) = schema.get("const")
            && instance != expected
        {
            let extra = if pointer.ends_with("schema_version") {
                "; update the runner rather than the case if this is a newer corpus"
            } else {
                ""
            };
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "const".to_owned(),
                message: format!("expected {expected}, found {instance}{extra}"),
            });
        }

        if let Some(Value::Array(allowed)) = schema.get("enum")
            && !allowed.contains(instance)
        {
            let rendered: Vec<String> = allowed.iter().map(ToString::to_string).collect();
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "enum".to_owned(),
                message: format!("{instance} is not one of [{}]", rendered.join(", ")),
            });
        }

        self.check_string(schema, instance, pointer, out);
        self.check_number(schema, instance, pointer, out);
        self.check_array(schema, instance, pointer, out);
        self.check_object(schema, instance, pointer, out);
        self.check_combinators(schema, instance, pointer, out);
    }

    fn check_string(&self, schema: &Value, instance: &Value, pointer: &str, out: &mut Vec<Violation>) {
        let Some(text) = instance.as_str() else { return };
        if let Some(source) = schema.get("pattern").and_then(Value::as_str) {
            match self.patterns.get(source) {
                Some(pattern) if pattern.is_match(text) => {}
                Some(_) => out.push(Violation {
                    pointer: pointer.to_owned(),
                    keyword: "pattern".to_owned(),
                    message: format!("{text:?} does not match `{source}`"),
                }),
                None => out.push(Violation {
                    pointer: pointer.to_owned(),
                    keyword: "pattern".to_owned(),
                    message: format!("pattern `{source}` was not compiled"),
                }),
            }
        }
        let length = text.chars().count() as i64;
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_integer)
            && length < minimum
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "minLength".to_owned(),
                message: format!("{length} characters, at least {minimum} required"),
            });
        }
        if let Some(maximum) = schema.get("maxLength").and_then(Value::as_integer)
            && length > maximum
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "maxLength".to_owned(),
                message: format!("{length} characters, at most {maximum} allowed"),
            });
        }
    }

    fn check_number(&self, schema: &Value, instance: &Value, pointer: &str, out: &mut Vec<Violation>) {
        let Some(number) = numeric(instance) else { return };
        if let Some(minimum) = schema.get("minimum").and_then(numeric)
            && number < minimum
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "minimum".to_owned(),
                message: format!("{number} is below the minimum {minimum}"),
            });
        }
        if let Some(maximum) = schema.get("maximum").and_then(numeric)
            && number > maximum
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "maximum".to_owned(),
                message: format!("{number} is above the maximum {maximum}"),
            });
        }
    }

    fn check_array(&self, schema: &Value, instance: &Value, pointer: &str, out: &mut Vec<Violation>) {
        let Some(items) = instance.as_array() else { return };
        if let Some(minimum) = schema.get("minItems").and_then(Value::as_integer)
            && (items.len() as i64) < minimum
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "minItems".to_owned(),
                message: format!("{} items, at least {minimum} required", items.len()),
            });
        }
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_integer)
            && (items.len() as i64) > maximum
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "maxItems".to_owned(),
                message: format!("{} items, at most {maximum} allowed", items.len()),
            });
        }
        if let Some(item_schema) = schema.get("items") {
            for (index, item) in items.iter().enumerate() {
                self.check(item_schema, item, &format!("{pointer}/{index}"), out);
            }
        }
    }

    fn check_object(&self, schema: &Value, instance: &Value, pointer: &str, out: &mut Vec<Violation>) {
        let Some(entries) = instance.as_table() else { return };
        if let Some(Value::Array(required)) = schema.get("required") {
            for name in required.iter().filter_map(Value::as_str) {
                if instance.get(name).is_none() {
                    out.push(Violation {
                        pointer: pointer.to_owned(),
                        keyword: "required".to_owned(),
                        message: format!("required field `{name}` is missing"),
                    });
                }
            }
        }
        if let Some(minimum) = schema.get("minProperties").and_then(Value::as_integer)
            && (entries.len() as i64) < minimum
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "minProperties".to_owned(),
                message: format!("{} fields, at least {minimum} required", entries.len()),
            });
        }
        let properties = schema.get("properties");
        for (key, value) in entries {
            let child_pointer = format!("{pointer}/{key}");
            if let Some(name_schema) = schema.get("propertyNames") {
                self.check(name_schema, &Value::String(key.clone()), &child_pointer, out);
            }
            match properties.and_then(|table| table.get(key)) {
                Some(child_schema) => self.check(child_schema, value, &child_pointer, out),
                None => match schema.get("additionalProperties") {
                    None | Some(Value::Bool(true)) => {}
                    Some(Value::Bool(false)) => out.push(Violation {
                        pointer: child_pointer,
                        keyword: "additionalProperties".to_owned(),
                        message: format!(
                            "`{key}` is not a field of this object; the schema is frozen and \
                             tolerating an unknown key is how a mistyped assertion becomes a case \
                             that asserts nothing"
                        ),
                    }),
                    Some(child_schema) => self.check(child_schema, value, &child_pointer, out),
                },
            }
        }
    }

    fn check_combinators(&self, schema: &Value, instance: &Value, pointer: &str, out: &mut Vec<Violation>) {
        if let Some(Value::Array(branches)) = schema.get("allOf") {
            for branch in branches {
                self.check(branch, instance, pointer, out);
            }
        }
        if let Some(Value::Array(branches)) = schema.get("anyOf")
            && !branches.iter().any(|branch| self.satisfies(branch, instance))
        {
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "anyOf".to_owned(),
                message: "no permitted form matches".to_owned(),
            });
        }
        if let Some(Value::Array(branches)) = schema.get("oneOf") {
            let mut matched = Vec::new();
            let mut reasons = Vec::new();
            for (index, branch) in branches.iter().enumerate() {
                let mut branch_out = Vec::new();
                self.check(branch, instance, pointer, &mut branch_out);
                let title = branch
                    .get("title")
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("form {index}"), ToOwned::to_owned);
                if branch_out.is_empty() {
                    matched.push(title);
                } else {
                    let first = branch_out.first().map_or_else(String::new, ToString::to_string);
                    reasons.push(format!("{title}: {first}"));
                }
            }
            if matched.len() != 1 {
                let message = if matched.is_empty() {
                    format!("no permitted form matches — {}", reasons.join("; "))
                } else {
                    format!("{} forms match at once ({}); exactly one must", matched.len(), matched.join(", "))
                };
                out.push(Violation {
                    pointer: pointer.to_owned(),
                    keyword: "oneOf".to_owned(),
                    message,
                });
            }
        }
        if let Some(forbidden) = schema.get("not")
            && self.satisfies(forbidden, instance)
        {
            let fields = forbidden
                .get("required")
                .and_then(Value::as_array)
                .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" and "))
                .unwrap_or_default();
            let message = if fields.is_empty() {
                "this form is not allowed".to_owned()
            } else {
                format!("`{fields}` may not be used together")
            };
            out.push(Violation {
                pointer: pointer.to_owned(),
                keyword: "not".to_owned(),
                message,
            });
        }
        if let Some(condition) = schema.get("if") {
            let branch = if self.satisfies(condition, instance) {
                schema.get("then")
            } else {
                schema.get("else")
            };
            if let Some(branch) = branch {
                self.check(branch, instance, pointer, out);
            }
        }
    }

    fn satisfies(&self, schema: &Value, instance: &Value) -> bool {
        let mut out = Vec::new();
        self.check(schema, instance, "", &mut out);
        out.is_empty()
    }
}

fn numeric(value: &Value) -> Option<f64> {
    match value {
        Value::Integer(number) => Some(*number as f64),
        Value::Float(number) => Some(*number),
        _ => None,
    }
}

fn type_matches(expected: &str, instance: &Value) -> bool {
    match expected {
        "object" => matches!(instance, Value::Table(_)),
        "array" => matches!(instance, Value::Array(_)),
        "string" => matches!(instance, Value::String(_)),
        "boolean" => matches!(instance, Value::Bool(_)),
        "integer" => matches!(instance, Value::Integer(_)),
        "number" => matches!(instance, Value::Integer(_) | Value::Float(_)),
        "null" => false,
        _ => true,
    }
}

/// Keywords this subset evaluates. Anything else in a schema position is refused.
const KNOWN_KEYWORDS: &[&str] = &[
    "$ref",
    "type",
    "const",
    "enum",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "items",
    "required",
    "properties",
    "additionalProperties",
    "propertyNames",
    "minProperties",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "if",
    "then",
    "else",
];

/// Keywords that carry no assertion, plus the document-level bookkeeping fields.
const ANNOTATION_KEYWORDS: &[&str] = &["$schema", "$id", "$defs", "title", "description", "default", "examples"];

fn collect_patterns(node: &Value, out: &mut BTreeMap<String, Pattern>) -> Result<(), SchemaError> {
    match node {
        Value::Table(entries) => {
            for (key, value) in entries {
                if key == "pattern"
                    && let Some(source) = value.as_str()
                    && !out.contains_key(source)
                {
                    let compiled = Pattern::compile(source).map_err(|error| SchemaError {
                        message: error.to_string(),
                    })?;
                    out.insert(source.to_owned(), compiled);
                }
                collect_patterns(value, out)?;
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                collect_patterns(item, out)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Walks every schema position and refuses a keyword this subset does not implement.
fn reject_unknown_keywords(node: &Value, pointer: &str) -> Result<(), SchemaError> {
    let Some(entries) = node.as_table() else { return Ok(()) };
    for (key, value) in entries {
        if key.starts_with("x-") || ANNOTATION_KEYWORDS.contains(&key.as_str()) {
            continue;
        }
        if !KNOWN_KEYWORDS.contains(&key.as_str()) {
            return Err(SchemaError {
                message: format!(
                    "{pointer}: schema keyword `{key}` is not implemented by this runner; \
                     implement it before the schema starts relying on it"
                ),
            });
        }
        let child = format!("{pointer}/{key}");
        match key.as_str() {
            // Sub-schema maps: every value is itself a schema.
            "properties" => {
                if let Some(children) = value.as_table() {
                    for (name, child_schema) in children {
                        reject_unknown_keywords(child_schema, &format!("{child}/{name}"))?;
                    }
                }
            }
            // Sub-schema lists.
            "allOf" | "anyOf" | "oneOf" => {
                if let Some(children) = value.as_array() {
                    for (index, child_schema) in children.iter().enumerate() {
                        reject_unknown_keywords(child_schema, &format!("{child}/{index}"))?;
                    }
                }
            }
            // Single sub-schemas.
            "items" | "additionalProperties" | "propertyNames" | "not" | "if" | "then" | "else" => {
                reject_unknown_keywords(value, &child)?;
            }
            // Assertion values: `enum` and `const` hold instance data, never schemas.
            _ => {}
        }
    }
    // `$defs` holds named schemas and is walked separately so it is not mistaken for an assertion.
    if let Some(defs) = node.get("$defs").and_then(Value::as_table) {
        for (name, child_schema) in defs {
            reject_unknown_keywords(child_schema, &format!("{pointer}/$defs/{name}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::toml;

    fn schema(source: &str) -> Schema {
        Schema::compile(source).expect("compilable schema")
    }

    #[test]
    fn an_unknown_field_is_refused_when_additional_properties_is_false() {
        let subject = schema(r#"{"type":"object","additionalProperties":false,"properties":{"a":{"type":"integer"}}}"#);
        let instance = toml::parse("a = 1\nb = 2\n").expect("valid TOML");
        let violations = subject.validate(&instance);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].pointer, "/b");
    }

    #[test]
    fn a_missing_required_field_names_the_field() {
        let subject = schema(r#"{"type":"object","required":["rationale"]}"#);
        let violations = subject.validate(&toml::parse("a = 1\n").expect("valid TOML"));
        assert!(violations[0].message.contains("rationale"), "{violations:?}");
    }

    #[test]
    fn one_of_reports_every_branch_when_nothing_matches() {
        let subject =
            schema(r#"{"oneOf":[{"title":"single","required":["request"]},{"title":"multi","required":["exchanges"]}]}"#);
        let violations = subject.validate(&toml::parse("other = 1\n").expect("valid TOML"));
        assert_eq!(violations.len(), 1);
        assert!(violations[0].message.contains("single"), "{violations:?}");
        assert!(violations[0].message.contains("multi"), "{violations:?}");
    }

    #[test]
    fn one_of_rejects_two_matching_branches() {
        let subject = schema(r#"{"oneOf":[{"title":"a","required":["x"]},{"title":"b","required":["y"]}]}"#);
        let violations = subject.validate(&toml::parse("x = 1\ny = 2\n").expect("valid TOML"));
        assert!(violations[0].message.contains("2 forms match"), "{violations:?}");
    }

    #[test]
    fn a_false_schema_forbids_the_field() {
        let subject = schema(r#"{"properties":{"exchanges":false}}"#);
        let violations = subject.validate(&toml::parse("exchanges = 1\n").expect("valid TOML"));
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].keyword, "false");
    }

    #[test]
    fn not_required_reports_the_mutually_exclusive_pair() {
        let subject = schema(r#"{"not":{"required":["body","chunks"]}}"#);
        let violations = subject.validate(&toml::parse("body = 1\nchunks = 2\n").expect("valid TOML"));
        assert!(violations[0].message.contains("body and chunks"), "{violations:?}");
    }

    #[test]
    fn if_then_applies_only_to_the_matching_branch() {
        let subject = schema(
            r#"{"allOf":[{"if":{"properties":{"kind":{"const":"stream_error"}},"required":["kind"]},
                          "then":{"required":["body_bytes_before_error"]}}]}"#,
        );
        assert!(
            subject
                .validate(&toml::parse("kind = \"response\"\n").expect("valid TOML"))
                .is_empty()
        );
        assert_eq!(
            subject
                .validate(&toml::parse("kind = \"stream_error\"\n").expect("valid TOML"))
                .len(),
            1
        );
    }

    #[test]
    fn a_const_mismatch_on_schema_version_says_update_the_runner() {
        let subject = schema(r#"{"properties":{"schema_version":{"const":1}}}"#);
        let violations = subject.validate(&toml::parse("schema_version = 2\n").expect("valid TOML"));
        assert!(violations[0].message.contains("update the runner"), "{violations:?}");
    }

    #[test]
    fn an_unimplemented_keyword_is_refused_at_compile_time() {
        let error = Schema::compile(r#"{"type":"string","format":"uri"}"#).expect_err("must be refused");
        assert!(error.message.contains("format"), "{error}");
    }

    #[test]
    fn an_unsupported_pattern_is_refused_at_compile_time() {
        assert!(Schema::compile(r#"{"pattern":"(?i)abc"}"#).is_err());
    }
}
