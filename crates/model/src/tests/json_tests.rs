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

//! Compile-time or regression support for this module.
//!
//! Responsible for: exercising the contract named by this file.
//! NOT responsible for: implementing the production behavior under test.
//! Upstream: the test harness and subject module. Downstream: the repository verification gate.

//! Tests for the JSON reader and the canonical writer.

use crate::json::{Value, parse, write_canonical};

#[test]
fn parses_nested_documents_in_order() {
    let v = parse(r#"{"b": 1, "a": [true, null, "x"], "c": {"d": -2}}"#).expect("parses");
    let keys: Vec<&str> = v.as_object().expect("object").iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["b", "a", "c"], "object order is preserved");
    assert_eq!(v.get("c").and_then(|c| c.get("d")), Some(&Value::Int(-2)));
}

#[test]
fn n_rejects_trailing_input() {
    assert!(parse("{} {}").is_err());
}

#[test]
fn n_rejects_unterminated_string() {
    assert!(parse("\"abc").is_err());
}

#[test]
fn n_rejects_truncated_object() {
    assert!(parse(r#"{"a": 1"#).is_err());
}

#[test]
fn n_rejects_bare_word() {
    assert!(parse("nope").is_err());
}

#[test]
fn round_trips_escapes() {
    let v = parse(r#""a\"b\\c\ndAé""#).expect("parses");
    assert_eq!(v.as_str(), Some("a\"b\\c\ndAé"));
    let text = write_canonical(&v);
    assert_eq!(text, "\"a\\\"b\\\\c\\ndAé\"\n");
}

#[test]
fn writes_short_composites_flat_and_long_ones_expanded() {
    let short = Value::object([("kind".into(), Value::Str("Method".into()))]);
    assert_eq!(write_canonical(&short), "{ \"kind\": \"Method\" }\n");

    let long = Value::Array((0..40).map(|i| Value::Str(format!("value-{i:02}"))).collect());
    let text = write_canonical(&long);
    assert!(text.starts_with("[\n  \"value-00\","), "long arrays expand: {text}");
    assert!(text.ends_with("]\n"));
}

#[test]
fn writing_is_a_pure_function_of_the_value() {
    let v = parse(r#"{"a":[1,2,3],"b":{"c":"d"}}"#).expect("parses");
    assert_eq!(write_canonical(&v), write_canonical(&v.clone()));
}

#[test]
fn n_write_never_emits_a_trailing_comma() {
    let long = Value::Array((0..40).map(Value::Int).collect());
    let text = write_canonical(&long);
    assert!(!text.contains(",\n]"), "no dangling comma: {text}");
}
