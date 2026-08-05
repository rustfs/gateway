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

//! Tests for the overlay TOML subset.

use crate::toml_lite::{Toml, parse};

#[test]
fn reads_tables_arrays_and_arrays_of_tables() {
    let doc = parse(
        "overlays/test.toml",
        r#"
# a comment
include = ["A", "B"]

[op.A]
precedence = 100
auth_presigned = false

[op.A.empty_value]
Name = "emit"

[[op.A.field]]
side = "input"
name = "Bucket"
quirks = ["q-a-0001"]

[[op.A.field]]
side = "output"
name = "ETag"
"#,
    )
    .expect("parses");

    assert_eq!(doc.get("include").expect("include").string_array("include").expect("array"), ["A", "B"]);
    let a = doc.get("op").and_then(|o| o.get("A")).expect("op.A");
    assert_eq!(a.get("precedence").and_then(Toml::as_int), Some(100));
    assert_eq!(a.get("auth_presigned").and_then(Toml::as_bool), Some(false));
    assert_eq!(a.get("empty_value").and_then(|e| e.get("Name")).and_then(Toml::as_str), Some("emit"));
    let fields = a.get("field").and_then(Toml::as_array).expect("field array");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[1].get("name").and_then(Toml::as_str), Some("ETag"));
}

#[test]
fn n_rejects_inline_tables() {
    let err = parse("t.toml", "a = { b = 1 }").expect_err("inline tables are outside the subset");
    assert!(format!("{err}").contains("inline tables"), "{err}");
}

#[test]
fn n_rejects_floats() {
    assert!(parse("t.toml", "a = 1.5").is_err());
}

#[test]
fn n_rejects_duplicate_keys() {
    let err = parse("t.toml", "a = 1\na = 2").expect_err("duplicate key");
    assert!(format!("{err}").contains("duplicate key"), "{err}");
}

#[test]
fn n_rejects_newline_in_string() {
    assert!(parse("t.toml", "a = \"one\ntwo\"").is_err());
}

#[test]
fn n_reports_the_line_number() {
    let err = parse("overlays/x.toml", "a = 1\nb = 1.5\n").expect_err("float on line 2");
    assert!(format!("{err}").starts_with("overlays/x.toml:2:"), "{err}");
}

#[test]
fn n_rejects_a_table_header_without_a_closing_bracket() {
    assert!(parse("t.toml", "[a.b\n").is_err());
}
