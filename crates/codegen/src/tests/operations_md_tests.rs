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

//! The `**Body shapes**` line `OPERATIONS.md` renders for one nested shape.
//!
//! Responsible for: the separator between a shape's `(kind)` and its member list — present with a
//! space on either side when there are members, absent entirely (no dangling em dash, no trailing
//! space) when a shape carries none, the way `SSES3` does in the pinned model today.
//! NOT responsible for: whether a fresh run matches the file on disk, which is the zero-diff gate
//! in `codegen_tests`, or the JSON sibling, which is `operations_json_tests`.
//! Upstream: the module's declared inputs. Downstream: its callers and regression tests.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeMap;

use rustfs_gateway_model::ir::{Binding, Field, Shape, ShapeKind, ShapeXml, Type};

use super::codegen_tests::artifacts;
use crate::emit::operations_md;

fn shape_xml() -> ShapeXml {
    ShapeXml {
        element_order: Vec::new(),
        empty_value_policy: Vec::new(),
        attributes: Vec::new(),
    }
}

/// A single operation, carrying exactly the one shape under test, so the rendered `**Body
/// shapes**` section holds exactly one line to assert on.
fn rendered_shape_line(shape: Shape) -> String {
    let mut ir = artifacts()
        .operations
        .into_iter()
        .next()
        .expect("the pinned model generates operations");
    ir.shapes = BTreeMap::from([("Sample".to_owned(), shape)]);

    let rendered = operations_md::render(&[ir], &[], &BTreeMap::new(), &BTreeMap::new());
    rendered
        .lines()
        .find(|line| line.starts_with("- `Sample`"))
        .expect("the shape line is rendered")
        .to_owned()
}

/// A shape with no members renders no separator at all: no em dash, no trailing space — the shape
/// that a Markdown renderer producing a fieldless `SSES3` line as `- \`SSES3\` (Structure) — `
/// (`OPERATIONS.md:1555`/`:2743`) fails to do.
#[test]
fn n_a_shape_with_no_members_renders_no_dangling_separator() {
    let shape = Shape {
        kind: ShapeKind::Structure,
        fields: Vec::new(),
        xml: shape_xml(),
    };

    let line = rendered_shape_line(shape);

    assert_eq!(line, "- `Sample` (Structure)", "a fieldless shape must not carry a trailing separator");
    assert!(!line.ends_with(' '), "the line must not end in trailing whitespace: {line:?}");
    assert!(!line.contains('\u{2014}'), "the line must not carry a dangling em dash: {line:?}");
}

/// A shape with members keeps the ` — ` separator, on both sides, between `(kind)` and the list.
#[test]
fn a_shape_with_members_keeps_the_separator_around_its_member_list() {
    let shape = Shape {
        kind: ShapeKind::Structure,
        fields: vec![Field {
            name: "Value".to_owned(),
            wire_name: Some("Value".to_owned()),
            required: false,
            binding: Binding::BodyXml,
            ty: Type::String,
            hot: false,
            default: None,
            omit_when: None,
            missing_error: None,
            quirk_refs: Vec::new(),
        }],
        xml: shape_xml(),
    };

    let line = rendered_shape_line(shape);

    assert_eq!(line, "- `Sample` (Structure) — `Value: String`");
}
