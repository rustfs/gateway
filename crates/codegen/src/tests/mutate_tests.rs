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

//! The mutation planner and the writer that puts a planned flip back into the IR.
//!
//! Responsible for: proving that a planned flip differs from the current value, that the writer
//! lands where the reader reads, and that every way it could quietly do nothing is an error.
//! NOT responsible for: whether a case catches the mutation — that needs a built gateway and lives
//! behind `cargo xtask conformance mutate`.
//! Upstream: `crate::mutate`. Downstream: nothing.

use rustfs_gateway_model::MutationDimension;
use rustfs_gateway_model::ir::OperationIr;

use super::codegen_tests::{artifacts, root};
use crate::emit::quirk_toml::{ResolvedSource, SourceValue, resolve_at};
use crate::mutate::apply::apply;
use crate::mutate::{Mutation, plan, quirk_families};
use crate::{CodegenInput, CodegenOutput, generate, generate_mutated};

/// The lifecycle request root: a string source with a real production consumer, used as the
/// worked example throughout.
const REQUEST_ROOT: &str = "PutBucketLifecycleConfiguration.xml.request_root";

fn lowered() -> Vec<OperationIr> {
    artifacts().operations
}

fn source(path: &str, current: SourceValue) -> ResolvedSource {
    ResolvedSource {
        path: path.to_owned(),
        current,
    }
}

#[test]
fn a_written_mutation_is_what_the_reader_finds_afterwards() {
    let mut operations = lowered();
    let current = resolve_at(&operations, REQUEST_ROOT).expect("the lifecycle request root resolves");
    let mutation = plan("q-lc-0002", MutationDimension::ElementRename, &source(REQUEST_ROOT, current.clone()))
        .expect("an element rename is plannable");

    apply(&mut operations, &mutation).expect("the writer accepts its own plan");

    let found = resolve_at(&operations, REQUEST_ROOT).expect("the mutated root still resolves");
    assert_eq!(found, mutation.to, "the writer must land where the reader reads");
    assert_ne!(found, current, "a mutation that leaves the value alone measures nothing");
}

#[test]
fn a_boolean_rule_is_flipped_and_a_list_shape_follows_it() {
    let mut operations = lowered();
    let path = "GetBucketLifecycleConfiguration.output.Rules.list_flattened";
    let current = resolve_at(&operations, path).expect("the flattened rule list resolves");
    assert_eq!(current, SourceValue::Bool(true), "the rules are flattened on the wire");
    let mutation = plan("q-lc-0003", MutationDimension::WrapStrategy, &source(path, current)).expect("plannable");

    apply(&mut operations, &mutation).expect("the writer accepts its own plan");

    assert_eq!(resolve_at(&operations, path).expect("still resolves"), SourceValue::Bool(false));
}

#[test]
fn n_a_plan_equal_to_the_current_value_is_refused() {
    let error = Mutation::new(
        "q-lc-0002",
        REQUEST_ROOT,
        SourceValue::Text("LifecycleConfiguration".to_owned()),
        SourceValue::Text("LifecycleConfiguration".to_owned()),
    )
    .expect_err("a mutation that changes nothing is not a mutation");
    assert!(error.contains("equals the current value"), "{error}");
}

#[test]
fn n_the_writer_refuses_a_plan_the_ir_has_moved_away_from() {
    let mut operations = lowered();
    let stale = Mutation::new(
        "q-lc-0002",
        REQUEST_ROOT,
        SourceValue::Text("SomethingNobodyWrote".to_owned()),
        SourceValue::Text("MutatedLifecycleConfiguration".to_owned()),
    )
    .expect("the plan itself is well formed");

    let error = apply(&mut operations, &stale).expect_err("a stale plan must not be written");
    assert!(error.contains("disagree"), "{error}");
}

#[test]
fn n_an_unknown_path_shape_is_an_error_and_not_a_silent_no_op() {
    let mut operations = lowered();
    let nonsense = Mutation::new(
        "q-lc-0002",
        "PutBucketLifecycleConfiguration.nowhere.at.all",
        SourceValue::Bool(true),
        SourceValue::Bool(false),
    )
    .expect("the plan itself is well formed");

    let error = apply(&mut operations, &nonsense).expect_err("an unresolvable path must fail");
    assert!(error.contains("unsupported path shape") || error.contains("names"), "{error}");
}

#[test]
fn n_an_absent_optional_value_has_no_planned_mutation() {
    let error = plan(
        "q-example",
        MutationDimension::Optionality,
        &source("Op.errors.not_configured", SourceValue::OptionalText(None)),
    )
    .expect_err("dropping an already absent value changes nothing");
    assert!(error.contains("already absent"), "{error}");
}

#[test]
fn n_a_single_element_order_has_no_second_order() {
    let error = plan(
        "q-example",
        MutationDimension::ElementOrder,
        &source("Op.xml.element_order", SourceValue::TextList(vec!["Rules".to_owned()])),
    )
    .expect_err("one element admits one order");
    assert!(error.contains("fewer than two"), "{error}");
}

#[test]
fn n_a_dimension_with_no_string_mutation_is_refused_rather_than_guessed() {
    let error = plan(
        "q-example",
        MutationDimension::ListMax,
        &source("Op.xml.request_root", SourceValue::Text("Whatever".to_owned())),
    )
    .expect_err("an unplanned dimension must not invent a value");
    assert!(error.contains("no planned string mutation"), "{error}");
}

#[test]
fn n_generation_refuses_a_mutation_that_does_not_resolve() {
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let nonsense = Mutation::new(
        "q-lc-0002",
        "NoSuchOperation.xml.request_root",
        SourceValue::Text("a".to_owned()),
        SourceValue::Text("b".to_owned()),
    )
    .expect("the plan itself is well formed");

    let error =
        generate_mutated(&input, &out, std::slice::from_ref(&nonsense)).expect_err("an unresolvable mutation must stop the run");
    assert!(error.to_string().contains("unknown operation"), "{error}");
}

#[test]
fn generating_with_no_mutation_is_generating() {
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let plain = generate(&input, &out).expect("codegen runs");
    let empty = generate_mutated(&input, &out, &[]).expect("codegen runs");
    assert_eq!(plain.files, empty.files, "an empty mutation list must change nothing");
}

#[test]
fn a_mutated_run_produces_different_artefacts_than_an_unmutated_one() {
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let plain = generate(&input, &out).expect("codegen runs");
    let current = resolve_at(&plain.operations, REQUEST_ROOT).expect("resolves");
    let mutation = plan("q-lc-0002", MutationDimension::ElementRename, &source(REQUEST_ROOT, current)).expect("plannable");

    let mutated = generate_mutated(&input, &out, std::slice::from_ref(&mutation)).expect("codegen runs");

    assert_ne!(
        plain.files, mutated.files,
        "a mutation nothing generates from is a mutation nothing can measure"
    );
    let paths: Vec<_> = plain.files.iter().map(|(path, _)| path).collect();
    let mutated_paths: Vec<_> = mutated.files.iter().map(|(path, _)| path).collect();
    assert_eq!(paths, mutated_paths, "a mutation must not add or remove an artefact");
}

#[test]
fn every_quirk_belongs_to_exactly_one_overlay_family() {
    let families = quirk_families(&root().join("model/overlays")).expect("the overlay families load");
    assert_eq!(
        families.get("q-lc-0002").map(String::as_str),
        Some("lifecycle"),
        "the lifecycle rules come from the lifecycle overlay"
    );
    assert_eq!(
        families.get("q-tag-limits-0094").map(String::as_str),
        Some("tagging"),
        "the tagging rules come from the tagging overlay"
    );
    let overlay = rustfs_gateway_model::Overlay::load(&root().join("model/overlays")).expect("the overlay loads");
    for id in overlay.quirks.keys() {
        assert!(families.contains_key(id), "{id} belongs to no overlay family");
    }
}

#[test]
fn n_a_write_the_reader_cannot_express_stops_the_run() {
    // `wire_type` is the one property whose writer can put the IR in a state its reader has no
    // spelling for: the reader answers `OpaqueString` only while the field *is* an opaque string,
    // so turning it into a parsed string leaves the source unreadable. Regenerating from an IR the
    // ledger can no longer describe would produce a mutation run nobody could reproduce, so the
    // read-back is what stops it — and this is the case that proves the read-back is not
    // decoration.
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let unreadable = Mutation::new(
        "q-timestamp-0005",
        "PutObject.input.Expires.wire_type",
        SourceValue::Text("OpaqueString".to_owned()),
        SourceValue::Text("String".to_owned()),
    )
    .expect("the plan itself is well formed");

    let error = generate_mutated(&input, &out, std::slice::from_ref(&unreadable))
        .expect_err("a write the reader cannot express must stop the run");
    assert!(error.to_string().contains("does not read back"), "{error}");
}
