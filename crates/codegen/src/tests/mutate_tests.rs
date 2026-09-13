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

use rustfs_gateway_model::ir::OperationIr;
use rustfs_gateway_model::{
    AllUnknownChildrenValue, CodecRule, CodecValue, HeaderToleranceValue, MutationDimension, UnknownElementPolicyValue,
};

use super::codegen_tests::{artifacts, root};
use crate::emit::quirk_toml::{ResolvedSource, SourceValue, resolve_at};
use crate::mutate::apply::apply;
use crate::mutate::{ABSENT_NOT_CONFIGURED_MUTANT, Mutation, apply_codec, plan, plan_codec, plan_contract, quirk_families};
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
        request_structure: false,
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
    let rules = operations
        .iter()
        .find(|operation| operation.operation == "GetBucketLifecycleConfiguration")
        .and_then(|operation| operation.output.iter().find(|field| field.name == "Rules"))
        .expect("the lifecycle output still has its Rules field");
    assert_eq!(
        rules.wire_name.as_deref(),
        Some("Rules"),
        "the wrapped mutant needs the list wrapper name"
    );
    let rustfs_gateway_model::ir::Type::List { wrapper_name, .. } = &rules.ty else {
        panic!("the mutated Rules field is still a list");
    };
    assert_eq!(wrapper_name.as_deref(), Some("Rule"), "the wrapped mutant keeps the entry name");
}

#[test]
fn a_wrapped_list_mutant_repeats_the_original_entry_name() {
    let mut operations = lowered();
    let path = "ListBuckets.output.Buckets.list_flattened";
    let current = resolve_at(&operations, path).expect("the wrapped bucket list resolves");
    assert_eq!(current, SourceValue::Bool(false), "the bucket list is wrapped on the wire");
    let mutation = plan("q-wrapped-0062", MutationDimension::WrapStrategy, &source(path, current)).expect("plannable");

    apply(&mut operations, &mutation).expect("the writer accepts its own plan");

    let buckets = operations
        .iter()
        .find(|operation| operation.operation == "ListBuckets")
        .and_then(|operation| operation.output.iter().find(|field| field.name == "Buckets"))
        .expect("the ListBuckets output still has its Buckets field");
    assert_eq!(
        buckets.wire_name.as_deref(),
        Some("Bucket"),
        "the flattened mutant repeats the entry name"
    );
    let rustfs_gateway_model::ir::Type::List {
        flattened, wrapper_name, ..
    } = &buckets.ty
    else {
        panic!("the mutated Buckets field is still a list");
    };
    assert!(*flattened, "the mutant is flattened");
    assert!(wrapper_name.is_none(), "a flattened mutant has no wrapper entry metadata");
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
fn an_absent_not_configured_error_is_flipped_to_a_declared_code() {
    // The rule's content is the absence: "this operation owes no operation-specific 404". Any
    // declared code violates it, so the flip that tests it is `None -> Some(..)` — and refusing to
    // plan it, as this planner once did, put six rules beyond the reach of the whole command
    // before anything was built (rustfs/backlog#1761).
    let mutation = plan(
        "q-example",
        MutationDimension::Optionality,
        &source("GetBucketAcl.errors.not_configured", SourceValue::OptionalText(None)),
    )
    .expect("an absent not-configured error has one obvious violation");
    assert_eq!(mutation.from, SourceValue::OptionalText(None));
    assert_eq!(
        mutation.to,
        SourceValue::OptionalText(Some(ABSENT_NOT_CONFIGURED_MUTANT.to_owned())),
        "the flip has to name a code the error-status authority declares, or the mutated tree \
         fails to compile and the row reads KILLED_BY_COMPILE instead of being measured"
    );
}

#[test]
fn n_the_code_the_absence_flip_writes_is_one_the_pinned_authority_declares() {
    // The control on the constant above. `OperationSpec::standard` asserts at const-evaluation
    // time that a lowered unconfigured code has a row in `model/overlays/error-status.toml`; a
    // constant that drifted out of that table would turn every one of these six rows into a
    // compile kill, which reads exactly like the compiler catching the mutation.
    let artifacts = artifacts();
    artifacts
        .error_codes
        .path(ABSENT_NOT_CONFIGURED_MUTANT)
        .unwrap_or_else(|error| panic!("`{ABSENT_NOT_CONFIGURED_MUTANT}` has no status row: {error}"));
}

#[test]
fn n_an_absent_optional_value_that_is_not_a_not_configured_error_has_no_planned_mutation() {
    // Absence is only self-evidently violable where the rule is "there is no code here". For any
    // other optional source the planner still has no evidence for which present value the protocol
    // would carry, and guessing one would test the harness rather than the corpus.
    let error = plan(
        "q-example",
        MutationDimension::Optionality,
        &source("GetObject.output.StorageClass.omit_when", SourceValue::OptionalText(None)),
    )
    .expect_err("dropping an already absent value changes nothing");
    assert!(error.contains("already absent"), "{error}");
}

#[test]
fn n_a_not_configured_source_under_another_dimension_is_still_unplannable() {
    // The absence flip is the `optionality` rule's flip. A different dimension pointed at the same
    // path is a declaration this planner has no reviewed answer for, and inventing one there would
    // silently widen what the matrix claims to have tested.
    let error = plan(
        "q-example",
        MutationDimension::ElementRename,
        &source("GetBucketAcl.errors.not_configured", SourceValue::OptionalText(None)),
    )
    .expect_err("only the optionality dimension has a planned absence flip");
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
fn a_contract_mutation_changes_the_generated_signature_input() {
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let plain = generate(&input, &out).expect("codegen runs");
    let rule = plain
        .contract_rules
        .get("q-sig-v2-included-query")
        .expect("the signature contract exists");
    let mutation = plan_contract("q-sig-v2-included-query", rule).expect("the boolean contract is plannable");

    let mutated = generate_mutated(&input, &out, std::slice::from_ref(&mutation)).expect("codegen runs");

    assert_ne!(plain.files, mutated.files, "the contract mutation must reach a generated consumer input");
    let paths: Vec<_> = plain.files.iter().map(|(path, _)| path).collect();
    let mutated_paths: Vec<_> = mutated.files.iter().map(|(path, _)| path).collect();
    assert_eq!(paths, mutated_paths, "a contract mutation must not add or remove an artefact");
}

#[test]
fn an_upload_id_scope_mutation_changes_the_generated_types_input() {
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let plain = generate(&input, &out).expect("codegen runs");
    let rule = plain
        .contract_rules
        .get("q-mpu-upload-id-0037")
        .expect("the upload-id scope contract exists");
    let mutation = plan_contract("q-mpu-upload-id-0037", rule).expect("the ownership scope is plannable");

    let mutated = generate_mutated(&input, &out, std::slice::from_ref(&mutation)).expect("codegen runs");

    assert_ne!(plain.files, mutated.files, "the ownership mutation must reach a generated types input");
    let current = plain
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("generated/upload_id_contracts.rs"))
        .expect("the upload-id contracts are emitted for the types exchange");
    let mutant = mutated
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("generated/upload_id_contracts.rs"))
        .expect("the mutant upload-id contracts are emitted for the types exchange");
    assert!(current.1.contains("UPLOAD_ID_REQUIRES_BUCKET_AND_KEY: bool = true"));
    assert!(mutant.1.contains("UPLOAD_ID_REQUIRES_BUCKET_AND_KEY: bool = false"));
    let current_record = plain
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-mpu-upload-id-0037.toml"))
        .expect("the upload-id mutable rule is emitted");
    let mutant_record = mutated
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-mpu-upload-id-0037.toml"))
        .expect("the mutant upload-id mutable rule is emitted");
    assert!(current_record.1.contains("contract_value = \"bucket_and_key\""));
    assert!(mutant_record.1.contains("contract_value = \"upload_id_only\""));
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

#[test]
fn an_empty_element_rule_is_planned_in_the_irs_own_spelling() {
    // The IR spells these `emit`/`omit`. Matching them capitalised made every empty-element rule
    // report UNPLANNABLE — a rule the executor silently declines to test reads, in a matrix, very
    // much like a rule with nothing to test.
    let mut operations = lowered();
    let path = "GetBucketLocation.xml.empty_value.LocationConstraint";
    let current = resolve_at(&operations, path).expect("the location constraint has an empty-value policy");
    assert_eq!(current, SourceValue::Text("emit".to_owned()));
    let mutation = plan("q-empty-0002", MutationDimension::EmptyElementRender, &source(path, current))
        .expect("an empty-element rule has exactly one opposite");

    apply(&mut operations, &mutation).expect("the writer accepts its own plan");

    assert_eq!(
        resolve_at(&operations, path).expect("still resolves"),
        SourceValue::Text("omit".to_owned())
    );
}

#[test]
fn n_an_empty_element_spelling_the_ir_does_not_define_is_refused() {
    let error = plan(
        "q-empty-0002",
        MutationDimension::EmptyElementRender,
        &source("Op.xml.empty_value.X", SourceValue::Text("Emit".to_owned())),
    )
    .expect_err("a capitalised spelling is not an IR spelling");
    assert!(error.contains("does not define"), "{error}");
}

#[test]
fn a_codec_enum_is_flipped_and_read_back() {
    let mut rules = std::collections::BTreeMap::from([(
        "q-acl-0006".to_owned(),
        CodecRule {
            current: CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Skip),
            mutation_dimension: MutationDimension::UnknownElementPolicy,
        },
    )]);
    let mutation = plan_codec("q-acl-0006", &rules["q-acl-0006"]).expect("the codec rule is plannable");

    assert!(apply_codec(&mut rules, &mutation).expect("the writer accepts its own plan"));
    assert_eq!(
        rules["q-acl-0006"].current,
        CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Reject)
    );
}

#[test]
fn an_all_unknown_children_guard_is_flipped_and_read_back() {
    let mut rules = std::collections::BTreeMap::from([(
        "q-repl-0014".to_owned(),
        CodecRule {
            current: CodecValue::AllUnknownChildren(AllUnknownChildrenValue::Reject),
            mutation_dimension: MutationDimension::AllUnknownChildren,
        },
    )]);
    let mutation = plan_codec("q-repl-0014", &rules["q-repl-0014"]).expect("the codec rule is plannable");

    assert!(apply_codec(&mut rules, &mutation).expect("the writer accepts its own plan"));
    assert_eq!(
        rules["q-repl-0014"].current,
        CodecValue::AllUnknownChildren(AllUnknownChildrenValue::Allow)
    );
}

#[test]
fn a_codec_integer_range_is_flipped_to_the_unbounded_default() {
    let mut rules = std::collections::BTreeMap::from([(
        "q-part-number-0072".to_owned(),
        CodecRule {
            current: CodecValue::IntegerRange { min: 1, max: 10_000 },
            mutation_dimension: MutationDimension::IntegerRange,
        },
    )]);
    let mutation = plan_codec("q-part-number-0072", &rules["q-part-number-0072"]).expect("the range is plannable");

    assert!(apply_codec(&mut rules, &mutation).expect("the writer accepts its own plan"));
    assert!(!rules.contains_key("q-part-number-0072"), "absence selects the unbounded integer parser");
}

#[test]
fn a_contract_wire_form_has_no_codec_mutation_plan() {
    let artifacts = super::codegen_tests::artifacts();
    for id in ["q-etag-form-0074", "q-token-form-0075", "q-marker-form-0076"] {
        assert!(
            !artifacts.codec_rules.contains_key(id),
            "{id} must not produce a duplicate codec mutation"
        );
    }
}

#[test]
fn a_header_tolerance_is_flipped_to_the_strict_default() {
    let mut rules = std::collections::BTreeMap::from([(
        "q-cond-0050".to_owned(),
        CodecRule {
            current: CodecValue::HeaderTolerance(HeaderToleranceValue::DateCondition),
            mutation_dimension: MutationDimension::HeaderTolerance,
        },
    )]);
    let mutation = plan_codec("q-cond-0050", &rules["q-cond-0050"]).expect("the tolerance is plannable");

    assert!(apply_codec(&mut rules, &mutation).expect("the writer accepts its own plan"));
    assert!(!rules.contains_key("q-cond-0050"), "absence is the strict decoder default");
}

#[test]
fn n_the_codec_writer_refuses_a_stale_plan() {
    let mut rules = std::collections::BTreeMap::from([(
        "q-acl-0006".to_owned(),
        CodecRule {
            current: CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Reject),
            mutation_dimension: MutationDimension::UnknownElementPolicy,
        },
    )]);
    let stale = Mutation::new(
        "q-acl-0006",
        "@codec.q-acl-0006",
        SourceValue::Text("skip".to_owned()),
        SourceValue::Text("reject".to_owned()),
    )
    .expect("the plan itself is well formed");

    let error = apply_codec(&mut rules, &stale).expect_err("a stale plan must not be written");
    assert!(error.contains("disagree"), "{error}");
}

#[test]
fn n_a_codec_value_and_its_dimension_must_agree() {
    let rule = CodecRule {
        current: CodecValue::MediaType("application/json".to_owned()),
        mutation_dimension: MutationDimension::IntegerRange,
    };

    let error = plan_codec("q-example", &rule).expect_err("a mismatched codec declaration must not be planned");
    assert!(error.contains("media_type") && error.contains("integer_range"), "{error}");
}

#[test]
fn n_a_codec_path_cannot_name_a_different_rule() {
    let mut rules = std::collections::BTreeMap::from([(
        "q-acl-0006".to_owned(),
        CodecRule {
            current: CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Skip),
            mutation_dimension: MutationDimension::UnknownElementPolicy,
        },
    )]);
    let misplaced = Mutation::new(
        "q-acl-0006",
        "@codec.q-cors-0007",
        SourceValue::Text("skip".to_owned()),
        SourceValue::Text("reject".to_owned()),
    )
    .expect("the plan itself is well formed");

    let error = apply_codec(&mut rules, &misplaced).expect_err("one rule must not write another rule's value");
    assert!(
        error.contains("names `q-cors-0007`") && error.contains("belongs to `q-acl-0006`"),
        "{error}"
    );
}

/// The three `required_body` rules and the one generated decoder each one's mutation must reach.
const REQUIRED_BODY_RULES: [(&str, &str); 3] = [
    ("q-lock-0007", "codec/ops/put_object_retention.rs"),
    ("q-restore-0006", "codec/ops/restore_object.rs"),
    ("q-web-0004", "codec/ops/put_bucket_website.rs"),
];

fn file<'a>(artifacts: &'a crate::Artifacts, suffix: &str) -> &'a str {
    artifacts
        .files
        .iter()
        .find(|(path, _)| path.ends_with(suffix))
        .map(|(_, bytes)| bytes.as_str())
        .unwrap_or_else(|| panic!("no generated artefact ends with `{suffix}`"))
}

#[test]
fn a_required_body_rule_is_violated_on_the_wire_without_retyping_its_member() {
    // rustfs/backlog#1726: flipping `required` to `false` made each payload `Option<T>`, the
    // fixture stopped compiling, and all three rows read KILLED_BY_COMPILE with no case consulted.
    // The plan now has to change the decoder and nothing a consumer compiles against.
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let plain = generate(&input, &out).expect("codegen runs");
    for (quirk, decoder) in REQUIRED_BODY_RULES {
        let sources = plain.source_rules.get(quirk).expect("the rule has resolved sources");
        let mutations: Vec<Mutation> = sources
            .iter()
            .map(|source| {
                assert!(source.request_structure, "`{}` is a required structure member", source.path);
                plan(quirk, MutationDimension::Optionality, source).expect("a required structure is plannable")
            })
            .collect();
        for mutation in &mutations {
            assert!(
                mutation.path.ends_with(".default_document"),
                "`{quirk}` must not be planned as a type change: {}",
                mutation.path
            );
        }

        let mutated = generate_mutated(&input, &out, &mutations).expect("codegen runs");

        // Doc comments may say the member now has a wire default; the code a consumer compiles
        // against may not change by a single token.
        let dto = |artifacts: &crate::Artifacts| -> Vec<(std::path::PathBuf, String)> {
            artifacts
                .files
                .iter()
                .filter(|(path, _)| path.components().any(|part| part.as_os_str() == "dto"))
                .map(|(path, bytes)| {
                    let code: Vec<&str> = bytes.lines().filter(|line| !line.trim_start().starts_with("///")).collect();
                    (path.clone(), code.join("\n"))
                })
                .collect()
        };
        assert_eq!(dto(&plain), dto(&mutated), "`{quirk}` must leave every dto type as it was");
        assert_ne!(
            file(&plain, decoder),
            file(&mutated, decoder),
            "`{quirk}` must reach the decoder that refuses the absent document"
        );
    }
}

#[test]
fn a_defaulted_payload_reads_an_empty_body_as_the_default_document() {
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let plain = generate(&input, &out).expect("codegen runs");
    let mutations: Vec<Mutation> = plain.source_rules["q-lock-0007"]
        .iter()
        .map(|source| plan("q-lock-0007", MutationDimension::Optionality, source).expect("plannable"))
        .collect();

    let mutated = generate_mutated(&input, &out, &mutations).expect("codegen runs");

    let defaulted =
        "        if raw_body.as_ref().is_empty() {\n            input.retention = Default::default();\n        } else {\n";
    assert!(!file(&plain, "codec/ops/put_object_retention.rs").contains(defaulted));
    assert!(
        file(&mutated, "codec/ops/put_object_retention.rs").contains(defaulted),
        "the mutant is the upstream defect: an empty body read as a defaulted retention"
    );
}

#[test]
fn a_defaulted_shape_member_is_no_longer_refused_when_absent() {
    let root = root();
    let input = CodegenInput::at(&root);
    let out = CodegenOutput::at(&root);
    let plain = generate(&input, &out).expect("codegen runs");
    let mutations: Vec<Mutation> = plain.source_rules["q-web-0004"]
        .iter()
        .map(|source| plan("q-web-0004", MutationDimension::Optionality, source).expect("plannable"))
        .collect();

    let mutated = generate_mutated(&input, &out, &mutations).expect("codegen runs");

    let refusal = ".about(\"Redirect\")";
    assert!(file(&plain, "codec/ops/put_bucket_website.rs").contains(refusal));
    assert!(
        !file(&mutated, "codec/ops/put_bucket_website.rs").contains(refusal),
        "a routing rule with no Redirect must decode to a default redirect under the mutation"
    );
}

#[test]
fn n_a_required_member_that_is_not_a_request_structure_keeps_the_boolean_flip() {
    // Only a structure has a default document to fall back to; a required output string keeps
    // the plain opposite, and the planner must not widen the new plan onto it.
    let plain = artifacts();
    let source = plain.source_rules["q-empty-0063"]
        .iter()
        .find(|source| source.path == "ListObjects.output.Prefix.required")
        .expect("the ListObjects prefix source resolves");
    assert!(!source.request_structure);

    let mutation = plan("q-empty-0063", MutationDimension::Optionality, source).expect("plannable");

    assert_eq!(mutation.path, source.path);
    assert_eq!(mutation.to, SourceValue::Bool(false));
}

#[test]
fn n_a_default_document_is_refused_on_a_member_that_is_not_a_structure() {
    let mut operations = lowered();
    let path = "PutObjectRetention.input.Bucket.default_document";
    let error = resolve_at(&operations, path).expect_err("a bucket label has no default document");
    assert!(error.contains("not a required structure"), "{error}");

    let forced = Mutation::new("q-lock-0007", path, SourceValue::Bool(false), SourceValue::Bool(true))
        .expect("the plan itself is well formed");
    apply(&mut operations, &forced).expect_err("the writer must not invent a default for a scalar");
}

#[test]
fn a_default_document_is_written_where_the_reader_reads_it() {
    let mut operations = lowered();
    let path = "PutBucketWebsite.shapes.RoutingRule.fields.Redirect.default_document";
    assert_eq!(resolve_at(&operations, path).expect("resolves"), SourceValue::Bool(false));
    let mutation = Mutation::new("q-web-0004", path, SourceValue::Bool(false), SourceValue::Bool(true)).expect("well formed");

    apply(&mut operations, &mutation).expect("the writer accepts its own plan");

    assert_eq!(resolve_at(&operations, path).expect("resolves"), SourceValue::Bool(true));
    assert_eq!(
        resolve_at(&operations, "PutBucketWebsite.shapes.RoutingRule.fields.Redirect.required").expect("resolves"),
        SourceValue::Bool(true),
        "the member stays required, so its dto type stays bare"
    );
}
