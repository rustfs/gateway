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

//! Tests for the sharded overlay directory: the merge, and every collision it refuses.
//!
//! The merge itself is one positive case. Everything else here is a collision, because a
//! last-write-wins merge across ten family files is the failure this layout introduces and the
//! only reason the loader is more than a `read_to_string`.

use std::path::{Path, PathBuf};

use crate::overlay::{
    ContractValue, MutationDimension, Overlay, ROUTE_FILE, RuleClassification, UploadIdCapabilityScopeValue, is_quirk_id,
};

/// A throwaway overlay directory. Removed on drop, so a failing assertion does not leak one.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("gateway-overlay-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for sub in ["ops", "quirks"] {
            std::fs::create_dir_all(root.join(sub)).expect("test sandbox is creatable");
        }
        let sandbox = Self { root };
        sandbox.write("scalars.toml", "[scalar]\nETag = \"ETag\"\n");
        // The route overlay is required to exist: a missing authority is a failure, never an
        // empty declaration set. A fixture with no cross-precedence overlap declares none.
        sandbox.write(ROUTE_FILE, "# no reviewed cross-precedence overlap in this fixture\n");
        // The error-status authority is required for the same reason, and one row is enough for a
        // test that is about something else.
        sandbox.write(
            "error-status.toml",
            "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\n",
        );
        // Both directories must hold at least one family file, so every sandbox starts with the
        // one that is not the subject of the test.
        sandbox.write("quirks/base.toml", &quirk("q-base-0001", "c-base-0001"));
        sandbox
    }

    fn write(&self, relative: &str, body: &str) -> &Self {
        std::fs::write(self.root.join(relative), body).expect("test sandbox is writable");
        self
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// One well-formed quirk, so that a collision test is not also an evidence test.
fn quirk(id: &str, case: &str) -> String {
    format!(
        "[[quirk]]\nid = \"{id}\"\nkind = \"test\"\nclassification = \"contract\"\ntarget = \"Alpha\"\n\
         summary = \"A behaviour the model does not state at all.\"\ncases = [\"{case}\"]\n\n\
         [[quirk.evidence]]\nkind = \"observed\"\nref = \"https://example.invalid/a\"\n\
         summary = \"Written by the test, never pasted.\"\n"
    )
}

fn load_error(sandbox: &Sandbox) -> String {
    match Overlay::load(sandbox.path()) {
        Ok(_) => panic!("the overlay loaded when it should have been refused"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn merges_every_family_file_in_the_directory() {
    let sandbox = Sandbox::new("merge");
    sandbox
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n\n[op.Alpha]\nprecedence = 100\n")
        .write(
            "ops/beta.toml",
            "include = [\"Beta\"]\n\n[op.Beta]\nprecedence = 200\n\n[shape.Thing]\nhot = [\"Name\"]\n",
        )
        .write("quirks/alpha.toml", &quirk("q-alpha-0002", "c-alpha-0001"))
        .write("quirks/beta.toml", &quirk("q-beta-0003", "c-beta-0002"));

    let overlay = Overlay::load(sandbox.path()).expect("a sharded overlay with no collision loads");

    assert_eq!(overlay.include, vec!["Alpha".to_owned(), "Beta".to_owned()]);
    assert!(overlay.ops.contains_key("Alpha") && overlay.ops.contains_key("Beta"));
    assert!(overlay.shapes.contains_key("Thing"));
    assert_eq!(
        overlay.quirk_ids(),
        vec!["q-alpha-0002".to_owned(), "q-base-0001".to_owned(), "q-beta-0003".to_owned()]
    );
    assert_eq!(overlay.scalars.get("ETag").map(String::as_str), Some("ETag"));
}

#[test]
fn loads_a_mutable_runtime_contract_rule() {
    let sandbox = Sandbox::new("mutable-contract");
    sandbox
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n\n[op.Alpha]\nprecedence = 100\n")
        .write(
            "quirks/signature.toml",
            "[[quirk]]\nid = \"q-sig-test-9999\"\nkind = \"signature_policy\"\nclassification = \"mutable\"\nmutation_dimension = \"signature_canonical_host_policy\"\ncontract_value = \"raw_host_bytes\"\ntarget = \"Signature.Test\"\nsummary = \"A generated signature policy consumed by the verifier.\"\ncases = [\"c-sig-9999\"]\n\n[[quirk.evidence]]\nkind = \"decision\"\nref = \"https://example.invalid/signature\"\nsummary = \"The test records an independently reviewed signature decision.\"\n",
        );

    let overlay = Overlay::load(sandbox.path()).expect("a mutable runtime contract loads");

    assert_eq!(overlay.classifications.get("q-sig-test-9999"), Some(&RuleClassification::Mutable));
    assert!(overlay.contract_rules.contains_key("q-sig-test-9999"));
}

#[test]
fn loads_the_upload_id_resource_scope_as_a_mutable_runtime_contract() {
    let sandbox = Sandbox::new("upload-id-scope-contract");
    sandbox
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n\n[op.Alpha]\nprecedence = 100\n")
        .write(
            "quirks/multipart.toml",
            "[[quirk]]\nid = \"q-mpu-upload-id-0037\"\nkind = \"capability_token\"\nclassification = \"mutable\"\nmutation_dimension = \"upload_id_capability_scope\"\ncontract_value = \"bucket_and_key\"\ntarget = \"UploadPart.UploadId\"\nsummary = \"The upload token is resolved within its bucket and key.\"\ncases = [\"c-mpu-0028\"]\n\n[[quirk.evidence]]\nkind = \"observed\"\nref = \"local\"\nsummary = \"The test fixture records the ownership requirement.\"\n",
        );

    let overlay = Overlay::load(sandbox.path()).expect("the typed upload-id scope contract loads");
    let rule = overlay
        .contract_rules
        .get("q-mpu-upload-id-0037")
        .expect("the upload-id contract is retained");

    assert_eq!(rule.mutation_dimension, MutationDimension::UploadIdCapabilityScope);
    assert_eq!(
        rule.current,
        ContractValue::UploadIdCapabilityScope(UploadIdCapabilityScopeValue::BucketAndKey)
    );
}

#[test]
fn accepts_a_descriptive_quirk_id_without_a_numeric_suffix() {
    assert!(is_quirk_id("q-sig-v2-included-query"));
    assert!(!is_quirk_id("q-sig-v2-Included-query"));
    assert!(!is_quirk_id("q-sig-v2--included-query"));
}

#[test]
fn refuses_one_operation_declared_by_two_families() {
    let sandbox = Sandbox::new("op-twice");
    sandbox
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n\n[op.Alpha]\nprecedence = 100\n")
        .write("ops/zeta.toml", "[op.Alpha]\nprecedence = 900\n");

    let message = load_error(&sandbox);
    assert!(message.contains("ops/alpha.toml"), "{message}");
    assert!(message.contains("ops/zeta.toml"), "{message}");
    assert!(message.contains("Alpha"), "{message}");
}

#[test]
fn refuses_one_operation_included_by_two_families() {
    let sandbox = Sandbox::new("include-twice");
    sandbox
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n")
        .write("ops/zeta.toml", "include = [\"Alpha\"]\n");

    let message = load_error(&sandbox);
    assert!(message.contains("ops/alpha.toml") && message.contains("ops/zeta.toml"), "{message}");
}

#[test]
fn refuses_one_operation_deferred_by_two_families() {
    let sandbox = Sandbox::new("deferred-twice");
    sandbox
        .write("ops/alpha.toml", "[[deferred]]\nreason = \"not yet\"\noperations = [\"Alpha\"]\n")
        .write("ops/zeta.toml", "[[deferred]]\nreason = \"also not yet\"\noperations = [\"Alpha\"]\n");

    let message = load_error(&sandbox);
    assert!(message.contains("ops/alpha.toml") && message.contains("ops/zeta.toml"), "{message}");
}

#[test]
fn refuses_an_operation_one_family_includes_and_another_defers() {
    let sandbox = Sandbox::new("include-and-defer");
    sandbox
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n")
        .write("ops/zeta.toml", "[[deferred]]\nreason = \"not yet\"\noperations = [\"Alpha\"]\n");

    let message = load_error(&sandbox);
    assert!(message.contains("ops/alpha.toml") && message.contains("ops/zeta.toml"), "{message}");
}

#[test]
fn refuses_one_shape_declared_by_two_families() {
    let sandbox = Sandbox::new("shape-twice");
    sandbox
        .write("ops/alpha.toml", "[shape.Thing]\nhot = [\"Name\"]\n")
        .write("ops/zeta.toml", "[shape.Thing]\nhot = [\"Other\"]\n");

    let message = load_error(&sandbox);
    assert!(message.contains("ops/alpha.toml") && message.contains("ops/zeta.toml"), "{message}");
    assert!(message.contains("Thing"), "{message}");
}

#[test]
fn refuses_one_quirk_id_declared_by_two_families() {
    let sandbox = Sandbox::new("quirk-twice");
    sandbox
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n")
        .write("quirks/alpha.toml", &quirk("q-alpha-0001", "c-alpha-0001"))
        .write("quirks/zeta.toml", &quirk("q-alpha-0001", "c-zeta-0009"));
    // `quirks/base.toml` is the third file and declares a different id, so the only collision in
    // this sandbox is the one under test.

    let message = load_error(&sandbox);
    assert!(message.contains("quirks/alpha.toml") && message.contains("quirks/zeta.toml"), "{message}");
    assert!(message.contains("q-alpha-0001"), "{message}");
}

#[test]
fn n_a_codec_value_without_a_mutation_dimension_is_not_a_mutable_rule() {
    let sandbox = Sandbox::new("codec-without-mutation");
    sandbox.write("ops/alpha.toml", "include = [\"Alpha\"]\n").write(
        "quirks/codec.toml",
        "[[quirk]]\nid = \"q-codec-0001\"\nkind = \"payload_media\"\nclassification = \"mutable\"\ncodec_value = \"application/json\"\n\
             target = \"Alpha.Value\"\nsummary = \"The wire value has one grammar.\"\ncases = [\"c-codec-0001\"]\n\n\
             [[quirk.evidence]]\nkind = \"observed\"\nref = \"https://example.invalid/codec\"\n\
             summary = \"Written by the test, never pasted.\"\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("q-codec-0001") && message.contains("mutation_dimension"), "{message}");
}

#[test]
fn n_a_mutation_dimension_without_a_codec_value_is_metadata_not_a_rule() {
    let sandbox = Sandbox::new("mutation-without-codec");
    sandbox.write("ops/alpha.toml", "include = [\"Alpha\"]\n").write(
        "quirks/codec.toml",
        "[[quirk]]\nid = \"q-codec-0002\"\nkind = \"payload_media\"\nclassification = \"mutable\"\nmutation_dimension = \"media_type\"\n\
             target = \"Alpha.Value\"\nsummary = \"The wire value has one grammar.\"\ncases = [\"c-codec-0002\"]\n\n\
             [[quirk.evidence]]\nkind = \"observed\"\nref = \"https://example.invalid/codec\"\n\
             summary = \"Written by the test, never pasted.\"\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("q-codec-0002") && message.contains("`codec_value`"), "{message}");
}

#[test]
fn n_every_protocol_record_has_an_explicit_classification() {
    let sandbox = Sandbox::new("missing-classification");
    sandbox.write("ops/alpha.toml", "include = [\"Alpha\"]\n").write(
        "quirks/unclear.toml",
        &quirk("q-unclear-0001", "c-unclear-0001").replace("classification = \"contract\"\n", ""),
    );

    let message = load_error(&sandbox);
    assert!(message.contains("q-unclear-0001") && message.contains("classification"), "{message}");
}

#[test]
fn n_a_contract_cannot_carry_mutable_codec_input() {
    let sandbox = Sandbox::new("contract-with-codec");
    sandbox.write("ops/alpha.toml", "include = [\"Alpha\"]\n").write(
        "quirks/contract.toml",
        &quirk("q-contract-0001", "c-contract-0001").replace(
            "classification = \"contract\"\n",
            "classification = \"contract\"\ncodec_value = \"application/json\"\nmutation_dimension = \"media_type\"\n",
        ),
    );

    let message = load_error(&sandbox);
    assert!(message.contains("q-contract-0001") && message.contains("contract"), "{message}");
}

#[test]
fn n_a_mutable_record_cannot_lack_a_typed_rule() {
    let sandbox = Sandbox::new("mutable-without-rule");
    sandbox.write("ops/alpha.toml", "include = [\"Alpha\"]\n").write(
        "quirks/mutable.toml",
        &quirk("q-mutable-0001", "c-mutable-0001").replace("classification = \"contract\"", "classification = \"mutable\""),
    );

    let message = load_error(&sandbox);
    assert!(message.contains("q-mutable-0001") && message.contains("typed rule"), "{message}");
}

#[test]
fn a_mutable_source_rule_is_explicit_and_does_not_use_free_text_kind() {
    let sandbox = Sandbox::new("mutable-source");
    sandbox.write("ops/alpha.toml", "include = [\"Alpha\"]\n").write(
        "quirks/source.toml",
        &quirk("q-source-0001", "c-source-0001")
            .replace("kind = \"test\"", "kind = \"unrelated_metadata\"")
            .replace(
                "classification = \"contract\"\n",
                "classification = \"mutable\"\nmutation_dimension = \"element_order\"\n\
                 mutation_sources = [\"Alpha.xml.element_order\"]\n",
            ),
    );

    let overlay = Overlay::load(sandbox.path()).expect("an explicit source rule loads");
    let rule = overlay
        .source_rules
        .get("q-source-0001")
        .expect("the source rule is retained");
    assert_eq!(rule.sources, vec!["Alpha.xml.element_order"]);
}

#[test]
fn refuses_a_family_file_carrying_the_scalar_vocabulary() {
    let sandbox = Sandbox::new("family-scalar");
    sandbox.write("ops/alpha.toml", "[scalar]\nETag = \"String\"\n");

    let message = load_error(&sandbox);
    assert!(message.contains("scalars.toml"), "{message}");
    assert!(message.contains("ops/alpha.toml"), "{message}");
}

#[test]
fn refuses_the_scalar_file_carrying_an_operation() {
    let sandbox = Sandbox::new("scalar-op");
    sandbox
        .write("scalars.toml", "[scalar]\nETag = \"ETag\"\n\n[op.Alpha]\nprecedence = 1\n")
        .write("ops/alpha.toml", "include = [\"Alpha\"]\n");

    let message = load_error(&sandbox);
    assert!(message.contains("scalars.toml") && message.contains("ops/<family>.toml"), "{message}");
}

#[test]
fn refuses_an_ops_directory_with_no_family_file() {
    let sandbox = Sandbox::new("empty-ops");
    let message = load_error(&sandbox);
    assert!(message.contains("ops/"), "{message}");
}

#[test]
fn refuses_a_missing_quirks_directory() {
    let sandbox = Sandbox::new("no-quirks");
    sandbox.write("ops/alpha.toml", "include = [\"Alpha\"]\n");
    std::fs::remove_dir_all(sandbox.path().join("quirks")).expect("the sandbox directory is removable");

    let message = load_error(&sandbox);
    assert!(message.contains("quirks"), "{message}");
}

// ── The error code to HTTP status authority ───────────────────────────────────────────────────
//
// Every case below is a shape that would put a status nobody chose onto the wire. The positive
// one is last on purpose: what matters about this file is what it refuses.

/// The `ops/` file every error-status sandbox needs, so that a refusal is about the authority.
fn minimal_ops() -> &'static str {
    "include = [\"Alpha\"]\n\n[op.Alpha]\nprecedence = 100\n"
}

#[test]
fn n_optional_quirk_strings_reject_other_types() {
    let sandbox = Sandbox::new("optional-quirk-strings");
    sandbox.write("ops/alpha.toml", minimal_ops());
    for key in ["contract_value", "mutation_dimension"] {
        for value in ["false", "7", "[]"] {
            let declaration = quirk("q-optional-0001", "c-optional-0001").replace(
                "classification = \"contract\"\n",
                &format!("classification = \"contract\"\n{key} = {value}\n"),
            );
            sandbox.write("quirks/base.toml", &declaration);
            let message = load_error(&sandbox);
            assert!(
                message.contains("q-optional-0001") && message.contains(key) && message.contains("string"),
                "{message}"
            );
        }
    }
}

#[test]
fn refuses_one_error_code_declared_twice() {
    let sandbox = Sandbox::new("code-twice");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\n\n\
         [[code]]\nname = \"NoSuchKey\"\nconstant = \"MISSING_KEY\"\nstatus = 400\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("NoSuchKey") && message.contains("NO_SUCH_KEY"), "{message}");
    assert!(message.contains("MISSING_KEY"), "{message}");
}

#[test]
fn refuses_one_constant_declared_twice() {
    let sandbox = Sandbox::new("constant-twice");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\n\n\
         [[code]]\nname = \"NoSuchThing\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("NO_SUCH_KEY"), "{message}");
    assert!(message.contains("NoSuchThing"), "{message}");
}

#[test]
fn refuses_a_5xx_row_that_did_not_declare_itself_a_server_fault() {
    // The digit that turns a 400 into a 500 is one keystroke, and the consequence is an SDK
    // retrying a request that cannot succeed. The flag is what a typo cannot also write.
    let sandbox = Sandbox::new("unflagged-5xx");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"InvalidArgument\"\nconstant = \"INVALID_ARGUMENT\"\nstatus = 500\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("InvalidArgument") && message.contains("server_fault"), "{message}");
}

#[test]
fn refuses_a_server_fault_flag_on_a_client_error() {
    // The other direction: a flag that outlives the status it described would quietly widen the
    // allowlist for whatever row inherits it next.
    let sandbox = Sandbox::new("flagged-4xx");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"InvalidArgument\"\nconstant = \"INVALID_ARGUMENT\"\nstatus = 400\nserver_fault = true\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("InvalidArgument") && message.contains("server_fault"), "{message}");
}

#[test]
fn refuses_a_status_that_is_not_an_http_status() {
    let sandbox = Sandbox::new("nonsense-status");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 42\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("42") && message.contains("NoSuchKey"), "{message}");
}

/// c-err-1011 — the acceptance id rustfs/backlog#1694 §7 gives this rule.
#[test]
fn refuses_a_row_without_a_status() {
    let sandbox = Sandbox::new("no-status");
    sandbox
        .write("ops/alpha.toml", minimal_ops())
        .write("error-status.toml", "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\n");

    let message = load_error(&sandbox);
    assert!(message.contains("status"), "{message}");
}

#[test]
fn refuses_a_constant_that_is_not_a_rust_constant_name() {
    let sandbox = Sandbox::new("bad-constant");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"no_such_key\"\nstatus = 404\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("no_such_key"), "{message}");
}

#[test]
fn refuses_an_authority_with_no_rows() {
    let sandbox = Sandbox::new("no-rows");
    sandbox
        .write("ops/alpha.toml", minimal_ops())
        .write("error-status.toml", "# nothing at all\n");

    let message = load_error(&sandbox);
    assert!(message.contains("[[code]]"), "{message}");
}

#[test]
fn refuses_per_operation_keys_in_the_authority() {
    let sandbox = Sandbox::new("authority-op");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\n\n\
         [op.Alpha]\nprecedence = 1\n",
    );

    let message = load_error(&sandbox);
    assert!(
        message.contains("error-status.toml") && message.contains("ops/<family>.toml"),
        "{message}"
    );
}

#[test]
fn refuses_a_note_line_that_is_blank() {
    let sandbox = Sandbox::new("blank-note");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\nnote = [\"a line\", \"  \"]\n",
    );

    let message = load_error(&sandbox);
    assert!(message.contains("NoSuchKey") && message.contains("note"), "{message}");
}

#[test]
fn loads_a_well_formed_authority_in_declaration_order() {
    let sandbox = Sandbox::new("authority-ok");
    sandbox.write("ops/alpha.toml", minimal_ops()).write(
        "error-status.toml",
        "[[code]]\nname = \"NoSuchKey\"\nconstant = \"NO_SUCH_KEY\"\nstatus = 404\nnote = [\"Only when listable.\"]\n\n\
         [[code]]\nname = \"InternalError\"\nconstant = \"INTERNAL_ERROR\"\nstatus = 500\nserver_fault = true\n",
    );

    let overlay = Overlay::load(sandbox.path()).expect("a well-formed authority loads");
    let names: Vec<&str> = overlay.error_status.iter().map(|row| row.name.as_str()).collect();
    assert_eq!(names, vec!["NoSuchKey", "InternalError"]);
    assert_eq!(overlay.error_status[0].status, 404);
    assert_eq!(overlay.error_status[0].note, vec!["Only when listable.".to_owned()]);
    assert!(!overlay.error_status[0].server_fault);
    assert!(overlay.error_status[1].server_fault);
}
