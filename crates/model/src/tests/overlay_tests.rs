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

use crate::overlay::Overlay;

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
        "[[quirk]]\nid = \"q-codec-0001\"\nkind = \"wire_form\"\nclassification = \"mutable\"\ncodec_value = \"entity_tag\"\n\
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
        "[[quirk]]\nid = \"q-codec-0002\"\nkind = \"wire_form\"\nclassification = \"mutable\"\nmutation_dimension = \"wire_form\"\n\
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
            "classification = \"contract\"\ncodec_value = \"entity_tag\"\nmutation_dimension = \"wire_form\"\n",
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
