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
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{CodegenInput, CodegenOutput, generate, semantic, why};

pub(super) fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above the crate manifest")
        .to_path_buf()
}

pub(super) fn artifacts() -> crate::Artifacts {
    let root = root();
    generate(&CodegenInput::at(&root), &CodegenOutput::at(&root)).expect("codegen runs against the pinned model")
}

pub(super) fn body(artifacts: &crate::Artifacts, suffix: &str) -> String {
    artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with(suffix))
        .map(|(_, body)| body.clone())
        .unwrap_or_else(|| panic!("no generated file ends with {suffix}"))
}

#[test]
fn c_cg_0002_the_working_tree_matches_a_fresh_run() {
    let root = root();
    let count = crate::verify(&CodegenInput::at(&root), &CodegenOutput::at(&root))
        .expect("the checked-in artefacts are what codegen produces; run `cargo xtask codegen`");
    assert!(count >= 9, "every artefact is covered by the gate, saw {count}");
}

#[test]
fn c_cg_0004_two_runs_produce_identical_bytes() {
    let first = artifacts();
    let second = artifacts();
    assert_eq!(first.files.len(), second.files.len());
    for ((path_a, body_a), (path_b, body_b)) in first.files.iter().zip(second.files.iter()) {
        assert_eq!(path_a, path_b);
        assert_eq!(body_a, body_b, "{} is not deterministic", path_a.display());
    }
}

#[test]
fn routing_query_bits_are_generated_from_the_lowered_selectors() {
    let text = body(&artifacts(), "generated/subresource_bits.rs");
    assert!(text.contains("pub(crate) static SUBRESOURCE_BITS: phf::Map"), "{text}");
    assert!(text.contains("\"analytics\" =>"), "{text}");
    assert!(text.contains("\"id\" =>"), "{text}");
    assert!(text.contains("\"list-type\" =>"), "{text}");
    assert!(!text.contains("\"prefix\" =>"), "a non-selector query key must not consume a bit");
}

#[test]
fn c_cg_0003_operations_md_carries_three_reverse_indexes() {
    let text = body(&artifacts(), "OPERATIONS.md");
    for heading in [
        "## Reverse index: query key to operations",
        "## Reverse index: header to operations",
        "## Reverse index: error code to operations",
    ] {
        assert!(text.contains(heading), "missing {heading}");
    }
    // The reverse index is only useful if it actually resolves a failure to an operation. A row is
    // asserted up to the first operation it names and no further: a code or a header that a second
    // family also declares gains an entry in the same row, and pinning the whole row would make
    // this test fail for every family that legitimately shares one — which says nothing about
    // whether the index resolves.
    assert!(text.contains("| `list-type` | [ListObjectsV2](#listobjectsv2) |"));
    assert!(text.contains("| `MissingContentLength` | [PutObject](#putobject)"));
    assert!(text.contains("| `x-amz-checksum-` | [CompleteMultipartUpload](#completemultipartupload)"));
}

#[test]
fn a_source_rule_emits_current_values_from_the_lowered_ir() {
    let artifacts = artifacts();
    let (_, quirk) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-order-0014.toml"))
        .expect("the source-backed quirk table is generated");

    assert!(quirk.contains("mutation_dimension = \"element_order\""), "{quirk}");
    assert!(quirk.contains("path = \"ListObjectsV2.xml.element_order\""), "{quirk}");
    assert!(quirk.contains("current = [\"Name\", \"Prefix\", \"KeyCount\""), "{quirk}");
}

#[test]
fn element_rename_current_comes_from_the_lowered_root_name() {
    let artifacts = artifacts();
    let (_, quirk) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-root-0013.toml"))
        .expect("the root-name quirk table is generated");

    assert!(quirk.contains("mutation_dimension = \"element_rename\""), "{quirk}");
    assert_eq!(quirk.matches("current = \"ListBucketResult\"").count(), 2, "{quirk}");
}

#[test]
fn optionality_current_comes_from_each_lowered_field() {
    let artifacts = artifacts();
    let (_, quirk) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-empty-0016.toml"))
        .expect("the optionality quirk table is generated");

    assert!(
        quirk.contains("path = \"ListObjectsV2.output.Prefix.required\"\ncurrent = true"),
        "{quirk}"
    );
    assert!(
        quirk.contains("path = \"ListObjectsV2.output.Delimiter.required\"\ncurrent = false"),
        "{quirk}"
    );
}

#[test]
fn generated_source_tables_do_not_capture_root_metadata() {
    let artifacts = artifacts();
    let (_, quirk) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-order-0014.toml"))
        .expect("the source-backed quirk table is generated");
    let parsed = rustfs_gateway_model::toml_lite::parse("q-order-0014.toml", quirk).expect("generated TOML parses");

    assert_eq!(
        parsed.get("target").and_then(rustfs_gateway_model::toml_lite::Toml::as_str),
        Some("ListObjectsV2")
    );
}

#[test]
fn list_family_source_dimensions_read_the_real_lowered_fields() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the typed list-family quirk is generated")
    };

    assert!(emitted("q-etag-0020").contains("current = \"XmlQuoted\""));
    assert!(emitted("q-flat-0019").contains("current = true"));
    assert!(emitted("q-wrapped-0062").contains("current = false"));
    assert!(emitted("q-version-0061").contains("current = \"Version\""));
    assert!(emitted("q-owner-0017").contains("current = \"RequestField(FetchOwner==false)\""));
    assert!(emitted("q-storageclass-0022").contains("current_absent = true"));
    assert_eq!(
        emitted("q-storageclass-0024")
            .matches("current = \"ValueEquals(STANDARD)\"")
            .count(),
        2
    );
    assert!(emitted("q-encoding-0015").contains("current = [\"Prefix\", \"Delimiter\""));
    assert_eq!(emitted("q-maxkeys-0068").matches("current = 1000").count(), 2);
}

#[test]
fn protected_mutation_dimensions_read_distinct_lowered_ir_sources() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the source-backed quirk is generated")
    };

    assert!(emitted("q-timestamp-0011").contains("mutation_dimension = \"time_format\""));
    assert!(emitted("q-timestamp-0011").contains("current = \"Iso8601\""));
    assert!(emitted("q-bkt-0001").contains("mutation_dimension = \"status_mapping\""));
    assert!(emitted("q-bkt-0001").contains("current = 200"));
    assert!(emitted("q-empty-0002").contains("mutation_dimension = \"empty_element_render\""));
    assert!(emitted("q-empty-0002").contains("current = \"emit\""));
    assert!(emitted("q-acl-0002").contains("mutation_dimension = \"attribute_rename\""));
    assert!(emitted("q-acl-0002").contains("current = \"xmlns:xsi\""));
    assert!(emitted("q-acl-0003").contains("current = \"xsi:type\""));
}

#[test]
fn bucket_and_acl_wire_contracts_are_mutable_codegen_sources() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the source-backed family quirk is generated")
    };

    assert!(emitted("q-bkt-0007").contains("current = 204"));
    assert_eq!(emitted("q-acl-0001").matches("current = false").count(), 4);
    assert_eq!(emitted("q-acl-0009").matches("current = true").count(), 2);
}

/// c-location-0001 / q-unwrapped-0001: the location response has no generic output wrapper.
#[test]
fn c_location_0001_the_location_output_is_unwrapped() {
    let quirk = "q-unwrapped-0001";
    let artifacts = artifacts();
    let (_, emitted) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-unwrapped-0001.toml"))
        .expect("the location wrapper source is generated");
    ::core::assert!(emitted.contains("current = true"), "{}", quirk);
}

/// c-location-0002 / q-empty-0002: the empty us-east-1 location element is emitted.
#[test]
fn c_location_0002_the_empty_location_value_is_emitted() {
    let quirk = "q-empty-0002";
    let artifacts = artifacts();
    let (_, emitted) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-empty-0002.toml"))
        .expect("the empty location source is generated");
    ::core::assert!(emitted.contains("current = \"emit\""), "{}", quirk);
}

#[test]
fn checksum_requirement_family_reads_each_operation_current_value() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the checksum requirement is generated as a mutable rule")
    };

    assert!(emitted("q-acc-0003").contains("current = false"));
    assert!(emitted("q-ntf-0003").contains("current = false"));
    assert!(emitted("q-ver-0003").contains("current = true"));
    assert_eq!(emitted("q-lock-0006").matches("current = true").count(), 3);
}

#[test]
fn flattened_collection_families_read_their_actual_list_shapes() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the flattened collection is generated as a mutable rule")
    };

    assert_eq!(emitted("q-enc-0002").matches("current = true").count(), 2);
    assert_eq!(emitted("q-repl-0002").matches("current = true").count(), 2);
    assert_eq!(emitted("q-lc-0003").matches("current = true").count(), 2);
    assert_eq!(emitted("q-cors-0002").matches("current = true").count(), 2);
    assert_eq!(emitted("q-cors-0003").matches("current = true").count(), 8);
    assert_eq!(emitted("q-ntf-0002").matches("current = true").count(), 12);
    assert!(emitted("q-mpu-part-0031").contains("current = true"));
    assert!(emitted("q-mpu-upload-0032").contains("current = true"));
}

#[test]
fn root_and_element_names_are_not_inferred_from_quirk_ids() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the source-backed name quirk is generated")
    };

    assert!(emitted("q-mpu-root-0029").contains("current = \"InitiateMultipartUploadResult\""));
    assert!(emitted("q-mpu-request-root-0030").contains("current = \"CompleteMultipartUpload\""));
    assert!(emitted("q-copy-part-root-0084").contains("current = \"CopyPartResult\""));
    assert!(emitted("q-attributes-root-0087").contains("current = \"GetObjectAttributesOutput\""));
    assert!(emitted("q-select-0008").contains("current = \"SelectObjectContentRequest\""));
    assert_eq!(emitted("q-lock-0004").matches("current = \"Retention\"").count(), 2);
    assert_eq!(emitted("q-lock-0005").matches("current = \"LegalHold\"").count(), 2);
    assert!(emitted("q-lc-0002").contains("current = \"LifecycleConfiguration\""));
    assert_eq!(emitted("q-ver-0004").matches("current = \"MfaDelete\"").count(), 2);
    assert_eq!(emitted("q-ntf-0004").matches("current = ").count(), 10);
}

#[test]
fn unconfigured_resource_behavior_reads_the_operation_error_surface() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the unconfigured-resource rule is generated as mutable data")
    };

    for id in [
        "q-ver-0001",
        "q-acc-0001",
        "q-rqp-0001",
        "q-log-0001",
        "q-ntf-0001",
        "q-acl-0008",
    ] {
        assert!(emitted(id).contains("current_absent = true"), "{id}");
    }
    assert!(emitted("q-enc-0001").contains("current = \"ServerSideEncryptionConfigurationNotFoundError\""));
    assert!(emitted("q-pol-0003").contains("current = \"NoSuchBucketPolicy\""));
    assert!(emitted("q-cors-0001").contains("current = \"NoSuchCORSConfiguration\""));
}

#[test]
fn content_type_default_is_read_from_each_lowered_field() {
    let artifacts = artifacts();
    let (_, quirk) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-content-0008.toml"))
        .expect("the content-type default is generated as mutable data");

    // The default belongs to the read: the two response members carry it, and no request member
    // does, so a write without the header reaches its backend as "no type" (rustfs/gateway#749).
    assert_eq!(quirk.matches("current = \"binary/octet-stream\"").count(), 2);
    assert!(quirk.contains("GetObject.output.ContentType.default_string"), "{quirk}");
    assert!(quirk.contains("HeadObject.output.ContentType.default_string"), "{quirk}");
    assert!(!quirk.contains(".input.ContentType"), "{quirk}");
}

#[test]
fn a_response_header_default_is_written_by_the_encoder_and_a_request_one_is_not_invented() {
    let artifacts = artifacts();
    let codec = |name: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("generated/codec/ops/{name}.rs")))
            .map(|(_, body)| body.as_str())
            .expect("the operation has a generated codec")
    };
    for read in ["get_object", "head_object"] {
        assert!(
            codec(read).contains("response.set_header(\"content-type\", \"binary/octet-stream\")"),
            "{read} must answer the S3 default when its backend names no type"
        );
    }
    for write in ["put_object", "create_multipart_upload"] {
        assert!(
            !codec(write).contains("binary/octet-stream"),
            "{write} must not invent a type the client never sent"
        );
    }
}

#[test]
fn entity_tag_quote_rules_read_the_render_context() {
    let artifacts = artifacts();
    let emitted = |id: &str| {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.as_str())
            .expect("the entity-tag render rule is generated as mutable data")
    };

    assert_eq!(emitted("q-etag-0004").matches("current = \"HeaderQuoted\"").count(), 4);
    assert_eq!(emitted("q-etag-0004").matches("current = \"XmlQuoted\"").count(), 2);
    assert!(emitted("q-mpu-attributes-etag-0036").contains("current = \"XmlBare\""));
}

#[test]
fn opaque_expiration_values_are_a_typed_codegen_decision() {
    let artifacts = artifacts();
    let (_, quirk) = artifacts
        .files
        .iter()
        .find(|(path, _)| path.to_string_lossy().ends_with("spec/quirks/q-timestamp-0005.toml"))
        .expect("the opaque expiration rule is generated as mutable data");

    assert_eq!(quirk.matches("current = \"OpaqueString\"").count(), 5);
}

/// ADR-0007 splits request XML into two policies: ordinary documents skip an unknown element,
/// security configurations refuse it. Each row below is flipped to the *other* policy and
/// re-emitted, so the test sees the guard appear on the lenient rows and disappear from the strict
/// ones — a generator stuck on either answer fails one half.
#[test]
fn unknown_xml_element_policy_reaches_the_generated_reader() {
    use rustfs_gateway_model::{CodecValue, UnknownElementPolicyValue};
    const GUARD: &str = "the body contains an unknown element";
    const LENIENT: &[(&str, &str)] = &[("q-acl-0006", "codec/ops/put_bucket_acl.rs")];
    const STRICT: &[(&str, &[&str])] = &[
        ("q-enc-0006", &["codec/ops/put_bucket_encryption.rs"]),
        (
            "q-lock-0014",
            &[
                "codec/ops/put_object_lock_configuration.rs",
                "codec/ops/put_object_retention.rs",
                "codec/ops/put_object_legal_hold.rs",
            ],
        ),
        ("q-pab-0005", &["codec/ops/put_public_access_block.rs"]),
    ];
    fn emitted<'a>(files: &'a [(PathBuf, String)], suffix: &str) -> &'a str {
        files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(suffix))
            .map(|(_, body)| body.as_str())
            .expect("the operation codec exists")
    }
    let mut artifacts = artifacts();
    let quirk = |artifacts: &crate::Artifacts, id: &str| -> String {
        artifacts
            .files
            .iter()
            .find(|(path, _)| path.to_string_lossy().ends_with(&format!("spec/quirks/{id}.toml")))
            .map(|(_, body)| body.clone())
            .expect("the unknown-element policy is generated as mutable data")
    };
    let emit = |artifacts: &crate::Artifacts| {
        crate::emit::codec::emit(
            &artifacts.operations,
            &artifacts.codec_rules,
            &artifacts.error_codes,
            Path::new("generated"),
        )
        .expect("the codec renders in memory")
    };

    let current = emit(&artifacts);
    for (id, file) in LENIENT {
        assert!(quirk(&artifacts, id).contains("codec_value = \"skip\""), "{id}");
        assert!(!emitted(&current, file).contains(GUARD), "{id} is lenient today");
    }
    for (id, files) in STRICT {
        assert!(quirk(&artifacts, id).contains("codec_value = \"reject\""), "{id}");
        for file in *files {
            assert!(emitted(&current, file).contains(GUARD), "{id} guards {file}");
        }
    }

    for (id, _) in LENIENT {
        artifacts.codec_rules.get_mut(*id).expect("the codec rule exists").current =
            CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Reject);
    }
    artifacts
        .codec_rules
        .get_mut("q-select-0007")
        .expect("the codec rule exists")
        .current = CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Reject);
    for (id, _) in STRICT {
        artifacts.codec_rules.get_mut(*id).expect("the codec rule exists").current =
            CodecValue::UnknownElementPolicy(UnknownElementPolicyValue::Skip);
    }
    let flipped = emit(&artifacts);
    for (id, file) in LENIENT {
        assert!(emitted(&flipped, file).contains(GUARD), "{id} flipped to reject");
    }
    assert!(emitted(&flipped, "codec/ops/select_object_content.rs").contains("if root.children.iter().any(|child|"));
    for (id, files) in STRICT {
        for file in *files {
            assert!(!emitted(&flipped, file).contains(GUARD), "{id} flipped to skip still guards {file}");
        }
    }
}

#[test]
fn n_c_cg_0006_no_documentation_trait_survives_into_any_artefact() {
    for (path, text) in artifacts().files {
        assert!(!text.contains("smithy.api#documentation"), "{} carries a stripped trait", path.display());
    }
}

/// Negative — the decoder refuses an empty list only where the **model** requires the member, and
/// never where an overlay wanted a particular error code out of the parser.
///
/// `Delete.Objects` carries `smithy.api#required` in the pinned model, and its list is flattened,
/// so "no entries" and "member absent" are the same observation: the refusal is a reading of the
/// model. `CompletedMultipartUpload.Parts` carries no such trait; the overlay had added one, whose
/// only effect on a flattened list was to answer `MalformedXML` where the operation owes
/// `InvalidPart` — before the operation was called at all (issue #17).
///
/// Asserted on the generated bytes rather than on the overlay, because it is the generated bytes
/// that decide, and because the two halves have to be pinned together: the failure this guards is
/// somebody restoring one of them and reading the other as unchanged.
#[test]
fn n_only_a_model_required_list_refuses_an_empty_body() {
    let artifacts = artifacts();
    let refusal = "is_empty()";
    assert!(
        body(&artifacts, "codec/ops/delete_objects.rs").contains(refusal),
        "Delete.Objects is required in the model; an empty <Delete/> is not the document"
    );
    assert!(
        !body(&artifacts, "codec/ops/complete_multipart_upload.rs").contains(refusal),
        "an empty <Parts> reaches the operation, which answers InvalidPart; the parser has no code for it"
    );
}

#[test]
fn n_c_cg_0007_no_artefact_carries_upstream_prose() {
    // The documentation traits are HTML; a single tag anywhere in an artefact means the strip
    // failed or someone pasted service documentation into an overlay.
    for (path, text) in artifacts().files {
        for marker in ["<p>", "</p>", "<code>", "<important>"] {
            assert!(!text.contains(marker), "{} contains `{marker}`", path.display());
        }
    }
}

#[test]
fn c_cg_0001_the_generated_ir_is_compared_with_every_golden() {
    let root = root();
    let report = crate::write(&CodegenInput::at(&root), &CodegenOutput::at(&root)).expect("codegen runs");
    assert_eq!(report.goldens.len(), 3, "all three frozen samples take part in the comparison");
    // The differences themselves are reported by `cargo xtask codegen` and reviewed by a human:
    // a hand-written sample can be the stale side. What must hold is that the comparison covers
    // the wire dimensions rather than skipping them.
    for golden in &report.goldens {
        for difference in &golden.differences {
            assert!(
                !difference.path.starts_with("http") && !difference.path.starts_with("auth"),
                "{}: routing and auth must match the golden exactly, saw {difference}",
                golden.operation
            );
        }
    }
}

#[test]
fn n_c_cg_n001_a_hand_edited_spec_file_fails_verification() {
    let root = root();
    let scratch = std::env::temp_dir().join(format!("s3gate-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let output = CodegenOutput {
        spec_dir: scratch.join("spec/operations"),
        operations_md: scratch.join("OPERATIONS.md"),
        generated_dir: scratch.join("generated"),
    };
    let input = CodegenInput::at(&root);
    crate::write(&input, &output).expect("writes into the scratch tree");
    crate::verify(&input, &output).expect("a freshly written tree verifies");

    let edited = output.spec_dir.join("ListObjectsV2.toml");
    let text = std::fs::read_to_string(&edited).expect("read");
    std::fs::write(&edited, text.replace("precedence = 600", "precedence = 42")).expect("write");

    let err = crate::verify(&input, &output).expect_err("a hand-edited spec file must fail the gate");
    let message = format!("{err}");
    assert!(message.contains("ListObjectsV2.toml"), "{message}");
    assert!(message.contains("precedence = 42"), "the failure names the changed line: {message}");
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn n_c_cg_n002_an_edited_operations_md_fails_verification() {
    let root = root();
    let scratch = std::env::temp_dir().join(format!("s3gate-verify-md-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let output = CodegenOutput {
        spec_dir: scratch.join("spec/operations"),
        operations_md: scratch.join("OPERATIONS.md"),
        generated_dir: scratch.join("generated"),
    };
    let input = CodegenInput::at(&root);
    crate::write(&input, &output).expect("writes into the scratch tree");
    std::fs::write(&output.operations_md, "# hand written\n").expect("write");
    assert!(crate::verify(&input, &output).is_err(), "OPERATIONS.md is under the gate too");
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn n_a_stale_generated_file_fails_verification() {
    let root = root();
    let scratch = std::env::temp_dir().join(format!("s3gate-verify-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let output = CodegenOutput {
        spec_dir: scratch.join("spec/operations"),
        operations_md: scratch.join("OPERATIONS.md"),
        generated_dir: scratch.join("generated"),
    };
    let input = CodegenInput::at(&root);
    crate::write(&input, &output).expect("writes into the scratch tree");
    // A name no operation has: `GetObject` used to serve here and stopped being stale the day the
    // object family was generated.
    std::fs::write(output.spec_dir.join("NotAnOperation.toml"), "name = \"NotAnOperation\"\n").expect("write");

    let err = crate::verify(&input, &output).expect_err("a file codegen does not produce is drift");
    assert!(format!("{err}").contains("not produced by codegen"), "{err}");
    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn c_cg_0005_why_reports_a_quirk_with_its_evidence_and_cases() {
    let text = why::why(&artifacts().operations, "q-checksum-0006").expect("known quirk");
    assert!(text.contains("## Quirk `q-checksum-0006`"));
    assert!(text.contains("**Evidence**"));
    assert!(text.contains("https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html"));
    assert!(text.contains("c-checksum-0001"));
    assert!(text.contains("PutObject"));
}

#[test]
fn why_resolves_headers_error_codes_and_query_keys() {
    let artifacts = artifacts();
    // A real AWS header no operation in this build binds: the annotation surface is out of scope
    // in `ops/excluded.toml`, and `CopyObject` drops the directive it would otherwise carry. The
    // example used to be `x-amz-copy-source`, which the copy family now binds — so the same
    // property is asserted twice: a bound header resolves to the operations that bind it, and an
    // unbound one is not found.
    let header = why::why(&artifacts.operations, "x-amz-object-annotation-directive");
    assert!(header.is_err(), "a header nobody binds is not found");

    let copy_source = why::why(&artifacts.operations, "x-amz-copy-source").expect("a bound header");
    assert!(
        copy_source.contains("CopyObject") && copy_source.contains("UploadPartCopy"),
        "{copy_source}"
    );

    let found = why::why(&artifacts.operations, "X-Amz-Meta-").expect("prefix header, case-insensitively");
    assert!(found.contains("prefix family"), "{found}");

    let code = why::why(&artifacts.operations, "MissingContentLength").expect("error code");
    assert!(code.contains("required field `ContentLength`"), "{code}");

    let key = why::why(&artifacts.operations, "list-type").expect("query key");
    assert!(key.contains("route predicate"), "{key}");
}

#[test]
fn n_c_cg_n013_why_fails_with_candidates_for_an_unknown_target() {
    let err = why::why(&artifacts().operations, "x-amz-nonexistent-header").expect_err("unknown target");
    let message = format!("{err}");
    assert!(message.contains("not a known quirk id"), "{message}");
    assert!(message.contains("Closest candidates: x-amz-"), "suggestions are offered: {message}");
}

#[test]
fn semantic_diff_names_the_wire_dimension_that_moved() {
    let artifacts = artifacts();
    let new: BTreeMap<String, rustfs_gateway_model::json::Value> = artifacts
        .operations
        .iter()
        .map(|ir| (ir.operation.clone(), rustfs_gateway_model::ir::emit::to_json(ir)))
        .collect();

    let mut old = new.clone();
    old.remove("PutObject");
    let diff = semantic::compare_sets(&old, &new);
    assert_eq!(diff.changes.len(), 1);
    assert_eq!(diff.changes[0].dimension, semantic::Dimension::OperationAdded);
    assert!(diff.render().contains("operations added"));

    assert!(semantic::compare_sets(&new, &new).is_empty(), "no change is no diff");
}

#[test]
fn n_semantic_diff_classifies_a_precedence_move_as_a_route_change() {
    let artifacts = artifacts();
    let mut old: BTreeMap<String, rustfs_gateway_model::json::Value> = artifacts
        .operations
        .iter()
        .map(|ir| (ir.operation.clone(), rustfs_gateway_model::ir::emit::to_json(ir)))
        .collect();
    let new = old.clone();
    let mut broken = artifacts.operations[0].clone();
    broken.http.precedence = 1;
    old.insert(broken.operation.clone(), rustfs_gateway_model::ir::emit::to_json(&broken));

    let diff = semantic::compare_sets(&old, &new);
    assert_eq!(diff.changes.len(), 1, "{:?}", diff.changes);
    assert_eq!(diff.changes[0].dimension, semantic::Dimension::RouteSelector);
}
