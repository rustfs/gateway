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

//! The ADR-0004 policy guards, asserted against the text codegen produces.
//!
//! Responsible for: the shape rules that would otherwise need a shell script — no
//! `#[non_exhaustive]` on a dto struct, no real `enum` for a string enumeration, no exhaustive
//! destructuring, no AWS prose, and a field-count baseline that only grows.
//! NOT responsible for: whether the generated code compiles, which is `rustfs-gateway-types`' problem and
//! is proved by its own test suite.
//!
//! Case ids from the P1-06 issue are in the test names, so a red test names the criterion it
//! broke. Negative cases outnumber positive ones, as AGENTS.md requires.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::emit::dto::naming;
use crate::{CodegenInput, CodegenOutput, generate};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root is two levels above the crate manifest")
        .to_path_buf()
}

/// Every generated dto file, keyed by its path relative to `generated/`.
fn dto_files() -> BTreeMap<String, String> {
    let root = root();
    let artifacts = generate(&CodegenInput::at(&root), &CodegenOutput::at(&root)).expect("codegen runs against the pinned model");
    artifacts
        .files
        .into_iter()
        .filter_map(|(path, body)| {
            let text = path.to_string_lossy().replace('\\', "/");
            text.split_once("generated/dto/").map(|(_, tail)| (tail.to_owned(), body))
        })
        .collect()
}

fn rust_bodies() -> Vec<(String, String)> {
    dto_files().into_iter().filter(|(name, _)| name.ends_with(".rs")).collect()
}

// ── positive ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_dto_0001_every_operation_gets_a_module_and_a_flat_alias() {
    let files = dto_files();
    for module in ["get_bucket_location", "list_objects_v2", "put_object"] {
        assert!(files.contains_key(&format!("ops/{module}.rs")), "missing module for {module}");
    }
    let flat = files.get("flat.rs").expect("the flat alias module is generated");
    for alias in ["GetBucketLocationInput", "ListObjectsV2Output", "PutObjectInput"] {
        assert!(flat.contains(alias), "the flat module does not alias {alias}");
    }
}

#[test]
fn c_dto_0005_string_enumerations_carry_their_model_values_as_constants() {
    let files = dto_files();
    let storage_class = files
        .get("ops/enums/storage_class.rs")
        .expect("StorageClass is generated as its own module");
    assert!(storage_class.contains("pub const STANDARD: Self = Self(Cow::Borrowed(\"STANDARD\"));"));
    assert!(storage_class.contains("pub const GLACIER: Self = Self(Cow::Borrowed(\"GLACIER\"));"));
}

#[test]
fn c_dto_0007_every_input_gets_a_builder_without_losing_its_public_fields() {
    for (name, body) in rust_bodies() {
        if !name.starts_with("ops/") || !body.contains("pub struct Input {") {
            continue;
        }
        assert!(body.contains("pub struct InputBuilder"), "{name} has no builder (ADR-0004 P7)");
        assert!(body.contains("pub fn build(self) -> Input"), "{name}'s builder cannot be finished");
        assert!(
            body.matches("    pub ").count() > 2,
            "{name} kept no public fields; a builder must never replace them (ADR-0004 P7)"
        );
    }
}

#[test]
fn naming_conversions_are_acronym_aware() {
    assert_eq!(naming::module_name("ListObjectsV2"), "list_objects_v2");
    assert_eq!(naming::field_name("ETag"), "e_tag");
    assert_eq!(naming::field_name("ID"), "id");
    assert_eq!(naming::field_name("ContentMD5"), "content_md5");
    assert_eq!(naming::field_name("SSEKMSKeyId"), "ssekms_key_id");
    assert_eq!(naming::type_name("ACL"), "Acl");
    assert_eq!(naming::type_name("ETag"), "ETag");
    assert_eq!(naming::const_name("public-read-write"), "PUBLIC_READ_WRITE");
    assert_eq!(naming::const_name("aws:kms:dsse"), "AWS_KMS_DSSE");
}

// ── negative ──────────────────────────────────────────────────────────────────────────────────

#[test]
fn c_dto_n001_no_dto_struct_carries_non_exhaustive() {
    for (name, body) in rust_bodies() {
        for (index, line) in body.lines().enumerate() {
            if line.trim() != "#[non_exhaustive]" {
                continue;
            }
            let next = body.lines().nth(index + 1).unwrap_or_default();
            assert!(
                next.trim_start().starts_with("pub enum "),
                "{name}:{} applies #[non_exhaustive] to `{}`. Measured: it rejects \
                 `..Default::default()` too (E0639), which would break every downstream \
                 construction site with no mechanical fix. ADR-0004 P1.",
                index + 1,
                next.trim()
            );
        }
    }
}

#[test]
fn c_dto_n006_string_enumerations_are_never_real_enums() {
    for (name, body) in rust_bodies() {
        if !name.starts_with("ops/enums/") || name.ends_with("mod.rs") {
            continue;
        }
        assert!(
            !body.contains("pub enum "),
            "{name} generated a real `enum`. AWS adds values every quarter; ADR-0004 P4 requires a \
             newtype over `Cow<'static, str>` so that a new value stays a minor bump."
        );
        assert!(body.contains("(Cow<'static, str>);"), "{name} is not a `Cow` newtype");
    }
}

#[test]
fn c_dto_n007_structural_unions_keep_non_exhaustive() {
    for (name, body) in rust_bodies() {
        for (index, line) in body.lines().enumerate() {
            if !line.trim_start().starts_with("pub enum ") {
                continue;
            }
            let previous = index.checked_sub(1).and_then(|i| body.lines().nth(i)).unwrap_or_default();
            assert_eq!(
                previous.trim(),
                "#[non_exhaustive]",
                "{name}:{} declares a union without #[non_exhaustive]; ADR-0004 P5",
                index + 1
            );
        }
    }
}

#[test]
fn c_dto_n003_no_generated_line_destructures_a_dto_exhaustively() {
    for (name, body) in rust_bodies() {
        for line in body.lines() {
            let trimmed = line.trim_start();
            let destructures = trimmed.starts_with("let Input {")
                || trimmed.starts_with("let Output {")
                || trimmed.contains("} = input")
                || trimmed.contains("} = output");
            assert!(
                !destructures,
                "{name} destructures a dto: `{trimmed}`. A new member breaks exactly this and \
                 nothing else (ADR-0004 P3); use field access."
            );
        }
    }
}

#[test]
fn c_dto_n004_the_field_count_baseline_never_shrinks() {
    let generated = dto_files();
    let produced = generated.get("field_counts.txt").expect("the ratchet baseline is generated");
    let checked_in = std::fs::read_to_string(root().join("generated/dto/field_counts.txt")).unwrap_or_default();

    let parse = |text: &str| -> BTreeMap<String, usize> {
        text.lines()
            .filter_map(|line| line.split_once(' '))
            .filter_map(|(name, count)| count.parse().ok().map(|c| (name.to_owned(), c)))
            .collect()
    };
    let (old, new) = (parse(&checked_in), parse(produced));
    for (name, before) in &old {
        let after = new.get(name).copied().unwrap_or(0);
        assert!(
            after >= *before,
            "`{name}` lost public fields ({before} to {after}). Removing one is the breaking change \
             this layout still admits; ADR-0004 P9 needs a major version and an explicit decision."
        );
    }
}

#[test]
fn c_dto_n013_no_aws_documentation_prose_reaches_the_generated_tree() {
    for (name, body) in dto_files() {
        for marker in ["smithy.api#documentation", "<p>", "</p>", "<note>"] {
            assert!(!body.contains(marker), "{name} carries `{marker}`; ADR-0001 forbids AWS prose");
        }
    }
}

#[test]
fn c_dto_n017_no_generated_dto_derives_partial_eq() {
    // AGENTS.md: key material must never be compared with `==`, and `PutObjectInput` carries an
    // SSE-C key. The blanket rule is cheaper to keep true than a per-field exception list. Unit
    // markers (`pub struct PutObject;`) are out of scope — they hold nothing.
    for (name, body) in rust_bodies() {
        if !name.starts_with("ops/") || name.contains("/enums/") {
            continue;
        }
        let lines: Vec<&str> = body.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.starts_with("pub struct ") || !line.ends_with('{') {
                continue;
            }
            let derive = index.checked_sub(1).map(|i| lines[i]).unwrap_or_default();
            assert!(
                !derive.contains("PartialEq"),
                "{name}:{} derives PartialEq on `{line}`; a dto can carry an SSE-C key and \
                 AGENTS.md forbids `==` on key material",
                index + 1
            );
        }
    }
}

#[test]
fn c_dto_n018_secret_fields_are_redacted_in_debug() {
    let files = dto_files();
    let put_object = files.get("ops/put_object.rs").expect("PutObject is generated");
    assert!(
        !put_object.contains("#[derive(Debug, Default)]\npub struct Input {"),
        "PutObjectInput derives Debug while carrying an SSE-C key"
    );
    assert!(
        put_object.contains(".field(\"sse_customer_key\", &redact(&self.sse_customer_key))"),
        "the SSE-C key reaches Debug output; AGENTS.md forbids key material in logs"
    );
}

/// Every generated `pub` field, as `(file, doc line, declaration line)`.
///
/// The doc line above a field states `Required.` or `Optional.`, which is the same IR bit the
/// emitter branches on — so a wrapper that disagrees with the documentation is caught here without
/// the test having to re-derive requiredness from the model.
fn declared_fields() -> Vec<(String, String, String)> {
    let mut found = Vec::new();
    for (name, body) in rust_bodies() {
        if !name.starts_with("ops/") || name.contains("/enums/") {
            continue;
        }
        let lines: Vec<&str> = body.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if !trimmed.starts_with("pub ") || !trimmed.ends_with(',') || !trimmed.contains(": ") {
                continue;
            }
            let doc = index.checked_sub(1).map(|i| lines[i].trim()).unwrap_or_default();
            found.push((name.clone(), doc.to_owned(), trimmed.to_owned()));
        }
    }
    assert!(found.len() > 50, "the corpus is suspiciously small: {} fields", found.len());
    found
}

fn field_type_of(line: &str) -> &str {
    line.split_once(": ").expect("a field declaration").1.trim_end_matches(',')
}

fn is_container_type(ty: &str) -> bool {
    ty.starts_with("Vec<") || ty.starts_with("std::collections::BTreeMap<")
}

#[test]
fn c_dto_0009_a_required_member_is_generated_bare() {
    // The arbitration on issue 1722: requiredness is expressed by the type. Wrapping a required
    // member in an `Option` makes the type lie about the wire contract and forces an unwrap at
    // every consumer, which is what the earlier all-`Option` reading of P1 produced.
    for (name, doc, line) in declared_fields() {
        if !doc.contains(" Required.") {
            continue;
        }
        assert!(
            !field_type_of(&line).starts_with("Option<"),
            "{name} declares `{line}` for a required member; ADR-0004 P1 wants it bare so that no \
             consumer unwraps a value the wire contract guarantees"
        );
    }
}

#[test]
fn c_dto_n019_an_optional_scalar_member_is_never_generated_bare() {
    // The other half of P1. An optional scalar has to be `Option`: a bare one would have no way to
    // say "the client sent nothing", because the placeholder default means "never filled in",
    // which is a decoder bug rather than an absent member.
    for (name, doc, line) in declared_fields() {
        if doc.contains(" Required.") {
            continue;
        }
        let ty = field_type_of(&line);
        assert!(
            ty.starts_with("Option<") || is_container_type(ty),
            "{name} declares `{line}` for an optional member; only a required member or a container \
             may be bare (ADR-0004 P1/P2)"
        );
    }
}

#[test]
fn c_dto_n032_every_generated_struct_carries_the_decode_path_guard() {
    // ADR-0004 P10: the placeholder default is only safe because something refuses to let it off
    // the decode path. An emitter that stops writing `check_required` removes that silently.
    for (name, body) in rust_bodies() {
        if !name.starts_with("ops/") || name.contains("/enums/") || name.ends_with("mod.rs") {
            continue;
        }
        for (index, line) in body.lines().enumerate() {
            if !line.starts_with("pub struct ") || !line.ends_with('{') {
                continue;
            }
            let type_name = line.trim_start_matches("pub struct ").trim_end_matches('{').trim();
            if type_name == "InputBuilder" {
                continue;
            }
            assert!(
                body.contains(&format!("impl {type_name} {{\n    /// Rejects a required member")),
                "{name}:{} declares `{type_name}` without a `check_required`; the P10 placeholder \
                 would then have nothing stopping it at the decode exit",
                index + 1
            );
        }
    }
}

#[test]
fn c_dto_n034_a_required_member_with_no_representable_default_fails_the_run() {
    // ADR-0004 P2's hard CI failure. The two ways a type can have no `Default` are a structural
    // union (a `#[non_exhaustive]` enum with no neutral variant) and a streaming body. Neither may
    // be quietly wrapped back into an `Option`, and neither may acquire an invented `Default`:
    // the run stops and a human writes the ADR.
    use rustfs_gateway_model::ir::Type;

    let registry = crate::emit::dto::registry::Registry::default();
    assert!(
        registry.required_gap(&Type::Union("AnalyticsFilter".to_owned())).is_some(),
        "a required structural union must stop the run"
    );
    assert!(
        registry.required_gap(&Type::Blob { streaming: true }).is_some(),
        "a required streaming body must stop the run"
    );
    for ok in [
        Type::BucketName,
        Type::ObjectKey,
        Type::Long,
        Type::String,
        Type::Timestamp(rustfs_gateway_model::ir::TimestampFormat::Iso8601),
    ] {
        assert!(
            registry.required_gap(&ok).is_none(),
            "{ok:?} has a placeholder `Default` and may be required"
        );
    }
}

#[test]
fn c_dto_n033_every_generated_placeholder_default_documents_what_it_is() {
    // P10 is a documentation obligation as much as a code one: a `Default` that reads like a
    // plausible wire value is exactly what somebody reaches for by mistake.
    for (name, body) in rust_bodies() {
        if !name.starts_with("ops/enums/") || name.ends_with("mod.rs") {
            continue;
        }
        assert!(
            body.contains("impl Default for"),
            "{name} has no `Default`, so it could not sit in a required member"
        );
        assert!(
            body.contains("**invalid on the wire**") && body.contains("**The decoding path never produces it.**"),
            "{name}'s `Default` does not say it is a placeholder the decode path never produces (ADR-0004 P10)"
        );
        assert!(
            body.contains("impl crate::WirePlaceholder for"),
            "{name} cannot answer whether it holds a placeholder, so `check_required` would skip it"
        );
    }
}

#[test]
fn c_dto_n020_every_generated_rust_file_carries_the_licence_header() {
    for (name, body) in rust_bodies() {
        assert!(
            body.starts_with("// Copyright 2026 RustFS Team"),
            "{name} does not open with the Apache-2.0 header"
        );
        assert!(body.contains("@generated by `cargo xtask codegen`"), "{name} is not marked generated");
    }
}

#[test]
fn c_dto_n027_the_generated_text_is_what_rustfmt_would_produce() {
    // `cargo fmt` follows the `#[path]` modules into `generated/`, so an emitter that disagrees
    // with rustfmt turns `cargo fmt` into a `cargo xtask spec verify` failure. The emitter matches
    // rustfmt by construction (`slice_literal`, `use_group`); this test is what notices when a
    // toolchain bump moves the goalposts.
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    for (name, body) in rust_bodies() {
        let mut child = match Command::new("rustfmt")
            .args(["--emit", "stdout", "--edition", "2024", "--quiet"])
            .current_dir(root())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            // rustfmt ships with every rustup toolchain; a machine without it still gets every
            // other guard rather than a red suite it cannot fix.
            Err(_) => return,
        };
        if let Some(stdin) = child.stdin.as_mut() {
            stdin.write_all(body.as_bytes()).expect("rustfmt accepts the generated text");
        }
        let output = child.wait_with_output().expect("rustfmt finishes");
        let formatted = String::from_utf8_lossy(&output.stdout).to_string();
        assert!(output.status.success(), "rustfmt rejected {name}");
        assert_eq!(
            formatted.trim_end(),
            body.trim_end(),
            "{name} is not in rustfmt's normal form; adjust the emitter, never the checked-in file"
        );
    }
}

#[test]
fn c_dto_n021_no_generated_file_passes_the_eight_hundred_line_ceiling() {
    for (name, body) in rust_bodies() {
        let lines = body.lines().count();
        assert!(lines <= 800, "{name} is {lines} lines; AGENTS.md caps a file at 800");
    }
}
