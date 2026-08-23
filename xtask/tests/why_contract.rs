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

//! Process-boundary contracts for `cargo xtask why`.
//!
//! Responsible for: the stable text/JSON sections and failure exit codes.
//! NOT responsible for: interpreting protocol data; `xtask::why` owns that logic.
//! Upstream: repository evidence. Downstream: agents parsing reverse-trace output.

use std::process::{Command, Output};

fn why(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("why")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("xtask must start: {error}"))
}

#[test]
fn a_doc_0005_quirk_has_six_ordered_sections() {
    let output = why(&["q-etag-0001"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut cursor = 0;
    for section in ["RULE", "EVIDENCE", "CASES", "ADR", "SPEC", "RELATED"] {
        let offset = stdout[cursor..]
            .find(section)
            .unwrap_or_else(|| panic!("missing or unordered {section}: {stdout}"));
        cursor += offset + section.len();
    }
}

#[test]
fn a_doc_0006_operation_lists_related_quirks_and_cases() {
    let output = why(&["GetObject"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("q-etag-0004"), "{stdout}");
    assert!(stdout.contains("c-object-0001"), "{stdout}");
}

#[test]
fn a_doc_0007_error_code_and_header_resolve() {
    for target in ["NoSuchKey", "x-amz-restore"] {
        let output = why(&[target]);
        assert!(output.status.success(), "{target}: {}", String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("RULE"));
    }
}

#[test]
fn explicit_error_code_query_prints_status_producers_and_cases() {
    let output = why(&["error-code", "NoSuchKey"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("status=404"), "{stdout}");
    assert!(stdout.contains("GetObject"), "{stdout}");
    assert!(stdout.contains("c-object-0007"), "{stdout}");
}

#[test]
fn explicit_error_code_query_rejects_a_non_error_target() {
    let output = why(&["error-code", "GetObject"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8_lossy(&output.stderr), "error code `GetObject` not found\n");
}

#[test]
fn explicit_error_code_query_rejects_an_unknown_namespace() {
    let output = why(&["operation", "GetObject"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "usage: cargo xtask why [error-code] <quirk | operation | error-code | header | ADR | rule> [--json]\n"
    );
}

#[test]
fn a_doc_0008_adr_json_matches_the_text_sections() {
    let output = why(&["ADR-0005", "--json"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    for field in ["\"rule\"", "\"evidence\"", "\"cases\"", "\"adr\"", "\"spec\"", "\"related\""] {
        assert!(stdout.contains(field), "missing {field}: {stdout}");
    }
}

#[test]
fn a_doc_0017_quirk_has_its_repaired_case_backlink() {
    let output = why(&["q-attributes-root-0087"]);
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CASES     c-etag-0001"), "{stdout}");
    assert!(!stdout.contains("CASES     NONE — this is a bug"), "{stdout}");
}

#[test]
fn a_doc_0019_unknown_target_suggests_candidates_without_panicking() {
    let output = why(&["q-nonexistent-9999"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not found"), "{stderr}");
    assert!(stderr.contains("closest"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}

/// a-asm-0017. Every AssemblyError rule resolves through the real CLI and prints its explanation.
#[test]
fn every_assembly_rule_has_a_why_answer() {
    for rule in rustfs_gateway::RuleRef::ALL {
        let output = why(&[rule.as_str()]);
        assert!(output.status.success(), "{rule}: {}", String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains(rule.explanation()), "{rule}");
    }
}

#[test]
fn a_doc_0018_each_target_namespace_matches_its_golden() {
    let cases = [
        ("q-etag-0001", include_str!("why_golden/quirk.txt")),
        ("GetBucketLocation", include_str!("why_golden/operation.txt")),
        ("NoSuchKey", include_str!("why_golden/error-code.txt")),
        ("x-amz-restore", include_str!("why_golden/header.txt")),
        ("ADR-0005", include_str!("why_golden/adr.txt")),
        ("asm-missing-authorizer", include_str!("why_golden/rule.txt")),
    ];
    for (target, golden) in cases {
        let output = why(&[target]);
        assert!(output.status.success(), "{target}: {}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(String::from_utf8_lossy(&output.stdout), golden, "{target}");
    }
}
