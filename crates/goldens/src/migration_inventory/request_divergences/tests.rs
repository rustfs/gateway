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

//! The request-divergence register and its pinned tests cannot drift apart.
//!
//! Responsible for: reading the named-divergence sections of the pinned test files as source, and
//! proving both directions — every test there carries a `Ruling:` id with a register entry that
//! names that test, and every entry names a test that carries its id — plus refusing each kind of
//! malformed entry by name.
//! NOT responsible for: whether a divergence still diverges (the pinned tests observe that).
//! Upstream: `super`, and the four test files it pins. Downstream: nothing.

use super::{
    BODY_PARITY, CONFIG_DECODE, COPY_RESULT, DivergenceFollowUp, DivergenceRuling, ERROR_PARITY, LOCATION_CONTEXT, MINIO_CONFIG,
    PUT_CONTEXT, PUT_DECODE, REQUEST_DIVERGENCES, RequestDivergence, RequestDivergenceError, build_request_divergences,
    check_register,
};

/// The pinned test files, as source, keyed the way register entries name them.
const PINNED_SOURCES: [(&str, &str); 8] = [
    (PUT_DECODE, include_str!("../../operation_diff/put_object/divergences.rs")),
    (PUT_CONTEXT, include_str!("../../operation_diff/context/put_object.rs")),
    (LOCATION_CONTEXT, include_str!("../../operation_diff/context/get_bucket_location.rs")),
    (CONFIG_DECODE, include_str!("../../operation_diff/put_bucket_versioning.rs")),
    (COPY_RESULT, include_str!("../../operation_diff/copy_result.rs")),
    (MINIO_CONFIG, include_str!("../../operation_diff/minio_config.rs")),
    (ERROR_PARITY, include_str!("../../operation_diff/context/error_parity/divergences.rs")),
    (BODY_PARITY, include_str!("../../operation_diff/context/body_parity/divergences.rs")),
];

/// One `#[test]` function read out of a source file.
#[derive(Debug)]
struct PinnedTest {
    file: &'static str,
    test: String,
    ruling: Option<String>,
    in_divergence_section: bool,
}

/// Reads every `#[test] fn` out of `source`, with the `/// Ruling: `id`` marker directly above it.
///
/// A section starts at a `// ──` heading; one whose title mentions a divergence is a
/// named-divergence section. A marker binds to the next test only if nothing but doc comments and
/// attributes stands between them.
fn pinned_tests(file: &'static str, source: &str) -> Vec<PinnedTest> {
    let mut tests = Vec::new();
    let mut in_section = false;
    let mut ruling: Option<String> = None;
    let mut test_attribute = false;
    for line in source.lines() {
        let line = line.trim();
        if let Some(heading) = line.strip_prefix("// ──") {
            in_section = heading.contains("divergence");
            ruling = None;
            test_attribute = false;
        } else if let Some(marker) = line.strip_prefix("/// Ruling:") {
            let marker = marker.trim();
            let id = marker
                .strip_prefix('`')
                .and_then(|rest| rest.strip_suffix('`'))
                .unwrap_or(marker);
            ruling = Some(id.to_owned());
        } else if line == "#[test]" {
            test_attribute = true;
        } else if let (true, Some(signature)) = (test_attribute, line.strip_prefix("fn ")) {
            let name = signature.split('(').next().unwrap_or(signature).to_owned();
            tests.push(PinnedTest {
                file,
                test: name,
                ruling: ruling.take(),
                in_divergence_section: in_section,
            });
            test_attribute = false;
        } else if !line.starts_with("///") && !line.starts_with("#[") {
            ruling = None;
            test_attribute = false;
        }
    }
    tests
}

/// Both directions of the binding; the count of tests bound to an entry on success.
fn check_pins(register: &[RequestDivergence], sources: &[(&'static str, &str)]) -> Result<usize, String> {
    let tests: Vec<PinnedTest> = sources.iter().flat_map(|(file, source)| pinned_tests(file, source)).collect();
    let mut bound = 0;
    for test in &tests {
        let Some(id) = &test.ruling else {
            if test.in_divergence_section {
                return Err(format!("{}::{} pins a divergence without a ruling", test.file, test.test));
            }
            continue;
        };
        let Some(entry) = register.iter().find(|entry| entry.id == id) else {
            return Err(format!("{}::{} names {id}, which has no register entry", test.file, test.test));
        };
        if entry.test != test.test || entry.test_file != test.file {
            return Err(format!(
                "{}::{} names {id}, whose entry pins {}::{}",
                test.file, test.test, entry.test_file, entry.test
            ));
        }
        bound += 1;
    }
    for entry in register {
        let pinned = tests
            .iter()
            .any(|test| test.file == entry.test_file && test.test == entry.test && test.ruling.as_deref() == Some(entry.id));
        if !pinned {
            return Err(format!(
                "{} pins {}::{}, which is not a test carrying its id",
                entry.id, entry.test_file, entry.test
            ));
        }
    }
    Ok(bound)
}

fn entry(id: &'static str, test_file: &'static str, test: &'static str) -> RequestDivergence {
    RequestDivergence {
        id,
        test_file,
        test,
        ..REQUEST_DIVERGENCES[0]
    }
}

// ── the real register ─────────────────────────────────────────────────────────────────────────

#[test]
fn every_pinned_divergence_test_has_a_ruling_and_every_ruling_a_test() {
    assert_eq!(check_pins(&REQUEST_DIVERGENCES, &PINNED_SOURCES), Ok(REQUEST_DIVERGENCES.len()));
    // Non-vacuity: the scan found the named sections, and every test in them.
    let in_sections = PINNED_SOURCES
        .iter()
        .flat_map(|(file, source)| pinned_tests(file, source))
        .filter(|test| test.in_divergence_section)
        .count();
    assert_eq!(in_sections, REQUEST_DIVERGENCES.len());
}

#[test]
fn the_register_is_valid_and_renders_every_ruling() {
    let report = build_request_divergences();
    assert_eq!(report.as_ref().map(|report| report.entries().len()), Ok(50));
    let rendered = report.map(|report| report.render()).unwrap_or_default();
    assert!(
        rendered.starts_with(
            "request divergences: rulings=50 keep-gateway=28 align-s3s=12 align-aws=4 rustfs-profile=6 open-follow-ups=4 landed=22\n"
        ),
        "{rendered}"
    );
    for entry in &REQUEST_DIVERGENCES {
        assert!(rendered.contains(&format!("divergence {} ", entry.id)), "{} is not rendered", entry.id);
    }
}

// ── the binding fails closed ──────────────────────────────────────────────────────────────────

#[test]
fn n_a_divergence_test_without_a_ruling_is_refused() {
    let source = "// ── named divergences ──\n#[test]\nfn divergence_new() {}\n";
    let error = check_pins(&[], &[(PUT_DECODE, source)]);
    assert_eq!(error, Err(format!("{PUT_DECODE}::divergence_new pins a divergence without a ruling")));
}

#[test]
fn n_a_marker_naming_no_entry_is_refused() {
    let source = "// ── named divergences ──\n/// Ruling: `rd-put-9999`\n#[test]\nfn divergence_new() {}\n";
    let error = check_pins(&[], &[(PUT_DECODE, source)]);
    assert_eq!(
        error,
        Err(format!("{PUT_DECODE}::divergence_new names rd-put-9999, which has no register entry"))
    );
}

#[test]
fn n_an_entry_whose_test_is_gone_is_refused() {
    let register = [entry("rd-put-0001", PUT_DECODE, "deleted_test")];
    let error = check_pins(&register, &[(PUT_DECODE, "// ── named divergences ──\n")]);
    assert_eq!(
        error,
        Err(format!(
            "rd-put-0001 pins {PUT_DECODE}::deleted_test, which is not a test carrying its id"
        ))
    );
}

#[test]
fn n_an_entry_whose_test_carries_another_id_is_refused() {
    let register = [
        entry("rd-put-0001", PUT_DECODE, "one"),
        entry("rd-put-0002", PUT_DECODE, "two"),
    ];
    let source = "// ── named divergences ──\n/// Ruling: `rd-put-0002`\n#[test]\nfn one() {}\n\
                  /// Ruling: `rd-put-0001`\n#[test]\nfn two() {}\n";
    let error = check_pins(&register, &[(PUT_DECODE, source)]);
    assert_eq!(
        error,
        Err(format!("{PUT_DECODE}::one names rd-put-0002, whose entry pins {PUT_DECODE}::two"))
    );
}

#[test]
fn n_a_marker_separated_from_its_test_by_code_does_not_bind() {
    let register = [entry("rd-put-0001", PUT_DECODE, "one")];
    let source = "// ── named divergences ──\n/// Ruling: `rd-put-0001`\nconst X: u8 = 0;\n#[test]\nfn one() {}\n";
    let error = check_pins(&register, &[(PUT_DECODE, source)]);
    assert_eq!(error, Err(format!("{PUT_DECODE}::one pins a divergence without a ruling")));
}

#[test]
fn n_a_test_in_the_wrong_file_is_refused() {
    let register = [entry("rd-put-0001", PUT_DECODE, "one")];
    let source = "// ── named divergences ──\n/// Ruling: `rd-put-0001`\n#[test]\nfn one() {}\n";
    let error = check_pins(&register, &[(PUT_CONTEXT, source)]);
    assert_eq!(
        error,
        Err(format!("{PUT_CONTEXT}::one names rd-put-0001, whose entry pins {PUT_DECODE}::one"))
    );
}

#[test]
fn a_marked_test_outside_a_named_section_still_binds() {
    let register = [entry("rd-put-0001", PUT_DECODE, "one")];
    let source = "// ── the property ──\n/// Some doc.\n///\n/// Ruling: `rd-put-0001`\n#[test]\nfn one() {}\n";
    assert_eq!(check_pins(&register, &[(PUT_DECODE, source)]), Ok(1));
}

// ── malformed entries are refused by name ─────────────────────────────────────────────────────

#[test]
fn n_a_malformed_id_is_refused() {
    for id in [
        "rd-put-1",
        "rd-get-0001",
        "put-0001",
        "rd-put-00a1",
        "rd-cfg-1",
        "rd-cfg-00a1",
    ] {
        assert_eq!(
            check_register(&[entry(id, PUT_DECODE, "t")]),
            Err(RequestDivergenceError::MalformedId(id)),
            "{id}"
        );
    }
}

#[test]
fn n_a_duplicate_id_is_refused() {
    let register = [entry("rd-put-0001", PUT_DECODE, "a"), entry("rd-put-0001", PUT_DECODE, "b")];
    assert_eq!(check_register(&register), Err(RequestDivergenceError::DuplicateId("rd-put-0001")));
}

#[test]
fn n_a_behaviour_change_without_a_follow_up_is_refused() {
    for ruling in [
        DivergenceRuling::AlignS3s,
        DivergenceRuling::AlignAws,
        DivergenceRuling::RustfsProfile,
    ] {
        let unowned = RequestDivergence {
            ruling,
            follow_up: DivergenceFollowUp::None,
            ..entry("rd-put-0001", PUT_DECODE, "t")
        };
        assert_eq!(
            check_register(&[unowned]),
            Err(RequestDivergenceError::UnownedChange("rd-put-0001")),
            "{ruling:?}"
        );
    }
    let kept = RequestDivergence {
        ruling: DivergenceRuling::KeepGateway,
        follow_up: DivergenceFollowUp::None,
        ..entry("rd-put-0001", PUT_DECODE, "t")
    };
    assert_eq!(check_register(&[kept]), Ok(()));
}

#[test]
fn n_a_follow_up_that_is_neither_an_issue_nor_a_case_is_refused() {
    for follow_up in [
        DivergenceFollowUp::Open("https://example.invalid/issues/1"),
        DivergenceFollowUp::Open("https://github.com/rustfs/gateway/pull/748"),
        DivergenceFollowUp::Open("https://github.com/rustfs/gateway/issues/"),
        DivergenceFollowUp::Landed("object-0057"),
        DivergenceFollowUp::Landed("c-object-57"),
    ] {
        let malformed = RequestDivergence {
            follow_up,
            ..entry("rd-put-0001", PUT_DECODE, "t")
        };
        assert_eq!(
            check_register(&[malformed]),
            Err(RequestDivergenceError::MalformedFollowUp("rd-put-0001")),
            "{follow_up:?}"
        );
    }
}

#[test]
fn n_evidence_that_is_not_a_url_is_refused() {
    let uncited = RequestDivergence {
        aws_evidence: "the API reference",
        ..entry("rd-put-0001", PUT_DECODE, "t")
    };
    assert_eq!(check_register(&[uncited]), Err(RequestDivergenceError::EvidenceNotUrl("rd-put-0001")));
}

#[test]
fn n_a_test_outside_the_checked_files_is_refused() {
    let elsewhere = entry("rd-put-0001", "operation_diff/get_object.rs", "t");
    assert_eq!(check_register(&[elsewhere]), Err(RequestDivergenceError::UnknownTestFile("rd-put-0001")));
}

#[test]
fn n_an_empty_description_is_refused() {
    let blank = RequestDivergence {
        client_impact: "  ",
        ..entry("rd-put-0001", PUT_DECODE, "t")
    };
    assert_eq!(
        check_register(&[blank]),
        Err(RequestDivergenceError::MissingText {
            id: "rd-put-0001",
            field: "client_impact",
        })
    );
}
