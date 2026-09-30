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

//! The census of the seam generator's reviewed exceptions (rustfs/gateway#1076): every override
//! in `crates/codegen/src/emit/seam/overrides.rs`, read from its source, must be proven lossless or
//! fail-closed by something this test can check, so a new override cannot land unclassified.
//!
//! Responsible for: parsing the override table and judging each entry by its rule — a member the
//! seam drops has a `DroppedUnread` finding with RustFS evidence, a member it refuses has a
//! `FailClosed` finding and a row, a member it carries another way is handed over identically by a
//! row, a member one side lacks is absent from the pinned fact table, and each remaining output
//! rule names the test that proves it.
//! NOT responsible for: members no override touches; the member census in `tests/seam.rs` owns
//! those. Upstream: the override source, the seam register and rows. Downstream: none.

use std::collections::BTreeSet;

use crate::seam::{SEAM_FINDINGS, SEAM_OPERATIONS, SeamClass};

const OVERRIDES: &str = include_str!("../../../codegen/src/emit/seam/overrides.rs");
const FACTS: &str = include_str!("../../../codegen/src/emit/seam/s3s_0_17_0.facts");

/// One override: the legacy struct, the member, the rule's name.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Override {
    owner: String,
    member: String,
    rule: String,
}

/// Every entry of the override table's `MEMBERS`, in order.
fn overrides(source: &str) -> Vec<Override> {
    let start = source.find("pub const MEMBERS").unwrap_or_else(|| panic!("no MEMBERS table"));
    let table = &source[start..];
    let table = &table[..table.find("\n];").unwrap_or_else(|| panic!("MEMBERS is not closed"))];
    // One spelling for every entry, whether rustfmt wrapped it or not: `("Owner", "member", Rule::X(`.
    let flat: String = table
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ")
        .replace("( ", "(");
    flat.split("(\"")
        .skip(1)
        .filter_map(|entry| {
            let mut quoted = entry.split('"');
            let owner = quoted.next()?;
            let _ = quoted.next()?;
            let member = quoted.next()?;
            let rule = entry.split("Rule::").nth(1)?;
            let rule: String = rule.chars().take_while(char::is_ascii_alphanumeric).collect();
            Some(Override {
                owner: owner.to_owned(),
                member: member.to_owned(),
                rule,
            })
        })
        .collect()
}

/// A nested legacy struct an override names: the struct, the (operation, member-path prefix) it
/// sits under on the request side, and the legacy outputs it sits in on the answer side.
type Nested = (&'static str, &'static [(&'static str, &'static str)], &'static [&'static str]);

/// Every nested legacy struct an override names.
const NESTED: &[Nested] = &[
    ("CreateBucketConfiguration", &[("CreateBucket", "create_bucket_configuration.")], &[]),
    (
        "DefaultRetention",
        &[("PutObjectLockConfiguration", "")],
        &["GetObjectLockConfigurationOutput"],
    ),
    ("ObjectLockRetention", &[("PutObjectRetention", "")], &["GetObjectRetentionOutput"]),
];

/// Output-side overrides no row can exercise, and the test that proves each: (rule, owner, file,
/// test function).
const OUTPUT_PROOFS: &[(&str, &str, &str, &str)] = &[
    (
        "S3sOnly",
        "HeadBucketOutput",
        include_str!("../../../types/src/compat/seam/generated_tests.rs"),
        "n_every_legacy_only_output_member_set_is_refused_by_name",
    ),
    (
        "S3sOnly",
        "CreateBucketOutput",
        include_str!("../../../types/src/compat/seam/generated_tests.rs"),
        "n_every_legacy_only_output_member_set_is_refused_by_name",
    ),
    (
        "AbsentAsEmpty",
        "HeadBucketOutput",
        include_str!("../../../types/src/compat/seam/generated_tests.rs"),
        "n_an_empty_legacy_region_is_refused_not_written_as_none",
    ),
    (
        "Nested",
        "CopyObjectOutput",
        include_str!("../../../goldens/src/operation_diff/copy_result.rs"),
        "every_copy_result_checksum_crosses_the_seam_with_its_value",
    ),
    (
        "Nested",
        "UploadPartCopyOutput",
        include_str!("../../../goldens/src/operation_diff/copy_result.rs"),
        "every_copy_result_checksum_crosses_the_seam_with_its_value",
    ),
];

/// Whether the pinned fact table's `struct` holds `member`.
fn legacy_has(facts: &str, owner: &str, member: &str) -> bool {
    let Some(start) = facts.find(&format!("\nstruct {owner}\n")) else { return false };
    facts[start + 1..]
        .lines()
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .any(|line| line.trim_start().split(':').next() == Some(member))
}

/// The request-side places `owner` sits at: (operation, member-path prefix).
fn request_sides(owner: &str) -> Vec<(String, String)> {
    if let Some(operation) = owner
        .strip_suffix("Input")
        .filter(|operation| SEAM_OPERATIONS.contains(operation))
    {
        return vec![(operation.to_owned(), String::new())];
    }
    NESTED
        .iter()
        .filter(|(nested, _, _)| *nested == owner)
        .flat_map(|(_, sides, _)| {
            sides
                .iter()
                .map(|(operation, prefix)| ((*operation).to_owned(), (*prefix).to_owned()))
        })
        .collect()
}

/// The answer-side legacy structs `owner` sits in.
fn answer_sides(owner: &str) -> Vec<String> {
    if owner
        .strip_suffix("Output")
        .is_some_and(|operation| SEAM_OPERATIONS.contains(&operation))
    {
        return vec![owner.to_owned()];
    }
    NESTED
        .iter()
        .filter(|(nested, _, _)| *nested == owner)
        .flat_map(|(_, _, outputs)| outputs.iter().map(|output| (*output).to_owned()))
        .collect()
}

fn has_finding(operation: &str, path: &str, class: SeamClass) -> bool {
    SEAM_FINDINGS
        .iter()
        .any(|finding| finding.operation == operation && finding.path == path && finding.class == class)
}

fn output_proof(rule: &str, owner: &str, member: &str) -> Result<(), String> {
    let Some((_, _, file, test)) = OUTPUT_PROOFS
        .iter()
        .find(|(proof_rule, proof_owner, _, _)| *proof_rule == rule && *proof_owner == owner)
    else {
        return Err(format!("{owner}.{member} ({rule}): no test proves it"));
    };
    let Some(start) = file.find(&format!("fn {test}(")) else {
        return Err(format!("{owner}.{member} ({rule}): {test} does not exist"));
    };
    let body = &file[start..];
    let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
    if matches!(rule, "S3sOnly" | "AbsentAsEmpty") && !body.contains(&format!("\"{member}\"")) {
        return Err(format!("{owner}.{member} ({rule}): {test} does not name the member"));
    }
    Ok(())
}

/// Why one override is lossless or fail-closed, or what is missing.
fn classify(entry: &Override, covered: &BTreeSet<(String, String)>) -> Result<(), String> {
    let Override { owner, member, rule } = entry;
    let requests = request_sides(owner);
    let answers = answer_sides(owner);
    if requests.is_empty() && answers.is_empty() {
        return Err(format!(
            "{owner}.{member}: {owner} is neither a covered operation's structure nor a listed nested one"
        ));
    }
    let mut problems = Vec::new();
    for (operation, prefix) in &requests {
        let path = format!("{prefix}{member}");
        let proven = match rule.as_str() {
            "S3sOnly" => has_finding(operation, &path, SeamClass::DroppedUnread),
            "GatewayOnly" => has_finding(operation, member, SeamClass::FailClosed),
            "Supplied" | "FromQuery" | "FromBoolHeader" | "Rename" => covered.contains(&(operation.clone(), path.clone())),
            "CarriedByHeaders" => !legacy_has(FACTS, owner, member),
            _ => false,
        };
        if !proven {
            problems.push(format!("{operation}: {path} ({rule}) is not proven on the request side"));
        }
    }
    for output in &answers {
        let proven = match rule.as_str() {
            "GatewayOnly" => !legacy_has(FACTS, output, member) || !legacy_has(FACTS, owner, member),
            "S3sOnly" | "Nested" | "AbsentAsEmpty" => output_proof(rule, output, member)
                .map_err(|error| problems.push(error))
                .is_ok(),
            _ => false,
        };
        if !proven && !matches!(rule.as_str(), "S3sOnly" | "Nested" | "AbsentAsEmpty") {
            problems.push(format!("{output}: {member} ({rule}) is not proven on the answer side"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// Every (operation, member path) some row handed over identically.
fn covered() -> BTreeSet<(String, String)> {
    super::seam::identically_handed()
}

#[test]
fn every_seam_override_is_proven_lossless_or_fail_closed() {
    let entries = overrides(OVERRIDES);
    let table = &OVERRIDES[OVERRIDES.find("pub const MEMBERS").unwrap_or_default()..];
    let table = &table[..table.find("\n];").unwrap_or(table.len())];
    let rules = table
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.matches("Rule::").count())
        .sum::<usize>();
    assert_eq!(entries.len(), rules, "every entry of the table is parsed, and nothing else");
    let covered = covered();
    let problems: Vec<String> = entries.iter().filter_map(|entry| classify(entry, &covered).err()).collect();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn n_the_parser_reads_every_entry_spelling_the_table_uses() {
    let source = "pub const MEMBERS: &[MemberOverride] = &[\n    (\"A\", \"b\", Rule::S3sOnly(X)),\n    (\n        \"C\",\n        \"d\",\n        Rule::CarriedByHeaders(\"why\"),\n    ),\n];\n";
    assert_eq!(
        overrides(source),
        [
            Override {
                owner: "A".into(),
                member: "b".into(),
                rule: "S3sOnly".into()
            },
            Override {
                owner: "C".into(),
                member: "d".into(),
                rule: "CarriedByHeaders".into()
            },
        ]
    );
}

fn entry(owner: &str, member: &str, rule: &str) -> Override {
    Override {
        owner: owner.to_owned(),
        member: member.to_owned(),
        rule: rule.to_owned(),
    }
}

#[test]
fn n_a_dropped_request_member_without_a_finding_is_unproven() {
    assert!(classify(&entry("CopyObjectInput", "storage_class", "S3sOnly"), &BTreeSet::new()).is_err());
    assert!(classify(&entry("CopyObjectInput", "annotation_directive", "S3sOnly"), &BTreeSet::new()).is_ok());
}

#[test]
fn n_a_refused_request_member_without_a_fail_closed_finding_is_unproven() {
    assert!(classify(&entry("DeleteObjectInput", "object_lock_event_hold", "GatewayOnly"), &BTreeSet::new()).is_err());
}

#[test]
fn n_a_carried_member_no_row_hands_over_is_unproven() {
    let entry = entry("CopyObjectInput", "copy_source", "Supplied");
    assert!(classify(&entry, &BTreeSet::new()).is_err());
    let covered: BTreeSet<_> = [("CopyObject".to_owned(), "copy_source".to_owned())].into_iter().collect();
    assert!(classify(&entry, &covered).is_ok());
}

#[test]
fn n_an_unknown_owner_or_rule_is_unproven() {
    assert!(classify(&entry("SomeOtherStruct", "x", "S3sOnly"), &BTreeSet::new()).is_err());
    assert!(classify(&entry("CopyObjectInput", "annotation_directive", "Invented"), &BTreeSet::new()).is_err());
}

#[test]
fn n_an_output_rule_without_a_named_test_or_naming_another_member_is_unproven() {
    assert!(output_proof("S3sOnly", "ListBucketsOutput", "owner").is_err());
    assert!(output_proof("S3sOnly", "HeadBucketOutput", "bucket_region").is_err());
    assert!(output_proof("S3sOnly", "HeadBucketOutput", "bucket_arn").is_ok());
    assert!(output_proof("AbsentAsEmpty", "HeadBucketOutput", "bucket_region").is_ok());
    assert!(output_proof("AbsentAsEmpty", "HeadBucketOutput", "bucket_arn").is_err());
    assert!(output_proof("AbsentAsEmpty", "CreateBucketOutput", "bucket_region").is_err());
}

#[test]
fn n_a_member_one_side_lacks_is_read_from_the_fact_table() {
    assert!(legacy_has(FACTS, "HeadBucketOutput", "bucket_arn"));
    assert!(!legacy_has(FACTS, "GetObjectInput", "if_range"));
    assert!(!legacy_has(FACTS, "NoSuchStruct", "bucket"));
}
