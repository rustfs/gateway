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

//! Judges the seam answer diff (rustfs/gateway#1076, item 2): every member a RustFS app body can
//! set on a legacy output reaches the wire as the legacy stack writes it, or the seam refuses the
//! output by that member's name.
//!
//! Responsible for: holding every answer row (`seam::answer_rows`), and every encode-matrix sample
//! written through the production seam instead of this crate's own conversion, to exactly what it
//! declares; every member path of every covered operation's legacy output to a row that writes it
//! or a refusal that names it; and the negative controls that prove each judgement bites.
//! NOT responsible for: the answer's own response headers (`seam_answers.rs`), or the gateway
//! encoder beyond what these answers show (the encode matrix, `encoding.rs`).
//! Upstream: `crate::seam`, `crate::samples`, the checked-in register. Downstream: none.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::decode::Item;
use crate::s3s::dto as legacy;
use crate::seam::{
    ANSWER_FINDINGS, AnswerDiff, SEAM_OPERATIONS, SeamDiffer, UNWRITTEN_PATHS, Written, answer_rows, output_paths,
};
use crate::{KnownDiffs, OracleOutput, RawRequest};

/// Every problem `diff` shows against `expect`: a refusal where an answer was declared or the other
/// way round, a refused member other than the one declared or a refusal the gateway still wrote;
/// for a written answer, a register id or an answer finding matched or missed against the
/// declaration, a difference neither holds, a child order other than the declared, and any value
/// the legacy answer holds that the gateway answer does not.
fn judge(name: &str, diff: &AnswerDiff, expect: Written, register: &KnownDiffs) -> Vec<String> {
    let mut problems = Vec::new();
    match (expect, &diff.refused) {
        (Written::Refused(member), Some(error)) => {
            if error.field != member {
                problems.push(format!("{name}: the seam refused {}, not {member}", error.field));
            }
            if diff.gateway_status != 500 {
                problems.push(format!(
                    "{name}: the seam refused the output and the gateway still answered {}",
                    diff.gateway_status
                ));
            }
        }
        (Written::Refused(member), None) => {
            problems.push(format!("{name}: declared refused at {member}, and the seam handed the output over"));
        }
        (Written::As { .. }, Some(error)) => {
            problems.push(format!("{name}: the seam refused {}: {}", error.field, error.reason));
        }
        (Written::As { known, answer, orders }, None) => {
            let Some(encode) = &diff.encode else {
                problems.push(format!("{name}: the seam handed the output over and nothing was compared"));
                return problems;
            };
            let verdict = register.verdict(encode.findings());
            let matched: BTreeSet<&str> = verdict.known.iter().map(|(_, id)| id.as_str()).collect();
            let declared: BTreeSet<&str> = known.iter().copied().collect();
            if matched != declared {
                problems.push(format!("{name}: matched {matched:?}, declared {declared:?}"));
            }
            // A registered difference in a header or below the root is a spelling the register
            // argues; the containment check reads past it rather than reporting it twice.
            let mut excused = Excused::default();
            for (finding, _) in &verdict.known {
                match &finding.item {
                    Item::Header(header) => {
                        excused.headers.insert(header.clone());
                    }
                    Item::BodyElement(path) => {
                        if let Some(below_root) = value_path(path) {
                            excused.paths.insert(below_root);
                        }
                    }
                    _ => {}
                }
            }
            let mut reordered = BTreeSet::new();
            let mut answered = BTreeSet::new();
            for failure in verdict.failures {
                if let Item::BodyOrder(path) = &failure.item {
                    reordered.insert(shape_of(path));
                    continue;
                }
                let rendered = failure.item.to_string();
                match ANSWER_FINDINGS.iter().find(|entry| {
                    entry.operation == failure.operation
                        && entry.item == rendered
                        && entry.gateway == failure.gateway
                        && entry.legacy == failure.s3s
                }) {
                    Some(entry) => {
                        answered.insert(entry.id);
                        // A declared answer finding argues its own path, as a register entry does.
                        match &failure.item {
                            Item::Header(header) => {
                                excused.headers.insert(header.clone());
                            }
                            Item::BodyElement(path) => {
                                if let Some(below_root) = value_path(path) {
                                    excused.paths.insert(below_root);
                                }
                            }
                            _ => {}
                        }
                    }
                    None => problems.push(format!("{name}: unregistered {failure}")),
                }
            }
            let declared: BTreeSet<&str> = answer.iter().copied().collect();
            if answered != declared {
                problems.push(format!("{name}: answer findings {answered:?}, declared {declared:?}"));
            }
            let declared: BTreeSet<String> = orders.iter().map(|path| (*path).to_owned()).collect();
            if reordered != declared {
                problems.push(format!("{name}: children reordered at {reordered:?}, declared {declared:?}"));
            }
            for value in diff.lost(&excused.headers, &excused.paths) {
                problems.push(format!("{name}: the gateway answer lost {value}"));
            }
        }
    }
    problems
}

/// The header names and body paths a registered difference already accounts for.
#[derive(Default)]
struct Excused {
    headers: BTreeSet<String>,
    paths: BTreeSet<String>,
}

/// An element path of a finding (`ListBucketResult/Contents[0]/Key`) as the containment check
/// names values (`Contents/Key`): the root left out, list positions erased. `None` for the root
/// itself, whose name and attributes hold no value of the output.
fn value_path(path: &str) -> Option<String> {
    let (_, below_root) = path.split_once('/')?;
    let mut shape = String::with_capacity(below_root.len());
    let mut in_index = false;
    for character in below_root.chars() {
        match character {
            '[' => in_index = true,
            ']' => in_index = false,
            _ if in_index => {}
            _ => shape.push(character),
        }
    }
    Some(shape)
}

/// Encode-matrix samples the RustFS profile answers otherwise than the generic profile the matrix
/// pins beyond the response layout ([`under_the_rustfs_layout`]; the seam diff runs the RustFS
/// profile): each sample's register ids and answer findings under it. The RustFS listing rule
/// (#1088) keeps `/` literal in a URL-encoded delimiter, so the delimiter the generic profile
/// double-encodes (kd-encode-0037, 0039, 0041) is written as the legacy stack writes it, and it
/// echoes no multipart EncodingType (sa-0001). XML-valid control characters do not force the
/// RustFS profile into the generic profile's whole-page URL encoding (kd-encode-0051..0057).
const RUSTFS_PROFILE_SAMPLES: &[(&str, &[&str], &[&str])] = &[
    (
        "list-objects-v2-control-character",
        &["kd-encode-0001", "kd-encode-0002", "kd-encode-0003", "kd-encode-0004"],
        &[],
    ),
    (
        "list-objects-v2-url",
        &[
            "kd-encode-0001",
            "kd-encode-0002",
            "kd-encode-0003",
            "kd-encode-0004",
            "kd-encode-0038",
        ],
        &[],
    ),
    (
        "list-objects-url",
        &["kd-encode-0001", "kd-encode-0002", "kd-encode-0003", "kd-encode-0004"],
        &[],
    ),
    (
        "list-multipart-uploads-url",
        &["kd-encode-0001", "kd-encode-0002", "kd-encode-0003", "kd-encode-0004"],
        &["sa-0001"],
    ),
];

/// Negative — every RustFS-profile sample names a sample of the matrix and answers otherwise than
/// the matrix pins it: an entry that no longer differs is stale.
#[test]
fn n_every_rustfs_profile_sample_differs_from_what_the_matrix_pins() {
    let rows = crate::samples::outputs();
    for (name, known, answer) in RUSTFS_PROFILE_SAMPLES {
        let row = rows
            .iter()
            .find(|row| row.sample.name == *name)
            .unwrap_or_else(|| panic!("{name} is not an encode-matrix sample"));
        let pinned: BTreeSet<&str> = under_the_rustfs_layout(row.expect).iter().copied().collect();
        let profile: BTreeSet<&str> = known.iter().copied().collect();
        assert!(pinned != profile || !answer.is_empty(), "{name} answers as the matrix pins it");
    }
}

/// The register entries the RustFS response layout (`write_responses_as_rustfs`,
/// rustfs/gateway#1078) leaves nothing to match: the line end after the XML declaration
/// (`body.prolog`), every model-order entry (`body.order …`), the S3 namespace on a root the legacy
/// stack writes bare (an entry whose two sides differ in that attribute alone), and an entity tag's
/// quotes (an entry whose two sides differ in `&quot;` against `"` alone). The seam diff runs the
/// layout; the encode matrix, which pins these entries, runs the generic profile.
fn layout_entries() -> &'static BTreeSet<String> {
    static ENTRIES: OnceLock<BTreeSet<String>> = OnceLock::new();
    ENTRIES.get_or_init(|| {
        let namespace = " xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";
        KnownDiffs::checked_in()
            .expect("the checked-in register parses")
            .entries()
            .iter()
            .filter(|entry| {
                let (bare_root, quoted_tag) = match (&entry.gateway, &entry.s3s) {
                    (Some(gateway), Some(legacy)) if gateway != legacy => (
                        gateway.replacen(namespace, "", 1) == *legacy,
                        gateway.replace("&quot;", "\\\"") == *legacy,
                    ),
                    _ => (false, false),
                };
                entry.item == "body.prolog" || entry.item.starts_with("body.order ") || bare_root || quoted_tag
            })
            .map(|entry| entry.id.clone())
            .collect()
    })
}

/// A matrix sample's register ids as the seam diff's answers show them: the pinned ids without
/// [`layout_entries`].
fn under_the_rustfs_layout(pinned: &[&'static str]) -> &'static [&'static str] {
    let kept: Vec<&'static str> = pinned.iter().copied().filter(|id| !layout_entries().contains(*id)).collect();
    Box::leak(kept.into_boxed_slice())
}

/// One judged answer.
struct Outcome {
    name: String,
    diff: AnswerDiff,
    expect: Written,
}

/// Every answer row and every encode-matrix sample, written once through the seam.
fn outcomes() -> &'static [Outcome] {
    static OUTCOMES: OnceLock<Vec<Outcome>> = OnceLock::new();
    OUTCOMES.get_or_init(|| {
        let differ = SeamDiffer::new().expect("both stacks assemble");
        let mut outcomes = Vec::new();
        for row in answer_rows() {
            let diff = (row.run)(&differ).unwrap_or_else(|error| panic!("{}: {error}", row.name));
            outcomes.push(Outcome {
                name: row.name.to_owned(),
                diff,
                expect: row.expect,
            });
        }
        for row in crate::samples::outputs() {
            let diff =
                OracleOutput::through_seam(&row.sample, &differ).unwrap_or_else(|error| panic!("{}: {error}", row.sample.name));
            // What the matrix pins for its own conversion: the member it refuses, or the
            // registered differences of the two answers.
            let expect = match (row.sample.output)().into_gateway() {
                Err(unconvertible) => Written::Refused(unconvertible.member),
                Ok(_) => match RUSTFS_PROFILE_SAMPLES.iter().find(|(name, _, _)| *name == row.sample.name) {
                    Some((_, known, answer)) => Written::As {
                        known,
                        answer,
                        orders: &[],
                    },
                    None => Written::As {
                        known: under_the_rustfs_layout(row.expect),
                        answer: &[],
                        orders: &[],
                    },
                },
            };
            outcomes.push(Outcome {
                name: format!("encode matrix {}", row.sample.name),
                diff,
                expect,
            });
        }
        outcomes
    })
}

/// Positive — every answer row writes exactly what it declares.
#[test]
fn every_answer_row_writes_exactly_what_it_declares() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let mut names = BTreeSet::new();
    let mut problems = Vec::new();
    for outcome in outcomes()
        .iter()
        .filter(|outcome| !outcome.name.starts_with("encode matrix "))
    {
        assert!(names.insert(outcome.name.clone()), "row {} is listed twice", outcome.name);
        problems.extend(judge(&outcome.name, &outcome.diff, outcome.expect, &register));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Positive — every encode-matrix sample, written through the production seam as the RustFS adapter
/// converts an answer, shows exactly the registered differences the matrix pins for it with this
/// crate's own conversion: the seam hands the gateway writer what the matrix measured.
#[test]
fn every_encode_matrix_sample_written_through_the_seam_shows_what_the_matrix_pins() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let mut problems = Vec::new();
    for outcome in outcomes().iter().filter(|outcome| outcome.name.starts_with("encode matrix ")) {
        problems.extend(judge(&outcome.name, &outcome.diff, outcome.expect, &register));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// The path of a member with list positions erased.
fn shape_of(path: &str) -> String {
    let mut shape = String::with_capacity(path.len());
    let mut in_index = false;
    for character in path.chars() {
        match character {
            '[' => {
                in_index = true;
                shape.push('[');
            }
            ']' => {
                in_index = false;
                shape.push(']');
            }
            _ if in_index => {}
            _ => shape.push(character),
        }
    }
    shape
}

/// One answer, as the coverage judgement reads it: the operation, the member paths its legacy
/// output held, and the member the seam refused, if it refused.
type Covered<'a> = (&'a str, &'a [String], Option<&'static str>);

/// Every member path of every covered operation's legacy output that no written answer holds and
/// no refusal names, by operation, less the paths [`UNWRITTEN_PATHS`] explains; and every operation
/// no answer covers at all.
fn unwritten(answers: &[Covered<'_>]) -> BTreeMap<String, Vec<String>> {
    let mut written: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    let mut refused: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (operation, present, member) in answers {
        match member {
            Some(member) => {
                refused.entry(operation).or_default().insert(member);
            }
            None => written
                .entry(operation)
                .or_default()
                .extend(present.iter().map(|path| shape_of(path))),
        }
    }
    let mut missing = BTreeMap::new();
    for operation in SEAM_OPERATIONS {
        let paths = output_paths(operation).unwrap_or_else(|| panic!("{operation} has no output census"));
        if !written.contains_key(operation) && !refused.contains_key(operation) {
            missing.insert((*operation).to_owned(), vec!["<no answer at all>".to_owned()]);
            continue;
        }
        let held = written.get(operation).cloned().unwrap_or_default();
        let refusals = refused.get(operation).cloned().unwrap_or_default();
        let unexplained: Vec<String> = paths
            .iter()
            .filter(|path| !held.contains(**path))
            .filter(|path| {
                !refusals
                    .iter()
                    .any(|member| **path == *member || path.ends_with(&format!(".{member}")))
            })
            .filter(|path| {
                !UNWRITTEN_PATHS
                    .iter()
                    .any(|(listed, unwritten, _)| listed == operation && unwritten == *path)
            })
            .map(|path| (*path).to_owned())
            .collect();
        if !unexplained.is_empty() {
            missing.insert((*operation).to_owned(), unexplained);
        }
    }
    missing
}

/// Positive — every member path of every covered operation's legacy output is written by some
/// answer that reached the wire, or named by a refusal, or listed in [`UNWRITTEN_PATHS`] with why;
/// so a member the seam drops would leave a difference some answer shows.
#[test]
fn every_member_of_every_seam_output_is_written_or_refused_by_name() {
    let answers: Vec<Covered<'_>> = outcomes()
        .iter()
        .map(|outcome| {
            (
                outcome.diff.operation,
                outcome.diff.present.as_slice(),
                outcome.diff.refused.as_ref().map(|error| error.field),
            )
        })
        .collect();
    let missing = unwritten(&answers);
    assert!(missing.is_empty(), "output members no answer writes or refuses: {missing:#?}");
}

/// Negative — an [`UNWRITTEN_PATHS`] entry names a real output path that no written answer holds:
/// a listed path some answer does write is stale.
#[test]
fn n_no_unwritten_path_is_written_or_unknown() {
    let written: BTreeSet<(&str, String)> = outcomes()
        .iter()
        .filter(|outcome| outcome.diff.refused.is_none())
        .flat_map(|outcome| {
            outcome
                .diff
                .present
                .iter()
                .map(|path| (outcome.diff.operation, shape_of(path)))
        })
        .collect();
    for (operation, path, reason) in UNWRITTEN_PATHS {
        assert!(!reason.is_empty(), "{operation} {path} has no reason");
        let paths = output_paths(operation).unwrap_or_else(|| panic!("{operation} is not a covered operation"));
        assert!(paths.contains(path), "{operation} has no output path {path}");
        assert!(
            !written.contains(&(*operation, (*path).to_owned())),
            "{operation} {path} is written after all"
        );
    }
}

/// Negative — the coverage judgement names a member no answer writes, and an operation no answer
/// covers at all.
#[test]
fn n_a_member_no_answer_writes_is_named() {
    let tagging = vec!["tag_set[0].key".to_owned()];
    let mut answers: Vec<Covered<'_>> = vec![("GetBucketTagging", tagging.as_slice(), None)];
    let missing = unwritten(&answers);
    assert_eq!(missing.get("GetBucketTagging"), Some(&vec!["tag_set[].value".to_owned()]));
    assert_eq!(missing.get("GetObjectTagging"), Some(&vec!["<no answer at all>".to_owned()]));

    answers.push(("GetBucketTagging", &[], Some("value")));
    assert_eq!(
        unwritten(&answers).get("GetBucketTagging"),
        None,
        "a refusal naming the member accounts for it"
    );
}

fn tagging(tags: &[(&str, &str)]) -> legacy::GetBucketTaggingOutput {
    legacy::GetBucketTaggingOutput {
        tag_set: tags
            .iter()
            .map(|(key, value)| legacy::Tag {
                key: Some((*key).to_owned()),
                value: Some((*value).to_owned()),
            })
            .collect(),
    }
}

/// Negative — a member the gateway is handed less of than the legacy stack writes is an unregistered
/// difference: the comparison bites on a dropped member.
#[test]
fn n_a_member_the_gateway_is_not_handed_fails_its_row() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let diff = differ
        .answer_diff_pair(&RawRequest::get("/bucket?tagging"), &|| tagging(&[("a", "1")]), &|| {
            tagging(&[("a", "1"), ("b", "2")])
        })
        .expect("both stacks answer");
    let problems = judge(
        "dropped",
        &diff,
        crate::seam::Written::As {
            known: XML,
            answer: &[],
            orders: &[],
        },
        &register,
    );
    assert!(
        problems.iter().any(|problem| problem.contains("unregistered")),
        "a dropped tag went unreported: {problems:?}"
    );

    let same = differ
        .answer_diff_pair(&RawRequest::get("/bucket?tagging"), &|| tagging(&[("a", "1")]), &|| {
            tagging(&[("a", "1")])
        })
        .expect("both stacks answer");
    assert!(
        judge(
            "kept",
            &same,
            crate::seam::Written::As {
                known: XML,
                answer: &[],
                orders: &[],
            },
            &register
        )
        .is_empty()
    );
}

/// An XML answer's registered differences under the RustFS response layout: the four stamped
/// headers alone (the layout writes the legacy declaration, so `kd-encode-0005` never matches).
const XML: &[&str] = &["kd-encode-0001", "kd-encode-0002", "kd-encode-0003", "kd-encode-0004"];

/// Negative — a child order the row declares and the answers do not show (the RustFS layout writes
/// the ACL answer in the legacy order), a refusal declared as an answer and an answer declared as a
/// refusal each fail the row.
#[test]
fn n_an_undeclared_order_or_outcome_fails_the_row() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let acl = outcomes()
        .iter()
        .find(|outcome| outcome.name == "get-bucket-acl-every-member")
        .expect("the bucket ACL row");
    let problems = judge(
        &acl.name,
        &acl.diff,
        crate::seam::Written::As {
            known: XML,
            answer: &[],
            orders: &["AccessControlPolicy", "AccessControlPolicy/Owner"],
        },
        &register,
    );
    assert!(problems.iter().any(|problem| problem.contains("children reordered")), "{problems:?}");
    let problems = judge(&acl.name, &acl.diff, crate::seam::Written::Refused("grants"), &register);
    assert!(problems.iter().any(|problem| problem.contains("handed the output over")), "{problems:?}");

    let differ = SeamDiffer::new().expect("both stacks assemble");
    let arn = || legacy::HeadBucketOutput {
        bucket_arn: Some("arn:aws:s3:::bucket".to_owned()),
        bucket_region: Some("us-east-1".to_owned()),
        ..Default::default()
    };
    let refused = differ
        .answer_diff_pair(&RawRequest::head("/bucket"), &arn, &arn)
        .expect("both stacks answer");
    assert_eq!(refused.refused.as_ref().map(|error| error.field), Some("bucket_arn"));
    let problems = judge(
        "arn",
        &refused,
        crate::seam::Written::As {
            known: XML,
            answer: &[],
            orders: &[],
        },
        &register,
    );
    assert!(
        problems.iter().any(|problem| problem.contains("the seam refused bucket_arn")),
        "{problems:?}"
    );
    assert!(judge("arn", &refused, crate::seam::Written::Refused("bucket_arn"), &register).is_empty());
}

/// Negative — the answer register is well formed: unique `sa-<nnnn>` ids in order, each for a
/// covered operation, with the two sides it pins and a reason.
#[test]
fn n_the_answer_register_is_well_formed() {
    for (index, entry) in ANSWER_FINDINGS.iter().enumerate() {
        assert_eq!(entry.id, format!("sa-{:04}", index + 1), "ids run in order from sa-0001");
        assert!(
            SEAM_OPERATIONS.contains(&entry.operation),
            "{}: {} is not covered",
            entry.id,
            entry.operation
        );
        assert!(
            !entry.item.is_empty() && !entry.gateway.is_empty() && !entry.legacy.is_empty(),
            "{}",
            entry.id
        );
        assert!(entry.reason.len() >= 40, "{}: a reason says what differs and why", entry.id);
    }
}

/// Negative — an answer finding no row declares is stale: each row is held to the findings it
/// declares, so a declared finding is one some answer shows.
#[test]
fn n_no_answer_finding_outlives_the_difference_it_names() {
    let declared: BTreeSet<&str> = outcomes()
        .iter()
        .filter_map(|outcome| match outcome.expect {
            Written::As { answer, .. } => Some(answer),
            Written::Refused(_) => None,
        })
        .flatten()
        .copied()
        .collect();
    let stale: Vec<&str> = ANSWER_FINDINGS
        .iter()
        .map(|entry| entry.id)
        .filter(|id| !declared.contains(id))
        .collect();
    assert!(stale.is_empty(), "answer findings no row declares: {stale:?}");
}

/// Two answers rooted at `gateway_root` and `legacy_root`, the legacy one holding an object size
/// the gateway one may lack, compared as the seam diff compares them.
fn rooted(gateway_root: &str, legacy_root: &str, gateway_size: Option<i64>) -> AnswerDiff {
    let document = |root: &str, size: Option<i64>| {
        let size = size
            .map(|size| format!("<ObjectSize>{size}</ObjectSize>"))
            .unwrap_or_default();
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><{root} xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><StorageClass>STANDARD</StorageClass>{size}</{root}>"
        );
        crate::encode::WireAnswer::new(200, &http::HeaderMap::new(), body.into_bytes())
    };
    let (mut gateway, mut legacy) = (document(gateway_root, gateway_size), document(legacy_root, Some(15)));
    let encode = crate::encode::compare("GetObjectAttributes".to_owned(), false, &mut gateway, &mut legacy);
    AnswerDiff {
        operation: "GetObjectAttributes",
        present: Vec::new(),
        refused: None,
        gateway_status: 200,
        encode: Some(encode),
        answers: Some((gateway, legacy)),
    }
}

/// Negative — a value the gateway answer lacks is named by the containment check even where the
/// element comparison cannot reach: when two answers are rooted at different elements — as the
/// generic layout roots the attributes answer at `GetObjectAttributesOutput` and the legacy stack
/// at `GetObjectAttributesResponse` — the element diff stops at the root and only the containment
/// check reads the members below it. (The seam diff's own answers no longer differ at the root:
/// the RustFS response layout roots the attributes answer as the legacy stack does.)
#[test]
fn n_a_value_below_a_differing_root_that_the_gateway_lacks_is_named() {
    let none = BTreeSet::new();
    let dropped = rooted("GetObjectAttributesOutput", "GetObjectAttributesResponse", None);
    assert_eq!(dropped.lost(&none, &none), ["body ObjectSize: \"15\""]);
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let written = crate::seam::Written::As {
        known: &[],
        answer: &[],
        orders: &[],
    };
    let problems = judge("dropped", &dropped, written, &register);
    assert!(
        problems.contains(&"dropped: the gateway answer lost body ObjectSize: \"15\"".to_owned()),
        "{problems:?}"
    );

    let kept = rooted("GetObjectAttributesOutput", "GetObjectAttributesResponse", Some(15));
    assert!(kept.lost(&none, &none).is_empty());
    let same_root = rooted("GetObjectAttributesResponse", "GetObjectAttributesResponse", Some(15));
    assert!(judge("same", &same_root, written, &register).is_empty());
}

/// The register ids whose entry is about the body: its prolog, a child order, or an element.
fn body_entries() -> &'static BTreeSet<String> {
    static ENTRIES: OnceLock<BTreeSet<String>> = OnceLock::new();
    ENTRIES.get_or_init(|| {
        KnownDiffs::checked_in()
            .expect("the checked-in register parses")
            .entries()
            .iter()
            .filter(|entry| entry.item.starts_with("body"))
            .map(|entry| entry.id.clone())
            .collect()
    })
}

/// Positive — every answer the seam diff writes in the RustFS profile — each answer row and each
/// encode-matrix sample, across every covered operation — is the legacy stack's document byte for
/// byte whenever no body difference is declared (rustfs/gateway#1078); an answer that declares one
/// (a register entry about the body, an answer finding, a child order) is one whose bytes do
/// differ.
#[test]
fn every_rustfs_profile_document_is_the_legacy_bytes_bar_its_declared_differences() {
    let mut problems = Vec::new();
    let mut identical = 0usize;
    for outcome in outcomes() {
        let Written::As { known, answer, orders } = outcome.expect else {
            continue;
        };
        let Some((gateway, legacy)) = &outcome.diff.answers else {
            continue;
        };
        let body_declared = !answer.is_empty() || !orders.is_empty() || known.iter().any(|id| body_entries().contains(*id));
        let same = gateway.body == legacy.body;
        if !body_declared && !same {
            problems.push(format!(
                "{}: the documents differ\n  gateway {}\n  legacy  {}",
                outcome.name,
                String::from_utf8_lossy(&gateway.body),
                String::from_utf8_lossy(&legacy.body)
            ));
        }
        if body_declared && same {
            problems.push(format!("{}: declares a body difference its documents do not show", outcome.name));
        }
        identical += usize::from(same);
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(identical >= 100, "only {identical} answers compared byte for byte");
}

/// The containment check's reading of a document: every attribute but a namespace declaration,
/// every childless element's text with its entities resolved (an empty element included), paths
/// below the root with list positions left out.
#[test]
fn the_value_listing_reads_every_value_below_the_root() {
    let root = crate::xmltree::parse(
        "<R xmlns=\"ns\" a=\"1\"><L><G xmlns:xsi=\"x\" xsi:type=\"T\"><ID>&quot;i&amp;d&#x41;&#66;&bogus;</ID></G><G><ID></ID></G></L><E/></R>",
    )
    .expect("a document");
    assert_eq!(
        crate::xmltree::values(&root),
        [
            ("@a".to_owned(), "1".to_owned()),
            ("L/G@xsi:type".to_owned(), "T".to_owned()),
            ("L/G/ID".to_owned(), "\"i&dAB&bogus;".to_owned()),
            ("L/G/ID".to_owned(), String::new()),
            ("E".to_owned(), String::new()),
        ]
    );
}
