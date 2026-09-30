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

//! Judges the seam decode diff (rustfs/gateway#1076): what the RustFS app layer is handed on each
//! stack.
//!
//! Responsible for: every seam row showing exactly what it declares; every difference a decode
//! matrix row hands over being a registered finding; the census — every member of every covered
//! operation's legacy input handed over identically by some row, named by a finding, or listed as
//! unreached with a reason; no stale finding; a well-formed register; and the negative controls
//! proving a difference in a member or a body cannot go unreported.
//! NOT responsible for: the rows themselves (`seam/samples.rs`).
//! Upstream: `crate::seam`. Downstream: none.

use std::collections::BTreeSet;
use std::sync::OnceLock;

use crate::decode::BodySeen;
use crate::request::RawRequest;
use rustfs_gateway_types::compat::ConversionError;
use rustfs_gateway_types::compat::s3s_0_17_0::error::{Refusal, refusal_from_conversion};

use crate::seam::{
    Expect, SEAM_FINDINGS, SEAM_OPERATIONS, STORED_OPERATIONS, SeamClass, SeamDiff, SeamDiffer, SeamFinding, SeamVerdict,
    UNREACHED_PATHS, input_paths, seam_rows,
};

/// Where a judged request came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Seam,
    Matrix,
}

struct Outcome {
    source: Source,
    name: &'static str,
    expect: Option<Expect>,
    diff: SeamDiff,
}

/// Every seam row and every decode matrix row, sent once.
fn outcomes() -> &'static [Outcome] {
    static OUTCOMES: OnceLock<Vec<Outcome>> = OnceLock::new();
    OUTCOMES.get_or_init(|| {
        let differ = SeamDiffer::new().expect("both stacks assemble");
        let mut outcomes = Vec::new();
        for row in seam_rows() {
            let diff = differ
                .diff(&row.request)
                .unwrap_or_else(|error| panic!("{}: {error}", row.name));
            outcomes.push(Outcome {
                source: Source::Seam,
                name: row.name,
                expect: Some(row.expect),
                diff,
            });
        }
        for row in crate::samples::requests() {
            let diff = differ
                .diff(&row.request)
                .unwrap_or_else(|error| panic!("{}: {error}", row.name));
            outcomes.push(Outcome {
                source: Source::Matrix,
                name: row.name,
                expect: None,
                diff,
            });
        }
        outcomes
    })
}

/// A reported path with its list indices dropped, as the census spells it.
fn unindexed(path: &str) -> String {
    let mut out = String::new();
    let mut inside = false;
    for character in path.chars() {
        match character {
            '[' => {
                inside = true;
                out.push('[');
            }
            ']' => {
                inside = false;
                out.push(']');
            }
            _ if inside => {}
            other => out.push(other),
        }
    }
    out
}

fn finding(id: &str) -> Option<&'static SeamFinding> {
    SEAM_FINDINGS.iter().find(|finding| finding.id == id)
}

/// The finding registered for a difference at `path` of `operation`, if any.
fn registered(operation: &str, path: &str) -> Option<&'static SeamFinding> {
    SEAM_FINDINGS
        .iter()
        .find(|finding| finding.operation == operation && finding.path == path && finding.class != SeamClass::FailClosed)
}

fn both_handed(diff: &SeamDiff) -> bool {
    diff.verdict.gateway == SeamVerdict::Handed && diff.verdict.s3s == SeamVerdict::Handed
}

/// Every way `diff` fails to show `expect`.
fn judge(name: &str, diff: &SeamDiff, expect: &Expect) -> Vec<String> {
    let mut problems = Vec::new();
    let mut problem = |text: String| problems.push(format!("{name}: {text}"));
    let operation = diff.routed.gateway.clone().unwrap_or_default();
    match expect {
        Expect::Identical => {
            if !diff.identical() {
                problem(format!(
                    "expected identical, got routed {:?}, verdict {:?}, differing {:?}, same body {}, trailers {:?}",
                    diff.routed,
                    diff.verdict,
                    diff.differing,
                    diff.body.same(),
                    diff.trailers
                ));
            }
        }
        Expect::Differs(ids) => {
            if !diff.routed.same() || !both_handed(diff) || !diff.body.same() || !diff.trailers.same() {
                problem(format!(
                    "expected both handed, got routed {:?}, verdict {:?}, trailers {:?}",
                    diff.routed, diff.verdict, diff.trailers
                ));
            }
            let expected: BTreeSet<String> = ids
                .iter()
                .filter_map(|id| {
                    finding(id)
                        .filter(|finding| finding.operation == operation)
                        .map(|finding| finding.path.to_owned())
                })
                .collect();
            if expected.len() != ids.len() {
                problem(format!("{ids:?} names a finding that does not exist or is not about {operation}"));
            }
            let actual: BTreeSet<String> = diff.differing.iter().map(|path| unindexed(path)).collect();
            if actual != expected {
                problem(format!("expected differences {expected:?}, got {actual:?}"));
            }
        }
        Expect::FailsClosed(id) => match (finding(id), &diff.verdict.gateway, &diff.verdict.s3s) {
            (Some(finding), SeamVerdict::Unconverted { member, .. }, SeamVerdict::Handed | SeamVerdict::Refused(_))
                if finding.class == SeamClass::FailClosed && finding.path == *member && finding.operation == operation => {}
            other => problem(format!("expected the seam to refuse the member of {id}, got {other:?}")),
        },
        Expect::NeitherHandsOver => {
            if !matches!(
                (&diff.verdict.gateway, &diff.verdict.s3s),
                (SeamVerdict::Refused(_), SeamVerdict::Refused(_))
            ) {
                problem(format!("expected both stacks to refuse before any handler, got {:?}", diff.verdict));
            }
        }
        Expect::BothRefuse(member) => match (&diff.verdict.gateway, &diff.verdict.s3s) {
            (SeamVerdict::Unconverted { member: refused, reason }, SeamVerdict::Refused(legacy)) if refused == member => {
                let answer = refusal_from_conversion(&ConversionError { field: refused, reason });
                match answer {
                    Some(Refusal::Ordinary { code, .. })
                        if Some(code.as_str()) == legacy.code.as_deref() && code.default_status().as_u16() == legacy.status => {}
                    other => problem(format!("the seam answers {other:?} where the legacy decoder answered {legacy}")),
                }
            }
            other => problem(format!("expected both stacks to refuse {member} before any RustFS body, got {other:?}")),
        },
    }
    problems
}

#[test]
fn every_seam_row_shows_exactly_what_it_declares() {
    let problems: Vec<String> = outcomes()
        .iter()
        .filter_map(|outcome| {
            outcome
                .expect
                .as_ref()
                .map(|expect| judge(outcome.name, &outcome.diff, expect))
        })
        .flatten()
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn every_difference_a_decode_matrix_row_hands_over_is_a_registered_finding() {
    let mut problems = Vec::new();
    for outcome in outcomes().iter().filter(|outcome| outcome.source == Source::Matrix) {
        let diff = &outcome.diff;
        if !diff.routed.same() {
            // A routing divergence: the decode diff's register owns it, and nothing was compared.
            continue;
        }
        let operation = diff.routed.gateway.as_deref().unwrap_or_default();
        if both_handed(diff) {
            for path in &diff.differing {
                if registered(operation, &unindexed(path)).is_none() {
                    problems.push(format!("{}: {operation}.{path} differs and no finding names it", outcome.name));
                }
            }
        }
        if let (SeamVerdict::Unconverted { member, .. }, SeamVerdict::Handed) = (&diff.verdict.gateway, &diff.verdict.s3s)
            && !SEAM_FINDINGS.iter().any(|finding| {
                finding.class == SeamClass::FailClosed && finding.operation == operation && finding.path == *member
            })
        {
            problems.push(format!("{}: the seam refuses {operation}.{member} and no finding names it", outcome.name));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Every (operation, member path) some row made both stacks hand over identically.
pub(super) fn identically_handed() -> BTreeSet<(String, String)> {
    let mut covered: BTreeSet<(String, String)> = BTreeSet::new();
    for outcome in outcomes() {
        let diff = &outcome.diff;
        if !both_handed(diff) || !diff.routed.same() {
            continue;
        }
        let operation = diff.routed.gateway.clone().unwrap_or_default();
        let differing: BTreeSet<String> = diff.differing.iter().map(|path| unindexed(path)).collect();
        for path in &diff.present {
            if !differing.iter().any(|different| path.starts_with(different.as_str())) {
                covered.insert((operation.clone(), path.clone()));
            }
        }
    }
    covered
}

#[test]
fn every_member_of_every_covered_input_is_accounted_for() {
    let covered = identically_handed();
    let under = |path: &str, prefix: &str| {
        path == prefix || path.starts_with(&format!("{prefix}.")) || path.starts_with(&format!("{prefix}["))
    };
    let mut missing = Vec::new();
    for operation in SEAM_OPERATIONS {
        let paths = input_paths(operation).unwrap_or_else(|| panic!("{operation} has no census"));
        for path in paths {
            let accounted = covered.contains(&((*operation).to_owned(), (*path).to_owned()))
                || SEAM_FINDINGS
                    .iter()
                    .any(|finding| finding.operation == *operation && under(path, finding.path))
                || UNREACHED_PATHS
                    .iter()
                    .any(|(unreached_operation, prefix, _)| unreached_operation == operation && under(path, prefix));
            if !accounted {
                missing.push(format!("{operation}.{path}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "{} legacy input members are neither handed over identically by a row, nor named by a finding, nor listed as unreached:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

#[test]
fn n_no_finding_outlives_the_difference_it_names() {
    let mut used: BTreeSet<&str> = BTreeSet::new();
    for outcome in outcomes() {
        let diff = &outcome.diff;
        let operation = diff.routed.gateway.as_deref().unwrap_or_default();
        match &outcome.expect {
            Some(Expect::Differs(ids)) => used.extend(ids.iter().copied()),
            Some(Expect::FailsClosed(id)) => {
                used.insert(id);
            }
            _ => {}
        }
        if both_handed(diff) {
            for path in &diff.differing {
                if let Some(finding) = registered(operation, &unindexed(path)) {
                    used.insert(finding.id);
                }
            }
        }
        if let SeamVerdict::Unconverted { member, .. } = &diff.verdict.gateway
            && let Some(finding) = SEAM_FINDINGS.iter().find(|finding| {
                finding.class == SeamClass::FailClosed && finding.operation == operation && finding.path == *member
            })
        {
            used.insert(finding.id);
        }
    }
    let stale: Vec<&str> = SEAM_FINDINGS
        .iter()
        .map(|finding| finding.id)
        .filter(|id| !used.contains(id))
        .collect();
    assert!(stale.is_empty(), "findings no row exercises: {stale:?}");
}

/// The checksum-less rows route to exactly the operations the pinned model marks
/// `httpChecksumRequired`, one row each, and every one of them reaches both handlers: under the
/// RustFS profile no such write is refused for a checksum the legacy stack never asks for
/// (rustfs/backlog#1677, R5).
#[test]
fn every_checksum_required_write_without_a_checksum_reaches_both_handlers() {
    use crate::seam::OMITTED_OPERATIONS;

    let mut listed = OMITTED_OPERATIONS.to_vec();
    listed.sort_unstable();
    let mut required = rustfs_gateway::CHECKSUM_REQUIRED_OPERATIONS.to_vec();
    required.sort_unstable();
    assert_eq!(listed, required);

    let omitted: Vec<&Outcome> = outcomes()
        .iter()
        .filter(|outcome| outcome.source == Source::Seam && outcome.name.starts_with("omitted-"))
        .collect();
    let routed: Vec<Option<&str>> = omitted.iter().map(|outcome| outcome.diff.routed.gateway.as_deref()).collect();
    let expected: Vec<Option<&str>> = OMITTED_OPERATIONS.iter().copied().map(Some).collect();
    assert_eq!(routed, expected);
    for outcome in omitted {
        assert!(both_handed(&outcome.diff), "{}: {:?}", outcome.name, outcome.diff.verdict);
    }
}

#[test]
fn n_the_register_is_well_formed() {
    let mut ids = BTreeSet::new();
    for finding in SEAM_FINDINGS {
        assert!(ids.insert(finding.id), "{} is registered twice", finding.id);
        let digits = finding.id.strip_prefix("sd-").unwrap_or_default();
        assert!(
            digits.len() == 4 && digits.bytes().all(|byte| byte.is_ascii_digit()),
            "{}: not sd-<nnnn>",
            finding.id
        );
        assert!(
            SEAM_OPERATIONS.contains(&finding.operation),
            "{}: {} is not covered",
            finding.id,
            finding.operation
        );
        assert!(!finding.evidence.is_empty(), "{}: no evidence", finding.id);
        match finding.class {
            SeamClass::FailClosed => {}
            _ => {
                let paths = input_paths(finding.operation).unwrap_or_default();
                assert!(
                    paths.iter().any(|path| *path == finding.path
                        || path.starts_with(&format!("{}.", finding.path))
                        || path.starts_with(&format!("{}[", finding.path))),
                    "{}: {} is not a member of the {} legacy input",
                    finding.id,
                    finding.path,
                    finding.operation
                );
            }
        }
        if let SeamClass::Ruled(ruling) = finding.class {
            assert!(
                crate::tests::seam::rulings().contains(&ruling),
                "{}: {ruling} is not a ruling of the request-divergence register",
                finding.id
            );
        }
    }
    for (operation, path, reason) in UNREACHED_PATHS {
        assert!(SEAM_OPERATIONS.contains(operation), "unreached {operation}.{path}: not covered");
        assert!(!reason.is_empty(), "unreached {operation}.{path}: no reason");
    }
}

/// The ruling ids the difftest register already cites, which the seam register may cite too.
fn rulings() -> BTreeSet<&'static str> {
    // The register format keeps a ruling per entry; reading it here avoids a second copy of the
    // ruling list that could drift from the one the decode diff is judged against.
    static RULINGS: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    RULINGS
        .get_or_init(|| {
            let text = include_str!("../../known-diffs.toml");
            text.lines()
                .filter_map(|line| line.strip_prefix("ruling = \"").and_then(|rest| rest.strip_suffix('"')))
                .map(|ruling| &*Box::leak(ruling.to_owned().into_boxed_str()))
                .collect()
        })
        .clone()
}

#[test]
fn n_a_member_one_stack_decodes_differently_is_reported() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let copy = |color: &str| {
        RawRequest::new(http::Method::PUT, "/bucket/k")
            .header("x-amz-copy-source", "/src/k")
            .header("x-amz-metadata-directive", "REPLACE")
            .header("x-amz-meta-color", color)
    };
    let diff = differ.diff_pair(&copy("blue"), &copy("red")).expect("both stacks answer");
    assert_eq!(diff.differing, ["metadata"]);
    assert!(!diff.identical());
    let problems = judge("control", &diff, &Expect::Identical);
    assert_eq!(problems.len(), 1, "{problems:?}");
}

#[test]
fn n_a_nested_member_is_reported_at_its_path() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let tagging = |value: &str| {
        let body = format!(
            "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>b</Key><Value>{value}</Value></Tag></TagSet></Tagging>"
        );
        crate::seam::samples_document(http::Method::PUT, "/bucket?tagging", &body)
    };
    let diff = differ.diff_pair(&tagging("x"), &tagging("y")).expect("both stacks answer");
    // The two documents differ, so their Content-MD5 does too; the tag value is named at its index.
    assert_eq!(diff.differing, ["content_md5", "tagging.tag_set[1].value"]);
}

#[test]
fn n_a_body_one_handler_reads_differently_is_reported() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let part = |body: &[u8]| RawRequest::put(&format!("/bucket/k?partNumber=1&uploadId={}", crate::samples::UPLOAD_ID), body);
    let diff = differ
        .diff_pair(&part(b"0123456789"), &part(b"0123456780"))
        .expect("both stacks answer");
    assert!(diff.differing.is_empty(), "{:?}", diff.differing);
    assert!(!diff.body.same());
    assert_eq!(diff.body.gateway, Some(BodySeen::Read(b"0123456789".to_vec())));
    assert!(!diff.identical());
}

/// Negative — a trailer section the two handlers read differently is reported, even with the same
/// members and body: the legacy stack hands over a trailer value the gateway would refuse
/// (rustfs/gateway#1148).
#[test]
fn n_a_trailer_one_handler_reads_differently_is_reported() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let upload = |target: &str, checksum: &str| {
        let body = format!("5\r\nhello\r\n0\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n");
        let request = RawRequest::put(target, body.as_bytes())
            .header("content-encoding", "aws-chunked")
            .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
            .header("x-amz-trailer", "x-amz-checksum-crc32")
            .header("x-amz-decoded-content-length", "5");
        crate::sign::signed(&request).expect("an unsigned-payload trailer upload signs")
    };
    // A part: the trailer is the only difference.
    let part = format!("/bucket/k?partNumber=1&uploadId={}", crate::samples::UPLOAD_ID);
    let diff = differ
        .diff_pair(&upload(&part, "NhCmhg=="), &upload(&part, "AAAAAA=="))
        .expect("both stacks answer");
    assert!(diff.differing.is_empty() && diff.body.same(), "{:?} {:?}", diff.differing, diff.body);
    assert!(!diff.trailers.same(), "{:?}", diff.trailers);
    assert!(!diff.identical());
    assert_eq!(judge("control", &diff, &Expect::Identical).len(), 1);
    // An object: beside a registered difference, the trailer is still one too many.
    let diff = differ
        .diff_pair(&upload("/bucket/k", "NhCmhg=="), &upload("/bucket/k", "AAAAAA=="))
        .expect("both stacks answer");
    assert!(!diff.trailers.same(), "{:?}", diff.trailers);
    assert_eq!(judge("control", &diff, &Expect::Differs(&["sd-0033"])).len(), 1);
}

#[test]
fn n_a_refused_conversion_is_never_identical() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let request = RawRequest::put("/bucket/k", b"x").header("x-amz-object-lock-event-hold", "ON");
    let diff = differ.diff(&request).expect("both stacks answer");
    assert!(
        matches!(
            diff.verdict.gateway,
            SeamVerdict::Unconverted {
                member: "object_lock_event_hold",
                ..
            }
        ),
        "{:?}",
        diff.verdict
    );
    assert!(!diff.identical());
    assert_eq!(judge("control", &diff, &Expect::Identical).len(), 1);
    assert!(judge("control", &diff, &Expect::FailsClosed("sd-0016")).is_empty());
    assert_eq!(
        judge("control", &diff, &Expect::FailsClosed("sd-0019")).len(),
        1,
        "a finding about another operation"
    );
}

/// Every optional header member of `operation`'s input, by wire name, read from the generated
/// operation spec so a header added to the model is probed without editing this test.
fn optional_headers(operation: &str) -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../spec/operations/{operation}.toml"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let spec: toml::Value = toml::from_str(&text).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    spec.get("input")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|field| field.get("binding").and_then(toml::Value::as_str) == Some("Header"))
        .filter(|field| field.get("required").and_then(toml::Value::as_bool) != Some(true))
        .filter_map(|field| field.get("wire_name").and_then(toml::Value::as_str).map(str::to_owned))
        .collect()
}

/// The legacy decoder reads an optional header whose value is empty as absent (rustfs/gateway#1076).
/// For every optional header of every covered operation, sent empty on a request that is otherwise
/// handed over identically: whenever the gateway handler is reached, the RustFS body is handed the
/// same input on both stacks, but for a registered finding. A gateway that refuses the empty value
/// before its handler is a request-acceptance divergence, and is counted, not compared: the RustFS
/// profile reads the empty line as absent (rustfs/gateway#1087), so what it still refuses is the
/// request without that header.
#[test]
fn every_empty_optional_header_is_handed_over_as_absent() {
    let differ = SeamDiffer::new().expect("both stacks assemble");
    let rows = seam_rows();
    let mut problems = Vec::new();
    let (mut compared, mut refused_by_the_gateway) = (0_usize, 0_usize);
    for operation in SEAM_OPERATIONS {
        let base = outcomes()
            .iter()
            .filter(|outcome| outcome.source == Source::Seam && outcome.expect == Some(Expect::Identical))
            .filter(|outcome| outcome.diff.routed.gateway.as_deref() == Some(operation))
            .find_map(|outcome| rows.iter().find(|row| row.name == outcome.name));
        let Some(base) = base else {
            problems.push(format!("{operation}: no seam row hands it over identically to probe from"));
            continue;
        };
        for header in optional_headers(operation) {
            let request = base.request.clone().without(&header).header(&header, "");
            let diff = differ
                .diff(&request)
                .unwrap_or_else(|error| panic!("{operation} {header}: {error}"));
            let registered_only = both_handed(&diff)
                && diff.routed.same()
                && diff.body.same()
                && diff
                    .differing
                    .iter()
                    .all(|path| registered(operation, &unindexed(path)).is_some());
            match (&diff.verdict.gateway, &diff.verdict.s3s) {
                (SeamVerdict::Refused(_), _) => refused_by_the_gateway += 1,
                _ if registered_only => compared += 1,
                _ => problems.push(format!(
                    "{operation} with an empty {header}: verdict {:?}, differing {:?}",
                    diff.verdict, diff.differing
                )),
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    // Counts measured on 2026-09-30, so a probe that silently stopped reaching the handlers cannot
    // pass: 295 empty headers compared, 14 refused by the gateway before its handler. Both may
    // only move the right way. Under the RustFS profile an empty line is absent
    // (rustfs/gateway#1087); the 14 are one blanked header of an SSE-C trio or of a KMS request,
    // whose remaining headers the gateway refuses before any handler as an incomplete trio or a
    // KMS qualifier without its algorithm, where the legacy decoder leaves them to the RustFS body.
    assert!(compared >= 295, "only {compared} empty headers were compared");
    assert!(
        refused_by_the_gateway <= 14,
        "{refused_by_the_gateway} empty headers are refused by the gateway"
    );
}

/// Item 5 of rustfs/gateway#1076: a configuration written through the gateway path is stored as
/// the bytes legacy RustFS stores. For every configuration write both stacks hand over, the
/// gateway's persistence writer over its own decoded document and the legacy serializer RustFS
/// stores with over the legacy one produce the same bytes; and every configuration family is
/// written by at least one row.
#[test]
fn every_configuration_write_is_stored_as_the_bytes_legacy_rustfs_stores() {
    let mut problems = Vec::new();
    let mut written: BTreeSet<&str> = BTreeSet::new();
    for outcome in outcomes() {
        let diff = &outcome.diff;
        let Some(operation) = diff.routed.gateway.as_deref() else { continue };
        if !STORED_OPERATIONS.contains(&operation) || !both_handed(diff) {
            continue;
        }
        match (&diff.stored.gateway, &diff.stored.s3s) {
            (Some(Ok(gateway)), Some(Ok(legacy))) if gateway == legacy => {
                written.insert(
                    STORED_OPERATIONS
                        .iter()
                        .find(|name| **name == operation)
                        .copied()
                        .unwrap_or_default(),
                );
            }
            (None, None) => {}
            (gateway, legacy) => problems.push(format!(
                "{}: {operation} stores {} through the gateway and {} on the legacy stack",
                outcome.name,
                describe(gateway.as_ref()),
                describe(legacy.as_ref())
            )),
        }
    }
    let unwritten: Vec<&&str> = STORED_OPERATIONS
        .iter()
        .filter(|operation| !written.contains(**operation))
        .collect();
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(unwritten.is_empty(), "no row stores a configuration through {unwritten:?}");
}

fn describe(stored: Option<&Result<Vec<u8>, String>>) -> String {
    match stored {
        None => "nothing".to_owned(),
        Some(Err(error)) => format!("a refusal ({error})"),
        Some(Ok(bytes)) => format!("{:?}", String::from_utf8_lossy(bytes)),
    }
}

/// Chained calls of an assembly that the seam diff replaces by design: its own recording backend
/// and authenticator, an allow-all authorizer, a fixture owner, unlimited framework rates, no CORS,
/// none of the reference backend's own operation layers (its bucket-name registry), and the final
/// build. Every other call of the RustFS profile's builder chain is a switch.
const ASSEMBLY_CALLS: [&str; 10] = [
    "authenticator",
    "authorizer",
    "security_floor",
    "framework_governor_rates",
    "bucket_owner_source",
    "cors_source",
    "cors_cache",
    "register_cors",
    "op_layer",
    "build",
];

/// The name of every chained call in `text`: each line that starts with `.name`.
fn chained_calls(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|line| line.trim_start().strip_prefix('.'))
        .map(|call| {
            call.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .next()
                .unwrap_or_default()
        })
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Every switch a builder chain in `text` turns on: each chained call of the chain that starts at
/// `ServiceBuilder::new()` and ends at its `.build()` (the whole text when it holds no such chain),
/// the assembly calls the seam diff replaces by design left out. Switches nested in the chain (the
/// authenticator's, the security floor's) are read with it.
fn profile_switches(text: &str) -> BTreeSet<String> {
    let chain = text.find("ServiceBuilder::new()").map_or(text, |start| {
        let rest = &text[start..];
        let end = rest
            .match_indices('\n')
            .map(|(at, _)| at + 1)
            .find(|&at| rest[at..].trim_start().starts_with(".build()"))
            .map_or(rest.len(), |at| at + rest[at..].find('\n').unwrap_or(rest.len() - at));
        &rest[..end]
    });
    chained_calls(chain)
        .into_iter()
        .filter(|name| !ASSEMBLY_CALLS.contains(&name.as_str()))
        .collect()
}

/// The seam diff measures what RustFS will be handed, so its gateway runs every request-handling
/// switch of the RustFS profile, which is spelled once, in `compat/sut`: a switch added there and
/// not here fails, instead of the diff silently measuring another profile.
#[test]
fn the_seam_diff_runs_every_switch_of_the_rustfs_profile() {
    let read = |path: &str| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    };
    let profile = profile_switches(&read("../../compat/sut/src/service.rs"));
    assert!(profile.len() >= 12, "the RustFS profile's switches were not found: {profile:?}");
    // The whole seam stack: its authenticator is built before its builder chain.
    let seam = chained_calls(&read("src/seam/stacks.rs"));
    let missing: Vec<&String> = profile.difference(&seam).collect();
    assert!(missing.is_empty(), "RustFS profile switches the seam diff does not turn on: {missing:?}");
}

/// Negative — the switch reading names a missing switch.
#[test]
fn n_a_switch_the_profile_turns_on_and_the_seam_does_not_is_named() {
    let profile = profile_switches(
        "    ServiceBuilder::new()\n        .accept_all_checksum_omissions()\n        .slash_policy(SlashPolicy::RustfsLegacy)\n        .authorizer(A)\n        .build()",
    );
    assert_eq!(profile.into_iter().collect::<Vec<_>>(), ["accept_all_checksum_omissions", "slash_policy"]);
    let seam = profile_switches("        .accept_all_checksum_omissions()\n");
    assert_eq!(profile_switches("        .slash_policy(x)").difference(&seam).count(), 1);
}

/// Negative — a switch is read whatever its name says, the authenticator's and the floor's nested
/// in the chain included; what follows the chain's build, and the assembly the seam diff replaces,
/// are not switches.
#[test]
fn n_every_call_of_the_profile_chain_but_the_assembly_is_a_switch() {
    let profile = profile_switches(
        "fn options() -> O {\n    O::new()\n        .with_region(r)\n}\n    ServiceBuilder::new()\n        .authenticator(\n            A::new()\n                .verify_raw_paths_only_with_unencoded_bytes(),\n        )\n        .security_floor(F::new().with_presigned_expiry_rule(R))\n        .url_encode_listings_like_rustfs()\n        .legacy_rustfs_post_forms()\n        .register_cors(x)\n        .build()?;\n    later()\n        .not_a_switch()\n",
    );
    assert_eq!(
        profile.into_iter().collect::<Vec<_>>(),
        [
            "legacy_rustfs_post_forms",
            "url_encode_listings_like_rustfs",
            "verify_raw_paths_only_with_unencoded_bytes"
        ]
    );
}
