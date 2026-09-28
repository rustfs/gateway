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

//! Negative controls: the gateway side broken on purpose, and each break reported as exactly the
//! finding it is.
//!
//! Responsible for: a-df-0009 (a misroute is a route finding, ranked first), a-df-0010 (one body
//! byte too many is a rest-body finding), a-df-0003 (the four compared items, a member named by
//! its path), one skewed member per agreed member path, and the finding rules for refusals — each
//! in both directions, so a comparison stuck on one answer fails.
//! NOT responsible for: the request matrix (`samples/requests.rs`).
//! Upstream: the library's faults. Downstream: none.

use crate::decode::Fault;
use crate::decode::{BodyDigest, Cmp, DecodeDiff, S3ErrorView};
use crate::{Differ, FieldValue, Item, KnownDiffs, Priority, RawRequest};

fn differ(fault: Fault) -> Differ {
    Differ::with_fault(fault).expect("both stacks build")
}

/// Negative (a-df-0009) — a host resolver that reads every object path as a bucket path makes the
/// real route table pick ListObjects for a GetObject request; the diff reports it as a route
/// finding, first, and the register does not accept it.
#[test]
fn a_misrouting_gateway_is_a_route_finding_ranked_first() {
    let diff = differ(Fault::GatewayMisroutesObjects)
        .diff(&RawRequest::get("/bkt/k").header("range", "bytes=0-1"))
        .expect("the harness runs");
    let findings = diff.findings();
    assert_eq!(findings[0].item, Item::Route, "{findings:#?}");
    assert_eq!(findings[0].priority, Priority::Route);
    assert_eq!(findings[0].gateway, "ListObjects");
    assert_eq!(findings[0].s3s, "GetObject");
    assert!(findings[1..].iter().all(|finding| finding.priority > Priority::Route));
    let verdict = KnownDiffs::checked_in().expect("parses").verdict(findings);
    assert!(!verdict.passed());
}

/// Positive, the other direction — the same request through an unbroken gateway has no route
/// finding, so the control above is not an observer stuck on "different".
#[test]
fn an_unbroken_gateway_routes_the_same_request_as_s3s() {
    let diff = differ(Fault::None)
        .diff(&RawRequest::get("/bkt/k").header("range", "bytes=0-1"))
        .expect("the harness runs");
    assert_eq!(diff.operation.gateway.as_deref(), Some("GetObject"));
    assert!(diff.operation.same());
    assert!(diff.findings().is_empty(), "{:#?}", diff.findings());
}

/// Negative — the misrouting fault is specific: a bucket request, which it does not touch, still
/// routes the same on both stacks. A fault that broke everything would prove nothing.
#[test]
fn the_misrouting_fault_leaves_a_bucket_request_alone() {
    let diff = differ(Fault::GatewayMisroutesObjects)
        .diff(&RawRequest::get("/bkt?location"))
        .expect("the harness runs");
    assert!(diff.operation.same(), "{:?}", diff.operation);
    assert!(diff.findings().iter().all(|finding| finding.item != Item::Route));
}

/// Negative (a-df-0010) — a decoder that takes one body byte more than its framing said leaves the
/// handler a different body; the rest-body digest names it, and nothing else differs.
#[test]
fn a_decoder_that_eats_one_byte_is_a_rest_body_finding() {
    for request in [
        RawRequest::put("/bkt/k", b"hello"),
        RawRequest::put("/bkt/k?partNumber=1&uploadId=u", b"hello"),
        RawRequest::put("/bkt/k", b"hello").body_pieces(&[b"he", b"llo"]),
    ] {
        let diff = differ(Fault::GatewayDecoderEatsOneByte)
            .diff(&request)
            .expect("the harness runs");
        let findings = diff.findings();
        assert_eq!(findings.len(), 1, "{request:?}: {findings:#?}");
        assert_eq!(findings[0].item, Item::RestBody);
        assert!(findings[0].gateway.starts_with("4 bytes"), "{}", findings[0].gateway);
        assert!(findings[0].s3s.starts_with("5 bytes"), "{}", findings[0].s3s);
        assert!(!KnownDiffs::checked_in().expect("parses").verdict(findings).passed());
    }
}

/// Positive, the other direction — with nothing to eat (no body, or an empty one) the same fault
/// changes nothing, so the finding above comes from the byte and not from the fault's presence.
#[test]
fn the_eating_fault_without_a_byte_to_eat_changes_nothing() {
    for request in [RawRequest::get("/bkt/k"), RawRequest::put("/bkt/k", b"")] {
        let diff = differ(Fault::GatewayDecoderEatsOneByte)
            .diff(&request)
            .expect("the harness runs");
        assert!(diff.findings().is_empty(), "{request:?}: {:#?}", diff.findings());
    }
}

/// Positive (a-df-0003) — a decode diff carries the four compared items, and an input difference
/// is named by its field path, not as "the inputs differ".
#[test]
fn a_decode_diff_carries_the_four_items_and_names_a_member_by_path() {
    let member = differ(Fault::None)
        .diff(
            &RawRequest::get("/bkt/k")
                .header("if-range", "\"abc\"")
                .header("range", "bytes=0-1"),
        )
        .expect("the harness runs");
    assert_eq!(
        member.operation,
        Cmp {
            gateway: Some("GetObject".to_owned()),
            s3s: Some("GetObject".to_owned())
        }
    );
    assert_eq!(
        member.error,
        Cmp {
            gateway: None,
            s3s: None
        }
    );
    assert_eq!(member.input.len(), 1);
    assert_eq!(member.input[0].path, "GetObjectInput.if_range");
    assert_eq!(member.input[0].gateway, FieldValue::Present("\"abc\"".to_owned()));
    assert_eq!(member.input[0].s3s, FieldValue::NoMember);
    assert!(member.members.len() > 20);

    let body = differ(Fault::None)
        .diff(&RawRequest::put("/bkt/k", b"hello"))
        .expect("the harness runs");
    let digest = body.rest_body.gateway.clone().expect("the gateway handler read a body");
    assert_eq!(digest.len, 5);
    assert_eq!(digest.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    assert!(body.rest_body.same());

    let refused = differ(Fault::None)
        .diff(&RawRequest::get("/bkt/k?partNumber=abc"))
        .expect("the harness runs");
    let (gateway, s3s) = (refused.error.gateway.expect("refused"), refused.error.s3s.expect("refused"));
    assert_eq!((gateway.status, gateway.code.as_deref()), (400, Some("InvalidArgument")));
    assert_eq!((s3s.status, s3s.code.as_deref()), (400, Some("InvalidArgument")));
    assert_ne!(gateway.message, s3s.message);
}

/// Negative — one member decoded wrongly on the gateway side is reported as exactly that member's
/// path, for every member path any row sets and agrees on. This holds the comparison and its
/// path reporting; whether each projection reads the right member is held by the matrix (both
/// stacks must agree on a value the row set) and the census.
#[test]
fn every_agreed_member_skewed_on_the_gateway_is_named_by_its_path_alone() {
    let mut problems = Vec::new();
    let mut skewed = 0_usize;
    let mut seen = std::collections::BTreeSet::new();
    let clean = Differ::new().expect("both stacks build");
    for row in crate::samples::requests() {
        let diff = clean.diff(&row.request).expect("the harness runs");
        let Some(operation) = diff.operation.gateway.clone() else {
            continue;
        };
        let prefix = format!("{operation}Input.");
        for member in &diff.members {
            let agreed = matches!(member.gateway, FieldValue::Present(_)) && member.gateway == member.s3s;
            if !agreed || !seen.insert(member.path.clone()) {
                continue;
            }
            let relative = member
                .path
                .strip_prefix(&prefix)
                .expect("every path names its input")
                .to_owned();
            let broken = differ(Fault::GatewayMemberSkewed(relative))
                .diff(&row.request)
                .expect("the harness runs");
            let named: Vec<String> = broken
                .findings()
                .into_iter()
                .filter_map(|finding| match finding.item {
                    Item::Member(path) => Some(path),
                    _ => None,
                })
                .filter(|path| !diff.input.iter().any(|known| known.path == *path))
                .collect();
            if named != [member.path.clone()] {
                problems.push(format!("{}: skewing {} reported {named:?}", row.name, member.path));
            }
            skewed += 1;
        }
    }
    assert!(skewed > 300, "only {skewed} member paths were skewed");
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

fn refusal(status: u16, code: &str) -> Option<S3ErrorView> {
    Some(S3ErrorView {
        status,
        code: Some(code.to_owned()),
        message: None,
    })
}

fn constructed(
    gateway_op: Option<&str>,
    s3s_op: Option<&str>,
    gateway: Option<S3ErrorView>,
    s3s: Option<S3ErrorView>,
) -> DecodeDiff {
    DecodeDiff {
        operation: Cmp {
            gateway: gateway_op.map(str::to_owned),
            s3s: s3s_op.map(str::to_owned),
        },
        error: Cmp { gateway, s3s },
        input: Vec::new(),
        rest_body: Cmp {
            gateway: None,
            s3s: None,
        },
        members: Vec::new(),
        handed: Cmp {
            gateway: Vec::new(),
            s3s: Vec::new(),
        },
    }
}

fn items(diff: &DecodeDiff) -> Vec<Item> {
    diff.findings().into_iter().map(|finding| finding.item).collect()
}

/// Positive — both stacks refusing a bad bucket name with the same status and code, one of them
/// before it names an operation, is a refusal reached at different stages, not a route mismatch.
#[test]
fn the_same_refusal_before_one_stack_names_the_operation_is_not_a_route_finding() {
    let diff = constructed(
        Some("GetObject"),
        None,
        refusal(400, "InvalidBucketName"),
        refusal(400, "InvalidBucketName"),
    );
    assert_eq!(items(&diff), Vec::<Item>::new());
}

/// Negative — the same unnamed side with a different refusal code is a route finding again.
#[test]
fn a_different_refusal_from_a_stack_that_named_no_operation_is_a_route_finding() {
    let diff = constructed(Some("GetObject"), None, refusal(400, "InvalidBucketName"), refusal(400, "InvalidRequest"));
    assert_eq!(items(&diff), vec![Item::Route, Item::Code]);
}

/// Negative — a stack that named no operation while the other reached its handler is a route
/// finding and an outcome finding.
#[test]
fn an_unnamed_refusal_against_a_handled_request_is_a_route_finding() {
    let diff = constructed(Some("GetObject"), None, None, refusal(400, "InvalidBucketName"));
    assert_eq!(items(&diff), vec![Item::Route, Item::Outcome]);
}

/// Negative — two named, different operations are a route finding even when both refused alike.
#[test]
fn two_named_operations_are_a_route_finding_even_when_both_refused_alike() {
    let diff = constructed(
        Some("GetObject"),
        Some("ListObjects"),
        refusal(400, "InvalidArgument"),
        refusal(400, "InvalidArgument"),
    );
    assert_eq!(items(&diff), vec![Item::Route]);
}

/// Negative — a status difference between two refusals is its own finding.
#[test]
fn a_status_difference_between_refusals_is_a_status_finding() {
    let diff = constructed(
        Some("PutObject"),
        Some("PutObject"),
        refusal(411, "InvalidArgument"),
        refusal(400, "InvalidArgument"),
    );
    assert_eq!(items(&diff), vec![Item::Status]);
}

/// Positive — a body is compared only when both handlers were handed one; when one side refused,
/// the outcome finding says so and a second, body finding would only repeat it.
#[test]
fn the_rest_body_is_compared_only_when_both_handlers_ran() {
    let mut diff = constructed(Some("PutObject"), Some("PutObject"), refusal(411, "MissingContentLength"), None);
    diff.rest_body.s3s = Some(BodyDigest {
        len: 3,
        sha256: "x".to_owned(),
        failed: false,
    });
    assert_eq!(items(&diff), vec![Item::Outcome]);
    let mut both = constructed(Some("PutObject"), Some("PutObject"), None, None);
    both.rest_body.s3s = Some(BodyDigest {
        len: 3,
        sha256: "x".to_owned(),
        failed: false,
    });
    assert_eq!(items(&both), vec![Item::RestBody]);
}

/// Negative — a message difference no entry registers fails; the same difference registered is
/// information and passes. The default is failure, never tolerance.
#[test]
fn an_unregistered_message_difference_fails_and_a_registered_one_is_information() {
    let diff = differ(Fault::None)
        .diff(&RawRequest::get("/bkt/k?partNumber=abc"))
        .expect("the harness runs");
    let findings = diff.findings();
    assert_eq!(findings.len(), 1);
    assert_eq!((findings[0].item.clone(), findings[0].priority), (Item::Message, Priority::Info));
    let empty = KnownDiffs::default().verdict(findings.clone());
    assert!(!empty.passed());
    assert_eq!(empty.info().count(), 0);
    let registered = KnownDiffs::checked_in().expect("parses").verdict(findings);
    assert!(registered.passed());
    assert_eq!(registered.info().map(|(_, id)| id.as_str()).collect::<Vec<_>>(), ["kd-decode-0023"]);
}

/// Negative — findings are ordered route, then failures, then wording, whatever order they are
/// found in: a report read top-down starts with what invalidates the rest.
#[test]
fn findings_are_ordered_route_then_failures_then_wording() {
    let mut diff = constructed(
        Some("GetObject"),
        Some("ListObjects"),
        Some(S3ErrorView {
            status: 400,
            code: Some("InvalidArgument".to_owned()),
            message: Some("a".to_owned()),
        }),
        Some(S3ErrorView {
            status: 404,
            code: Some("NoSuchKey".to_owned()),
            message: Some("b".to_owned()),
        }),
    );
    diff.input.push(crate::FieldDiff {
        path: "GetObjectInput.range".to_owned(),
        gateway: FieldValue::Absent,
        s3s: FieldValue::Present("x".to_owned()),
    });
    let priorities: Vec<Priority> = diff.findings().iter().map(|finding| finding.priority).collect();
    assert_eq!(
        priorities,
        [
            Priority::Route,
            Priority::Fail,
            Priority::Fail,
            Priority::Fail,
            Priority::Info
        ]
    );
    assert_eq!(diff.findings().last().map(|finding| finding.item.clone()), Some(Item::Message));
}

/// Negative — one pair of stacks answers any number of requests without refusing for load: a
/// harness the gateway throttles would report `503 SlowDown` as a decode difference after the
/// governor's default burst (256).
#[test]
fn the_harness_is_never_refused_for_load() {
    let differ = Differ::new().expect("both stacks build");
    let request = RawRequest::get("/bkt/k");
    for step in 0..600 {
        let diff = differ.diff(&request).expect("the harness runs");
        assert!(diff.error.gateway.is_none(), "step {step}: {:?}", diff.error.gateway);
    }
}
