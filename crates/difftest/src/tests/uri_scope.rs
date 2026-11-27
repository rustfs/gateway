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

//! URI scope regressions for the known-difference matcher.
//!
//! Responsible for: matching the request head seen by both stacks, including fragment boundaries.
//! NOT responsible for: adding accepted differences or changing either service's routing policy.
//! Upstream: RawRequest and the known-difference register. Downstream: the nightly decode property.

use crate::RawRequest;
use crate::decode::{Finding, Item, Priority};
use crate::known::{Kind, KnownDiffs};

fn scoped(scope: &str) -> KnownDiffs {
    KnownDiffs::parse(&format!(
        r#"[[diff]]
id = "kd-decode-9999"
kind = "decode"
operation = "GetObject"
item = "route"
gateway = "GetObject"
s3s = "Other"
reason = "test an exact request scope"
expires = "2026-12-31"
{scope}
"#
    ))
    .expect("the scoped register parses")
}

fn finding() -> Vec<Finding> {
    vec![Finding {
        kind: Kind::Decode,
        operation: "GetObject".to_owned(),
        priority: Priority::Fail,
        item: Item::Route,
        gateway: "GetObject".to_owned(),
        s3s: "Other".to_owned(),
    }]
}

#[test]
fn query_scope_uses_the_parsed_request_uri() {
    let register = scoped(r#"when_query = "events""#);
    for (target, expected) in [
        ("/bkt?events", true),
        ("/bkt?events#", true),
        ("/bkt?events#&other=x", true),
        ("/bkt?events=x#ignored", true),
        ("/bkt?other=x&events#ignored", true),
        ("/bkt", false),
        ("/bkt#?events", false),
        ("/bkt?other=x#&events", false),
        ("/bkt?prefix=events#", false),
        ("/bkt?events%23", false),
        ("/bkt?%65vents#", false),
        ("/bkt?Events#", false),
        ("/bkt?event#s", false),
        ("/b kt?events", false),
        ("/bkt?events\0", false),
    ] {
        assert_eq!(register.verdict_for(&RawRequest::get(target), finding()).passed(), expected, "{target:?}");
    }
}

#[test]
fn query_conjunction_does_not_read_selectors_from_a_fragment() {
    let register = scoped(r#"when_queries = ["uploads", "events"]"#);
    for (target, expected) in [
        ("/bkt?uploads&events#", true),
        ("/bkt?events=&uploads#ignored", true),
        ("/bkt?uploads&events=#ignored", true),
        ("/bkt?uploads#&events", false),
        ("/bkt?events#&uploads", false),
        ("/bkt#?uploads&events", false),
        ("/bkt?uploads&events%23", false),
        ("/bkt?%75ploads&events#", false),
        ("/bkt?uploads&prefix=events#", false),
        ("/bkt?events#", false),
        ("/b kt?uploads&events", false),
    ] {
        assert_eq!(register.verdict_for(&RawRequest::get(target), finding()).passed(), expected, "{target:?}");
    }
}

#[test]
fn bucket_scope_uses_the_parsed_path_without_decoding_it() {
    let register = scoped(r#"when_bucket = "%2f""#);
    for (target, expected) in [
        ("/b%2Fkt/key#ignored", true),
        ("/b%2fkt#ignored", true),
        ("/b%2fkt?prefix=k#ignored", true),
        ("/bkt#%2F", false),
        ("/bkt#/%2F", false),
        ("/bkt?prefix=%2F", false),
        ("/bkt/k%2f", false),
        ("/b%252fkt", false),
        ("/b kt%2f/key", false),
        ("/bkt\0%2f", false),
    ] {
        assert_eq!(register.verdict_for(&RawRequest::get(target), finding()).passed(), expected, "{target:?}");
    }
}

#[test]
fn an_invalid_target_cannot_supply_a_header_scope() {
    let register = scoped(r#"when_header = "x-probe""#);
    for target in ["/b kt?events", "/bkt\0", "http://[::1"] {
        let request = RawRequest::get(target).header("x-probe", "present");
        assert!(!register.verdict_for(&request, finding()).passed(), "{target:?}");
    }
}

#[test]
fn fragment_events_artifacts_keep_the_decode_property() {
    for input in [
        &include_bytes!("../../../../fuzz/seeds/decode_diff/events-fragment-original")[..],
        &include_bytes!("../../../../fuzz/seeds/decode_diff/events-fragment-minimal")[..],
    ] {
        crate::fuzz::request_of(input).expect("the artifact remains in the compared request domain");
        assert_eq!(crate::fuzz::check_decode(input), Ok(()), "{}", String::from_utf8_lossy(input));
    }
}

/// Positive — both nightly artifacts remain compared requests with their exact route difference.
#[test]
fn attributes_upload_id_artifacts_keep_the_decode_property() {
    for input in [
        &include_bytes!("../../../../fuzz/seeds/decode_diff/attributes-upload-id-original")[..],
        &include_bytes!("../../../../fuzz/seeds/decode_diff/attributes-upload-id-minimal")[..],
    ] {
        crate::fuzz::request_of(input).expect("the artifact remains in the compared request domain");
        assert_eq!(crate::fuzz::check_decode(input), Ok(()), "{}", String::from_utf8_lossy(input));
    }
}

fn attributes_upload_id_route() -> Finding {
    Finding {
        kind: Kind::Decode,
        operation: "ListParts".to_owned(),
        priority: Priority::Route,
        item: Item::Route,
        gateway: "ListParts".to_owned(),
        s3s: "GetObjectAttributes".to_owned(),
    }
}

/// Negative — neither selector alone, an encoded lookalike, nor a fragment can scope the finding.
#[test]
fn attributes_upload_id_requires_both_selectors() {
    let register = KnownDiffs::checked_in().expect("the register parses");
    for target in [
        "/bkt/k",
        "/bkt/k?uploadId=u",
        "/bkt/k?attributes",
        "/bkt/k?uploadId=u#&attributes",
        "/bkt/k?attributes#&uploadId=u",
        "/bkt/k?%75ploadId=u&attributes",
        "/bkt/k?uploadId=u&%61ttributes",
        "/bkt/k?UploadId=u&attributes",
        "/bkt/k?uploadId=u&Attributes",
        "/bkt/k?uploadId=u&prefix=attributes",
    ] {
        assert!(
            !register
                .verdict_for(&RawRequest::get(target), vec![attributes_upload_id_route()])
                .passed(),
            "{target}"
        );
    }
}

/// Negative — the conjunction accepts neither another operation pair nor a different item.
#[test]
fn attributes_upload_id_rejects_other_route_findings() {
    let register = KnownDiffs::checked_in().expect("the register parses");
    let request = RawRequest::get("/bkt/k?uploadId=u&attributes");
    let mut findings = Vec::new();
    let mut other = attributes_upload_id_route();
    other.operation = "GetObject".to_owned();
    findings.push(other);
    let mut other = attributes_upload_id_route();
    other.gateway = "GetObject".to_owned();
    findings.push(other);
    let mut other = attributes_upload_id_route();
    other.s3s = "GetObject".to_owned();
    findings.push(other);
    let mut other = attributes_upload_id_route();
    other.item = Item::Outcome;
    findings.push(other);
    for finding in findings {
        assert!(!register.verdict_for(&request, vec![finding.clone()]).passed(), "{finding:?}");
    }
}

fn attributes_upload_id_failure(item: Item, gateway: &str, s3s: &str) -> Finding {
    Finding {
        item,
        priority: Priority::Fail,
        gateway: gateway.to_owned(),
        s3s: s3s.to_owned(),
        ..attributes_upload_id_route()
    }
}

/// A bare uploadId decodes as an empty claim; both observed differences have exact records.
#[test]
fn attributes_upload_id_accepts_only_the_recorded_empty_claim_differences() {
    let register = KnownDiffs::checked_in().expect("the register parses");
    let request = RawRequest::get("/bkt/k?uploadId&attributes");
    let diff = crate::decode_diff(&request).expect("both stacks run");
    let verdict = register.verdict_for(&request, diff.findings());
    assert!(verdict.passed(), "{verdict:?}");
    assert_eq!(
        verdict.known,
        [
            (attributes_upload_id_route(), "kd-decode-0110".to_owned()),
            (
                attributes_upload_id_failure(
                    Item::Outcome,
                    "handled",
                    "400 InvalidRequest: missing header: x-amz-object-attributes"
                ),
                "kd-decode-0111".to_owned(),
            ),
        ],
    );
}

/// Missing scope and unregistered decode differences must still fail.
#[test]
fn attributes_upload_id_does_not_accept_unscoped_or_malformed_outcomes() {
    let register = KnownDiffs::checked_in().expect("the register parses");
    assert!(!register.verdict(vec![attributes_upload_id_route()]).passed());

    let request = RawRequest::get("/bkt/k?uploadId&attributes").header("x-amz-object-attributes", "ETag");
    let diff = crate::decode_diff(&request).expect("both stacks run");
    let verdict = register.verdict_for(&request, diff.findings());
    assert_eq!(
        verdict.failures,
        [attributes_upload_id_failure(
            Item::Outcome,
            "handled",
            "501 NotImplemented: GetObjectAttributes is not implemented yet",
        )],
    );

    let request = RawRequest::get("/bkt/k?uploadId&attributes&max-parts=not-a-number").header("x-amz-object-attributes", "ETag");
    let diff = crate::decode_diff(&request).expect("both stacks run");
    let verdict = register.verdict_for(&request, diff.findings());
    assert_eq!(
        verdict.failures,
        [
            attributes_upload_id_failure(Item::Status, "400", "501"),
            attributes_upload_id_failure(Item::Code, "InvalidArgument", "NotImplemented"),
        ],
    );
}

fn multipart_selector_overlap_finding() -> Finding {
    Finding {
        kind: Kind::Decode,
        operation: "CompleteMultipartUpload".to_owned(),
        priority: Priority::Route,
        item: Item::Route,
        gateway: "CompleteMultipartUpload".to_owned(),
        s3s: "CreateMultipartUpload".to_owned(),
    }
}

/// Negative — both literal query names must occur in the parsed request, never in a value or fragment.
#[test]
fn multipart_selector_overlap_rejects_missing_or_disguised_selectors() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    for target in [
        "/bkt/k",
        "/bkt/k?uploads",
        "/bkt/k?uploadId=u",
        "/bkt/k?uploads&prefix=uploadId",
        "/bkt/k?uploadId=u&prefix=uploads",
        "/bkt/k?Uploads&uploadId=u",
        "/bkt/k?uploads&uploadid=u",
        "/bkt/k?%75ploads&uploadId=u",
        "/bkt/k?uploads&%75ploadId=u",
        "/bkt/k?uploads#&uploadId=u",
        "/bkt/k?uploadId=u#&uploads",
    ] {
        let verdict = register.verdict_for(&RawRequest::post(target, b""), vec![multipart_selector_overlap_finding()]);
        assert!(!verdict.passed(), "{target}");
    }
}

/// Negative — missing request context and changes to either operation pin remain unregistered.
#[test]
fn multipart_selector_overlap_rejects_other_findings() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    assert!(!register.verdict(vec![multipart_selector_overlap_finding()]).passed());
    let mut operation = multipart_selector_overlap_finding();
    operation.operation = "RestoreObject".to_owned();
    let mut gateway = multipart_selector_overlap_finding();
    gateway.gateway = "RestoreObject".to_owned();
    let mut legacy = multipart_selector_overlap_finding();
    legacy.s3s = "RestoreObject".to_owned();
    let mut outcome = multipart_selector_overlap_finding();
    outcome.item = Item::Outcome;
    for finding in [operation, gateway, legacy, outcome] {
        let verdict = register.verdict_for(&RawRequest::post("/bkt/k?uploads&uploadId=u", b""), vec![finding]);
        assert!(!verdict.passed(), "the registration must not accept a different finding");
    }
}

fn upload_part_acl_overlap_route() -> Finding {
    Finding {
        kind: Kind::Decode,
        operation: "UploadPart".to_owned(),
        priority: Priority::Route,
        item: Item::Route,
        gateway: "UploadPart".to_owned(),
        s3s: "PutObjectAcl".to_owned(),
    }
}

fn upload_part_acl_overlap_outcome() -> Finding {
    Finding {
        kind: Kind::Decode,
        operation: "UploadPart".to_owned(),
        priority: Priority::Fail,
        item: Item::Outcome,
        gateway: "handled".to_owned(),
        s3s: "501 NotImplemented: PutObjectAcl is not implemented yet".to_owned(),
    }
}

/// Positive — a valid part-upload PUT carrying `acl` matches exactly kd-decode-0116 and kd-decode-0117.
#[test]
fn upload_part_acl_overlap_accepts_only_recorded_route_and_outcome() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    let request = RawRequest::put("/bkt/k?partNumber=1&uploadId=u&acl", b"");
    let diff = crate::decode_diff(&request).expect("both stacks run");
    let verdict = register.verdict_for(&request, diff.findings());
    assert!(verdict.passed(), "{verdict:?}");
    assert_eq!(
        verdict.known,
        [
            (upload_part_acl_overlap_route(), "kd-decode-0116".to_owned()),
            (upload_part_acl_overlap_outcome(), "kd-decode-0117".to_owned()),
        ],
    );
}

/// Negative — all three literal query names must occur in the parsed request, never in a value,
/// wrong case, percent-encoded lookalike, or fragment, for both route and outcome entries.
#[test]
fn upload_part_acl_overlap_rejects_missing_or_disguised_selectors() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    for finding in [upload_part_acl_overlap_route(), upload_part_acl_overlap_outcome()] {
        for target in [
            "/bkt/k",
            "/bkt/k?partNumber=1&uploadId=u",
            "/bkt/k?partNumber=1&acl",
            "/bkt/k?uploadId=u&acl",
            "/bkt/k?partNumber=1&uploadId=u&prefix=acl",
            "/bkt/k?partNumber=1&acl&prefix=uploadId",
            "/bkt/k?uploadId=u&acl&prefix=partNumber",
            "/bkt/k?PartNumber=1&uploadId=u&acl",
            "/bkt/k?partNumber=1&UploadId=u&acl",
            "/bkt/k?partNumber=1&uploadId=u&Acl",
            "/bkt/k?%70artNumber=1&uploadId=u&acl",
            "/bkt/k?partNumber=1&%75ploadId=u&acl",
            "/bkt/k?partNumber=1&uploadId=u&%61cl",
            "/bkt/k?partNumber=1&uploadId=u#&acl",
            "/bkt/k?partNumber=1&acl#&uploadId=u",
            "/bkt/k?uploadId=u&acl#&partNumber=1",
        ] {
            let verdict = register.verdict_for(&RawRequest::put(target, b""), vec![finding.clone()]);
            assert!(!verdict.passed(), "{target}/{finding:?}");
        }
    }
}

/// Negative — missing request context, swapped or altered pins, and malformed-input decode
/// differences remain unregistered even when all three query parameters are present.
#[test]
fn upload_part_acl_overlap_rejects_other_findings() {
    let register = KnownDiffs::checked_in().expect("the checked-in register parses");
    assert!(!register.verdict(vec![upload_part_acl_overlap_route()]).passed());
    assert!(!register.verdict(vec![upload_part_acl_overlap_outcome()]).passed());

    let mut operation = upload_part_acl_overlap_route();
    operation.operation = "PutObject".to_owned();
    let mut gateway = upload_part_acl_overlap_route();
    gateway.gateway = "PutObject".to_owned();
    let mut legacy = upload_part_acl_overlap_route();
    legacy.s3s = "PutObject".to_owned();
    let mut swapped = upload_part_acl_overlap_route();
    swapped.gateway = "PutObjectAcl".to_owned();
    swapped.s3s = "UploadPart".to_owned();
    let mut status = upload_part_acl_overlap_route();
    status.item = Item::Status;
    let mut bad_outcome = upload_part_acl_overlap_outcome();
    bad_outcome.s3s = "500 InternalError: unexpected".to_owned();
    let request = RawRequest::put("/bkt/k?partNumber=1&uploadId=u&acl", b"");
    for finding in [operation, gateway, legacy, swapped, status, bad_outcome] {
        let verdict = register.verdict_for(&request, vec![finding.clone()]);
        assert!(!verdict.passed(), "must not accept unrelated finding: {finding:?}");
    }

    // Malformed partNumber and malformed XML body must still fail closed on their outcome/refusal diffs.
    let bad_part = RawRequest::put("/bkt/k?partNumber=0&uploadId=u&acl", b"");
    let bad_part_verdict = register.verdict_for(&bad_part, crate::decode_diff(&bad_part).expect("both stacks run").findings());
    assert!(
        !bad_part_verdict.passed(),
        "malformed partNumber refusal must stay unregistered: {bad_part_verdict:?}"
    );

    let bad_xml = RawRequest::put("/bkt/k?partNumber=1&uploadId=u&acl", b"x");
    let bad_xml_verdict = register.verdict_for(&bad_xml, crate::decode_diff(&bad_xml).expect("both stacks run").findings());
    assert!(
        !bad_xml_verdict.passed(),
        "malformed ACL XML refusal must stay unregistered: {bad_xml_verdict:?}"
    );
}

/// Negative — non-PUT methods with the same three query keys never produce the registered
/// UploadPart/PutObjectAcl overlap.
#[test]
fn upload_part_acl_overlap_other_methods_do_not_match_put_route_overlap() {
    for method in [http::Method::GET, http::Method::POST, http::Method::DELETE] {
        let request = RawRequest::new(method.clone(), "/bkt/k?partNumber=1&uploadId=u&acl");
        let diff = crate::decode_diff(&request).expect("both stacks run");
        assert!(
            !(diff.operation.gateway.as_deref() == Some("UploadPart") && diff.operation.s3s.as_deref() == Some("PutObjectAcl")),
            "{method} unexpectedly produced UploadPart vs PutObjectAcl: {:?}",
            diff.operation
        );
    }
}
