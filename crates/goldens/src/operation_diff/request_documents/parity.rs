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

//! The RustFS profile's document reading against the legacy stack, over every perturbation of a
//! baseline of every request document (rustfs/gateway#1078).
//!
//! Responsible for: the proof that, read with `DocumentReading::RustFs`, every document legacy
//! RustFS refuses is refused with its code and every document it accepts is handed to the RustFS
//! body exactly as legacy RustFS hands it — except the registered divergences, each named with its
//! reason, each of which must still occur.
//! NOT responsible for: the tree reading, which other deployments use and which keeps its own
//! behaviour and cases.
//! Upstream: the parent harness, `samples`, `perturb`. Downstream: nothing.

use rustfs_gateway_core::DocumentReading;

use super::perturb::perturbations;
use super::samples::samples;
use super::{Handed, Op, gateway, legacy};

/// One case both stacks were sent.
#[derive(Debug)]
struct Case {
    op: Op,
    sample: &'static str,
    variant: String,
    document: String,
    gateway: Handed,
    legacy: Handed,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (op, sample, baseline) in samples() {
        for (variant, document) in perturbations(&baseline) {
            let gateway = gateway(op, DocumentReading::RustFs, document.as_bytes());
            let legacy = legacy(op, document.as_bytes());
            cases.push(Case {
                op,
                sample,
                variant,
                document,
                gateway,
                legacy,
            });
        }
    }
    cases
}

/// Positive — every baseline is accepted, and handed over alike, by both stacks.
#[test]
fn every_baseline_is_handed_over_alike() {
    for (op, sample, baseline) in samples() {
        let legacy = legacy(op, baseline.as_bytes());
        assert!(legacy.is_ok(), "{op:?}/{sample}: the legacy stack refused its baseline: {legacy:?}");
        assert_eq!(gateway(op, DocumentReading::RustFs, baseline.as_bytes()), legacy, "{op:?}/{sample}");
    }
}

/// The last element a variant's label names, without its index: `Part` for
/// `removed CompleteMultipartUpload/Part[0]`.
fn member(case: &Case) -> &str {
    let path = case.variant.rsplit(' ').next().unwrap_or_default();
    let last = path.rsplit('/').next().unwrap_or_default();
    last.split('[').next().unwrap_or_default()
}

fn is(case: &Case, kind: &str) -> bool {
    case.variant.starts_with(&format!("{kind} "))
}

fn value_of(case: &Case, kinds: &[&str]) -> bool {
    kinds.iter().any(|kind| is(case, &format!("value {kind}")))
}

/// One registered divergence: the ruling id, the code the gateway answers for an operation, and the
/// perturbations it covers. Every one is a refusal where the legacy stack hands a document over.
struct Registered {
    id: &'static str,
    gateway: fn(Op) -> &'static str,
    covers: fn(&Case) -> bool,
}

const REGISTERED: &[Registered] = &[
    Registered {
        id: "rd-doc-0001",
        gateway: |_| "MalformedXML",
        covers: |case| case.variant == "document doctype",
    },
    Registered {
        id: "rd-doc-0002",
        gateway: |_| "MalformedXML",
        covers: |case| case.variant == "document control-character",
    },
    Registered {
        id: "rd-doc-0003",
        gateway: |_| "MalformedXML",
        covers: |case| {
            (is(case, "removed") && ["PartNumber", "Key", "Value"].contains(&member(case)))
                || (is(case, "emptied") && ["Part", "Tag"].contains(&member(case)))
        },
    },
    Registered {
        id: "rd-doc-0004",
        gateway: |_| "InvalidArgument",
        covers: |case| {
            (value_of(case, &["offset-date"]) && ["ExpiryUpdatedAt", "Date", "RetainUntilDate"].contains(&member(case)))
                || (member(case) == "ETag"
                    && value_of(case, &["empty", "cdata", "tag-with-quote", "leading-space", "trailing-space"]))
        },
    },
    Registered {
        id: "rd-doc-0005",
        gateway: |_| "InvalidArgument",
        covers: |case| {
            (is(case, "emptied") && ["AccessControlList", "TargetGrants", "RoutingRules", "UserMetadata"].contains(&member(case)))
                || ((is(case, "removed") || is(case, "prefixed"))
                    && ["Grant", "MetadataEntry", "RoutingRule"].contains(&member(case)))
        },
    },
    Registered {
        id: "rd-doc-0006",
        gateway: |op| {
            if op == Op::PutObjectLockConfiguration {
                "InvalidArgument"
            } else {
                "MalformedXML"
            }
        },
        covers: |case| {
            case.variant == "document empty-body" && [Op::PutObjectLockConfiguration, Op::RestoreObject].contains(&case.op)
        },
    },
    Registered {
        id: "rd-doc-0007",
        gateway: |_| "InvalidArgument",
        covers: |case| {
            is(case, "value")
                && member(case) == "Key"
                && (case.variant.contains("/Object[") || case.variant.contains("/ErrorDocument["))
        },
    },
    Registered {
        id: "rd-doc-0008",
        gateway: |_| "InvalidArgument",
        covers: |case| is(case, "value") && member(case) == "BucketName",
    },
];

/// Negative-majority — every perturbation answered alike, bar the registered divergences: each
/// difference falls in exactly one of them, with the gateway answering its code and the legacy
/// stack handing a document over, and each of them still happens.
#[test]
fn every_perturbation_is_answered_as_legacy_rustfs_answers_it() {
    let cases = cases();
    let mut unexplained = String::new();
    let mut unexplained_count = 0usize;
    let mut hits = vec![0usize; REGISTERED.len()];
    for case in cases.iter().filter(|case| case.gateway != case.legacy) {
        let matching: Vec<usize> = REGISTERED
            .iter()
            .enumerate()
            .filter(|(_, registered)| (registered.covers)(case))
            .map(|(index, _)| index)
            .collect();
        let explained = match matching.as_slice() {
            [index] => {
                let registered = &REGISTERED[*index];
                let pinned = case.gateway == Err((registered.gateway)(case.op).to_owned()) && case.legacy.is_ok();
                if pinned {
                    hits[*index] += 1;
                }
                pinned
            }
            _ => false,
        };
        if !explained {
            unexplained_count += 1;
            if unexplained_count <= 60 {
                unexplained.push_str(&format!(
                    "{:?}/{} {} (registered: {:?})\n  gateway {:?}\n  legacy  {:?}\n  document {:?}\n",
                    case.op,
                    case.sample,
                    case.variant,
                    matching.iter().map(|index| REGISTERED[*index].id).collect::<Vec<_>>(),
                    case.gateway
                        .as_ref()
                        .map(|handed| handed.chars().take(200).collect::<String>()),
                    case.legacy
                        .as_ref()
                        .map(|handed| handed.chars().take(200).collect::<String>()),
                    case.document.chars().take(300).collect::<String>(),
                ));
            }
        }
    }
    assert_eq!(
        unexplained_count,
        0,
        "{unexplained_count} of {} cases differ unexplained:\n{unexplained}",
        cases.len()
    );
    for (registered, hits) in REGISTERED.iter().zip(&hits) {
        assert!(*hits > 0, "{} no longer happens; its ruling is stale", registered.id);
    }
    // Coverage floors, measured at 9,408 cases of which 2,389 are legacy refusals: a battery that
    // stopped reaching refusals, or stopped agreeing, would pass the loop above vacuously.
    let agreed = cases.iter().filter(|case| case.gateway == case.legacy).count();
    let refused = cases.iter().filter(|case| case.legacy.is_err()).count();
    assert!(agreed >= 9_000, "only {agreed} of {} cases agree", cases.len());
    assert!(refused >= 2_000, "only {refused} of {} cases are legacy refusals", cases.len());
    assert!(
        cases.len() - refused >= 5_000,
        "only {} cases are legacy acceptances",
        cases.len() - refused
    );
}

/// Every operation that reads a request document has a baseline, so the battery reaches all of them.
#[test]
fn every_document_operation_has_a_baseline() {
    let covered: Vec<Op> = samples().into_iter().map(|(op, _, _)| op).collect();
    for op in Op::ALL {
        assert!(covered.contains(&op), "{op:?} has no baseline");
    }
}

/// An access control policy whose one grant names `grantee`.
fn acl(grantee: &str) -> String {
    format!(
        "<AccessControlPolicy><Owner><ID>o</ID></Owner><AccessControlList><Grant>{grantee}<Permission>READ</Permission></Grant>\
         </AccessControlList></AccessControlPolicy>"
    )
}

/// Negative — a grantee's type attribute is read as legacy RustFS reads it: by its literal
/// spelling `xsi:type`, and required. A grantee without it, or with the XML Schema instance
/// namespace bound to another prefix, is `MalformedXML` on both stacks, where the tree reading
/// resolved the other prefix and handed the grant over.
#[test]
fn n_a_grantee_without_the_literal_type_attribute_is_refused_as_legacy_rustfs_refuses_it() {
    for grantee in [
        "<Grantee><ID>g</ID></Grantee>",
        "<Grantee xmlns:x=\"http://www.w3.org/2001/XMLSchema-instance\" x:type=\"CanonicalUser\"><ID>g</ID></Grantee>",
    ] {
        let body = acl(grantee);
        for op in [Op::PutBucketAcl, Op::PutObjectAcl] {
            assert_eq!(legacy(op, body.as_bytes()), Err("MalformedXML".to_owned()), "{op:?} {grantee}");
            assert_eq!(
                gateway(op, DocumentReading::RustFs, body.as_bytes()),
                legacy(op, body.as_bytes()),
                "{op:?} {grantee}"
            );
        }
    }
    let other_prefix =
        acl("<Grantee xmlns:x=\"http://www.w3.org/2001/XMLSchema-instance\" x:type=\"CanonicalUser\"><ID>g</ID></Grantee>");
    assert!(gateway(Op::PutBucketAcl, DocumentReading::Tree, other_prefix.as_bytes()).is_ok());
}

/// Positive — a type attribute legacy RustFS reads is handed over as it hands it over: any value,
/// `Foo` included (legacy RustFS's handler then answers the document itself), and the literal
/// `xsi:type` even where no declaration binds the prefix.
#[test]
fn a_grantee_type_legacy_rustfs_reads_is_handed_over_as_it_hands_it_over() {
    for grantee in [
        "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Foo\"><ID>g</ID></Grantee>",
        "<Grantee xsi:type=\"CanonicalUser\"><ID>g</ID></Grantee>",
    ] {
        let body = acl(grantee);
        for op in [Op::PutBucketAcl, Op::PutObjectAcl] {
            let handed = legacy(op, body.as_bytes());
            assert!(handed.is_ok(), "{op:?} {grantee}: {handed:?}");
            assert_eq!(gateway(op, DocumentReading::RustFs, body.as_bytes()), handed, "{op:?} {grantee}");
        }
    }
}
