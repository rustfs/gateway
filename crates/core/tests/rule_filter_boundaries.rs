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

//! The rule `<Filter>` boundaries each consumer of the shared filter grammar still answers.
//!
//! Responsible for: the filter shapes the two families' unit tests leave open — `<And>` beside a
//! direct child, an `<And>` made only of object-size bounds, a duplicated tag key, an empty
//! `<Prefix>`, and which refusal wins when a filter breaks both rules — asked of
//! `validate_lifecycle` and `validate_replication` side by side through the public API, so that
//! the one per-family difference (lifecycle's object-size members) stays visible as a difference.
//! NOT responsible for: the cases `ops::shared::lifecycle` and `ops::shared::replication` already
//! pin in their own unit tests, the round-trip properties in `lifecycle_roundtrip.rs` and
//! `replication_roundtrip.rs`, or tag-key rules, which `ops::shared::tagging` owns and neither
//! family runs.
//! Upstream: `ops::shared::lifecycle`, `ops::shared::replication` and, behind both,
//! `ops::shared::rule_filter`. Downstream: nothing.
//!
//! Every answer here is the answer the families gave before the grammar was shared; the file is a
//! behaviour pin for that consolidation, not a new rule.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use rustfs_gateway_core::ops::shared::lifecycle::{LifecycleRejection, validate_lifecycle};
use rustfs_gateway_core::ops::shared::replication::{ReplicationRejection, validate_replication};
use rustfs_gateway_types::dto::{
    BucketLifecycleConfiguration, DeleteMarkerReplication, Destination, LifecycleRule, LifecycleRuleAndOperator,
    LifecycleRuleFilter, ReplicationConfiguration, ReplicationRule, ReplicationRuleAndOperator, ReplicationRuleFilter, Status,
    Tag,
};

fn tag(key: &str, value: &str) -> Tag {
    Tag {
        key: key.to_owned(),
        value: value.to_owned(),
    }
}

fn lifecycle(filter: LifecycleRuleFilter) -> Result<(), LifecycleRejection> {
    validate_lifecycle(&BucketLifecycleConfiguration {
        rules: vec![LifecycleRule {
            filter: Some(filter),
            status: Status::ENABLED,
            ..LifecycleRule::default()
        }],
        ..BucketLifecycleConfiguration::default()
    })
}

fn replication_rule(filter: ReplicationRuleFilter) -> ReplicationRule {
    ReplicationRule {
        filter: Some(filter),
        priority: Some(1),
        delete_marker_replication: Some(DeleteMarkerReplication {
            status: Some(Status::DISABLED),
        }),
        status: Status::ENABLED,
        destination: Destination {
            bucket: "arn:aws:s3:::replica-bucket".to_owned(),
            ..Destination::default()
        },
        ..ReplicationRule::default()
    }
}

fn replication_of(rule: ReplicationRule) -> Result<(), ReplicationRejection> {
    validate_replication(&ReplicationConfiguration {
        role: "arn:aws:iam::111122223333:role/replication".to_owned(),
        rules: vec![rule],
    })
}

fn replication(filter: ReplicationRuleFilter) -> Result<(), ReplicationRejection> {
    replication_of(replication_rule(filter))
}

fn lifecycle_and(and: LifecycleRuleAndOperator) -> LifecycleRuleFilter {
    LifecycleRuleFilter {
        and: Some(and),
        ..LifecycleRuleFilter::default()
    }
}

fn replication_and(prefix: Option<&str>, tags: Vec<Tag>) -> ReplicationRuleAndOperator {
    ReplicationRuleAndOperator {
        prefix: prefix.map(str::to_owned),
        tags,
    }
}

/// A two-condition `<And>` that passes on its own, so a refusal beside it is the sibling's doing.
fn legal_lifecycle_and() -> LifecycleRuleAndOperator {
    LifecycleRuleAndOperator {
        prefix: Some("logs/".to_owned()),
        tags: vec![tag("env", "prod")],
        ..LifecycleRuleAndOperator::default()
    }
}

fn legal_replication_and() -> ReplicationRuleAndOperator {
    replication_and(Some("logs/"), vec![tag("env", "prod")])
}

// ── lifecycle ────────────────────────────────────────────────────────────────────────────────

#[test]
fn lifecycle_counts_object_size_bounds_and_every_tag_as_and_conditions() {
    for (label, and) in [
        (
            "a size window inside And",
            LifecycleRuleAndOperator {
                object_size_greater_than: Some(1024),
                object_size_less_than: Some(4096),
                ..LifecycleRuleAndOperator::default()
            },
        ),
        (
            "a prefix and a lower size bound",
            LifecycleRuleAndOperator {
                prefix: Some("logs/".to_owned()),
                object_size_greater_than: Some(1024),
                ..LifecycleRuleAndOperator::default()
            },
        ),
        (
            "a tag and an upper size bound",
            LifecycleRuleAndOperator {
                tags: vec![tag("env", "prod")],
                object_size_less_than: Some(4096),
                ..LifecycleRuleAndOperator::default()
            },
        ),
        (
            "two tags sharing one key",
            LifecycleRuleAndOperator {
                tags: vec![tag("env", "prod"), tag("env", "stage")],
                ..LifecycleRuleAndOperator::default()
            },
        ),
        (
            "an empty prefix and a tag",
            LifecycleRuleAndOperator {
                prefix: Some(String::new()),
                tags: vec![tag("env", "prod")],
                ..LifecycleRuleAndOperator::default()
            },
        ),
    ] {
        assert_eq!(lifecycle(lifecycle_and(and)), Ok(()), "{label}");
    }
}

#[test]
fn n_lifecycle_refuses_any_direct_child_beside_an_and() {
    for (label, filter) in [
        (
            "a prefix",
            LifecycleRuleFilter {
                prefix: Some("logs/".to_owned()),
                ..lifecycle_and(legal_lifecycle_and())
            },
        ),
        (
            "an empty prefix",
            LifecycleRuleFilter {
                prefix: Some(String::new()),
                ..lifecycle_and(legal_lifecycle_and())
            },
        ),
        (
            "a tag",
            LifecycleRuleFilter {
                tag: Some(tag("env", "prod")),
                ..lifecycle_and(legal_lifecycle_and())
            },
        ),
        (
            "a lower size bound",
            LifecycleRuleFilter {
                object_size_greater_than: Some(1024),
                ..lifecycle_and(legal_lifecycle_and())
            },
        ),
        (
            "an upper size bound",
            LifecycleRuleFilter {
                object_size_less_than: Some(4096),
                ..lifecycle_and(legal_lifecycle_and())
            },
        ),
    ] {
        assert_eq!(lifecycle(filter), Err(LifecycleRejection::FilterNotExclusive), "{label} beside And");
    }
}

#[test]
fn n_lifecycle_refuses_direct_siblings_that_name_the_same_or_an_empty_value() {
    for (label, filter) in [
        (
            "an empty prefix beside a tag",
            LifecycleRuleFilter {
                prefix: Some(String::new()),
                tag: Some(tag("env", "prod")),
                ..LifecycleRuleFilter::default()
            },
        ),
        (
            "an upper size bound beside a tag",
            LifecycleRuleFilter {
                tag: Some(tag("env", "prod")),
                object_size_less_than: Some(4096),
                ..LifecycleRuleFilter::default()
            },
        ),
        (
            "a lower size bound beside a prefix",
            LifecycleRuleFilter {
                prefix: Some("logs/".to_owned()),
                object_size_greater_than: Some(1024),
                ..LifecycleRuleFilter::default()
            },
        ),
    ] {
        assert_eq!(lifecycle(filter), Err(LifecycleRejection::FilterNotExclusive), "{label}");
    }
}

#[test]
fn n_lifecycle_refuses_an_and_holding_one_condition_of_any_kind() {
    for (label, and) in [
        (
            "one tag",
            LifecycleRuleAndOperator {
                tags: vec![tag("env", "prod")],
                ..LifecycleRuleAndOperator::default()
            },
        ),
        (
            "one lower size bound",
            LifecycleRuleAndOperator {
                object_size_greater_than: Some(1024),
                ..LifecycleRuleAndOperator::default()
            },
        ),
        (
            "one upper size bound",
            LifecycleRuleAndOperator {
                object_size_less_than: Some(4096),
                ..LifecycleRuleAndOperator::default()
            },
        ),
        (
            "one empty prefix",
            LifecycleRuleAndOperator {
                prefix: Some(String::new()),
                ..LifecycleRuleAndOperator::default()
            },
        ),
    ] {
        assert_eq!(lifecycle(lifecycle_and(and)), Err(LifecycleRejection::AndBelowTwoConditions), "{label}");
    }
}

#[test]
fn n_lifecycle_names_the_sibling_when_a_filter_breaks_both_rules() {
    let filter = LifecycleRuleFilter {
        prefix: Some("logs/".to_owned()),
        ..lifecycle_and(LifecycleRuleAndOperator::default())
    };
    assert_eq!(lifecycle(filter), Err(LifecycleRejection::FilterNotExclusive));
}

// ── replication ──────────────────────────────────────────────────────────────────────────────

#[test]
fn replication_counts_every_tag_and_an_empty_prefix_as_and_conditions() {
    for (label, and) in [
        (
            "two tags sharing one key",
            replication_and(None, vec![tag("env", "prod"), tag("env", "stage")]),
        ),
        ("an empty prefix and a tag", replication_and(Some(""), vec![tag("env", "prod")])),
    ] {
        let filter = ReplicationRuleFilter {
            and: Some(and),
            ..ReplicationRuleFilter::default()
        };
        assert_eq!(replication(filter), Ok(()), "{label}");
    }
}

#[test]
fn n_replication_refuses_any_direct_child_beside_an_and() {
    for (label, filter) in [
        (
            "a prefix",
            ReplicationRuleFilter {
                prefix: Some("logs/".to_owned()),
                tag: None,
                and: Some(legal_replication_and()),
            },
        ),
        (
            "an empty prefix",
            ReplicationRuleFilter {
                prefix: Some(String::new()),
                tag: None,
                and: Some(legal_replication_and()),
            },
        ),
        (
            "a tag",
            ReplicationRuleFilter {
                prefix: None,
                tag: Some(tag("env", "prod")),
                and: Some(legal_replication_and()),
            },
        ),
    ] {
        assert_eq!(replication(filter), Err(ReplicationRejection::FilterNotExclusive), "{label} beside And");
    }
}

#[test]
fn n_replication_refuses_an_empty_prefix_beside_a_tag() {
    let filter = ReplicationRuleFilter {
        prefix: Some(String::new()),
        tag: Some(tag("env", "prod")),
        and: None,
    };
    assert_eq!(replication(filter), Err(ReplicationRejection::FilterNotExclusive));
}

#[test]
fn n_replication_refuses_an_and_holding_only_an_empty_prefix() {
    let filter = ReplicationRuleFilter {
        and: Some(replication_and(Some(""), Vec::new())),
        ..ReplicationRuleFilter::default()
    };
    assert_eq!(replication(filter), Err(ReplicationRejection::AndBelowTwoConditions));
}

#[test]
fn n_replication_names_the_sibling_when_a_filter_breaks_both_rules() {
    let filter = ReplicationRuleFilter {
        prefix: Some("logs/".to_owned()),
        tag: None,
        and: Some(replication_and(None, Vec::new())),
    };
    assert_eq!(replication(filter), Err(ReplicationRejection::FilterNotExclusive));
}

#[test]
fn n_replication_judges_the_schema_coupling_before_the_filter() {
    // The rule-level V1/V2 coupling is the family's own rule and runs first: a rule whose filter
    // has two siblings and which also lacks its Priority is refused for the Priority.
    let mut rule = replication_rule(ReplicationRuleFilter {
        prefix: Some("logs/".to_owned()),
        tag: Some(tag("env", "prod")),
        and: None,
    });
    rule.priority = None;
    assert_eq!(replication_of(rule), Err(ReplicationRejection::PriorityMissingWithFilter));
}

// ── the difference that stays a difference ───────────────────────────────────────────────────

#[test]
fn n_each_family_names_only_its_own_filter_members_when_it_refuses_siblings() {
    let lifecycle_reason = LifecycleRejection::FilterNotExclusive.reason();
    let replication_reason = ReplicationRejection::FilterNotExclusive.reason();
    for member in ["ObjectSizeGreaterThan", "ObjectSizeLessThan"] {
        assert!(lifecycle_reason.contains(member), "lifecycle's reason lists {member}");
        assert!(!replication_reason.contains(member), "replication has no {member} member to list");
    }
    for rejection in [
        LifecycleRejection::FilterNotExclusive,
        LifecycleRejection::AndBelowTwoConditions,
    ] {
        assert_eq!(rejection.code().as_str(), "MalformedXML");
    }
    for rejection in [
        ReplicationRejection::FilterNotExclusive,
        ReplicationRejection::AndBelowTwoConditions,
    ] {
        assert_eq!(rejection.code().as_str(), "MalformedXML");
    }
}
