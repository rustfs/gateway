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

//! The replication configuration document: what a stored one is allowed to say.
//!
//! Shares: replication
//! Members: DeleteBucketReplication, GetBucketReplication, PutBucketReplication
//!
//! Responsible for: the semantic rules of a `ReplicationConfiguration` document — the V1/V2
//! schema-version exclusivity of a rule (a `Filter` demands `Priority` and
//! `DeleteMarkerReplication` beside it; a legacy rule carries neither), the thousand-rule cap,
//! and the bounds and uniqueness of `ID` — held once so that every backend refuses the same
//! documents with the same codes. The filter's one-direct-child grammar and the two-condition
//! floor of `<And>` are `shared::rule_filter`'s, the one authority lifecycle uses too; this
//! module maps its refusal onto the family's codes.
//! NOT responsible for: decoding the document (the generated codec, which is deliberately
//! lenient about unknown elements — `q-repl-0005`), storing it, or **executing** it. Evaluating
//! a rule against an object write, assuming the Role, moving bytes between sites and producing
//! the per-object `x-amz-replication-status` header (task P5-01, with the object read encoders)
//! are the replication engine's questions, and nothing here answers them.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade,
//! which re-exports every item here for backends; the `crates/conformance` fixture is the first
//! caller.
//!
//! # Why leniency weighs more here than in any sibling family
//!
//! Every configuration family faces the same pressure — a stored document is re-parsed by every
//! future release — but the failure modes differ. RustFS's persistence parses most bucket
//! configurations fail-open: a document that stops parsing degrades to "no configuration".
//! Replication is the one configuration it parses **fail-closed**: a document that stops
//! parsing does not switch replication off, it makes the bucket unusable. So the checks below
//! are only the ones AWS documents as refusals, and everything else passes deliberately: an
//! out-of-set `Status` (`q-repl-0012`), a duplicated `Priority` (`q-repl-0009` — AWS documents
//! conflict resolution for it, not refusal), a rule with no scope at all (AWS's own
//! replicate-everything example), an unpaired `ReplicationTime`/`Metrics`, and any element this
//! release does not know (`q-repl-0005`). Getting stricter than this list is not a bug fix; it
//! is an availability incident scheduled for the next re-parse.
//!
//! # The refusal messages are constant, and neither the KMS key id nor the account appears
//!
//! These reasons follow [`super::cors`]'s stance — never built from request bytes. Here that
//! rule carries extra weight twice over: `Destination.EncryptionConfiguration.ReplicaKmsKeyID`
//! names a key and `Destination.Account` names an account, and a refusal that repeated either
//! would copy it into an error body and every log line that captures one (`q-repl-0010`). The
//! stored document echoes both on the read — that is the documented GET behaviour — but an
//! error message never does.

use super::rule_filter;

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{ReplicationConfiguration, ReplicationRule};

/// The most rules one bucket's configuration may carry: AWS's published, non-adjustable cap.
pub const MAX_REPLICATION_RULES: usize = 1000;

/// The longest `ID` a rule may carry, in characters: AWS's published cap.
pub const MAX_REPLICATION_ID_CHARS: usize = 255;

/// Why a decoded replication document was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error so that a backend outside this workspace can
/// map it into its own error type; [`ReplicationRejection::code`] and
/// [`ReplicationRejection::reason`] are the two halves an S3 error document needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicationRejection {
    /// More than [`MAX_REPLICATION_RULES`] rules.
    TooManyRules,
    /// A rule carrying both a `<Filter>` and the legacy rule-level `<Prefix>`: the two are the
    /// V2 and V1 spellings of the same scope, and one rule cannot be both schema versions.
    FilterBesideLegacyPrefix,
    /// A `<Filter>` with no `<Priority>` beside it: AWS documents the member as required the
    /// moment a rule opts into the V2 schema.
    PriorityMissingWithFilter,
    /// A `<Filter>` with no `<DeleteMarkerReplication>` beside it: the second member the V2
    /// schema demands.
    DeleteMarkerReplicationMissingWithFilter,
    /// A `<Priority>` on a rule with no `<Filter>`: the member belongs to the V2 schema, and a
    /// legacy rule carrying it is the two versions mixed the other way round.
    PriorityOnLegacyRule,
    /// A `<DeleteMarkerReplication>` on a rule with no `<Filter>`: same mixing, second member.
    DeleteMarkerReplicationOnLegacyRule,
    /// A `<Filter>` with more than one direct child. Several conditions must nest inside one
    /// `<And>`; two siblings are two contradictory scopes.
    FilterNotExclusive,
    /// An `<And>` with fewer than two conditions: the combinator exists only to combine.
    AndBelowTwoConditions,
    /// An `<ID>` longer than [`MAX_REPLICATION_ID_CHARS`] characters.
    IdTooLong,
    /// Two rules carrying the same `<ID>`.
    IdDuplicated,
}

impl ReplicationRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // A value outside a published bound the document as a whole must respect, and the
            // schema-version couplings: well-formed members whose combination the operation
            // refuses.
            ReplicationRejection::TooManyRules
            | ReplicationRejection::FilterBesideLegacyPrefix
            | ReplicationRejection::PriorityMissingWithFilter
            | ReplicationRejection::DeleteMarkerReplicationMissingWithFilter
            | ReplicationRejection::PriorityOnLegacyRule
            | ReplicationRejection::DeleteMarkerReplicationOnLegacyRule => ErrorCode::INVALID_REQUEST,
            // A grammar violation: the document's structure contradicts itself.
            ReplicationRejection::FilterNotExclusive | ReplicationRejection::AndBelowTwoConditions => ErrorCode::MALFORMED_XML,
            // A bound violation on an otherwise well-formed member.
            ReplicationRejection::IdTooLong | ReplicationRejection::IdDuplicated => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation, never built from request bytes — and in particular never carrying
    /// the KMS key id or the destination account the document named (`q-repl-0010`).
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            ReplicationRejection::TooManyRules => "The replication configuration allows a maximum of 1000 Rules",
            ReplicationRejection::FilterBesideLegacyPrefix => {
                "A Rule cannot combine a Filter with a rule-level Prefix; Prefix is the earlier schema's spelling of the scope"
            }
            ReplicationRejection::PriorityMissingWithFilter => "A Rule that specifies a Filter must also specify a Priority",
            ReplicationRejection::DeleteMarkerReplicationMissingWithFilter => {
                "A Rule that specifies a Filter must also specify DeleteMarkerReplication"
            }
            ReplicationRejection::PriorityOnLegacyRule => {
                "Priority can only be used together with a Filter; a rule-level Prefix belongs to the earlier schema"
            }
            ReplicationRejection::DeleteMarkerReplicationOnLegacyRule => {
                "DeleteMarkerReplication can only be used together with a Filter; a rule-level Prefix belongs to the earlier schema"
            }
            ReplicationRejection::FilterNotExclusive => "A Filter must have exactly one of Prefix, Tag or And specified",
            ReplicationRejection::AndBelowTwoConditions => "An And must contain at least two conditions",
            ReplicationRejection::IdTooLong => "ID must be no more than 255 characters",
            ReplicationRejection::IdDuplicated => "Rule ID must be unique; found the same ID for more than one rule",
        }
    }
}

/// Which schema version one rule is written in. The distinction is observable — AWS reports the
/// configuration's version through the read — and it is what the coupling rules below hang off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleShape {
    /// The earlier format: the scope is a rule-level `<Prefix>` (or nothing at all — AWS's own
    /// replicate-everything example), and `Priority` / `DeleteMarkerReplication` do not exist.
    LegacyPrefix,
    /// The current format: the scope is a `<Filter>`, and `Priority` and
    /// `DeleteMarkerReplication` are required beside it.
    FilterV2,
}

/// Classifies one rule and refuses the mixed forms, first refusal wins.
///
/// # Errors
///
/// [`ReplicationRejection`] naming the coupling the rule breaks.
pub fn classify_rule(rule: &ReplicationRule) -> Result<RuleShape, ReplicationRejection> {
    if rule.filter.is_some() {
        if rule.prefix.is_some() {
            return Err(ReplicationRejection::FilterBesideLegacyPrefix);
        }
        if rule.priority.is_none() {
            return Err(ReplicationRejection::PriorityMissingWithFilter);
        }
        if rule.delete_marker_replication.is_none() {
            return Err(ReplicationRejection::DeleteMarkerReplicationMissingWithFilter);
        }
        return Ok(RuleShape::FilterV2);
    }
    if rule.priority.is_some() {
        return Err(ReplicationRejection::PriorityOnLegacyRule);
    }
    if rule.delete_marker_replication.is_some() {
        return Err(ReplicationRejection::DeleteMarkerReplicationOnLegacyRule);
    }
    Ok(RuleShape::LegacyPrefix)
}

/// Checks a decoded document against the family's semantic rules, first refusal wins.
///
/// Deliberately no stricter than AWS's documented refusals — the module docs say why the
/// fail-closed persistence makes that a hard line here. Rules are checked in document order and
/// members in the order the wire carries them, so the same document is refused for the same
/// reason on every backend.
///
/// # Errors
///
/// [`ReplicationRejection`] naming the first rule the document breaks.
pub fn validate_replication(configuration: &ReplicationConfiguration) -> Result<(), ReplicationRejection> {
    if configuration.rules.len() > MAX_REPLICATION_RULES {
        return Err(ReplicationRejection::TooManyRules);
    }
    let mut seen_ids: Vec<&str> = Vec::new();
    for rule in &configuration.rules {
        validate_rule(rule)?;
        if let Some(id) = rule.id.as_deref() {
            if seen_ids.contains(&id) {
                return Err(ReplicationRejection::IdDuplicated);
            }
            seen_ids.push(id);
        }
    }
    Ok(())
}

fn validate_rule(rule: &ReplicationRule) -> Result<(), ReplicationRejection> {
    if let Some(id) = rule.id.as_deref()
        && id.chars().count() > MAX_REPLICATION_ID_CHARS
    {
        return Err(ReplicationRejection::IdTooLong);
    }
    classify_rule(rule)?;
    // The filter's grammar is `shared::rule_filter`'s; an empty `<Filter/>` passes there, as AWS's
    // documented spelling for "every object" (`q-repl-0007`).
    if let Some(filter) = &rule.filter {
        rule_filter::replication(filter).map_err(|reason| match reason {
            rule_filter::Rejection::FilterNotExclusive => ReplicationRejection::FilterNotExclusive,
            rule_filter::Rejection::AndBelowTwoConditions => ReplicationRejection::AndBelowTwoConditions,
        })?;
    }
    Ok(())
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `lifecycle`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_types::dto::{
        DeleteMarkerReplication, Destination, EncryptionConfiguration, ReplicationRuleAndOperator, ReplicationRuleFilter, Status,
        Tag,
    };

    /// A plausible destination and key/account pair for the negative cases; asserted absent from
    /// every reason.
    const DESTINATION_ARN: &str = "arn:aws:s3:::replica-bucket";
    const KEY_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    const ACCOUNT: &str = "111122223333";

    fn destination() -> Destination {
        Destination {
            bucket: DESTINATION_ARN.to_owned(),
            account: Some(ACCOUNT.to_owned()),
            encryption_configuration: Some(EncryptionConfiguration {
                replica_kms_key_id: Some(KEY_ARN.to_owned()),
            }),
            ..Destination::default()
        }
    }

    fn legacy_rule(prefix: &str) -> ReplicationRule {
        ReplicationRule {
            prefix: Some(prefix.to_owned()),
            status: Status::ENABLED,
            destination: destination(),
            ..ReplicationRule::default()
        }
    }

    fn v2_rule(filter: ReplicationRuleFilter) -> ReplicationRule {
        ReplicationRule {
            filter: Some(filter),
            priority: Some(1),
            delete_marker_replication: Some(DeleteMarkerReplication {
                status: Some(Status::DISABLED),
            }),
            status: Status::ENABLED,
            destination: destination(),
            ..ReplicationRule::default()
        }
    }

    fn config(rules: Vec<ReplicationRule>) -> ReplicationConfiguration {
        ReplicationConfiguration {
            role: "arn:aws:iam::111122223333:role/replication".to_owned(),
            rules,
        }
    }

    fn tag(key: &str, value: &str) -> Tag {
        Tag {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_legacy_prefix_rule_is_accepted_without_priority_or_delete_marker_replication() {
        assert_eq!(validate_replication(&config(vec![legacy_rule("logs/")])), Ok(()));
        assert_eq!(classify_rule(&legacy_rule("logs/")), Ok(RuleShape::LegacyPrefix));
    }

    #[test]
    fn a_rule_with_no_scope_at_all_is_accepted() {
        // AWS's own minimal example: Status and Destination alone replicate every object. A
        // ScopeMissing refusal here would refuse the first documented configuration.
        let entry = ReplicationRule {
            status: Status::ENABLED,
            destination: destination(),
            ..ReplicationRule::default()
        };
        assert_eq!(classify_rule(&entry), Ok(RuleShape::LegacyPrefix));
        assert_eq!(validate_replication(&config(vec![entry])), Ok(()));
    }

    #[test]
    fn a_v2_rule_with_priority_and_delete_marker_replication_is_accepted() {
        let filter = ReplicationRuleFilter {
            prefix: Some("logs/".to_owned()),
            ..ReplicationRuleFilter::default()
        };
        assert_eq!(classify_rule(&v2_rule(filter.clone())), Ok(RuleShape::FilterV2));
        assert_eq!(validate_replication(&config(vec![v2_rule(filter)])), Ok(()));
    }

    #[test]
    fn an_empty_filter_matches_everything_and_is_accepted() {
        let document = config(vec![v2_rule(ReplicationRuleFilter::default())]);
        assert_eq!(validate_replication(&document), Ok(()));
    }

    #[test]
    fn each_single_filter_condition_is_accepted_alone() {
        for filter in [
            ReplicationRuleFilter {
                prefix: Some("logs/".to_owned()),
                ..ReplicationRuleFilter::default()
            },
            ReplicationRuleFilter {
                tag: Some(tag("env", "prod")),
                ..ReplicationRuleFilter::default()
            },
        ] {
            assert_eq!(validate_replication(&config(vec![v2_rule(filter)])), Ok(()));
        }
    }

    #[test]
    fn an_and_with_two_conditions_is_accepted() {
        let filter = ReplicationRuleFilter {
            and: Some(ReplicationRuleAndOperator {
                prefix: Some("logs/".to_owned()),
                tags: vec![tag("env", "prod")],
            }),
            ..ReplicationRuleFilter::default()
        };
        assert_eq!(validate_replication(&config(vec![v2_rule(filter)])), Ok(()));
    }

    #[test]
    fn two_tags_alone_satisfy_the_and_floor() {
        let filter = ReplicationRuleFilter {
            and: Some(ReplicationRuleAndOperator {
                prefix: None,
                tags: vec![tag("env", "prod"), tag("team", "storage")],
            }),
            ..ReplicationRuleFilter::default()
        };
        assert_eq!(validate_replication(&config(vec![v2_rule(filter)])), Ok(()));
    }

    #[test]
    fn the_rule_cap_and_the_id_cap_are_inclusive() {
        let mut rules: Vec<ReplicationRule> = (0..MAX_REPLICATION_RULES).map(|_| legacy_rule("logs/")).collect();
        if let Some(first) = rules.first_mut() {
            first.id = Some("i".repeat(MAX_REPLICATION_ID_CHARS));
        }
        assert_eq!(validate_replication(&config(rules)), Ok(()));
    }

    #[test]
    fn a_duplicated_priority_passes_on_purpose() {
        // `q-repl-0009`: AWS documents how the engine resolves equal priorities, not a refusal —
        // and under fail-closed persistence an invented uniqueness rule is an availability bug.
        let filter = || ReplicationRuleFilter {
            prefix: Some("logs/".to_owned()),
            ..ReplicationRuleFilter::default()
        };
        let document = config(vec![v2_rule(filter()), v2_rule(filter())]);
        assert_eq!(validate_replication(&document), Ok(()));
    }

    #[test]
    fn an_out_of_set_status_passes_on_purpose() {
        // `q-repl-0012`: refusing `enabled` here would refuse a document already on disk the
        // next time it is re-parsed, and this is the one configuration whose re-parse failure
        // makes the bucket unusable rather than switching a feature off.
        let mut entry = legacy_rule("logs/");
        entry.status = Status::custom("enabled");
        assert_eq!(validate_replication(&config(vec![entry])), Ok(()));
    }

    #[test]
    fn an_unpaired_replication_time_passes_on_purpose() {
        // AWS documents RTC as "must be specified together with a Metrics block", but no refusal
        // code for the unpaired form — so the codec stores it and the engine decides. Getting
        // stricter here without a documented refusal is the guessed rule this family refuses to
        // write.
        use rustfs_gateway_types::dto::{ReplicationTime, ReplicationTimeValue};
        let mut entry = legacy_rule("logs/");
        entry.destination.replication_time = Some(ReplicationTime {
            status: Status::ENABLED,
            time: ReplicationTimeValue { minutes: Some(15) },
        });
        assert_eq!(validate_replication(&config(vec![entry])), Ok(()));
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_the_thousand_and_first_rule_is_refused() {
        let document = config((0..=MAX_REPLICATION_RULES).map(|_| legacy_rule("logs/")).collect());
        assert_eq!(validate_replication(&document), Err(ReplicationRejection::TooManyRules));
        assert_eq!(ReplicationRejection::TooManyRules.code(), ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn n_a_filter_beside_a_legacy_prefix_is_refused_as_invalid_request() {
        let mut entry = v2_rule(ReplicationRuleFilter::default());
        entry.prefix = Some("logs/".to_owned());
        assert_eq!(classify_rule(&entry), Err(ReplicationRejection::FilterBesideLegacyPrefix));
        assert_eq!(
            validate_replication(&config(vec![entry])),
            Err(ReplicationRejection::FilterBesideLegacyPrefix)
        );
        assert_eq!(ReplicationRejection::FilterBesideLegacyPrefix.code(), ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn n_a_filter_without_priority_is_refused() {
        let mut entry = v2_rule(ReplicationRuleFilter::default());
        entry.priority = None;
        assert_eq!(
            validate_replication(&config(vec![entry])),
            Err(ReplicationRejection::PriorityMissingWithFilter)
        );
        assert_eq!(ReplicationRejection::PriorityMissingWithFilter.code(), ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn n_a_filter_without_delete_marker_replication_is_refused() {
        let mut entry = v2_rule(ReplicationRuleFilter::default());
        entry.delete_marker_replication = None;
        assert_eq!(
            validate_replication(&config(vec![entry])),
            Err(ReplicationRejection::DeleteMarkerReplicationMissingWithFilter)
        );
    }

    #[test]
    fn n_a_priority_on_a_legacy_rule_is_refused() {
        let mut entry = legacy_rule("logs/");
        entry.priority = Some(1);
        assert_eq!(
            validate_replication(&config(vec![entry])),
            Err(ReplicationRejection::PriorityOnLegacyRule)
        );
    }

    #[test]
    fn n_a_delete_marker_replication_on_a_legacy_rule_is_refused() {
        let mut entry = legacy_rule("logs/");
        entry.delete_marker_replication = Some(DeleteMarkerReplication {
            status: Some(Status::ENABLED),
        });
        assert_eq!(
            validate_replication(&config(vec![entry])),
            Err(ReplicationRejection::DeleteMarkerReplicationOnLegacyRule)
        );
    }

    #[test]
    fn n_two_direct_filter_children_are_malformed() {
        let filter = ReplicationRuleFilter {
            prefix: Some("logs/".to_owned()),
            tag: Some(tag("env", "prod")),
            ..ReplicationRuleFilter::default()
        };
        assert_eq!(
            validate_replication(&config(vec![v2_rule(filter)])),
            Err(ReplicationRejection::FilterNotExclusive)
        );
        assert_eq!(ReplicationRejection::FilterNotExclusive.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_an_and_with_one_condition_is_malformed() {
        for and in [
            ReplicationRuleAndOperator {
                prefix: Some("logs/".to_owned()),
                tags: Vec::new(),
            },
            ReplicationRuleAndOperator {
                prefix: None,
                tags: vec![tag("env", "prod")],
            },
            ReplicationRuleAndOperator::default(),
        ] {
            let filter = ReplicationRuleFilter {
                and: Some(and),
                ..ReplicationRuleFilter::default()
            };
            assert_eq!(
                validate_replication(&config(vec![v2_rule(filter)])),
                Err(ReplicationRejection::AndBelowTwoConditions)
            );
        }
        assert_eq!(ReplicationRejection::AndBelowTwoConditions.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_an_id_over_the_cap_is_refused_as_invalid_argument() {
        let mut entry = legacy_rule("logs/");
        entry.id = Some("i".repeat(MAX_REPLICATION_ID_CHARS + 1));
        assert_eq!(validate_replication(&config(vec![entry])), Err(ReplicationRejection::IdTooLong));
        assert_eq!(ReplicationRejection::IdTooLong.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_a_duplicated_id_is_refused_as_invalid_argument() {
        let mut first = legacy_rule("logs/");
        first.id = Some("rule-one".to_owned());
        let mut second = legacy_rule("tmp/");
        second.id = Some("rule-one".to_owned());
        assert_eq!(
            validate_replication(&config(vec![first, second])),
            Err(ReplicationRejection::IdDuplicated)
        );
        assert_eq!(ReplicationRejection::IdDuplicated.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_two_anonymous_rules_are_not_a_duplicate() {
        // Uniqueness binds ids, not their absence: a document with two id-less rules is legal.
        assert_eq!(validate_replication(&config(vec![legacy_rule("logs/"), legacy_rule("tmp/")])), Ok(()));
    }

    #[test]
    fn n_the_first_broken_rule_decides_the_refusal() {
        // Within one rule the id bound is checked before the shape coupling, so the second
        // rule's long id wins over its missing priority — one deterministic refusal per
        // document.
        let mut second = v2_rule(ReplicationRuleFilter::default());
        second.priority = None;
        second.id = Some("i".repeat(MAX_REPLICATION_ID_CHARS + 1));
        assert_eq!(
            validate_replication(&config(vec![legacy_rule("logs/"), second])),
            Err(ReplicationRejection::IdTooLong)
        );
    }

    #[test]
    fn n_no_reason_carries_the_key_id_the_account_or_any_request_bytes() {
        // `q-repl-0010`: the constant reasons must hold even for a document that named a KMS
        // key, an account and a destination ARN — none of them may surface in a refusal.
        for rejection in [
            ReplicationRejection::TooManyRules,
            ReplicationRejection::FilterBesideLegacyPrefix,
            ReplicationRejection::PriorityMissingWithFilter,
            ReplicationRejection::DeleteMarkerReplicationMissingWithFilter,
            ReplicationRejection::PriorityOnLegacyRule,
            ReplicationRejection::DeleteMarkerReplicationOnLegacyRule,
            ReplicationRejection::FilterNotExclusive,
            ReplicationRejection::AndBelowTwoConditions,
            ReplicationRejection::IdTooLong,
            ReplicationRejection::IdDuplicated,
        ] {
            assert!(!rejection.reason().contains(KEY_ARN));
            assert!(!rejection.reason().contains(ACCOUNT));
            assert!(!rejection.reason().contains("arn:"));
        }
    }

    #[test]
    fn n_the_status_side_of_each_code_is_the_one_aws_answers() {
        // The family's whole error surface, pinned to the statuses AWS answers.
        assert_eq!(ErrorCode::REPLICATION_CONFIGURATION_NOT_FOUND.default_status().as_u16(), 404);
        assert_eq!(ErrorCode::INVALID_REQUEST.default_status().as_u16(), 400);
        assert_eq!(ErrorCode::INVALID_ARGUMENT.default_status().as_u16(), 400);
        assert_eq!(ErrorCode::MALFORMED_XML.default_status().as_u16(), 400);
    }
}
