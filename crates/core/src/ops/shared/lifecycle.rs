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

//! The lifecycle configuration document: what a stored one is allowed to say.
//!
//! Shares: lifecycle
//! Members: DeleteBucketLifecycle, GetBucketLifecycleConfiguration, PutBucketLifecycleConfiguration
//!
//! Responsible for: the semantic rules of a `LifecycleConfiguration` document — the rule's
//! Filter-or-Prefix scope requirement, the `Days`/`Date`/`ExpiredObjectDeleteMarker` mutex, the
//! midnight rule on every `Date`, the thousand-rule cap and the bounds and uniqueness of `ID` —
//! held once so that every backend refuses the same documents with the same codes. The filter's
//! one-direct-child grammar and the two-condition floor of `<And>` are `shared::rule_filter`'s,
//! the one authority replication uses too; this module maps its refusal onto the family's codes.
//! NOT responsible for: decoding the document (the generated codec, which is deliberately lenient
//! about unknown elements — `q-lc-0006`), storing it, or **evaluating** it. When a rule fires,
//! what it expires and which storage class it transitions to are the storage backend's scanner's
//! questions, and nothing here answers them.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade, which
//! re-exports every item here for backends; the `crates/conformance` fixture is the first caller.
//!
//! # Why validation is narrower here than a schema would be
//!
//! The write path is not the only reader of this document: a stored configuration is re-parsed
//! by every future release, and RustFS's own persistence fails open — a configuration that stops
//! parsing is downgraded to "no configuration", which silently turns lifecycle rules off. So the
//! checks below are only the ones AWS documents as refusals, and everything else passes: a
//! `Status` outside the documented pair, an out-of-set storage class or an unknown element is
//! stored and echoed rather than refused (`q-lc-0014`, `q-lc-0006`). Getting stricter than this
//! list is a compatibility break with data already on disk, not a bug fix.
//!
//! # The refusal messages are constant
//!
//! These reasons follow [`super::cors`]'s stance — never built from request bytes — so the
//! offending value is named by position in the caller's own document, not repeated into the
//! response.

use super::rule_filter;

use rustfs_gateway_types::dto::{BucketLifecycleConfiguration, LifecycleRule};
use rustfs_gateway_types::{ErrorCode, Timestamp};

/// The most rules one bucket's configuration may carry: AWS's published cap.
pub const MAX_LIFECYCLE_RULES: usize = 1000;

/// The longest `ID` a rule may carry, in characters: AWS's published cap.
pub const MAX_LIFECYCLE_ID_CHARS: usize = 255;

/// Why a decoded lifecycle document was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error so that a backend outside this workspace can
/// map it into its own error type; [`LifecycleRejection::code`] and
/// [`LifecycleRejection::reason`] are the two halves an S3 error document needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleRejection {
    /// More than [`MAX_LIFECYCLE_RULES`] rules.
    TooManyRules,
    /// A rule with neither a `<Filter>` nor the legacy rule-level `<Prefix>`: the document has
    /// nothing that says which objects the rule applies to.
    ScopeMissing,
    /// A `<Filter>` with more than one direct child. Several conditions must nest inside one
    /// `<And>`; two siblings are two contradictory scopes.
    FilterNotExclusive,
    /// An `<And>` with fewer than two conditions: the combinator exists only to combine.
    AndBelowTwoConditions,
    /// An `<Expiration>` naming two or more of `Days`, `Date` and `ExpiredObjectDeleteMarker`.
    ExpirationConflict,
    /// An `<Expiration><Days>` below one.
    ExpirationDaysNotPositive,
    /// A `<Date>` — in an `Expiration` or a `Transition` — that is not midnight UTC.
    DateNotMidnight,
    /// An `<ID>` longer than [`MAX_LIFECYCLE_ID_CHARS`] characters.
    IdTooLong,
    /// Two rules carrying the same `<ID>`.
    IdDuplicated,
}

impl LifecycleRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // A value outside a published bound the document as a whole must respect.
            LifecycleRejection::TooManyRules => ErrorCode::INVALID_REQUEST,
            // A grammar violation: the document's structure contradicts itself.
            LifecycleRejection::ScopeMissing
            | LifecycleRejection::FilterNotExclusive
            | LifecycleRejection::AndBelowTwoConditions
            | LifecycleRejection::ExpirationConflict => ErrorCode::MALFORMED_XML,
            // A bound violation on an otherwise well-formed member.
            LifecycleRejection::ExpirationDaysNotPositive
            | LifecycleRejection::DateNotMidnight
            | LifecycleRejection::IdTooLong
            | LifecycleRejection::IdDuplicated => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation, never built from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            LifecycleRejection::TooManyRules => "The lifecycle configuration allows a maximum of 1000 Rules",
            LifecycleRejection::ScopeMissing => "Each Rule must identify objects with a Filter or a Prefix",
            LifecycleRejection::FilterNotExclusive => {
                "A Filter must have exactly one of Prefix, Tag, ObjectSizeGreaterThan, ObjectSizeLessThan or And specified"
            }
            LifecycleRejection::AndBelowTwoConditions => "An And must contain at least two conditions",
            LifecycleRejection::ExpirationConflict => {
                "Days, Date and ExpiredObjectDeleteMarker are mutually exclusive within an Expiration"
            }
            LifecycleRejection::ExpirationDaysNotPositive => "Days in the Expiration action must be a positive integer",
            LifecycleRejection::DateNotMidnight => "Date must be at midnight GMT",
            LifecycleRejection::IdTooLong => "ID must be no more than 255 characters",
            LifecycleRejection::IdDuplicated => "Rule ID must be unique; found the same ID for more than one rule",
        }
    }
}

/// Checks a decoded document against the family's semantic rules, first refusal wins.
///
/// Syntax only, and deliberately no stricter than AWS's documented refusals: a `Status` outside
/// the documented pair, an out-of-set storage class or an element this release does not know
/// passes, because a stored document refused by a later release is a lifecycle rule silently
/// turned off. Rules are checked in document order and members in the order the wire carries
/// them, so the same document is refused for the same reason on every backend.
///
/// # Errors
///
/// [`LifecycleRejection`] naming the first rule the document breaks.
pub fn validate_lifecycle(configuration: &BucketLifecycleConfiguration) -> Result<(), LifecycleRejection> {
    if configuration.rules.len() > MAX_LIFECYCLE_RULES {
        return Err(LifecycleRejection::TooManyRules);
    }
    let mut seen_ids: Vec<&str> = Vec::new();
    for rule in &configuration.rules {
        validate_rule(rule)?;
        if let Some(id) = rule.id.as_deref() {
            if seen_ids.contains(&id) {
                return Err(LifecycleRejection::IdDuplicated);
            }
            seen_ids.push(id);
        }
    }
    Ok(())
}

fn validate_rule(rule: &LifecycleRule) -> Result<(), LifecycleRejection> {
    if let Some(id) = rule.id.as_deref()
        && id.chars().count() > MAX_LIFECYCLE_ID_CHARS
    {
        return Err(LifecycleRejection::IdTooLong);
    }
    // The legacy rule-level Prefix is a scope of its own (`q-lc-0008`); an empty `<Filter/>` is
    // one too, matching every object. Only a rule with neither says nothing about its objects.
    if rule.prefix.is_none() && rule.filter.is_none() {
        return Err(LifecycleRejection::ScopeMissing);
    }
    // The filter's grammar, object-size members included, is `shared::rule_filter`'s.
    if let Some(filter) = &rule.filter {
        rule_filter::lifecycle(filter).map_err(|reason| match reason {
            rule_filter::Rejection::FilterNotExclusive => LifecycleRejection::FilterNotExclusive,
            rule_filter::Rejection::AndBelowTwoConditions => LifecycleRejection::AndBelowTwoConditions,
        })?;
    }
    if let Some(expiration) = &rule.expiration {
        let named = usize::from(expiration.days.is_some())
            + usize::from(expiration.date.is_some())
            + usize::from(expiration.expired_object_delete_marker.is_some());
        if named > 1 {
            return Err(LifecycleRejection::ExpirationConflict);
        }
        if let Some(days) = expiration.days
            && days < 1
        {
            return Err(LifecycleRejection::ExpirationDaysNotPositive);
        }
        if let Some(date) = expiration.date
            && !is_midnight_utc(date)
        {
            return Err(LifecycleRejection::DateNotMidnight);
        }
    }
    for transition in &rule.transitions {
        if let Some(date) = transition.date
            && !is_midnight_utc(date)
        {
            return Err(LifecycleRejection::DateNotMidnight);
        }
    }
    Ok(())
}

/// Whether the instant is exactly midnight UTC, to the nanosecond.
///
/// `rem_euclid` rather than `%`: an instant before 1970 has negative seconds, and a negative
/// remainder would call 1969-12-31T00:00:00Z something other than midnight.
fn is_midnight_utc(date: Timestamp) -> bool {
    date.secs().rem_euclid(86_400) == 0 && date.subsec_nanos() == 0
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `copy_source`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_types::dto::{
        LifecycleExpiration, LifecycleRuleAndOperator, LifecycleRuleFilter, Status, Tag, Transition,
    };

    /// 2030-01-01T00:00:00Z.
    const MIDNIGHT: i64 = 1_893_456_000;

    fn rule(prefix: &str) -> LifecycleRule {
        LifecycleRule {
            prefix: Some(prefix.to_owned()),
            status: Status::ENABLED,
            ..LifecycleRule::default()
        }
    }

    fn filter_rule(filter: LifecycleRuleFilter) -> LifecycleRule {
        LifecycleRule {
            filter: Some(filter),
            status: Status::ENABLED,
            ..LifecycleRule::default()
        }
    }

    fn config(rules: Vec<LifecycleRule>) -> BucketLifecycleConfiguration {
        BucketLifecycleConfiguration { rules }
    }

    fn tag(key: &str, value: &str) -> Tag {
        Tag {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn a_legacy_prefix_rule_is_a_valid_scope() {
        assert_eq!(validate_lifecycle(&config(vec![rule("logs/")])), Ok(()));
    }

    #[test]
    fn an_empty_filter_matches_everything_and_is_accepted() {
        let document = config(vec![filter_rule(LifecycleRuleFilter::default())]);
        assert_eq!(validate_lifecycle(&document), Ok(()));
    }

    #[test]
    fn each_single_filter_condition_is_accepted_alone() {
        for filter in [
            LifecycleRuleFilter {
                prefix: Some("logs/".to_owned()),
                ..LifecycleRuleFilter::default()
            },
            LifecycleRuleFilter {
                tag: Some(tag("env", "prod")),
                ..LifecycleRuleFilter::default()
            },
            LifecycleRuleFilter {
                object_size_greater_than: Some(1024),
                ..LifecycleRuleFilter::default()
            },
            LifecycleRuleFilter {
                object_size_less_than: Some(4096),
                ..LifecycleRuleFilter::default()
            },
        ] {
            assert_eq!(validate_lifecycle(&config(vec![filter_rule(filter)])), Ok(()));
        }
    }

    #[test]
    fn an_and_with_two_conditions_is_accepted() {
        let filter = LifecycleRuleFilter {
            and: Some(LifecycleRuleAndOperator {
                prefix: Some("logs/".to_owned()),
                tags: vec![tag("env", "prod")],
                ..LifecycleRuleAndOperator::default()
            }),
            ..LifecycleRuleFilter::default()
        };
        assert_eq!(validate_lifecycle(&config(vec![filter_rule(filter)])), Ok(()));
    }

    #[test]
    fn two_tags_alone_satisfy_the_and_floor() {
        let filter = LifecycleRuleFilter {
            and: Some(LifecycleRuleAndOperator {
                tags: vec![tag("env", "prod"), tag("team", "storage")],
                ..LifecycleRuleAndOperator::default()
            }),
            ..LifecycleRuleFilter::default()
        };
        assert_eq!(validate_lifecycle(&config(vec![filter_rule(filter)])), Ok(()));
    }

    #[test]
    fn each_expiration_member_is_accepted_alone() {
        for expiration in [
            LifecycleExpiration {
                days: Some(1),
                ..LifecycleExpiration::default()
            },
            LifecycleExpiration {
                date: Some(Timestamp::from_secs(MIDNIGHT)),
                ..LifecycleExpiration::default()
            },
            LifecycleExpiration {
                expired_object_delete_marker: Some(true),
                ..LifecycleExpiration::default()
            },
        ] {
            let mut entry = rule("logs/");
            entry.expiration = Some(expiration);
            assert_eq!(validate_lifecycle(&config(vec![entry])), Ok(()));
        }
    }

    #[test]
    fn the_rule_cap_and_the_id_cap_are_inclusive() {
        let mut rules: Vec<LifecycleRule> = (0..MAX_LIFECYCLE_RULES).map(|_| rule("logs/")).collect();
        if let Some(first) = rules.first_mut() {
            first.id = Some("i".repeat(MAX_LIFECYCLE_ID_CHARS));
        }
        assert_eq!(validate_lifecycle(&config(rules)), Ok(()));
    }

    #[test]
    fn an_out_of_set_status_passes_on_purpose() {
        // `q-lc-0014`: refusing `enabled` here would refuse a document already on disk the next
        // time it is re-parsed, and the fail-open persistence path turns that into "no rules".
        let mut entry = rule("logs/");
        entry.status = Status::custom("enabled");
        assert_eq!(validate_lifecycle(&config(vec![entry])), Ok(()));
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_the_thousand_and_first_rule_is_refused() {
        let document = config((0..=MAX_LIFECYCLE_RULES).map(|_| rule("logs/")).collect());
        assert_eq!(validate_lifecycle(&document), Err(LifecycleRejection::TooManyRules));
        assert_eq!(LifecycleRejection::TooManyRules.code(), ErrorCode::INVALID_REQUEST);
    }

    #[test]
    fn n_a_rule_with_neither_filter_nor_prefix_is_malformed() {
        let entry = LifecycleRule {
            status: Status::ENABLED,
            ..LifecycleRule::default()
        };
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::ScopeMissing));
        assert_eq!(LifecycleRejection::ScopeMissing.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_two_direct_filter_children_are_malformed() {
        let filter = LifecycleRuleFilter {
            prefix: Some("logs/".to_owned()),
            tag: Some(tag("env", "prod")),
            ..LifecycleRuleFilter::default()
        };
        assert_eq!(
            validate_lifecycle(&config(vec![filter_rule(filter)])),
            Err(LifecycleRejection::FilterNotExclusive)
        );
        assert_eq!(LifecycleRejection::FilterNotExclusive.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_a_size_pair_outside_an_and_is_malformed() {
        // The one pair a client plausibly believes is legal without <And>: a size window.
        let filter = LifecycleRuleFilter {
            object_size_greater_than: Some(1024),
            object_size_less_than: Some(4096),
            ..LifecycleRuleFilter::default()
        };
        assert_eq!(
            validate_lifecycle(&config(vec![filter_rule(filter)])),
            Err(LifecycleRejection::FilterNotExclusive)
        );
    }

    #[test]
    fn n_an_and_with_one_condition_is_malformed() {
        let filter = LifecycleRuleFilter {
            and: Some(LifecycleRuleAndOperator {
                prefix: Some("logs/".to_owned()),
                ..LifecycleRuleAndOperator::default()
            }),
            ..LifecycleRuleFilter::default()
        };
        assert_eq!(
            validate_lifecycle(&config(vec![filter_rule(filter)])),
            Err(LifecycleRejection::AndBelowTwoConditions)
        );
        assert_eq!(LifecycleRejection::AndBelowTwoConditions.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_an_empty_and_is_malformed() {
        let filter = LifecycleRuleFilter {
            and: Some(LifecycleRuleAndOperator::default()),
            ..LifecycleRuleFilter::default()
        };
        assert_eq!(
            validate_lifecycle(&config(vec![filter_rule(filter)])),
            Err(LifecycleRejection::AndBelowTwoConditions)
        );
    }

    #[test]
    fn n_days_and_date_together_are_malformed() {
        let mut entry = rule("logs/");
        entry.expiration = Some(LifecycleExpiration {
            days: Some(30),
            date: Some(Timestamp::from_secs(MIDNIGHT)),
            ..LifecycleExpiration::default()
        });
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::ExpirationConflict));
        assert_eq!(LifecycleRejection::ExpirationConflict.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_a_delete_marker_flag_beside_days_is_malformed_even_when_false() {
        // Presence conflicts, not truth: AWS's constraint is on naming the member at all.
        let mut entry = rule("logs/");
        entry.expiration = Some(LifecycleExpiration {
            days: Some(30),
            expired_object_delete_marker: Some(false),
            ..LifecycleExpiration::default()
        });
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::ExpirationConflict));
    }

    #[test]
    fn n_zero_expiration_days_are_refused_as_invalid_argument() {
        for days in [0, -30] {
            let mut entry = rule("logs/");
            entry.expiration = Some(LifecycleExpiration {
                days: Some(days),
                ..LifecycleExpiration::default()
            });
            assert_eq!(
                validate_lifecycle(&config(vec![entry])),
                Err(LifecycleRejection::ExpirationDaysNotPositive),
                "days = {days}"
            );
        }
        assert_eq!(LifecycleRejection::ExpirationDaysNotPositive.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_an_expiration_date_off_midnight_is_refused() {
        let mut entry = rule("logs/");
        entry.expiration = Some(LifecycleExpiration {
            date: Some(Timestamp::from_secs(MIDNIGHT + 12 * 3600 + 34 * 60 + 56)),
            ..LifecycleExpiration::default()
        });
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::DateNotMidnight));
        assert_eq!(LifecycleRejection::DateNotMidnight.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_a_subsecond_remainder_is_not_midnight() {
        let mut entry = rule("logs/");
        let date = Timestamp::from_secs_nanos(MIDNIGHT, 1).expect("a nanosecond below one second");
        entry.expiration = Some(LifecycleExpiration {
            date: Some(date),
            ..LifecycleExpiration::default()
        });
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::DateNotMidnight));
    }

    #[test]
    fn n_a_transition_date_off_midnight_is_refused() {
        let mut entry = rule("logs/");
        entry.transitions = vec![Transition {
            date: Some(Timestamp::from_secs(MIDNIGHT + 3600)),
            ..Transition::default()
        }];
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::DateNotMidnight));
    }

    #[test]
    fn n_a_pre_epoch_midnight_is_still_midnight_and_an_hour_off_it_is_not() {
        // 1969-12-31T00:00:00Z and 1969-12-31T01:00:00Z: the negative-seconds branch of the
        // midnight rule, where `%` would get the remainder's sign wrong.
        let mut entry = rule("logs/");
        entry.expiration = Some(LifecycleExpiration {
            date: Some(Timestamp::from_secs(-86_400)),
            ..LifecycleExpiration::default()
        });
        assert_eq!(validate_lifecycle(&config(vec![entry])), Ok(()));
        let mut entry = rule("logs/");
        entry.expiration = Some(LifecycleExpiration {
            date: Some(Timestamp::from_secs(-86_400 + 3600)),
            ..LifecycleExpiration::default()
        });
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::DateNotMidnight));
    }

    #[test]
    fn n_an_id_over_the_cap_is_refused_as_invalid_argument() {
        let mut entry = rule("logs/");
        entry.id = Some("i".repeat(MAX_LIFECYCLE_ID_CHARS + 1));
        assert_eq!(validate_lifecycle(&config(vec![entry])), Err(LifecycleRejection::IdTooLong));
        assert_eq!(LifecycleRejection::IdTooLong.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_a_duplicated_id_is_refused_as_invalid_argument() {
        let mut first = rule("logs/");
        first.id = Some("rule-one".to_owned());
        let mut second = rule("tmp/");
        second.id = Some("rule-one".to_owned());
        assert_eq!(validate_lifecycle(&config(vec![first, second])), Err(LifecycleRejection::IdDuplicated));
        assert_eq!(LifecycleRejection::IdDuplicated.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_two_anonymous_rules_are_not_a_duplicate() {
        // Uniqueness binds ids, not their absence: a document with two id-less rules is legal.
        assert_eq!(validate_lifecycle(&config(vec![rule("logs/"), rule("tmp/")])), Ok(()));
    }

    #[test]
    fn n_the_first_broken_rule_decides_the_refusal() {
        // Within one rule the id bound is checked before the scope, so the second rule's long id
        // wins over its missing filter — one deterministic refusal per document.
        let first = rule("logs/");
        let second = LifecycleRule {
            id: Some("i".repeat(MAX_LIFECYCLE_ID_CHARS + 1)),
            status: Status::ENABLED,
            ..LifecycleRule::default()
        };
        assert_eq!(validate_lifecycle(&config(vec![first, second])), Err(LifecycleRejection::IdTooLong));
    }

    #[test]
    fn n_the_status_side_of_each_code_is_the_one_aws_answers() {
        // The family's whole error surface, pinned to the statuses AWS answers.
        assert_eq!(ErrorCode::NO_SUCH_LIFECYCLE_CONFIGURATION.default_status().as_u16(), 404);
        assert_eq!(ErrorCode::INVALID_REQUEST.default_status().as_u16(), 400);
        assert_eq!(ErrorCode::INVALID_ARGUMENT.default_status().as_u16(), 400);
        assert_eq!(ErrorCode::MALFORMED_XML.default_status().as_u16(), 400);
    }
}
