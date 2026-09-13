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

//! The object-lock family's three documents: what a stored one is allowed to say.
//!
//! Shares: object_lock
//! Members: GetObjectLegalHold, GetObjectLockConfiguration, GetObjectRetention,
//!          PutObjectLegalHold, PutObjectLockConfiguration, PutObjectRetention
//!
//! Responsible for: the semantic rules of the `ObjectLockConfiguration`, `Retention` and
//! `LegalHold` documents — the closed `Mode`, `Status` and `ObjectLockEnabled` value sets, the
//! `Days`/`Years` mutex and its ≥1 floor, and the future-only `RetainUntilDate` — held once so
//! that every backend refuses the same documents with the same codes.
//! NOT responsible for: decoding the documents (the generated codecs, which refuse unknown
//! request elements — `q-lock-0014` — and already refuse an empty body, a wrong root and an
//! unreadable timestamp); storing them; or **enforcing** them. Whether a delete or
//! overwrite of a protected object is refused, whether a COMPLIANCE retention may be shortened,
//! and what `x-amz-bypass-governance-retention` actually bypasses are the storage side's
//! decisions — this module's whole contribution is that the intent reaching that code is exactly
//! what the client wrote, decoded conservatively.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade,
//! which re-exports every item here for backends; the `crates/conformance` fixture is the first
//! caller.
//!
//! # Why the value sets are closed here, and where the member sets are closed
//!
//! This is the one family with a legal-compliance meaning, and both failure directions are
//! expensive. Accepting a `Mode` or `Status` outside the documented sets stores a protection
//! promise no enforcement path can read — a client that wrote `ARCHIVE` walks away believing
//! its data is locked. The member sets are closed one layer earlier: the request codecs refuse
//! an unknown element (`q-lock-0014`, ADR-0007 `allow-registered`), because a skipped WORM
//! setting is a 200 for a lock nobody stored. A stored WORM document is a different boundary —
//! a reader that got *stricter* would downgrade it to "none", silently unlocking data — and is
//! read by `rustfs_gateway_types::persistence`, not by these codecs. So the checks below refuse
//! exactly what AWS documents as impossible — an out-of-set enum value, both periods at once, a
//! period under one, a retain-until instant already in the past — and nothing else: a
//! `Retention` carrying only a `Mode` or only a date passes, and a configuration with no
//! `ObjectLockEnabled` passes, because the model marks every member optional and AWS documents
//! no refusal for those shapes.
//!
//! # The clock is an argument
//!
//! `RetainUntilDate` must be in the future *at the moment the retention is applied*
//! (`q-lock-0013`), and "now" is the caller's — the conformance fixture pins it per case, and a
//! production backend passes its own. A validator that read the wall clock itself would be
//! untestable and would smuggle a side effect into a pure rule.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{Mode, ObjectLockConfiguration, ObjectLockLegalHold, ObjectLockRetention};

use crate::contracts::{
    OBJECT_LOCK_BUCKET_STATE_PRECONDITION, OBJECT_LOCK_DEFAULT_EXACTLY_ONE_PERIOD, OBJECT_LOCK_DEFAULT_MIN_PERIOD,
    OBJECT_LOCK_DEFAULT_REQUIRE_MODE, OBJECT_LOCK_ENABLED_VALUES, OBJECT_LOCK_LEGAL_HOLD_VALUES, OBJECT_LOCK_MODE_VALUES,
    OBJECT_LOCK_TEMPORAL_RELATION, ObjectLockBucketStatePrecondition, ObjectLockTemporalRelation,
};

/// Why a decoded object-lock document was refused, with the code AWS answers.
///
/// One rejection type for the family's three documents, carried as data rather than as a
/// rendered error so that a backend outside this workspace can map it into its own error type;
/// [`ObjectLockRejection::code`] and [`ObjectLockRejection::reason`] are the two halves an S3
/// error document needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectLockRejection {
    /// An `ObjectLockEnabled` other than `Enabled` — the only value AWS defines, because object
    /// lock has no wire spelling for "off" (`q-lock-0009`).
    EnabledUnknown,
    /// A retention `Mode` outside {`GOVERNANCE`, `COMPLIANCE`}, exactly in that spelling —
    /// the set is case-sensitive, so `governance` is out of it (`q-lock-0008`).
    ModeUnknown,
    /// A `DefaultRetention` naming both `Days` and `Years`; AWS documents the two as mutually
    /// exclusive (`q-lock-0010`).
    PeriodBoth,
    /// A `DefaultRetention` naming neither period, or naming a period without a mode; AWS
    /// documents the default as requiring both a mode and one period (`q-lock-0010`).
    PeriodOrModeMissing,
    /// A `Days` or `Years` under one (`q-lock-0010`).
    PeriodOutOfRange,
    /// A legal-hold `Status` outside {`ON`, `OFF`}, exactly in that spelling (`q-lock-0011`).
    StatusUnknown,
    /// A `RetainUntilDate` that is not in the future of the caller's clock (`q-lock-0013`).
    RetainUntilNotInFuture,
}

impl ObjectLockRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // Schema violations: a closed value set left, or a member combination the published
            // schema does not admit.
            ObjectLockRejection::EnabledUnknown
            | ObjectLockRejection::ModeUnknown
            | ObjectLockRejection::PeriodBoth
            | ObjectLockRejection::PeriodOrModeMissing
            | ObjectLockRejection::StatusUnknown => ErrorCode::MALFORMED_XML,
            // Well-formed values outside their documented range.
            ObjectLockRejection::PeriodOutOfRange | ObjectLockRejection::RetainUntilNotInFuture => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation, never built from request bytes.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            ObjectLockRejection::EnabledUnknown => "ObjectLockEnabled must be Enabled",
            ObjectLockRejection::ModeUnknown => "Mode must be GOVERNANCE or COMPLIANCE",
            ObjectLockRejection::PeriodBoth => "DefaultRetention cannot specify Days and Years at the same time",
            ObjectLockRejection::PeriodOrModeMissing => "DefaultRetention requires a Mode and either Days or Years",
            ObjectLockRejection::PeriodOutOfRange => "the retention period must be at least one day or one year",
            ObjectLockRejection::StatusUnknown => "Status must be ON or OFF",
            ObjectLockRejection::RetainUntilNotInFuture => "the retain until date must be in the future",
        }
    }
}

/// Whether a retention mode is one of the two the model declares.
///
/// Spelled as two comparisons rather than `Mode::is_known()` on purpose: the generated `Mode`
/// enum is shared by wire-member name across every family that binds a `Mode`, so a model
/// re-pin that adds a value to some other family's member would silently widen `is_known()` —
/// and with it, what a lock document may say. The two constants cannot drift that way.
fn mode_is_documented(mode: &Mode) -> bool {
    OBJECT_LOCK_MODE_VALUES.contains(&mode.as_str())
}

/// Whether object-level lock writes require object lock to be enabled on the bucket.
///
/// Adapters call this before storing retention or legal-hold state; the answer is generated from
/// the typed `bucket_state_precondition` contract rather than repeated in each backend.
#[must_use]
pub const fn object_lock_requires_enabled_bucket() -> bool {
    matches!(OBJECT_LOCK_BUCKET_STATE_PRECONDITION, ObjectLockBucketStatePrecondition::RequireEnabled)
}

/// Checks a decoded bucket lock configuration, first refusal wins.
///
/// Members are checked in wire order — `ObjectLockEnabled`, then the rule's `Mode`, then its
/// periods — so the same document is refused for the same reason on every backend. A
/// configuration with no `ObjectLockEnabled`, or no `Rule` at all, passes: the model marks both
/// optional, and refusing what AWS accepts would strand stored documents.
///
/// # Errors
///
/// [`ObjectLockRejection`] naming the first rule the document breaks.
pub fn validate_lock_configuration(configuration: &ObjectLockConfiguration) -> Result<(), ObjectLockRejection> {
    if let Some(enabled) = &configuration.object_lock_enabled
        && !OBJECT_LOCK_ENABLED_VALUES.contains(&enabled.as_str())
    {
        return Err(ObjectLockRejection::EnabledUnknown);
    }
    if let Some(retention) = configuration.rule.as_ref().and_then(|rule| rule.default_retention.as_ref()) {
        match &retention.mode {
            Some(mode) if !mode_is_documented(mode) => return Err(ObjectLockRejection::ModeUnknown),
            // AWS documents the default as requiring both a mode and a period.
            None if OBJECT_LOCK_DEFAULT_REQUIRE_MODE => return Err(ObjectLockRejection::PeriodOrModeMissing),
            None => {}
            Some(_) => {}
        }
        match (retention.days, retention.years) {
            (Some(_), Some(_)) if OBJECT_LOCK_DEFAULT_EXACTLY_ONE_PERIOD => return Err(ObjectLockRejection::PeriodBoth),
            (None, None) if OBJECT_LOCK_DEFAULT_EXACTLY_ONE_PERIOD => {
                return Err(ObjectLockRejection::PeriodOrModeMissing);
            }
            (Some(period), None) | (None, Some(period)) if period < OBJECT_LOCK_DEFAULT_MIN_PERIOD => {
                return Err(ObjectLockRejection::PeriodOutOfRange);
            }
            _ => {}
        }
    }
    Ok(())
}

/// Checks a decoded retention document against the caller's clock, first refusal wins.
///
/// `now_unix_seconds` is the instant the write is being applied; the retain-until instant must
/// be strictly after it. A document carrying only a `Mode`, only a `RetainUntilDate`, or
/// neither passes on purpose: the model marks both members optional and AWS documents no
/// refusal for the partial shapes, so refusing them here would be stricter than the schema the
/// document was written to.
///
/// # Errors
///
/// [`ObjectLockRejection`] naming the first rule the document breaks.
pub fn validate_retention(retention: &ObjectLockRetention, now_unix_seconds: i64) -> Result<(), ObjectLockRejection> {
    if let Some(mode) = &retention.mode
        && !mode_is_documented(mode)
    {
        return Err(ObjectLockRejection::ModeUnknown);
    }
    if let Some(until) = &retention.retain_until_date {
        // Strictly after: an instant equal to "now" has already stopped protecting anything.
        let future = match OBJECT_LOCK_TEMPORAL_RELATION {
            ObjectLockTemporalRelation::StrictlyFuture => {
                until.secs() > now_unix_seconds || (until.secs() == now_unix_seconds && until.subsec_nanos() > 0)
            }
            ObjectLockTemporalRelation::AllowAny => true,
        };
        if !future {
            return Err(ObjectLockRejection::RetainUntilNotInFuture);
        }
    }
    Ok(())
}

/// Checks a decoded legal-hold document.
///
/// The `Status` set is closed by comparison against the two documented constants rather than by
/// `Status::is_known()`: the generated `Status` enum is shared with the lifecycle family's
/// `Enabled`/`Disabled` member of the same wire name, so `is_known()` would accept a legal hold
/// of `Enabled` — a value no enforcement path reads, stored as a hold nobody can lift.
///
/// # Errors
///
/// [`ObjectLockRejection::StatusUnknown`] for a status outside {`ON`, `OFF`}.
pub fn validate_legal_hold(legal_hold: &ObjectLockLegalHold) -> Result<(), ObjectLockRejection> {
    if let Some(status) = &legal_hold.status
        && !OBJECT_LOCK_LEGAL_HOLD_VALUES.contains(&status.as_str())
    {
        return Err(ObjectLockRejection::StatusUnknown);
    }
    Ok(())
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `encryption`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use rustfs_gateway_types::Timestamp;
    use rustfs_gateway_types::dto::{DefaultRetention, ObjectLockEnabled, ObjectLockRule, Status};

    /// A fixed "now" for the clock-dependent checks: 2026-01-01T00:00:00Z.
    const NOW: i64 = 1_767_225_600;

    fn config(enabled: Option<ObjectLockEnabled>, retention: Option<DefaultRetention>) -> ObjectLockConfiguration {
        ObjectLockConfiguration {
            object_lock_enabled: enabled,
            rule: retention.map(|default_retention| ObjectLockRule {
                default_retention: Some(default_retention),
            }),
        }
    }

    fn default_retention(mode: Mode, days: Option<i32>, years: Option<i32>) -> DefaultRetention {
        DefaultRetention {
            mode: Some(mode),
            days,
            years,
        }
    }

    // ── positive ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn an_enabled_only_configuration_passes() {
        assert_eq!(validate_lock_configuration(&config(Some(ObjectLockEnabled::ENABLED), None)), Ok(()));
    }

    #[test]
    fn a_governance_days_default_and_a_compliance_years_default_both_pass() {
        for retention in [
            default_retention(Mode::GOVERNANCE, Some(30), None),
            default_retention(Mode::COMPLIANCE, None, Some(1)),
        ] {
            assert_eq!(
                validate_lock_configuration(&config(Some(ObjectLockEnabled::ENABLED), Some(retention))),
                Ok(())
            );
        }
    }

    #[test]
    fn a_configuration_with_no_enabled_member_passes_because_the_model_makes_it_optional() {
        // Refusing it would be stricter than the schema the stored document was written to.
        assert_eq!(
            validate_lock_configuration(&config(None, Some(default_retention(Mode::GOVERNANCE, Some(1), None)))),
            Ok(())
        );
    }

    #[test]
    fn a_retention_with_both_members_in_the_future_passes() {
        let retention = ObjectLockRetention {
            mode: Some(Mode::COMPLIANCE),
            retain_until_date: Some(Timestamp::from_secs(NOW + 1)),
        };
        assert_eq!(validate_retention(&retention, NOW), Ok(()));
    }

    #[test]
    fn a_partial_retention_passes_because_the_model_marks_both_members_optional() {
        let mode_only = ObjectLockRetention {
            mode: Some(Mode::GOVERNANCE),
            retain_until_date: None,
        };
        let date_only = ObjectLockRetention {
            mode: None,
            retain_until_date: Some(Timestamp::from_secs(NOW + 60)),
        };
        assert_eq!(validate_retention(&mode_only, NOW), Ok(()));
        assert_eq!(validate_retention(&date_only, NOW), Ok(()));
    }

    #[test]
    fn both_documented_hold_statuses_pass() {
        for status in [Status::ON, Status::OFF] {
            assert_eq!(validate_legal_hold(&ObjectLockLegalHold { status: Some(status) }), Ok(()));
        }
    }

    // ── negative ─────────────────────────────────────────────────────────────────────────────

    #[test]
    fn n_a_disabled_spelling_is_refused_as_malformed_xml() {
        for spelling in ["Disabled", "enabled", ""] {
            let document = config(Some(ObjectLockEnabled::custom(spelling.to_owned())), None);
            assert_eq!(
                validate_lock_configuration(&document),
                Err(ObjectLockRejection::EnabledUnknown),
                "spelling = {spelling:?}"
            );
        }
        assert_eq!(ObjectLockRejection::EnabledUnknown.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_an_out_of_set_default_mode_is_refused_case_sensitively() {
        for spelling in ["governance", "ARCHIVE", "Compliance", ""] {
            let retention = default_retention(Mode::custom(spelling.to_owned()), Some(30), None);
            assert_eq!(
                validate_lock_configuration(&config(Some(ObjectLockEnabled::ENABLED), Some(retention))),
                Err(ObjectLockRejection::ModeUnknown),
                "spelling = {spelling:?}"
            );
        }
        assert_eq!(ObjectLockRejection::ModeUnknown.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_days_and_years_together_are_refused() {
        let retention = default_retention(Mode::GOVERNANCE, Some(30), Some(1));
        assert_eq!(
            validate_lock_configuration(&config(Some(ObjectLockEnabled::ENABLED), Some(retention))),
            Err(ObjectLockRejection::PeriodBoth)
        );
        assert_eq!(ObjectLockRejection::PeriodBoth.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_a_default_with_neither_period_is_refused() {
        let retention = default_retention(Mode::GOVERNANCE, None, None);
        assert_eq!(
            validate_lock_configuration(&config(Some(ObjectLockEnabled::ENABLED), Some(retention))),
            Err(ObjectLockRejection::PeriodOrModeMissing)
        );
    }

    #[test]
    fn n_a_default_with_a_period_and_no_mode_is_refused() {
        let retention = DefaultRetention {
            mode: None,
            days: Some(30),
            years: None,
        };
        assert_eq!(
            validate_lock_configuration(&config(Some(ObjectLockEnabled::ENABLED), Some(retention))),
            Err(ObjectLockRejection::PeriodOrModeMissing)
        );
    }

    #[test]
    fn n_a_period_under_one_is_refused_as_invalid_argument() {
        for (days, years) in [(Some(0), None), (None, Some(0)), (Some(-1), None), (None, Some(-1))] {
            let retention = default_retention(Mode::GOVERNANCE, days, years);
            assert_eq!(
                validate_lock_configuration(&config(Some(ObjectLockEnabled::ENABLED), Some(retention))),
                Err(ObjectLockRejection::PeriodOutOfRange),
                "days = {days:?}, years = {years:?}"
            );
        }
        assert_eq!(ObjectLockRejection::PeriodOutOfRange.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_the_enabled_check_wins_over_a_broken_default() {
        // Both checks broken in one document: members are checked in wire order, so the refusal
        // is deterministic.
        let retention = default_retention(Mode::custom("ARCHIVE"), Some(0), Some(0));
        assert_eq!(
            validate_lock_configuration(&config(Some(ObjectLockEnabled::custom("Disabled")), Some(retention))),
            Err(ObjectLockRejection::EnabledUnknown)
        );
    }

    #[test]
    fn n_an_out_of_set_retention_mode_is_refused() {
        for spelling in ["governance", "compliance", "LEGAL"] {
            let retention = ObjectLockRetention {
                mode: Some(Mode::custom(spelling.to_owned())),
                retain_until_date: Some(Timestamp::from_secs(NOW + 60)),
            };
            assert_eq!(
                validate_retention(&retention, NOW),
                Err(ObjectLockRejection::ModeUnknown),
                "spelling = {spelling:?}"
            );
        }
    }

    #[test]
    fn n_a_retain_until_in_the_past_or_present_is_refused() {
        for instant in [NOW - 1, NOW, 0, -1] {
            let retention = ObjectLockRetention {
                mode: Some(Mode::GOVERNANCE),
                retain_until_date: Some(Timestamp::from_secs(instant)),
            };
            assert_eq!(
                validate_retention(&retention, NOW),
                Err(ObjectLockRejection::RetainUntilNotInFuture),
                "instant = {instant}"
            );
        }
        assert_eq!(ObjectLockRejection::RetainUntilNotInFuture.code(), ErrorCode::INVALID_ARGUMENT);
    }

    #[test]
    fn n_the_mode_check_wins_over_a_past_date() {
        let retention = ObjectLockRetention {
            mode: Some(Mode::custom("ARCHIVE")),
            retain_until_date: Some(Timestamp::from_secs(NOW - 1)),
        };
        assert_eq!(validate_retention(&retention, NOW), Err(ObjectLockRejection::ModeUnknown));
    }

    #[test]
    fn n_an_out_of_set_hold_status_is_refused_case_sensitively() {
        for spelling in ["on", "off", "HOLD", ""] {
            let hold = ObjectLockLegalHold {
                status: Some(Status::custom(spelling.to_owned())),
            };
            assert_eq!(
                validate_legal_hold(&hold),
                Err(ObjectLockRejection::StatusUnknown),
                "spelling = {spelling:?}"
            );
        }
        assert_eq!(ObjectLockRejection::StatusUnknown.code(), ErrorCode::MALFORMED_XML);
    }

    #[test]
    fn n_the_lifecycle_statuses_the_shared_enum_carries_are_not_legal_hold_values() {
        // The generated `Status` enum is shared by wire name with the lifecycle family, so its
        // `is_known()` admits `Enabled` and `Disabled`. This validator must not.
        for status in [Status::ENABLED, Status::DISABLED] {
            assert_eq!(
                validate_legal_hold(&ObjectLockLegalHold { status: Some(status) }),
                Err(ObjectLockRejection::StatusUnknown)
            );
        }
    }

    #[test]
    fn n_no_reason_is_empty_and_every_code_maps_to_a_400() {
        for rejection in [
            ObjectLockRejection::EnabledUnknown,
            ObjectLockRejection::ModeUnknown,
            ObjectLockRejection::PeriodBoth,
            ObjectLockRejection::PeriodOrModeMissing,
            ObjectLockRejection::PeriodOutOfRange,
            ObjectLockRejection::StatusUnknown,
            ObjectLockRejection::RetainUntilNotInFuture,
        ] {
            assert!(!rejection.reason().is_empty());
            assert_eq!(rejection.code().default_status().as_u16(), 400, "{rejection:?}");
        }
    }

    #[test]
    fn n_the_not_configured_codes_answer_404_and_stay_distinct() {
        // The family's two unconfigured answers: bucket-level and object-level are different
        // codes, and clients branch on the difference (q-lock-0001 … q-lock-0003).
        assert_eq!(ErrorCode::OBJECT_LOCK_CONFIGURATION_NOT_FOUND.default_status().as_u16(), 404);
        assert_eq!(ErrorCode::NO_SUCH_OBJECT_LOCK_CONFIGURATION.default_status().as_u16(), 404);
        assert_ne!(
            ErrorCode::OBJECT_LOCK_CONFIGURATION_NOT_FOUND,
            ErrorCode::NO_SUCH_OBJECT_LOCK_CONFIGURATION
        );
    }
}
