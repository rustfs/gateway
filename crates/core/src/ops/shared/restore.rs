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

//! What a retrieval request may ask for, which status each outcome answers, and how the state of
//! a copy is spelled on the wire.
//!
//! Shares: restore
//! Members: RestoreObject
//!
//! Responsible for: the semantic rules of a `RestoreRequest` — the two documented forms and the
//! members that may not cross between them, the closed `Tier` set, the `Days` floor; the
//! [`RestoreState`] → status mapping, which is the only place the difference between a `202` and
//! a `200` is written down; and [`RestoreStatus`], the structured `x-amz-restore` header, both
//! rendered and parsed by one pair of functions so the two spellings cannot drift.
//! NOT responsible for: **performing** a retrieval. Which tier a backend has, how long it takes,
//! what a restored copy costs and when it lapses are the storage side's, and nothing here waits,
//! schedules or expires anything. Nor for producing `x-amz-restore` on a read or a head: the
//! header belongs to those encoders, and this module gives them the one renderer to call.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`; [`super::select`], for the
//! query members a select-on-restore nests. Downstream: the facade, which re-exports every item
//! here; `crates/conformance`'s fixture is the first caller.
//!
//! # Why the status is data here rather than a number in a handler
//!
//! A restore has four outcomes and two of them are successes. A first retrieval is `202`; a
//! repeat against a copy that is already back is `200`; a repeat while one is running is `409`;
//! and a request against an object that was never archived is `403`. A client polls on the
//! difference between the first two — `202` means "not yet", `200` means "it is here" — so a
//! backend that answered whichever it felt like would break the poll loop while returning a
//! perfectly ordinary success. Statuses in the success family are the ones a status assertion is
//! least likely to catch, which is why the mapping is a function of the state and the state is
//! all a handler gets to choose.
//!
//! # Why the header is a type and not a `format!`
//!
//! `x-amz-restore` is one of the few S3 headers with internal structure: two quoted values, a
//! comma, exactly one space, and an RFC 1123 date inside the quotes. Every one of those is
//! load-bearing — an SDK parses the header by that grammar — and every one is the kind of detail
//! that a second `format!` somewhere else spells differently. So there is one renderer, one
//! parser, and a round-trip test that runs both.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{RestoreRequest, Tier, Type};

use super::select::{SelectRejection, validate_select};
use crate::contracts::{
    RESTORE_ALREADY_RESTORED_OUTCOME, RESTORE_DAYS_MINIMUM, RESTORE_DAYS_SELECT_EXCLUSION, RESTORE_DIRECT_TIER_VALUE_SET,
    RESTORE_FORM_PRESENCE, RESTORE_GLACIER_TIER_VALUE_SET, RESTORE_HEADER_ABSENCE, RESTORE_HEADER_ONGOING_FORM,
    RESTORE_HEADER_PARSE_GRAMMAR, RESTORE_HEADER_RESTORED_FORM, RESTORE_IN_PROGRESS_OUTCOME, RESTORE_INITIATED_OUTCOME,
    RESTORE_NESTED_SELECT_VALIDATION, RESTORE_NOT_ARCHIVED_OUTCOME, RESTORE_SELECT_MEMBERS_REQUIRE_TYPE,
    RESTORE_SELECT_OUTPUT_REQUIRED, RESTORE_SELECT_PARAMETERS_REQUIRED, RESTORE_TYPE_VALUE_SET,
    RestoreAlreadyRestoredOutcomePolicy, RestoreDaysMinimumPolicy, RestoreDaysSelectExclusionPolicy,
    RestoreDirectTierValueSetPolicy, RestoreFormPresencePolicy, RestoreGlacierTierValueSetPolicy, RestoreHeaderAbsencePolicy,
    RestoreHeaderOngoingFormPolicy, RestoreHeaderParseGrammarPolicy, RestoreHeaderRestoredFormPolicy,
    RestoreInProgressOutcomePolicy, RestoreInitiatedOutcomePolicy, RestoreNestedSelectValidationPolicy,
    RestoreNotArchivedOutcomePolicy, RestoreSelectMembersRequireTypePolicy, RestoreSelectOutputRequiredPolicy,
    RestoreSelectParametersRequiredPolicy, RestoreTypeValueSetPolicy,
};

/// The number of days a restored copy may be asked to stay available, at minimum.
///
/// One. A zero-day retrieval has no representable meaning: the copy would lapse at the instant
/// it appeared.
pub const MIN_RESTORE_DAYS: i32 = match RESTORE_DAYS_MINIMUM {
    RestoreDaysMinimumPolicy::Min1 => 1,
    RestoreDaysMinimumPolicy::Min0 => 0,
};

/// The state a retrieval request found the object copy in.
///
/// The four documented outcomes, and nothing else — a backend picks one of these and the status
/// follows. There is deliberately no `Other`: a state this enum cannot name is a state whose
/// status nobody has decided, and inventing one at the call site is how the poll loop breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreState {
    /// No retrieval was running and the copy was not already back: one has now been started.
    Initiated,
    /// A retrieval finished earlier and the copy is readable now.
    AlreadyRestored,
    /// A retrieval is running and has not finished.
    InProgress,
    /// The object is not in an archive storage class, so there is nothing to retrieve.
    NotArchived,
}

impl RestoreState {
    /// The status this state answers, or `None` when the state is a refusal.
    ///
    /// The two success statuses live here and nowhere else. `RestoreObject::ALT_SUCCESS_STATUSES`
    /// declares the second of them, and `crates/core/tests/params_and_dispatch.rs` asserts the two
    /// agree in both directions — a declared alternative no state produces is as wrong as a state
    /// whose status is undeclared.
    #[must_use]
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::Initiated => match RESTORE_INITIATED_OUTCOME {
                RestoreInitiatedOutcomePolicy::Success202 => Some(202),
                RestoreInitiatedOutcomePolicy::Success200 => Some(200),
            },
            Self::AlreadyRestored => match RESTORE_ALREADY_RESTORED_OUTCOME {
                RestoreAlreadyRestoredOutcomePolicy::Success200 => Some(200),
                RestoreAlreadyRestoredOutcomePolicy::Success202 => Some(202),
            },
            Self::InProgress => match RESTORE_IN_PROGRESS_OUTCOME {
                RestoreInProgressOutcomePolicy::RestoreAlreadyInProgress => None,
                RestoreInProgressOutcomePolicy::Success202 => Some(202),
            },
            Self::NotArchived => match RESTORE_NOT_ARCHIVED_OUTCOME {
                RestoreNotArchivedOutcomePolicy::InvalidObjectState => None,
                RestoreNotArchivedOutcomePolicy::SuccessNoop => Some(200),
            },
        }
    }

    /// The error code this state answers, or `None` when the state is a success.
    ///
    /// The exact complement of [`RestoreState::status`], which is asserted rather than assumed:
    /// a state that answered both, or neither, would be a state with no answer at all.
    #[must_use]
    pub const fn error(self) -> Option<ErrorCode> {
        match self {
            Self::Initiated | Self::AlreadyRestored => None,
            Self::InProgress => match RESTORE_IN_PROGRESS_OUTCOME {
                RestoreInProgressOutcomePolicy::RestoreAlreadyInProgress => Some(ErrorCode::RESTORE_ALREADY_IN_PROGRESS),
                RestoreInProgressOutcomePolicy::Success202 => None,
            },
            Self::NotArchived => match RESTORE_NOT_ARCHIVED_OUTCOME {
                RestoreNotArchivedOutcomePolicy::InvalidObjectState => Some(ErrorCode::INVALID_OBJECT_STATE),
                RestoreNotArchivedOutcomePolicy::SuccessNoop => None,
            },
        }
    }

    /// A constant explanation for the two refusals.
    #[must_use]
    pub const fn reason(self) -> Option<&'static str> {
        match self {
            Self::Initiated | Self::AlreadyRestored => None,
            Self::InProgress => match RESTORE_IN_PROGRESS_OUTCOME {
                RestoreInProgressOutcomePolicy::RestoreAlreadyInProgress => Some("Object restore is already in progress"),
                RestoreInProgressOutcomePolicy::Success202 => None,
            },
            Self::NotArchived => match RESTORE_NOT_ARCHIVED_OUTCOME {
                RestoreNotArchivedOutcomePolicy::InvalidObjectState => {
                    Some("The operation is not valid for the storage class of this object")
                }
                RestoreNotArchivedOutcomePolicy::SuccessNoop => None,
            },
        }
    }
}

/// The state of one object copy, as `x-amz-restore` spells it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreStatus {
    /// Whether a retrieval is still running.
    pub ongoing: bool,
    /// When the restored copy lapses, as an RFC 1123 date, present only once it is back.
    ///
    /// Carried as the wire string rather than as an instant on purpose: this header is asserted
    /// byte for byte, and a round trip through a date type would re-render it in whatever form
    /// that type prefers.
    pub expiry_date: Option<String>,
}

impl RestoreStatus {
    /// A copy whose retrieval is still running.
    #[must_use]
    pub const fn ongoing() -> Self {
        Self {
            ongoing: true,
            expiry_date: None,
        }
    }

    /// A copy that is back, and lapses at `expiry_date`.
    #[must_use]
    pub fn restored(expiry_date: impl Into<String>) -> Self {
        Self {
            ongoing: false,
            expiry_date: Some(expiry_date.into()),
        }
    }
}

/// Renders `x-amz-restore`, byte for byte.
///
/// `ongoing-request="true"` while a retrieval runs; `ongoing-request="false", expiry-date="<RFC
/// 1123>"` once it is back. The comma, the single space and both pairs of quotes are the
/// grammar, not formatting.
#[must_use]
pub fn format_restore_status(status: &RestoreStatus) -> String {
    match &status.expiry_date {
        Some(expiry) => match RESTORE_HEADER_RESTORED_FORM {
            RestoreHeaderRestoredFormPolicy::QuotedFalseCommaSpaceExpiry => {
                format!("ongoing-request=\"false\", expiry-date=\"{expiry}\"")
            }
            RestoreHeaderRestoredFormPolicy::CommaWithoutSpace => {
                format!("ongoing-request=\"false\",expiry-date=\"{expiry}\"")
            }
        },
        None => match RESTORE_HEADER_ONGOING_FORM {
            RestoreHeaderOngoingFormPolicy::QuotedTrue => {
                let ongoing = if status.ongoing { "true" } else { "false" };
                format!("ongoing-request=\"{ongoing}\"")
            }
            RestoreHeaderOngoingFormPolicy::UnquotedTrue => {
                let ongoing = if status.ongoing { "true" } else { "false" };
                format!("ongoing-request={ongoing}")
            }
        },
    }
}

/// Renders the optional `x-amz-restore` header.
///
/// `None` means the object has no restore state and therefore no header. This function is the
/// single consumer of that absence policy, so an adapter does not have to duplicate it.
#[must_use]
pub fn format_optional_restore_status(status: Option<&RestoreStatus>) -> Option<String> {
    match (RESTORE_HEADER_ABSENCE, status) {
        (_, Some(status)) => Some(format_restore_status(status)),
        (RestoreHeaderAbsencePolicy::Omit, None) => None,
        (RestoreHeaderAbsencePolicy::EmitDefault, None) => Some(format_restore_status(&RestoreStatus {
            ongoing: false,
            expiry_date: None,
        })),
    }
}

/// Reads `x-amz-restore` back.
///
/// Untrusted input: this is a header a peer sends, so every shape that is not the grammar is a
/// `None` rather than a partial reading. In particular a missing quote, a missing comma, a
/// second pair this side does not know, an `ongoing-request` that is not `true` or `false`, and
/// a header past [`MAX_RESTORE_HEADER_BYTES`] are all refused — never guessed, and never
/// resolved to "restored", which would tell a caller its data is readable when it is not.
///
/// The pairs are **not** found by splitting on the separator, because the expiry date contains
/// the separator: `Fri, 21 Dec 2012 00:00:00 GMT` carries a comma and a space of its own, and a
/// parser that split on `", "` cuts the date in half and then refuses the header it was given.
/// Each value is read to its closing quote instead, and the separator is only looked for outside
/// one.
#[must_use]
pub fn parse_restore_status(value: &str) -> Option<RestoreStatus> {
    if !restore_header_within_limit(value.len()) {
        return None;
    }
    if matches!(RESTORE_HEADER_PARSE_GRAMMAR, RestoreHeaderParseGrammarPolicy::AcceptUnquoted) {
        return match value {
            "ongoing-request=true" => Some(RestoreStatus::ongoing()),
            "ongoing-request=false" => Some(RestoreStatus {
                ongoing: false,
                expiry_date: None,
            }),
            _ => parse_strict_restore_status(value),
        };
    }
    parse_strict_restore_status(value)
}

const fn restore_header_within_limit(length: usize) -> bool {
    length <= MAX_RESTORE_HEADER_BYTES
}

fn parse_strict_restore_status(value: &str) -> Option<RestoreStatus> {
    let (ongoing, rest) = quoted_pair(value, "ongoing-request=")?;
    let ongoing = match ongoing {
        "true" => true,
        "false" => false,
        _ => return None,
    };
    if rest.is_empty() {
        return Some(RestoreStatus {
            ongoing,
            expiry_date: None,
        });
    }
    let (expiry, rest) = quoted_pair(rest.strip_prefix(", ")?, "expiry-date=")?;
    // Anything after the second pair is a header this side does not understand; reporting the
    // first two as though that were the whole of it is the guess this parser exists not to make.
    if !rest.is_empty() {
        return None;
    }
    // "Still running" and "lapses at" are contradictory: AWS writes the date only once the copy
    // is back, and a header that carries both is not one this side can act on.
    if ongoing {
        return None;
    }
    if !is_imf_fixdate(expiry) {
        return None;
    }
    Some(RestoreStatus {
        ongoing,
        expiry_date: Some(expiry.to_owned()),
    })
}

/// Whether `value` is the IMF-fixdate spelling required by HTTP response headers.
///
/// This deliberately validates the calendar as well as the punctuation. Accepting a string that
/// merely has commas in the expected places would turn an impossible expiry into a restored copy
/// that no caller can schedule or compare.
fn is_imf_fixdate(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 29
        || bytes.get(3) != Some(&b',')
        || bytes.get(4) != Some(&b' ')
        || bytes.get(7) != Some(&b' ')
        || bytes.get(11) != Some(&b' ')
        || bytes.get(16) != Some(&b' ')
        || bytes.get(19) != Some(&b':')
        || bytes.get(22) != Some(&b':')
        || bytes.get(25) != Some(&b' ')
        || bytes.get(26..) != Some(b"GMT")
    {
        return false;
    }
    let weekday = bytes.get(..3);
    if !matches!(weekday, Some(b"Mon" | b"Tue" | b"Wed" | b"Thu" | b"Fri" | b"Sat" | b"Sun")) {
        return false;
    }
    let Some(day) = decimal(bytes.get(5..7)) else { return false };
    let Some(year) = decimal(bytes.get(12..16)) else { return false };
    let Some(hour) = decimal(bytes.get(17..19)) else { return false };
    let Some(minute) = decimal(bytes.get(20..22)) else { return false };
    let Some(second) = decimal(bytes.get(23..25)) else { return false };
    let month_days = match bytes.get(8..11) {
        Some(b"Jan" | b"Mar" | b"May" | b"Jul" | b"Aug" | b"Oct" | b"Dec") => 31,
        Some(b"Apr" | b"Jun" | b"Sep" | b"Nov") => 30,
        Some(b"Feb") if is_leap_year(year) => 29,
        Some(b"Feb") => 28,
        _ => return false,
    };
    (1..=month_days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

fn decimal(bytes: Option<&[u8]>) -> Option<u32> {
    let bytes = bytes?;
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes
        .iter()
        .try_fold(0_u32, |value, digit| value.checked_mul(10)?.checked_add(u32::from(*digit - b'0')))
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Reads `<name>"<value>"` off the front of `input`, returning the value and what follows.
///
/// The value ends at the first closing quote, which is what makes a comma inside it harmless and
/// an escaped quote impossible: AWS writes neither a quote nor a backslash inside either field,
/// so a value containing one is refused rather than unescaped by a rule nobody published.
fn quoted_pair<'a>(input: &'a str, name: &str) -> Option<(&'a str, &'a str)> {
    let body = input.strip_prefix(name)?.strip_prefix('"')?;
    let end = body.find('"')?;
    let value = body.get(..end)?;
    if value.contains('\\') {
        return None;
    }
    Some((value, body.get(end + 1..)?))
}

/// The longest `x-amz-restore` this parser will look at.
///
/// The grammar's longest legal spelling is well under a hundred bytes. The bound is here so a
/// peer cannot make the split-and-scan above walk a megabyte of header.
pub const MAX_RESTORE_HEADER_BYTES: usize = 256;

/// Why a decoded `RestoreRequest` was refused, with the code AWS answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreRejection {
    /// A `Days` below [`MIN_RESTORE_DAYS`].
    DaysTooSmall,
    /// A document that is neither an ordinary retrieval nor a select-on-restore.
    FormMissing,
    /// `Days` beside `Type SELECT`: the select form has no active-copy lifetime.
    DaysWithSelect,
    /// `SelectParameters` or `OutputLocation` without `Type SELECT`.
    SelectMembersWithoutSelectType,
    /// `Type SELECT` without the two members that form requires.
    SelectFormIncomplete,
    /// A `Type` value other than the one documented select form.
    TypeUnknown,
    /// A `Tier` outside the documented three-value set, on either spelling of the member.
    TierUnknown,
    /// The nested `SelectParameters` broke one of the query rules.
    Select(SelectRejection),
}

impl RestoreRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // Well-formed values that cannot describe a retrieval.
            Self::DaysTooSmall | Self::TierUnknown | Self::TypeUnknown => ErrorCode::INVALID_ARGUMENT,
            // A document that does not match either published shape.
            Self::FormMissing | Self::SelectFormIncomplete => ErrorCode::MALFORMED_XML,
            // Two shapes crossed: the members are individually legal and cannot appear together.
            Self::DaysWithSelect | Self::SelectMembersWithoutSelectType => ErrorCode::INVALID_REQUEST,
            // The nested query keeps its own code, so a select-on-restore with a bad expression
            // type answers InvalidExpressionType exactly as a plain select does.
            Self::Select(inner) => inner.code(),
        }
    }

    /// A constant explanation, never built from request bytes — and in particular never carrying
    /// a character of the nested expression.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::DaysTooSmall => "Days must be at least 1",
            Self::FormMissing => "RestoreRequest must specify Days, or Type SELECT with SelectParameters and OutputLocation",
            Self::DaysWithSelect => "Days must not be specified for a SELECT restore",
            Self::SelectMembersWithoutSelectType => "SelectParameters and OutputLocation require Type SELECT",
            Self::SelectFormIncomplete => "A SELECT restore requires both SelectParameters and OutputLocation",
            Self::TypeUnknown => "Type must be SELECT when it is present",
            Self::TierUnknown => "Tier must be one of Expedited, Standard or Bulk",
            Self::Select(inner) => inner.reason(),
        }
    }

    /// Renders the refusal while preserving the nested expression's secret-flow contract.
    #[must_use]
    pub fn reason_with_expression(&self, expression: Option<&str>) -> String {
        match (self, expression) {
            (Self::Select(inner), Some(expression)) => inner.reason_with_expression(expression),
            _ => self.reason().to_owned(),
        }
    }
}

/// Checks a decoded `RestoreRequest` against the family's semantic rules, first refusal wins.
///
/// The two documented forms are checked as forms rather than member by member, because that is
/// what they are: `Days` describes how long an active copy survives and has no meaning for a
/// select, whose answer is written to an `OutputLocation` instead. A document that mixes them
/// has not asked for either retrieval, and picking one would run the retrieval the caller did
/// not describe.
///
/// # Errors
///
/// [`RestoreRejection`] naming the first rule the document breaks, in a fixed order: tiers,
/// then the form, then the nested query.
pub fn validate_restore(request: &RestoreRequest) -> Result<(), RestoreRejection> {
    // Both spellings of the tier, checked before the form: an unusable tier is an unusable
    // retrieval whichever form asked for it.
    if let Some(tier) = &request.tier
        && matches!(RESTORE_DIRECT_TIER_VALUE_SET, RestoreDirectTierValueSetPolicy::ExpeditedStandardBulk)
        && !is_known_tier(tier)
    {
        return Err(RestoreRejection::TierUnknown);
    }
    if let Some(parameters) = &request.glacier_job_parameters
        && matches!(RESTORE_GLACIER_TIER_VALUE_SET, RestoreGlacierTierValueSetPolicy::ExpeditedStandardBulk)
        && !is_known_tier(&parameters.tier)
    {
        return Err(RestoreRejection::TierUnknown);
    }

    let select_form = request.r#type.as_ref().is_some_and(|kind| *kind == Type::SELECT);
    if request.r#type.is_some() && !select_form && matches!(RESTORE_TYPE_VALUE_SET, RestoreTypeValueSetPolicy::SelectOnly) {
        return Err(RestoreRejection::TypeUnknown);
    }
    let select_members = request.select_parameters.is_some() || request.output_location.is_some();

    if select_form {
        if request.days.is_some() && matches!(RESTORE_DAYS_SELECT_EXCLUSION, RestoreDaysSelectExclusionPolicy::Reject) {
            return Err(RestoreRejection::DaysWithSelect);
        }
        if request.select_parameters.is_none()
            && matches!(RESTORE_SELECT_PARAMETERS_REQUIRED, RestoreSelectParametersRequiredPolicy::Require)
        {
            return Err(RestoreRejection::SelectFormIncomplete);
        }
        if request.output_location.is_none()
            && matches!(RESTORE_SELECT_OUTPUT_REQUIRED, RestoreSelectOutputRequiredPolicy::Require)
        {
            return Err(RestoreRejection::SelectFormIncomplete);
        }
        // The nested query is the same four members a plain select carries, validated by the
        // same function — a select-on-restore that AWS would refuse is refused identically here,
        // and with the same code.
        if let Some(parameters) = request.select_parameters.as_ref()
            && matches!(RESTORE_NESTED_SELECT_VALIDATION, RestoreNestedSelectValidationPolicy::Shared)
        {
            return validate_select(
                &parameters.expression,
                &parameters.expression_type,
                &parameters.input_serialization,
                &parameters.output_serialization,
                None,
            )
            .map_err(RestoreRejection::Select);
        }
        return Ok(());
    }

    if select_members && matches!(RESTORE_SELECT_MEMBERS_REQUIRE_TYPE, RestoreSelectMembersRequireTypePolicy::Reject) {
        return Err(RestoreRejection::SelectMembersWithoutSelectType);
    }
    match request.days {
        None if matches!(RESTORE_FORM_PRESENCE, RestoreFormPresencePolicy::RequireDaysOrSelect) => {
            Err(RestoreRejection::FormMissing)
        }
        None => Ok(()),
        Some(days) if days < MIN_RESTORE_DAYS => Err(RestoreRejection::DaysTooSmall),
        Some(_) => Ok(()),
    }
}

/// The closed tier set, spelled out rather than asked of the generated enum.
///
/// The same reasoning as the select family's compression set: `is_known()` answers for whatever
/// the model carries, and the refusal here is about what a backend can actually schedule.
fn is_known_tier(tier: &Tier) -> bool {
    *tier == Tier::STANDARD || *tier == Tier::BULK || *tier == Tier::EXPEDITED
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `encryption`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
