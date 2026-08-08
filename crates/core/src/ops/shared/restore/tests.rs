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

//! The two request forms, the four outcomes, and the header's byte-exact grammar.
//!
//! Responsible for: the status mapping in both directions, the header's byte-exact grammar and
//! its parser's refusals, and the two request forms with the members that may not cross.
//! NOT responsible for: the declared alternative status, which is asserted against this mapping
//! in `tests/params_and_dispatch.rs` because it lives on the operation rather than here.
//! Upstream: [`super`]. Downstream: nothing.
//!
//! The status mapping is asserted in both directions rather than case by case: a table that
//! answered `202` for everything satisfies "a first retrieval is 202" on its own, and a table
//! that answered `200` for everything satisfies "a repeat is 200". Both are checked against each
//! other, and against the complement — every state answers a status **or** an error, never both
//! and never neither.

use super::*;
use rustfs_gateway_types::dto::{CsvInput, CsvOutput, ExpressionType};
use rustfs_gateway_types::dto::{
    GlacierJobParameters, InputSerialization, OutputLocation, OutputSerialization, S3Location, SelectParameters,
};

/// The date AWS uses in its own worked example of this header.
const EXAMPLE_EXPIRY: &str = "Fri, 21 Dec 2012 00:00:00 GMT";

fn days(count: i32) -> RestoreRequest {
    RestoreRequest {
        days: Some(count),
        ..RestoreRequest::default()
    }
}

fn select_parameters() -> SelectParameters {
    SelectParameters {
        input_serialization: InputSerialization {
            csv: Some(CsvInput::default()),
            ..InputSerialization::default()
        },
        expression_type: ExpressionType::SQL,
        expression: "SELECT * FROM S3Object".to_owned(),
        output_serialization: OutputSerialization {
            csv: Some(CsvOutput::default()),
            ..OutputSerialization::default()
        },
    }
}

fn output_location() -> OutputLocation {
    OutputLocation {
        s3: Some(S3Location {
            bucket_name: rustfs_gateway_types::BucketName::new("results").expect("a legal bucket name"),
            prefix: "out/".to_owned(),
            ..S3Location::default()
        }),
    }
}

fn select_restore() -> RestoreRequest {
    RestoreRequest {
        r#type: Some(Type::SELECT),
        select_parameters: Some(select_parameters()),
        output_location: Some(output_location()),
        ..RestoreRequest::default()
    }
}

// ── the status mapping ───────────────────────────────────────────────────────────────────────

/// Each state answers its own status, and no two states answer the same one.
///
/// The distinctness assertion is what a per-case test cannot make: three tests each asserting
/// one number are all satisfied by a mapping stuck on that number for its own case, and only the
/// comparison between them catches a mapping that collapsed.
#[test]
fn each_state_answers_its_own_status() {
    assert_eq!(RestoreState::Initiated.status(), Some(202));
    assert_eq!(RestoreState::AlreadyRestored.status(), Some(200));
    assert_ne!(RestoreState::Initiated.status(), RestoreState::AlreadyRestored.status());
    assert_eq!(RestoreState::InProgress.status(), None);
    assert_eq!(RestoreState::NotArchived.status(), None);
}

/// Each refusing state answers its own code, at the status AWS documents for it.
#[test]
fn each_refusing_state_answers_its_own_code() {
    assert_eq!(RestoreState::InProgress.error(), Some(ErrorCode::RESTORE_ALREADY_IN_PROGRESS));
    assert_eq!(
        RestoreState::InProgress.error().map(|code| code.default_status()),
        Some(http::StatusCode::CONFLICT)
    );
    assert_eq!(RestoreState::NotArchived.error(), Some(ErrorCode::INVALID_OBJECT_STATE));
    assert_eq!(
        RestoreState::NotArchived.error().map(|code| code.default_status()),
        Some(http::StatusCode::FORBIDDEN)
    );
}

/// Every state answers exactly one of a status and an error.
///
/// The complement, asserted over the whole set: a state that answered both would let a backend
/// send a `202` carrying an `<Error>`, and one that answered neither would leave it with nothing
/// to send at all.
#[test]
fn every_state_answers_a_status_or_an_error_and_never_both() {
    for state in [
        RestoreState::Initiated,
        RestoreState::AlreadyRestored,
        RestoreState::InProgress,
        RestoreState::NotArchived,
    ] {
        assert_eq!(
            state.status().is_some(),
            state.error().is_none(),
            "{state:?} must answer exactly one of the two"
        );
        assert_eq!(state.error().is_some(), state.reason().is_some(), "{state:?}");
    }
}

/// Negative — the refusal reasons are constants that name no bucket, key or expression.
#[test]
fn n_the_refusal_reasons_are_constants() {
    for state in [RestoreState::InProgress, RestoreState::NotArchived] {
        let reason = state.reason().expect("a refusing state has a reason");
        assert!(!reason.contains("SELECT"), "{reason}");
        assert!(!reason.is_empty());
    }
}

// ── the x-amz-restore header ─────────────────────────────────────────────────────────────────

/// The in-progress spelling, byte for byte.
#[test]
fn the_ongoing_header_is_byte_exact() {
    assert_eq!(format_restore_status(&RestoreStatus::ongoing()), "ongoing-request=\"true\"");
}

/// The restored spelling, byte for byte, comma and single space included.
#[test]
fn the_restored_header_is_byte_exact() {
    assert_eq!(
        format_restore_status(&RestoreStatus::restored(EXAMPLE_EXPIRY)),
        "ongoing-request=\"false\", expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\""
    );
}

/// The renderer and the parser agree, in both states.
#[test]
fn the_header_round_trips() {
    for status in [RestoreStatus::ongoing(), RestoreStatus::restored(EXAMPLE_EXPIRY)] {
        let rendered = format_restore_status(&status);
        assert_eq!(parse_restore_status(&rendered).as_ref(), Some(&status), "{rendered}");
    }
}

/// The parser reads the date AWS's own example carries, commas inside the quotes and all.
///
/// The date itself contains `, ` — the same two bytes the pairs are separated by — so a parser
/// that split on the comma alone would cut the value in half. This is the case that says it
/// does not.
#[test]
fn the_parser_survives_the_comma_inside_the_date() {
    let parsed = parse_restore_status("ongoing-request=\"false\", expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\"")
        .expect("the documented spelling");
    assert!(!parsed.ongoing);
    assert_eq!(parsed.expiry_date.as_deref(), Some(EXAMPLE_EXPIRY));
}

/// Negative — every malformed spelling is refused, and none of them panics.
///
/// Refused rather than partially read: a header this side cannot parse must never resolve to
/// "the copy is back", which is what a caller acts on.
#[test]
fn n_a_malformed_restore_header_is_refused() {
    let malformed = [
        "",
        "ongoing-request=true",
        "ongoing-request=\"true",
        "ongoing-request=true\"",
        "ongoing-request=\"maybe\"",
        "ongoing-request=\"\"",
        "expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\"",
        "ongoing-request=\"false\",expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\"",
        "ongoing-request=\"false\",  expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\"",
        "ongoing-request=\"false\", expiry-date=Fri, 21 Dec 2012 00:00:00 GMT",
        "ongoing-request=\"false\", expires=\"Fri, 21 Dec 2012 00:00:00 GMT\"",
        "ongoing-request=\"true\", expiry-date=\"Fri, 21 Dec 2012 00:00:00 GMT\"",
        "ongoing-request=\"false\", expiry-date=\"a\", tier=\"Bulk\"",
        "ongoing-request=\"false\", expiry-date=\"a\\\"b\"",
    ];
    for value in malformed {
        assert_eq!(parse_restore_status(value), None, "{value:?} must be refused");
    }
}

/// Negative — a header past the ceiling is refused before it is scanned.
#[test]
fn n_an_oversized_restore_header_is_refused() {
    let huge = format!("ongoing-request=\"false\", expiry-date=\"{}\"", "A".repeat(4096));
    assert!(huge.len() > MAX_RESTORE_HEADER_BYTES);
    assert_eq!(parse_restore_status(&huge), None);
    // The other direction of the bound: a value at the ceiling is still parsed.
    let inner = MAX_RESTORE_HEADER_BYTES - "ongoing-request=\"false\", expiry-date=\"\"".len();
    let at_limit = format!("ongoing-request=\"false\", expiry-date=\"{}\"", "A".repeat(inner));
    assert_eq!(at_limit.len(), MAX_RESTORE_HEADER_BYTES);
    assert!(parse_restore_status(&at_limit).is_some());
}

// ── the request document ─────────────────────────────────────────────────────────────────────

/// The ordinary form passes, with and without a tier.
#[test]
fn the_days_form_passes() {
    validate_restore(&days(1)).expect("the minimum");
    validate_restore(&days(365)).expect("a year");
    for tier in [Tier::STANDARD, Tier::BULK, Tier::EXPEDITED] {
        let mut request = days(3);
        request.tier = Some(tier.clone());
        validate_restore(&request).expect("a documented tier");
        let mut nested = days(3);
        nested.glacier_job_parameters = Some(GlacierJobParameters { tier });
        validate_restore(&nested).expect("a documented tier, the other spelling");
    }
    let mut described = days(3);
    described.description = Some("nightly rehydrate".to_owned());
    validate_restore(&described).expect("a description is free text");
}

/// The select-on-restore form passes.
///
/// The legacy form is still in the pinned model and is not deprecated there, so it is decoded
/// and validated rather than refused; whether a backend implements it is a separate question.
#[test]
fn the_select_on_restore_form_passes() {
    validate_restore(&select_restore()).expect("the second documented form");
}

/// Negative — a zero or negative lifetime.
#[test]
fn n_a_lifetime_under_one_day_is_refused() {
    for count in [0, -1, i32::MIN] {
        let refusal = validate_restore(&days(count)).expect_err("under the floor");
        assert_eq!(refusal, RestoreRejection::DaysTooSmall, "{count}");
        assert_eq!(refusal.code(), ErrorCode::INVALID_ARGUMENT, "{count}");
    }
}

/// Negative — a document that describes neither form.
#[test]
fn n_a_document_with_neither_form_is_refused() {
    let refusal = validate_restore(&RestoreRequest::default()).expect_err("neither form");
    assert_eq!(refusal, RestoreRejection::FormMissing);
    assert_eq!(refusal.code(), ErrorCode::MALFORMED_XML);

    // A tier alone is still neither form: it says how to retrieve, not what to retrieve.
    let tier_only = RestoreRequest {
        tier: Some(Tier::BULK),
        ..RestoreRequest::default()
    };
    assert_eq!(validate_restore(&tier_only), Err(RestoreRejection::FormMissing));
}

/// Negative — the two forms may not be crossed, in either direction.
#[test]
fn n_the_two_forms_may_not_be_crossed() {
    let mut with_days = select_restore();
    with_days.days = Some(1);
    let refusal = validate_restore(&with_days).expect_err("Days beside a select");
    assert_eq!(refusal, RestoreRejection::DaysWithSelect);
    assert_eq!(refusal.code(), ErrorCode::INVALID_REQUEST);

    let mut orphan_parameters = days(1);
    orphan_parameters.select_parameters = Some(select_parameters());
    assert_eq!(
        validate_restore(&orphan_parameters),
        Err(RestoreRejection::SelectMembersWithoutSelectType)
    );

    let mut orphan_location = days(1);
    orphan_location.output_location = Some(output_location());
    assert_eq!(validate_restore(&orphan_location), Err(RestoreRejection::SelectMembersWithoutSelectType));
}

/// Negative — the select form needs both of its members.
#[test]
fn n_an_incomplete_select_form_is_refused() {
    let mut no_parameters = select_restore();
    no_parameters.select_parameters = None;
    let refusal = validate_restore(&no_parameters).expect_err("no parameters");
    assert_eq!(refusal, RestoreRejection::SelectFormIncomplete);
    assert_eq!(refusal.code(), ErrorCode::MALFORMED_XML);

    let mut no_location = select_restore();
    no_location.output_location = None;
    assert_eq!(validate_restore(&no_location), Err(RestoreRejection::SelectFormIncomplete));

    let bare_type = RestoreRequest {
        r#type: Some(Type::SELECT),
        ..RestoreRequest::default()
    };
    assert_eq!(validate_restore(&bare_type), Err(RestoreRejection::SelectFormIncomplete));
}

/// Negative — a tier outside the set, on both spellings of the member.
#[test]
fn n_an_unknown_tier_is_refused_on_both_spellings() {
    for spelling in ["expedited", "STANDARD", "Instant", ""] {
        let mut flat = days(1);
        flat.tier = Some(Tier::custom(spelling.to_owned()));
        assert_eq!(validate_restore(&flat), Err(RestoreRejection::TierUnknown), "{spelling}");

        let mut nested = days(1);
        nested.glacier_job_parameters = Some(GlacierJobParameters {
            tier: Tier::custom(spelling.to_owned()),
        });
        assert_eq!(validate_restore(&nested), Err(RestoreRejection::TierUnknown), "{spelling}");
    }
    assert_eq!(RestoreRejection::TierUnknown.code(), ErrorCode::INVALID_ARGUMENT);
}

/// Negative — the nested query is validated by the select rules, and keeps their codes.
///
/// This is what makes `shared::select` a two-member module rather than a one-member one: a
/// select-on-restore whose expression type is wrong must be refused for the same reason and with
/// the same code as a plain select's, or the two paths have drifted.
#[test]
fn n_a_nested_query_is_refused_by_the_select_rules() {
    let mut wrong_type = select_restore();
    if let Some(parameters) = wrong_type.select_parameters.as_mut() {
        parameters.expression_type = ExpressionType::custom("PARTIQL".to_owned());
    }
    let refusal = validate_restore(&wrong_type).expect_err("a bad expression type");
    assert_eq!(refusal, RestoreRejection::Select(SelectRejection::ExpressionTypeUnknown));
    assert_eq!(refusal.code(), ErrorCode::INVALID_EXPRESSION_TYPE);

    let mut two_formats = select_restore();
    if let Some(parameters) = two_formats.select_parameters.as_mut() {
        parameters.input_serialization.json = Some(rustfs_gateway_types::dto::JsonInput::default());
    }
    assert_eq!(
        validate_restore(&two_formats).expect_err("two formats").code(),
        ErrorCode::OBJECT_SERIALIZATION_CONFLICT
    );
}

/// Negative — no refusal message carries a character of the nested expression.
#[test]
fn n_no_restore_refusal_message_carries_the_expression() {
    let mut request = select_restore();
    if let Some(parameters) = request.select_parameters.as_mut() {
        parameters.expression = "SELECT ssn FROM S3Object".to_owned();
        parameters.expression_type = ExpressionType::custom("@@@".to_owned());
    }
    let refusal = validate_restore(&request).expect_err("a bad expression type");
    let reason = refusal.reason();
    assert!(!reason.contains("ssn"), "{reason}");
    assert!(!reason.contains("S3Object"), "{reason}");
    assert!(!reason.contains('@'), "{reason}");
}
