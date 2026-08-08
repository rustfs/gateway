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

//! What a select request may say, and what it may not.
//!
//! Responsible for: every rule in [`super`], asserted against its variant *and* its error code,
//! with the accepting direction of each exclusivity rule beside the refusing one.
//! NOT responsible for: the decoder that produces these values, which is generated; nor for the
//! routing predicate that decides a request is a select at all (`tests/route_table.rs`).
//! Upstream: [`super`]. Downstream: nothing.
//!
//! Every refusal below is checked against its code as well as its variant, because a rejection
//! that reaches the client under the wrong `<Code>` is the defect this family's twelve
//! operation-specific codes exist to prevent, and a variant assertion alone cannot see it.

use super::*;
use rustfs_gateway_types::dto::{CsvInput, CsvOutput, JsonInput, JsonOutput, ParquetInput};

fn csv_in() -> InputSerialization {
    InputSerialization {
        csv: Some(CsvInput::default()),
        ..InputSerialization::default()
    }
}

fn csv_out() -> OutputSerialization {
    OutputSerialization {
        csv: Some(CsvOutput::default()),
        ..OutputSerialization::default()
    }
}

fn range(start: Option<i64>, end: Option<i64>) -> ScanRange {
    ScanRange { start, end }
}

/// The ordinary request passes, with every optional member absent.
#[test]
fn a_minimal_well_formed_request_passes() {
    validate_select("SELECT * FROM S3Object", &ExpressionType::SQL, &csv_in(), &csv_out(), None).expect("well formed");
}

/// All three input formats are accepted, one at a time, and both output formats are.
///
/// The positive half of the exclusivity rules: a validator that refused everything would satisfy
/// every negative case below on its own.
#[test]
fn each_serialization_is_accepted_on_its_own() {
    let json_in = InputSerialization {
        json: Some(JsonInput::default()),
        ..InputSerialization::default()
    };
    let parquet_in = InputSerialization {
        parquet: Some(ParquetInput {}),
        ..InputSerialization::default()
    };
    let json_out = OutputSerialization {
        json: Some(JsonOutput::default()),
        ..OutputSerialization::default()
    };
    for input in [csv_in(), json_in, parquet_in] {
        for output in [csv_out(), json_out.clone()] {
            validate_select("SELECT 1", &ExpressionType::SQL, &input, &output, None).expect("one of each");
        }
    }
}

/// All three compression values are accepted, and so is an absent one.
#[test]
fn every_documented_compression_is_accepted() {
    for compression in [
        None,
        Some(CompressionType::NONE),
        Some(CompressionType::GZIP),
        Some(CompressionType::BZIP2),
    ] {
        let input = InputSerialization {
            csv: Some(CsvInput::default()),
            compression_type: compression.clone(),
            ..InputSerialization::default()
        };
        validate_input_serialization(&input).expect("a documented compression");
    }
}

/// The three documented scan-range forms are accepted.
#[test]
fn the_three_scan_range_forms_are_accepted() {
    for form in [range(Some(0), Some(100)), range(Some(50), None), range(None, Some(50))] {
        validate_scan_range(&form).expect("a documented form");
    }
    // A zero-length window is a window: Start and End equal is legal, and the inversion check
    // must not read it as inverted.
    validate_scan_range(&range(Some(7), Some(7))).expect("an empty but well-formed window");
}

/// An expression exactly at the ceiling passes — the other direction of the bound.
#[test]
fn an_expression_at_the_ceiling_passes() {
    let expression = "s".repeat(MAX_EXPRESSION_BYTES);
    validate_select(&expression, &ExpressionType::SQL, &csv_in(), &csv_out(), None).expect("the ceiling itself is legal");
}

/// Negative — an expression one byte past the ceiling is refused, with the operation's own code.
#[test]
fn n_an_expression_past_the_ceiling_is_refused() {
    let expression = "s".repeat(MAX_EXPRESSION_BYTES + 1);
    let refusal = validate_select(&expression, &ExpressionType::SQL, &csv_in(), &csv_out(), None).expect_err("too long");
    assert_eq!(refusal, SelectRejection::ExpressionTooLong);
    assert_eq!(refusal.code(), ErrorCode::EXPRESSION_TOO_LONG);
    assert_eq!(refusal.code().default_status(), http::StatusCode::BAD_REQUEST);
}

/// Negative — the ceiling is measured in bytes, not in characters.
///
/// A multi-byte expression whose character count is under the limit and whose byte length is
/// over it must be refused: a limit counted in characters lets a UTF-8 payload three times the
/// documented size through.
#[test]
fn n_the_ceiling_counts_bytes_and_not_characters() {
    // Three bytes per character, so a third of the ceiling plus one character is over it.
    let expression = "\u{4e00}".repeat(MAX_EXPRESSION_BYTES / 3 + 1);
    assert!(expression.chars().count() < MAX_EXPRESSION_BYTES, "under the limit in characters");
    assert!(expression.len() > MAX_EXPRESSION_BYTES, "over it in bytes");
    assert_eq!(
        validate_select(&expression, &ExpressionType::SQL, &csv_in(), &csv_out(), None),
        Err(SelectRejection::ExpressionTooLong)
    );
}

/// Negative — an empty expression is refused rather than read as "select everything".
#[test]
fn n_an_empty_expression_is_refused() {
    let refusal = validate_select("", &ExpressionType::SQL, &csv_in(), &csv_out(), None).expect_err("empty");
    assert_eq!(refusal, SelectRejection::ExpressionEmpty);
    assert_eq!(refusal.code(), ErrorCode::MALFORMED_XML);
}

/// Negative — an expression type outside the one-value set, in every near-miss spelling.
#[test]
fn n_an_expression_type_outside_the_set_is_refused() {
    for spelling in ["sql", "Sql", "SQL2", "", "PARTIQL"] {
        let refusal = validate_select("SELECT 1", &ExpressionType::custom(spelling.to_owned()), &csv_in(), &csv_out(), None)
            .expect_err(spelling);
        assert_eq!(refusal, SelectRejection::ExpressionTypeUnknown, "{spelling}");
        assert_eq!(refusal.code(), ErrorCode::INVALID_EXPRESSION_TYPE, "{spelling}");
    }
}

/// Negative — two input formats at once is a conflict, in all three pairings.
#[test]
fn n_two_input_serializations_are_a_conflict() {
    let pairs = [
        InputSerialization {
            csv: Some(CsvInput::default()),
            json: Some(JsonInput::default()),
            ..InputSerialization::default()
        },
        InputSerialization {
            csv: Some(CsvInput::default()),
            parquet: Some(ParquetInput {}),
            ..InputSerialization::default()
        },
        InputSerialization {
            json: Some(JsonInput::default()),
            parquet: Some(ParquetInput {}),
            ..InputSerialization::default()
        },
    ];
    for input in pairs {
        let refusal = validate_input_serialization(&input).expect_err("two formats");
        assert_eq!(refusal, SelectRejection::InputSerializationAmbiguous);
        assert_eq!(refusal.code(), ErrorCode::OBJECT_SERIALIZATION_CONFLICT);
    }
}

/// Negative — no input format at all is a malformed document, not a default.
#[test]
fn n_an_input_serialization_with_no_format_is_refused() {
    let refusal = validate_input_serialization(&InputSerialization::default()).expect_err("no format");
    assert_eq!(refusal, SelectRejection::InputSerializationMissing);
    assert_eq!(refusal.code(), ErrorCode::MALFORMED_XML);
}

/// Negative — both output formats, and neither.
#[test]
fn n_the_output_serialization_names_exactly_one_format() {
    let both = OutputSerialization {
        csv: Some(CsvOutput::default()),
        json: Some(JsonOutput::default()),
    };
    assert_eq!(validate_output_serialization(&both), Err(SelectRejection::OutputSerializationAmbiguous));
    assert_eq!(
        validate_output_serialization(&OutputSerialization::default()),
        Err(SelectRejection::OutputSerializationMissing)
    );
    assert_eq!(
        SelectRejection::OutputSerializationAmbiguous.code(),
        ErrorCode::OBJECT_SERIALIZATION_CONFLICT
    );
}

/// Negative — a compression this side cannot name is refused with the operation's own code.
#[test]
fn n_an_unknown_compression_is_refused() {
    for spelling in ["gzip", "ZSTD", "DEFLATE", ""] {
        let input = InputSerialization {
            csv: Some(CsvInput::default()),
            compression_type: Some(CompressionType::custom(spelling.to_owned())),
            ..InputSerialization::default()
        };
        let refusal = validate_input_serialization(&input).expect_err(spelling);
        assert_eq!(refusal, SelectRejection::CompressionUnknown, "{spelling}");
        assert_eq!(refusal.code(), ErrorCode::INVALID_COMPRESSION_FORMAT, "{spelling}");
    }
}

/// Negative — a scan range with no bound describes no window.
#[test]
fn n_an_empty_scan_range_is_refused() {
    let refusal = validate_scan_range(&range(None, None)).expect_err("no bound");
    assert_eq!(refusal, SelectRejection::ScanRangeEmpty);
    assert_eq!(refusal.code(), ErrorCode::INVALID_ARGUMENT);
}

/// Negative — an inverted or negative window.
#[test]
fn n_an_inverted_or_negative_scan_range_is_refused() {
    for form in [range(Some(100), Some(10)), range(Some(-1), None), range(None, Some(-5))] {
        assert_eq!(validate_scan_range(&form), Err(SelectRejection::ScanRangeInverted));
    }
}

/// Negative — the scan range is checked when a request carries one and skipped when it does not.
///
/// Both directions, because a validator that ignored the argument would pass the first half and
/// one that always refused would pass nothing.
#[test]
fn n_the_scan_range_is_checked_only_when_present() {
    validate_select("SELECT 1", &ExpressionType::SQL, &csv_in(), &csv_out(), None).expect("absent");
    assert_eq!(
        validate_select("SELECT 1", &ExpressionType::SQL, &csv_in(), &csv_out(), Some(&range(None, None))),
        Err(SelectRejection::ScanRangeEmpty)
    );
}

/// Negative — no refusal message repeats a character of the expression.
///
/// The expression is user SQL and can carry a customer's data. This is the assertion that says
/// so, and it is written over every variant rather than over the ones that seemed likely.
#[test]
fn n_no_refusal_message_can_carry_the_expression() {
    const SECRET: &str = "SELECT * FROM S3Object WHERE ssn = '000-00-0000'";
    let long = "@".repeat(MAX_EXPRESSION_BYTES + 1);
    let refusals = [
        validate_select(&long, &ExpressionType::SQL, &csv_in(), &csv_out(), None),
        validate_select(SECRET, &ExpressionType::custom("PARTIQL".to_owned()), &csv_in(), &csv_out(), None),
        validate_select(SECRET, &ExpressionType::SQL, &InputSerialization::default(), &csv_out(), None),
        validate_select(SECRET, &ExpressionType::SQL, &csv_in(), &OutputSerialization::default(), None),
        validate_select(SECRET, &ExpressionType::SQL, &csv_in(), &csv_out(), Some(&range(None, None))),
    ];
    for refusal in refusals {
        let refusal = refusal.expect_err("each of these is a refusal");
        let reason = refusal.reason();
        assert!(!reason.contains("ssn"), "{reason}");
        assert!(!reason.contains("S3Object"), "{reason}");
        assert!(!reason.contains('@'), "{reason}");
        assert!(!reason.is_empty());
    }
}

/// Every rejection maps to a status a client can act on, and never to a 5xx.
///
/// Upstream shipped a default of 500 for a code it did not know, which tells a client to retry a
/// request that will never succeed. This is the assertion that the twelve select codes are in
/// the table at all — a code with no row would fall back rather than answer its own status.
#[test]
fn every_rejection_answers_a_client_error() {
    let all = [
        SelectRejection::ExpressionTypeUnknown,
        SelectRejection::ExpressionTooLong,
        SelectRejection::ExpressionEmpty,
        SelectRejection::InputSerializationAmbiguous,
        SelectRejection::InputSerializationMissing,
        SelectRejection::OutputSerializationAmbiguous,
        SelectRejection::OutputSerializationMissing,
        SelectRejection::CompressionUnknown,
        SelectRejection::ScanRangeEmpty,
        SelectRejection::ScanRangeInverted,
    ];
    for rejection in all {
        let status = rejection.code().default_status();
        assert_eq!(status, http::StatusCode::BAD_REQUEST, "{rejection:?} answered {status}");
    }
}

/// The twelve operation-specific codes are all in the table with a 400, not the fallback.
///
/// Distinguishing "in the table" from "fell back" is the point, and the fallback happens to be a
/// 400 too — so the wire spelling is asserted as well, which the fallback path cannot produce
/// for a code the table does not carry.
#[test]
fn the_select_error_codes_are_in_the_status_table() {
    let codes = [
        (ErrorCode::CSV_PARSING_ERROR, "CSVParsingError"),
        (ErrorCode::EXPRESSION_TOO_LONG, "ExpressionTooLong"),
        (ErrorCode::INVALID_COLUMN_INDEX, "InvalidColumnIndex"),
        (ErrorCode::INVALID_COMPRESSION_FORMAT, "InvalidCompressionFormat"),
        (ErrorCode::INVALID_DATA_TYPE, "InvalidDataType"),
        (ErrorCode::INVALID_EXPRESSION_TYPE, "InvalidExpressionType"),
        (ErrorCode::INVALID_TEXT_ENCODING, "InvalidTextEncoding"),
        (ErrorCode::JSON_PARSING_ERROR, "JSONParsingError"),
        (ErrorCode::OBJECT_SERIALIZATION_CONFLICT, "ObjectSerializationConflict"),
        (ErrorCode::OVER_MAX_RECORD_SIZE, "OverMaxRecordSize"),
        (ErrorCode::PARSE_UNEXPECTED_TOKEN, "ParseUnexpectedToken"),
        (ErrorCode::UNSUPPORTED_FUNCTION, "UnsupportedFunction"),
    ];
    for (code, wire) in codes {
        assert_eq!(code.as_str(), wire);
        assert_eq!(code.default_status(), http::StatusCode::BAD_REQUEST, "{wire}");
    }
}
