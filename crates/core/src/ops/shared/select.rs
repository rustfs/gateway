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

//! What a select request is allowed to say about the data, before anybody reads a row of it.
//!
//! Shares: select
//! Members: RestoreObject, SelectObjectContent
//!
//! Responsible for: the semantic rules of the four members that describe a query — the
//! one-of-three `InputSerialization`, the one-of-two `OutputSerialization`, the `ScanRange`
//! grammar, the closed `ExpressionType` and `CompressionType` sets, and the expression's
//! documented ceiling — held once, because the same four members appear twice on the wire:
//! directly inside a `SelectObjectContentRequest`, and nested inside a `RestoreRequest` as
//! `SelectParameters` when a retrieval is a select-on-restore.
//! NOT responsible for: **the expression**. Not one character of it is parsed, matched,
//! lowercased or logged here; its length is measured and nothing else. SQL belongs to the
//! storage side, and the twelve select-specific error codes exist so that side can report what
//! it found, never so that this side can guess.
//! Upstream: `rustfs-gateway-types`' generated dto and `ErrorCode`. Downstream: the facade,
//! which re-exports every item here; `crates/conformance`'s fixture is the first caller.
//!
//! # Why an expression is a length and nothing else
//!
//! An expression is user-authored SQL, which makes it three things at once: untrusted input, a
//! value with no upper bound that a caller controls, and — this is the one that decides the
//! design — a string that must never appear in an error message or a log line. A predicate can
//! carry a customer's data (`WHERE ssn = '...'`), so echoing it into a refusal copies that data
//! into every error body and every log that captures one. So [`SelectRejection`] has no variant
//! that carries text, every reason is a `&'static str`, and the only fact this module ever
//! learns about an expression is how long it is.
//!
//! # Why the exclusivity rules are refusals and the rest is leniency
//!
//! Two serializations at once is not a document with a redundant element; it is a document that
//! says the object is two different formats. A reader that picked one would parse the bytes as
//! something the caller did not describe and return rows that look plausible — the worst
//! available outcome, and the reason AWS publishes `ObjectSerializationConflict` at all.
//! Everything the model leaves optional stays optional: a CSV description with no delimiters, an
//! empty `<Parquet/>`, an absent `RequestProgress`, a `ScanRange` with only a `Start`. Those are
//! defaults, not contradictions.

use rustfs_gateway_types::ErrorCode;
use rustfs_gateway_types::dto::{CompressionType, ExpressionType, InputSerialization, OutputSerialization, ScanRange};

use crate::contracts::{
    SELECT_COMPRESSION_VALUES, SELECT_EXPRESSION_ERROR_FLOW, SELECT_EXPRESSION_INSPECTION, SELECT_EXPRESSION_MAX_BYTES,
    SELECT_EXPRESSION_PRESENCE, SELECT_EXPRESSION_TYPE_VALUES, SELECT_INPUT_MISSING, SELECT_INPUT_MULTIPLE,
    SELECT_OUTPUT_MISSING, SELECT_OUTPUT_MULTIPLE, SELECT_RESPONSE_SHAPE, SELECT_SCAN_BOUNDED, SELECT_SCAN_END_ONLY,
    SELECT_SCAN_RANGE_EMPTY, SELECT_SCAN_RANGE_ORDER, SELECT_SCAN_RANGE_SIGN, SELECT_SCAN_START_ONLY,
    SelectCompressionValuesPolicy, SelectExpressionErrorFlowPolicy, SelectExpressionInspectionPolicy,
    SelectExpressionMaxBytesPolicy, SelectExpressionPresencePolicy, SelectExpressionTypeValuesPolicy, SelectInputMissingPolicy,
    SelectInputMultiplePolicy, SelectOutputMissingPolicy, SelectOutputMultiplePolicy, SelectResponseShapePolicy,
    SelectScanBoundedPolicy, SelectScanEndOnlyPolicy, SelectScanRangeEmptyPolicy, SelectScanRangeOrderPolicy,
    SelectScanRangeSignPolicy, SelectScanStartOnlyPolicy,
};

/// The documented ceiling on an expression, in bytes.
///
/// 256 KiB, measured over the UTF-8 the wire carried rather than over characters: the wire is
/// what the ceiling is about, and counting characters would let a multi-byte expression past a
/// limit expressed in bytes.
pub const MAX_EXPRESSION_BYTES: usize = match SELECT_EXPRESSION_MAX_BYTES {
    SelectExpressionMaxBytesPolicy::Max262144 => 256 * 1024,
    SelectExpressionMaxBytesPolicy::Unbounded => usize::MAX,
};

/// Why a decoded select request was refused, with the code AWS answers.
///
/// Carried as data rather than as a rendered error, so a backend outside this workspace maps it
/// into its own error type. No variant carries a value: see the module note on the expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectRejection {
    /// An `ExpressionType` outside the one-value set.
    ExpressionTypeUnknown,
    /// An expression longer than [`MAX_EXPRESSION_BYTES`].
    ExpressionTooLong,
    /// An expression that is present and empty. A query that selects nothing is not a default.
    ExpressionEmpty,
    /// More than one of `CSV`, `JSON` and `Parquet` in an `InputSerialization`.
    InputSerializationAmbiguous,
    /// None of them: the request describes an object it has not said how to read.
    InputSerializationMissing,
    /// Both `CSV` and `JSON` in an `OutputSerialization`.
    OutputSerializationAmbiguous,
    /// Neither of them.
    OutputSerializationMissing,
    /// A `CompressionType` outside the documented three-value set.
    CompressionUnknown,
    /// A `ScanRange` that names no bound at all.
    ScanRangeEmpty,
    /// A `ScanRange` whose `End` is below its `Start`, or whose bounds are negative.
    ScanRangeInverted,
}

impl SelectRejection {
    /// The S3 error code to render.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            // The two the operation publishes a code of its own for.
            Self::ExpressionTypeUnknown => ErrorCode::INVALID_EXPRESSION_TYPE,
            Self::ExpressionTooLong => ErrorCode::EXPRESSION_TOO_LONG,
            Self::CompressionUnknown => ErrorCode::INVALID_COMPRESSION_FORMAT,
            // Two descriptions of one object's format, which is the conflict AWS names.
            Self::InputSerializationAmbiguous | Self::OutputSerializationAmbiguous => ErrorCode::OBJECT_SERIALIZATION_CONFLICT,
            // A member the schema requires, absent or empty: the parser's own answer.
            Self::ExpressionEmpty | Self::InputSerializationMissing | Self::OutputSerializationMissing => {
                ErrorCode::MALFORMED_XML
            }
            // Well-formed values that cannot describe a window.
            Self::ScanRangeEmpty | Self::ScanRangeInverted => ErrorCode::INVALID_ARGUMENT,
        }
    }

    /// A constant explanation. Never built from request bytes, and in particular never carrying a
    /// character of the expression.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::ExpressionTypeUnknown => "ExpressionType must be SQL",
            Self::ExpressionTooLong => "Expression exceeds the maximum length of 262144 bytes",
            Self::ExpressionEmpty => "Expression must not be empty",
            Self::InputSerializationAmbiguous => "InputSerialization must name exactly one of CSV, JSON or Parquet",
            Self::InputSerializationMissing => "InputSerialization must name one of CSV, JSON or Parquet",
            Self::OutputSerializationAmbiguous => "OutputSerialization must name exactly one of CSV or JSON",
            Self::OutputSerializationMissing => "OutputSerialization must name one of CSV or JSON",
            Self::CompressionUnknown => "CompressionType must be one of NONE, GZIP or BZIP2",
            Self::ScanRangeEmpty => "ScanRange must specify Start, End, or both",
            Self::ScanRangeInverted => "ScanRange End must not be less than Start, and neither may be negative",
        }
    }

    /// Renders a refusal reason while enforcing the expression secret-flow policy.
    #[must_use]
    pub fn reason_with_expression(&self, expression: &str) -> String {
        match SELECT_EXPRESSION_ERROR_FLOW {
            SelectExpressionErrorFlowPolicy::Constant => self.reason().to_owned(),
            SelectExpressionErrorFlowPolicy::EchoRejectedValue => format!("{}: {expression}", self.reason()),
        }
    }
}

/// Checks the four members that describe a query, first refusal wins.
///
/// Shared by the two places the wire carries them: the members of a
/// `SelectObjectContentRequest`, and the members of a `RestoreRequest`'s `SelectParameters`. The
/// `scan_range` argument is `None` for the second, because a select-on-restore has no scan range
/// on the wire — passing it explicitly rather than reading it off a request is what lets one
/// function serve both.
///
/// # Errors
///
/// [`SelectRejection`] naming the first rule the request breaks. The order is fixed — expression
/// type, expression, input, output, scan range — so one document is refused for one reason on
/// every backend rather than for whichever the implementation happened to check first.
pub fn validate_select(
    expression: &str,
    expression_type: &ExpressionType,
    input: &InputSerialization,
    output: &OutputSerialization,
    scan_range: Option<&ScanRange>,
) -> Result<(), SelectRejection> {
    if matches!(SELECT_EXPRESSION_TYPE_VALUES, SelectExpressionTypeValuesPolicy::SqlOnly)
        && *expression_type != ExpressionType::SQL
    {
        return Err(SelectRejection::ExpressionTypeUnknown);
    }
    if expression.is_empty() && matches!(SELECT_EXPRESSION_PRESENCE, SelectExpressionPresencePolicy::Nonempty) {
        return Err(SelectRejection::ExpressionEmpty);
    }
    if expression.len() > MAX_EXPRESSION_BYTES {
        return Err(SelectRejection::ExpressionTooLong);
    }
    if matches!(SELECT_EXPRESSION_INSPECTION, SelectExpressionInspectionPolicy::ParseOrLog)
        && !expression.trim_start().starts_with("SELECT")
    {
        return Err(SelectRejection::ExpressionTypeUnknown);
    }
    validate_input_serialization(input)?;
    validate_output_serialization(output)?;
    if let Some(range) = scan_range {
        validate_scan_range(range)?;
    }
    Ok(())
}

/// The one-of-three rule, plus the closed compression set.
///
/// # Errors
///
/// [`SelectRejection`] when the input names no format, more than one, or an unknown compression.
pub fn validate_input_serialization(input: &InputSerialization) -> Result<(), SelectRejection> {
    let named = usize::from(input.csv.is_some()) + usize::from(input.json.is_some()) + usize::from(input.parquet.is_some());
    if named > 1 && matches!(SELECT_INPUT_MULTIPLE, SelectInputMultiplePolicy::RejectConflict) {
        return Err(SelectRejection::InputSerializationAmbiguous);
    }
    if named == 0 && matches!(SELECT_INPUT_MISSING, SelectInputMissingPolicy::RejectMalformed) {
        return Err(SelectRejection::InputSerializationMissing);
    }
    // Absent is the documented default, `NONE`; present and outside the set is not.
    if let Some(compression) = &input.compression_type
        && matches!(SELECT_COMPRESSION_VALUES, SelectCompressionValuesPolicy::NoneGzipBzip2)
        && !is_known_compression(compression)
    {
        return Err(SelectRejection::CompressionUnknown);
    }
    Ok(())
}

/// The one-of-two rule on the answer's shape.
///
/// # Errors
///
/// [`SelectRejection`] when the output names neither format or both.
pub fn validate_output_serialization(output: &OutputSerialization) -> Result<(), SelectRejection> {
    match (output.csv.is_some(), output.json.is_some()) {
        (true, true) if matches!(SELECT_OUTPUT_MULTIPLE, SelectOutputMultiplePolicy::RejectConflict) => {
            Err(SelectRejection::OutputSerializationAmbiguous)
        }
        (false, false) if matches!(SELECT_OUTPUT_MISSING, SelectOutputMissingPolicy::RejectMalformed) => {
            Err(SelectRejection::OutputSerializationMissing)
        }
        _ => Ok(()),
    }
}

/// The byte window's grammar.
///
/// The pinned model gives a `ScanRange` two members, `Start` and `End`, and AWS spells the three
/// documented forms with them: both bounds is a window, a `Start` alone runs to the end of the
/// object, and an `End` alone is the *suffix* form — the last `End` bytes, not the first. That
/// last reading is why an empty element cannot be tolerated as "the whole object": the same
/// absent-member shape would otherwise mean two different windows.
///
/// # Errors
///
/// [`SelectRejection`] for an element with no bound, a negative bound, or an `End` below a
/// `Start` that is also present.
pub fn validate_scan_range(range: &ScanRange) -> Result<(), SelectRejection> {
    match (range.start, range.end) {
        (None, None) if matches!(SELECT_SCAN_RANGE_EMPTY, SelectScanRangeEmptyPolicy::Reject) => {
            Err(SelectRejection::ScanRangeEmpty)
        }
        (start, end) => {
            if matches!(SELECT_SCAN_RANGE_SIGN, SelectScanRangeSignPolicy::Nonnegative)
                && (start.is_some_and(|value| value < 0) || end.is_some_and(|value| value < 0))
            {
                return Err(SelectRejection::ScanRangeInverted);
            }
            // Only meaningful when both are present: with a `Start` alone there is no upper
            // bound to compare, and with an `End` alone the value is a suffix length.
            if let (Some(from), Some(to)) = (start, end)
                && to < from
                && matches!(SELECT_SCAN_RANGE_ORDER, SelectScanRangeOrderPolicy::EndGteStart)
            {
                return Err(SelectRejection::ScanRangeInverted);
            }
            Ok(())
        }
    }
}

/// Selects the object bytes described by a validated `ScanRange`.
///
/// `None` selects the whole object. Bounds beyond the object are clamped, so this function is
/// total after [`validate_scan_range`] has accepted the grammar.
#[must_use]
pub fn select_scan_bytes<'a>(range: Option<&ScanRange>, body: &'a [u8]) -> &'a [u8] {
    let Some(range) = range else { return body };
    match (range.start, range.end) {
        (Some(start), Some(end)) => {
            if matches!(SELECT_SCAN_BOUNDED, SelectScanBoundedPolicy::DropRange) {
                return body;
            }
            let start = usize::try_from(start).unwrap_or(0).min(body.len());
            let end = usize::try_from(end)
                .ok()
                .and_then(|value| value.checked_add(1))
                .unwrap_or(body.len())
                .min(body.len());
            body.get(start..end.max(start)).unwrap_or_default()
        }
        (Some(start), None) => {
            if matches!(SELECT_SCAN_START_ONLY, SelectScanStartOnlyPolicy::WholeObject) {
                return body;
            }
            let start = usize::try_from(start).unwrap_or(0).min(body.len());
            body.get(start..).unwrap_or_default()
        }
        (None, Some(end)) => {
            let count = usize::try_from(end).unwrap_or(0).min(body.len());
            match SELECT_SCAN_END_ONLY {
                SelectScanEndOnlyPolicy::Suffix => body.get(body.len().saturating_sub(count)..).unwrap_or_default(),
                SelectScanEndOnlyPolicy::Prefix => body.get(..count).unwrap_or_default(),
            }
        }
        (None, None) => body,
    }
}

/// Whether a SelectObjectContent handler must return the event-stream answer shape.
#[must_use]
pub const fn select_uses_event_stream() -> bool {
    matches!(SELECT_RESPONSE_SHAPE, SelectResponseShapePolicy::EventStream)
}

/// The closed compression set, spelled out rather than asked of the generated enum.
///
/// `CompressionType::is_known()` would answer for the model's whole value set, and the model is
/// where a value AWS adds tomorrow arrives first. The refusal here is about what this
/// implementation can hand to a decompressor, so it names the three it can.
fn is_known_compression(compression: &CompressionType) -> bool {
    *compression == CompressionType::NONE || *compression == CompressionType::GZIP || *compression == CompressionType::BZIP2
}

#[cfg(test)]
// Test code is exempt from the no-expect rule; the allowance mirrors `encryption`'s test module.
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
