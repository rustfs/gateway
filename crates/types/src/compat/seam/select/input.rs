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

//! Nested Select input conversion for the enclosing legacy revision.
//!
//! Responsible for: preserving document fields, applying the measured legacy header reading, and
//! materializing already-decoded names under the caller's explicit policy.
//! NOT responsible for: parsing XML, authorization, query validation or choosing deployment policy.
//! Upstream: decoded owned/legacy inputs. Downstream: the migration adapter and its existing checks.

use super::{dto, legacy};
use crate::compat::ConversionError;
use crate::{BucketName, NamePolicy, ObjectKey, SseCustomerKey};

/// Every owned Select input member carried by this conversion.
pub const GATEWAY_INPUT_MEMBERS: &[&str] = &[
    "bucket",
    "key",
    "sse_customer_algorithm",
    "sse_customer_key",
    "sse_customer_key_md5",
    "expression",
    "expression_type",
    "request_progress",
    "input_serialization",
    "output_serialization",
    "scan_range",
    "expected_bucket_owner",
];

/// Converts a decoded owned request to the legacy nested request.
///
/// All three pinned legacy decoders read empty optional HTTP headers as absent. Whitespace and
/// empty XML fields remain unchanged; this conversion does not validate the query document.
#[must_use]
pub fn input_to_s3s(input: dto::SelectObjectContentInput) -> legacy::SelectObjectContentInput {
    legacy::SelectObjectContentInput {
        bucket: input.bucket.as_str().to_owned(),
        key: input.key.as_str().to_owned(),
        sse_customer_algorithm: header(input.sse_customer_algorithm),
        sse_customer_key: input
            .sse_customer_key
            .filter(|key| !key.expose_secret().is_empty())
            .map(|key| key.expose_secret().to_owned()),
        sse_customer_key_md5: header(input.sse_customer_key_md5),
        expected_bucket_owner: header(input.expected_bucket_owner),
        request: legacy::SelectObjectContentRequest {
            expression: input.expression,
            expression_type: legacy::ExpressionType::from(input.expression_type.as_str().to_owned()),
            input_serialization: serialization_to_s3s(input.input_serialization),
            output_serialization: output_serialization_to_s3s(input.output_serialization),
            request_progress: input
                .request_progress
                .map(|value| legacy::RequestProgress { enabled: value.enabled }),
            scan_range: input.scan_range.map(|value| legacy::ScanRange {
                start: value.start,
                end: value.end,
            }),
        },
    }
}

/// Converts a legacy request using the caller's name policy, without decoding its key again.
///
/// The caller must retain its existing authorization and name-validation order. No policy is
/// selected here. Optional DTO members, including explicitly empty headers, are carried as given.
///
/// # Errors
///
/// Returns a fixed, member-named error when the bucket or decoded key does not fit the policy.
/// Names outside the owned representation are refused rather than rewritten or silently dropped.
pub fn input_from_s3s(
    input: legacy::SelectObjectContentInput,
    policy: &NamePolicy,
) -> Result<dto::SelectObjectContentInput, ConversionError> {
    let legacy::SelectObjectContentInput {
        bucket,
        key,
        sse_customer_algorithm,
        sse_customer_key,
        sse_customer_key_md5,
        expected_bucket_owner,
        request,
    } = input;
    let bucket = BucketName::materialize(&bucket, policy).map_err(|_| ConversionError {
        field: "bucket",
        reason: "the bucket does not fit the requested name policy",
    })?;
    let key = ObjectKey::materialize_decoded(&key, policy).map_err(|_| ConversionError {
        field: "key",
        reason: "the decoded key does not fit the requested name policy",
    })?;
    let legacy::SelectObjectContentRequest {
        expression,
        expression_type,
        input_serialization,
        output_serialization,
        request_progress,
        scan_range,
    } = request;
    Ok(dto::SelectObjectContentInput {
        bucket,
        key,
        sse_customer_algorithm,
        sse_customer_key: sse_customer_key.map(SseCustomerKey::new),
        sse_customer_key_md5,
        expected_bucket_owner,
        expression,
        expression_type: dto::ExpressionType::custom(expression_type.as_str().to_owned()),
        input_serialization: serialization_from_s3s(input_serialization),
        output_serialization: output_serialization_from_s3s(output_serialization),
        request_progress: request_progress.map(|legacy::RequestProgress { enabled }| dto::RequestProgress { enabled }),
        scan_range: scan_range.map(|legacy::ScanRange { start, end }| dto::ScanRange { start, end }),
    })
}

fn header(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn serialization_to_s3s(value: dto::InputSerialization) -> legacy::InputSerialization {
    legacy::InputSerialization {
        csv: value.csv.map(|value| legacy::CSVInput {
            allow_quoted_record_delimiter: value.allow_quoted_record_delimiter,
            comments: value.comments,
            field_delimiter: value.field_delimiter,
            file_header_info: value
                .file_header_info
                .map(|value| legacy::FileHeaderInfo::from(value.as_str().to_owned())),
            quote_character: value.quote_character,
            quote_escape_character: value.quote_escape_character,
            record_delimiter: value.record_delimiter,
        }),
        compression_type: value
            .compression_type
            .map(|value| legacy::CompressionType::from(value.as_str().to_owned())),
        json: value.json.map(|value| legacy::JSONInput {
            type_: value.r#type.map(|value| legacy::JSONType::from(value.as_str().to_owned())),
        }),
        parquet: value.parquet.map(|_| legacy::ParquetInput {}),
    }
}

fn serialization_from_s3s(value: legacy::InputSerialization) -> dto::InputSerialization {
    let legacy::InputSerialization {
        csv,
        compression_type,
        json,
        parquet,
    } = value;
    dto::InputSerialization {
        csv: csv.map(
            |legacy::CSVInput {
                 allow_quoted_record_delimiter,
                 comments,
                 field_delimiter,
                 file_header_info,
                 quote_character,
                 quote_escape_character,
                 record_delimiter,
             }| dto::CsvInput {
                allow_quoted_record_delimiter,
                comments,
                field_delimiter,
                file_header_info: file_header_info.map(|value| dto::FileHeaderInfo::custom(value.as_str().to_owned())),
                quote_character,
                quote_escape_character,
                record_delimiter,
            },
        ),
        compression_type: compression_type.map(|value| dto::CompressionType::custom(value.as_str().to_owned())),
        json: json.map(|legacy::JSONInput { type_ }| dto::JsonInput {
            r#type: type_.map(|value| dto::Type::custom(value.as_str().to_owned())),
        }),
        parquet: parquet.map(|legacy::ParquetInput {}| dto::ParquetInput {}),
    }
}

fn output_serialization_to_s3s(value: dto::OutputSerialization) -> legacy::OutputSerialization {
    legacy::OutputSerialization {
        csv: value.csv.map(|value| legacy::CSVOutput {
            field_delimiter: value.field_delimiter,
            quote_character: value.quote_character,
            quote_escape_character: value.quote_escape_character,
            quote_fields: value
                .quote_fields
                .map(|value| legacy::QuoteFields::from(value.as_str().to_owned())),
            record_delimiter: value.record_delimiter,
        }),
        json: value.json.map(|value| legacy::JSONOutput {
            record_delimiter: value.record_delimiter,
        }),
    }
}

fn output_serialization_from_s3s(value: legacy::OutputSerialization) -> dto::OutputSerialization {
    let legacy::OutputSerialization { csv, json } = value;
    dto::OutputSerialization {
        csv: csv.map(
            |legacy::CSVOutput {
                 field_delimiter,
                 quote_character,
                 quote_escape_character,
                 quote_fields,
                 record_delimiter,
             }| dto::CsvOutput {
                field_delimiter,
                quote_character,
                quote_escape_character,
                quote_fields: quote_fields.map(|value| dto::QuoteFields::custom(value.as_str().to_owned())),
                record_delimiter,
            },
        ),
        json: json.map(|legacy::JSONOutput { record_delimiter }| dto::JsonOutput { record_delimiter }),
    }
}
