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

//! The GetBucketLocation migration seam: a pure conversion between the gateway typed shapes and the
//! s3s DTO of the revision this file is compiled against (`super::s3s`).
//!
//! Responsible for: turning a decoded gateway `GetBucketLocationInput` into the s3s input the
//! RustFS `get_bucket_location` body receives, and the s3s output that body returns into the
//! gateway output the gateway codec writes; and the same pair the other way round for a use case
//! ported to gateway types behind the legacy stack (rustfs/backlog#2749). Every direction but the
//! s3s input's is total: every value one side holds has exactly one spelling on the other; the
//! s3s input's bucket is text the gateway name grammar may refuse.
//! NOT responsible for: the request context ([`super::request_context`]), looking the bucket's
//! region up, or rendering the `LocationConstraint` body, which is the gateway codec's.
//! Upstream: the generated dto. Downstream: the goldens context diff under every seam revision, and
//! the RustFS ring-2 adapter through the revision RustFS links (rustfs/backlog#1752).

use super::s3s::dto as oracle;

use crate::compat::ConversionError;
use crate::{BucketName, dto};

/// Every member of the gateway `GetBucketLocationInput` that [`input_to_s3s`] maps.
///
/// The gateway DTO may not be destructured exhaustively (ADR-0004 P3), so the conversion declares
/// its members here and the goldens diff pins the count to `generated/dto/field_counts.txt`.
pub const GATEWAY_INPUT_MEMBERS: &[&str] = &["bucket", "expected_bucket_owner"];

/// Every member of the gateway `GetBucketLocationOutput` that [`output_from_s3s`] sets.
pub const GATEWAY_OUTPUT_MEMBERS: &[&str] = &["location_constraint"];

/// Converts a decoded gateway input into the s3s input the RustFS app body receives.
#[must_use]
pub fn input_to_s3s(input: dto::GetBucketLocationInput) -> oracle::GetBucketLocationInput {
    oracle::GetBucketLocationInput {
        bucket: input.bucket.as_str().to_owned(),
        expected_bucket_owner: input.expected_bucket_owner,
    }
}

/// Converts the s3s output the RustFS app body returned into the gateway output the codec writes.
///
/// The constraint keeps its exact spelling — a region the model does not list included — because
/// RustFS answers with the region its operator configured, which need not be an AWS region.
#[must_use]
pub fn output_from_s3s(output: oracle::GetBucketLocationOutput) -> dto::GetBucketLocationOutput {
    // Exhaustive on purpose: this is the s3s struct, not a gateway DTO, and a re-pin that adds a
    // member must be a compile error here rather than a member silently dropped.
    let oracle::GetBucketLocationOutput { location_constraint } = output;
    dto::GetBucketLocationOutput {
        location_constraint: location_constraint.map(|value| dto::LocationConstraint::custom(value.as_str().to_owned())),
    }
}

/// Converts a RustFS app body's whole answer — its output and the response headers it set beside
/// it — into the gateway output and the extra headers the gateway writes after it
/// (`Resp::with_extra_headers`), as every other operation's `answer_from_legacy` does. The output
/// has no member a header carries, so the headers are handed on whole and nothing is cleared.
#[must_use]
pub fn answer_from_legacy(
    output: oracle::GetBucketLocationOutput,
    headers: http::HeaderMap,
) -> (dto::GetBucketLocationOutput, http::HeaderMap) {
    (output_from_s3s(output), headers)
}

/// Converts the s3s input the legacy stack decoded into the gateway input a ported RustFS use
/// case takes (rustfs/backlog#2749).
///
/// # Errors
///
/// [`ConversionError`] naming the bucket when it is not a name the gateway can write.
pub fn input_from_s3s(input: oracle::GetBucketLocationInput) -> Result<dto::GetBucketLocationInput, ConversionError> {
    // Exhaustive on purpose, as `output_from_s3s` is.
    let oracle::GetBucketLocationInput {
        bucket,
        expected_bucket_owner,
    } = input;
    Ok(dto::GetBucketLocationInput {
        bucket: BucketName::new(bucket).map_err(|_| ConversionError {
            field: "bucket",
            reason: "not a bucket name the gateway can write",
        })?,
        expected_bucket_owner,
    })
}

/// Converts the gateway output a ported RustFS use case returned into the s3s output the legacy
/// stack writes, keeping the constraint's exact spelling as [`output_from_s3s`] does.
#[must_use]
pub fn output_to_s3s(output: dto::GetBucketLocationOutput) -> oracle::GetBucketLocationOutput {
    oracle::GetBucketLocationOutput {
        location_constraint: output.location_constraint.map(|value| value.as_str().to_owned().into()),
    }
}
