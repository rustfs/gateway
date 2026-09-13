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
//! gateway output the gateway codec writes. Both directions are total: every value one side holds
//! has exactly one spelling on the other.
//! NOT responsible for: the request context ([`super::request_context`]), looking the bucket's
//! region up, or rendering the `LocationConstraint` body, which is the gateway codec's.
//! Upstream: the generated dto. Downstream: the goldens context diff under every seam revision, and
//! the RustFS ring-2 adapter through the revision RustFS links (rustfs/backlog#1752).

use super::s3s::dto as oracle;

use crate::dto;

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
