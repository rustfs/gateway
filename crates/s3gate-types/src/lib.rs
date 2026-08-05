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

//! S3 scalar types, operation inputs/outputs, and their generated codecs.
//!
//! Responsible for: `ETag`, `Checksum`, `Timestamp`, names, `Range`, error codes, and the
//! generated per-operation DTOs plus their XML/header codec impls.
//! NOT responsible for: wire framing, signing, routing.
//! Upstream: `s3gate-xml`, `s3gate-stream`. Downstream: `s3gate-http` and everything above.
#![forbid(unsafe_code)]

mod scalar;

pub use crate::scalar::{
    BucketName, ByteRange, ChecksumAlgorithm, ChecksumDigest, ChecksumError, ChecksumSpec, ChecksumType, Checksummer, ContentMd5,
    ETag, ErrorCode, ErrorContext, EtagRender, ObjectKey, OpaqueString, ParseError, RangeOutcome, RangeParse, Timestamp,
    TimestampFormat, mask_for_authorization, parse_request_checksum, rules, status_of, validate_bucket_name, validate_object_key,
};
